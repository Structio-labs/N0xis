// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A planted release server, over real TLS with a certificate authority made for the test, so that
//! `https_only` is what is exercised and not a door left open for tests. No test here reaches the
//! network: it listens on the loopback only.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

/// What a path answers.
#[derive(Clone)]
pub enum Reply {
    Body(Vec<u8>),
    Status(u16),
    Redirect(String),
    /// Declares `declared` bytes, sends `body`, and drops the connection with no TLS close.
    CutOff { declared: usize, body: Vec<u8> },
    /// No declared length, and a clean close after `body`: the short body looks complete.
    EndsEarly(Vec<u8>),
    /// Sends for as long as anyone reads.
    Endless,
    /// Sends the head and part of a body, then nothing, for longer than a test waits.
    StallsInBody,
    /// Accepts and says nothing, for longer than a test waits.
    Silent,
    /// Sends `at` bytes of `body`, calls `meanwhile`, then sends the rest: for a test to look at or
    /// alter what the client has on the disk during its download.
    During { body: Vec<u8>, at: usize, meanwhile: Arc<dyn Fn() + Send + Sync> },
}

pub struct Server {
    pub port: u16,
    pub ca_der: Vec<u8>,
    pub ca_pem: String,
    /// The request head of everything asked, in order.
    pub requests: Arc<Mutex<Vec<String>>>,
    routes: Arc<Mutex<HashMap<String, Reply>>>,
}

impl Server {
    pub fn start() -> Server {
        let mut ca = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca.self_signed(&ca_key).expect("ca cert");
        let mut leaf = CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
        leaf.subject_alt_names.push(SanType::IpAddress("127.0.0.1".parse().expect("ip")));
        let leaf_key = KeyPair::generate().expect("leaf key");
        let issuer = Issuer::from_params(&ca, &ca_key);
        let leaf_cert = leaf.signed_by(&leaf_key, &issuer).expect("leaf cert");

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf_cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .expect("server config");
        let config = Arc::new(config);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let routes: Arc<Mutex<HashMap<String, Reply>>> = Arc::new(Mutex::new(HashMap::new()));
        let (seen, table) = (requests.clone(), routes.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (config, seen, table) = (config.clone(), seen.clone(), table.clone());
                std::thread::spawn(move || serve(stream, config, &seen, &table));
            }
        });
        Server { port, ca_der: ca_cert.der().to_vec(), ca_pem: ca_cert.pem(), requests, routes }
    }

    pub fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }

    pub fn route(&self, path: &str, reply: Reply) {
        self.routes.lock().unwrap().insert(path.to_string(), reply);
    }

    pub fn asked(&self, path: &str) -> usize {
        let line = format!("GET {path} ");
        self.requests.lock().unwrap().iter().filter(|r| r.starts_with(&line)).count()
    }
}

fn serve(stream: TcpStream, config: Arc<ServerConfig>, seen: &Mutex<Vec<String>>, table: &Mutex<HashMap<String, Reply>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
    let Ok(connection) = ServerConnection::new(config) else { return };
    let mut tls = StreamOwned::new(connection, stream);
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tls.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
    seen.lock().unwrap().push(head);
    let reply = table.lock().unwrap().get(&path).cloned().unwrap_or(Reply::Status(404));
    let close = "Connection: close\r\n\r\n";
    let _ = match reply {
        Reply::Body(body) => {
            let written = write!(tls, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{close}", body.len()).and_then(|()| tls.write_all(&body));
            tls.conn.send_close_notify();
            written.and_then(|()| tls.flush())
        }
        Reply::Status(code) => {
            let written = write!(tls, "HTTP/1.1 {code} Planted\r\nContent-Length: 0\r\n{close}");
            tls.conn.send_close_notify();
            written.and_then(|()| tls.flush())
        }
        Reply::Redirect(to) => {
            let written = write!(tls, "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\n{close}");
            tls.conn.send_close_notify();
            written.and_then(|()| tls.flush())
        }
        Reply::CutOff { declared, body } => write!(tls, "HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\n{close}")
            .and_then(|()| tls.write_all(&body))
            .and_then(|()| tls.flush()),
        Reply::EndsEarly(body) => {
            let written = write!(tls, "HTTP/1.1 200 OK\r\n{close}").and_then(|()| tls.write_all(&body));
            tls.conn.send_close_notify();
            written.and_then(|()| tls.flush())
        }
        Reply::Endless => {
            let chunk = vec![b'x'; 64 * 1024];
            write!(tls, "HTTP/1.1 200 OK\r\n{close}").and_then(|()| loop {
                tls.write_all(&chunk)?;
            })
        }
        Reply::StallsInBody => {
            let written = write!(tls, "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n{close}abc").and_then(|()| tls.flush());
            std::thread::sleep(Duration::from_secs(20));
            written
        }
        Reply::Silent => {
            std::thread::sleep(Duration::from_secs(20));
            Ok(())
        }
        Reply::During { body, at, meanwhile } => {
            let first = write!(tls, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{close}", body.len()).and_then(|()| tls.write_all(&body[..at])).and_then(|()| tls.flush());
            meanwhile();
            let written = first.and_then(|()| tls.write_all(&body[at..]));
            tls.conn.send_close_notify();
            written.and_then(|()| tls.flush())
        }
    };
}
