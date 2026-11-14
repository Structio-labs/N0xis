// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The receiver, by what it answers and what it leaves on the disk.
//!
//! The first test is the whole path, as a report goes: the client of `n0xis-update`, reading a
//! manifest signed by a key made for this test, over real TLS (a front that stands where the proxy
//! does) to the real receiver on the loopback. What the client was built to show is then compared with
//! what the front saw posted and what the receiver stored, byte for byte, and the stored digests are
//! checked by `sha256sum`, a reader that is not this code. The rest drive the receiver's own state, with
//! a clock the test moves. No test reaches the network.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use n0xis_feedback::{Built, Challenge, frame};
use n0xis_feedback_receiver::{Config, NotDeleted, Receiver};
use n0xis_update::{Limits, Transport, Trust, Updater};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{Value, json};

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("feedback-{name}-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

fn config(spool: &Path) -> Config {
    Config {
        listen: "127.0.0.1:0".parse().expect("addr"),
        spool: spool.to_path_buf(),
        quota_bytes: 1 << 30,
        max_body_bytes: 1 << 20,
        max_text_bytes: 4096,
        max_attachment_bytes: 64 * 1024,
        max_attachments: 2,
        difficulty: 8,
        nonce_ttl_seconds: 300,
        max_outstanding_nonces: 100,
        rate_limit_requests: 1000,
        rate_limit_window_seconds: 3600,
        max_tracked_addresses: 100,
        client_ip_header: Some("X-Real-IP".to_string()),
    }
}

fn png(fill: u8, len: usize) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    bytes.resize(len, fill);
    bytes
}

/// A real receiver on the loopback, serving on its own thread.
fn start_receiver(config: Config) -> u16 {
    let server = tiny_http::Server::http(config.listen).expect("listen");
    let port = server.server_addr().to_ip().expect("ip").port();
    let receiver = Receiver::new(config).expect("receiver");
    std::thread::spawn(move || n0xis_feedback_receiver::serve(receiver, &server));
    port
}

/// One HTTP/1.1 request on a plain connection; the status and the body of the answer.
fn plain(port: u16, head: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(head.as_bytes()).and_then(|()| stream.write_all(body)).expect("send");
    read_answer(&mut BufReader::new(stream))
}

fn read_answer(reader: &mut impl BufRead) -> (u16, Vec<u8>) {
    let mut status_line = String::new();
    reader.read_line(&mut status_line).expect("status");
    let status = status_line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).expect("a status");
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("header");
        if line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().expect("length");
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).expect("body");
    (status, body)
}

fn post(port: u16, nonce: &str, proof: u64, body: &[u8], ip: &str) -> (u16, Value) {
    let head = format!(
        "POST /report HTTP/1.1\r\nHost: x\r\nConnection: close\r\nX-Real-IP: {ip}\r\nX-N0xis-Nonce: {nonce}\r\nX-N0xis-Proof: {proof}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let (status, answer) = plain(port, &head, body);
    (status, serde_json::from_slice(&answer).unwrap_or(Value::Null))
}

fn challenge(port: u16, ip: &str) -> (u16, Option<Challenge>) {
    let (status, body) = plain(port, &format!("GET /challenge HTTP/1.1\r\nHost: x\r\nConnection: close\r\nX-Real-IP: {ip}\r\n\r\n"), b"");
    (status, serde_json::from_slice(&body).ok())
}

fn solved(c: &Challenge, body: &[u8]) -> u64 {
    n0xis_feedback::solve(&n0xis_feedback::nonce_from_hex(&c.nonce).expect("nonce"), body, c.difficulty).expect("solvable")
}

/// A TLS front where the proxy stands: it serves the planted manifest itself and passes `/challenge`
/// and `/report` on to the receiver, as nginx does, with the client's address in `X-Real-IP`. It
/// keeps every body posted through it, as it arrived.
struct Front {
    port: u16,
    ca_der: Vec<u8>,
    posted: Arc<Mutex<Vec<Vec<u8>>>>,
    routes: Routes,
}

/// What the front serves itself, by path.
type Routes = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

impl Front {
    fn start(receiver_port: u16) -> Front {
        let mut ca = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca.self_signed(&ca_key).expect("ca cert");
        let mut leaf = CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
        leaf.subject_alt_names.push(SanType::IpAddress("127.0.0.1".parse().expect("ip")));
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf_cert = leaf.signed_by(&leaf_key, &Issuer::from_params(&ca, &ca_key)).expect("leaf cert");
        let tls = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(leaf_cert.der().to_vec())], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())))
            .expect("tls");
        let tls = Arc::new(tls);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let posted = Arc::new(Mutex::new(Vec::new()));
        let routes: Routes = Arc::new(Mutex::new(Vec::new()));
        let (seen, table) = (posted.clone(), routes.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (tls, seen, table) = (tls.clone(), seen.clone(), table.clone());
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
                    let Ok(conn) = ServerConnection::new(tls) else { return };
                    let mut tls = StreamOwned::new(conn, stream);
                    let mut reader = BufReader::new(&mut tls);
                    let mut head = Vec::new();
                    let mut length = 0usize;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        if line == "\r\n" {
                            break;
                        }
                        if let Some((name, value)) = line.split_once(':')
                            && name.eq_ignore_ascii_case("content-length")
                        {
                            length = value.trim().parse().unwrap_or(0);
                        }
                        // The proxy states the address and closes; nothing of the client's on these passes.
                        if !line.to_ascii_lowercase().starts_with("connection:") && !line.to_ascii_lowercase().starts_with("x-real-ip:") {
                            head.push(line);
                        }
                    }
                    let mut body = vec![0u8; length];
                    if reader.read_exact(&mut body).is_err() {
                        return;
                    }
                    drop(reader);
                    let path = head.first().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("").to_string();
                    let (status, answer) = if path == "/challenge" || path == "/report" {
                        if path == "/report" {
                            seen.lock().unwrap().push(body.clone());
                        }
                        let forwarded = format!("{}Connection: close\r\nX-Real-IP: 198.51.100.23\r\n\r\n", head.concat());
                        plain(receiver_port, &forwarded, &body)
                    } else {
                        match table.lock().unwrap().iter().find(|(p, _)| *p == path) {
                            Some((_, b)) => (200, b.clone()),
                            None => (404, Vec::new()),
                        }
                    };
                    let _ = write!(tls, "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", answer.len()).and_then(|()| tls.write_all(&answer));
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                });
            }
        });
        Front { port, ca_der: ca_cert.der().to_vec(), posted, routes }
    }

    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }

    /// Serve `body` at `path`, in place of anything served there before.
    fn route(&self, path: &str, body: Vec<u8>) {
        let mut routes = self.routes.lock().unwrap();
        routes.retain(|(p, _)| p != path);
        routes.push((path.to_string(), body));
    }
}

/// A manifest signed by a key made here, at the front, naming the front's feedback addresses when
/// `feedback` says so; and the client that trusts that key and that front, through the code the door runs.
fn client(front: &Front, feedback: Option<Value>) -> Updater {
    let key = Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).expect("seed");
    let mut manifest = json!({ "version": "1.0.0", "components": {} });
    if let Some(f) = feedback {
        manifest["feedback"] = f;
    }
    let bytes = serde_json::to_vec(&manifest).expect("json");
    let signature: String = key.sign(&bytes).as_ref().iter().map(|b| format!("{b:02x}")).collect();
    front.route("/manifest.json", bytes);
    front.route("/manifest.json.sig", signature.into_bytes());
    let public: [u8; 32] = key.public_key().as_ref().try_into().expect("32");
    Updater {
        component: "n0xis".to_string(),
        platform: n0xis_update::platform(),
        current: semver::Version::new(1, 0, 0),
        exe: scratch("exe").join("n0xis"),
        addresses: vec![front.url("/manifest.json")],
        trust: Trust::of_keys(&[public]),
        transport: Transport::trusting(std::slice::from_ref(&front.ca_der), Limits::default(), "1.0.0"),
        config_dir: None,
    }
}

fn the_report_dir(spool: &Path) -> PathBuf {
    let ready = n0xis_feedback_receiver::export(spool).expect("export");
    assert_eq!(ready.len(), 1, "one report stored: {ready:?}");
    spool.join(&ready[0].report)
}

/// Every file under `dir`, read whole, with its path.
fn every_file(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(every_file(&path));
        } else {
            out.push((path.clone(), std::fs::read(&path).expect("read")));
        }
    }
    out
}

#[test]
fn what_is_shown_is_what_is_sent_and_what_is_stored() {
    let spool = scratch("spool");
    let front = Front::start(start_receiver(config(&spool)));
    let updater = client(&front, Some(json!({ "challenge": front.url("/challenge"), "report": front.url("/report") })));
    let shot = png(3, 2000);
    let built: Built = n0xis_feedback::build("the decompiler hangs on a switch", std::slice::from_ref(&shot), "1.0.0").expect("builds");

    let sent = updater.send_feedback(&built).unwrap_or_else(|r| panic!("{}: {}", r.why.code(), r.message));

    let posted = front.posted.lock().unwrap().clone();
    assert_eq!(posted.len(), 1);
    assert!(posted[0] == built.body(), "the body posted is not the one built");
    let dir = the_report_dir(&spool);
    assert!(dir.ends_with(&sent.id), "{} is not the id {} the client was told", dir.display(), sent.id);
    assert_eq!(std::fs::read(dir.join("report.json")).expect("report"), built.json().as_bytes(), "the stored JSON is not the shown JSON");
    assert_eq!(std::fs::read(dir.join("attachment-1.png")).expect("attachment"), shot);

    // The address the proxy stated, and the loopback the receiver saw, are nowhere on the disk.
    for (path, bytes) in every_file(&spool) {
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("198.51.100.23") && !text.contains("127.0.0.1"), "{} holds a client address", path.display());
    }

    // The digests are what `sha256sum`, a reader that is not this code, computes of the files.
    #[cfg(unix)]
    {
        let checked = std::process::Command::new("sha256sum").env("LC_ALL", "C").arg("-c").arg("--strict").arg("sha256").current_dir(&dir).output().expect("sha256sum");
        assert!(checked.status.success(), "sha256sum -c: {}", String::from_utf8_lossy(&checked.stdout));
        assert_eq!(String::from_utf8_lossy(&checked.stdout).lines().filter(|l| l.ends_with(": OK")).count(), 2);
    }
}

#[test]
fn a_manifest_that_names_no_receiver_is_said_and_nothing_is_posted() {
    let spool = scratch("spool");
    let front = Front::start(start_receiver(config(&spool)));
    let built = n0xis_feedback::build("x", &[], "1.0.0").expect("builds");
    let refused = client(&front, None).send_feedback(&built).expect_err("nowhere to send");
    assert_eq!(refused.why.code(), "no-feedback-endpoint", "{}", refused.message);
    let refused = client(&front, Some(json!({ "report": front.url("/report") }))).send_feedback(&built).expect_err("half an address");
    assert_eq!(refused.why.code(), "bad-manifest", "{}", refused.message);
    assert!(front.posted.lock().unwrap().is_empty());
    assert!(n0xis_feedback_receiver::export(&spool).expect("export").is_empty());
}

#[test]
fn a_demand_past_what_a_client_works_for_is_refused_not_obeyed() {
    let spool = scratch("spool");
    let front = Front::start(start_receiver(config(&spool)));
    // The front answers the challenge itself, with a difficulty no receiver may be configured to.
    let hard = json!({ "schema": 1, "nonce": "00".repeat(32), "difficulty": n0xis_feedback::MAX_DIFFICULTY + 1, "expires_in_seconds": 60 });
    front.route("/hard", serde_json::to_vec(&hard).expect("json"));
    let updater = client(&front, Some(json!({ "challenge": front.url("/hard"), "report": front.url("/report") })));
    let refused = updater.send_feedback(&n0xis_feedback::build("x", &[], "1.0.0").expect("builds")).expect_err("too hard");
    assert_eq!(refused.why.code(), "difficulty-too-high", "{}", refused.message);
    assert!(front.posted.lock().unwrap().is_empty());
}

#[test]
fn a_wrong_proof_fails_and_spends_its_nonce() {
    let spool = scratch("spool");
    let port = start_receiver(config(&spool));
    let built = n0xis_feedback::build("x", &[], "1.0.0").expect("builds");
    let (_, c) = challenge(port, "192.0.2.1");
    let c = c.expect("a challenge");
    let right = solved(&c, built.body());
    let nonce = n0xis_feedback::nonce_from_hex(&c.nonce).expect("nonce");
    // The first counter past the solution that does not solve it: a wrong proof by the verifier's own word.
    let wrong = (right + 1..).find(|p| !n0xis_feedback::verify(&nonce, built.body(), c.difficulty, *p)).expect("a wrong one");
    let (status, answer) = post(port, &c.nonce, wrong, built.body(), "192.0.2.1");
    assert_eq!((status, answer["error"].as_str()), (403, Some("unsolved")));
    let (status, answer) = post(port, &c.nonce, right, built.body(), "192.0.2.1");
    assert_eq!((status, answer["error"].as_str()), (403, Some("unknown-nonce")), "a nonce is one attempt");
    // A proof for another body does not carry over.
    let (_, c) = challenge(port, "192.0.2.1");
    let c = c.expect("a challenge");
    let other = n0xis_feedback::build("y", &[], "1.0.0").expect("builds");
    let for_other = solved(&c, other.body());
    if !n0xis_feedback::verify(&n0xis_feedback::nonce_from_hex(&c.nonce).expect("nonce"), built.body(), c.difficulty, for_other) {
        assert_eq!(post(port, &c.nonce, for_other, built.body(), "192.0.2.1").0, 403);
    }
    let (_, c) = challenge(port, "192.0.2.1");
    let c = c.expect("a challenge");
    assert_eq!(post(port, &c.nonce, solved(&c, built.body()), built.body(), "192.0.2.1").0, 201);
    assert_eq!(post(port, &"ab".repeat(32), 0, built.body(), "192.0.2.1").1["error"], "unknown-nonce");
    assert_eq!(n0xis_feedback_receiver::export(&spool).expect("export").len(), 1, "only the solved one is stored");
}

#[test]
fn a_nonce_past_its_time_is_refused() {
    let spool = scratch("spool");
    let mut receiver = Receiver::new(config(&spool)).expect("receiver");
    let now = Instant::now();
    let c: Challenge = serde_json::from_slice(&receiver.challenge(now).body).expect("challenge");
    let built = n0xis_feedback::build("x", &[], "1.0.0").expect("builds");
    let proof = solved(&c, built.body()).to_string();
    let late = now + Duration::from_secs(c.expires_in_seconds + 1);
    let answer = receiver.report(Some(&c.nonce), Some(&proof), built.body(), late, SystemTime::now());
    assert_eq!(answer.status, 403);
    assert!(String::from_utf8_lossy(&answer.body).contains("expired-nonce"));
    assert!(n0xis_feedback_receiver::export(&spool).expect("export").is_empty());
}

/// A report the client would never build, refused by the receiver's own limits before anything is stored.
fn refused_with(receiver: &mut Receiver, json: &Value, attachments: &[&[u8]]) -> (u16, String) {
    let now = Instant::now();
    let c: Challenge = serde_json::from_slice(&receiver.challenge(now).body).expect("challenge");
    let body = frame(serde_json::to_string(json).expect("json").as_bytes(), attachments);
    let proof = solved(&c, &body).to_string();
    let answer = receiver.report(Some(&c.nonce), Some(&proof), &body, now, SystemTime::now());
    let said: Value = serde_json::from_slice(&answer.body).expect("json");
    (answer.status, said["error"].as_str().unwrap_or("").to_string())
}

fn listed(bytes: &[u8], kind: &str) -> Value {
    json!({ "type": kind, "size": bytes.len(), "sha256": n0xis_feedback::sha256_hex(bytes) })
}

#[test]
fn the_limits_and_the_types_hold_before_anything_is_stored() {
    let spool = scratch("spool");
    let config = config(&spool);
    let mut receiver = Receiver::new(config.clone()).expect("receiver");
    let report = |text: String, attachments: Vec<Value>| json!({ "schema": 1, "version": "1.0.0", "os": "linux", "arch": "x86_64", "text": text, "attachments": attachments });

    let at = "a".repeat(config.max_text_bytes);
    assert_eq!(refused_with(&mut receiver, &report(at.clone() + "a", vec![]), &[]), (413, "text-too-long".to_string()));
    let shot = png(1, 100);
    let gif = b"GIF89a-not-taken".to_vec();
    assert_eq!(refused_with(&mut receiver, &report("x".into(), vec![listed(&gif, "png")]), &[&gif]), (415, "not-an-image".to_string()));
    assert_eq!(refused_with(&mut receiver, &report("x".into(), vec![listed(&shot, "jpeg")]), &[&shot]), (415, "type-mismatch".to_string()));
    let big = png(2, config.max_attachment_bytes as usize + 1);
    assert_eq!(refused_with(&mut receiver, &report("x".into(), vec![listed(&big, "png")]), &[&big]), (413, "attachment-too-large".to_string()));
    let three = vec![listed(&shot, "png"), listed(&shot, "png"), listed(&shot, "png")];
    assert_eq!(refused_with(&mut receiver, &report("x".into(), three), &[&shot, &shot, &shot]), (413, "too-many-attachments".to_string()));
    let mut leaky = report("x".into(), vec![]);
    leaky["path"] = json!("/home/someone/target.bin");
    assert_eq!(refused_with(&mut receiver, &leaky, &[]), (400, "malformed-report".to_string()), "a field the schema has no place for");
    let mut later = report("x".into(), vec![]);
    later["schema"] = json!(2);
    assert_eq!(refused_with(&mut receiver, &later, &[]), (400, "unknown-schema".to_string()));
    assert!(n0xis_feedback_receiver::export(&spool).expect("export").is_empty());
    assert_eq!(n0xis_feedback_receiver::spool_bytes(&spool).expect("size"), 0, "nothing was written");

    // Calibrated by the edge itself: the same report at the bound is stored.
    assert_eq!(refused_with(&mut receiver, &report(at, vec![listed(&shot, "png")]), &[&shot]).0, 201);
}

#[test]
fn a_body_past_the_bound_is_refused_by_its_length_before_it_is_read() {
    let spool = scratch("spool");
    let config = config(&spool);
    let max = config.max_body_bytes;
    let port = start_receiver(config);
    let (_, c) = challenge(port, "192.0.2.2");
    let c = c.expect("a challenge");
    // Declares one byte past the bound and sends none of it: the answer comes from the head alone.
    let head = format!("POST /report HTTP/1.1\r\nHost: x\r\nConnection: close\r\nX-N0xis-Nonce: {}\r\nX-N0xis-Proof: 0\r\nContent-Length: {}\r\n\r\n", c.nonce, max + 1);
    let (status, _) = plain(port, &head, b"");
    assert_eq!(status, 413);
    // The nonce was not spent on it.
    let built = n0xis_feedback::build("x", &[], "1.0.0").expect("builds");
    assert_eq!(post(port, &c.nonce, solved(&c, built.body()), built.body(), "192.0.2.2").0, 201);
    let chunked = "POST /report HTTP/1.1\r\nHost: x\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n";
    assert_eq!(plain(port, chunked, b"").0, 411, "a body that states no length");
}

#[test]
fn a_full_spool_answers_507_and_stores_nothing() {
    let spool = scratch("spool");
    let mut config = config(&spool);
    let mut probe = Receiver::new(config.clone()).expect("receiver");
    let built = n0xis_feedback::build("a report of some length", &[], "1.0.0").expect("builds");
    let send = |r: &mut Receiver| {
        let now = Instant::now();
        let c: Challenge = serde_json::from_slice(&r.challenge(now).body).expect("challenge");
        r.report(Some(&c.nonce), Some(&solved(&c, built.body()).to_string()), built.body(), now, SystemTime::now()).status
    };
    assert_eq!(send(&mut probe), 201);
    let one = n0xis_feedback_receiver::spool_bytes(&spool).expect("size");
    // Room for two reports and not a third.
    let spool = scratch("spool");
    config.spool = spool.clone();
    config.quota_bytes = 2 * one + one / 2;
    let mut receiver = Receiver::new(config).expect("receiver");
    assert_eq!((send(&mut receiver), send(&mut receiver)), (201, 201));
    let before = every_file(&spool);
    assert_eq!(send(&mut receiver), 507);
    assert_eq!(every_file(&spool), before, "the spool is as it was");
}

#[test]
fn the_rate_limit_is_per_address_and_kept_in_memory() {
    let spool = scratch("spool");
    let mut config = config(&spool);
    config.rate_limit_requests = 3;
    let port = start_receiver(config);
    let statuses: Vec<u16> = (0..4).map(|_| challenge(port, "203.0.113.9").0).collect();
    assert_eq!(statuses, vec![200, 200, 200, 429]);
    assert_eq!(challenge(port, "203.0.113.10").0, 200, "another address has its own count");
}

#[test]
fn delete_removes_a_report_only_by_its_digest() {
    let spool = scratch("spool");
    let mut receiver = Receiver::new(config(&spool)).expect("receiver");
    let now = Instant::now();
    let c: Challenge = serde_json::from_slice(&receiver.challenge(now).body).expect("challenge");
    let built = n0xis_feedback::build("keep me until pulled", &[png(5, 300)], "1.0.0").expect("builds");
    assert_eq!(receiver.report(Some(&c.nonce), Some(&solved(&c, built.body()).to_string()), built.body(), now, SystemTime::now()).status, 201);
    let ready = n0xis_feedback_receiver::export(&spool).expect("export");
    assert_eq!(ready[0].files, vec!["report.json".to_string(), "attachment-1.png".to_string()]);
    // The digest is of the listing, as `sha256sum` would give for the file `sha256`.
    let listing = std::fs::read(spool.join(&ready[0].report).join("sha256")).expect("listing");
    assert_eq!(ready[0].digest, n0xis_feedback::sha256_hex(&listing));

    let wrong = "0".repeat(64);
    assert_eq!(n0xis_feedback_receiver::delete(&spool, &ready[0].report, &wrong), Err(NotDeleted::DigestDiffers));
    assert_eq!(n0xis_feedback_receiver::delete(&spool, "../outside", &ready[0].digest), Err(NotDeleted::NotAReport));
    assert_eq!(n0xis_feedback_receiver::delete(&spool, "2026-11/..", &ready[0].digest), Err(NotDeleted::NotAReport));
    assert_eq!(n0xis_feedback_receiver::export(&spool).expect("export"), ready, "still there");
    n0xis_feedback_receiver::delete(&spool, &ready[0].report, &ready[0].digest).expect("deleted");
    assert!(n0xis_feedback_receiver::export(&spool).expect("export").is_empty());
    assert!(!spool.join(&ready[0].report).exists());
}

#[test]
fn a_configuration_that_is_not_whole_or_not_on_the_loopback_is_refused() {
    let dir = scratch("config");
    let path = dir.join("receiver.json");
    let mut value = serde_json::to_value(json!({
        "listen": "127.0.0.1:8471", "spool": dir.join("spool"), "quota_bytes": 1, "max_body_bytes": 1, "max_text_bytes": 1,
        "max_attachment_bytes": 1, "max_attachments": 1, "difficulty": 20, "nonce_ttl_seconds": 1, "max_outstanding_nonces": 1,
        "rate_limit_requests": 1, "rate_limit_window_seconds": 1, "max_tracked_addresses": 1, "client_ip_header": "X-Real-IP"
    }))
    .expect("json");
    std::fs::write(&path, value.to_string()).expect("write");
    Config::load(&path).expect("a whole configuration loads");
    // The example a deployment starts from is a configuration this receiver loads.
    Config::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("receiver.example.json")).expect("the example loads");
    value["listen"] = json!("0.0.0.0:8471");
    std::fs::write(&path, value.to_string()).expect("write");
    assert!(Config::load(&path).unwrap_err().contains("loopback"));
    value["listen"] = json!("127.0.0.1:8471");
    value["difficulty"] = json!(n0xis_feedback::MAX_DIFFICULTY + 1);
    std::fs::write(&path, value.to_string()).expect("write");
    assert!(Config::load(&path).unwrap_err().contains("difficulty"));
    value["difficulty"] = json!(20);
    value.as_object_mut().expect("object").remove("quota_bytes");
    std::fs::write(&path, value.to_string()).expect("write");
    assert!(Config::load(&path).unwrap_err().contains("quota_bytes"), "a missing key is no default");
}
