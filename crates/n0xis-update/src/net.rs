// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The network client: GET over HTTPS, bounded in time and in size. Nothing else in the tree opens
//! a connection, and it carries nothing about what is being analysed: the callers hand it addresses
//! from the configuration and a signed manifest, and have nothing else to give it.

use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;
use std::time::Duration;

use ureq::Agent;
use ureq::tls::{Certificate, RootCerts, TlsConfig, TlsProvider};

use crate::{Refusal, Why};

/// More than any manifest will ever need, so a server cannot make a client read without end before
/// the signature has said anything about the bytes.
const MANIFEST_MAX_BYTES: u64 = 4 * 1024 * 1024;
const SIGNATURE_MAX_BYTES: u64 = 64 * 1024;

/// The bounds of every request, and how long another run's lock is waited out.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub connect: Duration,
    /// From a sent request to the response's head.
    pub response: Duration,
    /// To read a whole manifest or signature.
    pub small_body: Duration,
    /// To read a whole file. Generous: 13 MB on a slow line takes minutes and is not a failure.
    pub file_body: Duration,
    pub redirects: u32,
    /// For the new file to answer `--version`. Generous: a first run under a slow scanner or an
    /// emulation layer is not a failure, and a hang is.
    pub run: Duration,
    /// For another run to let go of a file's lock before this one says `update-in-progress`. Short:
    /// it covers a run that is about to finish, a killed holder whose lock a process forked from
    /// it keeps until its exec, and a client before `Held` that let go by its close.
    pub lock: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            connect: Duration::from_secs(10),
            response: Duration::from_secs(20),
            small_body: Duration::from_secs(20),
            file_body: Duration::from_secs(30 * 60),
            // GitHub's `latest/download` takes two: to the tagged release, then to the asset's store.
            redirects: 5,
            run: Duration::from_secs(30),
            lock: Duration::from_millis(500),
        }
    }
}

/// HTTPS and nothing else: `https_only` is checked by the client on every hop, redirects included.
#[derive(Debug)]
pub struct Transport {
    small: Agent,
    file: Agent,
    pub(crate) run_bound: Duration,
    pub(crate) lock_patience: Duration,
}

/// What can happen to a GET before there is a body to judge.
enum Failed {
    Status(u16),
    Transport(String),
}

impl Failed {
    fn message(&self) -> String {
        match self {
            Failed::Status(code) => format!("the server answered {code}"),
            Failed::Transport(why) => why.clone(),
        }
    }
}

impl Transport {
    /// The client a release ships.
    ///
    /// Trusts the system's roots and the bundled ones together. A copy in the field lives for years,
    /// and the bundle it was built with ages; the system's are kept current for it. A machine with
    /// no certificates installed has the bundle. The signature is what guards the content, so
    /// the only thing a wider set of roots can cost is a request.
    pub fn standard(version: &str) -> Transport {
        let mut roots: Vec<Certificate<'static>> = webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().map(|c| Certificate::from_der(c.as_ref()).to_owned()).collect();
        // A store that cannot be read, in part or in whole, leaves the bundle.
        roots.extend(rustls_native_certs::load_native_certs().certs.iter().map(|c| Certificate::from_der(c.as_ref()).to_owned()));
        Self::build(roots, Limits::default(), version)
    }

    /// Trusting only these roots (DER), with these bounds: a planted server's certificate.
    pub fn trusting(roots: &[Vec<u8>], limits: Limits, version: &str) -> Transport {
        let roots = roots.iter().map(|der| Certificate::from_der(der).to_owned()).collect();
        Self::build(roots, limits, version)
    }

    fn build(roots: Vec<Certificate<'static>>, limits: Limits, version: &str) -> Transport {
        let roots = RootCerts::Specific(Arc::new(roots));
        let agent = |body: Duration| -> Agent {
            Agent::config_builder()
                .https_only(true)
                .max_redirects(limits.redirects)
                .max_redirects_will_error(true)
                .timeout_connect(Some(limits.connect))
                .timeout_recv_response(Some(limits.response))
                .timeout_recv_body(Some(body))
                .user_agent(format!("n0xis/{version}"))
                .tls_config(TlsConfig::builder().provider(TlsProvider::Rustls).root_certs(roots.clone()).build())
                .build()
                .into()
        };
        Transport { small: agent(limits.small_body), file: agent(limits.file_body), run_bound: limits.run, lock_patience: limits.lock }
    }

    fn get_small(&self, url: &str, max: u64) -> Result<Vec<u8>, Failed> {
        let mut response = self.small.get(url).call().map_err(failed)?;
        response.body_mut().with_config().limit(max).read_to_vec().map_err(failed)
    }

    pub(crate) fn get_manifest(&self, url: &str) -> Result<Vec<u8>, Refusal> {
        self.get_small(url, MANIFEST_MAX_BYTES).map_err(|f| Refusal::new(Why::ManifestUnavailable, f.message()))
    }

    /// No signature to be had, for whatever reason, is what the refusal says: the check was not done.
    pub(crate) fn get_signature(&self, url: &str) -> Result<Vec<u8>, Refusal> {
        self.get_small(url, SIGNATURE_MAX_BYTES).map_err(|f| Refusal::new(Why::NoSignature, format!("no signature at {url}: {}", f.message())))
    }

    /// Write the file at `url` to `out`, reading at most `size` bytes plus the one that shows it was
    /// longer than the manifest said. No digest here: what is checked is the file afterwards, because
    /// a digest of the stream says nothing about what is on the disk.
    pub(crate) fn download(&self, url: &str, size: u64, out: &mut impl Write) -> Result<(), Refusal> {
        let failed_with = |f: Failed| Refusal::new(Why::DownloadFailed, format!("{url}: {}", f.message()));
        let mut response = self.file.get(url).call().map_err(failed).map_err(failed_with)?;
        let mut reader = response.body_mut().as_reader();
        let mut buffer = vec![0u8; 64 * 1024];
        let mut got: u64 = 0;
        loop {
            let n = match reader.read(&mut buffer) {
                Ok(n) => n,
                // The connection ending early is what a truncated download looks like when the
                // server had declared a length: it says the same thing as a short body does.
                Err(e) if got < size && ended_early(&e) => {
                    return Err(short(url, got, size));
                }
                Err(e) => return Err(Refusal::new(Why::DownloadFailed, format!("{url}: {e}"))),
            };
            if n == 0 {
                break;
            }
            got += n as u64;
            if got > size {
                return Err(Refusal::new(Why::SizeMismatch, format!("{url} is longer than the {size} bytes the manifest states")));
            }
            out.write_all(&buffer[..n]).map_err(|e| Refusal::new(Why::InstallFailed, format!("writing the download: {e}")))?;
        }
        // A short body is found where the digest is, by reading the file back.
        Ok(())
    }
}

fn short(url: &str, got: u64, size: u64) -> Refusal {
    Refusal::new(Why::SizeMismatch, format!("{url} ended after {got} of the {size} bytes the manifest states"))
}

fn ended_early(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe)
}

fn failed(e: ureq::Error) -> Failed {
    match e {
        ureq::Error::StatusCode(code) => Failed::Status(code),
        other => Failed::Transport(other.to_string()),
    }
}
