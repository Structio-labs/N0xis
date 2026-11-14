// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! # The feedback receiver
//!
//! `GET /challenge` gives a nonce and a difficulty, `POST /report` takes a report solved for one, and
//! a stored report waits in the spool until the owner's machine pulls it (`export`) and, having checked
//! its digest, removes it (`delete`). It listens on the loopback only, behind a proxy that speaks
//! HTTPS; it is never linked by the tool, and the report's shape is `n0xis-feedback`'s, the client's.
//!
//! **Before anything is stored** a report has passed every check: its size, before a byte of it is
//! read; a nonce this receiver issued, unused and fresh, taken whether or not the work is right;
//! the work; the schema, every limit and each attachment's type by its magic bytes; and the spool's
//! quota, which when it would be passed is answered 507 with nothing written.
//!
//! **No address is stored.** The rate limit keeps one per client in memory, for its window, and no
//! more of them than the configuration allows; a report holds what the client sent and nothing the
//! receiver learned about the client.
//!
//! **Every number is the configuration's** ([`Config`]): a value in the code would be a second
//! statement of one the deployment makes.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use n0xis_feedback::{Challenge, Limits, SCHEMA};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_json::json;

/// The receiver's routes, as the proxy forwards them. The client is given whole addresses by the
/// signed manifest and never joins these itself.
pub const CHALLENGE_PATH: &str = "/challenge";
pub const REPORT_PATH: &str = "/report";

/// Where a report is put together before it is renamed into its month, so that a reader of the
/// spool sees a whole report or none. Swept at start: what is there is a run that died.
const INCOMING: &str = ".incoming";
/// Where a report is renamed to before it is removed, so it leaves `export` at once.
const DELETING: &str = ".deleting";
/// The file listing each other file's sha256, in `sha256sum` form. Its own digest is the report's.
pub const DIGESTS: &str = "sha256";
pub const REPORT_FILE: &str = "report.json";

/// Everything the receiver is told, from one file. Every key is required: a forgotten one is an
/// error at start, not a default nobody chose.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// A loopback address; anything else is refused.
    pub listen: SocketAddr,
    pub spool: PathBuf,
    /// All of the spool, reports being written included.
    pub quota_bytes: u64,
    /// One request's body, refused by its declared length before it is read.
    pub max_body_bytes: u64,
    pub max_text_bytes: usize,
    pub max_attachment_bytes: u64,
    pub max_attachments: usize,
    pub difficulty: u32,
    pub nonce_ttl_seconds: u64,
    /// Nonces issued and not yet used or expired; past it a challenge is answered 503.
    pub max_outstanding_nonces: usize,
    /// Requests one client address may make in a window, both routes together.
    pub rate_limit_requests: u32,
    pub rate_limit_window_seconds: u64,
    /// Client addresses tracked at once; past it, with none expired, a request is answered 429.
    pub max_tracked_addresses: usize,
    /// The header the proxy states the client's address in, or null to take the peer's: with a
    /// proxy in front the peer is always the proxy.
    pub client_ip_header: Option<String>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let config: Config = serde_json::from_slice(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.listen.ip().is_loopback() {
            return Err(format!("listen {} is not a loopback address: the proxy in front is the only way in", self.listen));
        }
        if self.difficulty > n0xis_feedback::MAX_DIFFICULTY {
            return Err(format!("difficulty {} is more than the {} a client works for", self.difficulty, n0xis_feedback::MAX_DIFFICULTY));
        }
        if self.nonce_ttl_seconds == 0 || self.rate_limit_window_seconds == 0 {
            return Err("nonce_ttl_seconds and rate_limit_window_seconds must be more than zero".to_string());
        }
        Ok(())
    }

    fn limits(&self) -> Limits {
        Limits { max_text_bytes: self.max_text_bytes, max_attachment_bytes: self.max_attachment_bytes, max_attachments: Some(self.max_attachments) }
    }
}

/// An answer: a status and a JSON body.
#[derive(Debug, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Answer {
    fn json(status: u16, value: serde_json::Value) -> Answer {
        Answer { status, body: value.to_string().into_bytes() }
    }

    fn refuse(status: u16, code: &str, message: impl std::fmt::Display) -> Answer {
        Answer::json(status, json!({ "error": code, "message": message.to_string() }))
    }
}

/// The receiver's state: nonces issued and the rate limit's counts. Memory only, and bounded.
pub struct Receiver {
    config: Config,
    nonces: HashMap<[u8; 32], Instant>,
    /// A client address and the start and count of its window. Never written anywhere.
    windows: HashMap<String, (Instant, u32)>,
    random: SystemRandom,
}

impl Receiver {
    /// A receiver over `config`'s spool. What a run that died left half-written is removed.
    pub fn new(config: Config) -> std::io::Result<Receiver> {
        fs::create_dir_all(&config.spool)?;
        for leftover in [INCOMING, DELETING] {
            let dir = config.spool.join(leftover);
            if dir.exists() {
                fs::remove_dir_all(&dir)?;
            }
        }
        Ok(Receiver { config, nonces: HashMap::new(), windows: HashMap::new(), random: SystemRandom::new() })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Whether `client` may make another request now. Counts it if so.
    pub fn admit(&mut self, client: &str, now: Instant) -> bool {
        let window = Duration::from_secs(self.config.rate_limit_window_seconds);
        if !self.windows.contains_key(client) && self.windows.len() >= self.config.max_tracked_addresses {
            self.windows.retain(|_, (start, _)| now.duration_since(*start) < window);
            if self.windows.len() >= self.config.max_tracked_addresses {
                return false;
            }
        }
        let entry = self.windows.entry(client.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        if entry.1 >= self.config.rate_limit_requests {
            return false;
        }
        entry.1 += 1;
        true
    }

    /// `GET /challenge`.
    pub fn challenge(&mut self, now: Instant) -> Answer {
        let ttl = Duration::from_secs(self.config.nonce_ttl_seconds);
        if self.nonces.len() >= self.config.max_outstanding_nonces {
            self.nonces.retain(|_, issued| now.duration_since(*issued) <= ttl);
            if self.nonces.len() >= self.config.max_outstanding_nonces {
                return Answer::refuse(503, "busy", "too many challenges are outstanding; try again later");
            }
        }
        let mut nonce = [0u8; 32];
        if self.random.fill(&mut nonce).is_err() {
            return Answer::refuse(500, "no-randomness", "the system gave no random bytes");
        }
        self.nonces.insert(nonce, now);
        let challenge = Challenge {
            schema: SCHEMA,
            nonce: n0xis_feedback::to_hex(&nonce),
            difficulty: self.config.difficulty,
            expires_in_seconds: self.config.nonce_ttl_seconds,
        };
        Answer::json(200, serde_json::to_value(challenge).unwrap_or_default())
    }

    /// `POST /report`, with a body already bounded by [`Config::max_body_bytes`].
    pub fn report(&mut self, nonce: Option<&str>, proof: Option<&str>, body: &[u8], now: Instant, wall: SystemTime) -> Answer {
        let Some(nonce) = nonce.and_then(n0xis_feedback::nonce_from_hex) else {
            return Answer::refuse(403, "no-nonce", "no nonce this receiver could read");
        };
        // Taken here, solved or not: a nonce is one attempt, so it cannot be ground against.
        let Some(issued) = self.nonces.remove(&nonce) else {
            return Answer::refuse(403, "unknown-nonce", "not a nonce this receiver issued, or one already used");
        };
        if now.duration_since(issued) > Duration::from_secs(self.config.nonce_ttl_seconds) {
            return Answer::refuse(403, "expired-nonce", "the nonce expired; ask for another");
        }
        let solved = proof.and_then(|p| p.parse::<u64>().ok()).is_some_and(|p| n0xis_feedback::verify(&nonce, body, self.config.difficulty, p));
        if !solved {
            return Answer::refuse(403, "unsolved", "the proof does not solve the nonce for this body");
        }
        let parts = match n0xis_feedback::unframe(body) {
            Ok(parts) => parts,
            Err(refusal) => return Answer::refuse(400, refusal.code(), refusal),
        };
        if let Err(refusal) = parts.report.check(&parts.attachments, &self.config.limits()) {
            let status = if refusal.is_size() {
                413
            } else if refusal.is_type() {
                415
            } else {
                400
            };
            return Answer::refuse(status, refusal.code(), refusal);
        }
        let stored = Stored::of(&parts);
        let held = match spool_bytes(&self.config.spool) {
            Ok(held) => held,
            Err(e) => return Answer::refuse(500, "spool-unreadable", e),
        };
        if held.saturating_add(stored.bytes()) > self.config.quota_bytes {
            return Answer::refuse(507, "spool-full", "the spool is full; nothing was stored");
        }
        match self.store(&stored, wall) {
            Ok(id) => Answer::json(201, json!({ "id": id })),
            Err(e) => Answer::refuse(500, "not-stored", e),
        }
    }

    /// Write a report by rename: put together under `.incoming`, then moved into its month whole.
    fn store(&self, stored: &Stored, wall: SystemTime) -> std::io::Result<String> {
        let (date, time) = utc(wall);
        let mut tag = [0u8; 8];
        self.random.fill(&mut tag).map_err(|_| std::io::Error::other("the system gave no random bytes"))?;
        let id = format!("{}{}{}T{}Z-{}", &date[..4], &date[5..7], &date[8..10], time.replace(':', ""), n0xis_feedback::to_hex(&tag));
        let incoming = self.config.spool.join(INCOMING);
        fs::create_dir_all(&incoming)?;
        let building = incoming.join(&id);
        fs::create_dir(&building)?;
        let written = (|| {
            for (name, bytes) in stored.files() {
                write_synced(&building.join(name), bytes)?;
            }
            write_synced(&building.join(DIGESTS), stored.digests.as_bytes())?;
            let month = self.config.spool.join(&date[..7]);
            fs::create_dir_all(&month)?;
            fs::rename(&building, month.join(&id))?;
            sync_dir(&month)
        })();
        if written.is_err() {
            let _ = fs::remove_dir_all(&building);
        }
        written.map(|()| id)
    }
}

/// What one report is on the disk: its files and the listing of their digests.
struct Stored<'a> {
    files: Vec<(String, &'a [u8])>,
    digests: String,
}

impl<'a> Stored<'a> {
    fn of(parts: &n0xis_feedback::Unframed<'a>) -> Stored<'a> {
        // The JSON as it came, byte for byte: what the client showed is what is kept.
        let mut files = vec![(REPORT_FILE.to_string(), parts.json)];
        for (n, (listed, bytes)) in parts.report.attachments.iter().zip(&parts.attachments).enumerate() {
            files.push((format!("attachment-{}.{}", n + 1, listed.kind.extension()), *bytes));
        }
        let digests = files.iter().map(|(name, bytes)| format!("{}  {name}\n", n0xis_feedback::sha256_hex(bytes))).collect();
        Stored { files, digests }
    }

    fn files(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.files.iter().map(|(name, bytes)| (name.as_str(), *bytes))
    }

    fn bytes(&self) -> u64 {
        self.files.iter().map(|(_, b)| b.len() as u64).sum::<u64>() + self.digests.len() as u64
    }
}

fn write_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Everything under the spool, in bytes of file content.
pub fn spool_bytes(dir: &Path) -> std::io::Result<u64> {
    let mut total = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            total += spool_bytes(&entry.path())?;
        } else {
            total += entry.metadata()?.len();
        }
    }
    Ok(total)
}

/// `YYYY-MM-DD` and `HH:MM:SS` in UTC.
fn utc(wall: SystemTime) -> (String, String) {
    let secs = wall.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    // Days to a civil date in the proleptic Gregorian calendar (H. Hinnant's `civil_from_days`).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (format!("{year:04}-{month:02}-{day:02}"), format!("{:02}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60))
}

/// A stored report as `export` lists it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Ready {
    /// `YYYY-MM/ID`, relative to the spool.
    pub report: String,
    /// The sha256 of its `sha256` file, which lists every other file's.
    pub digest: String,
    pub files: Vec<String>,
}

/// Every whole report in the spool, oldest first. Ones being written or removed are not whole.
pub fn export(spool: &Path) -> std::io::Result<Vec<Ready>> {
    let mut out = Vec::new();
    let mut months: Vec<_> = fs::read_dir(spool)?.filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| is_month(n)).collect();
    months.sort();
    for month in months {
        let mut ids: Vec<_> = fs::read_dir(spool.join(&month))?.filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| is_id(n)).collect();
        ids.sort();
        for id in ids {
            let listing = fs::read(spool.join(&month).join(&id).join(DIGESTS))?;
            let files = String::from_utf8_lossy(&listing).lines().filter_map(|l| l.split_once("  ").map(|(_, name)| name.to_string())).collect();
            out.push(Ready { report: format!("{month}/{id}"), digest: n0xis_feedback::sha256_hex(&listing), files });
        }
    }
    Ok(out)
}

/// Why `delete` removed nothing.
#[derive(Debug, PartialEq, Eq)]
pub enum NotDeleted {
    /// Not of the form `YYYY-MM/ID`, so it names nothing `export` lists.
    NotAReport,
    NoSuchReport,
    /// The digest given is not this report's: what was pulled is not what is here.
    DigestDiffers,
    Io(String),
}

/// Remove `report` (`YYYY-MM/ID`), only if `digest` is its digest as `export` states it.
pub fn delete(spool: &Path, report: &str, digest: &str) -> Result<(), NotDeleted> {
    let Some((month, id)) = report.split_once('/').filter(|(m, i)| is_month(m) && is_id(i)) else {
        return Err(NotDeleted::NotAReport);
    };
    let dir = spool.join(month).join(id);
    let listing = match fs::read(dir.join(DIGESTS)) {
        Ok(listing) => listing,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(NotDeleted::NoSuchReport),
        Err(e) => return Err(NotDeleted::Io(e.to_string())),
    };
    if n0xis_feedback::sha256_hex(&listing) != digest {
        return Err(NotDeleted::DigestDiffers);
    }
    let deleting = spool.join(DELETING);
    fs::create_dir_all(&deleting).map_err(|e| NotDeleted::Io(e.to_string()))?;
    let aside = deleting.join(id);
    fs::rename(&dir, &aside).map_err(|e| NotDeleted::Io(e.to_string()))?;
    fs::remove_dir_all(&aside).map_err(|e| NotDeleted::Io(e.to_string()))
}

fn is_month(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() == 7 && b[4] == b'-' && b.iter().enumerate().all(|(i, c)| i == 4 || c.is_ascii_digit())
}

/// `YYYYMMDDTHHMMSSZ-` and 16 hex digits, as [`Receiver::store`] names one.
fn is_id(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() == 33
        && b[8] == b'T'
        && b[15] == b'Z'
        && b[16] == b'-'
        && b[..8].iter().chain(&b[9..15]).all(u8::is_ascii_digit)
        && b[17..].iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

/// Serve until the listener fails. One request at a time: the proxy in front buffers a slow
/// client's body, so nothing here waits on one.
pub fn serve(mut receiver: Receiver, server: &tiny_http::Server) {
    for request in server.incoming_requests() {
        answer(&mut receiver, request);
    }
}

/// The client's address, as the proxy states it, or the peer's when no header is configured or it
/// is missing. Used for the rate limit and nothing else.
fn client_of(receiver: &Receiver, request: &tiny_http::Request) -> String {
    let stated = receiver.config.client_ip_header.as_deref().and_then(|name| header(request, name));
    stated.map(str::to_string).or_else(|| request.remote_addr().map(|a| a.ip().to_string())).unwrap_or_default()
}

fn header<'a>(request: &'a tiny_http::Request, name: &str) -> Option<&'a str> {
    request.headers().iter().find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name)).map(|h| h.value.as_str())
}

/// Answer one request.
pub fn answer(receiver: &mut Receiver, mut request: tiny_http::Request) {
    let now = Instant::now();
    let route = (request.method().clone(), request.url().split('?').next().unwrap_or("").to_string());
    let reply = match (&route.0, route.1.as_str()) {
        (tiny_http::Method::Get, CHALLENGE_PATH) | (tiny_http::Method::Post, REPORT_PATH) => {
            let client = client_of(receiver, &request);
            if !receiver.admit(&client, now) {
                Answer::refuse(429, "rate-limited", "too many requests from this address; try again later")
            } else if route.0 == tiny_http::Method::Get {
                receiver.challenge(now)
            } else {
                report_request(receiver, &mut request, now)
            }
        }
        _ => Answer::refuse(404, "no-such-route", "nothing here"),
    };
    let content_type = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).ok();
    let mut response = tiny_http::Response::from_data(reply.body).with_status_code(reply.status);
    if let Some(h) = content_type {
        response = response.with_header(h);
    }
    let _ = request.respond(response);
}

fn report_request(receiver: &mut Receiver, request: &mut tiny_http::Request, now: Instant) -> Answer {
    let max = receiver.config.max_body_bytes;
    // By the declared length, before a byte is read: a body that does not declare one is refused.
    let Some(length) = request.body_length() else {
        return Answer::refuse(411, "no-length", "a report states its length");
    };
    if length as u64 > max {
        return Answer::refuse(413, "too-large", format!("{length} bytes, more than the {max} taken"));
    }
    let mut body = Vec::with_capacity(length);
    if request.as_reader().take(max + 1).read_to_end(&mut body).is_err() || body.len() != length {
        return Answer::refuse(400, "short-body", "the body is not the length it states");
    }
    let nonce = header(request, n0xis_feedback::NONCE_HEADER).map(str::to_string);
    let proof = header(request, n0xis_feedback::PROOF_HEADER).map(str::to_string);
    receiver.report(nonce.as_deref(), proof.as_deref(), &body, now, SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_date_is_the_calendar_s() {
        // Known instants, from `date -u -d @N`.
        assert_eq!(utc(UNIX_EPOCH), ("1970-01-01".to_string(), "00:00:00".to_string()));
        assert_eq!(utc(UNIX_EPOCH + Duration::from_secs(951_782_400)), ("2000-02-29".to_string(), "00:00:00".to_string()));
        assert_eq!(utc(UNIX_EPOCH + Duration::from_secs(1_794_614_400 + 3661)), ("2026-11-14".to_string(), "01:01:01".to_string()));
    }

    #[test]
    fn an_id_and_a_month_are_what_store_writes() {
        assert!(is_month("2026-11") && !is_month("2026-1x") && !is_month("../x"));
        assert!(is_id("20261114T010101Z-0123456789abcdef"));
        assert!(!is_id("20261114T010101Z-0123456789abcdeF") && !is_id("..") && !is_id("20261114T010101Z-0123456789abcde/"));
    }
}
