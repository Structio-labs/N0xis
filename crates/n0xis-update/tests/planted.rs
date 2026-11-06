// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! docs/design/UPDATE.md §5, against a planted server: each failure ends in its stated refusal with
//! the installed file byte for byte unchanged, and nothing left beside it. Each is calibrated by
//! removing what it guards (`scripts/calibrate_update.py`).

mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use n0xis_update::{Limits, Refusal, Transport, Trust, Updater, Why, notice, rollback};
use ring::digest::{SHA256, digest};
use ring::signature::Ed25519KeyPair;
use semver::Version;
use serde_json::{Value, json};
use support::{Reply, Server};

const OLD: &[u8] = b"the installed binary, version 1.0.0";
/// The new file is really run, so it has to be a program. The old one never is.
static NEW: LazyLock<Vec<u8>> = LazyLock::new(|| program("2.0.0"));
const COMPONENT: &str = "n0xis";
const PLATFORM: &str = "test-platform";
/// What the candidate is called while it is prepared: on Windows its name ends in `.exe`.
const CANDIDATE: &str = if cfg!(windows) { "n0xis.update-new.exe" } else { "n0xis.update-new" };

/// A program answering `--version` as `says` tells it to (`tests/support/program.rs`).
fn program(says: &str) -> Vec<u8> {
    static BASE: LazyLock<Vec<u8>> = LazyLock::new(|| fs::read(env!("CARGO_BIN_EXE_n0xis-update-test-program")).expect("the test program"));
    let mut bytes = BASE.clone();
    bytes.push(b'\n');
    bytes.extend(says.as_bytes());
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha(bytes: &[u8]) -> String {
    hex(digest(&SHA256, bytes).as_ref())
}

/// A key made for the test, from a seed, so each run has the same one.
fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("seed")
}

fn public(key: &Ed25519KeyPair) -> [u8; 32] {
    use ring::signature::KeyPair;
    key.public_key().as_ref().try_into().expect("32 bytes")
}

fn sign(key: &Ed25519KeyPair, bytes: &[u8]) -> Vec<u8> {
    hex(key.sign(bytes).as_ref()).into_bytes()
}

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Bench {
    server: Server,
    dir: PathBuf,
    config: PathBuf,
    exe: PathBuf,
    key: Ed25519KeyPair,
}

impl Bench {
    fn new(name: &str) -> Bench {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("planted-{}-{name}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let _ = fs::remove_dir_all(&root);
        let dir = root.join("bin");
        let config = root.join("config");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(&config).unwrap();
        let exe = dir.join("n0xis");
        fs::write(&exe, OLD).unwrap();
        Bench { server: Server::start(), dir, config, exe, key: key(7) }
    }

    fn limits() -> Limits {
        Limits { connect: Duration::from_secs(5), response: Duration::from_secs(5), small_body: Duration::from_secs(5), file_body: Duration::from_secs(5), redirects: 3, run: Duration::from_secs(20) }
    }

    fn updater(&self) -> Updater {
        self.updater_with(vec![self.server.url("/manifest.json")], Trust::of_keys(&[public(&self.key)]), Self::limits())
    }

    fn updater_with(&self, addresses: Vec<String>, trust: Trust, limits: Limits) -> Updater {
        Updater {
            component: COMPONENT.to_string(),
            platform: PLATFORM.to_string(),
            current: Version::new(1, 0, 0),
            exe: self.exe.clone(),
            addresses,
            trust,
            transport: Transport::trusting(std::slice::from_ref(&self.server.ca_der), limits, "1.0.0"),
            config_dir: Some(self.config.clone()),
        }
    }

    /// The manifest of a release with one file served at `/file`.
    fn manifest(&self, version: &str) -> Value {
        json!({
            "version": version,
            "components": { COMPONENT: { PLATFORM: { "url": self.server.url("/file"), "size": NEW.len(), "sha256": sha(&NEW) } } },
        })
    }

    /// Plant `manifest`, signed, and the file.
    fn publish(&self, manifest: &Value) {
        let bytes = serde_json::to_vec(manifest).unwrap();
        self.server.route("/manifest.json.sig", Reply::Body(sign(&self.key, &bytes)));
        self.server.route("/manifest.json", Reply::Body(bytes));
        self.server.route("/file", Reply::Body(NEW.to_vec()));
    }

    /// What is beside the binary, apart from the lock, which stays by design and holds nothing.
    fn files(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).filter(|n| !n.ends_with(".update-lock")).collect();
        names.sort();
        names
    }

    /// The refusal stated, and the installed file exactly as it was, with nothing beside it.
    #[track_caller]
    fn refused(&self, result: Result<impl std::fmt::Debug, Refusal>, why: Why) -> Refusal {
        let refusal = result.expect_err("should have been refused");
        assert_eq!(refusal.why, why, "refused for another reason: {}", refusal.message);
        assert_eq!(fs::read(&self.exe).unwrap(), OLD, "the installed file changed");
        assert_eq!(self.files(), ["n0xis"], "something was left beside the installed file");
        refusal
    }
}

#[test]
fn a_newer_release_installs_keeps_the_old_file_and_rolls_back() {
    let b = Bench::new("install");
    b.publish(&b.manifest("2.0.0"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&b.exe, fs::Permissions::from_mode(0o750)).unwrap();
    }
    let report = b.updater().update().expect("update");
    assert_eq!((report.from.as_str(), report.to.as_str()), ("1.0.0", "2.0.0"));
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    let previous = b.dir.join("n0xis.previous");
    assert_eq!(fs::read(&previous).unwrap(), OLD);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&b.exe).unwrap().permissions().mode() & 0o777, 0o750, "a replaced binary must still run");
    }
    assert_eq!(b.files(), ["n0xis", "n0xis.previous", "n0xis.previous.json"], "a temporary file was left");

    let back = rollback(&b.exe, None).expect("rollback");
    assert_eq!((back.from.as_deref(), back.to.as_deref()), (Some("2.0.0"), Some("1.0.0")));
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
    assert_eq!(b.files(), ["n0xis", "n0xis.update-hold"], "one shot: nothing is kept to go forward to");

    let again = rollback(&b.exe, None).expect_err("a second rollback");
    assert_eq!(again.why, Why::NoPrevious);
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
}

#[test]
fn rollback_with_nothing_kept_is_a_refusal() {
    let b = Bench::new("noprevious");
    b.refused(rollback(&b.exe, None), Why::NoPrevious);
}

#[test]
fn a_tampered_file_is_refused() {
    let b = Bench::new("tampered");
    b.publish(&b.manifest("2.0.0"));
    let mut tampered = NEW.to_vec();
    tampered[3] ^= 1;
    b.server.route("/file", Reply::Body(tampered));
    b.refused(b.updater().update(), Why::DigestMismatch);
}

#[test]
fn a_wrong_digest_is_refused() {
    let b = Bench::new("wrongdigest");
    let mut m = b.manifest("2.0.0");
    m["components"][COMPONENT][PLATFORM]["sha256"] = json!(sha(b"something else"));
    b.publish(&m);
    b.refused(b.updater().update(), Why::DigestMismatch);
}

#[test]
fn no_digest_is_its_own_refusal_not_a_passed_check() {
    let b = Bench::new("nodigest");
    let mut m = b.manifest("2.0.0");
    m["components"][COMPONENT][PLATFORM].as_object_mut().unwrap().remove("sha256");
    b.publish(&m);
    b.refused(b.updater().update(), Why::NoDigest);
    assert_eq!(b.server.asked("/file"), 0, "a file that cannot be checked is not fetched");

    m["components"][COMPONENT][PLATFORM]["sha256"] = json!("not a digest");
    b.publish(&m);
    b.refused(b.updater().update(), Why::NoDigest);
}

#[test]
fn a_bad_signature_is_refused() {
    let b = Bench::new("badsig");
    let manifest = b.manifest("2.0.0");
    b.publish(&manifest);
    let bytes = serde_json::to_vec(&manifest).unwrap();
    // Signed by a key nobody trusts.
    b.server.route("/manifest.json.sig", Reply::Body(sign(&key(9), &bytes)));
    b.refused(b.updater().update(), Why::BadSignature);
    assert_eq!(b.server.asked("/file"), 0, "nothing an unverified manifest names is fetched");
}

#[test]
fn a_manifest_changed_after_signing_is_refused() {
    let b = Bench::new("changed");
    let manifest = b.manifest("2.0.0");
    b.publish(&manifest);
    let mut changed = manifest.clone();
    changed["version"] = json!("3.0.0");
    b.server.route("/manifest.json", Reply::Body(serde_json::to_vec(&changed).unwrap()));
    b.refused(b.updater().update(), Why::BadSignature);
}

#[test]
fn no_signature_is_its_own_refusal() {
    let b = Bench::new("nosig");
    b.publish(&b.manifest("2.0.0"));
    b.server.route("/manifest.json.sig", Reply::Status(404));
    b.refused(b.updater().update(), Why::NoSignature);
    b.server.route("/manifest.json.sig", Reply::Body(b"nothing that reads as a signature\n".to_vec()));
    b.refused(b.updater().update(), Why::NoSignature);
}

#[test]
fn a_truncated_download_is_refused() {
    let b = Bench::new("truncated");
    b.publish(&b.manifest("2.0.0"));
    b.server.route("/file", Reply::CutOff { declared: NEW.len(), body: NEW[..10].to_vec() });
    b.refused(b.updater().update(), Why::SizeMismatch);
    b.server.route("/file", Reply::EndsEarly(NEW[..10].to_vec()));
    b.refused(b.updater().update(), Why::SizeMismatch);
}

#[test]
fn a_claimed_size_past_what_is_sent_is_refused() {
    let b = Bench::new("claimed");
    let mut m = b.manifest("2.0.0");
    m["components"][COMPONENT][PLATFORM]["size"] = json!(NEW.len() + 1000);
    b.publish(&m);
    b.refused(b.updater().update(), Why::SizeMismatch);
}

#[test]
fn a_file_longer_than_the_manifest_says_is_refused() {
    let b = Bench::new("longer");
    let mut m = b.manifest("2.0.0");
    m["components"][COMPONENT][PLATFORM]["size"] = json!(NEW.len() - 1);
    b.publish(&m);
    b.refused(b.updater().update(), Why::SizeMismatch);
}

/// The size limit is enforced while reading: a server that never stops is cut off at the limit
/// straight away, and does not get to run the download out to its time bound or fill a disk.
#[test]
fn a_file_that_never_ends_stops_being_read_at_the_limit() {
    let b = Bench::new("endlessfile");
    b.publish(&b.manifest("2.0.0"));
    b.server.route("/file", Reply::Endless);
    b.refused(b.updater().update(), Why::SizeMismatch);
}

#[test]
fn an_older_version_is_refused_and_the_same_one_changes_nothing() {
    let b = Bench::new("older");
    b.publish(&b.manifest("0.9.0"));
    b.refused(b.updater().update(), Why::OlderVersion);
    assert_eq!(b.server.asked("/file"), 0);
    let report = b.updater().check().expect("check");
    assert!(!report.available);

    b.publish(&b.manifest("1.0.0"));
    let same = b.updater().update().expect("same version");
    assert!(same.replaced.is_empty());
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
    assert_eq!(b.server.asked("/file"), 0);
}

#[test]
fn unknown_fields_and_unknown_components_are_ignored() {
    let b = Bench::new("unknown");
    let mut m = b.manifest("2.0.0");
    m["a_field_of_a_later_release"] = json!({ "nested": [1, 2, 3] });
    m["next_key"] = json!(12345);
    m["components"][COMPONENT][PLATFORM]["delta"] = json!({ "from": "1.9.0", "url": b.server.url("/delta"), "size": 1, "sha256": "ab" });
    m["components"]["a-signature-pack"] = json!({ PLATFORM: { "version": 3, "layout": ["a", "b"] } });
    m["components"]["a-gui"] = json!("a shape no one has thought of yet");
    m["components"]["some-tool"] = json!({ PLATFORM: { "file": "some-tool", "url": b.server.url("/tool"), "size": 1 } });
    b.publish(&m);
    b.updater().update().expect("a manifest that grew is still a manifest");
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    assert_eq!(b.server.asked("/delta") + b.server.asked("/tool"), 0, "nothing this client does not know is fetched");
    assert!(!b.dir.join("some-tool").exists(), "a component not installed stays not installed");
}

#[test]
fn a_dead_first_address_falls_through_quietly() {
    let b = Bench::new("dead");
    b.publish(&b.manifest("2.0.0"));
    let dead = dead_address();
    let addresses = vec![dead.clone(), b.server.url("/manifest.json")];
    let updater = b.updater_with(addresses, Trust::of_keys(&[public(&b.key)]), Bench::limits());
    let report = updater.check().expect("the second address answers");
    assert!(report.available);
    assert_eq!(report.address, b.server.url("/manifest.json"));
    assert_eq!(report.tried.len(), 1);
    assert_eq!(report.tried[0].address, dead);
    assert_eq!(report.tried[0].code, "manifest-unavailable");
    updater.update().expect("and it installs");
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
}

/// A port nothing listens on, known to be free because it was just held.
fn dead_address() -> String {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    format!("https://127.0.0.1:{port}/manifest.json")
}

#[test]
fn a_first_address_answering_badly_does_not_strand_the_client() {
    let b = Bench::new("hijacked");
    b.publish(&b.manifest("2.0.0"));
    // A lapsed domain now serving something else entirely.
    b.server.route("/squatted", Reply::Body(b"<html>this domain is for sale</html>".to_vec()));
    b.server.route("/squatted.sig", Reply::Status(404));
    let addresses = vec![b.server.url("/squatted"), b.server.url("/manifest.json")];
    let updater = b.updater_with(addresses, Trust::of_keys(&[public(&b.key)]), Bench::limits());
    updater.update().expect("the second address is what it is for");
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
}

#[test]
fn the_most_serious_failure_is_the_one_reported() {
    let b = Bench::new("worst");
    let manifest = b.manifest("2.0.0");
    b.publish(&manifest);
    let bytes = serde_json::to_vec(&manifest).unwrap();
    b.server.route("/manifest.json.sig", Reply::Body(sign(&key(9), &bytes)));
    let trust = || Trust::of_keys(&[public(&b.key)]);
    let dead_first = b.updater_with(vec![dead_address(), b.server.url("/manifest.json")], trust(), Bench::limits());
    b.refused(dead_first.update(), Why::BadSignature);
    let dead_last = b.updater_with(vec![b.server.url("/manifest.json"), dead_address()], trust(), Bench::limits());
    b.refused(dead_last.update(), Why::BadSignature);
    let all_dead = b.updater_with(vec![dead_address(), dead_address()], trust(), Bench::limits());
    b.refused(all_dead.update(), Why::ManifestUnavailable);
}

#[test]
fn the_placeholder_refuses_every_manifest_whatever_the_key_file_says() {
    let b = Bench::new("placeholder");
    b.publish(&b.manifest("2.0.0"));
    // A key file naming the very key that signed: a chain has to start in the binary.
    fs::write(b.config.join("update-keys.json"), json!({ "keys": [hex(&public(&b.key))] }).to_string()).unwrap();
    let placeholder = "PLACEHOLDER: the release public key goes here, and until then every manifest is refused";
    for constant in [placeholder, "", "abcd", &"z".repeat(64)] {
        let trust = Trust::rooted_at(constant, Some(&b.config));
        assert!(trust.is_empty(), "{constant:?} should hold no key");
        let updater = b.updater_with(vec![b.server.url("/manifest.json")], trust, Bench::limits());
        b.refused(updater.update(), Why::NoReleaseKey);
    }
}

/// The constant itself: a placeholder that refuses, or a key that parses. Holds on both sides of the
/// lead setting it, and a typo in the real key fails here rather than in the field.
#[test]
fn the_built_in_key_is_a_key_or_the_placeholder() {
    let looks_like_a_key = n0xis_update::RELEASE_PUBLIC_KEY.len() == 64 && n0xis_update::RELEASE_PUBLIC_KEY.bytes().all(|c| c.is_ascii_hexdigit());
    let trust = Trust::rooted_at(n0xis_update::RELEASE_PUBLIC_KEY, None);
    assert_eq!(trust.is_empty(), !looks_like_a_key);
    if !looks_like_a_key {
        assert!(n0xis_update::RELEASE_PUBLIC_KEY.starts_with("PLACEHOLDER"), "neither a key nor the placeholder");
    }
}

#[test]
fn a_signed_manifest_can_name_the_next_key() {
    let b = Bench::new("nextkey");
    let root = hex(&public(&b.key));
    let next = key(8);
    let signed_by_next = |b: &Bench, m: &Value| {
        let bytes = serde_json::to_vec(m).unwrap();
        b.server.route("/manifest.json.sig", Reply::Body(sign(&next, &bytes)));
        b.server.route("/manifest.json", Reply::Body(bytes));
        b.server.route("/file", Reply::Body(NEW.to_vec()));
    };
    let trust = |b: &Bench| Trust::rooted_at(&root, Some(&b.config));

    // Before anything names it, the next key is a stranger.
    signed_by_next(&b, &b.manifest("2.0.0"));
    let updater = b.updater_with(vec![b.server.url("/manifest.json")], trust(&b), Bench::limits());
    b.refused(updater.update(), Why::BadSignature);

    // A manifest signed by a stranger does not get to name a key either.
    let mut forged = b.manifest("1.0.0");
    forged["next_key"] = json!(hex(&public(&next)));
    signed_by_next(&b, &forged);
    let updater = b.updater_with(vec![b.server.url("/manifest.json")], trust(&b), Bench::limits());
    b.refused(updater.check(), Why::BadSignature);
    assert!(!b.config.join("update-keys.json").exists(), "an unverified manifest named a key");

    // The old key names it, and from then on the new key signs.
    let mut naming = b.manifest("1.0.0");
    naming["next_key"] = json!(hex(&public(&next)));
    b.publish(&naming);
    let updater = b.updater_with(vec![b.server.url("/manifest.json")], trust(&b), Bench::limits());
    updater.check().expect("the naming manifest verifies");

    signed_by_next(&b, &b.manifest("2.0.0"));
    let updater = b.updater_with(vec![b.server.url("/manifest.json")], trust(&b), Bench::limits());
    updater.update().expect("the next key signs");
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
}

#[test]
fn either_of_two_signatures_is_enough() {
    let b = Bench::new("cosigned");
    let manifest = b.manifest("2.0.0");
    b.publish(&manifest);
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let mut file = sign(&key(9), &bytes);
    file.push(b'\n');
    file.extend(sign(&b.key, &bytes));
    file.extend(b"\na later form of signature this client cannot read\n");
    b.server.route("/manifest.json.sig", Reply::Body(file));
    b.updater().update().expect("one line verifies");
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
}

#[test]
fn a_manifest_that_verifies_and_does_not_read_is_refused() {
    let b = Bench::new("badmanifest");
    for bytes in [b"not json".to_vec(), json!({ "components": {} }).to_string().into_bytes(), json!({ "version": "soon", "components": {} }).to_string().into_bytes(), json!({ "version": "2.0.0" }).to_string().into_bytes()] {
        b.server.route("/manifest.json.sig", Reply::Body(sign(&b.key, &bytes)));
        b.server.route("/manifest.json", Reply::Body(bytes));
        b.refused(b.updater().update(), Why::BadManifest);
    }
}

#[test]
fn no_entry_for_this_platform_is_a_refusal() {
    let b = Bench::new("noentry");
    let mut m = b.manifest("2.0.0");
    m["components"][COMPONENT] = json!({ "another-platform": {} });
    b.publish(&m);
    b.refused(b.updater().update(), Why::NoEntry);
    let report = b.updater().check().expect("check");
    assert!(!report.available, "offering what cannot be installed is a false line");
    assert_eq!(report.blocked, Some("no-entry"));
}

#[test]
fn plain_http_is_refused_without_a_connection() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let b = Bench::new("plainhttp");
    let updater = b.updater_with(vec![format!("http://127.0.0.1:{port}/manifest.json")], Trust::of_keys(&[public(&b.key)]), Bench::limits());
    b.refused(updater.update(), Why::ManifestUnavailable);
    assert!(listener.accept().is_err(), "a connection was opened to a plain http address");
}

#[test]
fn a_file_at_a_plain_http_address_is_refused() {
    // A listener, because a closed port would refuse the connection with or without the rule.
    let plain = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    plain.set_nonblocking(true).unwrap();
    let port = plain.local_addr().unwrap().port();
    let b = Bench::new("httpfile");
    let mut m = b.manifest("2.0.0");
    m["components"][COMPONENT][PLATFORM]["url"] = json!(format!("http://127.0.0.1:{port}/file"));
    b.publish(&m);
    b.refused(b.updater().update(), Why::DownloadFailed);
    assert!(plain.accept().is_err(), "a connection was opened to a plain http address");
}

#[test]
fn a_redirect_to_plain_http_is_refused() {
    let plain = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    plain.set_nonblocking(true).unwrap();
    let port = plain.local_addr().unwrap().port();
    let b = Bench::new("redirecthttp");
    b.publish(&b.manifest("2.0.0"));
    b.server.route("/manifest.json", Reply::Redirect(format!("http://127.0.0.1:{port}/manifest.json")));
    b.refused(b.updater().update(), Why::ManifestUnavailable);
    assert!(plain.accept().is_err(), "the redirect to plain http was followed");

    b.publish(&b.manifest("2.0.0"));
    b.server.route("/file", Reply::Redirect(format!("http://127.0.0.1:{port}/file")));
    b.refused(b.updater().update(), Why::DownloadFailed);
    assert!(plain.accept().is_err(), "the redirect to plain http was followed");
}

#[test]
fn a_redirect_over_https_is_followed_and_a_loop_is_bounded() {
    let b = Bench::new("redirect");
    b.publish(&b.manifest("2.0.0"));
    // The shape of `latest/download`: a redirect to the release, then to the asset's store.
    let bytes = serde_json::to_vec(&b.manifest("2.0.0")).unwrap();
    b.server.route("/latest/manifest.json", Reply::Redirect(b.server.url("/v2/manifest.json")));
    b.server.route("/v2/manifest.json", Reply::Redirect(b.server.url("/store/manifest.json")));
    b.server.route("/store/manifest.json", Reply::Body(bytes.clone()));
    b.server.route("/latest/manifest.json.sig", Reply::Redirect(b.server.url("/store/manifest.json.sig")));
    b.server.route("/store/manifest.json.sig", Reply::Body(sign(&b.key, &bytes)));
    let updater = b.updater_with(vec![b.server.url("/latest/manifest.json")], Trust::of_keys(&[public(&b.key)]), Bench::limits());
    assert!(updater.check().expect("two redirects are routine").available);

    b.server.route("/loop", Reply::Redirect(b.server.url("/loop")));
    let updater = b.updater_with(vec![b.server.url("/loop")], Trust::of_keys(&[public(&b.key)]), Bench::limits());
    b.refused(updater.update(), Why::ManifestUnavailable);
    let hops = b.server.asked("/loop");
    assert!(hops <= 4, "{hops} requests for a limit of 3 redirects");
}

#[test]
fn a_silent_server_ends_in_a_refusal_within_the_bound() {
    let b = Bench::new("silent");
    b.publish(&b.manifest("2.0.0"));
    b.server.route("/manifest.json", Reply::Silent);
    let quick = Limits { response: Duration::from_millis(300), ..Bench::limits() };
    let updater = b.updater_with(vec![b.server.url("/manifest.json")], Trust::of_keys(&[public(&b.key)]), quick);
    let start = Instant::now();
    b.refused(updater.update(), Why::ManifestUnavailable);
    assert!(start.elapsed() < Duration::from_secs(4), "took {:?} against a bound of 300 ms", start.elapsed());
}

#[test]
fn a_body_that_stalls_ends_in_a_refusal_within_the_bound() {
    let b = Bench::new("stall");
    b.publish(&b.manifest("2.0.0"));
    b.server.route("/file", Reply::StallsInBody);
    let quick = Limits { file_body: Duration::from_millis(300), ..Bench::limits() };
    let updater = b.updater_with(vec![b.server.url("/manifest.json")], Trust::of_keys(&[public(&b.key)]), quick);
    let start = Instant::now();
    b.refused(updater.update(), Why::DownloadFailed);
    assert!(start.elapsed() < Duration::from_secs(4), "took {:?} against a bound of 300 ms", start.elapsed());
}

#[test]
fn an_endless_manifest_is_not_read_to_its_end() {
    let b = Bench::new("endless");
    b.publish(&b.manifest("2.0.0"));
    b.server.route("/manifest.json", Reply::Body(vec![b' '; 5 * 1024 * 1024]));
    b.refused(b.updater().update(), Why::ManifestUnavailable);
    assert_eq!(b.server.asked("/manifest.json.sig"), 0);
}

#[cfg(unix)]
#[test]
fn a_directory_that_cannot_be_written_is_a_refusal_naming_the_file() {
    use std::os::unix::fs::PermissionsExt;
    let b = Bench::new("readonly");
    b.publish(&b.manifest("2.0.0"));
    fs::set_permissions(&b.dir, fs::Permissions::from_mode(0o555)).unwrap();
    // As root the permission means nothing, and this would measure nothing.
    let probe = b.dir.join("probe");
    if fs::write(&probe, b"").is_ok() {
        let _ = fs::remove_file(&probe);
        fs::set_permissions(&b.dir, fs::Permissions::from_mode(0o755)).unwrap();
        eprintln!("not verified here: this user can write to a read-only directory");
        return;
    }
    let refused = b.updater().update();
    fs::set_permissions(&b.dir, fs::Permissions::from_mode(0o755)).unwrap();
    let refusal = b.refused(refused, Why::NotWritable);
    let hint = refusal.hint.expect("a hint");
    assert!(hint.contains(&b.server.url("/file")), "the refusal must name the file to fetch: {hint}");
    assert!(!format!("{hint} {}", refusal.message).contains("sudo"));
    assert_eq!(b.server.asked("/file"), 0, "nothing is fetched for a directory that cannot take it");
}

/// The manifest of a release with the MCP server beside the CLI.
fn with_the_mcp(b: &Bench, version: &str, mcp: &[u8]) -> Value {
    let mut m = b.manifest(version);
    m["components"]["n0xis-mcp"] = json!({ PLATFORM: { "url": b.server.url("/mcp"), "size": mcp.len(), "sha256": sha(mcp), "file": "n0xis-mcp" } });
    b.server.route("/mcp", Reply::Body(mcp.to_vec()));
    m
}

#[test]
fn a_component_beside_the_binary_goes_with_it_and_goes_back_by_its_name() {
    let b = Bench::new("sibling");
    let mcp = b.dir.join("n0xis-mcp");
    fs::write(&mcp, b"old mcp").unwrap();
    b.publish(&with_the_mcp(&b, "2.0.0", b"new mcp"));
    // Never executed, and these bytes would not start: only the running component is.
    b.updater().update().expect("update");
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    assert_eq!(fs::read(&mcp).unwrap(), b"new mcp");
    let back = rollback(&b.exe, Some("n0xis-mcp")).expect("rollback");
    assert_eq!(back.file, mcp.display().to_string());
    assert_eq!(fs::read(&mcp).unwrap(), b"old mcp");
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW, "only the file named");
    assert_eq!(fs::read(b.dir.join("n0xis-mcp.update-hold")).unwrap(), b"2.0.0", "the same function, and that file's own hold");
    assert_eq!(rollback(&b.exe, Some("n0xis-mcp")).expect_err("one shot").why, Why::NoPrevious);
    rollback(&b.exe, None).expect("rollback");
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
}

/// A sibling is never executed, so its version is not known: what the running binary is says nothing of
/// it. Its record has no `from`, and going back names the file and the digest. The running file's own
/// record goes on stating both, and a sibling's still reads, with a hold of the manifest's version.
#[test]
fn a_siblings_version_is_not_known() {
    let b = Bench::new("sibfrom");
    let mcp = b.dir.join("n0xis-mcp");
    fs::write(&mcp, b"mcp of no version anyone ran").unwrap();
    b.publish(&with_the_mcp(&b, "2.0.0", b"new mcp"));
    b.updater().update().expect("update");

    let record = |name: &str| serde_json::from_slice::<Value>(&fs::read(b.dir.join(name)).unwrap()).unwrap();
    let sibling = record("n0xis-mcp.previous.json");
    assert_eq!(sibling["from"], Value::Null, "{sibling}");
    assert_eq!(sibling["to"], "2.0.0");
    assert_eq!(sibling["previous_sha256"], sha(b"mcp of no version anyone ran"));
    assert_eq!(record("n0xis.previous.json")["from"], "1.0.0");

    let back = rollback(&b.exe, Some("n0xis-mcp")).expect("rollback");
    assert_eq!(back.file, mcp.display().to_string());
    assert_eq!((back.from.as_deref(), back.to.as_deref()), (None, None));
    assert_eq!(back.sha256, sha(b"mcp of no version anyone ran"));
    assert_eq!(fs::read(&mcp).unwrap(), b"mcp of no version anyone ran");
    assert_eq!(fs::read(b.dir.join("n0xis-mcp.update-hold")).unwrap(), b"2.0.0");

    let back = rollback(&b.exe, None).expect("rollback");
    assert_eq!((back.from.as_deref(), back.to.as_deref()), (Some("2.0.0"), Some("1.0.0")));
    assert_eq!(back.sha256, sha(OLD));
}

/// The running file goes back and nothing else moves: a sibling at another version harms nothing, and
/// another copy in the directory, with a record of its own, is not this one's to touch.
#[test]
fn rollback_leaves_a_sibling_and_another_copy_alone() {
    let b = Bench::new("onefile");
    let mcp = b.dir.join("n0xis-mcp");
    fs::write(&mcp, b"old mcp").unwrap();
    let other = b.dir.join("n0xis-nightly");
    fs::write(&other, OLD).unwrap();
    b.publish(&with_the_mcp(&b, "2.0.0", b"new mcp"));
    b.updater().update().expect("update");
    let mut nightly = b.updater();
    nightly.exe = other.clone();
    nightly.update().expect("update the other copy");
    assert_eq!(fs::read(&other).unwrap(), *NEW);

    let back = rollback(&b.exe, None).expect("rollback");
    assert_eq!(back.file, b.exe.display().to_string(), "the envelope states the one file");
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
    assert_eq!(fs::read(&mcp).unwrap(), b"new mcp", "the sibling moved");
    assert_eq!(fs::read(&other).unwrap(), *NEW, "the other copy moved");
    assert!(b.dir.join("n0xis-mcp.previous.json").exists() && b.dir.join("n0xis-nightly.previous.json").exists());

    // A stranger's record beside it is no one's business either, and turns no success into a refusal.
    let b = installed("stranger");
    fs::write(b.dir.join("stranger"), b"keep me").unwrap();
    fs::write(b.dir.join("stranger.previous.json"), serde_json::to_vec(&json!({ "from": "1.0.0", "to": "2.0.0", "previous_sha256": sha(b"x"), "installed_sha256": sha(b"y") })).unwrap()).unwrap();
    rollback(&b.exe, None).expect("rollback");
    assert_eq!(fs::read(b.dir.join("stranger")).unwrap(), b"keep me");
}

#[test]
fn rollback_takes_a_bare_name_and_that_files_own_lock() {
    let b = Bench::new("byname");
    let mcp = b.dir.join("n0xis-mcp");
    fs::write(&mcp, b"old mcp").unwrap();
    b.publish(&with_the_mcp(&b, "2.0.0", b"new mcp"));
    b.updater().update().expect("update");
    for name in ["../n0xis", "/etc/passwd", "..", "", "a\\b"] {
        assert_eq!(rollback(&b.exe, Some(name)).expect_err(name).why, Why::NotABareName, "{name}");
    }
    assert_eq!(rollback(&b.exe, Some("no-such-file")).expect_err("not there").why, Why::NoPrevious);

    let lock = fs::File::create(b.dir.join("n0xis-mcp.update-lock")).unwrap();
    lock.try_lock().unwrap();
    assert_eq!(rollback(&b.exe, Some("n0xis-mcp")).expect_err("its own lock is held").why, Why::UpdateInProgress);
    assert_eq!(fs::read(&mcp).unwrap(), b"new mcp");
    drop(lock);

    // And the running file's lock is not that one.
    let lock = fs::File::create(b.dir.join("n0xis.update-lock")).unwrap();
    lock.try_lock().unwrap();
    rollback(&b.exe, Some("n0xis-mcp")).expect("another file's lock stops nothing here");
    assert_eq!(fs::read(&mcp).unwrap(), b"old mcp");
}

/// An install takes each file's own lock too, or a rollback of a sibling could land inside its commit.
#[test]
fn an_install_skips_a_sibling_whose_own_lock_is_held() {
    let b = Bench::new("siblock");
    let mcp = b.dir.join("n0xis-mcp");
    fs::write(&mcp, b"old mcp").unwrap();
    b.publish(&with_the_mcp(&b, "2.0.0", b"new mcp"));
    let lock = fs::File::create(b.dir.join("n0xis-mcp.update-lock")).unwrap();
    lock.try_lock().unwrap();
    let report = b.updater().update().expect("the running file goes on");
    assert_eq!(skipped(&report), [("n0xis-mcp", "update-in-progress")]);
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    assert_eq!(fs::read(&mcp).unwrap(), b"old mcp");
}

/// The finding: a file put there by hand was overwritten by a rollback, and nothing kept it.
#[test]
fn a_hand_installed_target_is_refused_and_kept() {
    let b = installed("hand");
    let hand = program("9.9.9");
    fs::write(&b.exe, &hand).unwrap();
    let refusal = rollback(&b.exe, None).expect_err("not what was installed");
    assert_eq!(refusal.why, Why::NotWhatWasInstalled);
    assert!(refusal.message.contains("by other means"), "{}", refusal.message);
    assert_eq!(fs::read(&b.exe).unwrap(), hand);
    assert_eq!(fs::read(b.dir.join("n0xis.previous")).unwrap(), OLD);
    assert!(b.dir.join("n0xis.previous.json").exists(), "still there for a look");
    assert!(!b.dir.join("n0xis.update-hold").exists(), "a refusal holds nothing back");
}

fn skipped(report: &n0xis_update::UpdateReport) -> Vec<(&str, &str)> {
    report.skipped.iter().map(|s| (s.component.as_str(), s.code)).collect()
}

/// A rollback lands while a check is out asking. The check's write of the shared state once wrote the
/// hold away, and the next check undid the rollback.
#[test]
fn the_hold_survives_a_check_in_flight() {
    let b = installed("inflight");
    let exe = b.exe.clone();
    let meanwhile = Arc::new(move || {
        rollback(&exe, None).expect("rollback");
    });
    b.server.route("/manifest.json", Reply::During { body: serde_json::to_vec(&b.manifest("2.0.0")).unwrap(), at: 10, meanwhile });
    notice::run_check(&b.updater(), true);
    assert_eq!(fs::read(&b.exe).unwrap(), OLD, "the check in flight undid the rollback");
    assert_eq!(state_of(&b).installed, None, "and it says nothing moved");
    b.publish(&b.manifest("2.0.0"));
    notice::run_check(&b.updater(), true);
    assert_eq!(fs::read(&b.exe).unwrap(), OLD, "nor does the next one");
}

#[cfg(unix)]
#[test]
fn the_hold_needs_no_configuration_directory() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("not verified here: running as root");
        return;
    }
    // Read-only, where a hold in the state file was silently lost.
    let b = installed("readonlyconfig");
    fs::set_permissions(&b.config, fs::Permissions::from_mode(0o555)).unwrap();
    rollback(&b.exe, None).expect("rollback");
    notice::run_check(&b.updater(), true);
    fs::set_permissions(&b.config, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(fs::read(&b.exe).unwrap(), OLD, "the hold was lost with the directory");

    // None at all, and then a run that has one.
    let b = installed("noconfig");
    fs::remove_dir_all(&b.config).unwrap();
    rollback(&b.exe, None).expect("rollback");
    fs::create_dir_all(&b.config).unwrap();
    notice::run_check(&b.updater(), true);
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
}

/// A hold that cannot be written means nothing moves, since a rollback the next check undoes is not one.
#[cfg(unix)]
#[test]
fn a_hold_that_cannot_be_written_moves_nothing() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("not verified here: running as root");
        return;
    }
    let b = installed("nohold");
    fs::set_permissions(&b.dir, fs::Permissions::from_mode(0o555)).unwrap();
    let result = rollback(&b.exe, None);
    fs::set_permissions(&b.dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(result.expect_err("no hold").why, Why::NotWritable);
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    assert_eq!(fs::read(b.dir.join("n0xis.previous")).unwrap(), OLD);
}

/// What a kill leaves at each step of a rollback, planted; the kills themselves are run against the real
/// binaries outside these tests (`docs/design/UPDATE.md` §5).
#[test]
fn a_kill_at_each_step_of_a_rollback_keeps_the_hold_and_a_re_run_finishes() {
    let hold = |b: &Bench| b.dir.join("n0xis.update-hold");
    // After the hold's temporary: swept, and nothing else has happened.
    let b = installed("killtemp");
    fs::write(b.dir.join("n0xis.update-hold-new"), b"half").unwrap();
    rollback(&b.exe, None).expect("it finishes");
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
    assert_eq!(b.files(), ["n0xis", "n0xis.update-hold"]);

    // After the hold, before the swap: the target as it was, and a re-run finishes.
    let b = installed("killhold");
    fs::write(hold(&b), b"2.0.0").unwrap();
    notice::run_check(&b.updater(), true);
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW, "the target is as it was");
    rollback(&b.exe, None).expect("it finishes");
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
    notice::run_check(&b.updater(), true);
    assert_eq!(fs::read(&b.exe).unwrap(), OLD, "and it holds");

    // After the swap, before the record goes: gone back, held, and nothing further to do.
    let b = installed("killswap");
    fs::write(hold(&b), b"2.0.0").unwrap();
    fs::rename(b.dir.join("n0xis.previous"), &b.exe).unwrap();
    assert_eq!(rollback(&b.exe, None).expect_err("it is done").why, Why::NoPrevious);
    notice::run_check(&b.updater(), true);
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
}

#[test]
fn a_hold_leaves_what_it_names_and_anything_older_and_a_newer_one_passes() {
    let b = installed("holdwhat");
    rollback(&b.exe, None).expect("rollback");
    let hold = fs::read(b.dir.join("n0xis.update-hold")).unwrap();
    assert_eq!(hold, b"2.0.0", "the version rolled back from");
    // Newer than this build, and older than what was gone back from.
    publish_program(&b, "1.5.0", &program("1.5.0"));
    notice::run_check(&b.updater(), true);
    assert_eq!(fs::read(&b.exe).unwrap(), OLD, "older than the hold");
    assert_eq!(state_of(&b).latest.as_deref(), Some("1.5.0"), "and still offered");
    let later = program("2.0.1");
    publish_program(&b, "2.0.1", &later);
    notice::run_check(&b.updater(), true);
    assert_eq!(fs::read(&b.exe).unwrap(), later, "a newer release passes");
}

/// A hold on a sibling leaves that sibling, and the running file goes on.
#[test]
fn a_hold_on_a_sibling_holds_only_that_sibling() {
    let b = Bench::new("holdsib");
    let mcp = b.dir.join("n0xis-mcp");
    fs::write(&mcp, b"old mcp").unwrap();
    fs::write(b.dir.join("n0xis-mcp.update-hold"), b"2.0.0").unwrap();
    b.publish(&with_the_mcp(&b, "2.0.0", b"new mcp"));
    notice::run_check(&b.updater(), true);
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    assert_eq!(fs::read(&mcp).unwrap(), b"old mcp");
}

#[test]
fn an_explicit_update_ends_the_hold_and_only_after_it_installs() {
    let b = installed("endhold");
    rollback(&b.exe, None).expect("rollback");
    let hold = b.dir.join("n0xis.update-hold");
    // A refused install ends nothing.
    b.server.route("/file", Reply::Body(b"damaged".to_vec()));
    b.updater().update().expect_err("damaged");
    assert!(hold.exists(), "a refusal ended the hold");
    b.server.route("/file", Reply::Body(NEW.to_vec()));
    b.updater().update().expect("explicit");
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW, "the user asked, so a hold stops nothing");
    assert!(!hold.exists());
}

/// A server that changes its answer between two fetches once had the check say one version, the install
/// do another, and the line claim the first. There is one fetch now, so there is nothing to disagree.
#[test]
fn the_check_and_auto_agree_across_a_changing_server() {
    let b = Bench::new("onefetch");
    let older = b.manifest("1.5.0");
    let (first, then) = (serde_json::to_vec(&b.manifest("2.0.0")).unwrap(), serde_json::to_vec(&older).unwrap());
    let sequence = |a: Vec<u8>, z: Vec<u8>| Reply::Sequence(Arc::new(std::sync::Mutex::new([a, z].into())));
    b.server.route("/manifest.json.sig", sequence(sign(&b.key, &first), sign(&b.key, &then)));
    b.server.route("/manifest.json", sequence(first, then));
    b.server.route("/file", Reply::Body(NEW.to_vec()));
    notice::run_check(&b.updater(), true);
    assert_eq!(b.server.asked("/manifest.json"), 1, "one fetch");
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    let state = state_of(&b);
    assert_eq!(state.latest.as_deref(), Some("2.0.0"));
    assert_eq!(state.installed.map(|i| i.to).as_deref(), Some("2.0.0"));
}

/// The line is about what moved. Nothing moved here: the file is already the new one.
#[test]
fn the_line_is_written_only_from_what_moved() {
    let b = Bench::new("moved");
    fs::write(&b.exe, &*NEW).unwrap();
    b.publish(&b.manifest("2.0.0"));
    notice::run_check(&b.updater(), true);
    assert_eq!(state_of(&b).installed, None, "it said an install happened");

    // A commit that failed for a sibling after the running file moved: that one did.
    let b = Bench::new("movedsplit");
    fs::write(b.dir.join("n0xis-mcp"), b"old mcp").unwrap();
    #[cfg(unix)]
    fs::create_dir_all(b.dir.join("n0xis-mcp.previous").join("in-the-way")).unwrap();
    #[cfg(windows)]
    let _in_the_way = {
        use std::os::windows::fs::OpenOptionsExt;
        fs::OpenOptions::new().write(true).create(true).truncate(false).share_mode(0).open(b.dir.join("n0xis-mcp.previous")).unwrap()
    };
    b.publish(&with_the_mcp(&b, "2.0.0", b"new mcp"));
    notice::run_check(&b.updater(), true);
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    let state = state_of(&b);
    assert_eq!(state.installed.map(|i| i.to).as_deref(), Some("2.0.0"));
    assert_eq!(state.refusal.as_deref(), Some("install-failed"));
}

/// A later component of a new shape, with a file of its name beside the binary. It refused once, which
/// is what a shipped client must not do: it would stop every old copy.
#[test]
fn a_later_shaped_sibling_beside_the_binary_does_not_block() {
    let b = Bench::new("later");
    fs::write(b.dir.join("later-tool"), b"a stranger's file").unwrap();
    let mut m = b.manifest("2.0.0");
    m["components"]["later"] = json!({ PLATFORM: { "file": "later-tool", "parts": ["a", "b"] } });
    b.publish(&m);
    let check = b.updater().check().expect("check");
    assert!(check.available && check.blocked.is_none());
    let report = b.updater().update().expect("it agrees with --check");
    assert_eq!(skipped(&report), [("later", "no-digest")]);
    assert!(report.skipped[0].reason.contains("later"), "{}", report.skipped[0].reason);
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    assert_eq!(fs::read(b.dir.join("later-tool")).unwrap(), b"a stranger's file");
    // The same with nothing of its name beside the binary: not a thing that was skipped at all.
    let b = Bench::new("laternone");
    let mut m = b.manifest("2.0.0");
    m["components"]["later"] = json!({ PLATFORM: { "file": "later-tool", "parts": ["a", "b"] } });
    b.publish(&m);
    assert!(b.updater().update().expect("update").skipped.is_empty());
}

#[test]
fn a_component_not_installed_is_not_added() {
    let b = Bench::new("notbeside");
    b.publish(&with_the_mcp(&b, "2.0.0", b"new mcp"));
    b.updater().update().expect("update");
    assert!(!b.dir.join("n0xis-mcp").exists());
    assert_eq!(b.server.asked("/mcp"), 0);
}

#[test]
fn a_component_that_did_not_change_is_not_fetched() {
    let b = Bench::new("unchanged");
    let mcp = b.dir.join("n0xis-mcp");
    fs::write(&mcp, b"same mcp").unwrap();
    b.publish(&with_the_mcp(&b, "2.0.0", b"same mcp"));
    let report = b.updater().update().expect("update");
    assert_eq!(report.unchanged, ["n0xis-mcp"]);
    assert_eq!(b.server.asked("/mcp"), 0);
    assert!(!b.dir.join("n0xis-mcp.previous").exists());
}

#[test]
fn a_bad_sibling_file_is_skipped_and_the_running_file_goes_on() {
    let b = Bench::new("badsecond");
    let mcp = b.dir.join("n0xis-mcp");
    fs::write(&mcp, b"old mcp").unwrap();
    b.publish(&with_the_mcp(&b, "2.0.0", b"new mcp"));
    b.server.route("/mcp", Reply::Body(b"NEW MCP".to_vec()));
    let report = b.updater().update().expect("the running file goes on");
    assert_eq!(skipped(&report), [("n0xis-mcp", "digest-mismatch")]);
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    assert_eq!(fs::read(&mcp).unwrap(), b"old mcp");
    assert_eq!(b.files(), ["n0xis", "n0xis-mcp", "n0xis.previous", "n0xis.previous.json"], "a temp of the sibling was left");
}

#[test]
fn a_file_name_cannot_leave_the_directory() {
    let b = Bench::new("traversal");
    let outside = b.dir.parent().unwrap().join("outside");
    fs::write(&outside, b"not ours").unwrap();
    let mut m = b.manifest("2.0.0");
    m["components"]["n0xis-mcp"] = json!({ PLATFORM: { "url": b.server.url("/mcp"), "size": 3, "sha256": sha(b"abc"), "file": "../outside" } });
    b.server.route("/mcp", Reply::Body(b"abc".to_vec()));
    b.publish(&m);
    let report = b.updater().update().expect("only the running component's own entry can refuse");
    assert_eq!(skipped(&report), [("n0xis-mcp", "bad-manifest")]);
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    assert_eq!(fs::read(&outside).unwrap(), b"not ours");
    assert_eq!(b.server.asked("/mcp"), 0);
    assert!(!b.dir.parent().unwrap().join("outside.previous").exists(), "something was kept outside the directory");

    // Whether or not anything is there: such a name is not looked up at all.
    let b = Bench::new("traversalnone");
    let mut m = b.manifest("2.0.0");
    m["components"]["n0xis-mcp"] = json!({ PLATFORM: { "url": b.server.url("/mcp"), "size": 3, "sha256": sha(b"abc"), "file": "../no-such-file" } });
    b.publish(&m);
    assert_eq!(skipped(&b.updater().update().expect("update")), [("n0xis-mcp", "bad-manifest")]);
}

#[test]
fn a_request_carries_nothing_but_what_a_request_needs() {
    let b = Bench::new("carries");
    b.publish(&b.manifest("2.0.0"));
    b.updater().update().expect("update");
    let requests = b.server.requests.lock().unwrap();
    assert_eq!(requests.len(), 3, "manifest, signature, file: {requests:?}");
    for request in requests.iter() {
        for line in request.trim_end().lines().skip(1) {
            let name = line.split(':').next().unwrap().to_ascii_lowercase();
            assert!(["host", "user-agent", "accept"].contains(&name.as_str()), "a header no one asked for: {line}");
        }
        assert!(request.contains("user-agent: n0xis/1.0.0"), "{request}");
    }
}

fn state_of(b: &Bench) -> notice::State {
    serde_json::from_slice(&fs::read(notice::state_file(&b.config)).unwrap()).unwrap()
}

#[test]
fn the_daily_check_writes_what_it_learned_and_touches_nothing() {
    let b = Bench::new("daily");
    b.publish(&b.manifest("2.0.0"));
    notice::run_check(&b.updater(), false);
    let state = state_of(&b);
    assert_eq!(state.latest.as_deref(), Some("2.0.0"));
    assert_eq!(state.installed, None);
    assert_eq!(fs::read(&b.exe).unwrap(), OLD, "with update.auto off a check never installs");
    assert_eq!(b.server.asked("/file"), 0);

    // A failed check leaves what is known and says why it failed.
    b.server.route("/manifest.json", Reply::Status(503));
    notice::run_check(&b.updater(), false);
    let state = state_of(&b);
    assert_eq!(state.latest.as_deref(), Some("2.0.0"));
    assert_eq!(state.refusal.as_deref(), Some("manifest-unavailable"));

    // A check that finds nothing newer takes the offer back.
    b.publish(&b.manifest("1.0.0"));
    notice::run_check(&b.updater(), false);
    assert_eq!(state_of(&b).latest, None);
}

#[test]
fn update_auto_installs_under_the_same_checks_and_rollback_holds_it() {
    let b = Bench::new("auto");
    b.publish(&b.manifest("2.0.0"));
    notice::run_check(&b.updater(), true);
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    assert_eq!(fs::read(b.dir.join("n0xis.previous")).unwrap(), OLD, "the previous binary stays for --rollback");
    let said = state_of(&b).installed.expect("what was installed");
    assert_eq!((said.to.as_str(), said.path.as_str()), ("2.0.0", b.exe.display().to_string().as_str()), "the file that moved");

    rollback(&b.exe, None).expect("rollback");
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
    notice::run_check(&b.updater(), true);
    assert_eq!(fs::read(&b.exe).unwrap(), OLD, "the next check undid the rollback");
    assert_eq!(state_of(&b).latest.as_deref(), Some("2.0.0"), "it is still offered");

    // A later version is not what was gone back from.
    let later = program("2.0.1");
    let mut m = b.manifest("2.0.1");
    m["components"][COMPONENT][PLATFORM]["size"] = json!(later.len());
    m["components"][COMPONENT][PLATFORM]["sha256"] = json!(sha(&later));
    b.publish(&m);
    b.server.route("/file", Reply::Body(later.clone()));
    notice::run_check(&b.updater(), true);
    assert_eq!(fs::read(&b.exe).unwrap(), later);
}

/// Only a newer version is installed alone, and a manifest at or below this build is no refusal either.
#[test]
fn update_auto_with_nothing_newer_does_nothing() {
    let b = Bench::new("autosame");
    for version in ["1.0.0", "0.9.0"] {
        b.publish(&b.manifest(version));
        notice::run_check(&b.updater(), true);
        let state = state_of(&b);
        assert_eq!((state.refusal, state.installed), (None, None), "{version}");
        assert_eq!(fs::read(&b.exe).unwrap(), OLD, "{version}");
    }
}

#[test]
fn update_auto_refuses_what_update_refuses() {
    let b = Bench::new("autobad");
    b.publish(&b.manifest("2.0.0"));
    let mut tampered = NEW.to_vec();
    tampered[3] ^= 1;
    b.server.route("/file", Reply::Body(tampered));
    notice::run_check(&b.updater(), true);
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
    let state = state_of(&b);
    assert_eq!(state.refusal.as_deref(), Some("digest-mismatch"));
    assert_eq!(state.installed, None);
}

/// A manifest of `version`, signed by `key`, at `path` on the server, with its file at `/file`.
fn plant_at(b: &Bench, path: &str, version: &str, next: Option<[u8; 32]>, signer: &Ed25519KeyPair) {
    let mut m = b.manifest(version);
    if let Some(next) = next {
        m["next_key"] = json!(hex(&next));
    }
    let bytes = serde_json::to_vec(&m).unwrap();
    b.server.route(&format!("{path}.sig"), Reply::Body(sign(signer, &bytes)));
    b.server.route(path, Reply::Body(bytes));
    b.server.route("/file", Reply::Body(NEW.to_vec()));
}

#[test]
fn a_stale_first_address_does_not_hide_a_newer_second() {
    let b = Bench::new("stalefirst");
    plant_at(&b, "/first", "1.0.0", None, &b.key);
    plant_at(&b, "/second", "2.0.0", None, &b.key);
    let trust = || Trust::of_keys(&[public(&b.key)]);
    let report = b.updater_with(vec![b.server.url("/first"), b.server.url("/second")], trust(), Bench::limits()).check().expect("check");
    assert_eq!((report.latest.as_str(), report.available), ("2.0.0", true), "a replayed manifest froze the copy");
    assert_eq!(report.address, b.server.url("/second"));
    assert!(report.tried.is_empty(), "an address that answered with an older version did not fail");

    // The other way round is the same answer, and a dead address beside a success is only a note.
    let dead = dead_address();
    let report = b.updater_with(vec![b.server.url("/second"), b.server.url("/first"), dead.clone()], trust(), Bench::limits()).check().expect("check");
    assert_eq!(report.latest, "2.0.0");
    assert_eq!(b.server.asked("/first"), 2, "every frozen address is asked");
    assert_eq!(report.tried.iter().map(|t| t.address.as_str()).collect::<Vec<_>>(), [dead.as_str()]);
}

#[test]
fn a_next_key_is_remembered_from_a_manifest_that_did_not_win() {
    let b = Bench::new("nextloser");
    plant_at(&b, "/first", "1.0.0", Some(public(&key(8))), &b.key);
    plant_at(&b, "/second", "2.0.0", None, &b.key);
    let root = hex(&public(&b.key));
    let addresses = vec![b.server.url("/first"), b.server.url("/second")];
    b.updater_with(addresses, Trust::rooted_at(&root, Some(&b.config)), Bench::limits()).check().expect("check");
    plant_at(&b, "/third", "3.0.0", None, &key(8));
    let report = b.updater_with(vec![b.server.url("/third")], Trust::rooted_at(&root, Some(&b.config)), Bench::limits()).check().expect("the next key signs");
    assert_eq!(report.latest, "3.0.0");
}

/// The pin replaces the frozen addresses: someone who pinned a mirror meant for nothing public to be
/// asked. A pin that fell through once installed from the public address with the mirror down.
#[test]
fn a_pin_is_the_only_address() {
    use n0xis_update::config::Settings;
    let frozen: Vec<String> = n0xis_update::MANIFEST_ADDRESSES.iter().map(|a| a.to_string()).collect();
    assert_eq!(Settings::default().manifest_addresses(), frozen);

    let b = Bench::new("pin");
    plant_at(&b, "/pinned", "1.5.0", None, &b.key);
    let pinned = |url: String| Settings { manifest_url: Some(url), ..Settings::default() }.manifest_addresses();
    assert_eq!(pinned(b.server.url("/pinned")), [b.server.url("/pinned")]);
    let updater = b.updater_with(pinned(b.server.url("/pinned")), Trust::of_keys(&[public(&b.key)]), Bench::limits());
    assert_eq!(updater.check().expect("check").latest, "1.5.0");

    // A pin that does not verify is a refusal, as is a dead one, and there is nothing else to ask.
    b.server.route("/pinned.sig", Reply::Body(sign(&key(9), b"something else")));
    assert_eq!(updater.check().expect_err("a bad pin").why, Why::BadSignature);
    assert_eq!(updater.update().expect_err("a bad pin").why, Why::BadSignature);
    let updater = b.updater_with(pinned(dead_address()), Trust::of_keys(&[public(&b.key)]), Bench::limits());
    assert_eq!(updater.check().expect_err("a dead pin").why, Why::ManifestUnavailable);
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
}

#[test]
fn a_planted_key_file_trusts_nothing() {
    let b = Bench::new("plantedkeys");
    let attacker = key(9);
    let root = hex(&public(&b.key));
    plant_at(&b, "/manifest.json", "2.0.0", Some(public(&attacker)), &attacker);
    let bytes = serde_json::to_vec(&{
        let mut m = b.manifest("1.0.0");
        m["next_key"] = json!(hex(&public(&attacker)));
        m
    })
    .unwrap();
    let forged_link = json!({ "chain": [{ "manifest": hex(&bytes), "signature": String::from_utf8(sign(&attacker, &bytes)).unwrap() }] });
    for planted in [json!({ "keys": [hex(&public(&attacker))] }), forged_link] {
        fs::write(b.config.join("update-keys.json"), planted.to_string()).unwrap();
        let updater = b.updater_with(vec![b.server.url("/manifest.json")], Trust::rooted_at(&root, Some(&b.config)), Bench::limits());
        b.refused(updater.update(), Why::BadSignature);
        assert_eq!(b.server.asked("/file"), 0);
    }
}

#[test]
fn a_two_hop_chain_does() {
    let b = Bench::new("twohop");
    let root = hex(&public(&b.key));
    let (second, third) = (key(8), key(9));
    let trust = |b: &Bench| Trust::rooted_at(&root, Some(&b.config));
    let check = |b: &Bench, path: &str| b.updater_with(vec![b.server.url(path)], trust(b), Bench::limits()).check();

    plant_at(&b, "/hop1", "1.0.0", Some(public(&second)), &b.key);
    check(&b, "/hop1").expect("the root names the second key");
    plant_at(&b, "/hop2", "1.0.0", Some(public(&third)), &second);
    check(&b, "/hop2").expect("the second key verifies and names the third");
    plant_at(&b, "/manifest.json", "2.0.0", None, &third);
    b.updater_with(vec![b.server.url("/manifest.json")], trust(&b), Bench::limits()).update().expect("the third key signs");
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);

    // What is on the disk is the statements, and it is they that hold: out of order, the second link
    // proves nothing, and neither does the third key.
    let chain: Value = serde_json::from_slice(&fs::read(b.config.join("update-keys.json")).unwrap()).unwrap();
    let links = chain["chain"].as_array().expect("a chain");
    assert_eq!(links.len(), 2);
    fs::write(b.config.join("update-keys.json"), json!({ "chain": [links[1], links[0]] }).to_string()).unwrap();
    let err = check(&b, "/manifest.json").expect_err("the third key is not proved");
    assert_eq!(err.why, Why::BadSignature);
}

#[test]
fn a_key_file_past_its_bounds_proves_nothing_past_them() {
    let b = Bench::new("bounds");
    let root = hex(&public(&b.key));
    let bytes = serde_json::to_vec(&{
        let mut m = b.manifest("1.0.0");
        m["next_key"] = json!(hex(&public(&key(8))));
        m
    })
    .unwrap();
    let link = json!({ "manifest": hex(&bytes), "signature": String::from_utf8(sign(&b.key, &bytes)).unwrap() });
    let junk = json!({ "manifest": "00", "signature": "" });
    plant_at(&b, "/manifest.json", "2.0.0", None, &key(8));
    let check = |b: &Bench| b.updater_with(vec![b.server.url("/manifest.json")], Trust::rooted_at(&root, Some(&b.config)), Bench::limits()).check();

    // The calibration: the same link, within the bounds, does prove the key.
    let mut chain = vec![junk.clone(); 31];
    chain.push(link.clone());
    fs::write(b.config.join("update-keys.json"), json!({ "chain": chain }).to_string()).unwrap();
    check(&b).expect("the 32nd record is read");

    let mut chain = vec![junk; 32];
    chain.push(link.clone());
    fs::write(b.config.join("update-keys.json"), json!({ "chain": chain }).to_string()).unwrap();
    assert_eq!(check(&b).expect_err("the 33rd is not").why, Why::BadSignature);

    let mut text = json!({ "chain": [link] }).to_string();
    text.push_str(&" ".repeat(1024 * 1024));
    fs::write(b.config.join("update-keys.json"), text).unwrap();
    assert_eq!(check(&b).expect_err("past 1 MiB").why, Why::BadSignature);
}

/// A link that proves a next key, and the key it proves, for the tests of what is written back.
fn a_real_next_key(b: &Bench) -> (String, Trust) {
    let root = hex(&public(&b.key));
    plant_at(b, "/manifest.json", "1.0.0", Some(public(&key(8))), &b.key);
    let trust = Trust::rooted_at(&root, Some(&b.config));
    (root, trust)
}

/// 32 junk records once filled the chain, so a real key was never remembered and a change of key
/// stranded the copy.
#[test]
fn a_junk_chain_still_takes_a_real_key() {
    let b = Bench::new("junkchain");
    let keys = b.config.join("update-keys.json");
    fs::write(&keys, json!({ "chain": vec![json!({ "manifest": "00", "signature": "" }); 32] }).to_string()).unwrap();
    let (root, trust) = a_real_next_key(&b);
    b.updater_with(vec![b.server.url("/manifest.json")], trust, Bench::limits()).check().expect("check");
    let written: Value = serde_json::from_slice(&fs::read(&keys).unwrap()).unwrap();
    assert_eq!(written["chain"].as_array().unwrap().len(), 1, "only what verifies is kept: {written}");

    plant_at(&b, "/manifest.json", "2.0.0", None, &key(8));
    let report = b.updater_with(vec![b.server.url("/manifest.json")], Trust::rooted_at(&root, Some(&b.config)), Bench::limits()).check().expect("the next key signs");
    assert_eq!(report.latest, "2.0.0");
}

#[test]
fn a_file_past_the_bound_is_cleaned_rather_than_kept() {
    let b = Bench::new("oversize");
    let keys = b.config.join("update-keys.json");
    fs::write(&keys, " ".repeat(1024 * 1024 + 5)).unwrap();
    let (_, trust) = a_real_next_key(&b);
    b.updater_with(vec![b.server.url("/manifest.json")], trust, Bench::limits()).check().expect("check");
    assert!(fs::metadata(&keys).unwrap().len() < 64 * 1024, "the oversize file was kept");
}

/// A record that verifies under the walk stays, in its order, when a later one is appended.
#[test]
fn a_real_record_is_kept_when_another_is_appended() {
    let b = Bench::new("keepchain");
    let root = hex(&public(&b.key));
    plant_at(&b, "/manifest.json", "1.0.0", Some(public(&key(8))), &b.key);
    b.updater_with(vec![b.server.url("/manifest.json")], Trust::rooted_at(&root, Some(&b.config)), Bench::limits()).check().expect("first");
    plant_at(&b, "/manifest.json", "1.0.1", Some(public(&key(9))), &key(8));
    b.updater_with(vec![b.server.url("/manifest.json")], Trust::rooted_at(&root, Some(&b.config)), Bench::limits()).check().expect("second");
    plant_at(&b, "/manifest.json", "2.0.0", None, &key(9));
    let report = b.updater_with(vec![b.server.url("/manifest.json")], Trust::rooted_at(&root, Some(&b.config)), Bench::limits()).check().expect("two hops");
    assert_eq!(report.latest, "2.0.0");
}

/// A file that cannot be read may hold real records, so nothing is written over it.
#[cfg(unix)]
#[test]
fn a_chain_that_cannot_be_read_is_not_written_over() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("not verified here: running as root");
        return;
    }
    let b = Bench::new("noreadchain");
    let keys = b.config.join("update-keys.json");
    fs::write(&keys, b"what cannot be seen just now").unwrap();
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o000)).unwrap();
    let (_, trust) = a_real_next_key(&b);
    b.updater_with(vec![b.server.url("/manifest.json")], trust, Bench::limits()).check().expect("check");
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(fs::read(&keys).unwrap(), b"what cannot be seen just now");
}

#[cfg(unix)]
#[test]
fn a_link_planted_at_a_temporary_name_is_not_followed() {
    let b = Bench::new("templink");
    let victim = b.config.parent().unwrap().join("victim");
    fs::write(&victim, b"precious").unwrap();
    std::os::unix::fs::symlink(&victim, b.config.join(format!("update-keys.json.tmp-{}", std::process::id()))).unwrap();
    plant_at(&b, "/manifest.json", "1.0.0", Some(public(&key(8))), &b.key);
    let root = hex(&public(&b.key));
    b.updater_with(vec![b.server.url("/manifest.json")], Trust::rooted_at(&root, Some(&b.config)), Bench::limits()).check().expect("check");
    assert_eq!(fs::read(&victim).unwrap(), b"precious");
}

/// A release whose running file is `file`, every check on it passing.
fn publish_program(b: &Bench, version: &str, file: &[u8]) {
    let mut m = b.manifest(version);
    m["components"][COMPONENT][PLATFORM]["size"] = json!(file.len());
    m["components"][COMPONENT][PLATFORM]["sha256"] = json!(sha(file));
    b.publish(&m);
    b.server.route("/file", Reply::Body(file.to_vec()));
}

#[test]
fn a_garbage_signed_file_is_refused_with_the_target_unchanged() {
    let b = Bench::new("garbage");
    publish_program(&b, "2.0.0", b"signed, checked, and not a program\n");
    b.refused(b.updater().update(), Why::DoesNotRun);
}

#[test]
fn a_file_that_answers_wrongly_does_not_run() {
    let b = Bench::new("wronganswer");
    for (says, why) in [("fail 2.0.0", "a failing exit"), ("1.9.9", "another version"), ("12.0.0", "a version holding the version")] {
        publish_program(&b, "2.0.0", &program(says));
        let refusal = b.refused(b.updater().update(), Why::DoesNotRun);
        assert!(refusal.message.contains("--version"), "{why}: {}", refusal.message);
    }
}

#[test]
fn a_file_that_never_answers_ends_within_the_bound() {
    let b = Bench::new("hang");
    publish_program(&b, "2.0.0", &program("hang"));
    let quick = Limits { run: Duration::from_millis(1500), ..Bench::limits() };
    let updater = b.updater_with(vec![b.server.url("/manifest.json")], Trust::of_keys(&[public(&b.key)]), quick);
    let start = Instant::now();
    b.refused(updater.update(), Why::DoesNotRun);
    assert!(start.elapsed() < Duration::from_secs(10), "took {:?} against a bound of 1.5 s", start.elapsed());
}

/// Installed first, so that what comes back has a true record, and then the state under test is made.
fn installed(name: &str) -> Bench {
    let b = Bench::new(name);
    b.publish(&b.manifest("2.0.0"));
    b.updater().update().expect("update");
    b
}

#[test]
fn a_previous_that_does_not_match_is_refused() {
    let b = installed("nomatch");
    let previous = b.dir.join("n0xis.previous");
    fs::write(&previous, b"not what was kept").unwrap();
    let refusal = rollback(&b.exe, None).expect_err("altered");
    assert_eq!(refusal.why, Why::PreviousDoesNotMatch);
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);

    fs::write(&previous, OLD).unwrap();
    fs::remove_file(b.dir.join("n0xis.previous.json")).unwrap();
    assert_eq!(rollback(&b.exe, None).expect_err("no record").why, Why::PreviousDoesNotMatch);
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
}

#[cfg(unix)]
#[test]
fn a_planted_previous_symlink_is_refused() {
    let b = installed("plantedlink");
    let previous = b.dir.join("n0xis.previous");
    // A link to the very file the record vouches for: its digest matches, and it is still a link.
    let elsewhere = b.dir.parent().unwrap().join("elsewhere");
    fs::rename(&previous, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &previous).unwrap();
    assert_eq!(rollback(&b.exe, None).expect_err("a link").why, Why::PreviousDoesNotMatch);
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    assert!(!fs::symlink_metadata(&b.exe).unwrap().file_type().is_symlink());
}

/// What a kill between the record and the last rename leaves: nothing to go back from.
#[test]
fn a_previous_equal_to_the_target_says_that_nothing_changed() {
    let b = installed("equal");
    let previous = b.dir.join("n0xis.previous");
    let record = serde_json::to_vec(&json!({ "from": "2.0.0", "to": "2.0.1", "previous_sha256": sha(&NEW), "installed_sha256": sha(b"the next one") })).unwrap();
    fs::write(&previous, &*NEW).unwrap();
    fs::write(b.dir.join("n0xis.previous.json"), record).unwrap();
    let report = rollback(&b.exe, None).expect("an answer");
    assert!(report.nothing_changed.is_some());
    assert_eq!((report.from, report.to), (None, None));
    assert_eq!(report.file, b.exe.display().to_string());
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
}

#[test]
fn a_record_that_does_not_read_as_versions_is_no_record() {
    let b = installed("badrecord");
    let record = serde_json::to_vec(&json!({ "from": "\u{1b}[2Jfake", "to": "2.0.0", "previous_sha256": sha(OLD), "installed_sha256": sha(&NEW) })).unwrap();
    fs::write(b.dir.join("n0xis.previous.json"), record).unwrap();
    assert_eq!(rollback(&b.exe, None).expect_err("no such version").why, Why::PreviousDoesNotMatch);
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
}

/// The lock, held the way another process holds it, stops all three, and the detached one says nothing.
#[test]
fn a_held_lock_stops_update_rollback_and_the_detached_copy() {
    let b = Bench::new("held");
    b.publish(&b.manifest("2.0.0"));
    let lock = fs::File::create(b.dir.join("n0xis.update-lock")).unwrap();
    lock.try_lock().unwrap();
    b.refused(b.updater().update(), Why::UpdateInProgress);
    fs::write(b.dir.join("n0xis.previous"), OLD).unwrap();
    assert_eq!(rollback(&b.exe, None).expect_err("rollback").why, Why::UpdateInProgress);
    fs::remove_file(b.dir.join("n0xis.previous")).unwrap();
    notice::run_check(&b.updater(), true);
    assert_eq!(state_of(&b).refusal, None, "the detached copy skips in silence");
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
    drop(lock);
    b.updater().update().expect("and the kernel releases it");
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    assert!(b.dir.join("n0xis.update-lock").exists(), "the lock file stays");
}

/// The finding: two at once both said ok, `.previous` held the new file and the old one was gone.
#[test]
fn parallel_runs_keep_the_old_file_for_rollback() {
    let b = Bench::new("parallel");
    b.publish(&b.manifest("2.0.0"));
    // Slower than the lock's patience, all set off together, so they do overlap at the lock.
    let meanwhile = Arc::new(|| std::thread::sleep(Duration::from_millis(800)));
    b.server.route("/file", Reply::During { body: NEW.to_vec(), at: NEW.len() / 2, meanwhile });
    let together = Arc::new(std::sync::Barrier::new(6));
    let runs: Vec<_> = (0..6)
        .map(|_| {
            let (updater, together) = (b.updater(), together.clone());
            std::thread::spawn(move || {
                together.wait();
                updater.update().map(|_| ()).map_err(|r| r.why)
            })
        })
        .collect();
    let results: Vec<_> = runs.into_iter().map(|r| r.join().unwrap()).collect();
    assert!(results.iter().all(|r| matches!(r, Ok(()) | Err(Why::UpdateInProgress))), "{results:?}");
    assert!(results.iter().any(Result::is_ok), "{results:?}");
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    assert_eq!(fs::read(b.dir.join("n0xis.previous")).unwrap(), OLD, "the old file is what is kept");
    assert_eq!(b.files(), ["n0xis", "n0xis.previous", "n0xis.previous.json"]);
    rollback(&b.exe, None).expect("rollback");
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
}

/// What is installed is read under the lock. Read before it, a run that waited out another kept the
/// new file as `.previous`, the old one was gone, and a rollback went nowhere.
#[test]
fn a_run_that_waited_out_another_reads_what_it_left() {
    let b = Bench::new("waited");
    b.publish(&b.manifest("2.0.0"));
    let lock = fs::File::create(b.dir.join("n0xis.update-lock")).unwrap();
    lock.try_lock().unwrap();
    let updater = b.updater();
    let run = std::thread::spawn(move || updater.update());
    let start = Instant::now();
    while b.server.asked("/manifest.json.sig") == 0 && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(100));
    // Another run's install, done while this one waits at the lock.
    fs::write(&b.exe, &*NEW).unwrap();
    drop(lock);
    let report = run.join().unwrap().expect("it waits a moment for the lock");
    assert_eq!(report.unchanged, [COMPONENT]);
    assert_eq!(b.files(), ["n0xis"], "nothing to keep: the file is already the new one");
}

/// `meanwhile` while the manifest is on its way: what lands between the look at the file and the lock.
fn during_the_fetch(b: &Bench, manifest: &Value, meanwhile: impl Fn() + Send + Sync + 'static) {
    b.publish(manifest);
    let body = serde_json::to_vec(manifest).unwrap();
    b.server.route("/manifest.json", Reply::During { body, at: 0, meanwhile: Arc::new(meanwhile) });
}

/// A later release with its own file at `/file`, for a bench where one was already installed.
fn release_of(b: &Bench, version: &str) -> (Value, Vec<u8>) {
    let file = program(version);
    let mut m = b.manifest(version);
    m["components"][COMPONENT][PLATFORM]["size"] = json!(file.len());
    m["components"][COMPONENT][PLATFORM]["sha256"] = json!(sha(&file));
    (m, file)
}

/// The finding: a rollback during the fetch, and the install went on from what the process believed. The
/// record said `from` 2.0.0 of a kept file that was 1.0.0, and what had been gone back from moved forward.
#[test]
fn a_rollback_landing_during_the_fetch_moves_nothing() {
    let b = installed("fetchback");
    let (next, _) = release_of(&b, "2.0.1");
    let exe = b.exe.clone();
    during_the_fetch(&b, &next, move || {
        rollback(&exe, None).expect("rollback");
    });
    let mut updater = b.updater();
    updater.current = Version::new(2, 0, 0);
    let fetched_before = b.server.asked("/file");
    let refusal = updater.update().expect_err("the file is not what this process took it for");
    assert_eq!(refusal.why, Why::ChangedDuringUpdate, "{}", refusal.message);
    assert_eq!(refusal.why.code(), "changed-during-update");
    assert_eq!(fs::read(&b.exe).unwrap(), OLD, "it moved");
    assert_eq!(b.files(), ["n0xis", "n0xis.update-hold"], "it left something, or moved something");
    assert_eq!(b.server.asked("/file"), fetched_before, "nothing to fetch for a file not being replaced");
}

/// The same for the detached copy, and in silence: another run did this, and there is nothing to report.
#[test]
fn the_detached_copy_skips_a_file_that_changed_in_silence() {
    let b = installed("fetchquiet");
    let (next, _) = release_of(&b, "2.0.1");
    let exe = b.exe.clone();
    during_the_fetch(&b, &next, move || {
        rollback(&exe, None).expect("rollback");
    });
    let mut updater = b.updater();
    updater.current = Version::new(2, 0, 0);
    notice::run_check(&updater, true);
    let state = state_of(&b);
    assert_eq!((state.refusal, state.installed), (None, None));
    assert_eq!(state.latest.as_deref(), Some("2.0.1"), "it is still offered");
    assert_eq!(fs::read(&b.exe).unwrap(), OLD, "it moved");
    assert_eq!(b.files(), ["n0xis", "n0xis.update-hold"]);
}

/// Another updater, landing a release this one's manifest is not: its file is not gone over or kept.
#[test]
fn another_updater_landing_during_the_fetch_moves_nothing() {
    let b = Bench::new("fetchother");
    // What this run fetched is the older of the two, and it would have moved the target back to that.
    let (mut third, third_file) = release_of(&b, "3.0.0");
    b.server.route("/third", Reply::Body(third_file.clone()));
    third["components"][COMPONENT][PLATFORM]["url"] = json!(b.server.url("/third"));
    let third_bytes = serde_json::to_vec(&third).unwrap();
    b.server.route("/other.sig", Reply::Body(sign(&b.key, &third_bytes)));
    b.server.route("/other", Reply::Body(third_bytes));
    let other = b.updater_with(vec![b.server.url("/other")], Trust::of_keys(&[public(&b.key)]), Bench::limits());
    during_the_fetch(&b, &b.manifest("2.0.0"), move || {
        other.update().expect("the other updater");
    });
    let refusal = b.updater().update().expect_err("the target went past what this fetched");
    assert_eq!(refusal.why, Why::ChangedDuringUpdate, "{}", refusal.message);
    assert_eq!(fs::read(&b.exe).unwrap(), third_file, "it moved back");
    assert_eq!(fs::read(b.dir.join("n0xis.previous")).unwrap(), OLD, "what the other one kept");
}

/// Each of what is compared, alone, with the others kept as they were.
#[test]
fn each_of_inode_size_and_mtime_is_a_change() {
    fn with_the_time(path: &Path, then: std::time::SystemTime) {
        fs::OpenOptions::new().write(true).open(path).unwrap().set_modified(then).unwrap();
    }
    #[allow(clippy::type_complexity)]
    let mut changes: Vec<(&str, fn(&Path, std::time::SystemTime))> = vec![
        ("size", |exe, then| {
            fs::write(exe, [OLD, b"!".as_slice()].concat()).unwrap();
            with_the_time(exe, then);
        }),
        ("mtime", |exe, then| with_the_time(exe, then + Duration::from_secs(10))),
    ];
    #[cfg(unix)]
    changes.push(("inode", |exe, then| {
        let beside = exe.with_extension("planted");
        fs::write(&beside, OLD).unwrap();
        with_the_time(&beside, then);
        fs::rename(&beside, exe).unwrap();
    }));
    for (what, change) in changes {
        let b = Bench::new(&format!("each-{what}"));
        let (exe, then) = (b.exe.clone(), fs::metadata(&b.exe).unwrap().modified().unwrap());
        during_the_fetch(&b, &b.manifest("2.0.0"), move || change(&exe, then));
        let refusal = b.updater().update().expect_err(what);
        assert_eq!(refusal.why, Why::ChangedDuringUpdate, "{what}: {}", refusal.message);
    }
}

/// A file this same process just installed is not a change someone else made.
#[test]
fn a_fresh_install_in_this_process_is_not_its_own_trigger() {
    let b = Bench::new("fresh");
    b.publish(&b.manifest("2.0.0"));
    let updater = b.updater();
    updater.update().expect("the first");
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    let (next, file) = release_of(&b, "3.0.0");
    b.publish(&next);
    b.server.route("/file", Reply::Body(file.clone()));
    updater.update().expect("the second, by the same updater");
    assert_eq!(fs::read(&b.exe).unwrap(), file);
}

/// Wait for the download to have reached the disk and call `then` with the temporary's path.
fn during_the_download(b: &Bench, then: impl Fn(&Path) + Send + Sync + 'static) {
    b.publish(&b.manifest("2.0.0"));
    let at = NEW.len() / 2;
    let path = b.dir.join(CANDIDATE);
    let meanwhile = Arc::new(move || {
        let start = Instant::now();
        while fs::metadata(&path).map_or(0, |m| m.len()) < at as u64 && start.elapsed() < Duration::from_secs(4) {
            std::thread::sleep(Duration::from_millis(5));
        }
        then(&path);
    });
    b.server.route("/file", Reply::During { body: NEW.to_vec(), at, meanwhile });
}

/// Off Windows this reaches the process's umask, which every other test shares; a wider umask makes no
/// file of theirs less readable to them, so the only thing that can notice is this test's own check.
#[cfg(unix)]
#[test]
fn the_new_file_is_0600_under_umask_000() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicU32;
    let b = Bench::new("umask");
    let seen = Arc::new(AtomicU32::new(0));
    let saw = seen.clone();
    during_the_download(&b, move |path| saw.store(fs::metadata(path).map_or(0, |m| m.permissions().mode()) & 0o7777, Ordering::SeqCst));
    // SAFETY: umask takes a number and cannot fail.
    let before = unsafe { libc::umask(0) };
    let result = b.updater().update();
    unsafe { libc::umask(before) };
    result.expect("update");
    assert_eq!(seen.load(Ordering::SeqCst), 0o600);
}

#[test]
fn a_file_altered_after_the_download_is_refused() {
    use std::io::{Seek, SeekFrom, Write};
    let b = Bench::new("altered");
    during_the_download(&b, |path| {
        let mut file = fs::OpenOptions::new().write(true).open(path).expect("the temporary");
        file.seek(SeekFrom::Start(100)).unwrap();
        file.write_all(b"ALTERED").unwrap();
    });
    b.refused(b.updater().update(), Why::DigestMismatch);
}

#[cfg(unix)]
#[test]
fn setuid_is_not_carried_over() {
    use std::os::unix::fs::PermissionsExt;
    let b = Bench::new("setuid");
    fs::set_permissions(&b.exe, fs::Permissions::from_mode(0o4755)).unwrap();
    b.publish(&b.manifest("2.0.0"));
    b.updater().update().expect("update");
    assert_eq!(fs::metadata(&b.exe).unwrap().permissions().mode() & 0o7777, 0o755);
    assert_eq!(fs::metadata(b.dir.join("n0xis.previous")).unwrap().permissions().mode() & 0o7777, 0o755);
}

#[cfg(unix)]
#[test]
fn a_symlinked_sibling_stays_a_link_and_comes_back_by_its_name() {
    let b = Bench::new("siblink");
    let real = b.dir.parent().unwrap().join("real-mcp");
    fs::write(&real, b"old mcp").unwrap();
    let link = b.dir.join("n0xis-mcp");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    b.publish(&with_the_mcp(&b, "2.0.0", b"new mcp"));
    b.updater().update().expect("update");
    assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink(), "the link was replaced by a file");
    assert_eq!(fs::read(&real).unwrap(), b"new mcp");
    rollback(&b.exe, Some("n0xis-mcp")).expect("rollback");
    assert_eq!(fs::read(&real).unwrap(), b"old mcp");
    assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
}

#[test]
fn a_sibling_that_is_not_a_regular_file_is_skipped() {
    let b = Bench::new("sibdir");
    fs::create_dir(b.dir.join("n0xis-mcp")).unwrap();
    b.publish(&with_the_mcp(&b, "2.0.0", b"new mcp"));
    let report = b.updater().update().expect("a directory by that name stops nothing");
    assert_eq!(skipped(&report), [("n0xis-mcp", "not-a-regular-file")]);
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    assert_eq!(b.server.asked("/mcp"), 0);
    assert!(b.dir.join("n0xis-mcp").is_dir());
}

/// A commit failing on one component is that component's: the other stays in place, and each is named.
#[test]
fn a_commit_failure_reports_each_component() {
    let b = Bench::new("commitfails");
    let mcp = b.dir.join("n0xis-mcp");
    fs::write(&mcp, b"old mcp").unwrap();
    // Something a rename cannot go over. On Windows a directory does not stop it, under Wine at least,
    // and a file held open with no sharing does.
    #[cfg(unix)]
    fs::create_dir_all(b.dir.join("n0xis-mcp.previous").join("in-the-way")).unwrap();
    #[cfg(windows)]
    let _in_the_way = {
        use std::os::windows::fs::OpenOptionsExt;
        fs::OpenOptions::new().write(true).create(true).truncate(false).share_mode(0).open(b.dir.join("n0xis-mcp.previous")).unwrap()
    };
    b.publish(&with_the_mcp(&b, "2.0.0", b"new mcp"));
    let refusal = b.updater().update().expect_err("the sibling cannot be committed");
    assert_eq!(refusal.why, Why::InstallFailed);
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW, "no undo");
    assert_eq!(fs::read(&mcp).unwrap(), b"old mcp");
    let results: Vec<_> = refusal.components.iter().map(|o| (o.component.as_str(), o.error.is_some())).collect();
    assert_eq!(results, [("n0xis", false), ("n0xis-mcp", true)]);
    assert_eq!(b.files(), ["n0xis", "n0xis-mcp", "n0xis-mcp.previous", "n0xis.previous", "n0xis.previous.json"], "a temp was left");

    // Its own fact too: the one that did move goes back, and the other was never part of it.
    rollback(&b.exe, None).expect("rollback");
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
    assert_eq!(fs::read(&mcp).unwrap(), b"old mcp");
}

#[test]
fn a_sibling_from_an_earlier_install_stays_on_rollback() {
    let b = Bench::new("earliersib");
    let mcp = b.dir.join("n0xis-mcp");
    fs::write(&mcp, b"current mcp").unwrap();
    fs::write(b.dir.join("n0xis-mcp.previous"), b"older mcp").unwrap();
    fs::write(b.dir.join("n0xis-mcp.previous.json"), serde_json::to_vec(&json!({ "from": "0.8.0", "to": "0.9.0", "previous_sha256": sha(b"older mcp"), "installed_sha256": sha(b"current mcp") })).unwrap()).unwrap();
    b.publish(&b.manifest("2.0.0"));
    b.updater().update().expect("update");
    rollback(&b.exe, None).expect("rollback");
    assert_eq!(fs::read(&mcp).unwrap(), b"current mcp");
}

#[test]
fn what_a_dead_run_left_is_swept_under_the_lock() {
    let b = Bench::new("deadrun");
    fs::write(b.dir.join(CANDIDATE), b"half a download").unwrap();
    fs::write(b.dir.join("n0xis.previous-new"), b"half a copy").unwrap();
    fs::write(b.dir.join("n0xis.previous.json.new"), b"half a record").unwrap();
    fs::write(b.dir.join("n0xis.update-hold-new"), b"half a hold").unwrap();
    b.publish(&b.manifest("2.0.0"));
    b.updater().update().expect("update");
    assert_eq!(b.files(), ["n0xis", "n0xis.previous", "n0xis.previous.json"]);
    assert_eq!(fs::read(b.dir.join("n0xis.previous")).unwrap(), OLD);
}

/// The sweep once went by prefix, and took a user's file that happened to start the same.
#[test]
fn the_sweep_removes_exact_names_only() {
    let b = Bench::new("exactsweep");
    let strangers = ["n0xis.aside-notes.txt", "n0xis.aside-", "n0xis.aside-12a", "n0xis.update-new.bak", "n0xis.previous-new.txt", "n0xis.previous.txt"];
    for name in strangers {
        fs::write(b.dir.join(name), b"a user's").unwrap();
    }
    fs::write(b.dir.join("n0xis.aside-4242"), b"an old image").unwrap();
    b.publish(&b.manifest("2.0.0"));
    b.updater().update().expect("update");
    for name in strangers {
        assert_eq!(fs::read(b.dir.join(name)).unwrap(), b"a user's", "{name}");
    }
    // On Windows only: nothing else ever leaves such a file, and elsewhere it may be anyone's.
    assert_eq!(b.dir.join("n0xis.aside-4242").exists(), !cfg!(windows));
}

/// `.previous` belongs to the updater, and what was there goes when an install keeps its own.
#[test]
fn a_file_at_the_kept_name_is_the_updaters() {
    let b = Bench::new("kept");
    fs::write(b.dir.join("n0xis.previous"), b"a user's backup of something else").unwrap();
    b.publish(&b.manifest("2.0.0"));
    b.updater().update().expect("update");
    assert_eq!(fs::read(b.dir.join("n0xis.previous")).unwrap(), OLD);
}

/// A bare relative name would be looked for on `PATH`, and a file there would run in place of the one
/// just checked. Nothing here depends on the working directory but this, and it is put back.
#[test]
fn the_candidate_is_executed_by_absolute_path() {
    let b = Bench::new("absolute");
    b.publish(&b.manifest("2.0.0"));
    let mut updater = b.updater();
    updater.exe = PathBuf::from("n0xis");
    let back = std::env::current_dir().unwrap();
    std::env::set_current_dir(&b.dir).unwrap();
    let result = updater.update();
    std::env::set_current_dir(back).unwrap();
    result.expect("run from where it is");
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
}

/// On Windows a file planted with `.exe` added ran in place of the candidate that was checked, and its
/// name now ends in `.exe`, so there is no second name to plant.
#[cfg(windows)]
#[test]
fn a_planted_candidate_on_windows_does_not_run() {
    let b = Bench::new("shadow");
    fs::write(b.dir.join("n0xis.update-new.exe"), program("2.0.0")).unwrap();
    publish_program(&b, "2.0.0", b"signed, checked and not a program");
    b.refused(b.updater().update(), Why::DoesNotRun);
}

/// Puts something at a path, for a test of what is found there.
#[cfg(unix)]
type Plant = fn(&Bench, &Path);

/// A plant that would hang or be followed: bounded, so a guard removed fails rather than wedges.
#[cfg(unix)]
fn within_a_bound<T: Send + 'static>(run: impl FnOnce() -> T + Send + 'static) -> T {
    let (sender, answer) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(run());
    });
    answer.recv_timeout(Duration::from_secs(10)).expect("it hung on what was planted")
}

#[cfg(unix)]
fn mkfifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o666) }, 0);
}

#[cfg(unix)]
#[test]
fn a_link_or_a_fifo_at_the_lock_is_refused() {
    let plants: [(&str, Plant); 2] = [
        ("link", |b, at| std::os::unix::fs::symlink(b.dir.parent().unwrap().join("made-by-the-lock"), at).unwrap()),
        ("fifo", |_, at| mkfifo(at)),
    ];
    for (name, plant) in plants {
        let b = Bench::new(name);
        b.publish(&b.manifest("2.0.0"));
        let lock = b.dir.join("n0xis.update-lock");
        plant(&b, &lock);
        let updater = b.updater();
        let result = within_a_bound(move || updater.update());
        b.refused(result, Why::NotOurs);
        assert!(!b.dir.parent().unwrap().join("made-by-the-lock").exists(), "the lock followed a link");

        fs::write(b.dir.join("n0xis.previous"), OLD).unwrap();
        let exe = b.exe.clone();
        assert_eq!(within_a_bound(move || rollback(&exe, None)).expect_err("rollback").why, Why::NotOurs, "{name}");
        fs::remove_file(b.dir.join("n0xis.previous")).unwrap();
        // Refused and not skipped in silence, unlike a lock another run holds.
        notice::run_check(&b.updater(), true);
        assert_eq!(state_of(&b).refusal.as_deref(), Some("not-ours"), "{name}");
        assert_eq!(fs::read(&b.exe).unwrap(), OLD);
    }
}

#[cfg(unix)]
#[test]
fn a_link_or_a_fifo_at_the_record_or_the_kept_file_is_refused() {
    for kept in ["n0xis.previous", "n0xis.previous.json"] {
        // A link to a true copy, so nothing but its being a link is wrong with it.
        let b = installed("keptlink");
        let at = b.dir.join(kept);
        let elsewhere = b.dir.parent().unwrap().join("elsewhere");
        fs::rename(&at, &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &at).unwrap();
        let exe = b.exe.clone();
        assert_eq!(within_a_bound(move || rollback(&exe, None)).expect_err("a link").why, Why::PreviousDoesNotMatch, "{kept}");
        assert_eq!(fs::read(&b.exe).unwrap(), *NEW);

        let b = installed("keptfifo");
        let at = b.dir.join(kept);
        fs::remove_file(&at).unwrap();
        mkfifo(&at);
        let exe = b.exe.clone();
        assert_eq!(within_a_bound(move || rollback(&exe, None)).expect_err("a fifo").why, Why::PreviousDoesNotMatch, "{kept}");
        assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    }
}

#[cfg(unix)]
#[test]
fn a_link_a_fifo_or_junk_at_the_hold_stops_auto_and_not_the_user() {
    let plants: [(&str, Plant); 3] = [
        ("link", |b, at| {
            let real = b.dir.parent().unwrap().join("real-hold");
            fs::write(&real, b"0.0.1").unwrap();
            std::os::unix::fs::symlink(real, at).unwrap();
        }),
        ("fifo", |_, at| mkfifo(at)),
        ("junk", |_, at| fs::write(at, b"not a version").unwrap()),
    ];
    for (name, plant) in plants {
        let b = Bench::new(name);
        b.publish(&b.manifest("2.0.0"));
        plant(&b, &b.dir.join("n0xis.update-hold"));
        let updater = b.updater();
        within_a_bound(move || notice::run_check(&updater, true));
        assert_eq!(state_of(&b).refusal.as_deref(), Some("not-ours"), "{name}");
        assert_eq!(fs::read(&b.exe).unwrap(), OLD, "{name}");
        b.updater().update().expect("the user asked");
        assert!(fs::symlink_metadata(b.dir.join("n0xis.update-hold")).is_err(), "{name}");
    }
}

/// The same run against a sibling's own lock and hold: skipped, and the running file goes on.
#[cfg(unix)]
#[test]
fn a_plant_beside_a_sibling_makes_it_skipped() {
    let b = Bench::new("sibplant");
    let mcp = b.dir.join("n0xis-mcp");
    fs::write(&mcp, b"old mcp").unwrap();
    mkfifo(&b.dir.join("n0xis-mcp.update-lock"));
    b.publish(&with_the_mcp(&b, "2.0.0", b"new mcp"));
    let updater = b.updater();
    let report = within_a_bound(move || updater.update()).expect("the running file goes on");
    assert_eq!(skipped(&report), [("n0xis-mcp", "not-ours")]);
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    assert_eq!(fs::read(&mcp).unwrap(), b"old mcp");
}

/// The case nothing but another user can make: in a sticky directory anyone can plant a file, no one
/// else can remove it, and a record and `.previous` of theirs would otherwise say what is installed.
/// With no passwordless `sudo` this is not verified, and it says so.
#[cfg(unix)]
#[test]
fn files_another_user_planted_in_a_sticky_directory_decide_nothing() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("not verified here: running as root");
        return;
    }
    let sudo = |args: &[&str]| std::process::Command::new("sudo").arg("-n").args(args).output().is_ok_and(|o| o.status.success());
    let mut b = Bench::new("sticky");
    let sticky = b.dir.parent().unwrap().join("sticky");
    let path = |p: &Path| p.to_str().unwrap().to_string();
    if !sudo(&["install", "-d", "-o", "root", "-m", "1777", &path(&sticky)]) {
        eprintln!("not verified here: no passwordless sudo");
        return;
    }
    let exe = sticky.join("n0xis");
    fs::rename(&b.exe, &exe).unwrap();
    b.exe = exe;
    b.dir = sticky.clone();
    let source = b.config.parent().unwrap().join("to-plant");
    // World-writable, so that opening it is no problem and only its owner is.
    let plant = |name: &str, bytes: &[u8]| {
        fs::write(&source, bytes).unwrap();
        assert!(sudo(&["install", "-o", "nobody", "-m", "0666", &path(&source), &path(&sticky.join(name))]), "the plant");
    };
    let unplant = |name: &str| assert!(sudo(&["rm", "-f", &path(&sticky.join(name))]));
    b.publish(&b.manifest("2.0.0"));

    plant("n0xis.update-lock", b"");
    b.refused(b.updater().update(), Why::NotOurs);
    unplant("n0xis.update-lock");

    // A kept file and a record that vouch for each other and for what is installed.
    let attacker = program("6.6.6");
    let record = |to: &str| serde_json::to_vec(&json!({ "from": "1.0.0", "to": to, "previous_sha256": sha(&attacker), "installed_sha256": sha(OLD) })).unwrap();
    plant("n0xis.previous", &attacker);
    plant("n0xis.previous.json", &record("2.0.0"));
    assert_eq!(rollback(&b.exe, None).expect_err("not this user's").why, Why::PreviousDoesNotMatch);
    assert_eq!(fs::read(&b.exe).unwrap(), OLD, "a planted file was installed");
    unplant("n0xis.previous");
    fs::write(sticky.join("n0xis.previous"), &attacker).unwrap();
    assert_eq!(rollback(&b.exe, None).expect_err("the record is not this user's").why, Why::PreviousDoesNotMatch);
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
    fs::remove_file(sticky.join("n0xis.previous")).unwrap();
    unplant("n0xis.previous.json");

    plant("n0xis.update-hold", b"9.9.9");
    notice::run_check(&b.updater(), true);
    assert_eq!(state_of(&b).refusal.as_deref(), Some("not-ours"));
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
    unplant("n0xis.update-hold");

    // The calibration: with nothing planted the same directory works.
    b.updater().update().expect("update");
    assert_eq!(fs::read(&b.exe).unwrap(), *NEW);
    assert!(sudo(&["rm", "-rf", &path(&sticky)]));
}
