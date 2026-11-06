// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! docs/design/UPDATE.md §5, against a planted server: each failure ends in its stated refusal with
//! the installed file byte for byte unchanged, and nothing left beside it. Each is calibrated by
//! removing what it guards (`scripts/calibrate_update.py`).

mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use n0xis_update::{Limits, Refusal, Transport, Trust, Updater, Why, notice, rollback};
use ring::digest::{SHA256, digest};
use ring::signature::Ed25519KeyPair;
use semver::Version;
use serde_json::{Value, json};
use support::{Reply, Server};

const OLD: &[u8] = b"the installed binary, version 1.0.0";
const NEW: &[u8] = b"the new binary, version 2.0.0, whose length differs";
const COMPONENT: &str = "n0xis";
const PLATFORM: &str = "test-platform";

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
        Limits { connect: Duration::from_secs(5), response: Duration::from_secs(5), small_body: Duration::from_secs(5), file_body: Duration::from_secs(5), redirects: 3 }
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
            "components": { COMPONENT: { PLATFORM: { "url": self.server.url("/file"), "size": NEW.len(), "sha256": sha(NEW) } } },
        })
    }

    /// Plant `manifest`, signed, and the file.
    fn publish(&self, manifest: &Value) {
        let bytes = serde_json::to_vec(manifest).unwrap();
        self.server.route("/manifest.json.sig", Reply::Body(sign(&self.key, &bytes)));
        self.server.route("/manifest.json", Reply::Body(bytes));
        self.server.route("/file", Reply::Body(NEW.to_vec()));
    }

    fn files(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
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
    assert_eq!(fs::read(&b.exe).unwrap(), NEW);
    let previous = b.dir.join("n0xis.previous");
    assert_eq!(fs::read(&previous).unwrap(), OLD);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&b.exe).unwrap().permissions().mode() & 0o777, 0o750, "a replaced binary must still run");
    }
    assert_eq!(b.files(), ["n0xis", "n0xis.previous", "n0xis.previous.json"], "a temporary file was left");

    let back = rollback(&b.exe, Some(&b.config)).expect("rollback");
    assert_eq!(back.to.as_deref(), Some("1.0.0"));
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
    assert_eq!(fs::read(&previous).unwrap(), NEW, "the file gone back from stays, so it can be returned to");

    let forward = rollback(&b.exe, Some(&b.config)).expect("second rollback");
    assert_eq!(forward.to.as_deref(), Some("2.0.0"));
    assert_eq!(fs::read(&b.exe).unwrap(), NEW);
    assert_eq!(fs::read(&previous).unwrap(), OLD);
}

#[test]
fn rollback_with_nothing_kept_is_a_refusal() {
    let b = Bench::new("noprevious");
    b.refused(rollback(&b.exe, Some(&b.config)), Why::NoPrevious);
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
fn a_file_longer_than_the_manifest_says_stops_being_read() {
    let b = Bench::new("longer");
    let mut m = b.manifest("2.0.0");
    m["components"][COMPONENT][PLATFORM]["size"] = json!(NEW.len() - 1);
    b.publish(&m);
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
    assert_eq!(fs::read(&b.exe).unwrap(), NEW);
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
    assert_eq!(fs::read(&b.exe).unwrap(), NEW);
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
    assert_eq!(fs::read(&b.exe).unwrap(), NEW);
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
    assert_eq!(fs::read(&b.exe).unwrap(), NEW);
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
    assert_eq!(fs::read(&b.exe).unwrap(), NEW);
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
    let b = Bench::new("httpfile");
    let mut m = b.manifest("2.0.0");
    m["components"][COMPONENT][PLATFORM]["url"] = json!("http://127.0.0.1:9/file");
    b.publish(&m);
    b.refused(b.updater().update(), Why::DownloadFailed);
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
fn a_component_beside_the_binary_goes_with_it_and_comes_back_with_it() {
    let b = Bench::new("sibling");
    let mcp = b.dir.join("n0xis-mcp");
    fs::write(&mcp, b"old mcp").unwrap();
    b.publish(&with_the_mcp(&b, "2.0.0", b"new mcp"));
    b.updater().update().expect("update");
    assert_eq!(fs::read(&b.exe).unwrap(), NEW);
    assert_eq!(fs::read(&mcp).unwrap(), b"new mcp");
    rollback(&b.exe, Some(&b.config)).expect("rollback");
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
    assert_eq!(fs::read(&mcp).unwrap(), b"old mcp");
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
fn a_bad_second_file_leaves_the_first_alone() {
    let b = Bench::new("badsecond");
    let mcp = b.dir.join("n0xis-mcp");
    fs::write(&mcp, b"old mcp").unwrap();
    b.publish(&with_the_mcp(&b, "2.0.0", b"new mcp"));
    b.server.route("/mcp", Reply::Body(b"NEW MCP".to_vec()));
    let refusal = b.updater().update().expect_err("the second file is bad");
    assert_eq!(refusal.why, Why::DigestMismatch);
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
    assert_eq!(fs::read(&mcp).unwrap(), b"old mcp");
    assert_eq!(b.files(), ["n0xis", "n0xis-mcp"]);
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
    b.refused(b.updater().update(), Why::BadManifest);
    assert_eq!(fs::read(&outside).unwrap(), b"not ours");
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
    assert_eq!(fs::read(&b.exe).unwrap(), NEW);
    assert_eq!(fs::read(b.dir.join("n0xis.previous")).unwrap(), OLD, "the previous binary stays for --rollback");
    assert_eq!(state_of(&b).installed.map(|i| i.to).as_deref(), Some("2.0.0"));

    rollback(&b.exe, Some(&b.config)).expect("rollback");
    assert_eq!(fs::read(&b.exe).unwrap(), OLD);
    notice::run_check(&b.updater(), true);
    assert_eq!(fs::read(&b.exe).unwrap(), OLD, "the next check undid the rollback");
    assert_eq!(state_of(&b).latest.as_deref(), Some("2.0.0"), "it is still offered");

    // A later version is not what was gone back from.
    let mut m = b.manifest("2.0.1");
    m["components"][COMPONENT][PLATFORM]["sha256"] = json!(sha(NEW));
    b.publish(&m);
    notice::run_check(&b.updater(), true);
    assert_eq!(fs::read(&b.exe).unwrap(), NEW);
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
