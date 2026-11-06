// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `scripts/release.py`, with what signs not being what verifies: openssl signs, the client's own
//! check reads the result. Only on Unix, where `python3` and `openssl` are named that on every runner.
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use n0xis_update::{Manifest, Trust};
use ring::digest::{SHA256, digest};

/// The names v0.3.7 published and the README's links rest on.
const ASSETS: [&str; 4] = ["n0xis-linux-x86_64", "n0xis-mcp-linux-x86_64", "n0xis-mcp-windows-x86_64.exe", "n0xis-windows-x86_64.exe"];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn version() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

struct Bench {
    dir: PathBuf,
}

impl Bench {
    fn new(name: &str) -> Bench {
        let dir = std::env::temp_dir().join(format!("n0xis-release-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("prebuilt")).unwrap();
        for asset in ASSETS {
            fs::write(dir.join("prebuilt").join(asset), format!("the planted contents of {asset}")).unwrap();
        }
        let key = dir.join("release.pem");
        let made = Command::new("openssl").args(["genpkey", "-algorithm", "ed25519", "-out"]).arg(&key).output().expect("openssl");
        assert!(made.status.success());
        Bench { dir }
    }

    fn key(&self) -> PathBuf {
        self.dir.join("release.pem")
    }

    fn public(&self) -> [u8; 32] {
        let der = Command::new("openssl").args(["pkey", "-pubout", "-outform", "DER", "-in"]).arg(self.key()).output().expect("openssl").stdout;
        der[der.len() - 32..].try_into().unwrap()
    }

    fn out(&self) -> PathBuf {
        self.dir.join("out")
    }

    fn release(&self, tag: &str, extra: &[&str]) -> Output {
        Command::new("python3")
            .arg(root().join("scripts/release.py"))
            .args(["--tag", tag, "--prebuilt"])
            .arg(self.dir.join("prebuilt"))
            .arg("--out")
            .arg(self.out())
            .args(extra)
            .output()
            .expect("python3")
    }
}

fn refused(out: &Output, says: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "should have been refused: {}", String::from_utf8_lossy(&out.stdout));
    assert!(stderr.contains(says), "{stderr}");
}

#[test]
fn a_dry_run_writes_a_release_the_client_accepts() {
    let b = Bench::new("dry");
    let key = b.key();
    let out = b.release(&version(), &["--key", key.to_str().unwrap()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("nothing was tagged or uploaded"));

    let dist = b.out();
    let manifest = fs::read(dist.join("manifest.json")).unwrap();
    let signature = fs::read(dist.join("manifest.json.sig")).unwrap();
    Trust::of_keys(&[b.public()]).verify(&manifest, &signature).expect("the client's check accepts what openssl signed");
    Trust::of_keys(&[[9u8; 32]]).verify(&manifest, &signature).expect_err("and no other key's");

    let parsed = Manifest::parse(&manifest).unwrap();
    assert_eq!(format!("v{}", parsed.version), version());
    for (component, platform, asset, installed) in [
        ("n0xis", "linux-x86_64", ASSETS[0], "n0xis"),
        ("n0xis-mcp", "linux-x86_64", ASSETS[1], "n0xis-mcp"),
        ("n0xis-mcp", "windows-x86_64", ASSETS[2], "n0xis-mcp.exe"),
        ("n0xis", "windows-x86_64", ASSETS[3], "n0xis.exe"),
    ] {
        let entry = parsed.entry(component, platform).expect("an entry");
        let bytes = fs::read(dist.join(asset)).unwrap();
        assert_eq!(entry.size, bytes.len() as u64);
        assert_eq!(entry.sha256.as_slice(), digest(&SHA256, &bytes).as_ref());
        assert_eq!(entry.url, format!("https://github.com/Structio-labs/N0xis/releases/download/{}/{asset}", version()));
        assert_eq!(entry.file.as_deref(), Some(installed));
    }
    let sums = fs::read_to_string(dist.join("sha256sums.txt")).unwrap();
    assert_eq!(sums.lines().count(), 4);
    for asset in ASSETS {
        assert!(sums.contains(&format!("  {asset}\n")), "{sums}");
    }
    // The README's check, by the tool it names.
    let checked = Command::new("sha256sum").args(["-c", "sha256sums.txt"]).current_dir(&dist).output().expect("sha256sum");
    assert!(checked.status.success());
}

#[test]
fn the_readme_links_a_name_that_stays_published() {
    let readme = fs::read_to_string(root().join("README.md")).unwrap();
    assert!(readme.contains(&format!("releases/latest/download/{}", ASSETS[0])));
}

#[test]
fn a_tag_that_is_not_the_workspace_version_is_refused() {
    let b = Bench::new("tag");
    refused(&b.release("v0.0.1-not-this", &[]), "is not the workspace version");
    assert!(!b.out().exists(), "a refused release wrote something");
}

#[test]
fn a_key_inside_the_repository_is_refused() {
    let b = Bench::new("inrepo");
    // The script looks at where the path resolves, so this file need not exist for the refusal to
    // be about the place; and nothing is created in the repository.
    let inside = root().join("release.pem");
    refused(&b.release(&version(), &["--key", inside.to_str().unwrap()]), "inside the repository");
}

#[test]
fn publishing_refuses_prebuilt_files_and_a_key_the_binary_does_not_hold() {
    let b = Bench::new("publish");
    let key = b.key();
    let key = key.to_str().unwrap();
    // Nothing past these refusals runs, so no tag or upload can come of this test.
    refused(&b.release(&version(), &["--key", key, "--publish"]), "a published release is built here");
    let without_prebuilt = Command::new("python3")
        .arg(root().join("scripts/release.py"))
        .args(["--tag", &version(), "--key", key, "--publish"])
        .output()
        .expect("python3");
    refused(&without_prebuilt, "no --key is that key");
    let without_key = Command::new("python3").arg(root().join("scripts/release.py")).args(["--tag", &version(), "--publish"]).output().expect("python3");
    refused(&without_key, "--publish needs a --key");
}

#[test]
fn a_next_key_is_signed_into_the_manifest() {
    let b = Bench::new("next");
    let key = b.key();
    let next = "ab".repeat(32);
    let out = b.release(&version(), &["--key", key.to_str().unwrap(), "--next-key", &next]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let parsed = Manifest::parse(&fs::read(b.out().join("manifest.json")).unwrap()).unwrap();
    assert_eq!(parsed.next_key, Some([0xab; 32]));
}

#[test]
fn two_keys_sign_on_two_lines_and_either_verifies() {
    let b = Bench::new("two");
    let second = Bench::new("two-second");
    let (one, two) = (b.key(), second.key());
    let out = b.release(&version(), &["--key", one.to_str().unwrap(), "--key", two.to_str().unwrap()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let manifest = fs::read(b.out().join("manifest.json")).unwrap();
    let signature = fs::read(b.out().join("manifest.json.sig")).unwrap();
    assert_eq!(String::from_utf8_lossy(&signature).lines().count(), 2);
    Trust::of_keys(&[b.public()]).verify(&manifest, &signature).expect("the old key");
    Trust::of_keys(&[second.public()]).verify(&manifest, &signature).expect("the new key");
}
