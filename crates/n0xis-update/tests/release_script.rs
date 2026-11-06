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

/// `--publish` itself cannot be run here, so its runner is faked and the commands it builds are read.
/// The defect: it pushed to `origin`, which this repository does not have, so it tagged locally and died
/// halfway through a publish.
#[test]
fn publishing_pushes_only_the_tag_to_the_named_address() {
    let bench = Bench::new("pushes");
    let out = bench.out();
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("n0xis-linux-x86_64"), b"a file").unwrap();
    let script = r#"
import json, pathlib, sys
sys.path.insert(0, sys.argv[1])
import release
calls = []
release.run = lambda *cmd, **kw: calls.append(list(cmd))
release.release_notes = lambda version: "notes"
class Answer:
    stdout, returncode = "", 1
release.subprocess.run = lambda *a, **kw: Answer()
release.publish("v9.9.9", "9.9.9", pathlib.Path(sys.argv[2]))
print(json.dumps(calls))
"#;
    let output = Command::new("python3").arg("-c").arg(script).arg(root().join("scripts")).arg(&out).output().expect("python");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let printed = String::from_utf8_lossy(&output.stdout);
    let calls: Vec<Vec<String>> = serde_json::from_str(printed.lines().last().unwrap_or("")).expect("the commands");
    let pushes: Vec<&Vec<String>> = calls.iter().filter(|c| c[..2] == ["git", "push"]).collect();
    assert_eq!(pushes.len(), 1, "{calls:?}");
    assert_eq!(pushes[0][2..], ["git@github.com:Structio-labs/N0xis.git", "refs/tags/v9.9.9"]);
}

/// A checkout of its own with the script in it, so that every refusal below is a real run of the real
/// script with real `git`, reaching the commands it would run: `cargo`, `gh` and `wine` are planted on
/// its `PATH`, and the tag goes to a bare repository, by `git`'s own redirection of the frozen address.
struct Repo {
    root: PathBuf,
    fakes: PathBuf,
    key: PathBuf,
}

const REPO_VERSION: &str = "1.2.3";
const OLD_TAG: &str = "v1.2.2";
const TAG: &str = "v1.2.3";

fn trust_source(key: &str) -> String {
    format!("pub const RELEASE_PUBLIC_KEY: &str = \"{key}\";\n")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_program(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

impl Repo {
    /// With `key`'s public half built in, at HEAD. Nothing is tagged.
    fn new(name: &str, built: &Bench) -> Repo {
        let bench = built.dir.join(format!("repo-{name}"));
        let root = bench.join("work");
        let fakes = bench.join("fakes");
        fs::create_dir_all(root.join("scripts")).unwrap();
        fs::create_dir_all(root.join("crates/n0xis-update/src")).unwrap();
        fs::create_dir_all(&fakes).unwrap();
        fs::copy(self::root().join("scripts/release.py"), root.join("scripts/release.py")).unwrap();
        fs::write(root.join("Cargo.toml"), format!("[workspace.package]\nversion = \"{REPO_VERSION}\"\n")).unwrap();
        fs::write(root.join("CHANGELOG.md"), format!("## [{REPO_VERSION}]\n\nA release.\n")).unwrap();
        fs::write(root.join(".gitignore"), "target/\n").unwrap();
        fs::write(root.join("crates/n0xis-update/src/trust.rs"), trust_source(&hex(&built.public()))).unwrap();
        let repo = Repo { root, fakes, key: built.key() };
        // Everything the script reaches by name, and nothing else: so that "no wine on the path" is true
        // once `no_wine` has said so, whatever this machine has.
        for tool in ["git", "openssl", "sh", "rm", "mkdir"] {
            let found = Command::new("sh").args(["-c", &format!("command -v {tool}")]).output().expect("sh");
            let found = String::from_utf8_lossy(&found.stdout).trim().to_string();
            std::os::unix::fs::symlink(found, repo.fakes.join(tool)).unwrap();
        }
        write_program(&repo.fakes.join("cargo"), &format!("#!/bin/sh\nif [ \"$1\" = metadata ]; then printf '{{\"target_directory\":\"{}/target\"}}'; fi\n", repo.root.display()));
        write_program(&repo.fakes.join("gh"), &format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> {0}/gh.log\ncase \"$1 $2\" in\n\"release view\") . {0}/gh-view ;;\n\"release create\") . {0}/gh-create ;;\nesac\nexit 0\n", bench.display()));
        fs::write(bench.join("gh-view"), "echo release not found >&2; exit 1\n").unwrap();
        fs::write(bench.join("gh-create"), "exit 0\n").unwrap();
        repo.built(REPO_VERSION, REPO_VERSION);
        repo.wine();
        repo.git(&["init", "-q", "-b", "main"]);
        repo.commit("first");
        let bare = bench.join("remote.git");
        let made = Command::new("git").args(["init", "-q", "--bare"]).arg(&bare).output().unwrap();
        assert!(made.status.success());
        repo.git(&["config", &format!("url.{}.insteadOf", bare.display()), "git@github.com:Structio-labs/N0xis.git"]);
        repo
    }

    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git").args(["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "core.hooksPath=/dev/null"]).args(args).current_dir(&self.root).output().expect("git");
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn commit(&self, what: &str) {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "-m", what, "--allow-empty"]);
    }

    /// What `cargo build` is taken to have left: programs stating these versions, where cargo says.
    fn built(&self, host: &str, windows: &str) {
        let target = self.root.join("target");
        for (dir, name, says) in [("release", "n0xis", host), ("release", "n0xis-mcp", host), ("x86_64-pc-windows-gnu/release", "n0xis.exe", windows), ("x86_64-pc-windows-gnu/release", "n0xis-mcp.exe", windows)] {
            write_program(&target.join(dir).join(name), &format!("#!/bin/sh\necho n0xis {says}\n"));
        }
    }

    fn wine(&self) {
        write_program(&self.fakes.join("wine"), "#!/bin/sh\nexec \"$@\"\n");
    }

    fn no_wine(&self) {
        fs::remove_file(self.fakes.join("wine")).unwrap();
    }

    /// One of the four, answering as `says`, after `built`: (target directory, file name).
    fn built_file(&self, file: (&str, &str), says: &str) {
        write_program(&self.root.join("target").join(file.0).join(file.1), &format!("#!/bin/sh\necho n0xis {says}\n"));
    }

    fn gh_log(&self) -> String {
        fs::read_to_string(self.root.parent().unwrap().join("gh.log")).unwrap_or_default()
    }

    fn gh(&self, step: &str, script: &str) {
        fs::write(self.root.parent().unwrap().join(format!("gh-{step}")), script).unwrap();
    }

    fn run(&self, extra: &[&str]) -> Output {
        let python = String::from_utf8_lossy(&Command::new("sh").args(["-c", "command -v python3"]).output().unwrap().stdout).trim().to_string();
        Command::new(python)
            .arg(self.root.join("scripts/release.py"))
            .args(["--tag", TAG, "--key"])
            .arg(&self.key)
            .args(extra)
            .current_dir(&self.root)
            .env("PATH", &self.fakes)
            .env("N0XIS_RELEASE_SCOPED", "1")
            .env_remove("CARGO_TARGET_DIR")
            .output()
            .expect("python3")
    }

    /// The release before this one, whose binary holds `key`, and HEAD one commit on at this source.
    fn previous_release_holds(&self, key: &str) {
        let now = self.root.join("crates/n0xis-update/src/trust.rs");
        let source = fs::read_to_string(&now).unwrap();
        fs::write(&now, trust_source(key)).unwrap();
        self.commit("the previous release");
        self.git(&["tag", OLD_TAG]);
        fs::write(&now, source).unwrap();
        self.commit("this one");
    }

    fn remote_tags(&self) -> String {
        let bare = self.root.parent().unwrap().join("remote.git");
        let out = Command::new("git").args(["tag", "--list"]).current_dir(bare).output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }
}

/// The calibration of everything below: with nothing wrong, a real run gets all the way.
#[test]
fn a_real_run_publishes_and_says_which_binaries_ran() {
    let b = Bench::new("ok");
    let repo = Repo::new("ok", &b);
    let out = repo.run(&["--publish"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}{stdout}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("--version: n0xis 1.2.3") && stdout.contains("ran wine "), "{stdout}");
    assert_eq!(repo.remote_tags(), TAG);
    let log = repo.gh_log();
    assert!(log.contains("release create v1.2.3") && log.contains("release edit v1.2.3 --repo Structio-labs/N0xis --draft=false --latest"), "{log}");
}

#[test]
fn the_target_directory_is_where_cargo_says() {
    let b = Bench::new("targetdir");
    let repo = Repo::new("targetdir", &b);
    // A stale tree where a guess would look, with cargo pointing elsewhere.
    let elsewhere = repo.root.parent().unwrap().join("moved");
    fs::rename(repo.root.join("target"), &elsewhere).unwrap();
    write_program(&repo.root.join("target/release/n0xis"), "#!/bin/sh\necho n0xis 0.0.1\n");
    write_program(&repo.fakes.join("cargo"), &format!("#!/bin/sh\nif [ \"$1\" = metadata ]; then printf '{{\"target_directory\":\"{}\"}}'; fi\n", elsewhere.display()));
    let out = repo.run(&[]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains(elsewhere.to_str().unwrap()));
}

#[test]
fn a_host_binary_that_does_not_state_this_version_is_refused() {
    let b = Bench::new("stalehost");
    let repo = Repo::new("stalehost", &b);
    repo.built("1.2.2", REPO_VERSION);
    refused(&repo.run(&["--publish"]), "this release is 1.2.3");
    assert_eq!(repo.git(&["tag", "--list"]), "", "a refusal tagged");
    assert_eq!(repo.gh_log(), "");
}

#[test]
fn a_windows_binary_that_does_not_state_this_version_is_refused_when_wine_can_run_it() {
    let b = Bench::new("stalewin");
    let repo = Repo::new("stalewin", &b);
    repo.built(REPO_VERSION, "1.2.2");
    repo.no_wine();
    // With no wine it cannot be run, and it says so rather than passing it.
    let out = repo.run(&[]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("NOT RUN"), "{}", String::from_utf8_lossy(&out.stdout));
    repo.wine();
    refused(&repo.run(&[]), "this release is 1.2.3");
}

/// Only `n0xis` and `n0xis.exe` were run once, so a release with a dead server or a dead Windows server
/// went out with its manifest signed. Each of the four, alone, stops a publish and a dry run.
#[test]
fn each_of_the_four_built_files_must_state_this_version() {
    for file in [("release", "n0xis"), ("release", "n0xis-mcp"), ("x86_64-pc-windows-gnu/release", "n0xis.exe"), ("x86_64-pc-windows-gnu/release", "n0xis-mcp.exe")] {
        let b = Bench::new(&format!("four-{}", file.1));
        let repo = Repo::new("four", &b);
        repo.built_file(file, "1.2.2");
        let path = repo.root.join("target").join(file.0).join(file.1);
        let out = repo.run(&["--publish"]);
        refused(&out, &format!("{} --version said", path.display()));
        assert_eq!(repo.remote_tags(), "", "{}: a refusal pushed", file.1);
        assert_eq!(repo.gh_log(), "", "{}", file.1);
        refused(&repo.run(&[]), &format!("{} --version said", path.display()));
    }
}

/// A dry run may say a file was not run. A publish may not go on past that, whatever the host files said.
#[test]
fn a_file_that_could_not_be_run_stops_a_publish() {
    let b = Bench::new("nowine");
    let repo = Repo::new("nowine", &b);
    repo.no_wine();
    let out = repo.run(&["--publish"]);
    refused(&out, "no wine on the path");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("NOT RUN"), "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(repo.remote_tags(), "", "a refusal pushed");
    assert_eq!(repo.git(&["tag", "--list"]), "", "a refusal tagged");
    assert_eq!(repo.gh_log(), "");

    // A file that is not there to start is the same refusal, and so is one that does not start.
    let b = Bench::new("noperm");
    let repo = Repo::new("noperm", &b);
    fs::remove_file(repo.root.join("target/release/n0xis-mcp")).unwrap();
    refused(&repo.run(&["--publish"]), "did not answer --version");
    assert_eq!(repo.remote_tags(), "");
}

/// With standard input held open by whoever runs the script, and a bound brought down to a second: the
/// file below answers only if its standard input is null, and the other never does.
#[test]
fn a_built_file_runs_with_null_stdin_and_a_bound() {
    let b = Bench::new("bound");
    let reads = b.dir.join("reads");
    write_program(&reads, "#!/bin/sh\nread line\necho n0xis 1.2.3\n");
    let hangs = b.dir.join("hangs");
    write_program(&hangs, "#!/bin/sh\nsleep 20\n");
    let script = r#"
import sys
sys.path.insert(0, sys.argv[1])
import release
release.RUN_BOUND = 1
print(release.states_version(sys.argv[2], "1.2.3"))
"#;
    let run = |program: &Path| {
        let mut child = Command::new("python3")
            .arg("-c")
            .arg(script)
            .arg(root().join("scripts"))
            .arg(program)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("python3");
        // Held to the end: a child that inherited this waits on it.
        let held = child.stdin.take();
        let out = child.wait_with_output().expect("output");
        drop(held);
        out
    };
    let out = run(&reads);
    assert!(out.status.success() && String::from_utf8_lossy(&out.stdout).contains("n0xis 1.2.3"), "{}", String::from_utf8_lossy(&out.stderr));
    let start = std::time::Instant::now();
    refused(&run(&hangs), "did not answer --version");
    assert!(start.elapsed() < std::time::Duration::from_secs(10), "{:?}", start.elapsed());
}

#[test]
fn a_change_of_key_that_strands_older_copies_is_refused() {
    let b = Bench::new("strand");
    let older = Bench::new("strand-older");
    let repo = Repo::new("strand", &b);
    repo.previous_release_holds(&hex(&older.public()));
    let out = repo.run(&["--publish"]);
    refused(&out, "--strand-older-copies");
    assert_eq!(repo.remote_tags(), "", "a refusal pushed");

    // A dry run says the same and writes the release.
    let dry = repo.run(&[]);
    assert!(dry.status.success());
    assert!(String::from_utf8_lossy(&dry.stdout).contains("NOT PUBLISHABLE"), "{}", String::from_utf8_lossy(&dry.stdout));

    // Signed by both, nothing is stranded.
    let both = repo.run(&["--key", older.key().to_str().unwrap(), "--publish"]);
    assert!(both.status.success(), "{}", String::from_utf8_lossy(&both.stderr));
    assert_eq!(repo.remote_tags(), TAG);
}

#[test]
fn stranding_older_copies_can_be_said_to_be_meant() {
    let b = Bench::new("meant");
    let older = Bench::new("meant-older");
    let repo = Repo::new("meant", &b);
    repo.previous_release_holds(&hex(&older.public()));
    let out = repo.run(&["--strand-older-copies", "--publish"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn a_placeholder_or_no_file_at_the_previous_tag_is_no_constraint() {
    let b = Bench::new("noconstraint");
    let repo = Repo::new("noconstraint", &b);
    repo.previous_release_holds("PLACEHOLDER: the release public key goes here");
    let out = repo.run(&["--publish"]);
    assert!(out.status.success(), "a placeholder: {}", String::from_utf8_lossy(&out.stderr));

    let b = Bench::new("nofile");
    let repo = Repo::new("nofile", &b);
    let source = repo.root.join("crates/n0xis-update/src/trust.rs");
    let text = fs::read_to_string(&source).unwrap();
    fs::remove_file(&source).unwrap();
    repo.commit("before the client existed");
    repo.git(&["tag", OLD_TAG]);
    fs::write(&source, text).unwrap();
    repo.commit("this one");
    let out = repo.run(&["--publish"]);
    assert!(out.status.success(), "no such file: {}", String::from_utf8_lossy(&out.stderr));
}

/// A failed upload after the push: the commands that recover are printed, and they are what works.
#[test]
fn a_failed_upload_prints_the_way_back_and_a_re_run_finishes() {
    let b = Bench::new("recover");
    let repo = Repo::new("recover", &b);
    repo.gh("create", "echo the network went away >&2; exit 1\n");
    let out = repo.run(&["--publish"]);
    refused(&out, "gh release create v1.2.3");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("scripts/release.py --tag v1.2.3 --key") && stderr.contains("--publish"), "{stderr}");
    assert!(stderr.contains(":refs/tags/v1.2.3") && stderr.contains("git tag -d v1.2.3"), "{stderr}");
    assert_eq!(repo.remote_tags(), TAG, "the state this is about");

    // The tag exists, at HEAD, and no release does.
    repo.gh("create", "exit 0\n");
    let again = repo.run(&["--publish"]);
    assert!(again.status.success(), "{}", String::from_utf8_lossy(&again.stderr));
    assert!(repo.gh_log().lines().filter(|l| l.starts_with("release edit")).count() == 1);

    // A draft left over is finished by uploading over it, and not by creating a second.
    let b = Bench::new("recover-draft");
    let repo = Repo::new("draft", &b);
    repo.git(&["tag", TAG]);
    repo.gh("view", "echo '{\"isDraft\":true}'; exit 0\n");
    let out = repo.run(&["--publish"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let log = repo.gh_log();
    assert!(log.contains("release upload v1.2.3") && log.contains("--clobber") && !log.contains("release create"), "{log}");
}

#[test]
fn a_tag_elsewhere_or_already_published_is_refused() {
    let b = Bench::new("tagged");
    let repo = Repo::new("tagged", &b);
    repo.git(&["tag", TAG]);
    repo.commit("past the tag");
    refused(&repo.run(&["--publish"]), "that is not HEAD");

    let b = Bench::new("published");
    let repo = Repo::new("published", &b);
    repo.git(&["tag", TAG]);
    repo.gh("view", "echo '{\"isDraft\":false}'; exit 0\n");
    refused(&repo.run(&["--publish"]), "already published");

    // A gh that cannot say is not a gh that said no.
    let b = Bench::new("unknown");
    let repo = Repo::new("unknown", &b);
    repo.git(&["tag", TAG]);
    repo.gh("view", "echo token invalid >&2; exit 1\n");
    refused(&repo.run(&["--publish"]), "cannot tell whether");
    assert_eq!(repo.remote_tags(), "");
}
