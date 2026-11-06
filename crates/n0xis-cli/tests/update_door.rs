// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The real binary and what a script can see of the update path (docs/design/UPDATE.md §1).
//!
//! No test here reaches the network, and that has to be arranged, since the real binary goes on to
//! its two frozen addresses after any other. Every child is pointed at a proxy in this process, by
//! the environment any user's proxy is set with. So the proxy sees each connection the binary tries,
//! wherever it was going, passes on only those to the loopback, and refuses the rest.
//!
//! What this cannot show is a manifest being accepted: this binary holds the release key or the
//! placeholder, and a test holds neither's private half. That is `n0xis-update/tests/planted.rs`, and
//! `scripts/update_e2e.py` with a build made for it.

#[path = "../../n0xis-update/tests/support/mod.rs"]
mod planted;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use planted::{Reply, Server};
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_n0xis");

/// A forward proxy that records every `CONNECT` and tunnels only to the loopback.
struct Proxy {
    port: u16,
    targets: Arc<Mutex<Vec<String>>>,
}

impl Proxy {
    fn start() -> Proxy {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let targets = Arc::new(Mutex::new(Vec::new()));
        let seen = targets.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let seen = seen.clone();
                std::thread::spawn(move || tunnel(stream, &seen));
            }
        });
        Proxy { port, targets }
    }

    fn asked(&self) -> Vec<String> {
        self.targets.lock().unwrap().clone()
    }

    /// Wait for at least `n` connection attempts, or as long as a detached check could take.
    fn wait_for(&self, n: usize) -> Vec<String> {
        let start = Instant::now();
        while self.asked().len() < n && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        self.asked()
    }
}

fn tunnel(stream: TcpStream, seen: &Mutex<Vec<String>>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut first = String::new();
    if reader.read_line(&mut first).is_err() {
        return;
    }
    let target = first.split_whitespace().nth(1).unwrap_or("").to_string();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
    }
    seen.lock().unwrap().push(target.clone());
    let mut client = stream;
    let up = if target.starts_with("127.0.0.1:") { TcpStream::connect(&target).ok() } else { None };
    let Some(up) = up else {
        let _ = client.write_all(b"HTTP/1.1 502 Not in a test\r\nContent-Length: 0\r\n\r\n");
        return;
    };
    let _ = client.write_all(b"HTTP/1.1 200 Connected\r\n\r\n");
    let (mut a, mut b) = (client.try_clone().expect("clone"), up.try_clone().expect("clone"));
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut a, &mut b);
    });
    let (mut up, mut client) = (up, client);
    let _ = std::io::copy(&mut up, &mut client);
    let _ = client.shutdown(std::net::Shutdown::Both);
}

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Scene {
    config: PathBuf,
    proxy: Proxy,
    server: Server,
    ca_file: PathBuf,
    root: PathBuf,
}

impl Scene {
    fn new(name: &str) -> Scene {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("door-{}-{name}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let _ = std::fs::remove_dir_all(&root);
        let config = root.join("config");
        std::fs::create_dir_all(&config).unwrap();
        let server = Server::start();
        let ca_file = root.join("ca.pem");
        std::fs::write(&ca_file, &server.ca_pem).unwrap();
        Scene { config, proxy: Proxy::start(), server, ca_file, root }
    }

    /// The command, with nothing of the machine's own proxy or settings in it.
    fn command(&self, exe: &Path, args: &[&str]) -> Command {
        let mut c = Command::new(exe);
        c.args(args)
            .env("N0X_CONFIG_DIR", &self.config)
            .env("HTTPS_PROXY", format!("http://127.0.0.1:{}", self.proxy.port))
            .env("SSL_CERT_FILE", &self.ca_file)
            .env_remove("ALL_PROXY")
            .env_remove("HTTP_PROXY")
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .env_remove("N0X_NO_UPDATE_CHECK")
            .stdin(Stdio::null());
        c
    }

    fn piped(&self, args: &[&str]) -> Output {
        self.command(Path::new(BIN), args).output().expect("run")
    }

    fn plant_state(&self, state: Value) {
        std::fs::write(self.config.join("update-state.json"), state.to_string()).unwrap();
    }

    fn set(&self, key: &str, value: &str) {
        let out = self.piped(&["config", "set", key, value]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    }

    fn ever_checked(&self) -> bool {
        self.config.join("update-check.stamp").exists()
    }
}

/// Running a file this process just wrote. Another test's spawn can be holding the writable handle
/// for the instant between its fork and its exec, and the exec then fails with "text file busy".
fn output_of_a_fresh_copy(mut command: Command) -> Output {
    let start = Instant::now();
    loop {
        match command.output() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && start.elapsed() < Duration::from_secs(10) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            other => return other.expect("run"),
        }
    }
}

fn envelope(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("not an envelope ({e}): {}", String::from_utf8_lossy(&out.stdout)))
}

const NOTICE: &str = "[n0x] 99.0.0 is available: n0x update";

/// Any command that answers quickly and always the same: the line must not change it.
const A_COMMAND: &[&str] = &["guide", "update"];

#[test]
fn in_a_pipe_there_is_no_request_no_line_and_nothing_is_read() {
    let s = Scene::new("pipe");
    s.plant_state(json!({ "latest": "99.0.0" }));
    let out = s.piped(A_COMMAND);
    assert!(out.status.success());
    assert!(!String::from_utf8_lossy(&out.stderr).contains("[n0x]"), "a line in a pipe");
    assert!(!String::from_utf8_lossy(&out.stdout).contains(NOTICE));
    assert!(!s.ever_checked(), "a pipe claimed the daily check");
    // Long enough for a detached check to have reached the proxy, as the terminal test sees it do.
    std::thread::sleep(Duration::from_millis(800));
    assert_eq!(s.proxy.asked(), Vec::<String>::new(), "a request was made from a pipe");
}

#[test]
fn stderr_joined_to_stdout_is_a_pipe_like_any_other() {
    let s = Scene::new("joined");
    s.plant_state(json!({ "latest": "99.0.0" }));
    // The shape of `2>&1`: both into one file, which is what a scheduler's log is.
    let log = s.root.join("log");
    let file = std::fs::File::create(&log).unwrap();
    let status = s.command(Path::new(BIN), A_COMMAND).stdout(file.try_clone().unwrap()).stderr(file).status().unwrap();
    assert!(status.success());
    let text = std::fs::read_to_string(&log).unwrap();
    serde_json::from_str::<Value>(&text).expect("the file is the envelope and nothing else");
    assert!(!s.ever_checked());
    assert_eq!(s.proxy.asked(), Vec::<String>::new());
}

#[test]
fn the_background_copy_is_silent_and_writes_what_it_learned() {
    let s = Scene::new("background");
    let out = s.piped(&["__update-check"]);
    assert!(out.status.success());
    assert!(out.stdout.is_empty() && out.stderr.is_empty(), "the copy has no one to talk to");
    let state: Value = serde_json::from_slice(&std::fs::read(s.config.join("update-state.json")).unwrap()).unwrap();
    assert_eq!(state["refusal"], json!("manifest-unavailable"));
    assert_eq!(state["latest"], Value::Null);
}

#[test]
fn the_real_binary_asks_its_override_then_the_frozen_addresses_in_order() {
    let s = Scene::new("order");
    s.set("update.manifest_url", &s.server.url("/manifest.json"));
    let out = s.piped(&["update", "--check"]);
    let answer = envelope(&out);
    assert_eq!(answer["ok"], json!(false));
    assert_eq!(answer["error"]["code"], json!("manifest-unavailable"));
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        s.proxy.asked(),
        [format!("127.0.0.1:{}", s.server.port), "updates.structio.dev:443".to_string(), "github.com:443".to_string()],
        "the addresses are the one thing a shipped client is frozen to"
    );
}

/// This binary holds the placeholder or the real key. Either way a manifest signed by no key it holds
/// goes no further, and the file on disk stays as it was. Which of the two codes is the state of the
/// constant, and each is its own refusal.
#[test]
fn a_manifest_this_build_cannot_verify_installs_nothing() {
    let s = Scene::new("unverified");
    let body = json!({ "version": "99.0.0", "components": {} }).to_string().into_bytes();
    s.server.route("/manifest.json", Reply::Body(body));
    s.server.route("/manifest.json.sig", Reply::Body("00".repeat(64).into_bytes()));
    s.set("update.manifest_url", &s.server.url("/manifest.json"));

    let dir = s.root.join("bin");
    std::fs::create_dir_all(&dir).unwrap();
    let exe = dir.join(Path::new(BIN).file_name().unwrap());
    std::fs::copy(BIN, &exe).unwrap();
    let before = std::fs::read(&exe).unwrap();
    for args in [&["update", "--check"][..], &["update"][..]] {
        let out = output_of_a_fresh_copy(s.command(&exe, args));
        let answer = envelope(&out);
        let code = answer["error"]["code"].as_str().expect("a refusal");
        assert!(["no-release-key", "bad-signature"].contains(&code), "{answer}");
        assert_eq!(out.status.code(), Some(2));
    }
    assert!(std::fs::read(&exe).unwrap() == before, "the file on disk changed");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "something was left beside the binary");
}

#[test]
fn rollback_with_nothing_kept_refuses_and_needs_no_network() {
    let s = Scene::new("norollback");
    let dir = s.root.join("bin");
    std::fs::create_dir_all(&dir).unwrap();
    let exe = dir.join(Path::new(BIN).file_name().unwrap());
    std::fs::copy(BIN, &exe).unwrap();
    let out = output_of_a_fresh_copy(s.command(&exe, &["update", "--rollback"]));
    assert_eq!(envelope(&out)["error"]["code"], json!("no-previous"));
    assert_eq!(s.proxy.asked(), Vec::<String>::new());
}

#[test]
fn check_and_rollback_cannot_be_asked_together() {
    let s = Scene::new("both");
    let out = s.piped(&["update", "--check", "--rollback"]);
    assert_eq!(envelope(&out)["error"]["code"], json!("bad-arguments"));
}

#[test]
fn config_answers_in_the_envelope_and_keeps_the_setting() {
    let s = Scene::new("config");
    let read = envelope(&s.piped(&["config", "get", "update.check"]));
    assert_eq!(read["data"]["settings"][0]["value"], json!(true));
    assert_eq!(read["meta"]["schema"], json!("n0xis.config.v1"));
    s.set("update.check", "false");
    let read = envelope(&s.piped(&["config", "get", "update.check"]));
    assert_eq!(read["data"]["settings"][0]["value"], json!(false));
    assert_eq!(read["data"]["settings"][0]["set"], json!(true));
    assert_eq!(envelope(&s.piped(&["config", "set", "update.nope", "1"]))["error"]["code"], json!("unknown-setting"));
    let on_disk: Value = serde_json::from_slice(&std::fs::read(s.config.join("config.json")).unwrap()).unwrap();
    assert_eq!(on_disk["update.check"], json!(false));
}

/// Standard error on a real terminal is the one thing a pipe cannot stand in for.
#[cfg(unix)]
mod on_a_terminal {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::thread::JoinHandle;

    use super::*;

    struct Run {
        output: Output,
        stderr: String,
        elapsed: Duration,
    }

    /// Run with standard error on a new terminal and standard output on a pipe, reading both to their
    /// end. Reading a pipe to its end means every process holding it has let go, the detached copy
    /// included, which is what a script's `$(...)` waits for.
    fn run(mut command: Command) -> Run {
        let (mut master, mut slave) = (-1, -1);
        let made = unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), std::ptr::null()) };
        assert_eq!(made, 0, "openpty");
        // Close-on-exec, so no child of a test running beside this one keeps this terminal open.
        unsafe {
            libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(slave, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        let reader: JoinHandle<String> = std::thread::spawn(move || {
            let mut file = std::fs::File::from(master);
            let mut bytes = Vec::new();
            // A terminal's far end closing reads as an error here rather than an end of file.
            let _ = file.read_to_end(&mut bytes);
            String::from_utf8_lossy(&bytes).into_owned()
        });
        let start = Instant::now();
        let child = command.stdout(Stdio::piped()).stderr(Stdio::from(slave)).spawn().expect("spawn");
        let output = child.wait_with_output().expect("wait");
        let elapsed = start.elapsed();
        // The child's copy of the terminal is gone now, and so is this process's, moved into the spawn.
        drop(command);
        Run { output, stderr: reader.join().unwrap(), elapsed }
    }

    #[test]
    fn the_line_is_on_standard_error_once_a_day_and_changes_nothing_else() {
        let s = Scene::new("line");
        s.plant_state(json!({ "latest": "99.0.0" }));
        let plain = s.piped(A_COMMAND);

        let first = run(s.command(Path::new(BIN), A_COMMAND));
        assert_eq!(first.stderr.trim_end(), NOTICE, "exactly the one line");
        assert_eq!(first.output.stdout, plain.stdout, "standard output changed");
        assert_eq!(first.output.status.code(), plain.status.code(), "the exit code changed");

        let second = run(s.command(Path::new(BIN), A_COMMAND));
        assert_eq!(second.stderr, "", "more than once a day");

        // The day passes.
        std::fs::remove_file(s.config.join("update-notice.stamp")).unwrap();
        let third = run(s.command(Path::new(BIN), A_COMMAND));
        assert_eq!(third.stderr.trim_end(), NOTICE);
    }

    #[test]
    fn a_failing_command_exits_the_same_with_the_line_or_without_it() {
        let s = Scene::new("failing");
        s.plant_state(json!({ "latest": "99.0.0" }));
        let args = &["strings", "--file", "/nonexistent/file"];
        let plain = s.piped(args);
        assert_eq!(plain.status.code(), Some(2), "the calibration: this command does fail");
        let on_terminal = run(s.command(Path::new(BIN), args));
        assert_eq!(on_terminal.stderr.trim_end(), NOTICE);
        assert_eq!(on_terminal.output.status.code(), plain.status.code());
        assert_eq!(on_terminal.output.stdout, plain.stdout);
    }

    #[test]
    fn quiet_silences_it_and_starts_no_check() {
        let s = Scene::new("quiet");
        s.plant_state(json!({ "latest": "99.0.0" }));
        let mut args = A_COMMAND.to_vec();
        args.push("--quiet");
        let quiet = run(s.command(Path::new(BIN), &args));
        assert_eq!(quiet.stderr, "");
        assert!(!s.ever_checked());
    }

    #[test]
    fn each_way_of_turning_it_off_turns_off_the_line_and_the_request() {
        let s = Scene::new("off");
        s.plant_state(json!({ "latest": "99.0.0" }));
        let mut by_environment = s.command(Path::new(BIN), A_COMMAND);
        by_environment.env("N0X_NO_UPDATE_CHECK", "1");
        assert_eq!(run(by_environment).stderr, "", "the environment");

        s.set("update.check", "false");
        assert_eq!(run(s.command(Path::new(BIN), A_COMMAND)).stderr, "", "the setting");

        std::fs::write(s.config.join("config.json"), "{ damaged").unwrap();
        assert_eq!(run(s.command(Path::new(BIN), A_COMMAND)).stderr, "", "a damaged file may be one that turned it off");

        assert!(!s.ever_checked());
        assert_eq!(s.proxy.asked(), Vec::<String>::new());
    }

    #[test]
    fn neither_help_nor_version_nor_the_update_commands_say_it() {
        let s = Scene::new("exempt");
        s.plant_state(json!({ "latest": "99.0.0" }));
        for args in [&["--version"][..], &["--help"][..], &["config", "get"][..], &["update", "--rollback"][..]] {
            assert_eq!(run(s.command(Path::new(BIN), args)).stderr, "", "{args:?}");
        }
    }

    /// The calibration of the pipe tests above: from a terminal, the same scene does make the request.
    #[test]
    fn the_terminal_starts_one_check_a_day_in_the_background() {
        let s = Scene::new("daily");
        run(s.command(Path::new(BIN), A_COMMAND));
        // The dead end at the proxy leaves the override out, so two: both frozen addresses.
        let asked = s.proxy.wait_for(2);
        assert_eq!(asked, ["updates.structio.dev:443", "github.com:443"]);
        // The copy writes the state last; once it has, a second run must not start another.
        let start = Instant::now();
        while !s.config.join("update-state.json").exists() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        run(s.command(Path::new(BIN), A_COMMAND));
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(s.proxy.asked().len(), 2, "a second check on the same day");
    }

    /// A server that never answers: the command is not slower for it, and standard output closes.
    #[test]
    fn a_hung_address_delays_nothing_and_holds_no_pipe_open() {
        let s = Scene::new("hung");
        s.server.route("/manifest.json", Reply::Silent);
        s.set("update.manifest_url", &s.server.url("/manifest.json"));
        let plain = s.piped(A_COMMAND);
        let start = Instant::now();
        let hung = run(s.command(Path::new(BIN), A_COMMAND));
        assert_eq!(hung.output.stdout, plain.stdout);
        assert!(hung.elapsed < Duration::from_secs(5), "{:?} while the check hangs", hung.elapsed);
        // The check really was hanging while the command returned.
        let asked = s.proxy.wait_for(1);
        assert_eq!(asked, [format!("127.0.0.1:{}", s.server.port)], "after {:?}", start.elapsed());
        assert!(!s.config.join("update-state.json").exists(), "the copy finished, so this showed nothing about a hang");
    }

    /// A handle the script left open past the three standard ones, as `3>some-pipe` does, is inherited
    /// by a child unless it closes it. The copy must not keep the far end of such a pipe open while it
    /// waits on the network, or whoever reads that pipe waits with it.
    #[test]
    fn the_copy_lets_go_of_what_it_inherited() {
        let s = Scene::new("inherited");
        s.server.route("/manifest.json", Reply::Silent);
        s.set("update.manifest_url", &s.server.url("/manifest.json"));
        let mut ends = [-1, -1];
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        let (read_end, write_end) = unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
        // The read end is this process's own, and only the write end goes on to the child.
        unsafe { libc::fcntl(ends[0], libc::F_SETFD, libc::FD_CLOEXEC) };
        run(s.command(Path::new(BIN), A_COMMAND));
        assert_eq!(s.proxy.wait_for(1).len(), 1, "the calibration: the copy is out there, hanging");
        drop(write_end);
        let start = Instant::now();
        let mut rest = Vec::new();
        std::fs::File::from(read_end).read_to_end(&mut rest).unwrap();
        assert!(start.elapsed() < Duration::from_secs(5), "the pipe stayed open for {:?}", start.elapsed());
    }

    #[test]
    fn what_update_auto_installed_is_said_once_by_the_binary_that_was_installed() {
        let s = Scene::new("installed");
        let version = env!("CARGO_PKG_VERSION");
        s.plant_state(json!({ "installed": { "from": "0.0.1", "to": version } }));
        let first = run(s.command(Path::new(BIN), A_COMMAND));
        assert_eq!(first.stderr.trim_end(), format!("[n0x] {version} was installed in place of 0.0.1: n0x update --rollback goes back"));
        assert_eq!(run(s.command(Path::new(BIN), A_COMMAND)).stderr, "");

        let other = Scene::new("installed-other");
        other.plant_state(json!({ "installed": { "from": "0.0.1", "to": "99.0.0" } }));
        assert_eq!(run(other.command(Path::new(BIN), A_COMMAND)).stderr, "", "a run of the old file says nothing of what it is not");
    }
}
