// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A breakpoint outlives no run unaccounted for.** `debug await-hit` plants a `0xCC`
//! in the target's code. Interrupted, it used to die with the byte in place, and the
//! target died at its next pass over it. Now a signal restores the byte and detaches,
//! and a `SIGKILL`, which nothing can handle, leaves a journal record that `patch
//! undo` restores from.
//!
//! The target is its own oracle: `/proc/<pid>/mem` for the byte, and whether it
//! survives running the planted site, which it does only when told.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde_json::Value;

mod support;

/// Prints the address of `site`, and calls it each time a line arrives, printing `ran`.
const TARGET_SRC: &str = r#"
use std::io::{BufRead, Write};
const PR_SET_PTRACER: i32 = 0x59616d61;
unsafe extern "C" { fn prctl(o: i32, a: u64, b: u64, c: u64, d: u64) -> i32; }
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn site(x: u64) -> u64 { std::hint::black_box(x).wrapping_mul(3) }
fn main() {
    // Any process may trace this one, under any Yama scope.
    unsafe { prctl(PR_SET_PTRACER, u64::MAX, 0, 0, 0) };
    println!("{:#x}", site as extern "C" fn(u64) -> u64 as usize);
    std::io::stdout().flush().unwrap();
    for line in std::io::stdin().lock().lines() {
        line.unwrap();
        println!("ran {}", site(14));
        std::io::stdout().flush().unwrap();
    }
}
"#;

fn target_exe() -> &'static Path {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("n0xis-breakpoint-build-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("build dir");
        let src = dir.join("target.rs");
        let exe = dir.join("target");
        std::fs::write(&src, TARGET_SRC).expect("write the target");
        let out = Command::new("rustc").args(["-O", "--edition", "2024", "-o"]).arg(&exe).arg(&src).output().expect("invoke rustc");
        assert!(out.status.success(), "rustc failed on the target:\n{}", String::from_utf8_lossy(&out.stderr));
        exe
    })
}

struct Target {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    pid: u32,
    site: u64,
    original: u8,
    dir: PathBuf,
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Target {
    fn spawn(name: &str) -> Target {
        let dir = std::env::temp_dir().join(format!("n0xis-breakpoint-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".n0x")).expect("a project of its own");
        let mut child = Command::new(target_exe()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("run the target");
        let stdin = child.stdin.take().expect("stdin");
        let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        stdout.read_line(&mut line).expect("the target's address");
        let site = u64::from_str_radix(line.trim().trim_start_matches("0x"), 16).expect("an address");
        let pid = child.id();
        let mut t = Target { child, stdin, stdout, pid, site, original: 0, dir };
        t.original = t.byte();
        assert_ne!(t.original, 0xCC, "calibration: the site starts as code");
        t
    }

    fn byte(&self) -> u8 {
        let mem = std::fs::File::open(format!("/proc/{}/mem", self.pid)).expect("open the target's memory");
        let mut b = [0u8];
        mem.read_exact_at(&mut b, self.site).expect("read the site");
        b[0]
    }

    /// Have the target run the site. Whether it lived through that, by its own print.
    fn pass_over_the_site(&mut self) -> bool {
        writeln!(self.stdin, "go").expect("tell the target");
        self.stdin.flush().expect("flush");
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap_or(0) > 0 && line.trim() == "ran 42"
    }

    fn engine(&self, args: &[&str]) -> (Value, i32) {
        let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).current_dir(&self.dir).output().expect("run n0xis");
        (serde_json::from_slice(&out.stdout).unwrap_or(Value::Null), out.status.code().unwrap_or(-1))
    }

    /// `debug await-hit` on the site, with the byte seen in place by `/proc`.
    fn armed_engine(&self) -> Child {
        let site = format!("{:#x}", self.site);
        let pid = self.pid.to_string();
        let args = ["debug", "await-hit", "--pid", &pid, "--addr", &site, "--timeout-ms", "60000"];
        let tool = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
            .args(args)
            .current_dir(&self.dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("run n0xis");
        let start = Instant::now();
        while self.byte() != 0xCC {
            assert!(start.elapsed() < Duration::from_secs(20), "the breakpoint never landed");
            std::thread::sleep(Duration::from_millis(5));
        }
        tool
    }

    fn records(&self) -> usize {
        std::fs::read_dir(self.dir.join(".n0x/patches")).map_or(0, |d| d.count())
    }

    fn tracer(&self) -> Option<i64> {
        let s = std::fs::read_to_string(format!("/proc/{}/status", self.pid)).ok()?;
        s.lines().find_map(|l| l.strip_prefix("TracerPid:").and_then(|v| v.trim().parse().ok()))
    }
}

fn signal(pid: u32, sig: libc::c_int) {
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, sig) }, 0, "signal the engine");
}

fn signal_restores_and_detaches(name: &str, sig: libc::c_int) {
    let mut t = Target::spawn(name);
    let tool = t.armed_engine();
    assert_eq!(t.records(), 1, "{name}: the byte is on record while it is in the target");
    signal(tool.id(), sig);
    let out = tool.wait_with_output().expect("the engine ends");
    let answer: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    assert_eq!(answer["error"]["code"], "interrupted", "{name}: {answer}");
    assert_eq!(t.byte(), t.original, "{name}: the byte is back");
    assert_eq!(t.tracer(), Some(0), "{name}: the target is not traced");
    assert_eq!(t.records(), 0, "{name}: nothing is left to undo");
    assert!(t.pass_over_the_site(), "{name}: the target runs the site");
}

#[test]
fn sigint_restores_the_byte_and_detaches() {
    signal_restores_and_detaches("int", libc::SIGINT);
}

#[test]
fn sigterm_restores_the_byte_and_detaches() {
    signal_restores_and_detaches("term", libc::SIGTERM);
}

#[test]
fn sighup_restores_the_byte_and_detaches() {
    signal_restores_and_detaches("hup", libc::SIGHUP);
}

#[test]
fn a_killed_run_leaves_a_record_and_patch_undo_restores_the_byte() {
    let mut t = Target::spawn("kill");
    let mut tool = t.armed_engine();
    tool.kill().expect("SIGKILL");
    tool.wait().expect("reap");
    assert_eq!(t.byte(), 0xCC, "calibration: a kill can restore nothing");
    let (listed, _) = t.engine(&["patch", "list", "--status", "applied"]);
    let shown = listed.to_string();
    assert!(shown.contains("debug await-hit"), "the journal names who planted it: {listed}");
    let (undone, rc) = t.engine(&["patch", "undo"]);
    assert_eq!(rc, 0, "{undone}");
    assert_eq!(t.byte(), t.original, "the byte is back");
    assert!(t.pass_over_the_site(), "the target runs the site");
}

/// What `patch undo` is for: this is the death the record exists to prevent, and the
/// test above means nothing if the target would have lived anyway.
#[test]
fn without_the_undo_the_killed_runs_byte_kills_the_target() {
    let mut t = Target::spawn("death");
    let mut tool = t.armed_engine();
    tool.kill().expect("SIGKILL");
    tool.wait().expect("reap");
    assert!(!t.pass_over_the_site(), "a 0xCC with no debugger ends the target");
}

#[test]
fn a_run_that_ends_by_itself_leaves_no_record() {
    let mut t = Target::spawn("timeout");
    let site = format!("{:#x}", t.site);
    let pid = t.pid.to_string();
    let (a, rc) = t.engine(&["debug", "await-hit", "--pid", &pid, "--addr", &site, "--timeout-ms", "200"]);
    assert_eq!(rc, 0, "{a}");
    assert_eq!(a["data"]["timed_out"], true, "{a}");
    assert_eq!(t.records(), 0, "a timeout leaves nothing to undo");
    let (listed, _) = t.engine(&["patch", "list"]);
    assert!(!listed.to_string().contains("await-hit"), "{listed}");
    assert!(t.pass_over_the_site());
}

#[test]
fn a_journal_that_cannot_be_written_means_no_byte_is_written() {
    use std::os::unix::fs::PermissionsExt;
    let t = Target::spawn("readonly");
    let patches = t.dir.join(".n0x/patches");
    std::fs::create_dir_all(&patches).expect("the journal's directory");
    std::fs::set_permissions(&patches, std::fs::Permissions::from_mode(0o500)).expect("read-only");
    // Running as root writes anyway, and this asks nothing of that case.
    let writable = std::fs::write(patches.join("probe"), b"x").is_ok();
    let site = format!("{:#x}", t.site);
    let pid = t.pid.to_string();
    if !writable {
        let (a, rc) = t.engine(&["debug", "await-hit", "--pid", &pid, "--addr", &site, "--timeout-ms", "300"]);
        assert_ne!(rc, 0, "{a}");
        assert!(a["error"]["message"].as_str().unwrap_or("").contains("nothing was written"), "{a}");
        assert_eq!(t.byte(), t.original);
    }
    std::fs::set_permissions(&patches, std::fs::Permissions::from_mode(0o700)).expect("back");
}
