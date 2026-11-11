// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A wait says why it ended.** `debug await-hit` and `debug watch` answered
//! `timed_out: true` whenever they came back without a hit (audit 2026-11-06, row 11):
//! for a target `SIGKILL`ed 0.7 s into a 3 s wait, for a watch on an address no mapping
//! holds, and for a site that ran 569 times inside an `--exclude-rip` range, with no
//! count of what was set aside. Each of those is a statement about the program that the
//! loop's way out made, and each was false.
//!
//! The oracles are not the engine's: the kill is this test's own, `/proc/<pid>/maps`
//! says what is mapped, and the count of writes is the target's own counter, read
//! through `/proc/<pid>/mem`.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde_json::Value;

mod support;

/// Prints the address of a cell a thread writes about every millisecond, of the count of
/// those writes, of a cell nothing writes, and of a function nothing calls. Then waits.
const TARGET_SRC: &str = r#"
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
const PR_SET_PTRACER: i32 = 0x59616d61;
unsafe extern "C" { fn prctl(o: i32, a: u64, b: u64, c: u64, d: u64) -> i32; }
static CELL: AtomicU64 = AtomicU64::new(0);
static WRITES: AtomicU64 = AtomicU64::new(0);
static QUIET: AtomicU64 = AtomicU64::new(0);
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn never_called(x: u64) -> u64 { std::hint::black_box(x).wrapping_mul(3) }
fn main() {
    unsafe { prctl(PR_SET_PTRACER, u64::MAX, 0, 0, 0) };
    let _ = QUIET.load(Ordering::SeqCst);
    std::thread::spawn(|| loop {
        // The count first: a write the watch sees is always one counted.
        WRITES.fetch_add(1, Ordering::SeqCst);
        CELL.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(1));
    });
    println!("{:#x} {:#x} {:#x} {:#x}", &CELL as *const _ as usize, &WRITES as *const _ as usize, &QUIET as *const _ as usize,
        never_called as extern "C" fn(u64) -> u64 as usize);
    std::io::stdout().flush().unwrap();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    if std::env::args().count() > 99 { never_called(1); }
}
"#;

fn target_exe() -> &'static Path {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("n0xis-wait-build-{}", std::process::id()));
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
    pid: u32,
    cell: u64,
    writes: u64,
    quiet: u64,
    never_called: u64,
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
        let dir = std::env::temp_dir().join(format!("n0xis-wait-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".n0x")).expect("a project of its own");
        let mut child = Command::new(target_exe()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("run the target");
        let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        stdout.read_line(&mut line).expect("the target's addresses");
        let a: Vec<u64> = line.split_whitespace().map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).expect("an address")).collect();
        let pid = child.id();
        Target { child, pid, cell: a[0], writes: a[1], quiet: a[2], never_called: a[3], dir }
    }

    /// The target's own count of its writes to the cell, read through the kernel.
    fn writes(&self) -> u64 {
        let mem = std::fs::File::open(format!("/proc/{}/mem", self.pid)).expect("open the target's memory");
        let mut b = [0u8; 8];
        mem.read_exact_at(&mut b, self.writes).expect("read the count");
        u64::from_le_bytes(b)
    }

    /// Whether `/proc/<pid>/maps` has a mapping holding `addr`.
    fn mapped(&self, addr: u64) -> bool {
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", self.pid)).expect("maps");
        maps.lines().any(|l| {
            let range = l.split_whitespace().next().unwrap();
            let (lo, hi) = range.split_once('-').unwrap();
            let (lo, hi) = (u64::from_str_radix(lo, 16).unwrap(), u64::from_str_radix(hi, 16).unwrap());
            lo <= addr && addr < hi
        })
    }

    fn engine(&self, args: &[&str]) -> Command {
        let mut cmd = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")));
        cmd.args(args).args(["--pid", &self.pid.to_string()]).current_dir(&self.dir);
        cmd
    }

    fn answer(&self, args: &[&str]) -> Value {
        let out = self.engine(args).output().expect("run n0xis");
        serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("no JSON: {}", String::from_utf8_lossy(&out.stderr)))
    }

    /// The engine waiting with `args`, the target killed 500 ms in.
    fn killed_while_waiting(mut self, args: &[&str]) -> Value {
        let tool = self.engine(args).args(["--timeout-ms", "20000"]).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("run n0xis");
        // The journal's record is written once the engine is attached, before it arms.
        let start = Instant::now();
        while std::fs::read_dir(self.dir.join(".n0x/patches")).map_or(true, |mut d| d.next().is_none()) {
            assert!(start.elapsed() < Duration::from_secs(20), "the engine never attached");
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(500));
        self.child.kill().expect("kill the target");
        let out = tool.wait_with_output().expect("the engine's answer");
        let _ = self.child.wait();
        assert!(start.elapsed() < Duration::from_secs(15), "the engine waited for its deadline on a target that was gone");
        serde_json::from_slice(&out.stdout).expect("JSON")
    }
}

/// The deadline, and nothing else, is `timed_out`: the same wait with the target left
/// alone says it, so the other answers below are not a wait that cannot time out.
#[test]
fn a_wait_that_reaches_its_deadline_says_so() {
    let t = Target::spawn("deadline");
    let a = t.answer(&["debug", "await-hit", "--addr", &format!("{:#x}", t.never_called), "--timeout-ms", "300"]);
    assert_eq!(a["data"]["timed_out"], true, "{a}");
    assert_eq!(a["data"]["ended"], "timed-out", "{a}");
}

#[test]
fn a_target_killed_during_await_hit_is_gone_not_timed_out() {
    let t = Target::spawn("kill-hit");
    let addr = format!("{:#x}", t.never_called);
    let a = t.killed_while_waiting(&["debug", "await-hit", "--addr", &addr]);
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["data"]["ended"], "target-exited", "{a}");
    assert_eq!(a["data"]["timed_out"], false, "{a}");
}

#[test]
fn a_target_killed_during_a_watch_is_gone_not_timed_out() {
    let t = Target::spawn("kill-watch");
    let addr = format!("{:#x}", t.quiet);
    let a = t.killed_while_waiting(&["debug", "watch", "--addr", &addr, "--kind", "write", "--len", "8"]);
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["data"]["ended"], "target-exited", "{a}");
    assert_eq!(a["data"]["timed_out"], false, "{a}");
}

/// What `debug await-hit` refuses, `debug watch` refuses too, and arms nothing.
#[test]
fn a_watch_on_an_address_no_mapping_holds_is_refused() {
    let t = Target::spawn("unmapped");
    assert!(!t.mapped(0x10), "the oracle must see 0x10 unmapped");
    let a = t.answer(&["debug", "watch", "--addr", "0x10", "--kind", "write", "--len", "8", "--timeout-ms", "300"]);
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"]["code"], "bad-addr", "{a}");
    assert!(a["error"]["message"].as_str().unwrap_or("").contains("no mapping"), "{a}");
    let left = std::fs::read_dir(t.dir.join(".n0x/patches")).map_or(0, |d| d.count());
    assert_eq!(left, 0, "nothing was armed, so nothing is on the record");
    // The same address mapped is armed and waited on: the refusal is of the address.
    let quiet = format!("{:#x}", t.quiet);
    assert!(t.mapped(t.quiet));
    let a = t.answer(&["debug", "watch", "--addr", &quiet, "--kind", "write", "--len", "8", "--timeout-ms", "300"]);
    assert_eq!(a["data"]["ended"], "timed-out", "{a}");
}

/// Every hit set aside by `--exclude-rip` is counted, and the count is no more than the
/// writes the target made while it was watched.
#[test]
fn hits_set_aside_by_exclude_rip_are_counted() {
    let t = Target::spawn("exclude");
    let cell = format!("{:#x}", t.cell);
    let before = t.writes();
    let a = t.answer(&["debug", "watch", "--addr", &cell, "--kind", "write", "--len", "8", "--timeout-ms", "1500", "--exclude-rip", "0x1-0xffffffffffffffff"]);
    let after = t.writes();
    assert_eq!(a["data"]["ended"], "timed-out", "{a}");
    assert_eq!(a["data"]["timed_out"], true, "{a}");
    let excluded = a["data"]["excluded_hits"].as_u64().unwrap_or_else(|| panic!("no count of what was set aside: {a}"));
    assert!(excluded > 0, "the target wrote {} times while watched: {a}", after - before);
    assert!(excluded <= after - before, "{excluded} hits set aside of {} writes: {a}", after - before);
    // With no range given, no count is stated: it would be a count of nothing.
    let a = t.answer(&["debug", "watch", "--addr", &format!("{:#x}", t.quiet), "--kind", "write", "--len", "8", "--timeout-ms", "200"]);
    assert!(a["data"].get("excluded_hits").is_none(), "{a}");
}
