// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A backtrace through a call that does not return is the real one.** After such a
//! call, a compiler puts nothing: the return address is the first byte of the next
//! function, and its unwind rule is that function's. `stack backtrace` looked the rule up
//! there and printed a made-up `{rip: 0x801000}`, in no mapping, then stopped at 5 frames
//! where gdb gave 8 (audit 2026-11-06, row 8). Everything that called `exit`, `abort` or
//! a failed `assert` unwound that way.
//!
//! The layout is fixed in assembly, so no compiler decides it: `n0x_deep2` sets up a
//! frame on `rbp` and ends in a call, and `n0x_after` follows it at once with a rule of
//! its own. The oracle is the target, which prints where its functions are, and
//! `/proc/<pid>/maps`.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde_json::Value;

mod support;

const TARGET_SRC: &str = r#"
use std::io::Write;
const PR_SET_PTRACER: i32 = 0x59616d61;
unsafe extern "C" {
    fn prctl(o: i32, a: u64, b: u64, c: u64, d: u64) -> i32;
    fn n0x_deep2() -> !;
    fn n0x_after();
}
std::arch::global_asm!(
    ".text",
    ".globl n0x_deep2",
    ".type n0x_deep2,@function",
    "n0x_deep2:",
    ".cfi_startproc",
    "push rbp",
    ".cfi_def_cfa_offset 16",
    ".cfi_offset rbp, -16",
    "mov rbp, rsp",
    ".cfi_def_cfa_register rbp",
    "call n0x_wait_forever",
    ".cfi_endproc",
    ".size n0x_deep2, .-n0x_deep2",
    ".globl n0x_after",
    ".type n0x_after,@function",
    "n0x_after:",
    ".cfi_startproc",
    "sub rsp, 0x28",
    ".cfi_def_cfa_offset 0x30",
    "add rsp, 0x28",
    ".cfi_def_cfa_offset 8",
    "ret",
    ".cfi_endproc",
    ".size n0x_after, .-n0x_after",
);
#[unsafe(no_mangle)]
pub extern "C" fn n0x_wait_forever() -> ! {
    loop { std::thread::sleep(std::time::Duration::from_secs(1)); }
}
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn n0x_deep1() { unsafe { n0x_deep2() } }
fn main() {
    unsafe { prctl(PR_SET_PTRACER, u64::MAX, 0, 0, 0) };
    if std::env::args().count() > 99 { unsafe { n0x_after() } }
    let t = std::thread::spawn(|| { n0x_deep1(); });
    println!("{:#x} {:#x} {:#x} {:#x}", n0x_deep2 as usize, n0x_after as usize, n0x_deep1 as usize, n0x_wait_forever as usize);
    std::io::stdout().flush().unwrap();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    drop(t);
}
"#;

fn target_exe() -> &'static Path {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("n0xis-noreturn-build-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("build dir");
        let src = dir.join("target.rs");
        let exe = dir.join("target");
        std::fs::write(&src, TARGET_SRC).expect("write the target");
        let out = Command::new("rustc").args(["-O", "--edition", "2024", "-o"]).arg(&exe).arg(&src).output().expect("invoke rustc");
        assert!(out.status.success(), "rustc failed on the target:\n{}", String::from_utf8_lossy(&out.stderr));
        exe
    })
}

struct Target(Child);

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn mapped(pid: u32, addr: u64) -> bool {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).expect("maps");
    maps.lines().any(|l| {
        let (lo, hi) = l.split_whitespace().next().unwrap().split_once('-').unwrap();
        u64::from_str_radix(lo, 16).unwrap() <= addr && addr < u64::from_str_radix(hi, 16).unwrap()
    })
}

fn hex(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap_or("").trim_start_matches("0x"), 16).unwrap_or_else(|_| panic!("not an address: {v}"))
}

#[test]
fn the_walk_goes_on_past_a_call_that_ends_its_function() {
    let mut child = Command::new(target_exe()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("run the target");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let pid = child.id();
    let _target = Target(child);
    let mut line = String::new();
    stdout.read_line(&mut line).expect("the target's addresses");
    let a: Vec<u64> = line.split_whitespace().map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).expect("an address")).collect();
    let (deep2, after, deep1) = (a[0], a[1], a[2]);
    // The layout the test is about: deep2's call is its last byte, and `after` is next.
    assert!(after > deep2 && after - deep2 <= 16, "deep2 {deep2:#x}, after {after:#x}");

    let start = Instant::now();
    let (answer, thread) = loop {
        let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
            .args(["stack", "backtrace", "--pid", &pid.to_string(), "--all-threads"])
            .output()
            .expect("run n0xis");
        let answer: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("no JSON: {}", String::from_utf8_lossy(&out.stderr)));
        // The thread is in deep2's callee once a frame of it returns to `after`.
        let found = answer["data"]["threads"].as_array().into_iter().flatten().find(|t| t["frames"].as_array().into_iter().flatten().any(|f| hex(&f["rip"]) == after)).cloned();
        if let Some(t) = found {
            break (answer, t);
        }
        assert!(start.elapsed() < Duration::from_secs(20), "no thread reached deep2: {answer}");
        std::thread::sleep(Duration::from_millis(50));
    };
    let rips: Vec<u64> = thread["frames"].as_array().unwrap().iter().map(|f| hex(&f["rip"])).collect();
    let at = rips.iter().position(|&r| r == after).unwrap();
    // The frame after deep2's is deep1's, at the byte after its call to deep2.
    let next = *rips.get(at + 1).unwrap_or_else(|| panic!("the walk stopped at deep2's frame: {rips:x?}"));
    assert!(next > deep1 && next < deep1 + 0x40, "deep1 is at {deep1:#x}, the frame after deep2's is {next:#x}: {rips:x?}");
    // And it goes on, to the thread's start, through nothing made up.
    assert!(rips.len() >= at + 3, "{rips:x?}");
    for r in &rips {
        assert!(mapped(pid, *r), "{r:#x} is in no mapping: {rips:x?}");
    }
    assert_eq!(answer["data"]["threads_in_process"], 2, "{answer}");
}

/// Without `--all-threads` one thread is walked, and the answer says the process has two.
#[test]
fn a_backtrace_of_one_thread_says_how_many_the_process_has() {
    let mut child = Command::new(target_exe()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("run the target");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let pid = child.id();
    let _target = Target(child);
    let mut line = String::new();
    stdout.read_line(&mut line).expect("the target's addresses");
    let tasks = std::fs::read_dir(format!("/proc/{pid}/task")).expect("/proc").count();
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(["stack", "backtrace", "--pid", &pid.to_string()]).output().expect("run n0xis");
    let answer: Value = serde_json::from_slice(&out.stdout).expect("JSON");
    assert_eq!(answer["data"]["thread_count"], 1, "{answer}");
    assert_eq!(answer["data"]["threads_in_process"], tasks, "the kernel's count: {answer}");
}
