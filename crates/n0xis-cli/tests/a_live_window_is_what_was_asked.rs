// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A window on a live target is what was asked for, and the answer says when it
//! was not all there.** Two defects, one report: `--size` without `--start` was
//! ignored and the whole process scanned; and a window spanning a read-only mapping
//! then a writable one read only the writable part, with `regions_not_read: 0`, so
//! a pattern in the rest was missed in silence.
//!
//! A disposable target plants one reservation in a known order, with a pattern in
//! each mapping that reads, and prints the addresses:
//!
//! ```text
//! page 0   r--p   pattern 0x4D
//! page 1   rw-p   pattern 0x5E
//! page 2   ---p   no read permission
//! page 3   (unmapped)
//! page 4   r--p   pattern 0x6F
//! ```
//!
//! Which addresses read is checked with the kernel's own `process_vm_readv` before
//! anything measured on them is believed. Linux-only and run as `live_memory_exit`
//! is: built with `rustc`, and the target grants the reading itself.
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::OnceLock;

use serde_json::Value;

mod support;

const TARGET_SRC: &str = r##"
use std::io::{BufRead, Write};

const PROT_NONE: i32 = 0;
const PROT_READ: i32 = 1;
const PROT_READ_WRITE: i32 = 3;
const MAP_PRIVATE_ANON: i32 = 0x22;
const SC_PAGESIZE: i32 = 30;
const PR_SET_PTRACER: i32 = 0x59616d61;

unsafe extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn mprotect(addr: *mut u8, len: usize, prot: i32) -> i32;
    fn munmap(addr: *mut u8, len: usize) -> i32;
    fn prctl(o: i32, a: u64, b: u64, c: u64, d: u64) -> i32;
    fn sysconf(name: i32) -> i64;
}

fn plant(at: *mut u8, seed: u8) {
    for i in 0..16usize {
        unsafe { at.add(i).write_volatile(seed ^ (i as u8).wrapping_mul(37)) };
    }
}

fn main() {
    unsafe { prctl(PR_SET_PTRACER, u64::MAX, 0, 0, 0) };
    let page = unsafe { sysconf(SC_PAGESIZE) } as usize;
    let base = unsafe { mmap(std::ptr::null_mut(), 5 * page, PROT_READ_WRITE, MAP_PRIVATE_ANON, -1, 0) };
    assert!(base as isize != -1, "mmap failed");
    let at = |n: usize| unsafe { base.add(n * page) };
    plant(at(0), 0x4D);
    plant(at(1), 0x5E);
    plant(at(4), 0x6F);
    unsafe {
        assert_eq!(mprotect(at(0), page, PROT_READ), 0);
        assert_eq!(mprotect(at(2), page, PROT_NONE), 0);
        assert_eq!(munmap(at(3), page), 0);
        assert_eq!(mprotect(at(4), page, PROT_READ), 0);
    }
    let mut out = std::io::stdout().lock();
    writeln!(out, "page={page:#x}").unwrap();
    writeln!(out, "base={:#x}", base as usize).unwrap();
    writeln!(out, "ready").unwrap();
    out.flush().unwrap();
    for _ in std::io::stdin().lock().lines() {}
}
"##;

/// The planted bytes, as the target computes them.
fn pattern(seed: u8) -> String {
    (0..16u32).map(|i| format!("{:02x}", seed ^ (i as u8).wrapping_mul(37))).collect::<Vec<_>>().join(" ")
}

fn target_exe() -> &'static Path {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("n0xis-window-build-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("build dir");
        let (src, exe) = (dir.join("target.rs"), dir.join("target"));
        std::fs::write(&src, TARGET_SRC).expect("write the target");
        let out = Command::new("rustc").args(["-O", "-o"]).arg(&exe).arg(&src).output().expect("invoke rustc (it built this crate, so it is on PATH)");
        assert!(out.status.success(), "rustc failed on the target:\n{}", String::from_utf8_lossy(&out.stderr));
        exe
    })
}

struct Target {
    child: Child,
    _stdin: ChildStdin,
    pid: u32,
    at: HashMap<String, u64>,
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
    fn spawn() -> Target {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("n0xis-window-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".n0x")).expect("scratch dir");
        let mut child = Command::new(target_exe()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("spawn the target");
        let stdin = child.stdin.take().expect("piped stdin");
        let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut at = HashMap::new();
        loop {
            let mut line = String::new();
            assert!(stdout.read_line(&mut line).expect("read the target") > 0, "the target ended before it was ready");
            let line = line.trim();
            if line == "ready" {
                break;
            }
            let (k, v) = line.split_once('=').expect("name=value");
            at.insert(k.to_string(), u64::from_str_radix(v.trim_start_matches("0x"), 16).expect("hex"));
        }
        let pid = child.id();
        Target { child, _stdin: stdin, pid, at, dir }
    }

    fn page(&self) -> u64 {
        self.at["page"]
    }

    /// The address of page `n` of the reservation.
    fn at(&self, n: u64) -> u64 {
        self.at["base"] + n * self.page()
    }

    fn n0x(&self, args: &[&str]) -> Value {
        let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).current_dir(&self.dir).output().expect("run n0xis");
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("n0xis {args:?} did not print one JSON object: {e}\n{}", String::from_utf8_lossy(&out.stdout)))
    }

    fn pid_arg(&self) -> String {
        self.pid.to_string()
    }
}

/// `--start` alone was refused and `--size` alone ignored. Neither is a window.
#[test]
fn half_a_window_is_refused_whichever_half() {
    let t = Target::spawn();
    let pid = t.pid_arg();
    let start = format!("{:#x}", t.at(1));
    let pat = pattern(0x5E);
    for (half, says) in [(["--size", "256"], "start"), (["--start", start.as_str()], "size")] {
        let mut args = vec!["scan", "aob", "--pid", pid.as_str(), "--pattern", pat.as_str()];
        args.extend_from_slice(&half);
        let v = t.n0x(&args);
        assert_eq!(v["ok"], false, "{half:?} answered: {}", v["data"]);
        assert_eq!(v["error"]["code"], "bad-region", "{v}");
        let message = v["error"]["message"].as_str().expect("a message");
        assert!(message.contains(says), "{half:?}: it names what is missing: {message}");
    }
    // Every scanner that takes a live window goes through the same answer.
    let v = t.n0x(&["scan", "value", "--pid", &pid, "--size", "256", "--type", "u8", "--value", "1", "--save-as", "s"]);
    assert_eq!(v["error"]["code"], "bad-region", "{v}");
    let v = t.n0x(&["scan", "group", "--pid", &pid, "--size", "256", "--field", "u8=1"]);
    assert_eq!(v["error"]["code"], "bad-region", "{v}");
    let v = t.n0x(&["lua", "strings", "--pid", &pid, "--size", "256"]);
    assert_eq!(v["error"]["code"], "bad-region", "{v}");
    // Neither half is the default set, which still answers.
    let v = t.n0x(&["scan", "aob", "--pid", &pid, "--pattern", &pat]);
    assert_eq!(v["ok"], true, "{v}");
}

fn addrs(list: &Value) -> Vec<u64> {
    list.as_array().unwrap_or_else(|| panic!("a list, got {list}")).iter().map(|m| hex_of(m.as_str().expect("an address"))).collect()
}

fn hex_of(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex")
}

impl Target {
    fn ok(&self, args: &[&str]) -> Value {
        let v = self.n0x(args);
        assert_eq!(v["ok"], true, "n0xis {args:?} failed: {}", v["error"]);
        v["data"].clone()
    }

    /// A scan of `size` bytes from page `from`, for pattern `seed`.
    fn window(&self, from: u64, size: u64, seed: u8) -> Value {
        self.ok(&["scan", "aob", "--pid", &self.pid_arg(), "--start", &format!("{:#x}", self.at(from)), "--size", &size.to_string(), "--pattern", &pattern(seed)])
    }

    /// What the kernel itself answers to `process_vm_readv` at page `n`: the bytes
    /// it gave, or the errno.
    fn kernel_read(&self, n: u64) -> Result<usize, i32> {
        #[repr(C)]
        struct IoVec {
            base: *mut u8,
            len: usize,
        }
        unsafe extern "C" {
            fn process_vm_readv(pid: i32, local: *const IoVec, lc: u64, remote: *const IoVec, rc: u64, flags: u64) -> isize;
        }
        let len = self.page() as usize;
        let mut buf = vec![0u8; len];
        let local = IoVec { base: buf.as_mut_ptr(), len };
        let remote = IoVec { base: self.at(n) as *mut u8, len };
        let got = unsafe { process_vm_readv(self.pid as i32, &local, 1, &remote, 1, 0) };
        if got < 0 { Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)) } else { Ok(got as usize) }
    }

    /// The layout the header promises, from the kernel, before anything is measured.
    fn assert_fixture_holds(&self) {
        const EFAULT: i32 = 14;
        let page = self.page() as usize;
        assert_eq!(self.kernel_read(0), Ok(page), "page 0 reads");
        assert_eq!(self.kernel_read(1), Ok(page), "page 1 reads");
        assert_eq!(self.kernel_read(2), Err(EFAULT), "page 2 has no read permission");
        assert_eq!(self.kernel_read(3), Err(EFAULT), "page 3 is not mapped");
        assert_eq!(self.kernel_read(4), Ok(page), "page 4 reads");
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", self.pid)).expect("read maps");
        let perms = |n: u64| {
            let start = format!("{:x}-", self.at(n));
            maps.lines().find(|l| l.starts_with(&start)).and_then(|l| l.split_whitespace().nth(1)).map(str::to_string)
        };
        assert_eq!(perms(0).as_deref(), Some("r--p"), "{maps}");
        assert_eq!(perms(1).as_deref(), Some("rw-p"), "{maps}");
    }
}

/// The reported case: the pattern in the read-only half was missed in silence.
#[test]
fn a_window_over_read_only_then_writable_reads_both() {
    let t = Target::spawn();
    t.assert_fixture_holds();
    let page = t.page();

    let d = t.window(0, 2 * page, 0x4D);
    assert_eq!(addrs(&d["matches"]), [t.at(0)], "the pattern in the read-only page: {d}");
    assert_eq!(d["bytes_scanned"], 2 * page, "{d}");
    assert_eq!(d["regions_scanned"], 2, "{d}");
    assert_eq!(d["regions_not_read"], 0, "{d}");

    let d = t.window(0, 2 * page, 0x5E);
    assert_eq!(addrs(&d["matches"]), [t.at(1)], "the pattern in the writable page: {d}");
}

/// Every part of the window is read or stated, and what reads past a gap is reached.
#[test]
fn a_window_states_its_gaps_and_unreadable_parts() {
    let t = Target::spawn();
    t.assert_fixture_holds();
    let page = t.page();
    let d = t.window(0, 5 * page, 0x6F);
    assert_eq!(addrs(&d["matches"]), [t.at(4)], "past the gap: {d}");
    assert_eq!(d["bytes_scanned"], 3 * page, "{d}");
    assert_eq!(d["regions_scanned"], 3, "{d}");
    assert_eq!(d["regions_not_read"], 2, "{d}");
    let not_read = &d["not_read"];
    assert_eq!(hex_of(not_read[0]["start"].as_str().expect("a start")), t.at(2), "{d}");
    assert_eq!(not_read[0]["size"], page, "{d}");
    assert!(not_read[0]["why"].as_str().expect("a why").contains("---p"), "{d}");
    assert_eq!(hex_of(not_read[1]["start"].as_str().expect("a start")), t.at(3), "{d}");
    assert_eq!(not_read[1]["size"], page, "{d}");
    assert!(not_read[1]["why"].as_str().expect("a why").contains("not mapped"), "{d}");

    // A window that begins in the gap and reaches a mapping.
    let d = t.window(3, 2 * page, 0x6F);
    assert_eq!(addrs(&d["matches"]), [t.at(4)], "{d}");
    assert_eq!(hex_of(d["not_read"][0]["start"].as_str().expect("a start")), t.at(3), "{d}");

    // A window that ends in it: what is past the last mapping is stated too.
    let d = t.window(1, 3 * page, 0x5E);
    assert_eq!(addrs(&d["matches"]), [t.at(1)], "{d}");
    assert_eq!(d["regions_not_read"], 2, "{d}");
    assert_eq!(hex_of(d["not_read"][1]["start"].as_str().expect("a start")), t.at(3), "{d}");
}

/// A window inside one mapping reads exactly that, wherever it starts.
#[test]
fn a_window_reads_only_what_it_asks() {
    let t = Target::spawn();
    let pid = t.pid_arg();
    // The pattern starts at the page's first byte, so this window misses its head.
    let start = format!("{:#x}", t.at(1) + 1);
    let d = t.ok(&["scan", "aob", "--pid", &pid, "--start", &start, "--size", "256", "--pattern", &pattern(0x5E)]);
    assert_eq!(d["bytes_scanned"], 256, "{d}");
    assert_eq!(d["regions_scanned"], 1, "{d}");
    assert_eq!(d["matches"], serde_json::json!([]), "{d}");
    // It ends where it was told to, even across a mapping boundary.
    let start = format!("{:#x}", t.at(1) - 8);
    let d = t.ok(&["scan", "aob", "--pid", &pid, "--start", &start, "--size", "32", "--pattern", "??"]);
    assert_eq!(d["bytes_scanned"], 32, "{d}");
    assert_eq!(d["regions_scanned"], 2, "{d}");
}

/// A window of nothing that reads is refused, with the first reason.
#[test]
fn a_window_with_nothing_readable_is_refused() {
    let t = Target::spawn();
    t.assert_fixture_holds();
    let v = t.n0x(&["scan", "aob", "--pid", &t.pid_arg(), "--start", &format!("{:#x}", t.at(2)), "--size", &(2 * t.page()).to_string(), "--pattern", "00"]);
    assert_eq!(v["ok"], false, "{v}");
    assert_eq!(v["error"]["code"], "nothing-readable", "{v}");
    assert!(v["error"]["message"].as_str().expect("a message").contains("---p"), "{v}");
}

/// With no window the set stays the writable mappings: the read-only patterns are
/// not in it, and nothing is said to be missing.
#[test]
fn the_default_set_stays_writable_only() {
    let t = Target::spawn();
    t.assert_fixture_holds();
    let pid = t.pid_arg();
    let d = t.ok(&["scan", "aob", "--pid", &pid, "--pattern", &pattern(0x5E)]);
    assert!(addrs(&d["matches"]).contains(&t.at(1)), "the writable page is in the set: {d}");
    let d = t.ok(&["scan", "aob", "--pid", &pid, "--pattern", &pattern(0x4D)]);
    assert!(!addrs(&d["matches"]).contains(&t.at(0)), "the read-only page is not: {d}");
    assert_eq!(d["regions_not_read"], 0, "{d}");
}

/// The shared helper, so every scanner gets it.
#[test]
fn every_scanner_with_a_window_reads_it_the_same_way() {
    let t = Target::spawn();
    t.assert_fixture_holds();
    let pid = t.pid_arg();
    let page = t.page();
    let start = format!("{:#x}", t.at(0));
    let size = (5 * page).to_string();
    let stated = |d: &Value| {
        assert_eq!(d["regions_scanned"], 3, "{d}");
        assert_eq!(d["regions_not_read"], 2, "{d}");
    };
    // The first byte of the read-only page's pattern, which nothing else there repeats.
    let d = t.ok(&["scan", "value", "--pid", &pid, "--start", &start, "--size", &size, "--type", "u8", "--value", "77", "--save-as", "s", "--force"]);
    stated(&d);
    assert!(d["matches"].as_array().expect("matches").iter().any(|m| m["addr"] == start.as_str()), "{d}");
    assert_eq!(d["exhaustive"], false, "the gap and the unreadable page were not read: {d}");

    let d = t.ok(&["scan", "group", "--pid", &pid, "--start", &start, "--size", &size, "--field", "u8=77"]);
    stated(&d);
    assert!(d["hits"].as_array().expect("hits").iter().any(|h| h["base"] == start.as_str()), "{d}");

    let d = t.ok(&["lua", "strings", "--pid", &pid, "--start", &start, "--size", &size]);
    stated(&d);

    // `find` does not go through the region list, and has its own cut.
    let d = t.ok(&["find", "--pid", &pid, "--start", &start, "--size", &(2 * page).to_string(), "--bytes", &pattern(0x5E)]);
    assert_eq!(d["count"], 1, "{d}");
    assert_eq!(d["regions_read_short"], 0, "{d}");
}
