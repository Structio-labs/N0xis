// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A scan of a live process goes on past what will not read, and says what
//! that was.** The defect: one mapped region whose first byte faults ended
//! `scan aob` with `aob-failed`, with the pattern still ahead of it; and a scan
//! that did skip a region looked exactly like one that had not.
//!
//! A disposable target plants the regions, in a known address order:
//!
//! * a `rw-s` mapping of two pages over an **empty file**, whose first byte the
//!   kernel cannot bring in. `process_vm_readv` gives `EFAULT`, as it does for
//!   a device mapping that faults, and needs no device: the test checks that with
//!   a call of its own before it believes the fixture;
//! * a `rw-s` mapping of two pages over a **one-page file**: a read gets the
//!   first page and stops. A pattern lies in that page;
//! * a `rw-s` mapping that reads whole, with a pattern in it: what is shared or
//!   file-backed is not therefore unreadable;
//! * an anonymous `rw-p` page, at the highest address, holding the pattern the
//!   scan has to get past the others to reach.
//!
//! What the answer should say is not asked of n0xis: `/proc/<pid>/maps` gives the
//! region count and the bytes there are, and the kernel call gives the failures.
//! Linux-only, because the fixture and the source outside n0xis are, and run as
//! `live_memory_exit` is: the target is built with `rustc` and grants the reading
//! itself, so the test needs no privileges.
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::OnceLock;

use serde_json::Value;

mod support;

/// The target. Its patterns are computed into place, so that nothing else in its
/// writable memory holds them and a match can only be the planted one.
const TARGET_SRC: &str = r##"
use std::io::{BufRead, Write};
use std::os::fd::AsRawFd;

const PROT_READ_WRITE: i32 = 3;
const PROT_NONE: i32 = 0;
const MAP_SHARED: i32 = 0x01;
const MAP_PRIVATE: i32 = 0x02;
const MAP_FIXED: i32 = 0x10;
const MAP_ANONYMOUS: i32 = 0x20;
const SC_PAGESIZE: i32 = 30;
const PR_SET_DUMPABLE: i32 = 4;
const PR_SET_PTRACER: i32 = 0x59616d61;

unsafe extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn prctl(o: i32, a: u64, b: u64, c: u64, d: u64) -> i32;
    fn sysconf(name: i32) -> i64;
}

fn plant(at: *mut u8, seed: u8) {
    for i in 0..16usize {
        unsafe { at.add(i).write_volatile(seed ^ (i as u8).wrapping_mul(37)) };
    }
}

fn main() {
    // Yama's default lets only an ancestor read this process, and the harness
    // runs n0xis as a sibling.
    unsafe { prctl(PR_SET_PTRACER, u64::MAX, 0, 0, 0) };
    let dir = std::env::args().nth(1).expect("a directory for the files");
    let page = unsafe { sysconf(SC_PAGESIZE) } as usize;

    // One reservation, so the order of what is mapped into it is known. What
    // stays of it between them keeps the mappings apart.
    let base = unsafe { mmap(std::ptr::null_mut(), 12 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
    assert!(base as isize != -1, "reservation failed");
    let file_map = |name: &str, file_pages: usize, at_page: usize, pages: usize| -> *mut u8 {
        let file = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(format!("{dir}/{name}")).expect("create the file");
        file.set_len((file_pages * page) as u64).expect("size the file");
        let want = unsafe { base.add(at_page * page) };
        let got = unsafe { mmap(want, pages * page, PROT_READ_WRITE, MAP_SHARED | MAP_FIXED, file.as_raw_fd(), 0) };
        assert!(got == want, "file mapping failed");
        got
    };
    let fault = file_map("empty", 0, 0, 2);
    let short = file_map("one-page", 1, 3, 2);
    let shared = file_map("whole", 1, 6, 1);
    let anon = unsafe { base.add(8 * page) };
    let got = unsafe { mmap(anon, page, PROT_READ_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) };
    assert!(got == anon, "anonymous mapping failed");
    plant(short, 0x5A);
    plant(shared, 0x6B);
    plant(anon, 0x7C);

    let mut out = std::io::stdout().lock();
    writeln!(out, "page={page:#x}").unwrap();
    writeln!(out, "fault={:#x}", fault as usize).unwrap();
    writeln!(out, "short={:#x}", short as usize).unwrap();
    writeln!(out, "shared={:#x}", shared as usize).unwrap();
    writeln!(out, "anon={:#x}", anon as usize).unwrap();
    writeln!(out, "gap={:#x}", unsafe { base.add(2 * page) } as usize).unwrap();
    writeln!(out, "ready").unwrap();
    out.flush().unwrap();

    // Parked on a pipe: it wakes for an order, and ends with the harness.
    for line in std::io::stdin().lock().lines() {
        if matches!(line.as_deref(), Ok("refuse")) {
            // From here on a reader without CAP_SYS_PTRACE gets EPERM.
            unsafe { prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) };
            writeln!(out, "refused").unwrap();
            out.flush().unwrap();
        }
    }
}
"##;

/// The planted bytes, as the target computes them.
fn pattern(seed: u8) -> String {
    (0..16u32).map(|i| format!("{:02x}", seed ^ (i as u8).wrapping_mul(37))).collect::<Vec<_>>().join(" ")
}

/// One build of the target for the whole test binary.
fn target_exe() -> &'static Path {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("n0xis-unreadable-build-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("build dir");
        let src = dir.join("target.rs");
        let exe = dir.join("target");
        std::fs::write(&src, TARGET_SRC).expect("write the target");
        let out = Command::new("rustc").args(["-O", "-o"]).arg(&exe).arg(&src).output().expect("invoke rustc (it built this crate, so it is on PATH)");
        assert!(out.status.success(), "rustc failed on the target:\n{}", String::from_utf8_lossy(&out.stderr));
        exe
    })
}

struct Target {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
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
        let dir = std::env::temp_dir().join(format!("n0xis-unreadable-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Its own project: a run with none would write to the global one.
        std::fs::create_dir_all(dir.join(".n0x")).expect("scratch dir");
        let mut child = Command::new(target_exe()).arg(&dir).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("spawn the target");
        let stdin = child.stdin.take().expect("piped stdin");
        let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        // Blocks until the target has published everything or died: no waiting
        // on a clock, so a loaded machine changes nothing here.
        let mut at = HashMap::new();
        loop {
            let mut line = String::new();
            let n = stdout.read_line(&mut line).expect("read the target");
            assert!(n > 0, "the target ended before it was ready");
            let line = line.trim();
            if line == "ready" {
                break;
            }
            let (k, v) = line.split_once('=').expect("name=value");
            at.insert(k.to_string(), u64::from_str_radix(v.trim_start_matches("0x"), 16).expect("hex"));
        }
        let pid = child.id();
        Target { child, stdin, stdout, pid, at, dir }
    }

    fn at(&self, name: &str) -> u64 {
        self.at[name]
    }

    fn n0x(&self, args: &[&str]) -> Value {
        let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).current_dir(&self.dir).output().expect("run n0xis");
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("n0xis {args:?} did not print one JSON object: {e}\n{}", String::from_utf8_lossy(&out.stdout)))
    }

    fn ok(&self, args: &[&str]) -> Value {
        let v = self.n0x(args);
        assert_eq!(v["ok"], true, "n0xis {args:?} failed: {}", v["error"]);
        v["data"].clone()
    }

    fn error_code(&self, args: &[&str]) -> (String, String) {
        let v = self.n0x(args);
        assert_eq!(v["ok"], false, "n0xis {args:?} answered: {}", v["data"]);
        (v["error"]["code"].as_str().unwrap_or("").to_string(), v["error"]["message"].as_str().unwrap_or("").to_string())
    }

    fn pid_arg(&self) -> String {
        self.pid.to_string()
    }

    /// `(regions, bytes)` of the set a default scan covers, by the kernel's map.
    fn default_set(&self) -> (usize, u64) {
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", self.pid)).expect("read maps");
        let mut regions = 0;
        let mut bytes = 0;
        for line in maps.lines() {
            let mut f = line.split_whitespace();
            let (Some(range), Some(perms)) = (f.next(), f.next()) else { continue };
            if !perms.starts_with("rw") {
                continue;
            }
            let (s, e) = range.split_once('-').expect("a range");
            regions += 1;
            bytes += u64::from_str_radix(e, 16).unwrap() - u64::from_str_radix(s, 16).unwrap();
        }
        (regions, bytes)
    }

    /// What the kernel itself answers to `process_vm_readv`, with no n0xis in the
    /// way: the bytes it gave, or the errno.
    fn kernel_read(&self, addr: u64, len: usize) -> Result<usize, i32> {
        #[repr(C)]
        struct IoVec {
            base: *mut u8,
            len: usize,
        }
        unsafe extern "C" {
            fn process_vm_readv(pid: i32, local: *const IoVec, lc: u64, remote: *const IoVec, rc: u64, flags: u64) -> isize;
        }
        let mut buf = vec![0u8; len];
        let local = IoVec { base: buf.as_mut_ptr(), len };
        let remote = IoVec { base: addr as *mut u8, len };
        let n = unsafe { process_vm_readv(self.pid as i32, &local, 1, &remote, 1, 0) };
        if n < 0 { Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)) } else { Ok(n as usize) }
    }

    /// Check the fixture before believing anything measured on it: if the kernel
    /// stopped answering this way the test would pass or fail for nothing.
    fn assert_fixture_holds(&self) {
        const EFAULT: i32 = 14;
        let page = self.at("page") as usize;
        assert_eq!(self.kernel_read(self.at("fault"), 16), Err(EFAULT), "the empty file's mapping must fault on its first byte");
        assert_eq!(self.kernel_read(self.at("short"), 2 * page), Ok(page), "the one-page file's mapping must stop after one page");
        assert_eq!(self.kernel_read(self.at("shared"), page), Ok(page), "the whole file's mapping must read");
        assert_eq!(self.kernel_read(self.at("anon"), page), Ok(page), "the anonymous page must read");
        assert!(self.at("fault") < self.at("short") && self.at("short") < self.at("shared") && self.at("shared") < self.at("anon"), "the scan must meet the fault first");
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", self.pid)).expect("read maps");
        let line = maps.lines().find(|l| l.starts_with(&format!("{:x}-", self.at("fault")))).expect("the mapping is listed");
        assert!(line.contains(" rw-s "), "the mapping must be in the default scan set: {line}");
    }
}

fn hex(v: u64) -> String {
    format!("{v:#x}")
}

fn addrs(list: &Value) -> Vec<u64> {
    list.as_array().expect("an array").iter().map(|m| u64::from_str_radix(m.as_str().expect("an address").trim_start_matches("0x"), 16).expect("hex")).collect()
}

/// The `start`s of a coverage list, as addresses.
fn starts(list: &Value) -> Vec<u64> {
    let entries = list.as_array().unwrap_or_else(|| panic!("a coverage list, got {list}"));
    entries.iter().map(|e| u64::from_str_radix(e["start"].as_str().expect("a start").trim_start_matches("0x"), 16).expect("hex")).collect()
}

/// What every scan of this target has to state, however many regions it swept:
/// the faulting mapping as not read, with the kernel's reason, and the short one
/// as short by exactly its unbacked page.
fn assert_states_the_fixture(t: &Target, d: &Value) {
    let page = t.at("page");
    assert_eq!(starts(&d["not_read"]), [t.at("fault")], "{d}");
    assert_eq!(d["regions_not_read"], 1, "{d}");
    assert_eq!(d["not_read"][0]["size"], 2 * page, "{d}");
    let why = d["not_read"][0]["why"].as_str().expect("a why");
    assert!(why.contains("os error 14"), "the reason is the kernel's: {why}");
    assert_eq!(starts(&d["read_short"]), [t.at("short")], "{d}");
    assert_eq!(d["regions_read_short"], 1, "{d}");
    assert_eq!(d["read_short"][0]["size"], 2 * page, "{d}");
    assert_eq!(d["read_short"][0]["read"], page, "{d}");
}

#[test]
fn the_scan_gets_past_a_region_that_faults_and_says_so() {
    let t = Target::spawn();
    t.assert_fixture_holds();
    let d = t.ok(&["scan", "aob", "--pid", &t.pid_arg(), "--pattern", &pattern(0x7C)]);

    assert_eq!(addrs(&d["matches"]), [t.at("anon")], "the pattern lies past the fault");
    assert_states_the_fixture(&t, &d);

    // Against the kernel's map: every region of the default set accounted for,
    // and every byte: all of them but the two faulting pages and the one past
    // the short file's end.
    let (regions, bytes) = t.default_set();
    let page = t.at("page");
    assert_eq!(d["regions_scanned"].as_u64().unwrap() + d["regions_not_read"].as_u64().unwrap(), regions as u64, "{d}");
    assert_eq!(d["bytes_scanned"], bytes - 2 * page - page, "{d}");
}

/// A skip by path or by kind would pass the test above. The shared mapping that
/// reads whole, and the first page of the one that stops, hold patterns of their
/// own: what decides is what the read returned.
#[test]
fn a_shared_mapping_that_reads_is_scanned() {
    let t = Target::spawn();
    t.assert_fixture_holds();
    let pid = t.pid_arg();
    let d = t.ok(&["scan", "aob", "--pid", &pid, "--pattern", &pattern(0x6B)]);
    assert_eq!(addrs(&d["matches"]), [t.at("shared")], "a shared file mapping that reads holds what it holds");
    let d = t.ok(&["scan", "aob", "--pid", &pid, "--pattern", &pattern(0x5A)]);
    assert_eq!(addrs(&d["matches"]), [t.at("short")], "what a short read did give is scanned");
}

/// The same rule on every other sweep over a live target, on the same fixture:
/// each gets past the fault, states it, and still finds what lies beyond.
#[test]
fn every_other_scan_states_the_same() {
    let t = Target::spawn();
    t.assert_fixture_holds();
    let pid = t.pid_arg();
    let anon = hex(t.at("anon"));
    // The planted page's first dword, as an unsigned number: `scan value` and
    // `scan group` look for it, and it is not the kind of value that repeats.
    let dword = u32::from_le_bytes([0x7C, 0x7C ^ 37, 0x7C ^ 74, 0x7C ^ 111]).to_string();

    let d = t.ok(&["scan", "value", "--pid", &pid, "--type", "u32", "--value", &dword, "--save-as", "first", "--force"]);
    assert_states_the_fixture(&t, &d);
    assert!(d["matches"].as_array().expect("matches").iter().any(|m| m["addr"] == anon.as_str()), "scan value got past the fault: {d}");
    assert_eq!(d["shown"], d["total_matches"], "{d}");
    assert_eq!(d["exhaustive"], false, "all that was found is shown, and a region was not read: {d}");
    // The same scan of what does read, for the other half of that.
    let d = t.ok(&["scan", "value", "--pid", &pid, "--start", &anon, "--size", &t.at("page").to_string(), "--type", "u32", "--value", &dword, "--save-as", "clean", "--force"]);
    assert_eq!(d["exhaustive"], true, "{d}");

    let d = t.ok(&["scan", "filter", "--pid", &pid, "--from", "first", "--criterion", "unchanged", "--save-as", "second", "--force"]);
    assert!(d["matches"].as_array().expect("matches").iter().any(|m| m["addr"] == anon.as_str()), "{d}");
    assert_eq!(d["regions_not_read"], 0, "the first scan kept nothing of the region that did not read: {d}");
    assert_eq!(d["exhaustive"], true, "this rescan read all it held: {d}");

    let field = format!("u32={dword}");
    let d = t.ok(&["scan", "group", "--pid", &pid, "--field", &field]);
    assert_states_the_fixture(&t, &d);
    assert!(d["hits"].as_array().expect("hits").iter().any(|h| h["base"] == anon.as_str()), "scan group got past the fault: {d}");

    // This one sweeps read-only mappings too, and the kernel's own (`[vvar]`) fault
    // as well: every one it lists has to be one the kernel refuses.
    let d = t.ok(&["scan", "pointer-path", "--pid", &pid, "--target", &anon, "--module", "target", "--max-depth", "2"]);
    let not_read = starts(&d["not_read"]);
    assert!(not_read.contains(&t.at("fault")), "{d}");
    for start in not_read {
        assert_eq!(t.kernel_read(start, 16), Err(14), "listed as not read: {start:#x}");
    }
    assert_eq!(starts(&d["read_short"]), [t.at("short")], "{d}");

    let d = t.ok(&["locate", "by-transition", "--pid", &pid, "--type", "u32", "--transition", "changed", "--wait-ms", "1", "--save-as", "third", "--force"]);
    assert_states_the_fixture(&t, &d);
    assert_eq!(d["report"]["exhaustive"], false, "{d}");

    // The heap readers go through the same rule. Their answers depend on a VM
    // this target does not have; what is asked of them here is what they read.
    let d = t.ok(&["lua", "strings", "--pid", &pid, "--max-len", "8"]);
    assert_states_the_fixture(&t, &d);
    let d = t.ok(&["lua", "combo", "--pid", &pid, "--strings", "up,down"]);
    assert_states_the_fixture(&t, &d);
    let d = t.ok(&["lua", "seedscan", "--pid", &pid, "--combo", "up,down", "--lcg-a", "5", "--lcg-c", "1", "--range", "4"]);
    assert_states_the_fixture(&t, &d);

    // A window the caller names: a fault, then a read that stops short.
    let pattern_bytes = pattern(0x5A);
    let (code, message) = t.error_code(&["find", "--pid", &pid, "--start", &hex(t.at("fault")), "--size", "16", "--bytes", &pattern_bytes]);
    assert_eq!(code, "nothing-readable", "{message}");
    let size = (2 * t.at("page")).to_string();
    let d = t.ok(&["find", "--pid", &pid, "--start", &hex(t.at("short")), "--size", &size, "--bytes", &pattern_bytes]);
    assert_eq!(d["count"], 1, "{d}");
    assert_eq!(starts(&d["read_short"]), [t.at("short")], "{d}");

    let (code, message) = t.error_code(&["strings", "--pid", &pid, "--start", &hex(t.at("fault")), "--size", &size]);
    assert_eq!(code, "nothing-readable", "{message}");
    let d = t.ok(&["strings", "--pid", &pid, "--start", &hex(t.at("short")), "--size", &size]);
    assert_eq!(starts(&d["read_short"]), [t.at("short")], "{d}");
}

/// A scan that read everything must say so too, or "nothing was left out" could
/// not be told from "this build does not say".
#[test]
fn a_clean_scan_states_that_nothing_was_left_out() {
    let t = Target::spawn();
    let (anon, page) = (hex(t.at("anon")), t.at("page").to_string());
    let d = t.ok(&["scan", "aob", "--pid", &t.pid_arg(), "--start", &anon, "--size", &page, "--pattern", &pattern(0x7C)]);
    assert_eq!(addrs(&d["matches"]), [t.at("anon")]);
    assert_eq!(d["regions_scanned"], 1);
    assert_eq!(d["regions_not_read"], 0);
    assert_eq!(d["not_read"], serde_json::json!([]));
    assert_eq!(d["regions_read_short"], 0);
    assert_eq!(d["read_short"], serde_json::json!([]));
}

/// When every region fails, nothing was looked at. That is not "no matches".
#[test]
fn nothing_readable_is_an_error_not_an_empty_scan() {
    let t = Target::spawn();
    t.assert_fixture_holds();
    let pid = t.pid_arg();
    let size = (2 * t.at("page")).to_string();
    let pat = pattern(0x7C);

    // A window over the faulting mapping alone: clipped to it, one region, a fault.
    let (code, message) = t.error_code(&["scan", "aob", "--pid", &pid, "--start", &hex(t.at("fault")), "--size", &size, "--pattern", &pat]);
    assert_eq!(code, "nothing-readable", "{message}");
    assert!(message.contains("os error 14"), "it says why: {message}");

    // A mapping with no read permission: the one the reservation left between two.
    let (code, message) = t.error_code(&["scan", "aob", "--pid", &pid, "--start", &hex(t.at("gap")), "--size", "16", "--pattern", &pat]);
    assert_eq!(code, "nothing-readable", "{message}");
    assert!(message.contains("---p"), "it says why: {message}");

    // An address with no mapping.
    let (code, message) = t.error_code(&["scan", "aob", "--pid", &pid, "--start", "0x10", "--size", "16", "--pattern", &pat]);
    assert_eq!(code, "nothing-readable", "{message}");
    assert!(message.contains("not mapped"), "it says why: {message}");
}

/// The target ending is not a region that would not read. These read through the
/// real adapter, with the kernel's real answer: the region list is taken while
/// the target lives, and the read happens after it is gone, which is the order a
/// scan meets it in. The CLI cannot be stopped between those two, so the pass is
/// driven directly; what the capability does with the error is `aob-failed`.
#[test]
fn a_dead_target_is_an_error_not_an_empty_scan() {
    let mut t = Target::spawn();
    let live = n0xis_frontend::source::attach_live(t.pid).unwrap_or_else(|(c, m)| panic!("attach: {c}: {m}"));
    let regions = live.default_writable_regions();
    assert!(regions.len() > 2, "the target has its regions");
    let arch = n0xis_arch::X64::new();
    let ctx = n0xis_core::Ctx::new(live.as_ref(), &arch);
    let sweep = |regions: Vec<(n0xis_contracts::Va, usize)>| {
        let pattern = n0xis_core::parse_aob(&pattern(0x7C)).unwrap();
        n0xis_core::Pass::run(&n0xis_core::AobSweepPass, &ctx, n0xis_core::AobSweepInput { regions, pattern })
    };
    let alive = sweep(regions.clone()).expect("the scan runs on the living target");
    assert_eq!(alive.answer.matches.iter().map(|v| v.0).collect::<Vec<_>>(), [t.at("anon")], "shown to work first");

    t.child.kill().expect("kill");
    t.child.wait().expect("reap");
    let got = sweep(regions.clone());
    let failure = got.expect_err("a dead target must not answer").to_string();
    assert!(failure.contains("exited"), "{failure}");

    // And every other sweep, each a loop that used to step over any failure.
    let exited = |what: &str, failure: String| assert!(failure.contains("exited"), "{what}: {failure}");
    let scan_input = || n0xis_core::ScanInput {
        regions: regions.clone(),
        value_type: n0xis_core::ValueType::U32,
        criterion: n0xis_core::ScanCriterion::Unknown,
        align: 4,
    };
    exited("scan value", n0xis_core::Pass::run(&n0xis_core::ScanPass, &ctx, scan_input()).expect_err("scan value").to_string());
    let group = n0xis_core::GroupScanInput {
        regions: regions.clone(),
        fields: vec![n0xis_core::GroupField { value_type: n0xis_core::ValueType::U32, value: n0xis_core::ScanValue::Int(1) }],
        window: 16,
        align: 4,
        limit: 1,
    };
    exited("scan group", n0xis_core::Pass::run(&n0xis_core::GroupScanPass, &ctx, group).expect_err("scan group").to_string());
    let previous = n0xis_core::ScanState {
        value_type: n0xis_core::ValueType::U32,
        align: 4,
        regions: vec![n0xis_core::RegionState { base: regions[0].0, data: n0xis_core::RegionData::Dense { bytes: vec![0; 16] } }],
    };
    let filter = n0xis_core::FilterInput { previous, criterion: n0xis_core::FilterCriterion::Changed };
    exited("scan filter", n0xis_core::Pass::run(&n0xis_core::FilterPass, &ctx, filter).expect_err("scan filter").to_string());
    let chain = n0xis_core::PointerPathInput { target: regions[0].0, search_regions: regions.clone(), roots: Vec::new(), max_depth: 1, max_offset: 16, pointer_size: 8 };
    exited("pointer path", n0xis_core::Pass::run(&n0xis_core::PointerPathPass, &ctx, chain).expect_err("pointer path").to_string());
    let classes = n0xis_core::ClassScanInput { windows: regions.clone(), probe: 0, max_probe: 0, limit: 0, min_hits: 0, require_self_pointer: false };
    exited("il2cpp classes", n0xis_core::Pass::run(&n0xis_core::ClassScanPass, &ctx, classes).expect_err("il2cpp classes").to_string());
    let ui = n0xis_core::UiLocateInput {
        regions: regions.clone(),
        rect: n0xis_core::Rect::new(0.0, 0.0, 1.0, 1.0),
        space: n0xis_core::CoordSpace::Screen,
        layout: n0xis_core::AabbLayout::BITSQUID,
        align: 4,
    };
    exited("ui locate", n0xis_core::Pass::run(&n0xis_core::UiLocatePass, &ctx, ui).expect_err("ui locate").to_string());
    let targets = std::collections::HashMap::new();
    let layout = n0xis_luajit::GcstrLayout::BITSQUID_GC64;
    exited("lua strings", n0xis_luajit::scan_strings(live.as_ref(), &regions, layout, 1, 8).expect_err("lua strings").to_string());
    exited("lua runs", n0xis_luajit::find_string_runs(live.as_ref(), &regions, &targets, 2).expect_err("lua runs").to_string());
    exited("lua refs", n0xis_luajit::find_gcref32_runs(live.as_ref(), &regions, &targets, 2).expect_err("lua refs").to_string());
    let lcg = n0xis_luajit::Lcg { a: 5, c: 1 };
    exited("lua seeds", n0xis_luajit::find_seeds(live.as_ref(), &regions, &lcg, 4, &[1], None).expect_err("lua seeds").to_string());

    // Attached after it ended, the whole command says so.
    let v = t.n0x(&["scan", "aob", "--pid", &t.pid_arg(), "--pattern", &pattern(0x7C)]);
    assert_eq!(v["ok"], false, "{v}");
}

/// The same for a read that starts being refused, by the kernel, on the real
/// adapter: the target turns itself undumpable after the region list is taken.
#[test]
fn a_refused_target_is_an_error_not_an_empty_scan() {
    const EPERM: i32 = 1;
    let mut t = Target::spawn();
    let live = n0xis_frontend::source::attach_live(t.pid).unwrap_or_else(|(c, m)| panic!("attach: {c}: {m}"));
    let regions = live.default_writable_regions();
    writeln!(t.stdin, "refuse").expect("order the target");
    t.stdin.flush().expect("flush");
    let mut line = String::new();
    t.stdout.read_line(&mut line).expect("read the target");
    assert_eq!(line.trim(), "refused");
    if t.kernel_read(t.at("anon"), 16) != Err(EPERM) {
        // A reader with CAP_SYS_PTRACE is not refused. Not measured here, and
        // recorded as that rather than as a pass.
        eprintln!("not measured: this reader is not refused by an undumpable target");
        return;
    }
    let arch = n0xis_arch::X64::new();
    let ctx = n0xis_core::Ctx::new(live.as_ref(), &arch);
    let pattern = n0xis_core::parse_aob(&pattern(0x7C)).unwrap();
    let got = n0xis_core::Pass::run(&n0xis_core::AobSweepPass, &ctx, n0xis_core::AobSweepInput { regions, pattern });
    let failure = got.expect_err("a refused target must not answer").to_string();
    assert!(failure.contains("denied"), "{failure}");
}

/// A window of a file states no coverage: what a file holds does not come and go.
/// Its answer is the two fields it has always been.
#[test]
fn a_file_window_states_no_coverage() {
    let bytes = std::fs::read(target_exe()).expect("read the image");
    let elf = goblin::elf::Elf::parse(&bytes).expect("an ELF");
    let text = elf.section_headers.iter().find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".text")).expect("a .text");
    let dir = std::env::temp_dir().join(format!("n0xis-unreadable-file-{}", std::process::id()));
    std::fs::create_dir_all(dir.join(".n0x")).expect("scratch dir");
    let exe = target_exe().to_str().expect("a path").to_string();
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .args(["scan", "aob", "--file", &exe, "--start", &hex(text.sh_addr), "--size", "64", "--pattern", "??"])
        .current_dir(&dir)
        .output()
        .expect("run n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
    assert_eq!(v["data"]["bytes_scanned"], 64, "the window has to have been read: {v}");
    let keys: Vec<String> = v["data"].as_object().expect("an object").keys().cloned().collect();
    assert_eq!(keys, ["bytes_scanned", "matches"], "{v}");
    let _ = std::fs::remove_dir_all(&dir);
}
