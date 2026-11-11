// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A failed write says what landed.** `patch apply` and `mem write` across the end of a
//! mapping said `patch-failed` / `write-failed` after 4 of 8 bytes had changed, and
//! `patch apply` took back its record of what was there, so nothing could put them back
//! (audit 2026-11-06, row 10). `patch dry-run` on the same said `wouldChange` of 8 bytes.
//!
//! The oracle is the kernel: `/proc/<pid>/maps` for where a mapping ends, and the bytes
//! read through `/proc/<pid>/mem`, by no code of the engine's.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;

use serde_json::Value;

mod support;

/// Maps two places where a writable page is followed by one that takes no write: a page
/// with nothing mapped after it (`hole`), and one followed by a shared read-only mapping of
/// a file (`wall`), which `/proc/<pid>/mem` reads and will not write. Prints both seams.
const TARGET_SRC: &str = r#"
use std::io::Write;
use std::os::fd::AsRawFd;
const PR_SET_PTRACER: i32 = 0x59616d61;
unsafe extern "C" {
    fn prctl(o: i32, a: u64, b: u64, c: u64, d: u64) -> i32;
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn munmap(addr: *mut u8, len: usize) -> i32;
}
const PAGE: usize = 4096;
fn main() {
    unsafe { prctl(PR_SET_PTRACER, u64::MAX, 0, 0, 0) };
    let file = std::env::args().nth(1).unwrap();
    std::fs::write(&file, vec![0x22u8; PAGE]).unwrap();
    let ro = std::fs::File::open(&file).unwrap();
    unsafe {
        let a = mmap(std::ptr::null_mut(), 2 * PAGE, 3, 0x22, -1, 0);
        assert!(!a.is_null() && a as isize != -1);
        std::ptr::write_bytes(a, 0x11, PAGE);
        assert_eq!(munmap(a.add(PAGE), PAGE), 0);
        let c = mmap(std::ptr::null_mut(), 2 * PAGE, 3, 0x22, -1, 0);
        std::ptr::write_bytes(c, 0x33, PAGE);
        let d = mmap(c.add(PAGE), PAGE, 1, 0x01 | 0x10, ro.as_raw_fd(), 0);
        assert_eq!(d, c.add(PAGE));
        println!("{:#x} {:#x}", a as usize + PAGE, c as usize + PAGE);
    }
    std::io::stdout().flush().unwrap();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
}
"#;

fn target_exe() -> &'static Path {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("n0xis-landed-build-{}", std::process::id()));
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
    hole: u64,
    wall: u64,
    dir: PathBuf,
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const BYTES: &str = "a1 a2 a3 a4 a5 a6 a7 a8";

impl Target {
    fn spawn(name: &str) -> Target {
        let dir = std::env::temp_dir().join(format!("n0xis-landed-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".n0x")).expect("a project of its own");
        let mut child =
            Command::new(target_exe()).arg(dir.join("page")).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("run the target");
        let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        stdout.read_line(&mut line).expect("the target's seams");
        let a: Vec<u64> = line.split_whitespace().map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).expect("an address")).collect();
        let t = Target { pid: child.id(), child, hole: a[0], wall: a[1], dir };
        let (hole, wall) = (t.mapping_at(t.hole), t.mapping_at(t.wall));
        assert!(hole.is_none(), "the oracle must see nothing mapped at the hole");
        assert!(wall.as_deref().is_some_and(|p| p.starts_with("r--s")), "the oracle must see a shared read-only page at the wall: {wall:?}");
        assert!(t.mapping_at(t.hole - 1).is_some() && t.mapping_at(t.wall - 1).is_some());
        t
    }

    /// The permissions of the mapping holding `addr`, by `/proc/<pid>/maps`.
    fn mapping_at(&self, addr: u64) -> Option<String> {
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", self.pid)).expect("maps");
        maps.lines().find_map(|l| {
            let mut f = l.split_whitespace();
            let (lo, hi) = f.next()?.split_once('-')?;
            let (lo, hi) = (u64::from_str_radix(lo, 16).ok()?, u64::from_str_radix(hi, 16).ok()?);
            (lo <= addr && addr < hi).then(|| f.next().unwrap_or("").to_string())
        })
    }

    /// The four bytes before `seam`, by the kernel.
    fn before_seam(&self, seam: u64) -> [u8; 4] {
        let mem = std::fs::File::open(format!("/proc/{}/mem", self.pid)).expect("open the target's memory");
        let mut b = [0u8; 4];
        mem.read_exact_at(&mut b, seam - 4).expect("read before the seam");
        b
    }

    fn answer(&self, args: &[&str]) -> Value {
        let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
            .args(args)
            .args(["--pid", &self.pid.to_string()])
            .current_dir(&self.dir)
            .output()
            .expect("run n0xis");
        serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("no JSON: {}", String::from_utf8_lossy(&out.stderr)))
    }

    fn records(&self) -> Vec<Value> {
        let Ok(dir) = std::fs::read_dir(self.dir.join(".n0x/patches")) else { return Vec::new() };
        dir.filter_map(|e| std::fs::read(e.unwrap().path()).ok()).filter_map(|b| serde_json::from_slice(&b).ok()).collect()
    }
}

/// Four of the eight old bytes are there to read, so the patch could not be undone: it
/// is not written, and `dry-run` says the same before anything is.
#[test]
fn a_patch_across_a_mappings_end_is_refused_and_writes_nothing() {
    let t = Target::spawn("hole");
    let at = format!("{:#x}", t.hole - 4);
    let dry = t.answer(&["patch", "dry-run", "--addr", &at, "--bytes", BYTES]);
    assert_eq!(dry["ok"], false, "{dry}");
    assert!(dry["error"]["message"].as_str().unwrap_or("").contains("only 4 of the 8 bytes"), "{dry}");
    let a = t.answer(&["patch", "apply", "--addr", &at, "--bytes", BYTES]);
    assert_eq!(a["ok"], false, "{a}");
    assert!(a["error"]["message"].as_str().unwrap_or("").contains("nothing was written"), "{a}");
    assert_eq!(t.before_seam(t.hole), [0x11; 4], "the bytes the refusal says it left alone");
    assert!(t.records().is_empty(), "nothing was written, so nothing is on the record");
    // The same eight bytes inside the page are written: the refusal is of the seam.
    let inside = format!("{:#x}", t.hole - 8);
    let a = t.answer(&["patch", "apply", "--addr", &inside, "--bytes", BYTES]);
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(t.before_seam(t.hole), [0xa5, 0xa6, 0xa7, 0xa8]);
}

/// `mem write` keeps no record by design: what it can do is say what it changed.
#[test]
fn mem_write_across_a_mappings_end_says_how_many_bytes_changed() {
    let t = Target::spawn("mem-write");
    let at = format!("{:#x}", t.hole - 4);
    let a = t.answer(&["mem", "write", "--addr", &at, "--bytes", BYTES]);
    assert_eq!(a["ok"], false, "{a}");
    let landed = t.before_seam(t.hole);
    let changed = landed.iter().filter(|&&b| b != 0x11).count();
    assert_eq!(changed, 4, "the oracle's count: {landed:x?}");
    let msg = a["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains(&format!("{changed} of the 8 bytes changed")), "{a}");
    assert!(msg.contains("4 past the first 4 could not be read back"), "{a}");
}

/// Every old byte could be read, and the write still failed part way: what changed is
/// counted from the target, and the record of what was there stays.
#[test]
fn a_patch_that_fails_part_way_keeps_its_record_and_says_what_changed() {
    let t = Target::spawn("wall");
    let at = format!("{:#x}", t.wall - 4);
    let a = t.answer(&["patch", "apply", "--addr", &at, "--bytes", BYTES]);
    assert_eq!(a["ok"], false, "{a}");
    let landed = t.before_seam(t.wall);
    let changed = landed.iter().filter(|&&b| b != 0x33).count();
    assert!(changed > 0, "this test needs a write that lands part way: {landed:x?}: {a}");
    let msg = a["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains(&format!("{changed} of the 8 bytes changed")), "{a}");
    let records = t.records();
    assert_eq!(records.len(), 1, "{a}");
    assert_eq!(records[0]["before_hex"], "33 33 33 33 22 22 22 22", "{records:?}");
    assert!(msg.contains(records[0]["id"].as_str().unwrap()), "{a}");
}

/// An undo is a write too, and fails part way the same: `patch undo --force` over the
/// same seam put back 4 of the 8 bytes and said only that it failed (audit 2026-11-06,
/// left from the second pass). What changed is counted from the target, and the record
/// stays applied with what finishes it.
#[test]
fn an_undo_that_fails_part_way_says_what_changed_and_keeps_its_record() {
    let t = Target::spawn("undo");
    let at = format!("{:#x}", t.wall - 4);
    let a = t.answer(&["patch", "apply", "--addr", &at, "--bytes", BYTES]);
    assert_eq!(a["ok"], false, "{a}");
    let records = t.records();
    assert_eq!(records.len(), 1, "{a}");
    let id = records[0]["id"].as_str().expect("an id").to_string();
    let applied = t.before_seam(t.wall);
    assert!(applied.iter().any(|&b| b != 0x33), "this test needs a patch that landed part way: {applied:x?}");
    let u = t.answer(&["patch", "undo", "--id", &id, "--force"]);
    assert_eq!(u["ok"], false, "{u}");
    let restored = t.before_seam(t.wall);
    let changed = applied.iter().zip(&restored).filter(|(a, b)| a != b).count();
    assert!(changed > 0, "this test needs an undo that lands part way: {applied:x?} -> {restored:x?}: {u}");
    let msg = u["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains(&format!("{changed} of the 8 bytes changed")), "{u}");
    assert!(msg.contains(&id) && msg.contains("--force"), "{u}");
    let records = t.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["status"], "applied", "{records:?}");
    assert_eq!(records[0]["before_hex"], "33 33 33 33 22 22 22 22", "{records:?}");
}
