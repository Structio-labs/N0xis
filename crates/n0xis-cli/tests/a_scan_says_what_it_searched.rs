// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **An answer of "nothing" from a scan says where it looked, and finds what is
//! where it says it looked.** The claims audit of 2026-11-06 found `scan value`
//! answering `exhaustive: true, total_matches: 0` about a process holding the
//! value, three ways: in `.rodata`, outside the writable mappings it picks when no
//! window is named; at an offset its default stride steps over; and across two
//! adjacent mappings, which were read and searched one at a time, so a value over
//! the seam was in neither, at any stride, for `scan aob` and `scan group` too. On
//! a file, a window was read to the end of its first section and no further, and
//! one starting between two sections was refused as `nothing-readable`.
//!
//! Each test plants the thing where the old answer said there was nothing:
//!
//! ```text
//! page 0   rw-p   0x5A5A1234 at its end - 6, and the first half of
//! page 1   rwxp   0xFACEB00C, which starts 2 bytes before page 1
//! page 2   rw-p   0xFEEDFACE at 0x101, not on a 4-byte boundary
//! other    r--p   0xBADC0FFE at 0x40
//! ```
//!
//! What the kernel reads there, and that pages 0 and 1 are two mappings, is
//! checked from `/proc` before anything measured on them is believed.
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

const PROT_READ: i32 = 1;
const PROT_READ_WRITE: i32 = 3;
const PROT_RWX: i32 = 7;
const MAP_PRIVATE_ANON: i32 = 0x22;
const SC_PAGESIZE: i32 = 30;
const PR_SET_PTRACER: i32 = 0x59616d61;

unsafe extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn mprotect(addr: *mut u8, len: usize, prot: i32) -> i32;
    fn prctl(o: i32, a: u64, b: u64, c: u64, d: u64) -> i32;
    fn sysconf(name: i32) -> i64;
}

fn put(at: *mut u8, v: u32) {
    for (i, b) in v.to_le_bytes().iter().enumerate() {
        unsafe { at.add(i).write_volatile(*b) };
    }
}

fn main() {
    unsafe { prctl(PR_SET_PTRACER, u64::MAX, 0, 0, 0) };
    let page = unsafe { sysconf(SC_PAGESIZE) } as usize;
    let base = unsafe { mmap(std::ptr::null_mut(), 3 * page, PROT_READ_WRITE, MAP_PRIVATE_ANON, -1, 0) };
    let ro = unsafe { mmap(std::ptr::null_mut(), page, PROT_READ_WRITE, MAP_PRIVATE_ANON, -1, 0) };
    assert!(base as isize != -1 && ro as isize != -1, "mmap failed");
    let seam = unsafe { base.add(page) };
    put(unsafe { seam.sub(6) }, 0x5A5A_1234);
    put(unsafe { seam.sub(2) }, 0xFACE_B00C);
    put(unsafe { base.add(2 * page + 0x101) }, 0xFEED_FACE);
    put(unsafe { ro.add(0x40) }, 0xBADC_0FFE);
    unsafe {
        assert_eq!(mprotect(seam, page, PROT_RWX), 0);
        assert_eq!(mprotect(ro, page, PROT_READ), 0);
    }
    let mut out = std::io::stdout().lock();
    writeln!(out, "seam={:#x}", seam as usize).unwrap();
    writeln!(out, "unaligned={:#x}", base as usize + 2 * page + 0x101).unwrap();
    writeln!(out, "ro={:#x}", ro as usize).unwrap();
    writeln!(out, "page={page:#x}").unwrap();
    writeln!(out, "ready").unwrap();
    out.flush().unwrap();
    for _ in std::io::stdin().lock().lines() {}
}
"##;

fn target_exe() -> &'static Path {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("n0xis-searched-build-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("build dir");
        let (src, exe) = (dir.join("target.rs"), dir.join("target"));
        std::fs::write(&src, TARGET_SRC).expect("write the target");
        let out = Command::new("rustc").args(["-O", "-o"]).arg(&exe).arg(&src).output().expect("invoke rustc (it built this crate, so it is on PATH)");
        assert!(out.status.success(), "rustc failed on the target:\n{}", String::from_utf8_lossy(&out.stderr));
        exe
    })
}

/// A scratch project: a run with none would write to the global one.
fn project(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis-searched-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("scratch dir");
    dir
}

fn n0x(dir: &Path, args: &[&str]) -> Value {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).current_dir(dir).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("n0xis {args:?} did not print one JSON object: {e}\n{}", String::from_utf8_lossy(&out.stdout)))
}

fn ok(dir: &Path, args: &[&str]) -> Value {
    let v = n0x(dir, args);
    assert_eq!(v["ok"], true, "{args:?}: {v}");
    v["data"].clone()
}

fn hex(s: &Value) -> u64 {
    u64::from_str_radix(s.as_str().expect("an address").trim_start_matches("0x"), 16).expect("hex")
}

/// Every address a scan's answer lists, whatever it calls its entries.
fn found(d: &Value) -> Vec<u64> {
    let list = d.get("matches").or_else(|| d.get("hits")).and_then(Value::as_array).cloned().unwrap_or_default();
    list.iter().map(|m| if m.is_string() { hex(m) } else { hex(m.get("addr").or_else(|| m.get("base")).expect("an address field")) }).collect()
}

struct Target {
    child: Child,
    _stdin: ChildStdin,
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
    fn spawn(name: &str) -> Target {
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
        let t = Target { child, _stdin: stdin, at, dir: project(name) };
        t.assert_fixture_holds();
        t
    }

    fn pid(&self) -> String {
        self.child.id().to_string()
    }

    fn u32_at(&self, va: u64) -> u32 {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(format!("/proc/{}/mem", self.child.id())).expect("open the target's memory");
        f.seek(SeekFrom::Start(va)).unwrap();
        let mut b = [0u8; 4];
        f.read_exact(&mut b).expect("the kernel reads it");
        u32::from_le_bytes(b)
    }

    /// What the tests below stand on, from the kernel and not from n0xis.
    fn assert_fixture_holds(&self) {
        let seam = self.at["seam"];
        assert_eq!(self.u32_at(seam - 2), 0xFACE_B00C);
        assert_eq!(self.u32_at(seam - 6), 0x5A5A_1234);
        assert_eq!(self.u32_at(self.at["unaligned"]), 0xFEED_FACE);
        assert_eq!(self.u32_at(self.at["ro"] + 0x40), 0xBADC_0FFE);
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", self.child.id())).expect("the map");
        let ends = |line: &str| line.split(['-', ' ']).nth(1).and_then(|e| u64::from_str_radix(e, 16).ok());
        let at_seam = maps.lines().find(|l| ends(l) == Some(seam)).unwrap_or_else(|| panic!("no mapping ends at the seam {seam:#x}:\n{maps}"));
        assert!(at_seam.contains(" rw-p "), "the mapping before the seam is its own: {at_seam}");
        assert!(maps.lines().any(|l| l.starts_with(&format!("{seam:x}-")) && l.contains(" rwxp ")), "the one after it is its own");
    }
}

/// A value across two adjacent mappings is in the process, at every stride that
/// reaches it, for each scan that looks for one.
#[test]
fn a_value_across_two_mappings_is_found_by_every_scan() {
    let t = Target::spawn("seam");
    let (pid, dir) = (t.pid(), t.dir.clone());
    let at = t.at["seam"] - 2;

    let d = ok(&dir, &["scan", "value", "--pid", &pid, "--type", "u32", "--value", "0xFACEB00C", "--align", "1", "--save-as", "s", "--force"]);
    assert!(found(&d).contains(&at), "scan value missed {at:#x}: {d}");
    let d = ok(&dir, &["scan", "aob", "--pid", &pid, "--pattern", "0C B0 CE FA"]);
    assert!(found(&d).contains(&at), "scan aob missed {at:#x}: {d}");
    let d = ok(&dir, &["scan", "group", "--pid", &pid, "--field", "u32=0x5A5A1234", "--field", "u32=0xFACEB00C", "--align", "1", "--window", "16"]);
    assert!(found(&d).contains(&(at - 4)), "scan group missed the pair at {:#x}: {d}", at - 4);
    // A window of the two pages is cut at the seam as well, and joined again.
    let start = format!("{:#x}", t.at["seam"] - 0x10);
    let d = ok(&dir, &["scan", "aob", "--pid", &pid, "--pattern", "0C B0 CE FA", "--start", &start, "--size", "0x20"]);
    assert!(found(&d).contains(&at), "a window over the seam missed it: {d}");
}

/// Where a scan did not look, its answer says so, and `exhaustive` is not `true`.
#[test]
fn an_answer_of_nothing_names_what_it_left_out() {
    let t = Target::spawn("left-out");
    let (pid, dir) = (t.pid(), t.dir.clone());

    // In a read-only mapping, outside the set picked when no window is named.
    let d = ok(&dir, &["scan", "value", "--pid", &pid, "--type", "u32", "--value", "0xBADC0FFE", "--save-as", "s", "--force"]);
    let ro = t.at["ro"] + 0x40;
    if !found(&d).contains(&ro) {
        assert_eq!(d["exhaustive"], false, "not found, and called exhaustive: {d}");
        assert_eq!(d["searched"]["over"]["kind"], "chosen", "{d}");
        let rest = &d["searched"]["not_searched"][0];
        assert!(rest["count"].as_u64().unwrap_or(0) >= 1 && rest["bytes"].as_u64().unwrap_or(0) >= 0x1000, "the rest is counted: {d}");
    }
    // Named as a window, it is searched, and found: the value is there to find.
    let start = format!("{:#x}", t.at["ro"]);
    let page = t.at["page"].to_string();
    let d = ok(&dir, &["scan", "value", "--pid", &pid, "--type", "u32", "--value", "0xBADC0FFE", "--start", &start, "--size", &page, "--align", "1", "--save-as", "s", "--force"]);
    assert!(found(&d).contains(&ro), "{d}");
    assert_eq!(d["exhaustive"], true, "every byte of the named window, read whole, all shown: {d}");

    // At the default stride, an unaligned value is stepped over, and the answer says the stride.
    let un = t.at["unaligned"];
    let d = ok(&dir, &["scan", "value", "--pid", &pid, "--type", "u32", "--value", "0xFEEDFACE", "--save-as", "s", "--force"]);
    if !found(&d).contains(&un) {
        assert_eq!(d["exhaustive"], false, "{d}");
        assert_eq!(d["searched"]["stride"], 4, "{d}");
    }
    let d = ok(&dir, &["scan", "value", "--pid", &pid, "--type", "u32", "--value", "0xFEEDFACE", "--align", "1", "--save-as", "s", "--force"]);
    assert!(found(&d).contains(&un), "every byte: {d}");
}

const IMAGE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/strings_planted.so");

/// A window of an image over all of its allocated sections finds the first four
/// bytes of each, as the image's own section table (read with `goblin`) places
/// them; one starting in a gap before the first is not refused.
#[test]
fn a_window_of_an_image_is_read_past_its_first_section() {
    let bytes = std::fs::read(IMAGE).expect("read the fixture");
    let elf = goblin::elf::Elf::parse(&bytes).expect("an ELF");
    let alloc: Vec<_> = elf
        .section_headers
        .iter()
        .filter(|s| s.sh_flags & u64::from(goblin::elf::section_header::SHF_ALLOC) != 0 && s.sh_type != goblin::elf::section_header::SHT_NOBITS && s.sh_size >= 4)
        .collect();
    assert!(alloc.len() >= 3, "the fixture has sections to cross");
    let lo = alloc.iter().map(|s| s.sh_addr).min().unwrap();
    let hi = alloc.iter().map(|s| s.sh_addr + s.sh_size).max().unwrap();
    assert!(lo > 0, "the window below starts in a gap");
    let dir = project("file");
    let size = hi.to_string();
    let mut tried = 0;
    for s in &alloc {
        let off = s.sh_offset as usize;
        let word = &bytes[off..off + 4];
        let pattern = word.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        let d = ok(&dir, &["scan", "aob", "--file", IMAGE, "--start", "0x0", "--size", &size, "--pattern", &pattern]);
        assert!(found(&d).contains(&s.sh_addr), "{:#x}: {pattern} not found in a window over the whole image: {d}", s.sh_addr);
        let value = u32::from_le_bytes(word.try_into().unwrap()).to_string();
        let d = ok(&dir, &["scan", "value", "--file", IMAGE, "--start", "0x0", "--size", &size, "--type", "u32", "--value", &value, "--align", "1", "--save-as", "f", "--force"]);
        assert!(found(&d).contains(&s.sh_addr), "{:#x}: {value} not found by scan value: {d}", s.sh_addr);
        assert_eq!(d["exhaustive"], false, "the window holds gaps the image has no bytes for: {d}");
        assert!(d["regions_not_read"].as_u64().unwrap() >= 1, "and says so: {d}");
        tried += 1;
    }
    assert_eq!(tried, alloc.len());
}
