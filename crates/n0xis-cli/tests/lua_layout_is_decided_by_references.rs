// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`lua combo` and `lua strings` decide a string's header from what the process's
//! memory refers to, and say so.** They read every base with one hardcoded offset; on
//! a process with another header every base was 4 bytes low and `lua combo` answered
//! `count: 0`, with no error.
//!
//! A disposable target plants, on a page of its own, strings with a header of the
//! `len` offset it is told and an array of tagged references to them, then prints the
//! addresses: the answer is known before the question. Which references there are is
//! told too, because each `count: 0` is a different answer. A real LuaJIT is measured
//! in `lua_layout_on_a_real_luajit.rs`.
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::OnceLock;

use serde_json::Value;

mod support;

/// `target <len offset> <array|lone|none>`: `array` plants `{alpha, gamma, gamma, alpha}`,
/// `lone` single references with other values between them, `none` nothing. The tokens
/// are on purpose not words a running program holds anyway.
const TARGET_SRC: &str = r##"
use std::io::{BufRead, Write};

const PROT_READ_WRITE: i32 = 3;
const MAP_PRIVATE_ANON: i32 = 0x22;
const PR_SET_PTRACER: i32 = 0x59616d61;
const STRING_TAG: u64 = 0x1FFFB << 47;
const ALPHA_AT: usize = 0x100;
const GAMMA_AT: usize = 0x200;
const ARRAY_AT: usize = 0x1000;

unsafe extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn prctl(o: i32, a: u64, b: u64, c: u64, d: u64) -> i32;
}

/// A string object at `base`: `len`, then the text, built a byte at a time so that
/// nothing else in this process's writable memory holds it.
unsafe fn plant(base: *mut u8, len_offset: usize, seed: u8, len: usize) {
    unsafe {
        (base.add(len_offset) as *mut u32).write_unaligned(len as u32);
        for i in 0..len {
            base.add(len_offset + 4 + i).write_volatile(b'A' + (seed + i as u8) % 26);
        }
    }
}

fn main() {
    unsafe { prctl(PR_SET_PTRACER, u64::MAX, 0, 0, 0) };
    let mut args = std::env::args().skip(1);
    let len_offset = usize::from_str_radix(args.next().expect("an offset").trim_start_matches("0x"), 16).expect("hex");
    let refs = args.next().expect("array, lone or none");
    let page = unsafe { mmap(std::ptr::null_mut(), 0x4000, PROT_READ_WRITE, MAP_PRIVATE_ANON, -1, 0) };
    assert!(page as isize != -1, "mmap failed");
    // By offset from the page only: an address of a string kept in a local is a bare
    // pointer in this process's memory, which is exactly what is being counted.
    unsafe {
        plant(page.add(ALPHA_AT), len_offset, 0, 5);
        plant(page.add(GAMMA_AT), len_offset, 7, 5);
    }
    let tagged = |at: usize| STRING_TAG | (page as u64 + at as u64);
    let array = unsafe { page.add(ARRAY_AT) as *mut u64 };
    match refs.as_str() {
        "array" => {
            for (i, v) in [tagged(ALPHA_AT), tagged(GAMMA_AT), tagged(GAMMA_AT), tagged(ALPHA_AT)].iter().enumerate() {
                unsafe { array.add(i).write_volatile(*v) };
            }
        }
        "lone" => {
            for (i, v) in [tagged(ALPHA_AT), 7.0f64.to_bits(), tagged(GAMMA_AT)].iter().enumerate() {
                unsafe { array.add(i).write_volatile(*v) };
            }
        }
        _ => {}
    }
    let mut out = std::io::stdout().lock();
    writeln!(out, "page={:#x}", page as usize).unwrap();
    writeln!(out, "ready").unwrap();
    out.flush().unwrap();
    for _ in std::io::stdin().lock().lines() {}
}
"##;

/// The two planted tokens, as the target spells them.
fn token(seed: u8) -> String {
    (0..5u8).map(|i| (b'A' + (seed + i) % 26) as char).collect()
}

fn target_exe() -> &'static Path {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("n0xis-layout-build-{}", std::process::id()));
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
    fn spawn(len_offset: u64, refs: &str) -> Target {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("n0xis-layout-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".n0x")).expect("scratch dir");
        let mut child = Command::new(target_exe()).args([format!("{len_offset:#x}").as_str(), refs]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("spawn the target");
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
        Target { child, _stdin: stdin, at, dir }
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

    fn combo(&self, extra: &[&str]) -> Value {
        let pid = self.child.id().to_string();
        let strings = format!("{},{}", token(0), token(7));
        let mut args = vec!["lua", "combo", "--pid", pid.as_str(), "--strings", strings.as_str()];
        args.extend_from_slice(extra);
        self.ok(&args)
    }

    /// The address of what the target planted, from the page it printed.
    fn hex(&self, name: &str) -> String {
        let at = match name {
            "alpha" => 0x100,
            "gamma" => 0x200,
            "array" => 0x1000,
            other => panic!("nothing planted called {other}"),
        };
        format!("{:#x}", self.at["page"] + at)
    }
}

fn candidate<'a>(d: &'a Value, off: &str) -> &'a Value {
    d["layout"]["candidates"].as_array().expect("candidates").iter().find(|c| c["len_offset"] == off).unwrap_or_else(|| panic!("no candidate {off}: {d}"))
}

fn target<'a>(d: &'a Value, text: &str) -> &'a Value {
    d["targets"].as_array().expect("targets").iter().find(|t| t["text"] == text).unwrap_or_else(|| panic!("no target {text}: {d}"))
}

/// Each header, planted, is found: the run read back, each base where the target says
/// it is, and the references exactly the ones planted, on that candidate alone.
#[test]
fn each_layout_answers_with_the_planted_run() {
    for off in ["0xc", "0x10", "0x14"] {
        let t = Target::spawn(u64::from_str_radix(off.trim_start_matches("0x"), 16).unwrap(), "array");
        let d = t.combo(&[]);
        assert_eq!(d["layout"]["len_offset"], off, "{d}");
        assert_eq!(d["layout"]["chosen_by"], "references", "{d}");
        assert_eq!(d["count"], 1, "the array is found under {off}: {d}");
        assert_eq!(d["runs"][0]["addr"], t.hex("array"), "{d}");
        assert_eq!(d["runs"][0]["values"], serde_json::json!([token(0), token(7), token(7), token(0)]), "{d}");
        assert_eq!(target(&d, &token(0))["addr"], t.hex("alpha"), "{d}");
        assert_eq!(target(&d, &token(7))["addr"], t.hex("gamma"), "{d}");
        assert_eq!(target(&d, &token(0))["references"], 2, "{d}");
        assert_eq!(target(&d, &token(0))["in_values"], 2, "{d}");
        assert_eq!(candidate(&d, off)["references"], 4, "{d}");
        for other in ["0xc", "0x10", "0x14"].into_iter().filter(|o| *o != off) {
            assert_eq!(candidate(&d, other)["references"], 0, "planted {off}: {d}");
        }
    }
}

/// `lua strings` reports the same base from the same decision.
#[test]
fn lua_strings_gives_the_base_the_target_printed() {
    let t = Target::spawn(0x0c, "array");
    let pid = t.child.id().to_string();
    let d = t.ok(&["lua", "strings", "--pid", &pid, "--contains", &token(0)]);
    assert_eq!(d["layout"]["len_offset"], "0xc", "{d}");
    assert_eq!(d["layout"]["chosen_by"], "references", "{d}");
    let hits = d["matches"].as_array().expect("matches");
    let hit = hits.iter().find(|h| h["object_base"] == t.hex("alpha").as_str()).unwrap_or_else(|| panic!("the planted base: {d}"));
    assert_eq!(hit["references"], 2, "{d}");
    assert_eq!(hit["in_values"], 2, "{d}");
}

/// The string exists and nothing refers to it. No base is claimed.
#[test]
fn strings_nothing_refers_to_are_said_to_be_that() {
    let t = Target::spawn(0x14, "none");
    let d = t.combo(&[]);
    assert_eq!(d["count"], 0, "{d}");
    assert_eq!(d["layout"]["chosen_by"], "none", "{d}");
    assert_eq!(d["layout"]["len_offset"], Value::Null, "{d}");
    assert!(d["layout"]["why"].as_str().expect("a why").contains("referred"), "{d}");
    assert_eq!(target(&d, &token(0))["addr"], Value::Null, "no base without a layout: {d}");
    assert_eq!(target(&d, &token(0))["references"], 0, "{d}");
    assert!(d["note"].as_str().expect("a note").contains("exist"), "{d}");

    let pid = t.child.id().to_string();
    let d = t.ok(&["lua", "strings", "--pid", &pid, "--contains", &token(0)]);
    assert_eq!(d["layout"]["chosen_by"], "none", "{d}");
    assert!(d["matches"].as_array().expect("matches").iter().all(|h| h["object_base"].is_null()), "{d}");
}

/// References exist and form no run: not the same `count: 0`.
#[test]
fn references_that_form_no_run_are_said_to_be_that() {
    let t = Target::spawn(0x14, "lone");
    let d = t.combo(&[]);
    assert_eq!(d["count"], 0, "{d}");
    assert_eq!(d["layout"]["len_offset"], "0x14", "{d}");
    assert_eq!(target(&d, &token(0))["references"], 1, "{d}");
    assert_eq!(target(&d, &token(7))["references"], 1, "{d}");
    let note = d["note"].as_str().expect("a note");
    assert!(note.contains("2 references") && note.contains("run"), "{note}");
    // The same memory with a run of one allowed is a run.
    assert_eq!(t.combo(&["--min-run", "1"])["count"], 2);
}

/// Neither a word nor a target's own: no such string at all is a third answer.
#[test]
fn no_such_string_is_a_third_answer() {
    let t = Target::spawn(0x14, "array");
    let pid = t.child.id().to_string();
    let d = t.ok(&["lua", "combo", "--pid", &pid, "--strings", "QQQQQQQ"]);
    assert_eq!(d["count"], 0, "{d}");
    assert_eq!(d["targets"], serde_json::json!([]), "{d}");
    assert!(d["note"].as_str().expect("a note").contains("none of the target strings"), "{d}");
    assert_eq!(d["layout"]["chosen_by"], "none", "{d}");
}

/// The override is taken and says so, with what memory says beside it: a wrong offset
/// now shows itself as the count it costs.
#[test]
fn the_override_says_it_overrode() {
    let t = Target::spawn(0x14, "array");
    let d = t.combo(&["--gcstr-len-off", "0x14"]);
    assert_eq!(d["layout"]["chosen_by"], "override", "{d}");
    assert_eq!(d["layout"]["len_offset"], "0x14", "{d}");
    assert_eq!(d["count"], 1, "{d}");

    let d = t.combo(&["--gcstr-len-off", "0xc"]);
    assert_eq!(d["layout"]["chosen_by"], "override", "{d}");
    assert_eq!(d["count"], 0, "the header is not that one: {d}");
    assert_eq!(candidate(&d, "0x14")["references"], 4, "and the answer shows which is: {d}");
    assert_eq!(candidate(&d, "0xc")["references"], 0, "{d}");
}
