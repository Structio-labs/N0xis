// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A function the x64 exception table states in several entries is one
//! function** — every continuation entry (`UNW_FLAG_CHAININFO`) a part of the
//! function at the end of its chain, never a start; the function's extent its
//! first entry and every part, contiguous or not.
//!
//! The truth is planted bytes (`tests/fixtures/chained/*.s`, rebuilt by
//! `build.sh`), and what an independent reader says they hold:
//! `chained.dll.unwind.txt` is `llvm-readobj --unwind`, read here by a parser
//! of this file's own ([`readobj_functions`]), and `chained.dll.disassembly.txt`
//! is `llvm-objdump -d`. By the sources: `f` is the assembler's
//! `.seh_splitchained`, three entries each continuing the first, all
//! contiguous; `g` is a first entry, a continuation right after it, and one
//! past `h`, chained through the first continuation (a chain nested once),
//! which calls `h`, loads `0x1234` and jumps back into `g`; `h` is one entry.
//!
//! Each test fails on its own line on the build before this was fixed (the
//! defect: every entry was a function, ending where its entry ends).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod support;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chained").join(name)
}

fn image() -> String {
    fixture("chained.dll").to_str().expect("a UTF-8 path").to_string()
}

/// A project of its own for each test.
fn project(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis_chained_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("project");
    dir
}

fn run(dir: &Path, args: &[&str]) -> Value {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).arg("--quiet").current_dir(dir).output().expect("run n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("one JSON object from {args:?}: {e}"));
    assert_eq!(v["ok"], true, "{args:?}: {v}");
    v
}

fn hex(v: u64) -> String {
    format!("{v:#x}")
}

/// One function as the recording states it: its first entry's start, the end
/// of the code that runs on from there without a gap, and the parts apart.
#[derive(Debug, PartialEq, Eq)]
struct Truth {
    end: u64,
    apart: Vec<(u64, u64)>,
    continuations: Vec<u64>,
}

/// `llvm-readobj --unwind`, read as functions: each entry is
/// `StartAddress`/`EndAddress` and, where chained, a `Chained {
/// StartAddress }` naming the entry it continues; a chain is followed to the
/// entry that names none.
fn readobj_functions() -> BTreeMap<u64, Truth> {
    let text = std::fs::read_to_string(fixture("chained.dll.unwind.txt")).expect("the recording");
    let addr = |line: &str| -> Option<u64> {
        let open = line.find("(0x")?;
        u64::from_str_radix(line[open + 3..].trim_end_matches(')').trim(), 16).ok()
    };
    // (start, end, continues)
    let mut entries: Vec<(u64, u64, Option<u64>)> = Vec::new();
    let mut in_chain = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with("Chained {") {
            in_chain = true;
        } else if line.starts_with("StartAddress:") {
            let a = addr(line).expect("an address");
            if in_chain {
                entries.last_mut().expect("an entry").2 = Some(a);
                in_chain = false;
            } else {
                entries.push((a, 0, None));
            }
        } else if line.starts_with("EndAddress:") && !in_chain {
            let e = entries.last_mut().expect("an entry");
            if e.1 == 0 {
                e.1 = addr(line).expect("an address");
            }
        }
    }
    assert!(entries.len() >= 6 && entries.iter().any(|e| e.2.is_some()), "the recording parsed: {entries:?}");
    let parent: BTreeMap<u64, Option<u64>> = entries.iter().map(|e| (e.0, e.2)).collect();
    let root = |mut a: u64| {
        while let Some(Some(p)) = parent.get(&a) {
            a = *p;
        }
        a
    };
    let mut out: BTreeMap<u64, Truth> = BTreeMap::new();
    for e in entries.iter().filter(|e| e.2.is_none()) {
        out.insert(e.0, Truth { end: e.1, apart: Vec::new(), continuations: Vec::new() });
    }
    let mut parts: Vec<(u64, u64, u64)> = entries.iter().filter(|e| e.2.is_some()).map(|e| (root(e.0), e.0, e.1)).collect();
    parts.sort_unstable();
    for (r, s, e) in parts {
        let f = out.get_mut(&r).expect("every chain ends at an entry of the table");
        f.continuations.push(s);
        if s == f.end {
            f.end = e;
        } else {
            f.apart.push((s, e));
        }
    }
    out
}

/// `va → (end, [(start, end)] of every part apart)` of every function a list
/// holds; an end nothing states is `0`, which no truth has.
fn listed(data: &Value) -> BTreeMap<u64, (u64, Vec<(u64, u64)>)> {
    let num = |v: &Value| u64::from_str_radix(v.as_str().expect("an address").trim_start_matches("0x"), 16).expect("hex");
    data["functions"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|f| {
            let apart = f["detached"].as_array().map(|ps| ps.iter().map(|p| (num(&p["start"]), num(&p["end"]))).collect()).unwrap_or_default();
            (num(&f["va"]), (if f["end"].is_null() { 0 } else { num(&f["end"]) }, apart))
        })
        .collect()
}

fn expected() -> BTreeMap<u64, (u64, Vec<(u64, u64)>)> {
    readobj_functions().into_iter().map(|(s, t)| (s, (t.end, t.apart))).collect()
}

#[test]
fn the_pdata_list_holds_one_function_per_chain_with_its_whole_extent() {
    let truth = readobj_functions();
    assert_eq!(truth.len(), 3, "f, g and h: {truth:?}");
    let v = run(&project("pdata"), &["function", "discover", "--file", &image(), "--pdata"]);
    assert_eq!(listed(&v["data"]), expected(), "{v}");
    assert_eq!(v["meta"]["total"], 3, "the total counts functions, not entries: {v}");
}

#[test]
fn the_default_list_starts_no_function_in_a_continuation() {
    let truth = readobj_functions();
    let v = run(&project("default"), &["function", "discover", "--file", &image()]);
    let got = listed(&v["data"]);
    let continuations: Vec<u64> = truth.values().flat_map(|t| t.continuations.iter().copied()).collect();
    let wrong: Vec<String> = got.keys().filter(|va| continuations.contains(va)).map(|va| hex(*va)).collect();
    assert!(wrong.is_empty(), "continuations listed as functions: {wrong:?} in {v}");
    assert_eq!(got, expected(), "{v}");
}

#[test]
fn a_window_narrows_the_pdata_list() {
    // `h`, by its symbol: the export table and the recording agree on it.
    let truth = readobj_functions();
    let (&h, t) = truth.iter().find(|(_, t)| t.continuations.is_empty()).expect("one function of one entry");
    let size = (t.end - h).to_string();
    let v = run(&project("window"), &["function", "discover", "--file", &image(), "--pdata", "--start", &hex(h), "--size", &size]);
    assert_eq!(listed(&v["data"]).keys().copied().collect::<Vec<_>>(), vec![h], "only the function in the window: {v}");
    assert_eq!(v["meta"]["total"], 1, "{v}");
}

#[test]
fn decomp_ends_where_the_last_contiguous_part_ends_and_goes_on_in_the_part_apart() {
    let truth = readobj_functions();
    let dir = project("decomp");
    for (start, t) in truth.iter().filter(|(_, t)| !t.continuations.is_empty()) {
        let v = run(&dir, &["decomp", "pseudo", "--file", &image(), "--addr", &hex(*start)]);
        assert_eq!(v["data"]["end_address"], hex(t.end), "{v}");
        if !t.apart.is_empty() {
            // `g`'s part apart loads `0x1234` (`tables.s`, and the recorded
            // disassembly at `0x180001045`); it is reached only by the jump.
            let body = v["data"]["pseudo"].to_string();
            assert!(body.contains("0x1234") || body.contains("4660"), "the part apart is in the body: {v}");
        }
    }
}

#[test]
fn why_places_an_address_in_a_part_apart_in_its_function() {
    let truth = readobj_functions();
    let (&g, t) = truth.iter().find(|(_, t)| !t.apart.is_empty()).expect("a function with a part apart");
    let (lo, hi) = t.apart[0];
    let v = run(&project("why"), &["why", "--file", &image(), "--addr", &hex(lo + 5)]);
    let found = &v["data"]["function"]["found"];
    assert_eq!(found["start"], hex(g), "{v}");
    assert_eq!(found["in_part"], serde_json::json!({"start": hex(lo), "end": hex(hi)}), "{v}");
}

#[test]
fn a_call_in_a_part_apart_is_a_call_of_its_function() {
    // `g`'s part apart calls `h` (`tables.s`; the recorded disassembly at
    // `0x180001040`). No other code of `g` calls anything.
    let truth = readobj_functions();
    let (&g, _) = truth.iter().find(|(_, t)| !t.apart.is_empty()).expect("a function with a part apart");
    let (&h, _) = truth.iter().find(|(_, t)| t.continuations.is_empty()).expect("h");
    let v = run(&project("trace"), &["function", "trace", "--file", &image(), "--addr", &hex(g), "--depth", "1"]);
    // On `g`'s own node, not on a node of the part taken for a function the
    // jump tail-calls.
    let root = v["data"]["nodes"].as_array().expect("nodes").iter().find(|n| n["addr"] == hex(g)).expect("g's node").clone();
    let callees: Vec<&Value> = root["calls"].as_array().expect("calls").iter().map(|c| &c["target"]).collect();
    assert_eq!(callees, vec![&Value::String(hex(h))], "the call in the part apart is g's: {v}");
}
