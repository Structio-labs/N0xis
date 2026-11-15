// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A function an element segment holds is referenced there.**
//!
//! A table's function is called through `call_indirect`, and no instruction
//! names it; the element segment that puts it in the table does. `xref to` read
//! only instructions and answered such a function with a bare count of 0
//! (claims audit, 2026-11-14). It now lists the items that hold it beside its
//! rows, `{segment, item}`, and says the segments were read.
//!
//! The truth is `wasm-objdump`'s, recorded beside the fixture: `-x`
//! (`indexed.details.txt`) for each segment's items, `-d`
//! (`indexed.disassembly.txt`) for where each function's body is.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod support;

fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wasm").join(name)
}

/// `wasm-objdump -x`'s `Elem` section: function index → `(segment, item)`s,
/// and how many segments there are.
fn element_items() -> (BTreeMap<u32, Vec<(u32, u32)>>, usize) {
    let text = std::fs::read_to_string(fixture("indexed.details.txt")).expect("record");
    let mut out: BTreeMap<u32, Vec<(u32, u32)>> = BTreeMap::new();
    let (mut segments, mut segment, mut inside) = (0usize, 0u32, false);
    for line in text.lines() {
        if line.starts_with("Elem[") {
            inside = true;
            continue;
        }
        if inside && !line.starts_with(' ') {
            break;
        }
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("- segment[") {
            segment = rest.split(']').next().unwrap().parse().unwrap();
            segments += 1;
        } else if let Some(rest) = l.strip_prefix("- elem[") {
            let item: u32 = rest.split(']').next().unwrap().parse().unwrap();
            let f: u32 = rest.split("ref.func:").nth(1).unwrap().split_whitespace().next().unwrap().parse().unwrap();
            out.entry(f).or_default().push((segment, item));
        }
    }
    (out, segments)
}

/// `wasm-objdump -d`: each defined function's index and body address.
fn bodies() -> Vec<(u32, u64)> {
    let text = std::fs::read_to_string(fixture("indexed.disassembly.txt")).expect("record");
    text.lines()
        .filter_map(|l| {
            let (addr, rest) = l.split_once(" func[")?;
            Some((rest.split(']').next()?.parse().ok()?, u64::from_str_radix(addr.trim(), 16).ok()?))
        })
        .collect()
}

#[test]
fn xref_to_lists_the_element_segment_items_that_hold_a_function() {
    let exe = n0xis_exe();
    if !exe.exists() {
        eprintln!("skipping: {} not built", exe.display());
        return;
    }
    let (items, segments) = element_items();
    let bodies = bodies();
    assert!(items.contains_key(&1) && segments == 2 && bodies.len() == 5, "the record says what the test assumes: {items:?} {bodies:?}");
    let wasm = fixture("indexed.wasm");
    for (index, body) in bodies {
        let out = support::isolated(Command::new(&exe))
            .args(["xref", "to", "--file", wasm.to_str().unwrap(), "--addr", &format!("{body:#x}")])
            .output()
            .expect("run n0xis");
        let v: Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
        assert_eq!(v["ok"], Value::Bool(true), "{v}");
        let got: Vec<(u32, u32)> = v["data"]["element_refs"]
            .as_array()
            .unwrap_or_else(|| panic!("func[{index}]: no element_refs: {v}"))
            .iter()
            .map(|r| (r["segment"].as_u64().unwrap() as u32, r["item"].as_u64().unwrap() as u32))
            .collect();
        assert_eq!(got, items.get(&index).cloned().unwrap_or_default(), "func[{index}] at {body:#x}: {v}");
        assert_eq!(v["data"]["searched"]["element_segments"]["segments"].as_u64(), Some(segments as u64), "{v}");
    }
}
