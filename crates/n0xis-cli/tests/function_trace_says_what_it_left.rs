// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **What a call-graph walk could not follow is in its answer.**
//!
//! `function trace` marked `call [rax+8]` as `kind: "direct"` with no target, and
//! said `truncated: false` with everything behind that call left out, so a walk that
//! stopped at the first virtual call read as a whole program.
//!
//! `oracle/xref/trace.cpp` says what `root` calls, and `objdump -d` where each call
//! is: which name a direct one, and which go through memory or a register.

// It builds its target with a compiler at run time, so its answer depends on that
// compiler's version: a local instrument, not a CI gate.
#![cfg(feature = "oracle")]
#![cfg(target_os = "linux")]

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
    p.join("n0xis")
}

fn build(tag: &str, compiler: &str, flags: &[&str]) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("n0xis_trace_{}_{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let file = dir.join("trace");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../oracle/xref/trace.cpp");
    match Command::new(compiler).args(["-O2"]).args(flags).arg("-o").arg(&file).arg(source).output() {
        Ok(o) if o.status.success() => Some(file),
        _ => {
            eprintln!("{tag}: skipped, {compiler} could not build");
            None
        }
    }
}

/// `(address, text)` of each `call` in `function`, from `objdump -d`.
fn calls(file: &Path, function: &str) -> Vec<(u64, String)> {
    let wanted = format!("--disassemble={function}");
    let out = Command::new("objdump").env("LC_ALL", "C").args(["-d", "-M", "intel", "--no-show-raw-insn", &wanted]).arg(file).output().expect("objdump");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let (head, text) = l.split_once(":\t")?;
            let text = text.trim();
            text.starts_with("call").then(|| Some((u64::from_str_radix(head.trim(), 16).ok()?, text.to_string())))?
        })
        .collect()
}

fn symbol(file: &Path, name: &str) -> u64 {
    let out = Command::new("nm").env("LC_ALL", "C").arg(file).output().expect("nm");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() == 3 && f[2] == name).then(|| u64::from_str_radix(f[0], 16).expect("hex"))
        })
        .unwrap_or_else(|| panic!("nm has no {name}"))
}

fn trace(file: &Path, root: u64, depth: u32) -> Value {
    let mut cmd = support::isolated(Command::new(n0xis_exe()));
    let out = cmd.args(["function", "trace", "--file"]).arg(file).args(["--addr", &format!("{root:#x}"), "--depth", &depth.to_string()]).output().expect("n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("no envelope ({e})"));
    assert_eq!(v["ok"], true, "{v}");
    v["data"].clone()
}

fn hex(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().expect("an address").trim_start_matches("0x"), 16).expect("hex")
}

fn the_walk(tag: &str, file: &Path) {
    let root = symbol(file, "root");
    let by_objdump = calls(file, "root");
    let indirect: Vec<u64> = by_objdump.iter().filter(|(_, t)| !t.contains('<')).map(|(a, _)| *a).collect();
    let direct: Vec<u64> = by_objdump.iter().filter(|(_, t)| t.contains('<')).map(|(a, _)| *a).collect();
    assert_eq!(indirect.len(), 2, "{tag}: the source has a virtual call and one through a value: {by_objdump:?}");
    assert_eq!(direct.len(), 1, "{tag}: and one direct: {by_objdump:?}");

    // Deep enough for everything a direct call reaches.
    let whole = trace(file, root, 8);
    let node = whole["nodes"].as_array().expect("nodes").iter().find(|n| hex(&n["addr"]) == root).expect("the root");
    let rows = node["calls"].as_array().expect("calls");
    assert_eq!(rows.len(), 3, "{tag}: {node}");
    for row in rows {
        let at = hex(&row["from"]);
        if indirect.contains(&at) {
            assert_eq!(row["kind"], "indirect", "{tag}: {row}");
            assert!(row.get("target").is_none(), "{tag}: {row}");
        } else {
            assert!(direct.contains(&at), "{tag}: a call objdump does not show: {row}");
            assert_ne!(row["kind"], "indirect", "{tag}: {row}");
            assert_eq!(hex(&row["target"]), symbol(file, "middle"), "{tag}: {row}");
        }
    }
    assert_eq!(whole["not_followed"]["indirect_calls"], 2, "{tag}: {whole}");
    assert_eq!(whole["not_followed"]["past_depth"], 0, "{tag}: {whole}");
    assert_eq!(whole["truncated"], true, "{tag}: what is behind the two calls was left out: {whole}");
    assert_eq!(whole["truncate_reason"], "indirect", "{tag}: {whole}");
    assert_eq!(whole["node_count"], 3, "{tag}: root, middle, leaf: {whole}");

    // One level: `middle` is visited, and `leaf` behind it is what was left.
    let shallow = trace(file, root, 1);
    assert_eq!(shallow["not_followed"]["past_depth"], 1, "{tag}: {shallow}");
    assert_eq!(shallow["truncated"], true, "{tag}: {shallow}");
    assert_eq!(shallow["truncate_reason"], "depth", "{tag}: {shallow}");

    // A call through a slot that names an import is no indirect call.
    let logs = trace(file, symbol(file, "logs"), 8);
    let rows = logs["nodes"][0]["calls"].as_array().expect("calls");
    assert_eq!(rows.len(), 1, "{tag}: {logs}");
    assert_eq!(rows[0]["kind"], "named", "{tag}: {logs}");
    assert_eq!(logs["not_followed"]["indirect_calls"], 0, "{tag}: {logs}");

    // A walk with nothing unknown and nothing past its depth is whole, and says so.
    let leaf = trace(file, symbol(file, "leaf"), 8);
    assert_eq!(leaf["truncated"], false, "{tag}: {leaf}");
    assert_eq!(leaf["not_followed"]["indirect_calls"], 0, "{tag}: {leaf}");
    assert_eq!(leaf["not_followed"]["past_depth"], 0, "{tag}: {leaf}");
}

#[test]
fn gcc() {
    if let Some(file) = build("gcc", "g++", &["-fPIE", "-pie", "-fno-plt", "-fno-devirtualize-speculatively"]) {
        the_walk("gcc", &file);
    }
}

#[test]
fn clang() {
    if let Some(file) = build("clang", "clang++", &["-fPIE", "-pie", "-fno-plt"]) {
        the_walk("clang", &file);
    }
}
