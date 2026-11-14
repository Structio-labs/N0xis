// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A whole-program command reads a jump table as `ir build` does.**
//!
//! A table with no guard of its index ends where the image's next table begins,
//! and the next is named by whatever code takes its address, often another
//! function's. `ir build` reads against the image's table bases; `analyze` built
//! its graphs against the function's own code, and read on into the next table:
//! two answers to one question.
//!
//! The fixture, `fixtures/switch-bases/tables.s` (an ELF built with gcc, the
//! command in the file), as binutils read it: `fa` at 0x1000..0x1042 and `fb` at
//! 0x1042..0x105f (`readelf -wF`); `fa` dispatches at 0x1010 through the table at
//! 0x2000 (`lea rdx,[rip+0xff7]`), `fb` at 0x105d through the one at 0x2020 (`lea
//! rdx,[rip+0xfca]` at 0x104f), and `objdump -s -j .rodata` shows eight words for
//! `fa` before `fb`'s four. Read relative to 0x2000, `fb`'s words lead into `fa`
//! (0x1024..0x1027): only the next table's base ends `fa`'s at eight.

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

fn run(cwd: &Path, args: &[&str]) -> Value {
    let out = support::isolated(Command::new(n0xis_exe())).current_dir(cwd).args(args).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("one envelope ({e}): {}", String::from_utf8_lossy(&out.stdout)))
}

fn project(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis-tables-as-ir-build-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("temp project");
    dir
}

/// The cases of the switch at `at` in a graph's JSON.
fn cases_at(graph: &Value, at: &str) -> Option<usize> {
    graph["switches"].as_array()?.iter().find(|s| s["at"] == at).and_then(|s| s["cases"].as_array()).map(Vec::len)
}

#[test]
fn analyze_reads_a_table_where_ir_build_does() {
    if !n0xis_exe().exists() {
        return; // binary not built in this profile
    }
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/switch-bases/tables.so");
    let fixture = fixture.to_str().expect("utf-8 path");

    let one = project("ir");
    let built = run(&one, &["ir", "build", "--file", fixture, "--addr", "0x1000"]);
    let by_ir_build = cases_at(&built["data"], "0x1010").unwrap_or_else(|| panic!("ir build reads fa's switch: {built}"));
    let _ = std::fs::remove_dir_all(&one);
    assert_eq!(by_ir_build, 8, "fa's table holds eight words before fb's: {built}");

    // `analyze` keeps every graph it builds in the project's IR cache: the graph of
    // `fa` there is the whole-program command's answer.
    let all = project("analyze");
    let analysed = run(&all, &["analyze", "--file", fixture, "--quiet"]);
    assert_eq!(analysed["ok"], true, "{analysed}");
    let graphs: Vec<Value> = std::fs::read_dir(all.join(".n0x/ir-cache"))
        .expect("analyze keeps its graphs")
        .filter_map(|e| std::fs::read_to_string(e.ok()?.path()).ok())
        .filter_map(|j| serde_json::from_str(&j).ok())
        .collect();
    let _ = std::fs::remove_dir_all(&all);
    let by_analyze: Vec<usize> = graphs.iter().filter_map(|g| cases_at(g, "0x1010")).collect();
    assert_eq!(by_analyze, vec![by_ir_build], "analyze's graph of fa reads its table as ir build does");
}
