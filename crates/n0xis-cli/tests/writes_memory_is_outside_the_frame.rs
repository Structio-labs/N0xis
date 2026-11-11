// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`writes_memory` is a store outside the function's own frame.**
//!
//! It was a text match on `mov ` and `[`: `mov (%rdi),%eax` was a store and `addl
//! $1,(%rdi)` was not, 13 of 17 wrong (audit 2026-11-06, row 7). And with the meaning
//! unsettled, every `-O0` function wrote memory and its `-O2` build did not.
//!
//! `oracle/summary/writes.c` names each function by its answer, written from the
//! source: `W_` stores outside its frame, `F_` does not. Built at `-O0` and `-O2`, by
//! gcc and clang, for x64, i386 and Win64; `nm` says where each one is.

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
    let dir = std::env::temp_dir().join(format!("n0xis_writes_{}_{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    // mingw adds `.exe` to a name that has none, and `nm` would read nothing.
    let file = dir.join(if compiler.contains("mingw") { "writes.exe" } else { "writes" });
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../oracle/summary/writes.c");
    match Command::new(compiler).args(flags).arg("-o").arg(&file).arg(source).output() {
        Ok(o) if o.status.success() => Some(file),
        _ => {
            eprintln!("{tag}: skipped, {compiler} could not build");
            None
        }
    }
}

/// `(name, address)` of every `W_` and `F_` function, from `nm`.
fn functions(file: &Path) -> Vec<(String, u64)> {
    let out = Command::new("nm").env("LC_ALL", "C").arg(file).output().expect("nm");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let name = f.get(2)?.trim_start_matches('_');
            (f.len() == 3 && matches!(f[1], "T" | "t") && (name.starts_with("W_") || name.starts_with("F_")))
                .then(|| (name.to_string(), u64::from_str_radix(f[0], 16).expect("hex")))
        })
        .collect()
}

fn writes_memory(file: &Path, va: u64) -> Value {
    let mut cmd = support::isolated(Command::new(n0xis_exe()));
    let out = cmd.args(["function", "summary", "--quiet", "--file"]).arg(file).args(["--addr", &format!("{va:#x}")]).output().expect("n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("no envelope ({e})"));
    assert_eq!(v["ok"], true, "{v}");
    v["data"]["summaries"][0]["writes_memory"].clone()
}

/// What this does not answer yet, by build and function, and why. Each is a store into
/// the frame counted as a write: the safe side of the rule, and still not the answer.
const NOT_YET: &[(&str, &str, &str)] = &[
    // `fstl (%esp)` / `fstpl 0x18(%esp)`: the lift keeps x87 stores verbatim, with no
    // address, so they are counted.
    ("i386-O0", "F_spill_d", "an x87 spill is not lifted"),
    ("i386-O2", "F_spill_d", "an x87 spill is not lifted"),
    // The pointer into the frame is kept in a slot and loaded back; on i386 the
    // optimizer does not forward that load, so the store through it is not placed.
    ("i386-O0", "F_frame_ptr", "a slot's load is not forwarded on i386"),
];

#[test]
fn every_function_says_whether_it_stores_outside_its_frame() {
    let builds: &[(&str, &str, &[&str])] = &[
        ("gcc-O0", "gcc", &["-O0", "-fno-pie", "-no-pie"]),
        ("gcc-O2", "gcc", &["-O2", "-fno-pie", "-no-pie"]),
        ("clang-O0", "clang", &["-O0", "-fno-pie", "-no-pie"]),
        ("clang-O2", "clang", &["-O2", "-fno-pie", "-no-pie"]),
        ("i386-O0", "gcc", &["-m32", "-msse2", "-O0"]),
        ("i386-O2", "gcc", &["-m32", "-msse2", "-O2"]),
        ("win64-O0", "x86_64-w64-mingw32-gcc", &["-O0"]),
        ("win64-O2", "x86_64-w64-mingw32-gcc", &["-O2"]),
    ];
    let mut asked = 0;
    let mut wrong = Vec::new();
    for (tag, compiler, flags) in builds {
        let Some(file) = build(tag, compiler, flags) else { continue };
        let found = functions(&file);
        assert_eq!(found.len(), 20, "{tag}: nm lists the fixture's 20 functions: {found:?}");
        for (name, va) in found {
            if NOT_YET.iter().any(|(t, n, _)| t == tag && *n == name) {
                continue;
            }
            asked += 1;
            let want = name.starts_with("W_");
            let got = writes_memory(&file, va);
            if got != Value::Bool(want) {
                wrong.push(format!("{tag} {name} {va:#x}: {got}, the source says {want}"));
            }
        }
    }
    assert!(asked > 0, "no build ran: nothing was asked");
    assert!(wrong.is_empty(), "{} of {asked} wrong:\n{}", wrong.len(), wrong.join("\n"));
}
