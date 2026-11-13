// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`returns` is what the source says.** `returns: true` was said of `exit` and
//! `abort` wrappers on i386 and PE32 (audit 2026-11-06, row 7): a 32-bit machine calls
//! an import through a stub that jumps through an absolute slot, which was not read as
//! one, so the stub had no name; and a function ending in a call to one of the image's
//! own that does not return was not asked about it.
//!
//! `oracle/summary/returns.c` names each function by its answer: `RET_` returns, `NR_`
//! does not. Built at `-O2` by gcc and clang for x64, by gcc for a fixed and for a
//! position-independent i386 image (whose PLT stubs jump through `ebx`) and by mingw for
//! PE32; `nm` says where each one is.
//!
//! `{"unknown": true}` is no claim, so it cannot contradict the source, but it is
//! accepted only of a function that leaves by a jump through a table, by `objdump`:
//! `RET_computed`'s computed `goto`. Anywhere else it fails as a wrong answer does.

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
    let dir = std::env::temp_dir().join(format!("n0xis_returns_{}_{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    // mingw adds `.exe` to a name that has none, and `nm` would read nothing.
    let file = dir.join(if compiler.contains("mingw") { "returns.exe" } else { "returns" });
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../oracle/summary/returns.c");
    match Command::new(compiler).args(flags).arg("-o").arg(&file).arg(source).output() {
        Ok(o) if o.status.success() => Some(file),
        _ => {
            eprintln!("{tag}: skipped, {compiler} could not build");
            None
        }
    }
}

/// `(name, address)` of every `RET_` and `NR_` function, from `nm`.
fn functions(file: &Path) -> Vec<(String, u64)> {
    let out = Command::new("nm").env("LC_ALL", "C").arg(file).output().expect("nm");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let name = f.get(2)?.trim_start_matches('_');
            (f.len() == 3 && matches!(f[1], "T" | "t") && (name.starts_with("RET_") || name.starts_with("NR_")) && !name.contains('.'))
                .then(|| (name.to_string(), u64::from_str_radix(f[0], 16).expect("hex")))
        })
        .collect()
}

/// Does the function at `va` leave by an indirect jump whose address is read out of a
/// table, by `objdump`: a `jmp *` and, before it in the function, an operand with an
/// index (`(,%eax,4)`, `(%rip,%rax,8)`)? Its extent is up to the next symbol `nm` lists.
fn jumps_through_a_table(file: &Path, va: u64) -> bool {
    let out = Command::new("nm").env("LC_ALL", "C").arg("--defined-only").arg(file).output().expect("nm");
    let next = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| u64::from_str_radix(l.split_whitespace().next()?, 16).ok())
        .filter(|&a| a > va)
        .min()
        .unwrap_or(va + 0x100);
    let out = Command::new("objdump")
        .env("LC_ALL", "C")
        .args(["-d", "--no-show-raw-insn", &format!("--start-address={va:#x}"), &format!("--stop-address={next:#x}")])
        .arg(file)
        .output()
        .expect("objdump");
    let text = String::from_utf8_lossy(&out.stdout);
    let insns: Vec<&str> = text.lines().filter_map(|l| l.split_once(":\t").map(|(_, i)| i.trim())).collect();
    let indexed = |i: &str| i.split('(').skip(1).any(|op| op.split(')').next().is_some_and(|inner| inner.split(',').count() == 3));
    insns.iter().enumerate().any(|(k, i)| i.starts_with("jmp") && i.contains('*') && (indexed(i) || insns[..k].iter().any(|j| indexed(j))))
}

fn returns(file: &Path, va: u64) -> Value {
    let mut cmd = support::isolated(Command::new(n0xis_exe()));
    let out = cmd.args(["function", "summary", "--quiet", "--file"]).arg(file).args(["--addr", &format!("{va:#x}")]).output().expect("n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("no envelope ({e})"));
    assert_eq!(v["ok"], true, "{v}");
    v["data"]["summaries"][0]["returns"].clone()
}

#[test]
fn every_function_says_whether_it_returns() {
    let builds: &[(&str, &str, &[&str])] = &[
        ("gcc", "gcc", &["-O2"]),
        ("clang", "clang", &["-O2"]),
        ("i386", "gcc", &["-m32", "-O2", "-fno-pie", "-no-pie"]),
        ("i386-pie", "gcc", &["-m32", "-O2", "-fPIE", "-pie"]),
        ("pe32", "i686-w64-mingw32-gcc", &["-O2"]),
    ];
    let mut asked = 0;
    let mut wrong = Vec::new();
    let unknown = serde_json::json!({ "unknown": true });
    for (tag, compiler, flags) in builds {
        let Some(file) = build(tag, compiler, flags) else { continue };
        let found = functions(&file);
        assert_eq!(found.len(), 13, "{tag}: nm lists the fixture's 13 functions: {found:?}");
        let mut not_known = 0;
        for (name, va) in found {
            asked += 1;
            let want = name.starts_with("RET_");
            let got = returns(&file, va);
            if got == unknown && jumps_through_a_table(&file, va) {
                not_known += 1;
            } else if got != Value::Bool(want) {
                wrong.push(format!("{tag} {name} {va:#x}: {got}, the source says {want}"));
            }
        }
        eprintln!("{tag}: {not_known} not known, each leaving by a jump through a table");
    }
    assert!(asked > 0, "no build ran: nothing was asked");
    assert!(wrong.is_empty(), "{} of {asked} wrong:\n{}", wrong.len(), wrong.join("\n"));
}
