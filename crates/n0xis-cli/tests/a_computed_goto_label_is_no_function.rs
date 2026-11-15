// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A label a computed `goto` lands on is no function's start.**
//!
//! Built with control-flow protection, the compiler marks every place an
//! indirect jump may land with `endbr64`: a function's entry, and a label
//! whose address `&&label` takes. Discovery trusts that marker inside an
//! unwind range, where it trusts no other pattern, so that two entries
//! sharing one range stay two; and on a static executable without symbols it
//! listed 24 labels of glibc's printf as functions (24 of 1 126 starts inside
//! a function `nm` sizes on the unstripped twin), and `why` called each a
//! start.
//!
//! The truth is `nm -S` of the same build with its symbols, and `objdump`
//! says where the labels are: `oracle/computed_goto.c`, built with `gcc -O2
//! -fcf-protection=full -falign-labels=16` and stripped.

#![cfg(feature = "oracle")]

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

fn tool(dir: &Path, args: &[&str]) -> Value {
    let out = support::isolated(Command::new(n0xis_exe())).current_dir(dir).args(args).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("not one JSON object ({e}): {}", String::from_utf8_lossy(&out.stdout)))
}

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex")
}

/// The build with symbols, its stripped twin, and the directory they are in;
/// `None` with a printed reason where no compiler or binutils is installed.
fn build(tag: &str) -> Option<(tempdir::Dir, PathBuf, PathBuf)> {
    let dir = tempdir::Dir::new(tag);
    std::fs::create_dir_all(dir.path().join(".n0x")).ok()?;
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../oracle/computed_goto.c");
    let full = dir.path().join("goto");
    let stripped = dir.path().join("goto.stripped");
    let built = Command::new("gcc")
        .args(["-O2", "-fcf-protection=full", "-falign-labels=16", "-o"])
        .arg(&full)
        .arg(&src)
        .status()
        .is_ok_and(|s| s.success());
    let strip = built && Command::new("strip").arg("-o").arg(&stripped).arg(&full).status().is_ok_and(|s| s.success());
    if !strip {
        eprintln!("skipping: gcc or strip unavailable or failed");
        return None;
    }
    Some((dir, full, stripped))
}

/// `nm -S`: every sized code symbol, `(start, end, name)`.
fn sized_functions(binary: &Path) -> Vec<(u64, u64, String)> {
    let out = Command::new("nm").env("LC_ALL", "C").args(["-S", "--defined-only"]).arg(binary).output().expect("nm");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| match l.split_whitespace().collect::<Vec<_>>()[..] {
            [a, z, t, name] if "tTwW".contains(t) => {
                let (a, z) = (u64::from_str_radix(a, 16).ok()?, u64::from_str_radix(z, 16).ok()?);
                (z > 0).then(|| (a, a + z, name.to_string()))
            }
            _ => None,
        })
        .collect()
}

/// `objdump -d`: the `endbr64`s strictly inside `run`, on a 16-byte boundary,
/// where the labels are. The fixture holds the shape the test is about, or the
/// test proves nothing.
fn labels(binary: &Path, run: (u64, u64)) -> Vec<u64> {
    let out = Command::new("objdump").env("LC_ALL", "C").arg("-d").arg(binary).output().expect("objdump");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.trim_end().ends_with("endbr64"))
        .filter_map(|l| u64::from_str_radix(l.split(':').next()?.trim(), 16).ok())
        .filter(|&a| a > run.0 && a < run.1 && a % 16 == 0)
        .collect()
}

#[test]
fn discovery_lists_no_label_of_a_computed_goto_as_a_function() {
    let Some((dir, full, stripped)) = build("goto-discover") else { return };
    let truth = sized_functions(&full);
    let run = truth.iter().find(|(_, _, n)| n == "run").map(|(a, e, _)| (*a, *e)).expect("nm: run");
    let labels = labels(&full, run);
    assert!(labels.len() >= 5, "the build has the labels the test is about (objdump): {labels:x?}");

    let v = tool(dir.path(), &["function", "discover", "--file", stripped.to_str().unwrap(), "--limit", "0"]);
    let starts: Vec<u64> = v["data"]["functions"].as_array().unwrap_or_else(|| panic!("{v}")).iter().map(|f| hex(f["va"].as_str().unwrap())).collect();
    let inside: Vec<(u64, &str)> =
        starts.iter().filter_map(|&a| truth.iter().find(|(s, e, _)| *s < a && a < *e).map(|(_, _, n)| (a, n.as_str()))).collect();
    assert!(inside.is_empty(), "starts inside a function nm sizes: {inside:x?}");
    assert!(starts.contains(&run.0), "run itself is found: {starts:x?}");
}

#[test]
fn why_calls_a_label_of_a_computed_goto_no_start() {
    let Some((dir, full, stripped)) = build("goto-why") else { return };
    let truth = sized_functions(&full);
    let run = truth.iter().find(|(_, _, n)| n == "run").map(|(a, e, _)| (*a, *e)).expect("nm: run");
    let label = *labels(&full, run).first().expect("objdump: a label");
    let v = tool(dir.path(), &["why", "--file", stripped.to_str().unwrap(), "--addr", &format!("{label:#x}")]);
    let found = &v["data"]["function"]["found"];
    assert_eq!(found["addr_is_start"], Value::Bool(false), "{label:#x} is inside run ({:#x}..{:#x}): {v}", run.0, run.1);
    assert_eq!(hex(found["start"].as_str().unwrap_or_else(|| panic!("{v}"))), run.0, "{v}");
}

/// A directory removed when the test ends, without a crate for it.
mod tempdir {
    pub struct Dir(std::path::PathBuf);
    impl Dir {
        pub fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("n0xis-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).expect("temp dir");
            Dir(p)
        }
        pub fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
