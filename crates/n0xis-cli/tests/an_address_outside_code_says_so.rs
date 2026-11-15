// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Code asked for where the image keeps none says so, in `decomp` as in
//! `disasm`, by one rule.**
//!
//! Both decode the bytes at an address they are handed, whatever the section
//! there is; that is what was asked for. What they must not do is answer as if
//! the bytes were code: a claims audit (2026-11-06) recorded `decomp pseudo` at
//! an address in `.rodata` as `ok`, quality 0.5, with nothing said. Re-measured
//! 2026-11-15, the answer carried the statement `disasm` carries, and the
//! audit's own pattern (`not executable`) did not match its words (`not in any
//! section this image marks executable`): no test held it, so nothing kept it.
//!
//! The truth is the section's flags as `readelf -SW` recorded them beside the
//! fixture (`fixtures/discovery/x86_64.so.sections.txt`): `.eh_frame` at
//! `0x3000` is `A` (no `X`); `.text` from `0x1020` is `AX`.

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
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/discovery").join(name)
}

/// `readelf -SW`'s flags for the section starting at `va`.
fn flags_at(va: u64) -> String {
    let text = std::fs::read_to_string(fixture("x86_64.so.sections.txt")).expect("the recorded section table");
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_once(']')?.1.split_whitespace().collect();
            (u64::from_str_radix(f.get(2)?, 16).ok()? == va).then(|| f.get(6).copied().unwrap_or("").to_string())
        })
        .next()
        .unwrap_or_else(|| panic!("no section at {va:#x} in the record"))
}

fn note(args: &[&str]) -> Option<Option<String>> {
    let exe = n0xis_exe();
    if !exe.exists() {
        eprintln!("skipping: {} not built", exe.display());
        return None;
    }
    let dir = std::env::temp_dir().join(format!("n0xis-outside-code-{}-{}", std::process::id(), args[0]));
    std::fs::create_dir_all(dir.join(".n0x")).expect("project dir");
    let out = support::isolated(Command::new(&exe)).current_dir(&dir).args(args).output().expect("run n0xis");
    let _ = std::fs::remove_dir_all(&dir);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("not one JSON object ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    assert_eq!(v["ok"], Value::Bool(true), "{v}");
    Some(v["meta"]["note"].as_str().map(str::to_string))
}

const NOT_CODE: &str = "is not in any section this image marks executable";

#[test]
fn decomp_and_disasm_say_an_address_in_a_section_without_code_is_not_code() {
    assert!(!flags_at(0x3000).contains('X') && flags_at(0x1020).contains('X'), "the record says what the test assumes");
    let so = fixture("x86_64.so");
    let so = so.to_str().unwrap();
    for cmd in [&["decomp", "pseudo"][..], &["disasm"][..]] {
        let at = |addr: &str| note(&[cmd, &["--file", so, "--addr", addr][..]].concat());
        let Some(outside) = at("0x3000") else { return };
        assert!(outside.as_deref().is_some_and(|n| n.contains(&format!("0x3000 {NOT_CODE}"))), "{cmd:?} at .eh_frame: {outside:?}");
        let Some(inside) = at("0x1030") else { return };
        assert!(!inside.as_deref().is_some_and(|n| n.contains(NOT_CODE)), "{cmd:?} in .text: {inside:?}");
    }
}
