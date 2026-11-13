// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A count of nothing says what kind of thing was not read.** `rtti scan` on a
//! PE reads MSVC's RTTI only; on a PE built for the GNU ABI, whose classes are
//! Itanium `_ZTV`/`_ZTI` objects, it answered `count: 0` and nothing else, the
//! shape of "this image has no class" (audit 2026-11-06).

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

mod support;

fn n0x(args: &[&str]) -> Value {
    let dir: PathBuf = std::env::temp_dir().join(format!("n0xis-nothing-{}", std::process::id()));
    std::fs::create_dir_all(dir.join(".n0x")).expect("a project of its own");
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).current_dir(&dir).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{args:?}: {e}: {}", String::from_utf8_lossy(&out.stdout)))
}

#[test]
fn an_rtti_scan_of_a_pe_that_finds_nothing_says_only_msvc_is_read() {
    // A mingw-built PE: no MSVC RTTI in it.
    const PE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/chained/chained.dll");
    let v = n0x(&["rtti", "scan", "--file", PE]);
    assert_eq!(v["data"]["count"], 0, "{v}");
    let said = v["data"]["not_read"].as_str().unwrap_or_else(|| panic!("nothing said of what was not read: {v}"));
    assert!(said.contains("only MSVC RTTI is read") && said.contains("Itanium"), "{v}");
}
