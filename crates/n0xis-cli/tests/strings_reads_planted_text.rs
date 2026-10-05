// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`strings`** on text planted before the tool is asked: the fixture
//! `fixtures/strings_planted.so` is built from `fixtures/strings_planted.c`,
//! which holds an ASCII string, a UTF-8 string in Cyrillic, a UTF-16 string,
//! and one string too short to count. Where each lies was read with `nm` and
//! `readelf` (binutils), not with this tool.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

const ASCII: u64 = 0x2050;
const UTF8: u64 = 0x2030;
const WIDE: u64 = 0x2010;
const SHORT: u64 = 0x2000;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/strings_planted.so")
}

fn strings(cwd: &Path, extra: &[&str]) -> Value {
    let out = Command::new(n0xis_exe())
        .current_dir(cwd)
        .args(["strings", "--file"])
        .arg(fixture())
        .args(extra)
        .output()
        .expect("run n0xis");
    serde_json::from_slice(&out.stdout).expect("one envelope")
}

fn at(found: &Value, va: u64) -> Option<Value> {
    found["data"]["strings"].as_array()?.iter().find(|s| s["address"] == format!("{va:#x}")).cloned()
}

fn project() -> PathBuf {
    // A `.n0x/` here keeps anything the engine writes out of the user's global project.
    let dir = std::env::temp_dir().join(format!("n0xis-strings-{}", std::process::id()));
    std::fs::create_dir_all(dir.join(".n0x")).expect("temp project");
    dir
}

#[test]
fn every_planted_string_is_found_where_the_symbol_table_puts_it() {
    if !n0xis_exe().exists() {
        return; // binary not built in this profile
    }
    let cwd = project();
    let all = strings(&cwd, &["--limit", "0"]);
    assert_eq!(all["ok"], true, "{all}");
    assert_eq!(all["meta"]["schema"], "n0xis.strings.v1");
    let expect = [
        (ASCII, "n0xis-planted-ascii-7f3a", "utf8", 24, 24),
        (UTF8, "Привіт, n0xis", "utf8", 13, 19),
        (WIDE, "n0xis wide ✓", "utf16le", 12, 24),
    ];
    for (va, text, encoding, length, size) in expect {
        let s = at(&all, va).unwrap_or_else(|| panic!("nothing found at {va:#x}: {all}"));
        assert_eq!(s["text"], text, "{s}");
        assert_eq!(s["encoding"], encoding, "{s}");
        assert_eq!((s["length"].as_u64(), s["size"].as_u64()), (Some(length), Some(size)), "{s}");
        assert_eq!(s["section"], ".rodata", "{s}");
    }
    assert!(at(&all, SHORT).is_none(), "three characters are fewer than the default four");
    assert!(at(&strings(&cwd, &["--min", "3", "--limit", "0"]), SHORT).is_some(), "and are a string at --min 3");
    let read: Vec<&str> = all["data"]["ranges"].as_array().expect("ranges").iter().filter_map(|r| r["name"].as_str()).collect();
    assert!(read.contains(&".rodata") && !read.contains(&".text"), "code is not read unless asked: {read:?}");

    let filtered = strings(&cwd, &["--contains", "ПРИВІТ"]);
    assert_eq!(filtered["meta"]["total"], 1, "the filter ignores case in any script: {filtered}");
    assert!(at(&filtered, UTF8).is_some());

    let total = all["meta"]["total"].as_u64().expect("total");
    let page = strings(&cwd, &["--limit", "1", "--offset", "1"]);
    assert_eq!((page["meta"]["total"].as_u64(), page["meta"]["returned"].as_u64()), (Some(total), Some(1)));
    assert_eq!(page["data"]["strings"][0], all["data"]["strings"][1], "a page is a slice of the one list");
    let _ = std::fs::remove_dir_all(&cwd);
}
