// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`table pin` was renamed from `table freeze`; the catalog shows one name and
//! the old one still runs.**
//!
//! The same three promises as `concept_grep_keeps_its_first_name.rs`:
//!
//! - `n0x guide` lists the command under its current name, in its category,
//!   and not under the old name beside it — a second entry would also move the
//!   command count the documents state.
//! - The old spelling parses to exactly the same command with the same
//!   arguments (`table_pin_alias_tests` in `main.rs`).
//! - A call spelled the old way answers as it did. On Windows that is the
//!   schema id `n0xis.freeze.v1` against `n0xis.pin.v1` for the new spelling
//!   (the mapping is checked in `renamed_command_tests`); off Windows the
//!   command refuses before it writes anything, and the refusal names the
//!   command the way the caller spelled it, which is what is run here.

use std::path::Path;
use std::process::Command;

use serde_json::Value;

fn run_in(dir: &Path, args: &[&str]) -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_n0xis")).args(args).current_dir(dir).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("`n0xis {}` printed no envelope ({e}); stderr: {}", args.join(" "), String::from_utf8_lossy(&out.stderr)))
}

/// Every leaf command in the catalog, as `(path, category)`.
fn catalog() -> Vec<(String, String)> {
    let v = run_in(&std::env::temp_dir(), &["guide", "--brief", "--quiet"]);
    assert_eq!(v["ok"], Value::Bool(true), "guide failed: {v}");
    v["data"]["commands"]
        .as_array()
        .expect("guide carries a command array")
        .iter()
        .map(|c| {
            (
                c["path"].as_str().expect("every command has a path").to_string(),
                c["category"].as_str().expect("every command has a category").to_string(),
            )
        })
        .collect()
}

#[test]
fn the_guide_lists_table_pin_and_not_table_freeze() {
    let cat = catalog();
    let found = cat.iter().find(|(p, _)| p == "table pin");
    assert_eq!(found.map(|(_, c)| c.as_str()), Some("Live memory"), "the guide must list `table pin` under Live memory");
    let old: Vec<&String> = cat.iter().map(|(p, _)| p).filter(|p| p.as_str() == "table freeze").collect();
    assert!(old.is_empty(), "the guide lists the retired name: {old:?}");
}

/// A fresh project with one table entry, so the command reaches its platform
/// gate instead of refusing for the ordinary reason (no such table).
#[cfg(not(windows))]
fn project_with_an_entry() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis_table_pin_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let v = run_in(&dir, &["init", "--name", "pin-test", "--quiet"]);
    assert_eq!(v["ok"], Value::Bool(true), "init failed: {v}");
    let v = run_in(&dir, &["table", "add", "--table", "t", "--name", "counter", "--addr", "0x1000", "--type", "i32", "--quiet"]);
    assert_eq!(v["ok"], Value::Bool(true), "table add failed: {v}");
    dir
}

#[cfg(not(windows))]
#[test]
fn off_windows_each_spelling_refuses_under_its_own_name() {
    let dir = project_with_an_entry();
    let args = ["--table", "t", "--name", "counter", "--pid", "1", "--value", "5", "--quiet"];
    let mut answers = Vec::new();
    for sub in ["pin", "freeze"] {
        let argv: Vec<&str> = ["table", sub].into_iter().chain(args).collect();
        answers.push((sub, run_in(&dir, &argv)));
    }
    let _ = std::fs::remove_dir_all(&dir);
    for (sub, v) in &answers {
        assert_eq!(v["ok"], Value::Bool(false), "`table {sub}` must refuse off Windows: {v}");
        assert_eq!(v["error"]["code"], "live-unsupported", "`table {sub}` must reach the platform gate: {v}");
        let msg = v["error"]["message"].as_str().unwrap_or_default();
        assert!(msg.starts_with(&format!("table {sub} ")), "`table {sub}` refused under another name: {msg:?}");
    }
}
