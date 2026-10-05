// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`concept grep` was renamed from `game grep`; the catalog shows one name and
//! the old one still runs.**
//!
//! Two promises, each of which can break without anything else noticing:
//!
//! - `n0x guide` is what an agent reads instead of guessing. It must list the
//!   command under its current name, in its category, and must not list the
//!   old name beside it — a second entry would also move the command count the
//!   documents state.
//! - Every script written against `game grep` must keep getting the same
//!   answer. The parse-level check lives beside the CLI definition
//!   (`concept_alias_tests` in `main.rs`); this one runs the binary on a
//!   directory planted here, whose answer is known before either spelling is
//!   asked, and requires both spellings to return it.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn run(args: &[&str]) -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_n0xis")).args(args).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("`n0xis {}` printed no envelope ({e}); stderr: {}", args.join(" "), String::from_utf8_lossy(&out.stderr)))
}

/// Every leaf command in the catalog, as `(path, category)`.
fn catalog() -> Vec<(String, String)> {
    let v = run(&["guide", "--brief", "--quiet"]);
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
fn the_guide_does_not_list_the_first_name() {
    let old: Vec<String> = catalog().into_iter().map(|(p, _)| p).filter(|p| p.split(' ').next() == Some("game")).collect();
    assert!(old.is_empty(), "the guide lists the retired name `game`: {old:?}");
}

#[test]
fn the_guide_lists_concept_grep_in_the_method_tooling_category() {
    let cat = catalog();
    let found = cat.iter().find(|(p, _)| p == "concept grep");
    assert!(found.is_some(), "the guide does not list `concept grep`");
    // The category map is keyed by the top-level name, so a rename that misses
    // it drops the command into "Other" without any other test noticing.
    assert_eq!(found.map(|(_, c)| c.as_str()), Some("Spec-first method tooling (Phase 8)"));
}

/// A directory whose ranking is known by construction: one file carries two of
/// the three terms, one carries one, one carries none.
fn plant(dir: &Path) {
    std::fs::create_dir_all(dir).expect("temp dir");
    std::fs::write(dir.join("both.txt"), "call retry() then backoff(250)\n").expect("write");
    std::fs::write(dir.join("one.txt"), "timeout = 30\n").expect("write");
    std::fs::write(dir.join("none.txt"), "nothing to see here\n").expect("write");
}

#[test]
fn both_names_return_the_same_answer_on_a_planted_directory() {
    let dir: PathBuf = std::env::temp_dir().join(format!("n0xis_concept_grep_{}", std::process::id()));
    plant(&dir);
    let d = dir.to_string_lossy().to_string();
    let new = run(&["concept", "grep", "retry,backoff,timeout", "--dir", &d, "--quiet"]);
    let old = run(&["game", "grep", "retry,backoff,timeout", "--dir", &d, "--quiet"]);
    let _ = std::fs::remove_dir_all(&dir);

    // The planted answer first, so the comparison below cannot pass by both
    // spellings failing, or both answering nothing, in the same way.
    assert_eq!(new["ok"], Value::Bool(true), "concept grep failed: {new}");
    assert_eq!(new["data"]["documents_scanned"], 3);
    assert_eq!(new["data"]["documents_matched"], 2);
    let top = new["data"]["hits"][0]["id"].as_str().unwrap_or_default();
    assert!(top.ends_with("both.txt"), "the two-term file must rank first, got {top:?}");

    assert_eq!(old, new, "`game grep` and `concept grep` answered differently");
}
