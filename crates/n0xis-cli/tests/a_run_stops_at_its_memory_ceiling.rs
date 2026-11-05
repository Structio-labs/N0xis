// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A run past its memory ceiling answers `out-of-memory` in the usual envelope.
//! Killed by the kernel it would answer nothing, and raise a desktop alarm.

use std::process::{Command, Output};

use serde_json::Value;

mod support;

/// The engine's own file: tens of megabytes, known to be there.
const BIG: &str = env!("CARGO_BIN_EXE_n0xis");

fn project(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis_ceiling_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("project");
    dir
}

/// With `--min 1` this file's rows alone take gigabytes, so the low ceiling is asked
/// with it and the others without.
fn strings_of_itself(tag: &str, ceiling: &str, min: &str) -> Output {
    let out = support::isolated(Command::new(BIG))
        .args(["strings", "--file", BIG, "--limit", "0", "--min", min, "--quiet"])
        .env("N0X_MEMORY_MAX", ceiling)
        .current_dir(project(tag))
        .output()
        .expect("run n0xis");
    let _ = std::fs::remove_dir_all(project(tag));
    out
}

#[test]
fn past_the_ceiling_is_an_answer_and_not_a_death() {
    let out = strings_of_itself("low", "8M", "1");
    let answer: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!("one JSON object: {e}; status {:?}; stderr {}", out.status, String::from_utf8_lossy(&out.stderr))
    });
    assert_eq!(answer["ok"], false, "{answer}");
    assert_eq!(answer["error"]["code"], "out-of-memory", "{answer}");
    assert!(answer["error"]["message"].as_str().is_some_and(|m| m.contains("8 MiB")), "it says which ceiling: {answer}");
    assert_eq!(out.status.code(), Some(2), "the exit code of `ok:false`");
}

#[test]
fn under_the_ceiling_nothing_changes() {
    let out = strings_of_itself("high", "2G", "8");
    let answer: Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
    assert_eq!(answer["ok"], true, "{answer}");
    assert!(answer["data"]["count"].as_u64().is_some_and(|n| n > 1000), "and it found its strings");
}

/// A value that cannot be read is no ceiling of its own: the host's still holds.
#[test]
fn a_ceiling_that_does_not_read_is_ignored() {
    let out = strings_of_itself("wrong", "lots", "8");
    let answer: Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
    assert_eq!(answer["ok"], true, "{answer}");
}
