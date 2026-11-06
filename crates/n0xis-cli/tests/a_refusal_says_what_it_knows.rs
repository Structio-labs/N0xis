// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A refusal says what happened.** Each of these was true and of no use: an
//! argument refused against the docs' own number rule, a message about PE on a command
//! that reads ELF, and "address not mapped" for an image with no such table.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

mod support;

const ELF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/strings_planted.so");

fn project(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis-refusal-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("a project of its own");
    dir
}

fn n0x(dir: &PathBuf, args: &[&str]) -> Value {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).current_dir(dir).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{args:?}: {e}: {}", String::from_utf8_lossy(&out.stdout)))
}

#[test]
fn find_takes_a_hex_size_as_every_size_is_taken() {
    let dir = project("find");
    let hex = n0x(&dir, &["find", "--file", ELF, "--bytes", "48", "--start", "0x1000", "--size", "0x200"]);
    let decimal = n0x(&dir, &["find", "--file", ELF, "--bytes", "48", "--start", "0x1000", "--size", "512"]);
    assert_eq!(hex["ok"], true, "{hex}");
    assert_eq!(hex["data"], decimal["data"]);
}

#[test]
fn pdata_on_an_image_without_it_says_so() {
    let dir = project("pdata");
    let a = n0x(&dir, &["function", "discover", "--file", ELF, "--pdata"]);
    assert_eq!(a["error"]["code"], "discover-failed", "{a}");
    let message = a["error"]["message"].as_str().expect("a message");
    assert!(message.contains(".pdata"), "{a}");
    assert!(!message.contains("not mapped"), "{a}");
}

#[test]
fn analyze_on_what_it_does_not_take_does_not_ask_for_a_pe() {
    let dir = project("analyze");
    let saved = n0x(&dir, &["snapshot", "dump", "--file", ELF, "--name", "s"]);
    assert_eq!(saved["ok"], true, "{saved}");
    let a = n0x(&dir, &["analyze", "--snapshot", "s"]);
    assert_eq!(a["error"]["code"], "unsupported", "{a}");
    let message = a["error"]["message"].as_str().expect("a message");
    assert!(message.contains("--file"), "{a}");
    assert!(!message.contains("needs a static PE"), "the same command reads an ELF: {a}");
}
