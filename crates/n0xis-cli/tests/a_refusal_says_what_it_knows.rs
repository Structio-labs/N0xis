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

/// `sig gen` on an image that names no function is not a library of none: a
/// PE whose names are in no table this reader reads (here no export table and
/// no COFF symbols; on the audit's mingw image, a COFF symbol table) answered
/// `functions_total: 0, ok: true` over the functions its `.text` holds.
#[test]
fn sig_gen_on_an_image_that_names_nothing_refuses() {
    const PE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/imports/ordinals-i686.exe");
    let dir = project("sig-gen");
    let a = n0x(&dir, &["sig", "gen", "--file", PE]);
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"]["code"], "no-named-functions", "{a}");
}

/// `ir slice` of a name that is no register, or at a place outside the
/// function, answered `ok: true` with no nodes: the shape of "nothing computes
/// it" (audit 2026-11-06). The bytes are `mov rax, rdi; ret` at 0x1000.
#[test]
fn ir_slice_of_no_register_or_outside_the_function_refuses() {
    let dir = project("slice");
    let base = ["ir", "slice", "--bytes", "48 89 f8 c3", "--addr", "0x1000"];
    let ok = n0x(&dir, &[&base[..], &["--reg", "rax"]].concat());
    assert_eq!(ok["data"]["node_count"], 1, "{ok}");
    let unknown = n0x(&dir, &[&base[..], &["--reg", "zzz"]].concat());
    assert_eq!(unknown["error"]["code"], "unknown-register", "{unknown}");
    let outside = n0x(&dir, &[&base[..], &["--reg", "rax", "--at", "0x10"]].concat());
    assert_eq!(outside["error"]["code"], "not-in-function", "{outside}");
    // Inside the function, past the last write, is a place: rax at the `ret`.
    let inside = n0x(&dir, &[&base[..], &["--reg", "rax", "--at", "0x1003"]].concat());
    assert_eq!(inside["data"]["node_count"], 1, "{inside}");
}
