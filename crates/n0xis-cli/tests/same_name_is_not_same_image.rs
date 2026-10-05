// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Two files of one name are two images.**
//!
//! A long-running process (the MCP server, anything that dispatches many
//! requests) keeps work between requests: the unwind map, the function list,
//! the reverse-xref index. Those memos were keyed by the source's label,
//! `static:<file name>`, so a file asked about after another file of the same
//! name was answered partly from the other: `function discover` counted 4
//! functions in a file that has 10, with `ok: true`.
//!
//! Each answer below, given in one process after the other file's, must equal
//! the answer a fresh process gives. One test in its own binary, because it
//! moves the process into a scratch project: without a `.n0x/` the engine
//! would keep what it writes in the user's global project.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

/// What a fresh process answers.
fn fresh(cwd: &Path, args: &[&str]) -> Value {
    let out = Command::new(n0xis_exe()).current_dir(cwd).args(args).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).expect("one envelope")
}

/// The part of an answer that must not depend on what was asked before.
fn answer(v: &Value) -> (Value, Value, Value) {
    (v["ok"].clone(), v["data"].clone(), v["meta"]["total"].clone())
}

#[test]
fn a_file_is_not_answered_from_another_file_of_the_same_name() {
    if !n0xis_exe().exists() {
        return; // binary not built in this profile
    }
    let root = std::env::temp_dir().join(format!("n0xis-same-name-{}", std::process::id()));
    for dir in ["A", "B", ".n0x"] {
        std::fs::create_dir_all(root.join(dir)).expect("scratch project");
    }
    // Two different images under one name: an ELF shared object and a PE DLL,
    // both checked-in fixtures.
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    std::fs::copy(fixtures.join("../n0xis-sources/tests/fixtures/tls_overlap.so"), root.join("A/t.so")).expect("copy A");
    std::fs::copy(fixtures.join("tests/fixtures/native_pe.dll"), root.join("B/t.so")).expect("copy B");
    let a = root.join("A/t.so");
    let b = root.join("B/t.so");
    let (a, b) = (a.to_str().expect("utf-8"), b.to_str().expect("utf-8"));

    let discover = |file: &str| json!({ "file": file, "limit": 0 });
    let xref = |file: &str| json!({ "file": file, "addr": "0x1109", "dir": "to" });
    let want_discover_a = answer(&fresh(&root, &["function", "discover", "--file", a, "--limit", "0", "--quiet"]));
    let want_discover_b = answer(&fresh(&root, &["function", "discover", "--file", b, "--limit", "0", "--quiet"]));
    let want_xref_a = answer(&fresh(&root, &["xref", "to", "--file", a, "--addr", "0x1109"]));
    assert_eq!(want_discover_a.0, true, "the fixture is discovered: {want_discover_a:?}");
    assert_ne!(want_discover_a.2, want_discover_b.2, "the two files differ in what they hold");

    std::env::set_current_dir(&root).expect("into the scratch project");
    let registry = n0xis_frontend::build_registry();
    let ask = |cap: &str, args: Value| answer(&serde_json::to_value(registry.dispatch(cap, &args)).expect("an envelope"));
    for (file, want) in [(b, &want_discover_b), (a, &want_discover_a), (b, &want_discover_b), (a, &want_discover_a)] {
        assert_eq!(&ask("function.discover", discover(file)), want, "function discover on {file}, after the other file");
    }
    assert_eq!(ask("xref", xref(b)).0, true);
    assert_eq!(ask("xref", xref(a)), want_xref_a, "xref to on {a}, after the other file's index was built");

    let _ = std::env::set_current_dir(std::env::temp_dir());
    let _ = std::fs::remove_dir_all(&root);
}
