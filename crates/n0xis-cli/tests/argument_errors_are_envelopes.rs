// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The envelope has to survive an argument error.**
//!
//! The documented contract is that every command emits exactly one JSON object
//! on stdout and exits non-zero on failure. A wrong flag did neither: the
//! argument parser printed a usage message to stderr, wrote nothing at all to
//! stdout, and exited 2. A consumer written against the contract got an empty
//! stdout and no error code to branch on — a second failure format for the one
//! thing the tool promises there is only one of.
//!
//! `--help` and `--version` are not failures and keep their plain rendering:
//! a caller asking for help wants the text.

use std::process::Command;

use serde_json::Value;

fn n0xis_exe() -> std::path::PathBuf {
    // `target/<profile>/deps/<test>` → `target/<profile>/n0xis`
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

fn run(args: &[&str]) -> Option<(i32, String, String)> {
    let exe = n0xis_exe();
    if !exe.exists() {
        eprintln!("skipping: {} not built", exe.display());
        return None;
    }
    let out = Command::new(&exe).args(args).output().expect("run n0xis");
    Some((
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    ))
}

/// The failing envelope, or a panic naming what came out instead.
fn error_envelope(args: &[&str]) -> Value {
    let Some((code, stdout, stderr)) = run(args) else { return Value::Null };
    assert_eq!(code, 2, "an argument error exits 2; stdout={stdout:?} stderr={stderr:?}");
    let v: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is not one JSON object ({e}): {stdout:?} / stderr {stderr:?}"));
    assert_eq!(v["ok"], Value::Bool(false), "{v}");
    v
}

#[test]
fn a_missing_required_argument_is_an_envelope_not_a_usage_message() {
    let v = error_envelope(&["scan", "aob", "--file", "/nonexistent"]);
    if v.is_null() {
        return;
    }
    assert_eq!(v["error"]["code"], "bad-arguments");
    let msg = v["error"]["message"].as_str().unwrap_or_default();
    assert!(msg.contains("--pattern"), "the message must name the missing flag: {msg}");
}

#[test]
fn an_unknown_subcommand_is_an_envelope_too() {
    let v = error_envelope(&["definitely-not-a-command"]);
    if v.is_null() {
        return;
    }
    assert_eq!(v["error"]["code"], "bad-arguments");
}

#[test]
fn help_is_not_a_failure_and_keeps_its_own_rendering() {
    let Some((code, stdout, _)) = run(&["scan", "aob", "--help"]) else { return };
    assert_eq!(code, 0, "--help succeeds");
    assert!(stdout.contains("--pattern"), "help still lists the flags: {stdout}");
    assert!(serde_json::from_str::<Value>(stdout.trim()).is_err(), "help is text, not an envelope");
}

#[test]
fn naming_two_targets_is_refused_by_both_source_paths() {
    // A capability-dispatched command, which resolves its source through the
    // shared frontend seam…
    let Some((_, stdout, _)) = run(&["find", "--string", "x", "--file", "/nonexistent", "--snapshot", "nope", "--quiet"]) else {
        return;
    };
    let v: Value = serde_json::from_str(stdout.trim()).expect("one envelope");
    assert_eq!(v["error"]["code"], "ambiguous-source", "{v}");

    // …and `disasm`, which resolves its own (it needs the image base for its
    // out-of-image hint). Two implementations of "which target" is how the
    // question got two answers; both must refuse.
    let Some((_, stdout, _)) = run(&["disasm", "--addr", "0x0", "--bytes", "48 89 c8 c3", "--file", "/nonexistent", "--quiet"]) else {
        return;
    };
    let v: Value = serde_json::from_str(stdout.trim()).expect("one envelope");
    assert_eq!(v["error"]["code"], "ambiguous-source", "{v}");
}
