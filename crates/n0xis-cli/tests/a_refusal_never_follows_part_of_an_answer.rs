// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Standard output holds one answer. An answer is written as it serializes, so part of it
//! may have left when something goes wrong, and a second envelope after that part would
//! be neither of the two. `examples/an_answer_past_the_ceiling.rs` plants the moment.

use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

#[cfg(unix)]
mod support;

fn example() -> PathBuf {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_n0xis"));
    let built = bin.parent().expect("a directory").join("examples").join(format!("an_answer_past_the_ceiling{}", std::env::consts::EXE_SUFFIX));
    assert!(built.exists(), "{}: `cargo test` builds examples", built.display());
    built
}

fn run(args: &[&str]) -> Output {
    Command::new(example()).args(args).output().expect("run the example")
}

fn text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn past_the_ceiling_while_writing_the_answer_is_written_whole() {
    let out = run(&["takes-memory"]);
    let answer: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!("one JSON object: {e}; {} bytes; ends {:?}", out.stdout.len(), text(&out).chars().rev().take(200).collect::<String>())
    });
    assert_eq!(answer["ok"], true);
    assert_eq!(answer["data"].as_array().map(Vec::len), Some(8192), "every row");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(text(&out).matches('\n').count(), 1, "and one line");
}

#[test]
fn the_same_when_pretty() {
    let out = run(&["takes-memory", "--pretty"]);
    let answer: Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
    assert_eq!(answer["data"].as_array().map(Vec::len), Some(8192));
    assert!(text(&out).starts_with("{\n  \"ok\": true,\n"), "pretty");
}

/// Lifted while writing, and no longer: a session's next line has its ceiling.
#[test]
fn the_ceiling_is_back_once_the_answer_is_written() {
    let out = run(&["two-answers"]);
    let all = text(&out);
    let lines: Vec<&str> = all.lines().collect();
    assert_eq!(lines.len(), 2, "the answer, then its own refusal: {:?}", out.status);
    let first: Value = serde_json::from_str(lines[0]).expect("the first is whole");
    let second: Value = serde_json::from_str(lines[1]).expect("the second is whole");
    assert_eq!(first["ok"], true);
    assert_eq!(second["error"]["code"], "out-of-memory", "{second}");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn a_failure_to_serialize_with_nothing_written_is_the_whole_answer() {
    let out = run(&["fails-early"]);
    let answer: Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
    assert_eq!(answer["error"]["code"], "serialize", "{answer}");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn a_failure_to_serialize_past_the_first_write_adds_no_second_envelope() {
    let out = run(&["fails-late"]);
    let all = text(&out);
    assert!(all.len() > 64 << 10, "some of it left: {} bytes", all.len());
    assert!(all.starts_with("{\"ok\":true"), "{}", &all[..40]);
    assert!(!all.contains("\"code\""), "nothing after the part that left");
    assert!(String::from_utf8_lossy(&out.stderr).contains("could not be serialized"), "and it is said where it can be");
    assert_eq!(out.status.code(), Some(2), "and by the exit code");
}

/// What a closed pipe has always done, through the real binary. Not pretty, and not this
/// pass's to change: the buffer must not have turned it into something else.
#[cfg(unix)]
#[test]
fn a_closed_pipe_is_what_it_was() {
    use std::process::Stdio;

    let dir = std::env::temp_dir().join(format!("n0xis_closed_pipe_{}", std::process::id()));
    std::fs::create_dir_all(dir.join(".n0x")).expect("a project");
    let mut child = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .args(["capability", "list"])
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run n0xis");
    drop(child.stdout.take());
    let out = child.wait_with_output().expect("wait");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(101), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("failed printing to stdout: Broken pipe"), "{}", String::from_utf8_lossy(&out.stderr));
}
