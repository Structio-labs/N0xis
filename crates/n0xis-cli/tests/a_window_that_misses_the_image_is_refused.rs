// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Asked about a window of a file that gives no byte, the answer is an error.**
//! These commands used to answer `ok: true` with nothing in it, the worst shape an
//! answer can take: the caller has no error to branch on and no reason to doubt that
//! the image holds no such thing, when nothing was looked at.
//!
//! Each command is asked twice about a committed image: a window the image's own
//! section table places (read with `goblin`, outside n0xis), which has to answer,
//! so that a refusal below is not simply a command that refuses everything; and a
//! window past every address the image states.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod support;

const IMAGE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/strings_planted.so");

/// Past every address a small shared object states.
const OUTSIDE: &str = "0x700000000000";

/// A scratch project: a run with none would write to the global one.
fn project(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis-window-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("scratch dir");
    dir
}

fn n0x(dir: &Path, args: &[&str]) -> Value {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).current_dir(dir).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{args:?} did not print one JSON object: {e}\n{}", String::from_utf8_lossy(&out.stdout)))
}

/// `(start, size)` of `.rodata`, from the image's own table.
fn rodata() -> (String, String) {
    let bytes = std::fs::read(IMAGE).expect("read the fixture");
    let elf = goblin::elf::Elf::parse(&bytes).expect("an ELF");
    let s = elf.section_headers.iter().find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".rodata")).expect("a .rodata");
    assert!(s.sh_size >= 4, "the fixture has to hold something");
    (format!("{:#x}", s.sh_addr), s.sh_size.to_string())
}

/// The commands that take a file and a window, each with what else it needs.
fn commands<'a>(start: &'a str, size: &'a str) -> Vec<Vec<&'a str>> {
    let window = |head: &[&'a str], tail: &[&'a str]| {
        let mut a: Vec<&'a str> = head.to_vec();
        a.extend(["--file", IMAGE, "--start", start, "--size", size]);
        a.extend_from_slice(tail);
        a
    };
    vec![
        window(&["scan", "aob"], &["--pattern", "00"]),
        window(&["scan", "value"], &["--type", "u8", "--criterion", "unknown", "--save-as", "w", "--force"]),
        window(&["scan", "group"], &["--field", "u8=0"]),
        window(&["find"], &["--bytes", "00"]),
        window(&["strings"], &[]),
    ]
}

#[test]
fn a_window_the_image_places_is_answered() {
    let dir = project("placed");
    let (start, size) = rodata();
    for args in commands(&start, &size) {
        let v = n0x(&dir, &args);
        assert_eq!(v["ok"], true, "{args:?}: {v}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_window_outside_the_image_is_an_error_saying_nothing_was_read() {
    let dir = project("outside");
    for args in commands(OUTSIDE, "64") {
        let v = n0x(&dir, &args);
        assert_eq!(v["ok"], false, "{args:?} answered: {v}");
        assert_eq!(v["error"]["code"], "nothing-readable", "{args:?}: {v}");
        let message = v["error"]["message"].as_str().expect("a message");
        assert!(message.contains(OUTSIDE), "{args:?}: it names the window: {message}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A scan that read nothing does not put an empty set where a real one was saved.
#[test]
fn a_refused_scan_saves_nothing() {
    let dir = project("saved");
    let (start, size) = rodata();
    let scan = |start: &str, size: &str| n0x(&dir, &["scan", "value", "--file", IMAGE, "--start", start, "--size", size, "--type", "u8", "--criterion", "unknown", "--save-as", "kept", "--force"]);
    let first = scan(&start, &size);
    assert_eq!(first["ok"], true, "{first}");
    let saved = dir.join(".n0x/dumps/scan/kept.bin");
    let before = std::fs::read(&saved).unwrap_or_else(|e| panic!("{}: {e}", saved.display()));
    assert_eq!(scan(OUTSIDE, "64")["ok"], false);
    assert_eq!(std::fs::read(&saved).expect("still there"), before);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Refused because nothing read, not because little was asked: a window of no
/// bytes has failed at nothing, and a window running off the end of a section
/// has read what it could.
#[test]
fn only_a_window_that_read_nothing_is_refused() {
    let dir = project("partly");
    let (start, _) = rodata();
    let v = n0x(&dir, &["scan", "aob", "--file", IMAGE, "--start", &start, "--size", "0", "--pattern", "00"]);
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["data"]["bytes_scanned"], 0, "{v}");
    let v = n0x(&dir, &["scan", "aob", "--file", IMAGE, "--start", &start, "--size", "999999999", "--pattern", "00"]);
    assert_eq!(v["ok"], true, "{v}");
    assert!(v["data"]["bytes_scanned"].as_u64().expect("a count") > 0, "{v}");
    // Reading off the end is a short read, which `exhaustive` reports.
    let v = n0x(&dir, &["scan", "value", "--file", IMAGE, "--start", &start, "--size", "999999999", "--type", "u32", "--value", "4294967295", "--save-as", "s", "--force"]);
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["data"]["exhaustive"], false, "{v}");
    let _ = std::fs::remove_dir_all(&dir);
}
