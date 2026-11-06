// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Calls through a relocated slot, and calls that do not return, on images
//! planted to hold each case (`fixtures/discovery/noreturn.s`,
//! `noreturn_a64.s`, built by `plant.sh`). Where each address and slot lies is
//! what binutils says, recorded beside the images
//! (`noreturn.so.disassembly.txt`, `.relocations.txt`, `.segments.txt`,
//! `noreturn_a64.so.disassembly.txt`), not what the engine reads.
//!
//! Every function here has no FDE and no sized symbol, so its end is the
//! graph's. Calibrated by removing each rule (`docs/design/RUST.md` §2).

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod support;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/discovery").join(name)
}

fn project(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis_calls_noreturn_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("project");
    dir
}

fn run(dir: &Path, args: &[&str]) -> Value {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).arg("--quiet").current_dir(dir).output().expect("the engine runs");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("one JSON object from {args:?}: {e}"));
    assert_eq!(v["ok"], true, "{args:?}: {v}");
    v["data"].clone()
}

/// The address `objdump` prints for a function of the image, from the recording
/// (`0000000000001060 <named_through_relro>:`).
fn address_of(recording: &str, function: &str) -> String {
    let text = std::fs::read_to_string(fixture(recording)).expect("the recording");
    let label = format!(" <{function}>:");
    let line = text.lines().find(|l| l.ends_with(&label)).unwrap_or_else(|| panic!("{function} is not in {recording}"));
    let hex = line.split(' ').next().expect("an address");
    format!("0x{}", hex.trim_start_matches('0'))
}

/// `ir build`, as a user has it: the end heuristic on, the default window.
fn cfg(dir: &Path, image: &str, addr: &str) -> Value {
    run(dir, &["ir", "build", "--file", fixture(image).to_str().expect("a UTF-8 path"), "--addr", addr])
}

const X64: &str = "noreturn.so";
const X64_LISTING: &str = "noreturn.so.disassembly.txt";

/// through.
#[test]
fn a_call_through_a_read_only_relocated_slot_is_a_call_to_that_address() {
    let dir = project("named");
    let helper = address_of(X64_LISTING, "helper");
    let got = cfg(&dir, X64, &address_of(X64_LISTING, "named_through_relro"));
    let site = &got["callsites"][0];
    assert_eq!(site["target"], helper.as_str(), "{got}");
    assert_eq!(site["target_name"], "helper", "{got}");
    assert!(site["via_slot"].is_string(), "{got}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// by reading a slot.
#[test]
fn a_known_callee_with_no_name_is_called_by_its_address() {
    let dir = project("nameless");
    let image = "noreturn.stripped.so";
    let helper = address_of(X64_LISTING, "helper");
    let caller = address_of(X64_LISTING, "named_through_relro");
    let got = cfg(&dir, image, &caller);
    assert_eq!(got["callsites"][0]["target"], helper.as_str(), "{got}");
    assert!(got["callsites"][0]["target_name"].is_null(), "{got}");
    let c = run(&dir, &["decomp", "pseudo", "--file", fixture(image).to_str().expect("a UTF-8 path"), "--addr", &caller]);
    let text = c["pseudo"].to_string();
    let expect = format!("sub_{}", helper.trim_start_matches("0x").to_uppercase());
    assert!(text.contains(&expect), "{expect} is not in:\n{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// that reads as a wrong function if the rule ever takes a slot it cannot know.
#[test]
fn a_slot_the_program_may_write_is_not_known() {
    let dir = project("variable");
    let got = cfg(&dir, X64, &address_of(X64_LISTING, "through_a_variable"));
    assert!(got["callsites"][0]["target"].is_null(), "{got}");
    assert!(got["callsites"][0]["target_name"].is_null(), "{got}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// False: no relocation writes this slot, so nothing states what it holds.
#[test]
fn an_unrelocated_slot_is_not_known() {
    let dir = project("unknown");
    let got = cfg(&dir, X64, &address_of(X64_LISTING, "through_an_unknown_slot"));
    assert!(got["callsites"][0]["target"].is_null(), "{got}");
    assert!(got["callsites"][0]["target_name"].is_null(), "{got}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// not return.
#[test]
fn the_whole_program_fixpoint_sees_through_a_slot() {
    let dir = project("fixpoint");
    let wraps = address_of(X64_LISTING, "wraps_through_a_slot");
    let got = run(&dir, &["function", "noreturn", "--file", fixture("noreturn.stripped.so").to_str().expect("a UTF-8 path")]);
    let proved: Vec<&str> = got["noreturn"].as_array().expect("a list").iter().map(|v| v.as_str().expect("an address")).collect();
    assert!(proved.contains(&wraps.as_str()), "{wraps} is not in {proved:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
