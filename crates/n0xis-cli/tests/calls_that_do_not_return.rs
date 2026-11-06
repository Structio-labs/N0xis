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

fn plus(addr: &str, n: u64) -> String {
    format!("0x{:x}", u64::from_str_radix(addr.trim_start_matches("0x"), 16).expect("hex") + n)
}

/// `ir build`, as a user has it: the end heuristic on, the default window.
fn cfg(dir: &Path, image: &str, addr: &str) -> Value {
    run(dir, &["ir", "build", "--file", fixture(image).to_str().expect("a UTF-8 path"), "--addr", addr])
}

fn terminators(cfg: &Value) -> Vec<String> {
    cfg["blocks"].as_array().expect("blocks").iter().map(|b| b["terminator"].as_str().expect("a terminator").to_string()).collect()
}

/// The graph's end `why` reports for the function at `addr`.
fn why_end(dir: &Path, image: &str, addr: &str) -> Value {
    let got = run(dir, &["why", "--file", fixture(image).to_str().expect("a UTF-8 path"), "--addr", addr]);
    assert_eq!(got["function"]["found"]["end"]["source"], "not_stated", "{got}");
    got["function"]["found"]["end"]["cfg"].clone()
}

const X64: &str = "noreturn.so";
const X64_LISTING: &str = "noreturn.so.disassembly.txt";
const A64: &str = "noreturn_a64.so";
const A64_LISTING: &str = "noreturn_a64.so.disassembly.txt";

/// Rule 1: a slot under `PT_GNU_RELRO` with a relative relocation (both in the
/// recordings) holds the address it is relocated to, so the call is a call to
/// that function: its name, the callee the graph lists, and the slot it went
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

/// The same call on the stripped image: the callee is known and has no name, so
/// it has a target and no name, and pseudo-C calls it by its address rather than
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

/// False: `.data` is written at run time, so a relative relocation there is only
/// the value a variable starts with (the relocation and the segment are in the
/// recordings). The call stays indirect, with no callee. This is the one case
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

/// The fixpoint sees through a slot, even to a function only the slot reaches
/// and nothing lists: `.Lspins` loops for ever, and `wraps_through_a_slot` has
/// plain code after its call to it, so no rule but the fixpoint's can say it does
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

/// Rule 3: a panic by its demangled name, in the middle of a function, with plain
/// code after it and no trap or filler to say so. On the stripped image there is
/// False: `std::panicking::panic_count::is_zero_slow_path` is on the way to a
/// Rule 2: a trap after a call. Nothing follows the call, so the block ends as
/// `call-noreturn`; the trap is the compiler's and part of the function, so the
/// end is after it. The same bytes are what a person writes as `helper();
/// __builtin_trap();`, where `helper` does return: the function still goes no
/// further, which is the part this states.
#[test]
fn a_trap_after_a_call_ends_the_block_and_stays_in_the_function() {
    let dir = project("trap");
    for (image, listing, trap_end) in [(X64, X64_LISTING, 7), (A64, A64_LISTING, 8)] {
        let start = address_of(listing, "before_a_trap");
        let got = cfg(&dir, image, &start);
        assert_eq!(terminators(&got)[0], "call-noreturn", "{image}: {got}");
        assert_eq!(got["end"], plus(&start, trap_end).as_str(), "{image}: {got}");
        let end = why_end(&dir, image, &start);
        assert_eq!(end["end"], plus(&start, trap_end).as_str(), "{image}: {end}");
        assert_eq!(end["ended_by"], "call_before_trap", "{image}: {end}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// False, for the function: the block ends at the trap, and a landing pad comes
/// next, which no branch reaches. Cut at the trap, a Rust function with no unwind
/// table lost its landing pads: 41 of 41 such ends short.
#[test]
fn a_trap_with_code_after_it_ends_the_block_and_not_the_function() {
    let dir = project("pad");
    let start = address_of(X64_LISTING, "before_a_trap_and_a_landing_pad");
    let got = cfg(&dir, X64, &start);
    assert_eq!(terminators(&got)[0], "call-noreturn", "{got}");
    // call, `ud2`, `mov`, call, `ret`.
    assert_eq!(got["end"], plus(&start, 16).as_str(), "{got}");
    assert_eq!(why_end(&dir, X64, &start)["ended_by"], "terminator");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Rule 2: `int3` filler after a call traps if it is reached, and is the
/// linker's, so the function ends at the call. This is the end that was one byte
/// long on 44 602 stripped Rust functions (`private/held-out-own/RESULTS.md`).
#[test]
fn trapping_filler_after_a_call_is_outside_the_function() {
    let dir = project("int3");
    let start = address_of(X64_LISTING, "before_trapping_filler");
    let got = cfg(&dir, X64, &start);
    assert_eq!(terminators(&got), ["call-noreturn"], "{got}");
    assert_eq!(got["end"], plus(&start, 5).as_str(), "{got}");
    let end = why_end(&dir, X64, &start);
    assert_eq!(end["end"], plus(&start, 5).as_str(), "{end}");
    assert_eq!(end["ended_by"], "call_before_filler", "{end}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Rule 2: filler that does nothing, up to an aligned address nothing jumps to:
/// no compiler pads where control flows on without a reason to align.
#[test]
fn filler_after_a_call_up_to_an_address_nothing_jumps_to_ends_the_function() {
    let dir = project("nop");
    for (image, listing, call_len) in [(X64, X64_LISTING, 5), (A64, A64_LISTING, 4)] {
        let start = address_of(listing, "before_filler");
        let got = cfg(&dir, image, &start);
        assert_eq!(terminators(&got), ["call-noreturn"], "{image}: {got}");
        assert_eq!(got["end"], plus(&start, call_len).as_str(), "{image}: {got}");
        assert_eq!(why_end(&dir, image, &start)["ended_by"], "call_before_filler", "{image}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// False: the filler is run, and the loop it aligns is the function going on: a
/// later jump comes back to where the filler ends. Compilers align loop heads.
#[test]
fn filler_before_a_loop_head_is_run() {
    let dir = project("loop");
    let start = address_of(X64_LISTING, "before_a_loop");
    let got = cfg(&dir, X64, &start);
    assert!(!terminators(&got).contains(&"call-noreturn".to_string()), "{got}");
    // call, the filler up to +0x10, `dec`, `jne`, `ret`.
    assert_eq!(got["end"], plus(&start, 0x15).as_str(), "{got}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// False: a branch before the call lands where the filler ends, so the aligned
/// address is a join, and the `call` may return into it. Seen in real code as
/// `je F; call release; nop; F:`.
#[test]
fn filler_a_branch_jumps_past_is_no_end() {
    let dir = project("past");
    let start = address_of(X64_LISTING, "jumped_past");
    let got = cfg(&dir, X64, &start);
    assert!(!terminators(&got).contains(&"call-noreturn".to_string()), "{got}");
    // `test`, `je`, call, the filler up to +0x10, `mov`, `ret`.
    assert_eq!(got["end"], plus(&start, 0x16).as_str(), "{got}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// False: `nop; nop` after a call is what gcc `-O0` writes for two statements, and
/// the statement after them can land on an aligned address. Nothing fills so
/// little, on any machine here: this much padding is not read as filler.
#[test]
fn nops_a_compiler_writes_as_statements_are_run() {
    let dir = project("statements");
    for (image, listing, end) in [(X64, X64_LISTING, 10), (A64, A64_LISTING, 0x18)] {
        let start = address_of(listing, "statement_nops");
        let got = cfg(&dir, image, &start);
        assert!(!terminators(&got).contains(&"call-noreturn".to_string()), "{image}: {got}");
        assert_eq!(got["end"], plus(&start, end).as_str(), "{image}: {got}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// False: no branch lands where the filler ends, and the function goes on there:
/// a jump table's case does this, and a block clang aligns before a loop. In a
/// graph, a call filler follows ends a block only if nothing of its function is
/// at the end of the filler.
#[test]
fn filler_with_the_function_going_on_past_it_is_run() {
    let dir = project("goes_on");
    let start = address_of(X64_LISTING, "filler_with_the_function_going_on");
    let got = cfg(&dir, X64, &start);
    assert!(!terminators(&got).contains(&"call-noreturn".to_string()), "{got}");
    // `test`, `je`, call, the filler up to +0x10, `mov`, `ret`.
    assert_eq!(got["end"], plus(&start, 0x16).as_str(), "{got}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// False: three one-byte `nop`s are as long as a fill, and are gcc `-O0`'s
/// statements (`libfuzzer` at `-O0`, the call before `leave` at `0x5426d`).
#[test]
fn one_byte_nops_in_a_row_are_run() {
    let dir = project("three");
    let start = address_of(X64_LISTING, "three_statement_nops");
    let got = cfg(&dir, X64, &start);
    assert!(!terminators(&got).contains(&"call-noreturn".to_string()), "{got}");
    assert_eq!(got["end"], plus(&start, 10).as_str(), "{got}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// False: more filler than a function's alignment asks for is an alignment asked
/// for inside one. zstd writes this before a hot loop whose jump back is past the
/// 4 KiB window, so nothing here can see that the address is jumped to.
#[test]
fn an_alignment_asked_for_by_hand_is_run() {
    let dir = project("hand");
    let start = address_of(X64_LISTING, "before_a_hand_written_alignment");
    let got = cfg(&dir, X64, &start);
    assert!(!terminators(&got).contains(&"call-noreturn".to_string()), "{got}");
    assert_eq!(got["end"], plus(&start, 0x26).as_str(), "{got}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// False, and not cured: `int3` written as a breakpoint with the function going
/// on after it. The address after it is not aligned, so this is no filler and
/// the rule says nothing. The heuristic it was left to ends at the `int3`, as it
/// always did; the rest of the function is not in the graph, which is a defect
/// of that heuristic, stated here so that it does not pass for a result.
#[test]
fn a_breakpoint_a_person_wrote_is_not_read_as_filler() {
    let dir = project("breakpoint");
    let start = address_of(X64_LISTING, "past_a_breakpoint");
    let got = cfg(&dir, X64, &start);
    assert!(!terminators(&got).contains(&"call-noreturn".to_string()), "{got}");
    assert_eq!(got["end"], plus(&start, 6).as_str(), "{got}");
    assert_eq!(why_end(&dir, X64, &start)["ended_by"], "terminator");
    let _ = std::fs::remove_dir_all(&dir);
}
