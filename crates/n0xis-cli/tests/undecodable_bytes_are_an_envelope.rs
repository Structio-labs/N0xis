// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A word the decoder cannot read is an answer, not a crash.**
//!
//! The A32 decoder panics on some words — `ldrd`/`strd` with `Rt = 15`, where
//! it names the pair's second register `r16` — and a panic ends the process
//! with exit 101 and nothing on stdout: no envelope, no error code to branch
//! on, for four bytes a disassembler meets whenever it walks data. LLVM
//! calls them "invalid
//! instruction encoding", so the right answer is a `(bad)` marker inside an
//! ordinary `ok` envelope.

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

/// The envelope a command printed, or a panic naming what came out instead.
fn envelope(args: &[&str]) -> Option<Value> {
    let exe = n0xis_exe();
    if !exe.exists() {
        eprintln!("skipping: {} not built", exe.display());
        return None;
    }
    let out = Command::new(&exe).args(args).output().expect("run n0xis");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(101), "the process panicked; stderr: {stderr}");
    Some(
        serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("stdout is not one JSON object ({e}): {stdout:?} / stderr {stderr:?}")),
    )
}

#[test]
fn a_word_the_a32_decoder_panics_on_disassembles_to_bad() {
    // fc fa 00 00 — the word 0x0000fafc, `ldrd`/`strd` with `Rt = 15`.
    let Some(v) = envelope(&["disasm", "--arch", "arm32", "--bytes", "fc fa 00 00", "--addr", "0x1000"]) else { return };
    assert_eq!(v["ok"], Value::Bool(true), "{v}");
    let insns = v["data"]["insns"].as_array().unwrap_or_else(|| panic!("no instruction list: {v}"));
    assert_eq!(insns.len(), 1, "{v}");
    assert_eq!(insns[0]["text"], "(bad)", "{v}");
}

#[test]
fn a_word_the_a32_decoder_panics_on_still_decompiles_to_an_envelope() {
    let Some(v) = envelope(&["decomp", "pseudo", "--arch", "arm32", "--bytes", "fc fa 00 00", "--addr", "0x1000"]) else { return };
    assert!(v["ok"].is_boolean(), "an envelope either way: {v}");
}

/// **And a word the crate cannot read, but the processor can, is not `(bad)`.**
/// `yaxpeax-arm` 0.5.0 returns an error for the whole A32 media class, so each
/// such word (`uxtb`, `uxth`, `sxth`, …) stopped `disasm`'s linear sweep. `arm32.rs` decodes
/// the class itself now, so the sweep goes through.
#[test]
fn a_media_instruction_does_not_stop_the_linear_sweep() {
    // e6ef8073 `uxtb r8, r3`, e12fff1e `bx lr` (llvm-mc).
    let Some(v) = envelope(&["disasm", "--arch", "arm32", "--bytes", "73 80 ef e6 1e ff 2f e1", "--addr", "0x1000", "--count", "4"]) else { return };
    assert_eq!(v["ok"], Value::Bool(true), "{v}");
    let insns = v["data"]["insns"].as_array().unwrap_or_else(|| panic!("no instruction list: {v}"));
    let texts: Vec<&str> = insns.iter().filter_map(|i| i["text"].as_str()).collect();
    assert_eq!(texts, ["uxtb r8, r3", "bx lr"], "{v}");
}
