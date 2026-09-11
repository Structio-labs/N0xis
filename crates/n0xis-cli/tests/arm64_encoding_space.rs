// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **What a compiler emits is a narrow slice of what a decoder must judge.**
//!
//! `oracle/arm64.c` covers 147 instructions and every one of them agrees with
//! LLVM. That says nothing about the far larger space of words a decoder meets
//! when it walks data, padding, or a section it should not be in — and *that*
//! is where a decoder does its quiet damage: a reserved encoding read as a
//! plausible instruction turns bytes that are not code into a program.
//!
//! So this walks the encoding space itself: deterministic pseudo-random 32-bit
//! words, each judged by `llvm-mc --mattr=+all` and by n0xis, comparing only
//! **validity** — whether each thinks the word is an instruction at all. The
//! names are the other test's job.
//!
//! **This documents a gap rather than asserting it away.** Over this test's own
//! 600 words:
//!
//! | | count | share |
//! | --- | --- | --- |
//! | both say invalid | 304 | |
//! | both say valid | 241 | |
//! | **n0xis accepts, LLVM rejects** | **48** | **8.0%** — reserved encodings read as instructions |
//! | **LLVM accepts, n0xis rejects** | **7** | **1.2%** — mostly LSE atomics and exclusives |
//!
//! A second, independent sample of 600 words drawn a different way gave 31 and
//! 12 — 5.2% and 2.0%. The two disagree on the exact figure and agree on the
//! scale, which is what a sample is for.
//!
//! Three of the 31 were decoded by hand against the architecture's rules and
//! are genuinely UNALLOCATED: `0x0a559521` and `0x2a9da3bc` are 32-bit logical
//! shifted-register forms with `imm6` of 37 and 40, where the architecture
//! requires it below 32, and n0xis calls them `and` and `orr`.
//!
//! The bounds below are a **ratchet**: they hold the gap where it is and fail
//! if it grows. They are deliberately not zero, because zero would be a lie —
//! and lowering them is the work, tracked in `ROADMAP.md`.

use std::process::{Command, Stdio};
use std::io::Write;
use std::path::PathBuf;

use serde_json::Value;

fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

/// A deterministic word sequence — the same every run, so a number that moves
/// is a change in the decoder and never in the sample.
fn words(n: usize) -> Vec<u32> {
    let mut state: u64 = 0x2026_0909_dead_beef;
    (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 16) as u32
        })
        .collect()
}

/// Does LLVM consider this word an instruction, with every feature enabled?
fn llvm_accepts(word: u32) -> Option<bool> {
    let bytes = word.to_le_bytes();
    let input = bytes.iter().map(|b| format!("0x{b:02x}")).collect::<Vec<_>>().join(" ");
    let mut child = Command::new("llvm-mc")
        .env("LC_ALL", "C")
        .args(["--disassemble", "--triple=aarch64", "--mattr=+all"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    child.stdin.as_mut()?.write_all(input.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let decoded = stdout.lines().any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('.'));
    Some(decoded && !stderr.contains("invalid"))
}

fn n0xis_accepts(word: u32) -> Option<bool> {
    let hex = word.to_le_bytes().iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
    let out = Command::new(n0xis_exe())
        .args(["disasm", "--quiet", "--arch", "arm64", "--addr", "0x0", "--count", "1", "--bytes", &hex])
        .output()
        .ok()?;
    let v: Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).ok()?;
    let mnemonic = v["data"]["insns"][0]["mnemonic"].as_str()?;
    Some(mnemonic != "(bad)")
}

/// The measured gap, held where it is. Lowering these is the work; raising one
/// needs a reason written beside it.
const ACCEPTS_RESERVED_MAX: usize = 48; // of 600, this test's own sample
const MISSES_REAL_MAX: usize = 7; // of 600, this test's own sample

#[test]
fn the_arm64_decoders_validity_gap_does_not_grow() {
    if !n0xis_exe().exists() || Command::new("llvm-mc").arg("--version").output().is_err() {
        eprintln!("encoding space: skipping — n0xis or llvm-mc unavailable, so nothing was checked");
        return;
    }
    let sample = words(600);
    let (mut both_valid, mut both_invalid, mut accepts_reserved, mut misses_real) = (0, 0, 0, 0);
    let mut examples = Vec::new();
    for w in &sample {
        let (Some(llvm), Some(ours)) = (llvm_accepts(*w), n0xis_accepts(*w)) else { continue };
        match (llvm, ours) {
            (true, true) => both_valid += 1,
            (false, false) => both_invalid += 1,
            (false, true) => {
                accepts_reserved += 1;
                if examples.len() < 4 {
                    examples.push(format!("{w:#010x} is reserved and was decoded as an instruction"));
                }
            }
            (true, false) => misses_real += 1,
        }
    }
    let judged = both_valid + both_invalid + accepts_reserved + misses_real;
    assert!(judged > 500, "only {judged} words judged — the harness is broken, not the decoder");
    eprintln!(
        "encoding space: {judged} words — both valid {both_valid}, both invalid {both_invalid}, \
         reserved-but-accepted {accepts_reserved}, real-but-rejected {misses_real}"
    );
    assert!(
        accepts_reserved <= ACCEPTS_RESERVED_MAX,
        "the decoder now accepts {accepts_reserved} reserved encodings (was {ACCEPTS_RESERVED_MAX}); \
         a reserved word read as an instruction turns data into a plausible program:\n  {}",
        examples.join("\n  ")
    );
    assert!(
        misses_real <= MISSES_REAL_MAX,
        "the decoder now fails on {misses_real} real instructions (was {MISSES_REAL_MAX})"
    );
}
