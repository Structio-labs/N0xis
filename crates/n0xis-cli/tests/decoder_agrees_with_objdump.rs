// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The decoder is the floor everything else stands on, and nothing outside
//! the tool had ever checked it.**
//!
//! Every later answer — the CFG, the SSA, the types, the signatures — is built
//! on "these bytes are this instruction, and it is this long". A decoder that
//! desynchronises by one byte produces a plausible, entirely wrong program, and
//! no test above it can tell: they all read the same wrong stream.
//!
//! So this compares against an **independent disassembler**, `objdump`, on the
//! one property that is syntax-free and where a desync is immediately visible:
//! the **instruction boundaries**. Two decoders that agree on every `(address,
//! length)` pair over a range read the same program, whatever they call the
//! instructions or how they print the operands.
//!
//! Text is deliberately *not* compared. `sub esp,0Ch` and `sub esp,0xc` are the
//! same instruction, and chasing formatting would turn a real check into a
//! cosmetic one — the boundary is the fact.
//!
//! Measured when this was written, over `.text` from the first instruction:
//! all three oracle shapes exact, **20 000 instructions of a shared library and
//! 20 000 of a 32-bit system DLL with zero disagreements**.
//!
//! No `objdump` (or no compiler for a shape) skips that shape and says so.

#![cfg(feature = "oracle")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

/// `objdump -d`'s view: address → byte length.
///
/// Three details, each of which silently produced a wrong answer while this was
/// being written and each of which would have made the check pass on nothing:
///
/// - **`LC_ALL=C`.** The section banner is translated, and so is everything
///   else; a parser keyed on the English form finds no instructions at all.
/// - **Continuation lines.** A long instruction's bytes wrap onto the next
///   line, which carries bytes and no mnemonic. Counting only the first line
///   reports 7 bytes for a 10-byte instruction — four false "disagreements" on
///   the first run.
/// - **No leading whitespace.** `objdump` aligns the address column, so a
///   32-bit image whose addresses are already 8 hex digits has none. A regex
///   requiring an indent parsed zero instructions from a PE.
fn objdump_boundaries(binary: &Path) -> Option<BTreeMap<u64, usize>> {
    let out = Command::new("objdump")
        .env("LC_ALL", "C")
        .args(["-d", "-M", "intel", "--section=.text"])
        .arg(binary)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut map = BTreeMap::new();
    let mut current: Option<u64> = None;
    for line in text.lines() {
        // `<addr>:\t<bytes>[\t<mnemonic> …]`
        let Some((head, rest)) = line.split_once(":\t") else {
            current = None;
            continue;
        };
        let Ok(va) = u64::from_str_radix(head.trim(), 16) else {
            current = None;
            continue;
        };
        let (bytes_col, has_mnemonic) = match rest.split_once('\t') {
            Some((b, _)) => (b, true),
            None => (rest, false),
        };
        let n = bytes_col.split_whitespace().filter(|t| t.len() == 2 && u8::from_str_radix(t, 16).is_ok()).count();
        if n == 0 {
            current = None;
            continue;
        }
        if has_mnemonic {
            map.insert(va, n);
            current = Some(va);
        } else if let Some(prev) = current {
            // A continuation of the previous instruction's byte column.
            *map.get_mut(&prev).expect("previous instruction") += n;
        }
    }
    (!map.is_empty()).then_some(map)
}

fn n0xis_boundaries(binary: &Path, start: u64, count: usize) -> Option<BTreeMap<u64, usize>> {
    let out = Command::new(n0xis_exe())
        .args(["disasm", "--quiet", "--count", &count.to_string(), "--addr", &format!("{start:#x}"), "--file"])
        .arg(binary)
        .output()
        .ok()?;
    let v: Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).ok()?;
    let insns = v["data"]["insns"].as_array()?;
    let mut map = BTreeMap::new();
    for i in insns {
        let va = i["va"].as_str()?.trim_start_matches("0x");
        let va = u64::from_str_radix(va, 16).ok()?;
        map.insert(va, i["len"].as_u64()? as usize);
    }
    Some(map)
}

/// Build one oracle shape into `dir`, or `None` with a printed reason.
fn build(dir: &Path, cc: &str, src: &str, out_name: &str, extra: &[&str]) -> Option<PathBuf> {
    let out = dir.join(out_name);
    let source = repo_root().join("oracle").join(src);
    let mut cmd = Command::new(cc);
    cmd.args(["-shared", "-O1"]).args(extra).arg("-o").arg(&out).arg(&source);
    match cmd.output() {
        Ok(o) if o.status.success() => Some(out),
        _ => {
            eprintln!("decoder-vs-objdump: skipping {out_name} — `{cc}` unavailable or failed");
            None
        }
    }
}

/// AArch64 aliases: two correct names for one encoding, defined by the
/// architecture itself. LLVM prints the alias, the decoder behind this tool
/// prints the base form, and **neither is wrong** — so they are listed rather
/// than papered over, because a check that silently forgave every difference
/// would forgive a real one too.
///
/// `(what LLVM prints, what n0xis prints, why they are the same instruction)`
const AARCH64_ALIASES: &[(&str, &str, &str)] = &[
    ("mov", "orr", "`mov Xd, Xm` is `orr Xd, xzr, Xm`"),
    ("mov", "movz", "`mov Xd, #imm` with a zeroed remainder is `movz`"),
    ("mov", "movn", "`mov Xd, #negative` is `movn` with the inverted immediate"),
    ("mov", "dup", "the SIMD `mov Vd.T, Vn.T[i]` is `dup`"),
    ("mul", "madd", "`mul Xd, Xn, Xm` is `madd Xd, Xn, Xm, xzr`"),
    ("cmp", "subs", "`cmp Xn, op` is `subs xzr, Xn, op` — the result is discarded"),
    ("b.hs", "b.cs", "HS (unsigned higher-or-same) and CS (carry set) are the same condition code"),
    ("b.lo", "b.cc", "LO (unsigned lower) and CC (carry clear) are the same condition code"),
    // Found by walking the encoding space rather than compiler output — no
    // compiler emitted these three, and each is an alias the architecture
    // defines over a bitfield-move or logical instruction.
    ("sbfiz", "sbfm", "`sbfiz` is `sbfm` with the immediates arranged to insert"),
    ("bfxil", "bfm", "`bfxil` is `bfm` with the immediates arranged to extract-and-insert-low"),
    ("tst", "ands", "`tst Xn, op` is `ands xzr, Xn, op` — the result is discarded"),
    // `MOV (to/from SP)`: the architecture defines `mov <Xd|SP>, <Xn|SP>` as the
    // preferred disassembly of `add <Xd|SP>, <Xn|SP>, #0` — shift 0, imm12 0,
    // and one of the two registers the stack pointer. It is the second half of
    // every AArch64 frame-pointer prologue (`stp x29,x30,[sp,#-16]!` then
    // `add x29, sp, #0`), so no compiler output can avoid it for long.
    ("mov", "add", "`mov <Xd|SP>, <Xn|SP>` is `add <Xd|SP>, <Xn|SP>, #0`"),
];

fn is_alias(llvm: &str, ours: &str) -> bool {
    AARCH64_ALIASES.iter().any(|(a, b, _)| *a == llvm && *b == ours)
}

/// **AArch64 was verified by three hand-written encodings and nothing else.**
///
/// That proves the ISA seam holds — a second architecture runs through the core
/// unchanged — and says nothing about whether the decoder reads real compiler
/// output correctly. The project's own notes were right to say "implemented and
/// self-tested" rather than "working".
///
/// Fixed-width instructions make boundaries meaningless here, so the comparison
/// is the **mnemonic** at each address, against `llvm-objdump --triple=aarch64`
/// over `oracle/arm64.c` compiled at `-O2`. Two things are asserted that a
/// boundary check cannot give: that nothing decodes as `(bad)` where LLVM
/// reads an instruction, and that every name matches or is a listed alias.
///
/// Measured when this was written: **147 instructions, 147 shared addresses, 0
/// failures, and every one of the 28 name differences a documented alias.**
///
/// **That count is not stable, and the instability is the useful part.** The
/// corpus is whatever `clang --target=aarch64-linux-gnu` emits *on this
/// machine*, and clang picks its target defaults partly from whichever GCC
/// installation for that target it can find. Installing `aarch64-linux-gnu-gcc`
/// moved the count 147 → 148 and immediately produced a disagreement the
/// smaller sample never contained: `add x29, sp, #0`, which the architecture
/// prefers to disassemble as `mov x29, sp`. Re-measured 2026-09-10 with the
/// cross toolchain present: **148 instructions, 0 failures, 29 aliases.**
/// A number here describes the machine as much as the decoder; treat a change
/// in it as a new sample to explain, not as a regression to revert.
#[test]
fn the_arm64_decoder_names_the_same_instructions_as_llvm() {
    if !n0xis_exe().exists() {
        eprintln!("arm64-vs-llvm: skipping — {} is not built", n0xis_exe().display());
        return;
    }
    for tool in ["clang", "llvm-objdump", "llvm-objcopy"] {
        if Command::new(tool).arg("--version").output().is_err() {
            eprintln!("arm64-vs-llvm: skipping — `{tool}` is not installed, so nothing was checked");
            return;
        }
    }
    let tmp = std::env::temp_dir().join(format!("n0xis_arm64_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("temp dir");
    let obj = tmp.join("arm64.o");
    let bin = tmp.join("arm64.bin");

    let compiled = Command::new("clang")
        .args(["--target=aarch64-linux-gnu", "-ffreestanding", "-O2", "-c", "-o"])
        .arg(&obj)
        .arg(repo_root().join("oracle").join("arm64.c"))
        .output();
    match compiled {
        Ok(o) if o.status.success() => {}
        _ => {
            eprintln!("arm64-vs-llvm: skipping — clang cannot target aarch64 here");
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }
    }
    let extracted = Command::new("llvm-objcopy")
        .args(["-O", "binary", "--only-section=.text"])
        .arg(&obj)
        .arg(&bin)
        .output();
    if !extracted.map(|o| o.status.success()).unwrap_or(false) {
        eprintln!("arm64-vs-llvm: skipping — could not extract .text");
        let _ = std::fs::remove_dir_all(&tmp);
        return;
    }

    // The reference: address -> mnemonic, from LLVM's own AArch64 disassembler.
    let dump = Command::new("llvm-objdump")
        .env("LC_ALL", "C")
        .args(["-d", "--triple=aarch64", "--no-show-raw-insn"])
        .arg(&obj)
        .output()
        .expect("llvm-objdump");
    let text = String::from_utf8_lossy(&dump.stdout);
    let mut reference: BTreeMap<u64, String> = BTreeMap::new();
    for line in text.lines() {
        let Some((head, rest)) = line.split_once(':') else { continue };
        let Ok(va) = u64::from_str_radix(head.trim(), 16) else { continue };
        let Some(mnemonic) = rest.split_whitespace().next() else { continue };
        // Section banners and symbol lines have no instruction after the colon.
        if mnemonic.starts_with('<') || mnemonic.starts_with("file") {
            continue;
        }
        reference.insert(va, mnemonic.to_ascii_lowercase());
    }

    let bytes = std::fs::read(&bin).expect("read .text");
    let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let out = Command::new(n0xis_exe())
        .args(["disasm", "--quiet", "--arch", "arm64", "--addr", "0x0", "--count", "9000", "--bytes", &hex.join(" ")])
        .output()
        .expect("run n0xis");
    let v: Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("one envelope");
    let mut ours: BTreeMap<u64, (String, String)> = BTreeMap::new();
    for i in v["data"]["insns"].as_array().expect("insns") {
        let va = u64::from_str_radix(i["va"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        ours.insert(va, (i["mnemonic"].as_str().unwrap().to_ascii_lowercase(), i["text"].as_str().unwrap().to_string()));
    }
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(reference.len() > 100, "only {} instructions in the reference — the parse is broken", reference.len());
    let mut problems = Vec::new();
    let mut aliases = 0usize;
    for (va, want) in &reference {
        match ours.get(va) {
            None => problems.push(format!("{va:#x}: LLVM decodes `{want}` here, n0xis has no instruction")),
            Some((got, text)) if got == "(bad)" => {
                problems.push(format!("{va:#x}: LLVM decodes `{want}`, n0xis fails to decode it ({text})"))
            }
            Some((got, _)) if got != want => {
                if is_alias(want, got) {
                    aliases += 1;
                } else {
                    problems.push(format!("{va:#x}: LLVM says `{want}`, n0xis says `{got}` — not a listed alias"));
                }
            }
            _ => {}
        }
    }
    for va in ours.keys() {
        if !reference.contains_key(va) {
            problems.push(format!("{va:#x}: n0xis has an instruction here, LLVM does not"));
        }
    }
    eprintln!(
        "arm64-vs-llvm: {} instructions, {} names identical, {aliases} architecture aliases",
        reference.len(),
        reference.len() - aliases - problems.len()
    );
    assert!(
        problems.is_empty(),
        "the AArch64 decoder disagrees with LLVM:\n  {}",
        problems.iter().take(12).cloned().collect::<Vec<_>>().join("\n  ")
    );
}

#[test]
fn the_decoder_reads_the_same_instruction_stream_as_an_independent_disassembler() {
    if !n0xis_exe().exists() {
        eprintln!("decoder-vs-objdump: skipping — {} is not built", n0xis_exe().display());
        return;
    }
    if Command::new("objdump").arg("--version").output().is_err() {
        eprintln!("decoder-vs-objdump: skipping — objdump is not installed, so nothing was checked");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("n0xis_decoder_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("temp dir");

    let shapes: Vec<(&str, Option<PathBuf>)> = vec![
        ("sysv (ELF x86-64)", build(&tmp, "gcc", "sysv.c", "sysv.so", &["-fPIC"])),
        ("win64 (PE x86-64)", build(&tmp, "x86_64-w64-mingw32-gcc", "win64.c", "win64.dll", &[])),
        ("i386 (PE32)", build(&tmp, "i686-w64-mingw32-gcc", "i386.c", "i386.dll", &[])),
    ];

    let mut checked = 0usize;
    let mut ran = 0usize;
    let mut problems = Vec::new();

    for (label, built) in &shapes {
        let Some(binary) = built else { continue };
        let Some(reference) = objdump_boundaries(binary) else {
            eprintln!("decoder-vs-objdump: objdump read no instructions from {label} — skipped");
            continue;
        };
        let first = *reference.keys().next().expect("non-empty");
        let Some(mine) = n0xis_boundaries(binary, first, 6000) else {
            problems.push(format!("{label}: n0xis produced no disassembly at {first:#x}"));
            continue;
        };
        // Compare only where both looked: whichever stopped first ends the window.
        // Past objdump's last instruction is section padding, which n0xis is
        // right to keep decoding and which is not a disagreement.
        let last = std::cmp::min(*reference.keys().last().unwrap(), *mine.keys().last().unwrap());
        let refr: BTreeMap<_, _> = reference.range(first..=last).map(|(k, v)| (*k, *v)).collect();
        let ours: BTreeMap<_, _> = mine.range(first..=last).map(|(k, v)| (*k, *v)).collect();
        ran += 1;
        checked += refr.len();

        let differing: Vec<String> = refr
            .iter()
            .filter_map(|(va, len)| match ours.get(va) {
                Some(mine_len) if mine_len != len => Some(format!("{va:#x}: objdump {len}B, n0xis {mine_len}B")),
                None => Some(format!("{va:#x}: objdump has an instruction here, n0xis does not")),
                _ => None,
            })
            .chain(ours.keys().filter(|va| !refr.contains_key(va)).map(|va| {
                format!("{va:#x}: n0xis has an instruction here, objdump does not — a desync")
            }))
            .take(8)
            .collect();
        if !differing.is_empty() {
            problems.push(format!("{label} ({} instructions):\n      {}", refr.len(), differing.join("\n      ")));
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);

    if ran == 0 {
        eprintln!("decoder-vs-objdump: no shape could be built — this verified nothing");
        return;
    }
    // A comparison over a handful of instructions would pass on almost any
    // decoder; say what was actually covered.
    assert!(checked > 500, "only {checked} instructions compared across {ran} shape(s) — too few to mean anything");
    eprintln!("decoder-vs-objdump: {checked} instructions across {ran} shape(s), boundaries identical");
    assert!(problems.is_empty(), "the two decoders read different instruction streams:\n  {}", problems.join("\n  "));
}
