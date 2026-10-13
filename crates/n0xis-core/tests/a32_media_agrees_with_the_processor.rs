// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The A32 extend, bitfield, pack, halfword-multiply and reverse lifts,
//! against an emulated ARM processor.**
//!
//! `arm32/own.rs` lifts `uxtb`/`sxth`/`uxtab`/…, `ubfx`/`sbfx`/`bfi`/`bfc`,
//! `pkhbt`/`pkhtb`, `smul<x><y>` and `rev`/`rev16`/`revsh` to exact
//! expressions. Its unit tests pin the shape of each expression; whether that
//! shape is the instruction is a question only something that executes the
//! instruction can answer. So each form is assembled into a one-instruction
//! function (`<insn>; bx lr`, arguments in `r0`-`r2`, result in `r0`), run by
//! `qemu-arm-static` over adversarial inputs — sign bits, half and byte
//! boundaries, all-ones — and n0xis lifts the same bytes through the real
//! pipeline (CFG, SSA, the emulator) and must produce the same 32 bits. Not one
//! more: an A32 register is 32 bits, and a lift that leaves a sign extension or
//! a carry above bit 31 returns a different number here.
//!
//! The functions run in a freestanding driver written in assembly (no C
//! toolchain for 32-bit ARM Linux is needed): it calls each function on each
//! input triple and writes the results to stdout as raw words.
//!
//! **Calibration.** A form that stays `asm` (`uadd8`) is in the corpus too, and
//! must stop as not modelled — a harness that answered it would be answering
//! from somewhere other than the lift. Two forms are predicated behind a
//! compare, so the reaching-flags path is exercised as well as the value.
//!
//! Needs `arm-none-eabi-as`, `arm-none-eabi-ld`, `arm-none-eabi-nm` and
//! `qemu-arm-static`, so it is behind the `oracle` feature:
//!
//! ```text
//! cargo test -p n0xis-core --features oracle --test a32_media_agrees_with_the_processor -- --nocapture
//! ```

#![cfg(feature = "oracle")]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use n0xis_arch::{Arch, Arm32};
use n0xis_contracts::Va;
use n0xis_core::{CfgInput, CfgPass, Ctx, EmuConfig, EmuError, Emulator, Pass, SsaPass};
use n0xis_sources::{MemorySource, StaticElf, SymbolProvider};

const AS: &str = "arm-none-eabi-as";
const LD: &str = "arm-none-eabi-ld";
const NM: &str = "arm-none-eabi-nm";
const QEMU: &str = "qemu-arm-static";

/// Each case: a function name and its body before `bx lr`. Arguments arrive in
/// `r0`-`r2`; the result is `r0`.
const CASES: &[(&str, &str)] = &[
    ("uxtb_0", "uxtb r0, r1"),
    ("uxtb_8", "uxtb r0, r1, ror #8"),
    ("uxtb_16", "uxtb r0, r1, ror #16"),
    ("uxtb_24", "uxtb r0, r1, ror #24"),
    ("uxth_0", "uxth r0, r1"),
    ("uxth_8", "uxth r0, r1, ror #8"),
    ("uxth_16", "uxth r0, r1, ror #16"),
    ("uxth_24", "uxth r0, r1, ror #24"),
    ("sxtb_0", "sxtb r0, r1"),
    ("sxtb_8", "sxtb r0, r1, ror #8"),
    ("sxtb_24", "sxtb r0, r1, ror #24"),
    ("sxth_0", "sxth r0, r1"),
    ("sxth_16", "sxth r0, r1, ror #16"),
    ("sxth_24", "sxth r0, r1, ror #24"),
    ("uxtab_0", "uxtab r0, r1, r2"),
    ("uxtab_24", "uxtab r0, r1, r2, ror #24"),
    ("uxtah_8", "uxtah r0, r1, r2, ror #8"),
    ("uxtah_24", "uxtah r0, r1, r2, ror #24"),
    ("sxtab_0", "sxtab r0, r1, r2"),
    ("sxtab_16", "sxtab r0, r1, r2, ror #16"),
    ("sxtah_0", "sxtah r0, r1, r2"),
    ("sxtah_24", "sxtah r0, r1, r2, ror #24"),
    ("ubfx_0_1", "ubfx r0, r1, #0, #1"),
    ("ubfx_4_8", "ubfx r0, r1, #4, #8"),
    ("ubfx_31_1", "ubfx r0, r1, #31, #1"),
    ("ubfx_16_16", "ubfx r0, r1, #16, #16"),
    ("ubfx_0_32", "ubfx r0, r1, #0, #32"),
    ("sbfx_0_1", "sbfx r0, r1, #0, #1"),
    ("sbfx_4_8", "sbfx r0, r1, #4, #8"),
    ("sbfx_31_1", "sbfx r0, r1, #31, #1"),
    ("sbfx_16_16", "sbfx r0, r1, #16, #16"),
    ("sbfx_1_31", "sbfx r0, r1, #1, #31"),
    ("sbfx_0_32", "sbfx r0, r1, #0, #32"),
    ("bfi_8_4", "bfi r0, r1, #8, #4"),
    ("bfi_0_1", "bfi r0, r1, #0, #1"),
    ("bfi_31_1", "bfi r0, r1, #31, #1"),
    ("bfi_0_32", "bfi r0, r1, #0, #32"),
    ("bfi_4_28", "bfi r0, r1, #4, #28"),
    ("bfc_8_4", "bfc r0, #8, #4"),
    ("bfc_0_32", "bfc r0, #0, #32"),
    ("bfc_31_1", "bfc r0, #31, #1"),
    ("pkhbt_0", "pkhbt r0, r1, r2"),
    ("pkhbt_1", "pkhbt r0, r1, r2, lsl #1"),
    ("pkhbt_16", "pkhbt r0, r1, r2, lsl #16"),
    ("pkhbt_31", "pkhbt r0, r1, r2, lsl #31"),
    ("pkhtb_1", "pkhtb r0, r1, r2, asr #1"),
    ("pkhtb_16", "pkhtb r0, r1, r2, asr #16"),
    ("pkhtb_31", "pkhtb r0, r1, r2, asr #31"),
    ("pkhtb_32", "pkhtb r0, r1, r2, asr #32"),
    ("smulbb", "smulbb r0, r1, r2"),
    ("smulbt", "smulbt r0, r1, r2"),
    ("smultb", "smultb r0, r1, r2"),
    ("smultt", "smultt r0, r1, r2"),
    ("rev", "rev r0, r1"),
    ("rev16", "rev16 r0, r1"),
    ("revsh", "revsh r0, r1"),
    // Predicated: the select and the reaching compare, not only the value.
    ("uxtbne", "cmp r1, r2\n    uxtbne r0, r2"),
    ("sxthhi", "cmp r1, r2\n    sxthhi r0, r1, ror #8"),
];

/// Forms that stay `asm`: each must stop as not modelled.
const CONTROLS: &[(&str, &str)] = &[("uadd8", "uadd8 r0, r1, r2")];

/// Values that sit on every boundary these instructions care about.
const VALUES: [u32; 12] =
    [0, 1, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, 0x89ab_cdef];

/// The input triples `(r0, r1, r2)`: every pair of [`VALUES`] in `r1`/`r2`,
/// with `r0` (read by `bfi`/`bfc`) walking the values too.
fn inputs() -> Vec<[u32; 3]> {
    let mut out = Vec::new();
    for (i, &a) in VALUES.iter().enumerate() {
        for (j, &b) in VALUES.iter().enumerate() {
            out.push([VALUES[(i + j * 5 + 3) % VALUES.len()] ^ 0x5a5a_0000, a, b]);
        }
    }
    out
}

fn work_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("n0xis-a32-media-cpu-{}", std::process::id()));
    std::fs::create_dir_all(&d).expect("work dir");
    d
}

/// The corpus and its driver, as one assembly file.
fn assembly(funcs: &[(&str, &str)], inputs: &[[u32; 3]]) -> String {
    let mut s = String::from(".syntax unified\n.arch armv7-a\n.arm\n.text\n");
    for (name, body) in funcs {
        s += &format!(".global f_{name}\n.type f_{name}, %function\nf_{name}:\n    {body}\n    bx lr\n");
    }
    s += &format!(
        "
.global _start
_start:
    ldr r4, =inputs
    ldr r5, ={n_in}
    ldr r8, =out
1:  ldr r6, =funcs
    ldr r10, ={n_f}
2:  ldm r4, {{r0, r1, r2}}
    ldr r9, [r6], #4
    blx r9
    str r0, [r8], #4
    subs r10, r10, #1
    bne 2b
    add r4, r4, #12
    subs r5, r5, #1
    bne 1b
    mov r0, #1
    ldr r1, =out
    ldr r2, ={size}
    mov r7, #4
    svc #0
    mov r0, #0
    mov r7, #1
    svc #0
.ltorg
.data
.align 2
funcs:
",
        n_in = inputs.len(),
        n_f = funcs.len(),
        size = inputs.len() * funcs.len() * 4
    );
    for (name, _) in funcs {
        s += &format!("    .word f_{name}\n");
    }
    s += "inputs:\n";
    for [a, b, c] in inputs {
        s += &format!("    .word {a:#x}, {b:#x}, {c:#x}\n");
    }
    s += &format!(".bss\n.align 2\nout:\n    .space {}\n", inputs.len() * funcs.len() * 4);
    s
}

fn run(cmd: &mut Command, what: &str) -> Vec<u8> {
    let out = cmd.output().unwrap_or_else(|e| panic!("{what}: cannot run ({e})"));
    assert!(out.status.success(), "{what} failed: {}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

#[test]
fn a32_media_lifts_compute_what_the_processor_computes() {
    let funcs: Vec<(&str, &str)> = CASES.iter().chain(CONTROLS).copied().collect();
    let inputs = inputs();
    let dir = work_dir();
    let (src, obj, elf) = (dir.join("media.s"), dir.join("media.o"), dir.join("media.elf"));
    std::fs::write(&src, assembly(&funcs, &inputs)).expect("write the corpus");
    run(Command::new(AS).arg("-o").arg(&obj).arg(&src), AS);
    run(Command::new(LD).args(["-Ttext=0x10000", "-o"]).arg(&elf).arg(&obj), LD);

    // The processor's answers, `inputs × funcs` words in driver order.
    let raw = run(Command::new(QEMU).arg(&elf), QEMU);
    assert_eq!(raw.len(), inputs.len() * funcs.len() * 4, "the processor answered every call");
    let answers: Vec<u32> = raw.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)).collect();

    // Where each function is, from the symbol table, read by an independent tool.
    let nm = String::from_utf8(run(Command::new(NM).arg(&elf), NM)).expect("nm text");
    let addrs: BTreeMap<String, u64> = nm
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let (a, _, n) = (it.next()?, it.next()?, it.next()?);
            Some((n.strip_prefix("f_")?.to_string(), u64::from_str_radix(a, 16).ok()?))
        })
        .collect();
    assert_eq!(addrs.len(), funcs.len(), "nm found every function: {addrs:?}");

    let image = StaticElf::load(&elf).expect("n0xis loads the corpus");
    assert_eq!(image.machine(), "arm", "n0xis is reading the 32-bit ARM image the assembler produced");
    let arch = Arm32::a32();
    let ctx = Ctx::new(&image, &arch as &dyn Arch).with_symbols(&image as &dyn SymbolProvider);

    let (mut agree, mut wrong, mut gaps) = (0usize, Vec::new(), Vec::new());
    let mut controls_stopped = 0usize;
    for (fi, (name, body)) in funcs.iter().enumerate() {
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(addrs[*name]), 64)).unwrap_or_else(|e| panic!("{name}: CFG failed: {e}"));
        let ssa = SsaPass.run(&ctx, cfg).unwrap_or_else(|e| panic!("{name}: SSA failed: {e}"));
        let control = CONTROLS.iter().any(|c| c.0 == *name);
        for (ii, [r0, r1, r2]) in inputs.iter().enumerate() {
            let expected = answers[ii * funcs.len() + fi];
            let mut emu = Emulator::with_config(&ssa.blocks, Some(&image as &dyn MemorySource), EmuConfig::default());
            emu.set_var("r0", u64::from(*r0)).set_var("r1", u64::from(*r1)).set_var("r2", u64::from(*r2));
            match (emu.run(), control) {
                (Err(EmuError::Unlifted { .. }), true) => controls_stopped += 1,
                (got, true) => wrong.push(format!("{name} (`{body}`) must stay asm, got {got:?}")),
                (Ok(r), false) if r.ret == Some(u64::from(expected)) => agree += 1,
                (Ok(r), false) => wrong.push(format!(
                    "{name} (`{body}`) r0={r0:#x} r1={r1:#x} r2={r2:#x}: processor {expected:#x}, n0xis {:x?}",
                    r.ret
                )),
                (Err(e), false) => gaps.push(format!("{name} (`{body}`): {e:?}")),
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!(
        "a32 media vs the processor: {} forms x {} inputs -> {agree} agree, {} wrong, {} not modelled; {controls_stopped} control answers stopped as asm",
        CASES.len(),
        inputs.len(),
        wrong.len(),
        gaps.len()
    );
    for w in wrong.iter().take(30) {
        eprintln!("  WRONG {w}");
    }
    for g in gaps.iter().take(10) {
        eprintln!("  GAP   {g}");
    }
    assert_eq!(controls_stopped, CONTROLS.len() * inputs.len(), "every control stopped as asm: the harness answers only from the lift");
    assert!(wrong.is_empty(), "{} answers differ from the processor", wrong.len());
    assert!(gaps.is_empty(), "{} answers were not modelled", gaps.len());
    assert_eq!(agree, CASES.len() * inputs.len(), "every case was compared");
}
