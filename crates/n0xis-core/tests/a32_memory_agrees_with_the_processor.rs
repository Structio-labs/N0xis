// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The AArch32 load, store and block-transfer lifts, and every read of `pc`,
//! against an emulated ARM processor.**
//!
//! `arm32.rs` lifts every single load and store (`ldr`/`ldrb`/`ldrh`/`ldrsb`/
//! `ldrsh`/`ldrd` and the stores; immediate and (shifted-)register index,
//! pre-indexed with and without write-back, post-indexed), `ldm`/`stm` in all
//! four modes, and reads `pc` as the constant the processor sees. Its unit
//! tests pin the shape of each lift; whether that shape is the instruction is a
//! question only something that executes the instruction can answer. So each
//! form is assembled into a small function — A32 and Thumb — run by
//! `qemu-arm-static`, and n0xis lifts the same bytes through the real pipeline
//! (CFG, SSA, the emulator) and must return the same 32 bits.
//!
//! Every function is called with `r0` and `r3` random, `r1` pointing into the
//! middle of a buffer of random bytes, and `r2` a small index. The driver
//! copies the buffer from a pristine image of it before every call, so each
//! call — on the processor and in the emulator, which starts from the image —
//! sees the same memory. A function returns what it loaded, or, after a store,
//! what it reads back; one with write-back folds the written-back base into its
//! result with `eor`, so a wrong base is a wrong answer. The buffer's bytes
//! alternate their sign in pairs, so every byte and halfword width meets both
//! signs. Literal-pool loads read the function's own bytes; a Thumb load placed
//! two bytes past a word reads through `Align(PC, 4)`.
//!
//! **What the inputs avoid, and why.** The A32 lift does not hold its
//! arithmetic at 32 bits — an `add` that carries out of bit 31 or a `lsl` past
//! it leaves the bits above in the emulator's 64-bit word (the class the i386
//! lift closed with explicit widths; open here for every data-processing
//! instruction, not only these). So no input makes an address or a combined
//! result wrap: the index is non-negative and small, results are combined with
//! `eor` and `lsr` only. That gap is not measured here, and is not this file's
//! to hide: it is recorded in the report that introduced this instrument.
//!
//! **Calibration.** Forms that stay `asm` (`ldrbt`, a predicated store, a
//! predicated write-back, Thumb's `add rd, pc`) are in the corpus too, and must
//! stop as not modelled — a harness that answered them would be answering from
//! somewhere other than the lift.
//!
//! Needs `arm-none-eabi-as`, `arm-none-eabi-ld`, `arm-none-eabi-nm` and
//! `qemu-arm-static`, so it is behind the `oracle` feature:
//!
//! ```text
//! cargo test -p n0xis-core --features oracle --test a32_memory_agrees_with_the_processor -- --nocapture
//! ```
//!
//! The inputs are drawn from a fixed seed, printed; `N0XIS_ORACLE_SEED`
//! overrides it.

#![cfg(feature = "oracle")]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use n0xis_arch::{Arch, Arm32};
use n0xis_contracts::Va;
use n0xis_core::{CfgInput, CfgPass, Ctx, EmuConfig, EmuError, Emulator, Pass, SsaPass};
use n0xis_sources::{MemorySource, ImageSource, SymbolProvider};

const AS: &str = "arm-none-eabi-as";
const LD: &str = "arm-none-eabi-ld";
const NM: &str = "arm-none-eabi-nm";
const QEMU: &str = "qemu-arm-static";

/// The seed the inputs and the buffer are drawn from, unless overridden.
const DEFAULT_SEED: u64 = 0x5ee_da32_0001;

/// How many random input quadruples each function is called on.
const CALLS: usize = 40;

/// The buffer `r1` points into: `BUF_WORDS` words, `r1` at its middle.
const BUF_WORDS: usize = 24;
const R1_OFFSET: u64 = 48;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Set {
    A32,
    Thumb,
}

/// One function: its instruction set, name, body before `bx lr`, and what
/// follows the `bx lr` (a literal pool), all GNU `as` syntax.
struct Case {
    set: Set,
    name: &'static str,
    body: &'static str,
    tail: &'static str,
}

const fn a32(name: &'static str, body: &'static str) -> Case {
    Case { set: Set::A32, name, body, tail: "" }
}

const fn a32_pool(name: &'static str, body: &'static str, tail: &'static str) -> Case {
    Case { set: Set::A32, name, body, tail }
}

const fn thumb(name: &'static str, body: &'static str) -> Case {
    Case { set: Set::Thumb, name, body, tail: "" }
}

const fn thumb_pool(name: &'static str, body: &'static str, tail: &'static str) -> Case {
    Case { set: Set::Thumb, name, body, tail }
}

/// Every lifted form. `r1` = buffer, `r2` = index (0, 4, 8 or 12), `r0`/`r3`
/// random.
const CASES: &[Case] = &[
    // ---- A32 byte loads
    a32("ldrb_imm", "ldrb r0, [r1, #3]"),
    a32("ldrb_neg", "ldrb r0, [r1, #-5]"),
    a32("ldrb_pre_wb", "ldrb r0, [r1, #-3]!\n    eor r0, r0, r1"),
    a32("ldrb_post", "ldrb r0, [r1], #3\n    eor r0, r0, r1"),
    a32("ldrb_reg", "ldrb r0, [r1, r2]"),
    a32("ldrb_reg_sub", "ldrb r0, [r1, -r2]"),
    a32("ldrb_regshift_wb", "ldrb r0, [r1, -r2, lsl #1]!\n    eor r0, r0, r1"),
    a32("ldrb_post_regshift", "ldrb r0, [r1], r2, lsr #1\n    eor r0, r0, r1"),
    a32("ldrsb_imm", "ldrsb r0, [r1, #1]"),
    a32("ldrsb_neg", "ldrsb r0, [r1, #-2]"),
    a32("ldrsb_reg", "ldrsb r0, [r1, r2]"),
    a32("ldrsb_post", "ldrsb r0, [r1], #-1\n    eor r0, r0, r1"),
    // ---- A32 halfword loads
    a32("ldrh_imm", "ldrh r0, [r1, #6]"),
    a32("ldrh_pre_wb", "ldrh r0, [r1, #-6]!\n    eor r0, r0, r1"),
    a32("ldrh_post", "ldrh r0, [r1], #2\n    eor r0, r0, r1"),
    a32("ldrh_reg", "ldrh r0, [r1, r2]"),
    a32("ldrh_post_reg_sub", "ldrh r0, [r1], -r2\n    eor r0, r0, r1"),
    a32("ldrsh_neg", "ldrsh r0, [r1, #-2]"),
    a32("ldrsh_imm", "ldrsh r0, [r1, #2]"),
    a32("ldrsh_reg_wb", "ldrsh r0, [r1, r2]!\n    eor r0, r0, r1"),
    a32("ldrsh_post", "ldrsh r0, [r1], #2\n    eor r0, r0, r1"),
    // ---- A32 word loads
    a32("ldr_imm", "ldr r0, [r1, #4]"),
    a32("ldr_pre_wb", "ldr r0, [r1, #-8]!\n    eor r0, r0, r1"),
    a32("ldr_post", "ldr r0, [r1], #4\n    eor r0, r0, r1"),
    a32("ldr_regshift", "ldr r0, [r1, r2, lsl #1]"),
    a32("ldr_post_regshift", "ldr r0, [r1], -r2, asr #2\n    eor r0, r0, r1"),
    // ---- A32 dual loads
    a32("ldrd_imm", "ldrd r2, r3, [r1, #8]\n    eor r0, r2, r3, lsr #1"),
    a32("ldrd_post", "ldrd r2, r3, [r1], #8\n    eor r0, r2, r3, lsr #1\n    eor r0, r0, r1"),
    a32("ldrd_reg_wb", "mov r12, r2\n    ldrd r2, r3, [r1, r12]!\n    eor r0, r2, r3, lsr #1\n    eor r0, r0, r1"),
    a32("ldrd_base_in_pair", "ldrd r0, r1, [r1, #-8]\n    eor r0, r0, r1, lsr #1"),
    // ---- A32 stores, read back
    a32("strb_imm", "strb r0, [r1, #3]\n    ldr r0, [r1]"),
    a32("strb_post", "strb r3, [r1], #-1\n    ldr r0, [r1, #1]\n    eor r0, r0, r1"),
    a32("strb_reg_wb", "strb r0, [r1, r2]!\n    ldr r0, [r1]\n    eor r0, r0, r1"),
    a32("strh_imm", "strh r0, [r1, #2]\n    ldr r0, [r1]"),
    a32("strh_pre_wb", "strh r3, [r1, #-6]!\n    ldr r0, [r1, #-2]\n    eor r0, r0, r1"),
    a32("strh_post_reg", "strh r0, [r1], r2\n    ldr r0, [r1, -r2]\n    eor r0, r0, r1"),
    a32("str_pre_wb", "str r3, [r1, #4]!\n    ldrb r0, [r1, #1]\n    eor r0, r0, r1"),
    a32("str_post_regshift", "str r0, [r1], r2, lsl #1\n    ldr r0, [r1, -r2, lsl #1]\n    eor r0, r0, r1"),
    a32("strd_pre_wb", "mov r2, r0\n    strd r2, r3, [r1, #-8]!\n    ldr r0, [r1]\n    ldr r2, [r1, #4]\n    eor r0, r0, r2, lsr #1\n    eor r0, r0, r1"),
    // An immediate whose low nibble is 1111 — the field that is `Rm` in the
    // register form. llvm-mc warns "potentially undefined" on `strd` with it
    // (not on `ldrd`); the ARM ARM sets no condition there, and this asks
    // the processor.
    a32("strd_imm4l_f", "add r12, r1, #3\n    mov r2, r0\n    strd r2, r3, [r12, #-15]\n    ldr r0, [r1, #-12]\n    ldr r2, [r1, #-8]\n    eor r0, r0, r2, lsr #1"),
    a32("strd_reg","mov r12, r2\n    mov r2, r0\n    strd r2, r3, [r1, r12]\n    add r1, r1, r12\n    ldr r0, [r1]\n    ldr r2, [r1, #4]\n    eor r0, r0, r2, lsr #1"),
    // ---- A32 predicated loads: the select and the reaching compare
    a32("ldrbhi", "cmp r2, #4\n    ldrbhi r0, [r1, #1]"),
    a32("ldrsheq", "cmp r2, #4\n    ldrsheq r0, [r1, #2]"),
    // ---- A32 reads of pc
    a32_pool("lit_word", "ldr r0, 1f", ".align 2\n1:  .word 0x8badf00d"),
    a32("lit_word_back", "b 2f\n1:  .word 0x12345678\n2:  ldr r0, 1b"),
    a32_pool("lit_sbyte", "ldrsb r0, 1f", ".align 2\n1:  .byte 0x80, 0x7f, 0, 0"),
    a32_pool("lit_shalf", "ldrsh r0, 1f", ".align 2\n1:  .hword 0x8001, 0"),
    a32_pool("lit_dword", "ldrd r2, r3, 1f\n    eor r0, r2, r3, lsr #1", ".align 3\n1:  .word 0x01234567, 0x89abcdef"),
    a32_pool("lit_reg", "ldr r0, [pc, r2]", ".word 0x11111111, 0x22222222, 0x33333333, 0x44444444"),
    a32_pool("adr_add", "adr r0, 1f\n    ldr r0, [r0]", ".align 2\n1:  .word 0xcafe0001"),
    a32("adr_sub", "b 2f\n1:  .word 0xfeed0002\n2:  adr r0, 1b\n    ldr r0, [r0]"),
    a32_pool("add_pc", "add r0, pc, r2\n    ldr r0, [r0]", ".word 0x55555555, 0x66666666, 0x77777777, 0x88888888"),
    a32("mov_pc", "mov r0, pc\n    ldr r0, [r0]"),
    // ---- A32 block transfers
    a32("ldm_ia", "ldm r1, {r0, r2, r3}\n    eor r0, r0, r2, lsr #1\n    eor r0, r0, r3, lsr #2"),
    a32("ldm_ia_wb", "ldm r1!, {r2, r3}\n    eor r0, r2, r3, lsr #1\n    eor r0, r0, r1"),
    a32("ldm_ib", "ldmib r1, {r2, r3}\n    eor r0, r2, r3, lsr #1"),
    a32("ldm_ib_wb", "ldmib r1!, {r2, r3}\n    eor r0, r2, r3, lsr #1\n    eor r0, r0, r1"),
    a32("ldm_da", "ldmda r1, {r2, r3}\n    eor r0, r2, r3, lsr #1"),
    a32("ldm_da_wb", "ldmda r1!, {r2, r3}\n    eor r0, r2, r3, lsr #1\n    eor r0, r0, r1"),
    a32("ldm_db", "ldmdb r1, {r0, r2, r3}\n    eor r0, r0, r2, lsr #1\n    eor r0, r0, r3, lsr #2"),
    a32("ldm_db_wb", "ldmdb r1!, {r2, r3}\n    eor r0, r2, r3, lsr #1\n    eor r0, r0, r1"),
    a32("ldm_base_in_list", "ldm r1, {r0, r1}\n    eor r0, r0, r1, lsr #1"),
    a32("stm_ia", "stm r1, {r0, r3}\n    ldr r0, [r1]\n    ldr r2, [r1, #4]\n    eor r0, r0, r2, lsr #1"),
    a32("stm_ia_wb", "stm r1!, {r0, r3}\n    ldr r0, [r1, #-8]\n    ldr r2, [r1, #-4]\n    eor r0, r0, r2, lsr #1\n    eor r0, r0, r1"),
    a32("stm_ib", "stmib r1, {r0, r3}\n    ldr r0, [r1, #4]\n    ldr r2, [r1, #8]\n    eor r0, r0, r2, lsr #1"),
    a32("stm_ib_wb", "stmib r1!, {r0, r3}\n    ldr r0, [r1, #-4]\n    ldr r2, [r1]\n    eor r0, r0, r2, lsr #1\n    eor r0, r0, r1"),
    a32("stm_da", "stmda r1, {r0, r3}\n    ldr r0, [r1, #-4]\n    ldr r2, [r1]\n    eor r0, r0, r2, lsr #1"),
    a32("stm_da_wb", "stmda r1!, {r0, r3}\n    ldr r0, [r1, #4]\n    ldr r2, [r1, #8]\n    eor r0, r0, r2, lsr #1\n    eor r0, r0, r1"),
    a32("stm_db", "stmdb r1, {r0, r3}\n    ldr r0, [r1, #-8]\n    ldr r2, [r1, #-4]\n    eor r0, r0, r2, lsr #1"),
    a32("stm_db_wb", "stmdb r1!, {r0, r3}\n    ldr r0, [r1]\n    ldr r2, [r1, #4]\n    eor r0, r0, r2, lsr #1\n    eor r0, r0, r1"),
    a32("push_pop_round_trip", "push {r4, r5}\n    ldr r4, [r1]\n    mov r5, r0\n    stmdb sp!, {r4, r5}\n    ldm sp!, {r2, r3}\n    pop {r4, r5}\n    eor r0, r2, r3, lsr #1"),
    a32("pop_pc_single", "push {lr}\n    ldr r0, [r1, r2]\n    pop {pc}"),
    a32("pop_pc_list", "push {r4, lr}\n    ldr r4, [r1]\n    eor r0, r4, r0\n    pop {r4, pc}"),
    a32("ldm_pc_return", "str lr, [r1, #4]\n    str r3, [r1]\n    ldm r1, {r0, pc}"),
    // ---- Thumb
    thumb("t_ldrb_imm", "ldrb r0, [r1, #3]"),
    thumb("t_ldrsb_reg", "ldrsb r0, [r1, r2]"),
    thumb("t_ldrh_post", "ldrh r0, [r1], #2\n    eor.w r0, r0, r1"),
    thumb("t_ldrsh_pre_wb", "ldrsh r0, [r1, #-2]!\n    eor.w r0, r0, r1"),
    thumb("t_ldr_regshift", "ldr.w r0, [r1, r2, lsl #1]"),
    thumb("t_ldrd_post", "ldrd r2, r3, [r1], #8\n    eor.w r0, r2, r3, lsr #1\n    eor.w r0, r0, r1"),
    // Pre-indexed write-back with `sp` as the base: llvm-mc warns
    // "potentially undefined" on these (`strd r0, r8, [sp, #-16]!`); the ARM
    // ARM sets no such condition, and this asks the processor.
    thumb("t_strd_sp_wb", "strd r0, r3, [sp, #-8]!\n    ldr r2, [sp]\n    ldr r12, [sp, #4]\n    add sp, sp, #8\n    eor.w r0, r2, r12, lsr #1"),
    thumb("t_ldrd_sp_wb", "push {r0, r3}\n    add sp, sp, #8\n    ldrd r2, r12, [sp, #-8]!\n    add sp, sp, #8\n    eor.w r0, r2, r12, lsr #1"),
    thumb("t_strb_post","strb r0, [r1], #1\n    ldr r0, [r1, #-1]\n    eor.w r0, r0, r1"),
    thumb("t_strd_pre_wb", "mov r2, r0\n    strd r2, r3, [r1, #-8]!\n    ldr r0, [r1]\n    ldr r2, [r1, #4]\n    eor.w r0, r0, r2, lsr #1\n    eor.w r0, r0, r1"),
    thumb_pool("t_lit_aligned", "ldr r0, 1f", ".align 2\n1:  .word 0x0badcafe"),
    thumb_pool("t_lit_unaligned", "mov r12, r0\n    ldr r0, 1f", ".align 2\n1:  .word 0x1badcafe"),
    thumb("t_lit_w_back", "b 2f\n    .align 2\n1:  .word 0x2badcafe\n2:  mov r12, r0\n    ldr.w r0, 1b"),
    thumb_pool("t_lit_dword", "mov r12, r0\n    ldrd r2, r3, 1f\n    eor.w r0, r2, r3, lsr #1", ".align 3\n1:  .word 0x76543210, 0xfedcba98"),
    thumb_pool("t_lit_shalf", "mov r12, r0\n    ldrsh.w r0, 1f", ".align 2\n1:  .hword 0x8002, 0"),
    thumb_pool("t_adr", "mov r12, r0\n    adr r0, 1f\n    ldr r0, [r0]", ".align 2\n1:  .word 0x3badcafe"),
    thumb("t_adr_w_back", "b 2f\n    .align 2\n1:  .word 0x4badcafe\n2:  mov r12, r0\n    adr.w r0, 1b\n    ldr r0, [r0]"),
    thumb("t_mov_pc", "mov r12, r0\n    mov r0, pc\n    ldrh r0, [r0]"),
    thumb("t_ldm16_wb", "ldm r1!, {r2, r3}\n    eor.w r0, r2, r3, lsr #1\n    eor.w r0, r0, r1"),
    thumb("t_ldm16_base_in_list", "ldm r1, {r0, r1}\n    eor.w r0, r0, r1, lsr #1"),
    thumb("t_stm16", "stm r1!, {r0, r3}\n    ldr r0, [r1, #-8]\n    ldr r2, [r1, #-4]\n    eor.w r0, r0, r2, lsr #1\n    eor.w r0, r0, r1"),
    thumb("t_ldm_w", "ldm.w r1, {r2, r3}\n    eor.w r0, r2, r3, lsr #1"),
    thumb("t_ldmdb_wb", "ldmdb r1!, {r2, r3}\n    eor.w r0, r2, r3, lsr #1\n    eor.w r0, r0, r1"),
    thumb("t_stm_w_wb", "stm.w r1!, {r0, r3}\n    ldr r0, [r1, #-8]\n    ldr r2, [r1, #-4]\n    eor.w r0, r0, r2, lsr #1\n    eor.w r0, r0, r1"),
    thumb("t_stmdb", "stmdb r1, {r0, r3}\n    ldr r0, [r1, #-8]\n    ldr r2, [r1, #-4]\n    eor.w r0, r0, r2, lsr #1"),
    thumb("t_push_pop_round_trip", "push {r4, r5}\n    ldr r4, [r1]\n    mov r5, r0\n    push {r4, r5}\n    pop {r2, r3}\n    pop {r4, r5}\n    eor.w r0, r2, r3, lsr #1"),
    thumb("t_pop_pc", "push {r4, lr}\n    ldr r4, [r1]\n    eor.w r0, r4, r0\n    pop {r4, pc}"),
];

/// Forms that stay `asm`: each must stop as not modelled.
const CONTROLS: &[Case] = &[
    a32("ldrbt", "ldrbt r0, [r1], #1"),
    a32("strne", "cmp r2, #4\n    strne r0, [r1]\n    ldr r0, [r1]"),
    a32("ldrne_post", "cmp r2, #4\n    ldrne r0, [r1], #4\n    eor r0, r0, r1"),
    thumb("t_add_pc", "mov r0, #0\n    add r0, pc\n    ldrh r0, [r0]"),
];

/// A small deterministic generator (SplitMix64), so the inputs are a function
/// of the seed and nothing else.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn word(&mut self) -> u32 {
        self.next() as u32
    }
}

/// The buffer's bytes: random, with bit 7 set where `i/2 + i/4` is even and
/// clear where it is odd — so the sign of a byte and of a halfword changes
/// both with the immediate offset and from one word to the next, and every
/// sign-extending form, register-indexed ones included (the index moves in
/// whole words), meets both signs.
fn buffer(rng: &mut Rng) -> Vec<u8> {
    (0..BUF_WORDS * 4)
        .map(|i| {
            let b = rng.next() as u8;
            if (i / 2 + i / 4) % 2 == 0 { b | 0x80 } else { b & 0x7f }
        })
        .collect()
}

/// `CALLS` input quadruples `(r0, r2, r3)`; `r1` is the buffer's middle and is
/// filled in by the driver and the harness alike.
fn inputs(rng: &mut Rng) -> Vec<[u32; 3]> {
    let mut out: Vec<[u32; 3]> = vec![[0, 0, 0], [0xffff_ffff, 12, 0x8000_0000], [0x7fff_ffff, 4, 0xffff_ffff], [0x80, 8, 0x7f]];
    while out.len() < CALLS {
        out.push([rng.word(), 4 * (rng.next() % 4) as u32, rng.word()]);
    }
    out
}

fn work_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("n0xis-a32-memory-cpu-{}", std::process::id()));
    std::fs::create_dir_all(&d).expect("work dir");
    d
}

/// The corpus and its driver, as one assembly file.
fn assembly(funcs: &[&Case], inputs: &[[u32; 3]], buf: &[u8]) -> String {
    let mut s = String::from(".syntax unified\n.arch armv7-a\n.text\n");
    for c in funcs {
        let (set, kind) = match c.set {
            Set::A32 => (".arm", ""),
            Set::Thumb => (".thumb", ".thumb_func\n"),
        };
        s += &format!(
            "{set}\n.align 2\n.global f_{n}\n{kind}.type f_{n}, %function\nf_{n}:\n    {body}\n    bx lr\n{tail}\n",
            n = c.name,
            body = c.body,
            tail = c.tail
        );
    }
    s += &format!(
        "
.arm
.align 2
.global _start
_start:
    ldr r4, =inputs
    ldr r5, ={n_in}
    ldr r8, =out
1:  ldr r6, =funcs
    ldr r10, ={n_f}
2:  ldr r0, =pristine
    ldr r1, =buf
    mov r2, #{words}
3:  ldr r3, [r0], #4
    str r3, [r1], #4
    subs r2, r2, #1
    bne 3b
    ldm r4, {{r0, r2, r3}}
    ldr r1, =buf + {r1_offset}
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
        words = BUF_WORDS,
        r1_offset = R1_OFFSET,
        size = inputs.len() * funcs.len() * 4
    );
    for c in funcs {
        s += &format!("    .word f_{}\n", c.name);
    }
    s += "inputs:\n";
    for [a, b, c] in inputs {
        s += &format!("    .word {a:#x}, {b:#x}, {c:#x}\n");
    }
    let bytes = |label: &str| {
        let list: Vec<String> = buf.iter().map(|b| format!("{b:#04x}")).collect();
        format!(".global {label}\n.align 3\n{label}:\n    .byte {}\n", list.join(", "))
    };
    s += &bytes("pristine");
    s += &bytes("buf");
    s += &format!(".bss\n.align 2\nout:\n    .space {}\n", inputs.len() * funcs.len() * 4);
    s
}

fn run(cmd: &mut Command, what: &str) -> Vec<u8> {
    let out = cmd.output().unwrap_or_else(|e| panic!("{what}: cannot run ({e})"));
    assert!(out.status.success(), "{what} failed: {}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

#[test]
fn a32_memory_lifts_compute_what_the_processor_computes() {
    let seed = std::env::var("N0XIS_ORACLE_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_SEED);
    let mut rng = Rng(seed);
    let buf = buffer(&mut rng);
    let inputs = inputs(&mut rng);
    let funcs: Vec<&Case> = CASES.iter().chain(CONTROLS).collect();
    let dir = work_dir();
    let (src, obj, elf) = (dir.join("memory.s"), dir.join("memory.o"), dir.join("memory.elf"));
    std::fs::write(&src, assembly(&funcs, &inputs, &buf)).expect("write the corpus");
    run(Command::new(AS).arg("-o").arg(&obj).arg(&src), AS);
    run(Command::new(LD).args(["-Ttext=0x10000", "-o"]).arg(&elf).arg(&obj), LD);

    // The processor's answers, `inputs × funcs` words in driver order.
    let raw = run(Command::new(QEMU).arg(&elf), QEMU);
    assert_eq!(raw.len(), inputs.len() * funcs.len() * 4, "the processor answered every call");
    let answers: Vec<u32> = raw.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)).collect();

    // Where each function and the buffer are, from the symbol table, read by an
    // independent tool. `nm` prints a Thumb function's address without its
    // mode bit; the driver's table (`.word f_…`) carries it, and the processor
    // entering each function in the right state is what `blx` checks.
    let nm = String::from_utf8(run(Command::new(NM).arg(&elf), NM)).expect("nm text");
    let symbols: BTreeMap<String, u64> = nm
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let (a, _, n) = (it.next()?, it.next()?, it.next()?);
            Some((n.to_string(), u64::from_str_radix(a, 16).ok()?))
        })
        .collect();
    let r1 = symbols["buf"] + R1_OFFSET;

    let image = ImageSource::load(&elf).expect("n0xis loads the corpus");
    assert_eq!(image.machine(), "arm", "n0xis is reading the 32-bit ARM image the assembler produced");
    let (a32_arch, thumb_arch) = (Arm32::a32(), Arm32::thumb());
    let a32_ctx = Ctx::new(&image, &a32_arch as &dyn Arch).with_symbols(&image as &dyn SymbolProvider);
    let thumb_ctx = Ctx::new(&image, &thumb_arch as &dyn Arch).with_symbols(&image as &dyn SymbolProvider);

    let (mut agree, mut wrong, mut gaps) = (0usize, Vec::new(), Vec::new());
    let mut controls_stopped = 0usize;
    for (fi, c) in funcs.iter().enumerate() {
        let sym = symbols.get(&format!("f_{}", c.name)).copied().unwrap_or_else(|| panic!("nm has no f_{}", c.name));
        let ctx = if c.set == Set::Thumb { &thumb_ctx } else { &a32_ctx };
        let cfg = CfgPass.run(ctx, CfgInput::new(Va(sym & !1), 256)).unwrap_or_else(|e| panic!("{}: CFG failed: {e}", c.name));
        let ssa = SsaPass.run(ctx, cfg).unwrap_or_else(|e| panic!("{}: SSA failed: {e}", c.name));
        let control = CONTROLS.iter().any(|x| x.name == c.name);
        for (ii, [r0, r2, r3]) in inputs.iter().enumerate() {
            let expected = answers[ii * funcs.len() + fi];
            let mut emu = Emulator::with_config(&ssa.blocks, Some(&image as &dyn MemorySource), EmuConfig::default());
            emu.set_var("r0", u64::from(*r0)).set_var("r1", r1).set_var("r2", u64::from(*r2)).set_var("r3", u64::from(*r3));
            // What a `push` saves and its `pop` restores — values the result
            // never depends on, but which must hold something to be stored.
            for (k, reg) in ["r4", "r5", "r12", "lr"].iter().enumerate() {
                emu.set_var(reg, 0x1000 + k as u64);
            }
            let name = c.name;
            match (emu.run(), control) {
                (Err(EmuError::Unlifted { .. }), true) => controls_stopped += 1,
                (got, true) => wrong.push(format!("{name} must stay asm, got {got:?}")),
                (Ok(r), false) if r.ret == Some(u64::from(expected)) => agree += 1,
                (Ok(r), false) => wrong.push(format!(
                    "{name} (`{}`) r0={r0:#x} r1={r1:#x} r2={r2:#x} r3={r3:#x}: processor {expected:#x}, n0xis {:x?}",
                    c.body.replace('\n', ";"),
                    r.ret
                )),
                (Err(e), false) => gaps.push(format!("{name} (`{}`): {e:?}", c.body.replace('\n', ";"))),
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    let thumb_cases = CASES.iter().filter(|c| c.set == Set::Thumb).count();
    eprintln!(
        "a32/thumb memory vs the processor (seed {seed:#x}): {} forms ({} A32, {thumb_cases} Thumb) x {} inputs -> {agree} agree, {} wrong, {} not modelled; {controls_stopped} control answers stopped as asm",
        CASES.len(),
        CASES.len() - thumb_cases,
        inputs.len(),
        wrong.len(),
        gaps.len()
    );
    for w in wrong.iter().take(30) {
        eprintln!("  WRONG {w}");
    }
    for g in gaps.iter().take(20) {
        eprintln!("  GAP   {g}");
    }
    assert_eq!(controls_stopped, CONTROLS.len() * inputs.len(), "every control stopped as asm: the harness answers only from the lift");
    assert!(wrong.is_empty(), "{} answers differ from the processor", wrong.len());
    assert!(gaps.is_empty(), "{} answers were not modelled", gaps.len());
    assert_eq!(agree, CASES.len() * inputs.len(), "every case was compared");
}
