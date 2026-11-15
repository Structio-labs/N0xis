// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What a branch tests after `add`, `sub`, `inc`, `dec` and `bt`, against the
//! processor running the same instruction.
//!
//! These conditions printed as comments (`/*cond(jb) after result*/`), and a
//! reconstruction of a carry or an overflow is the kind of expression that reads
//! right and is wrong at one boundary. So each is run: the instruction under test
//! is executed here by inline assembly and its flags read back with `pushfq`, which
//! gives what the condition must answer; the same bytes then go through CFG, SSA
//! and the emulator as a function returning 1 when the branch is taken.

#![cfg(target_arch = "x86_64")]

use std::arch::asm;

use n0xis_arch::X64;
use n0xis_contracts::Va;
use n0xis_core::{CfgInput, CfgPass, Ctx, EmuConfig, Emulator, Pass, SsaPass};
use n0xis_sources::{MemorySource, Snapshot};

const CF: u64 = 1;
const ZF: u64 = 1 << 6;
const SF: u64 = 1 << 7;
const OF: u64 = 1 << 11;

/// The Intel manual's definition of each condition, over a flags word.
fn taken(jcc: u8, flags: u64) -> bool {
    let (cf, zf, sf, of) = (flags & CF != 0, flags & ZF != 0, flags & SF != 0, flags & OF != 0);
    match jcc {
        0x70 => of,
        0x71 => !of,
        0x72 => cf,
        0x73 => !cf,
        0x74 => zf,
        0x75 => !zf,
        0x76 => cf || zf,
        0x77 => !cf && !zf,
        0x78 => sf,
        0x79 => !sf,
        0x7c => sf != of,
        0x7d => sf == of,
        0x7e => zf || sf != of,
        0x7f => !zf && sf == of,
        _ => unreachable!("not a tested condition"),
    }
}

const EVERY_CONDITION: [u8; 14] = [0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7c, 0x7d, 0x7e, 0x7f];
/// What `inc` and `dec` answer: they leave the carry alone, so nothing that reads it.
const WITHOUT_CARRY: [u8; 10] = [0x70, 0x71, 0x74, 0x75, 0x78, 0x79, 0x7c, 0x7d, 0x7e, 0x7f];
/// What `bt` answers: the carry is all it sets that a compiler reads.
const CARRY_ONLY: [u8; 2] = [0x72, 0x73];

/// The flags word after `$insn`, with the two values in `rdi` and `rsi` and `rdx`
/// pointing at memory holding the first. Clears CF, ZF, SF and OF first so that an
/// instruction leaving one alone shows it clear, as the masks above then ignore.
macro_rules! machine {
    ($insn:literal) => {
        |a: u64, b: u64| -> (u64, u64) {
            let mut memory = a;
            let (mut rdi, mut flags) = (a, 0u64);
            // SAFETY: `rdx` points at a live local, and the instruction under test
            // touches only it and the registers named here.
            unsafe {
                asm!(
                    "xor eax, eax",
                    $insn,
                    "pushfq",
                    "pop {flags}",
                    flags = out(reg) flags,
                    inout("rdi") rdi,
                    in("rsi") b,
                    in("rcx") b,
                    in("rdx") std::ptr::addr_of_mut!(memory),
                    out("rax") _,
                );
            }
            let _ = rdi;
            (flags, memory)
        }
    };
}

struct Operation {
    name: &'static str,
    bytes: &'static [u8],
    conditions: &'static [u8],
    machine: fn(u64, u64) -> (u64, u64),
}

/// A function: the instruction, the branch, and which way it went.
fn function(insn: &[u8], jcc: u8) -> Vec<u8> {
    let mut code = insn.to_vec();
    code.extend([jcc, 0x06]); // jcc +6
    code.extend([0xb8, 0, 0, 0, 0, 0xc3]); // mov $0,%eax; ret
    code.extend([0xb8, 1, 0, 0, 0, 0xc3]); // mov $1,%eax; ret
    code
}

const MEMORY: u64 = 0x2000;

/// What the IR's function returns.
fn emulated(code: &[u8], a: u64, b: u64) -> Option<u64> {
    let snap = Snapshot::builder().region(Va(0x1000), code.to_vec()).region(Va(MEMORY), a.to_le_bytes().to_vec()).build();
    let arch = X64::new();
    let ctx = Ctx::new(&snap, &arch);
    let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), code.len())).expect("cfg");
    let ssa = SsaPass.run(&ctx, cfg).expect("ssa");
    let mut emu = Emulator::with_config(&ssa.blocks, Some(&snap as &dyn MemorySource), EmuConfig::default());
    emu.set_var("rdi", a).set_var("rsi", b).set_var("rcx", b).set_var("rdx", MEMORY);
    emu.run().unwrap_or_else(|e| panic!("emulating {code:02x?} on {a:x} {b:x}: {e}")).ret
}

const BOUNDARY: [u64; 18] = [
    0,
    1,
    2,
    0x7f,
    0x80,
    0xff,
    0x7fff,
    0x8000,
    0xffff,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
    0x1_0000_0000,
    0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0001,
    0xdead_beef_cafe_1234,
];

#[test]
fn every_condition_after_arithmetic_answers_as_the_processor_does() {
    let operations = [
        Operation { name: "add %rsi,%rdi", bytes: &[0x48, 0x01, 0xf7], conditions: &EVERY_CONDITION, machine: machine!("add rdi, rsi") },
        Operation { name: "add %esi,%edi", bytes: &[0x01, 0xf7], conditions: &EVERY_CONDITION, machine: machine!("add edi, esi") },
        Operation { name: "add %si,%di", bytes: &[0x66, 0x01, 0xf7], conditions: &EVERY_CONDITION, machine: machine!("add di, si") },
        Operation { name: "add %sil,%dil", bytes: &[0x40, 0x00, 0xf7], conditions: &EVERY_CONDITION, machine: machine!("add dil, sil") },
        Operation { name: "sub %rsi,%rdi", bytes: &[0x48, 0x29, 0xf7], conditions: &EVERY_CONDITION, machine: machine!("sub rdi, rsi") },
        Operation { name: "sub %esi,%edi", bytes: &[0x29, 0xf7], conditions: &EVERY_CONDITION, machine: machine!("sub edi, esi") },
        Operation { name: "add %rsi,(%rdx)", bytes: &[0x48, 0x01, 0x32], conditions: &EVERY_CONDITION, machine: machine!("add qword ptr [rdx], rsi") },
        Operation { name: "add %esi,(%rdx)", bytes: &[0x01, 0x32], conditions: &EVERY_CONDITION, machine: machine!("add dword ptr [rdx], esi") },
        Operation { name: "sub %rsi,(%rdx)", bytes: &[0x48, 0x29, 0x32], conditions: &EVERY_CONDITION, machine: machine!("sub qword ptr [rdx], rsi") },
        Operation { name: "sub %esi,(%rdx)", bytes: &[0x29, 0x32], conditions: &EVERY_CONDITION, machine: machine!("sub dword ptr [rdx], esi") },
        Operation { name: "incq (%rdx)", bytes: &[0x48, 0xff, 0x02], conditions: &WITHOUT_CARRY, machine: machine!("inc qword ptr [rdx]") },
        Operation { name: "incl (%rdx)", bytes: &[0xff, 0x02], conditions: &WITHOUT_CARRY, machine: machine!("inc dword ptr [rdx]") },
        Operation { name: "decq (%rdx)", bytes: &[0x48, 0xff, 0x0a], conditions: &WITHOUT_CARRY, machine: machine!("dec qword ptr [rdx]") },
        Operation { name: "decl (%rdx)", bytes: &[0xff, 0x0a], conditions: &WITHOUT_CARRY, machine: machine!("dec dword ptr [rdx]") },
        // A register keeps its result as the flags, and what a signed order or the carry
        // reads is the operation's: `dec` from the least value under `jg`, `inc` to it
        // under `jl`, `neg` of it, at both widths.
        Operation { name: "inc %rdi", bytes: &[0x48, 0xff, 0xc7], conditions: &WITHOUT_CARRY, machine: machine!("inc rdi") },
        Operation { name: "inc %edi", bytes: &[0xff, 0xc7], conditions: &WITHOUT_CARRY, machine: machine!("inc edi") },
        Operation { name: "dec %rdi", bytes: &[0x48, 0xff, 0xcf], conditions: &WITHOUT_CARRY, machine: machine!("dec rdi") },
        Operation { name: "dec %edi", bytes: &[0xff, 0xcf], conditions: &WITHOUT_CARRY, machine: machine!("dec edi") },
        Operation { name: "neg %rdi", bytes: &[0x48, 0xf7, 0xdf], conditions: &EVERY_CONDITION, machine: machine!("neg rdi") },
        Operation { name: "neg %edi", bytes: &[0xf7, 0xdf], conditions: &EVERY_CONDITION, machine: machine!("neg edi") },
        Operation { name: "bt %rsi,%rdi", bytes: &[0x48, 0x0f, 0xa3, 0xf7], conditions: &CARRY_ONLY, machine: machine!("bt rdi, rsi") },
        Operation { name: "bt %esi,%edi", bytes: &[0x0f, 0xa3, 0xf7], conditions: &CARRY_ONLY, machine: machine!("bt edi, esi") },
        Operation { name: "bt $5,%rdi", bytes: &[0x48, 0x0f, 0xba, 0xe7, 0x05], conditions: &CARRY_ONLY, machine: machine!("bt rdi, 5") },
        Operation { name: "bt $0x25,%edi", bytes: &[0x0f, 0xba, 0xe7, 0x25], conditions: &CARRY_ONLY, machine: machine!("bt edi, 0x25") },
    ];
    let mut compared = 0usize;
    let mut wrong = Vec::new();
    for op in &operations {
        for &jcc in op.conditions {
            let code = function(op.bytes, jcc);
            for &a in &BOUNDARY {
                for &b in &BOUNDARY {
                    let (flags, _) = (op.machine)(a, b);
                    let want = taken(jcc, flags);
                    let got = emulated(&code, a, b) == Some(1);
                    compared += 1;
                    if got != want {
                        wrong.push(format!("{} j{jcc:02x} on {a:x} {b:x}: processor {want}, IR {got}", op.name));
                    }
                }
            }
        }
    }
    // The store is written from the old value now, so the store is checked too.
    for op in operations.iter().filter(|op| op.name.ends_with("(%rdx)")) {
        let mut code = op.bytes.to_vec();
        code.extend([0x48, 0x8b, 0x02, 0xc3]); // mov (%rdx),%rax; ret
        for &a in &BOUNDARY {
            for &b in &BOUNDARY {
                let (_, memory) = (op.machine)(a, b);
                let got = emulated(&code, a, b);
                compared += 1;
                if got != Some(memory) {
                    wrong.push(format!("{} on {a:x} {b:x}: processor stored {memory:x}, IR {got:x?}", op.name));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{} of {compared} wrong; first: {:#?}", wrong.len(), &wrong[..wrong.len().min(12)]);
    assert!(compared > 20_000, "compared only {compared}");
}

/// `rax` and `rdx` after `$insn`, run with `rax`, `rdx` and `rcx` holding the three values.
macro_rules! accumulator {
    ($insn:literal) => {
        |a: u64, d: u64, b: u64| -> (u64, u64) {
            let (mut rax, mut rdx) = (a, d);
            // SAFETY: the instruction touches only the registers named here and the
            // flags. A divide is run only on operands `divide_faults` passes.
            unsafe {
                asm!($insn, inout("rax") rax, inout("rdx") rdx, in("rcx") b, options(nomem, nostack));
            }
            (rax, rdx)
        }
    };
}

/// What a one-operand divide divides by, and whether it divides by `ah`.
#[derive(Clone, Copy)]
enum Divide {
    No,
    By { width: u32, signed: bool, ah: bool },
}

/// Whether the divide faults on these operands, by the manual: a zero divisor, or
/// a quotient outside the operand's width. The dividend is `ax` at 8 bits and
/// `rdx:rax`'s low halves of the width above it.
fn divide_faults(div: Divide, a: u64, d: u64, b: u64) -> bool {
    let Divide::By { width, signed, ah } = div else { return false };
    let mask = |v: u64| u128::from(v) & ((1u128 << width) - 1);
    let divisor = if ah { mask(a >> 8) } else { mask(b) };
    let dividend = if width == 8 { u128::from(a) & 0xffff } else { (mask(d) << width) | mask(a) };
    if divisor == 0 {
        return true;
    }
    if !signed {
        return dividend / divisor >= 1u128 << width;
    }
    let sext = |v: u128, bits: u32| ((v << (128 - bits)) as i128) >> (128 - bits);
    let q = sext(dividend, 2 * width) / sext(divisor, width);
    q < -(1i128 << (width - 1)) || q >= 1i128 << (width - 1)
}

struct Accumulator {
    name: &'static str,
    bytes: &'static [u8],
    divide: Divide,
    machine: fn(u64, u64, u64) -> (u64, u64),
}

/// `rax` and `rdx` after the instruction under the IR, or the emulator's refusal.
/// One SSA per function, run on every input.
fn accumulator_lifts(bytes: &[u8]) -> [n0xis_core::SsaArtifact; 2] {
    let arch = X64::new();
    [&[0xc3][..], &[0x48, 0x89, 0xd0, 0xc3][..]].map(|tail| {
        let mut code = bytes.to_vec();
        code.extend(tail); // ret, or mov %rdx,%rax; ret
        let snap = Snapshot::builder().region(Va(0x1000), code.clone()).build();
        let ctx = Ctx::new(&snap, &arch);
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), code.len())).expect("cfg");
        SsaPass.run(&ctx, cfg).expect("ssa")
    })
}

fn accumulator_emulated(ssa: &n0xis_core::SsaArtifact, a: u64, d: u64, b: u64) -> Result<Option<u64>, String> {
    let mut emu = Emulator::with_config(&ssa.blocks, None, EmuConfig::default());
    emu.set_var("rax", a).set_var("rdx", d).set_var("rcx", b);
    emu.run().map(|r| r.ret).map_err(|e| e.to_string())
}

/// One-operand `mul`, `imul`, `div` and `idiv` in every width, and the two- and
/// three-operand `imul`, against the processor: `rax` and `rdx` afterwards, on
/// each width's boundary values and seeded random ones. An 8- or 16-bit one was
/// left untranslated (`/*mul bl*/`), so the IR could not answer at all.
///
/// A divide the manual says faults (a zero divisor, a quotient too wide) is not run
/// on the processor; the IR must refuse it rather than answer a number, and that
/// refusal is what a body states: the call of `__udiv` is the instruction's own.
#[test]
fn multiply_and_divide_in_every_width_leave_what_the_processor_leaves() {
    use Divide::{By, No};
    let d8 = |signed| By { width: 8, signed, ah: false };
    let operations = [
        Accumulator { name: "mul %cl", bytes: &[0xf6, 0xe1], divide: No, machine: accumulator!("mul cl") },
        Accumulator { name: "imul %cl", bytes: &[0xf6, 0xe9], divide: No, machine: accumulator!("imul cl") },
        Accumulator { name: "mul %ah", bytes: &[0xf6, 0xe4], divide: No, machine: accumulator!("mul ah") },
        Accumulator { name: "mul %cx", bytes: &[0x66, 0xf7, 0xe1], divide: No, machine: accumulator!("mul cx") },
        Accumulator { name: "imul %cx", bytes: &[0x66, 0xf7, 0xe9], divide: No, machine: accumulator!("imul cx") },
        Accumulator { name: "mul %ecx", bytes: &[0xf7, 0xe1], divide: No, machine: accumulator!("mul ecx") },
        Accumulator { name: "imul %ecx", bytes: &[0xf7, 0xe9], divide: No, machine: accumulator!("imul ecx") },
        Accumulator { name: "mul %edx", bytes: &[0xf7, 0xe2], divide: No, machine: accumulator!("mul edx") },
        Accumulator { name: "mul %rcx", bytes: &[0x48, 0xf7, 0xe1], divide: No, machine: accumulator!("mul rcx") },
        Accumulator { name: "imul %rcx", bytes: &[0x48, 0xf7, 0xe9], divide: No, machine: accumulator!("imul rcx") },
        Accumulator { name: "mul %rdx", bytes: &[0x48, 0xf7, 0xe2], divide: No, machine: accumulator!("mul rdx") },
        // The dividend setups: `rdx` (or `dx`) from the sign of `rax` (or `ax`).
        Accumulator { name: "cwtd", bytes: &[0x66, 0x99], divide: No, machine: accumulator!("cwd") },
        Accumulator { name: "cltd", bytes: &[0x99], divide: No, machine: accumulator!("cdq") },
        Accumulator { name: "cqto", bytes: &[0x48, 0x99], divide: No, machine: accumulator!("cqo") },
        Accumulator { name: "div %cl", bytes: &[0xf6, 0xf1], divide: d8(false), machine: accumulator!("div cl") },
        Accumulator { name: "idiv %cl", bytes: &[0xf6, 0xf9], divide: d8(true), machine: accumulator!("idiv cl") },
        Accumulator { name: "div %ah", bytes: &[0xf6, 0xf4], divide: By { width: 8, signed: false, ah: true }, machine: accumulator!("div ah") },
        Accumulator { name: "div %cx", bytes: &[0x66, 0xf7, 0xf1], divide: By { width: 16, signed: false, ah: false }, machine: accumulator!("div cx") },
        Accumulator { name: "idiv %cx", bytes: &[0x66, 0xf7, 0xf9], divide: By { width: 16, signed: true, ah: false }, machine: accumulator!("idiv cx") },
        Accumulator { name: "div %ecx", bytes: &[0xf7, 0xf1], divide: By { width: 32, signed: false, ah: false }, machine: accumulator!("div ecx") },
        Accumulator { name: "idiv %ecx", bytes: &[0xf7, 0xf9], divide: By { width: 32, signed: true, ah: false }, machine: accumulator!("idiv ecx") },
        Accumulator { name: "div %rcx", bytes: &[0x48, 0xf7, 0xf1], divide: By { width: 64, signed: false, ah: false }, machine: accumulator!("div rcx") },
        Accumulator { name: "idiv %rcx", bytes: &[0x48, 0xf7, 0xf9], divide: By { width: 64, signed: true, ah: false }, machine: accumulator!("idiv rcx") },
        Accumulator { name: "imul %cx,%ax", bytes: &[0x66, 0x0f, 0xaf, 0xc1], divide: No, machine: accumulator!("imul ax, cx") },
        Accumulator { name: "imul %ecx,%eax", bytes: &[0x0f, 0xaf, 0xc1], divide: No, machine: accumulator!("imul eax, ecx") },
        Accumulator { name: "imul %rcx,%rax", bytes: &[0x48, 0x0f, 0xaf, 0xc1], divide: No, machine: accumulator!("imul rax, rcx") },
        Accumulator { name: "imul $0x1234,%cx,%ax", bytes: &[0x66, 0x69, 0xc1, 0x34, 0x12], divide: No, machine: accumulator!("imul ax, cx, 0x1234") },
        Accumulator { name: "imul $-7,%ecx,%eax", bytes: &[0x6b, 0xc1, 0xf9], divide: No, machine: accumulator!("imul eax, ecx, -7") },
        Accumulator { name: "imul $0x12345678,%rcx,%rax", bytes: &[0x48, 0x69, 0xc1, 0x78, 0x56, 0x34, 0x12], divide: No, machine: accumulator!("imul rax, rcx, 0x12345678") },
        Accumulator { name: "imul $-3,%rcx,%rax", bytes: &[0x48, 0x6b, 0xc1, 0xfd], divide: No, machine: accumulator!("imul rax, rcx, -3") },
    ];
    // The boundary values, each width's least value among them, and seeded random ones.
    let mut values = BOUNDARY.to_vec();
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..14 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        values.push(seed);
    }
    let (mut compared, mut refused) = (0usize, 0usize);
    let mut wrong = Vec::new();
    for op in &operations {
        let [rax_of, rdx_of] = accumulator_lifts(op.bytes);
        for &a in &values {
            for &b in &values {
                // `rdx` as a divide's high half: zero, the sign of `rax`, and two others.
                for d in [0, ((a as i64) >> 63) as u64, b >> 3, a ^ b] {
                    let got = (accumulator_emulated(&rax_of, a, d, b), accumulator_emulated(&rdx_of, a, d, b));
                    compared += 1;
                    if divide_faults(op.divide, a, d, b) {
                        refused += 1;
                        if got.0.is_ok() || got.1.is_ok() {
                            wrong.push(format!("{} on rax={a:x} rdx={d:x} rcx={b:x}: the processor faults, IR {got:x?}", op.name));
                        }
                        continue;
                    }
                    let (rax, rdx) = (op.machine)(a, d, b);
                    if got != (Ok(Some(rax)), Ok(Some(rdx))) {
                        wrong.push(format!("{} on rax={a:x} rdx={d:x} rcx={b:x}: processor rax={rax:x} rdx={rdx:x}, IR {got:x?}", op.name));
                    }
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{} of {compared} wrong; first: {:#?}", wrong.len(), &wrong[..wrong.len().min(12)]);
    assert!(compared > 100_000 && refused > 1_000, "compared only {compared}, refused {refused}");
}
