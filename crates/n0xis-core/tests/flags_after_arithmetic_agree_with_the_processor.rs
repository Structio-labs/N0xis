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
