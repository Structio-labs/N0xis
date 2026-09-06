// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `X64::lift` / `X64::branch_condition` — the x86-64 instruction → micro-IR
//! lowering. Kept in its own file (rather than inline in `x64.rs`) purely for
//! size; it is still x64-only ISA knowledge, so it stays behind the `Arch`
//! seam like everything else in this crate.
//!
//! Coverage mirrors the archived v0 template renderer
//! (v0's `pseudo.rs::lift_instruction`) — same mnemonic
//! set — but every operand becomes a typed [`MicroExpr`], and every
//! flag-touching instruction (not just `cmp`/`test`) writes the shared
//! [`FLAGS_VAR`], which is what makes SSA construction able to detect a stale
//! compare instead of silently reusing one (see `microir.rs` module docs).

use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};

use crate::insn::DecodedInsn;
use crate::microir::{BinOp, Bits, CallTarget, CmpKind, MicroExpr, MicroStmt, UnOp, FLAGS_VAR};
use crate::x64::x64reg;
use crate::{Arch, CallConv, RegisterFile};

/// Re-decode a `DecodedInsn` back to a full iced [`Instruction`] from its
/// captured bytes, for operand-level detail the neutral `DecodedInsn`
/// intentionally omits. Mirrors `x64::decode_raw` (kept separate: that one is
/// private to `x64.rs`, and duplicating a 6-line decode is cheaper than
/// threading visibility through a third module).
fn decode_raw(insn: &DecodedInsn, bitness: u32) -> Option<Instruction> {
    let mut decoder = Decoder::with_ip(bitness, &insn.bytes, insn.va.0, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return None;
    }
    let instr = decoder.decode();
    if instr.is_invalid() { None } else { Some(instr) }
}

fn reg_name(r: Register) -> String {
    if r == Register::None {
        return String::new();
    }
    format!("{:?}", r.full_register()).to_lowercase()
}

fn mem_bits_signed(size: MemorySize) -> (Bits, bool) {
    use MemorySize as MS;
    match size {
        MS::Int8 => (8, true),
        MS::UInt8 => (8, false),
        MS::Int16 => (16, true),
        MS::UInt16 => (16, false),
        MS::Int32 => (32, true),
        MS::UInt32 => (32, false),
        MS::Int64 => (64, true),
        MS::UInt64 => (64, false),
        MS::Float32 => (32, false),
        MS::Float64 => (64, false),
        _ => (64, false),
    }
}

/// The effective-address expression of a `Memory`-kind operand: RIP-relative
/// folds to an absolute constant; otherwise `base + index*scale + disp`.
fn mem_addr_expr(instr: &Instruction) -> MicroExpr {
    if instr.is_ip_rel_memory_operand() {
        return MicroExpr::constant(instr.ip_rel_memory_address() as i128, 64);
    }
    let base = instr.memory_base();
    let index = instr.memory_index();
    let scale = instr.memory_index_scale();
    let disp = instr.memory_displacement64() as i64 as i128;

    let mut parts: Vec<MicroExpr> = Vec::new();
    if base != Register::None {
        parts.push(MicroExpr::var(reg_name(base)));
    }
    if index != Register::None {
        let idx = MicroExpr::var(reg_name(index));
        parts.push(if scale > 1 {
            MicroExpr::binary(BinOp::Mul, idx, MicroExpr::constant(scale as i128, 64))
        } else {
            idx
        });
    }
    if disp != 0 || parts.is_empty() {
        parts.push(MicroExpr::constant(disp, 64));
    }
    let mut it = parts.into_iter();
    let first = it.next().expect("at least the displacement is always pushed");
    it.fold(first, |acc, p| MicroExpr::binary(BinOp::Add, acc, p))
}

/// Read operand `idx` as an rvalue expression (register / immediate / memory
/// load / near-branch target).
fn read_operand(instr: &Instruction, idx: u32) -> MicroExpr {
    match instr.op_kind(idx) {
        OpKind::Register => MicroExpr::var(reg_name(instr.op_register(idx))),
        OpKind::Immediate8 => MicroExpr::constant(instr.immediate8() as i128, 8),
        OpKind::Immediate16 => MicroExpr::constant(instr.immediate16() as i128, 16),
        OpKind::Immediate32 => MicroExpr::constant(instr.immediate32() as i128, 32),
        OpKind::Immediate64 => MicroExpr::constant(instr.immediate64() as i128, 64),
        OpKind::Immediate8to16 => MicroExpr::constant(instr.immediate8to16() as i128, 16),
        OpKind::Immediate8to32 => MicroExpr::constant(instr.immediate8to32() as i128, 32),
        OpKind::Immediate8to64 => MicroExpr::constant(instr.immediate8to64() as i128, 64),
        OpKind::Immediate32to64 => MicroExpr::constant(instr.immediate32to64() as i128, 64),
        OpKind::Memory => {
            let (bits, signed) = mem_bits_signed(instr.memory_size());
            MicroExpr::load(mem_addr_expr(instr), bits, signed)
        }
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            MicroExpr::constant(instr.near_branch_target() as i128, 64)
        }
        _ => MicroExpr::Unknown(format!("op{idx}")),
    }
}

/// Name a vector register for the 128-bit SSE view the source used. `reg_name`
/// runs every register through `full_register()`, which widens `xmm6` to
/// `zmm6` — correct for the SSA-normalization of GPRs (`al`→`rax`) but
/// misleading here: a legacy `movaps`/`movdqu` only touches the low 128-bit
/// lane, so it should read as `xmm6`, not imply a full 512-bit `zmm6` write.
fn vector_reg_name(r: Register) -> String {
    reg_name(r).replacen("zmm", "xmm", 1)
}

/// One operand of a vector move as an rvalue: an xmm register var, or a load of
/// `bits` width from a memory operand. Unlike [`read_operand`], the memory
/// width comes from the move's own vector size (`memory_size()` reports
/// `Packed128_*`, which [`mem_bits_signed`] deliberately doesn't special-case),
/// so a 128-bit load is modelled as 128 bits rather than the scalar fallback.
fn vector_operand(instr: &Instruction, idx: u32, bits: Bits) -> MicroExpr {
    match instr.op_kind(idx) {
        OpKind::Register => MicroExpr::var(vector_reg_name(instr.op_register(idx))),
        OpKind::Memory => MicroExpr::load(mem_addr_expr(instr), bits, false),
        _ => MicroExpr::Unknown(format!("vop{idx}")),
    }
}

/// Lower a legacy 128-bit SSE **data move** (`movups`/`movupd`/`movaps`/
/// `movapd`/`movdqu`/`movdqa`) — the single largest source of `// asm:` fallout
/// in the corpus census, and pure data movement (no FP/packed *arithmetic*), so
/// modelling it as a load/store/copy is sound. The width is taken from the xmm
/// register operand (16 bytes → 128 bits); one operand is always an xmm
/// register in these forms, so the two sides agree on 128.
fn lift_vector_move(instr: &Instruction, out: &mut Vec<MicroStmt>) {
    if instr.op_count() < 2 {
        return;
    }
    let bits = (0..instr.op_count())
        .find(|&i| instr.op_kind(i) == OpKind::Register)
        .map(|i| (instr.op_register(i).size() as Bits) * 8)
        .unwrap_or(128);
    let src = vector_operand(instr, 1, bits);
    match instr.op_kind(0) {
        OpKind::Register => out.push(MicroStmt::Assign { dst: vector_reg_name(instr.op_register(0)), value: src }),
        OpKind::Memory => out.push(MicroStmt::Store { addr: mem_addr_expr(instr), value: src, bits }),
        _ => {}
    }
}

fn is_vector_reg(r: Register) -> bool {
    r.is_xmm() || r.is_ymm() || r.is_zmm()
}

/// Read operand `idx` naming a vector register by its `xmm` view (`read_operand`
/// would run it through `full_register()` and print `zmm`); everything else —
/// GPRs, immediates, memory — falls to the ordinary reader.
fn smart_read(instr: &Instruction, idx: u32) -> MicroExpr {
    if instr.op_kind(idx) == OpKind::Register && is_vector_reg(instr.op_register(idx)) {
        MicroExpr::var(vector_reg_name(instr.op_register(idx)))
    } else {
        read_operand(instr, idx)
    }
}

/// Write `value` to operand `idx`, vector-aware in the same way as
/// [`smart_read`].
fn smart_write(instr: &Instruction, idx: u32, value: MicroExpr, out: &mut Vec<MicroStmt>) {
    if instr.op_kind(idx) == OpKind::Register && is_vector_reg(instr.op_register(idx)) {
        out.push(MicroStmt::Assign { dst: vector_reg_name(instr.op_register(idx)), value });
    } else {
        write_operand(instr, idx, value, out);
    }
}

/// The intrinsic name for a mnemonic: `Tzcnt` → `__tzcnt`. Uses the mnemonic
/// itself so the name never drifts from what the instruction actually is.
fn mnemonic_intrinsic(m: Mnemonic) -> String {
    format!("__{}", format!("{m:?}").to_lowercase())
}

/// `dst = __name(src)` — a one-operand-in intrinsic (`op0` written, `op1` read).
fn intr_unary(instr: &Instruction, name: &str, out: &mut Vec<MicroStmt>) {
    let src = smart_read(instr, 1);
    smart_write(instr, 0, MicroExpr::intrinsic(name, vec![src]), out);
}

/// `dst = __name(dst, src)` — a read-modify intrinsic (`op0` read *and* written,
/// `op1` read), the shape of the packed-compare and scalar-FP-arithmetic ops.
fn intr_binary(instr: &Instruction, name: &str, out: &mut Vec<MicroStmt>) {
    let dst = smart_read(instr, 0);
    let src = smart_read(instr, 1);
    smart_write(instr, 0, MicroExpr::intrinsic(name, vec![dst, src]), out);
}

/// Sign-extend the accumulator's low `from` bits to `to` bits in place — the
/// `cbw`/`cwde`/`cdqe` family. The inner cast reinterprets the low bits, the
/// outer sign-extends, so it renders as `(int64_t)(int32_t)rax`.
fn sext_acc(from: Bits, to: Bits, out: &mut Vec<MicroStmt>) {
    let low = MicroExpr::Cast { signed: true, bits: from, expr: Box::new(MicroExpr::var("rax")) };
    let value = MicroExpr::Cast { signed: true, bits: to, expr: Box::new(low) };
    out.push(MicroStmt::Assign { dst: "rax".to_string(), value });
}

/// A BMI2 flag-less shift (`shlx`/`shrx`/`sarx`): `op0 = op1 <shift> op2`, with
/// no flag side effect (unlike the legacy `shl`/`shr`).
fn bmi_shift(instr: &Instruction, op: BinOp, out: &mut Vec<MicroStmt>) {
    let src = read_operand(instr, 1);
    let count = read_operand(instr, 2);
    write_operand(instr, 0, MicroExpr::binary(op, src, count), out);
}

/// `dst @= src` for an SSE *bitwise* op — bitwise operations don't cross lanes,
/// so a packed `pxor`/`por`/`pand` is exactly a 128-bit scalar bit-op and needs
/// no intrinsic. Sound and precise.
fn sse_binop(instr: &Instruction, op: BinOp, out: &mut Vec<MicroStmt>) {
    let dst = smart_read(instr, 0);
    let src = smart_read(instr, 1);
    smart_write(instr, 0, MicroExpr::binary(op, dst, src), out);
}

fn op_bits(instr: &Instruction, idx: u32) -> Bits {
    match instr.op_kind(idx) {
        OpKind::Register => (instr.op_register(idx).size() * 8) as Bits,
        OpKind::Memory => mem_bits_signed(instr.memory_size()).0,
        _ => 32,
    }
}

/// Write `value` to operand `idx` — a register `Assign` or a memory `Store`.
fn write_operand(instr: &Instruction, idx: u32, value: MicroExpr, out: &mut Vec<MicroStmt>) {
    match instr.op_kind(idx) {
        OpKind::Register => out.push(MicroStmt::Assign { dst: reg_name(instr.op_register(idx)), value }),
        OpKind::Memory => {
            let (bits, _signed) = mem_bits_signed(instr.memory_size());
            out.push(MicroStmt::Store { addr: mem_addr_expr(instr), value, bits });
        }
        _ => {}
    }
}

fn opaque_flags(mnemonic: Mnemonic) -> MicroStmt {
    MicroStmt::Assign {
        dst: FLAGS_VAR.to_string(),
        value: MicroExpr::OpaqueFlags { mnemonic: format!("{mnemonic:?}").to_lowercase() },
    }
}

fn compare_flags(kind: CmpKind, lhs: MicroExpr, rhs: MicroExpr) -> MicroStmt {
    MicroStmt::Assign { dst: FLAGS_VAR.to_string(), value: MicroExpr::compare(kind, lhs, rhs) }
}

/// Flags left by a result-producing op (`add`/`sub`/`dec`/`and`/…). The zero
/// flag is a pure function of the written result, so a 32- or 64-bit
/// **register** destination lets `branch_condition` reconstruct an equality
/// branch — `dec ecx; jne` becomes `ecx != 0`, the common loop-latch idiom
/// that previously rendered `/*cond(jne)*/`. Guarded to 32/64-bit register
/// destinations on purpose:
/// - a 32- or 64-bit register write zeroes the rest of the 64-bit register on
///   x64, so the full register's zero-ness *is* the result's zero-ness;
/// - an 8/16-bit destination leaves the upper bits intact (`dec cl` doesn't
///   make `rcx == 0` mean `cl == 0`), and a memory destination isn't a plain
///   `Var` to re-read — both stay `opaque_flags`, which is sound (an
///   unreconstructable condition, never a wrong one).
///
/// The flags statement is emitted *after* the result write, so its re-read of
/// the destination resolves — under SSA's statement ordering — to the written
/// result, exactly the value whose zero-ness the branch tests.
fn result_flags(instr: &Instruction, mn: Mnemonic, out: &mut Vec<MicroStmt>) {
    if instr.op0_kind() == OpKind::Register {
        let bits = op_bits(instr, 0);
        if bits == 32 || bits == 64 {
            let result = read_operand(instr, 0);
            // A logical op (`and`/`or`/`xor`) clears OF and CF, so its result
            // reconstructs the full `jcc` family (LogicalResult); an arithmetic
            // op's signed/carry branches need the real flags (Result).
            let kind = if matches!(mn, Mnemonic::And | Mnemonic::Or | Mnemonic::Xor) { CmpKind::LogicalResult } else { CmpKind::Result };
            out.push(compare_flags(kind, result, MicroExpr::constant(0, bits)));
            return;
        }
    }
    out.push(opaque_flags(mn));
}

/// A read-modify-write binary op: `dst @= src` where `dst` is operand 0
/// (register or memory, read *and* written) and `src` is operand 1.
fn binary_rmw(instr: &Instruction, op: BinOp, out: &mut Vec<MicroStmt>) {
    if instr.op_count() < 2 {
        return;
    }
    let lhs = read_operand(instr, 0);
    let rhs = read_operand(instr, 1);
    write_operand(instr, 0, MicroExpr::binary(op, lhs, rhs), out);
}

/// Map a `setcc` mnemonic to the equivalent `jcc` string that
/// [`branch_condition`] understands. The condition codes are identical — only
/// the opcode family differs (`sete`↔`je`, `setb`↔`jb`, …) — so a `setcc` can
/// reuse the exact branch-condition reconstruction, evaluated against the same
/// reaching flags. `None` for anything that isn't a conditional-set (matched
/// explicitly so unrelated `set*` opcodes like the CET `setssbsy` never slip
/// in).
pub(crate) fn setcc_jcc(m: Mnemonic) -> Option<&'static str> {
    use Mnemonic as M;
    Some(match m {
        M::Sete => "je",
        M::Setne => "jne",
        M::Seta => "ja",
        M::Setae => "jae",
        M::Setb => "jb",
        M::Setbe => "jbe",
        M::Setg => "jg",
        M::Setge => "jge",
        M::Setl => "jl",
        M::Setle => "jle",
        M::Sets => "js",
        M::Setns => "jns",
        M::Seto => "jo",
        M::Setno => "jno",
        M::Setp => "jp",
        M::Setnp => "jnp",
        _ => return None,
    })
}

/// Map a `cmovcc` mnemonic to the equivalent `jcc` string, on the same
/// principle as [`setcc_jcc`] — the condition code is identical, only the
/// opcode family differs (`cmovb`↔`jb`). `None` for a non-conditional-move.
pub(crate) fn cmovcc_jcc(m: Mnemonic) -> Option<&'static str> {
    use Mnemonic as M;
    Some(match m {
        M::Cmove => "je",
        M::Cmovne => "jne",
        M::Cmova => "ja",
        M::Cmovae => "jae",
        M::Cmovb => "jb",
        M::Cmovbe => "jbe",
        M::Cmovg => "jg",
        M::Cmovge => "jge",
        M::Cmovl => "jl",
        M::Cmovle => "jle",
        M::Cmovs => "js",
        M::Cmovns => "jns",
        M::Cmovo => "jo",
        M::Cmovno => "jno",
        M::Cmovp => "jp",
        M::Cmovnp => "jnp",
        _ => return None,
    })
}

pub(crate) fn is_jcc(m: Mnemonic) -> bool {
    use Mnemonic as M;
    matches!(
        m,
        M::Ja | M::Jae
            | M::Jb
            | M::Jbe
            | M::Je
            | M::Jne
            | M::Jg
            | M::Jge
            | M::Jl
            | M::Jle
            | M::Js
            | M::Jns
            | M::Jo
            | M::Jno
            | M::Jp
            | M::Jnp
            | M::Jcxz
            | M::Jecxz
            | M::Jrcxz
    )
}

/// Registers a call may clobber per the Win64 ABI (`cc.volatile`), minus
/// `rax` (the call's own `ret` slot already assigns it precisely). Each gets
/// an `Unknown` def so a later read can't silently reuse the *pre-call*
/// value — a correctness gap the v0 template renderer had (it never modeled
/// interprocedural clobber at all).
fn call_clobbers(regs: &RegisterFile, cc: &CallConv) -> Vec<String> {
    cc.volatile
        .iter()
        .filter(|&&r| r != x64reg::RAX)
        .filter_map(|&r| regs.name(r))
        .map(str::to_string)
        .collect()
}

/// The forwarded argument expressions of a call: the convention's integer
/// argument registers, in order. Taken from [`CallConv`] rather than spelled
/// out inline so a second x64 convention (SysV) needs no edit here. Arity is
/// *not* narrowed at this stage — `TypeInferPass` recovers how many are real.
fn call_args(regs: &RegisterFile, cc: &CallConv) -> Vec<MicroExpr> {
    cc.int_args.iter().filter_map(|&r| regs.name(r)).map(MicroExpr::var).collect()
}

/// The convention's integer return register (`rax` on Win64).
fn ret_reg(regs: &RegisterFile, cc: &CallConv) -> String {
    regs.name(cc.ret).unwrap_or("rax").to_string()
}

/// Pick the [`CallConv`] whose name matches the source `abi` (e.g. `"sysv"`
/// for an ELF, `"win64"` for a PE), falling back to the arch's first/native
/// convention when the name is unknown. This is what makes a `call`'s argument
/// registers *and* its caller-saved clobber set follow the target's ABI rather
/// than always assuming Win64 — on System V that both forwards the right
/// registers (`rdi, rsi, …`) and, crucially, invalidates `rsi`/`rdi` across the
/// call (they are caller-saved there but callee-saved on Win64), so a later read
/// can't unsoundly reuse a pre-call value.
fn cc_for<'a>(arch: &'a crate::X64, abi: &str) -> &'a CallConv {
    let ccs = arch.calling_conventions();
    ccs.iter().find(|c| c.name == abi).unwrap_or(&ccs[0])
}

/// The callee expression of a call-like instruction: a direct near-branch
/// operand, else the RIP-relative memory operand (the IAT-slot shape of both
/// `call qword ptr [rip+disp]` and an import thunk's `jmp qword ptr
/// [rip+disp]`), else whatever the first operand reads. Shared by `call` and
/// by [`lift_tail_call`] — the two differ in what happens *after* the call,
/// never in how the callee is addressed.
fn call_target(instr: &Instruction, insn: &DecodedInsn) -> CallTarget {
    match insn.target {
        Some(va) => CallTarget::Direct { va },
        None => match insn.rip_target {
            Some(slot) => CallTarget::Indirect(Box::new(MicroExpr::load(
                MicroExpr::constant(slot.0 as i128, 64),
                64,
                false,
            ))),
            None => CallTarget::Indirect(Box::new(read_operand(instr, 0))),
        },
    }
}

/// Lower a **tail call** — a `jmp` the CFG determined leaves this function
/// (ROADMAP Phase 10, priority 0: "recognize `jmp func` as call+return").
/// Semantically it is `return f(args)`: the callee runs on this frame and its
/// result *is* this function's result. `lift` cannot see that — it is handed
/// one instruction, not the function bounds — so [`crate::Arch::lift_tail_call`]
/// is a separate entry point the core calls only for a block whose terminator
/// is `tail-call`.
///
/// No clobber invalidation and no flags statement follow the call here (as
/// they do for an ordinary call): control returns to *this function's* caller,
/// so nothing in this frame can observe a clobbered register afterwards.
pub(crate) fn lift_tail_call(arch: &crate::X64, insn: &DecodedInsn, abi: &str) -> Vec<MicroStmt> {
    let Some(instr) = decode_raw(insn, arch.bitness()) else {
        return vec![MicroStmt::Unlifted { va: insn.va, text: insn.text.clone() }];
    };
    let cc = cc_for(arch, abi);
    let ret = ret_reg(arch.regs(), cc);
    vec![
        MicroStmt::Call {
            target: call_target(&instr, insn),
            args: call_args(arch.regs(), cc),
            ret: Some(ret.clone()),
        },
        MicroStmt::Return(Some(MicroExpr::var(ret))),
    ]
}

pub(crate) fn lift(arch: &crate::X64, insn: &DecodedInsn, abi: &str) -> Vec<MicroStmt> {
    let Some(instr) = decode_raw(insn, arch.bitness()) else {
        return vec![MicroStmt::Unlifted { va: insn.va, text: insn.text.clone() }];
    };
    let mut out: Vec<MicroStmt> = Vec::new();
    let mn = instr.mnemonic();

    match mn {
        Mnemonic::Mov => {
            let v = read_operand(&instr, 1);
            write_operand(&instr, 0, v, &mut out);
        }
        // The same packed data move in its VEX/EVEX spelling, plus the
        // non-temporal variants — all of them still pure movement, and together
        // the largest single block of `// asm:` fallout left on an AVX build
        // (`vmovdqa`/`vmovdqu` alone were 3 687 of 14 268 nodes over 1 460 Qt
        // methods). A **masked** EVEX form is deliberately excluded below: with
        // a `{k}` operand the move is conditional per element, and modelling it
        // as an unconditional one would be a confident lie about which bytes
        // changed.
        Mnemonic::Vmovups
        | Mnemonic::Vmovupd
        | Mnemonic::Vmovaps
        | Mnemonic::Vmovapd
        | Mnemonic::Vmovdqu
        | Mnemonic::Vmovdqa
        | Mnemonic::Vmovdqa32
        | Mnemonic::Vmovdqa64
        | Mnemonic::Vmovdqu8
        | Mnemonic::Vmovdqu16
        | Mnemonic::Vmovdqu32
        | Mnemonic::Vmovdqu64
        | Mnemonic::Vmovntdq
        | Mnemonic::Vmovntdqa
        | Mnemonic::Vmovntps
        | Mnemonic::Vmovntpd
        | Mnemonic::Movntdq
        | Mnemonic::Movntdqa
        | Mnemonic::Movntps
            if instr.op_mask() == Register::None =>
        {
            lift_vector_move(&instr, &mut out);
        }
        Mnemonic::Movups | Mnemonic::Movupd | Mnemonic::Movaps | Mnemonic::Movapd | Mnemonic::Movdqu | Mnemonic::Movdqa => {
            lift_vector_move(&instr, &mut out);
        }
        Mnemonic::Movzx => {
            let bits = op_bits(&instr, 0);
            let v = read_operand(&instr, 1);
            write_operand(&instr, 0, MicroExpr::Cast { signed: false, bits, expr: Box::new(v) }, &mut out);
        }
        Mnemonic::Movsx | Mnemonic::Movsxd => {
            let bits = op_bits(&instr, 0);
            let v = read_operand(&instr, 1);
            write_operand(&instr, 0, MicroExpr::Cast { signed: true, bits, expr: Box::new(v) }, &mut out);
        }
        Mnemonic::Lea => {
            let addr = mem_addr_expr(&instr);
            write_operand(&instr, 0, MicroExpr::AddrOf(Box::new(addr)), &mut out);
        }
        Mnemonic::Add => {
            binary_rmw(&instr, BinOp::Add, &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Sub => {
            binary_rmw(&instr, BinOp::Sub, &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Adc => {
            binary_rmw(&instr, BinOp::Add, &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Sbb => {
            binary_rmw(&instr, BinOp::Sub, &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::And => {
            binary_rmw(&instr, BinOp::And, &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Or => {
            binary_rmw(&instr, BinOp::Or, &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Xor => {
            // `xor reg, reg` zeroing idiom — the value is exactly 0 even
            // though we still don't model the flags precisely.
            if instr.op0_kind() == OpKind::Register
                && instr.op1_kind() == OpKind::Register
                && instr.op0_register().full_register() == instr.op1_register().full_register()
            {
                let bits = op_bits(&instr, 0);
                write_operand(&instr, 0, MicroExpr::constant(0, bits), &mut out);
            } else {
                binary_rmw(&instr, BinOp::Xor, &mut out);
            }
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Shl | Mnemonic::Sal => {
            binary_rmw(&instr, BinOp::Shl, &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Shr => {
            binary_rmw(&instr, BinOp::Shr, &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Sar => {
            binary_rmw(&instr, BinOp::Sar, &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Inc => {
            let bits = op_bits(&instr, 0);
            let cur = read_operand(&instr, 0);
            write_operand(&instr, 0, MicroExpr::binary(BinOp::Add, cur, MicroExpr::constant(1, bits)), &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Dec => {
            let bits = op_bits(&instr, 0);
            let cur = read_operand(&instr, 0);
            write_operand(&instr, 0, MicroExpr::binary(BinOp::Sub, cur, MicroExpr::constant(1, bits)), &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Neg => {
            let cur = read_operand(&instr, 0);
            write_operand(&instr, 0, MicroExpr::unary(UnOp::Neg, cur), &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Not => {
            let cur = read_operand(&instr, 0);
            write_operand(&instr, 0, MicroExpr::unary(UnOp::Not, cur), &mut out);
            // `not` does not touch the flags.
        }
        Mnemonic::Imul | Mnemonic::Mul if instr.op_count() >= 2 => {
            // 2-operand `imul dst, src` (dst @= src) or 3-operand
            // `imul dst, src1, src2`; the 1-operand implicit-rax:rdx form
            // falls through to the generic unhandled path below.
            let (lhs, rhs) = if instr.op_count() >= 3 {
                (read_operand(&instr, 1), read_operand(&instr, 2))
            } else {
                (read_operand(&instr, 0), read_operand(&instr, 1))
            };
            write_operand(&instr, 0, MicroExpr::binary(BinOp::Mul, lhs, rhs), &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Test => {
            let lhs = read_operand(&instr, 0);
            let rhs = read_operand(&instr, 1);
            out.push(compare_flags(CmpKind::Test, lhs, rhs));
        }
        Mnemonic::Cmp => {
            let lhs = read_operand(&instr, 0);
            let rhs = read_operand(&instr, 1);
            out.push(compare_flags(CmpKind::Cmp, lhs, rhs));
        }
        Mnemonic::Push | Mnemonic::Pop | Mnemonic::Nop => {
            // Stack-pointer effects aren't modeled in Phase 3 (no memory-SSA
            // for the stack yet); nothing to assign.
        }
        Mnemonic::Ret | Mnemonic::Retf => {
            out.push(MicroStmt::Return(Some(MicroExpr::var("rax"))));
        }
        Mnemonic::Call => {
            let cc = cc_for(arch, abi);
            out.push(MicroStmt::Call {
                target: call_target(&instr, insn),
                args: call_args(arch.regs(), cc),
                ret: Some(ret_reg(arch.regs(), cc)),
            });
            for clobbered in call_clobbers(arch.regs(), cc) {
                out.push(MicroStmt::Assign {
                    dst: clobbered,
                    value: MicroExpr::Unknown("call-clobbered".to_string()),
                });
            }
            out.push(opaque_flags(mn));
        }
        Mnemonic::Jmp => {
            // Structural: the CFG already carries the direct/tail/indirect
            // edge (`CfgArtifact::blocks[..].successors` / `.callsites`); no
            // dataflow statement needed here.
        }
        m if is_jcc(m) => {
            // Structural: the condition is synthesized by `branch_condition`
            // from whatever SSA value of `FLAGS_VAR` reaches this point, not
            // lifted eagerly here.
        }
        m if setcc_jcc(m).is_some() => {
            // `setcc dst` writes 0/1 from a condition code. The value depends on
            // the *reaching* flags — known only after SSA — so it is emitted as a
            // `setcc:<jcc>` marker the SSA builder resolves through
            // `branch_condition`, exactly as it resolves a `cjmp` terminator (see
            // `n0xis-core::ssa`). Left as a marker here, never guessed.
            let jcc = setcc_jcc(m).expect("guarded by the arm pattern");
            write_operand(&instr, 0, MicroExpr::OpaqueFlags { mnemonic: format!("setcc:{jcc}") }, &mut out);
        }
        m if cmovcc_jcc(m).is_some() => {
            // `cmovcc dst, src` is `dst = cond ? src : dst` — a conditional
            // select, not a branch. The condition rides in the `Select` as a
            // `setcc:<jcc>` marker the SSA builder resolves from the reaching
            // flags (same path as `setcc`); `a` is the source, `b` is the
            // current destination (the value kept when the condition is false).
            let jcc = cmovcc_jcc(m).expect("guarded by the arm pattern");
            let cond = MicroExpr::OpaqueFlags { mnemonic: format!("setcc:{jcc}") };
            let src = read_operand(&instr, 1);
            let keep = read_operand(&instr, 0);
            write_operand(&instr, 0, MicroExpr::select(cond, src, keep), &mut out);
        }
        // Bit scan / population count: `dst = __f(src)`, and each sets flags
        // (ZF at least), so keep an opaque flag write after.
        Mnemonic::Tzcnt | Mnemonic::Lzcnt | Mnemonic::Popcnt | Mnemonic::Bsf | Mnemonic::Bsr => {
            intr_unary(&instr, &mnemonic_intrinsic(mn), &mut out);
            out.push(opaque_flags(mn));
        }
        // Byte swap is one operand, read and written in place, and touches no flags.
        Mnemonic::Bswap => {
            let src = smart_read(&instr, 0);
            smart_write(&instr, 0, MicroExpr::intrinsic("__bswap", vec![src]), &mut out);
        }
        // SSE *bitwise* ops are exact 128-bit bit-operations (no intrinsic).
        Mnemonic::Pxor | Mnemonic::Xorps | Mnemonic::Xorpd => sse_binop(&instr, BinOp::Xor, &mut out),
        Mnemonic::Por | Mnemonic::Orps | Mnemonic::Orpd => sse_binop(&instr, BinOp::Or, &mut out),
        Mnemonic::Pand | Mnemonic::Andps | Mnemonic::Andpd => sse_binop(&instr, BinOp::And, &mut out),
        Mnemonic::Pandn | Mnemonic::Andnps | Mnemonic::Andnpd => {
            // `pandn dst, src` = (~dst) & src (same for the float-typed forms —
            // bitwise is bitwise regardless of the lane type).
            let dst = smart_read(&instr, 0);
            let src = smart_read(&instr, 1);
            smart_write(&instr, 0, MicroExpr::binary(BinOp::And, MicroExpr::unary(UnOp::Not, dst), src), &mut out);
        }
        // SSE packed compare (produces a mask) and the byte-mask extract — the
        // core of the SSE2 string-scan idioms — as named intrinsics.
        Mnemonic::Pmovmskb => intr_unary(&instr, "__pmovmskb", &mut out),
        Mnemonic::Pcmpeqb
        | Mnemonic::Pcmpgtb
        | Mnemonic::Pcmpeqw
        | Mnemonic::Pcmpgtw
        | Mnemonic::Pcmpeqd
        | Mnemonic::Pcmpgtd => intr_binary(&instr, &mnemonic_intrinsic(mn), &mut out),
        // Scalar/packed FP arithmetic — the IR has no float type, so these read
        // as named intrinsics over their operands (`__addsd(x, y)`), which is
        // honest and keeps the dataflow intact.
        Mnemonic::Addsd
        | Mnemonic::Subsd
        | Mnemonic::Mulsd
        | Mnemonic::Divsd
        | Mnemonic::Minsd
        | Mnemonic::Maxsd
        | Mnemonic::Addss
        | Mnemonic::Subss
        | Mnemonic::Mulss
        | Mnemonic::Divss
        | Mnemonic::Minss
        | Mnemonic::Maxss
        // packed forms — same shape, one intrinsic per instruction.
        | Mnemonic::Addpd
        | Mnemonic::Subpd
        | Mnemonic::Mulpd
        | Mnemonic::Divpd
        | Mnemonic::Minpd
        | Mnemonic::Maxpd
        | Mnemonic::Addps
        | Mnemonic::Subps
        | Mnemonic::Mulps
        | Mnemonic::Divps
        | Mnemonic::Minps
        | Mnemonic::Maxps
        // pack/unpack/shuffle permutes — a value out of the two register
        // operands; the shuffle-control immediate (when present) is a permute
        // detail the dataflow doesn't need.
        | Mnemonic::Punpcklqdq
        | Mnemonic::Punpckhqdq
        | Mnemonic::Punpckldq
        | Mnemonic::Punpckhdq
        | Mnemonic::Punpcklbw
        | Mnemonic::Punpcklwd
        | Mnemonic::Unpcklpd
        | Mnemonic::Unpckhpd
        | Mnemonic::Unpcklps
        | Mnemonic::Unpckhps
        | Mnemonic::Shufps
        | Mnemonic::Shufpd => intr_binary(&instr, &mnemonic_intrinsic(mn), &mut out),
        Mnemonic::Sqrtsd | Mnemonic::Sqrtss => intr_unary(&instr, &mnemonic_intrinsic(mn), &mut out),
        // Int↔FP conversions (scalar and packed): `dst = __cvt*(src)`.
        Mnemonic::Cvtsi2sd
        | Mnemonic::Cvtsi2ss
        | Mnemonic::Cvtsd2si
        | Mnemonic::Cvtss2si
        | Mnemonic::Cvttsd2si
        | Mnemonic::Cvttss2si
        | Mnemonic::Cvtsd2ss
        | Mnemonic::Cvtss2sd
        | Mnemonic::Cvtps2pd
        | Mnemonic::Cvtpd2ps
        | Mnemonic::Cvtdq2ps
        | Mnemonic::Cvtps2dq
        | Mnemonic::Cvttps2dq
        | Mnemonic::Cvtdq2pd
        | Mnemonic::Cvtpd2dq
        | Mnemonic::Cvttpd2dq => intr_unary(&instr, &mnemonic_intrinsic(mn), &mut out),
        // Scalar / cross-domain moves (`movss`/`movsd`/`movd`/`movq`). Only lift
        // when a vector register is actually involved — that disambiguates the
        // SSE scalar `movsd` from the string `movsd`, which has no xmm operand
        // and must stay opaque.
        Mnemonic::Movss
        | Mnemonic::Movsd
        | Mnemonic::Movd
        | Mnemonic::Movq
        | Mnemonic::Vmovss
        | Mnemonic::Vmovsd
        | Mnemonic::Vmovd
        | Mnemonic::Vmovq
            if instr.op_mask() == Register::None =>
        {
            let vector = (0..instr.op_count())
                .any(|i| instr.op_kind(i) == OpKind::Register && is_vector_reg(instr.op_register(i)));
            if !vector {
                // The string `movsd` — no xmm operand, entirely different
                // instruction — must stay opaque.
                lift_opaque(arch, insn, mn, &mut out);
            } else if instr.op_count() == 3 {
                // The VEX *merge* form `vmovsd xmm0, xmm1, xmm2`: the result is
                // the scalar from `op2` over the upper lanes of `op1`. This model
                // gives a vector register one name and no lanes, so it cannot
                // express that merge — an intrinsic states the dependency on both
                // sources without claiming the value is either one of them.
                let hi = smart_read(&instr, 1);
                let lo = smart_read(&instr, 2);
                smart_write(&instr, 0, MicroExpr::intrinsic(mnemonic_intrinsic(mn), vec![hi, lo]), &mut out);
            } else {
                let src = smart_read(&instr, 1);
                smart_write(&instr, 0, src, &mut out);
            }
        }
        // Instructions with no effect this model can observe. `endbr64` is a CET
        // landing pad — architecturally a `nop`. `vzeroupper`/`vzeroall` clear
        // the lanes *above* 128 bits, which this model does not represent at all
        // (a vector register is one SSA name, no lanes), so there is nothing for
        // them to clear here. Together they were 2 101 of 14 268 `// asm:` nodes
        // over 1 460 Qt methods — pure noise in the output, hiding the rest.
        Mnemonic::Endbr64 | Mnemonic::Endbr32 | Mnemonic::Vzeroupper | Mnemonic::Vzeroall => {
            out.push(MicroStmt::Nop);
        }
        // A trap: it produces no value and does not return. Emit a no-result
        // intrinsic call so it reads as `__ud2();` instead of a raw `// asm:`.
        Mnemonic::Ud2 | Mnemonic::Int3 => {
            out.push(MicroStmt::Call { target: CallTarget::Intrinsic(mnemonic_intrinsic(mn)), args: vec![], ret: None });
        }
        // 1-operand unsigned multiply: `rdx:rax = rax * src`. The low half is a
        // plain product; the high half is the `__umulh` intrinsic. Both read the
        // pre-multiply `rax`, so the high write is emitted first. Only the 32/64-
        // bit forms (which really target rdx:rax) are lifted.
        Mnemonic::Mul if op_bits(&instr, 0) >= 32 => {
            let src = read_operand(&instr, 0);
            let rax = MicroExpr::var("rax");
            out.push(MicroStmt::Assign { dst: "rdx".into(), value: MicroExpr::intrinsic("__umulh", vec![rax.clone(), src.clone()]) });
            out.push(MicroStmt::Assign { dst: "rax".into(), value: MicroExpr::binary(BinOp::Mul, rax, src) });
            out.push(opaque_flags(mn));
        }
        // Sign-extend the accumulator in place (`cbw`/`cwde`/`cdqe`): the low
        // `from` bits, sign-extended to `to`. Reads as `(int64_t)(int32_t)rax`.
        Mnemonic::Cbw => sext_acc(8, 16, &mut out),
        Mnemonic::Cwde => sext_acc(16, 32, &mut out),
        Mnemonic::Cdqe => sext_acc(32, 64, &mut out),
        // Sign-extend rax into rdx (`cdq`/`cqo`) — the `rdx:rax` dividend setup.
        Mnemonic::Cdq | Mnemonic::Cqo => {
            out.push(MicroStmt::Assign { dst: "rdx".into(), value: MicroExpr::intrinsic(mnemonic_intrinsic(mn), vec![MicroExpr::var("rax")]) });
        }
        // BMI2 flag-less shifts (`shlx`/`shrx`/`sarx`): `dst = src <shift> count`,
        // three operands and — the whole point of the BMI2 forms — no flag write.
        Mnemonic::Shlx => bmi_shift(&instr, BinOp::Shl, &mut out),
        Mnemonic::Shrx => bmi_shift(&instr, BinOp::Shr, &mut out),
        Mnemonic::Sarx => bmi_shift(&instr, BinOp::Sar, &mut out),
        // BMI2 `bzhi dst, src, index` — zero `src`'s bits from `index` up. The
        // mask is index-dependent, so it reads as an intrinsic; sets flags.
        Mnemonic::Bzhi => {
            let src = read_operand(&instr, 1);
            let index = read_operand(&instr, 2);
            write_operand(&instr, 0, MicroExpr::intrinsic("__bzhi", vec![src, index]), &mut out);
            out.push(opaque_flags(mn));
        }
        // BMI2 `mulx hi, lo, src` — `hi:lo = src * rdx` (implicit `rdx`), no
        // flags. Low half is the product, high half `__umulh`; the high write is
        // emitted first so both read the pre-multiply `rdx`.
        Mnemonic::Mulx => {
            let src = read_operand(&instr, 2);
            let rdx = MicroExpr::var("rdx");
            write_operand(&instr, 0, MicroExpr::intrinsic("__umulh", vec![rdx.clone(), src.clone()]), &mut out);
            write_operand(&instr, 1, MicroExpr::binary(BinOp::Mul, rdx, src), &mut out);
        }
        // Bit test-and-reset/set/complement, immediate index: the value change is
        // exact (`dst &= ~(1<<n)` / `|=` / `^=`); the CF it also sets (the old
        // bit) stays opaque. A register index falls through to the opaque path.
        Mnemonic::Btr | Mnemonic::Bts | Mnemonic::Btc if instr.op1_kind() == OpKind::Immediate8 => {
            let bits = op_bits(&instr, 0);
            let n = (instr.immediate8() as u32) & bits.saturating_sub(1);
            let mask = MicroExpr::constant(1i128 << n, bits);
            let dst = read_operand(&instr, 0);
            let value = match mn {
                Mnemonic::Btr => MicroExpr::binary(BinOp::And, dst, MicroExpr::unary(UnOp::Not, mask)),
                Mnemonic::Bts => MicroExpr::binary(BinOp::Or, dst, mask),
                _ => MicroExpr::binary(BinOp::Xor, dst, mask),
            };
            write_operand(&instr, 0, value, &mut out);
            out.push(opaque_flags(mn));
        }
        Mnemonic::Rol | Mnemonic::Ror => {
            // A rotate by an **immediate** is exact as a shift/shift/or, which is
            // also the shape a reverse-engineer recognizes (hash/PRNG code is
            // full of them — making them visible feeds `const identify`). Only
            // the immediate, 32/64-bit form is lifted: a `CL`-count rotate would
            // need the x86 count-masking modelled to stay sound, so it falls
            // through to the opaque path instead of guessing.
            let width = op_bits(&instr, 0);
            let n = (instr.immediate8() as u32) & width.saturating_sub(1);
            if instr.op1_kind() == OpKind::Immediate8 && (width == 32 || width == 64) && n != 0 {
                // `rol n` = (x << n) | (x >> (w-n)); `ror n` swaps the two shift
                // *directions* — note each direction keeps its own amount, so
                // the two forms are not a mere reordering of the same shifts.
                let shift = |op, amount: u32| MicroExpr::binary(op, read_operand(&instr, 0), MicroExpr::constant(amount as i128, width));
                let value = match mn {
                    Mnemonic::Rol => MicroExpr::binary(BinOp::Or, shift(BinOp::Shl, n), shift(BinOp::Shr, width - n)),
                    _ => MicroExpr::binary(BinOp::Or, shift(BinOp::Shr, n), shift(BinOp::Shl, width - n)),
                };
                write_operand(&instr, 0, value, &mut out);
                out.push(opaque_flags(mn));
            } else {
                lift_opaque(arch, insn, mn, &mut out);
            }
        }
        _ => lift_opaque(arch, insn, mn, &mut out),
    }

    out
}

/// Unrecognized (or deliberately unmodelled) instruction: preserve it verbatim
/// (never silently drop semantics — CONCEPT §3 rule 6), *and* soundly
/// invalidate everything it might have written, using the arch's own
/// register-access info so a later read can't reuse a stale SSA value across an
/// instruction we don't understand.
fn lift_opaque(arch: &crate::X64, insn: &DecodedInsn, mn: Mnemonic, out: &mut Vec<MicroStmt>) {
    out.push(MicroStmt::Unlifted { va: insn.va, text: insn.text.clone() });
    for w in &arch.reg_access(insn).writes {
        out.push(MicroStmt::Assign { dst: w.clone(), value: MicroExpr::Unknown(insn.text.clone()) });
    }
    out.push(opaque_flags(mn));
}

/// The x64 condition-code table: which combination of `"flags"` each `Jcc`
/// tests, given the precise `Compare` that defined it. Only sound when the
/// dataflow value reaching the branch *is* a `Compare` (see module docs on
/// [`MicroExpr::OpaqueFlags`]).
/// The exact branch condition for a `jcc` whose flags came from a **logical**
/// operation (`test`/`and`/`or`/`xor`), where the value the flags reflect is
/// `val`. A logical op clears **OF and CF to 0**, so every condition collapses
/// to a sign/zero test on `val` and reconstructs soundly (unlike an arithmetic
/// result, whose signed/carry conditions need the real OF/CF):
///   - signed: `jl`→`val<0`, `jle`→`val<=0`, `jg`→`val>0`, `jge`→`val>=0`;
///   - unsigned (CF=0): `ja`→`val!=0`, `jbe`→`val==0`, `jae`→always, `jb`→never.
fn logical_flag_cond(mnemonic: &str, val: MicroExpr) -> MicroExpr {
    let zero = MicroExpr::constant(0, 64);
    let cmp = |op| MicroExpr::binary(op, val.clone(), zero.clone());
    match mnemonic {
        "je" | "jz" => cmp(BinOp::Eq),
        "jne" | "jnz" => cmp(BinOp::Ne),
        "js" => cmp(BinOp::Slt),
        "jns" => cmp(BinOp::Sge),
        "jl" | "jnge" => cmp(BinOp::Slt),
        "jle" | "jng" => cmp(BinOp::Sle),
        "jg" | "jnle" => cmp(BinOp::Sgt),
        "jge" | "jnl" => cmp(BinOp::Sge),
        "ja" | "jnbe" => cmp(BinOp::Ne),
        "jbe" | "jna" => cmp(BinOp::Eq),
        // CF is provably 0 after a logical op: `jae`/`jnb` always taken, `jb`/
        // `jnae` never. Sound constants (compiler artifacts / provable bounds).
        "jae" | "jnb" | "jnc" => MicroExpr::constant(1, 8),
        "jb" | "jnae" | "jc" => MicroExpr::constant(0, 8),
        _ => MicroExpr::Unknown(format!("cond({mnemonic})")),
    }
}

pub(crate) fn branch_condition(mnemonic: &str, flags_value: &MicroExpr) -> MicroExpr {
    let MicroExpr::Compare { kind, lhs, rhs } = flags_value else {
        return MicroExpr::Unknown(format!("cond({mnemonic})"));
    };
    let (lhs, rhs) = (lhs.as_ref().clone(), rhs.as_ref().clone());

    if *kind == CmpKind::Result {
        // Flags from a stored result (`dec ecx`, `sub rax,rbx`, `and edx,edx`):
        // `lhs` is the result, `rhs` is the constant 0. Only the zero flag is a
        // sound function of the result alone, so recover just the equality
        // branches; the sign/magnitude conditions need carry/overflow the
        // result doesn't carry and stay opaque (a missing condition, never a
        // wrong one).
        return match mnemonic {
            "je" => MicroExpr::binary(BinOp::Eq, lhs, rhs),
            "jne" => MicroExpr::binary(BinOp::Ne, lhs, rhs),
            // SF is literally the sign bit of the stored result — a pure function
            // of it, independent of the overflow the magnitude branches need — so
            // `js`/`jns` reconstruct even after arithmetic (`rhs` is the `0`).
            "js" => MicroExpr::binary(BinOp::Slt, lhs, rhs),
            "jns" => MicroExpr::binary(BinOp::Sge, lhs, rhs),
            _ => MicroExpr::Unknown(format!("cond({mnemonic}) after result")),
        };
    }

    if *kind == CmpKind::LogicalResult {
        // Flags from a logical op that kept its result (`and edx,edx`): OF=CF=0,
        // so the whole family reconstructs from the result's sign/zero-ness.
        return logical_flag_cond(mnemonic, lhs);
    }

    if *kind == CmpKind::Test {
        // `test a,b` sets flags from `a & b` (a *logical* op, so OF and CF are
        // cleared to 0) without storing it; `a,a` is the common "is a zero /
        // negative / <=0" idiom. Because OF=CF=0, every signed *and* unsigned
        // condition is a pure function of the tested value's sign and zero-ness
        // — so the whole `jcc` family reconstructs soundly, not just `je`/`jne`.
        let val = if lhs == rhs { lhs } else { MicroExpr::binary(BinOp::And, lhs, rhs) };
        return logical_flag_cond(mnemonic, val);
    }

    match mnemonic {
        "je" => MicroExpr::binary(BinOp::Eq, lhs, rhs),
        "jne" => MicroExpr::binary(BinOp::Ne, lhs, rhs),
        "ja" => MicroExpr::binary(BinOp::Ugt, lhs, rhs),
        "jae" => MicroExpr::binary(BinOp::Uge, lhs, rhs),
        "jb" => MicroExpr::binary(BinOp::Ult, lhs, rhs),
        "jbe" => MicroExpr::binary(BinOp::Ule, lhs, rhs),
        "jg" => MicroExpr::binary(BinOp::Sgt, lhs, rhs),
        "jge" => MicroExpr::binary(BinOp::Sge, lhs, rhs),
        "jl" => MicroExpr::binary(BinOp::Slt, lhs, rhs),
        "jle" => MicroExpr::binary(BinOp::Sle, lhs, rhs),
        "js" => MicroExpr::binary(BinOp::Slt, MicroExpr::binary(BinOp::Sub, lhs, rhs), MicroExpr::constant(0, 64)),
        "jns" => MicroExpr::binary(BinOp::Sge, MicroExpr::binary(BinOp::Sub, lhs, rhs), MicroExpr::constant(0, 64)),
        _ => MicroExpr::Unknown(format!("cond({mnemonic})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Arch, X64};
    use n0xis_contracts::Va;

    fn lift_one(bytes: &[u8]) -> Vec<MicroStmt> {
        let arch = X64::new();
        let insns = arch.decode_stream(bytes, Va(0x1000), 4);
        arch.lift(&insns[0], "win64")
    }

    /// The `flags = <expr>` value written by the last statement of a lifted
    /// instruction (every flag-touching instruction writes `FLAGS_VAR` last).
    fn last_flags(stmts: &[MicroStmt]) -> MicroExpr {
        match stmts.last() {
            Some(MicroStmt::Assign { dst, value }) if dst == FLAGS_VAR => value.clone(),
            other => panic!("expected a trailing flags assign, got {other:?}"),
        }
    }

    #[test]
    fn mov_lifts_to_a_plain_assign() {
        // mov rax, rcx
        let stmts = lift_one(&[0x48, 0x89, 0xC8]);
        assert_eq!(stmts, vec![MicroStmt::Assign { dst: "rax".into(), value: MicroExpr::var("rcx") }]);
    }

    #[test]
    fn an_sse_store_moves_128_bits_named_xmm_not_zmm() {
        // movups [rdi], xmm0  = 0F 11 07
        let stmts = lift_one(&[0x0F, 0x11, 0x07]);
        assert_eq!(
            stmts,
            vec![MicroStmt::Store {
                addr: MicroExpr::var("rdi"),
                value: MicroExpr::var("xmm0"),
                bits: 128,
            }],
            "a legacy SSE move is 128-bit data movement, and the register reads as the xmm view",
        );
    }

    #[test]
    fn an_sse_load_reads_128_bits_from_memory() {
        // movaps xmm6, [rsp+0x70]  = 0F 28 74 24 70
        let stmts = lift_one(&[0x0F, 0x28, 0x74, 0x24, 0x70]);
        assert_eq!(
            stmts,
            vec![MicroStmt::Assign {
                dst: "xmm6".into(),
                value: MicroExpr::load(MicroExpr::binary(BinOp::Add, MicroExpr::var("rsp"), MicroExpr::constant(0x70, 64)), 128, false),
            }],
        );
    }

    #[test]
    fn the_vex_spelling_of_a_packed_move_lifts_the_same_as_the_legacy_one() {
        // vmovdqu [rdi], xmm0  = C5 FA 7F 07
        assert_eq!(
            lift_one(&[0xC5, 0xFA, 0x7F, 0x07]),
            vec![MicroStmt::Store { addr: MicroExpr::var("rdi"), value: MicroExpr::var("xmm0"), bits: 128 }]
        );
        // vmovdqa ymm0, [rax]  = C5 FD 6F 00 — 256 bits, taken from the operand.
        assert_eq!(
            lift_one(&[0xC5, 0xFD, 0x6F, 0x00]),
            vec![MicroStmt::Assign { dst: "xmm0".into(), value: MicroExpr::load(MicroExpr::var("rax"), 256, false) }],
            "the width comes from the ymm operand; the name stays the one SSA name this model gives a vector register"
        );
    }

    #[test]
    fn a_cross_domain_vex_move_is_the_copy_that_joins_the_two_register_files() {
        // vmovq rax, xmm0  = C4 E1 F9 7E C0. Unlifted, this is where a copy
        // chain through a vector register dies — measured in `QAction::toolTip`.
        assert_eq!(
            lift_one(&[0xC4, 0xE1, 0xF9, 0x7E, 0xC0]),
            vec![MicroStmt::Assign { dst: "rax".into(), value: MicroExpr::var("xmm0") }]
        );
        // vmovd xmm3, esi  = C5 F9 6E DE — the other direction. The GPR reads as
        // `rsi`: SSA normalizes a sub-register to its full register everywhere.
        assert_eq!(
            lift_one(&[0xC5, 0xF9, 0x6E, 0xDE]),
            vec![MicroStmt::Assign { dst: "xmm3".into(), value: MicroExpr::var("rsi") }]
        );
    }

    #[test]
    fn the_vex_merge_form_states_both_sources_rather_than_claiming_either() {
        // vmovsd xmm0, xmm1, xmm2  = C5 F3 10 C2. The result is xmm2's scalar
        // over xmm1's upper lanes; this model has no lanes, so neither operand
        // alone is the answer.
        assert_eq!(
            lift_one(&[0xC5, 0xF3, 0x10, 0xC2]),
            vec![MicroStmt::Assign {
                dst: "xmm0".into(),
                value: MicroExpr::intrinsic("__vmovsd", vec![MicroExpr::var("xmm1"), MicroExpr::var("xmm2")]),
            }]
        );
    }

    #[test]
    fn a_masked_evex_move_is_refused_because_it_is_conditional() {
        // vmovdqu32 zmm0{k1}, [rax]  = 62 F1 7E 49 6F 00. Per-element predicated:
        // lifting it as an unconditional move would state which bytes changed
        // when the mask decides that at run time.
        let stmts = lift_one(&[0x62, 0xF1, 0x7E, 0x49, 0x6F, 0x00]);
        assert!(
            matches!(stmts.first(), Some(MicroStmt::Unlifted { .. })),
            "a masked move must stay opaque, got {stmts:?}"
        );
    }

    #[test]
    fn architectural_no_ops_lift_to_nothing_instead_of_asm_noise() {
        // endbr64 = F3 0F 1E FA — a CET landing pad.
        assert_eq!(lift_one(&[0xF3, 0x0F, 0x1E, 0xFA]), vec![MicroStmt::Nop]);
        // vzeroupper = C5 F8 77 — clears lanes above 128, which this model has
        // no representation for.
        assert_eq!(lift_one(&[0xC5, 0xF8, 0x77]), vec![MicroStmt::Nop]);
    }

    #[test]
    fn an_sse_register_copy_is_a_plain_assign_between_xmm_registers() {
        // movaps xmm1, xmm0  = 0F 28 C8
        let stmts = lift_one(&[0x0F, 0x28, 0xC8]);
        assert_eq!(stmts, vec![MicroStmt::Assign { dst: "xmm1".into(), value: MicroExpr::var("xmm0") }]);
    }

    #[test]
    fn rol_by_an_immediate_lifts_to_the_exact_shift_or_shift() {
        // rol eax, 5  = C1 C0 05  ->  eax = (eax << 5) | (eax >> 27)
        let stmts = lift_one(&[0xC1, 0xC0, 0x05]);
        assert_eq!(
            stmts[0],
            MicroStmt::Assign {
                dst: "rax".into(),
                value: MicroExpr::binary(
                    BinOp::Or,
                    MicroExpr::binary(BinOp::Shl, MicroExpr::var("rax"), MicroExpr::constant(5, 32)),
                    MicroExpr::binary(BinOp::Shr, MicroExpr::var("rax"), MicroExpr::constant(27, 32)),
                ),
            },
        );
    }

    #[test]
    fn ror_by_an_immediate_mirrors_rol() {
        // ror eax, 5  = C1 C8 05  ->  eax = (eax >> 5) | (eax << 27)
        let stmts = lift_one(&[0xC1, 0xC8, 0x05]);
        assert_eq!(
            stmts[0],
            MicroStmt::Assign {
                dst: "rax".into(),
                value: MicroExpr::binary(
                    BinOp::Or,
                    MicroExpr::binary(BinOp::Shr, MicroExpr::var("rax"), MicroExpr::constant(5, 32)),
                    MicroExpr::binary(BinOp::Shl, MicroExpr::var("rax"), MicroExpr::constant(27, 32)),
                ),
            },
        );
    }

    #[test]
    fn a_register_count_rotate_stays_opaque_rather_than_guess_the_mask() {
        // rol eax, cl  = D3 C0 — a CL-count rotate needs x86 count-masking to be
        // sound, so it is preserved verbatim, not lifted to an unmasked shift.
        let stmts = lift_one(&[0xD3, 0xC0]);
        assert!(
            stmts.iter().any(|s| matches!(s, MicroStmt::Unlifted { .. })),
            "a variable-count rotate must stay opaque: {stmts:?}",
        );
    }

    #[test]
    fn tzcnt_lifts_to_a_named_intrinsic_over_its_source() {
        // tzcnt eax, ecx  = F3 0F BC C1
        let stmts = lift_one(&[0xF3, 0x0F, 0xBC, 0xC1]);
        assert_eq!(
            stmts[0],
            MicroStmt::Assign { dst: "rax".into(), value: MicroExpr::intrinsic("__tzcnt", vec![MicroExpr::var("rcx")]) },
        );
    }

    #[test]
    fn pxor_is_an_exact_128_bit_bitwise_xor_not_an_intrinsic() {
        // pxor xmm0, xmm1  = 66 0F EF C1  -> xmm0 = (xmm0 ^ xmm1), named xmm
        let stmts = lift_one(&[0x66, 0x0F, 0xEF, 0xC1]);
        assert_eq!(
            stmts,
            vec![MicroStmt::Assign {
                dst: "xmm0".into(),
                value: MicroExpr::binary(BinOp::Xor, MicroExpr::var("xmm0"), MicroExpr::var("xmm1")),
            }],
        );
    }

    #[test]
    fn pmovmskb_extracts_a_gpr_mask_from_an_xmm_source() {
        // pmovmskb eax, xmm1  = 66 0F D7 C1
        let stmts = lift_one(&[0x66, 0x0F, 0xD7, 0xC1]);
        assert_eq!(
            stmts[0],
            MicroStmt::Assign { dst: "rax".into(), value: MicroExpr::intrinsic("__pmovmskb", vec![MicroExpr::var("xmm1")]) },
        );
    }

    #[test]
    fn addsd_reads_as_a_scalar_fp_intrinsic_over_both_xmm_operands() {
        // addsd xmm0, xmm1  = F2 0F 58 C1
        let stmts = lift_one(&[0xF2, 0x0F, 0x58, 0xC1]);
        assert_eq!(
            stmts[0],
            MicroStmt::Assign {
                dst: "xmm0".into(),
                value: MicroExpr::intrinsic("__addsd", vec![MicroExpr::var("xmm0"), MicroExpr::var("xmm1")]),
            },
        );
    }

    #[test]
    fn cdqe_sign_extends_the_accumulator() {
        // cdqe = 48 98  ->  rax = (int64_t)(int32_t)rax
        let stmts = lift_one(&[0x48, 0x98]);
        assert_eq!(
            stmts,
            vec![MicroStmt::Assign {
                dst: "rax".into(),
                value: MicroExpr::Cast {
                    signed: true,
                    bits: 64,
                    expr: Box::new(MicroExpr::Cast { signed: true, bits: 32, expr: Box::new(MicroExpr::var("rax")) }),
                },
            }],
        );
    }

    #[test]
    fn btr_and_bts_with_an_immediate_flip_exactly_one_bit() {
        // btr eax, 5 = 0F BA F0 05  ->  rax = rax & ~0x20
        let btr = lift_one(&[0x0F, 0xBA, 0xF0, 0x05]);
        assert_eq!(
            btr[0],
            MicroStmt::Assign {
                dst: "rax".into(),
                value: MicroExpr::binary(BinOp::And, MicroExpr::var("rax"), MicroExpr::unary(UnOp::Not, MicroExpr::constant(0x20, 32))),
            },
        );
        // bts eax, 5 = 0F BA E8 05  ->  rax = rax | 0x20
        let bts = lift_one(&[0x0F, 0xBA, 0xE8, 0x05]);
        assert_eq!(
            bts[0],
            MicroStmt::Assign { dst: "rax".into(), value: MicroExpr::binary(BinOp::Or, MicroExpr::var("rax"), MicroExpr::constant(0x20, 32)) },
        );
    }

    #[test]
    fn cmp_writes_flags_as_a_precise_compare() {
        // cmp rcx, 0
        let stmts = lift_one(&[0x48, 0x83, 0xF9, 0x00]);
        assert_eq!(
            stmts,
            vec![MicroStmt::Assign {
                dst: FLAGS_VAR.into(),
                value: MicroExpr::compare(CmpKind::Cmp, MicroExpr::var("rcx"), MicroExpr::constant(0, 64)),
            }]
        );
    }

    #[test]
    fn je_after_cmp_resolves_to_an_exact_equality() {
        let flags = MicroExpr::compare(CmpKind::Cmp, MicroExpr::var("rcx"), MicroExpr::constant(4, 8));
        let cond = branch_condition("je", &flags);
        assert_eq!(cond, MicroExpr::binary(BinOp::Eq, MicroExpr::var("rcx"), MicroExpr::constant(4, 8)));
    }

    #[test]
    fn je_after_an_intervening_flag_setter_uses_that_setter_not_a_stale_compare() {
        // The correctness property ROADMAP Phase 3 calls out: a flag-setting
        // instruction between `cmp` and `jcc` must invalidate the compare
        // rather than let a stale one render a wrong condition. `add rcx,rdx`
        // now records its *own* result flags (a `Result` compare), so a
        // following `je` decodes from the add's result (`rcx == 0`) — the
        // stale `cmp` can never be what a subsequent branch reads.
        let add_stmts = lift_one(&[0x48, 0x01, 0xD1]); // add rcx, rdx
        assert_eq!(
            add_stmts.last(),
            Some(&MicroStmt::Assign {
                dst: FLAGS_VAR.into(),
                value: MicroExpr::compare(CmpKind::Result, MicroExpr::var("rcx"), MicroExpr::constant(0, 64)),
            })
        );

        let cond = branch_condition("je", &last_flags(&add_stmts));
        assert_eq!(cond, MicroExpr::binary(BinOp::Eq, MicroExpr::var("rcx"), MicroExpr::constant(0, 64)));
    }

    #[test]
    fn dec_then_jne_reconstructs_the_loop_latch_condition() {
        // `dec ecx ; jne` is the canonical loop-counter latch. `dec` keeps its
        // result in ecx and sets ZF from it, so the branch reads `ecx != 0`
        // instead of the old opaque `/*cond(jne)*/`.
        let dec_stmts = lift_one(&[0xFF, 0xC9]); // dec ecx
        let flags = last_flags(&dec_stmts);
        assert_eq!(flags, MicroExpr::compare(CmpKind::Result, MicroExpr::var("rcx"), MicroExpr::constant(0, 32)));
        assert_eq!(branch_condition("jne", &flags), MicroExpr::binary(BinOp::Ne, MicroExpr::var("rcx"), MicroExpr::constant(0, 32)));
    }

    #[test]
    fn a_result_flag_magnitude_branch_stays_opaque() {
        // Only the zero flag is a sound function of a stored result; a signed
        // magnitude branch (`jg`) after `sub` needs overflow the result alone
        // does not carry, so it must stay a placeholder, never a wrong guess.
        let flags = MicroExpr::compare(CmpKind::Result, MicroExpr::var("rax"), MicroExpr::constant(0, 64));
        assert_eq!(branch_condition("jg", &flags), MicroExpr::Unknown("cond(jg) after result".into()));
    }

    #[test]
    fn test_reg_reg_reconstructs_the_full_signed_and_unsigned_jcc_family() {
        // `test rax,rax` is a logical op (OF=CF=0), so every condition is a
        // sign/zero test on rax — the whole family reconstructs, not just je/jne.
        let flags = last_flags(&lift_one(&[0x48, 0x85, 0xC0])); // test rax, rax
        let z = || MicroExpr::constant(0, 64);
        let rax = || MicroExpr::var("rax");
        assert_eq!(branch_condition("jle", &flags), MicroExpr::binary(BinOp::Sle, rax(), z())); // <= 0
        assert_eq!(branch_condition("jl", &flags), MicroExpr::binary(BinOp::Slt, rax(), z())); // < 0
        assert_eq!(branch_condition("jg", &flags), MicroExpr::binary(BinOp::Sgt, rax(), z())); // > 0
        assert_eq!(branch_condition("jge", &flags), MicroExpr::binary(BinOp::Sge, rax(), z())); // >= 0
        assert_eq!(branch_condition("ja", &flags), MicroExpr::binary(BinOp::Ne, rax(), z())); // != 0
        assert_eq!(branch_condition("jbe", &flags), MicroExpr::binary(BinOp::Eq, rax(), z())); // == 0
        assert_eq!(branch_condition("je", &flags), MicroExpr::binary(BinOp::Eq, rax(), z()));
        // CF is provably 0: jae always, jb never.
        assert_eq!(branch_condition("jae", &flags), MicroExpr::constant(1, 8));
        assert_eq!(branch_condition("jb", &flags), MicroExpr::constant(0, 8));
    }

    #[test]
    fn and_that_keeps_its_result_reconstructs_signed_branches_via_logical_result() {
        // `and edx,edx` keeps edx and clears OF/CF, so `jle` after it is `edx<=0`
        // — a LogicalResult, the full family, not the arithmetic je/jne-only.
        let flags = last_flags(&lift_one(&[0x21, 0xD2])); // and edx, edx
        assert_eq!(flags, MicroExpr::compare(CmpKind::LogicalResult, MicroExpr::var("rdx"), MicroExpr::constant(0, 32)));
        assert_eq!(branch_condition("jle", &flags), MicroExpr::binary(BinOp::Sle, MicroExpr::var("rdx"), MicroExpr::constant(0, 64)));
    }

    #[test]
    fn js_jns_reconstruct_after_an_arithmetic_result() {
        // SF is the sign bit of the stored result, so `js`/`jns` recover even
        // after `sub`/`add` (the magnitude branches, needing overflow, do not).
        let flags = last_flags(&lift_one(&[0x48, 0x01, 0xD1])); // add rcx, rdx
        assert_eq!(branch_condition("js", &flags), MicroExpr::binary(BinOp::Slt, MicroExpr::var("rcx"), MicroExpr::constant(0, 64)));
        assert_eq!(branch_condition("jns", &flags), MicroExpr::binary(BinOp::Sge, MicroExpr::var("rcx"), MicroExpr::constant(0, 64)));
        // A magnitude branch still stays opaque (needs the real overflow flag).
        assert_eq!(branch_condition("jl", &flags), MicroExpr::Unknown("cond(jl) after result".into()));
    }

    #[test]
    fn an_eight_bit_result_destination_stays_opaque_for_soundness() {
        // `dec cl` leaves the upper bits of rcx intact, so `rcx == 0` would not
        // mean `cl == 0` — the guard keeps sub-32-bit destinations opaque.
        let dec_cl = lift_one(&[0xFE, 0xC9]); // dec cl
        assert_eq!(
            dec_cl.last(),
            Some(&MicroStmt::Assign { dst: FLAGS_VAR.into(), value: MicroExpr::OpaqueFlags { mnemonic: "dec".into() } })
        );
    }

    #[test]
    fn lea_takes_the_address_not_the_value() {
        // lea rax, [rcx+8]
        let stmts = lift_one(&[0x48, 0x8D, 0x41, 0x08]);
        assert_eq!(
            stmts,
            vec![MicroStmt::Assign {
                dst: "rax".into(),
                value: MicroExpr::AddrOf(Box::new(MicroExpr::binary(
                    BinOp::Add,
                    MicroExpr::var("rcx"),
                    MicroExpr::constant(8, 64)
                ))),
            }]
        );
    }

    #[test]
    fn ret_returns_rax() {
        let stmts = lift_one(&[0xC3]);
        assert_eq!(stmts, vec![MicroStmt::Return(Some(MicroExpr::var("rax")))]);
    }

    #[test]
    fn call_clobbers_volatile_regs_but_not_rax_which_gets_the_real_result() {
        // call +5 (direct near call)
        let stmts = lift_one(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
        let Some(MicroStmt::Call { ret, .. }) = stmts.first() else { panic!("expected a Call stmt") };
        assert_eq!(ret.as_deref(), Some("rax"));
        // rcx is Win64-volatile and must be invalidated, not left stale.
        assert!(stmts.iter().any(|s| matches!(
            s,
            MicroStmt::Assign { dst, value: MicroExpr::Unknown(_) } if dst == "rcx"
        )));
    }

    fn lift_one_abi(bytes: &[u8], abi: &str) -> Vec<MicroStmt> {
        let arch = X64::new();
        let insns = arch.decode_stream(bytes, Va(0x1000), 4);
        arch.lift(&insns[0], abi)
    }

    fn call_arg_regs(stmts: &[MicroStmt]) -> Vec<String> {
        let Some(MicroStmt::Call { args, .. }) = stmts.iter().find(|s| matches!(s, MicroStmt::Call { .. })) else {
            panic!("expected a Call stmt in {stmts:?}");
        };
        args.iter()
            .map(|a| match a {
                MicroExpr::Var(n) => n.clone(),
                other => panic!("a call arg should be a register var, got {other:?}"),
            })
            .collect()
    }

    #[test]
    fn a_system_v_call_forwards_the_sysv_argument_registers_not_the_win64_ones() {
        // call +5, lowered under the ELF/System V ABI.
        let stmts = lift_one_abi(&[0xE8, 0x00, 0x00, 0x00, 0x00], "sysv");
        assert_eq!(
            call_arg_regs(&stmts),
            ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            "System V passes six integer args starting at rdi, not the Win64 rcx,rdx,r8,r9",
        );
    }

    #[test]
    fn a_system_v_call_invalidates_rsi_and_rdi_which_win64_would_wrongly_preserve() {
        // The soundness half of ABI-aware lifting: rsi/rdi are caller-saved on
        // System V (clobbered by any call) but callee-saved on Win64. Lowering an
        // ELF call with the Win64 clobber set would let a later read reuse a
        // pre-call rsi/rdi value that the callee is free to have destroyed.
        let call = &[0xE8, 0x00, 0x00, 0x00, 0x00];
        let clobbered = |stmts: &[MicroStmt], reg: &str| {
            stmts.iter().any(|s| matches!(
                s,
                MicroStmt::Assign { dst, value: MicroExpr::Unknown(_) } if dst == reg
            ))
        };

        let sysv = lift_one_abi(call, "sysv");
        assert!(clobbered(&sysv, "rsi"), "rsi is caller-saved on System V");
        assert!(clobbered(&sysv, "rdi"), "rdi is caller-saved on System V");

        let win64 = lift_one_abi(call, "win64");
        assert!(!clobbered(&win64, "rsi"), "rsi is callee-saved on Win64 — must survive the call");
        assert!(!clobbered(&win64, "rdi"), "rdi is callee-saved on Win64 — must survive the call");
    }

    #[test]
    fn an_unknown_abi_falls_back_to_the_native_win64_convention() {
        // A source whose abi_name the arch does not recognize must not crash or
        // drop calls — it gets the arch's first/native convention.
        let stmts = lift_one_abi(&[0xE8, 0x00, 0x00, 0x00, 0x00], "made-up");
        assert_eq!(call_arg_regs(&stmts), ["rcx", "rdx", "r8", "r9"]);
    }

    fn lift_tail_one(bytes: &[u8]) -> Vec<MicroStmt> {
        let arch = X64::new();
        let insns = arch.decode_stream(bytes, Va(0x1000), 4);
        arch.lift_tail_call(&insns[0], "win64")
    }

    #[test]
    fn a_plain_jmp_lifts_to_nothing_but_a_tail_jmp_lifts_to_call_plus_return() {
        // jmp +0 — as an intra-function branch it carries no dataflow (the CFG
        // edge is the whole story); as a *tail call* it is `return f(...)`.
        let branch = &[0xE9, 0x00, 0x00, 0x00, 0x00];
        assert!(lift_one(branch).is_empty());

        let stmts = lift_tail_one(branch);
        assert_eq!(stmts.len(), 2, "call + return, nothing else: {stmts:?}");
        let MicroStmt::Call { target, args, ret } = &stmts[0] else {
            panic!("expected a Call stmt, got {stmts:?}")
        };
        assert_eq!(*target, CallTarget::Direct { va: Va(0x1005) });
        assert_eq!(args.len(), 4, "the Win64 integer arg registers, in order");
        assert_eq!(ret.as_deref(), Some("rax"));
        assert_eq!(stmts[1], MicroStmt::Return(Some(MicroExpr::var("rax"))));
    }

    #[test]
    fn an_import_thunk_tail_jmp_calls_through_the_iat_slot() {
        // jmp qword ptr [rip+0] -> the IAT slot at 0x1006 is the callee
        // *pointer*, so the call target is a load from it, not the slot value.
        let stmts = lift_tail_one(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
        let MicroStmt::Call { target, .. } = &stmts[0] else {
            panic!("expected a Call stmt, got {stmts:?}")
        };
        assert_eq!(
            *target,
            CallTarget::Indirect(Box::new(MicroExpr::load(MicroExpr::constant(0x1006, 64), 64, false)))
        );
        assert_eq!(stmts[1], MicroStmt::Return(Some(MicroExpr::var("rax"))));
    }
}

