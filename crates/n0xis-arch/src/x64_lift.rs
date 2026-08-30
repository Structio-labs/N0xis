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
fn decode_raw(insn: &DecodedInsn) -> Option<Instruction> {
    let mut decoder = Decoder::with_ip(64, &insn.bytes, insn.va.0, DecoderOptions::NONE);
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
            out.push(compare_flags(CmpKind::Result, result, MicroExpr::constant(0, bits)));
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
    let Some(instr) = decode_raw(insn) else {
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
    let Some(instr) = decode_raw(insn) else {
        return vec![MicroStmt::Unlifted { va: insn.va, text: insn.text.clone() }];
    };
    let mut out: Vec<MicroStmt> = Vec::new();
    let mn = instr.mnemonic();

    match mn {
        Mnemonic::Mov => {
            let v = read_operand(&instr, 1);
            write_operand(&instr, 0, v, &mut out);
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
            _ => MicroExpr::Unknown(format!("cond({mnemonic}) after result")),
        };
    }

    if *kind == CmpKind::Test {
        // `test a,b` sets flags from `a & b` without storing it; `a,a` is the
        // common "is a zero / negative" idiom.
        let same = lhs == rhs;
        return match mnemonic {
            "je" => {
                if same {
                    MicroExpr::binary(BinOp::Eq, lhs, MicroExpr::constant(0, 64))
                } else {
                    MicroExpr::binary(BinOp::Eq, MicroExpr::binary(BinOp::And, lhs, rhs), MicroExpr::constant(0, 64))
                }
            }
            "jne" => {
                if same {
                    MicroExpr::binary(BinOp::Ne, lhs, MicroExpr::constant(0, 64))
                } else {
                    MicroExpr::binary(BinOp::Ne, MicroExpr::binary(BinOp::And, lhs, rhs), MicroExpr::constant(0, 64))
                }
            }
            "js" => MicroExpr::binary(BinOp::Slt, lhs, MicroExpr::constant(0, 64)),
            "jns" => MicroExpr::binary(BinOp::Sge, lhs, MicroExpr::constant(0, 64)),
            _ => MicroExpr::Unknown(format!("cond({mnemonic}) after test")),
        };
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

