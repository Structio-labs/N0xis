// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `X64::lift` — the x86-64 instruction → micro-IR lowering. Kept in its own
//! file (rather than inline in `x64.rs`) purely for size; it is still x64-only
//! ISA knowledge, so it stays behind the `Arch` seam like everything else in
//! this crate.
//!
//! The condition-code reconstruction that used to live here — `branch_condition`
//! and its helpers — is in [`crate::flags`] now, because it reads a [`CmpKind`]
//! rather than an instruction and AArch64 needs the identical rules.
//!
//! Coverage mirrors the archived v0 template renderer
//! (v0's `pseudo.rs::lift_instruction`) — same mnemonic
//! set — but every operand becomes a typed [`MicroExpr`], and every
//! flag-touching instruction (not just `cmp`/`test`) writes the shared
//! [`FLAGS_VAR`], which is what makes SSA construction able to detect a stale
//! compare instead of silently reusing one (see `microir.rs` module docs).

use iced_x86::{CodeSize, Decoder, DecoderOptions, EncodingKind, Instruction, MemorySize, Mnemonic, OpKind, Register};

use crate::insn::DecodedInsn;
use crate::microir::{
    BinOp, Bits, CallTarget, CmpKind, FLAGS_VAR, JUMP_TARGET_VAR, MicroExpr, MicroStmt, UnOp,
};
use crate::flags::signed_view;
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

/// The mode the instruction was decoded in. A register's *full* width is the
/// smaller of its container and the mode: `eax` is a sub-register in 64-bit
/// code and the whole register in 32-bit code, and the difference is exactly
/// whether writing it clears anything.
fn mode_bits(instr: &Instruction) -> Bits {
    match instr.code_size() {
        CodeSize::Code16 => 16,
        CodeSize::Code32 => 32,
        _ => 64,
    }
}

/// The four registers that name the *second* byte of their container.
/// The width of the IR's variable. Every consumer — the emulator, the constant
/// folder, a signed predicate — models a 64-bit word, so anything narrower than
/// this has to be stated in the IR rather than left to the container.
const WORD_BITS: Bits = 64;

const HIGH_BYTE: [Register; 4] = [Register::AH, Register::CH, Register::DH, Register::BH];

/// Where a register sits inside the canonical full-width variable that carries
/// it: `(container name, offset in bits, width in bits, container width)`.
///
/// Canonical names are always the widest spelling (`al`, `ax`, `eax` all live
/// in `rax`) so SSA and def-use can treat one register as one variable. That
/// normalization is right, and on its own it is also a **lie**: it says `mov
/// eax, ecx` copies 64 bits. This is the one place that knows otherwise, and
/// every register operand goes through it.
fn reg_slice(instr: &Instruction, r: Register) -> (String, Bits, Bits, Bits) {
    let full = r.full_register();
    let container = mode_bits(instr).min((full.size() * 8) as Bits);
    let offset = if HIGH_BYTE.contains(&r) { 8 } else { 0 };
    (reg_name(r), offset, (r.size() * 8) as Bits, container)
}

/// Read a register operand at its **own** width.
///
/// A sub-register read is the low `width` bits, zero-extended — which is what
/// the value *is*, whatever the consumer does with it next. Only a read of the
/// IR's full word needs no statement.
///
/// **The threshold is the IR's word, not the register's container.** This asked
/// `width >= container`, which is the same thing in 64-bit mode and is not in
/// 32-bit mode: there `eax` *is* the container, so `add eax, ebx` lifted to
/// `rax = rax + rbx` with no width anywhere in it. Every consumer models a
/// 64-bit word, so a 32-bit sum that overflows stayed 33 bits wide, and every
/// signed predicate on a 32-bit value answered the unsigned question — the
/// exact defect class that cost 52 wrong answers on x86-64 and was never closed
/// one bitness down, because nothing had ever executed a 32-bit target.
fn reg_read(instr: &Instruction, r: Register) -> MicroExpr {
    let (name, offset, width, _container) = reg_slice(instr, r);
    let var = MicroExpr::var(name);
    if offset > 0 {
        let shifted = MicroExpr::binary(BinOp::Shr, var, MicroExpr::constant(offset as i128, 8));
        return MicroExpr::Cast { signed: false, bits: width, expr: Box::new(shifted) };
    }
    if width >= WORD_BITS {
        return var;
    }
    MicroExpr::Cast { signed: false, bits: width, expr: Box::new(var) }
}

/// Write a register operand at its **own** width, with x86's two opposite
/// rules made explicit:
///
/// * a 32-bit write in 64-bit mode **zeroes** the upper half;
/// * an 8- or 16-bit write **keeps** it.
///
/// Both are the same instruction family, so a lifter that models one and not
/// the other is wrong exactly once — and silently, since the difference only
/// shows in the bits it dropped.
fn reg_write(instr: &Instruction, r: Register, value: MicroExpr, out: &mut Vec<MicroStmt>) {
    let (name, offset, width, container) = reg_slice(instr, r);
    if width >= WORD_BITS {
        out.push(MicroStmt::Assign { dst: name, value });
        return;
    }
    // A write that fills its whole container still has to *say* how wide it is:
    // the IR's variable is a 64-bit word whatever the container is, and in
    // 32-bit mode `eax` fills its container. Without this the value keeps every
    // bit the operation produced above bit 31 and nothing ever truncates it.
    if width >= container {
        let narrowed = MicroExpr::Cast { signed: false, bits: width, expr: Box::new(value) };
        out.push(MicroStmt::Assign { dst: name, value: narrowed });
        return;
    }
    if offset == 0 && width == 32 && container == 64 {
        let widened = MicroExpr::Cast { signed: false, bits: 32, expr: Box::new(value) };
        out.push(MicroStmt::Assign { dst: name, value: widened });
        return;
    }
    let field = ((1u128 << width) - 1) << offset;
    let keep_mask = (!field & ((1u128 << container) - 1)) as i128;
    let kept = MicroExpr::binary(
        BinOp::And,
        MicroExpr::var(name.clone()),
        MicroExpr::constant(keep_mask, container),
    );
    let narrowed = MicroExpr::Cast { signed: false, bits: width, expr: Box::new(value) };
    let placed = if offset > 0 {
        MicroExpr::binary(BinOp::Shl, narrowed, MicroExpr::constant(offset as i128, 8))
    } else {
        narrowed
    };
    out.push(MicroStmt::Assign {
        dst: name,
        value: MicroExpr::binary(BinOp::Or, kept, placed),
    });
}

/// The width and signedness of a memory operand.
///
/// The width comes from the decoder's own size for the operand, not from a
/// table of the sizes someone thought to list. That table ended in
/// `_ => (64, false)`, so **every operand it did not name read as eight
/// bytes**: a 128-bit `movdqa xmm0, [mem]` loaded half a register and the upper
/// lane was silently zero, and a packed add against a memory operand added
/// zeros to it. A default that answers rather than refuses is the worst shape a
/// fallback can take, because nothing downstream can tell it from a measurement.
///
/// Signedness stays a list, because only a handful of operand sizes are signed
/// and the decoder says so by naming them.
fn mem_bits_signed(size: MemorySize) -> (Bits, bool) {
    use MemorySize as MS;
    let signed = matches!(size, MS::Int8 | MS::Int16 | MS::Int32 | MS::Int64);
    let bits = (size.size() as Bits) * 8;
    // A memory operand whose size the decoder does not state is not something
    // this can size either; the machine word is what it read before and the
    // only thing left to read.
    if bits == 0 { (64, signed) } else { (bits, signed) }
}

/// The effective-address expression of a `Memory`-kind operand.
///
/// An explicit `fs:`/`gs:` override makes the operand relative to a per-thread
/// base the function never loads, so the offset is *not* an address: `fs:0x28`
/// is the stack canary, not a read of the second page of the address space.
/// Wrapping it keeps the offset visible and stops anything downstream from
/// folding it into a global. In 64-bit mode `cs:`/`ds:`/`es:`/`ss:` have a zero
/// base and a prefix on them changes nothing, so those stay bare.
fn mem_addr_expr(instr: &Instruction) -> MicroExpr {
    let addr = mem_offset_expr(instr);
    match instr.segment_prefix() {
        Register::FS => MicroExpr::intrinsic("__seg_fs", vec![addr]),
        Register::GS => MicroExpr::intrinsic("__seg_gs", vec![addr]),
        _ => addr,
    }
}

/// The offset part of a `Memory`-kind operand, ignoring any segment:
/// RIP-relative folds to an absolute constant; otherwise `base + index*scale + disp`.
fn mem_offset_expr(instr: &Instruction) -> MicroExpr {
    if instr.is_ip_rel_memory_operand() {
        return MicroExpr::constant(instr.ip_rel_memory_address() as i128, 64);
    }
    let base = instr.memory_base();
    let index = instr.memory_index();
    let scale = instr.memory_index_scale();
    let disp = instr.memory_displacement64() as i64 as i128;

    let mut parts: Vec<MicroExpr> = Vec::new();
    if base != Register::None {
        parts.push(reg_read(instr, base));
    }
    if index != Register::None {
        let idx = reg_read(instr, index);
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
    let addr = it.fold(first, |acc, p| MicroExpr::binary(BinOp::Add, acc, p));

    // **An effective address is computed at the address size, and wraps.** On a
    // 32-bit target `[ebp-0x10]` is `(ebp - 0x10) mod 2^32`, and the IR built it
    // with a 64-bit add that carries: `0xbfffefec + 0xfffffff0` came out
    // `0x1bfffefdc`. Every dword access in a function used that address while a
    // byte access through a `lea`-produced pointer — which *is* truncated,
    // because a register write states its width — used `0xbfffefdc`. Two
    // addresses for one stack slot, so a byte written through the pointer was
    // invisible to the next read of the same local.
    //
    // The width comes from the addressing registers, not from the mode, so a
    // `0x67`-prefixed operand is right too. With no register at all the address
    // is the displacement, which is already the value it will be.
    let addr_bits = address_width(instr);
    if addr_bits < WORD_BITS {
        return MicroExpr::Cast { signed: false, bits: addr_bits, expr: Box::new(addr) };
    }
    addr
}

/// The width an effective address is computed at: the size of whichever
/// register addresses it, else the mode's default.
fn address_width(instr: &Instruction) -> Bits {
    for r in [instr.memory_base(), instr.memory_index()] {
        if r != Register::None {
            return (r.size() * 8) as Bits;
        }
    }
    mode_bits(instr)
}

/// Read operand `idx` as an rvalue expression (register / immediate / memory
/// load / near-branch target).
fn read_operand(instr: &Instruction, idx: u32) -> MicroExpr {
    match instr.op_kind(idx) {
        OpKind::Register => reg_read(instr, instr.op_register(idx)),
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

/// The same, for an instruction whose integer source is **signed**.
///
/// `cvtsi2sd xmm0, eax` converts a *signed* 32-bit integer. Read the operand
/// the ordinary way and the 32-bit register arrives zero-extended, so -1
/// converts to 4294967295 — an answer that is wrong by 2^32 and looks like a
/// number rather than a fault. The same signed/unsigned split has now bitten in
/// three places (compare predicates, memory operands, and here), which is why
/// `signed_view` exists rather than three inline casts.
fn intr_unary_signed(instr: &Instruction, name: &str, out: &mut Vec<MicroStmt>) {
    let src = signed_view(smart_read(instr, 1));
    smart_write(instr, 0, MicroExpr::intrinsic(name, vec![src]), out);
}

/// [`vec_intr_unary`] for a VEX conversion whose integer source is signed.
fn vec_intr_unary_signed(instr: &Instruction, name: &str, out: &mut Vec<MicroStmt>) {
    let last = instr.op_count().saturating_sub(1);
    let src = signed_view(smart_read(instr, last));
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
/// The **source** operands of an ALU-shaped vector instruction, in whichever
/// encoding it came in.
///
/// The legacy SSE form is read-modify-write — `addsd xmm0, xmm1` means
/// `xmm0 = xmm0 + xmm1`, so operand 0 is a source too. The VEX/EVEX form is
/// non-destructive — `vaddsd xmm0, xmm1, xmm2` means `xmm0 = xmm1 + xmm2`, and
/// counting operand 0 as a source would invent a dependency on whatever the
/// destination register held before. `EncodingKind` says which, exactly, rather
/// than guessing from the operand count (`pinsrq` is legacy and takes three).
fn vec_sources(instr: &Instruction) -> Vec<MicroExpr> {
    let first = u32::from(instr.encoding() != EncodingKind::Legacy);
    (first..instr.op_count()).map(|i| smart_read(instr, i)).collect()
}

/// `dst = name(sources…)` for an ALU-shaped vector instruction.
fn vec_intr(instr: &Instruction, name: &str, out: &mut Vec<MicroStmt>) {
    let args = vec_sources(instr);
    smart_write(instr, 0, MicroExpr::intrinsic(name, args), out);
}

/// `dst = name(src)` where the meaningful input is the **last** operand — the
/// shape of a conversion or a square root. In the VEX form the middle operand is
/// only the merge source for the lanes the instruction does not write, which
/// this model has no representation for.
fn vec_intr_unary(instr: &Instruction, name: &str, out: &mut Vec<MicroStmt>) {
    let last = instr.op_count().saturating_sub(1);
    let src = smart_read(instr, last);
    smart_write(instr, 0, MicroExpr::intrinsic(name, vec![src]), out);
}

/// `dst = name(op0, op1, …)` — an intrinsic whose **destination is also an
/// input**, which `vec_sources` deliberately does not assume for a VEX form.
/// FMA is the family that needs it: `vfmadd231sd xmm0, xmm1, xmm2` is
/// `xmm0 = xmm1*xmm2 + xmm0`, so dropping operand 0 would lose an input the
/// instruction really reads.
fn vec_intr_accum(instr: &Instruction, name: &str, out: &mut Vec<MicroStmt>) {
    let args: Vec<MicroExpr> = (0..instr.op_count()).map(|i| smart_read(instr, i)).collect();
    smart_write(instr, 0, MicroExpr::intrinsic(name, args), out);
}

/// A fused multiply-add of any of its 48 spellings (`vfmadd132ps`,
/// `vfnmsub231sd`, …). Matched by name because enumerating the family would be
/// a page of mnemonics that says nothing the name does not.
fn is_fma(mn: Mnemonic) -> bool {
    let name = format!("{mn:?}");
    ["Vfmadd", "Vfmsub", "Vfnmadd", "Vfnmsub", "Vfmaddsub", "Vfmsubadd"].iter().any(|p| name.starts_with(p))
}

/// A packed/scalar compare carrying its predicate in the mnemonic
/// (`vcmpnlesd`, `vcmpordps`, …) — iced spells each predicate as its own
/// mnemonic, so the family is matched by name for the same reason as
/// [`is_fma`]. The result is a lane mask, which this IR has no type for.
fn is_vcmp(mn: Mnemonic) -> bool {
    let name = format!("{mn:?}");
    name.starts_with("Vcmp") && ["sd", "ss", "pd", "ps"].iter().any(|suffix| name.ends_with(suffix))
}

/// An exact bit-operation over the source operands, in either encoding.
fn vec_binop(instr: &Instruction, op: BinOp, out: &mut Vec<MicroStmt>) {
    let args = vec_sources(instr);
    let Some((first, rest)) = args.split_first() else { return };
    let value = rest.iter().fold(first.clone(), |acc, a| MicroExpr::binary(op, acc, a.clone()));
    smart_write(instr, 0, value, out);
}

/// `dst = (~a) & b` — `pandn`/`vpandn` and their float-typed spellings.
fn vec_andn(instr: &Instruction, out: &mut Vec<MicroStmt>) {
    let args = vec_sources(instr);
    let (Some(a), Some(b)) = (args.first(), args.get(1)) else { return };
    smart_write(instr, 0, MicroExpr::binary(BinOp::And, MicroExpr::unary(UnOp::Not, a.clone()), b.clone()), out);
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
        OpKind::Register => reg_write(instr, instr.op_register(idx), value, out),
        OpKind::Memory => {
            let (bits, _signed) = mem_bits_signed(instr.memory_size());
            out.push(MicroStmt::Store { addr: mem_addr_expr(instr), value, bits });
        }
        _ => {}
    }
}

/// The one synthetic name this lifter introduces: a divide's quotient, parked
/// while the remainder still needs the pre-division `rdx:rax`. Not a register,
/// so it can never collide with one; SSA versions it like anything else.
const DIV_TEMP: &str = "divt";

/// The same, for the one-operand multiply: both halves read `rax` and the
/// source, and the source is often `rdx`.
const MUL_TEMP: &str = "__mul_hi";

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
/// flag is a pure function of the written result, so a **register** destination
/// lets `branch_condition` reconstruct an equality branch — `dec ecx; jne`
/// becomes `ecx != 0`, the common loop-latch idiom that previously rendered
/// `/*cond(jne)*/`.
///
/// Any register width works. This was once restricted to 32 and 64 bits, on the
/// reasoning that "`dec cl` doesn't make `rcx == 0` mean `cl == 0`" — true when
/// a byte operand was read by widening it to the whole register, and false
/// since `read_operand` returns the byte itself. The restriction outlived its
/// reason and cost a real condition: mingw compiles `(a & 1) ? b : c` at `-Os`
/// to `and $1, %cl; cmove`, and the `cmove` came out with no condition at all.
/// `logical_flag_cond` already takes a signed view of a narrow result, so the
/// sign branches read bit 7 rather than bit 63.
///
/// A **memory** destination still stays opaque: re-reading it is a load, not a
/// re-read of a `Var`, and nothing guarantees it resolves to the value just
/// stored. An unreconstructable condition, never a wrong one.
///
/// The flags statement is emitted *after* the result write, so its re-read of
/// the destination resolves — under SSA's statement ordering — to the written
/// result, exactly the value whose zero-ness the branch tests.
fn result_flags(instr: &Instruction, mn: Mnemonic, out: &mut Vec<MicroStmt>) {
    if instr.op0_kind() == OpKind::Register {
        let bits = op_bits(instr, 0);
        {
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
/// `dst = dst <op> src <op> CF` — the carry-consuming add/subtract.
///
/// The carry is emitted as the `setcc:jb` marker because `jb` *is* CF: after
/// `cmp a,b` the carry is `a <u b`, and after a logical op it is provably 0.
/// Both fall out of the existing reconstruction; nothing new has to be trusted.
fn carry_rmw(instr: &Instruction, op: BinOp, out: &mut Vec<MicroStmt>) {
    if instr.op_count() < 2 {
        return;
    }
    let lhs = read_operand(instr, 0);
    let rhs = read_operand(instr, 1);
    let carry = MicroExpr::OpaqueFlags { mnemonic: "setcc:jb".to_string() };
    let value = MicroExpr::binary(op, MicroExpr::binary(op, lhs, rhs), carry);
    write_operand(instr, 0, value, out);
}

/// The canonical name of the stack pointer in the mode this was decoded in.
/// The stack pointer's variable name — **the same one every other register
/// read and write uses**.
///
/// This used to spell it by mode (`sp`/`esp`/`rsp`) while `reg_name` spells
/// every register by its *full* register, which is `rsp` in every mode. So on a
/// 32-bit target `push ebp` decremented a variable called `esp` and the very
/// next instruction, `mov %esp, %ebp`, read one called `rsp` — one register,
/// two names, and the second one still holding the value from function entry.
/// Every stack access after a push read a pointer four bytes stale, which on
/// i386 is every local in every function.
///
/// One fact, one place: it comes from `reg_name` like everything else.
fn stack_pointer(_instr: &Instruction) -> String {
    reg_name(Register::RSP)
}

/// A shift, with the count masked the way the hardware masks it: to 6 bits for
/// a 64-bit operand and to 5 bits otherwise. `shl %cl,%rax` with `rcx` holding
/// `0x8000000000000000` shifts by **zero**, and an IR that says `rax << rcx`
/// there describes a program that was never run.
fn shift_rmw(instr: &Instruction, op: BinOp, out: &mut Vec<MicroStmt>) {
    if instr.op_count() < 2 {
        return;
    }
    let width = op_bits(instr, 0);
    let mask = if width >= 64 { 63 } else { 31 };
    // An **arithmetic** right shift reads its operand as signed. A narrow
    // operand arrives zero-extended — which is what the bits are — so
    // `sar eax, cl` on `0xffffffff` shifted a 64-bit *positive* number and
    // produced zeros where the hardware produces ones. It was never caught in
    // 64-bit mode either: the corpus's only `sar` was on a 64-bit value, where
    // there is no cast to re-read.
    let lhs = match op {
        BinOp::Sar => signed_view(read_operand(instr, 0)),
        _ => read_operand(instr, 0),
    };
    let count = MicroExpr::binary(
        BinOp::And,
        read_operand(instr, 1),
        MicroExpr::constant(mask, 8),
    );
    write_operand(instr, 0, MicroExpr::binary(op, lhs, count), out);
}

/// `shld dst, src, count` / `shrd dst, src, count` — a **double-precision**
/// shift: the bits shifted out of `dst` are replaced by bits shifted in from
/// `src`, without `src` changing.
///
/// Exactly defined by the ISA for a 32- or 64-bit operand, and worth lifting
/// rather than leaving verbatim because clang reaches for it constantly — the
/// magic-number sequence for a signed division by a constant ends in
/// `shld rdx, rax, 63`.
///
/// `c = count & (width - 1)`, then `dst = (dst << c) | (src >> (width - c))`
/// for `shld`, and the mirror for `shrd`. `c == 0` leaves `dst` unchanged, and
/// the expression already says so: the complementary shift is by the full
/// width, which is zero. 16-bit operands are **left unlifted** — the
/// architecture leaves the result undefined for a count above 15 while still
/// masking by 31, and an undefined result is not something to model.
fn double_shift(instr: &Instruction, left: bool, out: &mut Vec<MicroStmt>) {
    let width = op_bits(instr, 0);
    if instr.op_count() < 3 || (width != 32 && width != 64) {
        return;
    }
    let count = MicroExpr::binary(
        BinOp::And,
        read_operand(instr, 2),
        MicroExpr::constant(i128::from(width) - 1, 8),
    );
    let complement =
        MicroExpr::binary(BinOp::Sub, MicroExpr::constant(i128::from(width), 8), count.clone());
    let (dst, src) = (read_operand(instr, 0), read_operand(instr, 1));
    let (a, b) = if left {
        (MicroExpr::binary(BinOp::Shl, dst, count), MicroExpr::binary(BinOp::Shr, src, complement))
    } else {
        (MicroExpr::binary(BinOp::Shr, dst, count), MicroExpr::binary(BinOp::Shl, src, complement))
    };
    write_operand(instr, 0, MicroExpr::binary(BinOp::Or, a, b), out);
}

/// State an expression's width explicitly, when the destination's own width
/// would not already say it. `write_operand` narrows anything below the IR's
/// word; at the word itself there is no narrowing and therefore no statement,
/// which is fine until a consumer models something wider.
fn at_width(instr: &Instruction, value: MicroExpr) -> MicroExpr {
    let bits = op_bits(instr, 0);
    if bits >= WORD_BITS {
        MicroExpr::Cast { signed: false, bits, expr: Box::new(value) }
    } else {
        value
    }
}

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

/// Registers a call may clobber, per the convention. Lives on [`CallConv`]
/// because it is a property of the ABI and both lifters ask it; see there for
/// what it excludes and why.
fn call_clobbers(regs: &RegisterFile, cc: &CallConv) -> Vec<String> {
    cc.clobbered_names(regs)
}

/// The forwarded argument expressions of a call: the convention's integer
/// argument registers, in order. Taken from [`CallConv`] rather than spelled
/// out inline so a second x64 convention (SysV) needs no edit here. Arity is
/// *not* narrowed at this stage — `TypeInferPass` recovers how many are real.
fn call_args(regs: &RegisterFile, cc: &CallConv) -> Vec<MicroExpr> {
    cc.int_arg_names(regs).into_iter().map(MicroExpr::var).collect()
}

/// The convention's integer return register (`rax` on both x86-64 ABIs).
fn ret_reg(regs: &RegisterFile, cc: &CallConv) -> String {
    cc.ret_name(regs).unwrap_or("rax").to_string()
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
    // `Arch::calling_convention` answers `None` only for an architecture that
    // declares no conventions at all. x86-64 declares two, in a `static`, and
    // `one_fact_one_place` asserts every architecture's list is non-empty — so
    // this cannot fire, and asserting it here keeps the *second* read of
    // `calling_conventions()` out of the codebase, which is the point.
    arch.calling_convention(abi).expect("x86-64 declares its calling conventions")
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

    // A `lock` prefix is not decoration, and dropping it is not a readability
    // choice — it changes what the instruction *means*. `lock inc [rax]` on a
    // shared reference count is an atomic increment; lifting the bare mnemonic
    // renders it as `*rax = *rax + 1`, which is a different program. Found by
    // differential review on `QFontIconEngine::QFontIconEngine`, where exactly
    // that turned two atomic refcount bumps into ordinary additions.
    //
    // The value effect is kept — the destination is still written from the same
    // inputs — but it goes through an intrinsic that says what it is, so nothing
    // downstream can treat it as a plain arithmetic store. A locked form this
    // does not model falls through to the opaque path rather than being lifted
    // as if the prefix were absent.
    if instr.has_lock_prefix() {
        lift_locked(arch, insn, &instr, mn, &mut out);
        return out;
    }

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
            // The zero-extension is the *source* operand's width, which the
            // read now carries. Casting to the destination width instead —
            // what this did — truncates `movzbl %dil,%edi` to 32 bits and
            // never touches the 8 that were the point.
            write_operand(&instr, 0, read_operand(&instr, 1), &mut out);
        }
        Mnemonic::Movsx | Mnemonic::Movsxd => {
            let bits = op_bits(&instr, 1);
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
            // A `sub` sets flags from `dst - src` — **identically to `cmp dst,
            // src`**, which is the same operation without the store. Recording
            // them as a stored *result* kept only the zero and sign conditions,
            // because carry and overflow are not functions of the result alone;
            // recording them as the comparison they are keeps the whole `jcc`
            // family. It matters because that is how clang writes a switch's
            // bounds check — `sub $0xe, %eax; ja default` — so every one of its
            // dispatches came out with no condition at all.
            //
            // The operands must be the ones the subtraction *read*, so they are
            // taken before the write rather than by re-reading afterwards.
            // The flags go **first**. SSA renames by statement position, so a
            // compare emitted after the store would re-read the destination and
            // resolve to the value the subtraction had just written — the same
            // trap `result_flags` documents, arrived at from the other side.
            out.push(compare_flags(
                CmpKind::Cmp,
                read_operand(&instr, 0),
                read_operand(&instr, 1),
            ));
            binary_rmw(&instr, BinOp::Sub, &mut out);
        }
        // `adc`/`sbb` read the **carry**, and dropping it is not a rounding
        // error: `sbb rax,rax` is the canonical "materialize CF" idiom, and as
        // a plain subtraction it lifts to a constant zero — a different program
        // on every input. CF is exactly the `jb` condition, so the carry rides
        // the `setcc:` marker the SSA builder already resolves against the
        // reaching flags. Where CF is not recoverable (an arithmetic result
        // carries no borrow), that marker stays a placeholder and the value is
        // honestly unknown instead of confidently wrong.
        Mnemonic::Adc => {
            carry_rmw(&instr, BinOp::Add, &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Sbb => {
            carry_rmw(&instr, BinOp::Sub, &mut out);
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
        // The **branchless** float compare: `cmpsd xmm0, xmm1, 4` writes a mask
        // of all-ones or all-zeros rather than flags, and clang reaches for it
        // wherever a comparison feeds arithmetic instead of a branch. iced
        // spells it `Cmpsd` with the predicate as an immediate; the disassembly
        // shows the pseudo-mnemonic `cmpneqsd`, which is the same instruction.
        //
        // The predicate travels in the intrinsic's *name*, in the same
        // vocabulary `float_branch_condition` uses — `o` ordered, `u` "or
        // unordered" — because SSE's `NEQ` is true for a NaN and its `EQ` is
        // not, and a name that said only "neq" would lose that. An immediate
        // outside the eight SSE predicates (AVX extends the range) stays
        // unlifted rather than guessed.
        Mnemonic::Cmpsd
        | Mnemonic::Cmpss
        | Mnemonic::Vcmpsd
        | Mnemonic::Vcmpss
        | Mnemonic::Cmppd
        | Mnemonic::Cmpps
        | Mnemonic::Vcmppd
        | Mnemonic::Vcmpps
            if instr.op_count() >= 3 && is_vector_reg(instr.op_register(0)) =>
        {
            // The packed forms differ from the scalar ones only in how many
            // lanes they write, and the suffix says which.
            let width = match mn {
                Mnemonic::Cmpsd | Mnemonic::Vcmpsd => "sd",
                Mnemonic::Cmpss | Mnemonic::Vcmpss => "ss",
                Mnemonic::Cmppd | Mnemonic::Vcmppd => "pd",
                _ => "ps",
            };
            match sse_compare_predicate(instr.immediate8()) {
                Some(pred) => {
                    let last = instr.op_count() - 1;
                    let first = u32::from(instr.encoding() != EncodingKind::Legacy);
                    let args: Vec<MicroExpr> =
                        (first..last).map(|i| smart_read(&instr, i)).collect();
                    smart_write(
                        &instr,
                        0,
                        MicroExpr::intrinsic(format!("__fcmpmask_{pred}_{width}"), args),
                        &mut out,
                    );
                }
                None => lift_opaque(arch, insn, mn, &mut out),
            }
        }
        Mnemonic::Shld => {
            double_shift(&instr, true, &mut out);
            out.push(opaque_flags(mn));
        }
        Mnemonic::Shrd => {
            double_shift(&instr, false, &mut out);
            out.push(opaque_flags(mn));
        }
        Mnemonic::Shl | Mnemonic::Sal => {
            shift_rmw(&instr, BinOp::Shl, &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Shr => {
            shift_rmw(&instr, BinOp::Shr, &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Sar => {
            shift_rmw(&instr, BinOp::Sar, &mut out);
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
        // `neg` and `not` are the only unary operations that reach both a
        // scalar register and a vector one — `andnps` lowers to `~a & b` — and
        // a bitwise complement means something different at each width. The
        // scalar form states its width here; the vector form has none to state
        // and is a full-register operation by construction. Without this a
        // 64-bit `not` at a 128-bit interpretation sets bits nothing ever
        // clears, and a `neg` produces a 128-bit two's complement.
        Mnemonic::Neg => {
            let cur = read_operand(&instr, 0);
            write_operand(&instr, 0, at_width(&instr, MicroExpr::unary(UnOp::Neg, cur)), &mut out);
            result_flags(&instr, mn, &mut out);
        }
        Mnemonic::Not => {
            let cur = read_operand(&instr, 0);
            write_operand(&instr, 0, at_width(&instr, MicroExpr::unary(UnOp::Not, cur)), &mut out);
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
        Mnemonic::Nop => {}
        // `push`/`pop` move the stack pointer and touch memory, and lifting them
        // to nothing made both invisible. Two consequences, neither of which
        // shows up as an error:
        //
        // * after `push rbp ; mov rsp,rbp`, the frame pointer is **8 too high**,
        //   so every `[rbp-N]` local is off by one slot — consistently, which is
        //   why nothing inside the tool ever disagreed. Measured against DWARF's
        //   `DW_OP_fbreg` addresses, which are the compiler's own.
        // * a callee-saved register `push`ed and `pop`ped around a call was
        //   never restored, so its value after the epilogue was whatever the
        //   call left there.
        //
        // `leave` in this same file already models the whole sequence, so this
        // is the file agreeing with itself rather than a new policy. The exact
        // stack delta comes from the decoder, not from the operand size — the
        // two differ for `push imm8`, and guessing is how an off-by-one returns.
        Mnemonic::Push => {
            let delta = i128::from(instr.stack_pointer_increment());
            let bits = (delta.unsigned_abs() as Bits) * 8;
            let value = read_operand(&instr, 0);
            let slot = MicroExpr::binary(
                BinOp::Add,
                MicroExpr::var(stack_pointer(&instr)),
                MicroExpr::constant(delta, 64),
            );
            // The store is emitted first so both it and the update below read the
            // *pre-push* stack pointer — which is also what makes `push rsp`
            // store the old value, as the manual specifies.
            out.push(MicroStmt::Store { addr: slot.clone(), value, bits });
            out.push(MicroStmt::Assign { dst: stack_pointer(&instr), value: slot });
        }
        Mnemonic::Pop => {
            let delta = i128::from(instr.stack_pointer_increment());
            let bits = (delta.unsigned_abs() as Bits) * 8;
            let sp = stack_pointer(&instr);
            let loaded = MicroExpr::load(MicroExpr::var(sp.clone()), bits, false);
            write_operand(&instr, 0, loaded, &mut out);
            // `pop rsp` loads the new stack pointer and must not then be adjusted
            // — the manual makes the loaded value final.
            let pops_sp = instr.op0_kind() == OpKind::Register
                && reg_name(instr.op0_register()) == sp;
            if !pops_sp {
                out.push(MicroStmt::Assign {
                    dst: sp.clone(),
                    value: MicroExpr::binary(
                        BinOp::Add,
                        MicroExpr::var(sp),
                        MicroExpr::constant(delta, 64),
                    ),
                });
            }
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
                    value: MicroExpr::Unknown(crate::CALL_CLOBBER.to_string()),
                });
            }
            out.push(opaque_flags(mn));
        }
        Mnemonic::Jmp => {
            // A **direct** jump is structural: the CFG carries the edge
            // (`CfgArtifact::blocks[..].successors` / `.callsites`) and the
            // address is in the instruction, so there is nothing to compute.
            //
            // An **indirect** one is not. `jmp *(%rdx,%rax,8)` computes an
            // address that appears nowhere else in the IR, and dropping it left
            // every switch dispatch with successors that nothing could check:
            // the resolved cases are a *claim* about where control goes, and
            // without the address there is no second opinion. Recording it is
            // what lets an execution of the IR land on a case and say whether
            // it is one the resolver found.
            if insn.target.is_none() && instr.op_count() > 0 {
                out.push(MicroStmt::Assign {
                    dst: JUMP_TARGET_VAR.to_string(),
                    value: read_operand(&instr, 0),
                });
            }
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
        // Vector *bitwise* ops are exact bit-operations (no intrinsic), in both
        // the legacy and the VEX/EVEX spelling. A **masked** EVEX form is
        // excluded throughout this group: with a `{k}` operand the operation is
        // conditional per element, and an unconditional lift would state which
        // lanes changed when the mask decides that at run time.
        Mnemonic::Pxor
        | Mnemonic::Xorps
        | Mnemonic::Xorpd
        | Mnemonic::Vpxor
        | Mnemonic::Vpxord
        | Mnemonic::Vpxorq
        | Mnemonic::Vxorps
        | Mnemonic::Vxorpd
            if instr.op_mask() == Register::None =>
        {
            vec_binop(&instr, BinOp::Xor, &mut out)
        }
        Mnemonic::Por
        | Mnemonic::Orps
        | Mnemonic::Orpd
        | Mnemonic::Vpor
        | Mnemonic::Vpord
        | Mnemonic::Vporq
        | Mnemonic::Vorps
        | Mnemonic::Vorpd
            if instr.op_mask() == Register::None =>
        {
            vec_binop(&instr, BinOp::Or, &mut out)
        }
        Mnemonic::Pand
        | Mnemonic::Andps
        | Mnemonic::Andpd
        | Mnemonic::Vpand
        | Mnemonic::Vpandd
        | Mnemonic::Vpandq
        | Mnemonic::Vandps
        | Mnemonic::Vandpd
            if instr.op_mask() == Register::None =>
        {
            vec_binop(&instr, BinOp::And, &mut out)
        }
        // `pandn dst, src` = (~dst) & src (same for the float-typed forms —
        // bitwise is bitwise regardless of the lane type).
        Mnemonic::Pandn
        | Mnemonic::Andnps
        | Mnemonic::Andnpd
        | Mnemonic::Vpandn
        | Mnemonic::Vpandnd
        | Mnemonic::Vpandnq
        | Mnemonic::Vandnps
        | Mnemonic::Vandnpd
            if instr.op_mask() == Register::None =>
        {
            vec_andn(&instr, &mut out)
        }
        // Packed compare (produces a mask) and the mask extracts — the core of
        // the SSE2/AVX2 string-scan idioms — as named intrinsics.
        Mnemonic::Pmovmskb => intr_unary(&instr, "__pmovmskb", &mut out),
        Mnemonic::Vpmovmskb | Mnemonic::Vmovmskps | Mnemonic::Vmovmskpd | Mnemonic::Movmskps | Mnemonic::Movmskpd => {
            vec_intr_unary(&instr, &mnemonic_intrinsic(mn), &mut out)
        }
        Mnemonic::Pcmpeqb
        | Mnemonic::Pcmpgtb
        | Mnemonic::Pcmpeqw
        | Mnemonic::Pcmpgtw
        | Mnemonic::Pcmpeqd
        | Mnemonic::Pcmpgtd
        | Mnemonic::Vpcmpeqb
        | Mnemonic::Vpcmpgtb
        | Mnemonic::Vpcmpeqw
        | Mnemonic::Vpcmpgtw
        | Mnemonic::Vpcmpeqd
        | Mnemonic::Vpcmpgtd
        | Mnemonic::Vpcmpeqq
        | Mnemonic::Vpcmpgtq
            if instr.op_mask() == Register::None =>
        {
            vec_intr(&instr, &mnemonic_intrinsic(mn), &mut out)
        }
        // Scalar FP compares write only flags, and the relation itself is a
        // float comparison this integer IR cannot state — so the flags value
        // stays an opaque intrinsic rather than a `Compare` anything downstream
        // could mistake for an integer relation.
        //
        // What it must NOT do is drop the operands, which is what emitting a
        // bare `opaque_flags` did. `ucomisd xmm1, xmm0` **reads** `xmm0`; with
        // the operands gone, a value whose only consumer is a float comparison
        // had zero uses in the SSA graph. Ten of eleven functions where the
        // return-register rule still answered wrongly on a Qt build traced back
        // to exactly that: a `0.0` compared against and never stored looked like
        // a value computed for the caller. An intrinsic call carries the
        // operands through every walker that already handles `Call`, which is
        // all of them.
        Mnemonic::Ucomisd | Mnemonic::Ucomiss | Mnemonic::Comisd | Mnemonic::Comiss | Mnemonic::Vucomisd | Mnemonic::Vucomiss | Mnemonic::Vcomisd | Mnemonic::Vcomiss => {
            // Every operand is a source here — a compare writes none of them,
            // so `vec_sources`' "skip the VEX destination" rule does not apply.
            let args: Vec<MicroExpr> = (0..instr.op_count()).map(|i| smart_read(&instr, i)).collect();
            out.push(MicroStmt::Assign {
                dst: FLAGS_VAR.to_string(),
                value: MicroExpr::intrinsic(mnemonic_intrinsic(mn), args),
            });
        }
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
        // The same arithmetic, shuffles, packed integer adds and lane
        // insert/extract in the VEX/EVEX spelling — three-operand and
        // non-destructive, which `vec_sources` is what accounts for.
        Mnemonic::Vaddsd
        | Mnemonic::Vsubsd
        | Mnemonic::Vmulsd
        | Mnemonic::Vdivsd
        | Mnemonic::Vminsd
        | Mnemonic::Vmaxsd
        | Mnemonic::Vaddss
        | Mnemonic::Vsubss
        | Mnemonic::Vmulss
        | Mnemonic::Vdivss
        | Mnemonic::Vminss
        | Mnemonic::Vmaxss
        | Mnemonic::Vaddpd
        | Mnemonic::Vsubpd
        | Mnemonic::Vmulpd
        | Mnemonic::Vdivpd
        | Mnemonic::Vminpd
        | Mnemonic::Vmaxpd
        | Mnemonic::Vaddps
        | Mnemonic::Vsubps
        | Mnemonic::Vmulps
        | Mnemonic::Vdivps
        | Mnemonic::Vminps
        | Mnemonic::Vmaxps
        | Mnemonic::Paddb
        | Mnemonic::Paddw
        | Mnemonic::Paddd
        | Mnemonic::Paddq
        | Mnemonic::Psubb
        | Mnemonic::Psubw
        | Mnemonic::Psubd
        | Mnemonic::Psubq
        | Mnemonic::Vpaddb
        | Mnemonic::Vpaddw
        | Mnemonic::Vpaddd
        | Mnemonic::Vpaddq
        | Mnemonic::Vpsubb
        | Mnemonic::Vpsubw
        | Mnemonic::Vpsubd
        | Mnemonic::Vpsubq
        | Mnemonic::Vpunpcklqdq
        | Mnemonic::Vpunpckhqdq
        | Mnemonic::Vpunpckldq
        | Mnemonic::Vpunpckhdq
        | Mnemonic::Vpunpcklbw
        | Mnemonic::Vpunpcklwd
        | Mnemonic::Vunpcklpd
        | Mnemonic::Vunpckhpd
        | Mnemonic::Vunpcklps
        | Mnemonic::Vunpckhps
        | Mnemonic::Vshufps
        | Mnemonic::Vshufpd
        | Mnemonic::Vpshufd
        | Mnemonic::Vpshufb
        | Mnemonic::Pshufd
        | Mnemonic::Pshufb
        | Mnemonic::Vpextrb
        | Mnemonic::Vpextrw
        | Mnemonic::Vpextrd
        | Mnemonic::Vpextrq
        | Mnemonic::Vpinsrb
        | Mnemonic::Vpinsrw
        | Mnemonic::Vpinsrd
        | Mnemonic::Vpinsrq
        | Mnemonic::Pextrb
        | Mnemonic::Pextrw
        | Mnemonic::Pextrd
        | Mnemonic::Pextrq
        // Lane insert/partial move. These write only *part* of the destination,
        // so the destination is genuinely one of the inputs and the intrinsic
        // keeps every source it reads — which is what `vec_intr` does in either
        // encoding.
        | Mnemonic::Insertps
        | Mnemonic::Vinsertps
        | Mnemonic::Movlps
        | Mnemonic::Movhps
        | Mnemonic::Movlpd
        | Mnemonic::Movhpd
        | Mnemonic::Vmovlps
        | Mnemonic::Vmovhps
        | Mnemonic::Vmovlpd
        | Mnemonic::Vmovhpd
        | Mnemonic::Movlhps
        | Mnemonic::Movhlps
        | Mnemonic::Vmovlhps
        | Mnemonic::Vmovhlps
            if instr.op_mask() == Register::None =>
        {
            vec_intr(&instr, &mnemonic_intrinsic(mn), &mut out)
        }
        // Permutes, blends, packs, shifts and lane-widening — everything whose
        // result is a rearrangement of its sources rather than a value this IR
        // can state. One intrinsic per instruction keeps the dataflow exact
        // while claiming nothing about the lane arithmetic.
        Mnemonic::Vperm2i128
        | Mnemonic::Vperm2f128
        | Mnemonic::Vpermq
        | Mnemonic::Vpermd
        | Mnemonic::Vpermpd
        | Mnemonic::Vpermps
        | Mnemonic::Vextracti128
        | Mnemonic::Vextractf128
        | Mnemonic::Vinserti128
        | Mnemonic::Vinsertf128
        | Mnemonic::Vpblendw
        | Mnemonic::Vpblendd
        | Mnemonic::Vpermilpd
        | Mnemonic::Vpermilps
        | Mnemonic::Vpsubusb
        | Mnemonic::Vpsubusw
        | Mnemonic::Vpaddusb
        | Mnemonic::Vpaddusw
        | Mnemonic::Vpsubsb
        | Mnemonic::Vpsubsw
        | Mnemonic::Vpaddsb
        | Mnemonic::Vpaddsw
        | Mnemonic::Vpmuldq
        | Mnemonic::Vpmuludq
        | Mnemonic::Vpmulhw
        | Mnemonic::Vpmulhuw
        | Mnemonic::Vpavgb
        | Mnemonic::Vpavgw
        | Mnemonic::Vblendvps
        | Mnemonic::Vblendvpd
        | Mnemonic::Vpblendvb
        | Mnemonic::Blendvps
        | Mnemonic::Blendvpd
        | Mnemonic::Pblendvb
        | Mnemonic::Vroundsd
        | Mnemonic::Vroundss
        | Mnemonic::Vroundpd
        | Mnemonic::Vroundps
        | Mnemonic::Roundsd
        | Mnemonic::Roundss
        | Mnemonic::Roundpd
        | Mnemonic::Roundps
        | Mnemonic::Vblendps
        | Mnemonic::Vblendpd
        | Mnemonic::Vpblendvb
        | Mnemonic::Vpalignr
        | Mnemonic::Vpackuswb
        | Mnemonic::Vpackusdw
        | Mnemonic::Vpacksswb
        | Mnemonic::Vpackssdw
        | Mnemonic::Vpshufhw
        | Mnemonic::Vpshuflw
        | Mnemonic::Vpsrld
        | Mnemonic::Vpsrlq
        | Mnemonic::Vpsrlw
        | Mnemonic::Vpslld
        | Mnemonic::Vpsllq
        | Mnemonic::Vpsllw
        | Mnemonic::Vpsrad
        | Mnemonic::Vpsraw
        | Mnemonic::Vpsrldq
        | Mnemonic::Vpslldq
        | Mnemonic::Psrld
        | Mnemonic::Psrlq
        | Mnemonic::Psrlw
        | Mnemonic::Pslld
        | Mnemonic::Psllq
        | Mnemonic::Psllw
        | Mnemonic::Psrad
        | Mnemonic::Psraw
        | Mnemonic::Psrldq
        | Mnemonic::Pslldq
        | Mnemonic::Vpmulld
        | Mnemonic::Vpmullw
        | Mnemonic::Vpmuludq
        | Mnemonic::Vpmaddwd
        | Mnemonic::Vpavgb
        | Mnemonic::Vpavgw
        | Mnemonic::Vpsadbw
        | Mnemonic::Vpminub
        | Mnemonic::Vpmaxub
        | Mnemonic::Vpminsb
        | Mnemonic::Vpmaxsb
        | Mnemonic::Vpminuw
        | Mnemonic::Vpmaxuw
        | Mnemonic::Vpminsw
        | Mnemonic::Vpmaxsw
        | Mnemonic::Vpminud
        | Mnemonic::Vpmaxud
        | Mnemonic::Vpminsd
        | Mnemonic::Vpmaxsd
            if instr.op_mask() == Register::None =>
        {
            vec_intr(&instr, &mnemonic_intrinsic(mn), &mut out)
        }
        // Lane-widening and duplicating reads: one source.
        Mnemonic::Vpmovzxbw
        | Mnemonic::Vpmovzxwd
        | Mnemonic::Vpmovzxdq
        | Mnemonic::Vpmovzxbd
        | Mnemonic::Vpmovsxbw
        | Mnemonic::Vpmovsxwd
        | Mnemonic::Vpmovsxdq
        | Mnemonic::Vpmovsxbd
        | Mnemonic::Vmovddup
        | Mnemonic::Vmovshdup
        | Mnemonic::Vmovsldup
        | Mnemonic::Pmovzxbw
        | Mnemonic::Pmovzxwd
        | Mnemonic::Pmovzxdq
        | Mnemonic::Pmovsxbw
        | Mnemonic::Pmovsxwd
        | Mnemonic::Pmovsxdq
        | Mnemonic::Movddup
            if instr.op_mask() == Register::None =>
        {
            vec_intr_unary(&instr, &mnemonic_intrinsic(mn), &mut out)
        }
        // `ptest`/`vptest` write only flags.
        Mnemonic::Ptest | Mnemonic::Vptest => out.push(opaque_flags(mn)),
        // `leave` = `mov rsp, rbp; pop rbp` — exact, not an intrinsic. The order
        // matters and is the whole trap: after the first statement `rsp` *is*
        // the old frame pointer, so the load and the adjust both read `rsp`.
        // Reading `rbp` in the last one would read the value just popped into it.
        Mnemonic::Leave => {
            out.push(MicroStmt::Assign { dst: "rsp".into(), value: MicroExpr::var("rbp") });
            out.push(MicroStmt::Assign { dst: "rbp".into(), value: MicroExpr::load(MicroExpr::var("rsp"), 64, false) });
            out.push(MicroStmt::Assign {
                dst: "rsp".into(),
                value: MicroExpr::binary(BinOp::Add, MicroExpr::var("rsp"), MicroExpr::constant(8, 64)),
            });
        }
        // A broadcast and a square root read one source and splat/compute it.
        Mnemonic::Vpbroadcastb
        | Mnemonic::Vpbroadcastw
        | Mnemonic::Vpbroadcastd
        | Mnemonic::Vpbroadcastq
        | Mnemonic::Vbroadcastss
        | Mnemonic::Vbroadcastsd
        | Mnemonic::Vsqrtsd
        | Mnemonic::Vsqrtss
        | Mnemonic::Vsqrtpd
        | Mnemonic::Vsqrtps
            if instr.op_mask() == Register::None =>
        {
            vec_intr_unary(&instr, &mnemonic_intrinsic(mn), &mut out)
        }
        Mnemonic::Sqrtsd | Mnemonic::Sqrtss => intr_unary(&instr, &mnemonic_intrinsic(mn), &mut out),
        // Int↔FP conversions (scalar and packed): `dst = __cvt*(src)`.
        // The integer source of `cvtsi2*` is signed; everything else in this
        // family converts between forms that carry their own sign.
        Mnemonic::Cvtsi2sd | Mnemonic::Cvtsi2ss => {
            intr_unary_signed(&instr, &mnemonic_intrinsic(mn), &mut out)
        }
        Mnemonic::Cvtsd2si
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
        | Mnemonic::Cvttpd2dq
        | Mnemonic::Pabsb
        | Mnemonic::Pabsw
        | Mnemonic::Pabsd => intr_unary(&instr, &mnemonic_intrinsic(mn), &mut out),
        // …and their VEX/EVEX spellings, where the extra operand is only the
        // merge source for the lanes the conversion does not write.
        Mnemonic::Vcvtsi2sd | Mnemonic::Vcvtsi2ss => {
            vec_intr_unary_signed(&instr, &mnemonic_intrinsic(mn), &mut out)
        }
        Mnemonic::Vcvtsd2si
        | Mnemonic::Vcvtss2si
        | Mnemonic::Vcvttsd2si
        | Mnemonic::Vcvttss2si
        | Mnemonic::Vcvtsd2ss
        | Mnemonic::Vcvtss2sd
        | Mnemonic::Vcvtdq2ps
        | Mnemonic::Vcvtps2dq
        | Mnemonic::Vcvttps2dq
        | Mnemonic::Vcvtdq2pd
        | Mnemonic::Vcvtpd2dq
        | Mnemonic::Vcvttpd2dq
        // Half-precision conversions. `vcvtps2ph` also takes a rounding-control
        // immediate, which `vec_intr_unary` drops on purpose — the *value* is
        // the vector, and the rounding mode is not modelled anywhere in this IR.
        | Mnemonic::Vcvtph2ps
        | Mnemonic::Vcvtps2ph
        // Packed absolute value, both encodings' VEX spelling.
        | Mnemonic::Vpabsb
        | Mnemonic::Vpabsw
        | Mnemonic::Vpabsd
        | Mnemonic::Vpabsq
        | Mnemonic::Vcvtpd2ps
        | Mnemonic::Vcvtps2pd
            if instr.op_mask() == Register::None =>
        {
            vec_intr_unary(&instr, &mnemonic_intrinsic(mn), &mut out)
        }
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
            // The high half is the product's *upper `width` bits*, and `width`
            // is not recoverable from the operands: a 32-bit `mul` leaves
            // `(a*b) >> 32` in `edx`, a 64-bit one `(a*b) >> 64` in `rdx`. It
            // travels as a third argument for the same reason the divide's does.
            let width = op_bits(&instr, 0);
            let narrow = |v: MicroExpr| {
                if width < WORD_BITS {
                    MicroExpr::Cast { signed: false, bits: width, expr: Box::new(v) }
                } else {
                    v
                }
            };
            let w = MicroExpr::constant(i128::from(width), 8);
            // **Order matters and needs one temporary**, exactly as it does for
            // the divide below — and here it did not have one. Both halves read
            // the *pre*-multiply `rax` **and** `src`, and `src` is frequently
            // `rdx`: writing the high half first left the low half reading the
            // value it had just written. clang builds the closed form of a
            // summation loop as `mul %edx`, so the wrong answer was the whole
            // loop's result. The high half is parked, the low half written while
            // both inputs are still live, and the high half moved in last.
            out.push(MicroStmt::Assign {
                dst: MUL_TEMP.into(),
                value: narrow(MicroExpr::intrinsic("__umulh", vec![rax.clone(), src.clone(), w])),
            });
            out.push(MicroStmt::Assign {
                dst: "rax".into(),
                value: narrow(MicroExpr::binary(BinOp::Mul, rax, src)),
            });
            out.push(MicroStmt::Assign { dst: "rdx".into(), value: MicroExpr::var(MUL_TEMP) });
            out.push(opaque_flags(mn));
        }
        // 1-operand divide: `rax = rdx:rax / src`, `rdx = rdx:rax % src`. The
        // dividend is **twice the operand width** — 128 bits for `idivq`, 64 for
        // `idivl` — and this IR has no value that wide, so both halves are
        // intrinsics over the three real inputs, sound and exact about *what is
        // read* and vague only about the arithmetic itself.
        //
        // The width travels as a fourth argument, because it is not recoverable
        // from the other three: a 32-bit divide reads `edx:eax`, and reading the
        // whole of `rdx` and `rax` instead made the dividend astronomically
        // larger, so every 32-bit signed division reported a quotient that does
        // not fit. It is an argument rather than a name so that everything which
        // walks a call's operands keeps seeing operands.
        //
        // **Order matters and needs one temporary.** Both results read the
        // *pre*-division `rdx` **and** `rax`, so writing either register first
        // would clobber the other's input; the quotient is parked, the remainder
        // written while both inputs are still live, and the quotient moved in
        // last. Division by zero traps on the hardware and nothing is invented
        // here to model that: the flags are left opaque, exactly as the manual
        // leaves them undefined.
        //
        // Only the 32/64-bit forms are lifted — the 8- and 16-bit ones write
        // `ax`/`ah` sub-registers this model would have to guess at.
        Mnemonic::Div | Mnemonic::Idiv if op_bits(&instr, 0) >= 32 => {
            let signed = mn == Mnemonic::Idiv;
            let (quot, rem) = if signed { ("__idiv", "__irem") } else { ("__udiv", "__urem") };
            let src = read_operand(&instr, 0);
            let width = op_bits(&instr, 0);
            let args = || {
                vec![
                    MicroExpr::var("rdx"),
                    MicroExpr::var("rax"),
                    src.clone(),
                    MicroExpr::constant(i128::from(width), 8),
                ]
            };
            // A 32-bit divide writes `eax`/`edx`, which is a 32-bit value —
            // and, in 64-bit mode, one that clears the upper half. These
            // assignments name the register directly rather than going through
            // `reg_write`, so the narrowing has to be here.
            let narrow = |v: MicroExpr| {
                if width < WORD_BITS {
                    MicroExpr::Cast { signed: false, bits: width, expr: Box::new(v) }
                } else {
                    v
                }
            };
            out.push(MicroStmt::Assign { dst: DIV_TEMP.into(), value: narrow(MicroExpr::intrinsic(quot, args())) });
            out.push(MicroStmt::Assign { dst: "rdx".into(), value: narrow(MicroExpr::intrinsic(rem, args())) });
            out.push(MicroStmt::Assign { dst: "rax".into(), value: MicroExpr::var(DIV_TEMP) });
            out.push(opaque_flags(mn));
        }
        // `movbe` — a load or store that swaps byte order on the way. Exactly a
        // move through `__bswap`, and the same intrinsic `bswap` itself uses.
        Mnemonic::Movbe => {
            let src = read_operand(&instr, 1);
            write_operand(&instr, 0, MicroExpr::intrinsic("__bswap", vec![src]), &mut out);
        }
        // BMI2 `rorx dst, src, imm8` — rotate right, **no flags**, which is the
        // whole reason the encoding exists. Exact as two shifts and an or.
        Mnemonic::Rorx if instr.op_count() == 3 => {
            let width = op_bits(&instr, 0);
            let n = (instr.immediate8() as u32) & width.saturating_sub(1);
            if n == 0 {
                write_operand(&instr, 0, read_operand(&instr, 1), &mut out);
            } else {
                let shift = |op, amount: u32| MicroExpr::binary(op, read_operand(&instr, 1), MicroExpr::constant(amount as i128, width));
                let value = MicroExpr::binary(BinOp::Or, shift(BinOp::Shr, n), shift(BinOp::Shl, width - n));
                write_operand(&instr, 0, value, &mut out);
            }
        }
        // `bt` reads a bit into CF and writes **nothing else** — so the honest
        // lift is the flag write alone. Going through the opaque path instead
        // would preserve the text and invalidate registers it never touches.
        Mnemonic::Bt => out.push(opaque_flags(mn)),
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
        // BMI1 `andn dst, src1, src2` — `dst = ~src1 & src2`, exactly; sets flags.
        Mnemonic::Andn if instr.op_count() == 3 => {
            let value = MicroExpr::binary(BinOp::And, MicroExpr::unary(UnOp::Not, read_operand(&instr, 1)), read_operand(&instr, 2));
            write_operand(&instr, 0, value, &mut out);
            out.push(opaque_flags(mn));
        }
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
            write_operand(
                &instr,
                0,
                MicroExpr::intrinsic(
                    "__umulh",
                    vec![rdx.clone(), src.clone(), MicroExpr::constant(i128::from(op_bits(&instr, 0)), 8)],
                ),
                &mut out,
            );
            write_operand(&instr, 1, MicroExpr::binary(BinOp::Mul, rdx, src), &mut out);
        }
        // Bit test-and-reset/set/complement, immediate index: the value change is
        // exact (`dst &= ~(1<<n)` / `|=` / `^=`); the CF it also sets (the old
        // bit) stays opaque. A register index falls through to the opaque path.
        // A **register** bit index, register destination: the index is masked to
        // the operand width by the hardware, so the mask is `1 << (src & (w-1))`
        // — still exact. A *memory* destination is deliberately excluded: there
        // the index is a signed bit offset that also displaces the address, and
        // modelling only the mask would be quietly wrong.
        Mnemonic::Btr | Mnemonic::Bts | Mnemonic::Btc
            if instr.op0_kind() == OpKind::Register && instr.op1_kind() == OpKind::Register =>
        {
            let bits = op_bits(&instr, 0);
            let index = MicroExpr::binary(BinOp::And, read_operand(&instr, 1), MicroExpr::constant((bits.saturating_sub(1)) as i128, bits));
            let mask = MicroExpr::binary(BinOp::Shl, MicroExpr::constant(1, bits), index);
            let dst = read_operand(&instr, 0);
            let value = match mn {
                Mnemonic::Btr => MicroExpr::binary(BinOp::And, dst, MicroExpr::unary(UnOp::Not, mask)),
                Mnemonic::Bts => MicroExpr::binary(BinOp::Or, dst, mask),
                _ => MicroExpr::binary(BinOp::Xor, dst, mask),
            };
            write_operand(&instr, 0, value, &mut out);
            out.push(opaque_flags(mn));
        }
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
            } else if width == 32 || width == 64 {
                // A `CL`-count rotate at a full width. The masking the hardware
                // applies is the same one `shift_rmw` applies, and the value is
                // then exact: `(x << c) | (x >> (w - c))`, which for `c == 0`
                // is `x | 0` because a shift by the full width is zero. The
                // flags are what stay opaque — a rotate by zero leaves them
                // alone — and they are opaque here as they were before.
                let count = MicroExpr::binary(
                    BinOp::And,
                    read_operand(&instr, 1),
                    MicroExpr::constant(i128::from(width) - 1, 8),
                );
                let complement = MicroExpr::binary(
                    BinOp::Sub,
                    MicroExpr::constant(i128::from(width), 8),
                    count.clone(),
                );
                let shift = |op, amount: MicroExpr| {
                    MicroExpr::binary(op, read_operand(&instr, 0), amount)
                };
                let value = match mn {
                    Mnemonic::Rol => MicroExpr::binary(
                        BinOp::Or,
                        shift(BinOp::Shl, count),
                        shift(BinOp::Shr, complement),
                    ),
                    _ => MicroExpr::binary(
                        BinOp::Or,
                        shift(BinOp::Shr, count),
                        shift(BinOp::Shl, complement),
                    ),
                };
                write_operand(&instr, 0, value, &mut out);
                out.push(opaque_flags(mn));
            } else {
                // A narrow rotate (8- or 16-bit) cannot be written as two
                // shifts without modelling x86's count masking — including the
                // masked-to-zero case, where a shift by the full width is not
                // what this IR's `Shr` means. It is a *named operation on two
                // values* rather than an unknown instruction, so it reads as an
                // intrinsic and keeps its dataflow instead of invalidating the
                // register through the opaque path.
                let value = MicroExpr::intrinsic(mnemonic_intrinsic(mn), vec![read_operand(&instr, 0), read_operand(&instr, 1)]);
                write_operand(&instr, 0, value, &mut out);
                out.push(opaque_flags(mn));
            }
        }
        // FMA and the predicate-carrying compares, matched by name — see
        // [`is_fma`] and [`is_vcmp`]. Both are ALU-shaped and both keep every
        // operand they read: an FMA accumulates into its destination, a compare
        // does not.
        _ if is_fma(mn) && instr.op_mask() == Register::None => vec_intr_accum(&instr, &mnemonic_intrinsic(mn), &mut out),
        _ if is_vcmp(mn) && instr.op_mask() == Register::None => vec_intr(&instr, &mnemonic_intrinsic(mn), &mut out),
        _ => lift_opaque(arch, insn, mn, &mut out),
    }

    out
}

/// A `lock`-prefixed read-modify-write. The destination is written from the
/// same operands as the unlocked form, but through `__atomic_<mnemonic>`, so the
/// atomicity is stated rather than silently dropped. Flags stay opaque — the
/// manual's flag effects are the same, and nothing here needs them precise.
///
/// `xchg` is the one form that is atomic *without* a prefix and is handled by
/// its own arm; `cmpxchg` and `xadd` read and write more state than this shape
/// models, so they take the opaque path where they would otherwise lie.
fn lift_locked(arch: &crate::X64, insn: &DecodedInsn, instr: &Instruction, mn: Mnemonic, out: &mut Vec<MicroStmt>) {
    let name = format!("__atomic_{}", format!("{mn:?}").to_lowercase());
    let modelled = matches!(
        mn,
        Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Add | Mnemonic::Sub | Mnemonic::Adc | Mnemonic::Sbb
            | Mnemonic::And | Mnemonic::Or | Mnemonic::Xor | Mnemonic::Neg | Mnemonic::Not
            | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc
    );
    if !modelled || instr.op_count() == 0 {
        lift_opaque(arch, insn, mn, out);
        return;
    }
    let mut args = vec![read_operand(instr, 0)];
    if instr.op_count() > 1 {
        args.push(read_operand(instr, 1));
    }
    write_operand(instr, 0, MicroExpr::intrinsic(name, args), out);
    out.push(opaque_flags(mn));
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

/// SSE's eight compare predicates, by immediate, in the same `fcmp` vocabulary
/// `crate::flags`'s float-condition table uses. `NEQ` is true for a NaN and `EQ` is not —
/// the `o`/`u` prefix is what carries that, and dropping it would make the two
/// look like negations of each other.
fn sse_compare_predicate(imm: u8) -> Option<&'static str> {
    Some(match imm {
        0 => "oeq",
        1 => "olt",
        2 => "ole",
        3 => "uno",
        4 => "une",
        5 => "uge",
        6 => "ugt",
        7 => "ord",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::branch_condition;
    use crate::{Arch, X64};
    use n0xis_contracts::Va;

    fn lift_one(bytes: &[u8]) -> Vec<MicroStmt> {
        let arch = X64::new();
        let insns = arch.decode_stream(bytes, Va(0x1000), 4);
        arch.lift(&insns[0], "win64")
    }

    /// The low `bits` of a register, zero-extended — how a **sub-register read**
    /// now reads. `mov eax, ecx` is not a 64-bit copy, and the IR says so here.
    fn low(bits: Bits, name: &str) -> MicroExpr {
        MicroExpr::Cast { signed: false, bits, expr: Box::new(MicroExpr::var(name)) }
    }

    /// The same bits read as **signed** — what a signed branch predicate asks
    /// for, and the difference between `jl` and `jb` on `0xffffffff`.
    fn low_signed(bits: Bits, name: &str) -> MicroExpr {
        MicroExpr::Cast { signed: true, bits, expr: Box::new(MicroExpr::var(name)) }
    }

    /// Wrap a value the way a **32-bit destination write** does: x86-64 clears
    /// the upper half, so the write is a cast, not a plain assign.
    fn write32(v: MicroExpr) -> MicroExpr {
        MicroExpr::Cast { signed: false, bits: 32, expr: Box::new(v) }
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
    fn a_segment_override_is_not_a_flat_address() {
        // mov rax, fs:[0x28]  = 64 48 8B 04 25 28 00 00 00
        // The canonical stack-canary read. Lifting it as a load of absolute
        // 0x28 describes a program that would fault on the null page.
        let stmts = lift_one(&[0x64, 0x48, 0x8B, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00]);
        assert_eq!(
            stmts,
            vec![MicroStmt::Assign {
                dst: "rax".into(),
                value: MicroExpr::load(
                    MicroExpr::intrinsic("__seg_fs", vec![MicroExpr::constant(0x28, 64)]),
                    64,
                    false,
                ),
            }],
        );
    }

    #[test]
    fn a_gs_override_on_a_store_is_kept() {
        // mov gs:[0x10], rcx  = 65 48 89 0C 25 10 00 00 00
        let stmts = lift_one(&[0x65, 0x48, 0x89, 0x0C, 0x25, 0x10, 0x00, 0x00, 0x00]);
        assert_eq!(
            stmts,
            vec![MicroStmt::Store {
                addr: MicroExpr::intrinsic("__seg_gs", vec![MicroExpr::constant(0x10, 64)]),
                value: MicroExpr::var("rcx"),
                bits: 64,
            }],
        );
    }

    #[test]
    fn a_segment_override_keeps_the_whole_offset_expression() {
        // mov rax, fs:[rbx+rcx*4+0x10]  = 64 48 8B 44 8B 10
        let stmts = lift_one(&[0x64, 0x48, 0x8B, 0x44, 0x8B, 0x10]);
        let MicroStmt::Assign { value: MicroExpr::Load { addr, .. }, .. } = &stmts[0] else {
            panic!("expected a load, got {stmts:?}");
        };
        let MicroExpr::Call { target: CallTarget::Intrinsic(name), args } = &**addr else {
            panic!("expected a segment intrinsic, got {addr:?}");
        };
        assert_eq!(name, "__seg_fs");
        assert_eq!(args.len(), 1, "the offset goes in whole, base and index included");
        assert!(format!("{:?}", args[0]).contains("rbx"), "the base survives: {:?}", args[0]);
    }

    #[test]
    fn a_zero_base_segment_override_changes_nothing() {
        // mov rax, ds:[0x28]  = 3E 48 8B 04 25 28 00 00 00
        // In 64-bit mode ds has a zero base, so the prefix is decoration.
        let stmts = lift_one(&[0x3E, 0x48, 0x8B, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00]);
        assert_eq!(
            stmts,
            vec![MicroStmt::Assign {
                dst: "rax".into(),
                value: MicroExpr::load(MicroExpr::constant(0x28, 64), 64, false),
            }],
        );
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
        // vmovd xmm3, esi  = C5 F9 6E DE — the other direction. The GPR keeps
        // the one SSA name (`rsi`) *and* its width: the move is 32 bits, and an
        // unqualified `rsi` here would claim the other 32 came along.
        assert_eq!(
            lift_one(&[0xC5, 0xF9, 0x6E, 0xDE]),
            vec![MicroStmt::Assign { dst: "xmm3".into(), value: low(32, "rsi") }]
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
    fn a_vex_alu_op_reads_its_two_source_operands_not_its_destination() {
        // vpxor xmm0, xmm1, xmm2  = C5 F1 EF C2 — non-destructive: xmm0 is
        // written only. Counting it as a source would invent a dependency on
        // whatever it held before.
        assert_eq!(
            lift_one(&[0xC5, 0xF1, 0xEF, 0xC2]),
            vec![MicroStmt::Assign {
                dst: "xmm0".into(),
                value: MicroExpr::binary(BinOp::Xor, MicroExpr::var("xmm1"), MicroExpr::var("xmm2")),
            }]
        );
        // pxor xmm0, xmm1 = 66 0F EF C1 — the legacy form is read-modify-write
        // and must be unchanged by the shared path.
        assert_eq!(
            lift_one(&[0x66, 0x0F, 0xEF, 0xC1]),
            vec![MicroStmt::Assign {
                dst: "xmm0".into(),
                value: MicroExpr::binary(BinOp::Xor, MicroExpr::var("xmm0"), MicroExpr::var("xmm1")),
            }]
        );
        // vandnpd xmm1, xmm3, xmm2 = C5 E1 55 CA  →  (~xmm3) & xmm2
        assert_eq!(
            lift_one(&[0xC5, 0xE1, 0x55, 0xCA]),
            vec![MicroStmt::Assign {
                dst: "xmm1".into(),
                value: MicroExpr::binary(
                    BinOp::And,
                    MicroExpr::unary(UnOp::Not, MicroExpr::var("xmm3")),
                    MicroExpr::var("xmm2")
                ),
            }]
        );
    }

    #[test]
    fn vex_arithmetic_and_conversions_read_as_named_intrinsics() {
        // vmulsd xmm0, xmm1, xmm2 = C5 F3 59 C2
        assert_eq!(
            lift_one(&[0xC5, 0xF3, 0x59, 0xC2]),
            vec![MicroStmt::Assign {
                dst: "xmm0".into(),
                value: MicroExpr::intrinsic("__vmulsd", vec![MicroExpr::var("xmm1"), MicroExpr::var("xmm2")]),
            }]
        );
        // vcvtsi2sd xmm0, xmm2, r13d = C4 C1 6B 2A C5 — the middle operand is
        // only the merge source; the conversion reads the last one, and reads
        // it **signed**. This asserted the unsigned form until the processor
        // was asked: `cvtsi2sd` converts a signed integer, so a zero-extended
        // `r13d` turns -1 into 4294967295 and the double is out by 2^32.
        assert_eq!(
            lift_one(&[0xC4, 0xC1, 0x6B, 0x2A, 0xC5]),
            vec![MicroStmt::Assign {
                dst: "xmm0".into(),
                value: MicroExpr::intrinsic("__vcvtsi2sd", vec![low_signed(32, "r13")]),
            }]
        );
        // vpextrb eax, xmm1, 3 = C4 E3 79 14 C8 03 — the lane index is a source.
        assert_eq!(
            lift_one(&[0xC4, 0xE3, 0x79, 0x14, 0xC8, 0x03]),
            vec![MicroStmt::Assign {
                dst: "rax".into(),
                value: write32(MicroExpr::intrinsic("__vpextrb", vec![MicroExpr::var("xmm1"), MicroExpr::constant(3, 8)])),
            }]
        );
    }

    #[test]
    fn leave_restores_the_frame_in_the_right_order() {
        // leave = C9. `rsp = rbp; rbp = [rsp]; rsp = rsp + 8` — the last two
        // must read `rsp`, not the `rbp` the middle statement just overwrote.
        assert_eq!(
            lift_one(&[0xC9]),
            vec![
                MicroStmt::Assign { dst: "rsp".into(), value: MicroExpr::var("rbp") },
                MicroStmt::Assign { dst: "rbp".into(), value: MicroExpr::load(MicroExpr::var("rsp"), 64, false) },
                MicroStmt::Assign {
                    dst: "rsp".into(),
                    value: MicroExpr::binary(BinOp::Add, MicroExpr::var("rsp"), MicroExpr::constant(8, 64)),
                },
            ]
        );
    }

    #[test]
    fn a_scalar_fp_compare_writes_only_flags() {
        // vucomisd xmm0, xmm1 = C5 F9 2E C1. The relation is a float one this
        // integer IR cannot state, so nothing is claimed beyond the flag write.
        let stmts = lift_one(&[0xC5, 0xF9, 0x2E, 0xC1]);
        assert_eq!(stmts.len(), 1);
        assert!(matches!(&stmts[0], MicroStmt::Assign { dst, .. } if dst == FLAGS_VAR), "got {stmts:?}");
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
                value: write32(MicroExpr::binary(
                    BinOp::Or,
                    MicroExpr::binary(BinOp::Shl, low(32, "rax"), MicroExpr::constant(5, 32)),
                    MicroExpr::binary(BinOp::Shr, low(32, "rax"), MicroExpr::constant(27, 32)),
                )),
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
                value: write32(MicroExpr::binary(
                    BinOp::Or,
                    MicroExpr::binary(BinOp::Shr, low(32, "rax"), MicroExpr::constant(5, 32)),
                    MicroExpr::binary(BinOp::Shl, low(32, "rax"), MicroExpr::constant(27, 32)),
                )),
            },
        );
    }

    #[test]
    fn a_register_count_rotate_is_exact_once_the_count_is_masked() {
        // rol eax, cl = D3 C0. This once asserted the *opposite*: a CL-count
        // rotate stayed the opaque `__rol` intrinsic because lowering it to two
        // shifts "needs x86 count-masking to be sound". The masking is the whole
        // of it — `c = count & (width-1)`, then `(x << c) | (x >> (width - c))`,
        // which for `c == 0` is `x | 0` because a shift by the full width is
        // zero — and `shift_rmw` had been masking counts for a while. So the
        // refusal outlived its reason, and a 32-bit corpus caught it as an
        // unmodelled intrinsic rather than as the recoverable operation it is.
        let stmts = lift_one(&[0xD3, 0xC0]);
        assert!(
            !stmts.iter().any(|s| matches!(s, MicroStmt::Unlifted { .. })),
            "a variable-count rotate is lowered, not unknown: {stmts:?}",
        );
        fn find(e: &MicroExpr, f: &mut impl FnMut(&MicroExpr) -> bool) -> bool {
            if f(e) {
                return true;
            }
            match e {
                MicroExpr::Cast { expr, .. } | MicroExpr::AddrOf(expr) | MicroExpr::Unary(_, expr) => {
                    find(expr, f)
                }
                MicroExpr::Binary(_, l, r) => find(l, f) || find(r, f),
                MicroExpr::Call { args, .. } => args.iter().any(|a| find(a, f)),
                _ => false,
            }
        }
        let value = stmts
            .iter()
            .find_map(|s| match s {
                MicroStmt::Assign { dst, value } if dst == "rax" => Some(value),
                _ => None,
            })
            .expect("the rotate writes rax");
        assert!(
            !find(value, &mut |e| matches!(
                e,
                MicroExpr::Call { target: CallTarget::Intrinsic(n), .. } if n == "__rol"
            )),
            "no intrinsic is needed any more: {value:?}",
        );
        assert!(
            find(value, &mut |e| matches!(e, MicroExpr::Binary(BinOp::Shl, ..)))
                && find(value, &mut |e| matches!(e, MicroExpr::Binary(BinOp::Shr, ..))),
            "a rotate is a pair of shifts: {value:?}",
        );
        // The count is masked to the operand width minus one — the part whose
        // absence made the refusal look necessary.
        assert!(
            find(value, &mut |e| matches!(e,
                MicroExpr::Binary(BinOp::And, _, r) if **r == MicroExpr::constant(31, 8))),
            "the count is masked to 31: {value:?}",
        );
    }

    #[test]
    fn a_divide_reads_the_whole_dividend_before_writing_either_half() {
        // idiv rcx  = 48 F7 F9 — `rax = rdx:rax / rcx`, `rdx = rdx:rax % rcx`.
        // Both halves read the pre-division pair, so the quotient is parked in a
        // temporary and moved in last; writing `rax` first would feed the
        // remainder its own result.
        let stmts = lift_one(&[0x48, 0xF7, 0xF9]);
        let dsts: Vec<&str> = stmts
            .iter()
            .filter_map(|s| match s {
                MicroStmt::Assign { dst, .. } => Some(dst.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(dsts, vec![DIV_TEMP, "rdx", "rax", "flags"], "{stmts:?}");
        // Four arguments, not three: the fourth is the **operand width**. A
        // 32-bit divide reads `edx:eax`, not `rdx:rax`, and nothing else in the
        // call says which — reading both whole registers for a 32-bit divide
        // made the dividend astronomically larger and every signed division of
        // a negative number reported a quotient that does not fit.
        let reads_pair = |s: &MicroStmt| {
            matches!(s, MicroStmt::Assign { value: MicroExpr::Call { args, .. }, .. }
                if args.len() == 4
                    && args[0] == MicroExpr::var("rdx")
                    && args[1] == MicroExpr::var("rax")
                    && args[3] == MicroExpr::constant(64, 8))
        };
        assert!(reads_pair(&stmts[0]) && reads_pair(&stmts[1]), "both halves read rdx:rax: {stmts:?}");
    }

    /// `lock incl (%rax)` = F0 FF 00 — an atomic reference-count bump. Lifting
    /// the bare mnemonic rendered it `*rax = *rax + 1`, which is a different
    /// program; the prefix has to reach the output.
    #[test]
    fn a_lock_prefix_is_not_dropped() {
        let stmts = lift_one(&[0xF0, 0xFF, 0x00]);
        assert!(
            stmts.iter().any(|s| matches!(s, MicroStmt::Store { value: MicroExpr::Call { target: CallTarget::Intrinsic(n), .. }, .. }
                if n == "__atomic_inc")),
            "the atomicity must be stated, not silently dropped: {stmts:?}",
        );
        assert!(
            !stmts.iter().any(|s| matches!(s, MicroStmt::Store { value: MicroExpr::Binary(BinOp::Add, ..), .. })),
            "and it must not also read as a plain addition: {stmts:?}",
        );
        // Without the prefix the same bytes stay an ordinary increment.
        let plain = lift_one(&[0xFF, 0x00]);
        assert!(
            plain.iter().any(|s| matches!(s, MicroStmt::Store { value: MicroExpr::Binary(BinOp::Add, ..), .. })),
            "an unlocked inc is still a plain addition: {plain:?}",
        );
    }

    #[test]
    fn a_bit_test_writes_only_flags() {
        // bt eax, ecx  = 0F A3 C8 — reads a bit into CF and changes no register,
        // so the honest lift is the flag write alone, with no asm node.
        let stmts = lift_one(&[0x0F, 0xA3, 0xC8]);
        assert_eq!(stmts.len(), 1, "{stmts:?}");
        assert!(matches!(&stmts[0], MicroStmt::Assign { dst, value: MicroExpr::OpaqueFlags { .. } } if dst == "flags"));
    }

    #[test]
    fn tzcnt_lifts_to_a_named_intrinsic_over_its_source() {
        // tzcnt eax, ecx  = F3 0F BC C1
        let stmts = lift_one(&[0xF3, 0x0F, 0xBC, 0xC1]);
        assert_eq!(
            stmts[0],
            MicroStmt::Assign {
                dst: "rax".into(),
                value: write32(MicroExpr::intrinsic("__tzcnt", vec![low(32, "rcx")])),
            },
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
            MicroStmt::Assign {
                dst: "rax".into(),
                value: write32(MicroExpr::intrinsic("__pmovmskb", vec![MicroExpr::var("xmm1")])),
            },
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
                value: write32(MicroExpr::binary(BinOp::And, low(32, "rax"), MicroExpr::unary(UnOp::Not, MicroExpr::constant(0x20, 32)))),
            },
        );
        // bts eax, 5 = 0F BA E8 05  ->  rax = rax | 0x20
        let bts = lift_one(&[0x0F, 0xBA, 0xE8, 0x05]);
        assert_eq!(
            bts[0],
            MicroStmt::Assign {
                dst: "rax".into(),
                value: write32(MicroExpr::binary(BinOp::Or, low(32, "rax"), MicroExpr::constant(0x20, 32))),
            },
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
        // The counter is `ecx`, so the flags are set from its low 32 bits —
        // not from `rcx`, whose upper half `dec ecx` cleared and never read.
        assert_eq!(flags, MicroExpr::compare(CmpKind::Result, low(32, "rcx"), MicroExpr::constant(0, 32)));
        assert_eq!(branch_condition("jne", &flags), MicroExpr::binary(BinOp::Ne, low(32, "rcx"), MicroExpr::constant(0, 32)));
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
        assert_eq!(flags, MicroExpr::compare(CmpKind::LogicalResult, low(32, "rdx"), MicroExpr::constant(0, 32)));
        // `jle` is a **signed** predicate, so it reads the same 32 bits signed.
        // With the zero-extended view it would answer the unsigned question and
        // never be true for a negative `edx` — measured against the CPU.
        assert_eq!(
            branch_condition("jle", &flags),
            MicroExpr::binary(BinOp::Sle, low_signed(32, "rdx"), MicroExpr::constant(0, 64))
        );
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
    fn an_eight_bit_result_destination_compares_the_byte_and_not_the_register() {
        // This asserted `OpaqueFlags` while a byte operand was read by widening
        // it to the whole register: `rcx == 0` genuinely did not mean
        // `cl == 0`. `read_operand` returns the byte now, so the flags are a
        // function of exactly the byte the instruction wrote, and refusing had
        // become a lost condition rather than a soundness guard — `and $1, %cl;
        // cmove` is how `-Os` compiles `(a & 1) ? b : c`, and the `cmove` had
        // no condition at all.
        let flags = last_flags(&lift_one(&[0xFE, 0xC9])); // dec cl
        assert_eq!(
            flags,
            MicroExpr::compare(CmpKind::Result, low(8, "rcx"), MicroExpr::constant(0, 8))
        );
        // …and the sign branch reads bit 7 of that byte, not bit 63 of `rcx`.
        assert_eq!(
            branch_condition("js", &flags),
            MicroExpr::binary(BinOp::Slt, low_signed(8, "rcx"), MicroExpr::constant(0, 8))
        );
        // A **memory** destination still refuses: re-reading it is a load, and
        // nothing says it resolves to the value just stored.
        let dec_mem = lift_one(&[0xFE, 0x09]); // dec byte ptr [rcx]
        assert_eq!(
            dec_mem.last(),
            Some(&MicroStmt::Assign {
                dst: FLAGS_VAR.into(),
                value: MicroExpr::OpaqueFlags { mnemonic: "dec".into() }
            })
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

    /// A call clobbers the vector registers too, and which ones is the ABI's
    /// answer, not one shared list.
    ///
    /// Left out, a value in `xmm0` survived a call in the model that the
    /// hardware had already overwritten with the callee's result — the same
    /// unsoundness the GPR clobber list exists to prevent, in the register file
    /// the list never covered.
    #[test]
    fn a_call_invalidates_the_vector_registers_its_abi_says_it_may_destroy() {
        let clobbered = |abi: &str| -> Vec<String> {
            lift_one_abi(&[0xE8, 0x00, 0x00, 0x00, 0x00], abi)
                .iter()
                .filter_map(|s| match s {
                    MicroStmt::Assign { dst, value: MicroExpr::Unknown(_) } if dst.starts_with("xmm") => Some(dst.clone()),
                    _ => None,
                })
                .collect()
        };
        let win = clobbered("win64");
        assert!(win.contains(&"xmm0".to_string()) && win.contains(&"xmm5".to_string()));
        // xmm6-xmm15 are callee-saved on Win64 — invalidating them would throw
        // away values a call genuinely preserves.
        assert!(!win.contains(&"xmm6".to_string()), "Win64 preserves xmm6: {win:?}");
        // System V saves none of them.
        let sysv = clobbered("sysv");
        assert!(sysv.contains(&"xmm6".to_string()) && sysv.contains(&"xmm15".to_string()), "{sysv:?}");
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

