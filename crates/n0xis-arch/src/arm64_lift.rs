// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `Arm64::lift` / `Arm64::branch_condition` — the AArch64 instruction →
//! micro-IR lowering. Same seam and same shape as `x64_lift.rs` relative to
//! `x64.rs`: ISA knowledge, kept behind the [`Arch`] trait, in its own file for
//! size.
//!
//! **This is the first increment and it is deliberately narrow.** It lifts the
//! base integer families a compiler emits for ordinary scalar arithmetic and
//! control flow — move-wide, add/sub (immediate and shifted-register, with
//! their flag-setting forms), the logical family, the 2-source
//! shift/divide/multiply group, branches, compare-and-branch, conditional
//! select, and PC-relative address formation. **Loads and stores are not in
//! it**, nor is the bitfield family, nor anything SIMD/FP/atomic/system.
//! Everything it does not name keeps the trait's [`MicroStmt::Unlifted`]
//! default, which preserves the instruction verbatim: an honest gap is the
//! point of that default, and a family lifted "approximately" would be a
//! confident wrong answer instead.
//!
//! ## Three decisions that are load-bearing
//!
//! **Dispatch is on [`InsnId`], not on `(class, mnemonic)`.** One token fixes
//! both the operation and the operand shape — `ADD_Rd_Rn_Rm_SFT` and
//! `ADD_Rd_SP_Rn_SP_AIMM` are different arms — so an operand can never be read
//! at the position some *other* encoding of the same mnemonic puts it. That
//! also makes the coverage list above a closed set the compiler checks.
//!
//! **Operand fields come from the decoder's own definition.** `field()` looks a
//! [`InsnBitField`] up in `definition().operands[i].bit_fields`, so this file
//! does not carry a second copy of where `Rd` or `imm12` sits. Four fields the
//! definition genuinely does not state are read positionally and each says so
//! at its use: the `sf` width bit, `Rm_SFT`'s register and shift, `MOVEWIDE`'s
//! `hw`, and `CONDSEL`'s condition — the same four `disarm64`'s own formatter
//! reads positionally, for the same reason.
//!
//! **The register model mirrors x86-64 exactly.** The IR variable is always the
//! canonical 64-bit name (`x0`) whatever width the instruction accesses, a
//! W-access is a 32-bit [`MicroExpr::Cast`] in both directions because an
//! AArch64 W-write zeroes the upper half exactly as an x86-64 32-bit write
//! does, `xzr` reads as the constant 0 and its writes are dropped, and `sp` is
//! a real variable. Getting the `xzr` half wrong would break everything below
//! it: `cmp` *is* `subs xzr, …` and `cset` *is* `csinc …, wzr, wzr`.

use disarm64::decoder::{self, InsnId, Opcode};
use disarm64_defn::defn::{Insn, InsnOpcode};
use disarm64_defn::{InsnBitField, InsnFlags, InsnOperandKind};

use crate::arm64::{Arm64, bitrange, gpr_name, sign_extend};
use crate::insn::DecodedInsn;
use crate::microir::{
    BinOp, Bits, CallTarget, CmpKind, FLAGS_VAR, JUMP_TARGET_VAR, MicroExpr, MicroStmt, UnOp,
};
use crate::{Arch, CallConv};

/// The width of the IR's variable — the same constant `x64_lift` keeps, and for
/// the same reason: every consumer models a 64-bit word, so anything narrower
/// than this has to be stated in the IR rather than left to the register.
const WORD_BITS: Bits = 64;

// ---------------------------------------------------------------------------
// Reading an instruction's fields
// ---------------------------------------------------------------------------

/// The value of the bit-field `which` inside operand `operand`, read through
/// the decoder's own definition.
///
/// `definition().operands[i].bit_fields` is a list of [`BitfieldSpec`]s — a
/// field name, an lsb and a width — so the position of `Rd`, `imm12`, `immr`
/// and the rest is a fact this crate already ships and does not need a second
/// copy of. Looking the field up **by name** rather than by index also survives
/// a table that lists an operand's fields in another order.
///
/// [`BitfieldSpec`]: disarm64_defn::BitfieldSpec
///
/// `None` when the operand or the field is absent, which every caller turns
/// into an unlifted instruction. A decoder table that stops matching this
/// file's assumptions therefore produces a gap, never a register read from the
/// wrong five bits.
fn field(op: &Opcode, operand: usize, which: InsnBitField) -> Option<u32> {
    let spec = op
        .definition()
        .operands
        .get(operand)?
        .bit_fields
        .iter()
        .find(|b| b.bitfield == which)?;
    let (lsb, width) = (u32::from(spec.lsb), u32::from(spec.width));
    Some(bitrange(op.bits(), lsb + width - 1, lsb))
}

/// The width this instruction accesses its general-purpose operands at.
///
/// `sf` (bit 31) selects 32 or 64 bits across nearly the whole base ISA, and
/// the definition says *whether* an encoding has that bit — `InsnFlags::
/// HAS_SF_FIELD` — but not where it is, exactly as `disarm64`'s own formatter
/// finds it (`format_int_operand_reg_pair` reads bit 31 under the same flag).
///
/// An encoding with no `sf` is 64-bit **for every id this file dispatches on**:
/// the branch, PC-relative and register-branch forms either take no GPR operand
/// or declare an `X`-only qualifier. That is a claim about the closed match
/// below, not about the ISA, which is why the fallback lives here rather than
/// in a general-purpose helper.
fn access_width(def: &'static Insn, bits: u32) -> Bits {
    if def.flags.contains(InsnFlags::HAS_SF_FIELD) && bits & (1 << 31) == 0 { 32 } else { WORD_BITS }
}

/// One general-purpose register operand, resolved to what the IR calls it.
///
/// Two states, and no third: either the operand names a variable, or it names
/// the zero register — for which a read is the constant 0 and a write goes
/// nowhere. Making that a *type* rather than a flag beside a name is what stops
/// a future arm from assigning to `xzr`: there is no name here to assign to.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Gpr {
    /// `x0`…`x30`, or `sp` where the operand position can encode it.
    Var(String),
    /// Register 31 in a position that reads it as `xzr`/`wzr`.
    Zero,
}

impl Gpr {
    /// Read at `width`. A W-access is the low 32 bits of the 64-bit variable,
    /// zero-extended — which is what the value *is* — so it states its width;
    /// an X-access is the whole word and needs no statement.
    fn read(&self, width: Bits) -> MicroExpr {
        match self {
            Gpr::Zero => MicroExpr::constant(0, width),
            Gpr::Var(name) => {
                let var = MicroExpr::var(name.clone());
                if width >= WORD_BITS {
                    var
                } else {
                    MicroExpr::Cast { signed: false, bits: width, expr: Box::new(var) }
                }
            }
        }
    }

    /// Write at `width`, appending at most one statement.
    ///
    /// A W-write **zeroes** the upper 32 bits — the same rule x86-64 has for a
    /// 32-bit destination, and the same lowering: a cast, not a masked merge.
    /// AArch64 has no narrower general-purpose destination, so there is no
    /// read-modify-write case here at all.
    ///
    /// A write to the zero register is discarded. That is not an optimization:
    /// `cmp`, `cmn`, `tst` and `cset` are all "real" instructions whose
    /// destination is `xzr`, and materializing an assignment to it would invent
    /// a variable the machine does not have.
    fn write(&self, width: Bits, value: MicroExpr, out: &mut Vec<MicroStmt>) {
        let Gpr::Var(name) = self else { return };
        let value = narrow(width, value);
        out.push(MicroStmt::Assign { dst: name.clone(), value });
    }
}

/// Every bit that fits in `width`.
fn width_mask(width: Bits) -> u64 {
    if width >= 64 { u64::MAX } else { (1u64 << width) - 1 }
}

/// State a value's width where it is narrower than the IR's word.
fn narrow(width: Bits, value: MicroExpr) -> MicroExpr {
    if width >= WORD_BITS {
        value
    } else {
        MicroExpr::Cast { signed: false, bits: width, expr: Box::new(value) }
    }
}

/// Resolve operand `operand` as a general-purpose register.
///
/// **Which reading of register 31 applies is the operand's own property, and
/// the definition states it**: a `Rd_SP`/`Rn_SP` position can encode the stack
/// pointer, every other GPR position is architecturally `xzr`-only. Deriving it
/// from the operand kind rather than from the instruction class is what makes
/// `and sp, x1, #0xf` (whose `Rd` *is* `Rd_SP`) and `subs xzr, x0, x1` come out
/// right from one rule.
///
/// The register number comes from the operand's first bit-field, which is how
/// `disarm64`'s own integer formatter reads it.
fn gpr(op: &Opcode, operand: usize) -> Option<Gpr> {
    let o = op.definition().operands.get(operand)?;
    let want_zr = match o.kind {
        InsnOperandKind::Rd_SP | InsnOperandKind::Rn_SP => false,
        InsnOperandKind::Rd
        | InsnOperandKind::Rn
        | InsnOperandKind::Rm
        | InsnOperandKind::Ra
        | InsnOperandKind::Rt => true,
        // Not a plain integer register operand; the caller has the wrong shape
        // and must not guess.
        _ => return None,
    };
    let spec = o.bit_fields.first()?;
    let (lsb, width) = (u32::from(spec.lsb), u32::from(spec.width));
    let n = bitrange(op.bits(), lsb + width - 1, lsb);
    if n == 31 && want_zr {
        return Some(Gpr::Zero);
    }
    // Always the canonical 64-bit spelling: `w0` and `x0` are one register, and
    // recording them as two names is the defect this project has already paid
    // for once. `gpr_name` is where that rule lives.
    Some(Gpr::Var(gpr_name(op.bits(), n, want_zr)))
}

/// The second source of a shifted-register data-processing form — `Rm`,
/// optionally shifted by a constant.
///
/// **This operand's `bit_fields` is empty in the decoder's tables** (measured:
/// every `Rm_SFT` operand of every id below reports no fields), so its three
/// pieces are read positionally: `Rm` at bits 20:16, the shift kind at 23:22
/// and the amount at 15:10. `disarm64`'s own `format_operand_reg_shift` reads
/// exactly those bits, which is the only other place the fact exists.
///
/// `None` — an unlifted instruction — for the two cases with nothing sound to
/// emit: a rotate, which this IR has no operator for, and a shift amount of 32
/// or more on a 32-bit form, which is an unallocated encoding.
fn shifted_reg(op: &Opcode, operand: usize, width: Bits) -> Option<MicroExpr> {
    let o = op.definition().operands.get(operand)?;
    if o.kind != InsnOperandKind::Rm_SFT {
        return None;
    }
    let bits = op.bits();
    let n = bitrange(bits, 20, 16);
    let kind = bitrange(bits, 23, 22);
    let amount = bitrange(bits, 15, 10);
    if width == 32 && amount >= 32 {
        return None;
    }
    let reg = if n == 31 { Gpr::Zero } else { Gpr::Var(gpr_name(bits, n, true)) };
    let base = reg.read(width);
    if kind == 0b00 && amount == 0 {
        return Some(base);
    }
    let count = MicroExpr::constant(i128::from(amount), 8);
    Some(match kind {
        0b00 => MicroExpr::binary(BinOp::Shl, base, count),
        0b01 => MicroExpr::binary(BinOp::Shr, base, count),
        // An **arithmetic** shift reads its operand as signed. A W-operand
        // arrives zero-extended — which is what the bits are — so without this
        // `asr` on a negative 32-bit value would shift in zeros where the
        // hardware shifts in ones. The same trap `x64_lift::shift_rmw`
        // documents, arrived at from the other architecture.
        0b10 => MicroExpr::binary(BinOp::Sar, crate::flags::signed_view(base), count),
        _ => return None,
    })
}

/// `#imm12` optionally shifted left by 12 — the `AIMM` operand of the
/// add/subtract immediate forms. Both fields come from the definition.
fn add_sub_imm(op: &Opcode, operand: usize, width: Bits) -> Option<MicroExpr> {
    let imm = field(op, operand, InsnBitField::imm12)?;
    let value = match field(op, operand, InsnBitField::shift)? {
        0 => u64::from(imm),
        1 => u64::from(imm) << 12,
        // 0b10 and 0b11 are unallocated; a shift this cannot name is one it
        // must not guess.
        _ => return None,
    };
    Some(MicroExpr::constant(i128::from(value), width))
}

/// The `LIMM` operand of the logical-immediate forms, decoded to the mask it
/// denotes.
///
/// AArch64 does not encode a logical immediate literally: `N:immr:imms` names a
/// run of ones of length `imms+1`, rotated right by `immr`, replicated across
/// the register. This is the architecture's `DecodeBitMasks`. The three fields
/// come from the definition; the algorithm cannot, because the decoder's own
/// implementation of it is private to that crate — so it is re-derived here and
/// pinned by `logical_immediates_match_an_assembler`, which checks it against
/// encodings a real assembler produced.
///
/// `None` for the reserved combinations (`imms` all-ones for the chosen width,
/// or a width the encoding cannot mean), which are unallocated instructions.
fn logical_imm(op: &Opcode, operand: usize, width: Bits) -> Option<MicroExpr> {
    let n = field(op, operand, InsnBitField::N)?;
    let immr = field(op, operand, InsnBitField::immr)?;
    let mut imms = field(op, operand, InsnBitField::imms)?;
    let element = if n != 0 {
        64
    } else {
        // With N=0 the leading ones of `imms` pick the element width and the
        // remaining bits are the length within it.
        match imms {
            0x00..=0x1f => 32,
            0x20..=0x2f => {
                imms &= 0xf;
                16
            }
            0x30..=0x37 => {
                imms &= 0x7;
                8
            }
            0x38..=0x3b => {
                imms &= 0x3;
                4
            }
            0x3c..=0x3d => {
                imms &= 0x1;
                2
            }
            _ => return None,
        }
    };
    if element > width || imms == element - 1 {
        return None;
    }
    let mask = width_mask(element);
    let immr = immr & (element - 1);
    let ones = (1u64 << (imms + 1)) - 1;
    let rotated =
        if immr == 0 { ones } else { ((ones << (element - immr)) | (ones >> immr)) & mask };
    let mut value = rotated;
    let mut filled = element;
    while filled < 64 {
        value |= value << filled;
        filled *= 2;
    }
    Some(MicroExpr::constant(i128::from(value & width_mask(width)), width))
}

/// The `#imm16` and the `lsl #shift` of a move-wide form.
///
/// `imm16` is in the definition; **`hw` (bits 22:21) is not**, so it is read
/// positionally — `disarm64`'s formatter reads the same two bits. A 32-bit form
/// with `hw >= 2` is unallocated. Returns both halves because `movk` needs the
/// shift itself, not only the placed value, and one reading of `hw` is enough.
fn move_wide_imm(op: &Opcode, operand: usize, width: Bits) -> Option<(u64, u32)> {
    let imm = u64::from(field(op, operand, InsnBitField::imm16_5)?);
    let hw = bitrange(op.bits(), 22, 21);
    if width == 32 && hw >= 2 {
        return None;
    }
    Some((imm, hw * 16))
}

/// The PC-relative address an `adr`/`adrp` forms. Both immediate halves are in
/// the definition; the two forms differ only in the scale and in whether the
/// program counter is first truncated to its page.
fn pc_rel_target(op: &Opcode, operand: usize, va: u64, page: bool) -> Option<u64> {
    let hi = field(op, operand, InsnBitField::immhi)?;
    let lo = field(op, operand, InsnBitField::immlo)?;
    let imm21 = sign_extend((hi << 2) | lo, 21);
    Some(if page {
        (va & !0xfff).wrapping_add((imm21 as u64) << 12)
    } else {
        va.wrapping_add(imm21 as u64)
    })
}

/// The sixteen AArch64 condition codes, by encoding.
///
/// A second copy of a table `disarm64` also has — its own is private — so
/// `condition_names_agree_with_the_decoder` checks the two against each other
/// on all sixteen values rather than trusting that they were typed the same.
fn cond_name(cond: u32) -> &'static str {
    const NAMES: [&str; 16] = [
        "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al",
        "nv",
    ];
    NAMES[(cond & 0xf) as usize]
}

/// The condition a `CONDSEL` form tests. **Its `COND` operand carries no
/// bit-fields**, so bits 15:12 are read positionally, as `disarm64`'s formatter
/// does. (A conditional *branch* is the opposite case: its condition is in the
/// definition, and `field()` reads it.)
fn condsel_cond(op: &Opcode) -> &'static str {
    cond_name(bitrange(op.bits(), 15, 12))
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

fn compare_flags(kind: CmpKind, lhs: MicroExpr, rhs: MicroExpr) -> MicroStmt {
    MicroStmt::Assign { dst: FLAGS_VAR.to_string(), value: MicroExpr::compare(kind, lhs, rhs) }
}

fn opaque_flags(mnemonic: &str) -> MicroStmt {
    MicroStmt::Assign {
        dst: FLAGS_VAR.to_string(),
        value: MicroExpr::OpaqueFlags { mnemonic: mnemonic.to_string() },
    }
}

/// What an `S`-form writes to `NZCV`, as a dataflow value.
///
/// Three shapes, and which one applies is a property of the operation:
///
/// * a **subtract** (`subs`, and therefore `cmp`) leaves the flags of
///   `lhs - rhs` without the result being needed — the same thing an x86 `cmp`
///   leaves — so the whole ordering family reconstructs from the two operands;
/// * a **logical** op (`ands`, `bics`, and therefore `tst`) sets `NZCV` to
///   `<N,Z,0,0>`, so every condition is a function of the stored result;
/// * an **add** (`adds`, and therefore `cmn`) leaves a real carry and overflow
///   that the result alone does not carry, so only the conditions that *are*
///   functions of the result — zero and sign — are recoverable, and
///   [`crate::flags::branch_condition`] refuses the rest.
///
/// The two result-shaped kinds take the **computed expression**, not a re-read
/// of the destination. x86-64's `result_flags` re-reads it and is careful to
/// emit the flags after the write for that reason; here it cannot, because the
/// destination of the most common S-forms is `xzr` — `cmp`, `cmn` and `tst` all
/// discard their result — and re-reading `xzr` would record the flags of the
/// constant zero. Carrying the expression instead is what lets every flags
/// statement be emitted **before** the write, which is the ordering the SSA
/// renamer needs: a compare emitted after the write would resolve its operands
/// to the value just written.
enum SFlags {
    Sub,
    Logical,
    Add,
}

impl SFlags {
    fn stmt(&self, width: Bits, lhs: MicroExpr, rhs: MicroExpr, result: &MicroExpr) -> MicroStmt {
        match self {
            SFlags::Sub => compare_flags(CmpKind::Cmp, lhs, rhs),
            SFlags::Logical => compare_flags(
                CmpKind::LogicalResult,
                narrow(width, result.clone()),
                MicroExpr::constant(0, width),
            ),
            SFlags::Add => compare_flags(
                CmpKind::Result,
                narrow(width, result.clone()),
                MicroExpr::constant(0, width),
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

fn cc_for<'a>(arch: &'a Arm64, abi: &str) -> &'a CallConv {
    // `Arch::calling_convention` answers `None` only for an architecture that
    // declares none at all; AArch64 declares AAPCS64 in a `static`, and
    // `one_fact_one_place` asserts every architecture's list is non-empty.
    arch.calling_convention(abi).expect("AArch64 declares its calling convention")
}

/// The statements a call lowers to: the call itself, then an `Unknown` def on
/// every register the ABI says the callee may destroy, then opaque flags.
///
/// AAPCS64 does not require `NZCV` to survive a call, so the flags after one are
/// genuinely unknown — the same reason x86-64's `call` writes opaque flags.
fn call_stmts(
    arch: &Arm64,
    mnemonic: &str,
    target: CallTarget,
    abi: &str,
    out: &mut Vec<MicroStmt>,
) {
    let cc = cc_for(arch, abi);
    let regs = arch.regs();
    let ret = cc.ret_name(regs).map(str::to_string);
    out.push(MicroStmt::Call {
        target,
        args: cc.int_arg_names(regs).into_iter().map(MicroExpr::var).collect(),
        ret: ret.clone(),
    });
    for clobbered in cc.clobbered_names(regs) {
        out.push(MicroStmt::Assign {
            dst: clobbered,
            value: MicroExpr::Unknown(crate::CALL_CLOBBER.to_string()),
        });
    }
    out.push(opaque_flags(mnemonic));
}

/// `bl`/`blr` also write the link register with the address of the following
/// instruction. Exact and known at lift time, so it is stated rather than left
/// to a later read of a stale `x30`.
fn link_register(arch: &Arm64, insn: &DecodedInsn) -> Option<MicroStmt> {
    Some(MicroStmt::Assign {
        dst: arch.regs().name(crate::arm64reg::LR)?.to_string(),
        value: MicroExpr::constant(i128::from(insn.va.0 + 4), 64),
    })
}

// ---------------------------------------------------------------------------
// The lift
// ---------------------------------------------------------------------------

pub(crate) fn lift(arch: &Arm64, insn: &DecodedInsn, abi: &str) -> Vec<MicroStmt> {
    match lift_known(arch, insn, abi) {
        // An empty vector is a *result*: `b`, `b.cond` and `cbz` carry their
        // edge in the CFG and compute nothing. `None` is the other thing —
        // "this file does not model that instruction" — and the two must not
        // share a representation, which is why this is an `Option<Vec<_>>` and
        // not a `Vec<_>` that happens to be empty.
        Some(stmts) => stmts,
        None => lift_opaque(arch, insn),
    }
}

/// An instruction this increment does not model: keep it verbatim, **and
/// soundly invalidate everything it might have written**.
///
/// The second half is not bookkeeping. Measured on a real `aarch64-linux-gnu-gcc
/// -O1` object, `unsigned long scale(unsigned long x) { return x * 8 + 3; }`
/// compiles to `lsl x0, x0, #3 ; add x0, x0, #3`, and the shift is a `ubfm` —
/// out of scope here. With only the `Unlifted` statement the following `add`
/// read the *entry* value of `x0` and the function decompiled to
/// `return x0 + 3`: a complete-looking expression with the shift silently gone.
/// An `Unknown` def on `x0` turns that into a visible gap instead.
///
/// The flags are invalidated for the same reason. Most AArch64 instructions
/// leave `NZCV` alone, so this loses precision on a `cmp` that an unmodelled
/// instruction happens to sit between — but the alternative is a `b.eq` that
/// reconstructs against a compare some `ccmp` or `fcmp` had already replaced,
/// and a missing condition costs less than a wrong one. Same policy as
/// `x64_lift::lift_opaque`, which is where it was decided.
fn lift_opaque(arch: &Arm64, insn: &DecodedInsn) -> Vec<MicroStmt> {
    let mut out = vec![MicroStmt::Unlifted { va: insn.va, text: insn.text.clone() }];
    for w in arch.reg_access(insn).writes {
        // `reg_access` names the zero register when an instruction discards its
        // result into it. There is no such variable, and defining one would
        // invent state the machine does not have.
        if w == "xzr" {
            continue;
        }
        out.push(MicroStmt::Assign { dst: w, value: MicroExpr::Unknown(insn.text.clone()) });
    }
    out.push(opaque_flags(&insn.mnemonic));
    out
}

/// A **tail call** — a branch the CFG determined leaves the function — is
/// `return f(args)`, not a branch. Same lowering as x86-64's, for the same
/// reason: the callee runs on this frame and its result is this function's
/// result. Without this the `b` would lift to nothing at all and the call would
/// vanish from the IR.
pub(crate) fn lift_tail_call(arch: &Arm64, insn: &DecodedInsn, abi: &str) -> Vec<MicroStmt> {
    let Some(target) = branch_call_target(insn) else {
        return lift(arch, insn, abi);
    };
    let cc = cc_for(arch, abi);
    let regs = arch.regs();
    let Some(ret) = cc.ret_name(regs) else { return lift(arch, insn, abi) };
    vec![
        MicroStmt::Call {
            target,
            args: cc.int_arg_names(regs).into_iter().map(MicroExpr::var).collect(),
            ret: Some(ret.to_string()),
        },
        MicroStmt::Return(Some(MicroExpr::var(ret))),
    ]
}

/// The callee of a branch used as a call: the resolved direct target if the
/// instruction has one, else the register an indirect branch reads.
fn branch_call_target(insn: &DecodedInsn) -> Option<CallTarget> {
    if let Some(va) = insn.target {
        return Some(CallTarget::Direct { va });
    }
    let bits = raw(insn)?;
    let op = decoder::decode(bits)?;
    if !matches!(op.id(), InsnId::BR_Rn | InsnId::BLR_Rn) {
        return None;
    }
    let rn = gpr(&op, 0)?;
    Some(CallTarget::Indirect(Box::new(rn.read(WORD_BITS))))
}

fn raw(insn: &DecodedInsn) -> Option<u32> {
    let b: [u8; 4] = insn.bytes.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

/// The whole lowering, as one closed match on the decoder's instruction
/// identity. `None` anywhere in here — an id this increment does not name, or a
/// field the definition did not supply — means the instruction is preserved
/// verbatim by the caller.
fn lift_known(arch: &Arm64, insn: &DecodedInsn, abi: &str) -> Option<Vec<MicroStmt>> {
    let op = decoder::decode(raw(insn)?)?;
    let def = op.definition();
    let width = access_width(def, op.bits());
    let mut out: Vec<MicroStmt> = Vec::new();

    match op.id() {
        // ---- MOVEWIDE ---------------------------------------------------
        // `movz`/`movn` place a 16-bit field and clear (or complement) the
        // rest; both are constants at lift time, so they are folded here
        // rather than emitted as an expression over an immediate.
        InsnId::MOVZ_Rd_HALF | InsnId::MOVN_Rd_HALF => {
            let (imm, shift) = move_wide_imm(&op, 1, width)?;
            let mask = width_mask(width);
            let placed = (imm << shift) & mask;
            let value = if op.id() == InsnId::MOVN_Rd_HALF { !placed & mask } else { placed };
            gpr(&op, 0)?.write(width, MicroExpr::constant(i128::from(value), width), &mut out);
        }
        // `movk` keeps every bit outside the 16 it writes, so it reads its own
        // destination.
        InsnId::MOVK_Rd_HALF => {
            let dst = gpr(&op, 0)?;
            let (imm, shift) = move_wide_imm(&op, 1, width)?;
            let mask = width_mask(width);
            let kept = MicroExpr::binary(
                BinOp::And,
                dst.read(width),
                MicroExpr::constant(i128::from(!(0xffffu64 << shift) & mask), width),
            );
            let placed = MicroExpr::constant(i128::from((imm << shift) & mask), width);
            dst.write(width, MicroExpr::binary(BinOp::Or, kept, placed), &mut out);
        }

        // ---- ADDSUB_IMM / ADDSUB_SHIFT ----------------------------------
        InsnId::ADD_Rd_SP_Rn_SP_AIMM
        | InsnId::ADDS_Rd_Rn_SP_AIMM
        | InsnId::SUB_Rd_SP_Rn_SP_AIMM
        | InsnId::SUBS_Rd_Rn_SP_AIMM => {
            let rhs = add_sub_imm(&op, 2, width)?;
            let (bin, flags) = match op.id() {
                InsnId::ADD_Rd_SP_Rn_SP_AIMM => (BinOp::Add, None),
                InsnId::ADDS_Rd_Rn_SP_AIMM => (BinOp::Add, Some(SFlags::Add)),
                InsnId::SUB_Rd_SP_Rn_SP_AIMM => (BinOp::Sub, None),
                _ => (BinOp::Sub, Some(SFlags::Sub)),
            };
            arith(&op, width, bin, rhs, flags, &mut out)?;
        }
        InsnId::ADD_Rd_Rn_Rm_SFT
        | InsnId::ADDS_Rd_Rn_Rm_SFT
        | InsnId::SUB_Rd_Rn_Rm_SFT
        | InsnId::SUBS_Rd_Rn_Rm_SFT => {
            let rhs = shifted_reg(&op, 2, width)?;
            let (bin, flags) = match op.id() {
                InsnId::ADD_Rd_Rn_Rm_SFT => (BinOp::Add, None),
                InsnId::ADDS_Rd_Rn_Rm_SFT => (BinOp::Add, Some(SFlags::Add)),
                InsnId::SUB_Rd_Rn_Rm_SFT => (BinOp::Sub, None),
                _ => (BinOp::Sub, Some(SFlags::Sub)),
            };
            arith(&op, width, bin, rhs, flags, &mut out)?;
        }

        // ---- LOG_IMM / LOG_SHIFT ----------------------------------------
        InsnId::AND_Rd_SP_Rn_LIMM
        | InsnId::ANDS_Rd_Rn_LIMM
        | InsnId::ORR_Rd_SP_Rn_LIMM
        | InsnId::EOR_Rd_SP_Rn_LIMM => {
            let rhs = logical_imm(&op, 2, width)?;
            let (bin, flags) = match op.id() {
                InsnId::AND_Rd_SP_Rn_LIMM => (BinOp::And, None),
                InsnId::ANDS_Rd_Rn_LIMM => (BinOp::And, Some(SFlags::Logical)),
                InsnId::ORR_Rd_SP_Rn_LIMM => (BinOp::Or, None),
                _ => (BinOp::Xor, None),
            };
            arith(&op, width, bin, rhs, flags, &mut out)?;
        }
        // The `N`-suffixed forms complement the second source; `orr Rd, xzr,
        // Rm` is how AArch64 spells `mov`, and falls out of the `xzr`-reads-as-
        // zero rule with no special case.
        InsnId::AND_Rd_Rn_Rm_SFT
        | InsnId::ANDS_Rd_Rn_Rm_SFT
        | InsnId::ORR_Rd_Rn_Rm_SFT
        | InsnId::EOR_Rd_Rn_Rm_SFT
        | InsnId::BIC_Rd_Rn_Rm_SFT
        | InsnId::BICS_Rd_Rn_Rm_SFT
        | InsnId::ORN_Rd_Rn_Rm_SFT
        | InsnId::EON_Rd_Rn_Rm_SFT => {
            let rm = shifted_reg(&op, 2, width)?;
            let negated = matches!(
                op.id(),
                InsnId::BIC_Rd_Rn_Rm_SFT
                    | InsnId::BICS_Rd_Rn_Rm_SFT
                    | InsnId::ORN_Rd_Rn_Rm_SFT
                    | InsnId::EON_Rd_Rn_Rm_SFT
            );
            let rhs = if negated { MicroExpr::unary(UnOp::Not, rm) } else { rm };
            let (bin, flags) = match op.id() {
                InsnId::AND_Rd_Rn_Rm_SFT | InsnId::BIC_Rd_Rn_Rm_SFT => (BinOp::And, None),
                InsnId::ANDS_Rd_Rn_Rm_SFT | InsnId::BICS_Rd_Rn_Rm_SFT => {
                    (BinOp::And, Some(SFlags::Logical))
                }
                InsnId::ORR_Rd_Rn_Rm_SFT | InsnId::ORN_Rd_Rn_Rm_SFT => (BinOp::Or, None),
                _ => (BinOp::Xor, None),
            };
            arith(&op, width, bin, rhs, flags, &mut out)?;
        }

        // ---- DP_2SRC: variable shifts and division -----------------------
        // A variable shift count is taken **modulo the register width** by the
        // hardware, and an IR that says `x1 << x2` describes a program that was
        // never run — the mask is the instruction's semantics, not a tidy-up.
        InsnId::LSLV_Rd_Rn_Rm | InsnId::LSRV_Rd_Rn_Rm | InsnId::ASRV_Rd_Rn_Rm => {
            let (dst, lhs, rhs) = (gpr(&op, 0)?, gpr(&op, 1)?, gpr(&op, 2)?);
            let count = MicroExpr::binary(
                BinOp::And,
                rhs.read(width),
                MicroExpr::constant(i128::from(width - 1), 8),
            );
            let value = match op.id() {
                InsnId::LSLV_Rd_Rn_Rm => MicroExpr::binary(BinOp::Shl, lhs.read(width), count),
                InsnId::LSRV_Rd_Rn_Rm => MicroExpr::binary(BinOp::Shr, lhs.read(width), count),
                _ => MicroExpr::binary(
                    BinOp::Sar,
                    crate::flags::signed_view(lhs.read(width)),
                    count,
                ),
            };
            dst.write(width, value, &mut out);
        }
        // AArch64 division does not trap: `x / 0` yields 0, and
        // `INT_MIN / -1` yields `INT_MIN`. The IR's `UDiv`/`SDiv` do not model
        // either, so the expression recovered here is exact for every divisor
        // the C source could legally supply and wrong for the two the hardware
        // defines and C does not. Stated rather than silently assumed.
        InsnId::UDIV_Rd_Rn_Rm | InsnId::SDIV_Rd_Rn_Rm => {
            let (dst, lhs, rhs) = (gpr(&op, 0)?, gpr(&op, 1)?, gpr(&op, 2)?);
            let signed = op.id() == InsnId::SDIV_Rd_Rn_Rm;
            let (a, b) = if signed {
                (
                    crate::flags::signed_view(lhs.read(width)),
                    crate::flags::signed_view(rhs.read(width)),
                )
            } else {
                (lhs.read(width), rhs.read(width))
            };
            let bin = if signed { BinOp::SDiv } else { BinOp::UDiv };
            dst.write(width, MicroExpr::binary(bin, a, b), &mut out);
        }
        // `mul`/`mneg` are these with `Ra` = `xzr`, which is the only way this
        // architecture spells a plain multiply; the zero-register rule turns
        // the accumulator into the constant 0 with no special case.
        InsnId::MADD_Rd_Rn_Rm_Ra | InsnId::MSUB_Rd_Rn_Rm_Ra => {
            let (dst, rn, rm, ra) = (gpr(&op, 0)?, gpr(&op, 1)?, gpr(&op, 2)?, gpr(&op, 3)?);
            let product = MicroExpr::binary(BinOp::Mul, rn.read(width), rm.read(width));
            let bin =
                if op.id() == InsnId::MADD_Rd_Rn_Rm_Ra { BinOp::Add } else { BinOp::Sub };
            dst.write(width, MicroExpr::binary(bin, ra.read(width), product), &mut out);
        }

        // ---- Branches ----------------------------------------------------
        // A direct branch is structural: the CFG carries the edge and the
        // address is in the instruction, so there is nothing to compute. Same
        // for a conditional one, whose condition `branch_condition` synthesizes
        // from the flags value that reaches it.
        InsnId::B_ADDR_PCREL26 | InsnId::B_C_ADDR_PCREL19 => {}
        InsnId::BL_ADDR_PCREL26 => {
            out.push(link_register(arch, insn)?);
            let target = CallTarget::Direct { va: insn.target? };
            call_stmts(arch, "bl", target, abi, &mut out);
        }
        InsnId::BLR_Rn => {
            out.push(link_register(arch, insn)?);
            let callee = gpr(&op, 0)?.read(WORD_BITS);
            call_stmts(arch, "blr", CallTarget::Indirect(Box::new(callee)), abi, &mut out);
        }
        // An **indirect** branch computes an address that appears nowhere else
        // in the IR. Recording it is what lets a resolved switch case be
        // checked against the address the machine would actually use.
        InsnId::BR_Rn => {
            out.push(MicroStmt::Assign {
                dst: JUMP_TARGET_VAR.to_string(),
                value: gpr(&op, 0)?.read(WORD_BITS),
            });
        }
        InsnId::RET_Rn => {
            let cc = cc_for(arch, abi);
            let ret = cc.ret_name(arch.regs())?;
            out.push(MicroStmt::Return(Some(MicroExpr::var(ret))));
        }
        // `cbz`/`cbnz` are conditional branches that read **no flags at all**,
        // so nothing this file emits could be the condition and
        // `branch_condition` renders a placeholder for them. Stating the
        // condition would mean writing the compare into `FLAGS_VAR`, which the
        // instruction does not touch — a later `b.cond` reading that value
        // would then test the wrong thing. x86-64 has the same shape in
        // `jrcxz`, and lifts it to nothing for the same reason. A missing
        // condition, never a wrong one; closing it needs a way for a terminator
        // to carry its own condition, which is a change to the IR's shape.
        InsnId::CBZ_Rt_ADDR_PCREL19 | InsnId::CBNZ_Rt_ADDR_PCREL19 => {}

        // ---- CONDSEL -----------------------------------------------------
        // `Rd = cond ? Rn : Rm` (and `Rm + 1` for the `inc` form, which is how
        // `cset`/`cinc` are spelled). The condition rides as the same
        // `setcc:<cond>` marker a `cmov` uses on x86-64: its value depends on
        // the flags reaching this point, which are known only after SSA, and
        // the SSA builder resolves the marker through `branch_condition`.
        InsnId::CSEL_Rd_Rn_Rm_COND | InsnId::CSINC_Rd_Rn_Rm_COND => {
            let (dst, rn, rm) = (gpr(&op, 0)?, gpr(&op, 1)?, gpr(&op, 2)?);
            let cond =
                MicroExpr::OpaqueFlags { mnemonic: format!("setcc:{}", condsel_cond(&op)) };
            let other = if op.id() == InsnId::CSINC_Rd_Rn_Rm_COND {
                MicroExpr::binary(BinOp::Add, rm.read(width), MicroExpr::constant(1, width))
            } else {
                rm.read(width)
            };
            dst.write(width, MicroExpr::select(cond, rn.read(width), other), &mut out);
        }

        // ---- PCRELADDR ---------------------------------------------------
        InsnId::ADR_Rd_ADDR_PCREL21 | InsnId::ADRP_Rd_ADDR_ADRP => {
            let page = op.id() == InsnId::ADRP_Rd_ADDR_ADRP;
            let target = pc_rel_target(&op, 1, insn.va.0, page)?;
            let value = MicroExpr::AddrOf(Box::new(MicroExpr::constant(i128::from(target), 64)));
            gpr(&op, 0)?.write(WORD_BITS, value, &mut out);
        }

        _ => return None,
    }
    Some(out)
}

/// The common shape of every two-source data-processing form: read `Rn`,
/// combine it with an already-built second operand, write `Rd`.
///
/// **The flags statement goes first.** SSA renames by statement position, so a
/// flags value emitted after the destination write would read the register the
/// instruction had just assigned. `SFlags` documents why carrying the computed
/// expression, rather than re-reading the destination, is what makes that
/// ordering possible here.
fn arith(
    op: &Opcode,
    width: Bits,
    bin: BinOp,
    rhs: MicroExpr,
    flags: Option<SFlags>,
    out: &mut Vec<MicroStmt>,
) -> Option<()> {
    let dst = gpr(op, 0)?;
    let lhs = gpr(op, 1)?.read(width);
    let result = MicroExpr::binary(bin, lhs.clone(), rhs.clone());
    if let Some(f) = flags {
        out.push(f.stmt(width, lhs, rhs, &result));
    }
    dst.write(width, result, out);
    Some(())
}

// ---------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------

/// One AArch64 condition, spelled the way [`crate::flags::branch_condition`]
/// names it.
///
/// **This mapping is where the two architectures' carry flags are reconciled.**
/// After a subtraction AArch64 sets `C` to *not borrow* and x86 sets `CF` to
/// *borrow*, so the two are inverted — and the inversion disappears here
/// because the conditions are matched by the *relation they express*, not by
/// the flag they read: `cs`/`hs` is "unsigned greater or equal", which x86
/// spells `jae`, and `cc`/`lo` is "unsigned less", which x86 spells `jb`.
/// Mapping them by flag name instead would invert every unsigned comparison in
/// the program.
///
/// `vs`/`vc` are deliberately absent: the shared table has no overflow
/// condition, so naming them would reach the same placeholder by a longer
/// route. `al`/`nv` are handled by the caller — they are not comparisons.
fn x86_spelling(cond: &str) -> Option<&'static str> {
    Some(match cond {
        "eq" => "je",
        "ne" => "jne",
        "cs" | "hs" => "jae",
        "cc" | "lo" => "jb",
        "mi" => "js",
        "pl" => "jns",
        "hi" => "ja",
        "ls" => "jbe",
        "ge" => "jge",
        "lt" => "jl",
        "gt" => "jg",
        "le" => "jle",
        _ => return None,
    })
}

pub(crate) fn branch_condition(mnemonic: &str, flags_value: &MicroExpr) -> MicroExpr {
    // Two spellings arrive here: a conditional branch's mnemonic (`b.ne`) from
    // the CFG terminator, and a bare condition (`ne`) from the `setcc:` marker
    // a `csel`/`csinc` carries.
    let cond = mnemonic.strip_prefix("b.").unwrap_or(mnemonic);

    // `al` is architecturally always taken, so the branch is not a condition at
    // all. `nv` is **not** its opposite — on AArch64 it behaves identically to
    // `al`, unlike the 32-bit architecture where the same encoding meant
    // "never" — and the two readings are exact opposites, so a refusal is the
    // only answer here that cannot be wrong. No compiler emits it.
    if cond == "al" {
        return MicroExpr::constant(1, 8);
    }

    // **The carry mapping below absorbs the two architectures' inverted `C`
    // for a subtraction and cannot absorb it for a logical op.** `ands`/`bics`
    // set `NZCV` to `<N,Z,0,0>`, so `cs` and `hi` are constantly *false* and
    // `cc` and `ls` constantly *true*; on x86 a logical op clears `CF`, which
    // makes `jae` constantly true and `jb` constantly false — the opposite
    // polarity. Delegating these four would answer every one of them backwards,
    // so they are answered here, as the sound constants they are.
    if let MicroExpr::Compare { kind: CmpKind::LogicalResult, .. } = flags_value {
        match cond {
            "cs" | "hs" | "hi" => return MicroExpr::constant(0, 8),
            "cc" | "lo" | "ls" => return MicroExpr::constant(1, 8),
            _ => {}
        }
    }

    let Some(jcc) = x86_spelling(cond) else {
        return MicroExpr::Unknown(format!("cond({mnemonic})"));
    };
    crate::flags::branch_condition(jcc, flags_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_contracts::Va;

    // Every encoding below was produced by an assembler that is not this
    // project and not `disarm64`:
    //
    //     aarch64-linux-gnu-as  +  aarch64-linux-gnu-objdump -d
    //
    // The source line each word came from is in the comment beside it, spelled
    // as the assembler accepted it. Nothing here was derived by hand.

    fn le(bits: u32) -> Vec<u8> {
        bits.to_le_bytes().to_vec()
    }

    fn lift_word(bits: u32) -> Vec<MicroStmt> {
        let arch = Arm64::new();
        let insn = arch.decode(&le(bits), Va(0x1000)).expect("decodes");
        arch.lift(&insn, "aapcs64")
    }

    /// The low 32 bits of a register, zero-extended — how a W-read reads.
    fn w(name: &str) -> MicroExpr {
        MicroExpr::Cast { signed: false, bits: 32, expr: Box::new(MicroExpr::var(name)) }
    }

    /// Wrap a value the way a **W-destination write** does: the upper half is
    /// zeroed, so the write is a cast, not a plain assign.
    fn write32(v: MicroExpr) -> MicroExpr {
        MicroExpr::Cast { signed: false, bits: 32, expr: Box::new(v) }
    }

    fn assign(dst: &str, value: MicroExpr) -> MicroStmt {
        MicroStmt::Assign { dst: dst.into(), value }
    }

    #[test]
    fn add_of_three_x_registers_is_one_plain_assign() {
        // `add x0, x1, x2` -> 8b020020
        assert_eq!(
            lift_word(0x8b020020),
            vec![assign(
                "x0",
                MicroExpr::binary(BinOp::Add, MicroExpr::var("x1"), MicroExpr::var("x2"))
            )]
        );
    }

    /// **The same operation at 32 bits is not the same statement.** A W-access
    /// reads the low half and a W-write clears the upper half, exactly as on
    /// x86-64 — and the variable is `x0` at both widths, because `w0` and `x0`
    /// are one register.
    #[test]
    fn add_of_three_w_registers_states_its_width_on_both_sides() {
        // `add w0, w1, w2` -> 0b020020
        assert_eq!(
            lift_word(0x0b020020),
            vec![assign("x0", write32(MicroExpr::binary(BinOp::Add, w("x1"), w("x2"))))]
        );
    }

    /// `cmp` **is** `subs xzr, x0, x1`. Two things have to be right at once:
    /// the destination is the zero register, so no register is written at all;
    /// and the flags are the `Cmp` of the two operands, which is what lets the
    /// whole ordering family reconstruct from them.
    #[test]
    fn cmp_writes_flags_and_no_register() {
        // `cmp x0, x1` -> eb01001f
        let stmts = lift_word(0xeb01001f);
        assert_eq!(
            stmts,
            vec![assign(
                FLAGS_VAR,
                MicroExpr::compare(CmpKind::Cmp, MicroExpr::var("x0"), MicroExpr::var("x1"))
            )],
            "a write to xzr must be dropped, leaving only the flags"
        );
    }

    /// `tst` is `ands xzr, …`: no register write, and flags that carry the
    /// *computed* value rather than a re-read of the discarded destination.
    #[test]
    fn tst_records_the_computed_value_not_the_discarded_destination() {
        // `tst x0, x1` -> ea01001f
        assert_eq!(
            lift_word(0xea01001f),
            vec![assign(
                FLAGS_VAR,
                MicroExpr::compare(
                    CmpKind::LogicalResult,
                    MicroExpr::binary(BinOp::And, MicroExpr::var("x0"), MicroExpr::var("x1")),
                    MicroExpr::constant(0, 64),
                )
            )]
        );
    }

    #[test]
    fn mov_immediate_is_a_folded_constant_at_the_written_width() {
        // `mov w0, #1` -> 52800020 (the assembler picks `movz`)
        assert_eq!(
            lift_word(0x52800020),
            vec![assign("x0", write32(MicroExpr::constant(1, 32)))]
        );
        // `mov x0, #-1` -> 92800000 (`movn x0, #0`)
        assert_eq!(
            lift_word(0x92800000),
            vec![assign("x0", MicroExpr::constant(i128::from(u64::MAX), 64))]
        );
    }

    /// `movk` is the one move-wide form that **keeps** what it does not write,
    /// so it reads its own destination — and the mask it keeps has to be stated
    /// at the destination's width, or a W-form would carry bits above 31 that
    /// the instruction never touches.
    #[test]
    fn movk_keeps_every_bit_outside_the_sixteen_it_writes() {
        // `movk w0, #1, lsl #16` -> 72a00020
        assert_eq!(
            lift_word(0x72a00020),
            vec![assign(
                "x0",
                write32(MicroExpr::binary(
                    BinOp::Or,
                    MicroExpr::binary(BinOp::And, w("x0"), MicroExpr::constant(0x0000_ffff, 32)),
                    MicroExpr::constant(0x0001_0000, 32),
                ))
            )]
        );
        // `movk x0, #0x1234, lsl #32` -> f2c24680
        assert_eq!(
            lift_word(0xf2c24680),
            vec![assign(
                "x0",
                MicroExpr::binary(
                    BinOp::Or,
                    MicroExpr::binary(
                        BinOp::And,
                        MicroExpr::var("x0"),
                        MicroExpr::constant(0xffff_0000_ffff_ffffu64 as i128, 64)
                    ),
                    MicroExpr::constant(0x0000_1234_0000_0000, 64),
                )
            )]
        );
    }

    /// A logical immediate is not encoded literally, and an S-form subtract
    /// immediate has to capture its operands *before* the write. Both at 32
    /// bits, where every read and the write state their width.
    #[test]
    fn immediate_forms_at_thirty_two_bits() {
        // `and w0, w1, #0xf` -> 12000c20
        assert_eq!(
            lift_word(0x12000c20),
            vec![assign(
                "x0",
                write32(MicroExpr::binary(BinOp::And, w("x1"), MicroExpr::constant(0xf, 32)))
            )]
        );
        // `subs w0, w1, #1` -> 71000420
        assert_eq!(
            lift_word(0x71000420),
            vec![
                assign(
                    FLAGS_VAR,
                    MicroExpr::compare(CmpKind::Cmp, w("x1"), MicroExpr::constant(1, 32))
                ),
                assign(
                    "x0",
                    write32(MicroExpr::binary(BinOp::Sub, w("x1"), MicroExpr::constant(1, 32)))
                ),
            ]
        );
    }

    /// `cset w0, ne` is `csinc w0, wzr, wzr, eq`: both sources are the zero
    /// register and the *inverted* condition is what is encoded. Three of this
    /// file's rules meet in one instruction — the zero register reads as 0, the
    /// `inc` form adds one to the false arm, and the condition travels as a
    /// marker the SSA pass resolves against the reaching flags.
    #[test]
    fn cset_is_csinc_of_two_zero_registers() {
        // `cset w0, ne` -> 1a9f07e0
        assert_eq!(
            lift_word(0x1a9f07e0),
            vec![assign(
                "x0",
                write32(MicroExpr::select(
                    MicroExpr::OpaqueFlags { mnemonic: "setcc:eq".into() },
                    MicroExpr::constant(0, 32),
                    MicroExpr::binary(
                        BinOp::Add,
                        MicroExpr::constant(0, 32),
                        MicroExpr::constant(1, 32)
                    ),
                ))
            )]
        );
    }

    #[test]
    fn ret_returns_the_conventions_result_register() {
        // `ret` -> d65f03c0
        assert_eq!(lift_word(0xd65f03c0), vec![MicroStmt::Return(Some(MicroExpr::var("x0")))]);
    }

    /// A direct branch computes nothing — and "nothing" is a *result*, not a
    /// failure to lift. If these ever came back as `Unlifted` the two would be
    /// indistinguishable downstream.
    #[test]
    fn structural_branches_lift_to_no_statements() {
        for (word, what) in [
            (0x14000002u32, "b .+8"),
            (0x54000041, "b.ne .+8"),
            (0x34000040, "cbz w0, .+8"),
            (0xb5000041, "cbnz x1, .+8"),
        ] {
            assert_eq!(lift_word(word), Vec::<MicroStmt>::new(), "{what}");
        }
    }

    #[test]
    fn sub_sp_is_the_one_form_that_really_writes_the_stack_pointer() {
        // `sub sp, sp, #0x20` -> d10083ff
        assert_eq!(
            lift_word(0xd10083ff),
            vec![assign(
                "sp",
                MicroExpr::binary(BinOp::Sub, MicroExpr::var("sp"), MicroExpr::constant(0x20, 64))
            )]
        );
    }

    #[test]
    fn orr_with_the_zero_register_is_how_this_architecture_spells_mov() {
        // `mov x0, x1` -> aa0103e0 (`orr x0, xzr, x1`)
        assert_eq!(
            lift_word(0xaa0103e0),
            vec![assign(
                "x0",
                MicroExpr::binary(BinOp::Or, MicroExpr::constant(0, 64), MicroExpr::var("x1"))
            )]
        );
    }

    /// A shifted second operand is part of the instruction, not decoration, and
    /// its three fields are the ones the decoder's tables do **not** carry.
    #[test]
    fn a_shifted_second_operand_is_lifted_with_its_shift() {
        // `add x0, x1, x2, lsl #3` -> 8b020c20
        assert_eq!(
            lift_word(0x8b020c20),
            vec![assign(
                "x0",
                MicroExpr::binary(
                    BinOp::Add,
                    MicroExpr::var("x1"),
                    MicroExpr::binary(BinOp::Shl, MicroExpr::var("x2"), MicroExpr::constant(3, 8))
                )
            )]
        );
        // `sub x0, x1, x2, asr #2` -> cb820820 — an arithmetic shift reads its
        // operand as signed.
        assert_eq!(
            lift_word(0xcb820820),
            vec![assign(
                "x0",
                MicroExpr::binary(
                    BinOp::Sub,
                    MicroExpr::var("x1"),
                    MicroExpr::binary(BinOp::Sar, MicroExpr::var("x2"), MicroExpr::constant(2, 8))
                )
            )]
        );
        // `orr w0, w1, w2, ror #3` -> 2ac20c20 — no rotate operator exists in
        // this IR, so the instruction is preserved verbatim instead of being
        // lifted as something else.
        assert!(
            matches!(lift_word(0x2ac20c20).first(), Some(MicroStmt::Unlifted { .. })),
            "a rotate this IR cannot express must stay unlifted"
        );
    }

    /// A variable shift is masked by the hardware; an IR that omits the mask
    /// describes a program that was never run.
    #[test]
    fn a_variable_shift_masks_its_count_to_the_register_width() {
        // `lsl w0, w1, w2` -> 1ac22020 (`lslv`)
        assert_eq!(
            lift_word(0x1ac22020),
            vec![assign(
                "x0",
                write32(MicroExpr::binary(
                    BinOp::Shl,
                    w("x1"),
                    MicroExpr::binary(BinOp::And, w("x2"), MicroExpr::constant(31, 8))
                ))
            )]
        );
        // `lsr x0, x1, x2` -> 9ac22420 — 64-bit, so the mask is 63.
        assert_eq!(
            lift_word(0x9ac22420),
            vec![assign(
                "x0",
                MicroExpr::binary(
                    BinOp::Shr,
                    MicroExpr::var("x1"),
                    MicroExpr::binary(
                        BinOp::And,
                        MicroExpr::var("x2"),
                        MicroExpr::constant(63, 8)
                    )
                )
            )]
        );
    }

    /// `mul` is `madd` with the accumulator discarded through `xzr` — the only
    /// spelling this architecture has for a plain multiply.
    #[test]
    fn mul_is_madd_with_a_zeroed_accumulator() {
        // `mul x0, x1, x2` -> 9b027c20
        assert_eq!(
            lift_word(0x9b027c20),
            vec![assign(
                "x0",
                MicroExpr::binary(
                    BinOp::Add,
                    MicroExpr::constant(0, 64),
                    MicroExpr::binary(BinOp::Mul, MicroExpr::var("x1"), MicroExpr::var("x2"))
                )
            )]
        );
    }

    /// An S-form add leaves a real carry, so its flags are the stored *result*
    /// — and the flags statement comes first, before the register write, or SSA
    /// would resolve its operands to the value just written.
    #[test]
    fn an_s_form_add_writes_its_flags_before_its_destination() {
        // `adds x0, x1, x2` -> ab020020
        let sum = MicroExpr::binary(BinOp::Add, MicroExpr::var("x1"), MicroExpr::var("x2"));
        assert_eq!(
            lift_word(0xab020020),
            vec![
                assign(
                    FLAGS_VAR,
                    MicroExpr::compare(CmpKind::Result, sum.clone(), MicroExpr::constant(0, 64))
                ),
                assign("x0", sum),
            ]
        );
    }

    #[test]
    fn adrp_forms_a_page_address_and_adr_a_byte_one() {
        // `adr x0, .+8` -> 10000040, lifted at 0x1000.
        assert_eq!(
            lift_word(0x10000040),
            vec![assign(
                "x0",
                MicroExpr::AddrOf(Box::new(MicroExpr::constant(0x1008, 64)))
            )]
        );
        // `adrp x0, .` -> 90000000: the program counter truncated to its page.
        assert_eq!(
            lift_word(0x90000000),
            vec![assign(
                "x0",
                MicroExpr::AddrOf(Box::new(MicroExpr::constant(0x1000, 64)))
            )]
        );
    }

    /// A call forwards the convention's argument registers, binds its result,
    /// invalidates the caller-saved set, and leaves the flags unknown — plus
    /// the one thing x86-64 has no equivalent of: `bl` writes the link
    /// register with the address of the next instruction.
    #[test]
    fn bl_writes_the_link_register_and_clobbers_the_volatile_set() {
        // `bl .+8` -> 94000002
        let stmts = lift_word(0x94000002);
        assert_eq!(stmts[0], assign("x30", MicroExpr::constant(0x1004, 64)));
        let MicroStmt::Call { target, args, ret } = &stmts[1] else {
            panic!("expected a call, got {:?}", stmts[1]);
        };
        assert_eq!(*target, CallTarget::Direct { va: Va(0x1008) });
        assert_eq!(args.len(), 8, "AAPCS64 passes eight integer arguments");
        assert_eq!(ret.as_deref(), Some("x0"));
        assert!(
            stmts.iter().any(|s| *s
                == assign("x1", MicroExpr::Unknown(crate::CALL_CLOBBER.to_string()))),
            "x1 is caller-saved and must be invalidated"
        );
        assert!(
            !stmts.iter().any(|s| *s
                == assign("x19", MicroExpr::Unknown(crate::CALL_CLOBBER.to_string()))),
            "x19 is callee-saved and must survive"
        );
        assert!(matches!(stmts.last(), Some(MicroStmt::Assign { dst, .. }) if dst == FLAGS_VAR));
    }

    /// An indirect branch's destination exists nowhere else in the IR.
    #[test]
    fn br_records_the_address_it_computes() {
        // `br x0` -> d61f0000
        assert_eq!(
            lift_word(0xd61f0000),
            vec![assign(JUMP_TARGET_VAR, MicroExpr::var("x0"))]
        );
    }

    /// Loads and stores are **not** in this increment, and the honest form of
    /// that is an `Unlifted` statement carrying the instruction verbatim — not
    /// an empty lift, which would say the instruction did nothing.
    ///
    /// **And it must also invalidate what it wrote.** Without that, the next
    /// instruction reads a value the unmodelled one had already replaced, and
    /// the result is a complete-looking expression with a step missing — which
    /// is worse than the `// asm:` line it hides behind.
    #[test]
    fn what_is_out_of_scope_stays_verbatim_and_invalidates_what_it_wrote() {
        // `ldr x0, [x1]` -> f9400020 and `ldp x29, x30, [sp], #16` ->
        // a8c17bfd, both from the same assembler.
        for (word, written) in [(0xf9400020u32, &["x0"][..]), (0xa8c17bfd, &["x29", "x30"])] {
            let stmts = lift_word(word);
            assert!(
                matches!(stmts.first(), Some(MicroStmt::Unlifted { text, .. }) if !text.is_empty()),
                "{word:#010x} must keep its text: {stmts:?}"
            );
            for reg in written {
                assert!(
                    stmts.iter().any(|s| matches!(
                        s,
                        MicroStmt::Assign { dst, value: MicroExpr::Unknown(_) } if dst == reg
                    )),
                    "{word:#010x} writes {reg} and must invalidate it: {stmts:?}"
                );
            }
            assert!(
                matches!(stmts.last(), Some(MicroStmt::Assign { dst, .. }) if dst == FLAGS_VAR),
                "an unmodelled instruction may have touched NZCV: {stmts:?}"
            );
        }
    }

    /// **A recorded defect, not an endorsement.**
    ///
    /// Whether register 31 in an operand position means `xzr` or `sp` is one
    /// fact, and this crate derives it twice: this file reads the operand's
    /// *kind* from the definition (`Rd_SP` ⇒ sp-eligible), while
    /// [`Arch::reg_access`] decides it from the instruction *class*. The two
    /// agree everywhere except `LOG_IMM`, whose `Rd` really is `Rd_SP` —
    /// `and sp, x0, #-16` is a real instruction (gcc emits it to realign the
    /// stack), and `reg_access` records it as writing `xzr`, so the stack
    /// pointer's definition is invisible to def-use.
    ///
    /// The lift is the one that is right. Fixing `reg_access` is a change to a
    /// separate, already-shipped answer and belongs with its own calibration,
    /// so this pins the disagreement: closing it fails **here**, on this line,
    /// instead of leaving a stale sentence behind.
    #[test]
    fn reg_access_and_the_lift_still_disagree_about_a_logical_immediate_writing_sp() {
        let arch = Arm64::new();
        // `and sp, x0, #0xfffffffffffffff0` -> 927cec1f, from the same
        // assembler as everything else here.
        let insn = arch.decode(&le(0x927cec1f), Va(0x1000)).expect("decodes");
        assert_eq!(
            arch.reg_access(&insn).writes,
            vec!["xzr".to_string()],
            "reg_access now agrees that this writes sp — delete this test"
        );
        assert_eq!(
            lift_word(0x927cec1f),
            vec![assign(
                "sp",
                MicroExpr::binary(
                    BinOp::And,
                    MicroExpr::var("x0"),
                    MicroExpr::constant(0xffff_ffff_ffff_fff0u64 as i128, 64)
                )
            )],
            "the lift reads the operand kind and gets it right"
        );
    }

    /// **A recorded limitation, not a passing check.**
    ///
    /// A pre- or post-indexed load/store writes its *base* register back —
    /// `stp x29, x30, [sp, #-16]!` decrements `sp` — and [`Arch::reg_access`]
    /// does not report that write. So the invalidation above cannot cover it,
    /// and after an unmodelled pre-indexed store the IR still believes `sp`
    /// holds its old value. Every stack offset computed from it afterwards is
    /// then a frame too high, which is the *same* defect x86-64 had when
    /// `push` lifted to nothing — and it was measured there against the
    /// compiler's own DWARF frame base.
    ///
    /// Loads and stores are out of this increment, so the fix belongs with
    /// them. This asserts the gap so that closing it fails **here**, on this
    /// line, rather than leaving a stale comment behind.
    #[test]
    fn a_writeback_base_register_is_not_yet_reported_and_therefore_not_invalidated() {
        let arch = Arm64::new();
        // `stp x29, x30, [sp, #-16]!` -> a9bf7bfd
        let insn = arch.decode(&le(0xa9bf7bfd), Va(0x1000)).expect("decodes");
        assert!(
            !arch.reg_access(&insn).writes.iter().any(|w| w == "sp"),
            "reg_access now reports the writeback — teach lift_opaque about it \
             and delete this test"
        );
        assert!(
            !lift_word(0xa9bf7bfd).iter().any(|s| matches!(
                s,
                MicroStmt::Assign { dst, value: MicroExpr::Unknown(_) } if dst == "sp"
            )),
            "sp is not invalidated across a pre-indexed store; see above"
        );
    }

    /// The exact shape the end-to-end run caught: an unmodelled `ubfm` between
    /// two modelled instructions must not let the second read the first's
    /// input. `lsl x0, x0, #3` is a `ubfm`, and `x0` after it is unknown.
    #[test]
    fn an_unmodelled_instruction_does_not_leave_its_destination_readable() {
        // `lsl x0, x1, #4` -> d37cec20, from the same assembler.
        let stmts = lift_word(0xd37cec20);
        assert!(
            stmts.iter().any(|s| matches!(
                s,
                MicroStmt::Assign { dst, value: MicroExpr::Unknown(_) } if dst == "x0"
            )),
            "{stmts:?}"
        );
    }

    // -- the condition seam --------------------------------------------------

    /// **The two architectures' carry flags are inverted, and the mapping is
    /// what absorbs it.** After `cmp x0, x1`, AArch64's `cs` is "no borrow",
    /// which is `x0 >= x1` unsigned — and that is what the reconstruction has
    /// to say, not whatever x86 calls the bit.
    #[test]
    fn unsigned_conditions_survive_the_carry_inversion() {
        let arch = Arm64::new();
        let flags =
            MicroExpr::compare(CmpKind::Cmp, MicroExpr::var("x0"), MicroExpr::var("x1"));
        let (a, b) = (MicroExpr::var("x0"), MicroExpr::var("x1"));
        for (cond, op) in [
            ("b.cs", BinOp::Uge),
            ("b.hs", BinOp::Uge),
            ("b.cc", BinOp::Ult),
            ("b.lo", BinOp::Ult),
            ("b.hi", BinOp::Ugt),
            ("b.ls", BinOp::Ule),
            ("b.eq", BinOp::Eq),
            ("b.ne", BinOp::Ne),
        ] {
            assert_eq!(
                arch.branch_condition(cond, &flags),
                MicroExpr::binary(op, a.clone(), b.clone()),
                "{cond}"
            );
        }
    }

    /// The inversion the mapping **cannot** absorb. `ands` sets `NZCV` to
    /// `<N,Z,0,0>`, so `cs` is constantly false and `cc` constantly true; x86's
    /// logical ops clear `CF`, which makes `jae` true and `jb` false — the
    /// opposite. Delegating these four would answer every one backwards.
    #[test]
    fn the_carry_conditions_after_a_logical_op_are_not_delegated() {
        let arch = Arm64::new();
        let flags = MicroExpr::compare(
            CmpKind::LogicalResult,
            MicroExpr::var("x0"),
            MicroExpr::constant(0, 64),
        );
        for cond in ["b.cs", "b.hs", "b.hi"] {
            assert_eq!(arch.branch_condition(cond, &flags), MicroExpr::constant(0, 8), "{cond}");
        }
        for cond in ["b.cc", "b.lo", "b.ls"] {
            assert_eq!(arch.branch_condition(cond, &flags), MicroExpr::constant(1, 8), "{cond}");
        }
        // The sign and zero conditions *do* delegate: both architectures leave
        // the overflow flag clear, so they mean the same thing on both.
        assert_eq!(
            arch.branch_condition("b.mi", &flags),
            MicroExpr::binary(BinOp::Slt, MicroExpr::var("x0"), MicroExpr::constant(0, 64))
        );
    }

    #[test]
    fn always_is_a_constant_and_never_is_a_refusal() {
        let arch = Arm64::new();
        let flags =
            MicroExpr::compare(CmpKind::Cmp, MicroExpr::var("x0"), MicroExpr::var("x1"));
        assert_eq!(arch.branch_condition("b.al", &flags), MicroExpr::constant(1, 8));
        // `nv` has two exactly opposite readings across architecture versions,
        // so the only answer that cannot be wrong is no answer.
        assert_eq!(
            arch.branch_condition("b.nv", &flags),
            MicroExpr::Unknown("cond(b.nv)".into())
        );
        // …and so does a compare-and-branch, which reads no flags at all.
        assert_eq!(
            arch.branch_condition("cbz", &flags),
            MicroExpr::Unknown("cond(cbz)".into())
        );
    }

    // -- guards on the facts this file reads positionally ---------------------

    /// This file carries its own copy of the condition-code table, because
    /// `disarm64`'s is private. Check the two against each other on all sixteen
    /// values rather than trusting that they were typed the same: assemble
    /// `b.<cond>` for every encoding and compare the decoder's rendering with
    /// [`cond_name`].
    #[test]
    fn condition_names_agree_with_the_decoder() {
        let arch = Arm64::new();
        for c in 0u32..16 {
            // The `B_C` encoding is 0x54000000 | (imm19 << 5) | cond.
            let insn = arch.decode(&le(0x54000000 | c), Va(0x1000)).expect("decodes");
            assert_eq!(
                insn.mnemonic,
                format!("b.{}", cond_name(c)),
                "condition {c} disagrees with the decoder"
            );
        }
    }

    /// The logical-immediate decoder is re-derived here because the decoder's
    /// own is private, so it is pinned against an assembler that is neither.
    /// Each row is `(word, source line, value)` straight out of
    /// `aarch64-linux-gnu-objdump -d`.
    #[test]
    fn logical_immediates_match_an_assembler() {
        let cases: &[(u32, &str, u64)] = &[
            (0x92401c20, "and x0, x1, #0xff", 0xff),
            (0x927cec20, "and x0, x1, #0xfffffffffffffff0", 0xffff_ffff_ffff_fff0),
            (0x1204cc20, "and w0, w1, #0xf0f0f0f0", 0xf0f0_f0f0),
            (0xb200f020, "orr x0, x1, #0x5555555555555555", 0x5555_5555_5555_5555),
            (0x52003c20, "eor w0, w1, #0xffff", 0xffff),
            (0xf2401420, "ands x0, x1, #0x3f", 0x3f),
            (0x7200081f, "tst w0, #0x7", 0x7),
            (0x92742083, "and x3, x4, #0x1ff000", 0x1ff000),
            (0x320100c5, "orr w5, w6, #0x80000000", 0x8000_0000),
            (0xd2410107, "eor x7, x8, #0x8000000000000000", 0x8000_0000_0000_0000),
            (0x1200f149, "and w9, w10, #0x55555555", 0x5555_5555),
            (0x721d718b, "ands w11, w12, #0xfffffff8", 0xffff_fff8),
            (0x92405dcd, "and x13, x14, #0xffffff", 0xffffff),
            (0x12000020, "and w0, w1, #0x1", 1),
        ];
        for (word, source, expected) in cases {
            let op = decoder::decode(*word).expect("decodes");
            let width = access_width(op.definition(), op.bits());
            assert_eq!(
                logical_imm(&op, 2, width),
                Some(MicroExpr::constant(i128::from(*expected), width)),
                "{source}"
            );
        }
    }

    /// The `sf` bit is the one width fact no operand definition carries, so
    /// check the width this file derives against the register spelling the
    /// decoder printed: a `w` in the disassembly means 32 bits, an `x` means
    /// 64. Covers both branches of `access_width`, including the encodings that
    /// have no `sf` at all.
    #[test]
    fn the_derived_width_agrees_with_the_printed_registers() {
        let arch = Arm64::new();
        for (word, expect) in [
            (0x8b020020u32, 64), // add x0, x1, x2
            (0x0b020020, 32),    // add w0, w1, w2
            (0x52800020, 32),    // mov w0, #1
            (0x92800000, 64),    // mov x0, #-1
            (0x1ac22020, 32),    // lsl w0, w1, w2
            (0x9ac20820, 64),    // udiv x0, x1, x2
            (0x34000040, 32),    // cbz w0, .+8
            (0xb5000041, 64),    // cbnz x1, .+8
            (0x10000040, 64),    // adr x0, .+8 — no sf field at all
            (0xd65f03c0, 64),    // ret — likewise
        ] {
            let op = decoder::decode(word).expect("decodes");
            let insn = arch.decode(&le(word), Va(0x1000)).expect("decodes");
            let got = access_width(op.definition(), op.bits());
            assert_eq!(got, expect, "{}", insn.text);
            let printed_w = insn.text.contains(" w") || insn.text.contains("\tw");
            assert_eq!(printed_w, expect == 32, "{}", insn.text);
        }
    }
}
