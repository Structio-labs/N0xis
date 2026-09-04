// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `Arm32` — AArch32 / ARMv7 (A32 + Thumb), decode-only, via `yaxpeax-arm`.
//!
//! Our [`Arm64`](crate::Arm64) arch (disarm64) decodes **AArch64 only**; the
//! 32-bit ARM targets that matter here — Android `armeabi-v7a`, the X96 TV-box
//! (`armv7l`) — are a different instruction set it cannot read. This is a
//! decoder for them (A32 by default, Thumb via [`Arm32::thumb`]) with
//! control-flow classification + resolved branch targets for the CFG, plus a
//! **semantic lift for A32**: data-processing (`mov`/`add`/`sub`/`and`/`orr`/
//! `eor`/`bic`/`mvn`/`mul`), simple `ldr`/`str`, `cmp` + the AArch32 branch
//! conditions, `push`/`pop`, `bl`/`bx lr` under AAPCS32, and **predication**
//! (`addne` → `dst = cond ? effect : dst`, via the same `Select` + reaching-flags
//! resolver x64 uses for `cmovcc`). Unmodelled forms (shifted-register operands,
//! `ldm`/`stm` beyond push/pop, FP/SIMD) are preserved as `asm` and **soundly
//! invalidate their writes** so no later read reuses a stale value.
//!
//! **Thumb `IT` blocks are handled soundly.** yaxpeax does not track `IT`
//! (if-then) blocks, so a post-`IT` conditional Thumb instruction decoded
//! standalone reads unconditional — lifting it would silently drop its
//! predicate. So [`Arm32::decode_stream`] is *stateful*: it walks the `IT`
//! mnemonic's Then/Else pattern and stamps each guarded instruction's
//! [`DecodedInsn::cond`], which the CFG carries and the `LiftPass` overlays onto
//! the re-decoded instruction, so the lift reads the real predicate. That is why
//! the lift reads its condition from `insn.cond`, never a fresh re-decode.

use yaxpeax_arch::{Decoder, LengthedInstruction, U8Reader};
use yaxpeax_arm::armv7::{InstDecoder, Instruction, Opcode, Operand, RegShiftStyle, ShiftStyle};

use n0xis_contracts::{Reg, Va};

use crate::insn::{DecodeError, DecodedInsn, InsnKind};
use crate::microir::{BinOp, CallTarget, CmpKind, MicroExpr, MicroStmt, UnOp, FLAGS_VAR};
use crate::{Arch, CallConv, RegAccess, RegDesc, RegisterFile};

/// Interned register ids for AArch32. `r13`=`sp`, `r14`=`lr`, `r15`=`pc`.
pub mod arm32reg {
    use n0xis_contracts::Reg;
    pub const R0: Reg = Reg(0);
    pub const SP: Reg = Reg(13);
    pub const LR: Reg = Reg(14);
    pub const PC: Reg = Reg(15);
}

static ARM32_REGS: &[RegDesc] = &[
    RegDesc { id: Reg(0), name: "r0", size_bits: 32 },
    RegDesc { id: Reg(1), name: "r1", size_bits: 32 },
    RegDesc { id: Reg(2), name: "r2", size_bits: 32 },
    RegDesc { id: Reg(3), name: "r3", size_bits: 32 },
    RegDesc { id: Reg(4), name: "r4", size_bits: 32 },
    RegDesc { id: Reg(5), name: "r5", size_bits: 32 },
    RegDesc { id: Reg(6), name: "r6", size_bits: 32 },
    RegDesc { id: Reg(7), name: "r7", size_bits: 32 },
    RegDesc { id: Reg(8), name: "r8", size_bits: 32 },
    RegDesc { id: Reg(9), name: "r9", size_bits: 32 },
    RegDesc { id: Reg(10), name: "r10", size_bits: 32 },
    RegDesc { id: Reg(11), name: "r11", size_bits: 32 },
    RegDesc { id: Reg(12), name: "r12", size_bits: 32 },
    RegDesc { id: arm32reg::SP, name: "sp", size_bits: 32 },
    RegDesc { id: arm32reg::LR, name: "lr", size_bits: 32 },
    RegDesc { id: arm32reg::PC, name: "pc", size_bits: 32 },
];

// AAPCS32 (the standard ARM 32-bit ABI): integer args in r0-r3, result in r0,
// r0-r3 and r12 caller-saved. Declared for the future lift's arg recovery.
static AAPCS32_INT_ARGS: &[Reg] = &[Reg(0), Reg(1), Reg(2), Reg(3)];
static AAPCS32_VOLATILE: &[Reg] = &[Reg(0), Reg(1), Reg(2), Reg(3), Reg(12)];
static AAPCS32_CC: CallConv = CallConv {
    name: "aapcs32",
    int_args: AAPCS32_INT_ARGS,
    ret: Reg(0),
    volatile: AAPCS32_VOLATILE,
};
static ARM32_CCS: &[CallConv] = &[AAPCS32_CC];

/// AArch32 in one of its two instruction sets. A real image interleaves them
/// (the mode follows a `BX`/`BLX` to an odd address, or a symbol's low bit);
/// tracking that automatically is a follow-on — for now the mode is chosen up
/// front (`--arch arm32` = A32, `--arch thumb` = T32).
#[derive(Clone, Copy, Debug)]
pub struct Arm32 {
    thumb: bool,
    regfile: RegisterFile,
}

impl Arm32 {
    /// A32 (the 4-byte ARM instruction set).
    pub const fn a32() -> Self {
        Arm32 { thumb: false, regfile: RegisterFile::new(ARM32_REGS) }
    }
    /// Thumb / Thumb-2 (2- or 4-byte). What most Android `armeabi-v7a` code is.
    pub const fn thumb() -> Self {
        Arm32 { thumb: true, regfile: RegisterFile::new(ARM32_REGS) }
    }
    fn decoder(&self) -> InstDecoder {
        if self.thumb {
            InstDecoder::default_thumb()
        } else {
            InstDecoder::default()
        }
    }
}

impl Default for Arm32 {
    fn default() -> Self {
        Arm32::a32()
    }
}

/// Best-effort control-flow class for the CFG. Exact only where the opcode
/// alone decides it; the `pc`-writing returns (`pop {…,pc}`, `mov pc, lr`) are
/// recognized from the formatted text, which is sound-conservative — a
/// misclassified edge degrades the CFG, never the decode.
fn classify(inst: &Instruction, text: &str) -> InsnKind {
    let cond_al = format!("{:?}", inst.condition) == "AL";
    match inst.opcode {
        Opcode::BL | Opcode::BLX => InsnKind::Call,
        Opcode::B => {
            if cond_al {
                InsnKind::Jump
            } else {
                InsnKind::CondJump
            }
        }
        Opcode::BX | Opcode::BXJ => {
            // `bx lr` is the canonical function return; any other `bx` is a
            // computed/interworking branch.
            if text.contains("lr") {
                InsnKind::Ret
            } else {
                InsnKind::Jump
            }
        }
        _ => {
            let writes_pc_return = (text.contains("pc") && (text.starts_with("pop") || text.starts_with("ldm")))
                || (text.starts_with("mov") && text.contains("pc") && text.contains("lr"));
            if writes_pc_return {
                InsnKind::Ret
            } else {
                InsnKind::Seq
            }
        }
    }
}

/// Resolve a PC-relative branch/call target so the CFG can split blocks and
/// follow edges. A32 exposes a clean `BranchOffset(words)` operand (`target =
/// va + words*4`, the offset already pipeline-adjusted relative to `va`). Thumb
/// doesn't surface the operand the same way, so its target is parsed from the
/// formatted `$±0xN` displacement — which for Thumb is relative to `PC = va+4`.
/// Returns `None` (a sound "unknown edge") for a computed/register branch or an
/// unparseable form, never a guess.
fn branch_target(inst: &Instruction, text: &str, va: Va, thumb: bool) -> Option<Va> {
    if let Operand::BranchOffset(words) = inst.operands[0] {
        // A32: pipeline-adjusted word offset from `va`.
        return Some(Va(va.0.wrapping_add((words as i64 as u64).wrapping_mul(4))));
    }
    // Thumb: parse `$+0xN` / `$-0xN` from the display; base is `PC = va+4`.
    let rest = text.get(text.find('$')? + 1..)?;
    let (neg, digits) = match rest.as_bytes().first()? {
        b'+' => (false, &rest[1..]),
        b'-' => (true, &rest[1..]),
        _ => return None,
    };
    let hex = digits.trim_start_matches("0x");
    let hex: String = hex.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    let n = u64::from_str_radix(&hex, 16).ok()?;
    let base = if thumb { va.0.wrapping_add(4) } else { va.0 };
    Some(Va(if neg { base.wrapping_sub(n) } else { base.wrapping_add(n) }))
}

/// Register name from a yaxpeax register number: `r0`-`r12`, then `sp`/`lr`/`pc`.
fn reg_n(n: u8) -> String {
    match n {
        13 => "sp".to_string(),
        14 => "lr".to_string(),
        15 => "pc".to_string(),
        _ => format!("r{n}"),
    }
}
fn reg_name(r: yaxpeax_arm::armv7::Reg) -> String {
    reg_n(r.number())
}

/// The instruction's condition code (`Some("eq")`), or `None` when
/// unconditional (`AL`).
fn cond_of(inst: &Instruction) -> Option<String> {
    let c = format!("{:?}", inst.condition).to_lowercase();
    (c != "al").then_some(c)
}

/// The inverse AArch32 condition, for the `else` (`E`) slots of an `IT` block.
fn invert_cond(c: &str) -> String {
    match c {
        "eq" => "ne", "ne" => "eq", "cs" | "hs" => "cc", "cc" | "lo" => "cs",
        "mi" => "pl", "pl" => "mi", "vs" => "vc", "vc" => "vs",
        "hi" => "ls", "ls" => "hi", "ge" => "lt", "lt" => "ge",
        "gt" => "le", "le" => "gt", other => other,
    }
    .to_string()
}

/// From an `IT` instruction's mnemonic (`it`/`itt`/`itte`/…) and its base
/// condition, the per-instruction conditions for the 1-4 instructions it guards.
/// The mnemonic's letters after `it` are `T`(hen)/`E`(lse) for instructions
/// 2..N; instruction 1 is always `Then`. Returns them in order.
fn it_block_conds(mnemonic: &str, cond: &str) -> Vec<String> {
    let Some(pattern) = mnemonic.strip_prefix("it") else {
        return Vec::new();
    };
    let mut conds = vec![cond.to_string()]; // instruction 1 is always Then
    let inv = invert_cond(cond);
    for ch in pattern.chars() {
        conds.push(if ch == 'e' { inv.clone() } else { cond.to_string() });
    }
    conds
}

/// The registers named in an `LDM`/`STM` register-list bitmask.
fn reglist(mask: u16) -> Vec<String> {
    (0u8..16).filter(|i| mask & (1u16 << i) != 0).map(reg_n).collect()
}

/// The binary op for a shift style — `LSL`/`LSR`/`ASR` map to the IR shifts;
/// `ROR` (rotate) has no single IR op and returns `None` (its instruction stays
/// `asm`, sound).
fn shift_op(style: ShiftStyle) -> Option<BinOp> {
    match style {
        ShiftStyle::LSL => Some(BinOp::Shl),
        ShiftStyle::LSR => Some(BinOp::Shr),
        ShiftStyle::ASR => Some(BinOp::Sar),
        _ => None,
    }
}

/// A second-operand as an rvalue: a register, an immediate, or a **shifted
/// register** (`r2, lsl #3` → `(r2 << 3)`; `r2, lsr r7` → `(r2 >>u r7)`).
/// Derefs, reg-lists and `ROR` shifts return `None` (not modelled here).
fn op_rvalue(op: &Operand) -> Option<MicroExpr> {
    match op {
        Operand::Reg(r) => Some(MicroExpr::var(reg_name(*r))),
        Operand::Imm32(v) => Some(MicroExpr::constant(*v as i128, 32)),
        Operand::RegShift(rs) => match rs.into_shift() {
            RegShiftStyle::RegImm(s) => {
                // `lsl #0` is a plain register (the index-register form of a deref).
                if s.stype() == ShiftStyle::LSL && s.imm() == 0 {
                    Some(MicroExpr::var(reg_name(s.shiftee())))
                } else {
                    shift_op(s.stype()).map(|op| MicroExpr::binary(op, MicroExpr::var(reg_name(s.shiftee())), MicroExpr::constant(s.imm() as i128, 32)))
                }
            }
            RegShiftStyle::RegReg(s) => {
                shift_op(s.stype()).map(|op| MicroExpr::binary(op, MicroExpr::var(reg_name(s.shiftee())), MicroExpr::var(reg_name(s.shifter()))))
            }
        },
        _ => None,
    }
}

/// The effective address of a `ldr`/`str` memory operand and, when it
/// write-backs, the base register it updates. Handles both `[Rn, #±off]` and the
/// **shifted-register index** `[Rn, Rm, lsl #k]` / `[Rn, Rm]`. `None` for an
/// addressing form (or a `ror` index) not modelled.
fn deref_addr_of(op: &Operand) -> Option<(MicroExpr, Option<String>)> {
    match op {
        Operand::RegDerefPreindexOffset(base, off, add, wb) => Some((deref_addr(*base, *off, *add), wb.then(|| reg_name(*base)))),
        Operand::RegDerefPreindexRegShift(base, rs, add, wb) => {
            let idx = op_rvalue(&Operand::RegShift(*rs))?;
            let addr = MicroExpr::binary(if *add { BinOp::Add } else { BinOp::Sub }, MicroExpr::var(reg_name(*base)), idx);
            Some((addr, wb.then(|| reg_name(*base))))
        }
        _ => None,
    }
}

/// The effective address of a `[Rn, #±off]` operand.
fn deref_addr(base: yaxpeax_arm::armv7::Reg, off: u16, add: bool) -> MicroExpr {
    let b = MicroExpr::var(reg_name(base));
    if off == 0 {
        b
    } else {
        MicroExpr::binary(if add { BinOp::Add } else { BinOp::Sub }, b, MicroExpr::constant(off as i128, 32))
    }
}

fn assign(dst: String, value: MicroExpr) -> MicroStmt {
    MicroStmt::Assign { dst, value }
}

/// Assign `dst = value`, honoring AArch32 **predication**: an unconditional
/// (`AL`) instruction is a plain assign; a predicated one (`addeq`, `movne`, …)
/// only writes when its condition holds, so it becomes `dst = cond ? value :
/// dst`. The condition rides as the same `setcc:<jcc>` marker the SSA builder
/// resolves from the reaching flags — the identical mechanism x64 uses for
/// `setcc`/`cmov`, reused across arches (the resolver calls `Arch::branch_
/// condition`, which for ARM maps `beq`→`==`, `bhi`→`>u`, …).
fn pred_assign(dst: String, value: MicroExpr, cond_lc: &str, out: &mut Vec<MicroStmt>) {
    if cond_lc == "al" {
        out.push(assign(dst, value));
    } else {
        let cond = MicroExpr::OpaqueFlags { mnemonic: format!("setcc:b{cond_lc}") };
        out.push(assign(dst.clone(), MicroExpr::select(cond, value, MicroExpr::var(dst))));
    }
}

fn reglist_mask(op: &Operand) -> Option<u16> {
    match op {
        Operand::RegList(m) => Some(*m),
        _ => None,
    }
}

/// The registers an instruction **writes**, a *sound over-approximation* — the
/// contract the lift's fallback relies on: an unhandled instruction must
/// invalidate every register it could write, or SSA would reuse a stale value
/// (the exact unsoundness that class of bug is about). Missing a write is
/// unsound; an extra one only costs precision, so where the exact set is unclear
/// the conservative side is taken.
fn writes_of(inst: &Instruction) -> Vec<String> {
    use Opcode::*;
    let mut w = Vec::new();
    // `operand[0]` is the destination for data-processing / loads / mov / mul —
    // for stores, compares and branches it is a *source*, so those are excluded.
    let non_dest0 = matches!(
        inst.opcode,
        STR | STRB | STRH | STRD | STM(..) | CMP | CMN | TST | TEQ | B | BX | BXJ | BL | BLX
    );
    if !non_dest0 && let Operand::Reg(r) = inst.operands[0] {
        w.push(reg_name(r));
    }
    // Multiply-long and `ldrd` write a *second* register (`operand[1]`).
    if matches!(inst.opcode, UMULL | SMULL | UMLAL | SMLAL | LDRD) && let Operand::Reg(r) = inst.operands[1] {
        w.push(reg_name(r));
    }
    for op in &inst.operands {
        match op {
            // `ldm`/`pop` writes its whole register list; `stm`/`push` reads it.
            Operand::RegList(mask) if matches!(inst.opcode, LDM(..)) => w.extend(reglist(*mask)),
            // Write-back updates the base register.
            Operand::RegWBack(base, true) => w.push(reg_name(*base)),
            Operand::RegDerefPreindexOffset(base, _, _, true) => w.push(reg_name(*base)),
            _ => {}
        }
    }
    if matches!(inst.opcode, BL | BLX) {
        w.push("lr".to_string());
    }
    w
}

/// Map an AArch32 conditional-branch mnemonic (`beq`, `bne.w`, `blt`, …) to its
/// comparison, evaluated against the `Compare` a preceding `cmp` set — the same
/// reaching-flags reconstruction the x64 arch uses for `jcc`. Only the
/// signed/unsigned magnitude and (in)equality conditions after a `cmp` are
/// sound from the captured operands; `mi`/`pl`/`vs`/`vc` need the raw N/V flags
/// and stay a placeholder.
fn arm_branch_condition(mnemonic: &str, flags: &MicroExpr) -> MicroExpr {
    let MicroExpr::Compare { kind, lhs, rhs } = flags else {
        return MicroExpr::Unknown(format!("cond({mnemonic})"));
    };
    if *kind != CmpKind::Cmp {
        return MicroExpr::Unknown(format!("cond({mnemonic})"));
    }
    let (l, r) = (lhs.as_ref().clone(), rhs.as_ref().clone());
    let cc = mnemonic.trim_start_matches('b').trim_end_matches(".w").trim_end_matches(".n");
    let bin = |op| MicroExpr::binary(op, l.clone(), r.clone());
    match cc {
        "eq" => bin(BinOp::Eq),
        "ne" => bin(BinOp::Ne),
        "lt" => bin(BinOp::Slt),
        "gt" => bin(BinOp::Sgt),
        "le" => bin(BinOp::Sle),
        "ge" => bin(BinOp::Sge),
        "hi" => bin(BinOp::Ugt),
        "ls" => bin(BinOp::Ule),
        "cc" | "lo" => bin(BinOp::Ult),
        "cs" | "hs" => bin(BinOp::Uge),
        _ => MicroExpr::Unknown(format!("cond({mnemonic})")),
    }
}

impl Arm32 {
    /// Re-decode a neutral `DecodedInsn` back to the yaxpeax instruction for
    /// operand-level lift detail — mirrors `x64_lift::decode_raw`.
    fn redecode(&self, insn: &DecodedInsn) -> Option<Instruction> {
        let mut reader = U8Reader::new(&insn.bytes);
        self.decoder().decode(&mut reader).ok()
    }

    /// The sound fallback for an instruction the lift does not model: preserve it
    /// verbatim, then invalidate every register it could write so no later read
    /// reuses a stale value.
    fn unlifted(&self, inst: &Instruction, insn: &DecodedInsn) -> Vec<MicroStmt> {
        let mut out = vec![MicroStmt::Unlifted { va: insn.va, text: insn.text.clone() }];
        for w in writes_of(inst) {
            out.push(assign(w, MicroExpr::Unknown(insn.text.clone())));
        }
        out
    }
}

impl Arch for Arm32 {
    fn name(&self) -> &'static str {
        if self.thumb {
            "thumb"
        } else {
            "arm32"
        }
    }

    fn pointer_size(&self) -> u8 {
        4
    }

    fn regs(&self) -> &RegisterFile {
        &self.regfile
    }

    fn calling_conventions(&self) -> &[CallConv] {
        ARM32_CCS
    }

    fn reg_access(&self, insn: &DecodedInsn) -> RegAccess {
        let Some(inst) = self.redecode(insn) else {
            return RegAccess::default();
        };
        RegAccess { reads: Vec::new(), writes: writes_of(&inst) }
    }

    fn branch_condition(&self, mnemonic: &str, flags_value: &MicroExpr) -> MicroExpr {
        arm_branch_condition(mnemonic, flags_value)
    }

    fn lift(&self, insn: &DecodedInsn, _abi: &str) -> Vec<MicroStmt> {
        use Opcode::*;
        let Some(inst) = self.redecode(insn) else {
            return vec![MicroStmt::Unlifted { va: insn.va, text: insn.text.clone() }];
        };
        // The condition comes from the *decoded instruction* (`insn.cond`), not a
        // fresh re-decode: for A32 that is the encoding's condition, and for a
        // Thumb `IT`-block member it is the real predicate that `decode_stream`
        // recovered statefully (a standalone re-decode of it reads `AL`). This is
        // what makes the Thumb lift sound — the predicate is never dropped. A
        // shifted-register operand (`add r0, r1, r2, lsl #3`) is handled by
        // `op_rvalue` (→ `(r2 << 3)`); a shift it can't model (`ror`) makes the
        // arm fall through to the sound `asm` fallback.
        let cond_lc = insn.cond.as_deref().unwrap_or("al").to_string();
        let cond_al = cond_lc == "al";
        let ops = &inst.operands;
        let mut out = Vec::new();
        match inst.opcode {
            MOV => match (&ops[0], op_rvalue(&ops[1])) {
                (Operand::Reg(rd), Some(v)) => pred_assign(reg_name(*rd), v, &cond_lc, &mut out),
                _ => return self.unlifted(&inst, insn),
            },
            MVN => match (&ops[0], op_rvalue(&ops[1])) {
                (Operand::Reg(rd), Some(v)) => pred_assign(reg_name(*rd), MicroExpr::unary(UnOp::Not, v), &cond_lc, &mut out),
                _ => return self.unlifted(&inst, insn),
            },
            ADD | SUB | AND | ORR | EOR | BIC => match (&ops[0], op_rvalue(&ops[1]), op_rvalue(&ops[2])) {
                (Operand::Reg(rd), Some(a), Some(b)) => {
                    let expr = match inst.opcode {
                        ADD => MicroExpr::binary(BinOp::Add, a, b),
                        SUB => MicroExpr::binary(BinOp::Sub, a, b),
                        AND => MicroExpr::binary(BinOp::And, a, b),
                        ORR => MicroExpr::binary(BinOp::Or, a, b),
                        EOR => MicroExpr::binary(BinOp::Xor, a, b),
                        // `bic Rd, Rn, op2` = Rn AND NOT op2.
                        _ => MicroExpr::binary(BinOp::And, a, MicroExpr::unary(UnOp::Not, b)),
                    };
                    pred_assign(reg_name(*rd), expr, &cond_lc, &mut out);
                }
                _ => return self.unlifted(&inst, insn),
            },
            MUL => match (&ops[0], op_rvalue(&ops[1]), op_rvalue(&ops[2])) {
                (Operand::Reg(rd), Some(a), Some(b)) => pred_assign(reg_name(*rd), MicroExpr::binary(BinOp::Mul, a, b), &cond_lc, &mut out),
                _ => return self.unlifted(&inst, insn),
            },
            LDR => match (&ops[0], deref_addr_of(&ops[1])) {
                (Operand::Reg(rd), Some((addr, wb))) => {
                    if let Some(base) = wb {
                        // A conditional write-back is two conditional effects —
                        // not modelled; the unconditional form is exact.
                        if !cond_al {
                            return self.unlifted(&inst, insn);
                        }
                        out.push(assign(reg_name(*rd), MicroExpr::load(addr.clone(), 32, false)));
                        out.push(assign(base, addr));
                    } else {
                        pred_assign(reg_name(*rd), MicroExpr::load(addr, 32, false), &cond_lc, &mut out);
                    }
                }
                _ => return self.unlifted(&inst, insn),
            },
            // A conditional store/compare/call/return is more than one predicated
            // register write; those stay `asm` (sound) until modelled.
            STR if cond_al => match (&ops[0], deref_addr_of(&ops[1])) {
                (Operand::Reg(rs), Some((addr, wb))) => {
                    out.push(MicroStmt::Store { addr: addr.clone(), value: MicroExpr::var(reg_name(*rs)), bits: 32 });
                    if let Some(base) = wb {
                        out.push(assign(base, addr));
                    }
                }
                _ => return self.unlifted(&inst, insn),
            },
            CMP if cond_al => {
                // `cmp Rn, op2` — yaxpeax's S-form carries `Rn` twice; the compare
                // is `operand[0]` against the last (immediate/register) operand.
                let lhs = op_rvalue(&ops[0]);
                let rhs = op_rvalue(&ops[2]).or_else(|| op_rvalue(&ops[1]));
                match (lhs, rhs) {
                    (Some(l), Some(r)) => out.push(MicroStmt::Assign {
                        dst: FLAGS_VAR.to_string(),
                        value: MicroExpr::compare(CmpKind::Cmp, l, r),
                    }),
                    _ => return self.unlifted(&inst, insn),
                }
            }
            // `push {…}` — the prologue's stack allocation. Only its `sp`
            // decrement is a GPR effect (the listed registers are *saved*, i.e.
            // read); the memory writes aren't modelled. `pop` is the mirror.
            STM(..) if cond_al && insn.text.starts_with("push") => match (&ops[0], reglist_mask(&ops[1])) {
                (Operand::RegWBack(base, true), Some(mask)) => {
                    let bytes = (mask.count_ones() * 4) as i128;
                    out.push(assign(reg_name(*base), MicroExpr::binary(BinOp::Sub, MicroExpr::var(reg_name(*base)), MicroExpr::constant(bytes, 32))));
                }
                _ => return self.unlifted(&inst, insn),
            },
            LDM(..) if cond_al && insn.text.starts_with("pop") => match (&ops[0], reglist_mask(&ops[1])) {
                (Operand::RegWBack(base, true), Some(mask)) => {
                    let regs = reglist(mask);
                    let has_pc = regs.iter().any(|r| r == "pc");
                    // Restored callee-saved values come off a stack this IR does
                    // not track — mark them Unknown (sound), then adjust `sp`.
                    for r in &regs {
                        if r != "pc" {
                            out.push(assign(r.clone(), MicroExpr::Unknown("restored".to_string())));
                        }
                    }
                    let bytes = (mask.count_ones() * 4) as i128;
                    out.push(assign(reg_name(*base), MicroExpr::binary(BinOp::Add, MicroExpr::var(reg_name(*base)), MicroExpr::constant(bytes, 32))));
                    // `pop {…, pc}` is the function return.
                    if has_pc {
                        out.push(MicroStmt::Return(Some(MicroExpr::var("r0"))));
                    }
                }
                _ => return self.unlifted(&inst, insn),
            },
            B => {
                // Structural: the CFG carries the edge; a conditional `b` is
                // reconstructed by `branch_condition` from the reaching flags.
            }
            BX | BXJ if cond_al => {
                // `bx lr` is the function return; any other `bx` is a computed
                // branch the CFG already models structurally.
                if insn.text.contains("lr") {
                    out.push(MicroStmt::Return(Some(MicroExpr::var("r0"))));
                }
            }
            BL | BLX if cond_al => {
                let args = ARM32_CCS[0].int_args.iter().filter_map(|&r| self.regfile.name(r)).map(MicroExpr::var).collect();
                let target = insn
                    .target
                    .map(|va| CallTarget::Direct { va })
                    .unwrap_or_else(|| CallTarget::Indirect(Box::new(MicroExpr::Unknown("blx-target".to_string()))));
                out.push(MicroStmt::Call { target, args, ret: Some("r0".to_string()) });
                // The call returns into `lr` and clobbers the AAPCS32 caller-saved
                // set — invalidate them so a later read can't reuse a pre-call value.
                for r in ["lr", "r1", "r2", "r3", "r12"] {
                    out.push(assign(r.to_string(), MicroExpr::Unknown("call-clobbered".to_string())));
                }
            }
            _ => return self.unlifted(&inst, insn),
        }
        out
    }

    fn decode(&self, bytes: &[u8], va: Va) -> Result<DecodedInsn, DecodeError> {
        let mut reader = U8Reader::new(bytes);
        let inst = self.decoder().decode(&mut reader).map_err(|_| DecodeError::Invalid(va))?;
        let len = inst.len().to_const() as usize;
        if len == 0 || bytes.len() < len {
            return Err(DecodeError::Truncated(va));
        }
        let text = format!("{inst}");
        // The formatted first word is a clean mnemonic (`pop`, `beq`, `bx`) —
        // the `Opcode` debug carries encoding tuples (`LDM(true, …)`) we don't
        // want in the mnemonic.
        let mnemonic = text.split_whitespace().next().unwrap_or("").to_string();
        let kind = classify(&inst, &text);
        // Resolve the target of a direct branch/call so the CFG follows it.
        let target = matches!(kind, InsnKind::Jump | InsnKind::CondJump | InsnKind::Call)
            .then(|| branch_target(&inst, &text, va, self.thumb))
            .flatten();
        // The condition as decoded standalone. Correct for A32 (it is in the
        // 32-bit encoding); for a Thumb `IT`-block member this reads `al` here
        // and is corrected by the stateful `decode_stream`.
        let cond = cond_of(&inst);
        Ok(DecodedInsn { va, len: len as u8, bytes: bytes[..len].to_vec(), mnemonic, text, kind, target, rip_target: None, cond })
    }

    fn decode_stream(&self, bytes: &[u8], va: Va, max: usize) -> Vec<DecodedInsn> {
        let mut out = Vec::new();
        let mut off = 0usize;
        // Thumb `IT`-block state: the conditions queued for the next instructions
        // (yaxpeax doesn't track this, and a post-`IT` instruction decoded
        // standalone reads `AL`). Because this walk is sequential, it can carry
        // the real per-instruction condition and stamp it onto each `DecodedInsn`
        // — which the CFG (`IrInsn.cond`) and the lift then read instead of a
        // stateless re-decode. This is what makes the Thumb lift *sound*.
        let mut it_conds: std::collections::VecDeque<String> = std::collections::VecDeque::new();
        while out.len() < max && off < bytes.len() {
            match self.decode(&bytes[off..], Va(va.0 + off as u64)) {
                Ok(mut di) => {
                    let l = di.len as usize;
                    if self.thumb {
                        if di.mnemonic.starts_with("it") && di.mnemonic.chars().all(|c| matches!(c, 'i' | 't' | 'e')) {
                            // An `IT` instruction: queue conditions for the block
                            // it opens (its own condition is the text's suffix).
                            let base = di.text.split_whitespace().nth(1).unwrap_or("al");
                            it_conds = it_block_conds(&di.mnemonic, base).into();
                        } else if let Some(c) = it_conds.pop_front() {
                            di.cond = Some(c);
                        }
                    }
                    out.push(di);
                    if l == 0 {
                        break;
                    }
                    off += l;
                }
                Err(_) => {
                    // Emit an Invalid marker (never silently drop bytes) and
                    // stop — a function ends at the first byte that isn't code.
                    out.push(DecodedInsn {
                        va: Va(va.0 + off as u64),
                        len: if self.thumb { 2 } else { 4 },
                        bytes: Vec::new(),
                        mnemonic: "(bad)".to_string(),
                        text: "(bad)".to_string(),
                        kind: InsnKind::Invalid,
                        target: None,
                        rip_target: None,
                        cond: None,
                    });
                    break;
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dis(arch: &Arm32, bytes: &[u8]) -> DecodedInsn {
        arch.decode(bytes, Va(0x1000)).expect("decodes")
    }

    #[test]
    fn a32_decodes_and_classifies_control_flow() {
        let a = Arm32::a32();
        // e12fff1e bx lr → Ret
        let bx = dis(&a, &[0x1e, 0xff, 0x2f, 0xe1]);
        assert_eq!(bx.mnemonic, "bx");
        assert_eq!(bx.len, 4);
        assert_eq!(bx.kind, InsnKind::Ret);
        // 0affffff beq … → CondJump
        let beq = dis(&a, &[0xff, 0xff, 0xff, 0x0a]);
        assert_eq!(beq.kind, InsnKind::CondJump);
        // ebfffffe bl … → Call
        let bl = dis(&a, &[0xfe, 0xff, 0xff, 0xeb]);
        assert_eq!(bl.kind, InsnKind::Call);
        // e8bd8000 pop {pc} → Ret
        let pop = dis(&a, &[0x00, 0x80, 0xbd, 0xe8]);
        assert_eq!(pop.kind, InsnKind::Ret);
    }

    #[test]
    fn a32_branch_target_is_resolved_for_the_cfg() {
        // ea000000 `b $+0x8` at 0x1000 → target 0x1008 (word offset 2 × 4).
        let a = Arm32::a32();
        let b = a.decode(&[0x00, 0x00, 0x00, 0xea], Va(0x1000)).unwrap();
        assert_eq!(b.kind, InsnKind::Jump);
        assert_eq!(b.target, Some(Va(0x1008)));
        // A `bx lr` (register/return) has no resolvable direct target.
        let bx = a.decode(&[0x1e, 0xff, 0x2f, 0xe1], Va(0x1000)).unwrap();
        assert_eq!(bx.target, None);
    }

    #[test]
    fn thumb_uses_two_byte_instructions() {
        // 4770 bx lr (Thumb) — a 2-byte instruction, unlike A32's fixed 4.
        let t = Arm32::thumb();
        let bx = dis(&t, &[0x70, 0x47]);
        assert_eq!(bx.mnemonic, "bx");
        assert_eq!(bx.len, 2);
    }

    fn lift1(bytes: &[u8]) -> Vec<MicroStmt> {
        let a = Arm32::a32();
        let di = a.decode(bytes, Va(0x1000)).unwrap();
        a.lift(&di, "aapcs32")
    }

    #[test]
    fn lifts_the_common_data_processing_and_memory_forms() {
        // e2433004 sub r3, r3, #4  → r3 = (r3 - 0x4)
        assert_eq!(
            lift1(&[0x04, 0x30, 0x43, 0xe2]),
            vec![MicroStmt::Assign { dst: "r3".into(), value: MicroExpr::binary(BinOp::Sub, MicroExpr::var("r3"), MicroExpr::constant(4, 32)) }],
        );
        // e0810002 add r0, r1, r2  → r0 = (r1 + r2)
        assert_eq!(
            lift1(&[0x02, 0x00, 0x81, 0xe0]),
            vec![MicroStmt::Assign { dst: "r0".into(), value: MicroExpr::binary(BinOp::Add, MicroExpr::var("r1"), MicroExpr::var("r2")) }],
        );
        // e5932000 ldr r2, [r3]  → r2 = *(r3)
        assert_eq!(
            lift1(&[0x00, 0x20, 0x93, 0xe5]),
            vec![MicroStmt::Assign { dst: "r2".into(), value: MicroExpr::load(MicroExpr::var("r3"), 32, false) }],
        );
    }

    #[test]
    fn a_shifted_register_operand_lifts_to_a_shift() {
        // e0820181 add r0, r2, r1, lsl #3 → r0 = (r2 + (r1 << 3)).
        assert_eq!(
            lift1(&[0x81, 0x01, 0x82, 0xe0]),
            vec![MicroStmt::Assign {
                dst: "r0".into(),
                value: MicroExpr::binary(
                    BinOp::Add,
                    MicroExpr::var("r2"),
                    MicroExpr::binary(BinOp::Shl, MicroExpr::var("r1"), MicroExpr::constant(3, 32)),
                ),
            }],
        );
    }

    #[test]
    fn a_shifted_index_load_lifts_to_the_scaled_address() {
        // e7900105 ldr r0, [r0, r5, lsl #2] → r0 = *(r0 + (r5 << 2)).
        assert_eq!(
            lift1(&[0x05, 0x01, 0x90, 0xe7]),
            vec![MicroStmt::Assign {
                dst: "r0".into(),
                value: MicroExpr::load(
                    MicroExpr::binary(BinOp::Add, MicroExpr::var("r0"), MicroExpr::binary(BinOp::Shl, MicroExpr::var("r5"), MicroExpr::constant(2, 32))),
                    32,
                    false,
                ),
            }],
        );
        // e7900005 ldr r0, [r0, r5] (plain register index, lsl #0) → r0 = *(r0 + r5).
        assert_eq!(
            lift1(&[0x05, 0x00, 0x90, 0xe7]),
            vec![MicroStmt::Assign { dst: "r0".into(), value: MicroExpr::load(MicroExpr::binary(BinOp::Add, MicroExpr::var("r0"), MicroExpr::var("r5")), 32, false) }],
        );
    }

    #[test]
    fn an_unhandled_instruction_invalidates_its_writes_for_soundness() {
        // e08201e1 add r0, r2, r1, ror #3 — `ror` has no single IR op, so the
        // instruction stays `asm`; but it must invalidate its destination r0 so a
        // later read can't reuse a stale value.
        let stmts = lift1(&[0xe1, 0x01, 0x82, 0xe0]);
        assert!(matches!(stmts.first(), Some(MicroStmt::Unlifted { .. })), "ror stays asm: {stmts:?}");
        let invalidated: Vec<&str> = stmts
            .iter()
            .filter_map(|s| match s {
                MicroStmt::Assign { dst, value: MicroExpr::Unknown(_) } => Some(dst.as_str()),
                _ => None,
            })
            .collect();
        assert!(invalidated.contains(&"r0"), "the unmodelled ror-add must invalidate its dest r0: {stmts:?}");
    }

    #[test]
    fn it_block_conditions_follow_the_then_else_pattern() {
        // `it eq` guards one Then instruction.
        assert_eq!(it_block_conds("it", "eq"), vec!["eq"]);
        // `itt eq` — two Thens.
        assert_eq!(it_block_conds("itt", "eq"), vec!["eq", "eq"]);
        // `ite ne` — Then(ne), Else(eq = the inverse).
        assert_eq!(it_block_conds("ite", "ne"), vec!["ne", "eq"]);
        // `itet gt` — Then(gt), Else(le), Then(gt).
        assert_eq!(it_block_conds("itet", "gt"), vec!["gt", "le", "gt"]);
        assert_eq!(invert_cond("ne"), "eq");
        assert_eq!(invert_cond("hi"), "ls");
    }

    #[test]
    fn thumb_decode_stream_stamps_the_it_block_condition() {
        // Thumb: bf14 'ite ne' ; 6fc0 'ldrne r0,[r0,#0x7c]' ; then the else slot.
        // The instruction after the IT must carry cond=Some("ne"), which the
        // standalone decode of its bytes would report as unconditional.
        let t = Arm32::thumb();
        let stream = t.decode_stream(&[0x14, 0xbf, 0xc0, 0x6f, 0x00, 0x20], Va(0x1000), 3);
        assert!(stream[0].mnemonic.starts_with("it"));
        assert_eq!(stream[1].cond.as_deref(), Some("ne"), "the Then slot gets the IT condition");
    }

    #[test]
    fn a_predicated_instruction_lifts_to_a_conditional_write() {
        // 00810002 addeq r0, r1, r2 — writes only when Z: r0 = cond ? (r1+r2) : r0.
        let a = Arm32::a32();
        let di = a.decode(&[0x02, 0x00, 0x81, 0x00], Va(0x1000)).unwrap();
        let stmts = a.lift(&di, "aapcs32");
        let MicroStmt::Assign { dst, value: MicroExpr::Select { a: then, b: els, .. } } = &stmts[0] else {
            panic!("a predicated add must be a conditional select, got {stmts:?}");
        };
        assert_eq!(dst, "r0");
        assert_eq!(**then, MicroExpr::binary(BinOp::Add, MicroExpr::var("r1"), MicroExpr::var("r2")));
        assert_eq!(**els, MicroExpr::var("r0"), "the else-branch keeps the old r0");
    }

    #[test]
    fn push_and_pop_move_the_stack_pointer_and_pop_pc_returns() {
        // e92d4010 push {r4, lr} → sp = sp - 8 (2 regs).
        let push = lift1(&[0x10, 0x40, 0x2d, 0xe9]);
        assert_eq!(
            push,
            vec![MicroStmt::Assign { dst: "sp".into(), value: MicroExpr::binary(BinOp::Sub, MicroExpr::var("sp"), MicroExpr::constant(8, 32)) }],
        );
        // e8bd8010 pop {r4, pc} → r4 restored, sp += 8, return.
        let pop = lift1(&[0x10, 0x80, 0xbd, 0xe8]);
        assert!(pop.iter().any(|s| matches!(s, MicroStmt::Assign { dst, .. } if dst == "sp")));
        assert!(pop.iter().any(|s| matches!(s, MicroStmt::Return(_))), "pop {{…,pc}} returns: {pop:?}");
    }

    #[test]
    fn a_bl_lifts_to_a_call_with_aapcs32_args_and_clobbers() {
        // ebfffffe bl $+0 → r0 = f(r0, r1, r2, r3); lr and caller-saved clobbered.
        let stmts = lift1(&[0xfe, 0xff, 0xff, 0xeb]);
        let call = stmts.iter().find(|s| matches!(s, MicroStmt::Call { .. })).expect("a call");
        let MicroStmt::Call { args, ret, .. } = call else { unreachable!() };
        assert_eq!(args.len(), 4, "AAPCS32 passes r0-r3");
        assert_eq!(ret.as_deref(), Some("r0"));
        // lr is clobbered by the call.
        assert!(stmts.iter().any(|s| matches!(s, MicroStmt::Assign { dst, value: MicroExpr::Unknown(_) } if dst == "lr")));
    }

    #[test]
    fn arm32_is_32bit_with_the_aapcs32_abi() {
        let a = Arm32::a32();
        assert_eq!(a.pointer_size(), 4);
        assert_eq!(a.calling_conventions()[0].name, "aapcs32");
        assert!(a.regs().by_name("lr").is_some());
    }
}
