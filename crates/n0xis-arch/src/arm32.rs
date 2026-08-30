//! `Arm32` — AArch32 / ARMv7 (A32 + Thumb), decode-only, via `yaxpeax-arm`.
//!
//! Our [`Arm64`](crate::Arm64) arch (disarm64) decodes **AArch64 only**; the
//! 32-bit ARM targets that matter here — Android `armeabi-v7a`, the X96 TV-box
//! (`armv7l`) — are a different instruction set it cannot read. This is a
//! decompiler for them: correct decode (A32 by default, Thumb via
//! [`Arm32::thumb`]), control-flow classification + resolved branch targets for
//! the CFG, and a **partial semantic lift** to micro-IR — the common
//! unconditional data-processing (`mov`/`add`/`sub`/`and`/`orr`/`eor`/`bic`/
//! `mvn`/`mul`), simple `ldr`/`str`, `cmp` + the AArch32 branch conditions, and
//! `bl`/`bx lr` calls/returns under AAPCS32. Everything else — predicated
//! (`cond != AL`) forms, shifted-register operands, `ldm`/`stm`, and FP/SIMD —
//! is preserved verbatim and **soundly invalidates its writes** (an unhandled
//! instruction must never let a later read reuse a stale value), so `decomp`
//! yields real pseudocode for the modelled subset and honest `asm` for the rest.
//! Predication-as-`cond ? effect : old`, shift lifting, and `ldm`/`stm` are the
//! remaining follow-ons.

use yaxpeax_arch::{Decoder, LengthedInstruction, U8Reader};
use yaxpeax_arm::armv7::{InstDecoder, Instruction, Opcode, Operand};

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

/// The registers named in an `LDM`/`STM` register-list bitmask.
fn reglist(mask: u16) -> Vec<String> {
    (0u8..16).filter(|i| mask & (1u16 << i) != 0).map(reg_n).collect()
}

/// A simple operand as an rvalue: a register or an immediate. Shifted registers,
/// derefs and reg-lists return `None` (their instructions aren't lifted yet).
fn op_rvalue(op: &Operand) -> Option<MicroExpr> {
    match op {
        Operand::Reg(r) => Some(MicroExpr::var(reg_name(*r))),
        Operand::Imm32(v) => Some(MicroExpr::constant(*v as i128, 32)),
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
        // Predicated (`cond != AL`) forms and any shifted-register operand aren't
        // modelled yet — preserve them and soundly invalidate their writes.
        let cond_al = format!("{:?}", inst.condition) == "AL";
        let has_shift = inst.operands.iter().any(|o| matches!(o, Operand::RegShift(_)));
        if !cond_al || has_shift {
            return self.unlifted(&inst, insn);
        }
        let ops = &inst.operands;
        let mut out = Vec::new();
        match inst.opcode {
            MOV => match (&ops[0], op_rvalue(&ops[1])) {
                (Operand::Reg(rd), Some(v)) => out.push(assign(reg_name(*rd), v)),
                _ => return self.unlifted(&inst, insn),
            },
            MVN => match (&ops[0], op_rvalue(&ops[1])) {
                (Operand::Reg(rd), Some(v)) => out.push(assign(reg_name(*rd), MicroExpr::unary(UnOp::Not, v))),
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
                    out.push(assign(reg_name(*rd), expr));
                }
                _ => return self.unlifted(&inst, insn),
            },
            MUL => match (&ops[0], op_rvalue(&ops[1]), op_rvalue(&ops[2])) {
                (Operand::Reg(rd), Some(a), Some(b)) => out.push(assign(reg_name(*rd), MicroExpr::binary(BinOp::Mul, a, b))),
                _ => return self.unlifted(&inst, insn),
            },
            LDR => match (&ops[0], &ops[1]) {
                (Operand::Reg(rd), Operand::RegDerefPreindexOffset(base, off, add, wb)) => {
                    let addr = deref_addr(*base, *off, *add);
                    out.push(assign(reg_name(*rd), MicroExpr::load(addr.clone(), 32, false)));
                    if *wb {
                        out.push(assign(reg_name(*base), addr));
                    }
                }
                _ => return self.unlifted(&inst, insn),
            },
            STR => match (&ops[0], &ops[1]) {
                (Operand::Reg(rs), Operand::RegDerefPreindexOffset(base, off, add, wb)) => {
                    let addr = deref_addr(*base, *off, *add);
                    out.push(MicroStmt::Store { addr: addr.clone(), value: MicroExpr::var(reg_name(*rs)), bits: 32 });
                    if *wb {
                        out.push(assign(reg_name(*base), addr));
                    }
                }
                _ => return self.unlifted(&inst, insn),
            },
            CMP => {
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
            B => {
                // Structural: the CFG carries the edge; a conditional `b` is
                // reconstructed by `branch_condition` from the reaching flags.
            }
            BX | BXJ => {
                // `bx lr` is the function return; any other `bx` is a computed
                // branch the CFG already models structurally.
                if insn.text.contains("lr") {
                    out.push(MicroStmt::Return(Some(MicroExpr::var("r0"))));
                }
            }
            BL | BLX => {
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
        Ok(DecodedInsn { va, len: len as u8, bytes: bytes[..len].to_vec(), mnemonic, text, kind, target, rip_target: None })
    }

    fn decode_stream(&self, bytes: &[u8], va: Va, max: usize) -> Vec<DecodedInsn> {
        let mut out = Vec::new();
        let mut off = 0usize;
        while out.len() < max && off < bytes.len() {
            match self.decode(&bytes[off..], Va(va.0 + off as u64)) {
                Ok(di) => {
                    let l = di.len as usize;
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
    fn an_unhandled_instruction_invalidates_its_writes_for_soundness() {
        // e92d4010 push {r4, lr} — not lifted, but must not let a later read of a
        // written register reuse a stale value. push writes sp (the writeback
        // base); its regs are a *source*. So sp is invalidated, r4 is not.
        let stmts = lift1(&[0x10, 0x40, 0x2d, 0xe9]);
        assert!(matches!(stmts.first(), Some(MicroStmt::Unlifted { .. })));
        let invalidated: Vec<&str> = stmts
            .iter()
            .filter_map(|s| match s {
                MicroStmt::Assign { dst, value: MicroExpr::Unknown(_) } => Some(dst.as_str()),
                _ => None,
            })
            .collect();
        assert!(invalidated.contains(&"sp"), "push updates sp (writeback): {stmts:?}");
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
