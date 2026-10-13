// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `Arm32` — AArch32 / ARMv7 (A32 + Thumb), decode + lift, via `yaxpeax-arm`.
//!
//! Our [`Arm64`](crate::Arm64) arch (disarm64) decodes **AArch64 only**; the
//! 32-bit ARM targets that matter here — Android `armeabi-v7a`, a 32-bit TV box
//! (`armv7l`) — are a different instruction set it cannot read. This is a
//! decoder for them (A32 by default, Thumb via [`Arm32::thumb`]) with
//! control-flow classification + resolved branch targets for the CFG, plus a
//! **semantic lift for A32**: data-processing (`mov`/`add`/`sub`/`and`/`orr`/
//! `eor`/`bic`/`mvn`/`mul`), simple `ldr`/`str`, `cmp` + the AArch32 branch
//! conditions, `push`/`pop`, `bl`/`bx lr` under AAPCS32, and **predication**
//! (`addne` → `dst = cond ? effect : dst`, via the same `Select` + reaching-flags
//! resolver x64 uses for `cmovcc`). Shifted-register operands lift to the
//! shift (`lsl`/`lsr`/`asr`, by an immediate or a register). Unmodelled forms
//! (rotates — `ror`/`rrx` — `ldm`/`stm` beyond push/pop, FP/SIMD) are preserved
//! as `asm` and **soundly invalidate their writes** so no later read reuses a
//! stale value.
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
use yaxpeax_arm::armv7::{ConditionCode, InstDecoder, Instruction, Opcode, Operand, RegShiftStyle, ShiftStyle};

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
// r0-r3 and r12 caller-saved. The lift's `bl` reads these for its arguments
// and its clobbers.
static AAPCS32_INT_ARGS: &[Reg] = &[Reg(0), Reg(1), Reg(2), Reg(3)];
static AAPCS32_VOLATILE: &[Reg] = &[Reg(0), Reg(1), Reg(2), Reg(3), Reg(12)];
static AAPCS32_CC: CallConv = CallConv {
    name: "aapcs32",
    int_args: AAPCS32_INT_ARGS,
    ret: Reg(0),
    volatile: AAPCS32_VOLATILE,
    // The lift models no floating-point register (VFP/NEON instructions stay
    // `asm`), so there is no modelled float return register and nothing to
    // invalidate across a call. `None` states that about the model; it is not
    // a claim about the ABI, whose hard-float variant returns in `s0`/`d0` and
    // clobbers `d0`-`d7` and `d16`-`d31`.
    ret_float: None,
    volatile_float: &[],
    ret_float_second: None,
    // Same as `ret_float`: a statement about this model, not about the ABI —
    // whose hard-float variant passes floating-point arguments in `s0`-`s15`
    // (`d0`-`d7`).
    float_args: &[],
    float_args_share_position: false,
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

    /// Decode one instruction. **The only call into yaxpeax in this file** —
    /// [`Arch::decode`], [`Arch::decode_stream`] and [`Arm32::redecode`] all
    /// come through here, so what the decoder gets wrong is corrected once:
    ///
    /// * **It panics on some words.** 0.5.0 builds the second register of an
    ///   A32 `ldrd`/`strd` as `Rt + 1` before checking `Rt`, and for `Rt = 15`
    ///   that is register 16, which `Reg::from_u8` refuses with a panic —
    ///   1 474 560 words of the 2^32 (0.4.0: none; Thumb: none in either). One
    ///   such word is enough to end the process without its JSON envelope. Those words are refused
    ///   *before* the decoder sees them ([`a32_rt_pair_overflows`]), and the
    ///   decode itself runs under `catch_unwind` as the backstop for a class
    ///   not yet known. Refusing first rather than relying on the backstop
    ///   alone is what keeps a sweep over data quiet: the panic hook is global
    ///   to the process, so silencing it here would also silence every other
    ///   panic the process has; a known class never reaches it, and an unknown
    ///   one *should* be loud. Under `panic = "abort"` the backstop cannot
    ///   catch anything and the refusal is the whole defence.
    /// * **It returns `Ok` with [`Opcode::Invalid`]** for 983 040 A32 words,
    ///   and the text read `invalideq` — an undecodable word shown as an
    ///   instruction. That is a decode error, with one exception the decoder
    ///   makes necessary: it returns the same `Invalid` for the whole A32
    ///   **hint** space, `nop` (`0xe320f000`) included, and a `nop` read as a
    ///   decode error would end every function walk at the first one. Those
    ///   are recognised here instead ([`a32_hint`]); everything else `Invalid`
    ///   is refused (`0x03200000`, which LLVM rejects too).
    /// * **It builds `mvn` (immediate) with a phantom operand** — the generic
    ///   `[Rd, Rn, #imm]` shape with `Rn` a should-be-zero field — so the text
    ///   read `mvn r3, r0, 0x0` for `mvn r3, #0`. The operand is dropped here, so
    ///   the text and the lift both see `[Rd, #imm]`, the shape every other move
    ///   has.
    fn decode_inst(&self, bytes: &[u8]) -> Option<Instruction> {
        if !self.thumb
            && let Some(word) = bytes.first_chunk::<4>().map(|b| u32::from_le_bytes(*b))
            && a32_rt_pair_overflows(word)
        {
            return None;
        }
        let decoder = self.decoder();
        let mut reader = U8Reader::new(bytes);
        let mut inst = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decoder.decode(&mut reader))).ok()?.ok()?;
        if inst.opcode == Opcode::Invalid {
            let word = bytes.first_chunk::<4>().map(|b| u32::from_le_bytes(*b)).filter(|_| !self.thumb)?;
            a32_hint(&mut inst, word)?;
        }
        if let [rd @ Operand::Reg(_), Operand::Reg(_), imm @ Operand::Imm32(_), Operand::Nothing] = inst.operands
            && inst.opcode == Opcode::MVN
        {
            inst.operands = [rd, imm, Operand::Nothing, Operand::Nothing];
        }
        Some(inst)
    }
}

/// An A32 **hint** — `cond 0011 0010 0000 1111 0000 op2`, the one encoding
/// space yaxpeax returns as [`Opcode::Invalid`] while the architecture
/// allocates every word of it: `nop`, `yield`, `wfe`, `wfi`, `sev`, `csdb` by
/// name, and any other `op2` an unallocated hint that executes as a `nop`
/// (`hint #n`). Checked against llvm-mc for `-triple=armv7`, which names them
/// all, and `armv6`, which prints each as `hint #n`. Sets the opcode, or
/// returns `None` for a word outside that space — a real decode error.
fn a32_hint(inst: &mut Instruction, word: u32) -> Option<()> {
    if word >> 28 == 0b1111 || word & 0x0fff_ff00 != 0x0320_f000 {
        return None;
    }
    let op2 = word & 0xff;
    let (opcode, operands) = match op2 {
        0x00 => (Opcode::NOP, Operand::Nothing),
        0x01 => (Opcode::YIELD, Operand::Nothing),
        0x02 => (Opcode::WFE, Operand::Nothing),
        0x03 => (Opcode::WFI, Operand::Nothing),
        0x04 => (Opcode::SEV, Operand::Nothing),
        0x14 => (Opcode::CSDB, Operand::Nothing),
        _ => (Opcode::HINT, Operand::Imm32(op2)),
    };
    inst.opcode = opcode;
    inst.operands = [operands, Operand::Nothing, Operand::Nothing, Operand::Nothing];
    Some(())
}

/// An A32 `ldrd`/`strd` (the "extra load/store" forms, `op2` = `1101`/`1111`
/// with `L` = 0) whose first register is `r15` — the class yaxpeax 0.5.0
/// panics on, because it names the pair's second register as `r16`. The
/// architecture makes these UNPREDICTABLE and LLVM rejects them, so refusing
/// them loses nothing. The mask is exactly the panicking set: 15 conditions ×
/// 16 `P`/`U`/`I`/`W` combinations × the free fields, less the `P = 0, W = 1`
/// words the decoder rejects before it builds a register — and rejecting those
/// too costs nothing, since they are decode errors either way. The exhaustive
/// check is `a32_decoder_boundary_holds_for_every_word`.
fn a32_rt_pair_overflows(word: u32) -> bool {
    const FIXED_MASK: u32 = 0x0e10_00d0; // bits 27-25, 20, 7, 6, 4
    const FIXED_BITS: u32 = 0x0000_00d0; // 000 . 0 . 1 1 . 1
    word >> 28 != 0b1111 && word & FIXED_MASK == FIXED_BITS && (word >> 12) & 0xf == 15
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
/// follow edges, from the decoded offset operand (never from the text). A32
/// exposes `BranchOffset(words)`, pipeline-adjusted relative to `va`: `target =
/// va + words*4`. Thumb exposes `BranchThumbOffset(halfwords)`, relative to
/// `PC = va + 4` — except the 16-bit conditional `b<cond>` (encoding T1), where
/// the decoder has already added one halfword to the field, so its base is
/// `va + 2`. Reading every Thumb form as `va + 4` put each 16-bit conditional
/// branch two bytes past its target (`01d0` at 0x100 is `beq 0x106`; this said
/// 0x108). Returns `None` (a sound "unknown edge") for a computed/register
/// branch, never a guess.
fn branch_target(inst: &Instruction, va: Va, len: usize) -> Option<Va> {
    let (base, offset) = match inst.operands[0] {
        Operand::BranchOffset(words) => (va.0, (words as i64).wrapping_mul(4)),
        Operand::BranchThumbOffset(halfwords) => {
            let t1_conditional = inst.opcode == Opcode::B && len == 2 && inst.condition != ConditionCode::AL;
            (va.0.wrapping_add(if t1_conditional { 2 } else { 4 }), (halfwords as i64).wrapping_mul(2))
        }
        _ => return None,
    };
    Some(Va(base.wrapping_add(offset as u64)))
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
/// `ROR` and `RRX` (rotates; `RRX` also shifts the carry flag in) have no IR op
/// and return `None`, so their instruction stays `asm` (sound).
fn shift_op(style: ShiftStyle) -> Option<BinOp> {
    match style {
        ShiftStyle::LSL => Some(BinOp::Shl),
        ShiftStyle::LSR => Some(BinOp::Shr),
        ShiftStyle::ASR => Some(BinOp::Sar),
        _ => None,
    }
}

/// A register shifted by an **immediate**, as an rvalue.
///
/// `LSR #32` and `ASR #32` are real A32 shifts (encoded with an amount field of
/// 0, which the decoder reports as 32), and a 32-bit value shifted by its own
/// width is not something this IR may say: an IR shift carries no width of its
/// own, so what `x >> 32` yields depends on how wide the evaluator holds `x`
/// (the emulator's `binop` works on `u64`), and printed as C on a 32-bit
/// operand it is undefined behaviour. So the result is stated outright —
/// `LSR #32` empties the register, `ASR #32` fills it with the sign bit, which
/// is exactly `rm >>s 31`. `LSL` cannot encode 32. Under the 0.4 decoder the
/// amount came back as 0 and these read as "no shift" — `lsr r0, r1, #32`
/// lifted to `r0 = r1`.
fn imm_shift(style: ShiftStyle, rm: MicroExpr, amount: u8) -> Option<MicroExpr> {
    match (style, amount) {
        // `lsl #0` is a plain register (the index-register form of a deref).
        (ShiftStyle::LSL, 0) => Some(rm),
        (ShiftStyle::LSR, 32) => Some(MicroExpr::constant(0, 32)),
        (ShiftStyle::ASR, 32) => Some(shift(BinOp::Sar, rm, MicroExpr::constant(31, 32))),
        _ => shift_op(style).map(|op| shift(op, rm, MicroExpr::constant(amount as i128, 32))),
    }
}

/// `rm <op> count`, with the operand of an arithmetic shift read as signed.
/// The IR's `Sar` sign-fills from whatever width its operand is held at, and an
/// A32 register is held zero-extended, so `asr` of a negative value shifted a
/// positive number — zeros where the processor shifts in ones — and printed as
/// a logical shift of a `uint32_t`. x86 and AArch64 read the operand through
/// `flags::signed_view` for the same reason.
fn shift(op: BinOp, rm: MicroExpr, count: MicroExpr) -> MicroExpr {
    let rm = if op == BinOp::Sar { signed32(rm) } else { rm };
    MicroExpr::binary(op, rm, count)
}

/// An A32 operand read as a signed 32-bit value. `flags::signed_view` finds the
/// width on a cast or a load, and an A32 register is a bare `Var` that carries
/// none — every one of them is 32 bits, so the width is stated here. A constant
/// with bit 31 clear means the same either way and stays as it is.
fn signed32(e: MicroExpr) -> MicroExpr {
    match e {
        MicroExpr::Const { value, .. } if value & 0x8000_0000 == 0 => e,
        other => MicroExpr::Cast { signed: true, bits: 32, expr: Box::new(other) },
    }
}

/// A second-operand as an rvalue: a register, an immediate, or a **shifted
/// register** (`r2, lsl #3` → `(r2 << 3)`; `r2, lsr r7` → `(r2 >>u r7)`).
/// Derefs, reg-lists and rotates (`ror`/`rrx`) return `None` (not modelled
/// here).
fn op_rvalue(op: &Operand) -> Option<MicroExpr> {
    match op {
        Operand::Reg(r) => Some(MicroExpr::var(reg_name(*r))),
        Operand::Imm32(v) => Some(MicroExpr::constant(*v as i128, 32)),
        Operand::RegShift(rs) => match rs.into_shift() {
            RegShiftStyle::RegImm(s) => imm_shift(s.stype(), MicroExpr::var(reg_name(s.shiftee())), s.imm()),
            // The count is the **low byte** of the shifting register (ARM ARM,
            // "Shifts applied to a register"); 32..=255 empty the register, or
            // fill it with the sign for `asr`, which is exactly what the IR's
            // shift means past the width (`Shift::apply`).
            RegShiftStyle::RegReg(s) => shift_op(s.stype()).map(|op| {
                let count = MicroExpr::binary(BinOp::And, MicroExpr::var(reg_name(s.shifter())), MicroExpr::constant(0xff, 32));
                shift(op, MicroExpr::var(reg_name(s.shiftee())), count)
            }),
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

/// The flags, written by an instruction whose flag result is not modelled.
/// `OpaqueFlags` is what the x64 and AArch64 lifts write for the same case: it
/// is not a `Compare`, so [`arm_branch_condition`] answers a placeholder.
fn opaque_flags(insn: &DecodedInsn) -> MicroStmt {
    assign(FLAGS_VAR.to_string(), MicroExpr::OpaqueFlags { mnemonic: insn.mnemonic.clone() })
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

/// The destination and source of a move-class instruction (`mov`/`mvn`), from
/// the operand shapes the decoder actually builds — matched whole, so a slot
/// that holds an encoding's should-be-zero field is never read as a value.
///
/// `[Rd, src]` — every register, shifted-register and immediate form, A32 and
/// Thumb. A32 `mvn` (immediate) arrives from the decoder as `[Rd, Rn, #imm]`
/// with `Rn` the should-be-zero field; [`Arm32::decode_inst`] drops that
/// operand, because reading slot 1 lifted `mvn r3, #0` to `r3 = ~r0` and the
/// text showed it too. Any other shape is not a move this lift knows.
///
/// Under the 0.4 decoder the shifted-register forms had the same extra slot —
/// `[Rd, Rn, Rm-shifted]` — and taking slot 1 lifted `lsl r0, r1, #2` to
/// `r0 = r0`, losing the result of every shifted move.
fn move_operands(ops: &[Operand; 4]) -> Option<(yaxpeax_arm::armv7::Reg, &Operand)> {
    match ops {
        [Operand::Reg(rd), src, Operand::Nothing, Operand::Nothing] => Some((*rd, src)),
        _ => None,
    }
}

/// A data-processing instruction's destination and result, for the forms the
/// lift models: the moves (via [`move_operands`]) and `add`/`sub`/`and`/`orr`/
/// `eor`/`bic`/`mul` as `[Rd, Rn, op2]`. `None` for any other shape (Thumb's
/// two-operand `adds r0, r1` among them) — the caller keeps it `asm`.
fn data_processing(inst: &Instruction) -> Option<(String, MicroExpr)> {
    use Opcode::*;
    let ops = &inst.operands;
    if matches!(inst.opcode, MOV | MVN) {
        let (rd, src) = move_operands(ops)?;
        let value = match (inst.opcode, src) {
            // `mvn rd, #imm` is a constant; state it as one (`mvn r0, #0` is
            // 0xffffffff, not `~0x0` left for a reader to evaluate).
            (MVN, Operand::Imm32(v)) => MicroExpr::constant(!*v as i128, 32),
            (MVN, src) => MicroExpr::unary(UnOp::Not, op_rvalue(src)?),
            (_, src) => op_rvalue(src)?,
        };
        return Some((reg_name(rd), value));
    }
    let [Operand::Reg(rd), a, b, Operand::Nothing] = ops else {
        return None;
    };
    let (a, b) = (op_rvalue(a)?, op_rvalue(b)?);
    let value = match inst.opcode {
        ADD => MicroExpr::binary(BinOp::Add, a, b),
        SUB => MicroExpr::binary(BinOp::Sub, a, b),
        AND => MicroExpr::binary(BinOp::And, a, b),
        ORR => MicroExpr::binary(BinOp::Or, a, b),
        EOR => MicroExpr::binary(BinOp::Xor, a, b),
        // `bic Rd, Rn, op2` = Rn AND NOT op2.
        BIC => MicroExpr::binary(BinOp::And, a, MicroExpr::unary(UnOp::Not, b)),
        MUL => MicroExpr::binary(BinOp::Mul, a, b),
        _ => return None,
    };
    Some((reg_name(*rd), value))
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
///
/// After a `tst` only `eq`/`ne` are answered. The shared x86-vocabulary rules
/// in [`crate::flags`] answer the whole family after `test`, because x86's
/// `test` (and AArch64's `ands`) clear carry and overflow; A32 `tst` does not —
/// it sets `C` from the shifter's carry-out and leaves `V` alone — so every
/// condition but the zero flag's would be read from bits nothing here models.
fn arm_branch_condition(mnemonic: &str, flags: &MicroExpr) -> MicroExpr {
    let MicroExpr::Compare { kind, lhs, rhs } = flags else {
        return MicroExpr::Unknown(format!("cond({mnemonic})"));
    };
    let (l, r) = (lhs.as_ref().clone(), rhs.as_ref().clone());
    let cc = mnemonic.trim_start_matches('b').trim_end_matches(".w").trim_end_matches(".n");
    if *kind == CmpKind::Test {
        // `Z` is `(Rn & op2) == 0`; `tst r, r` is the "is r zero" idiom.
        let val = if l == r { l } else { MicroExpr::binary(BinOp::And, l, r) };
        let zero = MicroExpr::constant(0, 32);
        return match cc {
            "eq" => MicroExpr::binary(BinOp::Eq, val, zero),
            "ne" => MicroExpr::binary(BinOp::Ne, val, zero),
            _ => MicroExpr::Unknown(format!("cond({mnemonic}) after tst")),
        };
    }
    if *kind != CmpKind::Cmp {
        return MicroExpr::Unknown(format!("cond({mnemonic})"));
    }
    let bin = |op| MicroExpr::binary(op, l.clone(), r.clone());
    // The signed conditions read both operands as signed 32-bit values; on raw
    // registers `-1 < 0` was false and printed as an unsigned compare.
    let signed = |op| MicroExpr::binary(op, signed32(l.clone()), signed32(r.clone()));
    match cc {
        "eq" => bin(BinOp::Eq),
        "ne" => bin(BinOp::Ne),
        "lt" => signed(BinOp::Slt),
        "gt" => signed(BinOp::Sgt),
        "le" => signed(BinOp::Sle),
        "ge" => signed(BinOp::Sge),
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
        self.decode_inst(&insn.bytes)
    }

    /// The sound fallback for an instruction the lift does not model: preserve it
    /// verbatim, then invalidate every register it could write so no later read
    /// reuses a stale value — and the flags, when it sets them, so no later
    /// branch reuses a stale compare. Without that a `tst` kept as `asm`
    /// between a `cmp` and a `beq` let the branch read the `cmp`.
    fn unlifted(&self, inst: &Instruction, insn: &DecodedInsn) -> Vec<MicroStmt> {
        let mut out = vec![MicroStmt::Unlifted { va: insn.va, text: insn.text.clone() }];
        for w in writes_of(inst) {
            out.push(assign(w, MicroExpr::Unknown(insn.text.clone())));
        }
        if self.sets_flags(inst, insn) {
            out.push(opaque_flags(insn));
        }
        out
    }

    /// Does this instruction write the condition flags? A *sound
    /// over-approximation*, like [`writes_of`]: a flags write the lift misses
    /// lets a later branch read an earlier compare — a wrong condition, not a
    /// missing one — while an extra one only costs that branch its condition.
    ///
    /// The compares always set them, `msr` may (its mask is not inspected), and
    /// any other instruction does when its `S` bit is set — except a 16-bit
    /// Thumb instruction inside an `IT` block, which never does: those
    /// encodings mean `adds` outside a block and `add` inside one. yaxpeax does
    /// not track `IT`, so it reports the outside reading; an instruction whose
    /// condition came from `decode_stream`'s `IT` walk (the standalone decode
    /// reads `AL`) is the inside one.
    fn sets_flags(&self, inst: &Instruction, insn: &DecodedInsn) -> bool {
        use Opcode::*;
        if matches!(inst.opcode, CMP | CMN | TST | TEQ | MSR) {
            return true;
        }
        let in_it_block = self.thumb && insn.cond.is_some() && cond_of(inst).is_none();
        inst.s() && !(in_it_block && insn.len == 2)
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
        // `op_rvalue` (→ `(r2 << 3)`); a shift it can't model (`ror`, `rrx`)
        // makes the arm fall through to the sound `asm` fallback.
        let cond_lc = insn.cond.as_deref().unwrap_or("al").to_string();
        let cond_al = cond_lc == "al";
        let ops = &inst.operands;
        let mut out = Vec::new();
        match inst.opcode {
            MOV | MVN | ADD | SUB | AND | ORR | EOR | BIC | MUL => {
                let Some((rd, value)) = data_processing(&inst) else {
                    return self.unlifted(&inst, insn);
                };
                if !self.sets_flags(&inst, insn) {
                    pred_assign(rd, value, &cond_lc, &mut out);
                } else if !cond_al {
                    // A predicated flag-setting write is two conditional
                    // effects — not modelled.
                    return self.unlifted(&inst, insn);
                } else if let MicroExpr::Binary(BinOp::Sub, a, b) = &value
                    && inst.opcode == SUB
                {
                    // `subs Rd, Rn, op2` sets the flags exactly as `cmp Rn, op2`
                    // does (the ARM ARM defines `cmp` as `subs` with the result
                    // discarded) — from the operands *before* `Rd` is written,
                    // so the flags come first: `subs r0, r0, #1` must compare
                    // the old `r0`.
                    out.push(assign(FLAGS_VAR.to_string(), MicroExpr::compare(CmpKind::Cmp, a.as_ref().clone(), b.as_ref().clone())));
                    out.push(assign(rd, value));
                } else {
                    // Any other `S` form: the result is exact, its flags are not
                    // modelled — and must still stop an earlier compare reaching
                    // the next branch.
                    out.push(assign(rd, value));
                    out.push(opaque_flags(insn));
                }
            }
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
            TST if cond_al => match ops {
                // `tst Rn, op2` sets `Z` from `Rn & op2` — the `Test` compare
                // kind; see `arm_branch_condition` for which conditions that
                // answers on this architecture.
                [rn @ Operand::Reg(_), op2, Operand::Nothing, Operand::Nothing] => match (op_rvalue(rn), op_rvalue(op2)) {
                    (Some(l), Some(r)) => out.push(assign(FLAGS_VAR.to_string(), MicroExpr::compare(CmpKind::Test, l, r))),
                    _ => return self.unlifted(&inst, insn),
                },
                _ => return self.unlifted(&inst, insn),
            },
            CMP if cond_al => {
                // `cmp Rn, op2` is exactly two operands. The shape is matched
                // whole, not read slot by slot: the 0.4 decoder emitted
                // `[Rd, Rn, op2]` with `Rd` a should-be-zero field, and the old
                // "slot 0 against the last operand" reading turned every
                // `cmp r3, #5` into a compare of `r0`. Any other shape is not a
                // form this lift knows, so it stays `asm`.
                let (lhs, rhs) = match ops {
                    [lhs @ Operand::Reg(_), rhs, Operand::Nothing, Operand::Nothing] => (op_rvalue(lhs), op_rvalue(rhs)),
                    _ => return self.unlifted(&inst, insn),
                };
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
                    out.push(assign(r.to_string(), MicroExpr::Unknown(crate::CALL_CLOBBER.to_string())));
                }
            }
            _ => return self.unlifted(&inst, insn),
        }
        out
    }

    fn decode(&self, bytes: &[u8], va: Va) -> Result<DecodedInsn, DecodeError> {
        let inst = self.decode_inst(bytes).ok_or(DecodeError::Invalid(va))?;
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
            .then(|| branch_target(&inst, va, len))
            .flatten();
        // The condition as decoded standalone. Correct for A32 (it is in the
        // 32-bit encoding); for a Thumb `IT`-block member this reads `al` here
        // and is corrected by the stateful `decode_stream`.
        let cond = cond_of(&inst);
        Ok(DecodedInsn { va, len: len as u8, bytes: bytes[..len].to_vec(), mnemonic, text, kind, target, rip_target: None, cond, stack_adjust: None })
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
                        stack_adjust: None,
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

    // ---- shifted moves, shift-by-32, rotates, compares -------------------------
    //
    // The expected meanings below are the ARM ARM's, and each encoding was
    // checked once against an independent disassembler (`llvm-mc --disassemble
    // -triple=armv6-none-eabi`), whose spelling is quoted per case. Under the
    // 0.4 decoder every shifted move lifted wrong or failed to decode.

    fn assign_to(dst: &str, value: MicroExpr) -> Vec<MicroStmt> {
        vec![MicroStmt::Assign { dst: dst.into(), value }]
    }

    fn c32(v: i128) -> MicroExpr {
        MicroExpr::constant(v, 32)
    }

    /// `e` read as a signed 32-bit value.
    fn s32(e: MicroExpr) -> MicroExpr {
        MicroExpr::Cast { signed: true, bits: 32, expr: Box::new(e) }
    }

    /// The registers an `asm` fallback invalidated, in order.
    fn invalidated(stmts: &[MicroStmt]) -> Vec<&str> {
        stmts
            .iter()
            .filter_map(|s| match s {
                MicroStmt::Assign { dst, value: MicroExpr::Unknown(_) } => Some(dst.as_str()),
                _ => None,
            })
            .collect()
    }

    /// A move with a shift-by-immediate is the shift. The decoder used to carry
    /// the should-be-zero `Rn` field as the move's source, so `lsl r0, r1, #2`
    /// lifted to `r0 = r0` and a whole function's result vanished.
    #[test]
    fn a_move_with_an_immediate_shift_lifts_to_the_shift() {
        // e1a00101  llvm-mc: `lsl r0, r1, #2`
        assert_eq!(lift1(&[0x01, 0x01, 0xa0, 0xe1]), assign_to("r0", MicroExpr::binary(BinOp::Shl, MicroExpr::var("r1"), c32(2))));
        // e1a00141  llvm-mc: `asr r0, r1, #2` — the operand read as signed.
        assert_eq!(lift1(&[0x41, 0x01, 0xa0, 0xe1]), assign_to("r0", MicroExpr::binary(BinOp::Sar, s32(MicroExpr::var("r1")), c32(2))));
    }

    /// A move with a shift-by-register decodes, and is the shift by the
    /// register's **low byte** — what the processor reads; counts of 32..=255
    /// then empty the register by the IR's own rule (`Shift::apply`). The 0.4
    /// decoder rejected every one of these as an invalid opcode (`(bad)`).
    #[test]
    fn a_move_with_a_register_shift_decodes_and_lifts_to_the_shift() {
        // e1a00211  llvm-mc: `lsl r0, r1, r2`
        let a = Arm32::a32();
        let di = a.decode(&[0x11, 0x02, 0xa0, 0xe1], Va(0x1000));
        assert!(di.is_ok(), "a register-shifted move is a valid A32 instruction, not `(bad)`: {di:?}");
        let di = di.unwrap();
        let low_byte = MicroExpr::binary(BinOp::And, MicroExpr::var("r2"), c32(0xff));
        assert_eq!(a.lift(&di, "aapcs32"), assign_to("r0", MicroExpr::binary(BinOp::Shl, MicroExpr::var("r1"), low_byte.clone())));
        // e1a00251  llvm-mc: `asr r0, r1, r2` — signed operand, same count.
        assert_eq!(lift1(&[0x51, 0x02, 0xa0, 0xe1]), assign_to("r0", MicroExpr::binary(BinOp::Sar, s32(MicroExpr::var("r1")), low_byte)));
    }

    /// `mvn` with a shift inverts the *shifted* register, not the `Rn` field.
    #[test]
    fn a_move_not_with_a_shift_inverts_the_shifted_register() {
        // e1e00101  llvm-mc: `mvn r0, r1, lsl #2`
        assert_eq!(
            lift1(&[0x01, 0x01, 0xe0, 0xe1]),
            assign_to("r0", MicroExpr::unary(UnOp::Not, MicroExpr::binary(BinOp::Shl, MicroExpr::var("r1"), c32(2)))),
        );
    }

    /// `mvn` with an immediate is the inverted immediate. The decoder builds this
    /// form with the generic three-operand shape — `[Rd, Rn, #imm]`, `Rn` being a
    /// should-be-zero field — so reading slot 1 lifted `mvn r3, #0` to
    /// `r3 = ~r0`.
    #[test]
    fn a_move_not_with_an_immediate_inverts_the_immediate() {
        // e3e03000  llvm-mc: `mvn r3, #0`
        assert_eq!(lift1(&[0x00, 0x30, 0xe0, 0xe3]), assign_to("r3", c32(0xffff_ffff)));
        // e3e00000  llvm-mc: `mvn r0, #0` — the case that decompiled to
        // `return ~r0;` where the answer is 0xffffffff.
        assert_eq!(lift1(&[0x00, 0x00, 0xe0, 0xe3]), assign_to("r0", c32(0xffff_ffff)));
        // e3e000ff  llvm-mc: `mvn r0, #255`
        assert_eq!(lift1(&[0xff, 0x00, 0xe0, 0xe3]), assign_to("r0", c32(0xffff_ff00)));
    }

    /// LSR and ASR by an immediate encode 32 as 0 (ARM ARM, "Shifts applied to a
    /// register"). A 32-bit value shifted by 32 is not something the IR may say:
    /// LSR #32 is the constant 0, ASR #32 fills with the sign — `rm >>s 31`.
    /// The 0.4 decoder reported the amount as 0, which read as "no shift".
    #[test]
    fn a_shift_by_32_is_never_a_shift_by_the_width() {
        // e1a00021  llvm-mc: `lsr r0, r1, #32`
        assert_eq!(lift1(&[0x21, 0x00, 0xa0, 0xe1]), assign_to("r0", c32(0)));
        // e1a00041  llvm-mc: `asr r0, r1, #32`
        assert_eq!(lift1(&[0x41, 0x00, 0xa0, 0xe1]), assign_to("r0", MicroExpr::binary(BinOp::Sar, s32(MicroExpr::var("r1")), c32(31))));
        // The same operand rule serves every data-processing instruction, not
        // only moves. e0810022  llvm-mc: `add r0, r1, r2, lsr #32`
        assert_eq!(lift1(&[0x22, 0x00, 0x81, 0xe0]), assign_to("r0", MicroExpr::binary(BinOp::Add, MicroExpr::var("r1"), c32(0))));
    }

    /// The IR has no rotate and no carry-in, so a rotate stays `asm` — and,
    /// like any `asm`, invalidates its destination.
    #[test]
    fn a_rotate_stays_asm_and_invalidates_its_destination() {
        // e1a00061  llvm-mc: `rrx r0, r1`;  e1a00161  llvm-mc: `ror r0, r1, #2`
        for bytes in [[0x61, 0x00, 0xa0, 0xe1], [0x61, 0x01, 0xa0, 0xe1]] {
            let stmts = lift1(&bytes);
            assert!(matches!(stmts.first(), Some(MicroStmt::Unlifted { .. })), "a rotate stays asm: {stmts:?}");
            assert_eq!(invalidated(&stmts), vec!["r0"], "the rotate's destination is invalidated: {stmts:?}");
        }
    }

    /// `cmp Rn, op2` compares `Rn`. The 0.4 decoder put the should-be-zero `Rd`
    /// field in slot 0, so every compare read `r0` as its left-hand side.
    #[test]
    fn a_compare_reads_its_first_register_not_the_destination_field() {
        let flags = |l: MicroExpr, r: MicroExpr| assign_to(FLAGS_VAR, MicroExpr::compare(CmpKind::Cmp, l, r));
        // e3530005  llvm-mc: `cmp r3, #5`
        assert_eq!(lift1(&[0x05, 0x00, 0x53, 0xe3]), flags(MicroExpr::var("r3"), c32(5)));
        // e1530002  llvm-mc: `cmp r3, r2`
        assert_eq!(lift1(&[0x02, 0x00, 0x53, 0xe1]), flags(MicroExpr::var("r3"), MicroExpr::var("r2")));
        // e1540003  llvm-mc: `cmp r4, r3`
        assert_eq!(lift1(&[0x03, 0x00, 0x54, 0xe1]), flags(MicroExpr::var("r4"), MicroExpr::var("r3")));
        // A predicated compare stays `asm`, and its fallback must not start
        // "writing" the register it only reads. 13530005  llvm-mc: `cmpne r3, #5`
        let a = Arm32::a32();
        let di = a.decode(&[0x05, 0x00, 0x53, 0x13], Va(0x1000)).unwrap();
        assert!(a.reg_access(&di).writes.is_empty(), "a compare writes no register: {:?}", a.reg_access(&di).writes);
    }

    /// The value the flags carry after a lift, if it writes them. Returns the
    /// absence rather than panicking, so a test fails on its own assertion.
    fn flags_of(stmts: &[MicroStmt]) -> Option<&MicroExpr> {
        stmts.iter().rev().find_map(|s| match s {
            MicroStmt::Assign { dst, value } if dst == FLAGS_VAR => Some(value),
            _ => None,
        })
    }

    /// `cmp r4, #0; beq` branches on `r4 == 0`. Through the decompiler the old
    /// lift printed `if ((r0 == 0x0))` for exactly this pair.
    #[test]
    fn a_branch_after_a_compare_tests_the_compared_register() {
        let a = Arm32::a32();
        // e3540000  llvm-mc: `cmp r4, #0`
        let cmp = lift1(&[0x00, 0x00, 0x54, 0xe3]);
        let cond = flags_of(&cmp).map(|f| a.branch_condition("beq", f));
        assert_eq!(cond, Some(MicroExpr::binary(BinOp::Eq, MicroExpr::var("r4"), c32(0))));
    }

    /// `tst r1, #255; beq` branches on `(r1 & 0xff) == 0` — and only the zero
    /// flag's conditions are answered, because A32 `tst` leaves `V` as it was
    /// and sets `C` from the shifter.
    #[test]
    fn a_branch_after_tst_tests_the_and_and_answers_only_the_zero_flag() {
        let a = Arm32::a32();
        // e31100ff  llvm-mc: `tst r1, #255`
        let tst = lift1(&[0xff, 0x00, 0x11, 0xe3]);
        let cond = |cc: &str| flags_of(&tst).map(|f| a.branch_condition(cc, f));
        let and = MicroExpr::binary(BinOp::And, MicroExpr::var("r1"), c32(0xff));
        assert_eq!(cond("beq"), Some(MicroExpr::binary(BinOp::Eq, and.clone(), c32(0))), "tst sets the flags: {tst:?}");
        assert_eq!(cond("bne"), Some(MicroExpr::binary(BinOp::Ne, and, c32(0))));
        for cc in ["blt", "bge", "bhi", "bcs"] {
            assert!(matches!(cond(cc), Some(MicroExpr::Unknown(_))), "{cc} after tst reads flags nothing models");
        }
    }

    /// An instruction that sets the flags must write them in the lift, modelled
    /// or not — otherwise the next branch reads whichever compare came before
    /// it, a wrong condition with nothing to say so.
    #[test]
    fn every_flag_setter_writes_the_flags() {
        let a = Arm32::a32();
        // Kept as `asm`: e3310001 `teq r1, #1`, e3710001 `cmn r1, #1`,
        // 13530005 `cmpne r3, #5`, 12500001 `subsne r0, r0, #1` (llvm-mc).
        for bytes in [[0x01, 0x00, 0x31, 0xe3], [0x01, 0x00, 0x71, 0xe3], [0x05, 0x00, 0x53, 0x13], [0x01, 0x00, 0x50, 0x12]] {
            let stmts = lift1(&bytes);
            assert!(matches!(stmts.first(), Some(MicroStmt::Unlifted { .. })), "stays asm: {stmts:?}");
            let f = flags_of(&stmts);
            assert!(matches!(f, Some(MicroExpr::OpaqueFlags { .. })), "an unmodelled flag setter leaves opaque flags: {stmts:?}");
            assert!(matches!(f.map(|f| a.branch_condition("beq", f)), Some(MicroExpr::Unknown(_))), "and a branch after it has no condition");
        }
        // e2900001  llvm-mc: `adds r0, r0, #1` — the add is exact, its flags
        // are not modelled.
        let adds = lift1(&[0x01, 0x00, 0x90, 0xe2]);
        assert_eq!(adds[0], MicroStmt::Assign { dst: "r0".into(), value: MicroExpr::binary(BinOp::Add, MicroExpr::var("r0"), c32(1)) });
        assert!(matches!(flags_of(&adds), Some(MicroExpr::OpaqueFlags { .. })), "adds writes the flags: {adds:?}");
        // e2500001  llvm-mc: `subs r0, r0, #1` — sets the flags exactly as
        // `cmp r0, #1`, from the old r0, so the flags are written first.
        assert_eq!(
            lift1(&[0x01, 0x00, 0x50, 0xe2]),
            vec![
                MicroStmt::Assign { dst: FLAGS_VAR.into(), value: MicroExpr::compare(CmpKind::Cmp, MicroExpr::var("r0"), c32(1)) },
                MicroStmt::Assign { dst: "r0".into(), value: MicroExpr::binary(BinOp::Sub, MicroExpr::var("r0"), c32(1)) },
            ],
        );
    }

    /// A 16-bit Thumb `adds` inside an `IT` block is `add<cond>`: it does not
    /// set the flags, so it stays a predicated write with no flags statement.
    #[test]
    fn a_thumb_instruction_inside_an_it_block_does_not_set_the_flags() {
        // bf08 `it eq`; 1840 `addeq r0, r0, r1` (llvm-mc, thumbv7).
        let t = Arm32::thumb();
        let stream = t.decode_stream(&[0x08, 0xbf, 0x40, 0x18], Va(0x1000), 2);
        let stmts = t.lift(&stream[1], "aapcs32");
        assert!(matches!(stmts.as_slice(), [MicroStmt::Assign { dst, value: MicroExpr::Select { .. } }] if dst == "r0"), "a predicated add and nothing else: {stmts:?}");
    }

    /// The signed conditions read both sides as signed 32-bit values; the
    /// unsigned and equality ones read them as they are.
    #[test]
    fn a_signed_condition_reads_its_operands_as_signed() {
        let a = Arm32::a32();
        // e1500001  llvm-mc: `cmp r0, r1`
        let cmp = lift1(&[0x01, 0x00, 0x50, 0xe1]);
        let f = flags_of(&cmp);
        let (r0, r1) = (MicroExpr::var("r0"), MicroExpr::var("r1"));
        assert_eq!(f.map(|f| a.branch_condition("blt", f)), Some(MicroExpr::binary(BinOp::Slt, s32(r0.clone()), s32(r1.clone()))));
        assert_eq!(f.map(|f| a.branch_condition("bge", f)), Some(MicroExpr::binary(BinOp::Sge, s32(r0.clone()), s32(r1.clone()))));
        assert_eq!(f.map(|f| a.branch_condition("blo", f)), Some(MicroExpr::binary(BinOp::Ult, r0.clone(), r1.clone())));
        assert_eq!(f.map(|f| a.branch_condition("beq", f)), Some(MicroExpr::binary(BinOp::Eq, r0.clone(), r1)));
        // A constant with bit 31 set is a negative number to a signed
        // condition. e3700001  llvm-mc: `cmn r0, #1` is asm, so build the
        // compare directly: `r0 <s 0xffffffff` is `r0 <s -1`.
        let neg = MicroExpr::compare(CmpKind::Cmp, r0.clone(), c32(0xffff_ffff));
        assert_eq!(a.branch_condition("blt", &neg), MicroExpr::binary(BinOp::Slt, s32(r0.clone()), s32(c32(0xffff_ffff))));
        let pos = MicroExpr::compare(CmpKind::Cmp, r0.clone(), c32(5));
        assert_eq!(a.branch_condition("bgt", &pos), MicroExpr::binary(BinOp::Sgt, s32(r0), c32(5)), "a positive constant needs no cast");
    }

    // ---- the decoder boundary --------------------------------------------------

    /// Words yaxpeax 0.5.0 panics on (`ldrd`/`strd` with `Rt = 15`; LLVM:
    /// "invalid instruction encoding") are decode errors, through every entry
    /// point — and the process keeps running.
    #[test]
    fn a_word_the_decoder_panics_on_is_a_decode_error() {
        let a = Arm32::a32();
        // 0x0000f0d0 and 0x0000fafc.
        for word in [0x0000_f0d0u32, 0x0000_fafc, 0x2000_f0d0] {
            let bytes = word.to_le_bytes();
            assert!(a32_rt_pair_overflows(word), "{word:#010x} is in the refused class");
            // Caught here so a panic that escapes the boundary fails on this
            // line, rather than somewhere inside the decoder.
            let decoded = std::panic::catch_unwind(|| a.decode(&bytes, Va(0x1000)));
            assert!(decoded.is_ok(), "{word:#010x}: the decoder's panic escaped the boundary");
            assert!(matches!(decoded.ok(), Some(Err(DecodeError::Invalid(Va(0x1000))))), "{word:#010x} is a decode error");
            let stream = a.decode_stream(&bytes, Va(0x1000), 4);
            assert_eq!(stream.len(), 1, "{word:#010x}: one marker, then the walk stops");
            assert_eq!(stream[0].kind, InsnKind::Invalid, "{word:#010x} is `(bad)` in a stream");
        }
        // The refusal is that class and no wider: the same field pattern with
        // an even `Rt` is a real `ldrd`. e1c020d0  llvm-mc: `ldrd r2, r3, [r0]`
        assert!(!a32_rt_pair_overflows(0xe1c0_20d0));
        assert_eq!(dis(&a, &[0xd0, 0x20, 0xc0, 0xe1]).mnemonic, "ldrd");
    }

    /// An `Ok` carrying `Opcode::Invalid` is not an instruction. 0x03200000
    /// (LLVM: "invalid instruction encoding") printed as `invalideq`.
    #[test]
    fn an_invalid_opcode_is_a_decode_error_not_an_instruction() {
        let a = Arm32::a32();
        // 0x03200000, 0xe3200000, 0x43200007, 0xe320f100 — LLVM rejects all four.
        for word in [0x0320_0000u32, 0xe320_0000, 0x4320_0007, 0xe320_f100] {
            assert!(a.decode(&word.to_le_bytes(), Va(0x1000)).is_err(), "{word:#010x} is not an instruction");
        }
    }

    /// The decoder returns `Invalid` for the whole hint space, `nop` included;
    /// those words are instructions (llvm-mc `-triple=armv7`), and a `nop`
    /// read as `(bad)` would end a function walk.
    #[test]
    fn the_a32_hint_space_decodes_as_hints() {
        let a = Arm32::a32();
        for (word, text) in [
            (0xe320_f000u32, "nop"),
            (0xe320_f001, "yield"),
            (0xe320_f002, "wfe"),
            (0xe320_f003, "wfi"),
            (0xe320_f004, "sev"),
            (0xe320_f014, "csdb"),
            (0x0320_f000, "nopeq"),
        ] {
            let di = a.decode(&word.to_le_bytes(), Va(0x1000)).unwrap_or_else(|e| panic!("{word:#010x} ({text}) is an instruction: {e:?}"));
            assert_eq!(di.text, text, "{word:#010x}");
        }
        // llvm-mc: `hint #5` — unallocated, executes as a nop.
        assert_eq!(dis(&a, &0xe320_f005u32.to_le_bytes()).mnemonic, "hint");
        // A walk goes through a `nop`: e320f000 then e12fff1e `bx lr`.
        let stream = a.decode_stream(&[0x00, 0xf0, 0x20, 0xe3, 0x1e, 0xff, 0x2f, 0xe1], Va(0x1000), 4);
        assert_eq!(stream.iter().map(|d| d.mnemonic.as_str()).collect::<Vec<_>>(), vec!["nop", "bx"]);
    }

    /// The text shows what the lift reads: `mvn r3, #0` has two operands.
    #[test]
    fn move_not_immediate_text_has_no_phantom_register() {
        let a = Arm32::a32();
        // e3e03000  llvm-mc: `mvn r3, #0`;  e3f00005  llvm-mc: `mvns r0, #5`
        assert_eq!(dis(&a, &[0x00, 0x30, 0xe0, 0xe3]).text, "mvn r3, 0x0");
        assert_eq!(dis(&a, &[0x05, 0x00, 0xf0, 0xe3]).text, "mvns r0, 0x5");
    }

    /// Thumb branch targets, against llvm-mc (`-triple=thumbv7`, whose `#imm`
    /// is relative to `PC = va + 4`), each decoded at 0x100.
    #[test]
    fn thumb_branch_targets_match_the_independent_disassembler() {
        let t = Arm32::thumb();
        for (bytes, target, what) in [
            (&[0x01, 0xd0][..], 0x106, "beq #2 (16-bit conditional, T1)"),
            (&[0xfe, 0xd0][..], 0x100, "beq #-4 (T1, backwards)"),
            (&[0x01, 0xe0][..], 0x106, "b #2 (16-bit, T2)"),
            (&[0x00, 0xf0, 0x01, 0xb8][..], 0x106, "b.w #2"),
            (&[0x00, 0xf0, 0x01, 0x80][..], 0x106, "beq.w #2"),
            (&[0x00, 0xf0, 0x01, 0xf8][..], 0x106, "bl #2"),
        ] {
            let di = t.decode(bytes, Va(0x100)).expect("decodes");
            assert_eq!(di.target, Some(Va(target)), "{what}: {}", di.text);
        }
    }

    /// **The instrument**: every one of the 2^32 A32 words, through the raw
    /// decoder and through [`a32_rt_pair_overflows`]. It asserts that the
    /// refusal covers every word the decoder panics on (so the `catch_unwind`
    /// backstop never has to fire, and never prints), and that every word it
    /// refuses is one the decoder would not have decoded anyway (so the
    /// refusal changes no answer). Measured at 32 s in release under a
    /// five-core quota; run it whenever the decoder version changes:
    ///
    /// ```text
    /// cargo test -p n0xis-arch --release --lib -- --ignored a32_decoder_boundary_holds_for_every_word
    /// ```
    #[test]
    #[ignore = "exhaustive over 2^32 words; run by hand when the decoder changes"]
    fn a32_decoder_boundary_holds_for_every_word() {
        use std::panic::{catch_unwind, AssertUnwindSafe};
        // The raw decoder panics ~1.5 million times here by design; a quiet
        // hook keeps the output readable. Test-only, and this test runs alone.
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get()) as u64;
        let chunk = (1u64 << 32).div_ceil(threads);
        let (unrefused_panics, refused_decodes, panics): (Vec<u32>, Vec<u32>, u64) = std::thread::scope(|s| {
            let workers: Vec<_> = (0..threads)
                .map(|t| {
                    s.spawn(move || {
                        let decoder = InstDecoder::default();
                        let (mut missed, mut over, mut panics) = (Vec::new(), Vec::new(), 0u64);
                        for w in (t * chunk)..((t + 1) * chunk).min(1 << 32) {
                            let word = w as u32;
                            let bytes = word.to_le_bytes();
                            let raw = catch_unwind(AssertUnwindSafe(|| decoder.decode(&mut U8Reader::new(&bytes))));
                            let refused = a32_rt_pair_overflows(word);
                            match raw {
                                Err(_) => {
                                    panics += 1;
                                    if !refused && missed.len() < 8 {
                                        missed.push(word);
                                    }
                                }
                                Ok(Ok(_)) if refused && over.len() < 8 => over.push(word),
                                _ => {}
                            }
                        }
                        (missed, over, panics)
                    })
                })
                .collect();
            workers.into_iter().map(|w| w.join().expect("worker")).fold((Vec::new(), Vec::new(), 0), |mut acc, (m, o, p)| {
                acc.0.extend(m);
                acc.1.extend(o);
                acc.2 += p;
                acc
            })
        });
        std::panic::set_hook(hook);
        assert!(panics > 0, "the decoder this was written against panics on 1 474 560 words; zero means the sweep did not run it");
        assert!(unrefused_panics.is_empty(), "the decoder panics on words the refusal lets through: {unrefused_panics:08x?}");
        assert!(refused_decodes.is_empty(), "the refusal rejects words the decoder decodes: {refused_decodes:08x?}");
        eprintln!("decoder panics on {panics} of 2^32 words; every one is refused before it reaches the decoder");
    }

    /// The forms that were already right stay right.
    #[test]
    fn the_unshifted_moves_and_a_shifted_add_are_unchanged() {
        // e1a00001  llvm-mc: `mov r0, r1`
        assert_eq!(lift1(&[0x01, 0x00, 0xa0, 0xe1]), assign_to("r0", MicroExpr::var("r1")));
        // e1e00001  llvm-mc: `mvn r0, r1`
        assert_eq!(lift1(&[0x01, 0x00, 0xe0, 0xe1]), assign_to("r0", MicroExpr::unary(UnOp::Not, MicroExpr::var("r1"))));
        // e0810102  llvm-mc: `add r0, r1, r2, lsl #2`
        assert_eq!(
            lift1(&[0x02, 0x01, 0x81, 0xe0]),
            assign_to("r0", MicroExpr::binary(BinOp::Add, MicroExpr::var("r1"), MicroExpr::binary(BinOp::Shl, MicroExpr::var("r2"), c32(2)))),
        );
    }

    #[test]
    fn arm32_is_32bit_with_the_aapcs32_abi() {
        let a = Arm32::a32();
        assert_eq!(a.pointer_size(), 4);
        assert_eq!(a.calling_conventions()[0].name, "aapcs32");
        assert!(a.regs().by_name("lr").is_some());
    }
}
