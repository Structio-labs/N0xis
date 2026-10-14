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
//! `eor`/`bic`/`mvn`/`mul`, `adr`), every single load and store (`ldr`/`ldrb`/
//! `ldrh`/`ldrsb`/`ldrsh`/`ldrd` and the stores, in every addressing mode),
//! `ldm`/`stm` in all four modes (`push`/`pop` among them), `cmp` + the
//! AArch32 branch conditions, `bl`/`bx lr` under AAPCS32, and **predication**
//! (`addne` → `dst = cond ? effect : dst`, via the same `Select` + reaching-flags
//! resolver x64 uses for `cmovcc`). Shifted-register operands lift to the
//! shift (`lsl`/`lsr`/`asr`, by an immediate or a register). A read of `pc` is
//! the constant the processor sees ([`PcView`]). Unmodelled forms (rotates —
//! `ror`/`rrx` — FP/SIMD, a predicated store or write-back, the UNPREDICTABLE
//! register choices) are preserved as `asm` and **soundly invalidate their
//! writes** so no later read reuses a stale value.
//!
//! Two A32 encoding spaces are decoded here rather than by the crate, which
//! fails on them — the media class and the halfword multiplies; see [`own`].
//! Of those, the byte/halfword extends, the bitfield instructions, `pkhbt`/
//! `pkhtb`, `smul<x><y>` and `rev`/`rev16`/`revsh` are lifted exactly; the
//! SIMD-within-a-register, saturating and accumulating forms stay `asm`.
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

mod own;

use crate::insn::{DecodeError, DecodedInsn, InsnKind};
use crate::microir::{BinOp, CallTarget, CmpKind, MemEffect, MicroExpr, MicroStmt, UnOp, UnliftedReads, FLAGS_VAR};
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
    ///
    /// And the spaces it cannot decode at all are not given to it: a word in
    /// the A32 media class or the halfword multiplies is decoded by [`own`],
    /// whatever that answers, so each space has one decoder.
    fn decode_inst(&self, bytes: &[u8]) -> Option<Inst> {
        if !self.thumb && let Some(word) = bytes.first_chunk::<4>().map(|b| u32::from_le_bytes(*b)) {
            if own::owns(word) {
                return own::decode(word).map(Inst::Own);
            }
            if a32_rt_pair_overflows(word) {
                return None;
            }
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
        Some(Inst::Crate(inst))
    }
}

/// What [`Arm32::decode_inst`] hands the rest of this file: an instruction the
/// crate decoded, or one from a space this file decodes itself. Every consumer
/// matches both, so a fact about an instruction (its text, its writes, its
/// flags, its lift) cannot be answered for one decoder and forgotten for the
/// other.
#[derive(Clone, Copy, Debug)]
enum Inst {
    Crate(Instruction),
    Own(own::Own),
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

/// The decoder's text for an A32 instruction, corrected where it names a
/// different instruction than the word holds — checked against llvm-mc
/// (`-triple=armv6-none-eabi`):
///
/// * an increment-before block transfer printed as `ldmia`/`stmia`, the name
///   of the increment-after mode (`e9900006` is `ldmib r0, {r1, r2}`). The
///   mnemonic is rebuilt from [`block_mode`], the mode the lift uses;
/// * the user-bank / exception-return `^` was not printed at all (`e8d00006`
///   is `ldm r0, {r1, r2} ^`);
/// * `sub rd, pc, #imm` printed as `adr rd, pc, #imm`, the same text as the
///   adding form — see [`adr`].
fn a32_text(inst: &Instruction, bytes: &[u8], text: String) -> String {
    match inst.opcode {
        Opcode::LDM(..) | Opcode::STM(..) => {
            let mnemonic = if matches!(inst.opcode, Opcode::LDM(..)) { "ldm" } else { "stm" };
            let (first, rest) = text.split_once(' ').unwrap_or((text.as_str(), ""));
            let mut out = match (first.strip_prefix(mnemonic), block_mode(bytes, false)) {
                (Some(suffixed), Some(mode)) => {
                    let cond = ["ia", "ib", "da", "db"].iter().find_map(|s| suffixed.strip_prefix(s)).unwrap_or(suffixed);
                    format!("{mnemonic}{}{cond} {rest}", mode.suffix())
                }
                _ => text.clone(),
            };
            if a32_user_bank(bytes) {
                out.push_str(" ^");
            }
            out
        }
        Opcode::ADR if a32_adr_adds(bytes) == Some(false) => text.replacen("adr", "sub", 1),
        _ => text,
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
    cond_name(inst.condition)
}

/// A condition's name (`Some("eq")`), or `None` for `AL` — for either decoder.
fn cond_name(c: ConditionCode) -> Option<String> {
    let c = format!("{c:?}").to_lowercase();
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

/// The register numbers of the stack pointer, the link register and the
/// program counter.
const SP: u8 = 13;
const LR: u8 = 14;
const PC: u8 = 15;

/// The 32-bit stack slot `off` bytes above (`add`) or below the register
/// `base` — the one shape every lifted memory access here uses, so a slot a
/// `push` writes and one a `str` or `ldr` names compare equal.
fn slot_addr(base: String, off: u32, add: bool) -> MicroExpr {
    let b = MicroExpr::var(base);
    if off == 0 {
        b
    } else {
        MicroExpr::binary(if add { BinOp::Add } else { BinOp::Sub }, b, MicroExpr::constant(i128::from(off), 32))
    }
}

/// The four addressing modes of a block transfer (`ldm`/`stm`): whether the
/// block lies above (`Increment`) or below (`Decrement`) the base, and whether
/// the first word is the base itself (`After`) or one word past it (`Before`).
/// `push` is `stmdb sp!`, `pop` is `ldmia sp!`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockMode {
    IncrementAfter,
    IncrementBefore,
    DecrementAfter,
    DecrementBefore,
}

impl BlockMode {
    /// The mode from the encoding's `P` (before) and `U` (increment) bits.
    fn from_pu(before: bool, increment: bool) -> BlockMode {
        match (increment, before) {
            (true, false) => BlockMode::IncrementAfter,
            (true, true) => BlockMode::IncrementBefore,
            (false, false) => BlockMode::DecrementAfter,
            (false, true) => BlockMode::DecrementBefore,
        }
    }

    /// The A32 suffix, as the ARM ARM and llvm-mc spell it — `ia` is the
    /// default and is not printed.
    fn suffix(self) -> &'static str {
        match self {
            BlockMode::IncrementAfter => "",
            BlockMode::IncrementBefore => "ib",
            BlockMode::DecrementAfter => "da",
            BlockMode::DecrementBefore => "db",
        }
    }

    /// Where the `i`-th of `n` registers goes, as an offset from the base
    /// (`true` = above it): the lowest-numbered register at the lowest
    /// address, always (ARM ARM, `LDM`/`STM`).
    fn slot(self, i: u32, n: u32) -> (u32, bool) {
        match self {
            BlockMode::IncrementAfter => (4 * i, true),
            BlockMode::IncrementBefore => (4 * (i + 1), true),
            BlockMode::DecrementAfter => (4 * (n - 1 - i), false),
            BlockMode::DecrementBefore => (4 * (n - i), false),
        }
    }

    fn increments(self) -> bool {
        matches!(self, BlockMode::IncrementAfter | BlockMode::IncrementBefore)
    }
}

/// The addressing mode of a block transfer, **read from the encoding**, never
/// from the decoder's opcode. yaxpeax 0.5.0 carries an `(add, pre, …)` tuple
/// that is right for A32 and wrong for Thumb's 16-bit `stmia`, which it builds
/// as `pre = true`; and it *prints* the A32 increment-before forms as `ldmia`/
/// `stmia` — the name of the other mode (llvm-mc: `e9900006` is `ldmib r0,
/// {r1, r2}`; the decoder said `ldmia`). So the mode is this function's answer,
/// for the text and the lift alike.
///
/// A32: `P` bit 24, `U` bit 23. Thumb: every 16-bit form is increment-after;
/// a 32-bit one is `1110 100 op 0 W L Rn` with `op` 01 = increment-after and
/// 10 = decrement-before (ARM ARM A6.3.5). `None` for anything else.
fn block_mode(bytes: &[u8], thumb: bool) -> Option<BlockMode> {
    if !thumb {
        let word = u32::from_le_bytes(*bytes.first_chunk::<4>()?);
        return Some(BlockMode::from_pu(word & (1 << 24) != 0, word & (1 << 23) != 0));
    }
    let hw1 = u16::from_le_bytes(*bytes.first_chunk::<2>()?);
    if hw1 >> 11 == 0b11000 || hw1 >> 11 == 0b11001 {
        return Some(BlockMode::IncrementAfter);
    }
    match (hw1 >> 9 == 0b111_0100, (hw1 >> 7) & 0b11) {
        (true, 0b01) => Some(BlockMode::IncrementAfter),
        (true, 0b10) => Some(BlockMode::DecrementBefore),
        _ => None,
    }
}

/// An A32 block transfer's `S` bit (22): the user-bank registers, or — with
/// `pc` in an `ldm` list — an exception return that also restores the CPSR.
/// Neither is an ordinary load or store. The decoder carries it as the
/// opcode's fourth field, which in Thumb it sets for every form, so it is read
/// from the word.
fn a32_user_bank(bytes: &[u8]) -> bool {
    bytes.first_chunk::<4>().is_some_and(|b| u32::from_le_bytes(*b) & (1 << 22) != 0)
}

/// A block transfer — `ldm`/`stm`, `push`/`pop` — as the stores or loads it
/// performs, then the base write-back: the lowest-numbered register at the
/// lowest address ([`BlockMode::slot`]), the block `4·n` bytes long. `push
/// {r4, lr}` (`stmdb sp!`) stores `r4` at `sp - 8` and `lr` at `sp - 4`, then
/// `sp = sp - 8`; `pop {r4, pc}` (`ldmia sp!`) loads `r4` from `sp`, moves `sp`
/// up by 8 and returns — `pc` in a loaded list is the return, its slot read by
/// the return itself, as the CFG classifies it.
///
/// Without the stores, nothing that reasons about memory knew the stack was
/// written: to store-to-load forwarding a `push` was no store at all. Without
/// the loads, a callee-saved register pushed and popped did not come back as
/// itself.
///
/// `None` — the `asm` fallback — for an empty list (UNPREDICTABLE); for `sp`
/// in the list (a stored `sp` is UNKNOWN unless it is the lowest register, a
/// loaded one disagrees with the write-back); for `pc` in a stored list (the
/// value stored is IMPLEMENTATION DEFINED, `PCStoreValue()`); and for the base
/// in the list with write-back (the stored value or the final base is
/// UNKNOWN). A loaded base without write-back is loaded last, so every address
/// before it is computed from the base the instruction started with.
fn block_stmts(base: &str, mode: BlockMode, load: bool, wback: bool, mask: u16) -> Option<Vec<MicroStmt>> {
    let regs = reglist(mask);
    let has = |r: &str| regs.iter().any(|x| x == r);
    if regs.is_empty() || has(&reg_n(SP)) || base == reg_n(PC) || (!load && has(&reg_n(PC))) || (wback && has(base)) {
        return None;
    }
    let n = regs.len() as u32;
    let slot = |i: usize| {
        let (off, up) = mode.slot(i as u32, n);
        slot_addr(base.to_string(), off, up)
    };
    let mut out = Vec::new();
    if load {
        let mut base_load = None;
        for (i, r) in regs.iter().enumerate() {
            let stmt = assign(r.clone(), MicroExpr::load(slot(i), 32, false));
            match r.as_str() {
                "pc" => {}
                r if r == base => base_load = Some(stmt),
                _ => out.push(stmt),
            }
        }
        out.extend(base_load);
    } else {
        out.extend(regs.iter().enumerate().map(|(i, r)| MicroStmt::Store { addr: slot(i), value: MicroExpr::var(r.clone()), bits: 32 }));
    }
    if wback {
        out.push(assign(base.to_string(), slot_addr(base.to_string(), 4 * n, mode.increments())));
    }
    if load && has(&reg_n(PC)) {
        out.push(MicroStmt::Return(Some(MicroExpr::var("r0"))));
    }
    Some(out)
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

/// What one instruction reads when it reads `pc` (ARM ARM, "Use of the PC"):
/// its own address plus 8 in A32, plus 4 in Thumb — the pipeline offset the
/// architecture fixes — and, for a `pc`-relative memory operand and `adr`, that
/// value rounded down to a word (`Align(PC, 4)`), which in Thumb is not the
/// same number.
///
/// Before this, `pc` was an ordinary register with no definition, so every
/// literal-pool load read an unknown entry value: `ldr r0, [pc, #0x18c]` at
/// 0x2000 rendered as `pc.0->field_0x18c`, where the processor loads the word
/// at 0x2194.
#[derive(Clone, Copy, Debug)]
struct PcView {
    /// What a register operand `pc` reads as, or `None` where that read is
    /// UNPREDICTABLE or not one this lift knows — the instruction then stays
    /// `asm`. A32 allows it in data processing with an immediate or
    /// immediate-shifted operand; Thumb only in a 16-bit `mov` (and in `adr`,
    /// which is [`PcView::literal_base`]'s).
    operand: Option<u64>,
    /// `Align(PC, 4)`: the base of a literal load and of `adr`.
    literal_base: u64,
}

impl PcView {
    fn a32(va: Va) -> PcView {
        let pc = va.0.wrapping_add(8) & 0xffff_ffff;
        PcView { operand: Some(pc), literal_base: pc & !3 }
    }

    /// Thumb's: `va + 4`, which a register operand reads only where `operand`
    /// says so — the 16-bit `mov rd, pc`, or the base of `addw`/`subw`, the
    /// two 32-bit `adr` encodings, which read `Align(PC, 4)`.
    fn thumb(va: Va, operand: ThumbPcOperand) -> PcView {
        let pc = va.0.wrapping_add(4) & 0xffff_ffff;
        let operand = match operand {
            ThumbPcOperand::Refused => None,
            ThumbPcOperand::Pc => Some(pc),
            ThumbPcOperand::Aligned => Some(pc & !3),
        };
        PcView { operand, literal_base: pc & !3 }
    }
}

/// Which value a Thumb instruction's register operand `pc` reads — see
/// [`PcView::thumb`].
#[derive(Clone, Copy, Debug)]
enum ThumbPcOperand {
    Refused,
    Pc,
    Aligned,
}

/// A register read as an rvalue: its variable, or for `pc` the constant the
/// processor reads — `None` where [`PcView::operand`] refuses it.
fn reg_rvalue(r: yaxpeax_arm::armv7::Reg, pc: Option<u64>) -> Option<MicroExpr> {
    if r.number() == PC {
        pc.map(|v| MicroExpr::constant(i128::from(v), 32))
    } else {
        Some(MicroExpr::var(reg_name(r)))
    }
}

/// A second-operand as an rvalue: a register, an immediate, or a **shifted
/// register** (`r2, lsl #3` → `(r2 << 3)`; `r2, lsr r7` → `(r2 >>u r7)`).
/// Derefs, reg-lists and rotates (`ror`/`rrx`) return `None` (not modelled
/// here). `pc` reads as `pc` says ([`PcView::operand`]); a register-shifted
/// register naming `pc` anywhere is UNPREDICTABLE and returns `None`.
fn op_rvalue(op: &Operand, pc: Option<u64>) -> Option<MicroExpr> {
    match op {
        Operand::Reg(r) => reg_rvalue(*r, pc),
        Operand::Imm32(v) => Some(MicroExpr::constant(*v as i128, 32)),
        Operand::RegShift(rs) => match rs.into_shift() {
            RegShiftStyle::RegImm(s) => imm_shift(s.stype(), reg_rvalue(s.shiftee(), pc)?, s.imm()),
            // The count is the **low byte** of the shifting register (ARM ARM,
            // "Shifts applied to a register"); 32..=255 empty the register, or
            // fill it with the sign for `asr`, which is exactly what the IR's
            // shift means past the width (`Shift::apply`).
            RegShiftStyle::RegReg(s) => {
                if s.shiftee().number() == PC || s.shifter().number() == PC {
                    return None;
                }
                shift_op(s.stype()).map(|op| {
                    let count = MicroExpr::binary(BinOp::And, MicroExpr::var(reg_name(s.shifter())), MicroExpr::constant(0xff, 32));
                    shift(op, MicroExpr::var(reg_name(s.shiftee())), count)
                })
            }
        },
        _ => None,
    }
}

/// How a single load or store finds its address: an immediate, a register, or
/// an immediate-shifted register, added to or subtracted from the base.
#[derive(Clone, Copy, Debug)]
enum Index {
    Imm(u16),
    Reg(yaxpeax_arm::armv7::Reg),
    Shifted(yaxpeax_arm::armv7::RegShift),
}

/// A single load/store's memory operand, from whichever of the decoder's six
/// shapes it came as. `pre` — the address is `base ± index`, else `base` alone
/// (post-indexed); `wback` — the base is updated to `base ± index` afterwards.
///
/// A **post-indexed** access always updates its base — that is what
/// post-indexing is (`ldr r0, [r1], #4` is `r0 = *r1; r1 += 4`). The decoder
/// carries a write-back flag on those forms too, and leaves it `false`:
/// reading the flag let the `asm` fallback keep `r1`'s old value, so `ldr r0,
/// [r1], #4; mov r0, r1` returned `r1` instead of `r1 + 4`. A pre-indexed
/// access updates it only when its `!` flag is set.
#[derive(Clone, Copy, Debug)]
struct MemOperand {
    base: yaxpeax_arm::armv7::Reg,
    index: Index,
    add: bool,
    pre: bool,
    wback: bool,
}

impl MemOperand {
    fn of(op: &Operand) -> Option<MemOperand> {
        let (base, index, add, pre, wback) = match *op {
            Operand::RegDerefPreindexOffset(b, off, add, wb) => (b, Index::Imm(off), add, true, wb),
            Operand::RegDerefPreindexReg(b, r, add, wb) => (b, Index::Reg(r), add, true, wb),
            Operand::RegDerefPreindexRegShift(b, rs, add, wb) => (b, Index::Shifted(rs), add, true, wb),
            Operand::RegDerefPostindexOffset(b, off, add, _) => (b, Index::Imm(off), add, false, true),
            Operand::RegDerefPostindexReg(b, r, add, _) => (b, Index::Reg(r), add, false, true),
            Operand::RegDerefPostindexRegShift(b, rs, add, _) => (b, Index::Shifted(rs), add, false, true),
            _ => return None,
        };
        Some(MemOperand { base, index, add, pre, wback })
    }

    /// The registers the index reads.
    fn index_regs(&self) -> Vec<u8> {
        match self.index {
            Index::Imm(_) => Vec::new(),
            Index::Reg(r) => vec![r.number()],
            Index::Shifted(rs) => match rs.into_shift() {
                RegShiftStyle::RegImm(s) => vec![s.shiftee().number()],
                RegShiftStyle::RegReg(s) => vec![s.shiftee().number(), s.shifter().number()],
            },
        }
    }

    /// `base ± index`, with a `pc` base read as `Align(PC, 4)` and an
    /// immediate folded into it — a literal load names the address it reads,
    /// `*0x2194`, not `*(0x2188 + 0xc)`. `None` for an index the lift does not
    /// model (a rotate) and for an index register `pc` (UNPREDICTABLE in every
    /// single load and store).
    fn offset_address(&self, pc: PcView) -> Option<MicroExpr> {
        let base_pc = self.base.number() == PC;
        let index = match self.index {
            Index::Imm(off) if base_pc => {
                let at = if self.add { pc.literal_base.wrapping_add(u64::from(off)) } else { pc.literal_base.wrapping_sub(u64::from(off)) };
                return Some(MicroExpr::constant(i128::from(at & 0xffff_ffff), 32));
            }
            Index::Imm(off) => return Some(slot_addr(reg_name(self.base), u32::from(off), self.add)),
            _ if self.index_regs().contains(&PC) => return None,
            Index::Reg(r) => MicroExpr::var(reg_name(r)),
            Index::Shifted(rs) => op_rvalue(&Operand::RegShift(rs), None)?,
        };
        Some(MicroExpr::binary(if self.add { BinOp::Add } else { BinOp::Sub }, self.base_value(pc), index))
    }

    /// The base as an rvalue — `Align(PC, 4)` for `pc`.
    fn base_value(&self, pc: PcView) -> MicroExpr {
        if self.base.number() == PC {
            MicroExpr::constant(i128::from(pc.literal_base), 32)
        } else {
            MicroExpr::var(reg_name(self.base))
        }
    }

    /// The address the access reads or writes.
    fn address(&self, pc: PcView) -> Option<MicroExpr> {
        if self.pre { self.offset_address(pc) } else { Some(self.base_value(pc)) }
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
/// two-operand `adds r0, r1` among them) — the caller keeps it `asm`. A
/// register operand `pc` reads as `pc` says ([`PcView::operand`]); in a
/// multiply it is UNPREDICTABLE, and the multiply stays `asm`.
fn data_processing(inst: &Instruction, pc: Option<u64>) -> Option<(String, MicroExpr)> {
    use Opcode::*;
    let ops = &inst.operands;
    if matches!(inst.opcode, MOV | MVN) {
        let (rd, src) = move_operands(ops)?;
        let value = match (inst.opcode, src) {
            // `mvn rd, #imm` is a constant; state it as one (`mvn r0, #0` is
            // 0xffffffff, not `~0x0` left for a reader to evaluate).
            (MVN, Operand::Imm32(v)) => MicroExpr::constant(!*v as i128, 32),
            (MVN, src) => MicroExpr::unary(UnOp::Not, op_rvalue(src, pc)?),
            (_, src) => op_rvalue(src, pc)?,
        };
        return Some((reg_name(rd), value));
    }
    let [Operand::Reg(rd), a, b, Operand::Nothing] = ops else {
        return None;
    };
    let pc = if inst.opcode == MUL { None } else { pc };
    let (a, b) = (op_rvalue(a, pc)?, op_rvalue(b, pc)?);
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

/// `adr rd, label` — `Align(PC, 4) ± imm`, a constant. Thumb's 16-bit form
/// arrives as `[Rd, #imm]` and only adds. A32's arrives as `[Rd, pc, #imm]`
/// for **both** of its encodings, `add rd, pc, #imm` (A1) and `sub rd, pc,
/// #imm` (A2): the decoder drops which one it was, so the direction is read
/// from the word's opcode field, bits 24-21 — `0100` adds, `0010` subtracts
/// (llvm-mc: `e28f0010` is `adr r0, #16`, `e24f0010` is `sub r0, pc, #16`).
/// Read from the operands alone, every backwards `adr` pointed forwards.
fn adr(inst: &Instruction, bytes: &[u8], thumb: bool, pc: PcView) -> Option<(String, MicroExpr)> {
    let (rd, imm, add) = match inst.operands {
        [Operand::Reg(rd), Operand::Imm32(imm), Operand::Nothing, Operand::Nothing] if thumb => (rd, imm, true),
        [Operand::Reg(rd), Operand::Reg(base), Operand::Imm32(imm), Operand::Nothing] if !thumb && base.number() == PC => {
            (rd, imm, a32_adr_adds(bytes)?)
        }
        _ => return None,
    };
    // `adr pc, label` is a branch, not a value written to a register.
    if rd.number() == PC {
        return None;
    }
    let at = if add { pc.literal_base.wrapping_add(u64::from(imm)) } else { pc.literal_base.wrapping_sub(u64::from(imm)) };
    Some((reg_name(rd), MicroExpr::constant(i128::from(at & 0xffff_ffff), 32)))
}

/// Whether an A32 `adr` word adds (`Some(true)`, opcode `0100`) or subtracts
/// (`Some(false)`, `0010`) — see [`adr`]. `None` for any other opcode field.
fn a32_adr_adds(bytes: &[u8]) -> Option<bool> {
    let word = u32::from_le_bytes(*bytes.first_chunk::<4>()?);
    match (word >> 21) & 0xf {
        0b0100 => Some(true),
        0b0010 => Some(false),
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
    // Multiply-long and `ldrd` write a *second* register (`operand[1]`) — and
    // so do `umaal` and, in Thumb, the halfword and dual multiply-longs
    // (`smlal<x><y>`, `smlald`, `smlsld`), all `RdLo, RdHi, …`. Those four were
    // missing, so their `RdHi` kept its old value through the `asm` fallback.
    if matches!(inst.opcode, UMULL | SMULL | UMLAL | SMLAL | LDRD | UMAAL | SMLAL_halfword(..) | SMLALD(_) | SMLSLD(_))
        && let Operand::Reg(r) = inst.operands[1]
    {
        w.push(reg_name(r));
    }
    for op in &inst.operands {
        match op {
            // `ldm`/`pop` writes its whole register list; `stm`/`push` reads it.
            Operand::RegList(mask) if matches!(inst.opcode, LDM(..) | POP) => w.extend(reglist(*mask)),
            // Write-back updates the base register.
            Operand::RegWBack(base, true) => w.push(reg_name(*base)),
            op => w.extend(writeback_base(op).map(reg_name)),
        }
    }
    // Thumb's `push`/`pop` name no base operand: the decoder gives them the
    // list alone, and the `sp` they move is implicit. Left out, a predicated
    // `push` kept as `asm` inside an `IT` block left `sp` where it was.
    if matches!(inst.opcode, PUSH | POP) {
        w.push(reg_n(SP));
    }
    // A call this lift leaves as `asm` — the conditional `blne`, which is two
    // effects — still clobbers what any call clobbers when it is taken: the
    // return address, and AAPCS32's caller-saved registers, which is where its
    // result comes back. Invalidating only `lr` let a later read of `r0` take
    // the value from before the call.
    if matches!(inst.opcode, BL | BLX) {
        w.push("lr".to_string());
        w.extend(names_of(AAPCS32_VOLATILE));
    }
    w
}

/// Register ids of this architecture by name, through its register file.
fn names_of(regs: &[Reg]) -> Vec<String> {
    let file = RegisterFile::new(ARM32_REGS);
    regs.iter().filter_map(|&r| file.name(r)).map(str::to_string).collect()
}

/// The base register a memory operand writes back, if it does — the one
/// answer [`MemOperand`] gives the lift, so the `asm` fallback and the lifted
/// form cannot disagree (post-indexing always writes back). The unindexed form
/// (`RegDeref`) never does.
fn writeback_base(op: &Operand) -> Option<yaxpeax_arm::armv7::Reg> {
    MemOperand::of(op).filter(|m| m.wback).map(|m| m.base)
}

/// The operand positions of an instruction that are **written and not read**:
/// the destinations whose old value the instruction never consults. Every
/// other register operand is a read.
///
/// A list of what is known to be write-only, rather than of what is known to
/// be read, because the two mistakes are not equal. Calling a source a
/// destination drops a read, and a dropped read is the defect
/// [`reads_of`] exists to close: the definition it consumed is deleted as dead.
/// Calling a destination a source only keeps one definition alive that need
/// not be. So an opcode not named here reads every register it mentions —
/// `movt` (keeps the low half), `bfi`, the accumulating long multiplies, the
/// stores and compares, and anything this list has not been taught.
fn write_only_operands(op: Opcode) -> &'static [usize] {
    use Opcode::*;
    match op {
        UMULL | SMULL | LDRD | LDREXD | LDAEXD => &[0, 1],
        AND | EOR | SUB | RSB | ADD | ADC | SBC | RSC | ORR | MOV | BIC | MVN | ORN | LSL | LSR | ASR
        | RRX | ROR | ADR | MRS | CLZ | RBIT | REV | REV16 | REVSH | MUL | MLA | MLS | SDIV | UDIV
        | SMUL(..) | SMLA(..) | SMLAW(_) | SMULW(_) | SMMUL | SMMLA | SMMLAR | SMMLS | SMMLSR | SMUAD
        | SMUSD | SMLAD | SMLSD | USAD8 | USADA8 | QADD | QSUB | QDADD | QDSUB | SXTH | UXTH | SXTB16
        | UXTB16 | SXTB | UXTB | SXTAH | UXTAH | SXTAB16 | UXTAB16 | SXTAB | UXTAB | PKHTB | PKHBT
        | SSAT | SSAT16 | USAT | USAT16 | SBFX | UBFX | SEL | SADD16 | QADD16 | SHADD16 | SASX | QASX
        | SHASX | SSAX | QSAX | SHSAX | SSUB16 | QSUB16 | SHSUB16 | SADD8 | QADD8 | SHADD8 | SSUB8
        | QSUB8 | SHSUB8 | UADD16 | UQADD16 | UHADD16 | UASX | UQASX | UHASX | USAX | UQSAX | UHSAX
        | USUB16 | UQSUB16 | UHSUB16 | UADD8 | UQADD8 | UHADD8 | USUB8 | UQSUB8 | UHSUB8 | LDR | LDRB
        | LDRH | LDRSH | LDRSB | LDRT | LDRBT | LDRHT | LDRSHT | LDRSBT | LDREX | LDREXB | LDREXH | LDA
        | LDAB | LDAH | LDAEX | LDAEXB | LDAEXH | STREX | STREXB | STREXH | STREXD | STLEX | STLEXB
        | STLEXH | STLEXD | SWP | SWPB => &[0],
        _ => &[],
    }
}

/// The registers an instruction **reads** — a *sound over-approximation*, the
/// mirror of [`writes_of`]: every register in every operand except the
/// write-only destinations ([`write_only_operands`]); the address registers of
/// every memory operand; the list a `stm`/`push` stores.
///
/// `predicated` (a condition other than `AL`) makes the destinations reads as
/// well: when the condition fails the register keeps its old value, so the
/// value after the instruction may be the one from before it.
///
/// A conditional call or return left as `asm` reads what the lifted forms read:
/// a call consumes AAPCS32's argument registers and the stack pointer, a `bx
/// lr` the return register — or the values a caller passed and a function
/// computed would be deleted on the path where the condition holds. Those are
/// the *convention's* reads, not the encoding's, and the callee may take none
/// of them, so the answer is then a [`UnliftedReads::Bound`]: it keeps the
/// definitions alive without saying the function has four parameters. Stated
/// exactly, every function with a `blne` claimed `r0`-`r3`.
fn reads_of(inst: &Instruction, predicated: bool) -> UnliftedReads {
    use Opcode::*;
    let mut r: Vec<String> = Vec::new();
    let push = |n: String, r: &mut Vec<String>| {
        if !r.contains(&n) {
            r.push(n);
        }
    };
    let write_only = if predicated { &[][..] } else { write_only_operands(inst.opcode) };
    for (i, op) in inst.operands.iter().enumerate() {
        let names: Vec<String> = match *op {
            Operand::Reg(reg) if !write_only.contains(&i) => vec![reg_name(reg)],
            Operand::RegWBack(base, _) | Operand::RegDeref(base) => vec![reg_name(base)],
            Operand::RegList(mask) if !matches!(inst.opcode, LDM(..) | POP) => reglist(mask),
            Operand::RegShift(rs) => shift_regs(rs),
            Operand::RegDerefPostindexOffset(base, ..) | Operand::RegDerefPreindexOffset(base, ..) => vec![reg_name(base)],
            Operand::RegDerefPostindexReg(base, idx, ..) | Operand::RegDerefPreindexReg(base, idx, ..) => {
                vec![reg_name(base), reg_name(idx)]
            }
            Operand::RegDerefPostindexRegShift(base, rs, ..) | Operand::RegDerefPreindexRegShift(base, rs, ..) => {
                let mut v = vec![reg_name(base)];
                v.extend(shift_regs(rs));
                v
            }
            _ => Vec::new(),
        };
        for n in names {
            push(n, &mut r);
        }
    }
    // The implicit base of Thumb's `push`/`pop` — see [`writes_of`].
    if matches!(inst.opcode, PUSH | POP) {
        push(reg_n(SP), &mut r);
    }
    match inst.opcode {
        BL | BLX => {
            for n in names_of(AAPCS32_INT_ARGS) {
                push(n, &mut r);
            }
            push("sp".to_string(), &mut r);
            UnliftedReads::Bound(r)
        }
        BX | BXJ if matches!(inst.operands[0], Operand::Reg(lr) if lr.number() == 14) => {
            push("r0".to_string(), &mut r);
            UnliftedReads::Bound(r)
        }
        _ => UnliftedReads::Exact(r),
    }
}

/// The registers a shifted-register operand reads: the shiftee, and the
/// shifting register when the count is in one.
fn shift_regs(rs: yaxpeax_arm::armv7::RegShift) -> Vec<String> {
    match rs.into_shift() {
        RegShiftStyle::RegImm(s) => vec![reg_name(s.shiftee())],
        RegShiftStyle::RegReg(s) => vec![reg_name(s.shiftee()), reg_name(s.shifter())],
    }
}

/// What an instruction does to memory, by opcode — one table for the whole
/// crate-decoded space, [`MemEffect::NoAccess`] only for the families that
/// provably name no memory: data processing, the multiplies and media
/// operations, branches, hints and barriers. A barrier orders accesses and
/// changes no value, which is all the forwarding that reads this asks about.
///
/// Everything not named — a supervisor or hypervisor call (whatever runs next
/// may write anything), a coprocessor operation (cache maintenance is one),
/// `msr`/`cps`/`setend`, a breakpoint — is [`MemEffect::Unknown`].
fn mem_of(op: Opcode) -> MemEffect {
    use Opcode::*;
    match op {
        STR | STRB | STRH | STRD | STRT | STRBT | STRHT | STM(..) | PUSH | STREX | STREXB | STREXH
        | STREXD | STL | STLB | STLH | STLEX | STLEXB | STLEXH | STLEXD | STC(..) | STCL(..) | SRS(..) => {
            MemEffect::Write
        }
        LDR | LDRB | LDRH | LDRSH | LDRSB | LDRD | LDRT | LDRBT | LDRHT | LDRSHT | LDRSBT | LDM(..) | POP
        | LDREX | LDREXB | LDREXH | LDREXD | LDA | LDAB | LDAH | LDAEX | LDAEXB | LDAEXH | LDAEXD
        | LDC(..) | LDCL(..) | RFE(..) | TBB | TBH | PLD | PLI => MemEffect::Read,
        SWP | SWPB => MemEffect::ReadWrite,
        AND | EOR | SUB | RSB | ADD | ADC | SBC | RSC | TST | TEQ | CMP | CMN | ORR | MOV | BIC | MVN
        | ORN | LSL | LSR | ASR | RRX | ROR | ADR | CLZ | RBIT | REV | REV16 | REVSH | MOVT | MUL | MLA
        | MLS | UMAAL | UMULL | UMLAL | SMULL | SMLAL | SMUL(..) | SMLA(..) | SMLAL_halfword(..)
        | SMAL(..) | SMLAW(_) | SMULW(_) | SMMUL | SMMLA | SMMLAR | SMMLS | SMMLSR | SMUAD | SMUSD
        | SMLAD | SMLSD | SMLALD(_) | SMLSLD(_) | SDIV | UDIV | USAD8 | USADA8 | QADD | QSUB | QDADD
        | QDSUB | SXTH | UXTH | SXTB16 | UXTB16 | SXTB | UXTB | SXTAH | UXTAH | SXTAB16 | UXTAB16 | SXTAB
        | UXTAB | PKHTB | PKHBT | SSAT | SSAT16 | USAT | USAT16 | SBFX | UBFX | BFI | BFC | SEL | SADD16
        | QADD16 | SHADD16 | SASX | QASX | SHASX | SSAX | QSAX | SHSAX | SSUB16 | QSUB16 | SHSUB16 | SADD8
        | QADD8 | SHADD8 | SSUB8 | QSUB8 | SHSUB8 | UADD16 | UQADD16 | UHADD16 | UASX | UQASX | UHASX
        | USAX | UQSAX | UHSAX | USUB16 | UQSUB16 | UHSUB16 | UADD8 | UQADD8 | UHADD8 | USUB8 | UQSUB8
        | UHSUB8 | B | BX | BXJ | CBZ | CBNZ | IT | NOP | HINT | YIELD | WFE | WFI | SEV | CSDB | DMB | DSB
        | ISB | CLREX => MemEffect::NoAccess,
        _ => MemEffect::Unknown,
    }
}

/// Does an instruction of this family write the `Q` (saturation) flag or the
/// `GE` flags? Both live in the APSR beside `N`/`Z`/`C`/`V`, and the lift keeps
/// the whole APSR as the one `flags` value — so a write to them must end the
/// value an earlier instruction left, like any other flags write. No branch
/// condition reads them, so the cost of counting them is a branch after one of
/// these losing its condition; the cost of missing them would be `sel` (which
/// reads `GE`) or `mrs` reading a stale value once either is modelled.
///
/// One table for both decoders: [`own::Own::opcode`] maps an instruction this
/// file decodes onto the same families. `GE`: the plain signed and unsigned
/// parallel add/sub (not the saturating `q`/`uq` or halving `sh`/`uh` forms).
/// `Q`: the saturating arithmetic and saturate instructions, `smla<x><y>`,
/// `smlaw<y>`, and the dual multiplies that can overflow (`smlad`, `smlsd`,
/// `smuad` — `smusd` cannot).
fn writes_q_or_ge(op: Opcode) -> bool {
    use Opcode::*;
    matches!(
        op,
        SADD16 | SASX | SSAX | SSUB16 | SADD8 | SSUB8 | UADD16 | UASX | USAX | USUB16 | UADD8 | USUB8
            | QADD | QSUB | QDADD | QDSUB | SSAT | USAT | SSAT16 | USAT16
            | SMLA(..) | SMLAW(_) | SMLAD | SMLSD | SMUAD
    )
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
    /// Re-decode a neutral `DecodedInsn` back to the decoded instruction for
    /// operand-level lift detail — mirrors `x64_lift::decode_raw`.
    fn redecode(&self, insn: &DecodedInsn) -> Option<Inst> {
        self.decode_inst(&insn.bytes)
    }

    /// The sound fallback for an instruction the lift does not model: preserve it
    /// verbatim, then invalidate every register it could write so no later read
    /// reuses a stale value — and the flags, when it sets them, so no later
    /// branch reuses a stale compare. Without that a `tst` kept as `asm`
    /// between a `cmp` and a `beq` let the branch read the `cmp`.
    fn unlifted(&self, inst: &Instruction, insn: &DecodedInsn) -> Vec<MicroStmt> {
        asm_fallback(insn, writes_of(inst), reads_of(inst, insn.cond.is_some()), mem_of(inst.opcode), self.sets_flags(inst, insn))
    }

    /// The lift of an instruction this file decodes itself: exact where
    /// [`own::Own::lift`] models it, predicated like any other write, and the
    /// same `asm` fallback otherwise. None of the modelled forms writes a
    /// flag; the guard keeps a form that does (a saturating one, say) on the
    /// fallback, where its flags write is not lost, until that write is
    /// modelled too.
    fn lift_own(&self, o: &own::Own, insn: &DecodedInsn) -> Vec<MicroStmt> {
        match o.lift() {
            Some((dst, value)) if !writes_q_or_ge(o.opcode()) => {
                let mut out = Vec::new();
                pred_assign(dst, value, insn.cond.as_deref().unwrap_or("al"), &mut out);
                out
            }
            _ => asm_fallback(
                insn,
                o.writes(),
                UnliftedReads::Exact(o.reads(insn.cond.is_some())),
                o.mem(),
                writes_q_or_ge(o.opcode()),
            ),
        }
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
        if matches!(inst.opcode, CMP | CMN | TST | TEQ | MSR) || writes_q_or_ge(inst.opcode) {
            return true;
        }
        let in_it_block = self.thumb && insn.cond.is_some() && cond_of(inst).is_none();
        inst.s() && !(in_it_block && insn.len == 2)
    }

    /// What this instruction reads from `pc` — see [`PcView`]. In Thumb a
    /// register operand `pc` is defined in two places only: the 16-bit `mov`
    /// (`va + 4`), and `addw`/`subw` (`11110 i 1 … Rn=1111`, bit 9 of the first
    /// halfword set), which are `adr`'s 32-bit encodings and read `Align(PC,
    /// 4)`. Everywhere else it is UNPREDICTABLE or a different instruction.
    fn pc_view(&self, inst: &Instruction, insn: &DecodedInsn) -> PcView {
        if !self.thumb {
            return PcView::a32(insn.va);
        }
        let hw1 = insn.bytes.first_chunk::<2>().map_or(0, |b| u16::from_le_bytes(*b));
        let plain_immediate = hw1 >> 11 == 0b11110 && hw1 & (1 << 9) != 0;
        // `adr.w` into `sp` or `pc` is UNPREDICTABLE (llvm-mc warns on it too).
        let rd_sp_or_pc = matches!(inst.operands[0], Operand::Reg(rd) if rd.number() == SP || rd.number() == PC);
        let operand = match (inst.opcode, insn.len) {
            (Opcode::MOV, 2) => ThumbPcOperand::Pc,
            (Opcode::ADD | Opcode::SUB, 4) if plain_immediate && !rd_sp_or_pc => ThumbPcOperand::Aligned,
            _ => ThumbPcOperand::Refused,
        };
        PcView::thumb(insn.va, operand)
    }

    /// A single load or store — `ldr`/`ldrb`/`ldrh`/`ldrsb`/`ldrsh`/`ldrd` and
    /// `str`/`strb`/`strh`/`strd` — in every addressing mode: an immediate, a
    /// register or a shifted-register index, added or subtracted, pre-indexed
    /// with or without write-back, post-indexed (which always writes back).
    /// The loaded value is held as a 32-bit register holds it: a byte or
    /// halfword zero-extended, or sign-extended and cast back to 32 bits, as
    /// the extends are. `ldrd`/`strd` are two words, the first register at the
    /// lower address.
    ///
    /// `None` — the `asm` fallback — for what is not one plain transfer:
    ///
    /// * a load into `pc` is a branch, and a store of `pc` stores
    ///   `PCStoreValue()`, which is IMPLEMENTATION DEFINED. The one load into
    ///   `pc` lifted is `ldr pc, [sp], #4` — `pop {pc}` — when the CFG
    ///   classified it as the return, which it then is;
    /// * the register choices the ARM ARM makes UNPREDICTABLE: write-back with
    ///   the base `pc` or one of the transferred registers; an index register
    ///   `pc`; an `ldrd`/`strd` pair that is not two different registers (A32:
    ///   an even register and the next); in Thumb, `sp` as a byte/halfword or
    ///   pair register or as an index, and a store or register-indexed load
    ///   based on `pc` (UNDEFINED; only the literal loads may name it);
    /// * a word the decoder accepts and the architecture does not define as
    ///   this instruction: an A32 register-indexed halfword/dual form with its
    ///   should-be-zero bits set ([`a32_extra_sbz_set`]), a malformed 32-bit
    ///   Thumb one ([`thumb_single_transfer_well_formed`]) — both found by
    ///   `tests/a32_memory_agrees_with_llvm_mc.rs`;
    /// * a written-back load whose index register is also loaded (`ldr r0, [r1],
    ///   r0`): the IR has no temporary for the old index, and the write-back
    ///   would read the loaded value;
    /// * a predicated store or write-back — two conditional effects. A
    ///   predicated load without write-back is a conditional write, as any
    ///   other.
    fn lift_transfer(&self, inst: &Instruction, insn: &DecodedInsn, pc: PcView) -> Option<Vec<MicroStmt>> {
        use Opcode::*;
        let (bits, signed, load, pair) = match inst.opcode {
            LDR => (32, false, true, false),
            LDRB => (8, false, true, false),
            LDRH => (16, false, true, false),
            LDRSB => (8, true, true, false),
            LDRSH => (16, true, true, false),
            LDRD => (32, false, true, true),
            STR => (32, false, false, false),
            STRB => (8, false, false, false),
            STRH => (16, false, false, false),
            STRD => (32, false, false, true),
            _ => return None,
        };
        let (regs, mem) = match (pair, &inst.operands) {
            (false, [Operand::Reg(rt), m, Operand::Nothing, Operand::Nothing]) => (vec![rt.number()], MemOperand::of(m)?),
            (true, [Operand::Reg(rt), Operand::Reg(rt2), m, Operand::Nothing]) => (vec![rt.number(), rt2.number()], MemOperand::of(m)?),
            _ => return None,
        };
        let cond_al = insn.cond.is_none();
        let base = mem.base.number();
        if regs.contains(&PC) {
            let pop_pc = inst.opcode == LDR
                && base == SP
                && !mem.pre
                && mem.add
                && matches!(mem.index, Index::Imm(4))
                && insn.kind == InsnKind::Ret
                && cond_al;
            return if pop_pc { block_stmts(&reg_n(SP), BlockMode::IncrementAfter, true, true, 1 << PC) } else { None };
        }
        let index_regs = mem.index_regs();
        let unpredictable = (mem.wback && (base == PC || regs.contains(&base)))
            || index_regs.contains(&PC)
            || (pair && (regs[0] == regs[1] || index_regs.iter().any(|r| regs.contains(r))))
            || (pair && !self.thumb && (regs[0] % 2 != 0 || regs[1] != regs[0] + 1))
            || (self.thumb && index_regs.contains(&SP))
            || (self.thumb && base == PC && (!index_regs.is_empty() || !load))
            || (self.thumb && (pair || bits < 32) && regs.contains(&SP))
            || (!self.thumb && a32_extra_sbz_set(&insn.bytes))
            || (self.thumb && !thumb_single_transfer_well_formed(&insn.bytes));
        let ordering = load && mem.wback && index_regs.iter().any(|r| regs.contains(r));
        if unpredictable || ordering || (!cond_al && (!load || mem.wback)) {
            return None;
        }
        let addr = mem.address(pc)?;
        let new_base = if mem.wback { Some(mem.offset_address(pc)?) } else { None };
        let addrs: Vec<MicroExpr> = if pair { vec![addr.clone(), plus_four(addr)] } else { vec![addr] };
        let mut out = Vec::new();
        if load {
            let value = |a: &MicroExpr| {
                let l = MicroExpr::load(a.clone(), bits, signed);
                if signed { MicroExpr::Cast { signed: false, bits: 32, expr: Box::new(l) } } else { l }
            };
            // A loaded base is loaded last, so the other address is computed
            // from the base the instruction started with (`ldrd r0, r1, [r0]`).
            let mut order: Vec<usize> = (0..regs.len()).collect();
            order.sort_by_key(|&i| regs[i] == base);
            let cond_lc = insn.cond.as_deref().unwrap_or("al");
            for i in order {
                pred_assign(reg_n(regs[i]), value(&addrs[i]), cond_lc, &mut out);
            }
        } else {
            for (r, a) in regs.iter().zip(addrs) {
                out.push(MicroStmt::Store { addr: a, value: MicroExpr::var(reg_n(*r)), bits });
            }
        }
        if let Some(nb) = new_base {
            out.push(assign(reg_name(mem.base), nb));
        }
        Some(out)
    }

    /// `ldm`/`stm` in any of the four modes, and `push`/`pop` — see
    /// [`block_stmts`] for what is refused. The mode is the encoding's
    /// ([`block_mode`]); an A32 user-bank or exception-return form (`^`) and a
    /// predicated one stay `asm`.
    fn lift_block(&self, inst: &Instruction, insn: &DecodedInsn) -> Option<Vec<MicroStmt>> {
        use Opcode::*;
        if insn.cond.is_some() {
            return None;
        }
        let (load, base, wback, mask, mode) = match (inst.opcode, &inst.operands) {
            (PUSH, [Operand::RegList(mask), ..]) => (false, SP, true, *mask, BlockMode::DecrementBefore),
            (POP, [Operand::RegList(mask), ..]) => (true, SP, true, *mask, BlockMode::IncrementAfter),
            (LDM(..) | STM(..), [Operand::RegWBack(base, wback), Operand::RegList(mask), Operand::Nothing, Operand::Nothing]) => {
                if !self.thumb && a32_user_bank(&insn.bytes) {
                    return None;
                }
                (matches!(inst.opcode, LDM(..)), base.number(), *wback, *mask, block_mode(&insn.bytes, self.thumb)?)
            }
            _ => return None,
        };
        // Thumb's 32-bit forms: fewer than two registers, or a loaded list
        // holding both `lr` and `pc`, is UNPREDICTABLE (ARM ARM, `LDM`/`STM`/
        // `PUSH`/`POP` encodings T2) — the decoder builds them anyway; llvm-mc
        // reads the one-register `pop.w {r2}` as `ldm.w sp!, {r2}` and warns.
        let both_lr_pc = mask & (1 << LR | 1 << PC) == (1 << LR | 1 << PC);
        if self.thumb && insn.len == 4 && (mask.count_ones() < 2 || (load && both_lr_pc)) {
            return None;
        }
        block_stmts(&reg_n(base), mode, load, wback, mask)
    }
}

/// Whether a 32-bit Thumb single load/store word is one the architecture
/// defines — the checks the decoder skips. Its `1111 100x` first halfwords
/// hold, for a base other than `pc` and bit 7 clear, two forms told apart by
/// bit 11 of the second halfword (ARM ARM A6.3.10, `LDR`/`STR` T3 and T4 and
/// their byte and halfword siblings):
///
/// * `Rt 1 P U W imm8`, where `P = 0, W = 0` is UNDEFINED — the decoder read
///   it as a post-indexed access (`strb.w r1, [r0], #-0`, which llvm-mc
///   rejects);
/// * `Rt 0 00000 imm2 Rm`, the register form, whose bits 10-6 must be zero —
///   the decoder read any value there as the same instruction.
///
/// Every other Thumb word passes; a 16-bit one has no such field.
fn thumb_single_transfer_well_formed(bytes: &[u8]) -> bool {
    let (Some(hw1), Some(hw2)) = (bytes.first_chunk::<2>().map(|b| u16::from_le_bytes(*b)), bytes.get(2..4).map(|b| u16::from_le_bytes([b[0], b[1]]))) else {
        return true;
    };
    let single = hw1 >> 9 == 0b111_1100 && hw1 & (1 << 7) == 0 && hw1 & 0xf != 0xf;
    if !single {
        return true;
    }
    if hw2 & (1 << 11) != 0 {
        let (p, w) = (hw2 & (1 << 10) != 0, hw2 & (1 << 8) != 0);
        p || w
    } else {
        (hw2 >> 6) & 0x1f == 0
    }
}

/// An A32 "extra" load/store with a register index — `ldrh`/`strh`/`ldrsb`/
/// `ldrsh`/`ldrd`/`strd`, `I` (bit 22) clear — whose bits 11-8, which should
/// be zero, are not. The decoder reads past them, and so does llvm-mc, which
/// prints such a word as if they were clear; the ARM ARM leaves it
/// UNPREDICTABLE, so the lift does not state a value for it.
fn a32_extra_sbz_set(bytes: &[u8]) -> bool {
    let Some(word) = bytes.first_chunk::<4>().map(|b| u32::from_le_bytes(*b)) else { return false };
    let extra = word & 0x0e00_0090 == 0x0000_0090 && word & 0x60 != 0;
    extra && word & (1 << 22) == 0 && word & 0x0f00 != 0
}

/// `addr + 4`, kept in the `base ± k` shape the forwarding pass keys stack
/// slots by — the second word of an `ldrd`/`strd`.
fn plus_four(addr: MicroExpr) -> MicroExpr {
    match addr {
        MicroExpr::Const { value, bits } => MicroExpr::constant((value + 4) & 0xffff_ffff, bits),
        MicroExpr::Binary(BinOp::Add, b, k) if matches!(*k, MicroExpr::Const { .. }) => {
            let MicroExpr::Const { value, bits } = *k else { unreachable!() };
            MicroExpr::binary(BinOp::Add, *b, MicroExpr::constant(value + 4, bits))
        }
        MicroExpr::Binary(BinOp::Sub, b, k) if matches!(*k, MicroExpr::Const { value, .. } if value >= 4) => {
            let MicroExpr::Const { value, bits } = *k else { unreachable!() };
            if value == 4 { *b } else { MicroExpr::binary(BinOp::Sub, *b, MicroExpr::constant(value - 4, bits)) }
        }
        other => MicroExpr::binary(BinOp::Add, other, MicroExpr::constant(4, 32)),
    }
}

/// `asm` stating what it reads and does to memory, then every register in
/// `writes` invalidated, then the flags when the instruction sets them — the
/// one shape of the fallback, for both decoders.
fn asm_fallback(insn: &DecodedInsn, writes: Vec<String>, reads: UnliftedReads, mem: MemEffect, sets_flags: bool) -> Vec<MicroStmt> {
    let mut out = vec![MicroStmt::Unlifted { va: insn.va, text: insn.text.clone(), reads, mem }];
    for w in writes {
        out.push(assign(w, MicroExpr::Unknown(insn.text.clone())));
    }
    if sets_flags {
        out.push(opaque_flags(insn));
    }
    out
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

    /// The same two answers the `asm` fallback states, from the same
    /// functions — so a def-use record and the IR cannot disagree about what an
    /// instruction touches. `reads` was always empty here, which said every
    /// A32 instruction consumed nothing.
    fn reg_access(&self, insn: &DecodedInsn) -> RegAccess {
        let predicated = insn.cond.is_some();
        match self.redecode(insn) {
            Some(Inst::Crate(inst)) => RegAccess { reads: reads_of(&inst, predicated).regs().to_vec(), writes: writes_of(&inst) },
            Some(Inst::Own(o)) => RegAccess { reads: o.reads(predicated), writes: o.writes() },
            None => RegAccess::default(),
        }
    }

    fn branch_condition(&self, mnemonic: &str, flags_value: &MicroExpr) -> MicroExpr {
        arm_branch_condition(mnemonic, flags_value)
    }

    fn lift(&self, insn: &DecodedInsn, _abi: &str) -> Vec<MicroStmt> {
        use Opcode::*;
        let inst = match self.redecode(insn) {
            Some(Inst::Crate(inst)) => inst,
            Some(Inst::Own(o)) => return self.lift_own(&o, insn),
            None => return vec![MicroStmt::unlifted_unknown(insn.va, &insn.text)],
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
        let pc = self.pc_view(&inst, insn);
        let mut out = Vec::new();
        match inst.opcode {
            MOV | MVN | ADD | SUB | AND | ORR | EOR | BIC | MUL | ADR => {
                let result = if inst.opcode == ADR { adr(&inst, &insn.bytes, self.thumb, pc) } else { data_processing(&inst, pc.operand) };
                let Some((rd, value)) = result else {
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
            LDR | LDRB | LDRH | LDRSB | LDRSH | LDRD | STR | STRB | STRH | STRD => match self.lift_transfer(&inst, insn, pc) {
                Some(stmts) => out = stmts,
                None => return self.unlifted(&inst, insn),
            },
            // A conditional store/compare/call/return is more than one predicated
            // register write; those stay `asm` (sound) until modelled.
            TST if cond_al => match ops {
                // `tst Rn, op2` sets `Z` from `Rn & op2` — the `Test` compare
                // kind; see `arm_branch_condition` for which conditions that
                // answers on this architecture.
                [rn @ Operand::Reg(_), op2, Operand::Nothing, Operand::Nothing] => match (op_rvalue(rn, pc.operand), op_rvalue(op2, pc.operand)) {
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
                    [lhs @ Operand::Reg(_), rhs, Operand::Nothing, Operand::Nothing] => (op_rvalue(lhs, pc.operand), op_rvalue(rhs, pc.operand)),
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
            // `ldm`/`stm` in all four modes, `push`/`pop` among them — the
            // stores and loads they are, then the base update. A32 spells
            // `push`/`pop` `stmdb sp!` / `ldmia sp!` (the decoder prints the
            // alias); Thumb has `push`/`pop` opcodes whose only operand is the
            // list.
            LDM(..) | STM(..) | PUSH | POP => match self.lift_block(&inst, insn) {
                Some(stmts) => out = stmts,
                None => return self.unlifted(&inst, insn),
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
        let inst = match self.decode_inst(bytes).ok_or(DecodeError::Invalid(va))? {
            Inst::Crate(inst) => inst,
            Inst::Own(o) => {
                // Owned words are A32, four bytes, and `decode_inst` read all
                // four to get here; none is a direct branch.
                let text = o.text();
                let mnemonic = text.split_whitespace().next().unwrap_or("").to_string();
                return Ok(DecodedInsn { va, len: 4, bytes: bytes[..4].to_vec(), mnemonic, text, kind: o.kind(), target: None, rip_target: None, cond: cond_name(o.cond), stack_adjust: None });
            }
        };
        let len = inst.len().to_const() as usize;
        if len == 0 || bytes.len() < len {
            return Err(DecodeError::Truncated(va));
        }
        let text = if self.thumb { format!("{inst}") } else { a32_text(&inst, bytes, format!("{inst}")) };
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
        // e92d4010 push {r4, lr} → *(sp - 8) = r4, *(sp - 4) = lr, sp = sp - 8.
        let push = lift1(&[0x10, 0x40, 0x2d, 0xe9]);
        assert_eq!(
            push,
            vec![
                MicroStmt::Store { addr: MicroExpr::binary(BinOp::Sub, MicroExpr::var("sp"), MicroExpr::constant(8, 32)), value: MicroExpr::var("r4"), bits: 32 },
                MicroStmt::Store { addr: MicroExpr::binary(BinOp::Sub, MicroExpr::var("sp"), MicroExpr::constant(4, 32)), value: MicroExpr::var("lr"), bits: 32 },
                MicroStmt::Assign { dst: "sp".into(), value: MicroExpr::binary(BinOp::Sub, MicroExpr::var("sp"), MicroExpr::constant(8, 32)) },
            ],
        );
        // e8bd8010 pop {r4, pc} → r4 restored, sp += 8, return.
        let pop = lift1(&[0x10, 0x80, 0xbd, 0xe8]);
        assert!(pop.iter().any(|s| matches!(s, MicroStmt::Assign { dst, .. } if dst == "sp")));
        assert!(pop.iter().any(|s| matches!(s, MicroStmt::Return(_))), "pop {{…,pc}} returns: {pop:?}");
    }

    /// `push` and `pop` are the stores and loads they are, in both instruction
    /// sets: the lowest-numbered register at the lowest address, the block
    /// ending at the incoming `sp` (ARM ARM, `STMDB`/`LDMIA`). They used to
    /// move `sp` and touch no memory, and Thumb's — whose only operand is the
    /// list — did not even move `sp`. Every encoding is llvm-mc's.
    #[test]
    fn push_stores_its_list_and_pop_loads_it_back() {
        let sp = |op: BinOp, n: i128| if n == 0 { MicroExpr::var("sp") } else { MicroExpr::binary(op, MicroExpr::var("sp"), MicroExpr::constant(n, 32)) };
        let store = |off: i128, r: &str| MicroStmt::Store { addr: sp(BinOp::Sub, off), value: MicroExpr::var(r), bits: 32 };
        let load = |r: &str, off: i128| MicroStmt::Assign { dst: r.into(), value: MicroExpr::load(sp(BinOp::Add, off), 32, false) };
        let push_r4_lr = vec![store(8, "r4"), store(4, "lr"), MicroStmt::Assign { dst: "sp".into(), value: sp(BinOp::Sub, 8) }];
        let pop_r4_pc = vec![load("r4", 0), MicroStmt::Assign { dst: "sp".into(), value: sp(BinOp::Add, 8) }, MicroStmt::Return(Some(MicroExpr::var("r0")))];
        let thumb = |bytes: &[u8]| {
            let t = Arm32::thumb();
            let di = t.decode(bytes, Va(0x1000)).unwrap();
            t.lift(&di, "aapcs32")
        };
        // e92d4010 push {r4, lr}; e8bd8010 pop {r4, pc}
        assert_eq!(lift1(&[0x10, 0x40, 0x2d, 0xe9]), push_r4_lr);
        assert_eq!(lift1(&[0x10, 0x80, 0xbd, 0xe8]), pop_r4_pc);
        // Thumb: b510 push {r4, lr}; bd10 pop {r4, pc}
        assert_eq!(thumb(&[0x10, 0xb5]), push_r4_lr);
        assert_eq!(thumb(&[0x10, 0xbd]), pop_r4_pc);
        // e8bd4010 pop {r4, lr} — no `pc`, so no return.
        assert_eq!(
            lift1(&[0x10, 0x40, 0xbd, 0xe8]),
            vec![load("r4", 0), load("lr", 4), MicroStmt::Assign { dst: "sp".into(), value: sp(BinOp::Add, 8) }]
        );
        // Thumb-2: e92d 4110 push.w {r4, r8, lr}
        assert_eq!(
            thumb(&[0x2d, 0xe9, 0x10, 0x41]),
            vec![store(12, "r4"), store(8, "r8"), store(4, "lr"), MicroStmt::Assign { dst: "sp".into(), value: sp(BinOp::Sub, 12) }]
        );
        // e92d2001 push {r0, sp} and e92d8001 push {r0, pc} store a value this
        // lift does not compute, so they stay `asm` — writing memory and `sp`.
        for bytes in [[0x01, 0x20, 0x2d, 0xe9], [0x01, 0x80, 0x2d, 0xe9]] {
            let stmts = lift1(&bytes);
            assert!(matches!(stmts.first(), Some(MicroStmt::Unlifted { mem: MemEffect::Write, .. })), "{stmts:?}");
            assert!(invalidated(&stmts).contains(&"sp"), "{stmts:?}");
        }
    }

    /// A predicated Thumb `push` inside an `IT` block stays `asm`, and the
    /// `sp` it moves is implicit — the decoder gives it the register list
    /// alone. The fallback has to name it anyway, as written and as read.
    #[test]
    fn a_predicated_thumb_push_kept_as_asm_still_moves_sp() {
        let t = Arm32::thumb();
        // bf18 it ne; b510 pushne {r4, lr}; bf18 it ne; bd10 popne {r4, pc}
        let stream = t.decode_stream(&[0x18, 0xbf, 0x10, 0xb5, 0x18, 0xbf, 0x10, 0xbd], Va(0x1000), 4);
        for di in [&stream[1], &stream[3]] {
            assert_eq!(di.cond.as_deref(), Some("ne"), "{}", di.text);
            let stmts = t.lift(di, "aapcs32");
            assert!(invalidated(&stmts).contains(&"sp"), "{}: {stmts:?}", di.text);
            let Some(MicroStmt::Unlifted { reads, .. }) = stmts.first() else { panic!("{stmts:?}") };
            assert!(reads.regs().iter().any(|r| r == "sp"), "{}: {stmts:?}", di.text);
            assert!(t.reg_access(di).writes.iter().any(|r| r == "sp"), "{}", di.text);
        }
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

    // ---- the encodings this file decodes itself (`own`) ------------------------
    //
    // Every encoding below was checked against `llvm-mc --disassemble
    // -triple=armv7ve-none-eabi`, whose text is quoted per case; the meanings
    // are the ARM ARM's, and the lifted forms were run against an emulated
    // processor (`n0xis-core/tests/a32_media_agrees_with_the_processor.rs`).
    // Under `yaxpeax-arm` 0.5.0 alone every media word here was `(bad)`. The
    // helpers return the absence rather than unwrapping, so a word that does not
    // decode fails on the assertion that names it.

    /// The lift of one A32 word, or `None` when it does not decode.
    fn word_lift(word: u32) -> Option<Vec<MicroStmt>> {
        let a = Arm32::a32();
        a.decode(&word.to_le_bytes(), Va(0x1000)).ok().map(|di| a.lift(&di, "aapcs32"))
    }

    /// The text of one A32 word, or `None` when it does not decode.
    fn word_text(word: u32) -> Option<String> {
        Arm32::a32().decode(&word.to_le_bytes(), Va(0x1000)).ok().map(|d| d.text)
    }

    fn v(name: &str) -> MicroExpr {
        MicroExpr::var(name)
    }

    fn cast(signed: bool, bits: u32, e: MicroExpr) -> MicroExpr {
        MicroExpr::Cast { signed, bits, expr: Box::new(e) }
    }

    fn bin(op: BinOp, a: MicroExpr, b: MicroExpr) -> MicroExpr {
        MicroExpr::binary(op, a, b)
    }

    fn lifted_to(dst: &str, value: MicroExpr) -> Option<Vec<MicroStmt>> {
        Some(assign_to(dst, value))
    }

    /// The extends are a cast of the rotated register: a plain cast at
    /// rotation 0, a right shift where the field lies inside the register, and
    /// the two halves OR-ed where a halfword wraps. A sign extension is cast
    /// back to 32 bits, because an A32 register holds nothing above bit 31.
    #[test]
    fn the_extends_lift_to_a_cast_of_the_rotated_register() {
        // e6ef8073  llvm-mc: `uxtb r8, r3`
        assert_eq!(word_lift(0xe6ef_8073), lifted_to("r8", cast(false, 8, v("r3"))));
        // e6ef8473  llvm-mc: `uxtb r8, r3, ror #8`
        assert_eq!(word_lift(0xe6ef_8473), lifted_to("r8", cast(false, 8, bin(BinOp::Shr, v("r3"), c32(8)))));
        // e6ff1c72  llvm-mc: `uxth r1, r2, ror #24` — bits 24-31, then 0-7.
        assert_eq!(
            word_lift(0xe6ff_1c72),
            lifted_to("r1", cast(false, 16, bin(BinOp::Or, bin(BinOp::Shr, v("r2"), c32(24)), bin(BinOp::Shl, v("r2"), c32(8))))),
        );
        // e6af0071  llvm-mc: `sxtb r0, r1`
        assert_eq!(word_lift(0xe6af_0071), lifted_to("r0", cast(false, 32, cast(true, 8, v("r1")))));
        // e6bf0871  llvm-mc: `sxth r0, r1, ror #16`
        assert_eq!(word_lift(0xe6bf_0871), lifted_to("r0", cast(false, 32, cast(true, 16, bin(BinOp::Shr, v("r1"), c32(16))))));
    }

    /// `uxtab`/`sxtah`: `Rn` plus the extension, the sum held at 32 bits.
    #[test]
    fn the_extend_and_add_forms_lift_to_a_sum_held_at_32_bits() {
        // e6e10072  llvm-mc: `uxtab r0, r1, r2`
        assert_eq!(word_lift(0xe6e1_0072), lifted_to("r0", cast(false, 32, bin(BinOp::Add, v("r1"), cast(false, 8, v("r2"))))));
        // e6b10472  llvm-mc: `sxtah r0, r1, r2, ror #8`
        assert_eq!(
            word_lift(0xe6b1_0472),
            lifted_to("r0", cast(false, 32, bin(BinOp::Add, v("r1"), cast(true, 16, bin(BinOp::Shr, v("r2"), c32(8)))))),
        );
    }

    /// `ubfx` is `(Rn >> lsb) & mask`; `sbfx` moves the field's top bit to bit
    /// 31 and shifts it back down arithmetically.
    #[test]
    fn the_bitfield_extracts_lift_to_the_field() {
        // e7e70251  llvm-mc: `ubfx r0, r1, #4, #8`
        assert_eq!(word_lift(0xe7e7_0251), lifted_to("r0", bin(BinOp::And, bin(BinOp::Shr, v("r1"), c32(4)), c32(0xff))));
        // e7a70251  llvm-mc: `sbfx r0, r1, #4, #8` — bits 4-11 to 24-31, then >>s 24.
        assert_eq!(word_lift(0xe7a7_0251), lifted_to("r0", cast(false, 32, bin(BinOp::Sar, s32(bin(BinOp::Shl, v("r1"), c32(20))), c32(24)))));
    }

    /// `bfi` keeps `Rd` outside the field and takes the field from `Rn`;
    /// `bfc` clears it.
    #[test]
    fn the_bitfield_inserts_lift_to_masks() {
        // e7cb0411  llvm-mc: `bfi r0, r1, #8, #4`
        assert_eq!(
            word_lift(0xe7cb_0411),
            lifted_to("r0", bin(BinOp::Or, bin(BinOp::And, v("r0"), c32(0xffff_f0ff)), bin(BinOp::And, bin(BinOp::Shl, v("r1"), c32(8)), c32(0xf00)))),
        );
        // e7cb041f  llvm-mc: `bfc r0, #8, #4`
        assert_eq!(word_lift(0xe7cb_041f), lifted_to("r0", bin(BinOp::And, v("r0"), c32(0xffff_f0ff))));
    }

    /// `pkhbt`: `Rn`'s bottom half, the shifted `Rm`'s top. `pkhtb`: `Rn`'s top
    /// half, the arithmetically shifted `Rm`'s bottom — and `asr #32` (encoded
    /// as 0) is the sign fill, never a shift by the width.
    #[test]
    fn the_pack_halfword_forms_lift_to_masked_halves() {
        // e6810812  llvm-mc: `pkhbt r0, r1, r2, lsl #16`
        assert_eq!(
            word_lift(0xe681_0812),
            lifted_to("r0", bin(BinOp::Or, bin(BinOp::And, v("r1"), c32(0xffff)), bin(BinOp::And, bin(BinOp::Shl, v("r2"), c32(16)), c32(0xffff_0000)))),
        );
        // e6810852  llvm-mc: `pkhtb r0, r1, r2, asr #16`
        assert_eq!(
            word_lift(0xe681_0852),
            lifted_to("r0", bin(BinOp::Or, bin(BinOp::And, v("r1"), c32(0xffff_0000)), bin(BinOp::And, bin(BinOp::Sar, s32(v("r2")), c32(16)), c32(0xffff)))),
        );
        // e6810052  llvm-mc: `pkhtb r0, r1, r2, asr #32`
        assert_eq!(
            word_lift(0xe681_0052),
            lifted_to("r0", bin(BinOp::Or, bin(BinOp::And, v("r1"), c32(0xffff_0000)), bin(BinOp::And, bin(BinOp::Sar, s32(v("r2")), c32(31)), c32(0xffff)))),
        );
    }

    /// `smul<x><y>`: the product of the two sign-extended halves, at 32 bits.
    #[test]
    fn the_halfword_multiplies_lift_to_a_product_of_signed_halves() {
        let lo = |r: &str| cast(true, 16, v(r));
        let hi = |r: &str| cast(true, 16, bin(BinOp::Shr, v(r), c32(16)));
        // e1630582  llvm-mc: `smulbb r3, r2, r5`
        assert_eq!(word_lift(0xe163_0582), lifted_to("r3", cast(false, 32, bin(BinOp::Mul, lo("r2"), lo("r5")))));
        // e16305a2  llvm-mc: `smultb r3, r2, r5`
        assert_eq!(word_lift(0xe163_05a2), lifted_to("r3", cast(false, 32, bin(BinOp::Mul, hi("r2"), lo("r5")))));
        // e16305c2  llvm-mc: `smulbt r3, r2, r5`
        assert_eq!(word_lift(0xe163_05c2), lifted_to("r3", cast(false, 32, bin(BinOp::Mul, lo("r2"), hi("r5")))));
    }

    /// `rev`/`rev16`/`revsh` are byte moves, which masks and shifts state
    /// exactly; `revsh` sign-extends the swapped low halfword.
    #[test]
    fn the_byte_reversals_lift_to_shifts_and_masks() {
        let masked = |mask: i128, op: BinOp, k: i128| bin(op, bin(BinOp::And, v("r1"), c32(mask)), c32(k));
        // e6bf0f31  llvm-mc: `rev r0, r1`
        assert_eq!(
            word_lift(0xe6bf_0f31),
            lifted_to(
                "r0",
                bin(
                    BinOp::Or,
                    bin(BinOp::Or, masked(0xff, BinOp::Shl, 24), masked(0xff00, BinOp::Shl, 8)),
                    bin(BinOp::Or, masked(0x00ff_0000, BinOp::Shr, 8), masked(0xff00_0000, BinOp::Shr, 24)),
                ),
            ),
        );
        // e6bf1fb1  llvm-mc: `rev16 r1, r1`
        assert_eq!(
            word_lift(0xe6bf_1fb1),
            lifted_to("r1", bin(BinOp::Or, masked(0x00ff_00ff, BinOp::Shl, 8), bin(BinOp::And, bin(BinOp::Shr, v("r1"), c32(8)), c32(0x00ff_00ff)))),
        );
        // e6ff0fb1  llvm-mc: `revsh r0, r1`
        assert_eq!(
            word_lift(0xe6ff_0fb1),
            lifted_to(
                "r0",
                cast(false, 32, cast(true, 16, bin(BinOp::Or, masked(0xff, BinOp::Shl, 8), bin(BinOp::And, bin(BinOp::Shr, v("r1"), c32(8)), c32(0xff))))),
            ),
        );
    }

    /// The text is llvm-mc's, condition suffix included — and where llvm-mc
    /// prints a field the encoding does not hold, the encoding's fields.
    #[test]
    fn the_owned_spaces_decode_to_the_reference_text() {
        for (word, text) in [
            (0x06ef_8073u32, "uxtbeq r8, r3"),
            (0xe6ff_1c72, "uxth r1, r2, ror #24"),
            (0xe681_0052, "pkhtb r0, r1, r2, asr #32"),
            (0xe6a1_1013, "ssat r1, #2, r3"),
            (0xe741_0213, "smlald r0, r1, r3, r2"),
            // The crate read this `smlawteq r0, r0, r0, r0`.
            (0x0120_00a0, "smulwbeq r0, r0, r0"),
            // The crate refused this (RdLo = RdHi; UNPREDICTABLE, executed).
            (0xe140_0281, "smlalbb r0, r0, r1, r2"),
            (0xe7f0_00f0, "udf #0"),
            // llvm-mc: `bfi r0, r0, #16, #1`, a field substituted for the
            // encoding's lsb 17 > msb 16; GNU objdump spells it like this.
            (0xe7d0_0890, "bfi r0, r0, (invalid: 17:16)"),
            // llvm-mc: `trap`, its own alias for this word.
            (0xe7ff_defe, "udf #65006"),
        ] {
            assert_eq!(word_text(word).as_deref(), Some(text), "{word:#010x}");
        }
        let udf = Arm32::a32().decode(&0xe7f0_00f0u32.to_le_bytes(), Va(0x1000)).map(|d| d.kind);
        assert!(matches!(udf, Ok(InsnKind::Int)), "a permanently undefined instruction traps: {udf:?}");
    }

    /// Words llvm-mc rejects (and the ARM ARM leaves UNDEFINED, or the reference
    /// refuses outright) are decode errors, not invented instructions.
    #[test]
    fn words_the_reference_rejects_stay_decode_errors() {
        let a = Arm32::a32();
        for (word, why) in [
            (0xe600_0010u32, "parallel add/sub with op1 = 00000"),
            (0xe680_0030, "packing op1 = 000, op2 = 001"),
            (0xe6b0_1031, "rev with its should-be-one Rn field clear"),
            (0xe711_0113, "sdiv with bits 15-12 not 1111"),
            (0xe6a0_0030, "ssat16 with bits 11-8 not 1111"),
            (0x07f0_00f0, "udf under a condition"),
            (0xf6ef_8073, "the media pattern in the unconditional space"),
        ] {
            assert!(a.decode(&word.to_le_bytes(), Va(0x1000)).is_err(), "{word:#010x} ({why}) is not an instruction");
        }
    }

    /// A predicated extend writes only when its condition holds, like any other
    /// predicated write — and carries its condition for the CFG.
    #[test]
    fn a_predicated_extend_is_a_conditional_write() {
        let a = Arm32::a32();
        // 06ef8073  llvm-mc: `uxtbeq r8, r3`
        let di = a.decode(&0x06ef_8073u32.to_le_bytes(), Va(0x1000));
        assert_eq!(di.as_ref().ok().and_then(|d| d.cond.as_deref()), Some("eq"), "{di:?}");
        let stmts = di.map(|d| a.lift(&d, "aapcs32")).unwrap_or_default();
        let select = match stmts.as_slice() {
            [MicroStmt::Assign { dst, value: MicroExpr::Select { a: then, b: els, .. } }] if dst == "r8" => Some(((**then).clone(), (**els).clone())),
            _ => None,
        };
        assert_eq!(select, Some((cast(false, 8, v("r3")), v("r8"))), "a conditional write of the extension, else the old r8: {stmts:?}");
    }

    /// A word llvm-mc decodes with a "potentially undefined" warning is shown,
    /// so the sweep goes on — and never lifted, because UNPREDICTABLE has no
    /// value to state. Its destination is invalidated like any `asm`.
    #[test]
    fn an_unpredictable_word_is_shown_but_not_lifted() {
        for (word, dst) in [
            (0xe6ef_f073u32, "pc"), // llvm-mc: `uxtb pc, r3`
            (0xe6ef_8373, "r8"),    // llvm-mc: `uxtb r8, r3` with bits 9-8 = 11
            (0xe7ff_0e51, "r0"),    // llvm-mc: `ubfx r0, r1, #28, #32` — past bit 31
            (0xe7d0_0890, "r0"),    // `bfi` with msb below lsb
        ] {
            let stmts = word_lift(word).unwrap_or_default();
            assert!(matches!(stmts.first(), Some(MicroStmt::Unlifted { .. })), "{word:#010x} decodes and stays asm: {stmts:?}");
            assert_eq!(invalidated(&stmts), vec![dst], "{word:#010x} invalidates its destination");
        }
    }

    /// The `RdLo, RdHi` multiplies write two registers, and the `asm` fallback
    /// must invalidate both — the crate-decoded `umaal` lost its `RdHi` before.
    #[test]
    fn the_two_destination_multiplies_invalidate_both_registers() {
        let a = Arm32::a32();
        for (word, writes) in [
            (0xe741_0213u32, ["r0", "r1"]), // llvm-mc: `smlald r0, r1, r3, r2`
            (0xe141_0382, ["r0", "r1"]),    // llvm-mc: `smlalbb r0, r1, r2, r3`
            (0xe042_1393, ["r1", "r2"]),    // llvm-mc: `umaal r1, r2, r3, r3` (the crate's)
        ] {
            let stmts = word_lift(word).unwrap_or_default();
            assert_eq!(invalidated(&stmts), writes, "{word:#010x}: {stmts:?}");
            let access = a.decode(&word.to_le_bytes(), Va(0x1000)).map(|d| a.reg_access(&d).writes);
            assert_eq!(access.ok(), Some(writes.map(String::from).to_vec()), "{word:#010x}: reg_access agrees with the lift");
        }
        // Thumb's are the crate's: c5fb9b32 `smlalbt r3, r2, r5, r11`,
        // c3fbc201 `smlald r0, r1, r3, r2`, d3fbc201 `smlsld r0, r1, r3, r2`
        // (llvm-mc, thumbv7) — `RdLo, RdHi` first in each.
        let t = Arm32::thumb();
        for (bytes, writes) in [([0xc5, 0xfb, 0x9b, 0x32], ["r3", "r2"]), ([0xc3, 0xfb, 0xc2, 0x01], ["r0", "r1"]), ([0xd3, 0xfb, 0xc2, 0x01], ["r0", "r1"])] {
            let access = t.decode(&bytes, Va(0x1000)).map(|d| t.reg_access(&d).writes);
            assert_eq!(access.ok(), Some(writes.map(String::from).to_vec()), "{bytes:02x?}");
        }
    }

    /// `GE` and `Q` are APSR bits, and the APSR is the one `flags` value: an
    /// instruction that writes them ends whatever compare came before. The
    /// saturating parallel forms write neither, and neither does a lifted form.
    #[test]
    fn the_q_and_ge_writers_end_the_flags_value() {
        for (word, what) in [
            (0xe651_0f92u32, "uadd8 r0, r1, r2 (GE)"),
            (0xe6a1_1013, "ssat r1, #2, r3 (Q)"),
            (0xe102_0051, "qadd r0, r1, r2 (Q; the crate's)"),
            (0xe100_1382, "smlabb r0, r2, r3, r1 (Q)"),
        ] {
            let stmts = word_lift(word).unwrap_or_default();
            assert!(matches!(flags_of(&stmts), Some(MicroExpr::OpaqueFlags { .. })), "{what} writes the flags: {stmts:?}");
        }
        for (word, what) in [(0xe621_0f92u32, "qadd8 r0, r1, r2"), (0xe163_0582, "smulbb r3, r2, r5")] {
            let stmts = word_lift(word).unwrap_or_default();
            assert!(!stmts.is_empty() && flags_of(&stmts).is_none(), "{what} leaves the flags alone: {stmts:?}");
        }
    }

    /// A linear walk goes through a media instruction instead of stopping at it.
    #[test]
    fn a_stream_walks_through_an_extend() {
        // e6ef8073 `uxtb r8, r3`; e12fff1e `bx lr`.
        let stream = Arm32::a32().decode_stream(&[0x73, 0x80, 0xef, 0xe6, 0x1e, 0xff, 0x2f, 0xe1], Va(0x1000), 4);
        assert_eq!(stream.iter().map(|d| d.mnemonic.as_str()).collect::<Vec<_>>(), vec!["uxtb", "bx"]);
    }

    /// The `Unlifted` statement of a lift: whether its reads are exact, the
    /// reads sorted, and its memory effect.
    fn unlifted_of(stmts: &[MicroStmt]) -> (bool, Vec<String>, MemEffect) {
        let Some(MicroStmt::Unlifted { reads, mem, .. }) = stmts.iter().find(|s| matches!(s, MicroStmt::Unlifted { .. })) else {
            panic!("no unlifted statement in {stmts:?}");
        };
        let mut regs = reads.regs().to_vec();
        regs.sort();
        (reads.exact().is_some(), regs, *mem)
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// An instruction kept as `asm` states what it reads and does to memory —
    /// for both decoders. Without the reads, `mov r8, r3; strb r8, [r1]` lost
    /// `r8 = r3` as dead; without the memory effect, a `strb` between a store
    /// and a load was invisible to forwarding. Every word is llvm-mc's
    /// (`-triple=armv7`).
    #[test]
    fn an_unlifted_instruction_states_its_reads_and_its_memory_effect() {
        // 15c18000  strbne r8, [r1] — the stored register and the base. (A
        // predicated store stays `asm`; the unconditional `strb` is lifted.)
        assert_eq!(unlifted_of(&lift1(&[0x00, 0x80, 0xc1, 0x15])), (true, names(&["r1", "r8"]), MemEffect::Write));
        // e1a00162  ror r0, r2, #2 — registers only, and the destination is
        // not read…
        assert_eq!(unlifted_of(&lift1(&[0x62, 0x01, 0xa0, 0xe1])), (true, names(&["r2"]), MemEffect::NoAccess));
        // 11a00162  rorne r0, r2, #2 — …unless the instruction is predicated:
        // a failed condition leaves the old `r0` as the result.
        assert_eq!(unlifted_of(&lift1(&[0x62, 0x01, 0xa0, 0x11])), (true, names(&["r0", "r2"]), MemEffect::NoAccess));
        // e4b10004  ldrt r0, [r1], #4 — reads the base, not its destination.
        // (The unprivileged form stays `asm`; `ldr r0, [r1], #4` is lifted.)
        assert_eq!(unlifted_of(&lift1(&[0x04, 0x00, 0xb1, 0xe4])), (true, names(&["r1"]), MemEffect::Read));
        // e68f0071  sxtb16 r0, r1 (this file's own decoder) — the source alone…
        assert_eq!(unlifted_of(&lift1(&[0x71, 0x00, 0x8f, 0xe6])), (true, names(&["r1"]), MemEffect::NoAccess));
        // 168f0071  sxtb16ne r0, r1 — …and predicated, the destination too.
        assert_eq!(unlifted_of(&lift1(&[0x71, 0x00, 0x8f, 0x16])), (true, names(&["r0", "r1"]), MemEffect::NoAccess));
        // e7410312  smlald r0, r1, r2, r3 — the accumulator pair is read.
        assert_eq!(unlifted_of(&lift1(&[0x12, 0x03, 0x41, 0xe7])), (true, names(&["r0", "r1", "r2", "r3"]), MemEffect::NoAccess));
    }

    /// A post-indexed access always writes back its base; the decoder's flag
    /// for it says `false`, and the fallback believed it: `ldr r0, [r1], #4;
    /// mov r0, r1` returned the old `r1`. Checked on a post-indexed form that
    /// stays `asm` — `ldr r0, [r1], #4` itself is lifted, write-back and all.
    #[test]
    fn a_post_indexed_access_invalidates_its_base() {
        // e4b10004  ldrt r0, [r1], #4 (llvm-mc)
        assert_eq!(invalidated(&lift1(&[0x04, 0x00, 0xb1, 0xe4])), vec!["r0", "r1"]);
    }

    /// A conditional call stays `asm`. When it is taken it clobbers what any
    /// call does, and it consumes the argument registers — which are the
    /// convention's reads, not the encoding's, so they are a bound: they keep
    /// the definitions alive without claiming the function takes four
    /// parameters.
    #[test]
    fn a_conditional_call_kept_as_asm_reads_and_clobbers_what_a_call_does() {
        // 1b000000  blne
        let stmts = lift1(&[0x00, 0x00, 0x00, 0x1b]);
        let (exact, regs, mem) = unlifted_of(&stmts);
        assert!(!exact, "a call's argument reads are a bound: {regs:?}");
        assert_eq!(regs, names(&["r0", "r1", "r2", "r3", "sp"]));
        assert_eq!(mem, MemEffect::Unknown);
        assert_eq!(invalidated(&stmts), vec!["lr", "r0", "r1", "r2", "r3", "r12"]);
    }

    // ---- single loads and stores, block transfers, reads of `pc` --------------
    //
    // Every encoding below is llvm-mc's (`-triple=armv6-none-eabi`, Thumb:
    // `thumbv7-none-eabi`), quoted per case; the meanings are the ARM ARM's,
    // and the lifted forms were run against an emulated processor
    // (`n0xis-core/tests/a32_memory_agrees_with_the_processor.rs`). Before
    // these, every form here but the pre-indexed word `ldr`/`str` and
    // `push`/`pop` was `asm`.

    /// The lift of one A32 word at `va`.
    fn lift_at(word: u32, va: u64) -> Vec<MicroStmt> {
        let a = Arm32::a32();
        a.decode(&word.to_le_bytes(), Va(va)).map(|di| a.lift(&di, "aapcs32")).unwrap_or_default()
    }

    /// The lift of one Thumb instruction at `va`.
    fn thumb_at(bytes: &[u8], va: u64) -> Vec<MicroStmt> {
        let t = Arm32::thumb();
        t.decode(bytes, Va(va)).map(|di| t.lift(&di, "aapcs32")).unwrap_or_default()
    }

    fn set(dst: &str, value: MicroExpr) -> MicroStmt {
        MicroStmt::Assign { dst: dst.into(), value }
    }

    /// A load as an A32 register holds it: zero-extended, or sign-extended and
    /// cast back to 32 bits.
    fn ld(bits: u32, signed: bool, addr: MicroExpr) -> MicroExpr {
        let l = MicroExpr::load(addr, bits, signed);
        if signed { cast(false, 32, l) } else { l }
    }

    fn st(addr: MicroExpr, r: &str, bits: u32) -> MicroStmt {
        MicroStmt::Store { addr, value: v(r), bits }
    }

    fn plus(r: &str, k: i128) -> MicroExpr {
        bin(BinOp::Add, v(r), c32(k))
    }

    fn minus(r: &str, k: i128) -> MicroExpr {
        bin(BinOp::Sub, v(r), c32(k))
    }

    /// Each width, each extension, each addressing mode: immediate and
    /// (shifted-)register index, added and subtracted, pre-indexed with and
    /// without write-back, post-indexed.
    #[test]
    fn every_single_load_and_store_form_lifts_to_the_access_it_makes() {
        let w32 = |a| ld(32, false, a);
        for (word, text, expected) in [
            (0xe5d1_0003u32, "ldrb r0, [r1, #3]", vec![set("r0", ld(8, false, plus("r1", 3)))]),
            (0xe571_0003, "ldrb r0, [r1, #-3]!", vec![set("r0", ld(8, false, minus("r1", 3))), set("r1", minus("r1", 3))]),
            (0xe4d1_0003, "ldrb r0, [r1], #3", vec![set("r0", ld(8, false, v("r1"))), set("r1", plus("r1", 3))]),
            (0xe7d1_0002, "ldrb r0, [r1, r2]", vec![set("r0", ld(8, false, bin(BinOp::Add, v("r1"), v("r2"))))]),
            (
                0xe771_0102,
                "ldrb r0, [r1, -r2, lsl #2]!",
                vec![
                    set("r0", ld(8, false, bin(BinOp::Sub, v("r1"), bin(BinOp::Shl, v("r2"), c32(2))))),
                    set("r1", bin(BinOp::Sub, v("r1"), bin(BinOp::Shl, v("r2"), c32(2)))),
                ],
            ),
            (
                0xe6d1_00c2,
                "ldrb r0, [r1], r2, asr #1",
                vec![set("r0", ld(8, false, v("r1"))), set("r1", bin(BinOp::Add, v("r1"), bin(BinOp::Sar, s32(v("r2")), c32(1))))],
            ),
            (0xe441_0001, "strb r0, [r1], #-1", vec![st(v("r1"), "r0", 8), set("r1", minus("r1", 1))]),
            (0xe171_00b6, "ldrh r0, [r1, #-6]!", vec![set("r0", ld(16, false, minus("r1", 6))), set("r1", minus("r1", 6))]),
            (0xe011_00b2, "ldrh r0, [r1], -r2", vec![set("r0", ld(16, false, v("r1"))), set("r1", bin(BinOp::Sub, v("r1"), v("r2")))]),
            (
                0xe1a1_00b2,
                "strh r0, [r1, r2]!",
                vec![st(bin(BinOp::Add, v("r1"), v("r2")), "r0", 16), set("r1", bin(BinOp::Add, v("r1"), v("r2")))],
            ),
            (0xe1d1_00d1, "ldrsb r0, [r1, #1]", vec![set("r0", ld(8, true, plus("r1", 1)))]),
            (0xe0d1_00f2, "ldrsh r0, [r1], #2", vec![set("r0", ld(16, true, v("r1"))), set("r1", plus("r1", 2))]),
            (0xe1c1_20d8, "ldrd r2, r3, [r1, #8]", vec![set("r2", w32(plus("r1", 8))), set("r3", w32(plus("r1", 12)))]),
            (0xe0c1_20d8, "ldrd r2, r3, [r1], #8", vec![set("r2", w32(v("r1"))), set("r3", w32(plus("r1", 4))), set("r1", plus("r1", 8))]),
            (0xe161_20f8, "strd r2, r3, [r1, #-8]!", vec![st(minus("r1", 8), "r2", 32), st(minus("r1", 4), "r3", 32), set("r1", minus("r1", 8))]),
            // The base is loaded last, so the second word's address is still
            // computed from the base the instruction started with.
            (0xe1c4_40d0, "ldrd r4, r5, [r4]", vec![set("r5", w32(plus("r4", 4))), set("r4", w32(v("r4")))]),
            (
                0xe611_0182,
                "ldr r0, [r1], -r2, lsl #3",
                vec![set("r0", w32(v("r1"))), set("r1", bin(BinOp::Sub, v("r1"), bin(BinOp::Shl, v("r2"), c32(3))))],
            ),
            // `pop {r4}`: the single-register pop is a post-indexed `ldr`.
            (0xe49d_4004, "ldr r4, [sp], #4", vec![set("r4", w32(v("sp"))), set("sp", plus("sp", 4))]),
            // A predicated load without write-back is a conditional write.
            (
                0x1151_00d1,
                "ldrsbne r0, [r1, #-1]",
                vec![set("r0", MicroExpr::select(MicroExpr::OpaqueFlags { mnemonic: "setcc:bne".into() }, ld(8, true, minus("r1", 1)), v("r0")))],
            ),
        ] {
            assert_eq!(lift_at(word, 0x1000), expected, "{word:#010x} {text}");
        }
    }

    /// What is not one plain transfer stays `asm`: a load into `pc` (a branch)
    /// and a store of it (an IMPLEMENTATION DEFINED value); the UNPREDICTABLE
    /// register choices; a written-back load whose index it overwrites; a
    /// predicated store or write-back; the unprivileged forms.
    #[test]
    fn a_transfer_that_is_not_one_plain_access_stays_asm() {
        for (word, text) in [
            (0xe5b0_0004u32, "ldr r0, [r0, #4]! (write-back into the loaded register)"),
            (0xe590_f000, "ldr pc, [r0] (a branch)"),
            (0x979f_f100, "ldrls pc, [pc, r0, lsl #2] (a switch dispatch)"),
            (0xe580_f000, "str pc, [r0] (PCStoreValue)"),
            (0xe691_0000, "ldr r0, [r1], r0 (the write-back reads the loaded index)"),
            (0xe791_000f, "ldr r0, [r1, pc] (index pc)"),
            (0x1581_0000, "strne r0, [r1]"),
            (0x1491_0004, "ldrne r0, [r1], #4"),
            (0xe1c0_10d0, "ldrd r1, r2, [r0] (odd first register)"),
            (0xe182_00d0, "ldrd r0, r1, [r2, r0] (index is a loaded register)"),
            (0xe4b1_0004, "ldrt r0, [r1], #4 (unprivileged)"),
        ] {
            let stmts = lift_at(word, 0x1000);
            assert!(matches!(stmts.first(), Some(MicroStmt::Unlifted { .. })), "{word:#010x} {text}: {stmts:?}");
        }
    }

    /// `pop {pc}` spelled as the single-register `ldr pc, [sp], #4` is the
    /// return the CFG classifies it as, exactly as `pop {r4, pc}` is.
    #[test]
    fn a_single_register_pop_of_pc_is_the_return() {
        // e49df004  llvm-mc: `pop {pc}`
        let a = Arm32::a32();
        let di = a.decode(&0xe49d_f004u32.to_le_bytes(), Va(0x1000)).expect("decodes");
        assert_eq!(di.kind, InsnKind::Ret, "{}", di.text);
        assert_eq!(a.lift(&di, "aapcs32"), vec![set("sp", plus("sp", 4)), MicroStmt::Return(Some(v("r0")))]);
    }

    /// A read of `pc` is the constant the processor reads: `va + 8` in A32;
    /// `va + 4` in Thumb, rounded down to a word for a literal load and `adr`.
    /// A literal-pool load is a load from a known address.
    #[test]
    fn a_read_of_pc_is_the_address_the_processor_reads() {
        // e59f018c  ldr r0, [pc, #396] at 0x2000 — the word at 0x2194.
        assert_eq!(lift_at(0xe59f_018c, 0x2000), vec![set("r0", ld(32, false, c32(0x2194)))]);
        // e51f0008  ldr r0, [pc, #-8] at 0x1000 — its own address.
        assert_eq!(lift_at(0xe51f_0008, 0x1000), vec![set("r0", ld(32, false, c32(0x1000)))]);
        // e79fc00c  ldr r12, [pc, r12] at 0x3000.
        assert_eq!(lift_at(0xe79f_c00c, 0x3000), vec![set("r12", ld(32, false, bin(BinOp::Add, c32(0x3008), v("r12"))))]);
        // e08fc00c  add r12, pc, r12 at 0x3100.
        assert_eq!(lift_at(0xe08f_c00c, 0x3100), vec![set("r12", bin(BinOp::Add, c32(0x3108), v("r12")))]);
        // e1df00b4  ldrh r0, [pc, #4]; e1cf00d8  ldrd r0, r1, [pc, #8]
        assert_eq!(lift_at(0xe1df_00b4, 0x1000), vec![set("r0", ld(16, false, c32(0x100c)))]);
        assert_eq!(lift_at(0xe1cf_00d8, 0x1000), vec![set("r0", ld(32, false, c32(0x1010))), set("r1", ld(32, false, c32(0x1014)))]);
        // e28f0010  adr r0, #16; e24f0010  sub r0, pc, #16 — the two `adr`
        // encodings, which the decoder hands over with the same operands.
        assert_eq!(lift_at(0xe28f_0010, 0x1000), vec![set("r0", c32(0x1018))]);
        assert_eq!(lift_at(0xe24f_0010, 0x1000), vec![set("r0", c32(0x0ff8))]);
        // e1a0000f  mov r0, pc
        assert_eq!(lift_at(0xe1a0_000f, 0x1000), vec![set("r0", c32(0x1008))]);
        // Thumb at 0x1002, where `va + 4` is not a word: 4802 `ldr r0, [pc,
        // #8]` and a002 `adr r0, #8` read Align(0x1006, 4) + 8 …
        assert_eq!(thumb_at(&[0x02, 0x48], 0x1002), vec![set("r0", ld(32, false, c32(0x100c)))]);
        assert_eq!(thumb_at(&[0x02, 0xa0], 0x1002), vec![set("r0", c32(0x100c))]);
        // … f85f 0008 `ldr.w r0, [pc, #-8]` and f2af 0008 `subw r0, pc, #8`
        // (`adr.w`) read the same aligned base …
        assert_eq!(thumb_at(&[0x5f, 0xf8, 0x08, 0x00], 0x1002), vec![set("r0", ld(32, false, c32(0x0ffc)))]);
        assert_eq!(thumb_at(&[0xaf, 0xf2, 0x08, 0x00], 0x1002), vec![set("r0", bin(BinOp::Sub, c32(0x1004), c32(8)))]);
        // … while 4678 `mov r0, pc` reads `va + 4` itself.
        assert_eq!(thumb_at(&[0x78, 0x46], 0x1002), vec![set("r0", c32(0x1006))]);
        // 4478 `add r0, pc` is a form this lift does not model: `asm`.
        assert!(matches!(thumb_at(&[0x78, 0x44], 0x1002).first(), Some(MicroStmt::Unlifted { .. })));
    }

    /// `ldm`/`stm` in all four modes, with and without write-back, the lowest
    /// register at the lowest address — and the mode comes from the encoding:
    /// the decoder builds Thumb's 16-bit `stmia` as increment-before.
    #[test]
    fn ldm_and_stm_lift_in_all_four_modes() {
        let w = |a| ld(32, false, a);
        for (word, text, expected) in [
            (0xe890_0006u32, "ldm r0, {r1, r2}", vec![set("r1", w(v("r0"))), set("r2", w(plus("r0", 4)))]),
            (0xe8b0_0006, "ldm r0!, {r1, r2}", vec![set("r1", w(v("r0"))), set("r2", w(plus("r0", 4))), set("r0", plus("r0", 8))]),
            (0xe990_0006, "ldmib r0, {r1, r2}", vec![set("r1", w(plus("r0", 4))), set("r2", w(plus("r0", 8)))]),
            (0xe830_0006, "ldmda r0!, {r1, r2}", vec![set("r1", w(minus("r0", 4))), set("r2", w(v("r0"))), set("r0", minus("r0", 8))]),
            (0xe910_0006, "ldmdb r0, {r1, r2}", vec![set("r1", w(minus("r0", 8))), set("r2", w(minus("r0", 4)))]),
            (0xe880_0006, "stm r0, {r1, r2}", vec![st(v("r0"), "r1", 32), st(plus("r0", 4), "r2", 32)]),
            (0xe9a0_0006, "stmib r0!, {r1, r2}", vec![st(plus("r0", 4), "r1", 32), st(plus("r0", 8), "r2", 32), set("r0", plus("r0", 8))]),
            (0xe800_0006, "stmda r0, {r1, r2}", vec![st(minus("r0", 4), "r1", 32), st(v("r0"), "r2", 32)]),
            (0xe920_0006, "stmdb r0!, {r1, r2}", vec![st(minus("r0", 8), "r1", 32), st(minus("r0", 4), "r2", 32), set("r0", minus("r0", 8))]),
            // The base in the list, no write-back: loaded last.
            (0xe890_0003, "ldm r0, {r0, r1}", vec![set("r1", w(plus("r0", 4))), set("r0", w(v("r0")))]),
            // `pc` in the list is the return.
            (
                0xe931_8030,
                "ldmdb r1!, {r4, r5, pc}",
                vec![set("r4", w(minus("r1", 12))), set("r5", w(minus("r1", 8))), set("r1", minus("r1", 12)), MicroStmt::Return(Some(v("r0")))],
            ),
        ] {
            assert_eq!(lift_at(word, 0x1000), expected, "{word:#010x} {text}");
        }
        for (bytes, text, expected) in [
            (&[0x06, 0xc8][..], "ldm r0!, {r1, r2}", vec![set("r1", w(v("r0"))), set("r2", w(plus("r0", 4))), set("r0", plus("r0", 8))]),
            (&[0x03, 0xc8][..], "ldm r0, {r0, r1}", vec![set("r1", w(plus("r0", 4))), set("r0", w(v("r0")))]),
            (&[0x06, 0xc0][..], "stm r0!, {r1, r2}", vec![st(v("r0"), "r1", 32), st(plus("r0", 4), "r2", 32), set("r0", plus("r0", 8))]),
            (
                &[0x30, 0xe9, 0x06, 0x00][..],
                "ldmdb r0!, {r1, r2}",
                vec![set("r1", w(minus("r0", 8))), set("r2", w(minus("r0", 4))), set("r0", minus("r0", 8))],
            ),
            (&[0x00, 0xe9, 0x06, 0x00][..], "stmdb r0, {r1, r2}", vec![st(minus("r0", 8), "r1", 32), st(minus("r0", 4), "r2", 32)]),
            (&[0x90, 0xe8, 0x02, 0x80][..], "ldm.w r0, {r1, pc}", vec![set("r1", w(v("r0"))), MicroStmt::Return(Some(v("r0")))]),
        ] {
            assert_eq!(thumb_at(bytes, 0x1000), expected, "{bytes:02x?} {text}");
        }
        // UNKNOWN or not a plain transfer: the base written back and in the
        // list, the user-bank `^`, `pc` stored, `sp` in the list, and a
        // predicated one.
        for (word, text) in [
            (0xe8b0_0003u32, "ldm r0!, {r0, r1}"),
            (0xe8d0_0006, "ldm r0, {r1, r2} ^"),
            (0xe880_8002, "stm r0, {r1, pc}"),
            (0xe890_2002, "ldm r0, {r1, sp}"),
            (0x1994_000a, "ldmibne r4, {r1, r3}"),
        ] {
            let stmts = lift_at(word, 0x1000);
            assert!(matches!(stmts.first(), Some(MicroStmt::Unlifted { .. })), "{word:#010x} {text} stays asm: {stmts:?}");
        }
    }

    /// The text names the instruction the word holds (llvm-mc's spelling of
    /// the mnemonic): the decoder printed `ldmib` as `ldmia`, dropped the
    /// `^`, and printed `sub rd, pc, #imm` as `adr`.
    #[test]
    fn a_block_transfer_and_an_adr_print_what_the_word_holds() {
        for (word, text) in [
            (0xe990_0006u32, "ldmib r0, {r1, r2}"),
            (0xe9a0_0006, "stmib r0!, {r1, r2}"),
            (0x1994_000a, "ldmibne r4, {r1, r3}"),
            (0xe8d0_0006, "ldm r0, {r1, r2} ^"),
            (0xe24f_0010, "sub r0, pc, 0x10"),
            // Unchanged where they were right.
            (0xe890_0006, "ldm r0, {r1, r2}"),
            (0xe830_0006, "ldmda r0!, {r1, r2}"),
            (0xe28f_0010, "adr r0, pc, 0x10"),
            (0xe92d_4010, "push {r4, lr}"),
        ] {
            assert_eq!(word_text(word).as_deref(), Some(text), "{word:#010x}");
        }
    }

    #[test]
    fn arm32_is_32bit_with_the_aapcs32_abi() {
        let a = Arm32::a32();
        assert_eq!(a.pointer_size(), 4);
        assert_eq!(a.calling_conventions()[0].name, "aapcs32");
        assert!(a.regs().by_name("lr").is_some());
    }
}
