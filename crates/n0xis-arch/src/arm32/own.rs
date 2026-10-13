// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The A32 encoding spaces this crate decodes **itself**, because `yaxpeax-arm`
//! 0.5.0 cannot:
//!
//! * the **media** class (ARM ARM A5.4: `cond 011x xxxx xxxx xxxx xxxx xxx1
//!   xxxx`) — the crate returns an error for every word of it, so `uxtb`,
//!   `sxth`, `uxtah`, `rev16`, `ubfx`, `pkhbt`, the parallel add/sub family and
//!   the dual multiplies all read `(bad)`, and each one stopped a linear sweep
//!   and cut a function's CFG;
//! * the **halfword multiplies** (A5.2.7: `cond 0001 0xx0 xxxx xxxx xxxx 1xx0
//!   xxxx`) — the crate decodes them, but reads `smulw<y>` as `smlaw<y>` with
//!   the wrong half (`0x012000a0`, `smulwbeq r0, r0, r0`, came out as
//!   `smlawteq r0, r0, r0, r0`) and refuses every `smlal<x><y>` whose two
//!   destination registers are the same.
//!
//! [`Arm32::decode_inst`](super::Arm32) routes a word in either space here and
//! never to the crate: one owner per encoding space, so no word's answer
//! depends on which decoder happened to fail first.
//!
//! **What is accepted is what `llvm-mc` accepts** (`-triple=armv7ve`), checked
//! word by word by `tests/a32_media_agrees_with_llvm_mc.rs` over every word of
//! both spaces at `AL` and a stratified sample under every other condition.
//! That includes the words it decodes with a "potentially undefined" warning
//! (an UNPREDICTABLE register choice, or a should-be field the other way),
//! because the processor executes them and a `(bad)` would end the sweep; and
//! it excludes the three should-be-field violations it refuses outright
//! (`rev`/`rev16`/`revsh`/`rbit`, `sdiv`/`udiv`, `ssat16`/`usat16`), each of
//! which GNU objdump refuses too where it was asked (one word per family). The
//! text is UAL, the assembler syntax that tool prints, and is compared with it
//! literally, with two recorded exceptions where it prints something the
//! encoding does not say (see [`Op::Bfi`] and [`Op::Udf`]).
//!
//! An accepted UNPREDICTABLE word is decoded and shown, never lifted:
//! [`Own::unpredictable`] is the one place that says which words those are.

use yaxpeax_arm::armv7::{ConditionCode, Opcode, ShiftStyle};

use super::{imm_shift, reg_n, shift};
use crate::insn::InsnKind;
use crate::microir::{BinOp, MicroExpr};

/// A general-purpose register field (4 bits, so 0..=15 by construction).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct R(u8);

impl R {
    fn at(word: u32, lsb: u32) -> R {
        R(((word >> lsb) & 0xf) as u8)
    }
    fn name(self) -> String {
        reg_n(self.0)
    }
    fn var(self) -> MicroExpr {
        MicroExpr::var(self.name())
    }
    fn is_pc(self) -> bool {
        self.0 == 15
    }
}

/// A register field that names `r15` to mean "no register" — the
/// non-accumulating forms (`sxtb` is `sxtab` with `Rn = 1111`, `smuad` is
/// `smlad` with `Ra = 1111`, `bfc` is `bfi` with `Rn = 1111`).
fn unless_pc(r: R) -> Option<R> {
    (!r.is_pc()).then_some(r)
}

/// The parallel add/sub prefix (A5.4.1, A5.4.2): `op1` bits 21-20 and the
/// signed/unsigned half of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ParPrefix {
    S,
    Q,
    Sh,
    U,
    Uq,
    Uh,
}

/// The parallel add/sub operation, `op2`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ParKind {
    Add16,
    Asx,
    Sax,
    Sub16,
    Add8,
    Sub8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExtSize {
    Byte,
    Half,
    /// `xtb16`: two bytes extended into two halfwords.
    Byte16,
}

/// The optional shift of `ssat`/`usat`. `Asr(32)` is the encoding `sh = 1,
/// imm5 = 0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SatShift {
    None,
    Lsl(u8),
    Asr(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RevKind {
    Rev,
    Rev16,
    Revsh,
    Rbit,
}

/// One instruction from a space this file owns. Each variant holds exactly the
/// fields its encoding has; an absent register is `None`, never `r15`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Op {
    /// `<prefix><kind> Rd, Rn, Rm`.
    Parallel { prefix: ParPrefix, kind: ParKind, d: R, n: R, m: R },
    /// `{s,u}xt[a]{b,h,b16} Rd, [Rn,] Rm[, ror #rot]`, `rot` in {0, 8, 16, 24}.
    Extend { signed: bool, size: ExtSize, d: R, n: Option<R>, m: R, rot: u8 },
    /// `pkhbt Rd, Rn, Rm[, lsl #sh]` (`sh` 0..=31) or `pkhtb Rd, Rn, Rm, asr
    /// #sh` (`sh` 1..=32).
    Pkh { top: bool, d: R, n: R, m: R, sh: u8 },
    /// `ssat Rd, #sat, Rn[, shift]` (`sat` 1..=32) / `usat` (`sat` 0..=31).
    Sat { unsigned: bool, d: R, sat: u8, n: R, shift: SatShift },
    /// `ssat16 Rd, #sat, Rn` (`sat` 1..=16) / `usat16` (0..=15).
    Sat16 { unsigned: bool, d: R, sat: u8, n: R },
    /// `sel Rd, Rn, Rm`.
    Sel { d: R, n: R, m: R },
    /// `rev`/`rev16`/`revsh`/`rbit Rd, Rm`.
    Reverse { kind: RevKind, d: R, m: R },
    /// `smlad[x] Rd, Rn, Rm, Ra` / `smlsd[x]`; `a: None` is `smuad[x]` /
    /// `smusd[x] Rd, Rn, Rm`.
    Dual { sub: bool, x: bool, d: R, n: R, m: R, a: Option<R> },
    /// `smlald[x] RdLo, RdHi, Rn, Rm` / `smlsld[x]`.
    DualLong { sub: bool, x: bool, lo: R, hi: R, n: R, m: R },
    /// `smmla[r] Rd, Rn, Rm, Ra` (`a: None` is `smmul[r] Rd, Rn, Rm`) and
    /// `smmls[r] Rd, Rn, Rm, Ra` (which has no `Ra`-less form).
    MostSig { sub: bool, round: bool, d: R, n: R, m: R, a: Option<R> },
    /// `sdiv`/`udiv Rd, Rn, Rm`.
    Div { signed: bool, d: R, n: R, m: R },
    /// `usada8 Rd, Rn, Rm, Ra`; `a: None` is `usad8 Rd, Rn, Rm`.
    Usad { d: R, n: R, m: R, a: Option<R> },
    /// `sbfx`/`ubfx Rd, Rn, #lsb, #width`.
    Bfx { signed: bool, d: R, n: R, lsb: u8, width: u8 },
    /// `bfi Rd, Rn, #lsb, #width`; `n: None` is `bfc Rd, #lsb, #width`. The
    /// encoding holds `msb`, and `width` is `msb - lsb + 1`. An `msb` below
    /// `lsb` is UNPREDICTABLE: `llvm-mc` decodes it and prints `lsb` replaced
    /// by `msb` and a width of 1 — a field the encoding does not hold — so this
    /// prints the two fields as they are, `(invalid: lsb:msb)`, which is GNU
    /// objdump's spelling.
    Bfi { d: R, n: Option<R>, lsb: u8, msb: u8 },
    /// `udf #imm16`. `llvm-mc` prints one of these, `0xe7ffdefe`, as `trap`
    /// (the encoding its compiler emits for a trap); the ARM ARM and GNU
    /// objdump call it `udf #65006`, and so does this.
    Udf { imm: u16 },
    /// `smul<x><y> Rd, Rn, Rm`; with `a`, `smla<x><y> Rd, Rn, Rm, Ra`.
    HalfMul { n_top: bool, m_top: bool, d: R, n: R, m: R, a: Option<R> },
    /// `smulw<y> Rd, Rn, Rm`; with `a`, `smlaw<y> Rd, Rn, Rm, Ra`.
    HalfMulWide { m_top: bool, d: R, n: R, m: R, a: Option<R> },
    /// `smlal<x><y> RdLo, RdHi, Rn, Rm`.
    HalfMulLong { n_top: bool, m_top: bool, lo: R, hi: R, n: R, m: R },
}

/// An instruction from an owned space: its condition, its decoded form, and
/// the word it came from (for the should-be fields, which no variant holds).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Own {
    pub(super) cond: ConditionCode,
    pub(super) op: Op,
    word: u32,
}

/// The A32 condition field. `None` for `1111`, the unconditional space, which
/// neither owned class covers.
fn condition(field: u32) -> Option<ConditionCode> {
    use ConditionCode::*;
    Some(match field & 0xf {
        0b0000 => EQ,
        0b0001 => NE,
        0b0010 => HS,
        0b0011 => LO,
        0b0100 => MI,
        0b0101 => PL,
        0b0110 => VS,
        0b0111 => VC,
        0b1000 => HI,
        0b1001 => LS,
        0b1010 => GE,
        0b1011 => LT,
        0b1100 => GT,
        0b1101 => LE,
        0b1110 => AL,
        _ => return None,
    })
}

/// The media class's fixed bits: 27-25 = `011`, 4 = `1`.
fn is_media(word: u32) -> bool {
    word & 0x0e00_0010 == 0x0600_0010
}

/// The halfword multiplies' fixed bits: 27-23 = `00010`, 20 = `0`, 7 = `1`,
/// 4 = `0`.
fn is_halfword_multiply(word: u32) -> bool {
    word & 0x0f90_0090 == 0x0100_0080
}

/// Is this word in a space this file owns? A word that is goes to [`decode`]
/// and nowhere else, whatever `decode` answers.
pub(super) fn owns(word: u32) -> bool {
    condition(word >> 28).is_some() && (is_media(word) || is_halfword_multiply(word))
}

/// Decode a word of an owned space, or `None` for one the architecture leaves
/// UNDEFINED (and the reference rejects).
pub(super) fn decode(word: u32) -> Option<Own> {
    let cond = condition(word >> 28)?;
    let op = if is_media(word) {
        media(word, cond)?
    } else if is_halfword_multiply(word) {
        halfword_multiply(word)
    } else {
        return None;
    };
    Some(Own { cond, op, word })
}

fn bit(word: u32, n: u32) -> bool {
    (word >> n) & 1 == 1
}

/// The media class, ARM ARM A5.4, by `op1` (bits 24-20) and `op2` (bits 7-5).
fn media(word: u32, cond: ConditionCode) -> Option<Op> {
    let op1 = (word >> 20) & 0x1f;
    let op2 = (word >> 5) & 0x7;
    let (r16, r12, r8, r0) = (R::at(word, 16), R::at(word, 12), R::at(word, 8), R::at(word, 0));
    Some(match op1 >> 3 {
        // 00xxx: parallel add/sub, signed (000xx) and unsigned (001xx).
        0b00 => {
            let prefix = match (bit(word, 22), op1 & 0b11) {
                (_, 0b00) => return None,
                (false, 0b01) => ParPrefix::S,
                (false, 0b10) => ParPrefix::Q,
                (false, _) => ParPrefix::Sh,
                (true, 0b01) => ParPrefix::U,
                (true, 0b10) => ParPrefix::Uq,
                (true, _) => ParPrefix::Uh,
            };
            let kind = match op2 {
                0b000 => ParKind::Add16,
                0b001 => ParKind::Asx,
                0b010 => ParKind::Sax,
                0b011 => ParKind::Sub16,
                0b100 => ParKind::Add8,
                0b111 => ParKind::Sub8,
                _ => return None,
            };
            Op::Parallel { prefix, kind, d: r12, n: r16, m: r0 }
        }
        // 01xxx: packing, unpacking, saturation and reversal (A5.4.3).
        0b01 => packing(word, op1 & 0b111, op2, r16, r12, r0)?,
        // 10xxx: signed multiplies and the divides (A5.4.4).
        0b10 => {
            let x = bit(word, 5);
            match (op1 & 0b111, op2) {
                (0b000, 0b000 | 0b001) => Op::Dual { sub: false, x, d: r16, n: r0, m: r8, a: unless_pc(r12) },
                (0b000, 0b010 | 0b011) => Op::Dual { sub: true, x, d: r16, n: r0, m: r8, a: unless_pc(r12) },
                // Bits 15-12 should be `1111`; the reference refuses them
                // otherwise.
                (0b001, 0b000) if r12.is_pc() => Op::Div { signed: true, d: r16, n: r0, m: r8 },
                (0b011, 0b000) if r12.is_pc() => Op::Div { signed: false, d: r16, n: r0, m: r8 },
                (0b100, 0b000 | 0b001) => Op::DualLong { sub: false, x, lo: r12, hi: r16, n: r0, m: r8 },
                (0b100, 0b010 | 0b011) => Op::DualLong { sub: true, x, lo: r12, hi: r16, n: r0, m: r8 },
                (0b101, 0b000 | 0b001) => Op::MostSig { sub: false, round: x, d: r16, n: r0, m: r8, a: unless_pc(r12) },
                (0b101, 0b110 | 0b111) => Op::MostSig { sub: true, round: x, d: r16, n: r0, m: r8, a: Some(r12) },
                _ => return None,
            }
        }
        // 11xxx: usad8/usada8, the bitfield instructions and udf.
        _ => {
            let lsb = ((word >> 7) & 0x1f) as u8;
            let high = ((word >> 16) & 0x1f) as u8; // `widthminus1` or `msb`
            match (op1, op2) {
                (0b11000, 0b000) => Op::Usad { d: r16, n: r0, m: r8, a: unless_pc(r12) },
                (0b11010 | 0b11011, 0b010 | 0b110) => Op::Bfx { signed: true, d: r12, n: r0, lsb, width: high + 1 },
                (0b11110 | 0b11111, 0b010 | 0b110) => Op::Bfx { signed: false, d: r12, n: r0, lsb, width: high + 1 },
                (0b11100 | 0b11101, 0b000 | 0b100) => Op::Bfi { d: r12, n: unless_pc(r0), lsb, msb: high },
                // `udf` is defined only unconditionally; under any other
                // condition the encoding is UNDEFINED.
                (0b11111, 0b111) if cond == ConditionCode::AL => Op::Udf { imm: (((word >> 8) & 0xfff) << 4 | (word & 0xf)) as u16 },
                _ => return None,
            }
        }
    })
}

/// A5.4.3, by `op1` (bits 22-20) and `op2`. `A` (bits 19-16) is `Rn`, and
/// `1111` there is the non-accumulating extend.
fn packing(word: u32, op1: u32, op2: u32, r16: R, r12: R, r0: R) -> Option<Op> {
    let rot = (((word >> 10) & 0b11) * 8) as u8;
    let imm5 = ((word >> 7) & 0x1f) as u8;
    let extend = |signed, size| Op::Extend { signed, size, d: r12, n: unless_pc(r16), m: r0, rot };
    // `ssat`/`usat`: `sat_imm` is bits 20-16 (`ssat` adds one); bit 6 picks
    // `asr`, and `asr` by 0 encodes `asr #32`.
    let sat = |unsigned: bool| {
        let field = ((word >> 16) & 0x1f) as u8;
        let shift = match (bit(word, 6), imm5) {
            (false, 0) => SatShift::None,
            (false, n) => SatShift::Lsl(n),
            (true, 0) => SatShift::Asr(32),
            (true, n) => SatShift::Asr(n),
        };
        Op::Sat { unsigned, d: r12, sat: if unsigned { field } else { field + 1 }, n: r0, shift }
    };
    let sat16 = |unsigned: bool| {
        let field = ((word >> 16) & 0xf) as u8;
        Op::Sat16 { unsigned, d: r12, sat: if unsigned { field } else { field + 1 }, n: r0 }
    };
    // The reference refuses these three families unless their should-be-one
    // fields hold: bits 11-8 for `ssat16`/`usat16`, bits 19-16 and 11-8 for
    // the reversals. (It accepts the same violation in `sel` and the parallel
    // add/sub, and a nonzero should-be-zero rotate field in the extends.)
    let sbo_11_8 = (word >> 8) & 0xf == 0xf;
    let reversal = |kind| (sbo_11_8 && r16.is_pc()).then_some(Op::Reverse { kind, d: r12, m: r0 });
    Some(match (op1, op2) {
        // `pkhtb` by 0 encodes `asr #32`.
        (0b000, 0b000 | 0b100) => Op::Pkh { top: false, d: r12, n: r16, m: r0, sh: imm5 },
        (0b000, 0b010 | 0b110) => Op::Pkh { top: true, d: r12, n: r16, m: r0, sh: if imm5 == 0 { 32 } else { imm5 } },
        (0b000, 0b011) => extend(true, ExtSize::Byte16),
        (0b000, 0b101) => Op::Sel { d: r12, n: r16, m: r0 },
        (0b010 | 0b011, 0b000 | 0b010 | 0b100 | 0b110) => sat(false),
        (0b010, 0b001) if sbo_11_8 => sat16(false),
        (0b010, 0b011) => extend(true, ExtSize::Byte),
        (0b011, 0b001) => reversal(RevKind::Rev)?,
        (0b011, 0b011) => extend(true, ExtSize::Half),
        (0b011, 0b101) => reversal(RevKind::Rev16)?,
        (0b100, 0b011) => extend(false, ExtSize::Byte16),
        (0b110 | 0b111, 0b000 | 0b010 | 0b100 | 0b110) => sat(true),
        (0b110, 0b001) if sbo_11_8 => sat16(true),
        (0b110, 0b011) => extend(false, ExtSize::Byte),
        (0b111, 0b001) => reversal(RevKind::Rbit)?,
        (0b111, 0b011) => extend(false, ExtSize::Half),
        (0b111, 0b101) => reversal(RevKind::Revsh)?,
        _ => return None,
    })
}

/// A5.2.7, by `op1` (bits 22-21); `M` (bit 6) picks `Rm`'s half, `N` (bit 5)
/// `Rn`'s — except in `op1 = 01`, where bit 5 picks `smulw` over `smlaw`.
/// Every word of the space is an instruction.
fn halfword_multiply(word: u32) -> Op {
    let (r16, r12, r8, r0) = (R::at(word, 16), R::at(word, 12), R::at(word, 8), R::at(word, 0));
    let (m_top, n_top) = (bit(word, 6), bit(word, 5));
    match (word >> 21) & 0b11 {
        0b00 => Op::HalfMul { n_top, m_top, d: r16, n: r0, m: r8, a: Some(r12) },
        0b01 => Op::HalfMulWide { m_top, d: r16, n: r0, m: r8, a: (!n_top).then_some(r12) },
        0b10 => Op::HalfMulLong { n_top, m_top, lo: r12, hi: r16, n: r0, m: r8 },
        _ => Op::HalfMul { n_top, m_top, d: r16, n: r0, m: r8, a: None },
    }
}

fn half(top: bool) -> char {
    if top { 't' } else { 'b' }
}

impl Own {
    /// The mnemonic without its condition suffix (`uxtab`, `smladx`).
    fn base_mnemonic(&self) -> String {
        match self.op {
            Op::Parallel { prefix, kind, .. } => {
                let p = match prefix {
                    ParPrefix::S => "s",
                    ParPrefix::Q => "q",
                    ParPrefix::Sh => "sh",
                    ParPrefix::U => "u",
                    ParPrefix::Uq => "uq",
                    ParPrefix::Uh => "uh",
                };
                let k = match kind {
                    ParKind::Add16 => "add16",
                    ParKind::Asx => "asx",
                    ParKind::Sax => "sax",
                    ParKind::Sub16 => "sub16",
                    ParKind::Add8 => "add8",
                    ParKind::Sub8 => "sub8",
                };
                format!("{p}{k}")
            }
            Op::Extend { signed, size, n, .. } => {
                let s = match size {
                    ExtSize::Byte => "b",
                    ExtSize::Half => "h",
                    ExtSize::Byte16 => "b16",
                };
                format!("{}xt{}{s}", if signed { 's' } else { 'u' }, if n.is_some() { "a" } else { "" })
            }
            Op::Pkh { top, .. } => (if top { "pkhtb" } else { "pkhbt" }).to_string(),
            Op::Sat { unsigned, .. } => (if unsigned { "usat" } else { "ssat" }).to_string(),
            Op::Sat16 { unsigned, .. } => (if unsigned { "usat16" } else { "ssat16" }).to_string(),
            Op::Sel { .. } => "sel".to_string(),
            Op::Reverse { kind, .. } => match kind {
                RevKind::Rev => "rev",
                RevKind::Rev16 => "rev16",
                RevKind::Revsh => "revsh",
                RevKind::Rbit => "rbit",
            }
            .to_string(),
            Op::Dual { sub, x, a, .. } => {
                format!("sm{}{}d{}", if a.is_some() { "l" } else { "u" }, if sub { "s" } else { "a" }, if x { "x" } else { "" })
            }
            Op::DualLong { sub, x, .. } => format!("sml{}ld{}", if sub { "s" } else { "a" }, if x { "x" } else { "" }),
            Op::MostSig { sub, round, a, .. } => {
                let base = match (sub, a) {
                    (true, _) => "smmls",
                    (false, Some(_)) => "smmla",
                    (false, None) => "smmul",
                };
                format!("{base}{}", if round { "r" } else { "" })
            }
            Op::Div { signed, .. } => (if signed { "sdiv" } else { "udiv" }).to_string(),
            Op::Usad { a, .. } => (if a.is_some() { "usada8" } else { "usad8" }).to_string(),
            Op::Bfx { signed, .. } => (if signed { "sbfx" } else { "ubfx" }).to_string(),
            Op::Bfi { n, .. } => (if n.is_some() { "bfi" } else { "bfc" }).to_string(),
            Op::Udf { .. } => "udf".to_string(),
            Op::HalfMul { n_top, m_top, a, .. } => format!("sm{}{}{}", if a.is_some() { "la" } else { "ul" }, half(n_top), half(m_top)),
            Op::HalfMulWide { m_top, a, .. } => format!("sm{}w{}", if a.is_some() { "la" } else { "ul" }, half(m_top)),
            Op::HalfMulLong { n_top, m_top, .. } => format!("smlal{}{}", half(n_top), half(m_top)),
        }
    }

    /// The operands, as UAL writes them.
    fn operands(&self) -> String {
        let r = |r: R| r.name();
        let rs = |regs: &[R]| regs.iter().map(|&x| r(x)).collect::<Vec<_>>().join(", ");
        // The register list with an optional trailing one (`Ra`).
        let with = |regs: &[R], last: Option<R>| match last {
            Some(a) => format!("{}, {}", rs(regs), r(a)),
            None => rs(regs),
        };
        match self.op {
            Op::Parallel { d, n, m, .. } | Op::Sel { d, n, m } | Op::Div { d, n, m, .. } => rs(&[d, n, m]),
            Op::Extend { d, n, m, rot, .. } => {
                let regs = match n {
                    Some(n) => rs(&[d, n, m]),
                    None => rs(&[d, m]),
                };
                if rot == 0 { regs } else { format!("{regs}, ror #{rot}") }
            }
            Op::Pkh { top, d, n, m, sh } => match (top, sh) {
                (false, 0) => rs(&[d, n, m]),
                (false, sh) => format!("{}, lsl #{sh}", rs(&[d, n, m])),
                (true, sh) => format!("{}, asr #{sh}", rs(&[d, n, m])),
            },
            Op::Sat { d, sat, n, shift, .. } => {
                let base = format!("{}, #{sat}, {}", r(d), r(n));
                match shift {
                    SatShift::None => base,
                    SatShift::Lsl(k) => format!("{base}, lsl #{k}"),
                    SatShift::Asr(k) => format!("{base}, asr #{k}"),
                }
            }
            Op::Sat16 { d, sat, n, .. } => format!("{}, #{sat}, {}", r(d), r(n)),
            Op::Reverse { d, m, .. } => rs(&[d, m]),
            Op::Dual { d, n, m, a, .. } | Op::MostSig { d, n, m, a, .. } | Op::Usad { d, n, m, a } => with(&[d, n, m], a),
            Op::DualLong { lo, hi, n, m, .. } | Op::HalfMulLong { lo, hi, n, m, .. } => rs(&[lo, hi, n, m]),
            Op::Bfx { d, n, lsb, width, .. } => format!("{}, #{lsb}, #{width}", rs(&[d, n])),
            Op::Bfi { d, n, lsb, msb } => {
                let regs = match n {
                    Some(n) => rs(&[d, n]),
                    None => r(d),
                };
                if msb < lsb { format!("{regs}, (invalid: {lsb}:{msb})") } else { format!("{regs}, #{lsb}, #{}", msb - lsb + 1) }
            }
            Op::Udf { imm } => format!("#{imm}"),
            Op::HalfMul { d, n, m, a, .. } | Op::HalfMulWide { d, n, m, a, .. } => with(&[d, n, m], a),
        }
    }

    /// The full text: mnemonic, the condition suffix (the crate's own
    /// spelling, so a predicated instruction reads the same whichever decoder
    /// produced it) and the operands.
    pub(super) fn text(&self) -> String {
        format!("{}{} {}", self.base_mnemonic(), self.cond, self.operands())
    }

    pub(super) fn kind(&self) -> InsnKind {
        match self.op {
            // A permanently undefined instruction traps; nothing follows it.
            // AArch64's `udf` is classified the same way.
            Op::Udf { .. } => InsnKind::Int,
            _ => InsnKind::Seq,
        }
    }

    /// The registers this instruction writes — exact, since every owned form
    /// writes its destination field(s) and nothing else (no write-back, no
    /// list). The two-destination forms write both halves of the result.
    pub(super) fn writes(&self) -> Vec<String> {
        match self.op {
            Op::DualLong { lo, hi, .. } | Op::HalfMulLong { lo, hi, .. } => vec![lo.name(), hi.name()],
            Op::Udf { .. } => Vec::new(),
            Op::Parallel { d, .. }
            | Op::Extend { d, .. }
            | Op::Pkh { d, .. }
            | Op::Sat { d, .. }
            | Op::Sat16 { d, .. }
            | Op::Sel { d, .. }
            | Op::Reverse { d, .. }
            | Op::Dual { d, .. }
            | Op::MostSig { d, .. }
            | Op::Div { d, .. }
            | Op::Usad { d, .. }
            | Op::Bfx { d, .. }
            | Op::Bfi { d, .. }
            | Op::HalfMul { d, .. }
            | Op::HalfMulWide { d, .. } => vec![d.name()],
        }
    }

    /// The crate's opcode for this instruction's family, for the facts that
    /// are kept per opcode in one place for both decoders —
    /// [`writes_q_or_ge`](super::writes_q_or_ge). Lossy on purpose: `smladx`
    /// and `smlad` are one family there.
    pub(super) fn opcode(&self) -> Opcode {
        match self.op {
            Op::Parallel { prefix, kind, .. } => {
                use Opcode::*;
                use ParKind::*;
                use ParPrefix::*;
                match (prefix, kind) {
                    (S, Add16) => SADD16,
                    (S, Asx) => SASX,
                    (S, Sax) => SSAX,
                    (S, Sub16) => SSUB16,
                    (S, Add8) => SADD8,
                    (S, Sub8) => SSUB8,
                    (Q, Add16) => QADD16,
                    (Q, Asx) => QASX,
                    (Q, Sax) => QSAX,
                    (Q, Sub16) => QSUB16,
                    (Q, Add8) => QADD8,
                    (Q, Sub8) => QSUB8,
                    (Sh, Add16) => SHADD16,
                    (Sh, Asx) => SHASX,
                    (Sh, Sax) => SHSAX,
                    (Sh, Sub16) => SHSUB16,
                    (Sh, Add8) => SHADD8,
                    (Sh, Sub8) => SHSUB8,
                    (U, Add16) => UADD16,
                    (U, Asx) => UASX,
                    (U, Sax) => USAX,
                    (U, Sub16) => USUB16,
                    (U, Add8) => UADD8,
                    (U, Sub8) => USUB8,
                    (Uq, Add16) => UQADD16,
                    (Uq, Asx) => UQASX,
                    (Uq, Sax) => UQSAX,
                    (Uq, Sub16) => UQSUB16,
                    (Uq, Add8) => UQADD8,
                    (Uq, Sub8) => UQSUB8,
                    (Uh, Add16) => UHADD16,
                    (Uh, Asx) => UHASX,
                    (Uh, Sax) => UHSAX,
                    (Uh, Sub16) => UHSUB16,
                    (Uh, Add8) => UHADD8,
                    (Uh, Sub8) => UHSUB8,
                }
            }
            Op::Extend { signed, size, n, .. } => match (signed, size, n.is_some()) {
                (true, ExtSize::Byte, false) => Opcode::SXTB,
                (true, ExtSize::Byte, true) => Opcode::SXTAB,
                (true, ExtSize::Half, false) => Opcode::SXTH,
                (true, ExtSize::Half, true) => Opcode::SXTAH,
                (true, ExtSize::Byte16, false) => Opcode::SXTB16,
                (true, ExtSize::Byte16, true) => Opcode::SXTAB16,
                (false, ExtSize::Byte, false) => Opcode::UXTB,
                (false, ExtSize::Byte, true) => Opcode::UXTAB,
                (false, ExtSize::Half, false) => Opcode::UXTH,
                (false, ExtSize::Half, true) => Opcode::UXTAH,
                (false, ExtSize::Byte16, false) => Opcode::UXTB16,
                (false, ExtSize::Byte16, true) => Opcode::UXTAB16,
            },
            Op::Pkh { top, .. } => if top { Opcode::PKHTB } else { Opcode::PKHBT },
            Op::Sat { unsigned, .. } => if unsigned { Opcode::USAT } else { Opcode::SSAT },
            Op::Sat16 { unsigned, .. } => if unsigned { Opcode::USAT16 } else { Opcode::SSAT16 },
            Op::Sel { .. } => Opcode::SEL,
            Op::Reverse { kind, .. } => match kind {
                RevKind::Rev => Opcode::REV,
                RevKind::Rev16 => Opcode::REV16,
                RevKind::Revsh => Opcode::REVSH,
                RevKind::Rbit => Opcode::RBIT,
            },
            Op::Dual { sub, a, .. } => match (sub, a.is_some()) {
                (false, true) => Opcode::SMLAD,
                (false, false) => Opcode::SMUAD,
                (true, true) => Opcode::SMLSD,
                (true, false) => Opcode::SMUSD,
            },
            Op::DualLong { sub, x, .. } => if sub { Opcode::SMLSLD(x) } else { Opcode::SMLALD(x) },
            Op::MostSig { sub, round, a, .. } => match (sub, round, a.is_some()) {
                (true, false, _) => Opcode::SMMLS,
                (true, true, _) => Opcode::SMMLSR,
                (false, false, true) => Opcode::SMMLA,
                (false, true, true) => Opcode::SMMLAR,
                (false, _, false) => Opcode::SMMUL,
            },
            Op::Div { signed, .. } => if signed { Opcode::SDIV } else { Opcode::UDIV },
            Op::Usad { a, .. } => if a.is_some() { Opcode::USADA8 } else { Opcode::USAD8 },
            Op::Bfx { signed, .. } => if signed { Opcode::SBFX } else { Opcode::UBFX },
            Op::Bfi { n, .. } => if n.is_some() { Opcode::BFI } else { Opcode::BFC },
            Op::Udf { .. } => Opcode::UDF,
            Op::HalfMul { n_top, m_top, a, .. } => if a.is_some() { Opcode::SMLA(n_top, m_top) } else { Opcode::SMUL(n_top, m_top) },
            Op::HalfMulWide { m_top, a, .. } => if a.is_some() { Opcode::SMLAW(m_top) } else { Opcode::SMULW(m_top) },
            Op::HalfMulLong { n_top, m_top, .. } => Opcode::SMLAL_halfword(n_top, m_top),
        }
    }

    /// Is this word UNPREDICTABLE — decoded and shown, but with no value the
    /// lift may state? Three causes, all from the ARM ARM's decode pseudocode
    /// for each instruction:
    ///
    /// * any register field naming `r15` (the forms where `1111` means "no
    ///   register" hold `None` there instead, so they do not count);
    /// * a should-be field the other way: bits 11-8 not `1111` in the parallel
    ///   add/sub and `sel`, bits 9-8 not `00` in the extends, bits 15-12 not
    ///   `0000` in `smul<x><y>` and `smulw<y>` (the reference accepts each of
    ///   these with a warning; the ones it refuses never decode);
    /// * a bitfield past bit 31 (`sbfx`/`ubfx`), or one whose `msb` is below
    ///   its `lsb` (`bfi`/`bfc`).
    pub(super) fn unpredictable(&self) -> bool {
        let w = self.word;
        let should_be_violated = match self.op {
            Op::Parallel { .. } | Op::Sel { .. } => (w >> 8) & 0xf != 0xf,
            Op::Extend { .. } => (w >> 8) & 0b11 != 0,
            Op::HalfMul { a: None, .. } | Op::HalfMulWide { a: None, .. } => (w >> 12) & 0xf != 0,
            _ => false,
        };
        let bad_field = match self.op {
            Op::Bfx { lsb, width, .. } => u32::from(lsb) + u32::from(width) > 32,
            Op::Bfi { lsb, msb, .. } => msb < lsb,
            _ => false,
        };
        should_be_violated || bad_field || self.registers().iter().any(|r| r.is_pc())
    }

    /// Every register field the instruction reads or writes.
    fn registers(&self) -> Vec<R> {
        match self.op {
            Op::Parallel { d, n, m, .. } | Op::Sel { d, n, m } | Op::Div { d, n, m, .. } | Op::Pkh { d, n, m, .. } => vec![d, n, m],
            Op::Extend { d, n, m, .. } => [Some(d), n, Some(m)].into_iter().flatten().collect(),
            Op::Sat { d, n, .. } | Op::Sat16 { d, n, .. } | Op::Bfx { d, n, .. } => vec![d, n],
            Op::Reverse { d, m, .. } => vec![d, m],
            Op::Dual { d, n, m, a, .. }
            | Op::MostSig { d, n, m, a, .. }
            | Op::Usad { d, n, m, a }
            | Op::HalfMul { d, n, m, a, .. }
            | Op::HalfMulWide { d, n, m, a, .. } => [Some(d), Some(n), Some(m), a].into_iter().flatten().collect(),
            Op::DualLong { lo, hi, n, m, .. } | Op::HalfMulLong { lo, hi, n, m, .. } => vec![lo, hi, n, m],
            Op::Bfi { d, n, .. } => [Some(d), n].into_iter().flatten().collect(),
            Op::Udf { .. } => Vec::new(),
        }
    }

    /// The destination and exact value of an instruction this lift models, or
    /// `None` for one that stays `asm`. Modelled: the byte and halfword
    /// extends (with or without the add), `sbfx`/`ubfx`/`bfi`/`bfc`,
    /// `pkhbt`/`pkhtb`, `smul<x><y>` and `rev`/`rev16`/`revsh` — each a
    /// function of whole registers that the IR's operators state exactly.
    /// Everything SIMD-within-a-register (the parallel add/sub family, `sel`,
    /// the `xtb16` extends, `usad8`), the saturating forms (which also set
    /// `Q`), the accumulating and dual multiplies, the divides and `rbit`
    /// stay `asm`.
    ///
    /// An A32 register is held zero-extended at 32 bits, so a value that could
    /// carry anything above bit 31 — a sign extension, a sum, a product — is
    /// cast back to 32 bits unsigned.
    pub(super) fn lift(&self) -> Option<(String, MicroExpr)> {
        if self.unpredictable() {
            return None;
        }
        let c = |v: i128| MicroExpr::constant(v, 32);
        let bin = MicroExpr::binary;
        let u32_of = |e: MicroExpr| MicroExpr::Cast { signed: false, bits: 32, expr: Box::new(e) };
        let ext = |signed: bool, bits: u32, e: MicroExpr| {
            let cast = MicroExpr::Cast { signed, bits, expr: Box::new(e) };
            if signed { u32_of(cast) } else { cast }
        };
        let shr = |e: MicroExpr, k: u8| if k == 0 { e } else { bin(BinOp::Shr, e, c(i128::from(k))) };
        let shl = |e: MicroExpr, k: u8| if k == 0 { e } else { bin(BinOp::Shl, e, c(i128::from(k))) };
        Some(match self.op {
            Op::Extend { signed, size: size @ (ExtSize::Byte | ExtSize::Half), d, n, m, rot } => {
                let bits = if size == ExtSize::Byte { 8 } else { 16 };
                // The low `bits` of `ROR(Rm, rot)`. A byte at any rotation, and
                // a halfword below 24, lie wholly inside the register, so a
                // right shift reaches them; only a halfword at 24 wraps, and
                // takes its high byte from the bottom of `Rm`.
                let field = if bits == 16 && rot == 24 { bin(BinOp::Or, shr(m.var(), 24), shl(m.var(), 8)) } else { shr(m.var(), rot) };
                let value = match n {
                    None => ext(signed, bits, field),
                    Some(n) => u32_of(bin(BinOp::Add, n.var(), MicroExpr::Cast { signed, bits, expr: Box::new(field) })),
                };
                (d.name(), value)
            }
            // `unpredictable` has refused a field past bit 31.
            Op::Bfx { signed, d, n, lsb, width } => {
                let value = match (signed, width) {
                    (_, 32) => n.var(),
                    (false, w) => bin(BinOp::And, shr(n.var(), lsb), c((1i128 << w) - 1)),
                    // Move the field's top bit to bit 31, then shift it back
                    // down arithmetically: the field, sign-extended.
                    (true, w) => u32_of(shift(BinOp::Sar, shl(n.var(), 32 - lsb - w), c(i128::from(32 - w)))),
                };
                (d.name(), value)
            }
            // `unpredictable` has refused `msb < lsb`.
            Op::Bfi { d, n, lsb, msb } => {
                let field = ((1i128 << (msb - lsb + 1)) - 1) << lsb;
                let keep = 0xffff_ffff ^ field;
                let value = match (n, keep) {
                    (None, 0) => c(0),
                    (None, keep) => bin(BinOp::And, d.var(), c(keep)),
                    (Some(n), 0) => n.var(),
                    (Some(n), keep) => bin(BinOp::Or, bin(BinOp::And, d.var(), c(keep)), bin(BinOp::And, shl(n.var(), lsb), c(field))),
                };
                (d.name(), value)
            }
            Op::Pkh { top: false, d, n, m, sh } => {
                (d.name(), bin(BinOp::Or, bin(BinOp::And, n.var(), c(0xffff)), bin(BinOp::And, shl(m.var(), sh), c(0xffff_0000))))
            }
            Op::Pkh { top: true, d, n, m, sh } => {
                // `asr #32` (the encoding's 0) is the sign fill; `imm_shift`
                // states it without a shift by the width.
                let shifted = imm_shift(ShiftStyle::ASR, m.var(), sh)?;
                (d.name(), bin(BinOp::Or, bin(BinOp::And, n.var(), c(0xffff_0000)), bin(BinOp::And, shifted, c(0xffff))))
            }
            Op::HalfMul { n_top, m_top, d, n, m, a: None } => {
                let half = |r: R, top: bool| MicroExpr::Cast { signed: true, bits: 16, expr: Box::new(if top { shr(r.var(), 16) } else { r.var() }) };
                (d.name(), u32_of(bin(BinOp::Mul, half(n, n_top), half(m, m_top))))
            }
            Op::Reverse { kind: RevKind::Rev, d, m } => {
                let byte = |mask: i128, op: BinOp, k: i128| bin(op, bin(BinOp::And, m.var(), c(mask)), c(k));
                let value = bin(
                    BinOp::Or,
                    bin(BinOp::Or, byte(0xff, BinOp::Shl, 24), byte(0xff00, BinOp::Shl, 8)),
                    bin(BinOp::Or, byte(0x00ff_0000, BinOp::Shr, 8), byte(0xff00_0000, BinOp::Shr, 24)),
                );
                (d.name(), value)
            }
            Op::Reverse { kind: RevKind::Rev16, d, m } => {
                let value = bin(BinOp::Or, shl(bin(BinOp::And, m.var(), c(0x00ff_00ff)), 8), bin(BinOp::And, shr(m.var(), 8), c(0x00ff_00ff)));
                (d.name(), value)
            }
            Op::Reverse { kind: RevKind::Revsh, d, m } => {
                // The low halfword byte-swapped, then sign-extended.
                let swapped = bin(BinOp::Or, shl(bin(BinOp::And, m.var(), c(0xff)), 8), bin(BinOp::And, shr(m.var(), 8), c(0xff)));
                (d.name(), ext(true, 16, swapped))
            }
            _ => return None,
        })
    }
}
