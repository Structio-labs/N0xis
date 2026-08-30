//! `Arm64` — the AArch64 implementation of [`Arch`], backed by `disarm64` (a
//! pure-Rust, no-`unsafe`, no-allocation decoder generated from the ARM
//! instruction spec — the same "reuse a mature decoder, don't reinvent one"
//! choice `X64` made with `iced-x86`). ROADMAP Phase 7: proves the ISA seam
//! built in Phase 1 actually works — everything below is new, but nothing in
//! `n0xis-core` changed to make it possible.
//!
//! **Deliberately scoped, honestly incomplete** (CONCEPT §3 rule 6: sound
//! over complete). This is not the full AArch64 ISA:
//! - [`Arch::reg_access`] is implemented for the base integer ISA a compiler
//!   actually emits for ordinary functions (data-processing, loads/stores,
//!   branches) — SIMD/FP/SVE/SME/crypto/system-register/atomic classes
//!   report no reads/writes, the same sound-but-empty default the trait
//!   itself defines for an ISA with no override. def-use tracking is
//!   therefore accurate for typical scalar code and silent (not wrong) for
//!   vector/crypto code.
//! - [`Arch::lift`] and [`Arch::branch_condition`] are **not** overridden —
//!   they keep the trait's sound defaults (`Unlifted` / a placeholder
//!   condition). SSA-level optimization and flag-precise condition recovery
//!   (Phase 3's `--style ssa` main) are an X64-only capability today;
//!   ARM64 still gets accurate CFG, discovery, xrefs, and `goto`/`structured`
//!   decompilation, just not the optimized SSA pass. A documented follow-on,
//!   not a silent gap — flags work (NZCV) is a comparable-sized effort to
//!   x64's `microir.rs`/`x64_lift.rs` and deserves its own pass.
//! - [`Arch::detect_switch`] is not implemented (ARM64 jump-table idioms
//!   differ from x64's two; a third pattern-recognizer, not attempted here).
//! - [`Arch::prologues`] only lists a few common exact prolog encodings
//!   (`stp x29, x30, [sp, #-N]!` for the frame sizes GCC/Clang emit most).

use disarm64::registers::get_int_reg_name;
use disarm64::{InsnDisplay, InsnOpcode, decoder};
use disarm64_defn::InsnClass;
use n0xis_contracts::{Reg, Va};

use crate::frame::FrameInfo;
use crate::insn::{DecodeError, DecodedInsn, InsnKind};
use crate::switch::SwitchDispatch;
use crate::{Arch, CallConv, RegAccess, RegDesc, RegisterFile};

/// Interned register ids for AArch64. Passes refer to registers *only*
/// through these ids resolved against the [`RegisterFile`] — never by name
/// literal (same discipline as [`crate::x64reg`]).
pub mod arm64reg {
    use n0xis_contracts::Reg;
    pub const X0: Reg = Reg(0);
    pub const X1: Reg = Reg(1);
    pub const X2: Reg = Reg(2);
    pub const X3: Reg = Reg(3);
    pub const X4: Reg = Reg(4);
    pub const X5: Reg = Reg(5);
    pub const X6: Reg = Reg(6);
    pub const X7: Reg = Reg(7);
    pub const X8: Reg = Reg(8);
    pub const X9: Reg = Reg(9);
    pub const X10: Reg = Reg(10);
    pub const X11: Reg = Reg(11);
    pub const X12: Reg = Reg(12);
    pub const X13: Reg = Reg(13);
    pub const X14: Reg = Reg(14);
    pub const X15: Reg = Reg(15);
    pub const X16: Reg = Reg(16);
    pub const X17: Reg = Reg(17);
    pub const X18: Reg = Reg(18);
    pub const X19: Reg = Reg(19);
    pub const X20: Reg = Reg(20);
    pub const X21: Reg = Reg(21);
    pub const X22: Reg = Reg(22);
    pub const X23: Reg = Reg(23);
    pub const X24: Reg = Reg(24);
    pub const X25: Reg = Reg(25);
    pub const X26: Reg = Reg(26);
    pub const X27: Reg = Reg(27);
    pub const X28: Reg = Reg(28);
    /// x29 — frame pointer by AAPCS64 convention (not enforced by hardware).
    pub const FP: Reg = Reg(29);
    /// x30 — link register (return address).
    pub const LR: Reg = Reg(30);
    pub const SP: Reg = Reg(31);
}

static ARM64_REGS: &[RegDesc] = &[
    RegDesc { id: arm64reg::X0, name: "x0", size_bits: 64 },
    RegDesc { id: arm64reg::X1, name: "x1", size_bits: 64 },
    RegDesc { id: arm64reg::X2, name: "x2", size_bits: 64 },
    RegDesc { id: arm64reg::X3, name: "x3", size_bits: 64 },
    RegDesc { id: arm64reg::X4, name: "x4", size_bits: 64 },
    RegDesc { id: arm64reg::X5, name: "x5", size_bits: 64 },
    RegDesc { id: arm64reg::X6, name: "x6", size_bits: 64 },
    RegDesc { id: arm64reg::X7, name: "x7", size_bits: 64 },
    RegDesc { id: arm64reg::X8, name: "x8", size_bits: 64 },
    RegDesc { id: arm64reg::X9, name: "x9", size_bits: 64 },
    RegDesc { id: arm64reg::X10, name: "x10", size_bits: 64 },
    RegDesc { id: arm64reg::X11, name: "x11", size_bits: 64 },
    RegDesc { id: arm64reg::X12, name: "x12", size_bits: 64 },
    RegDesc { id: arm64reg::X13, name: "x13", size_bits: 64 },
    RegDesc { id: arm64reg::X14, name: "x14", size_bits: 64 },
    RegDesc { id: arm64reg::X15, name: "x15", size_bits: 64 },
    RegDesc { id: arm64reg::X16, name: "x16", size_bits: 64 },
    RegDesc { id: arm64reg::X17, name: "x17", size_bits: 64 },
    RegDesc { id: arm64reg::X18, name: "x18", size_bits: 64 },
    RegDesc { id: arm64reg::X19, name: "x19", size_bits: 64 },
    RegDesc { id: arm64reg::X20, name: "x20", size_bits: 64 },
    RegDesc { id: arm64reg::X21, name: "x21", size_bits: 64 },
    RegDesc { id: arm64reg::X22, name: "x22", size_bits: 64 },
    RegDesc { id: arm64reg::X23, name: "x23", size_bits: 64 },
    RegDesc { id: arm64reg::X24, name: "x24", size_bits: 64 },
    RegDesc { id: arm64reg::X25, name: "x25", size_bits: 64 },
    RegDesc { id: arm64reg::X26, name: "x26", size_bits: 64 },
    RegDesc { id: arm64reg::X27, name: "x27", size_bits: 64 },
    RegDesc { id: arm64reg::X28, name: "x28", size_bits: 64 },
    RegDesc { id: arm64reg::FP, name: "x29", size_bits: 64 },
    RegDesc { id: arm64reg::LR, name: "x30", size_bits: 64 },
    RegDesc { id: arm64reg::SP, name: "sp", size_bits: 64 },
];

// AAPCS64 (the AArch64 Procedure Call Standard) — the ABI fact that must
// never be baked into a pass. x0-x7 carry integer/pointer args, x0 the
// return value, x9-x15+x0-x8+x16-x18 are caller-saved; x19-x28 are
// callee-saved (not listed as volatile).
static AAPCS64_INT_ARGS: &[Reg] = &[
    arm64reg::X0, arm64reg::X1, arm64reg::X2, arm64reg::X3,
    arm64reg::X4, arm64reg::X5, arm64reg::X6, arm64reg::X7,
];
static AAPCS64_VOLATILE: &[Reg] = &[
    arm64reg::X0, arm64reg::X1, arm64reg::X2, arm64reg::X3, arm64reg::X4, arm64reg::X5,
    arm64reg::X6, arm64reg::X7, arm64reg::X8, arm64reg::X9, arm64reg::X10, arm64reg::X11,
    arm64reg::X12, arm64reg::X13, arm64reg::X14, arm64reg::X15, arm64reg::X16, arm64reg::X17,
];
static AAPCS64_CC: CallConv = CallConv {
    name: "aapcs64",
    int_args: AAPCS64_INT_ARGS,
    ret: arm64reg::X0,
    volatile: AAPCS64_VOLATILE,
};

/// A handful of exact `stp x29, x30, [sp, #-N]!` prologs — the standard
/// frame-establishing first instruction GCC/Clang emit, for the frame sizes
/// seen most often. Exact-byte matching only (see `DiscoverPass`), so this
/// necessarily misses other frame sizes — a documented limitation, not a
/// silent one.
const ARM64_PROLOGUES: &[&[u8]] = &[
    &0xa9bf7bfdu32.to_le_bytes(), // stp x29, x30, [sp, #-0x10]!
    &0xa9be7bfdu32.to_le_bytes(), // stp x29, x30, [sp, #-0x20]!
    &0xa9bd7bfdu32.to_le_bytes(), // stp x29, x30, [sp, #-0x30]!
    &0xa9bc7bfdu32.to_le_bytes(), // stp x29, x30, [sp, #-0x40]!
];

/// The AArch64 architecture.
#[derive(Clone, Copy, Debug)]
pub struct Arm64 {
    regfile: RegisterFile,
}

impl Arm64 {
    pub const fn new() -> Self {
        Arm64 { regfile: RegisterFile::new(ARM64_REGS) }
    }
}

impl Default for Arm64 {
    fn default() -> Self {
        Arm64::new()
    }
}

/// `bits[hi:lo]`, inclusive, as an unsigned value.
fn bitrange(bits: u32, hi: u32, lo: u32) -> u32 {
    let width = hi - lo + 1;
    let mask = if width >= 32 { u32::MAX } else { (1u32 << width) - 1 };
    (bits >> lo) & mask
}

/// Sign-extend the low `width` bits of `value` to `i64`.
fn sign_extend(value: u32, width: u32) -> i64 {
    let shift = 32 - width;
    (((value << shift) as i32) >> shift) as i64
}

fn classify(class: InsnClass, mnemonic: &str) -> InsnKind {
    match class {
        InsnClass::BRANCH_IMM => {
            if mnemonic == "bl" {
                InsnKind::Call
            } else {
                InsnKind::Jump
            }
        }
        InsnClass::BRANCH_REG => match mnemonic {
            "ret" | "retaa" | "retab" => InsnKind::Ret,
            "blr" | "blraa" | "blrab" | "blraaz" | "blrabz" => InsnKind::Call,
            "br" | "braa" | "brab" | "braaz" | "brabz" => InsnKind::Jump,
            _ => InsnKind::Other, // eret, drps, ...
        },
        InsnClass::CONDBRANCH | InsnClass::COMPBRANCH | InsnClass::TESTBRANCH => InsnKind::CondJump,
        InsnClass::EXCEPTION => InsnKind::Int,
        _ => InsnKind::Seq,
    }
}

/// PC-relative branch target for the three fixed-width immediate forms ARM64
/// uses for *all* direct branches — no other encodings carry a direct target.
fn direct_target(bits: u32, va: Va, class: InsnClass) -> Option<Va> {
    match class {
        InsnClass::BRANCH_IMM => {
            let imm26 = bitrange(bits, 25, 0);
            Some(Va((va.0 as i64 + sign_extend(imm26, 26) * 4) as u64))
        }
        InsnClass::CONDBRANCH | InsnClass::COMPBRANCH => {
            let imm19 = bitrange(bits, 23, 5);
            Some(Va((va.0 as i64 + sign_extend(imm19, 19) * 4) as u64))
        }
        InsnClass::TESTBRANCH => {
            let imm14 = bitrange(bits, 18, 5);
            Some(Va((va.0 as i64 + sign_extend(imm14, 14) * 4) as u64))
        }
        _ => None,
    }
}

/// GPR name for encoded register number `n` (0-31), honoring the `sf` bit
/// (bit 31, 1 = 64-bit `x`, 0 = 32-bit `w`) that selects width across nearly
/// every base-ISA form. `want_zr` selects which reading of register 31 this
/// specific operand position permits: **not every instruction class can
/// encode `sp`** — only `ADDSUB_IMM`'s `Rd`/`Rn` and a load/store's base
/// `Rn` can; every other GPR position (register-form ALU operands, `Rt`
/// transfer registers, branch registers) is architecturally `xzr`-only, and
/// getting this backwards silently mislabels the classic `sub sp, sp, #N`
/// prologue and any `xzr`-using idiom (`madd x, y, z, xzr`, `orr x0, xzr,
/// xzr` as a `mov #0`) as touching the stack pointer instead — caught
/// against real, compiler-generated AArch64 code, not just hand-picked
/// bytes; see the call sites in [`Arch::reg_access`] for the per-class rule.
fn gpr_name(bits: u32, n: u32, want_zr: bool) -> String {
    let is_64 = bitrange(bits, 31, 31) == 1;
    get_int_reg_name(is_64, n as u8, want_zr).to_string()
}

fn build_insn(bits: u32, va: Va) -> DecodedInsn {
    match decoder::decode(bits) {
        Some(op) => {
            let def = op.definition();
            let kind = classify(def.class, def.mnemonic);
            let text = format!("{}", op.display_at(va.0));
            DecodedInsn {
                va,
                len: 4,
                bytes: bits.to_le_bytes().to_vec(),
                mnemonic: def.mnemonic.to_string(),
                text,
                kind,
                target: direct_target(bits, va, def.class),
                rip_target: None, // ARM64 has no separate "RIP-relative memory operand" concept the way x64 does; ADR/ADRP recovery is a documented follow-on.
                cond: None,
            }
        }
        None => DecodedInsn {
            va,
            len: 4,
            bytes: bits.to_le_bytes().to_vec(),
            mnemonic: "(bad)".to_string(),
            text: format!(".inst 0x{bits:08x}"),
            kind: InsnKind::Invalid,
            target: None,
            rip_target: None,
            cond: None,
        },
    }
}

impl Arch for Arm64 {
    fn name(&self) -> &'static str {
        "arm64"
    }

    fn decode(&self, bytes: &[u8], va: Va) -> Result<DecodedInsn, DecodeError> {
        if bytes.len() < 4 {
            return Err(DecodeError::Truncated(va));
        }
        let bits = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let di = build_insn(bits, va);
        if di.kind == InsnKind::Invalid {
            return Err(DecodeError::Invalid(va));
        }
        Ok(di)
    }

    fn decode_stream(&self, bytes: &[u8], va: Va, max: usize) -> Vec<DecodedInsn> {
        let mut out = Vec::new();
        let mut offset = 0usize;
        while out.len() < max && offset + 4 <= bytes.len() {
            let bits = u32::from_le_bytes([
                bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            ]);
            let di = build_insn(bits, Va(va.0 + offset as u64));
            let invalid = di.kind == InsnKind::Invalid;
            out.push(di);
            offset += 4;
            if invalid {
                break;
            }
        }
        out
    }

    fn reg_access(&self, insn: &DecodedInsn) -> RegAccess {
        if insn.bytes.len() < 4 {
            return RegAccess::default();
        }
        let bits = u32::from_le_bytes([insn.bytes[0], insn.bytes[1], insn.bytes[2], insn.bytes[3]]);
        let Some(op) = decoder::decode(bits) else {
            return RegAccess::default();
        };
        let class = op.definition().class;
        let mnemonic = op.definition().mnemonic;
        let mut access = RegAccess::default();

        let rd_rt = bitrange(bits, 4, 0);
        let rn = bitrange(bits, 9, 5);
        let rm = bitrange(bits, 20, 16);
        let rt2_ra = bitrange(bits, 14, 10);

        // `want_zr = false` (sp-eligible) only for ADDSUB_IMM's Rd/Rn (the
        // `add/sub sp, sp, #N` prologue idiom) and a load/store's base Rn
        // (`ldr x0, [sp, #16]`) — every other GPR position on AArch64 cannot
        // encode `sp` at all, so it's always `want_zr = true` there.
        match class {
            InsnClass::ADDSUB_IMM => {
                access.writes.push(gpr_name(bits, rd_rt, false));
                access.reads.push(gpr_name(bits, rn, false));
            }
            InsnClass::LOG_IMM | InsnClass::MOVEWIDE | InsnClass::BITFIELD | InsnClass::PCRELADDR => {
                access.writes.push(gpr_name(bits, rd_rt, true));
                if !matches!(class, InsnClass::MOVEWIDE | InsnClass::PCRELADDR) {
                    access.reads.push(gpr_name(bits, rn, true));
                }
            }
            InsnClass::ADDSUB_SHIFT | InsnClass::ADDSUB_EXT | InsnClass::ADDSUB_CARRY
            | InsnClass::LOG_SHIFT | InsnClass::EXTRACT | InsnClass::CONDSEL
            | InsnClass::CONDCMP_REG | InsnClass::DP_2SRC => {
                access.writes.push(gpr_name(bits, rd_rt, true));
                access.reads.push(gpr_name(bits, rn, true));
                access.reads.push(gpr_name(bits, rm, true));
            }
            InsnClass::CONDCMP_IMM => {
                access.reads.push(gpr_name(bits, rn, true));
            }
            InsnClass::DP_1SRC => {
                access.writes.push(gpr_name(bits, rd_rt, true));
                access.reads.push(gpr_name(bits, rn, true));
            }
            InsnClass::DP_3SRC => {
                access.writes.push(gpr_name(bits, rd_rt, true));
                access.reads.push(gpr_name(bits, rn, true));
                access.reads.push(gpr_name(bits, rm, true));
                access.reads.push(gpr_name(bits, rt2_ra, true)); // Ra (accumulator)
            }
            InsnClass::LDST_IMM9 | InsnClass::LDST_IMM10 | InsnClass::LDST_POS
            | InsnClass::LDST_UNSCALED | InsnClass::LDST_UNPRIV | InsnClass::LDSTEXCL => {
                access.reads.push(gpr_name(bits, rn, false));
                if mnemonic.starts_with("st") {
                    access.reads.push(gpr_name(bits, rd_rt, true));
                } else if mnemonic.starts_with("ld") {
                    access.writes.push(gpr_name(bits, rd_rt, true));
                }
            }
            InsnClass::LDST_REGOFF => {
                access.reads.push(gpr_name(bits, rn, false));
                access.reads.push(gpr_name(bits, rm, true));
                if mnemonic.starts_with("st") {
                    access.reads.push(gpr_name(bits, rd_rt, true));
                } else if mnemonic.starts_with("ld") {
                    access.writes.push(gpr_name(bits, rd_rt, true));
                }
            }
            InsnClass::LDSTPAIR_OFF | InsnClass::LDSTPAIR_INDEXED | InsnClass::LDSTNAPAIR_OFFS => {
                access.reads.push(gpr_name(bits, rn, false));
                if mnemonic.starts_with("st") {
                    access.reads.push(gpr_name(bits, rd_rt, true));
                    access.reads.push(gpr_name(bits, rt2_ra, true));
                } else if mnemonic.starts_with("ld") {
                    access.writes.push(gpr_name(bits, rd_rt, true));
                    access.writes.push(gpr_name(bits, rt2_ra, true));
                }
            }
            InsnClass::LOADLIT => {
                access.writes.push(gpr_name(bits, rd_rt, true));
            }
            InsnClass::COMPBRANCH | InsnClass::TESTBRANCH => {
                access.reads.push(gpr_name(bits, rd_rt, true));
            }
            InsnClass::BRANCH_REG => {
                if matches!(mnemonic, "br" | "blr") {
                    access.reads.push(gpr_name(bits, rn, true));
                }
            }
            _ => {}
        }
        access
    }

    fn prologues(&self) -> &'static [&'static [u8]] {
        ARM64_PROLOGUES
    }

    fn analyze_frame(&self, instrs: &[DecodedInsn]) -> FrameInfo {
        let mut frame = FrameInfo::default();
        // `stp x29, x30, [sp, #-N]!` — opcode 0xa9800000..=0xa9bf0000-ish family
        // with Rt=29(x29), Rt2=30(x30), Rn=31(sp), pre-indexed, negative
        // immediate. Matched structurally (decoded fields), not by raw byte
        // prefix, so it isn't limited to the four sizes `prologues()` lists.
        let Some(first) = instrs.first() else { return frame };
        if first.bytes.len() < 4 {
            return frame;
        }
        let bits = u32::from_le_bytes([first.bytes[0], first.bytes[1], first.bytes[2], first.bytes[3]]);
        let is_stp_pre = bits & 0xffc0_0000 == 0xa980_0000 && bitrange(bits, 24, 23) == 0b11;
        let rt = bitrange(bits, 4, 0);
        let rt2 = bitrange(bits, 14, 10);
        let rn = bitrange(bits, 9, 5);
        if is_stp_pre && rt == 29 && rt2 == 30 && rn == 31 {
            let imm7 = bitrange(bits, 21, 15);
            let disp = sign_extend(imm7, 7) * 8; // scaled by 8 for the 64-bit pair form
            frame.frame_size = (-disp) as u64;
            frame.spilled_regs.push("x29".to_string());
            frame.spilled_regs.push("x30".to_string());
            frame.prolog.push(first.va);
            // `mov x29, sp` (alias of `add x29, sp, #0`) commonly follows.
            if let Some(second) = instrs.get(1) {
                if second.mnemonic == "add" && second.text.trim_start().starts_with("mov") {
                    frame.uses_rbp = true;
                    frame.prolog.push(second.va);
                } else if second.bytes.len() == 4 {
                    let b2 = u32::from_le_bytes([second.bytes[0], second.bytes[1], second.bytes[2], second.bytes[3]]);
                    // `add x29, sp, #0` raw encoding (ADDSUB_IMM, Rd=29, Rn=31, imm12=0).
                    if b2 & 0xffc0_03ff == 0x9100_03fd {
                        frame.uses_rbp = true;
                        frame.prolog.push(second.va);
                    }
                }
            }
        }
        frame
    }

    fn detect_switch(&self, _block: &[DecodedInsn]) -> Option<SwitchDispatch> {
        None // ARM64 jump-table idioms differ from x64's; not implemented (documented in the module doc).
    }

    fn regs(&self) -> &RegisterFile {
        &self.regfile
    }

    fn calling_conventions(&self) -> &[CallConv] {
        std::slice::from_ref(&AAPCS64_CC)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le(bits: u32) -> Vec<u8> {
        bits.to_le_bytes().to_vec()
    }

    #[test]
    fn decodes_ret_as_ret_with_no_target() {
        let arch = Arm64::new();
        let di = arch.decode(&le(0xd65f03c0), Va(0x1000)).unwrap();
        assert_eq!(di.mnemonic, "ret");
        assert_eq!(di.kind, InsnKind::Ret);
        assert!(di.target.is_none());
    }

    #[test]
    fn decodes_unconditional_branch_with_resolved_target() {
        let arch = Arm64::new();
        // b <+8>: imm26 = 2 words = 8 bytes.
        let di = arch.decode(&le(0x14000000 | 2), Va(0x1000)).unwrap();
        assert_eq!(di.mnemonic, "b");
        assert_eq!(di.kind, InsnKind::Jump);
        assert_eq!(di.target, Some(Va(0x1008)));
    }

    #[test]
    fn decodes_bl_as_call_with_resolved_target() {
        let arch = Arm64::new();
        let di = arch.decode(&le(0x94000000 | 2), Va(0x2000)).unwrap();
        assert_eq!(di.mnemonic, "bl");
        assert_eq!(di.kind, InsnKind::Call);
        assert_eq!(di.target, Some(Va(0x2008)));
    }

    #[test]
    fn decodes_cbz_as_cond_jump_and_reads_the_tested_register() {
        let arch = Arm64::new();
        // cbz w0, <+8>: Rt=0, imm19=2 words.
        let bits = 0x34000000 | (2 << 5);
        let di = arch.decode(&le(bits), Va(0x1000)).unwrap();
        assert_eq!(di.kind, InsnKind::CondJump);
        assert_eq!(di.target, Some(Va(0x1008)));
        let access = arch.reg_access(&di);
        assert_eq!(access.reads, vec!["w0".to_string()]);
        assert!(access.writes.is_empty());
    }

    #[test]
    fn decodes_add_immediate_with_correct_def_use() {
        let arch = Arm64::new();
        // add w0, w0, #0 — verified against disarm64's own regression suite.
        let di = arch.decode(&le(0x11000000), Va(0x1000)).unwrap();
        assert_eq!(di.mnemonic, "add");
        assert_eq!(di.kind, InsnKind::Seq);
        let access = arch.reg_access(&di);
        assert_eq!(access.writes, vec!["w0".to_string()]);
        assert_eq!(access.reads, vec!["w0".to_string()]);
    }

    #[test]
    fn decodes_register_form_add_with_two_reads() {
        let arch = Arm64::new();
        // add w0, w0, w0 (ADDSUB_SHIFT, register form) — verified against
        // disarm64's regression suite (0x0b000000, "add\t\tw0, w0, w0").
        let di = arch.decode(&le(0x0b000000), Va(0x1000)).unwrap();
        let access = arch.reg_access(&di);
        assert_eq!(access.writes, vec!["w0".to_string()]);
        assert_eq!(access.reads, vec!["w0".to_string(), "w0".to_string()]);
    }

    #[test]
    fn recognizes_the_standard_frame_pointer_prolog() {
        // stp x29, x30, [sp, #-0x10]! ; add x29, sp, #0
        let stp_bits = 0xa9bf7bfdu32;
        let add_fp_bits = 0x9100_03fdu32;
        let arch = Arm64::new();
        let stp = arch.decode(&le(stp_bits), Va(0x1000)).expect("stp decodes");
        assert_eq!(stp.mnemonic, "stp", "expected the hand-derived prolog encoding to actually be stp");
        let add_fp = arch.decode(&le(add_fp_bits), Va(0x1004)).expect("add decodes");
        let frame = arch.analyze_frame(&[stp, add_fp]);
        assert_eq!(frame.frame_size, 16);
        assert!(frame.uses_rbp);
        assert_eq!(frame.spilled_regs, vec!["x29".to_string(), "x30".to_string()]);
        assert_eq!(frame.prolog.len(), 2);
    }

    #[test]
    fn all_zero_bytes_decode_as_udf_not_a_crash() {
        // 0x00000000 is the architecturally-reserved `udf #0` encoding — a
        // real, decodable instruction (a permanent trap), not a decode
        // failure, so this must succeed with InsnKind::Int (matching how
        // X64 classifies `int3`/`syscall`), not error.
        let arch = Arm64::new();
        let di = arch.decode(&le(0x00000000), Va(0x1000)).expect("udf decodes");
        assert_eq!(di.mnemonic, "udf");
        assert_eq!(di.kind, InsnKind::Int);
    }

    #[test]
    fn truncated_bytes_report_truncated() {
        let arch = Arm64::new();
        let err = arch.decode(&[0x01, 0x02], Va(0x1000));
        assert!(matches!(err, Err(DecodeError::Truncated(_))));
    }

    // The next three cases regression-test a real bug: `gpr_name`'s boolean
    // parameter, passed straight through to `disarm64::get_int_reg_name`'s
    // `with_zr`, was being set backwards for every register-form ALU/branch
    // operand, which any hand-picked single-instruction test happened not to
    // exercise. It surfaced only when a *real*, LLVM-compiled AArch64 object
    // file (`rustc --target aarch64-linux-android --emit=obj`, no hand-picked
    // bytes at all) decoded `xzr`-using idioms as reading/writing `sp`
    // instead — e.g. `madd x9, x9, x10, xzr` reported `reads: ["x9","x10","sp"]`.
    // These three encodings are the exact ones that caught it, still fixed
    // and cross-checked against `disarm64`'s own decoder output before being
    // hardcoded here (not re-derived by hand a second time).

    #[test]
    fn madd_reads_xzr_not_sp_for_a_discarded_accumulator() {
        let arch = Arm64::new();
        // madd x9, x9, x10, xzr — a real LLVM-emitted "x9 = x9*x10" idiom
        // (multiply-add with the accumulate operand discarded via xzr).
        let di = arch.decode(&le(0x9b0a7d29), Va(0x1000)).unwrap();
        assert_eq!(di.mnemonic, "madd");
        let access = arch.reg_access(&di);
        assert_eq!(access.reads, vec!["x9".to_string(), "x10".to_string(), "xzr".to_string()]);
        assert_eq!(access.writes, vec!["x9".to_string()]);
    }

    #[test]
    fn orr_with_xzr_operands_reads_xzr_not_sp() {
        let arch = Arm64::new();
        // orr x0, xzr, xzr — LLVM's "mov x0, #0" idiom (register-form ORR
        // with both source operands zeroed via xzr, not an immediate move).
        let di = arch.decode(&le(0xaa1f03e0), Va(0x1000)).unwrap();
        assert_eq!(di.mnemonic, "orr");
        let access = arch.reg_access(&di);
        assert_eq!(access.reads, vec!["xzr".to_string(), "xzr".to_string()]);
        assert_eq!(access.writes, vec!["x0".to_string()]);
    }

    #[test]
    fn addsub_imm_is_the_one_class_that_really_can_read_and_write_sp() {
        let arch = Arm64::new();
        // sub sp, sp, #0x20 — the standard stack-allocation prologue
        // instruction; ADDSUB_IMM's Rd/Rn are the only GPR positions in the
        // base ISA that can actually encode `sp` (register 31 elsewhere
        // always means `xzr`).
        let di = arch.decode(&le(0xd10083ff), Va(0x1000)).unwrap();
        assert_eq!(di.mnemonic, "sub");
        let access = arch.reg_access(&di);
        assert_eq!(access.reads, vec!["sp".to_string()]);
        assert_eq!(access.writes, vec!["sp".to_string()]);
    }
}
