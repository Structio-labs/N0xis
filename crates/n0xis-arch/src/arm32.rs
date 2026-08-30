//! `Arm32` — AArch32 / ARMv7 (A32 + Thumb), decode-only, via `yaxpeax-arm`.
//!
//! Our [`Arm64`](crate::Arm64) arch (disarm64) decodes **AArch64 only**; the
//! 32-bit ARM targets that matter here — Android `armeabi-v7a`, the X96 TV-box
//! (`armv7l`) — are a different instruction set it cannot read. This is a
//! *disassembler* for them: correct decode (A32 by default, Thumb via
//! [`Arm32::thumb`]), a best-effort control-flow classification for the CFG, and
//! the default (Unlifted) micro-IR — so `disasm`/`ir` work today while a full
//! A32/Thumb **semantic lift** (every instruction → typed micro-IR) is a
//! follow-on Phase. The register model (`r0`-`r15`) and AAPCS32 are declared so
//! that lift, when it lands, has them; nothing is hardcoded in a pass.

use yaxpeax_arch::{Decoder, LengthedInstruction, U8Reader};
use yaxpeax_arm::armv7::{InstDecoder, Instruction, Opcode};

use n0xis_contracts::{Reg, Va};

use crate::insn::{DecodeError, DecodedInsn, InsnKind};
use crate::{Arch, CallConv, RegDesc, RegisterFile};

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
        Ok(DecodedInsn { va, len: len as u8, bytes: bytes[..len].to_vec(), mnemonic, text, kind, target: None, rip_target: None })
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
    fn thumb_uses_two_byte_instructions() {
        // 4770 bx lr (Thumb) — a 2-byte instruction, unlike A32's fixed 4.
        let t = Arm32::thumb();
        let bx = dis(&t, &[0x70, 0x47]);
        assert_eq!(bx.mnemonic, "bx");
        assert_eq!(bx.len, 2);
    }

    #[test]
    fn arm32_is_32bit_with_the_aapcs32_abi() {
        let a = Arm32::a32();
        assert_eq!(a.pointer_size(), 4);
        assert_eq!(a.calling_conventions()[0].name, "aapcs32");
        assert!(a.regs().by_name("lr").is_some());
    }
}
