//! `X64` — the x86-64 implementation of [`Arch`], backed by `iced-x86`.
//!
//! Everything x64-specific lives in this file: the register table, the Win64
//! calling convention, the flow-control mapping. Nothing here touches the OS or
//! a memory source — bytes in, structure out.

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, InstructionInfoFactory,
    IntelFormatter, OpAccess, Register,
};
use n0xis_contracts::{Reg, Va};

use crate::insn::{DecodeError, DecodedInsn, InsnKind};
use crate::{Arch, CallConv, RegAccess, RegDesc, RegisterFile};

/// Interned register ids for x86-64. Passes refer to registers *only* through
/// these ids resolved against the [`RegisterFile`] — never by name literal.
pub mod x64reg {
    use n0xis_contracts::Reg;
    pub const RAX: Reg = Reg(0);
    pub const RCX: Reg = Reg(1);
    pub const RDX: Reg = Reg(2);
    pub const RBX: Reg = Reg(3);
    pub const RSP: Reg = Reg(4);
    pub const RBP: Reg = Reg(5);
    pub const RSI: Reg = Reg(6);
    pub const RDI: Reg = Reg(7);
    pub const R8: Reg = Reg(8);
    pub const R9: Reg = Reg(9);
    pub const R10: Reg = Reg(10);
    pub const R11: Reg = Reg(11);
    pub const R12: Reg = Reg(12);
    pub const R13: Reg = Reg(13);
    pub const R14: Reg = Reg(14);
    pub const R15: Reg = Reg(15);
}

static X64_REGS: &[RegDesc] = &[
    RegDesc { id: x64reg::RAX, name: "rax", size_bits: 64 },
    RegDesc { id: x64reg::RCX, name: "rcx", size_bits: 64 },
    RegDesc { id: x64reg::RDX, name: "rdx", size_bits: 64 },
    RegDesc { id: x64reg::RBX, name: "rbx", size_bits: 64 },
    RegDesc { id: x64reg::RSP, name: "rsp", size_bits: 64 },
    RegDesc { id: x64reg::RBP, name: "rbp", size_bits: 64 },
    RegDesc { id: x64reg::RSI, name: "rsi", size_bits: 64 },
    RegDesc { id: x64reg::RDI, name: "rdi", size_bits: 64 },
    RegDesc { id: x64reg::R8, name: "r8", size_bits: 64 },
    RegDesc { id: x64reg::R9, name: "r9", size_bits: 64 },
    RegDesc { id: x64reg::R10, name: "r10", size_bits: 64 },
    RegDesc { id: x64reg::R11, name: "r11", size_bits: 64 },
    RegDesc { id: x64reg::R12, name: "r12", size_bits: 64 },
    RegDesc { id: x64reg::R13, name: "r13", size_bits: 64 },
    RegDesc { id: x64reg::R14, name: "r14", size_bits: 64 },
    RegDesc { id: x64reg::R15, name: "r15", size_bits: 64 },
];

// Win64 argument/return/volatile registers — the ABI fact that must never be
// baked into a pass. Signature recovery (Phase 4) reads it from here.
static WIN64_INT_ARGS: &[Reg] = &[x64reg::RCX, x64reg::RDX, x64reg::R8, x64reg::R9];
static WIN64_VOLATILE: &[Reg] = &[
    x64reg::RAX, x64reg::RCX, x64reg::RDX, x64reg::R8, x64reg::R9, x64reg::R10, x64reg::R11,
];
static WIN64_CC: CallConv = CallConv {
    name: "win64",
    int_args: WIN64_INT_ARGS,
    ret: x64reg::RAX,
    volatile: WIN64_VOLATILE,
};

/// The x86-64 architecture.
#[derive(Clone, Copy, Debug)]
pub struct X64 {
    regfile: RegisterFile,
}

impl X64 {
    pub const fn new() -> Self {
        X64 {
            regfile: RegisterFile::new(X64_REGS),
        }
    }
}

impl Default for X64 {
    fn default() -> Self {
        X64::new()
    }
}

/// Full-width, lowercased register name (`eax`/`al` → `rax`). Empty for
/// `Register::None` so callers can skip it.
fn reg_name(r: Register) -> String {
    if r == Register::None {
        return String::new();
    }
    format!("{:?}", r.full_register()).to_lowercase()
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.iter().any(|x| x == &s) {
        v.push(s);
    }
}

fn classify(instr: &Instruction) -> InsnKind {
    if instr.is_invalid() {
        return InsnKind::Invalid;
    }
    match instr.flow_control() {
        FlowControl::Next => InsnKind::Seq,
        FlowControl::Call | FlowControl::IndirectCall => InsnKind::Call,
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => InsnKind::Jump,
        FlowControl::ConditionalBranch => InsnKind::CondJump,
        FlowControl::Return => InsnKind::Ret,
        FlowControl::Interrupt => InsnKind::Int,
        _ => InsnKind::Other,
    }
}

/// Direct near branch/call target, if the instruction has one.
fn direct_target(instr: &Instruction, kind: InsnKind) -> Option<Va> {
    use iced_x86::OpKind;
    if !matches!(kind, InsnKind::Call | InsnKind::Jump | InsnKind::CondJump) {
        return None;
    }
    match instr.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(Va(instr.near_branch_target()))
        }
        _ => None,
    }
}

fn build_insn(
    instr: &Instruction,
    all_bytes: &[u8],
    base_va: Va,
    fmt: &mut IntelFormatter,
) -> DecodedInsn {
    let mut text = String::new();
    fmt.format(instr, &mut text);

    let len = instr.len();
    let offset = (instr.ip() - base_va.0) as usize;
    let raw = all_bytes
        .get(offset..offset + len)
        .unwrap_or(&[])
        .to_vec();

    let kind = classify(instr);
    let mnemonic = format!("{:?}", instr.mnemonic()).to_lowercase();

    DecodedInsn {
        va: Va(instr.ip()),
        len: len as u8,
        bytes: raw,
        mnemonic,
        text,
        kind,
        target: direct_target(instr, kind),
    }
}

impl Arch for X64 {
    fn name(&self) -> &'static str {
        "x86-64"
    }

    fn decode(&self, bytes: &[u8], va: Va) -> Result<DecodedInsn, DecodeError> {
        let mut decoder = Decoder::with_ip(64, bytes, va.0, DecoderOptions::NONE);
        if !decoder.can_decode() {
            return Err(DecodeError::Truncated(va));
        }
        let instr = decoder.decode();
        if instr.is_invalid() {
            return Err(DecodeError::Invalid(va));
        }
        let mut fmt = IntelFormatter::new();
        Ok(build_insn(&instr, bytes, va, &mut fmt))
    }

    fn decode_stream(&self, bytes: &[u8], va: Va, max: usize) -> Vec<DecodedInsn> {
        let mut decoder = Decoder::with_ip(64, bytes, va.0, DecoderOptions::NONE);
        let mut fmt = IntelFormatter::new();
        let mut out = Vec::new();
        let mut instr = Instruction::default();
        while decoder.can_decode() && out.len() < max {
            decoder.decode_out(&mut instr);
            let di = build_insn(&instr, bytes, va, &mut fmt);
            let invalid = di.kind == InsnKind::Invalid;
            out.push(di);
            if invalid {
                break;
            }
        }
        out
    }

    fn reg_access(&self, insn: &DecodedInsn) -> RegAccess {
        let mut decoder = Decoder::with_ip(64, &insn.bytes, insn.va.0, DecoderOptions::NONE);
        if !decoder.can_decode() {
            return RegAccess::default();
        }
        let instr = decoder.decode();
        let mut factory = InstructionInfoFactory::new();
        let info = factory.info(&instr);

        let mut access = RegAccess::default();
        for u in info.used_registers() {
            let name = reg_name(u.register());
            if name.is_empty() {
                continue;
            }
            match u.access() {
                OpAccess::Read | OpAccess::CondRead => push_unique(&mut access.reads, name),
                OpAccess::Write | OpAccess::CondWrite => push_unique(&mut access.writes, name),
                OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                    push_unique(&mut access.reads, name.clone());
                    push_unique(&mut access.writes, name);
                }
                _ => {}
            }
        }
        access
    }

    fn regs(&self) -> &RegisterFile {
        &self.regfile
    }

    fn calling_conventions(&self) -> &[CallConv] {
        std::slice::from_ref(&WIN64_CC)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_mov_and_ret() {
        // 48 89 C8 = mov rax, rcx ; C3 = ret
        let bytes = [0x48u8, 0x89, 0xC8, 0xC3];
        let arch = X64::new();
        let insns = arch.decode_stream(&bytes, Va(0x1000), 16);
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].mnemonic, "mov");
        assert!(insns[0].text.contains("rax"));
        assert!(insns[0].text.contains("rcx"));
        assert_eq!(insns[0].va, Va(0x1000));
        assert_eq!(insns[0].len, 3);
        assert_eq!(insns[1].kind, InsnKind::Ret);
    }

    #[test]
    fn resolves_direct_jump_target() {
        // EB 02 = jmp +2 from 0x1000 → next ip 0x1002 + 2 = 0x1004
        let bytes = [0xEBu8, 0x02];
        let arch = X64::new();
        let insns = arch.decode_stream(&bytes, Va(0x1000), 4);
        assert_eq!(insns[0].kind, InsnKind::Jump);
        assert_eq!(insns[0].target, Some(Va(0x1004)));
    }

    #[test]
    fn register_file_maps_ids_and_names() {
        let arch = X64::new();
        assert_eq!(arch.regs().name(x64reg::RCX), Some("rcx"));
        assert_eq!(arch.regs().by_name("R8"), Some(x64reg::R8));
        assert_eq!(arch.calling_conventions()[0].int_args[0], x64reg::RCX);
    }
}
