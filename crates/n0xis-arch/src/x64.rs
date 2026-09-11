// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `X64` — the x86-64 implementation of [`Arch`], backed by `iced-x86`.
//!
//! Everything x64-specific lives in this file: the register table, the Win64
//! calling convention, the flow-control mapping. Nothing here touches the OS or
//! a memory source — bytes in, structure out.

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, InstructionInfoFactory,
    IntelFormatter, Mnemonic, OpAccess, OpKind, Register,
};
use n0xis_contracts::{Reg, Va};

use crate::frame::FrameInfo;
use crate::insn::{DecodeError, DecodedInsn, InsnKind};
use crate::switch::{SwitchDispatch, SwitchKind};
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
/// Win64 caller-saved vector registers: `xmm0`–`xmm5`. `xmm6`–`xmm15` are
/// callee-saved on this ABI (and only on this one) — an epilogue that restores
/// them is not a clobber, and listing them here would invalidate values a call
/// genuinely preserves.
static WIN64_VOLATILE_XMM: &[&str] = &["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"];
/// Win64 passes the first **four** arguments in registers, and a floating-point
/// one takes the vector register at its own position: `f(int, double)` uses
/// `rcx` and `xmm1`, leaving `xmm0` untouched.
static WIN64_FLOAT_ARGS: &[&str] = &["xmm0", "xmm1", "xmm2", "xmm3"];
static WIN64_CC: CallConv = CallConv {
    name: "win64",
    int_args: WIN64_INT_ARGS,
    ret: x64reg::RAX,
    volatile: WIN64_VOLATILE,
    ret_float: Some("xmm0"),
    volatile_float: WIN64_VOLATILE_XMM,
    ret_float_second: Some("xmm1"),
    float_args: WIN64_FLOAT_ARGS,
    float_args_share_position: true,
};

// System V AMD64 (Linux/macOS ELF) argument/return/volatile registers — the
// *other* x86-64 ABI. Integer args come in a different, six-register order, so
// a pass that assumed Win64 recovered the wrong parameters on an ELF target.
// Signature recovery selects between these by the source's declared ABI.
static SYSV_INT_ARGS: &[Reg] = &[x64reg::RDI, x64reg::RSI, x64reg::RDX, x64reg::RCX, x64reg::R8, x64reg::R9];
static SYSV_VOLATILE: &[Reg] = &[
    x64reg::RAX, x64reg::RCX, x64reg::RDX, x64reg::RSI, x64reg::RDI, x64reg::R8, x64reg::R9, x64reg::R10, x64reg::R11,
];
/// System V has **no** callee-saved vector registers: all sixteen are
/// caller-saved. The set differs from Win64's, which is why it is per-convention
/// data and not one shared list.
static SYSV_VOLATILE_XMM: &[&str] = &[
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12",
    "xmm13", "xmm14", "xmm15",
];
/// System V passes the first **eight** floating-point arguments in `xmm0`–`xmm7`,
/// counted independently of the six integer registers: `f(int, double)` uses
/// `rdi` and `xmm0`.
static SYSV_FLOAT_ARGS: &[&str] = &["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"];
static SYSV_CC: CallConv = CallConv {
    name: "sysv",
    int_args: SYSV_INT_ARGS,
    ret: x64reg::RAX,
    volatile: SYSV_VOLATILE,
    ret_float: Some("xmm0"),
    volatile_float: SYSV_VOLATILE_XMM,
    ret_float_second: Some("xmm1"),
    float_args: SYSV_FLOAT_ARGS,
    float_args_share_position: false,
};

/// Both x86-64 calling conventions, Win64 first. `calling_conventions()[0]`
/// stays Win64 (the lift's default), and signature recovery picks the entry
/// whose `name` matches the target's ABI (`MemorySource::abi_name`).
static X64_CCS: &[CallConv] = &[WIN64_CC, SYSV_CC];

// 32-bit i386 **cdecl**: all integer arguments are pushed on the stack (no
// argument *registers*), the result comes back in `eax`, and `eax`/`ecx`/`edx`
// are caller-saved. With an empty `int_args`, register-based argument recovery
// correctly finds zero args on a 32-bit target — the real args live in stack
// slots (`[esp+4]`, `[esp+8]`, …), whose recovery is a follow-on; conservative
// and sound, never a wrong register guess. (`stdcall`/`fastcall` differ only in
// who cleans the stack / two register args — added when arg recovery grows a
// stack model.)
static CDECL_INT_ARGS: &[Reg] = &[];
static CDECL_VOLATILE: &[Reg] = &[x64reg::RAX, x64reg::RCX, x64reg::RDX];
/// i386 caller-saved vector registers. The **return** is `None`: 32-bit cdecl
/// hands a `float`/`double` back on the x87 stack (`st0`), which this lift does
/// not model at all — claiming `xmm0` here would be a wrong answer dressed as a
/// right one.
static CDECL_VOLATILE_XMM: &[&str] = &["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"];
static CDECL_CC: CallConv = CallConv {
    name: "cdecl",
    int_args: CDECL_INT_ARGS,
    ret: x64reg::RAX,
    volatile: CDECL_VOLATILE,
    ret_float: None,
    volatile_float: CDECL_VOLATILE_XMM,
    ret_float_second: None,
    // i386 passes every argument on the stack, floating-point included. Not
    // "unmodelled" — the ABI genuinely has no floating-point argument
    // register, and listing one would invent parameters out of scratch use.
    float_args: &[],
    float_args_share_position: false,
};
static X86_CCS: &[CallConv] = &[CDECL_CC];

/// The x86 architecture (64-bit by default; 32-bit i386 via [`X64::x86`]). The
/// instruction *semantics* are shared — the same iced mnemonics lift identically
/// — so a single implementation serves both, parameterized by decoder
/// `bitness`. What 32-bit changes: the decoder reads 32-bit forms (e.g. `A1 mov
/// moffs` takes a 4-byte address, not 8, the very desync that made a PE32
/// decoded as x64 produce garbage), pointers are 4 bytes, and the calling
/// convention is stack-based cdecl rather than the Win64 register ABI.
#[derive(Clone, Copy, Debug)]
pub struct X64 {
    regfile: RegisterFile,
    bitness: u32,
}

impl X64 {
    pub const fn new() -> Self {
        X64 {
            regfile: RegisterFile::new(X64_REGS),
            bitness: 64,
        }
    }

    /// The rip-relative address a `lea` puts into `reg`, if that `lea` is the
    /// **most recent writer** of `reg` in `prefix`. Any other writer stops the
    /// search: the value in the register then came from somewhere this does not
    /// model, and a table address is not something to guess at.
    fn table_defined_before(&self, prefix: &[DecodedInsn], reg: &str) -> Option<Va> {
        for di in prefix.iter().rev() {
            let Some(ins) = decode_raw(di, self.bitness) else { continue };
            if ins.op_count() == 0 || ins.op0_kind() != OpKind::Register {
                continue;
            }
            if reg_name(ins.op0_register()) != reg {
                continue;
            }
            return (ins.mnemonic() == Mnemonic::Lea && ins.is_ip_rel_memory_operand())
                .then(|| Va(ins.ip_rel_memory_address()));
        }
        None
    }

    /// 32-bit (i386) mode — same register file and lift, decoder at 32-bit
    /// bitness. Selected by the frontend for a PE32 image.
    pub const fn x86() -> Self {
        X64 {
            regfile: RegisterFile::new(X64_REGS),
            bitness: 32,
        }
    }

    /// Decoder bitness (32 or 64).
    pub fn bitness(&self) -> u32 {
        self.bitness
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

/// The **vector** registers under the name the rest of the tool uses.
///
/// [`normalize_reg_x64`] folds `xmm0`/`ymm0`/`zmm0` onto one identity so a
/// write through any view is seen to destroy the others — and it picks the
/// widest spelling, `zmm0`, as that identity. Nothing else in the tool spells
/// it that way: the ABI's volatile lists, `function summary`'s clobbers,
/// `ir value-set`'s keys, the pseudocode and every disassembly line all say
/// `xmm0`, so `ir build` alone answered `"reads":["zmm0"]` next to its own
/// `"text":"addsd xmm0,xmm0"`.
///
/// Naming the whole physical register rather than the width one instruction
/// touched is the established rule here, not a new compromise: `mov al,1`
/// has always recorded a write to `rax`. This only settles *which* of the
/// three names that one register goes by, and the width actually written is
/// on the same object, in `text`.
static X64_DISPLAY_REGS: &[(&str, &str)] = &[
    ("zmm0", "xmm0"),
    ("zmm1", "xmm1"),
    ("zmm2", "xmm2"),
    ("zmm3", "xmm3"),
    ("zmm4", "xmm4"),
    ("zmm5", "xmm5"),
    ("zmm6", "xmm6"),
    ("zmm7", "xmm7"),
    ("zmm8", "xmm8"),
    ("zmm9", "xmm9"),
    ("zmm10", "xmm10"),
    ("zmm11", "xmm11"),
    ("zmm12", "xmm12"),
    ("zmm13", "xmm13"),
    ("zmm14", "xmm14"),
    ("zmm15", "xmm15"),
    ("zmm16", "xmm16"),
    ("zmm17", "xmm17"),
    ("zmm18", "xmm18"),
    ("zmm19", "xmm19"),
    ("zmm20", "xmm20"),
    ("zmm21", "xmm21"),
    ("zmm22", "xmm22"),
    ("zmm23", "xmm23"),
    ("zmm24", "xmm24"),
    ("zmm25", "xmm25"),
    ("zmm26", "xmm26"),
    ("zmm27", "xmm27"),
    ("zmm28", "xmm28"),
    ("zmm29", "xmm29"),
    ("zmm30", "xmm30"),
    ("zmm31", "xmm31"),
];

/// What **i386** calls the registers whose canonical name is a 64-bit
/// spelling — the vector rows above, plus the general-purpose ones.
///
/// The canonical identity is deliberately the 64-bit name — one token for
/// `al`/`ax`/`eax`/`rax` keeps every join honest — but it must not reach the
/// output of a 32-bit analysis, where no such register exists. `r8`–`r15` are
/// absent on purpose: they cannot occur in a 32-bit decode, so there is
/// nothing to translate and nothing to invent.
static X86_DISPLAY_REGS: &[(&str, &str)] = &[
    ("rax", "eax"),
    ("rbx", "ebx"),
    ("rcx", "ecx"),
    ("rdx", "edx"),
    ("rsi", "esi"),
    ("rdi", "edi"),
    ("rbp", "ebp"),
    ("rsp", "esp"),
    ("rip", "eip"),
    ("zmm0", "xmm0"),
    ("zmm1", "xmm1"),
    ("zmm2", "xmm2"),
    ("zmm3", "xmm3"),
    ("zmm4", "xmm4"),
    ("zmm5", "xmm5"),
    ("zmm6", "xmm6"),
    ("zmm7", "xmm7"),
    ("zmm8", "xmm8"),
    ("zmm9", "xmm9"),
    ("zmm10", "xmm10"),
    ("zmm11", "xmm11"),
    ("zmm12", "xmm12"),
    ("zmm13", "xmm13"),
    ("zmm14", "xmm14"),
    ("zmm15", "xmm15"),
    ("zmm16", "xmm16"),
    ("zmm17", "xmm17"),
    ("zmm18", "xmm18"),
    ("zmm19", "xmm19"),
    ("zmm20", "xmm20"),
    ("zmm21", "xmm21"),
    ("zmm22", "xmm22"),
    ("zmm23", "xmm23"),
    ("zmm24", "xmm24"),
    ("zmm25", "xmm25"),
    ("zmm26", "xmm26"),
    ("zmm27", "xmm27"),
    ("zmm28", "xmm28"),
    ("zmm29", "xmm29"),
    ("zmm30", "xmm30"),
    ("zmm31", "xmm31"),
];

/// Fold an x64 sub-register onto its 64-bit parent so callers can query by any
/// width. Mirrors the naming `reg_name` produces (iced's `full_register`), but
/// works from a string since a query register never comes from a decode.
fn normalize_reg_x64(reg: &str) -> String {
    let r = reg.trim().to_ascii_lowercase();
    match r.as_str() {
        "rax" | "eax" | "ax" | "al" | "ah" => "rax".into(),
        "rbx" | "ebx" | "bx" | "bl" | "bh" => "rbx".into(),
        "rcx" | "ecx" | "cx" | "cl" | "ch" => "rcx".into(),
        "rdx" | "edx" | "dx" | "dl" | "dh" => "rdx".into(),
        "rsi" | "esi" | "si" | "sil" => "rsi".into(),
        "rdi" | "edi" | "di" | "dil" => "rdi".into(),
        "rbp" | "ebp" | "bp" | "bpl" => "rbp".into(),
        "rsp" | "esp" | "sp" | "spl" => "rsp".into(),
        "rip" | "eip" | "ip" => "rip".into(),
        _ => {
            // The vector family is one physical register under three names:
            // `xmm0`, `ymm0` and `zmm0` are the 128-, 256- and 512-bit views of
            // the same thing, and writing any of them destroys the others. The
            // def-use records the widest (`zmm0`), while the micro-IR and every
            // disassembly line say `xmm0` — so the two seams had different names
            // for one register and nothing bridged them. `ir slice --reg xmm0`
            // on a function whose only instruction is `addsd xmm0,xmm1`
            // answered `node_count: 0`, and the ABI's clobber set never matched
            // a vector write at all.
            for prefix in ["xmm", "ymm", "zmm"] {
                if let Some(n) = r.strip_prefix(prefix)
                    && !n.is_empty()
                    && n.chars().all(|c| c.is_ascii_digit())
                {
                    return format!("zmm{n}");
                }
            }
            // r8..r15 and their d/w/b sub-registers (r8d, r9w, r10b, …).
            if let Some(n) = r.strip_prefix('r') {
                if n.chars().all(|c| c.is_ascii_digit()) {
                    return format!("r{n}");
                }
                if let Some(stem) = n.strip_suffix(['d', 'w', 'b'])
                    && !stem.is_empty()
                    && stem.chars().all(|c| c.is_ascii_digit())
                {
                    return format!("r{stem}");
                }
            }
            r
        }
    }
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.iter().any(|x| x == &s) {
        v.push(s);
    }
}

/// Re-decode a single `DecodedInsn` back to an iced [`Instruction`] from its
/// captured bytes. Used by structural recognizers (e.g. switch detection) that
/// need operand-level detail the neutral `DecodedInsn` intentionally omits.
fn decode_raw(insn: &DecodedInsn, bitness: u32) -> Option<Instruction> {
    let mut decoder = Decoder::with_ip(bitness, &insn.bytes, insn.va.0, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return None;
    }
    let instr = decoder.decode();
    if instr.is_invalid() {
        return None;
    }
    Some(instr)
}

/// The immediate value of operand 1, if it's an immediate of any encoded
/// width. Shared by switch-bound recovery and frame-size recovery — both are
/// "this instruction's second operand is a constant" checks.
fn imm_op1(instr: &Instruction) -> Option<u64> {
    match instr.op1_kind() {
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Some(instr.immediate(1)),
        _ => None,
    }
}

/// The immediate value of a `cmp`/`sub idx, imm` guard, if this instruction is
/// one. Powers switch-bound recovery.
impl X64 {
    /// The bound a jump table is guarded by, when it sits *before* the block
    /// that dispatches.
    ///
    /// `cmp $n, idx` / `ja default` is the canonical guard, and the conditional
    /// jump ends the block — so the comparison is never in the dispatch block
    /// itself. Looking only there left the table unbounded, and the walk then
    /// ran on into whatever followed it in memory.
    ///
    /// Deliberately narrow, because a wrong bound is worse than none: only the
    /// canonical shape counts — a `cmp`/`sub` against an immediate whose very
    /// next instruction is a conditional branch — and only within a short
    /// window, so an unrelated comparison further back cannot be mistaken for
    /// a guard.
    fn guard_before(&self, prefix: &[DecodedInsn]) -> Option<u64> {
        /// How far back the guard may sit. It is normally the last two
        /// instructions of the preceding block.
        const WINDOW: usize = 16;
        let from = prefix.len().saturating_sub(WINDOW);
        let window = &prefix[from..];
        window.iter().enumerate().rev().find_map(|(i, di)| {
            if !matches!(window.get(i + 1).map(|n| n.kind), Some(InsnKind::CondJump)) {
                return None;
            }
            guard_bound(&decode_raw(di, self.bitness)?)
        })
    }
}

fn guard_bound(instr: &Instruction) -> Option<u64> {
    if !matches!(instr.mnemonic(), Mnemonic::Cmp | Mnemonic::Sub)
        || instr.op_count() < 2
        || instr.op0_kind() != OpKind::Register
    {
        return None;
    }
    imm_op1(instr)
}

/// Whether an operand is relative to a thread base rather than the image.
///
/// In 64-bit mode `cs`/`ds`/`es`/`ss` have a zero base, so only `fs` and `gs`
/// move the operand out of the flat address space. Any pass that turns a
/// displacement into an address must ask this first.
pub(crate) fn segment_relative(instr: &Instruction) -> bool {
    matches!(instr.segment_prefix(), Register::FS | Register::GS)
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
    // A `fs:`/`gs:` override makes the computed value an offset from a
    // per-thread base, not an address in the image — reporting it as a
    // rip-relative target would invent a data reference. Measured zero times
    // across the verification corpus; guarded because the failure is silent.
    let rip_target = if instr.is_ip_rel_memory_operand() && !segment_relative(instr) {
        Some(Va(instr.ip_rel_memory_address()))
    } else {
        None
    };

    DecodedInsn {
        va: Va(instr.ip()),
        len: len as u8,
        bytes: raw,
        mnemonic,
        text,
        kind,
        target: direct_target(instr, kind),
        rip_target,
        cond: None,
        // `ret imm16` / `retf imm16`: the callee pops that many argument bytes
        // on the way out, which on a stack-argument ABI states the argument
        // size exactly. A plain `ret` has no operand and adjusts nothing.
        stack_adjust: match instr.mnemonic() {
            Mnemonic::Ret | Mnemonic::Retf if instr.op_count() > 0 => Some(instr.immediate16()),
            _ => None,
        },
    }
}

impl Arch for X64 {
    fn name(&self) -> &'static str {
        "x86-64"
    }

    /// The 32-bit and 64-bit x86 decoders are the same type with a different
    /// `bitness`, so the bitness has to be in the identity — otherwise a cache
    /// cannot tell one from the other.
    fn decoder_id(&self) -> String {
        format!("x86-{}", self.bitness)
    }

    /// Re-encode at a new address, fixing every position-dependent operand.
    ///
    /// `BlockEncoder` is the right tool and does the whole job: RIP-relative
    /// displacements are recomputed against the new instruction pointer, and a
    /// relative branch is re-encoded (widened if it no longer reaches). It
    /// refuses rather than truncating when a target cannot be expressed at all,
    /// which is exactly the contract this needs.
    fn relocate(&self, bytes: &[u8], from: Va, to: Va) -> Result<Vec<u8>, String> {
        if from == to {
            return Ok(bytes.to_vec());
        }
        let mut decoder = Decoder::with_ip(self.bitness, bytes, from.0, DecoderOptions::NONE);
        let mut instrs = Vec::new();
        while decoder.can_decode() {
            let insn = decoder.decode();
            if insn.is_invalid() {
                return Err(format!("byte {:#x} in the region to relocate does not decode", insn.ip()));
            }
            instrs.push(insn);
        }
        if instrs.is_empty() {
            return Err("nothing to relocate".to_string());
        }
        let block = iced_x86::InstructionBlock::new(&instrs, to.0);
        match iced_x86::BlockEncoder::encode(self.bitness, block, iced_x86::BlockEncoderOptions::NONE) {
            Ok(result) => Ok(result.code_buffer),
            Err(e) => Err(format!("cannot re-encode at {to}: {e}")),
        }
    }

    fn decode(&self, bytes: &[u8], va: Va) -> Result<DecodedInsn, DecodeError> {
        let mut decoder = Decoder::with_ip(self.bitness, bytes, va.0, DecoderOptions::NONE);
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
        let mut decoder = Decoder::with_ip(self.bitness, bytes, va.0, DecoderOptions::NONE);
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
        let mut decoder = Decoder::with_ip(self.bitness, &insn.bytes, insn.va.0, DecoderOptions::NONE);
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

    fn lift(&self, insn: &DecodedInsn, abi: &str) -> Vec<crate::MicroStmt> {
        crate::x64_lift::lift(self, insn, abi)
    }

    fn lift_tail_call(&self, insn: &DecodedInsn, abi: &str) -> Vec<crate::MicroStmt> {
        crate::x64_lift::lift_tail_call(self, insn, abi)
    }

    /// x86-64's condition codes *are* the vocabulary [`crate::flags`] speaks,
    /// so this forwards unchanged. An architecture that spells them otherwise
    /// translates first — see `Arm64::branch_condition`.
    fn branch_condition(&self, mnemonic: &str, flags_value: &crate::MicroExpr) -> crate::MicroExpr {
        crate::flags::branch_condition(mnemonic, flags_value)
    }

    fn normalize_reg(&self, reg: &str) -> String {
        normalize_reg_x64(reg)
    }

    /// 32-bit mode spells the canonical names as i386 does; in 64-bit mode the
    /// canonical spelling already *is* the target's, so the table is empty and
    /// the response walk that reads it does nothing.
    fn display_reg_map(&self) -> &'static [(&'static str, &'static str)] {
        if self.bitness == 32 { X86_DISPLAY_REGS } else { X64_DISPLAY_REGS }
    }

    /// Normalized to the full-width name the def-use records, so a 32-bit
    /// image's `esp` matches the `rsp` an access is recorded under.
    fn stack_pointer(&self) -> Option<&'static str> {
        Some("rsp")
    }

    fn prologues(&self, abi: &str) -> &'static [&'static [u8]] {
        // `mov [rsp+x], rbx` saves a callee-saved register into the caller's
        // **home space** — a Win64 concept. System V has no home space, so
        // under it those same bytes are an ordinary store into the callee's own
        // frame, and the commonest one of all: the stack-canary save that
        // follows `mov rbx, fs:[0x28]` in every protected function. Matching it
        // there does not find functions, it finds the middle of them — 3 993
        // false candidates against 3 true ones on one Qt build.
        if abi == "sysv" {
            return &[
                &[0x55, 0x48, 0x8B, 0xEC],
                &[0x55, 0x48, 0x89, 0xE5],
                &[0xF3, 0x0F, 0x1E, 0xFA],
                &[0x40, 0x53],
                &[0x48, 0x83, 0xEC],
                &[0x4C, 0x8B, 0xDC],
            ];
        }
        // Common Win64/MSVC & gnu x64 function entry idioms.
        &[
            &[0x55, 0x48, 0x8B, 0xEC], // push rbp; mov rbp, rsp  (MSVC encoding of the mov)
            // The SAME instruction pair as GCC/Clang encode it: `mov r/m64, r64`
            // (opcode 89) instead of MSVC's `mov r64, r/m64` (opcode 8B). Without
            // this the scan is blind to every frame-pointer function in an ELF —
            // the comment above claimed "gnu x64" while listing only the MSVC form.
            &[0x55, 0x48, 0x89, 0xE5], // push rbp; mov rbp, rsp  (GNU encoding)
            // `endbr64` — the CET landing pad modern GCC/Clang emit at the top of
            // essentially every function (`/usr/bin/gcc`: 4526 of them for 4461
            // functions). It also marks non-entry indirect-branch targets, so it is
            // a candidate hint, not proof; callers that need certainty validate a
            // candidate by building its CFG (see `provenance::find_function_containing`).
            &[0xF3, 0x0F, 0x1E, 0xFA], // endbr64
            &[0x40, 0x53],             // push rbx (REX)
            &[0x48, 0x89, 0x5C, 0x24], // mov [rsp+x], rbx (home-save)
            &[0x48, 0x83, 0xEC],       // sub rsp, imm8
            &[0x4C, 0x8B, 0xDC],       // mov r11, rsp
        ]
    }

    /// `endbr64` is the only x64 prologue byte sequence the *architecture*
    /// requires: with CET enabled, an indirect branch to anything else faults.
    /// Its precision reflects that — on one Qt build it matched 13 632 real
    /// starts against 8 false, where `sub rsp, imm8` matched 183 against 4 167.
    /// So it is trusted inside a declared extent, where the weak patterns are
    /// not: that is what keeps a multi-entry unwind range (glibc's `tlsdesc`
    /// helpers share one) from collapsing to its first entry, and it costs 3
    /// false candidates on the whole of that Qt build.
    fn entry_markers(&self) -> &'static [&'static [u8]] {
        &[&[0xF3, 0x0F, 0x1E, 0xFA]]
    }

    /// x86-64 toolchains align function entries to 16 bytes by default
    /// (`-falign-functions=16`, and MSVC's equivalent). Measured on one Qt
    /// build: starts confirmed by `.dynsym` or an `.eh_frame` FDE are aligned
    /// 99.3-99.8% of the time; unconfirmed prologue matches, 10.5%.
    fn entry_alignment(&self) -> u64 {
        16
    }

    fn detect_switch_with_context(&self, insns: &[DecodedInsn], block_start: usize) -> Option<SwitchDispatch> {
        let mut d = self.detect_switch(insns.get(block_start..)?)?;
        if d.bound.is_none() {
            d.bound = self.guard_before(&insns[..block_start]);
        }
        // The table base, when a loop hoisted its `lea` out of the dispatching
        // block. Searched **by register**, back to that register's most recent
        // definition and no further: if the instruction that last wrote it is
        // the `lea`, that is the table; if it is anything else, there is no
        // answer here and the dispatch stays unresolved. Widening the scan
        // instead would eventually find *some* `lea [rip+…]` and call it a
        // table, which is invented control flow — the one failure a CFG cannot
        // recover from.
        if d.table.is_none()
            && let Some(base) = d.base_reg.as_deref()
        {
            d.table = self.table_defined_before(&insns[..block_start], base);
        }
        Some(d)
    }

    fn detect_switch(&self, block: &[DecodedInsn]) -> Option<SwitchDispatch> {
        let (term_idx, term_di) = block.iter().enumerate().next_back()?;
        let term = decode_raw(term_di, self.bitness)?;
        if term.flow_control() != FlowControl::IndirectBranch {
            return None;
        }

        // The bound comes from the most recent `cmp`/`sub idx, imm` in the block.
        let bound = block[..term_idx]
            .iter()
            .rev()
            .filter_map(|di| decode_raw(di, self.bitness))
            .find_map(|ins| guard_bound(&ins));

        // Form 1: `jmp [table + idx*scale]` — the table holds absolute pointers.
        // The base is a rip-relative address (PIE) or an absolute displacement
        // (non-PIE `jmp [disp32 + idx*8]`). A register base can't be resolved
        // statically, so `table` stays `None` and only the shape is reported.
        if term.op0_kind() == OpKind::Memory && term.memory_index() != Register::None {
            let table = if segment_relative(&term) {
                // Thread-relative: the displacement is not an image address, so
                // no table can be read from it. Reporting one would invent
                // control flow, which is worse than reporting the shape alone.
                None
            } else if term.is_ip_rel_memory_operand() {
                Some(Va(term.ip_rel_memory_address()))
            } else if term.memory_base() == Register::None {
                Some(Va(term.memory_displacement64()))
            } else {
                None
            };
            return Some(SwitchDispatch {
                at: term_di.va,
                kind: SwitchKind::MemIndexed,
                table,
                index_reg: Some(reg_name(term.memory_index())),
                scale: term.memory_index_scale(),
                bound,
                base_reg: (term.memory_base() != Register::None)
                    .then(|| reg_name(term.memory_base())),
            });
        }

        // Form 2: `jmp <reg>` — back-scan for the MSVC rel32 table pattern.
        if term.op0_kind() == OpKind::Register {
            let mut table: Option<Va> = None;
            let mut index_reg: Option<String> = None;
            let mut base_reg: Option<String> = None;
            let mut scale: u32 = 0;
            for di in block[..term_idx].iter().rev() {
                let Some(ins) = decode_raw(di, self.bitness) else { continue };
                // `mov`/`movsxd r,[base + idx*scale]` discloses index + scale,
                // and names the register the table base lives in — which is the
                // only way to find that base when a loop hoisted its `lea` out
                // of this block.
                if index_reg.is_none() && ins.memory_index() != Register::None {
                    index_reg = Some(reg_name(ins.memory_index()));
                    scale = ins.memory_index_scale();
                    if ins.memory_base() != Register::None {
                        base_reg = Some(reg_name(ins.memory_base()));
                    }
                }
                // `lea reg,[rip+disp]` sets the table base.
                if table.is_none()
                    && ins.mnemonic() == Mnemonic::Lea
                    && ins.is_ip_rel_memory_operand()
                {
                    table = Some(Va(ins.ip_rel_memory_address()));
                }
                if table.is_some() && index_reg.is_some() {
                    break;
                }
            }
            if table.is_some() || index_reg.is_some() {
                return Some(SwitchDispatch {
                    at: term_di.va,
                    kind: SwitchKind::RegRel32,
                    table,
                    index_reg,
                    scale,
                    bound,
                    base_reg,
                });
            }
        }

        None
    }

    fn analyze_frame(&self, instrs: &[DecodedInsn]) -> FrameInfo {
        let mut out = FrameInfo::default();
        // Cap the scan (v0-proven heuristic): a real prolog finishes in a
        // handful of instructions, so a longer run means we've walked past it
        // into the function body without matching anything else.
        for di in instrs.iter().take(16) {
            let Some(ins) = decode_raw(di, self.bitness) else { continue };
            let recognized = match ins.mnemonic() {
                Mnemonic::Push if ins.op0_kind() == OpKind::Register => {
                    push_unique(&mut out.spilled_regs, reg_name(ins.op0_register()));
                    true
                }
                Mnemonic::Sub if ins.op0_register() == Register::RSP => {
                    if let Some(v) = imm_op1(&ins) {
                        out.frame_size = v;
                    }
                    true
                }
                Mnemonic::Mov
                    if ins.op0_register() == Register::RBP
                        && ins.op1_register() == Register::RSP =>
                {
                    out.uses_rbp = true;
                    true
                }
                // Home-space stores: `mov [rsp+disp], reg`.
                Mnemonic::Mov
                    if ins.op0_kind() == OpKind::Memory && ins.memory_base() == Register::RSP =>
                {
                    true
                }
                _ => false,
            };
            if recognized {
                out.prolog.push(di.va);
            } else if !out.prolog.is_empty() {
                break;
            }
        }
        out
    }

    fn regs(&self) -> &RegisterFile {
        &self.regfile
    }

    fn pointer_size(&self) -> u8 {
        (self.bitness / 8) as u8
    }

    fn calling_conventions(&self) -> &[CallConv] {
        if self.bitness == 32 {
            X86_CCS
        } else {
            X64_CCS
        }
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
    fn a_thread_relative_operand_is_not_a_data_reference() {
        // 64 48 8B 05 10 00 00 00 = mov rax, fs:[rip+0x10]
        // Same bytes without the 64 prefix name an address in the image; with
        // it the displacement is an offset from the thread base, and calling it
        // a rip-relative target would invent a cross-reference.
        let arch = X64::new();
        let seg = arch.decode_stream(&[0x64, 0x48, 0x8B, 0x05, 0x10, 0, 0, 0], Va(0x1000), 1);
        assert_eq!(seg[0].rip_target, None, "fs-relative, so no image address");

        let flat = arch.decode_stream(&[0x48, 0x8B, 0x05, 0x10, 0, 0, 0], Va(0x1000), 1);
        assert_eq!(flat[0].rip_target, Some(Va(0x1017)), "the same operand, flat");
    }

    #[test]
    fn a_thread_relative_jump_reports_no_table() {
        // 64 FF 24 C5 00 10 00 00 = jmp qword ptr fs:[rax*8 + 0x1000]
        // A table address read out of a thread-relative displacement would be
        // read from the wrong place and turn into invented control flow.
        let arch = X64::new();
        let seg = arch.decode_stream(&[0x64, 0xFF, 0x24, 0xC5, 0x00, 0x10, 0, 0], Va(0x1000), 1);
        let d = arch.detect_switch(&seg).expect("the shape is still a switch dispatch");
        assert_eq!(d.table, None, "no table can be read from a thread-relative base");

        let flat = arch.decode_stream(&[0xFF, 0x24, 0xC5, 0x00, 0x10, 0, 0], Va(0x1000), 1);
        let d = arch.detect_switch(&flat).expect("switch dispatch");
        assert_eq!(d.table, Some(Va(0x1000)), "the same dispatch, flat");
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

    #[test]
    fn exposes_both_win64_and_system_v_conventions() {
        // Win64 stays first (the lift's default). System V is selectable by
        // name and puts its integer args in the different rdi/rsi/… order —
        // this is what lets signature recovery get an ELF's parameters right.
        let arch = X64::new();
        let ccs = arch.calling_conventions();
        let win64 = ccs.iter().find(|c| c.name == "win64").expect("win64 cc");
        let sysv = ccs.iter().find(|c| c.name == "sysv").expect("sysv cc");
        assert_eq!(ccs[0].name, "win64", "the lift's default must stay Win64");
        assert_eq!(win64.int_args, &[x64reg::RCX, x64reg::RDX, x64reg::R8, x64reg::R9]);
        assert_eq!(sysv.int_args, &[x64reg::RDI, x64reg::RSI, x64reg::RDX, x64reg::RCX, x64reg::R8, x64reg::R9]);
    }
    /// A register name in an answer is a **claim about the target**. The
    /// canonical name is a 64-bit spelling — right as an identity, false as a
    /// claim on a 32-bit image, where `rax` and `rsp` are not registers of the
    /// machine. One `ir build` object shipped `"text":"sub esp,0Ch"` beside
    /// `"reads":["rsp"]`; `function summary` answered `clobbers:["rax"]`.
    #[test]
    fn a_32_bit_target_is_never_told_about_a_register_it_has_not_got() {
        let x86 = X64::x86();
        assert_eq!(x86.display_reg("rsp"), "esp");
        assert_eq!(x86.display_reg("rax"), "eax");
        assert_eq!(x86.display_reg("rip"), "eip");
        // Not in the table and not invented: `r8` cannot occur in a 32-bit decode.
        assert_eq!(x86.display_reg("r8"), "r8");
        // Not a register at all — a local, a temp, anything else — passes through.
        assert_eq!(x86.display_reg("local_18"), "local_18");
    }

    /// One register, one name. `normalize_reg` folds `xmm0`/`ymm0`/`zmm0` onto
    /// the widest spelling so a write through any view is seen to destroy the
    /// others; nothing else in the tool says `zmm0`, so `ir build` alone
    /// answered `"reads":["zmm0"]` next to its own `"text":"addsd xmm0,xmm0"`
    /// while `function summary`, `ir value-set`, the pseudocode and every
    /// disassembly line said `xmm0`.
    #[test]
    fn the_vector_register_has_the_same_name_in_an_answer_as_in_the_disassembly() {
        assert_eq!(X64::new().display_reg("zmm0"), "xmm0");
        assert_eq!(X64::new().display_reg("zmm15"), "xmm15");
        assert_eq!(X64::x86().display_reg("zmm7"), "xmm7");
        // Identity for a 64-bit target's general-purpose registers: `rax` is
        // what an x86-64 machine calls it.
        assert_eq!(X64::new().display_reg("rax"), "rax");
    }

    /// The response walk that applies the spelling asks the table whether there
    /// is anything to do. An empty table would silently turn the whole thing
    /// into a no-op, which is how this class comes back.
    #[test]
    fn both_modes_declare_something_to_spell_so_the_boundary_walk_runs() {
        assert!(!X64::new().display_reg_map().is_empty());
        assert!(!X64::x86().display_reg_map().is_empty());
    }

}
