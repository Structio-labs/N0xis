//! # n0xis-arch — the ISA seam
//!
//! Abstracts an instruction-set architecture behind [`Arch`]. The analysis in
//! `n0xis-core` depends only on this trait, never on a concrete ISA — so all
//! x64/Win64 knowledge (register model, calling conventions, flag semantics)
//! is confined here. That confinement is the whole point: in v0, x64 facts
//! leaked into the passes and made a second architecture impossible. This seam
//! makes ARM64 a matter of adding an `impl Arch`, not a rewrite.
//!
//! Phase 1 shipped the [`X64`] decoder (real, via `iced-x86`) and the register
//! / calling-convention model. Phase 3 fills in [`Arch::lift`] with a real
//! typed micro-IR ([`MicroStmt`] / [`MicroExpr`]) and adds
//! [`Arch::branch_condition`], the seam that turns a `Jcc` + the dataflow
//! value reaching it into an exact condition expression.

mod arm64;
mod frame;
mod insn;
mod microir;
mod switch;
mod x64;
mod x64_lift;

pub use arm64::{Arm64, arm64reg};
pub use frame::FrameInfo;
pub use insn::{DecodeError, DecodedInsn, InsnKind};
pub use microir::{BinOp, Bits, CallTarget, CmpKind, MicroExpr, MicroStmt, UnOp, FLAGS_VAR};
pub use switch::{SwitchDispatch, SwitchKind};
pub use x64::{X64, x64reg};

use n0xis_contracts::{Reg, Va};

/// Registers an instruction reads and writes, normalized to full-width names
/// (e.g. `eax`/`al` → `rax`). Names, not [`Reg`] ids, because def-use tracking
/// spans more than the 16 GPRs (flags, xmm, segment) and the typed [`Reg`]
/// model is reserved for the SSA IR (Phase 3). Produced by the arch so the
/// passes never touch an ISA decoder.
#[derive(Clone, Debug, Default)]
pub struct RegAccess {
    pub reads: Vec<String>,
    pub writes: Vec<String>,
}

/// One register description: its interned id, canonical name, and width.
#[derive(Clone, Copy, Debug)]
pub struct RegDesc {
    pub id: Reg,
    pub name: &'static str,
    pub size_bits: u16,
}

/// The register model of an architecture: the id↔name mapping the passes are
/// forbidden from hardcoding.
#[derive(Clone, Copy, Debug)]
pub struct RegisterFile {
    regs: &'static [RegDesc],
}

impl RegisterFile {
    pub const fn new(regs: &'static [RegDesc]) -> Self {
        RegisterFile { regs }
    }
    pub fn all(&self) -> &'static [RegDesc] {
        self.regs
    }
    pub fn name(&self, r: Reg) -> Option<&'static str> {
        self.regs.iter().find(|d| d.id == r).map(|d| d.name)
    }
    pub fn by_name(&self, name: &str) -> Option<Reg> {
        self.regs
            .iter()
            .find(|d| d.name.eq_ignore_ascii_case(name))
            .map(|d| d.id)
    }
}

/// A calling convention: how arguments and returns map to registers. Used by
/// signature recovery (Phase 4) — kept in the arch, never in the passes.
#[derive(Clone, Copy, Debug)]
pub struct CallConv {
    pub name: &'static str,
    /// Integer/pointer argument registers, in order.
    pub int_args: &'static [Reg],
    /// Integer return register.
    pub ret: Reg,
    /// Caller-saved (volatile) registers.
    pub volatile: &'static [Reg],
}

/// The ISA abstraction the analysis core is written against.
///
/// **Boundary rule:** implementors may touch `iced-x86` or any ISA library;
/// they must not touch the OS, I/O, or a memory source. Bytes come *in*;
/// decoded/lifted structure comes *out*.
pub trait Arch {
    /// Short stable id, e.g. `"x86-64"`.
    fn name(&self) -> &'static str;

    /// Native pointer size in bytes.
    fn pointer_size(&self) -> u8 {
        8
    }

    /// Decode exactly one instruction at `va` from the front of `bytes`.
    fn decode(&self, bytes: &[u8], va: Va) -> Result<DecodedInsn, DecodeError>;

    /// Decode a linear run of up to `max` instructions starting at `va`. Stops
    /// at the end of `bytes` or on the first invalid instruction (which is
    /// still emitted, marked [`InsnKind::Invalid`], so nothing is dropped).
    fn decode_stream(&self, bytes: &[u8], va: Va, max: usize) -> Vec<DecodedInsn>;

    /// Lower one instruction to micro-IR. Default: preserves the instruction
    /// verbatim (sound, uninterpreted) — ISA impls override per-mnemonic.
    fn lift(&self, insn: &DecodedInsn) -> Vec<MicroStmt> {
        vec![MicroStmt::Unlifted { va: insn.va, text: insn.text.clone() }]
    }

    /// Lower a **tail call** — a branch the CFG determined leaves the current
    /// function (`jmp func`, or an import thunk's `jmp [iat_slot]`) — to
    /// micro-IR. Semantically it is `return f(args)`, not a branch: the callee
    /// runs on this frame and its result becomes this function's result.
    /// [`Arch::lift`] cannot make that call — it sees one instruction, not the
    /// function bounds — so the core routes the terminating instruction of a
    /// `tail-call` block here instead.
    ///
    /// Default: whatever `lift` produces, i.e. no promotion. An ISA with no
    /// override keeps the honest "structural edge only" behavior rather than
    /// synthesizing a call it has no lowering for.
    fn lift_tail_call(&self, insn: &DecodedInsn) -> Vec<MicroStmt> {
        self.lift(insn)
    }

    /// Turn a conditional-branch mnemonic (`"je"`, `"jg"`, …) plus the
    /// dataflow value reaching it for [`FLAGS_VAR`] into an exact condition
    /// expression. Only sound when `flags_value` is the precise
    /// [`MicroExpr::Compare`] the mnemonic expects; anything else (an
    /// [`MicroExpr::OpaqueFlags`] from an intervening flag-setter with no
    /// following `cmp`/`test`) must render a placeholder, never a guess —
    /// this is the seam that fixes v0's "stale last-compare" bug structurally
    /// rather than heuristically. Default: always a placeholder (an ISA with
    /// no override has no condition-code knowledge to give).
    fn branch_condition(&self, mnemonic: &str, flags_value: &MicroExpr) -> MicroExpr {
        let _ = flags_value;
        MicroExpr::Unknown(format!("cond({mnemonic})"))
    }

    /// Registers read/written by an instruction, normalized to full width.
    /// Default is empty; ISA impls override. Used by def-use analysis in the
    /// core without the passes ever seeing a decoder.
    fn reg_access(&self, _insn: &DecodedInsn) -> RegAccess {
        RegAccess::default()
    }

    /// Canonicalize a register name to this ISA's full-width form, so a query
    /// for `eax`/`ax`/`al` matches a def-use recorded as `rax`. Lets analyses
    /// (e.g. the backward slice) compare a user-supplied register against the
    /// normalized names in [`RegAccess`] without knowing the ISA's aliasing.
    /// Default: trimmed + lowercased (identity for canonical names).
    fn normalize_reg(&self, reg: &str) -> String {
        reg.trim().to_ascii_lowercase()
    }

    /// Byte patterns that commonly begin a function (prologues), used by
    /// heuristic function discovery. ISA-specific, so it lives here — the
    /// discovery pass matches against these without knowing the ISA.
    fn prologues(&self) -> &'static [&'static [u8]] {
        &[]
    }

    /// Recognize a switch / jump-table dispatch whose terminating **indirect
    /// branch is the last instruction of `block`**. Returns the idiom and the
    /// table base/index/bound needed to resolve the cases — but does **not**
    /// read the table (the arch never touches memory; the core resolver does).
    /// Default: no recognition. See [`SwitchDispatch`].
    fn detect_switch(&self, _block: &[DecodedInsn]) -> Option<SwitchDispatch> {
        None
    }

    /// Recognize the function-entry prolog at the front of `instrs` (the
    /// function's linear decode, not a single block) and summarize the stack
    /// frame it sets up. Purely structural — no memory access. Default: empty
    /// (no prolog recognized).
    fn analyze_frame(&self, _instrs: &[DecodedInsn]) -> FrameInfo {
        FrameInfo::default()
    }

    /// The register model.
    fn regs(&self) -> &RegisterFile;

    /// Known calling conventions (first is the platform default).
    fn calling_conventions(&self) -> &[CallConv];
}
