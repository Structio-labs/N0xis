//! # n0xis-arch — the ISA seam
//!
//! Abstracts an instruction-set architecture behind [`Arch`]. The analysis in
//! `n0xis-core` depends only on this trait, never on a concrete ISA — so all
//! x64/Win64 knowledge (register model, calling conventions, flag semantics)
//! is confined here. That confinement is the whole point: in v0, x64 facts
//! leaked into the passes and made a second architecture impossible. This seam
//! makes ARM64 a matter of adding an `impl Arch`, not a rewrite.
//!
//! Phase 1 ships the [`X64`] decoder (real, via `iced-x86`) and the register /
//! calling-convention model. [`Arch::lift`] to micro-IR is stubbed here and
//! filled in Phase 3 (ROADMAP), where [`MicroStmt`] grows a real tree.

mod insn;
mod x64;

pub use insn::{DecodeError, DecodedInsn, InsnKind};
pub use x64::{X64, x64reg};

use n0xis_contracts::{Reg, Va};

/// A single micro-IR statement — the arch-neutral lowering of one machine
/// instruction. **Phase 3 placeholder**: today `lift` returns an empty slice;
/// the typed expression/statement tree (with flags modeled as values) is built
/// in the decompiler phase. The type exists now so the seam's signature is
/// stable and passes can be written against it.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum MicroStmt {
    /// Explicit "not yet lowered" — preserves the instruction verbatim so no
    /// semantics are silently lost (CONCEPT §3 rule 6).
    Unlifted { va: Va },
}

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

    /// Lower one instruction to micro-IR. **Phase 3**: currently a stub.
    fn lift(&self, insn: &DecodedInsn) -> Vec<MicroStmt> {
        vec![MicroStmt::Unlifted { va: insn.va }]
    }

    /// Registers read/written by an instruction, normalized to full width.
    /// Default is empty; ISA impls override. Used by def-use analysis in the
    /// core without the passes ever seeing a decoder.
    fn reg_access(&self, _insn: &DecodedInsn) -> RegAccess {
        RegAccess::default()
    }

    /// The register model.
    fn regs(&self) -> &RegisterFile;

    /// Known calling conventions (first is the platform default).
    fn calling_conventions(&self) -> &[CallConv];
}
