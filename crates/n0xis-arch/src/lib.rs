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

mod arm32;
mod arm64;
mod frame;
mod insn;
mod microir;
mod switch;
mod x64;
mod x64_lift;

pub use arm32::{Arm32, arm32reg};
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
    ///
    /// ⚠️ **Stopping is right for a function and wrong for a section.** Use
    /// [`decode_range`](Arch::decode_range) to sweep a whole code range.
    fn decode_stream(&self, bytes: &[u8], va: Va, max: usize) -> Vec<DecodedInsn>;

    /// Sweep a whole code **range**, resynchronizing past bytes that do not
    /// decode instead of stopping at them.
    ///
    /// A compiled section is not a pure instruction stream: it carries jump
    /// tables, alignment padding, string blobs and data islands between
    /// functions. [`decode_stream`](Arch::decode_stream) stops at the first of
    /// those, which is correct when the caller is walking one function — an
    /// undecodable byte means the function ended — and **catastrophic** when the
    /// caller is scanning a section, because everything past that byte silently
    /// disappears from the result.
    ///
    /// That is not hypothetical. On a Unity IL2CPP target whose code lives in a
    /// 61 MB section, the section-wide passes were reporting a *fraction* of the
    /// real references and it looked like a property of the binary rather than
    /// of the sweep: three builds returned 43 %, 4 % and 0 % of their icall
    /// sites, which reads as three codegen variants and is really three places
    /// where one sweep happened to die.
    ///
    /// Default: repeatedly `decode_stream`, and on an invalid instruction skip a
    /// single byte and start again — the standard linear-sweep recovery. An ISA
    /// with fixed-width instructions can override with something exact.
    fn decode_range(&self, bytes: &[u8], va: Va, max: usize) -> Vec<DecodedInsn> {
        let mut out: Vec<DecodedInsn> = Vec::new();
        let mut at = 0usize;
        while at < bytes.len() && out.len() < max {
            let chunk = self.decode_stream(&bytes[at..], Va(va.0 + at as u64), max - out.len());
            if chunk.is_empty() {
                at += 1;
                continue;
            }
            // Advance past everything decoded. When the run ended on an invalid
            // instruction, that entry is dropped and the sweep restarts one byte
            // later: an instruction may well begin inside what the decoder just
            // rejected.
            let consumed: usize = chunk.iter().map(|i| i.len as usize).sum();
            let ended_invalid = chunk.last().is_some_and(|i| i.kind == InsnKind::Invalid);
            if ended_invalid {
                let keep = chunk.len() - 1;
                let kept_bytes: usize = chunk.iter().take(keep).map(|i| i.len as usize).sum();
                out.extend(chunk.into_iter().take(keep));
                at += kept_bytes.max(1);
                at += 1;
            } else {
                out.extend(chunk);
                at += consumed.max(1);
            }
        }
        out
    }

    /// Lower one instruction to micro-IR. Default: preserves the instruction
    /// verbatim (sound, uninterpreted) — ISA impls override per-mnemonic.
    ///
    /// `abi` names the source's calling convention (e.g. `"win64"`, `"sysv"`);
    /// it selects which [`CallConv`] a `call` forwards as arguments and which
    /// registers it invalidates as caller-saved. A convention this arch does
    /// not expose falls back to its first (native default). The default `lift`
    /// emits no calls, so it ignores `abi`.
    fn lift(&self, insn: &DecodedInsn, abi: &str) -> Vec<MicroStmt> {
        let _ = abi;
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
    fn lift_tail_call(&self, insn: &DecodedInsn, abi: &str) -> Vec<MicroStmt> {
        self.lift(insn, abi)
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
