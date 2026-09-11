// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

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
mod arm64_lift;
mod flags;
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
pub use microir::{
    BinOp, Bits, CALL_CLOBBER, CallTarget, CmpKind, FLAGS_VAR, JUMP_TARGET_VAR, MicroExpr,
    MicroStmt, UnOp,
};
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
    /// The register a floating-point result comes back in, when the ABI has one
    /// separate from [`ret`](CallConv::ret) (`xmm0` on both x86-64 conventions).
    ///
    /// A **name**, not a [`Reg`]: the vector registers are not in any
    /// [`RegisterFile`] — the lift names them from the decoder — so there is no
    /// id to reference. `None` says *this model has no float return register
    /// here*, which is the honest answer for an ABI that returns floats on the
    /// x87 stack (i386) and for an architecture whose lift does not yet run.
    pub ret_float: Option<&'static str>,
    /// Caller-saved vector registers, by name — the other half of the ABI's
    /// clobber set. Empty where the lift does not model them.
    pub volatile_float: &'static [&'static str],
    /// The **second** register a floating-point result can come back in. A
    /// struct of two floating-point members (`{double x, y}`) is returned in
    /// `xmm0` *and* `xmm1` under both x86-64 conventions — one value in two
    /// registers, which this IR has no single name for. Knowing the pair is
    /// what lets the answer say so instead of quietly naming one half.
    pub ret_float_second: Option<&'static str>,
    /// The vector registers **floating-point arguments arrive in**, in order.
    ///
    /// The mirror of [`ret_float`](CallConv::ret_float), and it was the missing
    /// half: the convention knew where a floating-point result comes *back*
    /// and not where one goes *in*, so parameter recovery — which scans the
    /// argument registers a function reads at entry — could only ever see the
    /// integer ones. A function whose parameters are all floating-point read
    /// zero of them, and the signature then said `(void)`: `double f(double)`
    /// was reported as `double f(void)` on both x86-64 ABIs.
    ///
    /// Names, not [`Reg`]s, for the same reason as `ret_float`. Empty where
    /// the ABI passes floating-point arguments on the stack (i386 cdecl) or
    /// the lift does not model them.
    pub float_args: &'static [&'static str],
    /// Does a floating-point argument consume the same *positional* slot as an
    /// integer one?
    ///
    /// **Win64: yes.** Argument *position* picks the register in both files —
    /// `f(int, double)` passes in `rcx` and `xmm1`, and `xmm0` stays unused.
    /// The count is therefore the highest position used in either file.
    ///
    /// **System V: no.** The two files are consumed by independent counters —
    /// `f(int, double)` passes in `rdi` and `xmm0` — so the count is the sum.
    ///
    /// Getting this backwards miscounts every mixed signature, which is why it
    /// is per-convention data rather than a rule written once in the pass.
    pub float_args_share_position: bool,
}

impl CallConv {
    /// The argument registers **by name**, in order — exactly the list a lift
    /// puts into `MicroStmt::Call::args`, so position *i* of that list is this
    /// register. Anything that has to map an argument back to the register it
    /// arrived in reads it from here instead of keeping a second copy of the
    /// ABI, because the two copies drift silently: the optimizer may move an
    /// argument out of its register and into the call statement, after which
    /// only this mapping says where it belonged.
    pub fn int_arg_names(&self, regs: &RegisterFile) -> Vec<&'static str> {
        self.int_args.iter().filter_map(|&r| regs.name(r)).collect()
    }

    /// The convention's integer return register, by name. `None` only for a
    /// convention whose return register is not in the architecture's file.
    pub(crate) fn ret_name(&self, regs: &RegisterFile) -> Option<&'static str> {
        regs.name(self.ret)
    }

    /// Every register a call may destroy, by name: the volatile integer set
    /// **minus the return register** — the call statement already assigns that
    /// one precisely — plus the volatile vector set.
    ///
    /// Each name gets an `Unknown` def at a call site so a later read cannot
    /// silently reuse the *pre-call* value. Leaving the vector half out let a
    /// value in the float return register survive a call in the model when the
    /// hardware had already overwritten it.
    ///
    /// One rule, one place: two lifters ask this question and the answer is a
    /// property of the convention, not of the instruction set asking.
    pub(crate) fn clobbered_names(&self, regs: &RegisterFile) -> Vec<String> {
        self.volatile
            .iter()
            .filter(|&&r| r != self.ret)
            .filter_map(|&r| regs.name(r))
            .map(str::to_string)
            .chain(self.volatile_float.iter().map(|s| (*s).to_string()))
            .collect()
    }
}

/// The ISA abstraction the analysis core is written against.
///
/// **Boundary rule:** implementors may touch `iced-x86` or any ISA library;
/// they must not touch the OS, I/O, or a memory source. Bytes come *in*;
/// decoded/lifted structure comes *out*.
pub trait Arch {
    /// Short stable id, e.g. `"x86-64"`.
    fn name(&self) -> &'static str;

    /// The decoder's full identity, for anything that must not confuse two
    /// decoders — a cache key above all.
    ///
    /// [`name`](Arch::name) is not enough on its own: the 64-bit and 32-bit x86
    /// decoders are one type with a `bitness` field and both answer `"x86-64"`.
    /// A content-addressed cache keyed on bytes and that name alone returns one
    /// decoder's answer to the other's question, which is exactly what happened
    /// to the IR cache: the same ARM64 image analysed as x64 and then as arm64
    /// got the first answer both times, silently.
    fn decoder_id(&self) -> String {
        format!("{}/{}", self.name(), self.pointer_size())
    }

    /// Native pointer size in bytes.
    fn pointer_size(&self) -> u8 {
        8
    }

    /// Re-encode the instructions in `bytes` — decoded as if they began at
    /// `from` — so that they execute **identically** when placed at `to`.
    ///
    /// Moving code is not copying bytes. On x86-64 a great many instructions
    /// are position-dependent: `mov [rip+disp], rcx`, `call rel32`, every
    /// short branch. Copied verbatim to another address they still decode, so
    /// nothing looks wrong, and they read and write the wrong memory.
    ///
    /// This exists because a detour did exactly that. The ten bytes displaced
    /// from a real hook site were `mov rax,rcx; mov [rip+0xcf5ee],rcx` — a
    /// store to a global — and copied into a code cave 64 KiB away, the same
    /// encoding stored somewhere else entirely. The target died on the next
    /// call, and the only reason it had never been seen is that the cave used
    /// to be allocated too far away for the hook to be installed at all.
    ///
    /// The default refuses rather than guessing: an ISA with no relocator can
    /// only honestly say so.
    fn relocate(&self, bytes: &[u8], from: Va, to: Va) -> Result<Vec<u8>, String> {
        if from == to {
            return Ok(bytes.to_vec());
        }
        Err(format!("{} has no instruction relocator, so code cannot be moved from {from} to {to}", self.name()))
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
    /// That is not hypothetical. On an IL2CPP target whose code lives in a
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

    /// Registers whose **canonical** name is not what the target calls them,
    /// as `(canonical, target)` pairs. Empty for every ISA whose canonical
    /// spelling already is the target's.
    ///
    /// [`Arch::normalize_reg`] folds inward, so one identity serves every
    /// width and every join stays honest. That identity is a *64-bit* spelling
    /// on x86 — and on a 32-bit image it is false as a claim: `rsp` and `rax`
    /// are not registers of an i386. The mismatch shipped. One `ir build`
    /// object carried `"text":"sub esp,0Ch"` beside `"reads":["rsp"]`, and
    /// `function summary` answered `clobbers:["rax"]` for a machine that has
    /// no such register.
    ///
    /// It is a *table* rather than a function so the two questions asked of it
    /// — "what does the target call this one" and "does this target rename
    /// anything at all" — read the same fact. The second is what lets the
    /// response walk cost nothing on a target that renames nothing.
    fn display_reg_map(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }

    /// One canonical register name spelled as the target spells it — the
    /// inverse of [`Arch::normalize_reg`], and the only place a canonical name
    /// becomes user-facing text. Reads [`Arch::display_reg_map`]; a name the
    /// table does not mention has no other spelling and passes through.
    fn display_reg(&self, canonical: &str) -> String {
        self.display_reg_map()
            .iter()
            .find(|(c, _)| *c == canonical)
            .map(|(_, target)| (*target).to_string())
            .unwrap_or_else(|| canonical.to_string())
    }

    /// Byte patterns that commonly begin a function (prologues), used by
    /// heuristic function discovery. ISA-specific, so it lives here — the
    /// discovery pass matches against these without knowing the ISA.
    ///
    /// `abi` matters because a prologue is an *ABI* idiom, not only an ISA one:
    /// the same bytes that open a Win64 function are ordinary mid-function code
    /// under System V. The pass passes the ABI it is analysing under; an
    /// implementation that does not care ignores it.
    fn prologues(&self, _abi: &str) -> &'static [&'static [u8]] {
        &[]
    }

    /// The subset of [`Arch::prologues`] that is evidence of an entry **on its
    /// own** — a byte sequence the architecture requires at an entry, not an
    /// idiom that also occurs mid-function.
    ///
    /// Discovery refuses a prologue match that falls inside a function the
    /// image already declares, because a declared extent settles what is inside
    /// it. That rule is wrong for the one case where several entry points share
    /// one unwind range — hand-written assembly usually — so a marker in this
    /// list is exempt from it. Empty = every pattern yields to a declared
    /// extent.
    fn entry_markers(&self) -> &'static [&'static [u8]] {
        &[]
    }

    /// Byte alignment a compiler gives a function entry on this ISA.
    ///
    /// Discovery uses it to corroborate a prologue match no declaration
    /// confirms: the scan walks every byte offset, so a short pattern also
    /// matches inside a longer instruction, and an unaligned match is far more
    /// often mid-function than a real entry. `1` = no corroboration available.
    fn entry_alignment(&self) -> u64 {
        1
    }

    /// Recognize a switch / jump-table dispatch whose terminating **indirect
    /// branch is the last instruction of `block`**. Returns the idiom and the
    /// table base/index/bound needed to resolve the cases — but does **not**
    /// read the table (the arch never touches memory; the core resolver does).
    /// Default: no recognition. See [`SwitchDispatch`].
    /// [`Arch::detect_switch`] with the instructions *before* the dispatch
    /// block in view.
    ///
    /// The bound check a jump table is guarded by (`cmp $n, idx` / `ja
    /// default`) ends its own basic block, so it is never in the block that
    /// performs the dispatch. `insns` is everything decoded for the function up
    /// to and including the indirect branch, and `block_start` says where the
    /// dispatch block begins within it. The default forwards the dispatch block
    /// alone, which is exactly the old behaviour.
    fn detect_switch_with_context(&self, insns: &[DecodedInsn], block_start: usize) -> Option<SwitchDispatch> {
        self.detect_switch(insns.get(block_start..)?)
    }

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

    /// The canonical name of this ISA's stack pointer, when it has one.
    ///
    /// Analyses that ask about *data* need to tell the stack pointer apart from
    /// a value: every call reads it, so following that dependency answers a
    /// question about a computed value with the function's prologue. Default:
    /// none, which makes such an analysis follow every edge exactly as before.
    fn stack_pointer(&self) -> Option<&'static str> {
        None
    }

    /// The register model.
    fn regs(&self) -> &RegisterFile;

    /// Known calling conventions (first is the platform default).
    fn calling_conventions(&self) -> &[CallConv];

    /// **The** convention an ABI name selects, falling back to the
    /// architecture's first when the name is unknown.
    ///
    /// One rule, one place. It was written out in the lift (which decides what
    /// a `call` forwards and invalidates) and again in the core (which decides
    /// what a parameter is), in two crates that cannot share a private helper —
    /// so it lives on the trait both of them already depend on. A second reader
    /// arriving later (an emulator, deciding what a callee sees on entry) has to
    /// get the same answer, or the two disagree about what a call *is* and the
    /// disagreement never surfaces as an error.
    fn calling_convention(&self, abi: &str) -> Option<&CallConv> {
        let ccs = self.calling_conventions();
        ccs.iter().find(|c| c.name == abi).or_else(|| ccs.first())
    }
}
