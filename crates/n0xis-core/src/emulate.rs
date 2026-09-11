// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`Emulator`] — executes the micro-IR, so the IR can be checked against a CPU.
//!
//! Every pass above the lift agrees with every other pass because they all read
//! the same IR. That makes the whole stack self-consistent and says nothing
//! about whether it is *right*: a dropped operand width propagates through SSA,
//! the optimizer and the renderer without one of them ever disagreeing. The
//! question "is the IR what the machine does" has exactly one outside source,
//! and it is not another tool — it is the processor.
//!
//! So: run the recovered function on planted inputs, run the real one on the
//! same inputs, compare the numbers. `oracle/emu.c` + `oracle/emu_run.c` are
//! the other half of this instrument.
//!
//! **This emulator is deliberately naive.** It implements exactly what the IR
//! says and never re-derives anything the IR failed to record — no inferring a
//! 32-bit width from a mnemonic, no zeroing an undefined register. A helpful
//! emulator would hide the defects it exists to find. Every place the IR is
//! silent, this reports an error naming what was missing, and an error is a
//! result: it says *the IR does not model this*, which is a finding, not a
//! failure of the run.
//!
//! It operates on `Vec<SsaBlock>` — the shape of both [`SsaArtifact`] and
//! [`OptArtifact`], so the same instrument judges SSA construction and the
//! optimizer, and any disagreement between the two is the optimizer changing
//! the program's meaning.
//!
//! [`SsaArtifact`]: crate::ssa::SsaArtifact
//! [`OptArtifact`]: crate::optimize::OptArtifact

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use n0xis_arch::{BinOp, CallTarget, CmpKind, MicroExpr, MicroStmt, UnOp};
use n0xis_contracts::Va;
use n0xis_sources::MemorySource;

use crate::ssa::SsaBlock;

/// Where the emulated stack pointer starts. High, page-aligned, and far from
/// any image mapping so a stack address can never be mistaken for a global.
/// The widest value this emulator holds. 128 bits, because that is an SSE
/// register — the layer the census ranks second, after memory — and because a
/// vector value has to survive a load, a move and a store *as a value* before
/// any lane arithmetic is worth writing. Scalar arithmetic stays 64-bit: every
/// `Binary` but the bitwise ones narrows its operands and its result, which is
/// exactly what it did before this widened, so nothing scalar changed.
///
/// Wider than this — a 256-bit AVX register — is still
/// [`EmuError::WidthNotModelled`], which names itself.
pub const WORD_BITS: u32 = 128;

pub const DEFAULT_STACK_TOP: u64 = 0x7fff_0000_0000;

/// Where the `%fs` and `%gs` segments are pinned. Far from both the stack and
/// any image mapping, so a segment-relative address can never be confused with
/// either.
/// The return address the caller is standing in for. Never executed — the
/// emulator stops at the IR's `Return` — so any recognizable value does.
pub const RETURN_SENTINEL: u64 = 0xdead_0000_0000_0000;

/// The caller's frame pointer, saved and restored by an ordinary prologue.
pub const CALLER_FRAME: u64 = 0x7fff_0000_0100;

pub const DEFAULT_FS_BASE: u64 = 0x7f00_0000_0000;
pub const DEFAULT_GS_BASE: u64 = 0x7e00_0000_0000;

/// What happens at a `call`.
///
/// The default is [`CallPolicy::Refuse`], and that is not timidity: a run that
/// stops at a call and says so is a *measurement* of how far the IR carries,
/// while a run that walks past a call by inventing its result is a number
/// nobody can trust. Executing callees is opt-in because it changes what the
/// answer means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallPolicy {
    /// A call is a named error. One function, no assumptions.
    Refuse,
    /// Run the callee when a [`CodeProvider`] has its body, use its stub value
    /// when it has one, and refuse when it has neither. `max_depth` bounds the
    /// nesting, so recursion ends in a named error rather than a stack
    /// overflow of the emulator itself.
    Execute { max_depth: usize },
}

#[derive(Clone, Copy, Debug)]
pub struct EmuConfig {
    /// Statement budget. A recovered loop whose exit condition did not survive
    /// the lift runs forever; this turns that into a reported error instead.
    pub max_steps: usize,
    pub stack_top: u64,
    /// Where `%fs:`-relative addressing lands. Thread-local storage has no
    /// address the image can state, so the emulator gives the segment a base
    /// and the caller seeds whatever the code expects to find there (the stack
    /// canary at `fs:0x28`, on System V).
    pub fs_base: u64,
    pub gs_base: u64,
    /// Let a register that **entered** the function undefined hold an arbitrary
    /// value instead of stopping the run.
    ///
    /// `setg %al` merges one byte into whatever `rax` already held, and at
    /// `-O1` nothing initialized it — the next instruction throws those bits
    /// away. The register genuinely holds *something* on the hardware, so
    /// refusing reports a correct prologue as a defect. With this on, only an
    /// SSA **entry version** (`rax.0`, never `rax.3`) is invented; a later
    /// undefined name is still a real dataflow hole and still stops the run.
    ///
    /// Every invented register is listed in [`EmuResult::invented`], so a run
    /// that leans on one says so out loud. If the answer actually depended on
    /// the value, it will differ from the hardware's — which is a finding.
    pub entry_scratch: bool,
    /// What a `call` does. See [`CallPolicy`].
    pub calls: CallPolicy,
    /// The machine's word, in bits — 64 by default, 32 for an i386 target.
    ///
    /// It decides how wide the return address on the stack is, and therefore
    /// where a caller's first stack argument lands. Writing eight bytes at the
    /// stack top on a 32-bit target overwrites the first argument, which reads
    /// as a wrong answer in the function and not as a wrong setup.
    pub word_bits: u32,
}

impl Default for EmuConfig {
    fn default() -> Self {
        EmuConfig {
            max_steps: 2_000_000,
            stack_top: DEFAULT_STACK_TOP,
            fs_base: DEFAULT_FS_BASE,
            gs_base: DEFAULT_GS_BASE,
            entry_scratch: false,
            calls: CallPolicy::Refuse,
            word_bits: 64,
        }
    }
}

/// Why a run stopped without producing a value. Each variant names the thing
/// the IR did not say, because that — not the stop — is the finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EmuError {
    /// Read of a variable nothing defined. Never silently zero: an
    /// uninitialized read is either a real bug in the recovered dataflow or a
    /// missing input, and both are worth seeing.
    UndefinedVar(String),
    /// The lift left the instruction verbatim.
    Unlifted { va: Va, text: String },
    /// An operand the lift could not lower.
    UnknownExpr(String),
    /// A flags value the lift did not model, used where a value was needed.
    OpaqueFlags(String),
    /// A call whose callee nothing supplied — no body, no stated stub value.
    CallNotModelled(String),
    /// Nesting past [`CallPolicy::Execute`]'s bound. Recursion, or a chain
    /// deeper than the run was set up for; either way, named rather than run.
    CallDepthExceeded { limit: usize, va: Va },
    /// An intrinsic with no emulation. Named, so the gap is countable.
    IntrinsicNotModelled(String),
    /// Neither the written memory nor the backing source can answer.
    UnreadableMemory { addr: u64, bytes: u32 },
    /// A value wider than this emulator's 64-bit word — an SSE or AVX lane.
    /// Returned rather than truncated: taking the low 8 bytes of a 128-bit load
    /// and calling it the value is the exact shape of wrong answer this whole
    /// instrument exists to catch, and a `debug_assert` would have let it
    /// through in a release build.
    WidthNotModelled { bits: u32 },
    DivideByZero(Va),
    /// A terminator whose successor set does not let execution continue.
    NoSuccessor { block: usize, terminator: String },
    /// A `cjmp` block whose branch condition the SSA pass did not synthesize.
    NoCondition { block: usize },
    /// An indirect jump landed on an address the CFG does not record as an
    /// edge of this block. **This is the finding, not the failure**: the
    /// resolved switch cases are a claim about where a dispatch goes, and this
    /// says the machine goes somewhere else — a case the resolver missed, or a
    /// table it read the wrong bounds for.
    UnrecordedJump { block: usize, to: u64 },
    /// An indirect jump the CFG did not resolve at all — no edges, so nothing
    /// is being contradicted. Kept apart from [`EmuError::UnrecordedJump`]
    /// because the two are different findings: this one says *the dispatch was
    /// never recognized*, and that one says *it was recognized and the machine
    /// went somewhere else*. Counting them together would hide the second
    /// inside the first, and only the second accuses an answer.
    UnresolvedJump { block: usize, to: u64 },
    /// The jump's destination *is* a recorded edge, and no block begins there.
    /// A separate variant from [`EmuError::UnrecordedJump`] because it accuses
    /// something else — an edge whose target is not a leader is a CFG that
    /// disagrees with itself, not a resolver that missed a case.
    JumpToNonLeader { block: usize, to: u64 },
    StepLimit(usize),
    /// The entry block is not in the artifact.
    NoEntry,
}

impl fmt::Display for EmuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmuError::UndefinedVar(v) => write!(f, "read of undefined variable `{v}`"),
            EmuError::Unlifted { va, text } => write!(f, "unlifted instruction at {va}: {text}"),
            EmuError::UnknownExpr(s) => write!(f, "unlowered operand: {s}"),
            EmuError::OpaqueFlags(m) => write!(f, "opaque flags from `{m}` used as a value"),
            EmuError::CallNotModelled(t) => write!(f, "call to {t} is not modelled"),
            EmuError::CallDepthExceeded { limit, va } => {
                write!(f, "call to {va} would nest deeper than the limit of {limit}")
            }
            EmuError::IntrinsicNotModelled(n) => write!(f, "intrinsic `{n}` is not modelled"),
            EmuError::UnreadableMemory { addr, bytes } => {
                write!(f, "read of {bytes} unreadable bits at {addr:#x}")
            }
            EmuError::WidthNotModelled { bits } => {
                write!(f, "a {bits}-bit value is wider than this emulator's word")
            }
            EmuError::DivideByZero(va) => write!(f, "divide by zero at {va}"),
            EmuError::NoSuccessor { block, terminator } => {
                write!(f, "block {block} terminates as `{terminator}` with no usable successor")
            }
            EmuError::NoCondition { block } => {
                write!(f, "block {block} is a cjmp with no synthesized condition")
            }
            EmuError::UnrecordedJump { block, to } => write!(
                f,
                "block {block} jumps to {to:#x}, which is not one of the edges the CFG recorded"
            ),
            EmuError::UnresolvedJump { block, to } => write!(
                f,
                "block {block} jumps to {to:#x}; the CFG resolved no edges for this dispatch"
            ),
            EmuError::JumpToNonLeader { block, to } => write!(
                f,
                "block {block} jumps to {to:#x}, a recorded edge that no block begins at"
            ),
            EmuError::StepLimit(n) => write!(f, "step limit of {n} reached"),
            EmuError::NoEntry => write!(f, "no entry block"),
        }
    }
}

impl std::error::Error for EmuError {}

#[derive(Clone, Debug)]
pub struct EmuResult {
    /// The value the function returned, as the IR's `Return` statement gave it.
    /// `None` when the IR returned nothing.
    pub ret: Option<u64>,
    pub steps: usize,
    pub blocks_entered: usize,
    /// Entry registers whose value the emulator had to invent, under
    /// [`EmuConfig::entry_scratch`]. Empty on a run that needed none.
    pub invented: Vec<String>,
    /// How many callee bodies this run actually executed. Zero on a run that
    /// went through no call — which is the number that tells a test whether it
    /// exercised the thing it was written for, or quietly passed without it.
    pub calls: usize,
    /// How many calls were answered by a stated stub value instead of a body.
    pub stubbed: usize,
}

/// Byte-addressed memory: written bytes win, everything else falls through to
/// the image. Byte-addressed and not slot-keyed on purpose — an 8-bit store
/// followed by a 32-bit load must read its neighbours, exactly as the machine
/// does.
struct Memory<'a> {
    written: BTreeMap<u64, u8>,
    backing: Option<&'a dyn MemorySource>,
    /// Every address the run read or wrote. A recovered program's *addresses*
    /// are checkable against DWARF in a way its variable names are not: a name
    /// like `local_48` is a displacement from whichever frame pointer the
    /// expression happened to use, but an address is an address.
    touched: std::collections::BTreeSet<u64>,
}

impl Memory<'_> {
    fn read(&mut self, addr: u64, bytes: u32) -> Result<u128, EmuError> {
        if bytes > WORD_BITS {
            return Err(EmuError::WidthNotModelled { bits: bytes });
        }
        for i in 0..(((bytes as u64) / 8).clamp(1, 16)) {
            self.touched.insert(addr.wrapping_add(i));
        }
        self.read_inner(addr, bytes)
    }

    fn read_inner(&self, addr: u64, bytes: u32) -> Result<u128, EmuError> {
        let n = ((bytes as usize) / 8).clamp(1, 16);
        let mut buf = [0u8; 16];
        let mut backed: Option<Vec<u8>> = None;
        for (i, slot) in buf.iter_mut().enumerate().take(n) {
            let a = addr.wrapping_add(i as u64);
            if let Some(b) = self.written.get(&a) {
                *slot = *b;
                continue;
            }
            // Fall through to the image, fetching the whole span once.
            if backed.is_none() {
                let src = self.backing.ok_or(EmuError::UnreadableMemory { addr, bytes })?;
                backed = Some(
                    src.read(Va(addr), n).map_err(|_| EmuError::UnreadableMemory { addr, bytes })?,
                );
            }
            let bytes_read = backed.as_ref().expect("just filled");
            *slot = *bytes_read.get(i).ok_or(EmuError::UnreadableMemory { addr, bytes })?;
        }
        Ok(u128::from_le_bytes(buf))
    }

    fn write(&mut self, addr: u64, value: u128, bytes: u32) {
        let n = ((bytes as usize) / 8).clamp(1, 16);
        for (i, b) in value.to_le_bytes().into_iter().enumerate().take(n) {
            let a = addr.wrapping_add(i as u64);
            self.written.insert(a, b);
            self.touched.insert(a);
        }
    }
}

/// Where a callee's body comes from, and what an unrunnable one may return.
///
/// The emulator models one function; a `call` leaves it. Everything past the
/// call is somebody's *decision*, and this is where the decision is stated
/// instead of assumed: a body to run, a value a stub hands back, or nothing —
/// in which case the call stays [`EmuError::CallNotModelled`]. There is
/// deliberately no fallback, because a fabricated zero is indistinguishable
/// from a correct answer at exactly the point it matters.
pub trait CodeProvider {
    /// The SSA body to execute for a call to `va`, if one is available.
    ///
    /// The address is the one the IR named. Resolving a PLT stub to the local
    /// definition behind it belongs here — `SymbolProvider::thunk_to` is the
    /// source of that fact — because *which function this is* is a symbol
    /// question, not an emulation question.
    fn body(&self, va: Va) -> Option<&[SsaBlock]>;

    /// What a callee with no body returns.
    ///
    /// `args` are the values of the argument registers **the IR named** for
    /// this call, in order — the calling convention's own statement, not a
    /// second copy of it here. `None` in that list is a register that held no
    /// value; arity is not known at this level, so every register the
    /// convention names is reported as it stands and the stub decides what it
    /// needs. Returning `None` — the default — means the caller stated
    /// nothing, and the call stays an error.
    fn stub(&self, _va: Va, _args: &[Option<u64>]) -> Option<u64> {
        None
    }
}

/// A [`CodeProvider`] backed by two maps: bodies to run, values to hand back.
/// Both are filled explicitly by whoever builds the run, so nothing here can
/// invent a callee that was never supplied.
#[derive(Default)]
pub struct BodyMap {
    bodies: BTreeMap<u64, Vec<SsaBlock>>,
    stubs: BTreeMap<u64, u64>,
    #[allow(clippy::type_complexity)]
    stub_fns: BTreeMap<u64, Box<dyn Fn(&[Option<u64>]) -> Option<u64> + Send + Sync>>,
}

impl BodyMap {
    pub fn new() -> Self {
        BodyMap::default()
    }

    /// Register `blocks` as the body of the function at `va`.
    pub fn insert(&mut self, va: Va, blocks: Vec<SsaBlock>) -> &mut Self {
        self.bodies.insert(va.0, blocks);
        self
    }

    /// State what a callee with no body returns — an import, a syscall wrapper,
    /// anything outside the image. Stating it is the point: the value is the
    /// caller's claim about that function, and the CPU comparison judges it.
    pub fn stub(&mut self, va: Va, value: u64) -> &mut Self {
        self.stubs.insert(va.0, value);
        self
    }

    /// State a callee as a *function* of its arguments, for an import whose
    /// answer is not one number. Same rule as the constant form: the value is
    /// the caller's claim, and the processor judges the whole run.
    pub fn stub_with(
        &mut self,
        va: Va,
        f: impl Fn(&[Option<u64>]) -> Option<u64> + Send + Sync + 'static,
    ) -> &mut Self {
        self.stub_fns.insert(va.0, Box::new(f));
        self
    }

    pub fn len(&self) -> usize {
        self.bodies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bodies.is_empty()
    }
}

impl CodeProvider for BodyMap {
    fn body(&self, va: Va) -> Option<&[SsaBlock]> {
        self.bodies.get(&va.0).map(Vec::as_slice)
    }

    fn stub(&self, va: Va, args: &[Option<u64>]) -> Option<u64> {
        if let Some(v) = self.stubs.get(&va.0) {
            return Some(*v);
        }
        self.stub_fns.get(&va.0).and_then(|f| f(args))
    }
}

/// One activation record.
///
/// The register file exists here in both spellings the IR uses. SSA pins a
/// value to a *definition* (`rax.3`), which is what statements read and write;
/// a callee entering a function sees a *register file* (`rax`), which is what
/// the hardware hands it. Keeping only the first made a call's entry state
/// unrecoverable, so both are kept, written together, and never derived from
/// each other after the fact — "highest version number" is not "the value that
/// reached this point" once a loop is involved.
#[derive(Default)]
struct Frame {
    vars: HashMap<String, u128>,
    arch: HashMap<String, u128>,
}

impl Frame {
    fn set(&mut self, name: &str, value: u128) {
        self.arch.insert(base_name(name).to_string(), value);
        self.vars.insert(name.to_string(), value);
    }

    fn get(&self, name: &str) -> Option<u128> {
        self.vars.get(name).copied()
    }

    /// Bind a value only if nothing already holds that name — how the ABI's
    /// entry guarantees are seeded without overwriting a caller's planted input.
    fn seed(&mut self, name: &str, value: u128) {
        if let std::collections::hash_map::Entry::Vacant(e) = self.vars.entry(name.to_string()) {
            e.insert(value);
            self.arch.insert(base_name(name).to_string(), value);
        }
        self.vars.entry(format!("{name}.0")).or_insert(value);
    }
}

/// Executes one function's micro-IR — and, under [`CallPolicy::Execute`], the
/// functions it calls.
pub struct Emulator<'a> {
    blocks: &'a [SsaBlock],
    /// Seeded by [`Emulator::set_var`], then the entry frame's variables; left
    /// holding the entry frame's final state so a run can be inspected.
    vars: HashMap<String, u128>,
    mem: Memory<'a>,
    cfg: EmuConfig,
    code: Option<&'a (dyn CodeProvider + 'a)>,
    /// The registers this target's convention passes integer arguments in, in
    /// order. Position *i* of a `Call`'s `args` is `arg_regs[i]`.
    ///
    /// It is needed because the optimizer *moves* an argument: unoptimized, the
    /// value is assigned to `rdi` and the call names that variable, so a callee
    /// reading the caller's register file sees it. Optimized, the assignment is
    /// folded into the call's argument list and deleted — the register never
    /// holds the value at all, and a callee reading the register file gets
    /// whatever was there before, which is a wrong answer with no error in it.
    /// Empty means the caller stated no convention, and then only the register
    /// file is passed — correct for the unoptimized form and nothing else.
    arg_regs: Vec<String>,
    invented: Vec<String>,
    steps: usize,
    blocks_entered: usize,
    calls: usize,
    stubbed: usize,
    /// The register file the last executed callee left behind.
    ///
    /// The lift writes a `CALL_CLOBBER` marker onto every register the ABI says
    /// a callee *may* destroy — a statement about the convention, made by
    /// something that has seen one instruction and no callee. The machine makes
    /// no such statement: after a `call`, a register holds whatever the callee
    /// left in it, and a compiler that can see the callee (gcc's `-fipa-ra`, on
    /// by default at `-O2`) keeps live values in "clobbered" registers because
    /// it knows they survive. An emulator that has just *run* the callee knows
    /// it too, so the marker resolves to the callee's actual value rather than
    /// to nothing. `None` after a stubbed call: no body ran, so there is no
    /// register file, and the marker stays what it says — unknown.
    after_call: Option<HashMap<String, u128>>,
    /// How deep the call stack is *right now*. On the emulator rather than
    /// threaded through as a parameter: a tail call reaches [`Emulator::call`]
    /// from inside `eval`, which has no depth in hand, and handing it a zero
    /// there made the bound a suggestion — a cycle of tail calls recursed until
    /// the host stack ran out, which is the one failure mode a depth bound
    /// exists to prevent.
    depth: usize,
}

impl<'a> Emulator<'a> {
    pub fn new(blocks: &'a [SsaBlock], backing: Option<&'a dyn MemorySource>) -> Self {
        Self::with_config(blocks, backing, EmuConfig::default())
    }

    pub fn with_config(
        blocks: &'a [SsaBlock],
        backing: Option<&'a dyn MemorySource>,
        cfg: EmuConfig,
    ) -> Self {
        Emulator {
            blocks,
            vars: HashMap::new(),
            mem: Memory {
                written: BTreeMap::new(),
                backing,
                touched: std::collections::BTreeSet::new(),
            },
            cfg,
            code: None,
            arg_regs: Vec::new(),
            invented: Vec::new(),
            steps: 0,
            blocks_entered: 0,
            calls: 0,
            stubbed: 0,
            after_call: None,
            depth: 0,
        }
    }

    /// Supply the callees. Without one, [`CallPolicy::Execute`] has nothing to
    /// run and every call is still a named error.
    pub fn with_code(mut self, code: &'a (dyn CodeProvider + 'a)) -> Self {
        self.code = Some(code);
        self
    }

    /// State which registers carry integer arguments, in order. Take the list
    /// from the architecture's own [`CallConv`] — never a second copy of the
    /// ABI written out here.
    ///
    /// [`CallConv`]: n0xis_arch::CallConv
    pub fn with_arg_regs<I, S>(mut self, regs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.arg_regs = regs.into_iter().map(Into::into).collect();
        self
    }

    /// Seed a pre-SSA variable. The SSA pass renames a function's live-in
    /// registers to `name.0`, so an argument is set under that spelling; both
    /// are accepted so a caller need not know which form the artifact used.
    pub fn set_var(&mut self, name: &str, value: u64) -> &mut Self {
        self.vars.insert(name.to_string(), u128::from(value));
        self.vars.insert(format!("{name}.0"), u128::from(value));
        self
    }

    /// Seed a value wider than a general-purpose register — a vector operand.
    pub fn set_var_wide(&mut self, name: &str, value: u128) -> &mut Self {
        self.vars.insert(name.to_string(), value);
        self.vars.insert(format!("{name}.0"), value);
        self
    }

    /// The low 64 bits, which is what a general-purpose register holds.
    pub fn var(&self, name: &str) -> Option<u64> {
        self.vars.get(name).map(|v| *v as u64)
    }

    /// Every address the run read or wrote.
    pub fn touched(&self) -> &std::collections::BTreeSet<u64> {
        &self.mem.touched
    }

    pub fn write_mem(&mut self, addr: u64, value: u64, bits: u32) -> &mut Self {
        self.mem.write(addr, u128::from(value), bits);
        self
    }

    /// Plant a value wider than a general-purpose register.
    pub fn write_mem_wide(&mut self, addr: u64, value: u128, bits: u32) -> &mut Self {
        self.mem.write(addr, value, bits);
        self
    }

    /// Run from the first block until a `Return`, an error, or the step limit.
    pub fn run(&mut self) -> Result<EmuResult, EmuError> {
        let mut frame = Frame::default();
        for (k, v) in std::mem::take(&mut self.vars) {
            frame.set(&k, v);
        }

        // The entry state the ABI guarantees, and which a prologue legitimately
        // reads: the stack pointer, the return address the caller pushed, and
        // the caller's frame pointer that `push rbp` saves. All three are real
        // values at a real function's entry; refusing them would report a
        // correct prologue as a defect. Everything *else* stays undefined.
        let stack_top = self.cfg.stack_top;
        for sp in ["rsp", "esp", "sp"] {
            frame.seed(sp, u128::from(stack_top));
        }
        self.mem.write(stack_top, u128::from(RETURN_SENTINEL), self.cfg.word_bits);
        for fp in ["rbp", "ebp", "bp"] {
            frame.seed(fp, u128::from(CALLER_FRAME));
        }

        self.steps = 0;
        self.blocks_entered = 0;
        self.calls = 0;
        self.stubbed = 0;
        self.depth = 0;
        let ret = self.run_body(self.blocks, &mut frame);
        self.vars = std::mem::take(&mut frame.vars);
        let ret = ret?;

        let mut invented = std::mem::take(&mut self.invented);
        invented.sort();
        invented.dedup();
        Ok(EmuResult {
            ret,
            steps: self.steps,
            blocks_entered: self.blocks_entered,
            invented,
            calls: self.calls,
            stubbed: self.stubbed,
        })
    }

    /// One activation: run `blocks` against `frame` until it returns.
    fn run_body(
        &mut self,
        blocks: &'a [SsaBlock],
        frame: &mut Frame,
    ) -> Result<Option<u64>, EmuError> {
        let by_id: HashMap<usize, usize> =
            blocks.iter().enumerate().map(|(i, b)| (b.id, i)).collect();
        let mut idx = *by_id.get(&0).ok_or(EmuError::NoEntry)?;
        let mut prev: Option<usize> = None;

        loop {
            self.blocks_entered += 1;
            let block = blocks[idx].clone();
            let block = &block;

            // Phis are simultaneous: every input is read against the state as
            // it was on entry, then all destinations are written. Reading and
            // writing one at a time would let a phi see another phi's result,
            // which is a different program (a swap becomes a copy).
            if !block.phis.is_empty() {
                let from = prev.ok_or(EmuError::NoEntry)?;
                let block_start = block.start;
                let mut pending = Vec::with_capacity(block.phis.len());
                for phi in &block.phis {
                    let input = phi
                        .inputs
                        .iter()
                        .find(|i| i.from_block == from)
                        .ok_or_else(|| EmuError::UndefinedVar(phi.dst.clone()))?;
                    // A phi input is a *use*, so it resolves exactly the way
                    // any other read of that name does — including the entry
                    // scratch rule. Looking it up directly bypassed that and
                    // silently left the phi's destination undefined, which then
                    // surfaced far away as "undefined `rax.1`" with nothing to
                    // connect it to. Found by this instrument failing on its own
                    // corpus; the emulator was the broken part, not the IR.
                    let value = MicroExpr::Var(input.value.clone());
                    match self.eval(&value, block_start, frame) {
                        Ok(v) => pending.push((phi.dst.clone(), Some(v))),
                        // An undefined input leaves the destination undefined,
                        // and the error surfaces at whatever *reads* it — which
                        // is the only place it can matter, and the place worth
                        // naming. Failing here instead named a bookkeeping node:
                        // SSA inserts a phi for every variable defined on either
                        // path, so a call's clobber list alone (`r10` is
                        // caller-saved, the ABI says its value is gone) produced
                        // a phi over a register the program never mentions, and
                        // a correct function stopped on it.
                        Err(EmuError::UndefinedVar(_)) => {
                            pending.push((phi.dst.clone(), None))
                        }
                        Err(e) => return Err(e),
                    }
                }
                for (dst, v) in pending {
                    match v {
                        Some(v) => frame.set(&dst, v),
                        // Clear the architectural spelling too. Leaving a stale
                        // `r10` behind would hand the next callee a value the
                        // hardware no longer has there, which is precisely the
                        // plausible-wrong-answer shape this emulator refuses.
                        None => {
                            frame.vars.remove(&dst);
                            frame.arch.remove(base_name(&dst));
                        }
                    }
                }
            }

            for (i, stmt) in block.stmts.iter().enumerate() {
                self.steps += 1;
                if self.steps > self.cfg.max_steps {
                    return Err(EmuError::StepLimit(self.cfg.max_steps));
                }
                match &stmt.stmt {
                    MicroStmt::Assign { dst, value } => {
                        // Two assignments carry no number and must leave the
                        // destination *undefined* rather than take a zero: a
                        // flags value, and the marker a call leaves on every
                        // register its ABI may destroy. Undefined is the truth
                        // in both cases, and it surfaces at the read — which is
                        // the only place it can matter.
                        if matches!(value, MicroExpr::Unknown(s) if s == n0xis_arch::CALL_CLOBBER) {
                            match self.after_call.as_ref().and_then(|r| r.get(base_name(dst))) {
                                Some(v) => frame.set(dst, *v),
                                None => {
                                    frame.vars.remove(dst);
                                    frame.arch.remove(base_name(dst));
                                }
                            }
                            continue;
                        }
                        // The flags never carry a number here. Conditions are
                        // synthesized by the SSA pass from the *reaching
                        // compare*, so nothing reads the flags variable as a
                        // value — and evaluating it would fail on every
                        // construct that writes flags without producing one,
                        // starting with `ucomisd`, whose whole result is three
                        // flag bits.
                        if is_flags(dst) {
                            continue;
                        }
                        match self.eval(value, stmt.va, frame) {
                            Ok(v) => frame.set(dst, v),
                            Err(EmuError::OpaqueFlags(_)) => {}
                            Err(e) => return Err(e),
                        }
                    }
                    MicroStmt::Store { addr, value, bits } => {
                        if *bits > WORD_BITS {
                            return Err(EmuError::WidthNotModelled { bits: *bits });
                        }
                        let a = self.eval(addr, stmt.va, frame)? as u64;
                        let v = self.eval(value, stmt.va, frame)?;
                        self.mem.write(a, v, *bits);
                    }
                    MicroStmt::Call { target, args, ret } => {
                        // Where the callee returns to, and it is **not** a
                        // guess: the lift expands one instruction into several
                        // statements sharing its address, so the next larger
                        // address in this block is the next instruction, and a
                        // call at the end of a block returns to the block's
                        // fall-through successor. A sentinel stood here before,
                        // on the reasoning that this level does not know an
                        // instruction's length — it does not, and it does not
                        // need to, because the IR already says where execution
                        // continues. It matters: every position-independent
                        // 32-bit function begins by calling a thunk whose whole
                        // body is `mov (%esp), %eax`, so a fabricated return
                        // address is the *first* thing such a program reads.
                        let return_to = block.stmts[i + 1..]
                            .iter()
                            .map(|s| s.va)
                            .find(|v| *v > stmt.va)
                            .or_else(|| {
                                block
                                    .successors
                                    .iter()
                                    .find(|s| s.kind == "fall")
                                    .map(|s| s.to)
                            });
                        let value = self.call(target, args, stmt.va, return_to, frame)?;
                        match (ret, value) {
                            (Some(name), Some(v)) => frame.set(name, u128::from(v)),
                            // A callee that returned nothing leaves the result
                            // register *undefined*, not zero: reading it is the
                            // caller's bug and has to say so where it happens.
                            (Some(name), None) => {
                                frame.vars.remove(name);
                                frame.arch.remove(base_name(name));
                            }
                            (None, _) => {}
                        }
                    }
                    MicroStmt::Return(expr) => {
                        return match expr {
                            Some(e) => Ok(Some(self.eval(e, stmt.va, frame)? as u64)),
                            None => Ok(None),
                        };
                    }
                    MicroStmt::Nop => {}
                    MicroStmt::Unlifted { va, text } => {
                        return Err(EmuError::Unlifted { va: *va, text: text.clone() });
                    }
                }
            }

            let next = self.successor(blocks, block, frame)?;
            prev = Some(block.id);
            idx = *by_id.get(&next).ok_or_else(|| EmuError::NoSuccessor {
                block: block.id,
                terminator: block.terminator.clone(),
            })?;
        }
    }

    /// Perform a call: decide who the callee is, build its frame, run it.
    ///
    /// The frame is the whole point. A callee does not receive "the arguments"
    /// — it receives the machine, and reads whichever registers its prologue
    /// reads (`push rbx` reads the caller's `rbx`; `push rbp` reads the
    /// caller's `rbp`). So the callee's entry versions are the caller's
    /// register file, with the stack pointer moved down by the return address
    /// the `call` pushed. Nothing is propagated back: the caller's SSA already
    /// states which registers survive a call and which the lift invalidated,
    /// and that statement is the ABI's, so a callee that violates it will show
    /// up as a disagreement with the processor — which is the whole instrument.
    fn call(
        &mut self,
        target: &CallTarget,
        args: &[MicroExpr],
        va: Va,
        return_to: Option<Va>,
        frame: &mut Frame,
    ) -> Result<Option<u64>, EmuError> {
        let CallPolicy::Execute { max_depth } = self.cfg.calls else {
            return Err(EmuError::CallNotModelled(describe_target(target)));
        };
        // Who is called. A direct call names it. An indirect one names a
        // *slot*, and the slot's contents are the answer — so it is read, never
        // guessed; an unreadable slot stays the error it already was.
        let callee = match target {
            CallTarget::Direct { va } => *va,
            CallTarget::Indirect(e) => Va(self.eval(e, va, frame)? as u64),
            CallTarget::Intrinsic(name) => {
                return Err(EmuError::IntrinsicNotModelled(name.clone()));
            }
        };
        let body = self.code.and_then(|c| c.body(callee));
        let Some(body) = body else {
            // Only a stub reads these. The registers the *body* sees are the
            // caller's whole register file, below; this list is the IR's own
            // statement of the convention, handed on so a stub need not carry
            // a second copy of it.
            let mut argv = Vec::with_capacity(args.len());
            for a in args {
                argv.push(self.eval(a, va, frame).ok().map(|v| v as u64));
            }
            return match self.code.and_then(|c| c.stub(callee, &argv)) {
                Some(v) => {
                    self.stubbed += 1;
                    self.after_call = None;
                    Ok(Some(v))
                }
                None => Err(EmuError::CallNotModelled(describe_target(target))),
            };
        };
        if self.depth + 1 > max_depth {
            return Err(EmuError::CallDepthExceeded { limit: max_depth, va: callee });
        }

        let mut callee_frame = Frame::default();
        for (reg, v) in &frame.arch {
            callee_frame.set(reg, *v);
            callee_frame.vars.insert(format!("{reg}.0"), *v);
        }
        // The `call` itself: push the return address, then enter. When the IR
        // says where execution continues, that address is pushed; when it does
        // not (a tail call, whose return goes to this function's own caller), a
        // conspicuous sentinel is, so code that reads it gets an
        // unreadable-memory error naming the address rather than a plausible
        // wrong number.
        let sp = frame
            .arch
            .get("rsp")
            .copied()
            .ok_or_else(|| EmuError::UndefinedVar("rsp".to_string()))?;
        let sp = (sp as u64).wrapping_sub(u64::from(self.cfg.word_bits / 8));
        let ret_addr = return_to.map_or(RETURN_SENTINEL | (self.calls as u64 + 1), |v| v.0);
        self.mem.write(sp, u128::from(ret_addr), self.cfg.word_bits);
        for name in ["rsp", "esp", "sp"] {
            callee_frame.set(name, u128::from(sp));
            callee_frame.vars.insert(format!("{name}.0"), u128::from(sp));
        }

        // The arguments the IR states, laid onto the registers the convention
        // states. This is *on top of* the register-file copy above, and it has
        // to be: unoptimized IR names a variable the caller assigned, so the
        // copy already carries it; optimized IR carries the value here and
        // nowhere else. Applied second, so the more specific statement wins.
        let pairs: Vec<(MicroExpr, String)> =
            args.iter().cloned().zip(self.arg_regs.clone()).collect();
        for (expr, reg) in pairs {
            // An argument register the caller never set is not an error: arity
            // is unknown at this level, and the convention names six whatever
            // the function takes. Whatever the register file already had stands.
            if let Ok(v) = self.eval(&expr, va, frame) {
                callee_frame.set(&reg, v);
                callee_frame.vars.insert(format!("{reg}.0"), v);
            }
        }

        self.calls += 1;
        self.depth += 1;
        let out = self.run_body(body, &mut callee_frame);
        self.depth -= 1;
        // The callee's registers *are* the machine's registers now. Only the
        // ABI's clobber markers read this, so the caller's stack pointer and
        // its callee-saved names keep the values its own SSA gives them.
        self.after_call = Some(callee_frame.arch);
        out
    }

    /// Which block runs next. The CFG names its edges; a `cjmp` picks between
    /// them by the condition the SSA pass synthesized — which is the thing
    /// being tested, so it is evaluated, never guessed.
    fn successor(
        &mut self,
        blocks: &'a [SsaBlock],
        block: &SsaBlock,
        frame: &mut Frame,
    ) -> Result<usize, EmuError> {
        let no_succ =
            || EmuError::NoSuccessor { block: block.id, terminator: block.terminator.clone() };
        let to_id = |va: Va| -> Option<usize> {
            blocks.iter().find(|b| b.start == va).map(|b| b.id)
        };
        match block.terminator.as_str() {
            "cjmp" => {
                let cond =
                    block.condition.as_ref().ok_or(EmuError::NoCondition { block: block.id })?;
                let taken = self.eval(cond, block.end, frame)? != 0;
                let want = if taken { "cjmp-true" } else { "cjmp-false" };
                let edge = block.successors.iter().find(|s| s.kind == want).ok_or_else(no_succ)?;
                to_id(edge.to).ok_or_else(no_succ)
            }
            // An indirect jump: the address the machine computes, checked
            // against the edges the CFG claims. Both halves matter — following
            // it is what lets a switch execute at all, and *checking* it is the
            // only outside opinion the jump-table resolver has ever had.
            "ijmp" => {
                let target = block
                    .stmts
                    .iter()
                    .rev()
                    .find_map(|s| match &s.stmt {
                        MicroStmt::Assign { dst, value }
                            if base_name(dst) == n0xis_arch::JUMP_TARGET_VAR =>
                        {
                            Some(value.clone())
                        }
                        _ => None,
                    })
                    .ok_or_else(no_succ)?;
                // A jump target is an address, which is a machine word and
                // not a vector.
                let addr = self.eval(&target, block.end, frame)? as u64;
                if block.successors.is_empty() {
                    return Err(EmuError::UnresolvedJump { block: block.id, to: addr });
                }
                let recorded = block.successors.iter().any(|s| s.to.0 == addr);
                if !recorded {
                    return Err(EmuError::UnrecordedJump { block: block.id, to: addr });
                }
                to_id(Va(addr)).ok_or(EmuError::JumpToNonLeader { block: block.id, to: addr })
            }
            "fall" | "jmp" => {
                let edge = block
                    .successors
                    .iter()
                    .find(|s| s.kind == "fall" || s.kind == "jmp")
                    .ok_or_else(no_succ)?;
                to_id(edge.to).ok_or_else(no_succ)
            }
            _ => Err(no_succ()),
        }
    }

    fn eval(&mut self, e: &MicroExpr, va: Va, frame: &mut Frame) -> Result<u128, EmuError> {
        Ok(match e {
            // A constant is its bits, at the width the IR states. `cmpl
            // $0xffffffff, mem` encodes a sign-extended byte, so the IR holds
            // `-1` at 32 bits; taking `value as u64` made that
            // `0xffffffffffffffff` and compared it against a memory operand
            // that reads zero-extended — never equal, so a guard against
            // dividing by -1 fell through into the divide. The constant folder
            // has always masked to `bits`; this is the same rule in the second
            // place that reads them.
            MicroExpr::Const { value, bits } => extend(*value as u128, *bits, false),
            MicroExpr::Var(name) => match frame.get(name) {
                Some(v) => v,
                None if self.cfg.entry_scratch && is_entry_version(name) => {
                    let v = scratch_value(name);
                    frame.set(name, v);
                    self.invented.push(name.clone());
                    v
                }
                None => return Err(EmuError::UndefinedVar(name.clone())),
            },
            MicroExpr::Load { addr, bits, signed } => {
                let a = self.eval(addr, va, frame)? as u64;
                let raw = self.mem.read(a, *bits)?;
                extend(raw, *bits, *signed)
            }
            // Unary operations run at the **full** width, because the only
            // ones that reach a vector register are these: `andnps` lowers to
            // `~a & b`. The scalar forms state their own width in the IR (see
            // `x64_lift::at_width`), so a 64-bit `not` is narrowed by the cast
            // around it rather than by a guess here.
            MicroExpr::Unary(op, inner) => {
                let v = self.eval(inner, va, frame)?;
                match op {
                    UnOp::Neg => (v as i128).wrapping_neg() as u128,
                    UnOp::Not => !v,
                }
            }
            // Bitwise operations run at the full width for the same reason —
            // the lift models a vector `pxor`/`andps` as an exact bit operation
            // rather than an intrinsic, and truncating it to 64 bits would drop
            // half of every vector. They are safe there *and* for scalars,
            // because a scalar value never exceeds its stated width.
            //
            // Everything else narrows to 64 and back, which is precisely what
            // this did before it widened: a packed add is an intrinsic, never a
            // `Binary`, so a `Binary` that is not bitwise is scalar by
            // construction.
            MicroExpr::Binary(op @ (BinOp::And | BinOp::Or | BinOp::Xor), l, r) => {
                let a = self.eval(l, va, frame)?;
                let b = self.eval(r, va, frame)?;
                match op {
                    BinOp::And => a & b,
                    BinOp::Or => a | b,
                    _ => a ^ b,
                }
            }
            MicroExpr::Binary(op, l, r) => {
                let a = self.eval(l, va, frame)? as u64;
                let b = self.eval(r, va, frame)? as u64;
                u128::from(binop(*op, a, b, va)?)
            }
            MicroExpr::Cast { signed, bits, expr } => {
                let v = self.eval(expr, va, frame)?;
                extend(v, *bits, *signed)
            }
            // `lea` — the address is the value, so evaluating the inner
            // expression is the whole of it.
            MicroExpr::AddrOf(inner) => self.eval(inner, va, frame)?,
            // A compare is a flags value, not a number. It reaches here only
            // when the SSA pass wrote it into a condition, where the truth of
            // `lhs op rhs` is what the branch wants.
            MicroExpr::Compare { kind, lhs, rhs } => {
                let a = self.eval(lhs, va, frame)?;
                let b = self.eval(rhs, va, frame)?;
                match kind {
                    CmpKind::Cmp | CmpKind::Result => u128::from(a != b),
                    CmpKind::Test | CmpKind::LogicalResult => u128::from(a & b != 0),
                }
            }
            MicroExpr::OpaqueFlags { mnemonic } => {
                return Err(EmuError::OpaqueFlags(mnemonic.clone()));
            }
            MicroExpr::Call { target, args } => {
                if let CallTarget::Intrinsic(name) = target {
                    let mut vals = Vec::with_capacity(args.len());
                    for a in args {
                        vals.push(self.eval(a, va, frame)?);
                    }
                    intrinsic(name, &vals, va, self.cfg.fs_base, self.cfg.gs_base)?
                } else {
                    // A call in value position — a tail call the lift lowered
                    // as `return f(...)`. Same policy, same frame rules.
                    // A tail call in value position returns to this
                    // function's own caller, which this frame does not know.
                    u128::from(
                        self.call(target, args, va, None, frame)?.ok_or_else(|| {
                            EmuError::CallNotModelled(describe_target(target))
                        })?,
                    )
                }
            }
            MicroExpr::Select { cond, a, b } => {
                let c = self.eval(cond, va, frame)?;
                if c != 0 { self.eval(a, va, frame)? } else { self.eval(b, va, frame)? }
            }
            MicroExpr::Unknown(s) => return Err(EmuError::UnknownExpr(s.clone())),
        })
    }
}

/// The architectural register behind an SSA name: `rax.3` is a version of
/// `rax`. One rule, one place — the same fact spelled twice is how every drift
/// in this project has started.
fn base_name(name: &str) -> &str {
    match name.split_once('.') {
        Some((base, _)) => base,
        None => name,
    }
}

/// The intrinsics with **one** defined answer.
///
/// Everything here is a named operation the manual defines exactly, so
/// emulating it invents nothing. Anything whose result the ISA leaves
/// undefined, or that this has not been checked against, stays an error —
/// a gap that says so is worth more than a plausible number.
fn intrinsic(
    name: &str,
    args: &[u128],
    va: Va,
    fs_base: u64,
    gs_base: u64,
) -> Result<u128, EmuError> {
    let gap = || EmuError::IntrinsicNotModelled(name.to_string());
    // The **scalar** view of an operand. Every intrinsic below this point is a
    // one-value operation on a general-purpose or low-lane register, so it sees
    // 64 bits and behaves exactly as it did before the word widened. A packed
    // operation reads `args` directly instead — that is what the extra width is
    // for, and mixing the two accessors is what would make it a guess.
    let arg = |i: usize| args.get(i).copied().map(|v| v as u64).ok_or_else(gap);
    // The dividend is **twice the operand width**: `rdx:rax` for a 64-bit
    // divide, `edx:eax` for a 32-bit one. The lift states which as the fourth
    // argument, because reading the whole of both registers for a 32-bit divide
    // makes the dividend astronomically larger and every signed division of a
    // negative number reports a quotient that does not fit.
    let half = || -> Result<u32, EmuError> { Ok(arg(3)? as u32) };
    let mask = |v: u64, bits: u32| -> u128 {
        u128::from(if bits >= 64 { v } else { v & ((1u64 << bits) - 1) })
    };
    let dividend = || -> Result<u128, EmuError> {
        let b = half()?;
        Ok((mask(arg(0)?, b) << b) | mask(arg(1)?, b))
    };
    // Whether the quotient fits in the *operand's* width, which is what decides
    // whether the hardware traps.
    let fits_unsigned = |q: u128, bits: u32| -> bool { bits >= 128 || q < (1u128 << bits) };
    let fits_signed = |q: i128, bits: u32| -> bool {
        bits >= 128 || (q >= -(1i128 << (bits - 1)) && q < (1i128 << (bits - 1)))
    };
    Ok(u128::from(match name {
        // A segment-relative address is an address: the segment's base plus the
        // offset. Nothing is read here — the Load around it does that.
        "__seg_fs" => fs_base.wrapping_add(arg(0)?),
        "__seg_gs" => gs_base.wrapping_add(arg(0)?),
        // Sign-extend the accumulator into `rdx` — the dividend setup.
        "__cqo" => ((arg(0)? as i64) >> 63) as u64,
        "__cdq" => (((arg(0)? as i32) >> 31) as u32) as u64,
        "__bswap" => arg(0)?.swap_bytes(),
        // The high half of an unsigned 64x64 product — what `mul`/`mulx` leave
        // in `rdx`, and the second half of every magic-number division. Exact,
        // and computed in 128 bits because that is the width it is defined at.
        // The upper `width` bits of the product, at the width the lift states.
        // `mul %edx` leaves `(a*b) >> 32` in `edx`, not `>> 64` — clang builds
        // the closed form of a summation loop out of exactly that.
        "__umulh" => {
            // Two operands, then the width — the divide has three operands
            // before its width, so the position is per-intrinsic and not a
            // shared constant.
            let bits = arg(2)? as u32;
            ((mask(arg(0)?, bits) * mask(arg(1)?, bits)) >> bits) as u64
        }
        // The divides read `rdx:rax` and one source. A quotient that does not
        // fit in 64 bits **traps** on the hardware; nothing is invented for it.
        "__udiv" | "__urem" => {
            let bits = half()?;
            let d = mask(arg(2)?, bits);
            if d == 0 {
                return Err(EmuError::DivideByZero(va));
            }
            let n = dividend()?;
            if name == "__urem" {
                (n % d) as u64
            } else {
                let q = n / d;
                if !fits_unsigned(q, bits) {
                    return Err(EmuError::DivideByZero(va));
                }
                q as u64
            }
        }
        "__idiv" | "__irem" => {
            let bits = half()?;
            let d = sign_extend_128(arg(2)?, bits);
            if d == 0 {
                return Err(EmuError::DivideByZero(va));
            }
            let n = sign_extend_128_wide(dividend()?, bits * 2);
            if name == "__irem" {
                (n.wrapping_rem(d)) as u64
            } else {
                let q = n.wrapping_div(d);
                if !fits_signed(q, bits) {
                    return Err(EmuError::DivideByZero(va));
                }
                q as u64
            }
        }
        _ => {
            return packed(name, args)
                .or_else(|| scalar_float(name, args).map(u128::from))
                .ok_or_else(gap);
        }
    }))
}

/// The lanes of a vector, least significant first.
fn lanes(v: u128, bits: u32) -> Vec<u128> {
    let n = (128 / bits) as usize;
    let mask = if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 };
    (0..n).map(|i| (v >> (i as u32 * bits)) & mask).collect()
}

fn from_lanes(ls: &[u128], bits: u32) -> u128 {
    let mask = if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 };
    ls.iter().enumerate().fold(0u128, |acc, (i, l)| acc | ((l & mask) << (i as u32 * bits)))
}

/// `f` applied lane by lane, at `bits` per lane.
fn lane2(a: u128, b: u128, bits: u32, f: impl Fn(u128, u128) -> u128) -> u128 {
    let (la, lb) = (lanes(a, bits), lanes(b, bits));
    let out: Vec<u128> = la.iter().zip(&lb).map(|(x, y)| f(*x, *y)).collect();
    from_lanes(&out, bits)
}

/// `punpckl*` / `punpckh*`: interleave one half of each source, lane by lane.
fn unpack(a: u128, b: u128, bits: u32, high: bool) -> u128 {
    let n = (128 / bits) as usize;
    let (la, lb) = (lanes(a, bits), lanes(b, bits));
    let off = if high { n / 2 } else { 0 };
    let mut out = Vec::with_capacity(n);
    for i in 0..n / 2 {
        out.push(la[off + i]);
        out.push(lb[off + i]);
    }
    from_lanes(&out, bits)
}

/// A lane width from a mnemonic's suffix: `b`/`w`/`d`/`q`.
fn lane_bits(suffix: char) -> Option<u32> {
    Some(match suffix {
        'b' => 8,
        'w' => 16,
        'd' => 32,
        'q' => 64,
        _ => return None,
    })
}

/// The **packed** operations, lane by lane.
///
/// The census of a shipped library ranks these first among what it cannot run,
/// and the reason a low-lane answer is not an approximation is arithmetic: one
/// instruction writes four independent results, and taking the first is a
/// different value in every bit above it.
///
/// The VEX spelling computes the same thing as the legacy one — the difference
/// is which register the result lands in, which the lift has already resolved —
/// so `__vpaddd` resolves through the same arm as `__paddd`. What is *not* here
/// is anything whose result the ISA leaves partly undefined, and anything whose
/// control immediate the lift drops: a shuffle without its selector is not a
/// shuffle, and guessing the selector is exactly the kind of plausible answer
/// this refuses.
fn packed(name: &str, args: &[u128]) -> Option<u128> {
    let base = name.strip_prefix("__v").map(|r| format!("__{r}")).unwrap_or_else(|| name.into());
    let a = args.first().copied();
    let b = args.get(1).copied();
    let rest = base.strip_prefix("__")?;

    // Interleaves, whose suffix names both the lane width and the half.
    if let Some(k) = rest.strip_prefix("punpckl").or_else(|| rest.strip_prefix("punpckh")) {
        let high = rest.starts_with("punpckh");
        let bits = match k {
            "bw" => 8,
            "wd" => 16,
            "dq" => 32,
            "qdq" => 64,
            _ => return None,
        };
        return Some(unpack(a?, b?, bits, high));
    }
    // The floating-point spelling of the same two instructions.
    if let Some(k) = rest.strip_prefix("unpckl").or_else(|| rest.strip_prefix("unpckh")) {
        let high = rest.starts_with("unpckh");
        let bits = match k {
            "ps" => 32,
            "pd" => 64,
            _ => return None,
        };
        return Some(unpack(a?, b?, bits, high));
    }

    // Packed integer add/subtract and compare, whose last letter is the lane.
    for (prefix, is_add) in [("padd", true), ("psub", false)] {
        if let Some(k) = rest.strip_prefix(prefix)
            && k.len() == 1
            && let Some(bits) = lane_bits(k.chars().next()?)
        {
            let m = if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 };
            return Some(lane2(a?, b?, bits, |x, y| {
                if is_add { x.wrapping_add(y) & m } else { x.wrapping_sub(y) & m }
            }));
        }
    }
    if let Some(k) = rest.strip_prefix("pcmpeq")
        && let Some(bits) = lane_bits(k.chars().next()?)
    {
        let m = if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 };
        return Some(lane2(a?, b?, bits, |x, y| if x == y { m } else { 0 }));
    }
    // `pcmpgt` is **signed**, which is the whole difference between it and a
    // subtraction's carry.
    if let Some(k) = rest.strip_prefix("pcmpgt")
        && let Some(bits) = lane_bits(k.chars().next()?)
    {
        let m = if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 };
        return Some(lane2(a?, b?, bits, |x, y| {
            if sign_extend_128_wide(x, bits) > sign_extend_128_wide(y, bits) { m } else { 0 }
        }));
    }

    // The packed compare, lane by lane, in the same predicate vocabulary the
    // scalar one uses — `o` ordered, `u` "or unordered" — because SSE's `NEQ`
    // is true for a NaN and its `EQ` is not.
    if let Some(rest2) = base.strip_prefix("__fcmpmask_")
        && let Some((pred, width)) = rest2.rsplit_once('_')
        && (width == "pd" || width == "ps")
    {
        let bits = if width == "pd" { 64 } else { 32 };
        let one = format!("__fcmp_{pred}_{}", if bits == 64 { "sd" } else { "ss" });
        let m = (1u128 << bits) - 1;
        return Some(lane2(a?, b?, bits, |x, y| {
            match scalar_float(&one, &[x, y]) {
                Some(0) => 0,
                Some(_) => m,
                None => 0,
            }
        }));
    }

    // Whole-register **byte** shifts. The count is a byte count, not a bit
    // count, and a count past the register's width clears it rather than
    // wrapping — the two facts a plausible model gets backwards.
    if rest == "pslldq" || rest == "psrldq" {
        let n = b? as u32;
        if n >= 16 {
            return Some(0);
        }
        return Some(if rest == "pslldq" { a? << (n * 8) } else { a? >> (n * 8) });
    }
    // Per-lane bit shifts. The count is the *whole* second operand, and a count
    // at or past the lane width zeroes the lane instead of wrapping — x86 does
    // not mask a vector shift count the way it masks a scalar one.
    for (prefix, kind) in [("psll", 0u8), ("psrl", 1), ("psra", 2)] {
        if let Some(k) = rest.strip_prefix(prefix)
            && k.len() == 1
            && let Some(bits) = lane_bits(k.chars().next()?)
        {
            let n = b? as u32;
            let m = (1u128 << bits) - 1;
            return Some(from_lanes(
                &lanes(a?, bits)
                    .iter()
                    .map(|l| match kind {
                        _ if n >= bits && kind != 2 => 0,
                        0 => (l << n) & m,
                        1 => l >> n,
                        // An arithmetic shift saturates to the sign bit rather
                        // than clearing, which is why it is not in the guard.
                        _ => {
                            let sh = n.min(bits - 1);
                            ((sign_extend_128_wide(*l, bits) >> sh) as u128) & m
                        }
                    })
                    .collect::<Vec<_>>(),
                bits,
            ));
        }
    }
    // A shuffle *is* its selector, so the selector has to be an operand — and
    // it is the **last** one. The legacy form passes (dst, src, imm) and the
    // VEX form (src, imm), because a non-destructive encoding has no
    // destination to read; taking the first two would read the destination as
    // the source in one of the two spellings and be right only by accident.
    if rest == "pshufd" {
        let sel = args.last().copied()? as u32;
        let src = lanes(*args.get(args.len().checked_sub(2)?)?, 32);
        let out: Vec<u128> = (0..4).map(|i| src[((sel >> (2 * i)) & 3) as usize]).collect();
        return Some(from_lanes(&out, 32));
    }

    Some(match rest {
        // The sign bit of each byte, gathered into a scalar — the reduction
        // every `memchr` and `strlen` is built out of.
        "pmovmskb" => {
            lanes(a?, 8).iter().enumerate().fold(0u128, |acc, (i, l)| acc | ((l >> 7) << i))
        }
        // Packed double and single precision.
        "addpd" => lane2(a?, b?, 64, |x, y| fbits2(x, y, |p, q| p + q)),
        "subpd" => lane2(a?, b?, 64, |x, y| fbits2(x, y, |p, q| p - q)),
        "mulpd" => lane2(a?, b?, 64, |x, y| fbits2(x, y, |p, q| p * q)),
        "divpd" => lane2(a?, b?, 64, |x, y| fbits2(x, y, |p, q| p / q)),
        "addps" => lane2(a?, b?, 32, |x, y| fbits2_32(x, y, |p, q| p + q)),
        "subps" => lane2(a?, b?, 32, |x, y| fbits2_32(x, y, |p, q| p - q)),
        "mulps" => lane2(a?, b?, 32, |x, y| fbits2_32(x, y, |p, q| p * q)),
        "divps" => lane2(a?, b?, 32, |x, y| fbits2_32(x, y, |p, q| p / q)),
        _ => return None,
    })
}

/// One lane of a packed double operation, in and out as bits.
fn fbits2(x: u128, y: u128, f: impl Fn(f64, f64) -> f64) -> u128 {
    u128::from(f(f64::from_bits(x as u64), f64::from_bits(y as u64)).to_bits())
}

fn fbits2_32(x: u128, y: u128, f: impl Fn(f32, f32) -> f32) -> u128 {
    u128::from(f(f32::from_bits(x as u32), f32::from_bits(y as u32)).to_bits())
}

/// The **scalar** floating-point intrinsics, to the bit.
///
/// Everything here is defined exactly by the ISA, so emulating it invents
/// nothing — and the places where a plausible reading differs from the
/// hardware are the reason this exists at all:
///
/// * `minsd dst, src` is not `fmin`. If either operand is NaN the result is
///   `src`, and `min(+0.0, -0.0)` is `src` too. Rust's `if a < b { a } else
///   { b }` is that rule exactly, because the comparison is false for NaN and
///   false for equal zeros — which is why it is written that way rather than
///   with `f64::min`, whose NaN rule is the opposite one.
/// * a single-precision operation writes **32 bits**. The upper half of the
///   register is preserved, and this model keeps the low 64 bits of a vector
///   register, so the upper 32 of those are carried through rather than zeroed.
/// * the compare predicates carry "or unordered" in their names, because after
///   `ucomisd` a NaN takes the `jb` branch. See `float_branch_condition`.
///
/// The VEX spelling of a scalar operation computes the same thing — the
/// difference is which register the result lands in, which the lift has already
/// resolved — so `__vaddsd` resolves here through the same arm as `__addsd`.
/// What is *not* here is the packed forms: one lane of four is not the answer,
/// and this emulator's word is 64 bits, so they stay a named gap.
fn scalar_float(name: &str, args: &[u128]) -> Option<u64> {
    let base = name.strip_prefix("__v").map(|r| format!("__{r}")).unwrap_or_else(|| name.into());
    let a = args.first().copied().map(|v| v as u64);
    let b = args.get(1).copied().map(|v| v as u64);
    let d = |v: Option<u64>| v.map(f64::from_bits);
    let f = |v: Option<u64>| v.map(|x| f32::from_bits(x as u32));
    // A 32-bit result merged into the low 64 bits of the destination, which is
    // the operand this model has.
    let merge32 = |dst: Option<u64>, r: f32| Some((dst? & 0xffff_ffff_0000_0000) | u64::from(r.to_bits()));

    // The branchless form writes a **mask**, not a boolean: all-ones or
    // all-zeros in the lanes it computes, which is what makes it usable as an
    // operand to `and`/`andnot` without a branch. Same predicates, different
    // result shape, so it shares the table below and not the return value.
    if let Some(rest) = base.strip_prefix("__fcmpmask_") {
        let (_, width) = rest.rsplit_once('_')?;
        // The **packed** forms belong to the lane layer, not this one.
        if width == "pd" || width == "ps" {
            return None;
        }
        let taken = scalar_float(&format!("__fcmp_{rest}"), args)? != 0;
        return Some(if width == "sd" {
            if taken { u64::MAX } else { 0 }
        } else {
            let low = if taken { 0xffff_ffffu64 } else { 0 };
            (a? & 0xffff_ffff_0000_0000) | low
        });
    }

    if let Some(rest) = base.strip_prefix("__fcmp_") {
        let (pred, width) = rest.rsplit_once('_')?;
        let (x, y) = (a?, b?);
        let (lt, eq, gt, uno) = if width == "sd" {
            let (x, y) = (f64::from_bits(x), f64::from_bits(y));
            (x < y, x == y, x > y, x.is_nan() || y.is_nan())
        } else {
            let (x, y) = (f32::from_bits(x as u32), f32::from_bits(y as u32));
            (x < y, x == y, x > y, x.is_nan() || y.is_nan())
        };
        return Some(u64::from(match pred {
            "ogt" => gt,
            "oge" => gt || eq,
            "olt" => lt,
            "ole" => lt || eq,
            "oeq" => eq,
            "one" => !uno && !eq,
            "ugt" => uno || gt,
            "uge" => uno || gt || eq,
            "ult" => uno || lt,
            "ule" => uno || lt || eq,
            "ueq" => uno || eq,
            "une" => uno || !eq,
            "uno" => uno,
            "ord" => !uno,
            _ => return None,
        }));
    }

    Some(match base.as_str() {
        "__addsd" => (d(a)? + d(b)?).to_bits(),
        "__subsd" => (d(a)? - d(b)?).to_bits(),
        "__mulsd" => (d(a)? * d(b)?).to_bits(),
        "__divsd" => (d(a)? / d(b)?).to_bits(),
        "__minsd" => { let (x, y) = (d(a)?, d(b)?); if x < y { x } else { y }.to_bits() }
        "__maxsd" => { let (x, y) = (d(a)?, d(b)?); if x > y { x } else { y }.to_bits() }
        "__sqrtsd" => d(a)?.sqrt().to_bits(),
        "__addss" => merge32(a, f(a)? + f(b)?)?,
        "__subss" => merge32(a, f(a)? - f(b)?)?,
        "__mulss" => merge32(a, f(a)? * f(b)?)?,
        "__divss" => merge32(a, f(a)? / f(b)?)?,
        "__minss" => { let (x, y) = (f(a)?, f(b)?); merge32(a, if x < y { x } else { y })? }
        "__maxss" => { let (x, y) = (f(a)?, f(b)?); merge32(a, if x > y { x } else { y })? }
        "__sqrtss" => merge32(a, f(a)?.sqrt())?,
        // Conversions. The integer source of `cvtsi2*` is signed — the lift
        // reads it that way, so the value arriving here already is.
        "__cvtsi2sd" => ((a? as i64) as f64).to_bits(),
        "__cvtsi2ss" => u64::from(((a? as i64) as f32).to_bits()),
        "__cvtsd2ss" => u64::from((d(a)? as f32).to_bits()),
        "__cvtss2sd" => (f64::from(f(a)?)).to_bits(),
        // Truncate toward zero. Out of range — NaN included — the hardware
        // writes the "integer indefinite" value, not a saturated one, and this
        // is the 64-bit spelling of it. A 32-bit destination has its own
        // indefinite (`0x80000000`) and this intrinsic does not carry the
        // destination width, so that case is **not modelled**: it would need
        // the width in the IR, and inventing it here is the wrong place.
        "__cvttsd2si" | "__cvtsd2si" => truncate_to_int(d(a)?),
        "__cvttss2si" | "__cvtss2si" => truncate_to_int(f64::from(f(a)?)),
        _ => return None,
    })
}

/// x86's float→signed-integer conversion: truncate toward zero, and answer with
/// the *integer indefinite* rather than a saturated edge when the value does not
/// fit. Rust's `as` saturates, which is a different number on exactly the inputs
/// that matter.
fn truncate_to_int(v: f64) -> u64 {
    let t = v.trunc();
    if t.is_nan() || t < -(2f64.powi(63)) || t >= 2f64.powi(63) {
        return i64::MIN as u64;
    }
    (t as i64) as u64
}

/// A `bits`-wide value read as signed, in 128-bit arithmetic.
fn sign_extend_128(v: u64, bits: u32) -> i128 {
    sign_extend_128_wide(u128::from(v), bits)
}

fn sign_extend_128_wide(v: u128, bits: u32) -> i128 {
    if bits >= 128 {
        return v as i128;
    }
    let masked = v & ((1u128 << bits) - 1);
    if masked >> (bits - 1) & 1 == 1 {
        (masked | !((1u128 << bits) - 1)) as i128
    } else {
        masked as i128
    }
}

/// The CPU flags, in any SSA version. They carry a condition, never a number.
fn is_flags(name: &str) -> bool {
    base_name(name) == n0xis_arch::FLAGS_VAR
}

/// Is this the version a variable *entered* the function with? SSA names a
/// definition `name.N`; `.0` is the one nothing in the function defined.
fn is_entry_version(name: &str) -> bool {
    match name.rsplit_once('.') {
        Some((_, ver)) => ver == "0",
        // Pre-SSA IR has no versions at all, so every name is an entry name.
        None => true,
    }
}

/// A deterministic, conspicuous stand-in for a register the ABI does not pin.
/// Derived from the name so two registers never collide, and high enough that
/// it can never be mistaken for a plausible small result.
fn scratch_value(name: &str) -> u128 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    u128::from(0xA5A5_0000_0000_0000u64 | (h & 0x0000_ffff_ffff_ffff))
}

fn describe_target(t: &CallTarget) -> String {
    match t {
        CallTarget::Direct { va } => format!("{va}"),
        CallTarget::Indirect(_) => "an indirect target".to_string(),
        CallTarget::Intrinsic(n) => format!("intrinsic `{n}`"),
    }
}

/// Truncate to `bits` and widen back to 64, signed or not — the one place the
/// emulator knows about width, and it only ever applies a width the IR stated.
fn extend(v: u128, bits: u32, signed: bool) -> u128 {
    match bits {
        0 | 128.. => v,
        b => {
            let masked = v & ((1u128 << b) - 1);
            if signed && masked >> (b - 1) & 1 == 1 { masked | !((1u128 << b) - 1) } else { masked }
        }
    }
}

fn binop(op: BinOp, a: u64, b: u64, va: Va) -> Result<u64, EmuError> {
    let (sa, sb) = (a as i64, b as i64);
    // x86 masks the shift count; the IR carries the count unmasked, so a shift
    // of 64 or more would panic in debug and silently differ in release.
    // Saturating past the width to a defined all-bits result is what every
    // language-level shift means, and it never invents a number.
    let sh = |n: u64| -> u32 { n.min(63) as u32 };
    Ok(match op {
        BinOp::Add => a.wrapping_add(b),
        BinOp::Sub => a.wrapping_sub(b),
        BinOp::Mul => a.wrapping_mul(b),
        BinOp::UDiv => {
            if b == 0 { return Err(EmuError::DivideByZero(va)) }
            a / b
        }
        BinOp::SDiv => {
            if sb == 0 { return Err(EmuError::DivideByZero(va)) }
            sa.wrapping_div(sb) as u64
        }
        BinOp::UMod => {
            if b == 0 { return Err(EmuError::DivideByZero(va)) }
            a % b
        }
        BinOp::SMod => {
            if sb == 0 { return Err(EmuError::DivideByZero(va)) }
            sa.wrapping_rem(sb) as u64
        }
        BinOp::And => a & b,
        BinOp::Or => a | b,
        BinOp::Xor => a ^ b,
        BinOp::Shl => {
            if b >= 64 { 0 } else { a << sh(b) }
        }
        BinOp::Shr => {
            if b >= 64 { 0 } else { a >> sh(b) }
        }
        BinOp::Sar => (sa >> sh(b.min(63))) as u64,
        BinOp::Eq => u64::from(a == b),
        BinOp::Ne => u64::from(a != b),
        BinOp::Ult => u64::from(a < b),
        BinOp::Ule => u64::from(a <= b),
        BinOp::Ugt => u64::from(a > b),
        BinOp::Uge => u64::from(a >= b),
        BinOp::Slt => u64::from(sa < sb),
        BinOp::Sle => u64::from(sa <= sb),
        BinOp::Sgt => u64::from(sa > sb),
        BinOp::Sge => u64::from(sa >= sb),
    })
}
