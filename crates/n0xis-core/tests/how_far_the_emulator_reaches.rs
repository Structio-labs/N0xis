// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **How much real code the emulator can actually execute — as a census.**
//!
//! The corpus test says the emulator is *correct* on what it runs. It says
//! nothing about how much of a real program that is, and "correct on the
//! functions it happens to handle" is the kind of claim that quietly becomes
//! "correct". So this points it at a shared library nobody wrote for it and
//! counts the outcomes by *reason*.
//!
//! The census is the product: each error class names a construct the emulator
//! does not model, in the order a real program hands them over. That is a work
//! list built from measurement rather than from guessing what matters.
//!
//! The floor is ratcheted — the reach may rise, and a commit that lowers it has
//! to say so.

use std::collections::BTreeMap;
use std::path::Path;

use n0xis_arch::X64;
use n0xis_contracts::Va;
use n0xis_core::{
    BodyMap, CallPolicy, CfgInput, CfgPass, CodeProvider, Ctx, EmuConfig, Emulator, Pass, SsaBlock,
    SsaPass,
};
use n0xis_sources::{MemorySource, SourceError, StaticElf, SymbolProvider};

/// Candidate libraries, in preference order. Skipped loudly if none is present.
const LIBRARIES: [&str; 3] =
    ["/usr/lib/libQt6Gui.so.6", "/usr/lib/libstdc++.so.6", "/usr/lib/libc.so.6"];

/// How many functions to try. Enough for the shape of the census to be stable.
const SAMPLE: usize = 400;

/// How deep a call chain the census follows, and how many callee bodies it is
/// willing to build. Both are bounds on *this measurement*, not on the
/// emulator: a real library's call graph reaches most of the library from
/// almost anywhere, and a census that spent an hour building it would stop
/// being run. Whatever they cut off shows up in the census as a named class
/// (`a call nested past the depth bound`, `a call to another function`), which
/// is the point — a bound that hides itself is not a bound.
/// Measured, not assumed: raising `MAX_BODIES` to 2000 and then 4000 changed
/// the census by nothing at all — same 147 completions, same 50 calls — while
/// quadrupling the runtime. The bound binds (this library's call graph is far
/// larger than 1000 functions) and does not matter, which is the only way a
/// bound is worth keeping.
const MAX_DEPTH: usize = 6;
const MAX_BODIES: usize = 1000;

/// A window of zeroed memory the arguments point into.
///
/// The census hands a function six integers and asks it to run. A real caller
/// hands it *pointers* — to a `QImage`, a string, a vtable — and a function
/// whose first act is to dereference its first argument stops on memory nobody
/// mapped. That is a fact about this harness, not about the IR, and leaving it
/// in made the largest class in the census a measurement of the harness.
///
/// So the arguments point here, and here reads as zero. This is **inventing
/// input, never semantics**: the census counts how far execution *reaches*, and
/// nothing in it claims a function computed the right answer — that claim comes
/// from `emulator_agrees_with_the_cpu` and `the_emulator_follows_a_call`, where
/// the processor answers and the inputs are planted on purpose. A zeroed object
/// is a plausible thing for a caller to have passed; it is not a correct one.
const SCRATCH_BASE: u64 = 0x0000_5000_0000_0000;
const SCRATCH_LEN: u64 = 1 << 20;

/// The image, plus [`SCRATCH_BASE`]. Composed at the seam rather than taught to
/// the emulator, so the emulator keeps reporting unmapped memory as unmapped.
struct Planted<'a>(&'a StaticElf);

impl MemorySource for Planted<'_> {
    fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, SourceError> {
        if va.0 >= SCRATCH_BASE && va.0 - SCRATCH_BASE < SCRATCH_LEN {
            return Ok(vec![0u8; len]);
        }
        self.0.read(va, len)
    }
    fn contains(&self, va: Va) -> bool {
        (va.0 >= SCRATCH_BASE && va.0 - SCRATCH_BASE < SCRATCH_LEN) || self.0.contains(va)
    }
    fn label(&self) -> String {
        format!("{} + planted scratch", self.0.label())
    }
}

/// The callees, resolved the way the caller sees them.
struct Bodies<'a> {
    map: BodyMap,
    elf: &'a StaticElf,
}

impl CodeProvider for Bodies<'_> {
    fn body(&self, va: Va) -> Option<&[SsaBlock]> {
        // A shared object calls its own exported functions through the PLT, so
        // the address in the `call` is a stub and the body is elsewhere.
        self.map.body(va).or_else(|| self.elf.thunk_to(va).and_then(|t| self.map.body(t)))
    }
    // No `stub`: an import's answer is not something this census may invent.
    // Those calls stay a named class in the count, which is where they belong.
}

/// **The recorded reach**, as a percentage rather than a count: the library is
/// whatever version this machine has, so a hard count would be a property of
/// the packaging, not of the emulator. The floor sits below the measurement so
/// a distro bump does not fail the build, and the *census* below is the number
/// that matters.
///
/// Measured on Qt6Gui (2026-09-09): **11%**, then **36%** the same day, after
/// two changes with very different standing. Executing callees is the
/// emulator's: calls fell from 110 of 400 to 50, and 11 completed runs went
/// through one. Pointing the arguments at readable memory is the *harness's*,
/// and it was worth more — 143 of 400 stopped on unmapped memory because the
/// census handed a function that dereferences its first argument the integer
/// `0x1000`. Nothing about the IR had been measured there; the harness had.
const MIN_REACH_PERCENT: usize = 25;

#[test]
fn the_census_of_what_real_code_hands_the_emulator() {
    let Some(lib) = LIBRARIES.iter().find(|p| Path::new(p).is_file()) else {
        eprintln!("skip: none of {LIBRARIES:?} is present — nothing was checked");
        return;
    };
    let elf = StaticElf::load(Path::new(lib)).expect("loads");
    let arch = X64::new();
    // **With the symbol table**, because the pipeline this census is supposed
    // to describe has one. Without it a tail call through a GOT slot is not
    // recognized as a tail call at all — the callee's name is what classifies
    // it — and the census reported 19 functions "stopping at an indirect jump
    // the CFG resolved no edges for" that the real pipeline resolves to
    // `return QMetaObject::activate(...)`. A starved pass measures the harness.
    let ctx = Ctx::new(&elf, &arch).with_symbols(&elf as &dyn SymbolProvider);

    let mut starts: Vec<Va> =
        elf.named_functions().into_iter().map(|(va, _)| va).filter(|v| v.0 != 0).collect();
    starts.sort();
    starts.dedup();
    starts.truncate(SAMPLE);
    assert!(starts.len() > 50, "{lib}: only {} function symbols", starts.len());

    // Build the sample and the call graph under it, breadth-first, until the
    // bounds bite. Every body is built exactly once, and a function that fails
    // to build is simply absent — a call to it then reports "not modelled",
    // which is the honest outcome and a counted one.
    let mut bodies = BodyMap::new();
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    let mut built: BTreeMap<u64, ()> = BTreeMap::new();
    let mut frontier: Vec<Va> = starts.clone();
    for _ in 0..=MAX_DEPTH {
        let mut next: Vec<Va> = Vec::new();
        for va in std::mem::take(&mut frontier) {
            if built.contains_key(&va.0) || bodies.len() >= MAX_BODIES {
                continue;
            }
            built.insert(va.0, ());
            let Ok(cfg) = CfgPass.run(&ctx, CfgInput::new(va, 8192)) else {
                if starts.contains(&va) {
                    *reasons.entry("the CFG could not be built".into()).or_default() += 1;
                }
                continue;
            };
            let Ok(ssa) = SsaPass.run(&ctx, cfg) else {
                if starts.contains(&va) {
                    *reasons.entry("SSA could not be built".into()).or_default() += 1;
                }
                continue;
            };
            for cs in &ssa.callsites {
                if let Some(t) = cs.target {
                    next.push(elf.thunk_to(t).unwrap_or(t));
                }
            }
            bodies.insert(va, ssa.blocks);
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    let code = Bodies { map: bodies, elf: &elf };
    let planted = Planted(&elf);
    eprintln!("built {} bodies under the {SAMPLE} sampled functions", code.map.len());

    let mut completed = 0usize;
    let mut with_calls = 0usize;
    for va in &starts {
        let Some(blocks) = code.body(*va) else { continue };
        let cfg_e = EmuConfig {
            entry_scratch: true,
            calls: CallPolicy::Execute { max_depth: MAX_DEPTH },
            ..Default::default()
        };
        let mut emu = Emulator::with_config(blocks, Some(&planted as &dyn MemorySource), cfg_e)
            .with_code(&code as &dyn CodeProvider)
            .with_arg_regs(n0xis_core::abi_arg_registers(&ctx));
        // Spread out inside the window so two arguments are never the same
        // object, and far enough from its edges that a negative field offset
        // still lands inside it.
        for (i, reg) in ["rdi", "rsi", "rdx", "rcx", "r8", "r9"].iter().enumerate() {
            emu.set_var(reg, SCRATCH_BASE + 0x1_0000 + i as u64 * 0x1000);
        }
        emu.write_mem(n0xis_core::DEFAULT_FS_BASE + 0x28, 0x5ec0_ffee, 64);
        match emu.run() {
            Ok(r) => {
                completed += 1;
                if r.calls > 0 {
                    with_calls += 1;
                }
            }
            // Keep the *class*, not the instance: "a call" and "a switch" are
            // work items, while "a call to 0x1234" is one function's detail.
            // One class is not a gap but an **accusation**: the CFG resolved a
            // dispatch, said where its cases go, and the machine went somewhere
            // else. Every other line of this census is a count; this one names
            // the function, because a count is not enough to act on when the
            // finding is that an answer is wrong.
            Err(e) => {
                if matches!(e, n0xis_core::EmuError::UnresolvedJump { .. }) {
                    eprintln!("  UNRES {va} — {e}");
                }
                if matches!(e, n0xis_core::EmuError::UnrecordedJump { .. }) {
                    eprintln!("  ACCUSES {va} — {e}");
                }
                *reasons.entry(class_of(&e)).or_default() += 1
            }
        }
    }

    let pct = completed * 100 / starts.len();
    eprintln!(
        "\n{}: {completed} of {} functions ran to a return ({pct}%), {with_calls} of them \
         through at least one call",
        Path::new(lib).file_name().unwrap_or_default().to_string_lossy(),
        starts.len()
    );
    let mut ranked: Vec<_> = reasons.iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(a.1));
    for (reason, n) in ranked {
        eprintln!("  {n:4}  {reason}");
    }

    assert!(
        pct >= MIN_REACH_PERCENT,
        "the emulator reached {completed} of {} functions ({pct}%); the recorded floor is \
         {MIN_REACH_PERCENT}%",
        starts.len()
    );
    // The census must stay a census. A run where every function failed for one
    // reason means the harness broke, not that the program is uniform.
    assert!(reasons.len() > 3, "only {} distinct failure classes — check the harness", reasons.len());
}

/// The construct behind a failure, with the instance stripped off.
fn class_of(e: &n0xis_core::EmuError) -> String {
    use n0xis_core::EmuError as E;
    match e {
        E::CallNotModelled(_) => "a call to another function".into(),
        E::CallDepthExceeded { .. } => "a call nested past the depth bound".into(),
        E::IntrinsicNotModelled(n) => format!("the intrinsic `{n}`"),
        E::Unlifted { .. } => "an instruction the lift left verbatim".into(),
        E::UnknownExpr(_) => "an operand the lift could not lower".into(),
        E::OpaqueFlags(_) => "flags used as a value".into(),
        E::UndefinedVar(_) => "a variable nothing defined".into(),
        E::UnreadableMemory { .. } => "memory neither written nor in the image".into(),
        E::DivideByZero(_) => "a divide by zero on the planted inputs".into(),
        E::NoSuccessor { terminator, .. } => format!("a `{terminator}` terminator"),
        E::NoCondition { .. } => "a cjmp with no synthesized condition".into(),
        E::UnrecordedJump { .. } => {
            "**a dispatch the CFG resolved, to a case it did not record**".into()
        }
        E::UnresolvedJump { .. } => "an indirect jump the CFG resolved no edges for".into(),
        E::JumpToNonLeader { .. } => "an edge whose target no block begins at".into(),
        E::StepLimit(_) => "the step limit (a loop that did not end)".into(),
        E::WidthNotModelled { bits } => format!("a {bits}-bit (vector) value"),
        E::NoEntry => "no entry block".into(),
    }
}
