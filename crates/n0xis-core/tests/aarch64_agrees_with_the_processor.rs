// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The processor is the oracle, on a processor this project has never run.**
//!
//! Everything measured so far — two platforms, two compilers, two bitnesses,
//! four optimization levels — was x86. `n0xis_arch::Arm64` decodes AArch64 and
//! builds a CFG over it, and that is where it stops: the `Arch` trait's default
//! `lift` hands back [`MicroStmt::Unlifted`](n0xis_arch::MicroStmt::Unlifted)
//! for every instruction, so the IR carries the *text* of the program and none
//! of its meaning.
//!
//! This file is the judge that architecture will be measured by, and it is
//! written **before** the lift exists on purpose. A harness built after the
//! thing it judges is a harness tuned to agree with it; one built first has to
//! state, today, what it can and cannot see — and the only honest thing it can
//! say today is *nothing was compared*.
//!
//! So the shape is `emulator_agrees_with_the_cpu.rs`, unchanged: the same leaf
//! corpus (`oracle/emu.c`), the same driver (`oracle/emu_run.c`), the same
//! adversarial input walk — cross-compiled for AArch64 and executed under
//! `qemu-aarch64-static`, which runs the real instruction stream. Rung 1: the
//! answer exists before the question is asked and no tool of ours produced it.
//!
//! Three outcomes, kept apart, exactly as on x86:
//!
//! * **agrees** — the recovered program computes what the hardware computed.
//! * **not modelled** — the emulator stopped and named the construct the IR
//!   does not carry. A gap, and a countable one.
//! * **disagrees** — a *different number*. The only bad outcome.
//!
//! **And the calibration, which is the part that makes this worth having.**
//! A harness that reports "0 disagreements" because it silently ran nothing is
//! the exact failure this project keeps finding in its own instruments — a
//! `this`-pointer rule that scored 0-of-22-and-0-wrong because nothing had
//! given it a symbol table; a census whose largest failure class was its own
//! bad arguments. Zero-and-zero is not a weak result, it is an unasked
//! question. So this test asserts that it *reached* the state it claims to
//! report: that the library built, that the processor answered, that n0xis
//! produced blocks, that every case was accounted for, and that while nothing
//! agrees, every stop is [`EmuError::Unlifted`] **specifically** — because on
//! an architecture with no lift, any *other* stop would mean the harness
//! starved the run rather than the IR being incomplete.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use n0xis_arch::{Arch, Arm64};
use n0xis_contracts::Va;
use n0xis_core::{CfgInput, CfgPass, Ctx, EmuConfig, EmuError, Emulator, Pass, SsaPass};
use n0xis_sources::{MemorySource, StaticElf, SymbolProvider};

/// The cross toolchain, named once. Each is a machine fact, not a preference:
/// the compiler that emits AArch64, the `nm` that reads its symbol table, and
/// the user-mode emulator that executes the result.
const CC: &str = "aarch64-linux-gnu-gcc";
const NM: &str = "aarch64-linux-gnu-nm";
const QEMU: &str = "qemu-aarch64-static";

/// Where the AArch64 dynamic loader and libc live. `qemu-aarch64-static` needs
/// it to run a dynamically linked binary at all — without `-L` the driver dies
/// before it prints a single case, and this test would then be asserting over
/// an empty list.
const SYSROOT: &str = "/usr/aarch64-linux-gnu";

/// AAPCS64 passes the first eight integer/pointer arguments in `x0`–`x7` and
/// returns in `x0`. Stated here from the ABI, not read out of n0xis — and then
/// checked against what n0xis's own `CallConv` says, below, so the two copies
/// of this fact cannot drift apart in silence.
///
/// The names are the **canonical** ones: one physical register gets one name in
/// the records, so a function whose arguments arrive as `w0`/`w1` still reads
/// them under `x0`/`x1` (see `arm64_exit.rs`, where naming a 32-bit view `w0`
/// made `ir slice --reg x0` answer `node_count: 0`).
const ARG_REGS: [&str; 8] = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];
const RET_REG: &str = "x0";

/// How many input vectors the driver walks per function.
const CASES: u32 = 8;

fn oracle_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("oracle")
}

fn have(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

/// One case as the processor answered it. The *arguments* are read back from
/// the driver's own output rather than recomputed here: the walk over the value
/// list is one fact and it lives in `emu_run.c`.
#[derive(Debug)]
struct CpuCase {
    func: String,
    args: Vec<u64>,
    ret: u64,
}

fn parse_cases(stdout: &str) -> Vec<CpuCase> {
    stdout
        .lines()
        // The driver also prints the one constant it owns, for the sibling test
        // that stubs an import. Not a case; skipped by shape, not by position.
        .filter(|l| l.starts_with('{') && l.contains("\"fn\""))
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("driver emits JSON");
            CpuCase {
                func: v["fn"].as_str().expect("fn").to_string(),
                args: v["args"]
                    .as_array()
                    .expect("args")
                    .iter()
                    .map(|a| a.as_u64().expect("u64 arg"))
                    .collect(),
                ret: v["ret"].as_u64().expect("u64 ret"),
            }
        })
        .collect()
}

/// Function addresses from `aarch64-linux-gnu-nm` — an independent parser, not
/// n0xis's own symbol table. If n0xis placed a function wrongly, emulating the
/// bytes it points at would fail in a way that reads like an arithmetic defect;
/// taking the address from outside keeps those two questions apart.
fn addresses(so: &Path) -> BTreeMap<String, u64> {
    let out = Command::new(NM)
        .args(["-D", "--defined-only"])
        .arg(so)
        // Third time this has bitten the project: the listing is localized and
        // a parser keyed on the English form reads nothing at all.
        .env("LC_ALL", "C")
        .output()
        .expect("nm runs");
    let mut map = BTreeMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut it = line.split_whitespace();
        let (Some(addr), Some(kind), Some(name)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if kind == "T"
            && name.starts_with("emu_")
            && let Ok(a) = u64::from_str_radix(addr, 16)
        {
            map.insert(name.to_string(), a);
        }
    }
    map
}

/// Which [`EmuError`] a run stopped at, as a name that groups.
///
/// `Display` cannot do this job: it prints the address and text of the unlifted
/// instruction, so a thousand stops of one kind become a thousand distinct
/// keys and the breakdown says nothing. The match is **exhaustive on purpose**
/// — a new `EmuError` variant must fail to compile here rather than fall into
/// a default bucket and disappear from the tally.
fn stop_kind(e: &EmuError) -> &'static str {
    match e {
        EmuError::UndefinedVar(_) => "UndefinedVar",
        EmuError::Unlifted { .. } => "Unlifted",
        EmuError::UnknownExpr(_) => "UnknownExpr",
        EmuError::OpaqueFlags(_) => "OpaqueFlags",
        EmuError::CallNotModelled(_) => "CallNotModelled",
        EmuError::CallDepthExceeded { .. } => "CallDepthExceeded",
        EmuError::IntrinsicNotModelled(_) => "IntrinsicNotModelled",
        EmuError::UnreadableMemory { .. } => "UnreadableMemory",
        EmuError::WidthNotModelled { .. } => "WidthNotModelled",
        EmuError::DivideByZero(_) => "DivideByZero",
        EmuError::NoSuccessor { .. } => "NoSuccessor",
        EmuError::NoCondition { .. } => "NoCondition",
        EmuError::UnrecordedJump { .. } => "UnrecordedJump",
        EmuError::UnresolvedJump { .. } => "UnresolvedJump",
        EmuError::JumpToNonLeader { .. } => "JumpToNonLeader",
        EmuError::StepLimit(_) => "StepLimit",
        EmuError::NoEntry => "NoEntry",
    }
}

#[derive(Default)]
struct Tally {
    /// Corpus functions `nm` found and n0xis built IR for.
    functions: usize,
    /// SSA blocks n0xis produced across those functions.
    blocks: usize,
    /// Cases the processor answered — **every** one, matched or not, so that
    /// `unmatched` below is a subset of a number that does not move when the
    /// join breaks. Counting only the matched ones would make a broken join
    /// look like a smaller corpus instead of a defect.
    cases: usize,
    /// Cases the processor answered that no n0xis form was found for. Must stay
    /// zero: the driver is handed exactly the names `nm` gave, so a case with
    /// no form is a join defect, and a silently skipped case is the shape of
    /// wrong answer this whole file exists to refuse.
    unmatched: usize,
    agrees: usize,
    disagrees: Vec<String>,
    /// Why the runs stopped: kind → (count, one example in full).
    stops: BTreeMap<&'static str, (usize, String)>,
}

impl Tally {
    fn absorb(&mut self, other: Tally) {
        self.functions += other.functions;
        self.blocks += other.blocks;
        self.cases += other.cases;
        self.unmatched += other.unmatched;
        self.agrees += other.agrees;
        self.disagrees.extend(other.disagrees);
        for (kind, (n, example)) in other.stops {
            let slot = self.stops.entry(kind).or_insert((0, example));
            slot.0 += n;
        }
    }

    fn stops_total(&self) -> usize {
        self.stops.values().map(|(n, _)| *n).sum()
    }

    fn record(&mut self, case: &CpuCase, got: Result<Option<u64>, EmuError>) {
        match got {
            Ok(Some(v)) if v == case.ret => self.agrees += 1,
            Ok(Some(v)) => self.disagrees.push(format!(
                "{}({:#x}, {:#x}, {:#x}, {:#x}) -> n0xis {v:#x}, the processor {:#x}",
                case.func, case.args[0], case.args[1], case.args[2], case.args[3], case.ret
            )),
            Ok(None) => self.disagrees.push(format!(
                "{}: the IR returned nothing; the processor returned {:#x}",
                case.func, case.ret
            )),
            Err(e) => {
                let slot = self
                    .stops
                    .entry(stop_kind(&e))
                    .or_insert_with(|| (0, format!("{}: {e}", case.func)));
                slot.0 += 1;
            }
        }
    }
}

/// n0xis's own statement of AAPCS64, against the ABI's, which [`ARG_REGS`]
/// carries. One fact in two places is how every drift in this project started,
/// and the two cannot be merged here: the harness must be able to seed the
/// right registers even when the convention table is the thing that is wrong.
/// So they are compared instead, and the drift fails on its own line.
fn the_convention_matches_the_abi(arch: &Arm64) {
    let conv = arch
        .calling_conventions()
        .iter()
        .find(|c| c.name == "aapcs64")
        .expect("Arm64 states the AAPCS64 convention");
    let names: Vec<&str> =
        conv.int_args.iter().map(|r| arch.regs().name(*r).expect("a named register")).collect();
    assert_eq!(
        names, ARG_REGS,
        "n0xis's AAPCS64 integer argument registers no longer match the ABI's x0-x7; \
         the emulator below seeds ARG_REGS, so one of the two is now seeding the wrong \
         registers and every answer would be blamed on the lift"
    );
    assert_eq!(
        arch.regs().name(conv.ret),
        Some(RET_REG),
        "n0xis's AAPCS64 integer return register no longer matches the ABI's x0"
    );
}

#[test]
fn aarch64_computes_what_the_processor_computes() {
    // A skipped test must never read as a pass, so every reason to skip says
    // out loud that nothing was checked.
    for tool in [CC, NM, QEMU] {
        if !have(tool) {
            eprintln!("skip: `{tool}` is not on this machine — NOTHING WAS CHECKED");
            return;
        }
    }
    if !Path::new(SYSROOT).is_dir() {
        eprintln!("skip: no AArch64 sysroot at {SYSROOT} — NOTHING WAS CHECKED");
        return;
    }

    let dir = oracle_dir();
    let tmp = std::env::temp_dir().join("n0xis-aarch64-oracle");
    std::fs::create_dir_all(&tmp).expect("tmp dir");

    // The driver is cross-compiled too: it runs *inside* qemu, beside the
    // library it dlopens, so both are AArch64 and the call between them is the
    // real AAPCS64 call this test is about.
    let driver = tmp.join("emu_run");
    let built = Command::new(CC)
        .args(["-O2", "-o"])
        .arg(&driver)
        .arg(dir.join("emu_run.c"))
        .arg("-ldl")
        .output()
        .expect("the cross compiler runs");
    assert!(
        built.status.success(),
        "{CC} could not build oracle/emu_run.c:\n{}",
        String::from_utf8_lossy(&built.stderr)
    );

    let arch = Arm64::new();
    the_convention_matches_the_abi(&arch);

    // One optimization level is one shape of blindness, and on AArch64 the
    // shapes differ from x86's: `-O0` spills everything to the frame, while
    // `-O2`/`-Os` reach for `csel`, `csinc`, `cinc`, `ubfx`, `madd` and the
    // flag-setting `adds`/`subs` forms — the instructions a lift is most likely
    // to get subtly wrong, and none of which appear at `-O0`.
    let mut totals = Tally::default();
    for level in ["-O0", "-O1", "-O2", "-Os"] {
        let so = tmp.join(format!("emu{level}.so"));
        // **The scalar corpus stays scalar.** Left to itself the compiler
        // vectorizes a byte-scatter loop into NEON, and packed SIMD is a layer
        // this emulator does not model and says so — one lane of four is not
        // the answer. Same flags as the x86 corpus, for the same reason.
        let built = Command::new(CC)
            .args([
                level,
                "-fno-tree-vectorize",
                "-fno-tree-slp-vectorize",
                "-fPIC",
                "-shared",
                "-o",
            ])
            .arg(&so)
            .arg(dir.join("emu.c"))
            .output()
            .expect("the cross compiler runs");
        assert!(
            built.status.success(),
            "{CC} could not build oracle/emu.c at {level}:\n{}",
            String::from_utf8_lossy(&built.stderr)
        );
        totals.absorb(check_one_build(&so, &driver, &arch, level));
    }

    // ---- what actually happened, before any verdict about the subject -------

    eprintln!(
        "\naarch64, all levels: {} functions, {} blocks, {} processor answers -> \
         {} agree, {} disagree, {} not modelled",
        totals.functions,
        totals.blocks,
        totals.cases,
        totals.agrees,
        totals.disagrees.len(),
        totals.stops_total()
    );
    for (kind, (n, example)) in &totals.stops {
        eprintln!("  stopped at {kind} ({n}x), e.g. {example}");
    }
    if totals.unmatched > 0 {
        eprintln!("  {} answers had no n0xis form at all", totals.unmatched);
    }

    // ---- the harness is alive ----------------------------------------------
    //
    // Each of these is a way this file could report "0 disagreements" while
    // having compared nothing at all.

    assert!(totals.functions > 0, "no corpus function reached n0xis — nothing was checked");
    assert!(totals.blocks > 0, "n0xis produced no SSA blocks — nothing was checked");
    assert!(totals.cases > 0, "the processor answered no case — nothing was checked");
    assert_eq!(
        totals.unmatched, 0,
        "{} cases the processor answered had no n0xis form; the driver is handed exactly \
         the names `nm` gave, so this is a join defect and it would silently shrink what \
         is being compared",
        totals.unmatched
    );
    assert_eq!(
        totals.agrees + totals.disagrees.len() + totals.stops_total() + totals.unmatched,
        totals.cases,
        "cases went missing between the processor and the tally"
    );

    // ---- the verdict about the subject -------------------------------------

    assert!(
        totals.disagrees.is_empty(),
        "{} answers differ from what the processor computed:\n  {}",
        totals.disagrees.len(),
        totals.disagrees.iter().take(40).cloned().collect::<Vec<_>>().join("\n  ")
    );

    let unlifted = totals.stops.get("Unlifted").map_or(0, |(n, _)| *n);
    assert!(
        totals.agrees > 0 || unlifted > 0,
        "the run reached no verdict: nothing agreed with the processor and nothing stopped \
         at an unlifted instruction either. On an architecture with no lift every case must \
         stop at `Unlifted`; anything else means this harness starved the pipeline. \
         Stops seen: {:?}",
        totals.stops.keys().collect::<Vec<_>>()
    );

    if totals.agrees == 0 {
        // Nothing has been lifted, so nothing has been *computed*, so every
        // stop must be the lift's absence and not the harness's. An
        // `UndefinedVar` here would mean the argument registers were seeded
        // under the wrong names; a `NoEntry` that the CFG produced no entry
        // block; an `UnreadableMemory` that the image was not attached. Each of
        // those reads as "the IR does not carry this construct" and is nothing
        // of the kind.
        let other: Vec<&&str> = totals.stops.keys().filter(|k| **k != "Unlifted").collect();
        assert!(
            other.is_empty(),
            "no case agreed with the processor, so no instruction has been lifted — yet \
             {} of the {} stops were not `Unlifted`: {:?}. On an unlifted architecture that \
             is this harness failing, not the IR being incomplete. (If the lift has since \
             begun and genuinely stops for one of these reasons before any function \
             completes, that is the state to report here — with the numbers.)",
            totals.stops_total() - unlifted,
            totals.stops_total(),
            other
        );
        eprintln!(
            "\nMEASURING: the AArch64 lift does not exist yet. All {} processor answers \
             across {} functions and {} SSA blocks stopped at `EmuError::Unlifted` — the \
             IR carries the instruction text and none of its meaning, so **nothing was \
             compared**. `0 disagreements` above means \"no number was ever produced\", \
             not \"every number was right\". This harness is live and will start comparing \
             the moment `n0xis_arch::Arm64` lifts anything.",
            totals.cases, totals.functions, totals.blocks
        );
    } else {
        eprintln!(
            "\nMEASURING: the AArch64 lift is live. {} of {} processor answers were \
             reproduced by the recovered program, {} stopped at a construct the IR does \
             not carry, and {} differed.",
            totals.agrees,
            totals.cases,
            totals.stops_total(),
            totals.disagrees.len()
        );
    }
}

/// Check one compiled shape.
fn check_one_build(so: &Path, driver: &Path, arch: &Arm64, level: &str) -> Tally {
    let addrs = addresses(so);
    assert!(!addrs.is_empty(), "{level}: {NM} found no emu_* exports — the corpus did not build");

    let mut args: Vec<String> =
        vec![so.display().to_string(), CASES.to_string()];
    args.extend(addrs.keys().cloned());
    let out = Command::new(QEMU)
        .args(["-L", SYSROOT])
        .arg(driver)
        .args(&args)
        .output()
        .expect("qemu runs");
    assert!(
        out.status.success(),
        "{level}: the driver failed under {QEMU}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cases = parse_cases(&String::from_utf8_lossy(&out.stdout));
    assert!(
        cases.len() >= addrs.len(),
        "{level}: the processor answered {} cases for {} functions",
        cases.len(),
        addrs.len()
    );

    let elf = StaticElf::load(so).expect("n0xis loads the same library");
    // An independent statement that n0xis is looking at the AArch64 object the
    // cross toolchain produced, and not at a stale x86 build left in the temp
    // directory by a sibling test.
    assert_eq!(elf.machine(), "arm64", "{level}: n0xis did not load an AArch64 image");

    // `Ctx::new` starts empty — no symbols, no vtables, no function table — and
    // a pass measured without them measures the harness. The symbol table is
    // what lets a call through a GOT slot be recognized by its callee's name,
    // and its absence has already produced one confident wrong measurement in
    // this project ("19 functions stopping at an unresolved indirect jump",
    // every one of them a tail call to a named import).
    let ctx = Ctx::new(&elf, arch as &dyn Arch).with_symbols(&elf as &dyn SymbolProvider);

    let mut tally = Tally::default();
    let mut forms = BTreeMap::new();
    let mut ir_failures: Vec<String> = Vec::new();
    for (name, addr) in &addrs {
        let cfg = match CfgPass.run(&ctx, CfgInput::new(Va(*addr), 4096)) {
            Ok(c) => c,
            Err(e) => {
                ir_failures.push(format!("{name}: CFG failed: {e}"));
                continue;
            }
        };
        match SsaPass.run(&ctx, cfg) {
            Ok(ssa) => {
                tally.functions += 1;
                tally.blocks += ssa.blocks.len();
                forms.insert(name.clone(), ssa);
            }
            Err(e) => ir_failures.push(format!("{name}: SSA failed: {e}")),
        }
    }
    // A function whose IR never built contributes no case to any tally, so it
    // would leave the counts looking clean while shrinking what was measured.
    assert!(
        ir_failures.is_empty(),
        "{level}: {} of {} corpus functions produced no IR:\n  {}",
        ir_failures.len(),
        addrs.len(),
        ir_failures.join("\n  ")
    );

    for case in &cases {
        tally.cases += 1;
        let Some(ssa) = forms.get(&case.func) else {
            tally.unmatched += 1;
            continue;
        };
        // A register the function never wrote holds whatever the caller left
        // there; refusing would report a correct prologue as a defect. Whatever
        // gets invented would have to match the hardware's answer to pass, so
        // an answer that leaned on one shows up as a disagreement.
        let cfg = EmuConfig { entry_scratch: true, ..Default::default() };
        let mut emu =
            Emulator::with_config(&ssa.blocks, Some(&elf as &dyn MemorySource), cfg);
        // AAPCS64: the first eight integer arguments arrive in x0-x7. The
        // driver passes four, so the rest stay undefined exactly as they are on
        // the hardware.
        for (reg, val) in ARG_REGS.iter().zip(&case.args) {
            emu.set_var(reg, *val);
        }
        tally.record(case, emu.run().map(|r| r.ret));
    }

    eprintln!(
        "\naarch64 {level}: {} functions, {} blocks, {} answers -> {} agree, {} disagree, \
         {} not modelled",
        tally.functions,
        tally.blocks,
        tally.cases,
        tally.agrees,
        tally.disagrees.len(),
        tally.stops_total()
    );
    for d in tally.disagrees.iter().take(20) {
        eprintln!("  WRONG  {d}");
    }
    for (kind, (n, example)) in &tally.stops {
        eprintln!("  gap    {kind} ({n}x), e.g. {example}");
    }
    if tally.unmatched > 0 {
        eprintln!("  unmatched  {} answers had no n0xis form at all", tally.unmatched);
    }
    tally
}
