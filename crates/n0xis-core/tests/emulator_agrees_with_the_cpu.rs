// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The processor is the oracle.**
//!
//! Eleven layers of this project are checked against an outside source. Three
//! were not, and could not be by the same method: SSA, the optimizer, and the
//! arithmetic of the decompiled body. No second tool settles those — a second
//! tool guesses too. The question is not "what does another disassembler
//! think", it is "what does the machine do", and only one thing answers that.
//!
//! So: `oracle/emu.c` holds leaf functions; `oracle/emu_run.c` dlopens the
//! compiled library and calls each one on planted inputs, printing what came
//! back. That output is rung 1 — an answer that exists before the question is
//! asked, produced by hardware, with no tool in the path. This test hands the
//! *same* inputs to n0xis's own recovered form of the *same* function and
//! compares the numbers.
//!
//! Each function is run twice: over the SSA form and over the optimized form.
//! A disagreement with the CPU is a lie in the lift or in SSA construction; a
//! disagreement *between the two runs* is the optimizer changing what the
//! program means.
//!
//! Three outcomes, kept apart on purpose:
//!
//! * **agrees** — the recovered program computes what the hardware computed.
//! * **not modelled** — the emulator stopped and said which construct the IR
//!   does not carry. Honest, and countable; it is a gap, not a lie.
//! * **disagrees** — the recovered program returned a *different number*. This
//!   is the only bad outcome, and the only one a user would ever act on.
//!
//! The counts are ratcheted. `disagrees` must stay at its recorded floor, and
//! the floor may only be lowered by a commit that says why.

#![cfg(feature = "oracle")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use n0xis_arch::X64;
use n0xis_contracts::Va;
use n0xis_core::{CfgInput, CfgPass, Ctx, Emulator, OptimizePass, Pass, SsaPass};
use n0xis_sources::StaticElf;

/// An arbitrary but fixed canary. Its value never reaches a result; only its
/// consistency between the prologue's store and the epilogue's compare does.
const STACK_CANARY: u64 = 0x5ec0_ffee_dead_1234;

/// SysV's integer argument registers, in order — the driver passes four.
const ARG_REGS: [&str; 4] = ["rdi", "rsi", "rdx", "rcx"];

// **Both floors are zero, and both are assertions rather than budgets.**
//
// A *wrong number* is never acceptable — it is the one outcome a user would act
// on — so `disagrees` must be empty, always. A *gap* is acceptable in principle
// but not silently: a new corpus case whose construct the IR does not carry
// must fail here, so it is either modelled or recorded as refused. Neither is
// a ratchet with slack, because slack is where a regression hides.

fn oracle_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("oracle")
}

fn have(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

/// Every C compiler on this machine, because one compiler is one shape of
/// blindness in exactly the way one optimization level is. gcc and clang pick
/// different instructions for the same source — different idioms for a branch,
/// a select, a narrow compare — so a lift that is right for one selection is
/// not thereby right.
fn compilers() -> Vec<&'static str> {
    ["gcc", "clang"].into_iter().filter(|c| have(c)).collect()
}

/// One case as the CPU answered it. Note that the *arguments* are read back
/// from the driver's own output rather than recomputed here: the walk over the
/// value list is one fact, and it lives in `emu_run.c`.
#[derive(Debug)]
struct CpuCase {
    func: String,
    args: Vec<u64>,
    ret: u64,
}

fn parse_cases(stdout: &str) -> Vec<CpuCase> {
    stdout
        .lines()
        .filter(|l| l.starts_with('{'))
        // The driver also prints the one constant it owns, for the sibling
        // test that stubs an import. Not a case; skipped by shape, not by
        // position, so neither test cares what order the driver prints in.
        .filter(|l| l.contains("\"fn\""))
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

/// Function addresses from `nm` — an independent parser, not n0xis's own
/// symbol table. If n0xis placed a function wrongly, emulating the bytes it
/// points at would fail in a way that reads like an arithmetic defect; taking
/// the address from outside keeps those two questions separate.
fn addresses(so: &Path) -> BTreeMap<String, u64> {
    let out = Command::new("nm")
        .args(["-D", "--defined-only"])
        .arg(so)
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

#[derive(Default, Debug)]
struct Tally {
    agrees: usize,
    disagrees: Vec<String>,
    not_modelled: BTreeMap<String, usize>,
}

#[test]
fn the_recovered_function_computes_what_the_processor_computes() {
    if !have("gcc") || !have("nm") {
        eprintln!("skip: needs gcc and nm — nothing was checked");
        return;
    }
    let dir = oracle_dir();
    let tmp = std::env::temp_dir().join("n0xis-emu-oracle");
    std::fs::create_dir_all(&tmp).expect("tmp dir");
    let driver = tmp.join("emu_run");
    let built = Command::new("gcc")
        .args(["-O2", "-o"])
        .arg(&driver)
        .arg(dir.join("emu_run.c"))
        .arg("-ldl")
        .status()
        .expect("gcc runs");
    assert!(built.success(), "gcc could not build oracle/emu_run.c");

    // One optimization level is one shape of blindness. `-O0` keeps everything
    // in the frame and reads it back; `-O2` and `-Os` reach for `cmov`, `sbb`,
    // `lea`-as-arithmetic and branchless idioms that never appear at `-O0`.
    // Same source, same expected answers, four different instruction selections
    // — the cheapest way to widen the corpus that exists.
    let mut totals = (0usize, 0usize, 0usize);
    for cc in compilers() {
        for level in ["-O0", "-O1", "-O2", "-Os"] {
            let so = tmp.join(format!("emu-{cc}{level}.so"));
            // **The scalar corpus stays scalar.** Left to itself, clang
            // vectorizes a byte-scatter loop into `pshufd`, and packed SIMD is
            // a layer this emulator does not model and says so — one lane of
            // four is not the answer. A corpus function the compiler turns into
            // a vector operation stops testing what this file is for; the
            // packed layer has its own line in ROADMAP and will get its own
            // corpus when it gets a model. Both compilers accept the gcc
            // spelling, and on clang it was checked to actually silence the
            // vectorizer rather than merely be accepted.
            let built = Command::new(cc)
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
                .status()
                .expect("the compiler runs");
            assert!(built.success(), "{cc} could not build oracle/emu.c at {level}");
            let (a, d, g) = check_one_build(&so, &driver, &format!("{cc} {level}"));
            totals = (totals.0 + a, totals.1 + d, totals.2 + g);
        }
    }
    eprintln!(
        "\nall levels: {} agree, {} disagree, {} not modelled",
        totals.0, totals.1, totals.2
    );
    assert!(totals.0 > 0, "nothing was actually checked");
}

/// Check one compiled shape, and return `(agree, disagree, gaps)`.
fn check_one_build(so: &Path, driver: &Path, level: &str) -> (usize, usize, usize) {
    let addrs = addresses(so);
    assert!(!addrs.is_empty(), "nm found no emu_* exports — the corpus did not build");

    let mut args: Vec<String> = vec![so.display().to_string(), "8".to_string()];
    args.extend(addrs.keys().cloned());
    let out = Command::new(driver).args(&args).output().expect("driver runs");
    assert!(out.status.success(), "driver failed: {}", String::from_utf8_lossy(&out.stderr));
    let cases = parse_cases(&String::from_utf8_lossy(&out.stdout));
    assert!(cases.len() >= addrs.len(), "the CPU answered fewer cases than there are functions");

    let elf = StaticElf::load(so).expect("n0xis loads the same library");
    let arch = X64::new();
    let ctx = Ctx::new(&elf, &arch);

    // Build each function's IR once; the cases only change the inputs.
    let mut forms = BTreeMap::new();
    for (name, addr) in &addrs {
        let cfg = match CfgPass.run(&ctx, CfgInput::new(Va(*addr), 4096)) {
            Ok(c) => c,
            Err(e) => panic!("{name}: CFG failed: {e}"),
        };
        let ssa = SsaPass.run(&ctx, cfg).unwrap_or_else(|e| panic!("{name}: SSA failed: {e}"));
        let opt = OptimizePass
            .run(&ctx, ssa.clone())
            .unwrap_or_else(|e| panic!("{name}: optimize failed: {e}"));
        forms.insert(name.clone(), (ssa, opt));
    }

    let invented: std::cell::RefCell<std::collections::BTreeSet<String>> = Default::default();
    let mut ssa_tally = Tally::default();
    let mut opt_tally = Tally::default();
    let mut optimizer_changed_meaning: Vec<String> = Vec::new();

    for case in &cases {
        let Some((ssa, opt)) = forms.get(&case.func) else { continue };
        let run = |blocks: &[n0xis_core::SsaBlock]| {
            // A register the function never wrote holds whatever the caller
            // left there. `setg %al` merges into exactly such a register at
            // `-O1`, and the next instruction discards the merged-in bits — so
            // refusing would call a correct prologue a defect. Whatever gets
            // invented is reported below, and if an answer actually leaned on
            // one it would differ from the hardware's.
            let cfg = n0xis_core::EmuConfig { entry_scratch: true, ..Default::default() };
            let mut emu = Emulator::with_config(
                blocks,
                Some(&elf as &dyn n0xis_sources::MemorySource),
                cfg,
            );
            for (reg, val) in ARG_REGS.iter().zip(&case.args) {
                emu.set_var(reg, *val);
            }
            // System V's stack protector reads its canary from `%fs:0x28`.
            // Any value does, as long as it is the *same* one both times: the
            // epilogue compares what it stored against what it re-reads, so
            // seeding it exercises that branch instead of skipping it.
            emu.write_mem(n0xis_core::DEFAULT_FS_BASE + 0x28, STACK_CANARY, 64);
            let out = emu.run();
            if let Ok(r) = &out {
                for name in &r.invented {
                    invented.borrow_mut().insert(format!("{}: {name}", case.func));
                }
            }
            out.map(|r| r.ret)
        };
        let record = |tally: &mut Tally, got: Result<Option<u64>, n0xis_core::EmuError>| {
            match got {
                Ok(Some(v)) if v == case.ret => tally.agrees += 1,
                Ok(Some(v)) => tally.disagrees.push(format!(
                    "{}({:#x}, {:#x}, {:#x}, {:#x}) → n0xis {:#x}, the CPU {:#x}",
                    case.func, case.args[0], case.args[1], case.args[2], case.args[3], v, case.ret
                )),
                Ok(None) => tally
                    .disagrees
                    .push(format!("{}: the IR returned nothing; the CPU returned {:#x}", case.func, case.ret)),
                Err(e) => {
                    *tally.not_modelled.entry(format!("{}: {e}", case.func)).or_default() += 1;
                }
            }
        };
        let ssa_ret = run(&ssa.blocks);
        let opt_ret = run(&opt.blocks);
        if let (Ok(Some(a)), Ok(Some(b))) = (&ssa_ret, &opt_ret)
            && a != b
        {
            optimizer_changed_meaning.push(format!(
                "{}({:#x}, …) → SSA {a:#x}, optimized {b:#x}",
                case.func, case.args[0]
            ));
        }
        record(&mut ssa_tally, ssa_ret);
        record(&mut opt_tally, opt_ret);
    }

    let report = |label: &str, t: &Tally| {
        eprintln!(
            "\n{level} {label}: {} agree, {} disagree, {} not modelled",
            t.agrees,
            t.disagrees.len(),
            t.not_modelled.values().sum::<usize>()
        );
        for d in t.disagrees.iter().take(40) {
            eprintln!("  WRONG  {d}");
        }
        for (g, n) in &t.not_modelled {
            eprintln!("  gap    ({n}×) {g}");
        }
    };
    for name in invented.borrow().iter() {
        eprintln!("  {level} scratch  {name}");
    }
    report("over SSA", &ssa_tally);
    report("over the optimized form", &opt_tally);

    assert!(
        optimizer_changed_meaning.is_empty(),
        "{level}: the optimizer changed what the program computes:\n  {}",
        optimizer_changed_meaning.join("\n  ")
    );
    assert!(
        ssa_tally.disagrees.is_empty(),
        "{level} SSA form: {} answers differ from what the processor computed:\n  {}",
        ssa_tally.disagrees.len(),
        ssa_tally.disagrees.join("\n  ")
    );
    assert!(
        opt_tally.disagrees.is_empty(),
        "{level} optimized form: {} answers differ from what the processor computed:\n  {}",
        opt_tally.disagrees.len(),
        opt_tally.disagrees.join("\n  ")
    );
    let gaps: Vec<&String> = ssa_tally.not_modelled.keys().collect();
    assert!(
        gaps.is_empty(),
        "{level}: {} constructs the IR does not carry. Model them, or record the refusal \
         and say why here:\n  {}",
        gaps.len(),
        gaps.iter().map(|g| g.as_str()).collect::<Vec<_>>().join("\n  ")
    );
    (
        ssa_tally.agrees + opt_tally.agrees,
        ssa_tally.disagrees.len() + opt_tally.disagrees.len(),
        ssa_tally.not_modelled.values().sum::<usize>()
            + opt_tally.not_modelled.values().sum::<usize>(),
    )
}
