// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The processor is the oracle, past the call this time.**
//!
//! [`emulator_agrees_with_the_cpu`] checks leaf functions: 1920 comparisons
//! over four optimization levels, no disagreements. It could only check
//! leaves, because a `call` had no answer — the emulator reported
//! "not modelled" and stopped. On real code that was the largest single gap:
//! 110 of 400 functions in a shipped library stopped at exactly this.
//!
//! A call needs four decisions, and each is a place a plausible wrong answer
//! could be produced instead:
//!
//! * **who** — a direct branch names the callee; a shared object calling its
//!   own exported function names a *PLT stub* and the body is elsewhere; an
//!   indirect call names nothing until the target expression is evaluated.
//! * **what the callee sees** — its register file is the caller's. A callee
//!   that `push`es a callee-saved register reads the caller's value of it.
//! * **where its frame goes** — below the return address the `call` pushed. An
//!   argument passed on the stack is only found if that is exactly right.
//! * **when to stop** — recursion ends at a stated depth, as a named error.
//!
//! None of those is decided here by guessing. The callee's body comes from a
//! [`CodeProvider`]; a callee outside the image is answered by a *stated* stub
//! value, and one that is neither stays [`EmuError::CallNotModelled`]. The
//! test that this is honest is the same as before: `oracle/emu_calls.c` runs
//! on the real processor, and the numbers must match.
//!
//! [`emulator_agrees_with_the_cpu`]: ../emulator_agrees_with_the_cpu/index.html

#![cfg(feature = "oracle")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use n0xis_arch::X64;
use n0xis_contracts::Va;
use n0xis_core::{
    BodyMap, CallPolicy, CfgInput, CfgPass, CodeProvider, Ctx, EmuConfig, Emulator, OptimizePass,
    Pass, SsaBlock, SsaPass,
};
use n0xis_sources::{MemorySource, StaticElf, SymbolProvider};

/// An arbitrary but fixed canary, as in the leaf test: its value never reaches
/// a result, only its consistency between prologue and epilogue does.
const STACK_CANARY: u64 = 0x5ec0_ffee_dead_1234;

/// SysV's integer argument registers, in order — the driver passes four.
const ARG_REGS: [&str; 4] = ["rdi", "rsi", "rdx", "rcx"];

/// Deep enough for `emu_h_fact(7)` plus the frames above it, shallow enough
/// that a lost termination condition is a named error and not a hang.
const MAX_DEPTH: usize = 24;

/// The one exported function in the corpus that is a leaf on purpose: it exists
/// to be *called* — by `emu_call_through_plt`, through the PLT — and calls
/// nothing itself. Everything else exported must go through a call, or this
/// test is not testing calls. One name with a reason, rather than a threshold
/// that lets any future silent leaf through.
const DELIBERATE_LEAVES: [&str; 1] = ["emu_call_exported_target"];

fn oracle_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("oracle")
}

fn have(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

/// Every C compiler on this machine. One compiler is one shape of blindness in
/// exactly the way one optimization level is — gcc and clang differ on how a
/// call is set up, on whether a small callee is reached through a register or a
/// direct branch, and on which registers survive it.
fn compilers() -> Vec<&'static str> {
    ["gcc", "clang"].into_iter().filter(|c| have(c)).collect()
}

#[derive(Debug)]
struct CpuCase {
    func: String,
    args: Vec<u64>,
    ret: u64,
}

/// What the driver reported: the cases, and the one value it owns.
///
/// `emu_ext_const` is defined in the driver executable, not in the library, so
/// nothing that reads the library can know what it returns. The driver prints
/// it, and that printed number is the stub value handed to the emulator — one
/// fact, one place. A copy of it in this file would be a second definition of
/// the same thing, which is how every drift in this project started.
fn parse_driver(stdout: &str) -> (Vec<CpuCase>, Option<u64>) {
    let mut cases = Vec::new();
    let mut ext = None;
    for line in stdout.lines().filter(|l| l.starts_with('{')) {
        let v: serde_json::Value = serde_json::from_str(line).expect("driver emits JSON");
        if v.get("extern").is_some() {
            ext = v["value"].as_u64();
            continue;
        }
        cases.push(CpuCase {
            func: v["fn"].as_str().expect("fn").to_string(),
            args: v["args"].as_array().expect("args").iter().map(|a| a.as_u64().expect("u64")).collect(),
            ret: v["ret"].as_u64().expect("u64 ret"),
        });
    }
    (cases, ext)
}

/// Symbols from `nm` — an independent parser, not n0xis's own symbol table.
/// `-D` narrows to the dynamic table (the entry points the driver can call);
/// without it, the corpus's own `emu_h_*` helpers come too.
fn symbols(so: &Path, dynamic: bool) -> BTreeMap<String, u64> {
    let mut cmd = Command::new("nm");
    if dynamic {
        cmd.arg("-D");
    }
    let out = cmd
        .arg("--defined-only")
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
        let wanted = if dynamic { name.starts_with("emu_call_") } else { name.starts_with("emu_") };
        if (kind == "T" || kind == "t")
            && wanted
            && let Ok(a) = u64::from_str_radix(addr, 16)
        {
            map.insert(name.to_string(), a);
        }
    }
    map
}

/// The PLT stub for an imported name, from `objdump` — again an outside
/// parser. n0xis's own view of the PLT is what the `thunk_to` half of this
/// test exercises, so the *import* half must not be taken from the same place.
fn plt_stub(so: &Path, name: &str) -> Option<u64> {
    let out = Command::new("objdump").arg("-d").arg(so).env("LC_ALL", "C").output().ok()?;
    let want = format!("<{name}@plt>:");
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if line.trim_end().ends_with(&want)
            && let Some(addr) = line.split_whitespace().next()
            && let Ok(a) = u64::from_str_radix(addr, 16)
        {
            return Some(a);
        }
    }
    None
}

/// The callee supply: bodies the corpus defines, plus the one callee it does
/// not — and the PLT stubs in between.
struct Bodies<'a> {
    map: BodyMap,
    elf: &'a StaticElf,
    ext_plt: Option<u64>,
    ext_value: u64,
}

impl CodeProvider for Bodies<'_> {
    fn body(&self, va: Va) -> Option<&[SsaBlock]> {
        // A shared object calls its own exported functions through the PLT, so
        // the address in the `call` is a stub and the body is elsewhere. Which
        // function this *is* is a symbol question, and the relocation answers
        // it — `thunk_to` reads the `JUMP_SLOT` whose `st_value` names a local
        // definition. Without this the call lands on six bytes of jump table.
        self.map.body(va).or_else(|| self.elf.thunk_to(va).and_then(|t| self.map.body(t)))
    }

    fn stub(&self, va: Va, _args: &[Option<u64>]) -> Option<u64> {
        // Exactly one callee is stubbed, at exactly one address, with a value
        // the driver printed. Everything else with no body stays an error.
        (Some(va.0) == self.ext_plt).then_some(self.ext_value)
    }
}

#[derive(Default, Debug)]
struct Tally {
    agrees: usize,
    disagrees: Vec<String>,
    not_modelled: BTreeMap<String, usize>,
}

#[test]
fn a_call_runs_the_callee_and_the_answer_is_the_processors() {
    if !have("gcc") || !have("nm") || !have("objdump") {
        eprintln!("skip: needs gcc, nm and objdump — nothing was checked");
        return;
    }
    let dir = oracle_dir();
    let tmp = std::env::temp_dir().join("n0xis-emu-calls");
    std::fs::create_dir_all(&tmp).expect("tmp dir");
    let driver = tmp.join("emu_run");
    // `-rdynamic` is what lets the library resolve `emu_ext_const` back into
    // this executable — the whole point of that case.
    let built = Command::new("gcc")
        .args(["-O2", "-rdynamic", "-o"])
        .arg(&driver)
        .arg(dir.join("emu_run.c"))
        .arg("-ldl")
        .status()
        .expect("gcc runs");
    assert!(built.success(), "gcc could not build oracle/emu_run.c");

    let mut totals = (0usize, 0usize, 0usize);
    let mut executed = 0usize;
    // Which functions ever went through a call at all. This is the
    // calibration: turn the call policy back to `Refuse` and every one of
    // these is zero, so the test fails on its own assertion rather than
    // passing while measuring nothing.
    let mut reached: BTreeMap<String, usize> = BTreeMap::new();

    for cc in compilers() {
        for level in ["-O0", "-O1", "-O2", "-Os"] {
            let so = tmp.join(format!("emu_calls-{cc}{level}.so"));
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
                .arg(dir.join("emu_calls.c"))
                .status()
                .expect("the compiler runs");
            assert!(built.success(), "{cc} could not build oracle/emu_calls.c at {level}");
            let label = format!("{cc} {level}");
            let (a, d, g) = check_one_build(&so, &driver, &label, &mut reached, &mut executed);
            totals = (totals.0 + a, totals.1 + d, totals.2 + g);
        }
    }

    eprintln!(
        "\nall levels: {} agree, {} disagree, {} not modelled; {executed} callee frames executed",
        totals.0, totals.1, totals.2
    );
    assert!(totals.0 > 0, "nothing was actually checked");
    let never: Vec<&String> = reached
        .iter()
        .filter(|(f, n)| **n == 0 && !DELIBERATE_LEAVES.contains(&f.as_str()))
        .map(|(f, _)| f)
        .collect();
    assert!(
        never.is_empty(),
        "these functions never went through a call, so this test did not check what it says \
         it checks:\n  {}",
        never.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n  ")
    );
}

fn check_one_build(
    so: &Path,
    driver: &Path,
    level: &str,
    reached: &mut BTreeMap<String, usize>,
    executed: &mut usize,
) -> (usize, usize, usize) {
    let entries = symbols(so, true);
    let all = symbols(so, false);
    assert!(!entries.is_empty(), "nm found no emu_call_* exports — the corpus did not build");
    assert!(all.len() > entries.len(), "nm found no emu_h_* helpers — the calls were inlined away");

    let mut args: Vec<String> = vec![so.display().to_string(), "8".to_string()];
    args.extend(entries.keys().cloned());
    let out = Command::new(driver).args(&args).output().expect("driver runs");
    assert!(out.status.success(), "driver failed: {}", String::from_utf8_lossy(&out.stderr));
    let (cases, ext_value) = parse_driver(&String::from_utf8_lossy(&out.stdout));
    let ext_value = ext_value.expect("the driver prints the constant it owns");
    let ext_plt = plt_stub(so, "emu_ext_const");
    assert!(ext_plt.is_some(), "{level}: no PLT stub for emu_ext_const — the import case is absent");

    let elf = StaticElf::load(so).expect("n0xis loads the same library");
    let arch = X64::new();
    let ctx = Ctx::new(&elf, &arch);

    // Every function in the corpus, in both forms. The callee a run executes
    // is the *same form* as its caller, so the optimized run judges the
    // optimizer end to end and not a mixture of the two.
    let mut ssa_bodies = BodyMap::new();
    let mut opt_bodies = BodyMap::new();
    let mut skipped = Vec::new();
    for (name, addr) in &all {
        let Ok(cfg) = CfgPass.run(&ctx, CfgInput::new(Va(*addr), 4096)) else {
            skipped.push(name.clone());
            continue;
        };
        let Ok(ssa) = SsaPass.run(&ctx, cfg) else {
            skipped.push(name.clone());
            continue;
        };
        let opt = OptimizePass.run(&ctx, ssa.clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
        ssa_bodies.insert(Va(*addr), ssa.blocks);
        opt_bodies.insert(Va(*addr), opt.blocks);
    }
    assert!(skipped.is_empty(), "{level}: no IR for {skipped:?}");

    let ssa_code = Bodies { map: ssa_bodies, elf: &elf, ext_plt, ext_value };
    let opt_code = Bodies { map: opt_bodies, elf: &elf, ext_plt, ext_value };

    let mut ssa_tally = Tally::default();
    let mut opt_tally = Tally::default();
    let mut optimizer_changed_meaning: Vec<String> = Vec::new();

    for case in &cases {
        let Some(addr) = entries.get(&case.func) else { continue };
        reached.entry(case.func.clone()).or_insert(0);
        let mut run = |code: &Bodies<'_>, tally: &mut Tally| -> Option<u64> {
            let Some(blocks) = code.body(Va(*addr)) else {
                tally.not_modelled.insert(format!("{}: no body", case.func), 1);
                return None;
            };
            let cfg = EmuConfig {
                entry_scratch: true,
                calls: CallPolicy::Execute { max_depth: MAX_DEPTH },
                ..Default::default()
            };
            let mut emu = Emulator::with_config(blocks, Some(&elf as &dyn MemorySource), cfg)
                .with_code(code as &dyn CodeProvider)
                // The argument registers come from the architecture's own
                // calling convention, through the same lookup the lift used to
                // build the call in the first place. Spelling `rdi, rsi, …` out
                // here would be a second copy of the ABI, and the first thing
                // this test found is what happens when two copies of one fact
                // drift.
                .with_arg_regs(n0xis_core::abi_arg_registers(&ctx));
            for (reg, val) in ARG_REGS.iter().zip(&case.args) {
                emu.set_var(reg, *val);
            }
            emu.write_mem(n0xis_core::DEFAULT_FS_BASE + 0x28, STACK_CANARY, 64);
            match emu.run() {
                Ok(r) => {
                    *executed += r.calls;
                    *reached.get_mut(&case.func).expect("just inserted") += r.calls + r.stubbed;
                    match (r.ret, case.ret) {
                        (Some(v), want) if v == want => {
                            tally.agrees += 1;
                            Some(v)
                        }
                        (Some(v), want) => {
                            tally.disagrees.push(format!(
                                "{}({:#x}, {:#x}, {:#x}, {:#x}) → n0xis {v:#x}, the CPU {want:#x}",
                                case.func, case.args[0], case.args[1], case.args[2], case.args[3]
                            ));
                            Some(v)
                        }
                        (None, want) => {
                            tally.disagrees.push(format!(
                                "{}: the IR returned nothing; the CPU returned {want:#x}",
                                case.func
                            ));
                            None
                        }
                    }
                }
                Err(e) => {
                    *tally.not_modelled.entry(format!("{}: {e}", case.func)).or_default() += 1;
                    None
                }
            }
        };
        let a = run(&ssa_code, &mut ssa_tally);
        let b = run(&opt_code, &mut opt_tally);
        if let (Some(a), Some(b)) = (a, b)
            && a != b
        {
            optimizer_changed_meaning.push(format!(
                "{}({:#x}, …) → SSA {a:#x}, optimized {b:#x}",
                case.func, case.args[0]
            ));
        }
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
    report("over SSA", &ssa_tally);
    report("over the optimized form", &opt_tally);

    assert!(
        optimizer_changed_meaning.is_empty(),
        "{level}: the optimizer changed what the program computes:\n  {}",
        optimizer_changed_meaning.join("\n  ")
    );
    for (label, t) in [("SSA", &ssa_tally), ("optimized", &opt_tally)] {
        assert!(
            t.disagrees.is_empty(),
            "{level} {label} form: {} answers differ from what the processor computed:\n  {}",
            t.disagrees.len(),
            t.disagrees.join("\n  ")
        );
        let gaps: Vec<&String> = t.not_modelled.keys().collect();
        assert!(
            gaps.is_empty(),
            "{level} {label} form: {} constructs the IR does not carry. Model them, or record \
             the refusal and say why here:\n  {}",
            gaps.len(),
            gaps.iter().map(|g| g.as_str()).collect::<Vec<_>>().join("\n  ")
        );
    }
    (
        ssa_tally.agrees + opt_tally.agrees,
        ssa_tally.disagrees.len() + opt_tally.disagrees.len(),
        ssa_tally.not_modelled.values().sum::<usize>()
            + opt_tally.not_modelled.values().sum::<usize>(),
    )
}
