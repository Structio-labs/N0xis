// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Everything measured so far was an ELF.**
//!
//! The oracle corpora, the 1920 leaf comparisons, the calls, the floating
//! point — all of it compiled with gcc, loaded by n0xis's ELF reader, and run
//! under System V. PE and Win64 had a corpus of their own for *format*
//! questions and no execution anywhere, so a defect in the PE path or in the
//! Win64 half of the ABI had nothing that could see it. "It builds for
//! Windows" is not a measurement.
//!
//! This is the same instrument pointed at the other platform: the same two
//! corpora built as DLLs by mingw, the same driver built as an `.exe`, run on
//! the real processor under Wine, and compared against what n0xis recovers
//! from the PE. What changes between the two runs is everything that is not
//! arithmetic — the container format, the loader's image base, which registers
//! carry arguments (`rcx, rdx, r8, r9`, not `rdi, rsi, …`), and which
//! registers a call is allowed to destroy.
//!
//! The *answers* do not change: `emu_add32(0, 0xffffffff)` is `0xffffffff` on
//! both, because the C says so. That is what makes the comparison worth
//! anything — the expected value comes from the hardware, on this platform,
//! and any difference is n0xis's.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use n0xis_arch::X64;
use n0xis_contracts::Va;
use n0xis_core::{CfgInput, CfgPass, Ctx, EmuConfig, Emulator, OptimizePass, Pass, SsaPass};
use n0xis_sources::{MemorySource, StaticImage};

const CC: &str = "x86_64-w64-mingw32-gcc";
const NM: &str = "x86_64-w64-mingw32-nm";

fn oracle_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("oracle")
}

fn have(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

/// Wine, quiet. The default prefix starts a .NET optimization service that
/// prints a page of diagnostics and adds seconds to every run; neither is this
/// test's business, and only stdout is read.
fn wine(exe: &str, args: &[String], cwd: &Path) -> std::process::Output {
    Command::new("wine")
        .arg(exe)
        .args(args)
        .current_dir(cwd)
        .env("WINEDEBUG", "-all")
        .env("WINEDLLOVERRIDES", "mscoree=d")
        .output()
        .expect("wine runs")
}

#[derive(Debug)]
struct CpuCase {
    func: String,
    args: Vec<u64>,
    ret: u64,
}

fn parse_cases(stdout: &str) -> Vec<CpuCase> {
    stdout
        .lines()
        .filter(|l| l.starts_with('{') && l.contains("\"fn\""))
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("driver emits JSON");
            CpuCase {
                func: v["fn"].as_str().expect("fn").to_string(),
                args: v["args"].as_array().expect("args").iter().map(|a| a.as_u64().expect("u64")).collect(),
                ret: v["ret"].as_u64().expect("u64 ret"),
            }
        })
        .collect()
}

/// Exported functions and their **absolute** addresses, from mingw's `nm` —
/// an independent parser again, and one that has already added the image base
/// the PE header declares. If n0xis read that base differently, every address
/// would be wrong by a constant and the whole run would fail on unreadable
/// memory rather than on arithmetic, which is a distinction worth keeping.
fn exports(dll: &Path) -> BTreeMap<String, u64> {
    let out = Command::new(NM)
        .args(["--defined-only"])
        .arg(dll)
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
            && !name.starts_with("emu_call_")
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
fn a_windows_dll_computes_what_the_processor_computes() {
    if !have(CC) || !have(NM) || !have("wine") {
        eprintln!("skip: needs {CC}, {NM} and wine — nothing was checked");
        return;
    }
    let dir = oracle_dir();
    let tmp = std::env::temp_dir().join("n0xis-emu-win");
    std::fs::create_dir_all(&tmp).expect("tmp dir");
    let built = Command::new(CC)
        .args(["-O2", "-o", "emu_run.exe"])
        .arg(dir.join("emu_run.c"))
        .current_dir(&tmp)
        .status()
        .expect("mingw runs");
    assert!(built.success(), "{CC} could not build oracle/emu_run.c");

    // Both corpora, and only these two: `emu_calls.c` reaches a callee defined
    // in the driver executable, which on Windows needs an import library the
    // corpus does not have. Calls on Win64 are worth measuring and are not
    // measured here — recorded, not skipped quietly.
    let mut totals = (0usize, 0usize, 0usize);
    for corpus in ["emu.c", "emu_fp.c"] {
        for level in ["-O0", "-O1", "-O2", "-Os"] {
            let name = format!("{}{level}.dll", corpus.trim_end_matches(".c"));
            let built = Command::new(CC)
                .args([level, "-shared", "-o", &name])
                .arg(dir.join(corpus))
                .current_dir(&tmp)
                .status()
                .expect("mingw runs");
            assert!(built.success(), "{CC} could not build oracle/{corpus} at {level}");
            let (a, d, g) = check_one(&tmp, &name, &format!("{corpus} {level}"));
            totals = (totals.0 + a, totals.1 + d, totals.2 + g);
        }
    }
    eprintln!(
        "\nwin64, all levels: {} agree, {} disagree, {} not modelled",
        totals.0, totals.1, totals.2
    );
    assert!(totals.0 > 0, "nothing was actually checked");
}

fn check_one(tmp: &Path, dll_name: &str, label: &str) -> (usize, usize, usize) {
    let dll = tmp.join(dll_name);
    let addrs = exports(&dll);
    assert!(!addrs.is_empty(), "{label}: nm found no emu_* exports");

    let mut args: Vec<String> = vec![dll_name.to_string(), "8".to_string()];
    args.extend(addrs.keys().cloned());
    let out = wine("emu_run.exe", &args, tmp);
    let cases = parse_cases(&String::from_utf8_lossy(&out.stdout));
    assert!(
        cases.len() >= addrs.len(),
        "{label}: the driver answered {} cases for {} functions:\n{}",
        cases.len(),
        addrs.len(),
        String::from_utf8_lossy(&out.stderr)
    );

    let image = StaticImage::load(&dll).expect("n0xis loads the same DLL");
    let arch = X64::new();
    let ctx = Ctx::new(&image, &arch);
    // Win64 passes integers in `rcx, rdx, r8, r9`. Asked for, never spelled:
    // the whole point of this file is that the platform changed, and a literal
    // register list here would be the one thing that did not notice.
    let arg_regs = n0xis_core::abi_arg_registers(&ctx);
    assert_eq!(arg_regs.first().copied(), Some("rcx"), "{label}: the PE's ABI did not resolve to Win64");

    let mut forms = BTreeMap::new();
    for (name, addr) in &addrs {
        let Ok(cfg) = CfgPass.run(&ctx, CfgInput::new(Va(*addr), 4096)) else {
            panic!("{label}: {name}: CFG failed");
        };
        let ssa = SsaPass.run(&ctx, cfg).unwrap_or_else(|e| panic!("{label}: {name}: {e}"));
        let opt = OptimizePass.run(&ctx, ssa.clone()).unwrap_or_else(|e| panic!("{label}: {name}: {e}"));
        forms.insert(name.clone(), (ssa, opt));
    }

    let mut ssa_tally = Tally::default();
    let mut opt_tally = Tally::default();
    let mut optimizer_changed_meaning: Vec<String> = Vec::new();

    for case in &cases {
        let Some((ssa, opt)) = forms.get(&case.func) else { continue };
        let run = |blocks: &[n0xis_core::SsaBlock]| {
            let cfg = EmuConfig { entry_scratch: true, ..Default::default() };
            let mut emu = Emulator::with_config(blocks, Some(&image as &dyn MemorySource), cfg);
            for (reg, val) in arg_regs.iter().zip(&case.args) {
                emu.set_var(reg, *val);
            }
            emu.run().map(|r| r.ret)
        };
        let record = |tally: &mut Tally, got: Result<Option<u64>, n0xis_core::EmuError>| match got {
            Ok(Some(v)) if v == case.ret => tally.agrees += 1,
            Ok(Some(v)) => tally.disagrees.push(format!(
                "{}({:#x}, {:#x}, {:#x}, {:#x}) → n0xis {v:#x}, the CPU {:#x}",
                case.func, case.args[0], case.args[1], case.args[2], case.args[3], case.ret
            )),
            Ok(None) => tally.disagrees.push(format!(
                "{}: the IR returned nothing; the CPU returned {:#x}",
                case.func, case.ret
            )),
            Err(e) => {
                *tally.not_modelled.entry(format!("{}: {e}", case.func)).or_default() += 1;
            }
        };
        let a = run(&ssa.blocks);
        let b = run(&opt.blocks);
        if let (Ok(Some(x)), Ok(Some(y))) = (&a, &b)
            && x != y
        {
            optimizer_changed_meaning
                .push(format!("{}({:#x}, …) → SSA {x:#x}, optimized {y:#x}", case.func, case.args[0]));
        }
        record(&mut ssa_tally, a);
        record(&mut opt_tally, b);
    }

    for (which, t) in [("over SSA", &ssa_tally), ("over the optimized form", &opt_tally)] {
        eprintln!(
            "\n{label} {which}: {} agree, {} disagree, {} not modelled",
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
    }

    assert!(
        optimizer_changed_meaning.is_empty(),
        "{label}: the optimizer changed what the program computes:\n  {}",
        optimizer_changed_meaning.join("\n  ")
    );
    for (which, t) in [("SSA", &ssa_tally), ("optimized", &opt_tally)] {
        assert!(
            t.disagrees.is_empty(),
            "{label} {which} form: {} answers differ from what the processor computed:\n  {}",
            t.disagrees.len(),
            t.disagrees.join("\n  ")
        );
        let gaps: Vec<&String> = t.not_modelled.keys().collect();
        assert!(
            gaps.is_empty(),
            "{label} {which} form: {} constructs the IR does not carry:\n  {}",
            gaps.len(),
            gaps.iter().map(|g| g.as_str()).collect::<Vec<_>>().join("\n  ")
        );
    }
    (
        ssa_tally.agrees + opt_tally.agrees,
        ssa_tally.disagrees.len() + opt_tally.disagrees.len(),
        ssa_tally.not_modelled.values().sum::<usize>() + opt_tally.not_modelled.values().sum::<usize>(),
    )
}
