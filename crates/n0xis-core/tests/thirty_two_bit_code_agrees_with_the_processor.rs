// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Everything measured until now was 64-bit.**
//!
//! Two platforms, two compilers, four optimization levels, thirteen thousand
//! comparisons — and every one of them a 64-bit target. That is not a small
//! omission, because the rule that decides whether an operand's width is
//! *stated in the IR* asked whether the operand filled its **container**. In
//! 64-bit mode that is the same question as "is it 64 bits wide". In 32-bit
//! mode it is a different question: there `eax` **is** the container, so
//! `add eax, ebx` lifted to `rax = rax + rbx` with no width anywhere in it.
//!
//! Every consumer models a 64-bit word. So a 32-bit sum that overflows stayed
//! 33 bits wide with nothing to truncate it, and every signed predicate on a
//! 32-bit value compared a container that is never negative — which is exactly
//! the defect class that cost 52 wrong answers on x86-64 and was never closed
//! one bitness down, because nothing had ever executed a 32-bit target.
//!
//! `oracle/emu32.c` is `uint32_t` in and out, so the i386 convention is four
//! four-byte stack slots and a result in `eax`: no register pairs, nothing but
//! the width under test. The arguments are placed in the emulated stack where
//! the ABI puts them, and the answer comes from the processor.

#![cfg(feature = "oracle")]

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::Command;

use n0xis_arch::X64;
use n0xis_contracts::Va;
use n0xis_core::{
    BodyMap, CallPolicy, CfgInput, CfgPass, CodeProvider, Ctx, EmuConfig, Emulator, OptimizePass,
    Pass, SsaPass,
};
use n0xis_sources::{MemorySource, StaticImage};

/// i386 passes everything on the stack: the return address at `esp`, then the
/// arguments, four bytes each.
const WORD: u64 = 4;

/// A stack that fits in a 32-bit address space.
///
/// The default sits at `0x7fff_0000_0000`, which is fine for a 64-bit target
/// and is *not an address* on this one: `esp` is written through a 32-bit cast,
/// so the top truncates to zero and the first push lands at `0xfffffffc`. A
/// machine property, set where the machine is described.
const STACK32: u64 = 0xbfff_f000;

/// System V on i386 keeps the stack canary at `%gs:0x14`, not `%fs:0x28`. Any
/// value does, as long as it is the same one the epilogue re-reads.
const CANARY32_OFFSET: u64 = 0x14;
const STACK_CANARY: u64 = 0x5ec0_ffee;

/// The one refusal this corpus is allowed to hit, named rather than tolerated.
///
/// **The carry after an addition is not a function of the sum alone.** The IR
/// records an arithmetic op's flags as `Compare { Result, sum, 0 }` — two slots
/// — from which the zero and sign conditions reconstruct exactly and the carry
/// ones cannot: `CF` after `add a, b` is `sum <u a`, and `a` is no longer in
/// the record. So `jb`/`jae`/`sbb` after an `add` come back as *no condition*,
/// which is a refusal and not a wrong answer, and `emu32_carry` — the standard
/// unsigned-overflow idiom, `s = a + b; s + (s < a)` — is here to keep it
/// measured. Closing it needs a flags model with room for both operands, which
/// is an IR change and not a lift fix.
///
/// Anything *else* the IR does not carry still fails this test.
const REFUSED: [&str; 1] = ["cond(jb) after result"];

fn oracle_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("oracle")
}

fn have(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

/// One way of producing and running 32-bit code.
///
/// The **container** is the axis here, not only the bitness: an ELF32 built by
/// gcc or clang and run natively, and a PE32 built by mingw and run under
/// Wine. The instruction set is the same and almost nothing else is — the
/// image format, the loader's base, the position-independence idiom, the
/// stack-protector convention. Every one of those has produced a defect on one
/// of the other axes already.
struct Target {
    label: &'static str,
    cc: &'static str,
    /// Flags that select 32-bit output for this compiler.
    bitness_flag: &'static [&'static str],
    ext: &'static str,
    /// The driver, and how to run it.
    driver_ext: &'static str,
    under_wine: bool,
}

const TARGETS: [Target; 3] = [
    Target { label: "elf32 gcc", cc: "gcc", bitness_flag: &["-m32"], ext: "so", driver_ext: "", under_wine: false },
    Target { label: "elf32 clang", cc: "clang", bitness_flag: &["-m32"], ext: "so", driver_ext: "", under_wine: false },
    Target {
        label: "pe32 mingw",
        cc: "i686-w64-mingw32-gcc",
        bitness_flag: &[],
        ext: "dll",
        driver_ext: ".exe",
        under_wine: true,
    },
];

/// One optimization level is one instruction selection. Four of them times
/// three containers is what this file claims to measure, and the count is used
/// below to check that every one of the twelve was accounted for.
const LEVELS: [&str; 4] = ["-O0", "-O1", "-O2", "-Os"];

/// A C file that exercises nothing but the toolchain: if this does not link,
/// the machine has no runtime for that bitness and the axis is genuinely
/// unavailable. Kept separate from the corpus on purpose — a corpus that fails
/// to build is *our* defect and must never be reported as a missing toolchain.
const PROBE_C: &str = "int main(void) { return 0; }\n";

/// What one sub-target — a container, a compiler and an optimization level —
/// produced.
///
/// **There is deliberately no case that means "nothing happened".** For as long
/// as this file existed, all eight ELF32 sub-targets were skipped on every run:
/// `-fPIC` was appended *after* `-o`, so the output file was named `-fPIC` and
/// the image was passed as an input, the link failed, and the loop printed
/// `skip` and moved on. `assert!(totals.0 > 0)` was satisfied by the four PE32
/// sub-targets, so one working axis reported success for twelve.
///
/// So a sub-target now ends in exactly one of two states: the toolchain is
/// **absent from this machine**, which is a fact about the machine, proven by a
/// probe build and printed loudly; or it **ran and compared**, and `agrees` is
/// a `NonZeroUsize`, so "ran and compared nothing" cannot be constructed. Any
/// third thing — a compiler that is present and could not build the corpus —
/// fails the test at the line where it happens.
enum Outcome {
    Absent(String),
    Measured { agrees: NonZeroUsize, disagrees: usize, gaps: usize },
}

/// The compiler argv, built in one place and printed with every build.
///
/// **The order is load-bearing, which is why it is not spelled out at the call
/// site any more.** Every flag goes in before `-o`, `-o` is immediately
/// followed by the output, and the source is last; the defect this replaces was
/// a single conditional `.arg("-fPIC")` that landed between `-o` and its
/// operand.
fn compile_argv(t: &Target, level: &str, out: &Path, src: &Path) -> Vec<String> {
    let mut argv: Vec<String> = t.bitness_flag.iter().map(|s| s.to_string()).collect();
    argv.push(level.to_string());
    // The scalar corpus stays scalar: a vectorized byte loop stops testing the
    // width under test and starts testing a layer this emulator does not model.
    argv.push("-fno-tree-vectorize".into());
    argv.push("-fno-tree-slp-vectorize".into());
    // A PE is position-independent by relocation, not by a PC-thunk; mingw
    // accepts `-fPIC` and ignores it (checked: same bytes with and without),
    // so it is left off to keep the PE argv saying only what it does.
    if !t.under_wine {
        argv.push("-fPIC".into());
    }
    argv.push("-shared".into());
    argv.push("-o".into());
    argv.push(out.display().to_string());
    argv.push(src.display().to_string());
    argv
}

/// Run a compiler and return its combined diagnostics on failure.
///
/// `LC_ALL=C` because the failure text is the report: gcc's message about the
/// missing `-fPIC` operand came out in the machine's own language, which is one
/// more reason a human skimming the log did not read it.
fn compile(cc: &str, argv: &[String]) -> Result<(), String> {
    let out = Command::new(cc).args(argv).env("LC_ALL", "C").output().expect("the compiler runs");
    if out.status.success() {
        return Ok(());
    }
    Err(format!("{cc} {}\n{}", argv.join(" "), String::from_utf8_lossy(&out.stderr)))
}

/// Run the driver, natively or under Wine. Wine's default prefix starts a .NET
/// service that prints a page of noise and adds seconds; only stdout is read.
fn run_driver(driver: &Path, args: &[String], under_wine: bool, cwd: &Path) -> std::process::Output {
    let mut cmd = if under_wine {
        let mut c = Command::new("wine");
        c.arg(driver);
        c
    } else {
        Command::new(driver)
    };
    cmd.args(args)
        .current_dir(cwd)
        .env("WINEDEBUG", "-all")
        .env("WINEDLLOVERRIDES", "mscoree=d")
        .output()
        .expect("the driver runs")
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

/// Exported corpus functions, or — with `all` — every local symbol too.
///
/// The locals matter here in a way they did not on x86-64: **there are no leaf
/// functions in position-independent 32-bit code.** i386 has no RIP-relative
/// addressing, so every PIC function begins by calling
/// `__x86.get_pc_thunk.<reg>`, whose entire body is `mov (%esp), %reg; ret` —
/// it reads the return address the `call` just pushed. So this corpus is
/// leaf-only in its source and not in its object code, and the emulator has to
/// follow that call and push a *real* return address for it to read.
fn addresses(so: &Path, all: bool, nm: &str, undecorate: bool, dynamic: bool) -> BTreeMap<String, u64> {
    let mut cmd = Command::new(nm);
    // `-D` narrows to the ELF dynamic table. A PE has no such table and `nm -D`
    // simply answers nothing there — which reads as "the corpus did not build"
    // rather than as "this flag does not apply".
    if dynamic && !all {
        cmd.arg("-D");
    }
    let out = cmd
        .args(["--defined-only"])
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
        // i386 Windows decorates a cdecl symbol with a leading underscore, so
        // the symbol table says `_emu32_add` while the *export* — what
        // `GetProcAddress` takes and what the driver is handed — says
        // `emu32_add`. Two names for one function, and the address belongs to
        // both.
        let name = if undecorate { name.strip_prefix('_').unwrap_or(name) } else { name };
        let wanted = if all {
            name.starts_with("emu32_") || name.starts_with("__x86.get_pc_thunk")
        } else {
            name.starts_with("emu32_")
        };
        if (kind == "T" || (all && kind == "t"))
            && wanted
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
fn thirty_two_bit_code_computes_what_the_processor_computes() {
    if !have("gcc") || !have("nm") {
        eprintln!("skip: needs gcc and nm — nothing was checked");
        return;
    }
    let dir = oracle_dir();
    // **A directory of this run's own, not a shared one.** The mis-ordered `-o`
    // above only produced a clean skip because no stale image happened to be
    // lying in the shared `/tmp/n0xis-emu32`: with one there, the link
    // *succeeds* — against the previous session's library — and the comparison
    // then measures bytes this run never built. A pass against a stale artifact
    // is worse than a skip, so the shared directory is gone rather than cleaned:
    // a fresh path makes that state impossible instead of unlikely. It is
    // removed when the test passes and kept when it fails, because a failure is
    // the one time the images are worth looking at.
    let tmp = std::env::temp_dir().join(format!(
        "n0xis-emu32-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmp).expect("tmp dir");
    let probe_c = tmp.join("probe.c");
    std::fs::write(&probe_c, PROBE_C).expect("the probe source is written");

    let mut outcomes: Vec<(String, Outcome)> = Vec::new();
    for t in &TARGETS {
        let label = |level: &str| format!("{} {level}", t.label);
        // Three ways this axis can be genuinely unavailable, each a fact about
        // the machine and none of them about the corpus: no compiler, no Wine
        // to run a PE, or no runtime for that bitness. The last one is decided
        // by PROBE_C and not by the corpus, so a corpus that stops building
        // can never disguise itself as a missing toolchain.
        let absent = if !have(t.cc) {
            Some(format!("{} is not installed", t.cc))
        } else if t.under_wine && !have("wine") {
            Some("wine is not installed, so a PE32 cannot be executed here".to_string())
        } else {
            let probe = tmp.join(format!("probe-{}{}", t.cc, t.driver_ext));
            let mut argv: Vec<String> = t.bitness_flag.iter().map(|s| s.to_string()).collect();
            argv.extend(["-o".to_string(), probe.display().to_string(), probe_c.display().to_string()]);
            compile(t.cc, &argv).err().map(|e| format!("no runtime for 32-bit code here:\n{e}"))
        };
        if let Some(reason) = absent {
            for level in LEVELS {
                outcomes.push((label(level), Outcome::Absent(reason.clone())));
            }
            continue;
        }

        // Past this point the toolchain has been shown to work, so every
        // failure below is this repository's and is fatal. It used to `continue`.
        let driver = tmp.join(format!("emu_run32-{}{}", t.cc, t.driver_ext));
        let mut argv: Vec<String> = t.bitness_flag.iter().map(|s| s.to_string()).collect();
        argv.extend([
            "-O2".to_string(),
            "-o".to_string(),
            driver.display().to_string(),
            dir.join("emu_run.c").display().to_string(),
        ]);
        if !t.under_wine {
            argv.push("-ldl".into());
        }
        if let Err(e) = compile(t.cc, &argv) {
            panic!("{}: the probe linked but oracle/emu_run.c did not:\n{e}", t.label);
        }

        for level in LEVELS {
            let img = tmp.join(format!("emu32-{}{level}.{}", t.cc, t.ext));
            let argv = compile_argv(t, level, &img, &dir.join("emu32.c"));
            eprintln!("build {}: {} {}", label(level), t.cc, argv.join(" "));
            if let Err(e) = compile(t.cc, &argv) {
                panic!("{}: the probe linked but oracle/emu32.c did not:\n{e}", label(level));
            }
            let (a, d, g) = check_one(&img, &driver, t, &label(level));
            let agrees = NonZeroUsize::new(a).unwrap_or_else(|| {
                panic!("{}: built and ran and compared nothing to the processor", label(level))
            });
            outcomes.push((label(level), Outcome::Measured { agrees, disagrees: d, gaps: g }));
        }
    }

    // Every sub-target this file claims to cover has to have said something.
    // A `continue` that lost one is what the count catches.
    assert_eq!(
        outcomes.len(),
        TARGETS.len() * LEVELS.len(),
        "{} of {} sub-targets reported an outcome: {:?}",
        outcomes.len(),
        TARGETS.len() * LEVELS.len(),
        outcomes.iter().map(|(l, _)| l.as_str()).collect::<Vec<_>>()
    );

    let mut totals = (0usize, 0usize, 0usize);
    let mut measured = 0usize;
    eprintln!();
    for (label, o) in &outcomes {
        match o {
            Outcome::Absent(reason) => eprintln!("UNAVAILABLE {label}: {reason}"),
            Outcome::Measured { agrees, disagrees, gaps } => {
                measured += 1;
                totals = (totals.0 + agrees.get(), totals.1 + disagrees, totals.2 + gaps);
                eprintln!("MEASURED    {label}: {agrees} agree, {disagrees} disagree, {gaps} not modelled");
            }
        }
    }
    eprintln!(
        "\n32-bit, {measured} of {} sub-targets measured: {} agree, {} disagree, {} not modelled",
        outcomes.len(),
        totals.0,
        totals.1,
        totals.2
    );
    assert!(measured > 0, "every axis was unavailable — nothing was actually checked");
    std::fs::remove_dir_all(&tmp).expect("the run's own directory is removed");
}

fn check_one(so: &Path, driver: &Path, target: &Target, label: &str) -> (usize, usize, usize) {
    // A PE needs mingw's `nm`, which prints absolute VAs with the image base
    // already added — the same shape GNU `nm` gives for an ELF.
    let nm = if target.under_wine { "i686-w64-mingw32-nm" } else { "nm" };
    let addrs = addresses(so, false, nm, target.under_wine, !target.under_wine);
    let all = addresses(so, true, nm, target.under_wine, !target.under_wine);
    assert!(!addrs.is_empty(), "{label}: nm found no emu32_* exports");

    // `dlopen` searches the library path for a bare name and only the given
    // path for one with a slash; `LoadLibraryA` looks in the working directory.
    // Both are run from the image's own directory, so the difference is a `./`.
    let bare = so.file_name().expect("a file name").to_string_lossy().to_string();
    let name = if target.under_wine { bare } else { format!("./{bare}") };
    let cwd = so.parent().expect("a directory");
    let mut args: Vec<String> = vec![name, "8".to_string()];
    args.extend(addrs.keys().cloned());
    let out = run_driver(driver, &args, target.under_wine, cwd);
    assert!(out.status.success(), "{label}: driver failed: {}", String::from_utf8_lossy(&out.stderr));
    let cases = parse_cases(&String::from_utf8_lossy(&out.stdout));
    assert!(cases.len() >= addrs.len(), "{label}: fewer answers than functions");

    let image = StaticImage::load(so).expect("n0xis loads the same library");
    // The decoder, the register widths and the lift all follow from this.
    let arch = X64::x86();
    let ctx = Ctx::new(&image, &arch);

    let mut forms = BTreeMap::new();
    let mut ssa_bodies = BodyMap::new();
    let mut opt_bodies = BodyMap::new();
    for (name, addr) in &all {
        let cfg = CfgPass
            .run(&ctx, CfgInput::new(Va(*addr), 4096))
            .unwrap_or_else(|e| panic!("{label}: {name}: CFG failed: {e}"));
        let ssa = SsaPass.run(&ctx, cfg).unwrap_or_else(|e| panic!("{label}: {name}: {e}"));
        let opt = OptimizePass.run(&ctx, ssa.clone()).unwrap_or_else(|e| panic!("{label}: {name}: {e}"));
        ssa_bodies.insert(Va(*addr), ssa.blocks.clone());
        opt_bodies.insert(Va(*addr), opt.blocks.clone());
        if addrs.contains_key(name) {
            forms.insert(name.clone(), (ssa, opt));
        }
    }

    let mut ssa_tally = Tally::default();
    let mut opt_tally = Tally::default();
    let mut optimizer_changed_meaning: Vec<String> = Vec::new();

    for case in &cases {
        let Some((ssa, opt)) = forms.get(&case.func) else { continue };
        let run = |blocks: &[n0xis_core::SsaBlock], code: &BodyMap| {
            let cfg = EmuConfig {
                entry_scratch: true,
                word_bits: 32,
                stack_top: STACK32,
                calls: CallPolicy::Execute { max_depth: 8 },
                ..Default::default()
            };
            let mut emu = Emulator::with_config(blocks, Some(&image as &dyn MemorySource), cfg)
                .with_code(code as &dyn CodeProvider);
            // The i386 frame at entry: the return address the `call` pushed
            // sits at `esp`, and the arguments follow it, four bytes each. Not
            // a register in sight — which is the point, since this is the one
            // convention nothing here had ever executed.
            for (i, v) in case.args.iter().enumerate() {
                emu.write_mem(STACK32 + WORD * (i as u64 + 1), *v, 32);
            }
            emu.write_mem(n0xis_core::DEFAULT_GS_BASE + CANARY32_OFFSET, STACK_CANARY, 32);
            emu.run().map(|r| r.ret)
        };
        let record = |tally: &mut Tally, got: Result<Option<u64>, n0xis_core::EmuError>| match got {
            // The whole 64-bit value is compared, not its low half: a bit above
            // 31 surviving into the result *is* the defect this file exists for.
            Ok(Some(v)) if v == case.ret => tally.agrees += 1,
            Ok(Some(v)) => tally.disagrees.push(format!(
                "{}({:#x}, {:#x}, {:#x}, {:#x}) → n0xis {v:#x}, the CPU {:#x}",
                case.func, case.args[0], case.args[1], case.args[2], case.args[3], case.ret
            )),
            Ok(None) => tally
                .disagrees
                .push(format!("{}: the IR returned nothing; the CPU returned {:#x}", case.func, case.ret)),
            Err(e) => {
                *tally.not_modelled.entry(format!("{}: {e}", case.func)).or_default() += 1;
            }
        };
        let a = run(&ssa.blocks, &ssa_bodies);
        let b = run(&opt.blocks, &opt_bodies);
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
        let gaps: Vec<&String> =
            t.not_modelled.keys().filter(|g| !REFUSED.iter().any(|r| g.contains(r))).collect();
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
