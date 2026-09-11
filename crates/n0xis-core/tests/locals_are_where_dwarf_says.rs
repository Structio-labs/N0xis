// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Recovered locals, against the addresses the compiler wrote down.**
//!
//! This check was attempted once and **thrown away**. It compared a recovered
//! local's name — `local_48`, a displacement from whichever frame register the
//! expression happened to use — against the displacement `objdump` prints from
//! the *current* `rsp`, which moves with every push. 781 of 782 matched, and the
//! one that did not explained why the 781 meant nothing: the two numbers count
//! from different places and collided because the frames were small.
//!
//! The units are the problem, so this removes them. DWARF states each local as
//! `DW_OP_fbreg <n>` against `DW_OP_call_frame_cfa`, and the CFA is pinned by
//! the ABI: on System V x86-64 it is `rsp` as the caller had it, which is entry
//! `rsp` plus the 8 bytes `call` pushed. That makes every declared local a
//! concrete address. The emulator then runs the recovered program and reports
//! the concrete addresses it actually touched. Address against address — there
//! is nothing left to convert, and so nothing left to collide.
//!
//! Every local in `oracle/locals.c` is `volatile` and written on every path, so
//! "DWARF declares it" and "the run must touch it" are the same statement. A
//! local the compiler could keep in a register would prove nothing, and is not
//! what this claims to check.
//!
//! **The soundness gate is explicit:** a function whose `DW_AT_frame_base` is
//! not `DW_OP_call_frame_cfa` is skipped and counted, because the arithmetic
//! above is only true for that frame base. Guessing there is how the first
//! attempt went wrong.

#![cfg(feature = "oracle")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use n0xis_arch::X64;
use n0xis_contracts::Va;
use n0xis_core::{CfgInput, CfgPass, Ctx, EmuConfig, Emulator, Pass, SsaPass};
use n0xis_sources::StaticElf;

/// System V x86-64: the CFA is the caller's `rsp`, and `call` pushed 8 bytes
/// before the callee's first instruction — so entry `rsp` is `CFA - 8`.
const CALL_PUSHED: u64 = 8;

const STACK_CANARY: u64 = 0x5ec0_ffee_dead_1234;
const ARG_REGS: [&str; 4] = ["rdi", "rsi", "rdx", "rcx"];
/// Planted inputs. Nothing here depends on their values — every local is
/// written unconditionally — but they are fixed so a failure reproduces.
const ARGS: [u64; 4] = [0x1111_2222_3333_4444, 0x00ff_00ff_00ff_00ff, 0x2a, 0xdead_beef];

fn oracle_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("oracle")
}

#[derive(Debug, Default)]
struct Subprogram {
    name: String,
    low_pc: u64,
    /// `true` only when `DW_AT_frame_base` is `DW_OP_call_frame_cfa`.
    cfa_frame_base: bool,
    /// Declared stack objects: name → offset from the CFA.
    locals: BTreeMap<String, i64>,
}

/// Read the subprograms and their frame-based locals out of `.debug_info`.
///
/// `objdump` is the independent parser here — the third rung — and `LC_ALL=C`
/// is not optional: a localized build prints translated attribute text and this
/// silently finds nothing, which has already cost this project three sessions.
fn dwarf_subprograms(so: &Path) -> Vec<Subprogram> {
    let out = Command::new("objdump")
        .arg("--dwarf=info")
        .arg(so)
        .env("LC_ALL", "C")
        .output()
        .expect("objdump runs");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("DW_TAG_subprogram"),
        "objdump reported no subprograms — the target was built without -g, or the output is \
         not the C locale"
    );

    let mut subs: Vec<Subprogram> = Vec::new();
    let mut in_var = false;
    let mut pending: Option<String> = None;
    for line in text.lines() {
        if line.contains("(DW_TAG_subprogram)") {
            subs.push(Subprogram::default());
            in_var = false;
            pending = None;
            continue;
        }
        if line.contains("(DW_TAG_variable)") || line.contains("(DW_TAG_formal_parameter)") {
            in_var = true;
            pending = None;
            continue;
        }
        // Any other tag ends the current variable but stays inside the function.
        if line.contains("DW_TAG_") {
            in_var = false;
            pending = None;
            continue;
        }
        let Some(current) = subs.last_mut() else { continue };

        if let Some(v) = line.split("DW_AT_name").nth(1) {
            // `: (indirect string, offset: 0xb2): loc_deep` or plain `: v0`
            let name = v.rsplit(especially_last_colon).next().unwrap_or("").trim().to_string();
            if in_var {
                pending = Some(name);
            } else if current.name.is_empty() {
                current.name = name;
            }
            continue;
        }
        if let Some(v) = line.split("DW_AT_low_pc").nth(1) {
            // **The first one only.** A `DW_TAG_lexical_block` inside the
            // function carries its own `DW_AT_low_pc`, and letting it overwrite
            // the subprogram's started the emulation in the middle of a loop —
            // where the prologue had not run, the stack pointer was still the
            // entry value and the counter began at an invented number. The run
            // then span forever and looked like a defect in the IR.
            let hex = v.trim().trim_start_matches(':').trim().trim_start_matches("0x");
            if current.low_pc == 0
                && let Ok(a) = u64::from_str_radix(hex, 16)
            {
                current.low_pc = a;
            }
            continue;
        }
        if line.contains("DW_AT_frame_base") {
            current.cfa_frame_base = line.contains("DW_OP_call_frame_cfa");
            continue;
        }
        if let Some(v) = line.split("DW_OP_fbreg:").nth(1) {
            let off: i64 = v.trim().trim_end_matches(')').trim().parse().unwrap_or(i64::MIN);
            if off != i64::MIN
                && let Some(name) = pending.take()
            {
                current.locals.insert(name, off);
            }
        }
    }
    subs.retain(|s| !s.name.is_empty() && s.low_pc != 0 && !s.locals.is_empty());
    subs
}

/// `objdump` writes a name as `: (indirect string, offset: 0xb2): loc_deep`
/// or as a bare `: v0`, so the value is whatever follows the **last** colon.
fn especially_last_colon(c: char) -> bool {
    c == ':'
}

#[test]
fn every_declared_local_is_touched_at_the_address_dwarf_states() {
    if Command::new("gcc").arg("--version").output().is_err()
        || Command::new("objdump").arg("--version").output().is_err()
    {
        eprintln!("skip: needs gcc and objdump — nothing was checked");
        return;
    }
    let tmp = std::env::temp_dir().join("n0xis-locals-oracle");
    std::fs::create_dir_all(&tmp).expect("tmp dir");

    let mut checked = 0usize;
    let mut skipped_frame_base = 0usize;
    let mut missed: Vec<String> = Vec::new();
    let mut unrunnable: Vec<String> = Vec::new();

    for level in ["-O0", "-O1", "-O2"] {
        let so = tmp.join(format!("locals{level}.so"));
        let built = Command::new("gcc")
            .args([level, "-g", "-fPIC", "-shared", "-o"])
            .arg(&so)
            .arg(oracle_dir().join("locals.c"))
            .status()
            .expect("gcc runs");
        assert!(built.success(), "gcc could not build oracle/locals.c at {level}");

        let subs = dwarf_subprograms(&so);
        assert!(!subs.is_empty(), "{level}: DWARF declared no frame-based locals");

        let elf = StaticElf::load(&so).expect("n0xis loads the same library");
        let arch = X64::new();
        let ctx = Ctx::new(&elf, &arch);

        for sub in &subs {
            if !sub.cfa_frame_base {
                // The CFA arithmetic below is only true for this frame base.
                skipped_frame_base += 1;
                continue;
            }
            let cfg = match CfgPass.run(&ctx, CfgInput::new(Va(sub.low_pc), 4096)) {
                Ok(c) => c,
                Err(e) => {
                    unrunnable.push(format!("{level} {}: CFG failed: {e}", sub.name));
                    continue;
                }
            };
            let ssa = match SsaPass.run(&ctx, cfg) {
                Ok(s) => s,
                Err(e) => {
                    unrunnable.push(format!("{level} {}: SSA failed: {e}", sub.name));
                    continue;
                }
            };

            let conf = EmuConfig { entry_scratch: true, ..Default::default() };
            let mut emu = Emulator::with_config(
                &ssa.blocks,
                Some(&elf as &dyn n0xis_sources::MemorySource),
                conf,
            );
            for (reg, val) in ARG_REGS.iter().zip(ARGS.iter()) {
                emu.set_var(reg, *val);
            }
            emu.write_mem(n0xis_core::DEFAULT_FS_BASE + 0x28, STACK_CANARY, 64);
            if let Err(e) = emu.run() {
                unrunnable.push(format!("{level} {}: {e}", sub.name));
                continue;
            }

            let cfa = conf.stack_top + CALL_PUSHED;
            let touched: BTreeSet<i64> = emu
                .touched()
                .iter()
                .map(|a| (*a as i64).wrapping_sub(cfa as i64))
                .collect();
            for (name, off) in &sub.locals {
                checked += 1;
                if !touched.contains(off) {
                    let near = touched.range(off - 32..off + 32).count();
                    missed.push(format!(
                        "{level} {}: `{name}` is at CFA{off:+} and the run never touched it \
                         ({near} other addresses within 32 bytes of it)",
                        sub.name
                    ));
                }
            }
        }
    }

    eprintln!(
        "locals: {checked} declared stack objects checked, {} missed, \
         {skipped_frame_base} function(s) skipped for a non-CFA frame base, \
         {} function(s) the emulator could not run",
        missed.len(),
        unrunnable.len()
    );
    for u in &unrunnable {
        eprintln!("  unrun  {u}");
    }

    assert!(checked > 0, "nothing was actually checked");
    assert!(
        missed.is_empty(),
        "{} declared local(s) are not where the recovered program looked:\n  {}",
        missed.len(),
        missed.join("\n  ")
    );
    // The emulator failing to run a corpus function is a gap in this instrument,
    // not a pass. Recorded as an assertion so it cannot drift into silence.
    assert!(
        unrunnable.is_empty(),
        "{} corpus function(s) could not be emulated; model them or take them out:\n  {}",
        unrunnable.len(),
        unrunnable.join("\n  ")
    );
}
