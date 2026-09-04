// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The Phase 4b exit test** (ROADMAP P4b / CONCEPT §9-10): "headless
//! scan→filter→freeze loop on a live target, results saved to `.n0xt`."
//!
//! Gated behind `--features live` (opt-in, same reasoning as `n0xis-sources`
//! itself: default builds/tests stay OS-free — the Phase 1 boundary). Spawns a
//! real, disposable process and drives the actual `ScanPass`/`FilterPass` +
//! `n0xis-project::table` persistence against it — not a mock.
//!
//! Cross-platform: instead of a `powershell` sleep (Windows-only), it compiles a
//! tiny Rust target at test time (`rustc` is guaranteed present — it built this
//! crate) that leaks a known, zeroed buffer and prints its address + pid. We
//! then write the "world" into *that buffer* ourselves via the proven
//! `MemorySource::write` path, so the test is deterministic (it never races the
//! target) and safe (it never scribbles on an arbitrary region of a real
//! process) on every OS. The concrete live adapter is the only per-OS piece.

#![cfg(feature = "live")]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use n0xis_arch::X64;
use n0xis_contracts::{Table, TableEntry, TableLocator, TableValueType, Va};
use n0xis_core::{Ctx, FilterCriterion, FilterInput, FilterPass, Pass, ScanCriterion, ScanInput, ScanPass, ScanValue, ValueType, PREVIEW_LIMIT};
#[cfg(windows)]
use n0xis_sources::LiveProcess as LiveAdapter;
#[cfg(any(target_os = "linux", target_os = "android"))]
use n0xis_sources::LinuxProcess as LiveAdapter;
use n0xis_sources::MemorySource;

/// The disposable target: leak a zeroed 0x4000-byte buffer, print its data
/// address and pid, then sleep. The buffer stays put (leaked) and untouched, so
/// the only writes into it are the ones this test makes — deterministic.
const TARGET_SRC: &str = r#"
fn main() {
    let buf = vec![0u8; 0x4000];
    let p = buf.as_ptr() as usize;
    std::mem::forget(buf);
    println!("addr=0x{:x}", p);
    println!("pid={}", std::process::id());
    use std::io::Write;
    std::io::stdout().flush().unwrap();
    loop { std::thread::sleep(std::time::Duration::from_secs(1)); }
}
"#;

struct DisposableProcess(Child);
impl Drop for DisposableProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct CompiledTarget {
    exe_path: std::path::PathBuf,
}
impl Drop for CompiledTarget {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.exe_path);
        let _ = std::fs::remove_file(self.exe_path.with_extension("pdb"));
    }
}

fn compile_target() -> CompiledTarget {
    let dir = std::env::temp_dir().join(format!("n0xis-phase4b-exit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let src_path = dir.join("p4b_target.rs");
    let exe_path = dir.join(format!("p4b_target{}", std::env::consts::EXE_SUFFIX));
    std::fs::write(&src_path, TARGET_SRC).expect("write target source");
    let status = Command::new("rustc")
        .args(["-O", "-C", "debuginfo=0", "-o"])
        .arg(&exe_path)
        .arg(&src_path)
        .status()
        .expect("invoke rustc (must be on PATH — it built this crate)");
    assert!(status.success(), "rustc failed to compile the disposable phase4b target");
    CompiledTarget { exe_path }
}

fn spawn_target(exe: &CompiledTarget) -> (DisposableProcess, Va, u32) {
    let mut child = Command::new(&exe.exe_path).stdout(Stdio::piped()).spawn().expect("spawn the compiled target");
    let stdout = child.stdout.take().expect("captured stdout");
    let mut lines = BufReader::new(stdout).lines();
    let addr_line = lines.next().expect("target prints addr=").expect("read addr line");
    let pid_line = lines.next().expect("target prints pid=").expect("read pid line");
    let addr = Va::parse(addr_line.strip_prefix("addr=").expect("addr= prefix")).expect("parse addr");
    let pid: u32 = pid_line.strip_prefix("pid=").expect("pid= prefix").trim().parse().expect("parse pid");
    (DisposableProcess(child), addr, pid)
}

#[test]
fn headless_scan_filter_freeze_loop_saves_to_n0xt() {
    let target = compile_target();
    let (_child, buf_addr, pid) = spawn_target(&target);
    // Give the process a moment to finish initializing its address space.
    std::thread::sleep(Duration::from_millis(300));

    let live = LiveAdapter::attach(pid).expect("attach to the disposable target");
    // Our known, safe scratch region: the leaked buffer the target printed.
    let region_start = buf_addr;
    let region_size: usize = 0x4000;

    // We control the "world": write a known value ourselves (the proven write
    // path), scan for it, then write an increased value and confirm the filter
    // narrows to exactly that address.
    let probe_offset: u64 = 0x40;
    let probe_addr = region_start.offset(probe_offset);
    live.write(probe_addr, &4242i32.to_le_bytes()).expect("write the known first value");

    let arch = X64::new();
    let ctx = Ctx::new(&live, &arch);

    let first = ScanPass
        .run(
            &ctx,
            ScanInput {
                regions: vec![(region_start, region_size)],
                value_type: ValueType::I32,
                criterion: ScanCriterion::Exact { value: ScanValue::Int(4242) },
                align: 4,
            },
        )
        .expect("first scan succeeds");
    assert!(
        first.materialize(PREVIEW_LIMIT).iter().any(|m| m.addr == probe_addr),
        "expected to find our own written value"
    );

    // Narrow the world: bump the value up.
    live.write(probe_addr, &4300i32.to_le_bytes()).expect("write the increased value");

    let filtered = FilterPass
        .run(&ctx, FilterInput { previous: first, criterion: FilterCriterion::Increased })
        .expect("filter succeeds");
    assert!(
        filtered.materialize(PREVIEW_LIMIT).iter().any(|m| m.addr == probe_addr),
        "the increased value must survive the filter"
    );

    // --- The CE "value too common" flow, live: an `unknown` first scan
    // (snapshot-backed / dense — no address list materialized up front),
    // narrowed by what *changed*. Proves the snapshot-narrow path against a
    // real process, not just a mock. Bounded to a small window so the dense
    // capture stays cheap and deterministic.
    let window: usize = 0x1000;
    let unknown = ScanPass
        .run(
            &ctx,
            ScanInput {
                regions: vec![(region_start, window)],
                value_type: ValueType::I32,
                criterion: ScanCriterion::Unknown,
                align: 4,
            },
        )
        .expect("unknown first scan succeeds");
    // Dense capture: every aligned slot in the window is a live candidate.
    let unknown_total = unknown.total();
    assert!(unknown_total >= window / 4 - 1, "unknown scan should capture the whole window densely");

    // Change exactly one slot; a `changed` rescan must keep it (and drop the
    // untouched slots, which the sleeping target doesn't write).
    live.write(probe_addr, &1234i32.to_le_bytes()).expect("perturb one slot");
    let changed = FilterPass
        .run(&ctx, FilterInput { previous: unknown, criterion: FilterCriterion::Changed })
        .expect("changed rescan succeeds");
    assert!(
        changed.materialize(PREVIEW_LIMIT).iter().any(|m| m.addr == probe_addr && m.value == ScanValue::Int(1234)),
        "the one slot we changed must survive a `changed` rescan"
    );
    assert!(
        changed.total() < unknown_total,
        "a `changed` rescan of a mostly-static window must narrow the set"
    );

    // Restore the probe for the freeze-loop portion below.
    live.write(probe_addr, &4300i32.to_le_bytes()).expect("restore the probe value");

    // Persist the narrowed result as a `.n0xt` table entry (CONCEPT §10) — in a
    // throwaway `.n0x/` project directory so this test never touches the real one.
    let project_dir = std::env::temp_dir().join(format!("n0xis-phase4b-project-{}-{pid}", std::process::id()));
    std::fs::create_dir_all(project_dir.join(".n0x")).expect("create a scratch .n0x project");
    let prev_cwd = std::env::current_dir().expect("read cwd");
    std::env::set_current_dir(&project_dir).expect("cd into the scratch project");

    let entry = TableEntry {
        name: "probe".to_string(),
        locator: TableLocator::Address { va: probe_addr },
        value_type: TableValueType::I32,
        description: Some("phase4b exit test probe".to_string()),
        hotkey: None,
        groups: vec![],
        frozen: true,
        freeze_value: Some(9999.0),
        provenance: Default::default(),
        verification: Default::default(),
    };
    n0xis_project::table::add_entry("phase4b-exit", entry).expect("save the entry to a .n0xt table");

    // Freeze loop: repeatedly write the frozen value for a short, bounded
    // duration, then confirm it actually landed.
    let frozen_bytes = 9999i32.to_le_bytes();
    for _ in 0..5 {
        live.write(probe_addr, &frozen_bytes).expect("freeze write");
        std::thread::sleep(Duration::from_millis(20));
    }
    let after_freeze = live.read(probe_addr, 4).expect("read back after freezing");
    assert_eq!(after_freeze, frozen_bytes, "the frozen value must be what we last wrote");

    // The table survives as a real `.n0xt` file — reload it fresh (not the
    // in-memory value) to prove persistence, not just in-process state.
    let reloaded: Table = n0xis_project::table::load("phase4b-exit").expect("reload the .n0xt table from disk");
    assert_eq!(reloaded.entries.len(), 1);
    assert_eq!(reloaded.entries[0].name, "probe");
    assert!(reloaded.entries[0].frozen);
    assert_eq!(reloaded.entries[0].freeze_value, Some(9999.0));

    std::env::set_current_dir(prev_cwd).ok();
    std::fs::remove_dir_all(&project_dir).ok();
}
