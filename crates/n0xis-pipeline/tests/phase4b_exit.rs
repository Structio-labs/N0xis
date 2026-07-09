//! **The Phase 4b exit test** (ROADMAP P4b / CONCEPT §9-10): "headless
//! scan→filter→freeze loop on a live target, results saved to `.n0xt`."
//!
//! Gated behind `--features live` (opt-in, same reasoning as
//! `n0xis-sources` itself: default builds/tests stay OS-free — the Phase 1
//! boundary). Spawns a real, disposable process (a long-lived benign
//! `powershell` sleep) and drives the actual `ScanPass`/`FilterPass`/
//! `TypeInferPass`-adjacent `n0xis-project::table` persistence against it —
//! not a mock. We write the "world" ourselves via the already-proven
//! `LiveProcess::write` (Phase 2) rather than racing an independently
//! ticking counter, so the test is deterministic instead of timing-sensitive.

#![cfg(feature = "live")]

use std::process::{Child, Command};
use std::time::Duration;

use n0xis_arch::X64;
use n0xis_contracts::{Table, TableEntry, TableLocator, TableValueType, Va};
use n0xis_core::{Ctx, FilterCriterion, FilterInput, FilterPass, Pass, ScanCriterion, ScanInput, ScanPass, ScanValue, ValueType};
use n0xis_sources::{LiveProcess, MemorySource};

struct DisposableProcess(Child);
impl Drop for DisposableProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_target() -> DisposableProcess {
    let child = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 60"])
        .spawn()
        .expect("spawn a disposable powershell target");
    DisposableProcess(child)
}

fn find_writable_region(live: &LiveProcess) -> (Va, usize) {
    live.regions(100_000)
        .into_iter()
        .find(|r| r.state == "commit" && matches!(r.protect.as_str(), "rw-" | "rwx"))
        .map(|r| (r.base, r.size as usize))
        .expect("the target process has at least one committed writable region")
}

#[test]
fn headless_scan_filter_freeze_loop_saves_to_n0xt() {
    let target = spawn_target();
    // Give the process a moment to finish initializing its address space.
    std::thread::sleep(Duration::from_millis(300));
    let pid = target.0.id();

    let live = LiveProcess::attach(pid).expect("attach to the disposable target");
    let (region_start, region_size) = find_writable_region(&live);

    // We control the "world": write a known value ourselves (the proven
    // Phase 2 write path), scan for it, then write an increased value and
    // confirm the filter narrows to exactly that address.
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
    assert!(first.matches.iter().any(|m| m.addr == probe_addr), "expected to find our own written value");

    // Narrow the world: bump the value up.
    live.write(probe_addr, &4300i32.to_le_bytes()).expect("write the increased value");

    let filtered = FilterPass
        .run(&ctx, FilterInput { previous: first.matches, value_type: ValueType::I32, criterion: FilterCriterion::Increased })
        .expect("filter succeeds");
    assert!(filtered.matches.iter().any(|m| m.addr == probe_addr), "the increased value must survive the filter");

    // Persist the narrowed result as a `.n0xt` table entry (CONCEPT §10) —
    // in a throwaway `.n0x/` project directory so this test never touches
    // the real one.
    let project_dir = std::env::temp_dir().join(format!("n0xis-phase4b-exit-{}-{pid}", std::process::id()));
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
