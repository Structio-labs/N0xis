//! **The Phase 4c exit test** (ROADMAP P4c / CONCEPT §11): "agent goes
//! 'find & freeze HP' → explained provenance + verified freeze entry in
//! `.n0xt`, end-to-end, no human bridging static/dynamic."
//!
//! Gated behind `--features live` (same opt-in-for-OS-tests convention as
//! `n0xis-sources` and `phase4b_exit.rs`). Unlike `phase4b_exit.rs` (which
//! targets an arbitrary `powershell` process — fine for scan/filter/freeze,
//! which only need *some* live memory), this test needs a target whose code
//! it can actually decompile, so it compiles a tiny, known Rust program at
//! test time (`rustc` is guaranteed present — it built this very crate) and
//! drives the real "find & freeze" loop against it:
//!
//!   1. scan for the target's counter (a real value in real memory),
//!   2. arm a hardware watchpoint on it and catch a real write,
//!   3. **fuse that hit with the SSA decompiler** (`ProvenancePass`) to get
//!      back the exact source-level statement that wrote it — the principal
//!      capability, verified against real compiled code, not a mock,
//!   4. freeze the value and record the explanation onto a real `.n0xt`
//!      table entry,
//!   5. reload the table from disk and confirm the provenance + verification
//!      state actually persisted.

#![cfg(feature = "live")]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use n0xis_arch::X64;
use n0xis_contracts::{Provenance, Table, TableEntry, TableLocator, TableValueType, Va, VerificationState};
use n0xis_core::{Ctx, Pass, ProvenanceHit, ProvenanceInput, ProvenancePass};
use n0xis_sources::{await_watchpoint_hit, LiveProcess, MemorySource, ModuleProvider, WatchKind};

/// A known, tiny target: a heap counter incremented in a loop, with its
/// address and PID printed so the test doesn't have to guess either.
const TARGET_SRC: &str = r#"
fn main() {
    let boxed: Box<i32> = Box::new(1000);
    let ptr = Box::into_raw(boxed);
    println!("addr=0x{:x}", ptr as usize);
    println!("pid={}", std::process::id());
    loop {
        unsafe { *ptr += 1; }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
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
    let dir = std::env::temp_dir().join(format!("n0xis-phase4c-exit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let src_path = dir.join("target.rs");
    let exe_path = dir.join("target.exe");
    std::fs::write(&src_path, TARGET_SRC).expect("write target source");

    let status = Command::new("rustc")
        .args(["-O", "-o"])
        .arg(&exe_path)
        .arg(&src_path)
        .status()
        .expect("invoke rustc (must be on PATH — it built this crate)");
    assert!(status.success(), "rustc failed to compile the disposable test target");
    CompiledTarget { exe_path }
}

fn spawn_target(exe: &CompiledTarget) -> (DisposableProcess, Va, u32) {
    let mut child = Command::new(&exe.exe_path)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn the compiled target");
    let stdout = child.stdout.take().expect("captured stdout");
    let mut lines = BufReader::new(stdout).lines();

    let addr_line = lines.next().expect("target prints an addr= line").expect("read addr line");
    let pid_line = lines.next().expect("target prints a pid= line").expect("read pid line");
    let addr = Va::parse(addr_line.strip_prefix("addr=").expect("addr= prefix")).expect("parse addr");
    let pid: u32 = pid_line.strip_prefix("pid=").expect("pid= prefix").trim().parse().expect("parse pid");

    (DisposableProcess(child), addr, pid)
}

#[test]
fn agent_finds_and_freezes_hp_with_explained_provenance() {
    let target = compile_target();
    let (_child, counter_addr, pid) = spawn_target(&target);
    std::thread::sleep(Duration::from_millis(300));

    // Step 1 — "find HP": we already know the address (the target printed
    // it), matching what a prior `scan value`/`scan filter` pass would have
    // narrowed down to in the interactive workflow (already exit-tested in
    // phase4b_exit.rs); this test focuses on what Phase 4c adds on top.
    let live = LiveProcess::attach(pid).expect("attach to the compiled target");
    let bytes = live.read(counter_addr, 4).expect("read the counter");
    assert_eq!(i32::from_le_bytes(bytes.try_into().unwrap()) >= 1000, true, "sanity: counter is in its expected range");
    let main_module = live.main_module().cloned();
    drop(live);

    // Step 2 — arm a hardware watchpoint and catch a real write.
    let outcome = await_watchpoint_hit(pid, counter_addr, WatchKind::Write, 4, 5000, 0, main_module.as_ref())
        .expect("watch succeeds");
    let hit = outcome.hit.expect("the target's own loop writes within the timeout");

    // Step 3 — fuse the hit with the SSA decompiler: the principal fusion.
    let live = LiveProcess::attach(pid).expect("re-attach");
    let insn_module = live.modules().iter().find(|m| m.contains(hit.rip)).cloned();
    let (code_start, code_size) = insn_module
        .as_ref()
        .and_then(|m| live.section_range_of(m.base, ".text"))
        .map(|(s, sz)| (Some(s), sz as usize))
        .unwrap_or((None, 0));
    let arch = X64::new();
    let ctx = Ctx::new(&live, &arch);
    let graph = ProvenancePass
        .run(
            &ctx,
            ProvenanceInput {
                value_addr: counter_addr,
                hits: vec![ProvenanceHit { instruction_va: hit.rip, access_kind: "write".to_string() }],
                module: insn_module,
                code_scan_start: code_start,
                code_scan_size: code_size,
            },
        )
        .expect("provenance resolves");

    assert_eq!(graph.entries.len(), 1);
    let entry = &graph.entries[0];
    assert!(entry.function_va.is_some(), "must resolve the containing function, not just the raw address");
    assert!(!entry.decompiled_context.is_empty(), "must produce a decompiled explanation, not just an address");
    let explanation = entry.decompiled_context.join("\n");
    // The target's own source is `*ptr += 1;` — the decompiled statement
    // must show an actual increment, not a bare, unexplained address.
    assert!(explanation.contains("0x1"), "expected the increment-by-one to show up in the explanation: {explanation}");

    // Step 4 — freeze it and record the explanation onto a real `.n0xt` entry.
    live.write(counter_addr, &42i32.to_le_bytes()).expect("freeze write");
    drop(live);

    let project_dir = std::env::temp_dir().join(format!("n0xis-phase4c-project-{}", std::process::id()));
    std::fs::create_dir_all(project_dir.join(".n0x")).expect("create scratch .n0x project");
    let prev_cwd = std::env::current_dir().expect("read cwd");
    std::env::set_current_dir(&project_dir).expect("cd into scratch project");

    let entry_record = TableEntry {
        name: "hp".to_string(),
        locator: TableLocator::Address { va: counter_addr },
        value_type: TableValueType::I32,
        description: Some("agent-found counter".to_string()),
        hotkey: None,
        groups: vec!["phase4c-exit-test".to_string()],
        frozen: true,
        freeze_value: Some(42.0),
        provenance: Provenance {
            function_va: entry.function_va,
            struct_type: None,
            field_offset: None,
            note: Some(explanation.clone()),
        },
        verification: VerificationState { last_confirmed_unix: Some(n0xis_project::patch::now_unix_secs()), module_build: None },
    };
    n0xis_project::table::add_entry("phase4c-exit", entry_record).expect("save the entry");

    // Step 5 — reload from disk (not in-memory state) and confirm it stuck.
    let reloaded: Table = n0xis_project::table::load("phase4c-exit").expect("reload from disk");
    assert_eq!(reloaded.entries.len(), 1);
    let saved = &reloaded.entries[0];
    assert_eq!(saved.name, "hp");
    assert!(saved.frozen);
    assert_eq!(saved.freeze_value, Some(42.0));
    assert_eq!(saved.provenance.function_va, entry.function_va, "provenance must survive the round trip through disk");
    assert!(saved.verification.last_confirmed_unix.is_some());

    std::env::set_current_dir(prev_cwd).ok();
    std::fs::remove_dir_all(&project_dir).ok();
}
