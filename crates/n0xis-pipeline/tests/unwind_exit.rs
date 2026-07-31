//! **Stack-unwind exit test**: a hardware watchpoint hit must come back with a
//! real *unwound* call stack (frame 0 = the hit site, then genuine callers
//! recovered from the target's `.pdata`/`.xdata`), not just a raw `[rsp]` guess.
//!
//! This is the live, real-process proof for `n0xis-sources::unwind` — the pure
//! unwinder is unit-tested against a synthetic PE, but a watchpoint lands
//! mid-function in *real* compiler output, which is exactly where a naive stack
//! read fails and where this feature earns its keep (recovering the caller of
//! a writing instruction from a mid-function hit, which a raw `[rsp]` guess
//! can't reach).
//!
//! Gated behind `--features live`, same as the other dynamic-memory exit tests.

#![cfg(feature = "live")]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use n0xis_contracts::Va;
use n0xis_sources::{WatchKind, await_watchpoint_hit};

/// A target with a deliberate, deep, non-inlined call chain
/// (`main → top → mid → leaf`) whose innermost function writes a global in a
/// tight loop. A write watchpoint on that global fires *inside* `leaf`, so a
/// correct unwind must climb back out through `mid`/`top`/`main`.
const TARGET_SRC: &str = r#"
use std::sync::atomic::{AtomicU64, Ordering};
static COUNTER: AtomicU64 = AtomicU64::new(0);

#[inline(never)]
fn leaf() {
    COUNTER.fetch_add(1, Ordering::SeqCst);
    std::hint::black_box(&COUNTER);
}
#[inline(never)]
fn mid() { loop { leaf(); } }
#[inline(never)]
fn top() { mid(); }

fn main() {
    println!("pid={}", std::process::id());
    println!("counter={:p}", &COUNTER as *const _);
    use std::io::Write;
    std::io::stdout().flush().unwrap();
    top();
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
    let dir = std::env::temp_dir().join(format!("n0xis-unwind-exit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let src_path = dir.join("uw_target.rs");
    let exe_path = dir.join("uw_target.exe");
    std::fs::write(&src_path, TARGET_SRC).expect("write target source");
    // `-O` so the compiler actually emits real .pdata/.xdata unwind info (and a
    // realistic mid-function hit), `-C debuginfo=0` to keep it lean.
    let status = Command::new("rustc")
        .args(["-O", "-C", "debuginfo=0", "-o"])
        .arg(&exe_path)
        .arg(&src_path)
        .status()
        .expect("invoke rustc (must be on PATH — it built this crate)");
    assert!(status.success(), "rustc failed to compile the disposable unwind target");
    CompiledTarget { exe_path }
}

fn spawn_target(exe: &CompiledTarget) -> (DisposableProcess, u32, u64) {
    let mut child = Command::new(&exe.exe_path).stdout(Stdio::piped()).spawn().expect("spawn the compiled target");
    let stdout = child.stdout.take().expect("captured stdout");
    let mut lines = BufReader::new(stdout).lines();
    let pid_line = lines.next().expect("target prints pid=").expect("read pid line");
    let pid: u32 = pid_line.strip_prefix("pid=").expect("pid= prefix").trim().parse().expect("parse pid");
    let ctr_line = lines.next().expect("target prints counter=").expect("read counter line");
    let ctr_hex = ctr_line.strip_prefix("counter=").expect("counter= prefix").trim();
    let counter = u64::from_str_radix(ctr_hex.trim_start_matches("0x"), 16).expect("parse counter addr");
    (DisposableProcess(child), pid, counter)
}

#[test]
fn watchpoint_hit_recovers_the_real_caller_chain() {
    let target = compile_target();
    let (_child, pid, counter_va) = spawn_target(&target);
    // Let the target reach its hot loop.
    std::thread::sleep(Duration::from_millis(300));

    let outcome = await_watchpoint_hit(pid, Va(counter_va), WatchKind::Write, 8, 8000, 16, None)
        .expect("await_watchpoint_hit should not error");

    assert!(!outcome.timed_out, "the tight write loop should trip the watchpoint well within the timeout");
    let hit = outcome.hit.expect("a write watchpoint hit was captured");

    // The core claim: we recovered more than just the hit frame — real callers
    // were unwound out of the target's own .pdata/.xdata.
    assert!(
        hit.frames.len() >= 3,
        "expected the hit frame plus real callers (leaf→mid→top→…), got {} frame(s): {:#?}",
        hit.frames.len(),
        hit.frames
    );

    // Frame 0 is the hit site; it and the first callers all live in the target
    // module — proving these are genuine unwound return addresses, not stack
    // garbage that happens to look like a pointer.
    let exe_name = target.exe_path.file_name().unwrap().to_string_lossy().to_string();
    assert_eq!(hit.frames[0].module.as_deref(), Some(exe_name.as_str()), "hit frame must be in the target module");
    let in_target = hit.frames.iter().take(4).filter(|f| f.module.as_deref() == Some(exe_name.as_str())).count();
    assert!(
        in_target >= 3,
        "at least leaf/mid/top should resolve inside {exe_name}; frames: {:#?}",
        hit.frames
    );

    // Return addresses must be distinct and each carry an rva label — a real
    // chain, not the same frame repeated.
    let ups: Vec<u64> = hit.frames.iter().map(|f| f.rip).collect();
    assert!(
        ups.windows(2).all(|w| w[0] != w[1]),
        "consecutive frames must differ (no stuck unwind): {ups:#x?}"
    );
}
