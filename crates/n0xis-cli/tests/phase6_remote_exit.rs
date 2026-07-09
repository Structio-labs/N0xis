//! **Phase 6 exit test (RemoteAgent slice)**: `mem read --remote-cmd "<n0xis>
//! remote-serve --pid <p>"` must return the exact same bytes as `mem read
//! --pid <p>` directly — proving the whole remote transport (spawn the real
//! `n0xis-cli` binary as `remote-serve`, speak the wire protocol over its
//! piped stdio, get bytes back) against a real, disposable process, not a
//! mock. `--remote-cmd` is transport-agnostic (any argv works — `ssh host ...`
//! reaches a real remote machine; this test's argv is just the same binary
//! invoked directly, which is the exact same code path minus the `ssh` hop).

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use serde_json::Value;

const TARGET_SRC: &str = r#"
fn main() {
    println!("pid={}", std::process::id());
    loop {
        std::thread::sleep(std::time::Duration::from_millis(200));
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
    let dir = std::env::temp_dir().join(format!("n0xis-phase6-remote-exit-{}", std::process::id()));
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

fn spawn_target(exe: &CompiledTarget) -> (DisposableProcess, u32) {
    let mut child = Command::new(&exe.exe_path).stdout(Stdio::piped()).spawn().expect("spawn the compiled target");
    let stdout = child.stdout.take().expect("captured stdout");
    let mut lines = BufReader::new(stdout).lines();
    let pid_line = lines.next().expect("target prints a pid= line").expect("read pid line");
    let pid: u32 = pid_line.strip_prefix("pid=").expect("pid= prefix").trim().parse().expect("parse pid");
    (DisposableProcess(child), pid)
}

fn run_n0xis(args: &[&str]) -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_n0xis")).args(args).output().expect("run n0xis");
    assert!(out.status.success(), "n0xis {args:?} exited non-zero: {}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("n0xis {args:?} did not print JSON: {e}: {}", String::from_utf8_lossy(&out.stdout)))
}

#[test]
fn remote_cmd_mem_read_matches_direct_mem_read() {
    let target = compile_target();
    let (_child, pid) = spawn_target(&target);
    std::thread::sleep(std::time::Duration::from_millis(300));

    // The target's own image base is always mapped — no function discovery
    // needed, keeping this test focused on the transport, not analysis.
    let modules = run_n0xis(&["module", "list", "--pid", &pid.to_string()]);
    let base = modules["data"]["modules"][0]["base"].as_str().expect("base address").to_string();

    let direct = run_n0xis(&["mem", "read", "--pid", &pid.to_string(), "--addr", &base, "--size", "32"]);
    assert_eq!(direct["ok"], true, "direct mem read failed: {direct}");

    let n0xis_exe = env!("CARGO_BIN_EXE_n0xis");
    let remote_cmd = format!("{n0xis_exe} remote-serve --pid {pid}");
    let via_remote = run_n0xis(&["mem", "read", "--remote-cmd", &remote_cmd, "--addr", &base, "--size", "32"]);
    assert_eq!(via_remote["ok"], true, "remote mem read failed: {via_remote}");

    assert_eq!(
        via_remote["data"]["hex"], direct["data"]["hex"],
        "remote-cmd transport must return byte-identical data to a direct attach"
    );
    assert!(
        via_remote["meta"]["source"].as_str().unwrap_or("").starts_with("remote:"),
        "meta.source should be tagged remote:...: {via_remote}"
    );
}
