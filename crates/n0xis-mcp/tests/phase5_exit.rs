//! **The Phase 5 exit test** (ROADMAP): "an agent drives attach → discover →
//! decompile → explain end-to-end through MCP only."
//!
//! Unlike the tool-level checks a unit test could do in-process, this test
//! spawns the *real* `n0xis-mcp` binary as a child process and speaks raw
//! JSON-RPC-over-stdio to it — the same way an actual MCP client (an agent
//! harness) would — so it proves the transport wiring, not just the tool
//! function bodies. It also spawns a real, disposable Windows process as the
//! attach target (same `rustc`-at-test-time trick as `phase4c_exit.rs`), so
//! `attach`/`discover`/`decompile`/`explain` all run against real bytes, not
//! a mock.
//!
//! Windows-only, and gated rather than left to fail: the test drives `attach`
//! and `discover` **by pid**, and off Windows those tools return the
//! `live-unsupported` stub because there is no non-Win32 `LiveProcess` behind
//! the source seam. Without this gate `cargo test --workspace` on Linux fails
//! on an unimplemented capability rather than on a regression.
#![cfg(windows)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

use serde_json::{Value, json};

const TARGET_SRC: &str = r#"
fn main() {
    let mut total: u64 = 0;
    for i in 0..1_000_000u64 {
        total = total.wrapping_add(i ^ (i >> 3));
    }
    println!("pid={}", std::process::id());
    println!("total={total}");
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
    let dir = std::env::temp_dir().join(format!("n0xis-phase5-exit-{}", std::process::id()));
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
    let mut child = Command::new(&exe.exe_path)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn the compiled target");
    let stdout = child.stdout.take().expect("captured stdout");
    let mut lines = BufReader::new(stdout).lines();
    let pid_line = lines.next().expect("target prints a pid= line").expect("read pid line");
    let pid: u32 = pid_line.strip_prefix("pid=").expect("pid= prefix").trim().parse().expect("parse pid");
    (DisposableProcess(child), pid)
}

/// A live `n0xis-mcp` child process, driven over raw JSON-RPC/stdio.
struct McpClient {
    child: Child,
    stdin: std::process::ChildStdin,
    lines: std::io::Lines<BufReader<std::process::ChildStdout>>,
    next_id: u64,
}
impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl McpClient {
    fn spawn(project_dir: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_n0xis-mcp"))
            .current_dir(project_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn n0xis-mcp");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");
        McpClient { child, stdin, lines: BufReader::new(stdout).lines(), next_id: 1 }
    }

    fn send(&mut self, msg: &Value) {
        let mut line = serde_json::to_string(msg).expect("serialize request");
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).expect("write to n0xis-mcp stdin");
        self.stdin.flush().expect("flush n0xis-mcp stdin");
    }

    fn recv(&mut self) -> Value {
        let line = self
            .lines
            .next()
            .expect("n0xis-mcp produced a response line")
            .expect("read response line");
        serde_json::from_str(&line).expect("response is valid JSON")
    }

    fn initialize(&mut self) {
        self.send(&json!({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "phase5-exit-test", "version": "0.0.0" }
            }
        }));
        let resp = self.recv();
        assert!(resp.get("result").is_some(), "initialize failed: {resp}");
        self.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
    }

    /// Call a tool and return the parsed `{ok,data,meta}` envelope from its
    /// text content — the same envelope `n0xis-cli` prints to stdout.
    fn call_tool(&mut self, name: &str, arguments: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        }));
        let resp = self.recv();
        assert_eq!(resp["id"], id, "response id mismatch: {resp}");
        let text = resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("tool call '{name}' returned no text content: {resp}"));
        serde_json::from_str(text).unwrap_or_else(|e| panic!("tool '{name}' text wasn't the envelope JSON: {e}: {text}"))
    }
}

#[test]
fn agent_drives_attach_discover_decompile_explain_through_mcp_only() {
    let target = compile_target();
    let (_child, pid) = spawn_target(&target);
    std::thread::sleep(std::time::Duration::from_millis(300));

    let project_dir = std::env::temp_dir().join(format!("n0xis-phase5-project-{}", std::process::id()));
    std::fs::create_dir_all(project_dir.join(".n0x")).expect("create scratch .n0x project");

    let mut mcp = McpClient::spawn(&project_dir);
    mcp.initialize();

    // Step 1 — attach (no addr/pid resolution the agent has to do by hand;
    // it just names the pid it found via `process_ps` in a real workflow).
    let attach = mcp.call_tool("attach", json!({ "pid": pid }));
    assert_eq!(attach["ok"], true, "attach failed: {attach}");
    assert_eq!(attach["meta"]["schema"], "n0xis.project.info.v1");

    // The session default must be visible to any later tool call *and* to
    // the CLI, since both read `.n0x/session.json` in the same project dir.
    let session_path = project_dir.join(".n0x").join("session.json");
    assert!(session_path.exists(), "attach must persist .n0x/session.json");
    let session: Value = serde_json::from_str(&std::fs::read_to_string(&session_path).unwrap()).unwrap();
    assert_eq!(session["pid"], pid);

    // Step 2 — discover, with pid omitted: resolved from the session default.
    let discover = mcp.call_tool("function_discover", json!({}));
    assert_eq!(discover["ok"], true, "function_discover failed: {discover}");
    assert_eq!(discover["meta"]["schema"], "n0xis.function.discover.v1");
    let functions = discover["data"]["functions"].as_array().expect("functions array");
    assert!(!functions.is_empty(), "must discover at least one candidate in a real process's .text");
    let addr = functions[0]["va"].as_str().expect("candidate has a va").to_string();

    // Step 3 — decompile it (also pid-omitted; still the session default).
    let decomp = mcp.call_tool("decomp_pseudo", json!({ "addr": addr, "style": "ssa" }));
    assert_eq!(decomp["ok"], true, "decomp_pseudo failed: {decomp}");
    assert_eq!(decomp["meta"]["schema"], "n0x.decomp.pseudo.v1");
    let pseudo = decomp["data"]["pseudo"].as_array().expect("pseudo lines");
    assert!(!pseudo.is_empty(), "decompile must produce at least one pseudo-C line");

    // Step 4 — explain: surfaces the SSA optimizer's reasoning for the same function.
    let explain = mcp.call_tool("explain_opt_delta", json!({ "addr": addr }));
    assert_eq!(explain["ok"], true, "explain_opt_delta failed: {explain}");
    assert_eq!(explain["meta"]["schema"], "n0xis.opt.delta.v1");
    assert!(explain["data"]["entries"].is_array(), "explain must return the delta entries array");

    std::fs::remove_dir_all(&project_dir).ok();
}
