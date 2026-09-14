// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Cross-door parity** — the CLI and the MCP server must answer the same for
//! the same input. The MCP tools that reimplemented capabilities the CLI routes
//! through the shared frontend registry had drifted, and every drift was a
//! confident wrong answer on the MCP door alone:
//!
//! - `disasm`/`function_discover`/`explain_opt_delta` forced the x86-64 decoder
//!   regardless of the image's `e_machine`, so an AArch64 image came back as
//!   `add [rax],al` garbage and an i386 image with 64-bit-width operands, while
//!   the CLI auto-detected the ISA from the header (B1);
//! - `function_discover` (and everything on the same starved `Ctx`) never saw
//!   the project's symbol chain — user renames, recovered RTTI, FLIRT, IL2CPP —
//!   so a function the CLI names came back as `sub_XXXX` or was missed (B2);
//! - `disasm` returned `decode-failed` for an out-of-image address where the CLI
//!   returns `addr-out-of-image` with an actionable image-base hint (D1).
//!
//! The fix routes those MCP tools through `n0xis_frontend::build_registry()` —
//! the exact code the CLI reaches — so the two doors cannot diverge again. Each
//! test below drives the **real** `n0xis-mcp` binary over stdio (the way an
//! agent would) and the **real** `n0xis` CLI binary, and is calibrated: reverting
//! the delegation makes it fail on its own assertion (see the module test log).
//!
//! Independence: the correct decode is not taken from n0xis. The AArch64 bytes
//! at `add` are `0b010000 -> add w0, w0, w1` per `aarch64-linux-gnu-objdump`,
//! asserted here directly, so the arm64 test pins an externally-known answer.
//!
//! Fixtures are built at test time with `aarch64-linux-gnu-gcc` and `gcc -m32`;
//! if a cross-compiler (or the sibling `n0xis` binary) is absent the affected
//! test **skips loudly** rather than passing vacuously.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use serde_json::{Value, json};

/// The disposable C fixture: a handful of tiny named leaf functions plus a
/// loop, so `function discover` has real symbols to carry and `disasm` has a
/// known first instruction at `add`.
const FIXTURE_SRC: &str = r#"
int add(int a, int b) { return a + b; }
int sub(int a, int b) { return a - b; }
int mul(int a, int b) { return a * b; }
long work(long n) { long t = 0; for (long i = 0; i < n; i++) t += i ^ (i >> 3); return t; }
int main(void) { return add(1, 2) + sub(3, 4) + mul(5, 6) + (int) work(10); }
"#;

/// The real symbols the fixture defines — both doors must carry every one of
/// these at the same address whatever the arch scan does around them.
const EXPECTED_SYMBOLS: &[&str] = &["add", "sub", "mul", "work", "main"];

/// A process-unique scratch dir. `cargo` runs test fns as threads in one
/// process, so `std::process::id()` alone collides between parallel tests — an
/// atomic counter is what makes each probe/fixture dir its own.
fn unique_dir(prefix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("n0xis-{prefix}-{}-{n}", std::process::id()))
}

fn tool_present(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The `n0xis` CLI binary, found as a sibling of this crate's own test binary in
/// the same `target/<profile>/` directory (there is no `CARGO_BIN_EXE_n0xis`
/// across the package boundary). Present under `cargo test --workspace`.
fn cli_binary() -> Option<PathBuf> {
    let mcp = PathBuf::from(env!("CARGO_BIN_EXE_n0xis-mcp"));
    let dir = mcp.parent()?;
    let name = if cfg!(windows) { "n0xis.exe" } else { "n0xis" };
    let p = dir.join(name);
    p.exists().then_some(p)
}

struct Fixture {
    dir: PathBuf,
    file: String,
    cli: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Compile `FIXTURE_SRC` with `compiler` into a fresh scratch dir. Returns
/// `None` (with a loud skip line) when a prerequisite is missing, so a caller
/// `let Some(fx) = ... else { return }` skips rather than fails.
fn build_fixture(compiler: &str, extra: &[&str], tag: &str) -> Option<Fixture> {
    let Some(cli) = cli_binary() else {
        eprintln!("SKIP[{tag}]: sibling `n0xis` CLI binary not found next to n0xis-mcp — run under `cargo test --workspace`");
        return None;
    };
    if !compiler_can_build(compiler, extra) {
        eprintln!("SKIP[{tag}]: `{compiler} {}` cannot build a fixture here — arch not exercised", extra.join(" "));
        return None;
    }
    let dir = unique_dir(&format!("parity-{tag}"));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let src = dir.join("fixture.c");
    std::fs::write(&src, FIXTURE_SRC).expect("write fixture source");
    let out = dir.join("fixture.elf");
    let status = Command::new(compiler)
        .args(extra)
        .arg("-O1")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .unwrap_or_else(|e| panic!("invoke {compiler}: {e}"));
    assert!(status.success(), "{compiler} failed to build the fixture");
    Some(Fixture { dir, file: "fixture.elf".to_string(), cli })
}

/// Probe that `compiler` with `extra` can actually produce a binary — `gcc` may
/// be installed without the 32-bit multilib `-m32` needs, and a cross-gcc may be
/// a stub. A real compile is the only honest check.
fn compiler_can_build(compiler: &str, extra: &[&str]) -> bool {
    if !tool_present(compiler) {
        return false;
    }
    let dir = unique_dir("probe");
    let _ = std::fs::create_dir_all(&dir);
    let src = dir.join("p.c");
    let _ = std::fs::write(&src, "int main(void){return 0;}");
    let ok = Command::new(compiler)
        .args(extra)
        .arg("-o")
        .arg(dir.join("p.out"))
        .arg(&src)
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let _ = std::fs::remove_dir_all(&dir);
    ok
}

/// A live `n0xis-mcp` child driven over raw JSON-RPC/stdio, launched with a
/// chosen cwd so `.n0x/session.json` and the project's symbol layer resolve.
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
    fn spawn(cwd: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_n0xis-mcp"))
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn n0xis-mcp");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");
        let mut c = McpClient { child, stdin, lines: BufReader::new(stdout).lines(), next_id: 1 };
        c.send(&json!({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": { "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": { "name": "parity", "version": "0" } }
        }));
        let init = c.recv();
        assert!(init.get("result").is_some(), "initialize failed: {init}");
        c.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        c
    }
    fn send(&mut self, msg: &Value) {
        let mut line = serde_json::to_string(msg).expect("serialize request");
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).expect("write to n0xis-mcp stdin");
        self.stdin.flush().expect("flush n0xis-mcp stdin");
    }
    fn recv(&mut self) -> Value {
        let line = self.lines.next().expect("n0xis-mcp response line").expect("read response line");
        serde_json::from_str(&line).expect("response is valid JSON")
    }
    /// Call a tool and return its parsed `{ok,data,meta}` envelope.
    fn call(&mut self, name: &str, args: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": name, "arguments": args } }));
        let resp = self.recv();
        assert_eq!(resp["id"], id, "response id mismatch: {resp}");
        let text = resp["result"]["content"][0]["text"].as_str().unwrap_or_else(|| panic!("tool '{name}' returned no text: {resp}"));
        serde_json::from_str(text).unwrap_or_else(|e| panic!("tool '{name}' text wasn't the envelope: {e}: {text}"))
    }
}

/// Run the CLI binary in `cwd` and parse its stdout envelope (progress goes to
/// stderr, which we discard).
fn cli(cli_bin: &Path, cwd: &Path, args: &[&str]) -> Value {
    let out = Command::new(cli_bin)
        .current_dir(cwd)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .expect("run n0xis CLI");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("CLI {args:?} stdout wasn't the envelope: {e}: {}", String::from_utf8_lossy(&out.stdout)))
}

/// The address the CLI's discovery lists for a named function.
fn named_va(disc: &Value, name: &str) -> String {
    disc["data"]["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .find(|f| f["name"] == name)
        .and_then(|f| f["va"].as_str())
        .unwrap_or_else(|| panic!("fixture defines `{name}`"))
        .to_string()
}

/// The `(va, name)` pairs of every function that carries a *real* name (not a
/// synthesized `sub_XXXX`). This is the arch-independent part of discovery —
/// the stated symbol table — and it must match across doors even though the
/// heuristic prologue scan around it may not.
fn named_functions(env: &Value) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = env["data"]["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|f| {
            let va = f["va"].as_str()?.to_string();
            let name = f["name"].as_str()?.to_string();
            (!name.starts_with("sub_")).then_some((va, name))
        })
        .collect();
    v.sort();
    v
}

// ---- B1: the ISA the x64-forcing bug turned into garbage --------------------

/// AArch64 `disasm` must be identical across doors *and* be the ARM decode.
/// Calibration: with the bug, MCP `data.insns[0].text` is `add [rax],al` while
/// the CLI's is `add w0, w0, w1` — the whole-`data` equality fails here.
#[test]
fn disasm_agrees_across_doors_arm64() {
    let Some(fx) = build_fixture("aarch64-linux-gnu-gcc", &[], "arm64-disasm") else { return };
    let mut mcp = McpClient::spawn(&fx.dir);
    let add_va = named_va(&cli(&fx.cli, &fx.dir, &["function", "discover", "--file", &fx.file]), "add");

    let c = cli(&fx.cli, &fx.dir, &["disasm", "--file", &fx.file, "--addr", &add_va, "--count", "3"]);
    let m = mcp.call("disasm", json!({ "file": fx.file, "addr": add_va, "count": 3 }));
    assert_eq!(c["data"], m["data"], "arm64 disasm data must be identical across doors");
    // Externally-known answer (aarch64-linux-gnu-objdump): 0b010000 = add w0, w0, w1.
    assert_eq!(m["data"]["insns"][0]["mnemonic"], "add", "arm64 decode: first insn is `add` (objdump-confirmed)");
    assert!(
        m["data"]["insns"][0]["text"].as_str().unwrap().contains("w0"),
        "arm64 decode names the 32-bit ARM register `w0`, not an x86 register: {}",
        m["data"]["insns"][0]["text"]
    );
}

/// i386 `disasm` must be identical across doors and carry no 64-bit-width
/// operand. Calibration: with the bug, MCP prints `call 000000000000118Ch`
/// (16 hex digits) where the CLI prints `call 0000118Ch`.
#[test]
fn disasm_agrees_across_doors_i386() {
    let Some(fx) = build_fixture("gcc", &["-m32"], "i386-disasm") else { return };
    let mut mcp = McpClient::spawn(&fx.dir);
    let main_va = named_va(&cli(&fx.cli, &fx.dir, &["function", "discover", "--file", &fx.file]), "main");

    let c = cli(&fx.cli, &fx.dir, &["disasm", "--file", &fx.file, "--addr", &main_va, "--count", "3"]);
    let m = mcp.call("disasm", json!({ "file": fx.file, "addr": main_va, "count": 3 }));
    assert_eq!(c["data"], m["data"], "i386 disasm data must be identical across doors");
    let joined: String = m["data"]["insns"].as_array().unwrap().iter().map(|i| i["text"].as_str().unwrap_or("")).collect();
    assert!(!joined.contains("0000000000"), "i386 decode must not carry 64-bit-width operands: {joined}");
}

// ---- B2: the project symbol chain the starved Ctx never saw -----------------

/// `function_discover` must carry the fixture's real symbols, and its
/// named-function set must match the CLI's. Calibration: with the bug the MCP
/// door builds a `Ctx` with no stated-function set and forces x64, so on an
/// AArch64 image discovery returns nothing — `named_functions(&m)` is empty and
/// the set-equality assertion fails.
///
/// The comparison is over the *named* (stated-symbol) subset only, because it is
/// arch-independent. The `sub_XXXX` scan candidates legitimately differ: the CLI
/// `function discover` front door (`cmd_discover`) still selects the decoder with
/// `resolve_arch` (x64 default), while the registry — and now MCP — select it
/// from the header, so their prologue scans see different bytes. That CLI
/// front-door defect is reported separately; it does not touch the stated set.
#[test]
fn function_discover_symbol_chain_agrees_across_doors_arm64() {
    let Some(fx) = build_fixture("aarch64-linux-gnu-gcc", &[], "arm64-discover") else { return };
    let mut mcp = McpClient::spawn(&fx.dir);

    let c = cli(&fx.cli, &fx.dir, &["function", "discover", "--file", &fx.file]);
    let m = mcp.call("function_discover", json!({ "file": fx.file }));
    let c_named = named_functions(&c);
    let m_named = named_functions(&m);
    assert_eq!(c_named, m_named, "arm64 discover: named-function set must match across doors");
    for sym in EXPECTED_SYMBOLS {
        assert!(m_named.iter().any(|(_, n)| n == sym), "MCP discover must carry symbol `{sym}` (B2 chain): {m_named:?}");
    }
}

/// B2, isolated: a user rename recorded in `.n0x/` must reach the MCP
/// `function_discover` door. Calibration: with the bug `with_ctx` attaches only
/// the image's own symbols (never the `LocalNames` layer) *and* returns nothing
/// on arm64, so the rename never appears — the `find(add)` `expect` trips.
#[test]
fn function_discover_carries_a_project_rename() {
    let Some(fx) = build_fixture("aarch64-linux-gnu-gcc", &[], "arm64-rename") else { return };
    std::fs::create_dir_all(fx.dir.join(".n0x")).expect("create .n0x");
    let mut mcp = McpClient::spawn(&fx.dir);

    let add_va = mcp
        .call("function_discover", json!({ "file": fx.file }))["data"]["functions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "add")
        .and_then(|f| f["va"].as_str())
        .expect("fixture defines `add`")
        .to_string();

    let set = mcp.call("annotate_set", json!({ "addr": add_va, "field": "name", "value": "RenamedThroughMcp" }));
    assert_eq!(set["ok"], true, "annotate_set failed: {set}");

    let disc = mcp.call("function_discover", json!({ "file": fx.file }));
    let name = disc["data"]["functions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["va"].as_str() == Some(add_va.as_str()))
        .and_then(|f| f["name"].as_str());
    assert_eq!(name, Some("RenamedThroughMcp"), "MCP discover must carry the project rename (B2 chain)");
}

// ---- D1: the error contract for an out-of-image address ---------------------

/// An out-of-image address is refused with the *same* code on both doors, with
/// the CLI's actionable image-base hint. Calibration: with the bug the MCP door
/// answers `decode-failed` (its bespoke disasm never calls `refuse_unreadable`),
/// so the `addr-out-of-image` assertion fails.
#[test]
fn disasm_out_of_image_error_agrees_across_doors() {
    let Some(fx) = build_fixture("aarch64-linux-gnu-gcc", &[], "arm64-oor") else { return };
    let mut mcp = McpClient::spawn(&fx.dir);
    let oor = "0x99999999";

    let c = cli(&fx.cli, &fx.dir, &["disasm", "--file", &fx.file, "--addr", oor, "--count", "1"]);
    let m = mcp.call("disasm", json!({ "file": fx.file, "addr": oor, "count": 1 }));
    assert_eq!(c["ok"], false, "CLI must refuse an out-of-image address");
    assert_eq!(m["ok"], false, "MCP must refuse an out-of-image address");
    assert_eq!(m["error"]["code"], "addr-out-of-image", "MCP out-of-image code must be `addr-out-of-image`, not `decode-failed`");
    assert_eq!(c["error"]["code"], m["error"]["code"], "out-of-image error code must match across doors");
    assert!(m["error"]["hint"].is_string(), "MCP must carry the CLI's actionable image-base hint");
}
