// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The MCP server interrupts nothing during a session: its version, and that a newer one exists, are in
//! what it states at the start (docs/design/UPDATE.md §1). It reads what the check left, and asks no
//! one: `no_request` holds that with a proxy nothing should reach.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

#[path = "../../n0xis-cli/tests/support/mod.rs"]
mod support;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn config_dir(name: &str, state: Option<Value>) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("mcp-states-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    if let Some(state) = state {
        std::fs::write(dir.join("update-state.json"), state.to_string()).unwrap();
    }
    dir
}

/// What a client is told at `initialize`.
fn stated(config: &Path, env: &[(&str, &str)]) -> String {
    let mut command = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis-mcp")));
    command.env("N0X_CONFIG_DIR", config).env_remove("N0X_NO_UPDATE_CHECK").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("spawn n0xis-mcp");
    let mut stdin = child.stdin.take().expect("child stdin");
    let mut lines = BufReader::new(child.stdout.take().expect("child stdout")).lines();
    let hello = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": { "name": "test", "version": "0" } } });
    writeln!(stdin, "{hello}").expect("write");
    stdin.flush().expect("flush");
    let line = lines.next().expect("a response").expect("read");
    let _ = child.kill();
    let _ = child.wait();
    let answer: Value = serde_json::from_str(&line).expect("JSON");
    answer["result"]["instructions"].as_str().expect("instructions").to_string()
}

/// With nothing on standard input and a bound, as `scripts/release.py` runs it: a server that took this
/// for a session once exited 1 with `connection closed`.
#[test]
fn version_answers_with_null_stdin() {
    let dir = config_dir("version", None);
    let mut command = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis-mcp")));
    let mut child = command.env("N0X_CONFIG_DIR", &dir).arg("--version").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn n0xis-mcp");
    let start = std::time::Instant::now();
    while child.try_wait().expect("wait").is_none() {
        if start.elapsed() > std::time::Duration::from_secs(30) {
            let _ = child.kill();
            panic!("no answer within the bound");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let out = child.wait_with_output().expect("output");
    assert!(out.status.success(), "{:?}", out.status);
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("n0xis-mcp {VERSION}\n"));
}

#[test]
fn a_newer_version_is_stated_at_the_start() {
    let dir = config_dir("newer", Some(json!({ "latest": "99.0.0" })));
    let text = stated(&dir, &[]);
    assert!(text.contains(&format!("This is n0xis-mcp {VERSION}.")), "{text}");
    assert!(text.contains("99.0.0 is available: n0x update."), "{text}");
}

#[test]
fn nothing_newer_states_the_version_only() {
    for (name, state) in [("none", None), ("same", Some(json!({ "latest": VERSION }))), ("older", Some(json!({ "latest": "0.0.1" })))] {
        let dir = config_dir(name, state);
        let text = stated(&dir, &[]);
        assert!(text.contains(&format!("This is n0xis-mcp {VERSION}.")), "{text}");
        assert!(!text.contains("is available"), "{name}: {text}");
    }
}

#[test]
fn turned_off_means_not_said() {
    let dir = config_dir("off", Some(json!({ "latest": "99.0.0" })));
    assert!(!stated(&dir, &[("N0X_NO_UPDATE_CHECK", "1")]).contains("is available"));
    std::fs::write(dir.join("config.json"), json!({ "update.check": false }).to_string()).unwrap();
    assert!(!stated(&dir, &[]).contains("is available"));
}

#[test]
fn no_request() {
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let address = format!("http://127.0.0.1:{}", proxy.local_addr().unwrap().port());
    let dir = config_dir("request", None);
    stated(&dir, &[("HTTPS_PROXY", &address), ("ALL_PROXY", &address)]);
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert!(proxy.accept().is_err(), "the server made a request");
    assert!(!dir.join("update-check.stamp").exists(), "the server claimed the daily check");
}
