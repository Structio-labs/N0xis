// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `provenance_trace` arms a debug register as `debug watch` does, through the one sequence
//! they share, and a server can be killed like anything else. So this door's run is on the
//! record while it waits, under its own name, and leaves none once it has read the target
//! back. The kill and the `patch undo` are the CLI's test
//! (`a_watchpoint_outlives_no_run_unaccounted`), against the same code.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

#[path = "../../n0xis-cli/tests/support/mod.rs"]
mod support;

/// Prints a cell's address, and sleeps. Nothing writes the cell, so the wait times out.
const TARGET_SRC: &str = r#"
use std::io::Write;
const PR_SET_PTRACER: i32 = 0x59616d61;
unsafe extern "C" { fn prctl(o: i32, a: u64, b: u64, c: u64, d: u64) -> i32; }
static CELL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
fn main() {
    unsafe { prctl(PR_SET_PTRACER, u64::MAX, 0, 0, 0) };
    println!("{:#x}", &CELL as *const _ as usize);
    std::io::stdout().flush().unwrap();
    loop { std::thread::sleep(std::time::Duration::from_secs(1)); }
}
"#;

struct Ending(std::process::Child);
impl Drop for Ending {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn provenance_trace_is_on_the_record_while_it_waits_and_not_after() {
    let dir = std::env::temp_dir().join(format!("n0xis-mcp-watchpoint-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("a project of its own");
    let (src, exe) = (dir.join("target.rs"), dir.join("target"));
    std::fs::write(&src, TARGET_SRC).expect("write the target");
    let built = Command::new("rustc").args(["-O", "--edition", "2024", "-o"]).arg(&exe).arg(&src).output().expect("invoke rustc");
    assert!(built.status.success(), "{}", String::from_utf8_lossy(&built.stderr));

    let mut target = Ending(Command::new(&exe).stdout(Stdio::piped()).spawn().expect("run the target"));
    let mut line = String::new();
    BufReader::new(target.0.stdout.take().expect("stdout")).read_line(&mut line).expect("the address");
    let (pid, cell) = (target.0.id(), line.trim().to_string());

    let mut server = Ending(
        support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis-mcp")))
            .current_dir(&dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("run n0xis-mcp"),
    );
    let mut stdin = server.0.stdin.take().expect("stdin");
    let mut replies = BufReader::new(server.0.stdout.take().expect("stdout")).lines();
    let mut send = |msg: Value| {
        writeln!(stdin, "{msg}").and_then(|_| stdin.flush()).expect("write to the server");
    };
    send(json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}));
    let hello = replies.next().expect("a reply").expect("a line");
    assert!(hello.contains("\"result\""), "{hello}");
    send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    send(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "provenance_trace", "arguments": {"pid": pid, "addr": cell, "len": 8, "timeout_ms": 1500}}}));

    let patches = dir.join(".n0x/patches");
    let start = Instant::now();
    let record: Value = loop {
        let file = std::fs::read_dir(&patches).ok().and_then(|mut d| d.next()).and_then(Result::ok);
        if let Some(rec) = file.and_then(|f| std::fs::read(f.path()).ok()).and_then(|b| serde_json::from_slice(&b).ok()) {
            break rec;
        }
        assert!(start.elapsed() < Duration::from_secs(20), "no record appeared");
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(record["planted_by"], "provenance_trace", "{record}");
    assert_eq!(record["pid"], pid, "{record}");
    assert_eq!(record["debug_register"]["len"], 8, "{record}");

    let reply: Value = serde_json::from_str(&replies.next().expect("a reply").expect("a line")).expect("JSON");
    let text = reply["result"]["content"][0]["text"].as_str().expect("text");
    assert!(text.contains("\"timedOut\":true"), "{text}");
    let left = std::fs::read_dir(&patches).expect("the journal").count();
    assert_eq!(left, 0, "the record went when the target was seen to be clear");
    drop(server);
    drop(target);
    let _ = std::fs::remove_dir_all(&dir);
}
