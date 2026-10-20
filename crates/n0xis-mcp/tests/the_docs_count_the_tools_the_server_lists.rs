// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The documents count the tools the server lists.**
//!
//! The README and `docs/COMMUNITY_ROADMAP.md` said `n0xis-mcp` has 25 tools
//! while it listed 27: nothing compared them. This asks the server itself, over
//! `tools/list` as a client does, and fails where a document states another
//! number or no longer states one.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

#[path = "../../n0xis-cli/tests/support/mod.rs"]
mod support;

/// How many tools the server answers `tools/list` with.
fn listed() -> usize {
    let mut child = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis-mcp")))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn n0xis-mcp");
    let mut stdin = child.stdin.take().expect("child stdin");
    let mut lines = BufReader::new(child.stdout.take().expect("child stdout")).lines();
    for msg in [
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": { "name": "docs", "version": "0" } } }),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
    ] {
        writeln!(stdin, "{msg}").expect("write to n0xis-mcp stdin");
    }
    stdin.flush().expect("flush n0xis-mcp stdin");
    let count = loop {
        let line = lines.next().expect("a response line").expect("read a response line");
        let v: Value = serde_json::from_str(&line).expect("a JSON response");
        if v["id"] == 2 {
            break v["result"]["tools"].as_array().expect("a tool list").len();
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    count
}

/// Every count `doc` states as `<marker> <n> tools`, the number and the word
/// apart by any whitespace, a line break included.
fn stated(doc: &str, marker: &str) -> Vec<usize> {
    let text = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(doc)).expect("the document");
    text.match_indices(marker)
        .filter_map(|(at, _)| {
            let rest = text[at + marker.len()..].trim_start();
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            (!digits.is_empty() && rest[digits.len()..].trim_start().starts_with("tools")).then(|| digits.parse().expect("a count"))
        })
        .collect()
}

#[test]
fn the_docs_count_the_tools_the_server_lists() {
    let n = listed();
    assert_eq!(stated("README.md", "`n0xis-mcp` —"), vec![n], "README.md: the server lists {n} tools");
    assert_eq!(stated("docs/COMMUNITY_ROADMAP.md", "exposes"), vec![n], "docs/COMMUNITY_ROADMAP.md: the server lists {n} tools");
}
