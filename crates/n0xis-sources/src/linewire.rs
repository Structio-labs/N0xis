// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Shared low-level plumbing for every "spawn a process, speak newline-JSON
//! over its stdio" protocol in this workspace — one JSON object per line,
//! deliberately not a versioned `n0xis.*` schema (an internal transport
//! detail between two processes, never surfaced to an agent directly).
//! [`remote`](crate::remote)'s `RemoteAgent`/`serve_stdio` and
//! [`plugin`](crate::plugin)'s `PluginCall`/`PluginSession` both build on
//! this instead of each re-implementing line framing and process spawning.

use std::io::{BufRead, Write};
use std::process::{Child, Command, Stdio};

/// Read the next JSON value from `r`, or bail with an I/O-flavored error if
/// the stream closed.
pub(crate) fn read_line_json(r: &mut impl BufRead) -> Result<serde_json::Value, String> {
    let mut line = String::new();
    let n = r.read_line(&mut line).map_err(|e| e.to_string())?;
    if n == 0 {
        return Err("the other side closed the connection".to_string());
    }
    serde_json::from_str(line.trim()).map_err(|e| format!("bad response: {e}"))
}

pub(crate) fn write_line_json(w: &mut impl Write, v: &serde_json::Value) -> Result<(), String> {
    let mut line = serde_json::to_string(v).map_err(|e| e.to_string())?;
    line.push('\n');
    w.write_all(line.as_bytes()).and_then(|_| w.flush()).map_err(|e| e.to_string())
}

/// Spawn `argv[0] argv[1..]` with piped stdin/stdout (stderr inherited).
pub(crate) fn spawn_piped(argv: &[String]) -> Result<Child, String> {
    if argv.is_empty() {
        return Err("empty command".to_string());
    }
    Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn '{}': {e}", argv.join(" ")))
}
