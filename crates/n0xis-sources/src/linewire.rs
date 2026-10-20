// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Shared low-level plumbing for every "spawn a process, speak newline-JSON
//! over its stdio" protocol in this workspace — one JSON object per line,
//! deliberately not a versioned `n0xis.*` schema (an internal transport
//! detail between two processes, never surfaced to an agent directly).
//! [`remote`](crate::remote)'s `RemoteAgent`/`serve_stdio` and
//! [`plugin`](crate::plugin)'s `call_once` both build on this instead of each
//! re-implementing line framing and process spawning.

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
    parse_line_json(&line).map_err(|e| format!("bad response: {e}"))
}

/// Parse one received line as a JSON value. The one rule for what surrounds
/// the value on a line, for every reader here: [`str::trim`], so a line end of
/// `\n` or `\r\n` and any Unicode whitespace around the value are accepted.
/// That is wider than JSON's own whitespace (space, tab, CR, LF): a reply
/// ending in a form feed or a no-break space parses. A reply reader that
/// parsed its bytes with `serde_json::from_slice` instead refused those lines,
/// which every earlier version of `plugin::call_once` had accepted.
pub(crate) fn parse_line_json(line: &str) -> serde_json::Result<serde_json::Value> {
    serde_json::from_str(line.trim())
}

pub(crate) fn write_line_json(w: &mut impl Write, v: &serde_json::Value) -> Result<(), String> {
    let mut line = serde_json::to_string(v).map_err(|e| e.to_string())?;
    line.push('\n');
    w.write_all(line.as_bytes()).and_then(|_| w.flush()).map_err(|e| e.to_string())
}

/// Spawn `argv[0] argv[1..]` with all three of stdin, stdout and stderr
/// piped. Stderr was inherited, and an inherited stderr is the host's own,
/// passed on to every process the child starts — so a grandchild that
/// outlived the call kept a caller capturing the host's stderr waiting for
/// it. The caller copies the stderr pipe on (`plugin::forward_stderr`).
pub(crate) fn spawn_piped(argv: &[String]) -> Result<Child, String> {
    if argv.is_empty() {
        return Err("empty command".to_string());
    }
    Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn '{}': {e}", argv.join(" ")))
}
