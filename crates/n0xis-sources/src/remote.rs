//! [`RemoteAgent`] — a [`MemorySource`] that proxies to a **remote-serve**
//! process over its stdin/stdout (ROADMAP Phase 6: "`RemoteAgent` source over
//! SSH/Tailscale"). Deliberately generic over *how* that process is reached:
//! `connect` takes an argv and spawns it directly — `["ssh", "user@host",
//! "n0xis", "remote-serve", "--pid", "1234"]` reaches a real remote machine
//! over SSH (the transport is just "spawn a command with piped stdio", so SSH
//! is one possible argv prefix among others, never hardcoded here — CONCEPT's
//! anti-hardcode policy), while a bare local invocation is exactly what
//! [`tests`] use to prove the protocol without needing a second machine.
//!
//! Wire protocol: newline-delimited JSON, one request/response object per
//! line, deliberately *not* a versioned `n0xis.*` schema — it is an internal
//! transport detail between one `n0xis` process and another, never surfaced
//! to an agent directly. [`serve_stdio`] is the server half, generic over any
//! [`MemorySource`] so it can be protocol-tested against a `Snapshot` here and
//! wired to a real `LiveProcess` by the CLI's `remote-serve` command.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

use n0xis_contracts::Va;
use serde_json::{Value, json};

use crate::linewire::{read_line_json as linewire_read, write_line_json as linewire_write};
use crate::{MemorySource, SourceError};

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Split a `--remote-cmd` string into an argv, respecting `"..."` for
/// arguments containing spaces. **Deliberately not POSIX shell-word
/// splitting**: this tool is Windows-first, and a POSIX splitter treats `\`
/// as an escape character, silently mangling the Windows paths users will
/// actually type here (`"D:\tools\n0xis.exe remote-serve --pid 1"` would lose
/// every backslash). No escape sequences at all — `\` is always literal;
/// if you need a literal `"` inside a quoted argument, this doesn't support
/// it (a documented limitation, not expected to matter for `ssh host cmd
/// --flag value`-shaped commands).
pub fn split_command_line(s: &str) -> Result<Vec<String>, String> {
    let mut argv = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut has_token = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                has_token = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if has_token {
                    argv.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            c => {
                current.push(c);
                has_token = true;
            }
        }
    }
    if in_quotes {
        return Err("unterminated \" in --remote-cmd".to_string());
    }
    if has_token {
        argv.push(current);
    }
    Ok(argv)
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// One line of the wire protocol, either direction — thin `SourceError`
/// wrappers over the shared [`crate::linewire`] framing (also used by
/// [`crate::plugin`]'s transport, so the line-protocol logic lives once).
fn read_line_json(r: &mut impl BufRead) -> Result<Value, SourceError> {
    linewire_read(r).map_err(SourceError::Os)
}

fn write_line_json(w: &mut impl Write, v: &Value) -> Result<(), SourceError> {
    linewire_write(w, v).map_err(SourceError::Os)
}

struct RemoteIo {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

/// A live source reached by spawning `argv` and speaking the remote-serve
/// protocol over its stdio (typically an `ssh` invocation, but the agent
/// itself is transport-agnostic).
pub struct RemoteAgent {
    child: Child,
    io: Mutex<RemoteIo>,
    label: String,
}

impl RemoteAgent {
    /// Spawn `argv[0] argv[1..]` and perform one `label` round-trip so a bad
    /// command (wrong host, remote binary not on PATH, ...) fails fast at
    /// `connect` time rather than on the first real read.
    pub fn connect(argv: Vec<String>) -> Result<Self, SourceError> {
        if argv.is_empty() {
            return Err(SourceError::Load("empty remote command".to_string()));
        }
        let mut child = Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| SourceError::Load(format!("spawn '{}': {e}", argv.join(" "))))?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut io = RemoteIo { stdin, stdout };

        write_line_json(&mut io.stdin, &json!({ "op": "label" }))?;
        let resp = read_line_json(&mut io.stdout)?;
        let label = resp["label"].as_str().unwrap_or("remote").to_string();

        Ok(RemoteAgent { child, io: Mutex::new(io), label: format!("remote:{label}") })
    }

    fn roundtrip(&self, req: &Value) -> Result<Value, SourceError> {
        let mut io = self.io.lock().unwrap_or_else(|e| e.into_inner());
        write_line_json(&mut io.stdin, req)?;
        read_line_json(&mut io.stdout)
    }
}

impl Drop for RemoteAgent {
    fn drop(&mut self) {
        if let Ok(mut io) = self.io.lock() {
            let _ = write_line_json(&mut io.stdin, &json!({ "op": "quit" }));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl MemorySource for RemoteAgent {
    fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, SourceError> {
        let resp = self.roundtrip(&json!({ "op": "read", "va": va.to_string(), "len": len }))?;
        if resp["ok"].as_bool() != Some(true) {
            let msg = resp["error"].as_str().unwrap_or("remote read failed").to_string();
            return if msg.contains("not mapped") { Err(SourceError::Unmapped(va)) } else { Err(SourceError::Os(msg)) };
        }
        from_hex(resp["hex"].as_str().unwrap_or("")).ok_or_else(|| SourceError::Os("malformed hex in remote response".to_string()))
    }

    fn contains(&self, va: Va) -> bool {
        self.roundtrip(&json!({ "op": "contains", "va": va.to_string() }))
            .ok()
            .and_then(|r| r["contains"].as_bool())
            .unwrap_or(false)
    }

    fn write(&self, va: Va, bytes: &[u8]) -> Result<(), SourceError> {
        let resp = self.roundtrip(&json!({ "op": "write", "va": va.to_string(), "hex": to_hex(bytes) }))?;
        if resp["ok"].as_bool() == Some(true) {
            Ok(())
        } else {
            Err(SourceError::Os(resp["error"].as_str().unwrap_or("remote write failed").to_string()))
        }
    }

    fn label(&self) -> String {
        self.label.clone()
    }
}

/// The server half: read newline-JSON requests from `input` and reply on
/// `output` against `source`, until `quit` or EOF. Generic over any
/// [`MemorySource`] so the protocol itself is tested OS-free here (against a
/// `Snapshot`); the CLI's `remote-serve` command wires a real `LiveProcess`.
pub fn serve_stdio(source: &dyn MemorySource, input: impl Read, mut output: impl Write) -> std::io::Result<()> {
    let mut reader = BufReader::new(input);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(()); // EOF: client hung up.
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                write_response(&mut output, &json!({ "ok": false, "error": format!("bad request: {e}") }))?;
                continue;
            }
        };
        match req["op"].as_str().unwrap_or("") {
            "label" => write_response(&mut output, &json!({ "ok": true, "label": source.label() }))?,
            "contains" => {
                let va = parse_va(&req);
                write_response(&mut output, &json!({ "ok": true, "contains": va.map(|v| source.contains(v)).unwrap_or(false) }))?
            }
            "read" => {
                let Some(va) = parse_va(&req) else {
                    write_response(&mut output, &json!({ "ok": false, "error": "missing/bad va" }))?;
                    continue;
                };
                let len = req["len"].as_u64().unwrap_or(0) as usize;
                match source.read(va, len) {
                    Ok(bytes) => write_response(&mut output, &json!({ "ok": true, "hex": to_hex(&bytes) }))?,
                    Err(e) => write_response(&mut output, &json!({ "ok": false, "error": e.to_string() }))?,
                }
            }
            "write" => {
                let Some(va) = parse_va(&req) else {
                    write_response(&mut output, &json!({ "ok": false, "error": "missing/bad va" }))?;
                    continue;
                };
                let Some(bytes) = req["hex"].as_str().and_then(from_hex) else {
                    write_response(&mut output, &json!({ "ok": false, "error": "missing/bad hex" }))?;
                    continue;
                };
                match source.write(va, &bytes) {
                    Ok(()) => write_response(&mut output, &json!({ "ok": true }))?,
                    Err(e) => write_response(&mut output, &json!({ "ok": false, "error": e.to_string() }))?,
                }
            }
            "quit" => return Ok(()),
            other => write_response(&mut output, &json!({ "ok": false, "error": format!("unknown op '{other}'") }))?,
        }
    }
}

fn parse_va(req: &Value) -> Option<Va> {
    Va::parse(req["va"].as_str()?).ok()
}

fn write_response(output: &mut impl Write, v: &Value) -> std::io::Result<()> {
    let mut line = serde_json::to_string(v).unwrap_or_else(|_| "{\"ok\":false,\"error\":\"serialize\"}".to_string());
    line.push('\n');
    output.write_all(line.as_bytes())?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Snapshot;
    use std::io::Cursor;

    #[test]
    fn serve_stdio_answers_label_contains_and_read_over_a_snapshot() {
        let snap = Snapshot::builder().region(Va(0x1000), vec![1u8, 2, 3, 4]).label("test-remote").build();

        let requests = "{\"op\":\"label\"}\n\
                         {\"op\":\"contains\",\"va\":\"0x1000\"}\n\
                         {\"op\":\"contains\",\"va\":\"0x9999\"}\n\
                         {\"op\":\"read\",\"va\":\"0x1000\",\"len\":2}\n\
                         {\"op\":\"quit\"}\n";
        let mut output = Vec::new();
        serve_stdio(&snap, Cursor::new(requests.as_bytes()), &mut output).unwrap();

        let lines: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines[0]["label"], "test-remote");
        assert_eq!(lines[1]["contains"], true);
        assert_eq!(lines[2]["contains"], false);
        assert_eq!(lines[3]["hex"], "0102");
    }

    #[test]
    fn serve_stdio_reports_unmapped_reads_as_an_error() {
        let snap = Snapshot::builder().region(Va(0x1000), vec![1u8, 2]).build();
        let requests = "{\"op\":\"read\",\"va\":\"0x9999\",\"len\":1}\n{\"op\":\"quit\"}\n";
        let mut output = Vec::new();
        serve_stdio(&snap, Cursor::new(requests.as_bytes()), &mut output).unwrap();
        let first: Value = serde_json::from_str(String::from_utf8(output).unwrap().lines().next().unwrap()).unwrap();
        assert_eq!(first["ok"], false);
    }

    #[test]
    fn split_command_line_preserves_windows_backslashes() {
        let argv = split_command_line(r#"D:\tools\n0xis.exe remote-serve --pid 1234"#).unwrap();
        assert_eq!(argv, vec![r"D:\tools\n0xis.exe", "remote-serve", "--pid", "1234"]);
    }

    #[test]
    fn split_command_line_respects_double_quoted_segments() {
        let argv = split_command_line(r#"ssh "user@host" n0xis remote-serve --pid 1"#).unwrap();
        assert_eq!(argv, vec!["ssh", "user@host", "n0xis", "remote-serve", "--pid", "1"]);
    }

    #[test]
    fn split_command_line_rejects_unterminated_quote() {
        assert!(split_command_line(r#"ssh "user@host"#).is_err());
    }
}
