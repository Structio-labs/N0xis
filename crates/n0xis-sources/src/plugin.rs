//! Process-based plugin transport (`docs/COMMUNITY_ROADMAP.md`'s "Plugin
//! system"): vendor/game-specific logic runs as a separate executable
//! speaking JSON over stdio, instead of a Rust PR against this repo. Same
//! rationale as [`crate::remote`]'s `RemoteAgent` (no stable Rust ABI for a
//! `cdylib` plugin — a process boundary is safer and simpler), and built on
//! the same [`crate::linewire`] line-protocol plumbing, but two distinct
//! shapes for two distinct lifecycles:
//!
//! - [`PluginCall`] — single-shot: spawn, one JSON request in, one JSON
//!   response out, wait for exit. For analysis-result plugins (an artifact
//!   in, findings out, `n0xis-pipeline::PluginHost`) — one CLI/MCP call, one
//!   round trip, done.
//! - [`PluginSession`] — persistent: spawn once, hold the process open across
//!   many ops, explicit `quit`-then-kill teardown (mirrors `RemoteAgent`'s
//!   shape exactly). For `n0xis-hud`'s adapter dispatch, where `toggle_on`/
//!   `toggle_off` fire synchronously **on the UI thread** on every checkbox
//!   click or hotkey press — spawning a fresh OS process per click is a real
//!   latency risk for an interactive companion window, and a stateful adapter
//!   (e.g. one caching an already-scanned memory region) needs to keep that
//!   state across calls instead of rediscovering it every click.

use std::io::BufReader;
use std::process::{Child, ChildStdin, ChildStdout};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::linewire::{read_line_json, spawn_piped, write_line_json};

/// Spawn `argv`, send `request` as one JSON line, read one JSON line back,
/// then wait (up to `timeout`) for the process to exit. Writing and reading
/// happen on separate threads deliberately: for a large request (e.g. a full
/// `CfgArtifact`) written synchronously, a plugin that starts replying before
/// it has finished reading stdin could deadlock against a full OS pipe buffer
/// on either side — the classic hazard `std::process::Command`'s own docs
/// warn about. A crashing or wedged plugin degrades to an `Err` here, never a
/// panic — callers (`PluginHost`) turn that into "no findings," not a failure
/// of the underlying analysis (fail-open-but-visible).
pub fn call_once(argv: &[String], request: &Value, timeout: Duration) -> Result<Value, String> {
    let mut child = spawn_piped(argv)?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let req = request.clone();
    let writer = std::thread::spawn(move || {
        let _ = write_line_json(&mut stdin, &req);
        // `stdin` drops here, sending EOF — a well-behaved plugin reads until
        // EOF before replying.
    });

    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let response = read_line_json(&mut stdout);
    let _ = writer.join();

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("plugin '{}' timed out after {timeout:?}", argv.join(" ")));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    response
}

struct SessionIo {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

/// A persistent plugin process, held open across many ops. See the module
/// doc for why this exists alongside [`call_once`] rather than instead of it.
pub struct PluginSession {
    child: Child,
    io: Mutex<SessionIo>,
    label: String,
}

impl PluginSession {
    /// Spawn `argv` and hold it open. Deliberately does **not** perform an
    /// initial handshake round-trip (unlike `RemoteAgent::connect`'s `label`
    /// probe) — a binding only pays for a live plugin process once a real op
    /// is actually needed, not at config-load time.
    pub fn spawn(argv: &[String]) -> Result<Self, String> {
        let mut child = spawn_piped(argv)?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let label = argv.first().cloned().unwrap_or_else(|| "plugin".to_string());
        Ok(PluginSession { child, io: Mutex::new(SessionIo { stdin, stdout }), label })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    /// One request/response round trip. Strictly synchronous — one in flight
    /// at a time (mirrors `RemoteAgent::roundtrip`'s exact shape).
    pub fn call(&self, request: &Value) -> Result<Value, String> {
        let mut io = self.io.lock().unwrap_or_else(|e| e.into_inner());
        write_line_json(&mut io.stdin, request)?;
        read_line_json(&mut io.stdout)
    }
}

impl Drop for PluginSession {
    fn drop(&mut self) {
        if let Ok(mut io) = self.io.lock() {
            let _ = write_line_json(&mut io.stdin, &json!({ "op": "quit" }));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These exercise real process spawning (a plugin is, by definition, a
    // separate executable) — unlike `remote.rs`'s protocol tests, which stay
    // OS-free by calling `serve_stdio` directly against a `Cursor`. There is
    // no equivalent in-process server half here to test against, since a
    // plugin has no "server API" beyond the wire protocol itself; a real
    // child process is the thing under test.

    fn python_or_skip() -> Option<&'static str> {
        ["python3", "python"]
            .into_iter()
            .find(|candidate| std::process::Command::new(candidate).arg("--version").output().is_ok())
    }

    #[test]
    fn call_once_round_trips_through_a_real_child_process() {
        let Some(py) = python_or_skip() else {
            eprintln!("skipping: no python on PATH");
            return;
        };
        // A trivial echo-style plugin: read one JSON line, write it back with
        // an extra field, exit.
        let script = "import sys,json; req=json.loads(sys.stdin.readline()); \
                       print(json.dumps({'ok': True, 'echo': req}))";
        let argv = vec![py.to_string(), "-c".to_string(), script.to_string()];
        let resp = call_once(&argv, &json!({"op":"ping","n":42}), Duration::from_secs(5)).unwrap();
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["echo"]["n"], 42);
    }

    #[test]
    fn call_once_reports_a_nonexistent_binary_as_an_error_not_a_panic() {
        let argv = vec!["n0xis-this-binary-does-not-exist".to_string()];
        assert!(call_once(&argv, &json!({}), Duration::from_secs(1)).is_err());
    }

    #[test]
    fn plugin_session_supports_multiple_ops_over_one_process() {
        let Some(py) = python_or_skip() else {
            eprintln!("skipping: no python on PATH");
            return;
        };
        // `concat!` of one-line-per-line literals, NOT a `\`-continued string:
        // a backslash-newline in a Rust literal eats the newline *and all
        // leading whitespace* on the next line, so the previous form handed
        // python a `for` loop whose body had no indentation and died with
        // `IndentationError`. It went unnoticed because the test skips when no
        // python is on PATH, which is the norm on Windows and never true on a
        // Linux dev box. Indentation is load-bearing here — keep it literal.
        let script = concat!(
            "import sys,json\n",
            "for line in sys.stdin:\n",
            "    req = json.loads(line)\n",
            "    if req.get('op') == 'quit':\n",
            "        break\n",
            "    print(json.dumps({'ok': True, 'saw': req.get('op')}))\n",
            "    sys.stdout.flush()\n",
        );
        let argv = vec![py.to_string(), "-c".to_string(), script.to_string()];
        let session = PluginSession::spawn(&argv).unwrap();
        let r1 = session.call(&json!({"op":"on_launch"})).unwrap();
        assert_eq!(r1["saw"], "on_launch");
        let r2 = session.call(&json!({"op":"toggle_on"})).unwrap();
        assert_eq!(r2["saw"], "toggle_on");
        // Drop sends "quit" and kills/waits — no explicit assertion needed
        // beyond "this doesn't hang or panic," which the test harness itself
        // enforces via its own timeout.
    }
}
