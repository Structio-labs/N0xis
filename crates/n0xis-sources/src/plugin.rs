// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Process-based plugin transport (`docs/COMMUNITY_ROADMAP.md`'s "Plugin
//! system"): vendor/target-specific logic runs as a separate executable
//! speaking JSON over stdio, instead of a Rust PR against this repo. Same
//! rationale as [`crate::remote`]'s `RemoteAgent` (no stable Rust ABI for a
//! `cdylib` plugin — a process boundary is safer and simpler), and built on
//! the same [`crate::linewire`] line-protocol plumbing.
//!
//! One shape: [`call_once`] — spawn, one JSON request in, one JSON reply out,
//! wait for exit, all inside one deadline. For analysis-result plugins (an
//! artifact in, findings out) — one CLI/MCP call, one round trip, done.
//!
//! **The reply is data, not an n0xis envelope.** Whatever JSON value the
//! plugin writes is its findings, and every door hands it on inside a
//! successful answer: a reply of `{"ok":false,"error":…}` is a plugin's
//! findings that happen to have those keys, not a failure
//! (`docs/COMMUNITY_ROADMAP.md`'s plugin section defines the reply as
//! "additional findings as JSON on stdout"). A plugin with nothing to report
//! replies with an empty value of its own shape (`{}`, `[]`). A plugin
//! reports a failure by exiting without a reply line, a non-zero status
//! saying so — the host answers that with [`PluginError::NoReply`] and the
//! exit status — and what it writes to its stderr reaches the host's
//! stderr, not the answer. The one JSON value refused as a reply is `null`
//! ([`PluginError::NullReply`]): it carries nothing, and handed on it became
//! `{"ok":true,"data":null}`, a success with nothing in it.
//!
//! A persistent session (one process held open across many requests) sat
//! beside this as `PluginSession`. It had no caller in this workspace or in
//! the GUI, no deadline and no bound on its reply — a plugin that did not
//! answer left `call` blocked for as long as it liked — so it was removed
//! rather than carried; a caller that needs one should get it with the same
//! deadline and bound as [`call_once`].

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStderr, ChildStdout, ExitStatus};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::linewire::{parse_line_json, spawn_piped};

/// How long one [`call_once`] exchange may take, spawn to exit, before the
/// plugin is treated as wedged and killed. The one value every front door
/// (the registry's `plugin.<name>`, MCP's `plugin_run`, the pipeline's
/// `run_plugins_for`) passes; each used to carry its own copy of `10 s`.
pub const DEADLINE: Duration = Duration::from_secs(10);

/// The largest reply [`call_once`] accepts: one line, its newline included.
///
/// The bound is on the text because the text is what a plugin controls, but
/// the parsed form is what costs memory, and it costs far more than the text:
/// a `serde_json::Value` is 32 bytes, and an object is a `BTreeMap` (this
/// workspace does not enable serde_json's `preserve_order`), so every object,
/// even one with a single key, allocates a whole B-tree leaf node of about
/// 0.6 KB. Measured on 2026-10-20 with serde_json 1.0.150 through this
/// function, as the growth of the host's peak resident set (`VmHWM`) over the
/// reply's length, one shape per host process, on lines of just under the
/// bound — at 16 MiB first, then again at this 4 MiB value:
///
/// | one element of `[…,…]`                        | 16 MiB  | 4 MiB  |
/// |-----------------------------------------------|---------|--------|
/// | `0`                                           | 17.0x   | 17.0x  |
/// | `{}`                                          | 11.7x   | 12.0x  |
/// | `[0]`                                         | 45.0x   | 45.0x  |
/// | `{"":0}`                                      | 97.0x   | 97.4x  |
/// | `{"":{"":0}}`                                 | 110.4x  | 110.6x |
/// | eight nested single-key objects               | 123.8x  | 123.9x |
/// | 120 nested (serde_json's depth limit is 128)  | 128.6x  | 128.6x |
///
/// The ratio does not depend on the length, so the worst case a plugin can
/// force at this bound is about **0.54 GB** in the host for one reply
/// (measured: 539 484 160 bytes for a 4 194 136-byte line); at the 16 MiB
/// this bound started at it was about 2.0 GB, which is why it was lowered.
/// And it is per reply: the pipeline's `run_plugins_for` holds every
/// plugin's reply at once (it collects them into one `Vec`), so the cost adds
/// up over the plugins registered for a kind — read from the code, not
/// measured. The bound keeps a plugin from growing the host
/// without limit; it does not make a hostile reply cheap. A reply over the
/// bound is refused with [`PluginError::ReplyTooLarge`], never truncated.
pub const MAX_REPLY_BYTES: usize = 4 << 20;

/// Why a [`call_once`] exchange produced no answer. Every variant names the
/// plugin's command, so an error read in a list of findings says whose it is.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// The command is empty or the process could not be created.
    #[error("plugin '{command}' could not be started: {reason}")]
    Spawn { command: String, reason: String },
    /// The deadline passed before a reply arrived. The child has been killed
    /// and reaped by the time this is returned.
    #[error("plugin '{command}' timed out after {deadline:?} {pending}")]
    TimedOut { command: String, deadline: Duration, pending: Pending },
    /// The plugin closed its output without writing a line.
    #[error("plugin '{command}' {exit} without a reply")]
    NoReply { command: String, exit: PluginExit },
    /// The plugin wrote a line that is not one JSON value.
    #[error("plugin '{command}' replied with something that is not JSON: {reason}")]
    BadReply { command: String, reason: String },
    /// The plugin wrote `null`: valid JSON and no findings. Handed on, it was
    /// `{"ok":true,"data":null}` — a success with nothing in it, which the
    /// caller cannot tell from an answer.
    #[error("plugin '{command}' replied null, which is no answer")]
    NullReply { command: String },
    /// The reply line ran past [`MAX_REPLY_BYTES`]; reading stopped there.
    #[error("plugin '{command}' replied with more than {limit} bytes on one line")]
    ReplyTooLarge { command: String, limit: usize },
    /// Talking to the process failed below the protocol (a read error on its
    /// output, the request failing to serialize).
    #[error("plugin '{command}': {reason}")]
    Io { command: String, reason: String },
}

/// What a timed-out exchange was still waiting on when the deadline passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pending {
    /// The request had not been fully written: the plugin was not reading
    /// its input.
    WritingRequest,
    /// The request was delivered (or refused by the plugin closing its
    /// input) and no reply line had come back.
    Reply,
}

impl std::fmt::Display for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Pending::WritingRequest => "while its request was still being written (it was not reading its input)",
            Pending::Reply => "waiting for its reply",
        })
    }
}

/// How the plugin process ended, as far as the host saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginExit {
    /// It exited on its own with this status.
    Exited(ExitStatus),
    /// It was still running at the deadline and was killed.
    KilledAtDeadline,
    /// Its state could not be read; it was killed, and this is why.
    Unobserved(String),
}

impl std::fmt::Display for PluginExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginExit::Exited(status) => write!(f, "exited ({status})"),
            PluginExit::KilledAtDeadline => f.write_str("closed its output, did not exit by the deadline and was killed,"),
            PluginExit::Unobserved(why) => write!(f, "could not be observed ({why}) and was killed,"),
        }
    }
}

/// What the reader thread brought back from the plugin's stdout.
enum ReadOutcome {
    Line(Vec<u8>),
    Eof,
    TooLarge,
    Failed(String),
}

/// Spawn `argv`, send `request` as one JSON line, read one JSON line back, and
/// wait for the process to exit — all of it inside one `deadline` that starts
/// at spawn. Production callers pass [`DEADLINE`]; tests pass a short one.
///
/// The deadline used to start only once a reply had been read, so a plugin
/// that read its request and then slept hung the host indefinitely (measured:
/// still hanging at 30 s through `capability run`), and so did one that never
/// read a request larger than the pipe buffer. Now:
///
/// - the reply is waited for with the time that is left, and on expiry the
///   child is killed, reaped, and [`PluginError::TimedOut`] is returned;
/// - writing and reading happen on their own threads, which this function
///   never joins: a writer blocked on a plugin that does not read its stdin,
///   or a reader blocked on one that never writes, cannot hold the caller.
///   Killing the child closes its ends of both pipes, which ends both threads;
/// - a reply followed by a process that does not exit is still the answer:
///   the host waits for the exit until the deadline, then kills and reaps the
///   child and returns the reply;
/// - the reply line is bounded by [`MAX_REPLY_BYTES`];
/// - the plugin's stderr is a pipe of its own, copied to the host's stderr by
///   a thread this function never joins ([`forward_stderr`]). It used to be
///   the host's stderr itself, inherited, and a grandchild inherits it in
///   turn: a caller that captures the host's stderr then got control back
///   only when the grandchild exited, however early the host did (measured
///   2026-10-20: the CLI answered at 10 s, `subprocess.run(capture_output=
///   True)` returned at 40 s). Now a grandchild holds the plugin's pipe,
///   whose read end is the host's, and the host's stderr is held by the host
///   alone.
///
/// A crashing or wedged plugin degrades to an `Err` here, never a panic — the
/// caller turns that into "no findings," not a failure of the underlying
/// analysis (fail-open-but-visible).
///
/// Not covered: a plugin whose work runs in a grandchild that holds the pipes.
/// Only the direct child is killed. The call still returns by the deadline,
/// and the host's stderr is no longer held (see above), but the grandchild
/// lives on, and so do the threads talking to the pipes it holds — the
/// stderr copier among them — until it closes them. Measured 2026-10-20 through this function with a 2 000 ms deadline
/// (`/bin/sh` is bash 5.3 here): `sh -c 'cat >/dev/null; sleep 17; true'`
/// timed out at 2 000 ms with `sleep 17` still running afterwards, and
/// `sh -c 'cat >/dev/null; echo "{}"; sleep 17; true'` returned its reply at
/// 2 000 ms, `sleep 17` again still running. Without the trailing `; true`
/// the shell execs `sleep` in its own place, `sleep` is the direct child, and
/// it is killed — an earlier version of this comment cited that form as the
/// grandchild case, and it is not one.
/// On Windows a virtual environment's `python.exe` is a launcher that starts
/// the real interpreter as its child, so an ordinary `python plugin.py` there
/// is expected to have this shape too (not run on Windows). Killing the whole
/// tree needs a process group on Unix and a Job Object on Windows. Not done,
/// on purpose for now, for two reasons: a plugin in its own process group no
/// longer receives the terminal's Ctrl-C with the host, so an interrupted
/// host would leave it running instead; and both need an OS crate (`libc`,
/// `windows-sys`) that this crate links only under the `live` feature, while
/// this module is compiled in every build. The shipped CLI and MCP binaries
/// do enable `live` on Windows, Linux and Android, but `n0xis-pipeline`'s and
/// `n0xis-project`'s default builds, and every other OS, do not — so a tree
/// kill would either make an OS crate unconditional here or answer
/// differently by feature. Listed as open in
/// `docs/COMMUNITY_ROADMAP.md`'s plugin section.
pub fn call_once(argv: &[String], request: &Value, deadline: Duration) -> Result<Value, PluginError> {
    let started = Instant::now();
    let command = argv.join(" ");
    let mut line = serde_json::to_vec(request)
        .map_err(|e| PluginError::Io { command: command.clone(), reason: format!("serialize the request: {e}") })?;
    line.push(b'\n');

    let mut child =
        spawn_piped(argv).map_err(|reason| PluginError::Spawn { command: command.clone(), reason })?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    forward_stderr(child.stderr.take().expect("piped stderr"));

    let (written_tx, written_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = stdin.write_all(&line).and_then(|_| stdin.flush());
        let _ = written_tx.send(());
        // `stdin` drops here, sending EOF — a well-behaved plugin reads until
        // EOF before replying.
    });
    let (reply_tx, reply_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = reply_tx.send(read_reply(stdout));
    });

    let outcome = match reply_rx.recv_timeout(left(started, deadline)) {
        Ok(outcome) => outcome,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Read the writer's state before the kill: killing the child breaks
            // the pipe, which ends a blocked write at once and would report a
            // plugin that never read its input as one that did.
            let pending = match written_rx.try_recv() {
                Ok(()) => Pending::Reply,
                Err(_) => Pending::WritingRequest,
            };
            kill_and_reap(&mut child);
            return Err(PluginError::TimedOut { command, deadline, pending });
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            kill_and_reap(&mut child);
            return Err(PluginError::Io { command, reason: "the reply reader stopped without a result".into() });
        }
    };

    match outcome {
        ReadOutcome::Line(bytes) => match parse_reply(&bytes) {
            // Treated as a reply that is not one, like `BadReply`: the
            // exchange is over and the plugin is not waited for.
            Ok(Value::Null) => {
                kill_and_reap(&mut child);
                Err(PluginError::NullReply { command })
            }
            Ok(reply) => {
                // The answer is in; what is left is letting the plugin finish
                // (it may still be flushing its own state) inside the deadline.
                let _ = wait_for_exit(&mut child, started, deadline);
                Ok(reply)
            }
            Err(reason) => {
                kill_and_reap(&mut child);
                Err(PluginError::BadReply { command, reason })
            }
        },
        ReadOutcome::Eof => {
            // Its output closed: it is most likely exiting, and the status is
            // the useful part of this error (a crash says so here).
            let exit = wait_for_exit(&mut child, started, deadline);
            Err(PluginError::NoReply { command, exit })
        }
        ReadOutcome::TooLarge => {
            kill_and_reap(&mut child);
            Err(PluginError::ReplyTooLarge { command, limit: MAX_REPLY_BYTES })
        }
        ReadOutcome::Failed(reason) => {
            kill_and_reap(&mut child);
            Err(PluginError::Io { command, reason: format!("read its reply: {reason}") })
        }
    }
}

/// Copy everything the plugin writes to its stderr onto the host's stderr,
/// from a thread nothing joins or waits for.
///
/// Why a thread and not an inherited handle: see [`call_once`] — whatever
/// holds the host's own stderr decides when a caller capturing it gets
/// control back, and an inherited handle passes to the plugin's children.
/// Why never joined: the pipe reaches end-of-file only once every process
/// holding its write end has closed it, a grandchild included, and waiting
/// for that is the hold this exists to remove. The thread ends at that
/// end-of-file, or with the host.
///
/// It keeps reading after the host's stderr refuses a write (closed, or a
/// GUI process without one) and drops what it read: a reader that stopped
/// would leave the plugin blocked on a full pipe, and so timed out. What it
/// does not promise: when the host exits right after the call — the CLI
/// does — bytes the plugin wrote just before it answered may not have been
/// copied yet, since nothing waits for this thread. Measured 2026-10-20
/// through the CLI's `capability run` on Linux, a plugin writing one line to
/// stderr, then its reply, then exiting: the line was in the host's stderr
/// in 200 of 200 runs. That is one machine and one load, not a promise.
fn forward_stderr(mut from: ChildStderr) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match from.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => {
                    let mut to = std::io::stderr().lock();
                    let _ = to.write_all(&buf[..n]).and_then(|_| to.flush());
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
    });
}

/// Time left of `deadline`, counted from `started`; zero once it has passed.
fn left(started: Instant, deadline: Duration) -> Duration {
    deadline.saturating_sub(started.elapsed())
}

/// The reply line as a JSON value, by the same rule as every other line this
/// crate reads ([`parse_line_json`]). The line was read as bytes so its length
/// could be bounded before it is held, which is why UTF-8 is checked here:
/// the old `read_line` refused a line that was not UTF-8 too.
fn parse_reply(bytes: &[u8]) -> Result<Value, String> {
    let line = std::str::from_utf8(bytes).map_err(|e| format!("the line is not UTF-8: {e}"))?;
    parse_line_json(line).map_err(|e| e.to_string())
}

/// Read one line of at most [`MAX_REPLY_BYTES`], newline included.
fn read_reply(stdout: ChildStdout) -> ReadOutcome {
    let mut bounded = BufReader::new(stdout).take(MAX_REPLY_BYTES as u64 + 1);
    let mut buf = Vec::new();
    match bounded.read_until(b'\n', &mut buf) {
        Err(e) => ReadOutcome::Failed(e.to_string()),
        Ok(0) => ReadOutcome::Eof,
        Ok(_) if buf.len() > MAX_REPLY_BYTES => ReadOutcome::TooLarge,
        Ok(_) => ReadOutcome::Line(buf),
    }
}

/// Wait for the child to exit until the deadline; past it, kill and reap it.
fn wait_for_exit(child: &mut Child, started: Instant, deadline: Duration) -> PluginExit {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return PluginExit::Exited(status),
            Ok(None) => {
                let rest = left(started, deadline);
                if rest.is_zero() {
                    kill_and_reap(child);
                    return PluginExit::KilledAtDeadline;
                }
                std::thread::sleep(rest.min(Duration::from_millis(10)));
            }
            Err(e) => {
                kill_and_reap(child);
                return PluginExit::Unobserved(e.to_string());
            }
        }
    }
}

/// Kill the child and collect its exit, so no zombie outlives the call. Both
/// steps are bounded: the kill is unconditional (SIGKILL / TerminateProcess),
/// and the wait returns once the process is gone. Errors are ignored: the
/// answer is already decided by the time this runs, and a child that exited
/// on its own in the meantime is the outcome the kill was for.
fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
}
