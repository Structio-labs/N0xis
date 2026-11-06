// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! One stdio session over `n0xis-mcp`'s parent, with the engine dying under it.
//!
//! Against the real worker where the death can be asked for by a real query, and against
//! `examples/planted_worker.rs` where the death must fall at a chosen moment. Whether a
//! process is still there is read from its inherited standard error: its pipe ends only
//! when the last process holding it has gone, which needs no process list and reads the
//! same under Wine. Each mutation in `scripts/calibrate_memory.py` fails one of these.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use n0xis_mcp::supervisor::{CODE_ENGINE_CRASHED, CODE_OUT_OF_MEMORY};
use serde_json::{Value, json};

#[path = "../../n0xis-cli/tests/support/mod.rs"]
mod support;

const WAIT: Duration = Duration::from_secs(60);
/// The binary itself: large, and with `--min 1` its rows alone are far past [`CEILING`].
const BIG: &str = env!("CARGO_BIN_EXE_n0xis-mcp");
const CEILING: &str = "64M";

fn scratch(tag: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("session-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("a project");
    dir
}

/// What `cargo test` built beside the binary under test.
fn planted_worker() -> PathBuf {
    let exe = Path::new(BIG);
    let built = exe.parent().expect("a directory").join("examples").join(format!("planted_worker{}", std::env::consts::EXE_SUFFIX));
    assert!(built.exists(), "{}: `cargo test` builds examples", built.display());
    built
}

struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<Vec<u8>>,
    stderr: Receiver<String>,
    dir: PathBuf,
    next_id: u64,
}

impl Session {
    fn start(tag: &str, configure: impl FnOnce(&mut Command)) -> Session {
        let dir = scratch(tag);
        let mut command = support::isolated(Command::new(BIG));
        command.current_dir(&dir).env_remove("N0X_MEMORY_MAX").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        configure(&mut command);
        let mut child = command.spawn().expect("spawn n0xis-mcp");
        let stdin = child.stdin.take();
        let mut out = BufReader::new(child.stdout.take().expect("stdout"));
        let mut err = child.stderr.take().expect("stderr");
        let (to_lines, lines) = channel();
        std::thread::spawn(move || {
            let mut line = Vec::new();
            while matches!(out.read_until(b'\n', &mut line), Ok(n) if n > 0) {
                // Long ones are for one test, and are not what it reads.
                if line.len() > 1 << 20 {
                    line.truncate(1 << 10);
                }
                if to_lines.send(std::mem::take(&mut line)).is_err() {
                    return;
                }
            }
        });
        let (to_stderr, stderr) = channel();
        std::thread::spawn(move || {
            let mut text = Vec::new();
            let _ = err.read_to_end(&mut text);
            let _ = to_stderr.send(String::from_utf8_lossy(&text).into_owned());
        });
        Session { child, stdin, lines, stderr, dir, next_id: 100 }
    }

    /// The real worker under a low ceiling, past the opening of the session.
    fn real(tag: &str) -> Session {
        let mut session = Session::start(tag, |c| {
            c.env("N0X_MEMORY_MAX", CEILING);
        });
        session.open();
        session
    }

    /// The planted worker in `mode`, past the opening of the session.
    fn planted(tag: &str, mode: &str) -> Session {
        let mut session = Session::planted_unopened(tag, mode);
        session.open();
        session
    }

    fn planted_unopened(tag: &str, mode: &str) -> Session {
        let log = scratch(&format!("{tag}-log")).join("worker.log");
        Session::start(tag, |c| {
            c.env("N0X_MCP_TEST_WORKER", planted_worker()).env("N0X_PLANTED", mode).env("N0X_PLANTED_LOG", &log);
        })
    }

    fn open(&mut self) {
        self.send(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": { "name": "test", "version": "0" } } }));
        let answer = self.next_json();
        assert_eq!(answer["id"], 1, "{answer}");
        assert!(answer.get("result").is_some(), "{answer}");
        self.send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
    }

    fn send(&mut self, message: Value) {
        let stdin = self.stdin.as_mut().expect("still open");
        writeln!(stdin, "{message}").expect("write");
        stdin.flush().expect("flush");
    }

    fn call(&mut self, tool: &str, arguments: Value) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": tool, "arguments": arguments } }));
        id
    }

    fn next_line(&self) -> Vec<u8> {
        self.lines.recv_timeout(WAIT).unwrap_or_else(|e| panic!("a line from the parent: {e}; stderr so far is not read"))
    }

    fn next_json(&self) -> Value {
        let line = self.next_line();
        serde_json::from_slice(&line).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&line)))
    }

    fn the_log(&self, tag: &str) -> String {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("session-{}-{tag}-log", std::process::id()));
        std::fs::read_to_string(dir.join("worker.log")).expect("the log")
    }

    /// Close the client's side, and read how the parent went. Its standard error ends only
    /// when no process holding it is left, so this answering says no orphan either.
    fn close_and_read_stderr(mut self, bound: Duration) -> (Option<i32>, String) {
        self.stdin = None;
        let text = self.stderr.recv_timeout(bound).unwrap_or_else(|_| panic!("a process still holds standard error after {bound:?}"));
        (self.child.wait().ok().and_then(|s| s.code()), text)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn heavy() -> Value {
    json!({ "file": BIG, "limit": 0, "min": 1 })
}

/// A query with an answer known before it is asked: text planted in a module of this
/// test's. Its id, and the text with the offset it is planted at.
fn read_planted_bytes(session: &mut Session) -> (u64, (String, String)) {
    const TEXT: &[u8] = b"n0xis planted text";
    // A memory, and one data segment at its address 0.
    let mut module = b"\0asm\x01\0\0\0\x05\x03\x01\0\x01\x0b".to_vec();
    module.push(TEXT.len() as u8 + 6);
    module.extend_from_slice(&[1, 0, 0x41, 0, 0x0b, TEXT.len() as u8]);
    let at = module.len();
    module.extend_from_slice(TEXT);
    let file = session.dir.join("planted.wasm");
    std::fs::write(&file, module).expect("write");
    let id = session.call("strings", json!({ "file": file }));
    (id, (String::from_utf8_lossy(TEXT).into_owned(), format!("{at:#x}")))
}

fn error_of(answer: &Value, id: u64) -> (i64, String, String) {
    assert_eq!(answer["id"], id, "{answer}");
    let error = &answer["error"];
    assert!(answer.get("result").is_none(), "{answer}");
    (
        error["code"].as_i64().expect("a code"),
        error["message"].as_str().expect("a message").to_string(),
        error["data"]["code"].as_str().expect("a name").to_string(),
    )
}

/// The text of a tool's answer, read as the envelope it is.
fn envelope_of(answer: &Value, id: u64) -> Value {
    assert_eq!(answer["id"], id, "{answer}");
    let text = answer["result"]["content"][0]["text"].as_str().unwrap_or_else(|| panic!("a tool answer: {answer}"));
    serde_json::from_str(text).expect("the envelope")
}

#[test]
fn a_query_past_the_ceiling_gets_its_error_and_the_next_answers() {
    let mut session = Session::real("past");
    let (id, known) = read_planted_bytes(&mut session);
    let before = envelope_of(&session.next_json(), id);
    assert_eq!(before["data"]["strings"][0]["text"], known.0.as_str(), "{before}");

    let id = session.call("strings", heavy());
    let (code, message, name) = error_of(&session.next_json(), id);
    assert_eq!(code, CODE_OUT_OF_MEMORY, "{message}");
    assert_eq!(name, "out-of-memory");
    assert!(message.contains("N0X_MEMORY_MAX"), "it says what to do: {message}");
    assert!(message.contains("no request is retried") || message.contains("No request is retried"), "{message}");

    let (id, known) = read_planted_bytes(&mut session);
    let after = envelope_of(&session.next_json(), id);
    assert_eq!(after["ok"], true, "{after}");
    assert_eq!(after["data"]["strings"][0]["text"], known.0.as_str(), "{after}");
    assert_eq!(after["data"]["strings"][0]["address"], known.1.as_str(), "{after}");

    let (status, stderr) = session.close_and_read_stderr(WAIT);
    assert!(stderr.contains("its ceiling of 64 MiB"), "the worker says which ceiling: {stderr}");
    assert_eq!(status, Some(0), "the client closing is a normal end: {stderr}");
}

/// What the error says holds: `attach`'s default is on disk.
#[test]
fn the_default_target_stays_across_a_restart() {
    let mut session = Session::real("attach");
    // A real image is what `attach` takes: this crate's fixtures are in the CLI's.
    let image = Path::new(env!("CARGO_MANIFEST_DIR")).join("../n0xis-cli/tests/fixtures/wasm/indexed.wasm");
    let id = session.call("attach", json!({ "file": image }));
    assert_eq!(envelope_of(&session.next_json(), id)["ok"], true);
    let id = session.call("strings", json!({}));
    let before = envelope_of(&session.next_json(), id);
    assert_eq!(before["ok"], true, "{before}");

    let id = session.call("strings", heavy());
    assert_eq!(error_of(&session.next_json(), id).0, CODE_OUT_OF_MEMORY);

    let id = session.call("strings", json!({}));
    let after = envelope_of(&session.next_json(), id);
    assert_eq!(after["data"], before["data"], "the same target, with nothing named");
}

#[test]
fn every_request_in_flight_gets_the_error() {
    let mut session = Session::real("flight");
    let (a, b) = (session.call("strings", heavy()), session.call("strings", heavy()));
    let (first, second) = (session.next_json(), session.next_json());
    let mut ids = vec![first["id"].as_u64().expect("an id"), second["id"].as_u64().expect("an id")];
    ids.sort_unstable();
    assert_eq!(ids, [a, b], "{first} {second}");
    assert_eq!(first["error"]["code"], CODE_OUT_OF_MEMORY, "{first}");
    assert_eq!(second["error"]["code"], CODE_OUT_OF_MEMORY, "{second}");
}

/// The first is still being worked on when the second kills it, by construction.
#[test]
fn a_request_in_flight_when_another_dies_gets_the_error_too() {
    let mut session = Session::planted("two", "second-call-dies");
    let (a, b) = (session.call("x", json!({})), session.call("x", json!({})));
    let (first, second) = (session.next_json(), session.next_json());
    assert_eq!((first["id"].as_u64(), second["id"].as_u64()), (Some(a), Some(b)), "in the order they came");
    assert_eq!(error_of(&first, a).0, CODE_ENGINE_CRASHED);
    assert_eq!(error_of(&second, b).0, CODE_ENGINE_CRASHED);
}

#[test]
fn the_exit_code_tells_the_ceiling_from_a_crash() {
    for (mode, code, name) in [
        ("past-the-ceiling", CODE_OUT_OF_MEMORY, "out-of-memory"),
        ("abort", CODE_ENGINE_CRASHED, "engine-crashed"),
        ("exit-zero", CODE_ENGINE_CRASHED, "engine-crashed"),
        ("stack-overflow", CODE_ENGINE_CRASHED, "engine-crashed"),
    ] {
        let mut session = Session::planted(mode, mode);
        let id = session.call("x", json!({}));
        let (got, message, got_name) = error_of(&session.next_json(), id);
        assert_eq!((got, got_name.as_str()), (code, name), "{mode}: {message}");
        assert_eq!(message.contains("needs more memory"), code == CODE_OUT_OF_MEMORY, "{mode}: {message}");
        assert_eq!(message.contains("crashed"), code == CODE_ENGINE_CRASHED, "{mode}: {message}");
    }
}

/// The client's opening is given to the new worker, the response to it goes nowhere, and
/// what died is not asked again.
#[test]
fn a_new_worker_gets_the_opening_and_not_the_request() {
    let mut session = Session::planted("replay", "every-second-call-dies");
    session.call("x", json!({}));
    assert_eq!(session.next_json()["result"]["worker"], 0);
    let dies = session.call("dies", json!({}));
    assert_eq!(error_of(&session.next_json(), dies).0, CODE_ENGINE_CRASHED);
    let id = session.call("x", json!({}));
    let answer = session.next_json();
    assert_eq!(answer["id"], id, "no response to the second initialize came first: {answer}");
    assert_eq!(answer["result"]["worker"], 1, "{answer}");

    let log = session.the_log("replay");
    let second: Vec<&str> = log.lines().filter_map(|l| l.strip_prefix("1 ")).collect();
    assert_eq!(second.len(), 4, "{second:?}");
    assert_eq!(second[0], "started");
    assert!(second[1].contains("\"method\":\"initialize\"") && second[1].contains("\"id\":1"), "the client's own, whole: {}", second[1]);
    assert!(second[2].contains("notifications/initialized"), "{}", second[2]);
    assert!(second[3].contains(&format!("\"id\":{id}")), "{}", second[3]);
    assert_eq!(log.matches("\"name\":\"dies\"").count(), 1, "asked once and never again: {log}");
}

#[test]
fn a_worker_dead_mid_line_leaves_one_line_that_does_not_parse() {
    let mut session = Session::planted("midline", "mid-line");
    let id = session.call("x", json!({}));
    let half = session.next_line();
    assert!(serde_json::from_slice::<Value>(&half).is_err(), "{}", String::from_utf8_lossy(&half));
    assert!(half.ends_with(b"half of it\n"), "ended, and nothing added: {}", String::from_utf8_lossy(&half));
    let (code, ..) = error_of(&session.next_json(), id);
    assert_eq!(code, CODE_ENGINE_CRASHED, "a half answer is no answer");
}

/// A process the worker started keeps the pipe open. Its death is read from the worker.
#[test]
fn a_worker_dead_with_its_output_held_open_is_still_noticed() {
    let mut session = Session::planted("held", "leaves-its-output-held");
    let id = session.call("x", json!({}));
    let start = Instant::now();
    assert_eq!(error_of(&session.next_json(), id).0, CODE_ENGINE_CRASHED);
    assert!(start.elapsed() < Duration::from_secs(20), "before the holder went: {:?}", start.elapsed());
}

#[test]
fn a_cancelled_request_is_owed_nothing() {
    let mut session = Session::planted("cancel", "second-call-dies");
    let cancelled = session.call("x", json!({}));
    session.send(json!({ "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": cancelled } }));
    let id = session.call("x", json!({}));
    assert_eq!(error_of(&session.next_json(), id).0, CODE_ENGINE_CRASHED, "the first error is the live one's");
}

#[test]
fn a_worker_that_dies_at_once_ends_the_parent_with_its_reason() {
    let session = Session::planted_unopened("loop", "die-at-start");
    let (status, stderr) = session.close_when_it_ends();
    assert_eq!(status, Some(1), "{stderr}");
    assert!(stderr.contains("stopped: the engine died"), "{stderr}");
    assert_eq!(stderr.matches("starting it again").count(), 6, "a few tries and no more: {stderr}");
}

#[test]
fn a_worker_that_dies_on_the_replayed_initialize_ends_the_parent() {
    let mut session = Session::planted("noinit", "no-second-initialize");
    let ok = session.call("x", json!({}));
    assert_eq!(session.next_json()["id"], ok);
    let dies = session.call("x", json!({}));
    assert_eq!(error_of(&session.next_json(), dies).0, CODE_ENGINE_CRASHED);
    let (status, stderr) = session.close_when_it_ends();
    assert_eq!(status, Some(1), "{stderr}");
    assert!(stderr.contains("did not answer the client's initialize"), "{stderr}");
}

impl Session {
    /// A parent that ends by itself, with its client still there.
    fn close_when_it_ends(mut self) -> (Option<i32>, String) {
        let text = self.stderr.recv_timeout(WAIT).expect("the parent ended by itself");
        (self.child.wait().ok().and_then(|s| s.code()), text)
    }
}

/// Answers between the deaths: this is a query that dies now and then, and not a loop.
#[test]
fn deaths_with_answers_between_them_go_on_for_ever() {
    let mut session = Session::planted("noloop", "every-second-call-dies");
    for round in 0..9 {
        let ok = session.call("x", json!({}));
        let answer = session.next_json();
        assert_eq!(answer["id"], ok, "round {round}: {answer}");
        assert!(answer.get("result").is_some(), "round {round}: {answer}");
        let dies = session.call("x", json!({}));
        assert_eq!(error_of(&session.next_json(), dies).0, CODE_ENGINE_CRASHED, "round {round}");
    }
    assert!(session.child.try_wait().expect("wait").is_none(), "still there");
}

#[test]
fn deaths_with_no_answer_between_them_end_the_parent() {
    let mut session = Session::planted("loopcalls", "abort");
    let mut errors = 0;
    loop {
        session.next_id += 1;
        let id = session.next_id;
        let request = json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {} });
        // A parent that has stopped closes this pipe.
        if writeln!(session.stdin.as_mut().expect("still open"), "{request}").and_then(|()| session.stdin.as_mut().expect("still open").flush()).is_err() {
            break;
        }
        match session.lines.recv_timeout(WAIT) {
            Ok(line) => {
                let answer: Value = serde_json::from_slice(&line).expect("JSON");
                assert_eq!(error_of(&answer, id).0, CODE_ENGINE_CRASHED);
                errors += 1;
            }
            Err(_) => break,
        }
        assert!(errors < 20, "it should have stopped by now");
    }
    assert_eq!(errors, 6, "each death answered, and then no more");
    let (status, stderr) = session.close_when_it_ends();
    assert_eq!(status, Some(1), "{stderr}");
    assert!(stderr.contains("stopped: the engine died 6 times"), "{stderr}");
}

#[test]
fn the_client_closing_ends_the_real_worker_with_no_orphan() {
    let session = Session::real("close");
    let (status, stderr) = session.close_and_read_stderr(WAIT);
    assert_eq!(status, Some(0), "{stderr}");
}

/// Nothing else is going to end a worker that stays.
#[test]
fn a_worker_that_stays_after_the_client_closes_is_killed() {
    let session = Session::planted("stays", "stays-after-end-of-file");
    let start = Instant::now();
    let (_, stderr) = session.close_and_read_stderr(Duration::from_secs(40));
    assert!(start.elapsed() >= Duration::from_secs(8), "it was given its time: {:?}; {stderr}", start.elapsed());
}

/// The worker sees end of file on its own input when the parent goes, however it goes.
#[test]
fn the_parent_killed_ends_the_real_worker_with_no_orphan() {
    let mut session = Session::real("killed");
    let (id, _) = read_planted_bytes(&mut session);
    assert_eq!(envelope_of(&session.next_json(), id)["ok"], true);
    session.child.kill().expect("kill the parent");
    let _ = session.child.wait();
    session.stderr.recv_timeout(WAIT).expect("no process still holds standard error");
}

/// Not only an idle one: a query that would run for minutes does not keep it here. Dropping
/// the runtime on the way out would wait for that query.
#[test]
fn the_parent_killed_ends_a_busy_real_worker_with_no_orphan() {
    let mut session = Session::start("busy", |c| {
        c.env("N0X_MEMORY_MAX", "2G");
    });
    session.open();
    session.call("capability_run", json!({ "name": "function.summary", "args": { "file": BIG, "limit": 0 } }));
    // Long enough to be inside it, and it says nothing until it ends.
    std::thread::sleep(Duration::from_secs(2));
    assert!(session.lines.try_recv().is_err(), "still working on it");
    session.child.kill().expect("kill the parent");
    let _ = session.child.wait();
    // Five seconds for `rmcp`'s drain, and a margin.
    session.stderr.recv_timeout(Duration::from_secs(30)).expect("no process still holds standard error");
}

/// A response near the ceiling must not be doubled by a copy here.
#[cfg(target_os = "linux")]
#[test]
fn the_parent_holds_no_whole_response() {
    let mut session = Session::planted("huge", "huge");
    let id = session.call("x", json!({}));
    let line = session.next_line();
    assert!(line.starts_with(format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},").as_bytes()));
    let status = std::fs::read_to_string(format!("/proc/{}/status", session.child.id())).expect("its status");
    let peak: u64 = status.lines().find_map(|l| l.strip_prefix("VmHWM:")).and_then(|v| v.trim().trim_end_matches(" kB").trim().parse().ok()).expect("its peak");
    assert!(peak < 64 << 10, "256 MiB went through, and the parent's peak was {peak} kB");
}
