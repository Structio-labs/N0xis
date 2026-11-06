// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The small parent that keeps a client's session when the engine dies.
//!
//! The memory ceiling stops a run by ending its process, and a client's session
//! is that process's standard input and output: one query past the ceiling ended
//! the session, and everything the client had set up with it. So `n0xis-mcp` with
//! no arguments is this parent, and the server proper runs in a worker: the same
//! binary, started with [`WORKER_ARG`], with the ceiling set in it.
//!
//! This parent runs no analysis and holds no answer. A response can be near the
//! ceiling itself, and a copy here would double it, so a response passes through
//! by chunks ([`CHUNK`]) and only its top-level keys are read ([`LineScan`]), as
//! far as they settle what the line is. A client's requests are small, and are
//! parsed whole.
//!
//! When the worker exits, each request with no response yet gets a JSON-RPC error:
//! [`CODE_OUT_OF_MEMORY`] when the worker's exit says the ceiling stopped it
//! ([`EXIT_PAST_THE_CEILING`]), [`CODE_ENGINE_CRASHED`] for any other death, a stack
//! overflow on Windows included. Then a new worker gets the client's `initialize`
//! and `notifications/initialized` again, and the response to that is swallowed: the
//! client has had one. **A request is never retried here:** it would die again.
//!
//! A worker that dies in the middle of a response leaves half a line. This parent
//! ends the line and then answers, so **a client sees one line it cannot parse in
//! that case**, followed by the error for that request. No other framing keeps the
//! lines after it readable, and the half cannot be held back without holding the
//! whole.
//!
//! What the worker kept between requests is gone after a restart, and the error says
//! which ([`RESTART_LOSES`]). `tools.rs` keeps no state of its own: the default target
//! `attach` records is `.n0x/session.json` on disk, and stays. What goes is what the
//! engine caches in memory (the last image, the list of strings, the discovered
//! functions), which changes how long the next query takes and not what it answers.

use std::io::{self, BufRead, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// The hidden first argument that makes this binary the worker, as `__update-check`
/// makes the CLI its own background check.
pub const WORKER_ARG: &str = "__mcp-worker";

/// How a worker says its memory ceiling stopped it. Not 1 (an error returned from
/// `main`), 2 (what the CLI's `ok:false` exits with), 3 (`abort` in some Windows
/// runtimes) or 101 (a panic), and below what a shell uses for a signal.
pub const EXIT_PAST_THE_CEILING: i32 = 37;

/// The JSON-RPC error code of a request lost to the ceiling. Both are in the range
/// the specification keeps for a server's own errors.
pub const CODE_OUT_OF_MEMORY: i64 = -32001;
/// The JSON-RPC error code of a request lost to any other death of the engine.
pub const CODE_ENGINE_CRASHED: i64 = -32002;

/// What a restart costs a client, said in each error. See the module's last paragraph.
const RESTART_LOSES: &str = "The engine was started again and this session goes on. No request is retried. The target `attach` recorded is on disk and still holds; what the engine had cached in memory is gone, so the next query reads its image again.";

/// How much of a response this parent holds at once.
const CHUNK: usize = 64 << 10;
/// The longest `id` looked at. A client's id is its own and small; a response with a
/// longer one stays unmatched, and if the worker later dies that request is answered
/// a second time, by an error.
const MAX_ID_BYTES: usize = 4096;
/// More deaths than this in [`DEATH_WINDOW`], with no request answered among them, is
/// a loop: the engine cannot serve this client, and a client waiting on it should
/// hear so rather than wait.
const MOST_DEATHS: usize = 5;
const DEATH_WINDOW: Duration = Duration::from_secs(60);
/// How long a new worker may take to answer the `initialize` it is given again.
const REPLAY_DEADLINE: Duration = Duration::from_secs(30);
/// How long a worker may stay once the client has closed its input. Longer than the
/// five seconds `rmcp` gives handlers still running at end of file, which the worker
/// exits right after.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);
/// How long a worker that closed its output may take to exit, and how long its output
/// may stay open once it has: a process it started can hold the pipe open past it.
const EXIT_GRACE: Duration = Duration::from_secs(2);
/// How often the worker's exit is looked at when nothing else wakes this parent. The
/// usual death closes the output, which does wake it.
const POLL: Duration = Duration::from_millis(250);

/// Debug builds only, and only for the tests: the program to start as the worker,
/// which lets them plant a worker that dies in a chosen way.
#[cfg(debug_assertions)]
const PLANTED_WORKER: &str = "N0X_MCP_TEST_WORKER";

fn worker_program() -> io::Result<std::path::PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(planted) = std::env::var_os(PLANTED_WORKER) {
        return Ok(planted.into());
    }
    std::env::current_exe()
}

#[cfg(windows)]
fn no_console_window(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn no_console_window(_command: &mut Command) {}

/// What one complete line from the worker turned out to be.
#[derive(Debug, PartialEq)]
struct Finished {
    /// The id of the request this line answers, when it is a response.
    answers: Option<Value>,
    /// Whether that answer is a `result` rather than an `error`.
    succeeded: bool,
}

/// Where a [`LineScan`] is among an object's top-level keys and values.
#[derive(Clone, Copy, PartialEq)]
enum At {
    /// Nothing but white space so far.
    LineStart,
    Key,
    Colon,
    Value,
    /// The line is not an object, or enough is known. The rest passes unread.
    Settled,
}

/// Reads a line of JSON as it passes, holding only what it must, and stops reading
/// as soon as the line is known to be a response to a given id, or not to be one.
///
/// A response's `result` may be gigabytes, so nothing here is proportional to the
/// line. `rmcp` writes `id` before `result`, so in practice this stops within the
/// first few dozen bytes; the order is not assumed, since JSON does not fix it.
struct LineScan {
    at: At,
    depth: u32,
    in_string: bool,
    escaped: bool,
    key: [u8; 8],
    key_len: usize,
    /// Longer than any key looked for: it matches none of them.
    key_too_long: bool,
    /// The key whose value is being read at the top level is `id`.
    reading_id: bool,
    id: Vec<u8>,
    id_too_long: bool,
    has_result: bool,
    has_error: bool,
    has_method: bool,
}

impl LineScan {
    fn new() -> Self {
        Self {
            at: At::LineStart,
            depth: 0,
            in_string: false,
            escaped: false,
            key: [0; 8],
            key_len: 0,
            key_too_long: false,
            reading_id: false,
            id: Vec::new(),
            id_too_long: false,
            has_result: false,
            has_error: false,
            has_method: false,
        }
    }

    fn take_id_byte(&mut self, b: u8) {
        if self.id.len() < MAX_ID_BYTES {
            self.id.push(b);
        } else {
            self.id_too_long = true;
        }
    }

    fn key_ended(&mut self) {
        if self.key_too_long {
            return;
        }
        match &self.key[..self.key_len] {
            b"result" => self.has_result = true,
            b"error" => self.has_error = true,
            b"method" => self.has_method = true,
            b"id" => self.reading_id = true,
            _ => {}
        }
    }

    /// An id just ended, or a key that settles the line was read.
    fn settle_if_known(&mut self) {
        let id_read = !self.id.is_empty() && !self.reading_id;
        if self.has_method || (id_read && (self.has_result || self.has_error)) {
            self.at = At::Settled;
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.at == At::Settled {
                return;
            }
            if self.in_string {
                self.in_string_byte(b);
            } else {
                self.structural_byte(b);
            }
        }
    }

    fn in_string_byte(&mut self, b: u8) {
        let closes = !self.escaped && b == b'"';
        self.escaped = !self.escaped && b == b'\\';
        if self.depth == 1 && self.at == At::Key {
            if closes {
                self.at = At::Colon;
                self.key_ended();
            } else if self.key_len < self.key.len() {
                self.key[self.key_len] = b;
                self.key_len += 1;
            } else {
                self.key_too_long = true;
            }
        } else if self.reading_id {
            self.take_id_byte(b);
            if closes {
                self.reading_id = false;
                self.settle_if_known();
            }
        }
        if closes {
            self.in_string = false;
        }
    }

    fn structural_byte(&mut self, b: u8) {
        match (self.at, b) {
            (_, b' ' | b'\t' | b'\r' | b'\n') => {
                if self.reading_id && !self.id.is_empty() {
                    self.reading_id = false;
                    self.settle_if_known();
                }
            }
            (At::LineStart, b'{') => {
                self.depth = 1;
                self.at = At::Key;
                self.key_len = 0;
            }
            (At::LineStart, _) => self.at = At::Settled,
            (At::Key, b'"') if self.depth == 1 => {
                self.in_string = true;
                self.key_len = 0;
                self.key_too_long = false;
            }
            (At::Colon, b':') if self.depth == 1 => {
                self.at = At::Value;
                self.settle_if_known();
            }
            (_, b'"') => {
                self.in_string = true;
                if self.reading_id {
                    self.take_id_byte(b);
                }
            }
            (_, b'{' | b'[') => {
                // An id is a string or a number: this is no id.
                self.reading_id = false;
                self.depth += 1;
            }
            (_, b'}' | b']') => {
                self.depth = self.depth.saturating_sub(1);
                self.id_ended_by_structure();
            }
            (_, b',') => {
                self.id_ended_by_structure();
                if self.depth == 1 && self.at != At::Settled {
                    self.at = At::Key;
                    self.key_len = 0;
                }
            }
            _ => {
                if self.reading_id {
                    self.take_id_byte(b);
                }
            }
        }
    }

    fn id_ended_by_structure(&mut self) {
        if self.reading_id {
            self.reading_id = false;
            self.settle_if_known();
        }
    }

    /// The line ended. What it was, and ready for the next.
    fn finish(&mut self) -> Finished {
        let (has_result, has_error, has_method) = (self.has_result, self.has_error, self.has_method);
        let id = std::mem::take(&mut self.id);
        let too_long = self.id_too_long;
        *self = Self::new();
        let is_response = (has_result || has_error) && !has_method && !too_long;
        Finished { answers: if is_response { serde_json::from_slice(&id).ok() } else { None }, succeeded: has_result && !has_error }
    }
}

/// What a line from the client is to this parent.
#[derive(Debug, PartialEq)]
enum FromClient {
    Initialize(Value),
    Initialized,
    Request(Value),
    Cancelled(Value),
    /// Forwarded and not tracked: a response, some other notification, or anything
    /// that does not parse, which is the worker's to answer or ignore.
    Other,
}

fn classify(line: &[u8]) -> FromClient {
    let Ok(message) = serde_json::from_slice::<Value>(line) else { return FromClient::Other };
    let id = message.get("id").filter(|id| !id.is_null()).cloned();
    match (message.get("method").and_then(Value::as_str), id) {
        (Some("initialize"), Some(id)) => FromClient::Initialize(id),
        (Some(_), Some(id)) => FromClient::Request(id),
        (Some("notifications/initialized"), None) => FromClient::Initialized,
        (Some("notifications/cancelled"), None) => FromClient::Cancelled(message["params"]["requestId"].clone()),
        _ => FromClient::Other,
    }
}

/// A client's `initialize`, kept to give a new worker.
struct Hello {
    line: Vec<u8>,
    id: Value,
    /// Whether the client has its response. One it has not had is lost with the
    /// request, like any other, and the client decides what to do about it.
    answered: bool,
}

#[derive(Default)]
struct Session {
    /// Where requests go. `None` while there is no worker ready for one: a request
    /// read then waits for the next, and is the first thing it sees.
    worker: Option<Arc<Mutex<ChildStdin>>>,
    /// Requests with no response yet, in the order they came.
    pending: Vec<Value>,
    hello: Option<Hello>,
    initialized: Option<Vec<u8>>,
    /// A request was answered since the last death.
    answered_since_death: bool,
    client_gone: bool,
}

impl Session {
    /// A response to `id` has been written whole.
    fn answered(&mut self, id: &Value) {
        if let Some(at) = self.pending.iter().position(|p| p == id) {
            self.pending.remove(at);
            self.answered_since_death = true;
        }
        if let Some(hello) = self.hello.as_mut().filter(|h| h.id == *id) {
            hello.answered = true;
        }
    }
}

struct Shared {
    session: Mutex<Session>,
    worker_ready: Condvar,
}

impl Shared {
    fn session(&self) -> MutexGuard<'_, Session> {
        self.session.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

enum Event {
    ClientGone,
    /// The worker of this number closed its output.
    OutputEnded(u64),
    /// The worker of this number answered the `initialize` it was given again.
    Replayed(u64, bool),
}

/// How a worker's time ended.
enum Ended {
    Died(ExitStatus),
    /// The client closed its input: the process's exit code.
    ClientGone(i32),
    /// Nothing more can be done for this client, and why.
    CannotGoOn(String),
}

/// Read the client, track what it asks, and hand each line to the worker of the moment.
fn read_client(shared: &Shared, events: &Sender<Event>) {
    let mut input = io::stdin().lock();
    let mut line = Vec::new();
    loop {
        line.clear();
        if !matches!(input.read_until(b'\n', &mut line), Ok(n) if n > 0) {
            break;
        }
        let what = classify(&line);
        let worker = {
            let mut session = shared.session();
            while session.worker.is_none() {
                session = shared.worker_ready.wait(session).unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            match what {
                FromClient::Initialize(id) => {
                    session.pending.push(id.clone());
                    session.hello = Some(Hello { line: line.clone(), id, answered: false });
                }
                FromClient::Initialized => session.initialized = Some(line.clone()),
                FromClient::Request(id) => session.pending.push(id),
                // A cancelled request may get no response at all, and is not owed an
                // error for a death after it.
                FromClient::Cancelled(id) => session.pending.retain(|p| *p != id),
                FromClient::Other => {}
            }
            session.worker.clone()
        };
        // Not under the session's lock: a worker that is not reading must not stop its
        // own output from being tracked. A failed write is a worker that has died, and
        // what it was asked is pending, so the death answers it.
        if let Some(worker) = worker {
            let mut worker = worker.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let _ = worker.write_all(&line).and_then(|()| worker.flush());
        }
    }
    let mut session = shared.session();
    session.client_gone = true;
    session.worker = None;
    drop(session);
    let _ = events.send(Event::ClientGone);
}

/// Copy a worker's output to the client by chunks, and note each response that has
/// reached it whole. The first response is swallowed when `swallow` names its id.
fn pump(mut from: ChildStdout, number: u64, mut swallow: Option<Value>, abandoned: &AtomicBool, mid_line: &AtomicBool, shared: &Shared, events: &Sender<Event>) {
    let mut chunk = vec![0u8; CHUNK];
    let mut scan = LineScan::new();
    while let Ok(n) = from.read(&mut chunk) {
        if n == 0 {
            break;
        }
        // Under the lock, so that nothing of a worker given up on follows the answers
        // written for it.
        let mut out = io::stdout().lock();
        if abandoned.load(Ordering::SeqCst) {
            return;
        }
        for piece in chunk[..n].split_inclusive(|&b| b == b'\n') {
            let ends_line = piece.last() == Some(&b'\n');
            scan.feed(piece);
            if swallow.is_none() {
                // A client that has gone reads nothing more; its closing is what ends this
                // parent, by way of its input.
                let _ = out.write_all(piece);
                mid_line.store(!ends_line, Ordering::SeqCst);
            }
            if ends_line {
                let line = scan.finish();
                if let Some(id) = &line.answers {
                    if swallow.as_ref() == Some(id) {
                        swallow = None;
                        let _ = events.send(Event::Replayed(number, line.succeeded));
                    } else if swallow.is_none() {
                        // Flushed first: this says the client has it.
                        let _ = out.flush();
                        shared.session().answered(id);
                    }
                }
            }
        }
        let _ = out.flush();
    }
    let _ = events.send(Event::OutputEnded(number));
}

/// The error for a request the worker's death lost.
fn error_line(id: &Value, status: &ExitStatus) -> String {
    let (code, name, message) = if status.code() == Some(EXIT_PAST_THE_CEILING) {
        let message = format!(
            "this query, or another one in flight, needs more memory than the engine's ceiling, so the engine stopped. Ask for less (a narrower range, a limit, a higher minimum), or set N0X_MEMORY_MAX; a cgroup's limit stays the upper bound. {RESTART_LOSES}"
        );
        (CODE_OUT_OF_MEMORY, "out-of-memory", message)
    } else {
        (CODE_ENGINE_CRASHED, "engine-crashed", format!("the engine crashed ({status}) with this query in flight; that query may be what crashed it. {RESTART_LOSES}"))
    };
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message, "data": { "code": name } } }).to_string()
}

/// A worker's life: start it, give it the client's `initialize` again if there was
/// one, let requests through, and come back when it has ended.
fn one_worker(number: u64, shared: &Arc<Shared>, events: &Receiver<Event>, sender: &Sender<Event>, mid_line: &Arc<AtomicBool>) -> Ended {
    let mut command = match worker_program() {
        Ok(program) => Command::new(program),
        Err(e) => return Ended::CannotGoOn(format!("cannot find this program to start the engine: {e}")),
    };
    command.arg(WORKER_ARG).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit());
    no_console_window(&mut command);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => return Ended::CannotGoOn(format!("cannot start the engine: {e}")),
    };
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Ended::CannotGoOn("the engine was started without its pipes".to_string());
    };

    let (replay, initialized) = {
        let session = shared.session();
        match session.hello.as_ref().filter(|h| h.answered) {
            Some(hello) => (Some((hello.line.clone(), hello.id.clone())), session.initialized.clone()),
            None => (None, None),
        }
    };
    let abandoned = Arc::new(AtomicBool::new(false));
    let output_thread = {
        let (shared, sender, abandoned, mid_line) = (Arc::clone(shared), sender.clone(), Arc::clone(&abandoned), Arc::clone(mid_line));
        let swallow = replay.as_ref().map(|(_, id)| id.clone());
        std::thread::spawn(move || pump(stdout, number, swallow, &abandoned, &mid_line, &shared, &sender))
    };

    let mut output_ended = false;
    if let Some((hello, _)) = replay {
        let _ = stdin.write_all(&hello).and_then(|()| stdin.flush());
        let deadline = Instant::now() + REPLAY_DEADLINE;
        let answered = loop {
            match events.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(Event::Replayed(n, succeeded)) if n == number => break succeeded,
                Ok(Event::OutputEnded(n)) if n == number => {
                    output_ended = true;
                    break false;
                }
                Ok(Event::ClientGone) => {
                    drop(stdin);
                    return shut_down(child, output_ended, events);
                }
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break false,
            }
        };
        if !answered {
            let _ = child.kill();
            let status = child.wait().map_or_else(|e| e.to_string(), |s| s.to_string());
            abandoned.store(true, Ordering::SeqCst);
            return Ended::CannotGoOn(format!("a new engine did not answer the client's initialize when it was given again ({status})"));
        }
        if let Some(line) = initialized {
            let _ = stdin.write_all(&line).and_then(|()| stdin.flush());
        }
    }

    {
        let mut session = shared.session();
        if session.client_gone {
            drop(session);
            drop(stdin);
            return shut_down(child, output_ended, events);
        }
        session.worker = Some(Arc::new(Mutex::new(stdin)));
        shared.worker_ready.notify_all();
    }

    let status = loop {
        match events.recv_timeout(POLL) {
            Ok(Event::ClientGone) => return shut_down(child, output_ended, events),
            Ok(Event::OutputEnded(n)) if n == number => {
                output_ended = true;
                match wait_bounded(&mut child, EXIT_GRACE) {
                    Some(status) => break status,
                    None => {
                        let _ = child.kill();
                        match child.wait() {
                            Ok(status) => break status,
                            Err(e) => return Ended::CannotGoOn(format!("cannot wait for the engine: {e}")),
                        }
                    }
                }
            }
            Ok(_) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Ended::CannotGoOn("this program lost its own channel".to_string()),
        }
        if let Ok(Some(status)) = child.try_wait() {
            break status;
        }
    };

    // From here a request read waits for the next worker, so what is pending is all this
    // worker was given.
    shared.session().worker = None;
    if !output_ended {
        wait_for_output(number, events, EXIT_GRACE);
    }
    // Whether or not it ended: a process the worker started may hold the pipe for ever, and
    // that copy must not write again.
    abandoned.store(true, Ordering::SeqCst);
    drop(output_thread);
    Ended::Died(status)
}

fn wait_for_output(number: u64, events: &Receiver<Event>, bound: Duration) {
    let deadline = Instant::now() + bound;
    while let Ok(event) = events.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        if matches!(event, Event::OutputEnded(n) if n == number) {
            return;
        }
    }
}

fn wait_bounded(child: &mut Child, bound: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) | Err(_) => return None,
        }
    }
}

/// The client closed its input, and the worker's has been closed with it. A worker that
/// stays past the bound is killed: nothing else is going to end it.
fn shut_down(mut child: Child, output_ended: bool, events: &Receiver<Event>) -> Ended {
    let status = wait_bounded(&mut child, SHUTDOWN_DEADLINE).or_else(|| {
        let _ = child.kill();
        let _ = child.wait();
        None
    });
    if !output_ended {
        // What the worker said on its way out.
        let deadline = Instant::now() + EXIT_GRACE;
        while let Ok(event) = events.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            if matches!(event, Event::OutputEnded(_)) {
                break;
            }
        }
    }
    Ended::ClientGone(status.and_then(|s| s.code()).unwrap_or(1))
}

/// The parent's whole life. Its value is the process's exit code.
pub fn run() -> i32 {
    let shared = Arc::new(Shared { session: Mutex::new(Session::default()), worker_ready: Condvar::new() });
    let (sender, events) = mpsc::channel();
    {
        let (shared, sender) = (Arc::clone(&shared), sender.clone());
        std::thread::spawn(move || read_client(&shared, &sender));
    }
    let mid_line = Arc::new(AtomicBool::new(false));
    let mut deaths: Vec<Instant> = Vec::new();
    for number in 0.. {
        // The first runs whatever the client did, which says what a session that never
        // opened says. After a death, a client that has gone needs no new one.
        if number > 0 && shared.session().client_gone {
            return 0;
        }
        let status = match one_worker(number, &shared, &events, &sender, &mid_line) {
            Ended::Died(status) => status,
            Ended::ClientGone(code) => return code,
            Ended::CannotGoOn(reason) => {
                answer_pending_and_say(&shared, None, &mid_line);
                eprintln!("n0xis-mcp: stopped: {reason}");
                return 1;
            }
        };
        eprintln!("n0xis-mcp: the engine stopped ({status}); starting it again");
        let answered = answer_pending_and_say(&shared, Some(&status), &mid_line);
        if answered {
            deaths.clear();
        }
        let now = Instant::now();
        deaths.retain(|at| now.duration_since(*at) < DEATH_WINDOW);
        deaths.push(now);
        if deaths.len() > MOST_DEATHS {
            eprintln!("n0xis-mcp: stopped: the engine died {} times in {} seconds with no request answered, the last time with {status}", deaths.len(), DEATH_WINDOW.as_secs());
            return 1;
        }
    }
    unreachable!("the loop above ends only by returning")
}

/// End a line left unended and answer what is pending. Says whether a request had been
/// answered since the last death. With no status there is no new engine to speak of, and
/// the line is only ended.
fn answer_pending_and_say(shared: &Shared, status: Option<&ExitStatus>, mid_line: &AtomicBool) -> bool {
    let (pending, answered) = {
        let mut session = shared.session();
        (std::mem::take(&mut session.pending), std::mem::take(&mut session.answered_since_death))
    };
    let mut out = io::stdout().lock();
    if mid_line.swap(false, Ordering::SeqCst) {
        let _ = out.write_all(b"\n");
    }
    if let Some(status) = status {
        for id in &pending {
            let _ = writeln!(out, "{}", error_line(id, status));
        }
    }
    let _ = out.flush();
    answered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(line: &str) -> Finished {
        let mut scan = LineScan::new();
        scan.feed(line.as_bytes());
        scan.finish()
    }

    /// Fed a byte at a time, as a chunk boundary may fall anywhere.
    fn scan_bytewise(line: &str) -> Finished {
        let mut scan = LineScan::new();
        for b in line.as_bytes() {
            scan.feed(std::slice::from_ref(b));
        }
        scan.finish()
    }

    #[test]
    fn a_response_is_read_whatever_the_order_of_its_keys() {
        for line in [
            r#"{"jsonrpc":"2.0","id":7,"result":{"id":99,"method":"x"}}"#,
            r#"{"result":{"id":99,"error":1},"jsonrpc":"2.0","id":7}"#,
            r#"{ "jsonrpc" : "2.0" , "id" : 7 , "result" : [ "}" , "\"id\":8" ] }"#,
        ] {
            assert_eq!(scan(line), Finished { answers: Some(json!(7)), succeeded: true }, "{line}");
            assert_eq!(scan_bytewise(line), Finished { answers: Some(json!(7)), succeeded: true }, "{line}");
        }
    }

    #[test]
    fn an_id_is_the_top_level_one_and_keeps_its_type() {
        let line = r#"{"jsonrpc":"2.0","id":"a\"b","error":{"code":-1,"message":"m","data":{"id":3}}}"#;
        assert_eq!(scan(line), Finished { answers: Some(json!("a\"b")), succeeded: false });
        assert_eq!(scan(r#"{"id":"7","result":{}}"#).answers, Some(json!("7")));
        assert_eq!(scan(r#"{"result":{},"id":-7}"#).answers, Some(json!(-7)));
    }

    #[test]
    fn what_is_not_a_response_answers_nothing() {
        for line in [
            r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"id":3,"result":1}}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"roots/list"}"#,
            r#"{"method":"roots/list","id":4,"result":{}}"#,
            r#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid request"}}"#,
            r#"{"not_at_all_an_id":4,"result":{}}"#,
            r#"[{"id":1,"result":{}}]"#,
            "half a line",
            "",
        ] {
            assert_eq!(scan(line).answers, None, "{line}");
        }
    }

    /// The point of the type: past the keys that settle it, the line is not read. Bytes
    /// that could not be JSON after the settling point change nothing, and the id stays small.
    #[test]
    fn a_response_stops_being_read_once_it_is_known() {
        let mut s = LineScan::new();
        s.feed(br#"{"jsonrpc":"2.0","id":7,"result":"#);
        assert!(s.at == At::Settled, "settled at the key, before a byte of the result");
        s.feed(&vec![b'"'; 1 << 20]);
        assert_eq!(s.finish(), Finished { answers: Some(json!(7)), succeeded: true });
    }

    #[test]
    fn a_long_id_holds_no_more_than_its_bound() {
        let line = format!(r#"{{"id":"{}","result":{{}}}}"#, "x".repeat(MAX_ID_BYTES * 2));
        let mut s = LineScan::new();
        s.feed(line.as_bytes());
        assert!(s.id.len() <= MAX_ID_BYTES);
        assert_eq!(s.finish().answers, None);
    }

    /// An independent reader of the same lines: `serde_json`, whole.
    #[test]
    fn the_scan_agrees_with_a_whole_parse() {
        let lines = [
            json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"id\":2}"}]}}),
            json!({"jsonrpc":"2.0","id":"abc","error":{"code":-32601,"message":"no"}}),
            json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}),
            json!({"jsonrpc":"2.0","id":18446744073709551615u64,"result":null}),
            json!({"jsonrpc":"2.0","id":-1.5,"result":[[[{"result":1}]]]}),
        ];
        for line in lines {
            let text = line.to_string();
            let whole = if line.get("method").is_none() && (line.get("result").is_some() || line.get("error").is_some()) { line.get("id").cloned() } else { None };
            assert_eq!(scan(&text).answers, whole, "{text}");
        }
    }

    #[test]
    fn a_client_line_is_told_apart() {
        assert_eq!(classify(br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#), FromClient::Initialize(json!(1)));
        assert_eq!(classify(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#), FromClient::Initialized);
        assert_eq!(classify(br#"{"jsonrpc":"2.0","id":"x","method":"tools/call"}"#), FromClient::Request(json!("x")));
        assert_eq!(classify(br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}"#), FromClient::Cancelled(json!(3)));
        assert_eq!(classify(br#"{"jsonrpc":"2.0","id":null,"method":"x"}"#), FromClient::Other);
        assert_eq!(classify(br#"{"jsonrpc":"2.0","id":3,"result":{}}"#), FromClient::Other);
        assert_eq!(classify(b"not json"), FromClient::Other);
    }
}
