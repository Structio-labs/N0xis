// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`plugin_call_once`] against plugins that misbehave on purpose: one deadline
//! must cover the whole exchange, spawn to exit, and every way a plugin can
//! fail must come back as its own error — never a hang, never an empty success.
//!
//! The deadline used to start only after a reply had been read, so a plugin
//! that read its request and slept hung the host for good. Each case below
//! therefore runs under its own watchdog: on code that hangs, the case fails
//! with "no answer within …" instead of hanging the suite.
//!
//! **The plugin is this test binary**, re-executed with `--plugin-helper
//! <mode>`, so every case runs wherever the suite runs — Windows CI included —
//! with no shell, script or interpreter on the path. That is why this target
//! is `harness = false` (see `Cargo.toml`): libtest prints `running N tests`
//! to stdout before any test body runs, and a plugin's stdout is the protocol,
//! so the helper's first line would be the harness's, not its reply. `main`
//! below dispatches to the helper or runs the cases itself, printing the same
//! `test … ok` lines libtest does. Arguments are read the way libtest reads
//! them (see [`parse_args`]): positional ones filter by substring, `--exact`
//! makes them whole names, `--skip <s>` skips, `--list` lists, and a flag
//! that takes a value consumes it. An unknown flag is refused rather than
//! ignored, because ignoring one is how a value like the `1` of
//! `--test-threads 1` became a filter that matched nothing and the run
//! reported `ok` for zero cases.
//!
//! Cases run one after another on purpose: a child spawned while another
//! spawn is in flight can inherit that one's pipe ends on some platforms, and
//! then an end-of-output the case relies on arrives late.
//!
//! The stderr cases need one more role: the binary is also re-executed as the
//! **host** (`--plugin-helper host <plugin mode>`), which calls the plugin and
//! exits, so a case can capture the host's stderr the way a script driving
//! the CLI does and time when it gets control back.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use n0xis_sources::{
    PLUGIN_DEADLINE, PLUGIN_MAX_REPLY_BYTES, PluginError, PluginExit, PluginPending, plugin_call_once,
};
use serde_json::{Value, json};

/// The flag that turns this binary into a plugin.
const HELPER_FLAG: &str = "--plugin-helper";

/// How long a helper that is meant to hang actually stays alive. Bounded, so
/// a case that fails (or old code that never kills it) leaves no process
/// behind for longer than this.
const HELPER_LIFETIME: Duration = Duration::from_secs(30);

/// How often a lingering helper appends a byte to its marker file. The marker
/// is how a case observes, on every platform, whether the helper is still
/// running after the host returned.
const MARKER_TICK: Duration = Duration::from_millis(20);

/// The deadline handed to `call_once` in the cases that are meant to time out.
const SHORT_DEADLINE: Duration = Duration::from_millis(1500);

/// How long past its deadline a case may take before the watchdog calls it a
/// hang. Covers process spawn and reap on a loaded runner.
const WATCHDOG_MARGIN: Duration = Duration::from_secs(5);

/// How long a grandchild that holds the plugin's stderr stays alive. Far past
/// [`CAPTURE_LIMIT`], so a caller held until it exits is told apart from one
/// that is not by a margin no scheduler closes.
#[cfg(unix)]
const GRANDCHILD_LIFETIME: Duration = Duration::from_secs(20);

/// How long a caller capturing the host's output may wait for it: the host's
/// own deadline and room for three process spawns and a reap.
#[cfg(unix)]
const CAPTURE_LIMIT: Duration = SHORT_DEADLINE.saturating_add(Duration::from_secs(3));

/// What the stderr cases' plugin writes to its stderr, to be found in the
/// host's.
#[cfg(unix)]
const PLUGIN_STDERR_LINE: &str = "plugin_deadline: a line the plugin wrote to its stderr";

// ---------------------------------------------------------------- the plugin

/// The helper's behaviours. Each is one way a real plugin can behave.
fn run_helper(mode: &str, marker: Option<&Path>, arg: Option<&str>) -> ! {
    let read_request = || {
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        line
    };
    let reply = |text: &str| {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(text.as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    };
    match mode {
        "reply-exit" => {
            let req: Value = serde_json::from_str(&read_request()).unwrap_or(Value::Null);
            reply(&json!({ "ok": true, "echo": req }).to_string());
            std::process::exit(0)
        }
        "reply-linger" => {
            read_request();
            reply(&json!({ "ok": true, "lingering": true }).to_string());
            linger(marker)
        }
        "read-sleep" => {
            read_request();
            linger(marker)
        }
        "never-read" => linger(marker),
        "exit-silent" => {
            read_request();
            std::process::exit(3)
        }
        "reply-null" => {
            read_request();
            reply("null");
            std::process::exit(0)
        }
        "reply-ok-false" => {
            read_request();
            reply(r#"{"ok":false,"error":{"code":"plugin-says-no","message":"nothing found"}}"#);
            std::process::exit(0)
        }
        #[cfg(unix)]
        "host" => host(arg.unwrap_or("")),
        #[cfg(unix)]
        "stderr-grandchild-silent" => {
            read_request();
            stderr_and_grandchild();
            linger(None)
        }
        #[cfg(unix)]
        "stderr-grandchild-reply" => {
            read_request();
            stderr_and_grandchild();
            reply(&json!({ "ok": true }).to_string());
            std::process::exit(0)
        }
        #[cfg(unix)]
        "hold-stderr" => {
            std::thread::sleep(GRANDCHILD_LIFETIME);
            std::process::exit(0)
        }
        "bad-json" => {
            read_request();
            reply("this is not json");
            std::process::exit(0)
        }
        "trailing-space" => {
            read_request();
            // A form feed and a no-break space after the value, then CRLF:
            // whitespace to `str::trim`, not to JSON.
            reply("{\"ok\":4}\u{c}\u{a0}\r");
            std::process::exit(0)
        }
        "exact-bound" => {
            read_request();
            // A JSON string whose line, newline included, is exactly the bound.
            reply(&json_string_line(PLUGIN_MAX_REPLY_BYTES));
            std::process::exit(0)
        }
        "one-over-line" => {
            read_request();
            // The same, one byte longer: a complete, valid line, so a host
            // whose length check allows even one byte more accepts it and the
            // case sees `Ok` instead of the refusal.
            reply(&json_string_line(PLUGIN_MAX_REPLY_BYTES + 1));
            linger(marker)
        }
        "one-over-open" => {
            read_request();
            // One byte past the bound with no newline, and the output stays
            // open. A host that stops at the bound refuses it at once; one
            // that reads any further waits for bytes that never come and runs
            // into the deadline, so the case pins the read limit itself, not
            // only the length check after it.
            let mut out = std::io::stdout().lock();
            let mut line = vec![b'a'; PLUGIN_MAX_REPLY_BYTES + 1];
            line[0] = b'"';
            let _ = out.write_all(&line);
            let _ = out.flush();
            drop(out);
            linger(marker)
        }
        other => {
            let _ = arg;
            eprintln!("plugin_deadline helper: unknown mode {other:?}");
            std::process::exit(2)
        }
    }
}

/// The host role: call the plugin in `plugin_mode` with [`SHORT_DEADLINE`],
/// say on stdout how it went, and exit at once — as the CLI does after it
/// answers.
#[cfg(unix)]
fn host(plugin_mode: &str) -> ! {
    let started = Instant::now();
    let answer = plugin_call_once(&helper_argv(plugin_mode, None), &json!({ "op": "ping" }), SHORT_DEADLINE);
    let ms = started.elapsed().as_millis() as u64;
    let line = match answer {
        Ok(v) => json!({ "ms": ms, "reply": v }),
        Err(PluginError::TimedOut { .. }) => json!({ "ms": ms, "error": "timed-out" }),
        Err(e) => json!({ "ms": ms, "error": e.to_string() }),
    };
    println!("{line}");
    std::process::exit(0)
}

/// Write [`PLUGIN_STDERR_LINE`] to stderr, then start a grandchild that holds
/// the stderr this process was given and nothing else, for
/// [`GRANDCHILD_LIFETIME`] — the shape of a plugin that hands its work to a
/// child (a shell running a command, a launcher running an interpreter).
///
/// The grandchild is not waited for, on purpose: outliving the plugin is the
/// shape under test. When the plugin exits or is killed, the grandchild is
/// handed to init (or the nearest subreaper), which reaps it.
#[cfg(unix)]
#[allow(clippy::zombie_processes)]
fn stderr_and_grandchild() {
    eprintln!("{PLUGIN_STDERR_LINE}");
    let exe = std::env::current_exe().expect("the test binary's own path");
    std::process::Command::new(exe)
        .args([HELPER_FLAG, "hold-stderr"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("start the grandchild");
}

/// A JSON string of `a`s whose text plus the newline [`run_helper`]'s `reply`
/// adds is exactly `line_len` bytes.
fn json_string_line(line_len: usize) -> String {
    let inner = line_len.checked_sub(3).expect("room for two quotes and a newline");
    format!("\"{}\"", "a".repeat(inner))
}

/// Stay alive for [`HELPER_LIFETIME`], appending to `marker` every tick.
fn linger(marker: Option<&Path>) -> ! {
    let started = Instant::now();
    let mut file = marker.map(|p| std::fs::OpenOptions::new().create(true).append(true).open(p).unwrap());
    while started.elapsed() < HELPER_LIFETIME {
        if let Some(f) = file.as_mut() {
            let _ = f.write_all(b".");
            let _ = f.flush();
        }
        std::thread::sleep(MARKER_TICK);
    }
    std::process::exit(0)
}

// ----------------------------------------------------------------- the cases

fn helper_argv(mode: &str, marker: Option<&Path>) -> Vec<String> {
    let exe = std::env::current_exe().expect("the test binary's own path");
    let mut argv = vec![exe.to_string_lossy().into_owned(), HELPER_FLAG.to_string(), mode.to_string()];
    if let Some(m) = marker {
        argv.push(m.to_string_lossy().into_owned());
    }
    argv
}

fn marker_path(case: &str) -> PathBuf {
    std::env::temp_dir().join(format!("n0xis-plugin-deadline-{}-{case}", std::process::id()))
}

/// The helper behind `marker` was running before the host returned and is not
/// running now: the file grew at all, and does not grow over several ticks.
fn assert_helper_is_gone(marker: &Path) {
    let len = || std::fs::metadata(marker).map(|m| m.len()).unwrap_or(0);
    let before = len();
    std::thread::sleep(MARKER_TICK * 15);
    let after = len();
    let _ = std::fs::remove_file(marker);
    assert!(before > 0, "the helper never ran (its marker is empty), so this case measured nothing");
    assert_eq!(before, after, "the plugin is still running after call_once returned: it was not killed");
}

/// A command name carried in the error, so a list of findings says whose
/// failure each is.
fn assert_names_the_plugin(err: &PluginError, mode: &str) {
    let text = err.to_string();
    assert!(text.contains(mode), "the error does not name the plugin's command: {text}");
}

fn replies_and_exits() {
    let argv = helper_argv("reply-exit", None);
    let started = Instant::now();
    let reply = plugin_call_once(&argv, &json!({ "op": "ping", "n": 42 }), PLUGIN_DEADLINE).unwrap();
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["echo"]["n"], 42, "the reply must carry what the request said");
    assert!(started.elapsed() < PLUGIN_DEADLINE, "a plugin that exits must not cost the whole deadline");
}

fn replies_and_does_not_exit() {
    let marker = marker_path("reply-linger");
    let argv = helper_argv("reply-linger", Some(&marker));
    let deadline = Duration::from_secs(3);
    let started = Instant::now();
    let reply = plugin_call_once(&argv, &json!({ "op": "ping" }), deadline)
        .expect("a reply that arrived inside the deadline is the answer, exit or no exit");
    assert_eq!(reply["lingering"], true);
    assert!(started.elapsed() >= deadline, "the host must give the plugin until the deadline to exit");
    assert_helper_is_gone(&marker);
}

fn reads_and_sleeps() {
    let marker = marker_path("read-sleep");
    let argv = helper_argv("read-sleep", Some(&marker));
    let started = Instant::now();
    let err = plugin_call_once(&argv, &json!({ "op": "ping" }), SHORT_DEADLINE).unwrap_err();
    assert!(
        matches!(err, PluginError::TimedOut { pending: PluginPending::Reply, deadline, .. } if deadline == SHORT_DEADLINE),
        "a plugin that reads and never replies must time out waiting for its reply, got {err:?}"
    );
    assert!(started.elapsed() >= SHORT_DEADLINE, "timed out before the deadline: {:?}", started.elapsed());
    assert_names_the_plugin(&err, "read-sleep");
    assert_helper_is_gone(&marker);
}

fn never_reads_a_large_request() {
    let marker = marker_path("never-read");
    let argv = helper_argv("never-read", Some(&marker));
    // Far past any OS pipe buffer (64 KiB on Linux, 4 KiB to 64 KiB on
    // Windows), so the writer blocks for as long as the plugin does not read.
    let request = json!({ "blob": "x".repeat(8 << 20) });
    let err = plugin_call_once(&argv, &request, SHORT_DEADLINE).unwrap_err();
    assert!(
        matches!(err, PluginError::TimedOut { pending: PluginPending::WritingRequest, .. }),
        "a plugin that never reads its input must time out with the request unwritten, got {err:?}"
    );
    assert_helper_is_gone(&marker);
}

fn exits_with_no_reply() {
    let argv = helper_argv("exit-silent", None);
    let err = plugin_call_once(&argv, &json!({ "op": "ping" }), PLUGIN_DEADLINE).unwrap_err();
    assert!(
        matches!(&err, PluginError::NoReply { exit: PluginExit::Exited(status), .. } if status.code() == Some(3)),
        "a plugin that exits without a line must be a no-reply error carrying its exit status, got {err:?}"
    );
    assert_names_the_plugin(&err, "exit-silent");
}

/// `null` is valid JSON and no answer: handed on, it became
/// `{"ok":true,"data":null}`, a success with nothing in it.
fn a_null_reply_is_an_error() {
    let argv = helper_argv("reply-null", None);
    let err = plugin_call_once(&argv, &json!({ "op": "ping" }), PLUGIN_DEADLINE).unwrap_err();
    assert!(matches!(err, PluginError::NullReply { .. }), "a reply of null must be refused, got {err:?}");
    assert!(err.to_string().ends_with("replied null, which is no answer"), "{err}");
    assert_names_the_plugin(&err, "reply-null");
}

/// The reply is data, not an n0xis envelope (the module doc of
/// `n0xis-sources/src/plugin.rs`, and `docs/COMMUNITY_ROADMAP.md`'s plugin
/// section): a reply with `"ok": false` is the plugin's findings and comes
/// back as they are. This pins that contract; a host that read the reply as
/// an envelope would answer an error here.
fn a_reply_with_ok_false_is_data() {
    let argv = helper_argv("reply-ok-false", None);
    let reply = plugin_call_once(&argv, &json!({ "op": "ping" }), PLUGIN_DEADLINE)
        .expect("a reply with ok:false is a reply");
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["error"]["code"], "plugin-says-no");
}

/// Run the host with `plugin_mode` the way `subprocess.run(capture_output=
/// True)` does — both of its outputs piped, read to their end, the exit
/// waited for — and answer how long that took and what came back, or `None`
/// if it did not come back within [`CAPTURE_LIMIT`].
#[cfg(unix)]
fn capture_host(plugin_mode: &str) -> Option<(Duration, std::process::Output)> {
    let exe = std::env::current_exe().expect("the test binary's own path");
    let started = Instant::now();
    let host = std::process::Command::new(exe)
        .args([HELPER_FLAG, "host", plugin_mode])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start the host");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(host.wait_with_output());
    });
    let output = rx.recv_timeout(CAPTURE_LIMIT).ok()?.expect("read the host's output");
    Some((started.elapsed(), output))
}

/// A plugin that times out leaving a grandchild on its stderr does not hold a
/// caller that captures the host's stderr past the deadline. The plugin's
/// stderr was the host's own, inherited, and the grandchild inherited it in
/// turn, so the caller got control back only when the grandchild exited
/// (measured through the CLI: an answer at 10 s, the capture back at 40 s).
/// What the plugin wrote to its stderr still reaches the host's.
///
/// Unix only. The grandchild is portable, but the fix is not known to hold on
/// Windows: there `std` starts a process with handle inheritance on, so it
/// receives every inheritable handle its parent holds, not only its three
/// standard ones (the documentation of `CommandExt::inherit_handles`: "each
/// inheritable handle in the calling process is inherited by the new
/// process", default `true`), and the host's own stderr arrived as one — so
/// the plugin and its grandchild are expected to hold it anyway. Under Wine
/// they do: both stderr cases, built for Windows with the gate lifted, failed
/// on their capture assertion (2026-10-20, Wine 10 — a second implementation
/// of Windows, not Windows). Not run on Windows itself.
#[cfg(unix)]
fn a_grandchild_on_a_timed_out_plugins_stderr_does_not_hold_the_caller() {
    let captured = capture_host("stderr-grandchild-silent");
    let (took, output) = captured.unwrap_or_else(|| {
        panic!("the caller capturing the host's stderr got nothing back within {CAPTURE_LIMIT:?}: something outlived the call holding it")
    });
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("\"error\":\"timed-out\""), "the host's call must have timed out: {stdout}");
    assert!(stderr.contains(PLUGIN_STDERR_LINE), "the plugin's stderr must reach the host's: {stderr:?}");
    assert!(took < CAPTURE_LIMIT, "{took:?}");
}

/// The same with a plugin that answers and exits at once: the host is done in
/// milliseconds, and the caller must be too, not when the grandchild exits.
#[cfg(unix)]
fn a_grandchild_on_an_answered_plugins_stderr_does_not_hold_the_caller() {
    let captured = capture_host("stderr-grandchild-reply");
    let (took, output) = captured.unwrap_or_else(|| {
        panic!("the caller capturing the host's stderr got nothing back within {CAPTURE_LIMIT:?}: something outlived the call holding it")
    });
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"reply\":{\"ok\":true}"), "the host's call must have been answered: {stdout}");
    assert!(took < CAPTURE_LIMIT, "{took:?}");
}

fn writes_invalid_json() {
    let argv = helper_argv("bad-json", None);
    let err = plugin_call_once(&argv, &json!({ "op": "ping" }), PLUGIN_DEADLINE).unwrap_err();
    assert!(matches!(err, PluginError::BadReply { .. }), "a line that is not JSON must be a bad reply, got {err:?}");
    assert_names_the_plugin(&err, "bad-json");
}

/// Whitespace around the reply is read by `str::trim`, the rule every line
/// reader in the crate shares: a form feed or a no-break space after the value
/// is accepted, as it always was. Parsing the raw bytes refused it.
fn trailing_unicode_whitespace_is_accepted() {
    let argv = helper_argv("trailing-space", None);
    let reply = plugin_call_once(&argv, &json!({ "op": "ping" }), PLUGIN_DEADLINE)
        .expect("a value followed by whitespace `str::trim` strips is a reply");
    assert_eq!(reply, json!({ "ok": 4 }));
}

/// A reply of exactly the bound, newline included, is legal and comes back
/// whole.
fn a_reply_of_exactly_the_bound_is_accepted() {
    let argv = helper_argv("exact-bound", None);
    let reply = plugin_call_once(&argv, &json!({ "op": "ping" }), PLUGIN_DEADLINE)
        .expect("a line of exactly the bound is within it");
    assert_eq!(
        reply.as_str().map(str::len),
        Some(PLUGIN_MAX_REPLY_BYTES - 3),
        "the reply must come back whole: quotes and newline are the other three bytes"
    );
}

/// One byte over the bound in a complete line is refused: this pins the length
/// check. (A host that reads further but checks the same length still refuses
/// here; the next case pins how far it reads.)
fn a_complete_line_one_byte_over_the_bound_is_refused() {
    let marker = marker_path("one-over-line");
    let argv = helper_argv("one-over-line", Some(&marker));
    let err = plugin_call_once(&argv, &json!({ "op": "ping" }), PLUGIN_DEADLINE).unwrap_err();
    assert!(
        matches!(err, PluginError::ReplyTooLarge { limit, .. } if limit == PLUGIN_MAX_REPLY_BYTES),
        "a valid line one byte over the bound must be refused, got {err:?}"
    );
    assert_names_the_plugin(&err, "one-over-line");
    assert_not_growing(&marker);
}

/// One byte over the bound with no line end, and the plugin's output left
/// open: refused at once. A host that read further than the bound would be
/// waiting on the next byte here, and come back with a timeout instead.
fn the_host_stops_reading_one_byte_past_the_bound() {
    let marker = marker_path("one-over-open");
    let argv = helper_argv("one-over-open", Some(&marker));
    let err = plugin_call_once(&argv, &json!({ "op": "ping" }), PLUGIN_DEADLINE).unwrap_err();
    assert!(
        matches!(err, PluginError::ReplyTooLarge { limit, .. } if limit == PLUGIN_MAX_REPLY_BYTES),
        "the host must stop reading one byte past the bound and refuse, got {err:?}"
    );
    assert_names_the_plugin(&err, "one-over-open");
    assert_not_growing(&marker);
}

/// The helper behind `marker` is not running, without requiring that it ever
/// reached its marker. The refused-reply helpers write their reply first, and
/// the host can kill one before its first tick, so an empty marker is a state
/// this allows; one left alive keeps ticking and fails here.
fn assert_not_growing(marker: &Path) {
    let len = || std::fs::metadata(marker).map(|m| m.len()).unwrap_or(0);
    let before = len();
    std::thread::sleep(MARKER_TICK * 15);
    let after = len();
    let _ = std::fs::remove_file(marker);
    assert_eq!(before, after, "the plugin is still running after its reply was refused: it was not killed");
}

/// The run's own argument reading, held to what libtest accepts: a value a
/// flag takes is never a filter, and a flag it does not know is an error.
fn the_harness_reads_libtest_arguments() {
    let parse = |args: &[&str]| parse_args(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let all = parse(&["--test-threads", "1", "--color", "always", "--format", "pretty", "-Z", "unstable-options"])
        .expect("libtest's value-taking flags are accepted");
    assert!(all.filters.is_empty(), "a flag's value was read as a filter: {:?}", all.filters);
    assert_eq!(all.selected().len(), CASES.len());
    let eq = parse(&["--test-threads=1", "--nocapture", "-q", "reads"]).expect("`--flag=value` and plain flags");
    assert_eq!(eq.filters, ["reads"]);
    let exact = parse(&["--exact", "reads_and_sleeps"]).unwrap();
    assert_eq!(exact.selected().iter().map(|c| c.0).collect::<Vec<_>>(), ["reads_and_sleeps"]);
    let skip = parse(&["--skip", "reads"]).unwrap();
    assert!(skip.selected().iter().all(|c| !c.0.contains("reads")));
    // No case here is ignored or a benchmark, so these select none, as they
    // would under libtest.
    assert!(parse(&["--ignored"]).unwrap().selected().is_empty());
    assert!(parse(&["--test-threads"]).is_err(), "a value-taking flag without its value");
    assert!(parse(&["--no-such-flag"]).is_err(), "an unknown flag must be refused, not ignored");
}

/// Name, the case, and the deadline its call uses (the watchdog adds
/// [`WATCHDOG_MARGIN`] to it).
type Case = (&'static str, fn(), Duration);

const CASES: &[Case] = &[
    ("replies_and_exits", replies_and_exits, PLUGIN_DEADLINE),
    ("replies_and_does_not_exit", replies_and_does_not_exit, Duration::from_secs(3)),
    ("reads_and_sleeps", reads_and_sleeps, SHORT_DEADLINE),
    ("never_reads_a_large_request", never_reads_a_large_request, SHORT_DEADLINE),
    ("exits_with_no_reply", exits_with_no_reply, PLUGIN_DEADLINE),
    ("writes_invalid_json", writes_invalid_json, PLUGIN_DEADLINE),
    ("a_null_reply_is_an_error", a_null_reply_is_an_error, PLUGIN_DEADLINE),
    ("a_reply_with_ok_false_is_data", a_reply_with_ok_false_is_data, PLUGIN_DEADLINE),
    #[cfg(unix)]
    (
        "a_grandchild_on_a_timed_out_plugins_stderr_does_not_hold_the_caller",
        a_grandchild_on_a_timed_out_plugins_stderr_does_not_hold_the_caller,
        CAPTURE_LIMIT,
    ),
    #[cfg(unix)]
    (
        "a_grandchild_on_an_answered_plugins_stderr_does_not_hold_the_caller",
        a_grandchild_on_an_answered_plugins_stderr_does_not_hold_the_caller,
        CAPTURE_LIMIT,
    ),
    ("trailing_unicode_whitespace_is_accepted", trailing_unicode_whitespace_is_accepted, PLUGIN_DEADLINE),
    ("a_reply_of_exactly_the_bound_is_accepted", a_reply_of_exactly_the_bound_is_accepted, PLUGIN_DEADLINE),
    (
        "a_complete_line_one_byte_over_the_bound_is_refused",
        a_complete_line_one_byte_over_the_bound_is_refused,
        PLUGIN_DEADLINE,
    ),
    ("the_host_stops_reading_one_byte_past_the_bound", the_host_stops_reading_one_byte_past_the_bound, PLUGIN_DEADLINE),
    ("the_harness_reads_libtest_arguments", the_harness_reads_libtest_arguments, Duration::ZERO),
];

/// libtest's flags that take a value, as a separate argument or after `=`.
const VALUE_FLAGS: &[&str] =
    &["--test-threads", "--color", "--format", "--logfile", "--shuffle-seed", "--skip", "-Z"];

/// libtest's flags that take none. Accepted and, apart from the ones
/// [`parse_args`] acts on, without effect here: the cases already run one at a
/// time, with their output shown.
const PLAIN_FLAGS: &[&str] = &[
    "--list",
    "--exact",
    "--ignored",
    "--include-ignored",
    "--bench",
    "--test",
    "--nocapture",
    "--no-capture",
    "--show-output",
    "--quiet",
    "-q",
    "--force-run-in-process",
    "--report-time",
    "--ensure-time",
    "--shuffle",
];

/// What the arguments asked for.
struct Selection {
    filters: Vec<String>,
    skips: Vec<String>,
    exact: bool,
    list: bool,
    /// `--ignored` or `--bench`: libtest runs only ignored tests or only
    /// benchmarks then, and this target has neither.
    none: bool,
}

impl Selection {
    fn selected(&self) -> Vec<&'static Case> {
        let hit = |name: &str, pat: &str| if self.exact { name == pat } else { name.contains(pat) };
        CASES
            .iter()
            .filter(|_| !self.none)
            .filter(|(name, ..)| self.filters.is_empty() || self.filters.iter().any(|f| hit(name, f)))
            .filter(|(name, ..)| !self.skips.iter().any(|s| hit(name, s)))
            .collect()
    }
}

/// Read the arguments libtest would be given. Every flag libtest takes is
/// known here by whether it takes a value, so a value is never mistaken for a
/// filter; anything else that starts with `-` is an error.
fn parse_args(args: &[String]) -> Result<Selection, String> {
    let mut sel = Selection { filters: Vec::new(), skips: Vec::new(), exact: false, list: false, none: false };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) if f.starts_with('-') => (f, Some(v.to_string())),
            _ => (a.as_str(), None),
        };
        if VALUE_FLAGS.contains(&flag) {
            let value = match inline {
                Some(v) => v,
                None => it.next().cloned().ok_or_else(|| format!("{flag} takes a value"))?,
            };
            if flag == "--skip" {
                sel.skips.push(value);
            }
        } else if PLAIN_FLAGS.contains(&flag) && inline.is_none() {
            match flag {
                "--list" => sel.list = true,
                "--exact" => sel.exact = true,
                "--ignored" | "--bench" => sel.none = true,
                _ => {}
            }
        } else if a.starts_with('-') {
            return Err(format!("unknown argument {a:?}"));
        } else {
            sel.filters.push(a.clone());
        }
    }
    Ok(sel)
}

// ------------------------------------------------------------------- the run

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some(HELPER_FLAG) {
        let mode = args.get(1).map(String::as_str).unwrap_or("");
        // The third argument is a marker file for the lingering modes and the
        // plugin's mode for `host`.
        run_helper(mode, args.get(2).map(Path::new), args.get(2).map(String::as_str));
    }

    let selection = match parse_args(&args) {
        Ok(s) => s,
        Err(why) => {
            eprintln!("plugin_deadline: {why}");
            std::process::exit(101);
        }
    };
    let selected = selection.selected();
    if selection.list {
        for (name, ..) in &selected {
            println!("{name}: test");
        }
        return;
    }

    println!("\nrunning {} tests", selected.len());
    let mut failed = Vec::new();
    for (name, case, deadline) in &selected {
        let watchdog = *deadline + WATCHDOG_MARGIN;
        let (done_tx, done_rx) = mpsc::channel();
        let case = *case;
        // A panicking case drops `done_tx` unsent; the default panic hook has
        // already printed its file and line.
        std::thread::spawn(move || {
            case();
            let _ = done_tx.send(());
        });
        let verdict = match done_rx.recv_timeout(watchdog) {
            Ok(()) => Ok(()),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err("an assertion failed (see above)".to_string()),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                Err(format!("no answer within {watchdog:?}: call_once hung past its {deadline:?} deadline"))
            }
        };
        match verdict {
            Ok(()) => println!("test {name} ... ok"),
            Err(why) => {
                println!("test {name} ... FAILED: {why}");
                failed.push(*name);
            }
        }
    }
    let result = if failed.is_empty() { "ok" } else { "FAILED" };
    println!("\ntest result: {result}. {} passed; {} failed\n", selected.len() - failed.len(), failed.len());
    if !failed.is_empty() {
        println!("failures: {}", failed.join(", "));
        // A hung case's thread and helper are still alive; exiting is what
        // ends the thread, and the helper ends within HELPER_LIFETIME.
        std::process::exit(101);
    }
}
