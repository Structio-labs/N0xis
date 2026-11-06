// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The daily check and the one line it leads to.
//!
//! A command never waits for the network. At most once a day a run in a terminal starts a detached
//! copy of its own binary and carries on. That copy makes the request, writes what it learned to a
//! state file, and exits; a later run reads the file and prints the line. **A stamp file is the
//! claim:** it is written before the copy starts, so a failed or slow check costs one request a day
//! rather than one for every command.
//!
//! This is the simplest thing that holds against a script: the copy has none of the parent's standard
//! handles, so nothing reading a pipe waits on it, and it is no child of anything once the parent
//! exits. A thread would have to be waited for or killed at exit, and a process that outlives a
//! script's `wait` only because it is detached costs nothing, since a script gets no copy at all:
//! the first test here is that standard error is a terminal.

use std::fs::OpenOptions;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::config::{self, Settings};
use crate::{Updater, Why};

/// The hidden first argument that makes a binary the detached copy. Read before the door's argument
/// parser, so it is in no catalog.
pub const BACKGROUND_ARG: &str = "__update-check";

const DAY_SECONDS: u64 = 24 * 60 * 60;
const CHECK_STAMP: &str = "update-check.stamp";
const CHECK_LOCK: &str = "update-check.lock";
const NOTICE_STAMP: &str = "update-notice.stamp";
const STATE: &str = "update-state.json";

/// What the last check learned.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    /// The newest version a verified manifest stated with something installable for this build.
    pub latest: Option<String>,
    /// What `update.auto` put in place, until a notice has said so.
    pub installed: Option<Installed>,
    /// The code the last check ended in, for anyone who wants to know why nothing is offered.
    pub refusal: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Installed {
    pub from: String,
    pub to: String,
    /// The file that moved, as the install resolved it. The state is shared by every copy of this user's,
    /// and a version says nothing of which: a second copy that happened to be at `to` once said it had
    /// been installed, offered a rollback it did not have, and used up the line of the one that had.
    pub path: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct NoticeStamp {
    at: u64,
    /// The install a notice has already spoken of: that version of that file.
    spoken_of: Option<Installed>,
}

/// `update.check`, as the environment and the file together say: `N0X_NO_UPDATE_CHECK` set to
/// anything but empty or `0` turns it off, which errs towards making no request.
fn check_is_off_by_environment() -> bool {
    std::env::var_os("N0X_NO_UPDATE_CHECK").is_some_and(|v| !v.is_empty() && v != "0")
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// What is left of the state file once every version in it has read as one. Some of these reach a
/// terminal, and the file is only as trustworthy as whoever wrote to it: an `installed.from` holding
/// an escape sequence used to be printed as it stood.
fn read_state(dir: &Path) -> State {
    let is_version = |v: &String| Version::parse(v).is_ok();
    let state: State = std::fs::read(dir.join(STATE)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    State {
        latest: state.latest.filter(is_version),
        installed: state.installed.filter(|i| is_version(&i.from) && is_version(&i.to)),
        refusal: state.refusal,
    }
}

fn write_state(dir: &Path, state: &State) {
    if let Ok(text) = serde_json::to_vec_pretty(state) {
        let _ = crate::write_by_rename(&dir.join(STATE), &text);
    }
}

fn read_stamp(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// A stamp from the future, a clock set back, must not silence the check for as long as it is ahead.
fn a_day_has_passed(stamp: Option<u64>, now: u64) -> bool {
    stamp.is_none_or(|at| at > now || now - at >= DAY_SECONDS)
}

/// Whatever the door does before running a command, it is this: possibly one line on standard error,
/// and possibly a detached copy started. Nothing here can change what the command prints or how it
/// exits, and it returns before any request is made.
///
/// In a script nothing past the first test runs: no file is read and no process started.
pub fn at_start(version: &str, quiet: bool) {
    if quiet || !std::io::stderr().is_terminal() || check_is_off_by_environment() {
        return;
    }
    let Some(dir) = config::user_dir() else { return };
    // A file that does not read may be one that turned this off, so it counts as off.
    let Ok(settings) = Settings::load(&dir) else { return };
    if !settings.check {
        return;
    }
    let at = now();
    let this_file = std::env::current_exe().ok().and_then(|exe| crate::install::file_at(&exe));
    if let Some(line) = take_line(&dir, version, this_file.as_deref(), at) {
        let _ = writeln!(std::io::stderr(), "{line}");
    }
    start_check_if_due(&dir, at);
}

/// The line this run should print, if any, and the note that it was.
fn take_line(dir: &Path, version: &str, this_file: Option<&str>, at: u64) -> Option<String> {
    let current = Version::parse(version).ok()?;
    let state = read_state(dir);
    let path = dir.join(NOTICE_STAMP);
    let stamp: NoticeStamp = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let (line, spoken_of) = match &state.installed {
        // Only by the file that was installed: a run of the old file that started just before the swap
        // has nothing to say about what it is not, and neither has another copy at that version.
        Some(i) if i.to == version && this_file == Some(i.path.as_str()) && stamp.spoken_of.as_ref() != Some(i) => {
            (format!("[n0x] {} was installed in place of {}: n0x update --rollback goes back", i.to, i.from), Some(i.clone()))
        }
        _ => {
            let latest = state.latest.as_deref().and_then(|v| Version::parse(v).ok()).filter(|v| *v > current)?;
            if !a_day_has_passed(Some(stamp.at).filter(|&a| a != 0), at) {
                return None;
            }
            (format!("[n0x] {latest} is available: n0x update"), stamp.spoken_of.clone())
        }
    };
    // If this cannot be written the line would repeat on every command, so it is not printed at all.
    let text = serde_json::to_vec(&NoticeStamp { at, spoken_of }).ok()?;
    crate::write_by_rename(&path, &text).ok()?;
    Some(line)
}

fn start_check_if_due(dir: &Path, at: u64) {
    let path = dir.join(CHECK_STAMP);
    if !a_day_has_passed(read_stamp(&path), at) {
        return;
    }
    // Read and written under one lock, or runs started together each read an old stamp and each
    // claim the day. Held by another means it is claiming now, and a command never waits for that.
    let lock = std::fs::create_dir_all(dir).and_then(|()| OpenOptions::new().create(true).truncate(false).write(true).open(dir.join(CHECK_LOCK)));
    let Ok(lock) = lock else { return };
    if lock.try_lock().is_err() || !a_day_has_passed(read_stamp(&path), at) {
        return;
    }
    // The claim comes first. A directory that cannot be written means no check at all, rather than
    // one per command for ever.
    if crate::write_by_rename(&path, at.to_string().as_bytes()).is_err() {
        return;
    }
    let Ok(exe) = std::env::current_exe() else { return };
    let mut child = Command::new(exe);
    child.arg(BACKGROUND_ARG).current_dir(dir).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    detach(&mut child);
    // Not waited for, on purpose. It belongs to no one once this process exits.
    let _ = child.spawn();
}

#[cfg(unix)]
fn detach(child: &mut Command) {
    use std::os::unix::process::CommandExt;
    // Out of the terminal's foreground group, so a Ctrl-C meant for the command is not meant for it.
    child.process_group(0);
}

#[cfg(windows)]
fn detach(child: &mut Command) {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    child.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
}

#[cfg(not(any(unix, windows)))]
fn detach(_child: &mut Command) {}

/// A script may have left a pipe open past the standard three, as `3>some-pipe` does, and anything
/// reading that pipe waits for every holder to close it. The parent will exit in moments; this copy
/// may wait on the network for a minute, so it must not be one of the holders. Only this process's
/// first act: nothing in it has opened anything yet that it would miss.
///
/// Walked from `/proc/self/fd` because a fixed range misses a pipe above it: 3..1024 once left one at
/// 1024 held. Where there is no `/proc`, every number up to the limit, itself bounded because a limit
/// can be a billion.
#[cfg(unix)]
fn let_go_of_inherited_handles() {
    // SAFETY: sysconf takes a constant and returns a number.
    let limit = || unsafe { libc::sysconf(libc::_SC_OPEN_MAX) }.clamp(1024, 1 << 20) as i32;
    let open: Vec<i32> = match std::fs::read_dir("/proc/self/fd") {
        Ok(entries) => entries.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect(),
        Err(_) => (3..limit()).collect(),
    };
    for fd in open.into_iter().filter(|&fd| fd >= 3) {
        // SAFETY: closing a descriptor number that may not be open is an error return and no more,
        // and at this point no code in this process holds one it still means to use.
        unsafe { libc::close(fd) };
    }
}

/// Windows passes on only handles marked inheritable, and `DETACHED_PROCESS` has none of the console's.
#[cfg(not(unix))]
fn let_go_of_inherited_handles() {}

/// The detached copy's whole life: one check, and with `update.auto` on, the install. It says nothing
/// and has no one to say it to, so everything goes to the state file.
pub fn background_check(component: &str, version: &str) {
    let_go_of_inherited_handles();
    let Ok(updater) = Updater::for_running(component, version) else { return };
    let auto = updater.config_dir.as_deref().and_then(|d| Settings::load(d).ok()).is_some_and(|s| s.auto);
    run_check(&updater, auto);
}

/// One check against whatever `updater` stands on, with the state it leaves. Does nothing with no
/// directory to write the answer to.
pub fn run_check(updater: &Updater, auto: bool) {
    let Some(dir) = updater.config_dir.clone() else { return };
    let mut state = read_state(&dir);
    // One fetch: what is installed is what this check found, and it cannot say otherwise. The install
    // reads only what is on the disk, under its lock.
    match updater.fetch_manifest() {
        Ok(found) => {
            let report = updater.report(&found);
            state.refusal = report.blocked.map(str::to_string);
            state.latest = report.available.then(|| report.latest.clone());
            if report.available && auto {
                let done = updater.install_alone(&found);
                // Only from what moved, a commit that failed for a sibling included. A sentence once
                // said an install had happened where a version older than the one claimed had been.
                let moved = match &done {
                    Ok(done) => done.replaced.iter().find(|r| r.component == updater.component).map(|r| r.path.clone()),
                    Err(r) => r.components.iter().find(|o| o.component == updater.component && o.error.is_none()).map(|o| o.path.clone()),
                };
                if let Some(path) = moved {
                    state.installed = Some(Installed { from: report.current, to: report.latest, path });
                }
                match done {
                    // Another run is on it, and whichever finishes will have said what happened.
                    Err(r) if r.why == Why::UpdateInProgress => {}
                    // The line then offers what could not be done alone, and `n0x update` says why.
                    Err(r) => state.refusal = Some(r.why.code().to_string()),
                    Ok(_) => {}
                }
            }
        }
        // What an earlier check learned stays true after a failed one.
        Err(r) => state.refusal = Some(r.why.code().to_string()),
    }
    write_state(&dir, &state);
}

/// The file the check's result goes to, for a test that plants one.
pub fn state_file(dir: &Path) -> PathBuf {
    dir.join(STATE)
}

/// What the MCP server states when a session starts: its version, and that a newer one exists if
/// the last check found one.
///
/// It reads what the check left and makes no request of its own: its standard error is a pipe, and
/// `update.check`'s promise is that a pipe gets none. The session is never interrupted.
pub fn statement_for_a_session(version: &str) -> String {
    let newer = (!check_is_off_by_environment()).then(config::user_dir).flatten().and_then(|dir| {
        let settings = Settings::load(&dir).ok()?;
        if !settings.check {
            return None;
        }
        let latest = read_state(&dir).latest?;
        (Version::parse(&latest).ok()? > Version::parse(version).ok()?).then_some(latest)
    });
    match newer {
        Some(latest) => format!("This is n0xis-mcp {version}. {latest} is available: n0x update."),
        None => format!("This is n0xis-mcp {version}."),
    }
}
