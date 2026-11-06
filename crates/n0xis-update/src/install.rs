// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Putting a file in place, and going back: prepare, then commit, under one lock.
//!
//! **Prepare** puts every byte on the disk and touches nothing installed, so any failure, a full disk
//! included, leaves each installed file as it was. **Commit** is renames only, so it needs no space
//! and leaves at every step a target that is the old file or the new one. There is no undo, because
//! undoing was the defect: it was disk work done while swapping, its failure was reported as success,
//! and it poisoned the file `--rollback` goes back to. Each component is its own fact, and a failure
//! on one is reported as that.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ring::digest::{Context, SHA256};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::manifest::Entry;
use crate::{Refusal, Updater, Why, from_hex, notice, to_hex};

/// Beside each file: what `--rollback` goes back to. Startup never deletes it, or rollback would be
/// unreachable by construction.
const PREVIOUS: &str = ".previous";
/// Beside each file, not in the configuration directory, so that two copies do not share one and it
/// needs no configuration: what `.previous` is.
const RECORD: &str = ".previous.json";
/// Beside the running binary, and it stays: the kernel releases the lock on a kill, whoever holds it.
const LOCK: &str = ".update-lock";
const LOCK_PATIENCE: Duration = Duration::from_millis(500);
/// While preparing. Fixed names, because under the lock anything of ours is a dead run's.
const NEW_FILE: &str = ".update-new";
const PREVIOUS_NEW: &str = ".previous-new";
const RECORD_NEW: &str = ".previous.json.new";
/// On Windows only, with a pid, since a running exe can be renamed and not removed.
const ASIDE: &str = ".aside-";

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// A file that goes away unless it was moved first.
struct Temp(PathBuf);

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// What `.previous` is. The versions are read as versions and the digest as a digest, or there is no
/// record, because these reach the envelope and the hold.
#[derive(Serialize, Deserialize)]
struct Record {
    from: String,
    to: String,
    /// Of `.previous`.
    sha256: String,
}

fn read_record(target: &Path) -> Option<Record> {
    let record: Record = serde_json::from_slice(&fs::read(with_suffix(target, RECORD)).ok()?).ok()?;
    let reads = Version::parse(&record.from).is_ok() && Version::parse(&record.to).is_ok() && from_hex::<32>(&record.sha256).is_some();
    reads.then_some(record)
}

#[derive(Clone, Debug, Serialize)]
pub struct Replaced {
    pub component: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// What `n0x update` answers.
#[derive(Clone, Debug, Serialize)]
pub struct UpdateReport {
    pub from: String,
    pub to: String,
    pub replaced: Vec<Replaced>,
    /// Components already holding exactly the file the manifest names.
    pub unchanged: Vec<String>,
    pub address: String,
    pub tried: Vec<crate::Tried>,
}

/// What `n0x update --rollback` answers. `from` and `to` come only from a record that matched.
#[derive(Clone, Debug, Serialize)]
pub struct RollbackReport {
    pub from: Option<String>,
    pub to: Option<String>,
    pub restored: Vec<String>,
    /// Why nothing moved, when nothing did.
    pub nothing_changed: Option<String>,
}

/// One component's result where a commit did not go the same way for all of them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Outcome {
    pub component: String,
    pub path: String,
    /// Why it was not moved. None: it is in place.
    pub error: Option<String>,
}

struct Planned {
    component: String,
    target: PathBuf,
    entry: Entry,
    /// The running component, the only one executed: a later component may not answer `--version`.
    runs: bool,
}

/// Everything one component needs for its commit, on the disk and closed. A temp not renamed away
/// goes when this is dropped.
struct Prepared {
    new_file: Temp,
    previous_new: Temp,
    record_new: Temp,
}

impl Updater {
    /// `n0x update`.
    pub fn update(&self) -> Result<UpdateReport, Refusal> {
        let found = self.fetch_manifest()?;
        let manifest = &found.manifest;
        if manifest.version < self.current {
            return Err(Refusal::new(
                Why::OlderVersion,
                format!("the manifest states {}, older than this build's {}, and an update never goes back", manifest.version, self.current),
            )
            .with_hint("n0x update --rollback returns to the previous binary"));
        }
        let mut report = UpdateReport {
            from: self.current.to_string(),
            to: manifest.version.to_string(),
            replaced: Vec::new(),
            unchanged: Vec::new(),
            address: found.address.clone(),
            tried: found.tried.clone(),
        };
        if manifest.version == self.current {
            return Ok(report);
        }

        let plan = self.plan(manifest)?;
        let first = &plan[0];
        let _lock = take_lock(&first.target, |e| not_writable(&first.target, &first.entry, e))?;
        // What is installed is read only now, under the lock. Read before it, a run that waited out
        // another would go on to keep the new file as `.previous` and lose the old one.
        let mut changing = Vec::new();
        for item in plan {
            if measure(&item.target).is_ok_and(|(_, sum)| sum == item.entry.sha256) {
                report.unchanged.push(item.component);
            } else {
                changing.push(item);
            }
        }
        if changing.is_empty() {
            return Ok(report);
        }
        for item in &changing {
            sweep(&item.target);
        }
        let prepared = self.prepare_all(&changing, &report).map_err(|r| said_after_prepare(r, &changing))?;

        // The running component last. A run killed part way is then still the old binary, and running
        // it again finishes the job, since what is already in place is `unchanged`; the other order
        // leaves a new binary that sees nothing to do and a sibling stranded until the next release.
        let mut outcomes = Vec::new();
        for (item, files) in changing.iter().zip(&prepared).rev() {
            let result = commit(item, files);
            outcomes.push(Outcome { component: item.component.clone(), path: item.target.display().to_string(), error: result.err().map(|e| e.to_string()) });
        }
        outcomes.reverse();
        drop(prepared);
        if outcomes.iter().any(|o| o.error.is_some()) {
            return Err(split_result(Why::InstallFailed, outcomes));
        }
        report.replaced = changing
            .into_iter()
            .map(|i| Replaced { component: i.component, path: i.target.display().to_string(), size: i.entry.size, sha256: to_hex(&i.entry.sha256) })
            .collect();
        if let Some(dir) = &self.config_dir {
            notice::clear_hold(dir);
        }
        Ok(report)
    }

    /// The file the running binary's path leads to, where its lock goes.
    fn exe_target(&self) -> Result<PathBuf, Refusal> {
        regular_file(&self.exe)?.ok_or_else(|| Refusal::new(Why::InstallFailed, format!("{} is not there to replace", self.exe.display())))
    }

    /// The running component always, and each other one only if a file of its name is already
    /// beside the binary: this replaces what is installed and adds nothing.
    fn plan(&self, manifest: &crate::Manifest) -> Result<Vec<Planned>, Refusal> {
        let entry = manifest.entry(&self.component, &self.platform)?;
        let exe = self.exe_target()?;
        let dir = self.exe.parent().ok_or_else(|| Refusal::new(Why::InstallFailed, format!("{} has no directory", self.exe.display())))?;
        let mut plan = vec![Planned { component: self.component.clone(), target: exe, entry, runs: true }];
        for (name, raw, file) in manifest.others(&self.component, &self.platform) {
            // Only the file name is looked at here, and `decode` refuses one that is not a bare name.
            let Some(target) = regular_file(&dir.join(file))? else { continue };
            // Two names for one file are one file, and it has one previous.
            if plan.iter().all(|p| p.target != target) {
                plan.push(Planned { component: name.to_string(), target, entry: Entry::decode(name, raw)?, runs: false });
            }
        }
        Ok(plan)
    }

    /// In full, for each, before any commit. On a failure the temps of all of them go with the
    /// `Prepared` dropped here.
    fn prepare_all(&self, changing: &[Planned], report: &UpdateReport) -> Result<Vec<Prepared>, Refusal> {
        changing.iter().map(|item| self.prepare(item, report)).collect()
    }

    fn prepare(&self, item: &Planned, report: &UpdateReport) -> Result<Prepared, Refusal> {
        let disk = |e: io::Error| Refusal::new(Why::InstallFailed, format!("preparing {}: {e}", item.target.display()));
        let new_path = with_suffix(&item.target, NEW_FILE);
        // Before the download, so a directory that cannot be written costs no request for the file.
        let mut file = match create_private(&new_path) {
            Ok(file) => file,
            Err(e) => return Err(not_writable(&item.target, &item.entry, &e)),
        };
        let new_file = Temp(new_path);
        self.transport.download(&item.entry.url, item.entry.size, &mut file)?;
        file.sync_all().map_err(disk)?;
        drop(file);

        // The file, and not the stream: this is what will be installed, and the stream's digest once
        // passed a file altered on the disk during the download.
        let (size, sum) = measure(&new_file.0).map_err(disk)?;
        if size != item.entry.size {
            return Err(Refusal::new(Why::SizeMismatch, format!("{} gave {size} bytes, and the manifest states {}", item.entry.url, item.entry.size)));
        }
        if sum != item.entry.sha256 {
            return Err(Refusal::new(
                Why::DigestMismatch,
                format!("{} has sha256 {}, and the manifest states {}", item.entry.url, to_hex(&sum), to_hex(&item.entry.sha256)),
            ));
        }

        // Without the setuid bits: a replaced binary runs, and nothing more is carried over.
        let mode = plain_mode(&item.target).map_err(disk)?;
        if item.runs {
            set_mode(&new_file.0, 0o700).map_err(disk)?;
            answers_its_version(&new_file.0, &report.to, self.transport.run_bound)?;
        }
        set_mode(&new_file.0, mode).map_err(disk)?;

        let previous_new = Temp(with_suffix(&item.target, PREVIOUS_NEW));
        let kept = keep_a_copy(&item.target, &previous_new.0, mode).map_err(disk)?;
        let record_new = Temp(with_suffix(&item.target, RECORD_NEW));
        // Written now, so the commit is renames and needs no space.
        let record = Record { from: report.from.clone(), to: report.to.clone(), sha256: to_hex(&kept) };
        let text = serde_json::to_vec_pretty(&record).map_err(|e| disk(io::Error::other(e)))?;
        write_private(&record_new.0, &text).map_err(disk)?;
        Ok(Prepared { new_file, previous_new, record_new })
    }
}

/// Only when the temps are gone is the sentence said, and it is checked rather than assumed.
fn said_after_prepare(mut refusal: Refusal, changing: &[Planned]) -> Refusal {
    let left: Vec<String> = changing
        .iter()
        .flat_map(|item| [NEW_FILE, PREVIOUS_NEW, RECORD_NEW].map(|suffix| with_suffix(&item.target, suffix)))
        .filter(|path| fs::symlink_metadata(path).is_ok())
        .map(|path| path.display().to_string())
        .collect();
    let said = if left.is_empty() {
        "every installed file is unchanged".to_string()
    } else {
        format!("every installed file is unchanged, and these could not be removed: {}", left.join(", "))
    };
    refusal.message = format!("{}; {said}", refusal.message);
    refusal
}

/// Some moved and some did not: which, in the message and each in `components`.
fn split_result(why: Why, outcomes: Vec<Outcome>) -> Refusal {
    let name = |o: &Outcome| o.component.clone();
    let done: Vec<String> = outcomes.iter().filter(|o| o.error.is_none()).map(name).collect();
    let not: Vec<String> = outcomes.iter().filter_map(|o| o.error.as_ref().map(|e| format!("{} ({e})", o.component))).collect();
    let mut refusal = Refusal::new(why, format!("in place: {}; not in place: {}", if done.is_empty() { "none".to_string() } else { done.join(", ") }, not.join(", ")));
    refusal.components = outcomes;
    refusal
}

/// One component's renames, in the order that leaves every kill point readable: a kill after the first
/// leaves a `.previous` no record vouches for, which rollback refuses, and a kill after the second a
/// `.previous` equal to the target, of which rollback says that nothing changed.
fn commit(item: &Planned, files: &Prepared) -> io::Result<()> {
    replace_previous(&files.previous_new.0, &with_suffix(&item.target, PREVIOUS))?;
    fs::rename(&files.record_new.0, with_suffix(&item.target, RECORD))?;
    put_in_place(&files.new_file.0, &item.target)?;
    sync_directory_of(&item.target);
    Ok(())
}

/// `n0x update --rollback`: back to the file kept beside `exe`, and to each kept beside it by the same
/// install. It needs no network, and it is one shot: the file gone back from is not kept, so a second
/// run says there is nothing to go back to and never goes forward.
pub fn rollback(exe: &Path, config_dir: Option<&Path>) -> Result<RollbackReport, Refusal> {
    let Some(exe) = regular_file(exe)? else {
        return Err(Refusal::new(Why::InstallFailed, format!("{} is not there", exe.display())));
    };
    // Before the lock, so that asking with nothing kept leaves no file behind.
    if fs::symlink_metadata(with_suffix(&exe, PREVIOUS)).is_err() {
        return Err(no_previous(&exe));
    }
    let _lock = take_lock(&exe, |e| Refusal::new(Why::NotWritable, format!("{} cannot be replaced from here: {e}", exe.display())))?;
    sweep(&exe);
    let record = kept_for(&exe)?;
    if kept_equals_target(&exe, &record) {
        let says = format!("{} is what is already installed, so nothing changed: an install that died before its last step leaves this", with_suffix(&exe, PREVIOUS).display());
        return Ok(RollbackReport { from: None, to: None, restored: Vec::new(), nothing_changed: Some(says) });
    }

    // The running one last, whose record is what a second run would find: a kill part way can then
    // still be finished by running this again.
    let mut outcomes = Vec::new();
    let mut why = Why::InstallFailed;
    for target in others_of_the_same_install(&exe, &record.to) {
        sweep(&target);
        let result = match kept_for(&target) {
            Ok(own) if kept_equals_target(&target, &own) => continue,
            Ok(_) => go_back(&target).map_err(|e| e.to_string()),
            Err(r) => {
                why = r.why;
                Err(r.message)
            }
        };
        outcomes.push(Outcome { component: file_name(&target), path: target.display().to_string(), error: result.err() });
    }
    let result = go_back(&exe);
    let went_back = result.is_ok();
    outcomes.push(Outcome { component: file_name(&exe), path: exe.display().to_string(), error: result.err().map(|e| e.to_string()) });
    if went_back && let Some(dir) = config_dir {
        // With `update.auto` on, the next daily check would otherwise undo this.
        notice::hold_after_rollback(dir, &record.to);
    }
    if outcomes.iter().any(|o| o.error.is_some()) {
        return Err(split_result(why, outcomes));
    }
    Ok(RollbackReport { from: Some(record.to), to: Some(record.from), restored: outcomes.into_iter().map(|o| o.path).collect(), nothing_changed: None })
}

fn no_previous(target: &Path) -> Refusal {
    Refusal::new(Why::NoPrevious, format!("there is no {} to go back to", with_suffix(target, PREVIOUS).display()))
}

/// The record of what is kept beside `target`, once what is kept has been shown to be that: a regular
/// file, no link, with the digest the record states. Anything else is a refusal, because what comes
/// back here is then run, and a rollback once installed a planted symlink as the binary.
fn kept_for(target: &Path) -> Result<Record, Refusal> {
    let previous = with_suffix(target, PREVIOUS);
    let mismatch = |what: String| Refusal::new(Why::PreviousDoesNotMatch, format!("{what}, so {} stays as it is", target.display()));
    let metadata = fs::symlink_metadata(&previous).map_err(|_| no_previous(target))?;
    if !metadata.is_file() {
        return Err(mismatch(format!("{} is not a regular file", previous.display())));
    }
    let Some(record) = read_record(target) else {
        return Err(mismatch(format!("{} has no record that reads", previous.display())));
    };
    let sum = measure(&previous).map_err(|e| mismatch(format!("{} does not read: {e}", previous.display())))?.1;
    if from_hex::<32>(&record.sha256) != Some(sum) {
        return Err(mismatch(format!("{} has sha256 {}, and its record states {}", previous.display(), to_hex(&sum), record.sha256)));
    }
    Ok(record)
}

/// What a kill between the record and the rename leaves, and what a failed commit leaves.
fn kept_equals_target(target: &Path, record: &Record) -> bool {
    measure(target).is_ok_and(|(_, sum)| from_hex::<32>(&record.sha256) == Some(sum))
}

fn go_back(target: &Path) -> io::Result<()> {
    put_in_place(&with_suffix(target, PREVIOUS), target)?;
    let _ = fs::remove_file(with_suffix(target, RECORD));
    sync_directory_of(target);
    Ok(())
}

/// Every file beside `exe`, or behind a link beside it, with a record of going to the same version.
///
/// Each record states only itself, so the others are found by looking. A stranger's file in a shared
/// `bin` does not hold such a record, and a sibling last replaced by an earlier install holds an
/// earlier `to`, so it stays where it is.
fn others_of_the_same_install(exe: &Path, to: &str) -> Vec<PathBuf> {
    let Some(entries) = exe.parent().and_then(|dir| fs::read_dir(dir).ok()) else { return Vec::new() };
    let mut found: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let Ok(Some(target)) = regular_file(&entry.path()) else { continue };
        let is_other = target != exe && !found.contains(&target);
        if is_other && read_record(&target).is_some_and(|r| r.to == to) {
            found.push(target);
        }
    }
    found.sort();
    found
}

fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned())
}

/// The file behind `path`, resolving a link the way the running binary's path is resolved, or nothing
/// if nothing is there. Anything but a regular file there is a refusal: replacing a link with a file
/// once cut a symlinked sibling off from what it pointed at.
fn regular_file(path: &Path) -> Result<Option<PathBuf>, Refusal> {
    let strange = |why: String| Refusal::new(Why::NotARegularFile, format!("{} {why}", path.display()));
    let found = match fs::symlink_metadata(path) {
        Ok(found) => found,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(strange(format!("cannot be looked at: {e}"))),
    };
    let real = if found.file_type().is_symlink() { fs::canonicalize(path).map_err(|e| strange(format!("is a link that does not resolve: {e}")))? } else { path.to_path_buf() };
    if fs::symlink_metadata(&real).is_ok_and(|m| m.is_file()) { Ok(Some(real)) } else { Err(strange("is not a regular file".to_string())) }
}

/// Held until dropped, or by the kernel until the process dies: there is no state to go stale.
fn take_lock(exe: &Path, cannot_create: impl FnOnce(&io::Error) -> Refusal) -> Result<File, Refusal> {
    let path = with_suffix(exe, LOCK);
    let file = OpenOptions::new().create(true).truncate(false).write(true).open(&path).map_err(|e| cannot_create(&e))?;
    let start = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            // A process forked just as a holder let go keeps a copy of the lock until its exec, for
            // an instant. A moment's patience, so that only a real holder is called one.
            Err(TryLockError::WouldBlock) if start.elapsed() < LOCK_PATIENCE => std::thread::sleep(Duration::from_millis(20)),
            Err(TryLockError::WouldBlock) => return Err(Refusal::new(Why::UpdateInProgress, format!("another run holds {}", path.display()))),
            Err(TryLockError::Error(e)) => return Err(Refusal::new(Why::InstallFailed, format!("cannot lock {}: {e}", path.display()))),
        }
    }
}

/// Under the lock, anything of ours beside the file is a dead run's. An aside that does not go is the
/// image of a process still running on Windows, and goes on a later run.
fn sweep(target: &Path) {
    for suffix in [NEW_FILE, PREVIOUS_NEW, RECORD_NEW] {
        let _ = fs::remove_file(with_suffix(target, suffix));
    }
    let prefix = format!("{}{ASIDE}", file_name(target));
    let Some(entries) = target.parent().and_then(|dir| fs::read_dir(dir).ok()) else { return };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// `create_new` and owner-only whatever the umask, from before the first byte: under umask 000 the
/// temporary used to be writable by anyone until the rename.
fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = create_private(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Copy `target` to `to`, closed and on the disk, and return the digest of what was copied.
fn keep_a_copy(target: &Path, to: &Path, mode: u32) -> io::Result<[u8; 32]> {
    let mut from = File::open(target)?;
    let mut copy = create_private(to)?;
    let mut digest = Context::new(&SHA256);
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let n = from.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
        copy.write_all(&buffer[..n])?;
    }
    copy.sync_all()?;
    drop(copy);
    set_mode(to, mode)?;
    Ok(finished(digest))
}

/// Size and sha256 of a file as it is now.
fn measure(path: &Path) -> io::Result<(u64, [u8; 32])> {
    let mut file = File::open(path)?;
    let mut digest = Context::new(&SHA256);
    let mut buffer = vec![0u8; 64 * 1024];
    let mut size = 0;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            return Ok((size, finished(digest)));
        }
        size += n as u64;
        digest.update(&buffer[..n]);
    }
}

fn finished(digest: Context) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.finish().as_ref());
    out
}

/// Run the new file as a user would and require the manifest's version in what it says.
///
/// This is why a garbage file that verifies is not installed: `--rollback` lives inside the file being
/// replaced, so one that cannot start cannot be gone back from. Every later `n0xis` must keep answering
/// this. A word of the output is compared, not a substring, or 9.0.1 would pass in 19.0.10.
fn answers_its_version(file: &Path, version: &str, bound: Duration) -> Result<(), Refusal> {
    let refused = |what: String| Refusal::new(Why::DoesNotRun, format!("{} {what}", file.display()));
    let start = Instant::now();
    let mut child = loop {
        let spawned = Command::new(file).arg("--version").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn();
        match spawned {
            Ok(child) => break child,
            // A fork elsewhere in this process can hold the written file for an instant.
            Err(e) if e.kind() == io::ErrorKind::ExecutableFileBusy && start.elapsed() < bound => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(refused(format!("does not start: {e}"))),
        }
    };
    // Read aside, so a child that fills the pipe cannot wedge this and one that leaves a process
    // holding the pipe cannot either.
    let (sender, said) = std::sync::mpsc::channel();
    let mut stdout = child.stdout.take().expect("piped above");
    std::thread::spawn(move || {
        let mut text = Vec::new();
        let _ = stdout.by_ref().take(64 * 1024).read_to_end(&mut text);
        let _ = sender.send(text);
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < bound => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(refused(format!("did not answer --version within {bound:?}")));
            }
            Err(e) => return Err(refused(format!("cannot be waited for: {e}"))),
        }
    };
    if !status.success() {
        return Err(refused(format!("answered --version with {status}")));
    }
    let text = said.recv_timeout(Duration::from_secs(2)).unwrap_or_default();
    let text = String::from_utf8_lossy(&text);
    if text.split_whitespace().any(|word| word == version) {
        Ok(())
    } else {
        let start: String = text.chars().filter(|c| !c.is_control()).take(80).collect();
        Err(refused(format!("answered --version without {version}: {start:?}")))
    }
}

/// A rename over the kept file just works here.
#[cfg(not(windows))]
fn replace_previous(incoming: &Path, previous: &Path) -> io::Result<()> {
    fs::rename(incoming, previous)
}

/// The kept file may be the image of a process still running from an earlier update (a long `serve`),
/// and then nothing can overwrite or delete it, though it can still be renamed out of the way.
#[cfg(windows)]
fn replace_previous(incoming: &Path, previous: &Path) -> io::Result<()> {
    if fs::rename(incoming, previous).is_ok() {
        return Ok(());
    }
    if previous.exists() {
        let target = previous.with_extension("");
        fs::rename(previous, with_suffix(&target, &format!("{ASIDE}previous-{}", std::process::id())))?;
    }
    fs::rename(incoming, previous)
}

/// One rename: the target is the old file or the new at every moment, and a command started during
/// this finds a binary.
#[cfg(not(windows))]
fn put_in_place(incoming: &Path, target: &Path) -> io::Result<()> {
    fs::rename(incoming, target)
}

/// A running `.exe` can be renamed and not overwritten, so it is renamed aside first, and for the
/// moment between the two renames there is no target. That window cannot be closed on this platform,
/// and the specification says so.
#[cfg(windows)]
fn put_in_place(incoming: &Path, target: &Path) -> io::Result<()> {
    let aside = with_suffix(target, &format!("{ASIDE}{}", std::process::id()));
    fs::rename(target, &aside)?;
    if let Err(e) = fs::rename(incoming, target) {
        return Err(match fs::rename(&aside, target) {
            Ok(()) => e,
            Err(back) => io::Error::other(format!("{e}, and the old file could not be renamed back from {}: {back}", aside.display())),
        });
    }
    // The running image stays until a later run's sweep.
    let _ = fs::remove_file(&aside);
    Ok(())
}

/// So the rename survives a power cut too. A failure here is not a failure of the install: the file
/// is in place, and saying otherwise would be false.
fn sync_directory_of(target: &Path) {
    #[cfg(unix)]
    if let Some(dir) = target.parent()
        && let Ok(dir) = File::open(dir)
    {
        let _ = dir.sync_all();
    }
    #[cfg(not(unix))]
    let _ = target;
}

#[cfg(unix)]
fn plain_mode(target: &Path) -> io::Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::metadata(target)?.permissions().mode() & 0o777)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn plain_mode(_target: &Path) -> io::Result<u32> {
    Ok(0)
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

/// The refusal of a directory the user cannot write: it names the file to fetch, and never `sudo`.
fn not_writable(target: &Path, entry: &Entry, e: &io::Error) -> Refusal {
    Refusal::new(Why::NotWritable, format!("{} cannot be replaced from here: {e}", target.display()))
        .with_hint(format!("fetch {} ({} bytes, sha256 {}) and put it at {} yourself", entry.url, entry.size, to_hex(&entry.sha256), target.display()))
}
