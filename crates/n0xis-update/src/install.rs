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
//!
//! **A rollback is one file.** It once looked for every record beside the binary and moved what it
//! found, which moved other copies, reported a stranger's record as a refusal after the binary had
//! gone back, and left a sibling behind on a re-run. What it does not look for it cannot get wrong.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ring::digest::{Context, SHA256};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::manifest::{Entry, is_bare_file_name};
use crate::{Found, Held, Refusal, Updater, Why, from_hex, to_hex};

/// Beside each file: what `--rollback` goes back to. Startup never deletes it, or rollback would be
/// unreachable by construction.
const PREVIOUS: &str = ".previous";
/// Beside each file, not in the configuration directory, so that two copies do not share one and it
/// needs no configuration: what `.previous` is.
const RECORD: &str = ".previous.json";
/// Beside the running binary, and it stays: the kernel releases the lock on a kill, whoever holds it.
const LOCK: &str = ".update-lock";
const LOCK_PATIENCE: Duration = Duration::from_millis(500);
/// Beside each file: the version `--rollback` went back from, which `update.auto` leaves alone. Here and
/// not in the state file, because a check in flight rewrites that file and once wrote a hold away, and
/// so that it needs no configuration directory.
const HOLD: &str = ".update-hold";
/// While preparing. Fixed and exact names, because under the lock these are a dead run's and nothing
/// else is: a sweep by prefix once removed a user's `n0xis.aside-notes.txt`.
///
/// On Windows the candidate's name ends in `.exe`. Asked to start a name without it, the process API
/// looks for that name with `.exe` added first, so a file planted at `n0xis.exe.update-new.exe` ran in
/// place of the file just checked.
#[cfg(not(windows))]
const NEW_FILE: &str = ".update-new";
#[cfg(windows)]
const NEW_FILE: &str = ".update-new.exe";
const PREVIOUS_NEW: &str = ".previous-new";
const RECORD_NEW: &str = ".previous.json.new";
const HOLD_NEW: &str = ".update-hold-new";
/// On Windows only, with digits, since a running exe can be renamed and not removed.
#[cfg(windows)]
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

/// What `.previous` is, and what was installed in its place. The versions are read as versions and
/// the digests as digests, or there is no record, because these reach the envelope and the hold.
#[derive(Serialize, Deserialize)]
struct Record {
    /// The version the running file said it was as it replaced itself. Null for a sibling, which is
    /// never executed: this once held the running binary's version, and a rollback then stated that a
    /// file had gone back to a version it had never been.
    from: Option<String>,
    /// The manifest's version, which is what a hold is compared with.
    to: String,
    previous_sha256: String,
    /// Of the target this install left. Anything else there came by other means, and going back over
    /// it would destroy a file nothing keeps.
    installed_sha256: String,
}

fn read_record(target: &Path) -> Result<Record, String> {
    let path = with_suffix(target, RECORD);
    let bytes = read_ours(&path).map_err(|e| format!("its record {} cannot be used: {e}", path.display()))?;
    let unreadable = || format!("its record {} does not read", path.display());
    let record: Record = serde_json::from_slice(&bytes).map_err(|_| unreadable())?;
    let reads = record.from.as_deref().is_none_or(|from| Version::parse(from).is_ok()) && Version::parse(&record.to).is_ok() && from_hex::<32>(&record.previous_sha256).is_some() && from_hex::<32>(&record.installed_sha256).is_some();
    if reads { Ok(record) } else { Err(unreadable()) }
}

/// Why opening a file of ours failed.
enum Unusable {
    /// A link, a FIFO, anything but a regular file, or another user's. On Windows a plain open finds
    /// no such thing.
    #[cfg_attr(not(unix), allow(dead_code))]
    NotOurs(&'static str),
    Failed(io::Error),
}

impl std::fmt::Display for Unusable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unusable::NotOurs(what) => f.write_str(what),
            Unusable::Failed(e) => e.fmt(f),
        }
    }
}

/// What is wrong with a file found where one of ours belongs, if anything. The one test of it, on what
/// was opened and on what could not be.
#[cfg(unix)]
fn not_ours(found: &fs::Metadata) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    if !found.is_file() {
        return Some("is not a regular file");
    }
    // SAFETY: geteuid takes nothing and cannot fail.
    if found.uid() != unsafe { libc::geteuid() } {
        return Some("belongs to another user");
    }
    None
}

/// Open a file beside the binary that this client reads or locks. In a sticky directory anyone can plant
/// one, so that it decides nothing unless it is this user's: a link would be followed, a FIFO would
/// hang the run with the lock held, and another user's record could vouch for another user's `.previous`.
/// `O_NONBLOCK` is there for the FIFO: it is seen and refused, rather than waited on.
#[cfg(unix)]
fn open_ours(path: &Path, options: &mut OpenOptions) -> Result<File, Unusable> {
    use std::os::unix::fs::OpenOptionsExt;
    let opened = options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path);
    let file = opened.map_err(|e| match fs::symlink_metadata(path).ok().as_ref().and_then(not_ours) {
        Some(what) => Unusable::NotOurs(what),
        None => Unusable::Failed(e),
    })?;
    if let Some(what) = not_ours(&file.metadata().map_err(Unusable::Failed)?) {
        return Err(Unusable::NotOurs(what));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_ours(path: &Path, options: &mut OpenOptions) -> Result<File, Unusable> {
    options.open(path).map_err(Unusable::Failed)
}

fn read_ours(path: &Path) -> Result<Vec<u8>, Unusable> {
    let mut file = open_ours(path, OpenOptions::new().read(true))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(Unusable::Failed)?;
    Ok(bytes)
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
    /// Components left as they are, each with why. Nothing about a sibling stops the running file, or a
    /// later component of a new shape would stop every old copy.
    pub skipped: Vec<Skipped>,
    pub address: String,
    pub tried: Vec<crate::Tried>,
}

/// A component this install left alone.
#[derive(Clone, Debug, Serialize)]
pub struct Skipped {
    pub component: String,
    /// The refusal it would have been, by its code.
    pub code: &'static str,
    pub reason: String,
}

impl Skipped {
    fn of(component: &str, refusal: Refusal) -> Skipped {
        Skipped { component: component.to_string(), code: refusal.why.code(), reason: refusal.message }
    }
}

/// What `n0x update --rollback` answers, about the one file it was asked about. `from` and `to` come
/// only from a record that matched, and one of a sibling states neither, since no one ran that file:
/// what it says of a sibling is the file and the digest.
#[derive(Clone, Debug, Serialize)]
pub struct RollbackReport {
    pub file: String,
    pub from: Option<String>,
    pub to: Option<String>,
    /// Of the file there now.
    pub sha256: String,
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

/// Who asked. `update.auto` leaves what a hold names alone; `n0x update` installs it and ends the hold.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Asked {
    User,
    Auto,
}

/// A file as it looks from outside. Before a fetch, since that is what can take a minute with nothing
/// held: a rollback or another updater landing in it left `self.current` no longer what is there, so the
/// record stated a `from` that was false, and a file gone back from moved forward regardless. The standard
/// library has no number for a file on Windows, so there it is the other two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Seen {
    #[cfg(unix)]
    inode: u64,
    size: u64,
    modified: Option<std::time::SystemTime>,
}

impl Seen {
    /// Nothing, if nothing is there: which `plan` refuses, and which anything found later differs from.
    pub(crate) fn of(path: &Path) -> Option<Seen> {
        let found = fs::metadata(path).ok()?;
        Some(Seen {
            #[cfg(unix)]
            inode: std::os::unix::fs::MetadataExt::ino(&found),
            size: found.len(),
            modified: found.modified().ok(),
        })
    }
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
        self.install(&found, Asked::User)
    }

    /// `update.auto`, with the manifest the check already fetched. A second fetch once saw something
    /// else: the check said one version, the install did another, and the line claimed the first.
    pub(crate) fn install_alone(&self, found: &Found) -> Result<UpdateReport, Refusal> {
        self.install(found, Asked::Auto)
    }

    fn install(&self, found: &Found, asked: Asked) -> Result<UpdateReport, Refusal> {
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
            skipped: Vec::new(),
            address: found.address.clone(),
            tried: found.tried.clone(),
        };
        if manifest.version == self.current {
            return Ok(report);
        }

        let plan = self.plan(manifest, &mut report.skipped)?;
        // What is installed is read only now, under the lock. Read before it, a run that waited out
        // another would go on to keep the new file as `.previous` and lose the old one. The running
        // file comes first, and only it can refuse. Each file has its own lock, since a rollback of a
        // sibling takes that one and nothing else.
        let mut locks = Vec::new();
        let mut changing = Vec::new();
        for item in plan {
            match lock_for_install(&item, asked, &manifest.version) {
                Ok(lock) => locks.push(lock),
                Err(r) if item.runs && r.why == Why::Held => {
                    report.skipped.push(Skipped::of(&item.component, r));
                    return Ok(report);
                }
                Err(r) if item.runs => return Err(r),
                Err(r) => {
                    report.skipped.push(Skipped::of(&item.component, r));
                    continue;
                }
            }
            // Already the file named is said first, since moving nothing is true however it got there:
            // a run that waited out another at the lock answers `unchanged`.
            if measure(&item.target).is_ok_and(|(_, sum)| sum == item.entry.sha256) {
                report.unchanged.push(item.component);
            } else if item.runs && Seen::of(&item.target) != found.before {
                return Err(changed_during_update(&item.target));
            } else {
                changing.push(item);
            }
        }
        for item in &changing {
            sweep(&item.target);
        }
        let mut prepared = Vec::new();
        for item in changing {
            match self.prepare(&item, &report) {
                Ok(files) => prepared.push((item, files)),
                Err(r) if item.runs => return Err(said_after_prepare(r, &item)),
                Err(r) => report.skipped.push(Skipped::of(&item.component, r)),
            }
        }

        // The running component last. A run killed part way is then still the old binary, and running
        // it again finishes the job, since what is already in place is `unchanged`; the other order
        // leaves a new binary that sees nothing to do and a sibling stranded until the next release.
        let mut outcomes = Vec::new();
        for (item, files) in prepared.iter().rev() {
            let result = commit(item, files);
            if result.is_ok() && asked == Asked::User {
                // A failure leaves a hold on what is now installed, which holds nothing back.
                let _ = fs::remove_file(with_suffix(&item.target, HOLD));
            }
            outcomes.push(Outcome { component: item.component.clone(), path: item.target.display().to_string(), error: result.err().map(|e| e.to_string()) });
        }
        outcomes.reverse();
        if outcomes.iter().any(|o| o.error.is_some()) {
            return Err(split_result(Why::InstallFailed, outcomes));
        }
        report.replaced = prepared
            .into_iter()
            .map(|(i, _)| Replaced { component: i.component, path: i.target.display().to_string(), size: i.entry.size, sha256: to_hex(&i.entry.sha256) })
            .collect();
        Ok(report)
    }

    /// The file the running binary's path leads to, where its lock goes.
    fn exe_target(&self) -> Result<PathBuf, Refusal> {
        regular_file(&self.exe)?.ok_or_else(|| Refusal::new(Why::InstallFailed, format!("{} is not there to replace", self.exe.display())))
    }

    /// The running component always, and each other one only if a file of its name is already
    /// beside the binary: this replaces what is installed and adds nothing. Only the running
    /// component's own entry can refuse; anything wrong with another makes that one `skipped`.
    fn plan(&self, manifest: &crate::Manifest, skipped: &mut Vec<Skipped>) -> Result<Vec<Planned>, Refusal> {
        let entry = manifest.entry(&self.component, &self.platform)?;
        let exe = self.exe_target()?;
        let dir = self.exe.parent().ok_or_else(|| Refusal::new(Why::InstallFailed, format!("{} has no directory", self.exe.display())))?;
        let mut plan = vec![Planned { component: self.component.clone(), target: exe, entry, runs: true }];
        for (name, raw, file) in manifest.others(&self.component, &self.platform) {
            match sibling(dir, name, raw, file) {
                // Two names for one file are one file, and it has one previous.
                Ok(Some(item)) if plan.iter().all(|p| p.target != item.target) => plan.push(item),
                Ok(_) => {}
                Err(r) => skipped.push(Skipped::of(name, r)),
            }
        }
        Ok(plan)
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
        let record = Record { from: item.runs.then(|| report.from.clone()), to: report.to.clone(), previous_sha256: to_hex(&kept), installed_sha256: to_hex(&sum) };
        let text = serde_json::to_vec_pretty(&record).map_err(|e| disk(io::Error::other(e)))?;
        write_private(&record_new.0, &text).map_err(disk)?;
        Ok(Prepared { new_file, previous_new, record_new })
    }
}

/// A component other than the running one, if a file of its name is beside the binary. Its name is
/// looked at first, so that nothing outside the directory is even asked about.
fn sibling(dir: &Path, name: &str, raw: &serde_json::Value, file: &str) -> Result<Option<Planned>, Refusal> {
    if !is_bare_file_name(file) {
        return Err(Refusal::new(Why::BadManifest, format!("{name}: the file name is not a bare name")));
    }
    let Some(target) = regular_file(&dir.join(file))? else { return Ok(None) };
    Ok(Some(Planned { component: name.to_string(), target, entry: Entry::decode(name, raw)?, runs: false }))
}

/// This file's own lock, and under it its hold. A hold that does not read decides nothing in favour of
/// installing: `update.auto` turned on by a user must not undo what that user went back from.
fn lock_for_install(item: &Planned, asked: Asked, version: &Version) -> Result<Held, Refusal> {
    let lock = take_lock(&item.target, |e| not_writable(&item.target, &item.entry, e))?;
    if asked == Asked::Auto {
        let path = with_suffix(&item.target, HOLD);
        let held = match read_ours(&path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).trim().parse::<Version>().map_err(|e| Refusal::new(Why::NotOurs, format!("{} does not read as a version: {e}", path.display())))?,
            Err(Unusable::Failed(e)) if e.kind() == io::ErrorKind::NotFound => return Ok(lock),
            Err(e) => return Err(Refusal::new(Why::NotOurs, format!("{} {e}", path.display()))),
        };
        if *version <= held {
            return Err(Refusal::new(Why::Held, format!("--rollback went back from {held}, so update.auto leaves {version} alone; n0x update installs it")));
        }
    }
    Ok(lock)
}

fn changed_during_update(target: &Path) -> Refusal {
    Refusal::new(Why::ChangedDuringUpdate, format!("{} was replaced while the manifest was being fetched, so it stays as it is", target.display())).with_hint("n0x update looks again")
}

/// Only when the temps are gone is the sentence said, and it is checked rather than assumed. A sibling
/// only ever follows the running file, which is prepared first, so this one is the only one prepared.
fn said_after_prepare(mut refusal: Refusal, item: &Planned) -> Refusal {
    let left: Vec<String> =
        [NEW_FILE, PREVIOUS_NEW, RECORD_NEW].map(|suffix| with_suffix(&item.target, suffix)).iter().filter(|path| fs::symlink_metadata(path).is_ok()).map(|path| path.display().to_string()).collect();
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
    replace_previous(&files.previous_new.0, &item.target)?;
    fs::rename(&files.record_new.0, with_suffix(&item.target, RECORD))?;
    put_in_place(&files.new_file.0, &item.target)?;
    sync_directory_of(&item.target);
    Ok(())
}

/// `n0x update --rollback`: back to the file kept beside `exe`, or beside the file called `name` next
/// to it, and that file alone, with its own record and lock. It needs no network and no configuration,
/// and it is one shot: the file gone back from is not kept, so a second run says there is nothing to go
/// back to and never goes forward.
pub fn rollback(exe: &Path, name: Option<&str>) -> Result<RollbackReport, Refusal> {
    let beside = match name {
        None => exe.to_path_buf(),
        Some(name) if is_bare_file_name(name) => exe.with_file_name(name),
        Some(name) => return Err(Refusal::new(Why::NotABareName, format!("{name:?} is not a file beside this binary: --rollback takes a bare name"))),
    };
    let Some(target) = regular_file(&beside)? else { return Err(no_previous(&beside)) };
    // Before the lock, so that asking with nothing kept leaves no file behind.
    if fs::symlink_metadata(with_suffix(&target, PREVIOUS)).is_err() {
        return Err(no_previous(&target));
    }
    let _lock = take_lock(&target, |e| Refusal::new(Why::NotWritable, format!("{} cannot be replaced from here: {e}", target.display())))?;
    sweep(&target);
    let record = kept_for(&target)?;
    let file = target.display().to_string();
    let installed = measure(&target).map_err(|e| Refusal::new(Why::InstallFailed, format!("{file} does not read: {e}")))?.1;
    let (installed_hex, previous) = (to_hex(&installed), with_suffix(&target, PREVIOUS));
    // What a kill between the record and the rename leaves, and what a failed commit leaves.
    if installed_hex == record.previous_sha256 {
        let says = format!("{} is what is already installed, so nothing changed: an install that died before its last step leaves this", previous.display());
        return Ok(RollbackReport { file, from: None, to: None, sha256: installed_hex, nothing_changed: Some(says) });
    }
    if installed_hex != record.installed_sha256 {
        return Err(Refusal::new(
            Why::NotWhatWasInstalled,
            format!("{file} has sha256 {installed_hex}, and the last update installed {}: a file was put there by other means, so it and {} stay as they are", record.installed_sha256, previous.display()),
        ));
    }
    // Before the swap, or a kill between the two leaves a rollback the next check undoes. A kill here
    // leaves the target as it was, and a re-run finishes.
    write_hold(&target, &record.to)?;
    put_in_place(&previous, &target).map_err(|e| Refusal::new(Why::InstallFailed, format!("{file} could not be put back: {e}; it is as it was")))?;
    let _ = fs::remove_file(with_suffix(&target, RECORD));
    sync_directory_of(&target);
    let (from, to) = match record.from {
        Some(went_to) => (Some(record.to), Some(went_to)),
        None => (None, None),
    };
    Ok(RollbackReport { file, from, to, sha256: record.previous_sha256, nothing_changed: None })
}

/// By rename, under the lock. It cannot be written means nothing moves: a rollback the next check would
/// undo is not one.
fn write_hold(target: &Path, version: &str) -> Result<(), Refusal> {
    let temp = Temp(with_suffix(target, HOLD_NEW));
    let path = with_suffix(target, HOLD);
    write_private(&temp.0, version.as_bytes())
        .and_then(|()| fs::rename(&temp.0, &path))
        .map_err(|e| Refusal::new(Why::NotWritable, format!("{} cannot be written, so {} stays as it is: {e}", path.display(), target.display())))?;
    sync_directory_of(target);
    Ok(())
}

fn no_previous(target: &Path) -> Refusal {
    Refusal::new(Why::NoPrevious, format!("there is no {} to go back to", with_suffix(target, PREVIOUS).display()))
}

/// The record of what is kept beside `target`, once what is kept has been shown to be that: a regular
/// file of this user's, no link, with the digest the record states. Anything else is a refusal, because
/// what comes back here is then run, and a rollback once installed a planted symlink as the binary.
fn kept_for(target: &Path) -> Result<Record, Refusal> {
    let previous = with_suffix(target, PREVIOUS);
    let mismatch = |what: String| Refusal::new(Why::PreviousDoesNotMatch, format!("{what}, so {} stays as it is", target.display()));
    let kept = match open_ours(&previous, OpenOptions::new().read(true)) {
        Ok(kept) => kept,
        Err(Unusable::Failed(e)) if e.kind() == io::ErrorKind::NotFound => return Err(no_previous(target)),
        Err(e) => return Err(mismatch(format!("{} {e}", previous.display()))),
    };
    let record = read_record(target).map_err(|e| mismatch(format!("{} cannot be vouched for: {e}", previous.display())))?;
    let sum = digest_of(kept).map_err(|e| mismatch(format!("{} does not read: {e}", previous.display())))?.1;
    if from_hex::<32>(&record.previous_sha256) != Some(sum) {
        return Err(mismatch(format!("{} has sha256 {}, and its record states {}", previous.display(), to_hex(&sum), record.previous_sha256)));
    }
    Ok(record)
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

/// The name an install knows the file at `path` by, for telling whether it is this one.
pub(crate) fn file_at(path: &Path) -> Option<String> {
    regular_file(path).ok().flatten().map(|file| file.display().to_string())
}

/// Held until dropped, or by the kernel until the process dies: there is no state to go stale.
fn take_lock(target: &Path, cannot_create: impl FnOnce(&io::Error) -> Refusal) -> Result<Held, Refusal> {
    let path = with_suffix(target, LOCK);
    let file = open_ours(&path, OpenOptions::new().create(true).truncate(false).write(true)).map_err(|e| match e {
        Unusable::NotOurs(what) => Refusal::new(Why::NotOurs, format!("{} {what}, so it is not a lock this client takes", path.display())),
        Unusable::Failed(e) => cannot_create(&e),
    })?;
    let start = Instant::now();
    let mut file = file;
    loop {
        match Held::try_take(file) {
            Ok(held) => return Ok(held),
            // A holder that lets go by its close, as one killed does and as a client before `Held`
            // did, leaves the lock with whatever process its own forked just then, until that one's
            // exec. A moment's patience, so that only a real holder is called one.
            Err((back, TryLockError::WouldBlock)) if start.elapsed() < LOCK_PATIENCE => {
                file = back;
                std::thread::sleep(Duration::from_millis(20));
            }
            Err((_, TryLockError::WouldBlock)) => return Err(Refusal::new(Why::UpdateInProgress, format!("another run holds {}", path.display()))),
            Err((_, TryLockError::Error(e))) => return Err(Refusal::new(Why::InstallFailed, format!("cannot lock {}: {e}", path.display()))),
        }
    }
}

/// Under the lock, these exact names are a dead run's, and nothing else is.
fn sweep(target: &Path) {
    for suffix in [NEW_FILE, PREVIOUS_NEW, RECORD_NEW, HOLD_NEW] {
        let _ = fs::remove_file(with_suffix(target, suffix));
    }
    sweep_asides(target);
}

#[cfg(not(windows))]
fn sweep_asides(_target: &Path) {}

/// `<file>.aside-<digits>`, of which one that does not go is the image of a process still running and
/// goes on a later run.
#[cfg(windows)]
fn sweep_asides(target: &Path) {
    let Some(name) = target.file_name().and_then(|n| n.to_str()) else { return };
    let prefix = format!("{name}{ASIDE}");
    let Some(entries) = target.parent().and_then(|dir| fs::read_dir(dir).ok()) else { return };
    for entry in entries.flatten() {
        let found = entry.file_name();
        let digits = found.to_str().and_then(|n| n.strip_prefix(prefix.as_str()));
        if digits.is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())) {
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
    digest_of(File::open(path)?)
}

fn digest_of(mut file: File) -> io::Result<(u64, [u8; 32])> {
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
///
/// By absolute path always, so that nothing searches for it: a bare name would be looked for on `PATH`.
fn answers_its_version(file: &Path, version: &str, bound: Duration) -> Result<(), Refusal> {
    let refused = |what: String| Refusal::new(Why::DoesNotRun, format!("{} {what}", file.display()));
    let file = std::path::absolute(file).map_err(|e| refused(format!("has no absolute path: {e}")))?;
    let start = Instant::now();
    let mut child = loop {
        let spawned = Command::new(&file).arg("--version").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn();
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
fn replace_previous(incoming: &Path, target: &Path) -> io::Result<()> {
    fs::rename(incoming, with_suffix(target, PREVIOUS))
}

/// The kept file may be the image of a process still running from an earlier update (a long `serve`),
/// and then nothing can overwrite or delete it, though it can still be renamed out of the way.
#[cfg(windows)]
fn replace_previous(incoming: &Path, target: &Path) -> io::Result<()> {
    let previous = with_suffix(target, PREVIOUS);
    if fs::rename(incoming, &previous).is_ok() {
        return Ok(());
    }
    if previous.exists() {
        fs::rename(&previous, free_aside(target))?;
    }
    fs::rename(incoming, &previous)
}

/// The first free `<file>.aside-<digits>` from this pid: an aside still running blocks its name, and
/// one run can need two.
#[cfg(windows)]
fn free_aside(target: &Path) -> PathBuf {
    (u64::from(std::process::id())..).map(|n| with_suffix(target, &format!("{ASIDE}{n}"))).find(|path| !path.exists()).expect("a free number")
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
    let aside = free_aside(target);
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
