// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Putting a file in place, and going back.
//!
//! The order is the safety: the file downloads next to the binary, its size and digest are checked
//! against a manifest whose signature has already verified, and only then does anything move, by
//! rename. Until that last step the installed file has not been touched, so every refusal
//! leaves it byte for byte as it was.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::manifest::Entry;
use crate::{Refusal, Updater, Why, notice, sha256, to_hex};

/// Beside each file: what `--rollback` goes back to. Startup never deletes it, or rollback would be
/// unreachable by construction.
const PREVIOUS_SUFFIX: &str = ".previous";
/// Beside the running binary: what the last install or rollback did, for the next rollback.
const RECORD_SUFFIX: &str = ".previous.json";

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// A file that goes away unless it is moved first.
struct Temp(PathBuf);

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[derive(Serialize, Deserialize)]
struct Record {
    from: String,
    to: String,
    /// The installed names of the other files replaced, which rollback cannot learn elsewhere:
    /// it needs no network, and scanning a shared `bin` for `*.previous` would catch strangers.
    #[serde(default)]
    others: Vec<String>,
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

/// What `n0x update --rollback` answers.
#[derive(Clone, Debug, Serialize)]
pub struct RollbackReport {
    /// Unknown when the record beside the binary is missing; the files were still swapped.
    pub from: Option<String>,
    pub to: Option<String>,
    pub restored: Vec<String>,
}

struct Planned {
    component: String,
    target: PathBuf,
    entry: Entry,
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
        let mut changing = Vec::new();
        for item in plan {
            if digest_of(&item.target).is_some_and(|sum| sum == item.entry.sha256) {
                report.unchanged.push(item.component);
            } else {
                changing.push(item);
            }
        }

        // All of them are fetched and checked before any is moved, so a bad second file cannot
        // leave the first one installed.
        let mut ready = Vec::new();
        for item in &changing {
            ready.push(self.fetch_checked(item)?);
        }
        let others: Vec<String> = changing.iter().filter(|i| i.target != self.exe).filter_map(|i| i.entry.file.clone()).collect();
        let record = Record { from: report.from.clone(), to: report.to.clone(), others };
        self.swap_all(&changing, &ready, &record)?;
        report.replaced = changing
            .into_iter()
            .map(|i| Replaced { component: i.component, path: i.target.display().to_string(), size: i.entry.size, sha256: to_hex(&i.entry.sha256) })
            .collect();
        if let Some(dir) = &self.config_dir {
            notice::clear_hold(dir);
        }
        Ok(report)
    }

    /// The running component always, and each other one only if a file of its name is already
    /// beside the binary: this replaces what is installed and adds nothing.
    fn plan(&self, manifest: &crate::Manifest) -> Result<Vec<Planned>, Refusal> {
        let entry = manifest.entry(&self.component, &self.platform)?;
        let dir = self.exe.parent().ok_or_else(|| Refusal::new(Why::InstallFailed, format!("{} has no directory", self.exe.display())))?;
        if !self.exe.is_file() {
            return Err(Refusal::new(Why::InstallFailed, format!("{} is not there to replace", self.exe.display())));
        }
        let mut plan = vec![Planned { component: self.component.clone(), target: self.exe.clone(), entry }];
        for (name, raw, file) in manifest.others(&self.component, &self.platform) {
            // Only the file name is looked at here, and `decode` refuses one that is not a bare name.
            let target = dir.join(file);
            if target != self.exe && target.is_file() {
                plan.push(Planned { component: name.to_string(), target, entry: Entry::decode(name, raw)? });
            }
        }
        Ok(plan)
    }

    /// Download one file next to its target and check it. The file left behind has the target's
    /// permissions and is closed, ready to be renamed.
    fn fetch_checked(&self, item: &Planned) -> Result<Temp, Refusal> {
        let temp_path = with_suffix(&item.target, &format!(".update-{}.tmp", std::process::id()));
        // Before the download, so a directory that cannot be written costs no request for the file.
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&temp_path) {
            Ok(file) => file,
            Err(e) => return Err(not_writable(&item.target, &item.entry, &e)),
        };
        let temp = Temp(temp_path);
        let sum = self.transport.download(&item.entry.url, item.entry.size, &mut file)?;
        if sum != item.entry.sha256 {
            return Err(Refusal::new(
                Why::DigestMismatch,
                format!("{} has sha256 {}, and the manifest states {}", item.entry.url, to_hex(&sum), to_hex(&item.entry.sha256)),
            ));
        }
        finish_writing(file, &item.target, &temp.0).map_err(|e| not_writable(&item.target, &item.entry, &e))?;
        Ok(temp)
    }

    /// Every file or none: a failure part way puts back what had already moved.
    fn swap_all(&self, plan: &[Planned], ready: &[Temp], record: &Record) -> Result<(), Refusal> {
        let mut done: Vec<&Planned> = Vec::new();
        let outcome = (|| -> io::Result<()> {
            for (item, temp) in plan.iter().zip(ready) {
                let previous = with_suffix(&item.target, PREVIOUS_SUFFIX);
                free_previous(&previous)?;
                swap_in(&item.target, &temp.0, &previous)?;
                done.push(item);
            }
            write_record(&self.exe, record)
        })();
        outcome.map_err(|e| {
            for item in done.iter().rev() {
                let previous = with_suffix(&item.target, PREVIOUS_SUFFIX);
                let _ = swap_in(&item.target, &previous, &previous);
            }
            Refusal::new(Why::InstallFailed, format!("moving the new file into place: {e}; the installed files were put back"))
        })
    }
}

/// `n0x update --rollback`: back to the file kept beside `exe`. It needs no network, and running it
/// twice returns to where it started.
pub fn rollback(exe: &Path, config_dir: Option<&Path>) -> Result<RollbackReport, Refusal> {
    let previous = with_suffix(exe, PREVIOUS_SUFFIX);
    if !previous.is_file() {
        return Err(Refusal::new(Why::NoPrevious, format!("there is no {} to go back to", previous.display())));
    }
    let record: Option<Record> = fs::read(with_suffix(exe, RECORD_SUFFIX)).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let mut targets = vec![exe.to_path_buf()];
    if let (Some(record), Some(dir)) = (&record, exe.parent()) {
        for file in &record.others {
            let target = dir.join(file);
            if crate::manifest::is_bare_file_name(file) && with_suffix(&target, PREVIOUS_SUFFIX).is_file() {
                targets.push(target);
            }
        }
    }
    let mut done: Vec<&PathBuf> = Vec::new();
    for target in &targets {
        let kept = with_suffix(target, PREVIOUS_SUFFIX);
        if let Err(e) = swap_in(target, &kept, &kept) {
            for back in done.iter().rev() {
                let kept = with_suffix(back, PREVIOUS_SUFFIX);
                let _ = swap_in(back, &kept, &kept);
            }
            return Err(Refusal::new(Why::InstallFailed, format!("going back: {e}; the installed files were put back")));
        }
        done.push(target);
    }
    let report = RollbackReport {
        from: record.as_ref().map(|r| r.to.clone()),
        to: record.as_ref().map(|r| r.from.clone()),
        restored: targets.iter().map(|t| t.display().to_string()).collect(),
    };
    if let Some(record) = record {
        // A second rollback goes forward again, so the record now reads the other way round.
        let turned = Record { from: record.to.clone(), to: record.from, others: record.others };
        let _ = write_record(exe, &turned);
        if let Some(dir) = config_dir {
            // With `update.auto` on, the next daily check would otherwise undo this.
            notice::hold_after_rollback(dir, &record.to);
        }
    }
    Ok(report)
}

/// Put `incoming` at `target` and what `target` held at `previous`, restoring `target` on failure.
///
/// `incoming` and `previous` are the same path for a rollback, and that works: the old contents go
/// aside first and reach `previous` last.
///
/// Off Windows the old contents are copied aside, so that `target` exists at every moment and a
/// command started during this finds a binary. On Windows a running `.exe` can be renamed and not
/// overwritten, so it is renamed aside, which is the one thing that can be done.
fn swap_in(target: &Path, incoming: &Path, previous: &Path) -> io::Result<()> {
    let aside = with_suffix(target, &format!(".aside-{}", std::process::id()));
    set_aside(target, &aside)?;
    if let Err(e) = fs::rename(incoming, target) {
        let _ = restore_aside(&aside, target);
        return Err(e);
    }
    if let Err(e) = fs::rename(&aside, previous) {
        // The new file stays what it was given as, so the caller's cleanup still finds it.
        let _ = fs::rename(target, incoming);
        let _ = fs::rename(&aside, target);
        return Err(e);
    }
    Ok(())
}

#[cfg(not(windows))]
fn set_aside(target: &Path, aside: &Path) -> io::Result<()> {
    fs::copy(target, aside).map(|_| ())
}

#[cfg(windows)]
fn set_aside(target: &Path, aside: &Path) -> io::Result<()> {
    fs::rename(target, aside)
}

#[cfg(not(windows))]
fn restore_aside(aside: &Path, _target: &Path) -> io::Result<()> {
    fs::remove_file(aside)
}

#[cfg(windows)]
fn restore_aside(aside: &Path, target: &Path) -> io::Result<()> {
    fs::rename(aside, target)
}

/// On Windows the kept file may be the image of a process still running from an earlier update (a
/// long `serve`), and then nothing can overwrite or delete it, though it can still be renamed. It is
/// moved out of the way before anything else moves, since finding this out only after the new file
/// is in place would leave nowhere for the old one to go.
#[cfg(windows)]
fn free_previous(previous: &Path) -> io::Result<()> {
    if !previous.exists() || fs::remove_file(previous).is_ok() {
        return Ok(());
    }
    let stale = with_suffix(previous, &format!(".stale-{}", std::process::id()));
    fs::rename(previous, &stale)?;
    let _ = fs::remove_file(&stale);
    Ok(())
}

/// A rename over the kept file just works here, and only once the new file is in place.
#[cfg(not(windows))]
fn free_previous(_previous: &Path) -> io::Result<()> {
    Ok(())
}

fn write_record(exe: &Path, record: &Record) -> io::Result<()> {
    let text = serde_json::to_vec_pretty(record).map_err(io::Error::other)?;
    crate::write_by_rename(&with_suffix(exe, RECORD_SUFFIX), &text)
}

/// Flush, close, and take on the target's permissions, so a replaced binary still runs.
fn finish_writing(mut file: File, target: &Path, temp: &Path) -> io::Result<()> {
    file.flush()?;
    file.sync_all()?;
    drop(file);
    fs::set_permissions(temp, fs::metadata(target)?.permissions())
}

/// The refusal of a directory the user cannot write: it names the file to fetch, and never `sudo`.
fn not_writable(target: &Path, entry: &Entry, e: &io::Error) -> Refusal {
    Refusal::new(Why::NotWritable, format!("{} cannot be replaced from here: {e}", target.display()))
        .with_hint(format!("fetch {} ({} bytes, sha256 {}) and put it at {} yourself", entry.url, entry.size, to_hex(&entry.sha256), target.display()))
}

fn digest_of(path: &Path) -> Option<[u8; 32]> {
    fs::read(path).ok().map(|bytes| sha256(&bytes))
}
