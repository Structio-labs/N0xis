// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A content-addressed store under `.n0x/<dir>/<key>.json`: raw JSON in, raw
//! JSON out. The caller owns the key (a hash of everything the entry answers
//! for, prefixed with the analyzer generation) and the type stored. Each kind
//! of entry has its own directory, so one kind's generation sweep never
//! deletes another's.
//!
//! The IR cache, the decompile cache and the reference index each carry their
//! own copy of this code; new kinds use this one.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::resolve;

/// Replace the contents of the file at `path` with `contents` so that no
/// reader, and no interruption, ever sees anything but the old contents or
/// the new: written in full to a temporary file in the same directory,
/// flushed to the disk, then renamed over the old one, which is one step for
/// the file system. A `fs::write` in place truncates first, so a save
/// interrupted between the truncation and the last write leaves an empty or
/// a partial file — for the plugin registry, an empty `plugins.json`.
///
/// The rule is stated once, here; [`Store::put`] and the plugin registry use
/// it. (The IR cache, the decompile cache and the reference index still
/// carry their own copies, as this module's doc says.)
///
/// What an in-place write did that a rename would not, and is kept:
/// - a symbolic link at `path` is written through, as `fs::write` follows
///   it: the temporary file goes beside the file the link names, and the
///   link stays a link;
/// - an existing file's permissions carry over to the new one;
/// - a read-only file is refused, as an in-place write refuses it, instead
///   of being replaced by a rename the directory allows.
///
/// The temporary name carries the process id and a per-process counter, so
/// two threads or two processes saving at once do not write one temporary
/// file. A failure removes the temporary file. Not done: flushing the
/// directory entry itself, so after a power cut the rename may not have
/// happened — the old contents, whole, which is the state this promises.
pub(crate) fn write_replacing(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    let is_link = fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
    let target: PathBuf = if is_link {
        fs::canonicalize(path).with_context(|| format!("write through the symbolic link {}", path.display()))?
    } else {
        path.to_path_buf()
    };
    let existing = match fs::metadata(&target) {
        Ok(m) => Some(m.permissions()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("write {}", target.display())),
    };
    if existing.as_ref().is_some_and(|p| p.readonly()) {
        anyhow::bail!("write {}: the file is read-only", target.display());
    }
    let name = target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = target.with_file_name(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| -> Result<()> {
        let mut f = fs::File::create(&tmp).with_context(|| format!("write {}", tmp.display()))?;
        f.write_all(contents).with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all().with_context(|| format!("flush {}", tmp.display()))?;
        drop(f);
        if let Some(perms) = existing {
            fs::set_permissions(&tmp, perms).with_context(|| format!("set the permissions of {}", tmp.display()))?;
        }
        fs::rename(&tmp, &target).with_context(|| format!("rename into {}", target.display()))
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

/// One kind of stored entry, by its directory under `.n0x/`.
pub struct Store {
    dir: &'static str,
}

/// Function discovery over an image's code: the starts it finds, before names.
pub const DISCOVERED: Store = Store::new("discover-cache");

impl Store {
    pub const fn new(dir: &'static str) -> Self {
        Self { dir }
    }

    /// The directory under `.n0x/` this kind of entry lives in.
    pub const fn dir_name(&self) -> &'static str {
        self.dir
    }

    fn dir(&self) -> Result<PathBuf> {
        Ok(resolve()?.dir.join(self.dir))
    }

    fn path_for(&self, key: &str) -> Result<PathBuf> {
        // Keys are derived from hashes by the caller, never raw user input;
        // still checked, since this is a public API.
        if key.is_empty() || key.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|', '.']) {
            anyhow::bail!("invalid {} key '{key}'", self.dir);
        }
        let dir = self.dir()?;
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        Ok(dir.join(format!("{key}.json")))
    }

    /// The entry stored under `key`, if there is one.
    pub fn get(&self, key: &str) -> Result<Option<String>> {
        let path = self.path_for(key)?;
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?))
    }

    /// Store `json` under `key`. Written beside and renamed into place, so a
    /// reader in another process (a session beside an `analyze`) sees the old
    /// entry or the new one, never half of one.
    pub fn put(&self, key: &str, json: &str) -> Result<()> {
        write_replacing(&self.path_for(key)?, json.as_bytes())
    }

    /// Drop every entry whose key does not start with `prefix` (the current
    /// analyzer generation). Answers how many went.
    pub fn retain_prefix(&self, prefix: &str) -> Result<usize> {
        let dir = self.dir()?;
        if !dir.exists() {
            return Ok(0);
        }
        let mut removed = 0;
        for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let stale = path.file_stem().and_then(|s| s.to_str()).is_some_and(|name| !name.starts_with(prefix));
            if stale && fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Remove every entry of this kind.
    pub fn clear(&self) -> Result<usize> {
        self.retain_prefix("\u{0}")
    }
}
