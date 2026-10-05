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
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::resolve;

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
        let path = self.path_for(key)?;
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        fs::write(&tmp, json).with_context(|| format!("write {}", tmp.display()))?;
        fs::rename(&tmp, &path).with_context(|| format!("rename into {}", path.display()))
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
