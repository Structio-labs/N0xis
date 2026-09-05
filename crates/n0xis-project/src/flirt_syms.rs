// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Signature-matched name store (`.n0x/flirt-symbols.json`) — the library
//! functions `analyze --flirt` identified by their bytes, persisted as an
//! address→name map so the *whole* pipeline (function list, xref, decompiler,
//! GUI) renders them without re-matching, and without every command needing a
//! `--flirt` flag of its own.
//!
//! Sibling to [`rtti_syms`](crate::rtti_syms), deliberately in its **own file**
//! for two reasons that are not cosmetic:
//!
//! 1. **Precedence.** RTTI names come from a structure the compiler emitted;
//!    a signature match is a *heuristic over bytes*. Kept apart, the name layer
//!    can rank user rename ▸ RTTI ▸ signature without either overwriting the
//!    other on disk.
//! 2. **Interactivity.** The name layer memoizes each store on its own file's
//!    (path, len, mtime). A signature run rewrites this file; a rename rewrites
//!    only `annotations.json`. Sharing one file would re-parse a multi-megabyte
//!    map on every rename.
//!
//! Like `rtti_syms` this is **derived cache, not user truth**: regenerated
//! wholesale by `analyze`, safe to delete, and always outranked by the user's
//! own names.

use std::collections::BTreeMap;
use std::fs;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::resolve;

/// One signature-matched function name at an address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlirtSym {
    pub va: u64,
    pub name: String,
}

/// The whole matched set for a target, plus the `generation` token of the run
/// that produced it — which corpora, and how many signatures, so a set matched
/// from a different corpus chain is recognizable rather than silently reused.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlirtSymbols {
    #[serde(default)]
    pub generation: String,
    #[serde(default)]
    pub syms: Vec<FlirtSym>,
}

fn path() -> Result<std::path::PathBuf> {
    Ok(resolve()?.dir.join("flirt-symbols.json"))
}

/// Persist the matched set, replacing whatever was there.
pub fn save(store: &FlirtSymbols) -> Result<()> {
    let path = path()?;
    let json = serde_json::to_string(store).context("serialize flirt-symbols.json")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))
}

/// The matched names as `(va, name)` pairs, or an empty list when nothing has
/// been persisted. Non-fatal on a missing/unreadable/corrupt file — a derived
/// cache that cannot be read simply yields no names.
pub fn load() -> Result<Vec<(u64, String)>> {
    let path = path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let store: FlirtSymbols = serde_json::from_str(&raw).context("parse flirt-symbols.json")?;
    Ok(store.syms.into_iter().map(|s| (s.va, s.name)).collect())
}

/// Build a store from an address→name map, stamped with `generation`.
pub fn from_map(generation: impl Into<String>, names: BTreeMap<u64, String>) -> FlirtSymbols {
    FlirtSymbols {
        generation: generation.into(),
        syms: names.into_iter().map(|(va, name)| FlirtSym { va, name }).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CWD_TEST_LOCK;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn in_temp_project<T>(f: impl FnOnce() -> T) -> T {
        let _guard = CWD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "n0xis-flirt-syms-test-{}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(tmp.join(".n0x")).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&tmp).unwrap();
        let result = f();
        std::env::set_current_dir(prev).unwrap();
        fs::remove_dir_all(&tmp).ok();
        result
    }

    #[test]
    fn empty_when_nothing_persisted() {
        in_temp_project(|| assert!(load().unwrap().is_empty()));
    }

    #[test]
    fn round_trips_matched_names() {
        in_temp_project(|| {
            let mut m = BTreeMap::new();
            m.insert(0x1400_1000u64, "memcpy".to_string());
            m.insert(0x1400_2000u64, "crc32".to_string());
            save(&from_map("flirt:zlib:118", m)).unwrap();
            let mut got = load().unwrap();
            got.sort_by_key(|(va, _)| *va);
            assert_eq!(got, vec![(0x1400_1000, "memcpy".to_string()), (0x1400_2000, "crc32".to_string())]);
        });
    }
}
