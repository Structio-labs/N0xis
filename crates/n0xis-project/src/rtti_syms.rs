// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Recovered-symbol store (`.n0x/rtti-symbols.json`) — the class names the
//! `analyze` pass recovers from MSVC RTTI, persisted as an address→name map so
//! the decompiler can render them without re-scanning `.rdata` on every view.
//!
//! This is **derived cache, not user truth**: it is regenerated wholesale by
//! `analyze` (keyed by a `generation` token so a re-scan replaces it) and is safe
//! to delete — unlike [`annotate`](crate::annotate), which is the user's own
//! versioned truth and always wins over these. Kept in its own file (never in
//! `annotations.json`) precisely so a user rename and a recovered name never mix,
//! and so clearing recovered names never touches the user's work.

use std::collections::BTreeMap;
use std::fs;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::resolve;

/// One recovered symbol: a name at an address, tagged `"function"` (a virtual
/// method a vtable slot points to) or `"data"` (a vtable / type-descriptor
/// global, which renders `&Class::vftable`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RttiSym {
    pub va: u64,
    pub name: String,
    #[serde(default)]
    pub kind: String,
}

/// The whole recovered-symbol set for a target, plus the `generation` token of
/// the analysis run that produced it (so a stale set is recognizable).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RttiSymbols {
    #[serde(default)]
    pub generation: String,
    #[serde(default)]
    pub syms: Vec<RttiSym>,
}

fn path() -> Result<std::path::PathBuf> {
    Ok(resolve()?.dir.join("rtti-symbols.json"))
}

/// Persist the recovered-symbol set, replacing whatever was there. Called by
/// `analyze` after an RTTI scan; a fresh scan overwrites the previous cache.
pub fn save(store: &RttiSymbols) -> Result<()> {
    let path = path()?;
    let json = serde_json::to_string(store).context("serialize rtti-symbols.json")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))
}

/// The recovered symbols as `(va, name, kind)` triples, or an empty list when no
/// scan has been persisted. Non-fatal on a missing/unreadable/corrupt file — a
/// derived cache that cannot be read simply yields no names.
pub fn load() -> Result<Vec<(u64, String, String)>> {
    let path = path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let store: RttiSymbols = serde_json::from_str(&raw).context("parse rtti-symbols.json")?;
    Ok(store.syms.into_iter().map(|s| (s.va, s.name, s.kind)).collect())
}

/// Build a store from an address→name map (functions) and a data-symbol map,
/// stamped with `generation`. Convenience for `analyze`.
pub fn from_maps(
    generation: impl Into<String>,
    functions: BTreeMap<u64, String>,
    data: BTreeMap<u64, String>,
) -> RttiSymbols {
    let mut syms = Vec::with_capacity(functions.len() + data.len());
    for (va, name) in functions {
        syms.push(RttiSym { va, name, kind: "function".to_string() });
    }
    for (va, name) in data {
        syms.push(RttiSym { va, name, kind: "data".to_string() });
    }
    RttiSymbols { generation: generation.into(), syms }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CWD_TEST_LOCK;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn in_temp_project<T>(f: impl FnOnce() -> T) -> T {
        let _guard = CWD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "n0xis-rtti-syms-test-{}",
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
        in_temp_project(|| {
            assert!(load().unwrap().is_empty());
        });
    }

    #[test]
    fn round_trips_functions_and_data() {
        in_temp_project(|| {
            let mut fns = BTreeMap::new();
            fns.insert(0x1400_1000u64, "Ns::Foo::vf0".to_string());
            let mut data = BTreeMap::new();
            data.insert(0x1400_a000u64, "Ns::Foo::vftable".to_string());
            save(&from_maps("gen1", fns, data)).unwrap();

            let mut got = load().unwrap();
            got.sort_by_key(|(va, _, _)| *va);
            assert_eq!(got.len(), 2);
            assert_eq!(got[0], (0x1400_1000, "Ns::Foo::vf0".to_string(), "function".to_string()));
            assert_eq!(got[1], (0x1400_a000, "Ns::Foo::vftable".to_string(), "data".to_string()));
        });
    }
}
