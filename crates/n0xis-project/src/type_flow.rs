// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Whole-program type store (`.n0x/type-flow.json`) — the types
//! `analyze --typeflow` propagated along the call graph, persisted so the
//! decompiler renders them without re-running a whole-program fixpoint on every
//! view.
//!
//! Third sibling of [`rtti_syms`](crate::rtti_syms) and
//! [`flirt_syms`](crate::flirt_syms), and for the same reason: a whole-program
//! pass is worth running once, and everything downstream should see its result
//! without a flag of its own. **Derived cache, not user truth** — regenerated
//! wholesale, safe to delete, always outranked by what a function proves locally
//! and by the user's own annotations.

use std::collections::BTreeMap;
use std::fs;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::resolve;

/// Function VA → recovered types. Keys are decimal strings because JSON object
/// keys are strings; the VA itself is the identity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeFlow {
    #[serde(default)]
    pub generation: String,
    /// VA → per-parameter type name (`null` = unknown).
    #[serde(default)]
    pub params: BTreeMap<String, Vec<Option<String>>>,
    /// VA → return type name.
    #[serde(default)]
    pub rets: BTreeMap<String, String>,
}

impl TypeFlow {
    pub fn param(&self, va: u64, index: usize) -> Option<&str> {
        self.params.get(&va.to_string())?.get(index)?.as_deref()
    }
    pub fn ret(&self, va: u64) -> Option<&str> {
        self.rets.get(&va.to_string()).map(String::as_str)
    }
    pub fn is_empty(&self) -> bool {
        self.params.is_empty() && self.rets.is_empty()
    }
}

fn path() -> Result<std::path::PathBuf> {
    Ok(resolve()?.dir.join("type-flow.json"))
}

pub fn save(store: &TypeFlow) -> Result<()> {
    let path = path()?;
    let json = serde_json::to_string(store).context("serialize type-flow.json")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))
}

/// Non-fatal on a missing/unreadable/corrupt file — a derived cache that cannot
/// be read simply yields no types.
pub fn load() -> Result<TypeFlow> {
    let path = path()?;
    if !path.exists() {
        return Ok(TypeFlow::default());
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(TypeFlow::default());
    }
    serde_json::from_str(&raw).context("parse type-flow.json")
}

/// Build the persisted shape from the pass's own maps, keeping only the slots
/// that actually carry a type — an all-`null` row is bytes for nothing.
pub fn from_maps(
    generation: impl Into<String>,
    params: BTreeMap<u64, Vec<Option<String>>>,
    rets: BTreeMap<u64, Option<String>>,
) -> TypeFlow {
    TypeFlow {
        generation: generation.into(),
        params: params
            .into_iter()
            .filter(|(_, ps)| ps.iter().any(Option::is_some))
            .map(|(va, ps)| (va.to_string(), ps))
            .collect(),
        rets: rets.into_iter().filter_map(|(va, t)| t.map(|t| (va.to_string(), t))).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CWD_TEST_LOCK;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn in_temp_project<T>(f: impl FnOnce() -> T) -> T {
        let _guard = CWD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir()
            .join(format!("n0xis-typeflow-test-{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(tmp.join(".n0x")).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&tmp).unwrap();
        let r = f();
        std::env::set_current_dir(prev).unwrap();
        fs::remove_dir_all(&tmp).ok();
        r
    }

    #[test]
    fn empty_when_nothing_persisted() {
        in_temp_project(|| assert!(load().unwrap().is_empty()));
    }

    #[test]
    fn round_trips_and_drops_rows_that_carry_nothing() {
        in_temp_project(|| {
            let mut params = BTreeMap::new();
            params.insert(0x1000u64, vec![Some("Widget *".to_string()), None]);
            params.insert(0x2000u64, vec![None, None]); // nothing to say
            let mut rets = BTreeMap::new();
            rets.insert(0x1000u64, Some("Button *".to_string()));
            rets.insert(0x3000u64, None);
            save(&from_maps("gen1", params, rets)).unwrap();

            let got = load().unwrap();
            assert_eq!(got.param(0x1000, 0), Some("Widget *"));
            assert_eq!(got.param(0x1000, 1), None);
            assert_eq!(got.param(0x2000, 0), None, "an all-null row is not persisted");
            assert_eq!(got.ret(0x1000), Some("Button *"));
            assert_eq!(got.ret(0x3000), None);
        });
    }
}
