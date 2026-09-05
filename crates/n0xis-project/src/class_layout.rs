// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Program-wide class layouts (`.n0x/class-layout.json`) — the field sets
//! `analyze --layout` unified across every method of a class, persisted so the
//! decompiler resolves a dispatch through a field without re-running a
//! whole-program pass on every view.
//!
//! Fourth sibling of [`rtti_syms`](crate::rtti_syms),
//! [`flirt_syms`](crate::flirt_syms) and [`type_flow`](crate::type_flow), and
//! for the same reason. **Derived cache, not user truth** — regenerated
//! wholesale, safe to delete, always outranked by what a function proves locally
//! and by the user's own annotations.

use std::collections::BTreeMap;
use std::fs;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::resolve;

/// One field, as persisted. Offsets are decimal strings because JSON object
/// keys are strings; the offset itself is the identity, and it can be negative
/// (a base-class pointer adjusted backwards).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Field {
    #[serde(default)]
    pub size_bits: u32,
    #[serde(default)]
    pub signed: bool,
    #[serde(default)]
    pub access_count: usize,
    /// Distinct methods that touched this offset.
    #[serde(default)]
    pub methods: usize,
    /// The proven type, absent when nothing proved one or two methods disagreed
    /// — the ambiguous case is not persisted as a type, because it is not one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ty: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Class {
    #[serde(default)]
    pub methods: usize,
    #[serde(default)]
    pub extent: u64,
    /// Field offset (decimal string) → field.
    #[serde(default)]
    pub fields: BTreeMap<String, Field>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassLayouts {
    #[serde(default)]
    pub generation: String,
    #[serde(default)]
    pub classes: BTreeMap<String, Class>,
}

impl ClassLayouts {
    pub fn field_type(&self, class: &str, offset: i64) -> Option<&str> {
        self.classes.get(class)?.fields.get(&offset.to_string())?.ty.as_deref()
    }
    pub fn field(&self, class: &str, offset: i64) -> Option<&Field> {
        self.classes.get(class)?.fields.get(&offset.to_string())
    }
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }
    /// Fields carrying a proven type, across every class — the number worth
    /// reporting, since a layout with no typed field changes nothing downstream.
    pub fn typed_fields(&self) -> usize {
        self.classes.values().flat_map(|c| c.fields.values()).filter(|f| f.ty.is_some()).count()
    }
}

fn path() -> Result<std::path::PathBuf> {
    Ok(resolve()?.dir.join("class-layout.json"))
}

pub fn save(store: &ClassLayouts) -> Result<()> {
    let path = path()?;
    let json = serde_json::to_string(store).context("serialize class-layout.json")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))
}

/// Non-fatal on a missing/unreadable/corrupt file — a derived cache that cannot
/// be read simply yields no layouts.
pub fn load() -> Result<ClassLayouts> {
    let path = path()?;
    if !path.exists() {
        return Ok(ClassLayouts::default());
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(ClassLayouts::default());
    }
    serde_json::from_str(&raw).context("parse class-layout.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CWD_TEST_LOCK;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn in_temp_project<T>(f: impl FnOnce() -> T) -> T {
        let _guard = CWD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir()
            .join(format!("n0xis-layout-test-{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
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
    fn round_trips_including_a_negative_offset() {
        in_temp_project(|| {
            let mut fields = BTreeMap::new();
            fields.insert("48".into(), Field { size_bits: 64, signed: false, access_count: 9, methods: 3, ty: Some("QImage *".into()) });
            fields.insert("-8".into(), Field { size_bits: 64, signed: true, access_count: 1, methods: 1, ty: None });
            let store = ClassLayouts {
                generation: "gen1".into(),
                classes: [("Widget".to_string(), Class { methods: 3, extent: 0x40, fields })].into_iter().collect(),
            };
            save(&store).unwrap();

            let got = load().unwrap();
            assert_eq!(got.field_type("Widget", 0x30), Some("QImage *"));
            assert_eq!(got.field_type("Widget", -8), None, "an untyped field answers nothing");
            assert_eq!(got.field("Widget", -8).map(|f| f.signed), Some(true));
            assert_eq!(got.field_type("Button", 0x30), None);
            assert_eq!(got.typed_fields(), 1);
        });
    }
}
