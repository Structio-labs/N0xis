//! The analysis DB (ROADMAP Phase 6): user/agent-asserted **names, type
//! notes, and comments** at an address, kept as **versioned truth** — every
//! change is appended to that address's `history` rather than silently
//! overwriting the previous value, so "what did we used to think this was"
//! is always answerable. Complements `patch` (Phase 2's already-versioned
//! byte-level journal, `applied`/`undone` with timestamps) rather than
//! replacing it — together they're the "names/types/comments/patches"
//! versioned truth ROADMAP Phase 6 asks for. Storage: a single
//! `.n0x/annotations.json` (`BTreeMap<va-hex, AnnotationRecord>`), same
//! storage-only split as [`selection`](crate::selection)/[`table`](crate::table).

use std::collections::BTreeMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use n0xis_contracts::Va;
use serde::{Deserialize, Serialize};

use crate::resolve;

fn now_unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// One recorded change to a single field of an [`AnnotationRecord`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationChange {
    /// `"name"` | `"type"` | `"comment"`.
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<String>,
    pub unix: u64,
}

/// The current facts about one address, plus the full history that produced
/// them. Any field can be absent (nothing asserted yet).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnnotationRecord {
    pub va: Va,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(default)]
    pub history: Vec<AnnotationChange>,
}

fn path() -> Result<std::path::PathBuf> {
    Ok(resolve()?.dir.join("annotations.json"))
}

fn load_all() -> Result<BTreeMap<String, AnnotationRecord>> {
    let path = path()?;
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_str(&raw).context("parse annotations.json")
}

fn save_all(records: &BTreeMap<String, AnnotationRecord>) -> Result<()> {
    let path = path()?;
    let json = serde_json::to_string_pretty(records).context("serialize annotations.json")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))
}

/// Set one field (`"name"`, `"type"`, or `"comment"`) on the record at `va`,
/// appending a history entry iff the value actually changes. `value: None`
/// clears the field (still recorded in history, so "we un-named this" is
/// visible too). Returns the updated record.
fn set_field(va: Va, field: &str, value: Option<String>) -> Result<AnnotationRecord> {
    let mut all = load_all()?;
    let key = va.to_string();
    let record = all.entry(key).or_insert_with(|| AnnotationRecord { va, ..Default::default() });

    let old = match field {
        "name" => record.name.clone(),
        "type" => record.type_note.clone(),
        "comment" => record.comment.clone(),
        other => anyhow::bail!("unknown annotation field '{other}'"),
    };
    if old != value {
        record.history.push(AnnotationChange { field: field.to_string(), old, new: value.clone(), unix: now_unix_secs() });
        match field {
            "name" => record.name = value,
            "type" => record.type_note = value,
            "comment" => record.comment = value,
            _ => unreachable!(),
        }
    }
    let result = record.clone();
    save_all(&all)?;
    Ok(result)
}

pub fn set_name(va: Va, name: Option<String>) -> Result<AnnotationRecord> {
    set_field(va, "name", name)
}
pub fn set_type(va: Va, type_note: Option<String>) -> Result<AnnotationRecord> {
    set_field(va, "type", type_note)
}
pub fn set_comment(va: Va, comment: Option<String>) -> Result<AnnotationRecord> {
    set_field(va, "comment", comment)
}

/// The record at `va`, if anything has ever been asserted about it.
pub fn get(va: Va) -> Result<Option<AnnotationRecord>> {
    Ok(load_all()?.remove(&va.to_string()))
}

/// Every annotated address, va-sorted (the map is already keyed that way
/// since `Va::to_string()` zero-pads implicitly via consistent hex width —
/// re-sorted numerically here to be robust regardless).
pub fn list() -> Result<Vec<AnnotationRecord>> {
    let mut records: Vec<AnnotationRecord> = load_all()?.into_values().collect();
    records.sort_by_key(|r| r.va.0);
    Ok(records)
}

/// Drop every field and the full history at `va`. Returns `true` if a record existed.
pub fn remove(va: Va) -> Result<bool> {
    let mut all = load_all()?;
    let removed = all.remove(&va.to_string()).is_some();
    if removed {
        save_all(&all)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CWD_TEST_LOCK;

    fn in_temp_project<T>(f: impl FnOnce() -> T) -> T {
        let _guard = CWD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "n0xis-annotate-test-{}",
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
    fn set_name_type_comment_and_read_back() {
        in_temp_project(|| {
            assert!(get(Va(0x1000)).unwrap().is_none());

            let rec = set_name(Va(0x1000), Some("parse_header".to_string())).unwrap();
            assert_eq!(rec.name.as_deref(), Some("parse_header"));
            assert_eq!(rec.history.len(), 1);

            let rec = set_type(Va(0x1000), Some("int(char*, size_t)".to_string())).unwrap();
            assert_eq!(rec.type_note.as_deref(), Some("int(char*, size_t)"));
            let rec = set_comment(Va(0x1000), Some("bounds-checks then parses".to_string())).unwrap();
            assert_eq!(rec.comment.as_deref(), Some("bounds-checks then parses"));
            assert_eq!(rec.history.len(), 3, "one history entry per distinct field set");

            let fetched = get(Va(0x1000)).unwrap().expect("record exists");
            assert_eq!(fetched.name.as_deref(), Some("parse_header"));
            assert_eq!(fetched.type_note.as_deref(), Some("int(char*, size_t)"));
        });
    }

    #[test]
    fn renaming_never_loses_the_old_name_versioned_truth() {
        in_temp_project(|| {
            set_name(Va(0x2000), Some("sub_2000".to_string())).unwrap();
            let rec = set_name(Va(0x2000), Some("compute_checksum".to_string())).unwrap();
            assert_eq!(rec.name.as_deref(), Some("compute_checksum"));
            assert_eq!(rec.history.len(), 2);
            assert_eq!(rec.history[0].old, None);
            assert_eq!(rec.history[0].new.as_deref(), Some("sub_2000"));
            assert_eq!(rec.history[1].old.as_deref(), Some("sub_2000"));
            assert_eq!(rec.history[1].new.as_deref(), Some("compute_checksum"));
        });
    }

    #[test]
    fn setting_the_same_value_again_does_not_grow_history() {
        in_temp_project(|| {
            set_name(Va(0x3000), Some("f".to_string())).unwrap();
            let rec = set_name(Va(0x3000), Some("f".to_string())).unwrap();
            assert_eq!(rec.history.len(), 1, "idempotent set must not add a duplicate history entry");
        });
    }

    #[test]
    fn list_is_va_sorted_and_remove_drops_everything() {
        in_temp_project(|| {
            set_name(Va(0x3000), Some("c".to_string())).unwrap();
            set_name(Va(0x1000), Some("a".to_string())).unwrap();
            set_name(Va(0x2000), Some("b".to_string())).unwrap();
            let all = list().unwrap();
            assert_eq!(all.iter().map(|r| r.va).collect::<Vec<_>>(), vec![Va(0x1000), Va(0x2000), Va(0x3000)]);

            assert!(remove(Va(0x2000)).unwrap());
            assert!(!remove(Va(0x2000)).unwrap(), "already removed");
            assert_eq!(list().unwrap().len(), 2);
        });
    }
}
