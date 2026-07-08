//! Named memory-range selections under `.n0x/selections.json` — durable
//! anchors an agent saves once (`name` → `[start, end)` + optional label) and
//! refers back to instead of re-typing addresses across a session. Storage
//! only: resolving a selection into an analysis (`ir build --addr`, `mem
//! read`, …) is the frontend's job, same split as [`patch`](crate::patch).

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use n0xis_contracts::Va;
use serde::{Deserialize, Serialize};

use crate::resolve;

/// One named `[start, end)` range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionRecord {
    pub name: String,
    pub start: Va,
    pub end: Va,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub created_at_unix: u64,
}

impl SelectionRecord {
    pub fn size(&self) -> u64 {
        self.end.0.saturating_sub(self.start.0)
    }
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_all() -> Result<Vec<SelectionRecord>> {
    let path = resolve()?.selections_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&raw).context("parse selections.json")
}

fn save_all(records: &[SelectionRecord]) -> Result<()> {
    let path = resolve()?.selections_path();
    let json = serde_json::to_string_pretty(records).context("serialize selections.json")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Save (or overwrite, by name) a named selection.
pub fn save(name: &str, start: Va, end: Va, label: Option<String>) -> Result<SelectionRecord> {
    if name.is_empty() {
        bail!("selection name must not be empty");
    }
    if end.0 <= start.0 {
        bail!("selection end must be greater than start");
    }
    let record = SelectionRecord { name: name.to_string(), start, end, label, created_at_unix: now_unix_secs() };
    let mut records = load_all()?;
    records.retain(|s| !s.name.eq_ignore_ascii_case(name));
    records.push(record.clone());
    save_all(&records)?;
    Ok(record)
}

/// All selections, name-sorted.
pub fn list() -> Result<Vec<SelectionRecord>> {
    let mut records = load_all()?;
    records.sort_by_key(|s| s.name.to_ascii_lowercase());
    Ok(records)
}

/// A single selection by name (case-insensitive).
pub fn get(name: &str) -> Result<SelectionRecord> {
    load_all()?
        .into_iter()
        .find(|s| s.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| anyhow!("no selection named '{name}'"))
}

/// Remove a selection by name. Returns `true` if one was removed.
pub fn remove(name: &str) -> Result<bool> {
    let mut records = load_all()?;
    let before = records.len();
    records.retain(|s| !s.name.eq_ignore_ascii_case(name));
    let removed = records.len() != before;
    if removed {
        save_all(&records)?;
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
            "n0xis-sel-test-{}",
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
    fn save_list_get_remove_roundtrip() {
        in_temp_project(|| {
            save("hp", Va(0x1000), Va(0x1008), Some("player HP".into())).unwrap();
            save("mana", Va(0x2000), Va(0x2004), None).unwrap();

            let all = list().unwrap();
            assert_eq!(all.len(), 2);
            assert_eq!(all[0].name, "hp"); // name-sorted

            let hp = get("HP").unwrap(); // case-insensitive
            assert_eq!(hp.start, Va(0x1000));
            assert_eq!(hp.size(), 8);

            assert!(remove("hp").unwrap());
            assert!(!remove("hp").unwrap(), "already removed");
            assert_eq!(list().unwrap().len(), 1);
        });
    }

    #[test]
    fn save_overwrites_same_name() {
        in_temp_project(|| {
            save("target", Va(0x1000), Va(0x1010), None).unwrap();
            save("target", Va(0x3000), Va(0x3010), Some("moved".into())).unwrap();
            let all = list().unwrap();
            assert_eq!(all.len(), 1, "overwrite, not append");
            assert_eq!(all[0].start, Va(0x3000));
        });
    }

    #[test]
    fn rejects_empty_range() {
        in_temp_project(|| {
            let err = save("bad", Va(0x2000), Va(0x1000), None).unwrap_err();
            assert!(err.to_string().contains("end must be greater"));
        });
    }
}
