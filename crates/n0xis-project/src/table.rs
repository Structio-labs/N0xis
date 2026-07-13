//! `.n0xt` tables under `.n0x/tables/<name>.n0xt` (CONCEPT §10) — JSON-
//! serialized `n0xis_contracts::Table`. Storage only, same split as
//! [`crate::patch`]/[`crate::selection`]: resolving a locator to a live
//! address (walking a pointer path, re-finding an AOB match) is the
//! frontend's job, not this module's.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use n0xis_contracts::{Table, TableEntry};

use crate::resolve;

fn table_path(name: &str) -> Result<PathBuf> {
    Ok(resolve()?.tables_dir().join(format!("{name}.n0xt")))
}

/// `<n0x_dir>/tables/<name>.n0xt` for an explicit `.n0x` directory.
fn table_path_at(n0x_dir: &Path, name: &str) -> PathBuf {
    n0x_dir.join("tables").join(format!("{name}.n0xt"))
}

/// Save a whole table, overwriting any existing file of the same name.
pub fn save(table: &Table) -> Result<()> {
    save_at(&resolve()?.dir, table)
}

pub fn load(name: &str) -> Result<Table> {
    load_at(&resolve()?.dir, name)
}

/// Save into an explicit `.n0x` directory rather than the cwd-resolved one.
/// A long-running GUI frontend (n0xis-hud) must use this: some windowing/GL
/// init changes the process working directory out from under `resolve()`, so
/// the HUD pins its project dir once at startup and always passes it here.
pub fn save_at(n0x_dir: &Path, table: &Table) -> Result<()> {
    if table.name.is_empty() {
        bail!("table name must not be empty");
    }
    let dir = n0x_dir.join("tables");
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let path = table_path_at(n0x_dir, &table.name);
    let json = serde_json::to_string_pretty(table).context("serialize table")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Load from an explicit `.n0x` directory (see [`save_at`] for why).
pub fn load_at(n0x_dir: &Path, name: &str) -> Result<Table> {
    let path = table_path_at(n0x_dir, name);
    if !path.exists() {
        bail!("no table named '{name}' in {}", path.display());
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

/// All table names (file stem, no `.n0xt`), sorted.
pub fn list() -> Result<Vec<String>> {
    let dir = resolve()?.tables_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("n0xt")
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            names.push(stem.to_string());
        }
    }
    names.sort();
    Ok(names)
}

/// Add (or overwrite, by name) one entry in `table_name`, creating the table
/// if it doesn't exist yet.
pub fn add_entry(table_name: &str, entry: TableEntry) -> Result<Table> {
    let mut table = load(table_name).unwrap_or_else(|_| Table { name: table_name.to_string(), entries: Vec::new() });
    table.entries.retain(|e| !e.name.eq_ignore_ascii_case(&entry.name));
    table.entries.push(entry);
    save(&table)?;
    Ok(table)
}

/// Remove one entry by name. Returns `true` if one was removed.
pub fn remove_entry(table_name: &str, entry_name: &str) -> Result<bool> {
    let mut table = load(table_name)?;
    let before = table.entries.len();
    table.entries.retain(|e| !e.name.eq_ignore_ascii_case(entry_name));
    let removed = table.entries.len() != before;
    if removed {
        save(&table)?;
    }
    Ok(removed)
}

/// Delete an entire table file. Returns `true` if one existed.
pub fn delete(name: &str) -> Result<bool> {
    let path = table_path(name)?;
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CWD_TEST_LOCK;
    use n0xis_contracts::{TableLocator, TableValueType};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn in_temp_project<T>(f: impl FnOnce() -> T) -> T {
        let _guard = CWD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("n0xis-table-test-{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(tmp.join(".n0x")).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&tmp).unwrap();
        let result = f();
        std::env::set_current_dir(prev).unwrap();
        fs::remove_dir_all(&tmp).ok();
        result
    }

    fn sample_entry(name: &str) -> TableEntry {
        TableEntry {
            name: name.to_string(),
            locator: TableLocator::Address { va: n0xis_contracts::Va(0x1000) },
            value_type: TableValueType::I32,
            description: None,
            hotkey: None,
            groups: Vec::new(),
            frozen: false,
            freeze_value: None,
            provenance: Default::default(),
            verification: Default::default(),
        }
    }

    #[test]
    fn add_list_remove_roundtrip() {
        in_temp_project(|| {
            add_entry("cheats", sample_entry("hp")).unwrap();
            add_entry("cheats", sample_entry("mana")).unwrap();
            assert_eq!(list().unwrap(), vec!["cheats".to_string()]);

            let table = load("cheats").unwrap();
            assert_eq!(table.entries.len(), 2);

            assert!(remove_entry("cheats", "HP").unwrap()); // case-insensitive
            let table = load("cheats").unwrap();
            assert_eq!(table.entries.len(), 1);
            assert_eq!(table.entries[0].name, "mana");
        });
    }

    #[test]
    fn add_entry_overwrites_same_name() {
        in_temp_project(|| {
            add_entry("t", sample_entry("x")).unwrap();
            let mut updated = sample_entry("x");
            updated.description = Some("updated".to_string());
            add_entry("t", updated).unwrap();
            let table = load("t").unwrap();
            assert_eq!(table.entries.len(), 1, "overwrite, not append");
            assert_eq!(table.entries[0].description.as_deref(), Some("updated"));
        });
    }

    #[test]
    fn delete_removes_the_file() {
        in_temp_project(|| {
            add_entry("gone", sample_entry("x")).unwrap();
            assert!(delete("gone").unwrap());
            assert!(!delete("gone").unwrap(), "already deleted");
            assert!(load("gone").is_err());
        });
    }
}
