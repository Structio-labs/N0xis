//! User-defined **type catalog** (`.n0x/types.json`) — named `struct` and `enum`
//! definitions the decompiler consults so a typed pointer renders `p->count`
//! instead of `p->field_0x68`. This is *user truth* (like [`annotate`](crate::annotate)),
//! not derived cache: it survives re-analysis and is the source of field names,
//! which no amount of static inference can recover from a stripped binary.
//!
//! Storage-only, same split as the rest of `n0xis-project`: this module owns the
//! JSON shape; `n0xis-core` (the decompiler) is handed a plain
//! `struct name → (offset → field name)` map and never reads disk.

use std::collections::BTreeMap;
use std::fs;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::resolve;

/// One field of a struct: its byte offset, name, and C type (rendered when the
/// field itself is dereferenced/declared; the name is what makes `p->count` read).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructField {
    pub offset: i64,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ctype: String,
}

/// A named struct definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructDef {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default)]
    pub fields: Vec<StructField>,
}

/// One member of an enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumMember {
    pub name: String,
    pub value: i64,
}

/// A named enum definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumDef {
    pub name: String,
    #[serde(default)]
    pub members: Vec<EnumMember>,
}

/// The whole type catalog.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypesDb {
    #[serde(default)]
    pub structs: Vec<StructDef>,
    #[serde(default)]
    pub enums: Vec<EnumDef>,
}

fn path() -> Result<std::path::PathBuf> {
    Ok(resolve()?.dir.join("types.json"))
}

/// Load the catalog (empty when the file is absent/unreadable/corrupt — this is
/// user data, but a missing file is simply "no types defined yet").
pub fn load() -> Result<TypesDb> {
    let path = path()?;
    if !path.exists() {
        return Ok(TypesDb::default());
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(TypesDb::default());
    }
    serde_json::from_str(&raw).context("parse types.json")
}

fn save(db: &TypesDb) -> Result<()> {
    let path = path()?;
    let json = serde_json::to_string_pretty(db).context("serialize types.json")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))
}

/// Define (or replace) a struct by name.
pub fn put_struct(def: StructDef) -> Result<()> {
    let mut db = load()?;
    db.structs.retain(|s| s.name != def.name);
    db.structs.push(def);
    db.structs.sort_by(|a, b| a.name.cmp(&b.name));
    save(&db)
}

/// Define (or replace) an enum by name.
pub fn put_enum(def: EnumDef) -> Result<()> {
    let mut db = load()?;
    db.enums.retain(|e| e.name != def.name);
    db.enums.push(def);
    db.enums.sort_by(|a, b| a.name.cmp(&b.name));
    save(&db)
}

/// Remove a struct or enum by name. Returns whether anything was removed.
pub fn remove(name: &str) -> Result<bool> {
    let mut db = load()?;
    let before = db.structs.len() + db.enums.len();
    db.structs.retain(|s| s.name != name);
    db.enums.retain(|e| e.name != name);
    let removed = db.structs.len() + db.enums.len() != before;
    if removed {
        save(&db)?;
    }
    Ok(removed)
}

/// The decompiler-facing view: `struct name → (field offset → field name)`. This
/// is exactly what the renderer needs to turn `p->field_0x68` into `p->count`.
pub fn field_maps() -> BTreeMap<String, BTreeMap<i64, String>> {
    let db = load().unwrap_or_default();
    db.structs
        .into_iter()
        .map(|s| (s.name, s.fields.into_iter().map(|f| (f.offset, f.name)).collect()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CWD_TEST_LOCK;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn in_temp_project<T>(f: impl FnOnce() -> T) -> T {
        let _guard = CWD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("n0xis-types-test-{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(tmp.join(".n0x")).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&tmp).unwrap();
        let r = f();
        std::env::set_current_dir(prev).unwrap();
        fs::remove_dir_all(&tmp).ok();
        r
    }

    #[test]
    fn define_list_field_map_remove() {
        in_temp_project(|| {
            assert!(load().unwrap().structs.is_empty());
            put_struct(StructDef {
                name: "Foo".into(),
                size: Some(0x80),
                fields: vec![
                    StructField { offset: 0x0, name: "vftable".into(), ctype: "void *".into() },
                    StructField { offset: 0x68, name: "count".into(), ctype: "int".into() },
                ],
            })
            .unwrap();
            let fm = field_maps();
            assert_eq!(fm.get("Foo").and_then(|m| m.get(&0x68)).map(String::as_str), Some("count"));
            assert!(remove("Foo").unwrap());
            assert!(field_maps().is_empty());
        });
    }
}
