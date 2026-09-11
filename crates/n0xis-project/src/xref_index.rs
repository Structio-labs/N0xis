// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Content-addressed reverse-xref index under `.n0x/xref-index/<key>.json` — the
//! store that turns `xref to` from a full code-section re-scan into a map lookup.
//! Same storage-only split as [`ir_cache`](crate::ir_cache): raw string in, raw
//! string out, the caller (`n0xis-pipeline`) owns the key (a hash of the actual
//! code bytes + analyzer generation) and the artifact type. Kept in its own
//! directory so the CFG cache's generation sweep can never delete it.

use std::fs;

use anyhow::{Context, Result};

use crate::resolve;

fn path_for(key: &str) -> Result<std::path::PathBuf> {
    // Keys are hex-hash-derived by the caller, never raw user input — still
    // validated defensively since this is a public API.
    if key.is_empty() || key.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|', '.']) {
        anyhow::bail!("invalid xref-index key '{key}'");
    }
    let dir = resolve()?.xref_index_dir();
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir.join(format!("{key}.json")))
}

/// Fetch a stored index's raw JSON, if present.
pub fn get(key: &str) -> Result<Option<String>> {
    let path = path_for(key)?;
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?))
}

/// Store an index's raw JSON under `key`, overwriting any previous entry.
pub fn put(key: &str, json: &str) -> Result<()> {
    let path = path_for(key)?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))
}

/// Drop every entry whose key does **not** start with `prefix` (the analyzer
/// generation), returning how many were removed — the same one-generation policy
/// as [`ir_cache::retain_prefix`](crate::ir_cache::retain_prefix).
pub fn retain_prefix(prefix: &str) -> Result<usize> {
    let dir = resolve()?.xref_index_dir();
    if !dir.exists() {
        return Ok(0);
    }
    let mut removed = 0usize;
    for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stale = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|name| !name.starts_with(prefix))
            .unwrap_or(false);
        if stale && fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Remove every stored index. Storage-only twin of the CLI `analyze --clear` /
/// GUI cache panel that will call it.
pub fn clear() -> Result<usize> {
    let dir = resolve()?.xref_index_dir();
    if !dir.exists() {
        return Ok(0);
    }
    let mut removed = 0usize;
    for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        if entry.path().extension().and_then(|e| e.to_str()) == Some("json") {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
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
            "n0xis-xrefidx-test-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
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
    fn get_put_clear_roundtrip() {
        in_temp_project(|| {
            assert_eq!(get("xref-aaaa-1").unwrap(), None);
            put("xref-aaaa-1", "{\"edges\":{}}").unwrap();
            assert_eq!(get("xref-aaaa-1").unwrap(), Some("{\"edges\":{}}".to_string()));
            assert_eq!(clear().unwrap(), 1);
            assert_eq!(get("xref-aaaa-1").unwrap(), None);
        });
    }

    #[test]
    fn retain_prefix_keeps_only_the_current_generation() {
        in_temp_project(|| {
            put("xref-aaaa-1", "{}").unwrap();
            put("xref-bbbb-1", "{}").unwrap();
            assert_eq!(retain_prefix("xref-aaaa-").unwrap(), 1);
            assert!(get("xref-aaaa-1").unwrap().is_some());
            assert!(get("xref-bbbb-1").unwrap().is_none());
        });
    }

    #[test]
    fn rejects_unsafe_keys() {
        in_temp_project(|| {
            assert!(get("../escape").is_err());
            assert!(put("a/b", "{}").is_err());
        });
    }
}
