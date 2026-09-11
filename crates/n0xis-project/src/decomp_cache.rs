//! Content-addressed **decompilation-result** cache under
//! `.n0x/decomp-cache/<key>.json`. Same raw-string-in/out, caller-keys-on-content
//! discipline as [`ir_cache`](crate::ir_cache) — this module doesn't know a
//! `PseudoFunction` from a hole in the ground; `n0xis-pipeline` computes the key
//! (folding the CFG's own content key, the render style, and the variable
//! renames) and (de)serializes the artifact. Kept in its own directory so its
//! generation sweep is independent of the IR cache's.
//!
//! Why a second layer over `ir-cache/`: the CFG is only half the cost of a
//! `decomp pseudo` — SSA construction, optimization, type inference, coalescing
//! and rendering run *on top* of the cached CFG every view (~0.8 s on a real
//! function). Caching the finished pseudo-C makes re-viewing a function instant.

use std::fs;

use anyhow::{Context, Result};

use crate::resolve;

fn path_for(key: &str) -> Result<std::path::PathBuf> {
    if key.is_empty() || key.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|', '.']) {
        anyhow::bail!("invalid cache key '{key}'");
    }
    let dir = resolve()?.decomp_cache_dir();
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir.join(format!("{key}.json")))
}

/// Fetch a cached pseudo-function's raw JSON, if present.
pub fn get(key: &str) -> Result<Option<String>> {
    let path = path_for(key)?;
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?))
}

/// Store a pseudo-function's raw JSON under `key`, overwriting any previous entry.
pub fn put(key: &str, json: &str) -> Result<()> {
    let path = path_for(key)?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))
}

/// Drop every entry whose key does not start with `prefix` (the current
/// generation), returning how many were removed — see [`ir_cache::retain_prefix`].
pub fn retain_prefix(prefix: &str) -> Result<usize> {
    let dir = resolve()?.decomp_cache_dir();
    if !dir.exists() {
        return Ok(0);
    }
    let mut removed = 0usize;
    for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stale = path.file_stem().and_then(|s| s.to_str()).map(|name| !name.starts_with(prefix)).unwrap_or(false);
        if stale && fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Remove every cached entry.
pub fn clear() -> Result<usize> {
    let dir = resolve()?.decomp_cache_dir();
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
            "n0xis-decompcache-test-{}",
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
            assert_eq!(get("dfn1").unwrap(), None);
            put("dfn1", "{\"pseudo\":[]}").unwrap();
            assert_eq!(get("dfn1").unwrap(), Some("{\"pseudo\":[]}".to_string()));
            assert_eq!(clear().unwrap(), 1);
            assert_eq!(get("dfn1").unwrap(), None);
        });
    }

    #[test]
    fn retain_prefix_keeps_the_current_generation() {
        in_temp_project(|| {
            put("decomp-aaaa-1", "{}").unwrap();
            put("decomp-bbbb-1", "{}").unwrap();
            assert_eq!(retain_prefix("decomp-aaaa-").unwrap(), 1);
            assert!(get("decomp-aaaa-1").unwrap().is_some());
            assert!(get("decomp-bbbb-1").unwrap().is_none());
        });
    }
}
