//! Content-addressed artifact cache under `.n0x/ir-cache/<key>.json` — the
//! Phase 6 "don't rebuild IR on every call" store. Raw string in, raw string
//! out: this module doesn't know what an artifact *is* (that would leak
//! `n0xis-core` types into `n0xis-project`); the caller (today, `n0xis-
//! pipeline`) computes the key — including a hash of the actual bytes the
//! pass would read, never just an address — and (de)serializes its own
//! artifact type. That split is what keeps the cache self-invalidating: a
//! stale key never gets reused as long as the caller keys on real content,
//! not on an address/size pair that could quietly point at changed bytes
//! (self-modifying code, a redeployed DLL, ...). Storage only, same split as
//! [`selection`](crate::selection)/[`session`](crate::session).

use std::fs;

use anyhow::{Context, Result};

use crate::resolve;

fn path_for(key: &str) -> Result<std::path::PathBuf> {
    // Keys are hex-hash-derived by the caller (see n0xis-pipeline::cache_key),
    // never raw user input, so no path-traversal characters are possible —
    // still validated defensively since this is a public API.
    if key.is_empty() || key.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|', '.']) {
        anyhow::bail!("invalid cache key '{key}'");
    }
    let dir = resolve()?.ir_cache_dir();
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir.join(format!("{key}.json")))
}

/// Fetch a cached artifact's raw JSON, if present.
pub fn get(key: &str) -> Result<Option<String>> {
    let path = path_for(key)?;
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?))
}

/// Store an artifact's raw JSON under `key`, overwriting any previous entry.
pub fn put(key: &str, json: &str) -> Result<()> {
    let path = path_for(key)?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))
}

/// Remove every cached entry. Not yet wired to a CLI/MCP command (a
/// documented follow-on — see ROADMAP Phase 6); available now so tests (and
/// a future command) don't have to reach into `.n0x/ir-cache/` by hand.
pub fn clear() -> Result<usize> {
    let dir = resolve()?.ir_cache_dir();
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
            "n0xis-ircache-test-{}",
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
            assert_eq!(get("abc123").unwrap(), None);
            put("abc123", "{\"n\":1}").unwrap();
            assert_eq!(get("abc123").unwrap(), Some("{\"n\":1}".to_string()));
            put("abc123", "{\"n\":2}").unwrap();
            assert_eq!(get("abc123").unwrap(), Some("{\"n\":2}".to_string()));
            assert_eq!(clear().unwrap(), 1);
            assert_eq!(get("abc123").unwrap(), None);
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
