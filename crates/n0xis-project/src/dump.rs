//! Persistent artifact store under `.n0x/dumps/<kind>/<name>.<ext>` — where an
//! agent parks IR/pseudo-C/hex/notes it wants to survive past the current
//! session, addressable by name instead of a throwaway file path. Storage
//! only, same split as [`patch`](crate::patch) and [`selection`](crate::selection).

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::{DUMP_KINDS, extension_for_kind, is_valid_kind, resolve};

fn ensure_kind(kind: &str) -> Result<()> {
    if !is_valid_kind(kind) {
        bail!("unknown dump kind '{kind}'. valid: {}", DUMP_KINDS.join(", "));
    }
    Ok(())
}

fn path_for(kind: &str, name: &str) -> Result<PathBuf> {
    if name.is_empty() || name.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|']) {
        bail!("invalid dump name '{name}'");
    }
    let dir = resolve()?.dump_kind_dir(kind);
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir.join(format!("{name}.{}", extension_for_kind(kind))))
}

#[derive(Debug, Clone, Serialize)]
pub struct DumpSaved {
    pub name: String,
    pub kind: String,
    pub path: String,
    pub size: usize,
    pub overwrote: bool,
}

/// Write `bytes` to `.n0x/dumps/<kind>/<name>.<ext>`. Refuses to clobber an
/// existing dump unless `force`.
pub fn save(name: &str, kind: &str, bytes: &[u8], force: bool) -> Result<DumpSaved> {
    ensure_kind(kind)?;
    let path = path_for(kind, name)?;
    let existed = path.exists();
    if existed && !force {
        bail!("dump already exists at {} (use --force to overwrite)", path.display());
    }
    fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(DumpSaved {
        name: name.to_string(),
        kind: kind.to_string(),
        path: path.to_string_lossy().to_string(),
        size: bytes.len(),
        overwrote: existed,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct DumpItem {
    pub name: String,
    pub kind: String,
    pub path: String,
    pub size: u64,
}

/// List dumps, optionally restricted to one `kind`.
pub fn list(kind: Option<&str>) -> Result<Vec<DumpItem>> {
    let kinds: Vec<&str> = match kind {
        Some(k) => {
            ensure_kind(k)?;
            vec![k]
        }
        None => DUMP_KINDS.to_vec(),
    };
    let root = resolve()?;
    let mut items = Vec::new();
    for k in kinds {
        let dir = root.dump_kind_dir(k);
        if !dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
            let entry = entry?;
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let name = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            items.push(DumpItem { name, kind: k.to_string(), path: p.to_string_lossy().to_string(), size });
        }
    }
    items.sort_by(|a, b| (a.kind.as_str(), a.name.as_str()).cmp(&(b.kind.as_str(), b.name.as_str())));
    Ok(items)
}

#[derive(Debug, Clone, Serialize)]
pub struct DumpContent {
    pub name: String,
    pub kind: String,
    pub path: String,
    pub size: usize,
    pub bytes: Vec<u8>,
}

/// Read a dump's raw bytes. Searches all kinds when `kind` is `None`.
pub fn show(name: &str, kind: Option<&str>) -> Result<DumpContent> {
    let (kind, path) = match kind {
        Some(k) => {
            ensure_kind(k)?;
            (k.to_string(), path_for(k, name)?)
        }
        None => DUMP_KINDS
            .iter()
            .find_map(|k| {
                let p = path_for(k, name).ok()?;
                p.exists().then(|| (k.to_string(), p))
            })
            .ok_or_else(|| anyhow::anyhow!("no dump named '{name}' found in any kind"))?,
    };
    if !path.exists() {
        bail!("no dump at {}", path.display());
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(DumpContent { name: name.to_string(), kind, path: path.to_string_lossy().to_string(), size: bytes.len(), bytes })
}

#[derive(Debug, Clone, Serialize)]
pub struct DumpRemoved {
    pub kind: String,
    pub path: String,
}

/// Remove a dump by name. Searches all kinds when `kind` is `None`; removes
/// every matching kind (a name could collide across kinds).
pub fn remove(name: &str, kind: Option<&str>) -> Result<Vec<DumpRemoved>> {
    let kinds: Vec<&str> = match kind {
        Some(k) => {
            ensure_kind(k)?;
            vec![k]
        }
        None => DUMP_KINDS.to_vec(),
    };
    let mut removed = Vec::new();
    for k in kinds {
        let p = path_for(k, name)?;
        if p.exists() {
            fs::remove_file(&p).with_context(|| format!("remove {}", p.display()))?;
            removed.push(DumpRemoved { kind: k.to_string(), path: p.to_string_lossy().to_string() });
        }
    }
    if removed.is_empty() {
        bail!("no dump named '{name}' found");
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
            "n0xis-dump-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
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
    fn save_list_show_rm_roundtrip() {
        in_temp_project(|| {
            let saved = save("notes1", "note", b"hello agent", false).unwrap();
            assert!(!saved.overwrote);
            assert_eq!(saved.size, 11);

            let items = list(None).unwrap();
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].kind, "note");

            let content = show("notes1", None).unwrap();
            assert_eq!(content.bytes, b"hello agent");
            assert_eq!(content.kind, "note");

            let removed = remove("notes1", None).unwrap();
            assert_eq!(removed.len(), 1);
            assert!(list(None).unwrap().is_empty());
        });
    }

    #[test]
    fn refuses_overwrite_without_force() {
        in_temp_project(|| {
            save("x", "hex", b"aa bb", false).unwrap();
            let err = save("x", "hex", b"cc dd", false).unwrap_err();
            assert!(err.to_string().contains("already exists"));
            let saved = save("x", "hex", b"cc dd", true).unwrap();
            assert!(saved.overwrote);
        });
    }

    #[test]
    fn rejects_unknown_kind_and_bad_name() {
        in_temp_project(|| {
            assert!(save("x", "bogus", b"1", false).is_err());
            assert!(save("../etc", "note", b"1", false).is_err());
        });
    }
}
