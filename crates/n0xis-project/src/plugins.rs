//! Registered analysis plugins under `.n0x/plugins.json` — durable `name` →
//! spawn command bindings an agent registers once
//! (`docs/COMMUNITY_ROADMAP.md`'s "Plugin system"). Storage only: actually
//! spawning a plugin and merging its findings is `n0xis-pipeline::PluginHost`'s
//! job, same storage/logic split as [`selection`](crate::selection) and
//! [`patch`](crate::patch).

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::resolve;

/// One registered plugin: a name, the argv to spawn it (a single string,
/// split via `n0xis_sources::split_command_line` at call time — the exact
/// same contract as `--remote-cmd`), and which artifact kind(s) it wants to
/// see on stdin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRecord {
    pub name: String,
    pub command: String,
    /// Artifact kinds this plugin declares it handles: any of
    /// `"cfg"` / `"pseudo"` / `"discover"` (`CfgArtifact` / `PseudoFunction` /
    /// `DiscoverArtifact`).
    pub handles: Vec<String>,
    pub created_at_unix: u64,
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_all() -> Result<Vec<PluginRecord>> {
    let path = resolve()?.plugins_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&raw).context("parse plugins.json")
}

fn save_all(records: &[PluginRecord]) -> Result<()> {
    let path = resolve()?.plugins_path();
    let json = serde_json::to_string_pretty(records).context("serialize plugins.json")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Register (or overwrite, by name) a plugin.
pub fn add(name: &str, command: &str, handles: Vec<String>) -> Result<PluginRecord> {
    if name.is_empty() {
        bail!("plugin name must not be empty");
    }
    if command.trim().is_empty() {
        bail!("plugin command must not be empty");
    }
    let record = PluginRecord {
        name: name.to_string(),
        command: command.to_string(),
        handles,
        created_at_unix: now_unix_secs(),
    };
    let mut records = load_all()?;
    records.retain(|p| !p.name.eq_ignore_ascii_case(name));
    records.push(record.clone());
    save_all(&records)?;
    Ok(record)
}

/// All registered plugins, name-sorted.
pub fn list() -> Result<Vec<PluginRecord>> {
    let mut records = load_all()?;
    records.sort_by_key(|p| p.name.to_ascii_lowercase());
    Ok(records)
}

/// Every registered plugin that declares it handles `kind`
/// (`"cfg"`/`"pseudo"`/`"discover"`) — what `PluginHost` calls after a pass
/// runs.
pub fn for_kind(kind: &str) -> Result<Vec<PluginRecord>> {
    Ok(load_all()?
        .into_iter()
        .filter(|p| p.handles.iter().any(|h| h.eq_ignore_ascii_case(kind)))
        .collect())
}

/// A single plugin by name (case-insensitive).
pub fn get(name: &str) -> Result<PluginRecord> {
    load_all()?
        .into_iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| anyhow!("no plugin named '{name}'"))
}

/// Remove a plugin by name. Returns `true` if one was removed.
pub fn remove(name: &str) -> Result<bool> {
    let mut records = load_all()?;
    let before = records.len();
    records.retain(|p| !p.name.eq_ignore_ascii_case(name));
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
            "n0xis-plugin-test-{}",
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
    fn add_list_get_remove_roundtrip() {
        in_temp_project(|| {
            add("vendor-sigs", "vendor-plugin --mode sigs", vec!["cfg".into()]).unwrap();
            add("annotator", "annotator-bin", vec!["pseudo".into(), "discover".into()]).unwrap();

            let all = list().unwrap();
            assert_eq!(all.len(), 2);
            assert_eq!(all[0].name, "annotator"); // name-sorted

            let p = get("VENDOR-SIGS").unwrap(); // case-insensitive
            assert_eq!(p.command, "vendor-plugin --mode sigs");

            let cfg_plugins = for_kind("cfg").unwrap();
            assert_eq!(cfg_plugins.len(), 1);
            assert_eq!(cfg_plugins[0].name, "vendor-sigs");

            assert!(remove("vendor-sigs").unwrap());
            assert!(!remove("vendor-sigs").unwrap(), "already removed");
            assert_eq!(list().unwrap().len(), 1);
        });
    }

    #[test]
    fn add_overwrites_same_name() {
        in_temp_project(|| {
            add("p", "old-cmd", vec!["cfg".into()]).unwrap();
            add("p", "new-cmd", vec!["pseudo".into()]).unwrap();
            let all = list().unwrap();
            assert_eq!(all.len(), 1, "overwrite, not append");
            assert_eq!(all[0].command, "new-cmd");
        });
    }

    #[test]
    fn rejects_empty_command() {
        in_temp_project(|| {
            let err = add("bad", "", vec!["cfg".into()]).unwrap_err();
            assert!(err.to_string().contains("command must not be empty"));
        });
    }
}
