// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The user's own settings: one JSON file in the user's configuration directory, written by rename,
//! read through `n0x config` by the CLI and by the GUI, which keeps no copy of its own.
//!
//! A project's configuration is `.n0x/` and stays there; nothing else has moved here.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::{Refusal, Why, write_by_rename};

/// The daily check and the notice. On by default.
pub const UPDATE_CHECK: &str = "update.check";
/// Install without being asked. Off by default.
pub const UPDATE_AUTO: &str = "update.auto";
/// An address asked for the manifest ahead of the built-in two. It must still be signed.
pub const UPDATE_MANIFEST_URL: &str = "update.manifest_url";

/// Every setting there is, and its default.
pub fn known() -> [(&'static str, Value); 3] {
    [(UPDATE_CHECK, json!(true)), (UPDATE_AUTO, json!(false)), (UPDATE_MANIFEST_URL, Value::Null)]
}

const FILE: &str = "config.json";

/// The user's configuration directory for this tool. `N0X_CONFIG_DIR` overrides it, because on
/// Windows the system location is a known folder no environment variable moves, and a test must not
/// write to the user's own.
pub fn user_dir() -> Option<PathBuf> {
    match std::env::var_os("N0X_CONFIG_DIR") {
        Some(dir) if !dir.is_empty() => Some(PathBuf::from(dir)),
        _ => dirs::config_dir().map(|d| d.join("n0x")),
    }
}

/// The settings the code reads, with their defaults where the file is silent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub check: bool,
    pub auto: bool,
    pub manifest_url: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { check: true, auto: false, manifest_url: None }
    }
}

impl Settings {
    /// A file that does not read is a refusal, never the defaults: `update.check` is on by default,
    /// so reading a damaged file as "nothing set" would start making requests for a user who had
    /// turned them off.
    pub fn load(dir: &Path) -> Result<Settings, Refusal> {
        let map = read_file(dir)?;
        let unreadable = |key: &str, wanted: &str| Refusal::new(Why::ConfigUnreadable, format!("{}: {key} is not {wanted}", dir.join(FILE).display()));
        let boolean = |key: &str, default: bool| match map.get(key) {
            None => Ok(default),
            Some(v) => v.as_bool().ok_or_else(|| unreadable(key, "true or false")),
        };
        let manifest_url = match map.get(UPDATE_MANIFEST_URL) {
            None | Some(Value::Null) => None,
            Some(v) => Some(v.as_str().ok_or_else(|| unreadable(UPDATE_MANIFEST_URL, "a string"))?.to_string()),
        };
        Ok(Settings { check: boolean(UPDATE_CHECK, true)?, auto: boolean(UPDATE_AUTO, false)?, manifest_url })
    }
}

fn read_file(dir: &Path) -> Result<Map<String, Value>, Refusal> {
    let path = dir.join(FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Map::new()),
        Err(e) => return Err(Refusal::new(Why::ConfigUnreadable, format!("{}: {e}", path.display()))),
    };
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(Refusal::new(Why::ConfigUnreadable, format!("{} is not a JSON object", path.display()))),
        Err(e) => Err(Refusal::new(Why::ConfigUnreadable, format!("{}: {e}", path.display()))),
    }
}

fn unknown_setting(key: &str) -> Refusal {
    let names: Vec<&str> = known().iter().map(|(name, _)| *name).collect();
    Refusal::new(Why::UnknownSetting, format!("there is no setting {key:?}; there are {}", names.join(", ")))
}

/// One row of `config get`: the value, what it is by default, and whether the file set it.
fn row(key: &str, default: &Value, map: &Map<String, Value>) -> Value {
    let set = map.get(key);
    json!({ "key": key, "value": set.unwrap_or(default), "default": default, "set": set.is_some() })
}

/// `n0x config get [key]`.
pub fn get(dir: &Path, key: Option<&str>) -> Result<Value, Refusal> {
    let map = read_file(dir)?;
    let settings: Vec<Value> = match key {
        Some(key) => {
            let known = known();
            let (name, default) = known.iter().find(|(name, _)| *name == key).ok_or_else(|| unknown_setting(key))?;
            vec![row(name, default, &map)]
        }
        None => known().iter().map(|(name, default)| row(name, default, &map)).collect(),
    };
    Ok(json!({ "file": dir.join(FILE).display().to_string(), "settings": settings }))
}

/// `n0x config set <key> <value>`.
///
/// Keys this build does not know, which a later one wrote, are kept. A file that does not read
/// is refused rather than overwritten: it may hold what the user set.
pub fn set(dir: &Path, key: &str, value: &str) -> Result<Value, Refusal> {
    let known = known();
    let (name, default) = known.iter().find(|(name, _)| *name == key).ok_or_else(|| unknown_setting(key))?;
    let parsed = if default.is_boolean() {
        match value {
            "true" => json!(true),
            "false" => json!(false),
            _ => return Err(Refusal::new(Why::BadSettingValue, format!("{key} is true or false, not {value:?}"))),
        }
    } else if value.is_empty() {
        Value::Null
    } else if value.starts_with("https://") {
        json!(value)
    } else {
        return Err(Refusal::new(Why::BadSettingValue, format!("{key} must be an https:// address, or empty to clear it")));
    };
    let mut map = read_file(dir)?;
    if parsed.is_null() {
        map.remove(*name);
    } else {
        map.insert((*name).to_string(), parsed);
    }
    let path = dir.join(FILE);
    let text = serde_json::to_vec_pretty(&map).map_err(|e| Refusal::new(Why::ConfigUnreadable, e.to_string()))?;
    write_by_rename(&path, &text).map_err(|e| Refusal::new(Why::ConfigUnreadable, format!("{}: {e}", path.display())))?;
    get(dir, Some(key))
}
