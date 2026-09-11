// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The currently-attached target under `.n0x/session.json` — lets one
//! frontend's `attach` (typically `n0xis-mcp`, a long-lived server) set a
//! default `pid`/`file` that other tool calls can omit, and lets the CLI and
//! MCP server (both readers/writers of the same `.n0x/`) share it (ROADMAP
//! Phase 5: "Session/attach state shared with CLI via `n0xis-project`").
//! Storage only, same split as [`selection`](crate::selection).

use std::fs;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::resolve;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub attached_at_unix: u64,
}

fn path() -> Result<std::path::PathBuf> {
    Ok(resolve()?.session_path())
}

/// Record a live-process attach as the session default.
pub fn attach_pid(pid: u32) -> Result<SessionRecord> {
    let record = SessionRecord { pid: Some(pid), file: None, attached_at_unix: crate::selection::now_unix_secs() };
    save(&record)?;
    Ok(record)
}

/// Record a static-file attach as the session default.
pub fn attach_file(file: &str) -> Result<SessionRecord> {
    let record = SessionRecord { pid: None, file: Some(file.to_string()), attached_at_unix: crate::selection::now_unix_secs() };
    save(&record)?;
    Ok(record)
}

fn save(record: &SessionRecord) -> Result<()> {
    let path = path()?;
    let json = serde_json::to_string_pretty(record).context("serialize session.json")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// The current session default, if any (and if its `session.json` still parses).
pub fn current() -> Result<Option<SessionRecord>> {
    let path = path()?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&raw).context("parse session.json")?))
}

/// Clear the session default (e.g. on detach).
pub fn clear() -> Result<()> {
    let path = path()?;
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CWD_TEST_LOCK;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn in_temp_project<T>(f: impl FnOnce() -> T) -> T {
        let _guard = CWD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "n0xis-session-test-{}",
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
    fn attach_read_clear_roundtrip() {
        in_temp_project(|| {
            assert!(current().unwrap().is_none());
            attach_pid(1234).unwrap();
            let s = current().unwrap().expect("session set");
            assert_eq!(s.pid, Some(1234));
            assert!(s.file.is_none());

            attach_file("game.exe").unwrap();
            let s = current().unwrap().expect("session set");
            assert_eq!(s.file.as_deref(), Some("game.exe"));
            assert!(s.pid.is_none(), "re-attaching switches the target, not accumulates it");

            clear().unwrap();
            assert!(current().unwrap().is_none());
        });
    }
}
