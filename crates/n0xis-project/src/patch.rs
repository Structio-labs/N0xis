//! Persisted patch journal under `.n0x/patches/` — the durable undo record.
//!
//! Each applied patch writes a `patch-<id>.json` capturing the before/after
//! bytes so a write can always be rolled back, even across sessions. Storage
//! only: the read/write orchestration lives in the frontend over the
//! `MemorySource` seam. Back-compat: same directory and record shape as v0.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::resolve;

/// One journaled patch. `before_hex`/`after_hex` are space-separated hex.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchRecord {
    pub id: String,
    pub pid: u32,
    pub address: String,
    pub size: usize,
    pub before_hex: String,
    pub after_hex: String,
    /// `"applied"` or `"undone"`.
    pub status: String,
    pub created_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undone_at_unix: Option<u64>,
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A short, sortable, unique id (`<unixsecs>-<nanos>`).
pub fn new_patch_id() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("{}-{:09}", now.as_secs(), now.subsec_nanos())
}

pub fn patches_dir() -> Result<PathBuf> {
    let root = resolve()?;
    let dir = root.dir.join("patches");
    fs::create_dir_all(&dir).context("Failed to create .n0x/patches directory")?;
    Ok(dir)
}

pub fn record_path(id: &str) -> Result<PathBuf> {
    Ok(patches_dir()?.join(format!("patch-{id}.json")))
}

pub fn save(rec: &PatchRecord) -> Result<PathBuf> {
    let path = record_path(&rec.id)?;
    let json = serde_json::to_string_pretty(rec).context("serialize patch record")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

pub fn load_by_id(id: &str) -> Result<PatchRecord> {
    let path = record_path(id)?;
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("patch record {id} not found at {}", path.display()))?;
    serde_json::from_str(&raw).context("parse patch record")
}

/// The most recently created patch record, or an error if none exist.
pub fn load_latest() -> Result<PatchRecord> {
    let mut records = list(usize::MAX)?;
    records
        .drain(..)
        .next()
        .ok_or_else(|| anyhow!("no patch records under .n0x/patches/"))
}

/// All records, newest first, capped at `limit`.
pub fn list(limit: usize) -> Result<Vec<PatchRecord>> {
    let dir = patches_dir()?;
    let mut records: Vec<PatchRecord> = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(raw) = fs::read_to_string(&path)
            && let Ok(rec) = serde_json::from_str::<PatchRecord>(&raw)
        {
            records.push(rec);
        }
    }
    records.sort_by(|a, b| b.created_at_unix.cmp(&a.created_at_unix).then(b.id.cmp(&a.id)));
    records.truncate(limit);
    Ok(records)
}
