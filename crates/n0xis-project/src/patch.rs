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

#[cfg(feature = "live")]
use n0xis_contracts::Va;
#[cfg(feature = "live")]
use n0xis_sources::{LiveProcess, MemorySource};

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

#[cfg(feature = "live")]
fn to_hex_spaced(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

/// Parse this module's own `before_hex`/`after_hex` wire format (space-separated
/// `%02x`) — not the flexible free-form parser the CLI uses for user-typed
/// `--bytes` flags (which also accepts `0x`/comma separators); a `PatchRecord`
/// is always our own serialization, so this only needs to invert `to_hex_spaced`.
#[cfg(feature = "live")]
fn parse_hex_spaced(s: &str) -> Result<Vec<u8>> {
    s.split_whitespace()
        .map(|tok| u8::from_str_radix(tok, 16).map_err(|e| anyhow!("bad hex byte '{tok}': {e}")))
        .collect()
}

/// Read-verify-write-journal an in-place byte patch against a live process.
/// Shared by the CLI's `patch apply` and any other frontend driving a
/// live-process patch (e.g. n0xis-hud adapters) — same read/verify/journal
/// sequence either way, not a copy per caller.
#[cfg(feature = "live")]
pub fn apply(live: &LiveProcess, pid: u32, addr: Va, desired: &[u8]) -> Result<PatchRecord> {
    let before = live.read(addr, desired.len()).map_err(|e| anyhow!("{e}"))?;
    live.write(addr, desired).map_err(|e| anyhow!("{e}"))?;
    let after = live.read(addr, desired.len()).map_err(|e| anyhow!("{e}"))?;
    if after != desired {
        return Err(anyhow!("post-write bytes do not match"));
    }
    let rec = PatchRecord {
        id: new_patch_id(),
        pid,
        address: addr.to_string(),
        size: desired.len(),
        before_hex: to_hex_spaced(&before),
        after_hex: to_hex_spaced(desired),
        status: "applied".to_string(),
        created_at_unix: now_unix_secs(),
        undone_at_unix: None,
    };
    save(&rec)?;
    Ok(rec)
}

/// Restore a patch's `before` bytes and mark the record undone in place.
/// Refuses (unless `force`) if the live bytes no longer match what was
/// applied, mirroring the CLI's `patch undo` safety check exactly.
#[cfg(feature = "live")]
pub fn undo(rec: &mut PatchRecord, live: &LiveProcess, force: bool) -> Result<()> {
    if rec.status != "applied" {
        return Err(anyhow!("patch {} status is '{}', nothing to undo", rec.id, rec.status));
    }
    let addr = Va::parse(&rec.address).map_err(|e| anyhow!("{e}"))?;
    let before = parse_hex_spaced(&rec.before_hex)?;
    let after = parse_hex_spaced(&rec.after_hex)?;
    let current = live.read(addr, after.len()).map_err(|e| anyhow!("{e}"))?;
    if current != after && !force {
        return Err(anyhow!("current bytes no longer match the applied patch; re-run with --force"));
    }
    live.write(addr, &before).map_err(|e| anyhow!("{e}"))?;
    rec.status = "undone".to_string();
    rec.undone_at_unix = Some(now_unix_secs());
    save(rec)?;
    Ok(())
}
