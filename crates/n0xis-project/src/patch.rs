// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

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

// Not gated on the `live` feature: `MemorySource` is the OS-free seam, so the
// read/verify/write/journal sequence below works against a live process on any
// OS, a remote agent, or anything else implementing it. Only `locator` needs a
// concrete Win32 target, and that is what `live` still gates.
use n0xis_contracts::Va;
use n0xis_sources::MemorySource;

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
    /// The command that wrote this for the length of its own run, on a record that
    /// exists only while that run has something in the target. Seen by a person, the
    /// run was killed, and `patch undo` is what puts the bytes back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planted_by: Option<String>,
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

/// Take a record back that no longer stands for anything in a target.
fn remove(rec: &PatchRecord) -> Result<()> {
    let path = record_path(&rec.id)?;
    fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))
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

fn to_hex_spaced(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

/// Parse this module's own `before_hex`/`after_hex` wire format (space-separated
/// `%02x`) — not the flexible free-form parser the CLI uses for user-typed
/// `--bytes` flags (which also accepts `0x`/comma separators); a `PatchRecord`
/// is always our own serialization, so this only needs to invert `to_hex_spaced`.
fn parse_hex_spaced(s: &str) -> Result<Vec<u8>> {
    s.split_whitespace()
        .map(|tok| u8::from_str_radix(tok, 16).map_err(|e| anyhow!("bad hex byte '{tok}': {e}")))
        .collect()
}

/// The record of `after` about to replace `before` at `addr`, written before the bytes
/// are. A process can be killed at any instruction, and what is written first is what
/// outlives it: bytes with no record cannot be put back, and a record of bytes that
/// never landed only makes `patch undo` refuse.
pub fn record_before_writing(pid: u32, addr: Va, before: &[u8], after: &[u8], planted_by: Option<&str>) -> Result<PatchRecord> {
    let rec = PatchRecord {
        id: new_patch_id(),
        pid,
        address: addr.to_string(),
        size: after.len(),
        before_hex: to_hex_spaced(before),
        after_hex: to_hex_spaced(after),
        status: "applied".to_string(),
        created_at_unix: now_unix_secs(),
        undone_at_unix: None,
        planted_by: planted_by.map(str::to_string),
    };
    save(&rec)?;
    Ok(rec)
}

/// The write that a [`record_before_writing`] announced did not happen: nothing to undo.
pub fn take_back(rec: &PatchRecord) -> Result<()> {
    remove(rec)
}

/// A command that planted bytes for the length of its run has returned. If they are
/// out of the target again, its record goes, so that `patch list` and `patch undo` see
/// only what is still there. Whether they are out is read from the target, and not
/// taken from the command: a restore can fail. `None` is a target that is gone, which
/// holds nothing. Returns whether the bytes are out.
pub fn settle_planted(rec: &PatchRecord, live: Option<&dyn MemorySource>) -> Result<bool> {
    let addr = Va::parse(&rec.address).map_err(|e| anyhow!("{e}"))?;
    let out = match live {
        Some(live) => live.read(addr, rec.size).map_err(|e| anyhow!("{e}"))? == parse_hex_spaced(&rec.before_hex)?,
        None => true,
    };
    if out {
        remove(rec)?;
    }
    Ok(out)
}

/// Read-verify-write-journal an in-place byte patch against a live process.
/// Shared by the CLI's `patch apply` and any other frontend driving a
/// live-process patch — same read/verify/journal sequence either way, not a
/// copy per caller.
pub fn apply(live: &dyn MemorySource, pid: u32, addr: Va, desired: &[u8]) -> Result<PatchRecord> {
    let before = live.read(addr, desired.len()).map_err(|e| anyhow!("{e}"))?;
    let rec = record_before_writing(pid, addr, &before, desired, None)?;
    if let Err(e) = live.write(addr, desired) {
        take_back(&rec)?;
        return Err(anyhow!("{e}"));
    }
    let after = live.read(addr, desired.len()).map_err(|e| anyhow!("{e}"))?;
    if after != desired {
        // The record stays: something was written, and `--force` can put back the rest.
        return Err(anyhow!("post-write bytes do not match"));
    }
    Ok(rec)
}

/// Restore a patch's `before` bytes and mark the record undone in place.
/// Refuses (unless `force`) if the live bytes no longer match what was
/// applied, mirroring the CLI's `patch undo` safety check exactly.
pub fn undo(rec: &mut PatchRecord, live: &dyn MemorySource, force: bool) -> Result<()> {
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
