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
use n0xis_sources::{MemorySource, TargetSlots, WatchKind, WatchSlot};

/// One journaled patch of bytes. `before_hex`/`after_hex` are space-separated hex.
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

/// A debug register a command armed for the length of its own run, on every thread of a
/// target. Not a [`PatchRecord`], and without a `before_hex`: there are no bytes to compare
/// or put back, [`undo`] takes bytes and cannot be handed this, and an older build of this
/// tool, reading this file, skips it in `patch list` and refuses it in `patch undo --id`
/// for the missing fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchRecord {
    pub id: String,
    pub pid: u32,
    pub address: Va,
    pub debug_register: DebugRegister,
    pub status: Armed,
    pub created_at_unix: u64,
    /// The command that armed it. Seen by a person, the run was killed, and `patch undo`
    /// is what clears it.
    pub planted_by: String,
}

/// What a [`WatchRecord`] has in slot 0 of each thread, besides the address.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DebugRegister {
    pub kind: WatchKind,
    pub len: u8,
}

/// A record of a debug register exists only while one may be armed, and goes when it is
/// not: it has no `undone` to be, unlike bytes, which keep theirs for the audit trail.
/// Written as `applied`, which is what `patch list --status applied` looks for.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Armed {
    #[serde(rename = "applied")]
    Applied,
}

impl WatchRecord {
    /// What this record says is in the target's debug registers.
    pub fn slot(&self) -> WatchSlot {
        WatchSlot { addr: self.address, kind: self.debug_register.kind, len: self.debug_register.len }
    }
}

/// What a file in the journal is. Untagged, so a record of bytes stays the file it always
/// was and a journal from before the debug register reads as it did.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Record {
    Bytes(PatchRecord),
    DebugRegister(WatchRecord),
}

impl Record {
    pub fn id(&self) -> &str {
        match self {
            Record::Bytes(r) => &r.id,
            Record::DebugRegister(r) => &r.id,
        }
    }

    pub fn status(&self) -> &str {
        match self {
            Record::Bytes(r) => &r.status,
            Record::DebugRegister(_) => "applied",
        }
    }

    fn created_at_unix(&self) -> u64 {
        match self {
            Record::Bytes(r) => r.created_at_unix,
            Record::DebugRegister(r) => r.created_at_unix,
        }
    }
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
    write_record(&rec.id, rec)
}

fn write_record(id: &str, rec: &impl Serialize) -> Result<PathBuf> {
    let path = record_path(id)?;
    let json = serde_json::to_string_pretty(rec).context("serialize patch record")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// Take a record back that no longer stands for anything in a target.
fn remove(id: &str) -> Result<()> {
    let path = record_path(id)?;
    fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))
}

pub fn load_by_id(id: &str) -> Result<Record> {
    let path = record_path(id)?;
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("patch record {id} not found at {}", path.display()))?;
    serde_json::from_str(&raw).context("parse patch record")
}

/// The most recently created patch record, or an error if none exist.
pub fn load_latest() -> Result<Record> {
    let mut records = list(usize::MAX)?;
    records
        .drain(..)
        .next()
        .ok_or_else(|| anyhow!("no patch records under .n0x/patches/"))
}

/// All records, newest first, capped at `limit`.
pub fn list(limit: usize) -> Result<Vec<Record>> {
    let dir = patches_dir()?;
    let mut records: Vec<Record> = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(raw) = fs::read_to_string(&path)
            && let Ok(rec) = serde_json::from_str::<Record>(&raw)
        {
            records.push(rec);
        }
    }
    records.sort_by(|a, b| b.created_at_unix().cmp(&a.created_at_unix()).then_with(|| b.id().cmp(a.id())));
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
    remove(&rec.id)
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
        remove(&rec.id)?;
    }
    Ok(out)
}

/// The record of a debug register about to be armed on every thread of `pid`, written
/// before it is: a process can be killed at any instruction, and what is written first is
/// what outlives it. The registers stay in the threads when their tracer dies, and a thread
/// that keeps one dies at its next hit.
pub fn record_before_arming(pid: u32, slot: &WatchSlot, planted_by: &str) -> Result<WatchRecord> {
    let rec = WatchRecord {
        id: new_patch_id(),
        pid,
        address: slot.addr,
        debug_register: DebugRegister { kind: slot.kind, len: slot.len },
        status: Armed::Applied,
        created_at_unix: now_unix_secs(),
        planted_by: planted_by.to_string(),
    };
    write_record(&rec.id, &rec)?;
    Ok(rec)
}

/// The record goes if `found`, read from the target, says the debug register is in no
/// thread of it. Returns whether it is. Whether it went is not taken from the command that
/// armed it: a thread can refuse to stop, and a clear can fail.
pub fn settle_armed(rec: &WatchRecord, found: &TargetSlots) -> Result<bool> {
    let clear = found.clear();
    if clear {
        remove(&rec.id)?;
    }
    Ok(clear)
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

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = r#"{"id":"1-2","pid":7,"address":"0x1000","size":1,"before_hex":"90","after_hex":"cc","status":"undone","created_at_unix":3,"undone_at_unix":4}"#;
    const WATCH: &str = r#"{"id":"1-2","pid":7,"address":"0x1000","debug_register":{"kind":"write","len":8},"status":"applied","created_at_unix":3,"planted_by":"debug watch"}"#;

    /// A file of bytes reads as bytes and is written back as the same file, and what is
    /// listed comes out field for field.
    #[test]
    fn a_record_of_bytes_is_the_file_it_always_was() {
        let rec: Record = serde_json::from_str(OLD).unwrap();
        assert!(matches!(rec, Record::Bytes(_)));
        assert_eq!(serde_json::to_string(&rec).unwrap(), OLD);
        assert_eq!(rec.status(), "undone");
    }

    #[test]
    fn a_record_of_a_debug_register_is_never_read_as_bytes() {
        let rec: Record = serde_json::from_str(WATCH).unwrap();
        let Record::DebugRegister(watch) = &rec else { panic!("{rec:?}") };
        assert_eq!(watch.slot(), WatchSlot { addr: Va(0x1000), kind: WatchKind::Write, len: 8 });
        assert_eq!(rec.status(), "applied");
        assert_eq!(serde_json::to_string(&rec).unwrap(), WATCH);
        // What an older build of this tool does with it: the shape it reads, and it does not fit.
        let as_bytes = serde_json::from_str::<PatchRecord>(WATCH).unwrap_err().to_string();
        assert!(as_bytes.contains("missing field"), "{as_bytes}");
    }

    /// A record of a debug register exists only while one may be armed.
    #[test]
    fn a_debug_register_cannot_be_on_record_as_undone() {
        assert!(serde_json::from_str::<Record>(&WATCH.replace("applied", "undone")).is_err());
    }
}
