// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A hardware watchpoint on the record: the one way a command arms a debug register.
//!
//! The sequence is a fact with two front doors: `debug watch` and `provenance trace` on
//! the CLI, and `provenance_trace` over MCP. A debug register stays in a thread that
//! outlives its tracer, and that thread dies at its next hit. Nothing can handle
//! `SIGKILL` or `TerminateProcess`, so the journal has it before the target does, and
//! `patch undo` clears it from there.

use n0xis_contracts::{Module, Va};
use n0xis_project::patch as pj;
use n0xis_sources::{await_watchpoint_hit_where, read_watch_slots, AwaitHitOutcome, RegCond, SourceError, WatchKind};

/// What to watch, in whose name.
pub struct Watch<'a> {
    pub pid: u32,
    pub addr: Va,
    pub kind: WatchKind,
    pub len: u8,
    pub timeout_ms: u64,
    pub stack_qwords: usize,
    pub module: Option<&'a Module>,
    pub exclude_rip: &'a [(u64, u64)],
    pub cond: Option<&'a RegCond>,
    /// The command, as `patch list` will name it.
    pub planted_by: &'a str,
    /// Say the record's id on stderr at arming, for whoever has to use it.
    pub announce: bool,
}

/// How a watch on the record failed.
pub enum WatchFailed {
    /// The watch itself. The debug register is known to be out of the target.
    Source(SourceError),
    /// Whatever the watch answered, the register is not known to be out of the target,
    /// and that comes first.
    Left { addr: Va, id: String },
}

impl std::fmt::Display for WatchFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WatchFailed::Source(e) => write!(f, "{e}"),
            WatchFailed::Left { addr, id } => write!(
                f,
                "the debug register at {addr} could not be seen to be clear: `n0xis patch undo --id {id}` clears it, and until then a thread still holding it dies at its next hit"
            ),
        }
    }
}

/// Arm, wait, and read back from the target that it is clear. The record is written
/// before the first register, after the attach, so a run that could not attach leaves
/// nothing, and if it cannot be written nothing is armed.
pub fn await_watch_on_record(w: &Watch<'_>) -> Result<AwaitHitOutcome, WatchFailed> {
    let mut record = None;
    let result = await_watchpoint_hit_where(w.pid, w.addr, w.kind, w.len, w.timeout_ms, w.stack_qwords, w.module, w.exclude_rip, w.cond, &mut |slot| {
        let rec = pj::record_before_arming(w.pid, slot, w.planted_by)
            .map_err(|e| format!("nothing was armed, because no record of it could be kept: {e}"))?;
        if w.announce {
            eprintln!("[n0x] watchpoint at {} recorded as patch {}: if this run is killed, `n0xis patch undo --id {}` clears the debug register", w.addr, rec.id, rec.id);
        }
        record = Some(rec);
        Ok(())
    });
    if let Some(rec) = record {
        // Read after the run let go of the target, by what is now in its threads.
        let clear = read_watch_slots(w.pid, &rec.slot()).is_ok_and(|found| matches!(pj::settle_armed(&rec, &found), Ok(true)));
        if !clear {
            return Err(WatchFailed::Left { addr: w.addr, id: rec.id });
        }
    }
    result.map_err(WatchFailed::Source)
}
