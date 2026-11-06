// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What a hardware watchpoint is, in the x86 debug registers: the CPU's encoding, which
//! is the same on either OS, and how a target's threads stand against one.
//!
//! Outside the `live` feature, because the patch journal writes this down and the journal
//! is on every target: a journal is only a file, and it needs no debugger to be read.

use n0xis_contracts::Va;
use serde::{Deserialize, Serialize};

use crate::SourceError;

/// What a hardware watchpoint traps on. There is no hardware "read-only" mode on
/// x86 — only `Write` or `ReadOrWrite` — so this doesn't invent one (CONCEPT §3
/// rule 6: the API reflects what the CPU can actually do). Same three modes on
/// Windows and Linux; the DR7 encoding below is the CPU's, not the OS's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchKind {
    Execute,
    Write,
    ReadOrWrite,
}

impl WatchKind {
    fn rw_bits(self) -> u64 {
        match self {
            WatchKind::Execute => 0b00,
            WatchKind::Write => 0b01,
            WatchKind::ReadOrWrite => 0b11,
        }
    }
}

/// Intel SDM Vol 3B §17.2.5: LEN field encodes 1/2/8/4 bytes for `00/01/10/11`
/// — note the non-monotonic order. The address must be naturally aligned to
/// `len` or the CPU silently ignores the high bits; we reject that instead of
/// installing a watchpoint that won't fire as described.
fn len_bits(addr: Va, len: u8) -> Result<u64, SourceError> {
    if len > 1 && !addr.0.is_multiple_of(len as u64) {
        return Err(SourceError::Os(format!("watchpoint address {addr} is not {len}-byte aligned")));
    }
    match len {
        1 => Ok(0b00),
        2 => Ok(0b01),
        8 => Ok(0b10),
        4 => Ok(0b11),
        _ => Err(SourceError::Os(format!("unsupported watchpoint length {len} (must be 1, 2, 4, or 8)"))),
    }
}

/// `L0` and `G0`, either of which arms slot 0.
const DR7_ENABLE: u64 = 0b11;
/// `RW0` and `LEN0`.
const DR7_RW_LEN: u64 = 0b1111 << 16;

/// The one watchpoint a command arms, on each thread: slot 0, which is the only slot any
/// command arms, so a journal record of one does not need to name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchSlot {
    pub addr: Va,
    pub kind: WatchKind,
    pub len: u8,
}

impl WatchSlot {
    /// DR7 bits for slot 0 only: `L0` (local enable, bit 0), bit 10 (reserved,
    /// conventionally set), `RW0` (bits 16-17), `LEN0` (bits 18-19). The exact same
    /// encoding the CPU consumes whether the write comes from `SetThreadContext`
    /// (Win32) or `PTRACE_POKEUSER` (Linux).
    pub fn dr7_bits(&self) -> Result<u64, SourceError> {
        if self.kind == WatchKind::Execute && self.len != 1 {
            return Err(SourceError::Os("an execute watchpoint must have length 1 (Intel SDM Vol 3B §17.2.5)".into()));
        }
        let rw = self.kind.rw_bits();
        let lb = len_bits(self.addr, self.len)?;
        Ok(1u64 | (1u64 << 10) | (rw << 16) | (lb << 18))
    }

    /// Whether a thread's DR0 and DR7 hold this watchpoint, armed: its address, its type
    /// and length, and either enable bit. Slots 1 to 3 do not come into it, whatever they
    /// hold: those are the target's or another tool's. A slot this cannot encode holds nothing.
    pub fn held_in(&self, dr0: u64, dr7: u64) -> bool {
        self.dr7_bits().is_ok_and(|bits| dr0 == self.addr.0 && dr7 & DR7_ENABLE != 0 && dr7 & DR7_RW_LEN == bits & DR7_RW_LEN)
    }

    /// DR7 with slot 0 out of it, and every other bit as it was.
    pub fn cleared_from(dr7: u64) -> u64 {
        dr7 & !(DR7_ENABLE | DR7_RW_LEN)
    }
}

/// How the threads of a process that exists stood against one [`WatchSlot`], read from them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlotCensus {
    /// Threads it found.
    pub threads: usize,
    /// Of those, the ones it could not stop or read. Each may still hold the slot.
    pub unread: usize,
    /// Threads that hold the slot now.
    pub holding: usize,
    /// Threads the slot was cleared from by this walk, read back as clear.
    pub cleared: usize,
}

/// What looking for a [`WatchSlot`] in a process found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetSlots {
    /// There is no such process. It holds nothing.
    Gone,
    Present(SlotCensus),
}

impl TargetSlots {
    /// Whether the slot is known to be in no thread. A thread that could not be read is
    /// not known to be clear.
    pub fn clear(&self) -> bool {
        match self {
            TargetSlots::Gone => true,
            TargetSlots::Present(c) => c.holding == 0 && c.unread == 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOT: WatchSlot = WatchSlot { addr: Va(0x1000), kind: WatchKind::Write, len: 8 };

    /// DR7 as the two systems hand it back: the kernel keeps bit 10, and another OS need
    /// not, nor need it say `L0` rather than `G0`.
    #[test]
    fn held_compares_the_slot_and_not_the_rest_of_dr7() {
        let bits = SLOT.dr7_bits().unwrap();
        assert_eq!(bits, 0x90401, "RW0=01 LEN0=10, the Intel SDM's encoding");
        assert!(SLOT.held_in(0x1000, bits));
        assert!(SLOT.held_in(0x1000, bits & !(1 << 10)));
        assert!(SLOT.held_in(0x1000, (bits & !1) | 0b10), "G0 arms it as well as L0");
        assert!(!SLOT.held_in(0x2000, bits), "another address");
        assert!(!SLOT.held_in(0x1000, bits & !1), "disarmed");
        assert!(!SLOT.held_in(0x1000, bits ^ (1 << 17)), "another type");
        assert!(!SLOT.held_in(0x1000, bits ^ (1 << 19)), "another length");
    }

    #[test]
    fn clearing_leaves_every_other_slot_as_it_was() {
        // Slot 1 armed by someone else: L1, RW1=01, LEN1=11.
        let theirs = (1u64 << 2) | (0b1101 << 20);
        let both = SLOT.dr7_bits().unwrap() | theirs;
        assert_eq!(WatchSlot::cleared_from(both), theirs | (1 << 10));
    }

    #[test]
    fn a_slot_the_cpu_cannot_hold_is_held_nowhere() {
        let bad = WatchSlot { addr: Va(0x1001), kind: WatchKind::Write, len: 8 };
        assert!(!bad.held_in(0x1001, 0x90401));
    }

    #[test]
    fn only_a_thread_read_as_clear_is_clear() {
        assert!(TargetSlots::Gone.clear());
        let read = |holding, unread| TargetSlots::Present(SlotCensus { threads: 2, unread, holding, cleared: 0 });
        assert!(read(0, 0).clear());
        assert!(!read(1, 0).clear());
        assert!(!read(0, 1).clear(), "a thread that could not be read may hold it");
    }
}
