// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The OS-free vocabulary of a debug hit — shared by the Win32 ([`crate::debug`])
//! and Linux ([`crate::dbg_linux`]) adapters so both emit the identical
//! `n0xis.debug.watchpoint.v1` / `n0xis.debug.await_hit.v1` wire shape.
//!
//! Only the *arming* and *event-loop* code is OS-specific; the report types, the
//! register model, the condition filter, and even the x86 debug-register bit
//! encodings (the CPU's, identical on either OS) live here. Hoisting them out of
//! the windows-gated `debug.rs` is what lets a Linux hit be byte-for-byte the
//! same envelope a Windows hit is — a single source of truth for the contract.

use n0xis_contracts::Va;
use serde::Serialize;

use crate::unwind;
use crate::SourceError;

/// Depth cap for stack unwinding — a bound against a corrupt frame chain looping
/// forever, generous enough for any real call stack.
pub(crate) const MAX_UNWIND_FRAMES: usize = 128;

/// How many non-matching conditional hits to tolerate before giving up. Every
/// miss is a full stop/inspect/resume round-trip for the target thread; on a
/// per-frame function that is thousands of them and the target effectively runs
/// single-stepped — enough to kill a game. Past this, bail with a diagnostic
/// ("trap site too hot") instead of grinding the target to death. Shared by both
/// adapters so the budget is one number, not a copy per OS.
pub(crate) const MAX_CONDITION_MISSES: u32 = 300;

/// Full integer GPR snapshot at the moment of the hit.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

impl Registers {
    /// Read a register by lowercase name, for condition matching.
    pub fn by_name(&self, name: &str) -> Option<u64> {
        Some(match name {
            "rax" => self.rax,
            "rbx" => self.rbx,
            "rcx" => self.rcx,
            "rdx" => self.rdx,
            "rsi" => self.rsi,
            "rdi" => self.rdi,
            "rbp" => self.rbp,
            "r8" => self.r8,
            "r9" => self.r9,
            "r10" => self.r10,
            "r11" => self.r11,
            "r12" => self.r12,
            "r13" => self.r13,
            "r14" => self.r14,
            "r15" => self.r15,
            _ => return None,
        })
    }
}

/// A condition a hit must satisfy to be reported, e.g. `r9=4`.
///
/// Without this a breakpoint on a hot function is close to useless: the first
/// hit is whatever ran first, and re-arming just returns the same caller every
/// time. Filtering in the debug loop lets the interesting call be singled out
/// instead of hoping to land on it.
#[derive(Clone, Debug)]
pub struct RegCond {
    pub reg: String,
    pub value: u64,
}

impl RegCond {
    /// Parse `"<reg>=<value>"`; value may be decimal or `0x`-prefixed.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (reg, val) = s.split_once('=').ok_or_else(|| format!("expected <reg>=<value>, got `{s}`"))?;
        let reg = reg.trim().to_ascii_lowercase();
        let val = val.trim();
        let value = if let Some(hex) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).map_err(|e| format!("bad hex value `{val}`: {e}"))?
        } else {
            val.parse::<u64>().map_err(|e| format!("bad value `{val}`: {e}"))?
        };
        if Registers::default().by_name(&reg).is_none() {
            return Err(format!("unknown register `{reg}`"));
        }
        Ok(RegCond { reg, value })
    }

    pub(crate) fn matches(&self, r: &Registers) -> bool {
        r.by_name(&self.reg) == Some(self.value)
    }
}

/// One breakpoint/watchpoint hit.
#[derive(Clone, Debug, Serialize)]
pub struct BreakpointHit {
    pub thread_id: u32,
    pub rip: Va,
    pub rsp: Va,
    /// `"<module>+0x<rva>"`, when `rip` falls inside the module passed to the
    /// arming call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relative_rip: Option<String>,
    pub registers: Registers,
    /// Qwords read from the stack starting at `rsp`, in order.
    pub stack: Vec<u64>,
    /// The recovered call-stack: frame 0 is `rip` (the hit site), each further
    /// entry a real caller resolved through unwind data (PE `.pdata`/`.xdata` or
    /// ELF `.eh_frame`), not a raw `[rsp]` guess. Empty if unwinding couldn't
    /// start (e.g. no module map). See [`crate::unwind`].
    pub frames: Vec<unwind::Frame>,
}

/// Result of one await-hit call.
#[derive(Clone, Debug, Serialize)]
pub struct AwaitHitOutcome {
    pub breakpoint_va: Va,
    pub timed_out: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hit: Option<BreakpointHit>,
}

/// What a hardware watchpoint traps on. There is no hardware "read-only" mode on
/// x86 — only `Write` or `ReadOrWrite` — so this doesn't invent one (CONCEPT §3
/// rule 6: the API reflects what the CPU can actually do). Same three modes on
/// Windows and Linux; the DR7 encoding below is the CPU's, not the OS's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchKind {
    Execute,
    Write,
    ReadOrWrite,
}

impl WatchKind {
    pub(crate) fn rw_bits(self) -> u64 {
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
pub(crate) fn len_bits(addr: Va, len: u8) -> Result<u64, SourceError> {
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

/// DR7 bits for slot 0 only: `L0` (local enable, bit 0), bit 10 (reserved,
/// conventionally set), `RW0` (bits 16-17), `LEN0` (bits 18-19). The exact same
/// encoding the CPU consumes whether the write comes from `SetThreadContext`
/// (Win32) or `PTRACE_POKEUSER` (Linux).
pub(crate) fn dr7_slot0(kind: WatchKind, addr: Va, len: u8) -> Result<u64, SourceError> {
    if kind == WatchKind::Execute && len != 1 {
        return Err(SourceError::Os("an execute watchpoint must have length 1 (Intel SDM Vol 3B §17.2.5)".into()));
    }
    let rw = kind.rw_bits();
    let lb = len_bits(addr, len)?;
    Ok(1u64 | (1u64 << 10) | (rw << 16) | (lb << 18))
}
