// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The OS-free vocabulary of a debug hit — shared by the Win32 ([`crate::debug`])
//! and Linux ([`crate::dbg_linux`]) adapters so both emit the identical
//! `n0xis.debug.watchpoint.v1` / `n0xis.debug.await_hit.v1` wire shape.
//!
//! Only the *arming* and *event-loop* code is OS-specific; the report types, the
//! register model and the condition filter live here, and the x86 debug-register
//! bit encodings (the CPU's, identical on either OS) in [`crate::watch_slot`].
//! Hoisting them out of the windows-gated `debug.rs` is what lets a Linux hit be
//! byte-for-byte the same envelope a Windows hit is — a single source of truth for
//! the contract.

use n0xis_contracts::Va;
use serde::Serialize;

use crate::unwind;

// What the debug registers hold is in `crate::watch_slot`, which the journal reads too.
pub(crate) use crate::watch_slot::{SlotCensus, TargetSlots, WatchKind, WatchSlot};

/// Depth cap for stack unwinding — a bound against a corrupt frame chain looping
/// forever, generous enough for any real call stack.
pub(crate) const MAX_UNWIND_FRAMES: usize = 128;

/// How many non-matching conditional hits to tolerate before giving up. Every
/// miss is a full stop/inspect/resume round-trip for the target thread; on a
/// per-frame function that is thousands of them and the target effectively runs
/// single-stepped — enough to kill the target. Past this, bail with a diagnostic
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

/// How a wait on a breakpoint or a watchpoint ended.
///
/// It used to be `timed_out: hit.is_none()`, and so a target that was killed half way
/// through a three-second wait was reported as one that ran the whole three seconds
/// without reaching the site (audit 2026-11-06, row 11): an answer about the program
/// made of what the loop happened to leave with. Each loop now says which of these
/// ended it, where it ends.
#[derive(Clone, Debug)]
pub enum Ended {
    /// The site was reached; what the thread held then.
    Hit(Box<BreakpointHit>),
    /// The deadline passed with the target alive and the site not reached.
    TimedOut,
    /// No thread of the target was left to reach the site: it exited or was killed
    /// before the deadline.
    TargetExited,
}

impl Ended {
    /// The word an answer carries for it.
    pub fn word(&self) -> &'static str {
        match self {
            Ended::Hit(_) => "hit",
            Ended::TimedOut => "timed-out",
            Ended::TargetExited => "target-exited",
        }
    }
}

/// Result of one await-hit call.
///
/// On the wire: `breakpoint_va`, `timed_out` (true for [`Ended::TimedOut`] only, as
/// the field always meant), `hit` when there was one, `ended`, and the counts of hits
/// a filter set aside when the wait had that filter. Written by hand so the wire keeps
/// the fields it always had beside the one that says why.
#[derive(Clone, Debug)]
pub struct AwaitHitOutcome {
    pub breakpoint_va: Va,
    pub ended: Ended,
    /// Hits at a site in an `exclude_rip` range, resumed and not counted: `None`
    /// when the wait was given no such range.
    pub excluded_hits: Option<u64>,
    /// Hits whose registers did not satisfy the condition: `None` when the wait
    /// was given no condition.
    pub condition_misses: Option<u32>,
}

impl AwaitHitOutcome {
    /// An outcome with no filter.
    pub fn new(breakpoint_va: Va, ended: Ended) -> Self {
        AwaitHitOutcome { breakpoint_va, ended, excluded_hits: None, condition_misses: None }
    }

    pub fn hit(&self) -> Option<&BreakpointHit> {
        match &self.ended {
            Ended::Hit(h) => Some(h),
            _ => None,
        }
    }

    pub fn into_hit(self) -> Option<BreakpointHit> {
        match self.ended {
            Ended::Hit(h) => Some(*h),
            _ => None,
        }
    }

    /// The deadline passed with the target alive and the site not reached.
    pub fn timed_out(&self) -> bool {
        matches!(self.ended, Ended::TimedOut)
    }
}

impl Serialize for AwaitHitOutcome {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let hit = self.hit();
        let n = 3 + usize::from(hit.is_some()) + usize::from(self.excluded_hits.is_some()) + usize::from(self.condition_misses.is_some());
        let mut st = s.serialize_struct("AwaitHitOutcome", n)?;
        st.serialize_field("breakpoint_va", &self.breakpoint_va)?;
        st.serialize_field("timed_out", &self.timed_out())?;
        if let Some(h) = hit {
            st.serialize_field("hit", h)?;
        }
        st.serialize_field("ended", self.ended.word())?;
        if let Some(n) = self.excluded_hits {
            st.serialize_field("excluded_hits", &n)?;
        }
        if let Some(n) = self.condition_misses {
            st.serialize_field("condition_misses", &n)?;
        }
        st.end()
    }
}
