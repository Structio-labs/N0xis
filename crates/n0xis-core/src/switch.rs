//! Memory-side jump-table resolution — the edge static tools lack.
//!
//! The arch recognizes the *shape* of a switch dispatch ([`SwitchDispatch`])
//! but never reads memory. Here the core reads the jump table through the
//! [`MemorySource`](n0xis_sources::MemorySource) seam and turns it into
//! concrete case targets. Because the seam is source-agnostic, this resolves
//! tables from a **running process** exactly as from a file on disk — so an
//! indirect `switch` in a live game gets its edges filled in, which a
//! file-only disassembler cannot do (CONCEPT §5.1, KILLER_FEATURES).

use n0xis_arch::{SwitchDispatch, SwitchKind};
use n0xis_contracts::Va;
use serde::{Deserialize, Serialize};

use crate::Ctx;

/// Hard cap on resolved cases, even when a larger bound is recovered — a guard
/// against a misread bound blowing up into a huge table read.
const MAX_SWITCH_CASES: usize = 4096;
/// How many entries to probe when no upper bound was recovered; the walk also
/// stops early at the first entry that doesn't land in the address space.
const UNBOUNDED_PROBE_LIMIT: usize = 256;
/// Confidence attached to a memory-resolved switch-case edge — high, but below
/// the `1.0` of a directly-encoded branch, since a table read is best-effort.
pub const SWITCH_CASE_CONFIDENCE: f32 = 0.9;

/// A switch dispatch with its cases resolved from memory (`cases` empty when
/// the table base was unknown or unreadable). Embedded in the CFG artifact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedSwitch {
    pub at: Va,
    /// `"mem-indexed"` or `"reg-rel32"`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<Va>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_reg: Option<String>,
    pub scale: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<u64>,
    /// Bytes per table entry (pointer width for mem-indexed, 4 for rel32).
    pub entry_size: u32,
    /// Whether `cases` were actually read from memory.
    pub resolved: bool,
    /// Resolved case targets, in table order.
    pub cases: Vec<Va>,
}

/// Read the jump table for `disp` through the source seam and resolve cases.
pub fn resolve_switch(ctx: &Ctx, disp: &SwitchDispatch) -> ResolvedSwitch {
    let entry_size = disp.kind.entry_size(ctx.arch.pointer_size());
    let mut out = ResolvedSwitch {
        at: disp.at,
        kind: disp.kind.as_str().to_string(),
        table: disp.table,
        index_reg: disp.index_reg.clone(),
        scale: disp.scale,
        bound: disp.bound,
        entry_size,
        resolved: false,
        cases: Vec::new(),
    };

    let Some(table) = disp.table else {
        return out; // base is a runtime register — nothing to read statically.
    };

    // A recovered bound `n` caps the walk at `n + 1` entries (indices 0..=n);
    // without one, probe a fixed window. Either way the walk stops at the first
    // entry that leaves executable code — that word marks the table's end.
    let count = match disp.bound {
        Some(n) => (n.saturating_add(1) as usize).min(MAX_SWITCH_CASES),
        None => UNBOUNDED_PROBE_LIMIT,
    };

    let want = count.saturating_mul(entry_size as usize);
    let Ok(raw) = ctx.source.read(table, want) else {
        return out;
    };
    let step = entry_size as usize;
    // Prefer the executable ranges as the "is this code?" gate; fall back to
    // mere mapped-ness when the source can't report a code extent.
    //
    // **All** of them, not just `.text`: a Unity IL2CPP image keeps its
    // transpiled C# in a second executable section, so gating on `.text` alone
    // rejected every jump table in 89% of the binary — switch recovery quietly
    // giving up on the bulk of the code, reported as "unresolved".
    let code = ctx.source.code_ranges();

    for chunk in raw.chunks_exact(step) {
        let Some(target) = decode_entry(disp.kind, table, chunk) else {
            break;
        };
        if !is_code(ctx, &code, target) {
            break;
        }
        out.cases.push(target);
    }

    out.resolved = !out.cases.is_empty();
    out
}

/// Does `target` land in executable code? Uses the source's code extent when
/// known (rejects data addresses like the table itself), else falls back to
/// plain mapped-ness.
fn is_code(ctx: &Ctx, code: &[(Va, u64)], target: Va) -> bool {
    if code.is_empty() {
        return ctx.source.contains(target);
    }
    code.iter().any(|(base, size)| target.0 >= base.0 && target.0 < base.0.saturating_add(*size))
}

/// Turn one table entry into a case target VA.
fn decode_entry(kind: SwitchKind, table: Va, bytes: &[u8]) -> Option<Va> {
    match kind {
        SwitchKind::MemIndexed => {
            // Little-endian native pointer (entry_size == pointer width).
            let mut v: u64 = 0;
            for (i, b) in bytes.iter().enumerate() {
                v |= (*b as u64) << (8 * i);
            }
            (v != 0).then_some(Va(v))
        }
        SwitchKind::RegRel32 => {
            // Signed 32-bit offset from the table base.
            let arr: [u8; 4] = bytes.try_into().ok()?;
            let rel = i32::from_le_bytes(arr) as i64;
            Some(Va(table.0.wrapping_add(rel as u64)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    /// The gate must accept a target in **any** executable range, not only the
    /// first. On a Unity IL2CPP image the second one holds 89% of the code, so
    /// a first-range-only check rejected every jump table there and reported
    /// the switch as unresolved.
    #[test]
    fn a_target_in_a_second_code_range_is_still_code() {
        let snap = Snapshot::builder().region(Va(0x1000), vec![0u8; 16]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let ranges = [(Va(0x1000), 0x200u64), (Va(0x8000), 0x4000)];

        assert!(is_code(&ctx, &ranges, Va(0x1100)), "first range");
        assert!(is_code(&ctx, &ranges, Va(0x9000)), "second range — the case that used to fail");
        assert!(!is_code(&ctx, &ranges, Va(0x5000)), "between the ranges is not code");
        assert!(!is_code(&ctx, &ranges, Va(0xC000)), "past the last range is not code");
    }

    /// With no ranges at all the gate falls back to plain mapped-ness, exactly
    /// as it did when the source could not report a code extent.
    #[test]
    fn no_known_ranges_falls_back_to_mapped_ness() {
        let snap = Snapshot::builder().region(Va(0x1000), vec![0u8; 16]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        assert!(is_code(&ctx, &[], Va(0x1000)));
        assert!(!is_code(&ctx, &[], Va(0x9999)));
    }
}
