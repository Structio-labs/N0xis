//! Typed value scanning + iterative filtering (ROADMAP Phase 4b) — the
//! value-scanning first-scan/rescan loop. Pure comparison logic over the
//! `MemorySource` seam: region enumeration (`VirtualQueryEx` on live,
//! sections on static) is an OS/format concern that stays in
//! `n0xis-sources`/`n0xis-cli`, handed in here as plain `(Va, usize)` ranges
//! so this pass never touches an OS API — the same boundary every other
//! `n0xis-core` pass holds.

use n0xis_contracts::Va;
use serde::{Deserialize, Serialize};

use crate::{Ctx, CoreError, Pass};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
}

impl ValueType {
    pub fn size(self) -> usize {
        match self {
            ValueType::I8 | ValueType::U8 => 1,
            ValueType::I16 | ValueType::U16 => 2,
            ValueType::I32 | ValueType::U32 | ValueType::F32 => 4,
            ValueType::I64 | ValueType::U64 | ValueType::F64 => 8,
        }
    }
}

/// A scanned value, typed generically enough to compare across every
/// [`ValueType`] without re-parsing bytes at each comparison site.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScanValue {
    Int(i64),
    Float(f64),
}

impl ScanValue {
    pub fn as_f64(self) -> f64 {
        match self {
            ScanValue::Int(v) => v as f64,
            ScanValue::Float(v) => v,
        }
    }

    /// The integer reading of this value — pointers and integer scans are
    /// always [`ScanValue::Int`]; a float scan truncates (never meaningfully
    /// used as a pointer, so truncation is harmless here).
    pub fn as_int(self) -> i64 {
        match self {
            ScanValue::Int(v) => v,
            ScanValue::Float(v) => v as i64,
        }
    }

    fn read(bytes: &[u8], ty: ValueType) -> Option<ScanValue> {
        Some(match ty {
            ValueType::I8 => ScanValue::Int(i8::from_le_bytes(bytes.try_into().ok()?) as i64),
            ValueType::U8 => ScanValue::Int(u8::from_le_bytes(bytes.try_into().ok()?) as i64),
            ValueType::I16 => ScanValue::Int(i16::from_le_bytes(bytes.try_into().ok()?) as i64),
            ValueType::U16 => ScanValue::Int(u16::from_le_bytes(bytes.try_into().ok()?) as i64),
            ValueType::I32 => ScanValue::Int(i32::from_le_bytes(bytes.try_into().ok()?) as i64),
            ValueType::U32 => ScanValue::Int(u32::from_le_bytes(bytes.try_into().ok()?) as i64),
            ValueType::I64 => ScanValue::Int(i64::from_le_bytes(bytes.try_into().ok()?)),
            ValueType::U64 => ScanValue::Int(u64::from_le_bytes(bytes.try_into().ok()?) as i64),
            ValueType::F32 => ScanValue::Float(f32::from_le_bytes(bytes.try_into().ok()?) as f64),
            ValueType::F64 => ScanValue::Float(f64::from_le_bytes(bytes.try_into().ok()?)),
        })
    }
}

fn values_eq(a: ScanValue, b: ScanValue) -> bool {
    match (a, b) {
        (ScanValue::Int(x), ScanValue::Int(y)) => x == y,
        _ => (a.as_f64() - b.as_f64()).abs() < f64::EPSILON,
    }
}

/// A first-scan criterion.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ScanCriterion {
    Exact { value: ScanValue },
    InRange { min: ScanValue, max: ScanValue },
    /// Record every value in range — the "unknown initial value" first scan
    /// a later [`FilterCriterion`] narrows down.
    Unknown,
}

fn scan_criterion_matches(c: &ScanCriterion, v: ScanValue) -> bool {
    match c {
        ScanCriterion::Exact { value } => values_eq(*value, v),
        ScanCriterion::InRange { min, max } => v.as_f64() >= min.as_f64() && v.as_f64() <= max.as_f64(),
        ScanCriterion::Unknown => true,
    }
}

/// A rescan criterion — compares each previously-matched address's *new*
/// value against its old one.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FilterCriterion {
    Exact { value: ScanValue },
    Increased,
    Decreased,
    Changed,
    Unchanged,
    InRange { min: ScanValue, max: ScanValue },
}

#[derive(Clone, Debug)]
pub struct ScanInput {
    pub regions: Vec<(Va, usize)>,
    pub value_type: ValueType,
    pub criterion: ScanCriterion,
    /// Byte stride between candidate addresses ("fast scan" in a memory scanner
    /// terms); `1` checks every byte offset, `value_type.size()` is the
    /// natural-alignment default.
    pub align: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanMatch {
    pub addr: Va,
    pub value: ScanValue,
}

/// Safety budget on match count — not a tuned business rule, just a floor
/// against accidentally materializing millions of matches from an
/// under-constrained first scan over a huge region (CONCEPT anti-hardcode
/// note: a budget, not a magic threshold).
const MAX_MATCHES: usize = 200_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanArtifact {
    pub value_type: ValueType,
    pub matches: Vec<ScanMatch>,
    pub regions_scanned: usize,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ScanPass;

impl Pass for ScanPass {
    type In = ScanInput;
    type Out = ScanArtifact;

    fn name(&self) -> &'static str {
        "scan.value"
    }

    fn run(&self, ctx: &Ctx, input: ScanInput) -> Result<ScanArtifact, CoreError> {
        let size = input.value_type.size();
        let align = input.align.max(1);
        let mut matches = Vec::new();
        let mut truncated = false;

        'regions: for (start, len) in &input.regions {
            let Ok(bytes) = ctx.source.read(*start, *len) else { continue };
            let mut off = 0usize;
            while off + size <= bytes.len() {
                if let Some(v) = ScanValue::read(&bytes[off..off + size], input.value_type)
                    && scan_criterion_matches(&input.criterion, v)
                {
                    matches.push(ScanMatch { addr: start.offset(off as u64), value: v });
                    if matches.len() >= MAX_MATCHES {
                        truncated = true;
                        break 'regions;
                    }
                }
                off += align;
            }
        }
        Ok(ScanArtifact { value_type: input.value_type, regions_scanned: input.regions.len(), matches, truncated })
    }
}

pub struct FilterInput {
    pub previous: Vec<ScanMatch>,
    pub value_type: ValueType,
    pub criterion: FilterCriterion,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FilterPass;

impl Pass for FilterPass {
    type In = FilterInput;
    type Out = ScanArtifact;

    fn name(&self) -> &'static str {
        "scan.filter"
    }

    fn run(&self, ctx: &Ctx, input: FilterInput) -> Result<ScanArtifact, CoreError> {
        let size = input.value_type.size();
        let mut matches = Vec::new();
        for prev in &input.previous {
            let Ok(bytes) = ctx.source.read(prev.addr, size) else { continue };
            if bytes.len() < size {
                continue;
            }
            let Some(now) = ScanValue::read(&bytes, input.value_type) else { continue };
            let keep = match &input.criterion {
                FilterCriterion::Exact { value } => values_eq(*value, now),
                FilterCriterion::Increased => now.as_f64() > prev.value.as_f64(),
                FilterCriterion::Decreased => now.as_f64() < prev.value.as_f64(),
                FilterCriterion::Changed => !values_eq(prev.value, now),
                FilterCriterion::Unchanged => values_eq(prev.value, now),
                FilterCriterion::InRange { min, max } => now.as_f64() >= min.as_f64() && now.as_f64() <= max.as_f64(),
            };
            if keep {
                matches.push(ScanMatch { addr: prev.addr, value: now });
            }
        }
        Ok(ScanArtifact { value_type: input.value_type, regions_scanned: 0, matches, truncated: false })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    #[test]
    fn exact_first_scan_finds_the_needle() {
        let mut region = vec![0u8; 64];
        region[8..12].copy_from_slice(&100i32.to_le_bytes());
        region[40..44].copy_from_slice(&100i32.to_le_bytes());
        let snap = Snapshot::builder().region(Va(0x1000), region).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let art = ScanPass
            .run(
                &ctx,
                ScanInput {
                    regions: vec![(Va(0x1000), 64)],
                    value_type: ValueType::I32,
                    criterion: ScanCriterion::Exact { value: ScanValue::Int(100) },
                    align: 4,
                },
            )
            .unwrap();
        assert_eq!(art.matches.len(), 2);
        assert_eq!(art.matches[0].addr, Va(0x1008));
        assert_eq!(art.matches[1].addr, Va(0x1028));
    }

    #[test]
    fn increased_filter_narrows_across_a_rescan() {
        // First "world": both candidates hold 100.
        let mut before = vec![0u8; 16];
        before[0..4].copy_from_slice(&100i32.to_le_bytes());
        before[8..12].copy_from_slice(&100i32.to_le_bytes());
        let snap1 = Snapshot::builder().region(Va(0x2000), before).build();
        let arch = X64::new();
        let ctx1 = Ctx::new(&snap1, &arch);
        let first = ScanPass
            .run(
                &ctx1,
                ScanInput {
                    regions: vec![(Va(0x2000), 16)],
                    value_type: ValueType::I32,
                    criterion: ScanCriterion::Exact { value: ScanValue::Int(100) },
                    align: 4,
                },
            )
            .unwrap();
        assert_eq!(first.matches.len(), 2);

        // Second "world": only the first candidate increased.
        let mut after = vec![0u8; 16];
        after[0..4].copy_from_slice(&150i32.to_le_bytes());
        after[8..12].copy_from_slice(&100i32.to_le_bytes());
        let snap2 = Snapshot::builder().region(Va(0x2000), after).build();
        let ctx2 = Ctx::new(&snap2, &arch);
        let filtered = FilterPass
            .run(&ctx2, FilterInput { previous: first.matches, value_type: ValueType::I32, criterion: FilterCriterion::Increased })
            .unwrap();
        assert_eq!(filtered.matches.len(), 1);
        assert_eq!(filtered.matches[0].addr, Va(0x2000));
        assert_eq!(filtered.matches[0].value, ScanValue::Int(150));
    }

    #[test]
    fn unchanged_filter_keeps_only_the_stable_candidate() {
        let mut before = vec![0u8; 16];
        before[0..4].copy_from_slice(&7i32.to_le_bytes());
        before[8..12].copy_from_slice(&7i32.to_le_bytes());
        let snap1 = Snapshot::builder().region(Va(0x3000), before).build();
        let arch = X64::new();
        let ctx1 = Ctx::new(&snap1, &arch);
        let first = ScanPass
            .run(&ctx1, ScanInput { regions: vec![(Va(0x3000), 16)], value_type: ValueType::I32, criterion: ScanCriterion::Unknown, align: 4 })
            .unwrap();
        assert_eq!(first.matches.len(), 4); // every 4-byte slot, including the two zero words

        let mut after = vec![0u8; 16];
        after[0..4].copy_from_slice(&7i32.to_le_bytes());
        after[8..12].copy_from_slice(&9i32.to_le_bytes());
        let snap2 = Snapshot::builder().region(Va(0x3000), after).build();
        let ctx2 = Ctx::new(&snap2, &arch);
        let filtered = FilterPass
            .run(&ctx2, FilterInput { previous: first.matches, value_type: ValueType::I32, criterion: FilterCriterion::Unchanged })
            .unwrap();
        // Slots at +0 (still 7) and +4 (still 0) are unchanged; +8 changed 7->9, +12 stayed 0.
        assert!(filtered.matches.iter().any(|m| m.addr == Va(0x3000) && m.value == ScanValue::Int(7)));
        assert!(!filtered.matches.iter().any(|m| m.addr == Va(0x3008)));
    }
}
