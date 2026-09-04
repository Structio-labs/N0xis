// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Structural-predicate scanning (ROADMAP Phase 9, item 3) — matches memory
//! by *relations between fields*, not by fixed byte constants. `scan aob` can
//! answer "is this exact byte sequence here"; it cannot answer "are these six
//! floats a valid bounding box" or "is `d0 == d3` and `d1 == d2`" — both were
//! needed during the interact-combo campaign and both had to be abandoned for
//! lack of an expressive-enough scanner (see
//! `docs/PHASE9_UI_LOCATE_BRIEF.md` §8). AOB patterns match *constants*; this
//! primitive matches *shapes*.
//!
//! [`UiLocatePass`](crate::ui_locate::UiLocatePass) is the first consumer —
//! its AABB predicate is a configuration of this primitive, not a separate
//! scanning mechanism.

use n0xis_contracts::Va;
use serde::Serialize;

use crate::scan::{ScanValue, ValueType};
use crate::{CoreError, Ctx, Pass};

/// One field read at a fixed byte offset from a candidate window's base.
#[derive(Clone, Copy, Debug)]
pub struct FieldSpec {
    pub offset: usize,
    pub ty: ValueType,
}

/// A structural predicate: given every [`FieldSpec`]'s value at one candidate
/// position (same order as the `fields` list), decide whether they satisfy
/// some relation. `None` rejects the candidate; `Some(score)` accepts it with
/// a caller-defined relevance score (ranking is the caller's business — this
/// primitive only reports what matched and in what order it was found in,
/// the artifact is *not* pre-sorted, so a caller who doesn't care about score
/// still gets stable position order).
pub type Predicate = dyn Fn(&[ScanValue]) -> Option<f64>;

pub struct StructuralScanInput {
    pub start: Va,
    pub size: usize,
    /// Byte stride between candidate windows. `1` checks every byte offset;
    /// callers scanning dword-aligned fields (the common case) should pass 4.
    pub align: usize,
    /// Fields read at each candidate position, relative to that position.
    pub fields: Vec<FieldSpec>,
    pub predicate: Box<Predicate>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StructuralHit {
    /// The candidate's own base address (where offset `0` of `fields` is
    /// read) — *not* necessarily the "object" a caller cares about; callers
    /// with their own field-offset convention (e.g. "field 0 is at
    /// `+0xa4`") recover their object base themselves.
    pub base: Va,
    pub score: f64,
    /// Every field's value, same order as the input `fields` list.
    pub values: Vec<ScanValue>,
}

/// `n0xis.scan.structural.v1`. Deliberately **not** pre-truncated to a
/// caller-supplied limit — sound-over-complete: `candidates_tested` and
/// `bytes_scanned` always reflect the *whole* scanned window, so "found
/// nothing" is never confusable with "gave up partway" (RE_METHOD F6). A
/// caller wanting only the top N ranks `matches` itself.
#[derive(Clone, Debug, Serialize)]
pub struct StructuralScanArtifact {
    pub matches: Vec<StructuralHit>,
    pub candidates_tested: usize,
    pub bytes_scanned: usize,
}

#[derive(Default)]
pub struct StructuralScanPass;

impl Pass for StructuralScanPass {
    type In = StructuralScanInput;
    type Out = StructuralScanArtifact;

    fn name(&self) -> &'static str {
        "scan.structural"
    }

    fn run(&self, ctx: &Ctx, input: StructuralScanInput) -> Result<StructuralScanArtifact, CoreError> {
        let bytes = ctx.source.read(input.start, input.size)?;
        let align = input.align.max(1);
        let field_span = input.fields.iter().map(|f| f.offset + f.ty.size()).max().unwrap_or(0);

        let mut matches = Vec::new();
        let mut candidates_tested = 0usize;
        if field_span == 0 || bytes.len() < field_span {
            return Ok(StructuralScanArtifact { matches, candidates_tested, bytes_scanned: bytes.len() });
        }

        let mut off = 0usize;
        while off + field_span <= bytes.len() {
            candidates_tested += 1;
            let mut values = Vec::with_capacity(input.fields.len());
            let mut readable = true;
            for f in &input.fields {
                let start = off + f.offset;
                match ScanValue::read(&bytes[start..start + f.ty.size()], f.ty) {
                    Some(v) => values.push(v),
                    None => {
                        readable = false;
                        break;
                    }
                }
            }
            if readable
                && let Some(score) = (input.predicate)(&values)
            {
                matches.push(StructuralHit { base: input.start.offset(off as u64), score, values });
            }
            off += align;
        }
        Ok(StructuralScanArtifact { matches, candidates_tested, bytes_scanned: bytes.len() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    fn ctx_over(bytes: Vec<u8>) -> (Snapshot, X64) {
        (Snapshot::builder().region(Va(0x1000), bytes).build(), X64::new())
    }

    /// "d0 == d3 and d1 == d2" — the exact relation the campaign needed
    /// (ROADMAP Phase 9 item 3) and `scan aob` cannot express (it only
    /// matches fixed constants, never a relation between two *unknown* but
    /// equal fields).
    fn mirrored_u32s(a: u32, b: u32) -> Vec<u8> {
        let mut v = Vec::new();
        for x in [a, b, b, a] {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v
    }

    #[test]
    fn finds_a_mirrored_relation_regardless_of_the_actual_values() {
        let mut bytes = vec![0u8; 8]; // junk padding
        bytes.extend(mirrored_u32s(11, 22)); // hit at offset 8
        bytes.extend(vec![1, 2, 3, 4]); // junk, breaks the relation
        bytes.extend(mirrored_u32s(99, 5)); // hit at offset 28

        let (snap, arch) = ctx_over(bytes);
        let ctx = Ctx::new(&snap, &arch);
        let fields = vec![
            FieldSpec { offset: 0, ty: ValueType::U32 },
            FieldSpec { offset: 4, ty: ValueType::U32 },
            FieldSpec { offset: 8, ty: ValueType::U32 },
            FieldSpec { offset: 12, ty: ValueType::U32 },
        ];
        let predicate: Box<Predicate> = Box::new(|v| {
            let d0 = v[0].as_int();
            let d1 = v[1].as_int();
            let d2 = v[2].as_int();
            let d3 = v[3].as_int();
            (d0 == d3 && d1 == d2 && d0 != d1).then_some(1.0)
        });
        // Dword-aligned stride — the realistic case this primitive targets
        // (ROADMAP Phase 9 item 3's own example is "four *dwords*").
        let art = StructuralScanPass
            .run(&ctx, StructuralScanInput { start: Va(0x1000), size: 44, align: 4, fields, predicate })
            .unwrap();

        let hit_offsets: Vec<u64> = art.matches.iter().map(|m| m.base.delta(Va(0x1000)) as u64).collect();
        assert_eq!(hit_offsets, vec![8, 28], "expected exactly the two mirrored-relation offsets: {art:?}");
    }

    #[test]
    fn never_truncates_scanning_even_with_no_matches() {
        let bytes = vec![0xAAu8; 100];
        let (snap, arch) = ctx_over(bytes);
        let ctx = Ctx::new(&snap, &arch);
        let fields = vec![FieldSpec { offset: 0, ty: ValueType::U8 }];
        let predicate: Box<Predicate> = Box::new(|_| None);
        let art = StructuralScanPass
            .run(&ctx, StructuralScanInput { start: Va(0x1000), size: 100, align: 1, fields, predicate })
            .unwrap();
        assert!(art.matches.is_empty());
        // "0 results" must be distinguishable from "the scan died": these
        // must reflect the *whole* window, not a partial/early-exited one.
        assert_eq!(art.candidates_tested, 100);
        assert_eq!(art.bytes_scanned, 100);
    }

    #[test]
    fn a_window_smaller_than_the_field_span_yields_zero_candidates_not_an_error() {
        let bytes = vec![0u8; 3];
        let (snap, arch) = ctx_over(bytes);
        let ctx = Ctx::new(&snap, &arch);
        let fields = vec![FieldSpec { offset: 0, ty: ValueType::U32 }]; // needs 4 bytes
        let predicate: Box<Predicate> = Box::new(|_| Some(0.0));
        let art = StructuralScanPass
            .run(&ctx, StructuralScanInput { start: Va(0x1000), size: 3, align: 1, fields, predicate })
            .unwrap();
        assert_eq!(art.candidates_tested, 0);
        assert!(art.matches.is_empty());
    }
}
