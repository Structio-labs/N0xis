// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `ui locate` — screen-region → memory-address hit-testing over a target's
//! own retained-scene-graph bounding boxes (ROADMAP Phase 9, item 2). Built
//! entirely on [`StructuralScanPass`](crate::structural::StructuralScanPass):
//! this module is that primitive's configuration for one concrete shape (an
//! AABB + radius), not a separate scanning mechanism. Full rationale, the
//! verified field layout, and the rejected alternatives (byte-pattern
//! signature on the `FLT_MAX` init sentinel — zero hits, it's transient; a
//! contiguous-array search — the arrows are separate widgets, not adjacent)
//! live in `docs/PHASE9_UI_LOCATE_BRIEF.md`.
//!
//! Two things are deliberately split, per the brief's own algorithm (§4):
//! **plausibility** ([`aabb_plausible`] — is this a real AABB at all; a
//! structural, engine-level question) is independent of **relevance**
//! ([`rect_overlap`] — does it overlap the caller's query rectangle; a
//! `ui-locate`-specific question). The structural pass only ever asks the
//! first; this module asks the second afterward, over already-found AABBs.

use n0xis_contracts::Va;
use serde::{Deserialize, Serialize};

use crate::scan::{ScanValue, ValueType};
use crate::structural::{FieldSpec, StructuralScanInput, StructuralScanPass};
use crate::{CoreError, Ctx, Pass};

/// Where the six AABB floats + radius sit **relative to the element's own
/// base address** — a config value, not a hardcode (PRODUCT_POLICY §4 anti-hardcode
/// rule): a different engine/build gets a different `AabbLayout`, passed in,
/// never inlined into the algorithm below. `STINGRAY` is the one verified
/// layout so far (brief §3, confirmed by decompiling a Bitsquid/Stingray-engine
/// game binary): `min.x` at `+0xa4`, ..., `radius` at `+0xbc`, all `f32`,
/// contiguous.
#[derive(Clone, Copy, Debug)]
pub struct AabbLayout {
    /// Byte offset of `min.x` from the element's base. The remaining six
    /// fields (`min.y/z`, `max.x/y/z`, `radius`) are contiguous `f32`s
    /// immediately after it — that contiguity is itself part of the verified
    /// layout, not an assumption this type re-derives.
    pub min_x_offset: usize,
}

impl AabbLayout {
    pub const STINGRAY: AabbLayout = AabbLayout { min_x_offset: 0xa4 };

    /// The seven contiguous `f32` fields, relative to wherever the scanner is
    /// currently probing (i.e. relative to `min.x`'s own position, since the
    /// scan sweeps starting there — brief §4 step 3/5).
    fn fields() -> Vec<FieldSpec> {
        (0..7).map(|i| FieldSpec { offset: i * 4, ty: ValueType::F32 }).collect()
    }

    /// Recover the element's own base address from a scan hit's base (which
    /// is the position of `min.x`, per [`fields`](Self::fields)).
    pub fn element_base(&self, hit_base: Va) -> Va {
        Va(hit_base.0.wrapping_sub(self.min_x_offset as u64))
    }
}

/// Coordinate-space bound for plausibility (brief §4's `--space`). Kept
/// separate from `Rect` because the bound bounds *individual coordinates*
/// (rejecting an implausible AABB outright), while `Rect` is the caller's
/// specific query region within whatever space the bound describes.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordSpace {
    /// Unknown space: a permissive bound, plus the artifact reports the
    /// *observed* coordinate range across every plausible AABB found — so the
    /// operator can see which space the numbers are actually in, rather than
    /// the tool silently guessing (brief §4: "make the space observable, not
    /// assumed" — the most likely reason a first cut returns nothing useful).
    Auto,
    /// Pixel/window coordinates.
    Screen,
    /// Normalized device coordinates, canonically `[-1, 1]`.
    Ndc,
}

#[derive(Clone, Copy, Debug)]
pub struct SpaceBound {
    pub min: f32,
    pub max: f32,
    /// Smallest x/y extent still plausible for a *UI element* in this space
    /// (brief §4: "the extents are plausible for a UI element"). This is the
    /// filter that separates a real widget from float garbage that merely
    /// satisfies `min <= max`: arbitrary memory is full of runs that decode as
    /// valid-but-absurdly-tiny boxes (extents around `1e-5`), and they pass
    /// every finiteness/ordering/radius test. Scaling the floor to the space
    /// is what makes the test meaningful — one pixel in screen space, one
    /// thousandth in NDC.
    pub min_extent: f32,
}

impl CoordSpace {
    pub fn bound(self) -> SpaceBound {
        match self {
            // A sub-pixel widget isn't a widget.
            CoordSpace::Screen => SpaceBound { min: -8192.0, max: 8192.0, min_extent: 1.0 },
            // NDC spans [-1,1] across the whole viewport; 1e-3 is ~1 pixel at 2K.
            CoordSpace::Ndc => SpaceBound { min: -2.0, max: 2.0, min_extent: 1.0e-3 },
            // `auto` is deliberately permissive — its whole job is to survey
            // whatever space the target actually uses and report the observed
            // range. It therefore only requires a *normal* (non-zero,
            // non-subnormal) extent, and will be correspondingly noisy; that
            // noise is the signal to re-run with a concrete `--space`.
            CoordSpace::Auto => SpaceBound { min: -1.0e6, max: 1.0e6, min_extent: f32::MIN_POSITIVE },
        }
    }
}

/// A caller-supplied 2D screen/UI-space query rectangle. Normalizes on
/// construction so `x0<=x1`/`y0<=y1` regardless of the order the caller typed
/// the corners in.
#[derive(Clone, Copy, Debug)]
pub struct Rect {
    pub x0: f32,
    pub y0: f32,
    pub x1: f32,
    pub y1: f32,
}

impl Rect {
    pub fn new(ax: f32, ay: f32, bx: f32, by: f32) -> Rect {
        Rect { x0: ax.min(bx), y0: ay.min(by), x1: ax.max(bx), y1: ay.max(by) }
    }
}

/// A decoded, not-yet-judged-relevant AABB.
#[derive(Clone, Copy, Debug)]
pub struct Aabb {
    pub min: [f32; 3],
    pub max: [f32; 3],
    pub radius: f32,
}

fn decode_aabb(values: &[ScanValue]) -> Option<Aabb> {
    if values.len() != 7 {
        return None;
    }
    let f = |v: ScanValue| match v {
        ScanValue::Float(x) => Some(x as f32),
        ScanValue::Int(_) => None,
    };
    Some(Aabb {
        min: [f(values[0])?, f(values[1])?, f(values[2])?],
        max: [f(values[3])?, f(values[4])?, f(values[5])?],
        radius: f(values[6])?,
    })
}

/// Brief §4 step 3: a **structural** test (not a byte pattern) that seven
/// floats form a plausible AABB — every value finite, `min <= max` on every
/// axis, coordinates within `bound`, and `radius` order-of-magnitude
/// consistent with the box's own half-diagonal. That last check is the
/// strong, cheap filter: the game computes radius as `sqrtf` of the max
/// squared extent (brief §3), so an unrelated run of floats essentially never
/// satisfies it by coincidence — unlike the `FLT_MAX` sentinel, which *did*
/// coincidentally exist but turned out to be transient (brief §5).
pub fn aabb_plausible(values: &[ScanValue], bound: SpaceBound) -> Option<Aabb> {
    let aabb = decode_aabb(values)?;
    let all = aabb.min.iter().chain(aabb.max.iter()).chain(std::iter::once(&aabb.radius));
    if !all.clone().all(|v| v.is_finite()) {
        return None;
    }
    if !(aabb.min[0] <= aabb.max[0] && aabb.min[1] <= aabb.max[1] && aabb.min[2] <= aabb.max[2]) {
        return None;
    }
    if aabb.min.iter().chain(aabb.max.iter()).any(|&v| v < bound.min || v > bound.max) {
        return None;
    }

    // Brief §4 step 3's "the extents are plausible for a UI element" clause.
    // Without a *size floor*, arbitrary float garbage sails through: real
    // memory is full of runs that decode as valid-but-absurdly-tiny boxes
    // (extents around `1e-5`) which satisfy `min <= max`, every finiteness
    // check, the coordinate bound, *and* the radius-consistency test. Measured
    // on a real live process, this floor is the difference between ~348k
    // candidate hits and a workable set.
    //
    // Only x and y are size-checked: a 2D UI widget legitimately has a flat
    // (zero-extent) z, so demanding a z extent would reject exactly the
    // elements this command exists to find.
    let d = [aabb.max[0] - aabb.min[0], aabb.max[1] - aabb.min[1], aabb.max[2] - aabb.min[2]];
    if !d[0].is_normal() || !d[1].is_normal() || d[0] < bound.min_extent || d[1] < bound.min_extent {
        return None;
    }

    let half_diag = (d[0] * d[0] + d[1] * d[1] + d[2] * d[2]).sqrt() / 2.0;
    // The strong, cheap filter: the game derives radius from the box's own
    // extents (brief §3), so an unrelated float run essentially never lands
    // within an order of magnitude of the true half-diagonal by chance.
    if !half_diag.is_normal() || !aabb.radius.is_normal() {
        return None;
    }
    let ratio = aabb.radius / half_diag;
    if !(0.1..=10.0).contains(&ratio) {
        return None;
    }
    Some(aabb)
}

/// Brief §4 step 4: 2D screen-space overlap fraction (x/y only — a screen
/// rectangle has no z; z was already validated for plausibility above).
/// `None` when the boxes don't intersect at all — irrelevant, not merely
/// low-scoring.
pub fn rect_overlap(aabb: &Aabb, rect: Rect) -> Option<f64> {
    let ox0 = aabb.min[0].max(rect.x0);
    let oy0 = aabb.min[1].max(rect.y0);
    let ox1 = aabb.max[0].min(rect.x1);
    let oy1 = aabb.max[1].min(rect.y1);
    if ox1 <= ox0 || oy1 <= oy0 {
        return None;
    }
    let overlap_area = (ox1 - ox0) as f64 * (oy1 - oy0) as f64;
    let elem_area = ((aabb.max[0] - aabb.min[0]) as f64 * (aabb.max[1] - aabb.min[1]) as f64).max(1e-9);
    Some((overlap_area / elem_area).min(1.0))
}

pub struct UiLocateInput {
    /// The scan set — every committed writable region by default (the same
    /// set `scan value`/`scan aob` use), or a caller-narrowed subset.
    pub regions: Vec<(Va, usize)>,
    pub rect: Rect,
    pub space: CoordSpace,
    pub layout: AabbLayout,
    /// Byte stride between candidate positions; the fields are dword-aligned,
    /// so 4 is the sound default (brief §4 step 2).
    pub align: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct UiElementHit {
    /// The element's base address (`min.x`'s position minus
    /// [`AabbLayout::min_x_offset`]) — dump from here to inspect the object.
    pub address: Va,
    pub min: [f32; 3],
    pub max: [f32; 3],
    pub radius: f32,
    /// Fraction of the element's own 2D area covered by the query rect,
    /// `0.0..=1.0`. Ranking key — `matches` is sorted by this, descending.
    pub area_overlap: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct UiLocateArtifact {
    pub rect: [f32; 4],
    pub space: CoordSpace,
    pub count: usize,
    pub elements: Vec<UiElementHit>,
    pub candidates_tested: usize,
    pub bytes_scanned: usize,
    /// `[min_x, min_y, max_x, max_y]` observed across *every* plausible AABB
    /// found, regardless of rect overlap — the "make the space observable"
    /// data (brief §4). `None` when nothing plausible was found at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_range: Option<[f32; 4]>,
}

#[derive(Default)]
pub struct UiLocatePass;

impl Pass for UiLocatePass {
    type In = UiLocateInput;
    type Out = UiLocateArtifact;

    fn name(&self) -> &'static str {
        "ui.locate"
    }

    fn run(&self, ctx: &Ctx, input: UiLocateInput) -> Result<UiLocateArtifact, CoreError> {
        let bound = input.space.bound();
        let align = input.align.max(1);
        let layout = input.layout;

        let mut elements = Vec::new();
        let mut candidates_tested = 0usize;
        let mut bytes_scanned = 0usize;
        let mut observed_min = [f32::INFINITY, f32::INFINITY];
        let mut observed_max = [f32::NEG_INFINITY, f32::NEG_INFINITY];
        let mut any_observed = false;

        for (start, size) in &input.regions {
            let scan_input = StructuralScanInput {
                start: *start,
                size: *size,
                align,
                fields: AabbLayout::fields(),
                predicate: Box::new(move |values| aabb_plausible(values, bound).map(|_| 0.0)),
            };
            // A region enumerated a moment ago can be freed/decommitted
            // before this scan reaches it (RE_METHOD F6) — skip it and keep
            // going, never abort the whole ~1.2 GB sweep over one stale
            // region (brief §7).
            let art = match StructuralScanPass.run(ctx, scan_input) {
                Ok(a) => a,
                Err(CoreError::Source(n0xis_sources::SourceError::Unmapped(_))) => continue,
                Err(e) => return Err(e),
            };
            candidates_tested += art.candidates_tested;
            bytes_scanned += art.bytes_scanned;

            for hit in &art.matches {
                let Some(aabb) = aabb_plausible(&hit.values, bound) else { continue };
                any_observed = true;
                observed_min[0] = observed_min[0].min(aabb.min[0]);
                observed_min[1] = observed_min[1].min(aabb.min[1]);
                observed_max[0] = observed_max[0].max(aabb.max[0]);
                observed_max[1] = observed_max[1].max(aabb.max[1]);
                if let Some(area_overlap) = rect_overlap(&aabb, input.rect) {
                    elements.push(UiElementHit {
                        address: layout.element_base(hit.base),
                        min: aabb.min,
                        max: aabb.max,
                        radius: aabb.radius,
                        area_overlap,
                    });
                }
            }
        }

        elements.sort_by(|a, b| b.area_overlap.partial_cmp(&a.area_overlap).unwrap_or(std::cmp::Ordering::Equal));
        let observed_range = any_observed.then_some([observed_min[0], observed_min[1], observed_max[0], observed_max[1]]);

        Ok(UiLocateArtifact {
            rect: [input.rect.x0, input.rect.y0, input.rect.x1, input.rect.y1],
            space: input.space,
            count: elements.len(),
            elements,
            candidates_tested,
            bytes_scanned,
            observed_range,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    /// Encode one AABB (7 contiguous `f32`s: min.x/y/z, max.x/y/z, radius) at
    /// `min_x_offset` inside a byte buffer, per [`AabbLayout::STINGRAY`].
    fn encode_aabb(buf: &mut [u8], min_x_offset: usize, min: [f32; 3], max: [f32; 3], radius: f32) {
        let floats = [min[0], min[1], min[2], max[0], max[1], max[2], radius];
        for (i, v) in floats.iter().enumerate() {
            let off = min_x_offset + i * 4;
            buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
        }
    }

    fn ctx_over(bytes: Vec<u8>) -> (Snapshot, X64) {
        (Snapshot::builder().region(Va(0x2000), bytes).build(), X64::new())
    }

    /// The brief's own §9.1 bar: "Synthesize a buffer with a known AABB at a
    /// known offset and assert the scanner finds it, with correct overlap
    /// maths."
    #[test]
    fn finds_a_known_aabb_and_computes_correct_overlap() {
        let mut buf = vec![0xCCu8; 0x200]; // junk everywhere else
        let elem_base = 0x40usize;
        let layout = AabbLayout::STINGRAY;
        // A 10x10x10 box at (0,0,0)-(10,10,10), radius = half-diagonal exactly.
        let half_diag = ((10.0f32 * 10.0 * 3.0).sqrt()) / 2.0;
        encode_aabb(&mut buf, elem_base + layout.min_x_offset, [0.0, 0.0, 0.0], [10.0, 10.0, 10.0], half_diag);

        let (snap, arch) = ctx_over(buf.clone());
        let ctx = Ctx::new(&snap, &arch);
        let art = UiLocatePass
            .run(
                &ctx,
                UiLocateInput {
                    regions: vec![(Va(0x2000), buf.len())],
                    rect: Rect::new(5.0, 5.0, 15.0, 15.0), // overlaps exactly the (5,5)-(10,10) quadrant
                    space: CoordSpace::Screen,
                    layout,
                    align: 4,
                },
            )
            .unwrap();

        assert_eq!(art.count, 1, "expected exactly one element: {art:?}");
        let hit = &art.elements[0];
        assert_eq!(hit.address, Va(0x2000).offset(elem_base as u64));
        assert_eq!(hit.min, [0.0, 0.0, 0.0]);
        assert_eq!(hit.max, [10.0, 10.0, 10.0]);
        // overlap area = 5x5 = 25; element area = 10x10 = 100 -> 0.25
        assert!((hit.area_overlap - 0.25).abs() < 1e-6, "got {}", hit.area_overlap);
        assert_eq!(art.bytes_scanned, buf.len());
        assert!(art.candidates_tested > 0);
    }

    #[test]
    fn an_aabb_outside_the_query_rect_is_not_reported() {
        let mut buf = vec![0u8; 0x200];
        let layout = AabbLayout::STINGRAY;
        encode_aabb(&mut buf, layout.min_x_offset, [0.0, 0.0, 0.0], [1.0, 1.0, 1.0], 0.87);

        let (snap, arch) = ctx_over(buf.clone());
        let ctx = Ctx::new(&snap, &arch);
        let art = UiLocatePass
            .run(
                &ctx,
                UiLocateInput {
                    regions: vec![(Va(0x2000), buf.len())],
                    rect: Rect::new(100.0, 100.0, 200.0, 200.0), // far away
                    space: CoordSpace::Screen,
                    layout,
                    align: 4,
                },
            )
            .unwrap();
        assert_eq!(art.count, 0);
        // But it *was* observed (just irrelevant to this rect) — the
        // "make the space observable" data still reports it.
        assert!(art.observed_range.is_some());
    }

    /// The `FLT_MAX` sentinel is transient junk, not a real AABB — the brief's
    /// §5 trap this predicate must not fall into.
    #[test]
    fn flt_max_sentinel_is_not_a_plausible_aabb() {
        let bound = CoordSpace::Screen.bound();
        let sentinel = vec![
            ScanValue::Float(f32::MAX as f64),
            ScanValue::Float(f32::MAX as f64),
            ScanValue::Float(f32::MAX as f64),
            ScanValue::Float(f32::MIN as f64),
            ScanValue::Float(f32::MIN as f64),
            ScanValue::Float(f32::MIN as f64),
            ScanValue::Float(0.0),
        ];
        assert!(aabb_plausible(&sentinel, bound).is_none());
    }

    #[test]
    fn a_box_with_an_inconsistent_radius_is_rejected() {
        let bound = CoordSpace::Screen.bound();
        let values = vec![
            ScanValue::Float(0.0), ScanValue::Float(0.0), ScanValue::Float(0.0),
            ScanValue::Float(10.0), ScanValue::Float(10.0), ScanValue::Float(10.0),
            ScanValue::Float(9999.0), // wildly inconsistent with a 10x10x10 box
        ];
        assert!(aabb_plausible(&values, bound).is_none());
    }

    /// A real false positive captured from a live scan of an *empty* process:
    /// every classic check passes (finite, `min <= max`, in-bound, radius
    /// consistent with the half-diagonal) — it is rejected only by the
    /// per-space size floor, because a 9e-5-wide "widget" is not a widget.
    /// This one sample is representative of the ~348k hits `auto` produced.
    #[test]
    fn an_absurdly_tiny_box_is_rejected_in_a_concrete_space() {
        let values = vec![
            ScanValue::Float(2.272818e-39), ScanValue::Float(2.272818e-39), ScanValue::Float(1.122221e-37),
            ScanValue::Float(9.1405585e-5), ScanValue::Float(9.1405585e-5), ScanValue::Float(9.1405585e-5),
            ScanValue::Float(9.1405585e-5),
        ];
        assert!(aabb_plausible(&values, CoordSpace::Screen.bound()).is_none(), "sub-pixel in screen space");
        assert!(aabb_plausible(&values, CoordSpace::Ndc.bound()).is_none(), "far below one NDC thousandth");
        // `auto` is documented as permissive — it surveys, it does not filter.
        assert!(aabb_plausible(&values, CoordSpace::Auto.bound()).is_some(), "auto stays permissive by contract");
    }

    /// A flat 2D widget (zero z-extent) must still be accepted — requiring a
    /// z extent would reject exactly what this command hunts.
    #[test]
    fn a_flat_2d_widget_with_zero_z_extent_is_accepted() {
        let bound = CoordSpace::Screen.bound();
        // 100x50 box, flat in z. half_diag = sqrt(100^2+50^2)/2 ~= 55.9
        let values = vec![
            ScanValue::Float(10.0), ScanValue::Float(20.0), ScanValue::Float(0.0),
            ScanValue::Float(110.0), ScanValue::Float(70.0), ScanValue::Float(0.0),
            ScanValue::Float(55.9),
        ];
        let aabb = aabb_plausible(&values, bound).expect("a flat 2D widget must be plausible");
        assert_eq!(aabb.min[2], 0.0);
        assert_eq!(aabb.max[2], 0.0);
    }

    #[test]
    fn rect_overlap_returns_none_for_non_intersecting_boxes() {
        let aabb = Aabb { min: [0.0, 0.0, 0.0], max: [1.0, 1.0, 1.0], radius: 0.87 };
        assert!(rect_overlap(&aabb, Rect::new(5.0, 5.0, 6.0, 6.0)).is_none());
    }

    #[test]
    fn observed_range_reports_across_the_permissive_auto_bound() {
        let mut buf = vec![0u8; 0x100];
        let layout = AabbLayout::STINGRAY;
        encode_aabb(&mut buf, layout.min_x_offset, [-0.5, -0.5, -0.5], [0.5, 0.5, 0.5], 0.87);
        let (snap, arch) = ctx_over(buf.clone());
        let ctx = Ctx::new(&snap, &arch);
        let art = UiLocatePass
            .run(
                &ctx,
                UiLocateInput {
                    regions: vec![(Va(0x2000), buf.len())],
                    rect: Rect::new(-1.0, -1.0, 1.0, 1.0),
                    space: CoordSpace::Auto,
                    layout,
                    align: 4,
                },
            )
            .unwrap();
        assert_eq!(art.count, 1);
        let range = art.observed_range.unwrap();
        assert!((range[0] - -0.5).abs() < 1e-6 && (range[2] - 0.5).abs() < 1e-6, "got {range:?}");
    }
}
