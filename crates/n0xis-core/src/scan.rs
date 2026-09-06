// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Typed value scanning + iterative narrowing (ROADMAP Phase 4b) — the
//! value-scanning first-scan/rescan loop, done the way CE actually does it:
//! **snapshot-backed narrowing, never a truncated address list**.
//!
//! ## Why snapshot-backed
//!
//! A naïve first scan that materializes one [`ScanMatch`] per hit falls apart on
//! a common value (scan i32 `4` in a game → millions of hits). The old
//! implementation "solved" this by capping at 200 000 and `break`-ing out of the
//! region loop — which silently stopped scanning every higher-address region, so
//! the real target usually wasn't even looked at, and no rescan could recover it.
//! That violated the sound-over-complete rule (a partial, order-dependent
//! working set returned as if usable). See `docs/PRODUCT_POLICY.md` §5.
//!
//! the scanning model, reproduced here:
//!
//! - The **first scan never truncates**. An `exact`/`in-range` scan records the
//!   matching offsets ([`RegionData::Sparse`]); an `unknown` scan records the
//!   region bytes themselves ([`RegionData::Dense`]) so a later rescan knows the
//!   *old* value at every position without materializing an address per byte.
//! - A **rescan** ([`FilterPass`]) re-reads each region from the source, compares
//!   old-vs-current per candidate (`changed`/`unchanged`/`increased`/…),
//!   narrows the survivor set, and stores their latest values (compare against
//!   the last scan, scanner-style).
//! - Addresses are **materialized only when asked** ([`ScanState::materialize`]),
//!   bounded by a display budget — the full working set is persisted compactly
//!   (see [`ScanState::encode`]), not dumped as fat JSON.
//!
//! The canonical "value 4 is too common" flow this enables:
//! `scan value --criterion unknown` → change it in-game → `scan filter
//! --criterion changed`.
//!
//! Pure comparison logic over the `MemorySource` seam: region enumeration
//! (`VirtualQueryEx` on live, sections on static) is an OS/format concern that
//! stays in `n0xis-sources`/`n0xis-cli`, handed in here as plain `(Va, usize)`
//! ranges so this pass never touches an OS API.

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

    /// Stable on-disk tag for [`ScanState::encode`]. Explicit (not `as u8` on
    /// the enum) so reordering variants can never silently corrupt a persisted
    /// working set.
    fn tag(self) -> u8 {
        match self {
            ValueType::I8 => 0,
            ValueType::U8 => 1,
            ValueType::I16 => 2,
            ValueType::U16 => 3,
            ValueType::I32 => 4,
            ValueType::U32 => 5,
            ValueType::I64 => 6,
            ValueType::U64 => 7,
            ValueType::F32 => 8,
            ValueType::F64 => 9,
        }
    }

    fn from_tag(t: u8) -> Option<ValueType> {
        Some(match t {
            0 => ValueType::I8,
            1 => ValueType::U8,
            2 => ValueType::I16,
            3 => ValueType::U16,
            4 => ValueType::I32,
            5 => ValueType::U32,
            6 => ValueType::I64,
            7 => ValueType::U64,
            8 => ValueType::F32,
            9 => ValueType::F64,
            _ => return None,
        })
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

    pub(crate) fn read(bytes: &[u8], ty: ValueType) -> Option<ScanValue> {
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

    /// The 8-byte on-disk / in-memory carrier used by [`RegionData::Sparse`]:
    /// an integer keeps its bits, a float keeps its `f64` bits.
    fn to_bits(self) -> u64 {
        match self {
            ScanValue::Int(v) => v as u64,
            ScanValue::Float(v) => v.to_bits(),
        }
    }

    fn from_bits(bits: u64, ty: ValueType) -> ScanValue {
        match ty {
            ValueType::F32 | ValueType::F64 => ScanValue::Float(f64::from_bits(bits)),
            _ => ScanValue::Int(bits as i64),
        }
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
    /// Record every value in range — the "unknown initial value" first scan a
    /// later [`FilterCriterion`] narrows down. Stored as region snapshots, not
    /// an address list.
    Unknown,
}

fn scan_criterion_matches(c: &ScanCriterion, v: ScanValue) -> bool {
    match c {
        ScanCriterion::Exact { value } => values_eq(*value, v),
        ScanCriterion::InRange { min, max } => v.as_f64() >= min.as_f64() && v.as_f64() <= max.as_f64(),
        ScanCriterion::Unknown => true,
    }
}

/// A rescan criterion — compares each surviving candidate's *new* value against
/// its previously-recorded one (or, for `exact`/`in-range`, against a literal).
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

fn filter_keeps(c: &FilterCriterion, old: ScanValue, now: ScanValue) -> bool {
    match c {
        FilterCriterion::Exact { value } => values_eq(*value, now),
        FilterCriterion::Increased => now.as_f64() > old.as_f64(),
        FilterCriterion::Decreased => now.as_f64() < old.as_f64(),
        FilterCriterion::Changed => !values_eq(old, now),
        FilterCriterion::Unchanged => values_eq(old, now),
        FilterCriterion::InRange { min, max } => now.as_f64() >= min.as_f64() && now.as_f64() <= max.as_f64(),
    }
}

#[derive(Clone, Debug)]
pub struct ScanInput {
    pub regions: Vec<(Va, usize)>,
    pub value_type: ValueType,
    pub criterion: ScanCriterion,
    /// Byte stride between candidate addresses (an aligned "fast scan");
    /// terms); `1` checks every byte offset, `value_type.size()` is the
    /// natural-alignment default.
    pub align: usize,
}

/// One region-relative surviving candidate and its last-seen value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Slot {
    pub off: u32,
    pub value: ScanValue,
}

/// How one region's live candidates are stored.
#[derive(Clone, Debug)]
pub enum RegionData {
    /// A fresh `unknown` first scan: the whole captured region. *Every* aligned
    /// offset is a live candidate; a rescan reads the old value straight from
    /// these bytes. Kept dense (no per-offset overhead) precisely because
    /// "unknown" means "all offsets", which would be pathological as a list.
    Dense { bytes: Vec<u8> },
    /// An `exact`/`in-range` scan, or any narrowed set: explicit survivors, each
    /// carrying its last-seen value so the next rescan has an "old" to compare.
    Sparse { slots: Vec<Slot> },
}

/// One region within a scan working set.
#[derive(Clone, Debug)]
pub struct RegionState {
    pub base: Va,
    pub data: RegionData,
}

impl RegionState {
    /// Number of live candidates in this region.
    fn candidate_count(&self, value_type: ValueType, align: usize) -> usize {
        match &self.data {
            RegionData::Sparse { slots } => slots.len(),
            RegionData::Dense { bytes } => dense_offsets(bytes.len(), value_type.size(), align),
        }
    }
}

/// Count of aligned offsets `off` with `off + size <= len`, stepping by `align`.
fn dense_offsets(len: usize, size: usize, align: usize) -> usize {
    if len < size {
        return 0;
    }
    (len - size) / align.max(1) + 1
}

/// The full a memory scanner-style scan working set: what the first scan produced
/// and every rescan narrows. Persisted compactly via [`encode`](Self::encode);
/// **not** `Serialize` — the response the CLI/MCP emits is the bounded
/// [`ScanReport`], never the (potentially region-sized) raw state.
#[derive(Clone, Debug)]
pub struct ScanState {
    pub value_type: ValueType,
    pub align: usize,
    pub regions: Vec<RegionState>,
}

/// A materialized `(address, value)` hit — produced on demand from a
/// [`ScanState`], never stored en masse.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScanMatch {
    pub addr: Va,
    pub value: ScanValue,
}

/// Preview budget: how many matches [`ScanState::materialize`] hands back for a
/// response. A display cap, not a business rule — the working set keeps *all*
/// candidates regardless; this only bounds what a single JSON response carries.
pub const PREVIEW_LIMIT: usize = 1000;

const SCAN_MAGIC: &[u8; 8] = b"N0XSCAN1";
const REGION_TAG_DENSE: u8 = 0;
const REGION_TAG_SPARSE: u8 = 1;

impl ScanState {
    /// Total live candidates across every region — always the *true* count, no
    /// matter how large. This is the number the old design silently capped.
    pub fn total(&self) -> usize {
        self.regions.iter().map(|r| r.candidate_count(self.value_type, self.align)).sum()
    }

    /// Materialize up to `limit` `(address, value)` hits, in region then offset
    /// order. Bounded on purpose — call with [`PREVIEW_LIMIT`] for a response,
    /// or a larger cap when a caller genuinely wants them all (e.g. the pointer
    /// scanner, whose candidate sets are bounded by construction).
    pub fn materialize(&self, limit: usize) -> Vec<ScanMatch> {
        let size = self.value_type.size();
        let align = self.align.max(1);
        let mut out = Vec::new();
        for r in &self.regions {
            match &r.data {
                RegionData::Sparse { slots } => {
                    for s in slots {
                        if out.len() >= limit {
                            return out;
                        }
                        out.push(ScanMatch { addr: r.base.offset(s.off as u64), value: s.value });
                    }
                }
                RegionData::Dense { bytes } => {
                    let mut off = 0usize;
                    while off + size <= bytes.len() {
                        if out.len() >= limit {
                            return out;
                        }
                        if let Some(v) = ScanValue::read(&bytes[off..off + size], self.value_type) {
                            out.push(ScanMatch { addr: r.base.offset(off as u64), value: v });
                        }
                        off += align;
                    }
                }
            }
        }
        out
    }

    /// Build the bounded response summary for a CLI/MCP reply.
    pub fn report(&self) -> ScanReport {
        let total = self.total();
        let matches = self.materialize(PREVIEW_LIMIT);
        ScanReport {
            value_type: self.value_type,
            regions: self.regions.len(),
            total_matches: total,
            shown: matches.len(),
            exhaustive: matches.len() == total,
            matches,
        }
    }

    /// Compact, self-describing binary encoding for `.n0x/dumps/scan/`. Little-
    /// endian throughout; dense regions store raw bytes, sparse regions store
    /// `(u32 offset, u64 value-bits)` per slot. Deliberately not JSON: a dense
    /// `unknown` scan of a live game is region-sized, and base64-in-JSON would
    /// bloat it ~2x for no benefit (the state is internal, never shown raw).
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(SCAN_MAGIC);
        b.push(self.value_type.tag());
        b.extend_from_slice(&(self.align as u64).to_le_bytes());
        b.extend_from_slice(&(self.regions.len() as u64).to_le_bytes());
        for r in &self.regions {
            b.extend_from_slice(&r.base.get().to_le_bytes());
            match &r.data {
                RegionData::Dense { bytes } => {
                    b.push(REGION_TAG_DENSE);
                    b.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                    b.extend_from_slice(bytes);
                }
                RegionData::Sparse { slots } => {
                    b.push(REGION_TAG_SPARSE);
                    b.extend_from_slice(&(slots.len() as u64).to_le_bytes());
                    for s in slots {
                        b.extend_from_slice(&s.off.to_le_bytes());
                        b.extend_from_slice(&s.value.to_bits().to_le_bytes());
                    }
                }
            }
        }
        b
    }

    /// Inverse of [`encode`](Self::encode). Errors (not panics) on any malformed
    /// or truncated buffer — a corrupt dump must never crash a scan.
    pub fn decode(buf: &[u8]) -> Result<ScanState, CoreError> {
        let mut c = Cursor::new(buf);
        let magic = c.take(8)?;
        if magic != SCAN_MAGIC {
            return Err(CoreError::Other("not a n0xis scan working set (bad magic)".into()));
        }
        let value_type = ValueType::from_tag(c.u8()?)
            .ok_or_else(|| CoreError::Other("scan dump: unknown value type tag".into()))?;
        let align = c.u64()? as usize;
        let region_count = c.u64()? as usize;
        let mut regions = Vec::with_capacity(region_count.min(1 << 20));
        for _ in 0..region_count {
            let base = Va(c.u64()?);
            let tag = c.u8()?;
            let data = match tag {
                REGION_TAG_DENSE => {
                    let n = c.u64()? as usize;
                    RegionData::Dense { bytes: c.take(n)?.to_vec() }
                }
                REGION_TAG_SPARSE => {
                    let n = c.u64()? as usize;
                    let mut slots = Vec::with_capacity(n.min(1 << 24));
                    for _ in 0..n {
                        let off = u32::from_le_bytes(c.take(4)?.try_into().unwrap());
                        let bits = u64::from_le_bytes(c.take(8)?.try_into().unwrap());
                        slots.push(Slot { off, value: ScanValue::from_bits(bits, value_type) });
                    }
                    RegionData::Sparse { slots }
                }
                _ => return Err(CoreError::Other("scan dump: unknown region tag".into())),
            };
            regions.push(RegionState { base, data });
        }
        Ok(ScanState { value_type, align, regions })
    }
}

/// A tiny checked reader over a byte buffer for [`ScanState::decode`].
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CoreError> {
        let end = self.pos.checked_add(n).ok_or_else(|| CoreError::Other("scan dump: length overflow".into()))?;
        if end > self.buf.len() {
            return Err(CoreError::Other("scan dump: unexpected end of buffer".into()));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, CoreError> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64, CoreError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

/// The first scan. Produces a [`ScanState`], never a truncated list: every
/// region is scanned in full, and the working set is stored densely (unknown)
/// or as offset survivors (exact/in-range).
#[derive(Clone, Copy, Debug, Default)]
pub struct ScanPass;

impl Pass for ScanPass {
    type In = ScanInput;
    type Out = ScanState;

    fn name(&self) -> &'static str {
        "scan.value"
    }

    fn run(&self, ctx: &Ctx, input: ScanInput) -> Result<ScanState, CoreError> {
        let size = input.value_type.size();
        let align = input.align.max(1);
        let mut regions = Vec::new();

        for (start, len) in &input.regions {
            let Ok(bytes) = ctx.source.read(*start, *len) else { continue };
            match input.criterion {
                ScanCriterion::Unknown => {
                    if bytes.len() >= size {
                        regions.push(RegionState { base: *start, data: RegionData::Dense { bytes } });
                    }
                }
                ref crit => {
                    let mut slots = Vec::new();
                    let mut off = 0usize;
                    while off + size <= bytes.len() {
                        if let Some(v) = ScanValue::read(&bytes[off..off + size], input.value_type)
                            && scan_criterion_matches(crit, v)
                        {
                            slots.push(Slot { off: off as u32, value: v });
                        }
                        off += align;
                    }
                    if !slots.is_empty() {
                        regions.push(RegionState { base: *start, data: RegionData::Sparse { slots } });
                    }
                }
            }
        }
        Ok(ScanState { value_type: input.value_type, align, regions })
    }
}

pub struct FilterInput {
    /// The working set from a previous [`ScanPass`] or [`FilterPass`].
    pub previous: ScanState,
    pub criterion: FilterCriterion,
}

/// A rescan. Re-reads every region's current bytes, compares old-vs-new per
/// candidate, and returns a narrowed [`ScanState`] whose survivors carry their
/// latest values (so the next rescan compares against the most recent world).
#[derive(Clone, Copy, Debug, Default)]
pub struct FilterPass;

impl Pass for FilterPass {
    type In = FilterInput;
    type Out = ScanState;

    fn name(&self) -> &'static str {
        "scan.filter"
    }

    fn run(&self, ctx: &Ctx, input: FilterInput) -> Result<ScanState, CoreError> {
        let value_type = input.previous.value_type;
        let align = input.previous.align.max(1);
        let size = value_type.size();
        let mut regions = Vec::new();

        for r in &input.previous.regions {
            // One read per region covering the candidate span, then index into
            // it — a syscall per candidate would be pathological for a large set.
            let (span_off, span) = match &r.data {
                RegionData::Dense { bytes } => (0usize, ctx.source.read(r.base, bytes.len()).unwrap_or_default()),
                RegionData::Sparse { slots } => {
                    let Some(min) = slots.iter().map(|s| s.off as usize).min() else { continue };
                    let max = slots.iter().map(|s| s.off as usize).max().unwrap();
                    let span_len = max + size - min;
                    (min, ctx.source.read(r.base.offset(min as u64), span_len).unwrap_or_default())
                }
            };

            let read_now = |abs_off: usize| -> Option<ScanValue> {
                let rel = abs_off.checked_sub(span_off)?;
                let end = rel.checked_add(size)?;
                if end > span.len() {
                    return None;
                }
                ScanValue::read(&span[rel..end], value_type)
            };

            let mut slots = Vec::new();
            match &r.data {
                RegionData::Dense { bytes } => {
                    let mut off = 0usize;
                    while off + size <= bytes.len() {
                        if let (Some(old), Some(now)) =
                            (ScanValue::read(&bytes[off..off + size], value_type), read_now(off))
                            && filter_keeps(&input.criterion, old, now)
                        {
                            slots.push(Slot { off: off as u32, value: now });
                        }
                        off += align;
                    }
                }
                RegionData::Sparse { slots: prev_slots } => {
                    for s in prev_slots {
                        if let Some(now) = read_now(s.off as usize)
                            && filter_keeps(&input.criterion, s.value, now)
                        {
                            slots.push(Slot { off: s.off, value: now });
                        }
                    }
                }
            }
            if !slots.is_empty() {
                regions.push(RegionState { base: r.base, data: RegionData::Sparse { slots } });
            }
        }
        Ok(ScanState { value_type, align, regions })
    }
}

/// The bounded response summary emitted to the CLI/MCP for a scan or rescan —
/// the true `total_matches` plus a capped `matches` preview. This is the
/// serializable artifact; [`ScanState`] itself (which can be region-sized)
/// never goes on the wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub value_type: ValueType,
    pub regions: usize,
    /// The real number of live candidates — never capped.
    pub total_matches: usize,
    /// How many are included in `matches` below.
    pub shown: usize,
    /// True when `matches` is the *complete* set (`shown == total_matches`), so
    /// a caller knows whether it's looking at a preview or the whole thing.
    pub exhaustive: bool,
    pub matches: Vec<ScanMatch>,
}

// --- Group scan: locate a struct by several interrelated values at once ------
//
// `scan value` finds ONE value; three small, common numbers (e.g. occupied/free/
// bots of a lobby) each return thousands of candidates and must be narrowed one
// at a time. But related fields live *together* in a struct, so scanning for
// their co-occurrence within a byte window pins the struct in a single pass —
// the "group scan" / known-adjacent-values technique. Each field is an exact
// typed value; a hit is a location where every field is present within `window`
// bytes of the others (any order, any offset — not a fixed AOB layout).

/// One required field of a group scan: an exact value of a given type.
#[derive(Clone, Copy, Debug)]
pub struct GroupField {
    pub value_type: ValueType,
    pub value: ScanValue,
}

#[derive(Clone, Debug)]
pub struct GroupScanInput {
    pub regions: Vec<(Va, usize)>,
    pub fields: Vec<GroupField>,
    /// Max byte span between the earliest and latest field of a single hit.
    pub window: usize,
    /// Candidate stride; `1` checks every byte, a larger value (e.g. 4) skips to
    /// aligned positions — faster, at the cost of missing an unaligned field.
    pub align: usize,
    /// Cap on hits returned in the artifact (the true count is still reported).
    pub limit: usize,
}

/// One field located inside a [`GroupHit`].
#[derive(Clone, Copy, Debug, Serialize)]
pub struct GroupFieldHit {
    /// Index into the request's `fields`.
    pub index: usize,
    pub va: Va,
    /// Signed byte offset from the hit's `base`.
    pub offset: i64,
    #[serde(rename = "type")]
    pub value_type: ValueType,
    pub value: ScanValue,
}

/// One location where every requested field was found within `window` bytes —
/// a candidate struct base (the lowest field address of the cluster).
#[derive(Clone, Debug, Serialize)]
pub struct GroupHit {
    pub base: Va,
    pub fields: Vec<GroupFieldHit>,
}

/// The serializable result of a [`GroupScanPass`].
#[derive(Clone, Debug, Serialize)]
pub struct GroupArtifact {
    pub hits: Vec<GroupHit>,
    /// True number of distinct clusters found (may exceed `hits.len()`).
    pub total_hits: usize,
    pub bytes_scanned: usize,
    pub window: usize,
    pub field_count: usize,
}

/// Find every location where all requested fields co-occur within `window` bytes.
/// Anchors on the *rarest* field per region (fewest candidates → fewest
/// false clusters and least work), then binds each other field to its nearest
/// match within `±window` of that anchor.
pub struct GroupScanPass;

impl Pass for GroupScanPass {
    type In = GroupScanInput;
    type Out = GroupArtifact;

    fn name(&self) -> &'static str {
        "scan.group"
    }

    fn run(&self, ctx: &Ctx, input: GroupScanInput) -> Result<GroupArtifact, CoreError> {
        let align = input.align.max(1);
        let nfields = input.fields.len();
        let win = input.window as i64;
        let mut hits: Vec<GroupHit> = Vec::new();
        let mut total_hits = 0usize;
        let mut bytes_scanned = 0usize;

        if nfields == 0 {
            return Ok(GroupArtifact { hits, total_hits, bytes_scanned, window: input.window, field_count: 0 });
        }

        for (start, len) in &input.regions {
            let Ok(bytes) = ctx.source.read(*start, *len) else { continue };
            bytes_scanned += bytes.len();

            // One pass over the region: collect each field's match offsets (kept
            // ascending, since `off` increases).
            let mut matches: Vec<Vec<usize>> = vec![Vec::new(); nfields];
            let mut off = 0usize;
            while off < bytes.len() {
                for (fi, f) in input.fields.iter().enumerate() {
                    let sz = f.value_type.size();
                    if off + sz <= bytes.len()
                        && let Some(v) = ScanValue::read(&bytes[off..off + sz], f.value_type)
                        && values_eq(v, f.value)
                    {
                        matches[fi].push(off);
                    }
                }
                off += align;
            }

            // A field with no match here makes a full cluster impossible.
            if matches.iter().any(|m| m.is_empty()) {
                continue;
            }
            let anchor = (0..nfields).min_by_key(|&i| matches[i].len()).unwrap();

            let mut seen_bases: std::collections::HashSet<u64> = std::collections::HashSet::new();
            for &a in &matches[anchor] {
                let mut chosen: Vec<(usize, usize)> = Vec::with_capacity(nfields);
                let mut ok = true;
                // `fi` is a field index used as data (compared to `anchor`,
                // stored in `chosen`), not merely to walk one slice.
                #[allow(clippy::needless_range_loop)]
                for fi in 0..nfields {
                    if fi == anchor {
                        chosen.push((fi, a));
                        continue;
                    }
                    // Nearest match of field `fi` to the anchor within ±window.
                    let offs = &matches[fi];
                    let ip = offs.partition_point(|&x| x < a);
                    let mut best: Option<usize> = None;
                    for cand in [ip.checked_sub(1).map(|i| offs[i]), offs.get(ip).copied()].into_iter().flatten() {
                        if (cand as i64 - a as i64).abs() <= win {
                            match best {
                                None => best = Some(cand),
                                Some(b) if (cand as i64 - a as i64).abs() < (b as i64 - a as i64).abs() => best = Some(cand),
                                _ => {}
                            }
                        }
                    }
                    match best {
                        Some(o) => chosen.push((fi, o)),
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                if !ok {
                    continue;
                }
                let base_off = chosen.iter().map(|&(_, o)| o).min().unwrap();
                let base_va = start.offset(base_off as u64);
                if !seen_bases.insert(base_va.get()) {
                    continue; // same cluster reached from another anchor match
                }
                total_hits += 1;
                if hits.len() < input.limit {
                    let mut fields: Vec<GroupFieldHit> = chosen
                        .iter()
                        .map(|&(fi, o)| GroupFieldHit {
                            index: fi,
                            va: start.offset(o as u64),
                            offset: o as i64 - base_off as i64,
                            value_type: input.fields[fi].value_type,
                            value: input.fields[fi].value,
                        })
                        .collect();
                    fields.sort_by_key(|f| f.offset);
                    hits.push(GroupHit { base: base_va, fields });
                }
            }
        }

        Ok(GroupArtifact { hits, total_hits, bytes_scanned, window: input.window, field_count: nfields })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    fn i32_region(base: Va, words: &[i32]) -> (Va, Vec<u8>) {
        let mut bytes = Vec::new();
        for w in words {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        (base, bytes)
    }

    #[test]
    fn group_scan_pins_a_struct_by_related_values() {
        // A lobby struct [total=4, occupied=3, free=1] at offset 0x10, plus lone
        // decoys (a stray 4 and a stray 3 far apart) that must NOT form a cluster.
        let mut bytes = vec![0u8; 0x100];
        let put = |b: &mut [u8], off: usize, v: i32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());
        put(&mut bytes, 0x10, 4);
        put(&mut bytes, 0x14, 3);
        put(&mut bytes, 0x18, 1);
        put(&mut bytes, 0x80, 4); // lone decoy
        put(&mut bytes, 0xC0, 3); // lone decoy, >window from the 1
        let base = Va(0x4000);
        let snap = Snapshot::builder().region(base, bytes).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = GroupScanPass
            .run(
                &ctx,
                GroupScanInput {
                    regions: vec![(base, 0x100)],
                    fields: vec![
                        GroupField { value_type: ValueType::I32, value: ScanValue::Int(4) },
                        GroupField { value_type: ValueType::I32, value: ScanValue::Int(3) },
                        GroupField { value_type: ValueType::I32, value: ScanValue::Int(1) },
                    ],
                    window: 16,
                    align: 4,
                    limit: 100,
                },
            )
            .unwrap();
        assert_eq!(art.total_hits, 1, "exactly the real cluster: {:#x?}", art.hits);
        let h = &art.hits[0];
        assert_eq!(h.base, Va(0x4010));
        assert_eq!(h.fields.len(), 3);
        // fields come back sorted by offset: total@0, occupied@4, free@8.
        assert_eq!(h.fields[0].offset, 0);
        assert_eq!(h.fields[2].offset, 8);
    }

    #[test]
    fn exact_first_scan_finds_the_needles() {
        let (base, bytes) = i32_region(Va(0x1000), &[0, 0, 100, 0, 0, 0, 0, 0, 0, 0, 100, 0, 0, 0, 0, 0]);
        let snap = Snapshot::builder().region(base, bytes).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let state = ScanPass
            .run(
                &ctx,
                ScanInput {
                    regions: vec![(base, 64)],
                    value_type: ValueType::I32,
                    criterion: ScanCriterion::Exact { value: ScanValue::Int(100) },
                    align: 4,
                },
            )
            .unwrap();
        assert_eq!(state.total(), 2);
        let m = state.materialize(PREVIEW_LIMIT);
        assert_eq!(m[0].addr, Va(0x1008));
        assert_eq!(m[1].addr, Va(0x1028));
    }

    #[test]
    fn first_scan_covers_every_region_no_truncation() {
        // Two regions; the needle is in the *second* one. The old `break
        // 'regions` bug would have missed it entirely once the first region
        // filled the budget. Here there's no budget to fill.
        let snap = Snapshot::builder()
            .region(Va(0x1000), 7i32.to_le_bytes().repeat(4))
            .region(Va(0x9000), 7i32.to_le_bytes().repeat(4))
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let state = ScanPass
            .run(
                &ctx,
                ScanInput {
                    regions: vec![(Va(0x1000), 16), (Va(0x9000), 16)],
                    value_type: ValueType::I32,
                    criterion: ScanCriterion::Exact { value: ScanValue::Int(7) },
                    align: 4,
                },
            )
            .unwrap();
        assert_eq!(state.total(), 8);
        let addrs: Vec<Va> = state.materialize(PREVIEW_LIMIT).into_iter().map(|m| m.addr).collect();
        assert!(addrs.contains(&Va(0x9000)), "second region must be scanned");
    }

    #[test]
    fn increased_filter_narrows_across_a_rescan() {
        let arch = X64::new();
        // First world: both candidates hold 100.
        let (base, before) = i32_region(Va(0x2000), &[100, 0, 100, 0]);
        let snap1 = Snapshot::builder().region(base, before).build();
        let ctx1 = Ctx::new(&snap1, &arch);
        let first = ScanPass
            .run(
                &ctx1,
                ScanInput {
                    regions: vec![(base, 16)],
                    value_type: ValueType::I32,
                    criterion: ScanCriterion::Exact { value: ScanValue::Int(100) },
                    align: 4,
                },
            )
            .unwrap();
        assert_eq!(first.total(), 2);

        // Second world: only the first candidate increased.
        let (_, after) = i32_region(Va(0x2000), &[150, 0, 100, 0]);
        let snap2 = Snapshot::builder().region(base, after).build();
        let ctx2 = Ctx::new(&snap2, &arch);
        let filtered = FilterPass
            .run(&ctx2, FilterInput { previous: first, criterion: FilterCriterion::Increased })
            .unwrap();
        assert_eq!(filtered.total(), 1);
        let m = filtered.materialize(PREVIEW_LIMIT);
        assert_eq!(m[0].addr, Va(0x2000));
        assert_eq!(m[0].value, ScanValue::Int(150));
    }

    #[test]
    fn unknown_scan_then_changed_narrows_from_a_snapshot() {
        // The canonical "value too common" flow: unknown first scan (dense),
        // then narrow by what changed — no address list ever materialized up
        // front.
        let arch = X64::new();
        let (base, before) = i32_region(Va(0x3000), &[7, 7, 7, 7]);
        let snap1 = Snapshot::builder().region(base, before).build();
        let ctx1 = Ctx::new(&snap1, &arch);
        let first = ScanPass
            .run(
                &ctx1,
                ScanInput { regions: vec![(base, 16)], value_type: ValueType::I32, criterion: ScanCriterion::Unknown, align: 4 },
            )
            .unwrap();
        assert_eq!(first.total(), 4);
        assert!(matches!(first.regions[0].data, RegionData::Dense { .. }));

        // Only the slot at +8 changes.
        let (_, after) = i32_region(Va(0x3000), &[7, 7, 9, 7]);
        let snap2 = Snapshot::builder().region(base, after).build();
        let ctx2 = Ctx::new(&snap2, &arch);
        let changed = FilterPass
            .run(&ctx2, FilterInput { previous: first, criterion: FilterCriterion::Changed })
            .unwrap();
        assert_eq!(changed.total(), 1);
        let m = changed.materialize(PREVIEW_LIMIT);
        assert_eq!(m[0].addr, Va(0x3008));
        assert_eq!(m[0].value, ScanValue::Int(9));
    }

    #[test]
    fn encode_decode_roundtrips_both_region_shapes() {
        let state = ScanState {
            value_type: ValueType::I32,
            align: 4,
            regions: vec![
                RegionState { base: Va(0x1000), data: RegionData::Dense { bytes: vec![1, 2, 3, 4, 5, 6, 7, 8] } },
                RegionState {
                    base: Va(0x2000),
                    data: RegionData::Sparse { slots: vec![Slot { off: 4, value: ScanValue::Int(42) }, Slot { off: 12, value: ScanValue::Int(-1) }] },
                },
            ],
        };
        let bytes = state.encode();
        let back = ScanState::decode(&bytes).unwrap();
        assert_eq!(back.value_type, ValueType::I32);
        assert_eq!(back.align, 4);
        assert_eq!(back.regions.len(), 2);
        assert_eq!(back.total(), state.total());
        let a = back.materialize(PREVIEW_LIMIT);
        let b = state.materialize(PREVIEW_LIMIT);
        assert_eq!(a, b);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(ScanState::decode(b"not-a-scan-buffer").is_err());
        assert!(ScanState::decode(&[]).is_err());
    }

    #[test]
    fn float_values_survive_roundtrip() {
        let state = ScanState {
            value_type: ValueType::F32,
            align: 4,
            regions: vec![RegionState {
                base: Va(0x1000),
                data: RegionData::Sparse { slots: vec![Slot { off: 0, value: ScanValue::Float(1.5) }] },
            }],
        };
        let back = ScanState::decode(&state.encode()).unwrap();
        assert_eq!(back.materialize(PREVIEW_LIMIT)[0].value, ScanValue::Float(1.5));
    }
}
