// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! # n0xis-luajit — live LuaJIT VM introspection
//!
//! Finds LuaJIT GC objects directly in a running process's heap by decoding
//! their real header layout, instead of hand-picking a byte pattern per
//! string (what the manual `scan aob` workflow required before this crate
//! existed — one signature per known string, useless for a string whose text
//! isn't already known).
//!
//! Scope (v1): [`GCstr`] discovery/validation only. `GCtab`/the custom
//! Bitsquid `array` container are a documented follow-on — their element
//! encoding is still unconfirmed (see the project's research notes),
//! and this crate should not guess at a layout it hasn't verified.
//!
//! Source-agnostic like the rest of n0xis: works over any
//! [`MemorySource`], so it is unit-tested against `Snapshot` with zero OS
//! APIs linked, and runs unchanged over a live process or a static dump.

use n0xis_contracts::Va;
use n0xis_sources::{MemorySource, RegionCoverage, SourceError, Swept};
use serde::Serialize;

mod layout;
mod lcg;
mod obj;
pub use layout::{locate_strings, LayoutCandidate, LayoutChoice, LayoutDecision, LocatedGcStr, LocatedStrings, References, GCSTR_LEN_OFFSETS};
pub use lcg::{find_seeds, ChanceMatches, Lcg, SeedHit, SeedScan, CHANCE_BOUND};
pub use obj::{decode_tvalue, read_table, string_ref_candidates, LuaLayout, TValue, TableDump};

/// Read a `GCstr` object at `addr` and return its text, using `layout` for the
/// `len`-field offset. `None` if the object or its bytes can't be read, or the
/// string isn't valid UTF-8 (LuaJIT strings are byte strings; the tokens we
/// care about are ASCII).
pub fn read_gcstr(src: &dyn MemorySource, addr: Va, layout: LuaLayout) -> Option<String> {
    let len_bytes = src.read(addr.offset(layout.gcstr_len_off), 4).ok()?;
    let len = u32::from_le_bytes(len_bytes.get(..4)?.try_into().ok()?);
    if len == 0 || len > 1 << 16 {
        return None;
    }
    let data = src.read(addr.offset(layout.gcstr_len_off + 4), len as usize).ok()?;
    String::from_utf8(data).ok()
}

/// `GCstr` header layout, offsets from the object's base address. It differs by build,
/// so a frontend asks [`locate_strings`], which decides it from the process's own
/// memory; this is for a caller that already knows.
#[derive(Debug, Clone, Copy)]
pub struct GcstrLayout {
    /// Offset of the `len` field (u32 LE) from the object base.
    pub len_offset: u64,
}

/// What every GC object's base is a multiple of. LuaJIT's allocator hands out 8-byte
/// aligned blocks (`MALLOC_ALIGNMENT` in its `lj_alloc.c`), and a `GCRef` in the header
/// of a 64-bit build needs that anyway. Measured on a real 2.1 build: 20 000 of 20 000
/// strings. So a `len` word whose base would land elsewhere is not a string's: it is a
/// small number that happens to be followed by printable bytes. One such false hit,
/// at an address not even 4-aligned, stood in the target list of a real scan.
const GC_OBJECT_ALIGN: u64 = 8;

/// One `GCstr` found live in a process's heap.
#[derive(Debug, Clone, Serialize)]
pub struct LiveGcStr {
    /// The object's own base address (`len_addr - layout.len_offset`).
    pub object_base: Va,
    /// Address of the `len` field itself.
    pub len_addr: Va,
    /// Address of the first byte of the string's data.
    pub data_addr: Va,
    pub len: u32,
    pub text: String,
}

/// Scan `regions` for live `GCstr` objects whose `len` field falls in
/// `[min_len, max_len]` and whose data decodes as printable ASCII (LuaJIT
/// interns short tokens like combo-direction strings as plain lowercase
/// ASCII — this is deliberately not a general UTF-8/binary-string decoder).
///
/// This is a byte-by-byte candidate scan (every offset is tried as a
/// possible `len` field), the same cost model as [`n0xis_core::AobScanPass`]
/// — expect it to take real time over a full `default_writable_regions()`
/// sweep; narrow with `--start`/`--size` or a tighter `max_len` when possible.
pub fn scan_strings(
    source: &dyn MemorySource,
    regions: &[(Va, usize)],
    layout: GcstrLayout,
    min_len: u32,
    max_len: u32,
) -> Result<Swept<Vec<LiveGcStr>>, SourceError> {
    let mut out = Vec::new();
    let mut read = RegionCoverage::default();
    for &(base, size) in regions {
        let bytes = read.read_region(source, base, size)?;
        if bytes.is_empty() {
            continue;
        }
        if bytes.len() < 4 {
            continue;
        }
        for off in 0..=(bytes.len() - 4) {
            let len = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
            if len < min_len || len > max_len {
                continue;
            }
            let data_start = off + 4;
            let data_end = data_start + len as usize;
            if data_end > bytes.len() {
                continue;
            }
            let candidate = &bytes[data_start..data_end];
            if !is_plausible_ascii(candidate) {
                continue;
            }
            let len_addr_abs = base.0 + off as u64;
            let Some(object_base_abs) = len_addr_abs.checked_sub(layout.len_offset) else { continue };
            if !object_base_abs.is_multiple_of(GC_OBJECT_ALIGN) {
                continue;
            }
            out.push(LiveGcStr {
                object_base: Va(object_base_abs),
                len_addr: Va(len_addr_abs),
                data_addr: base.offset(data_start as u64),
                len,
                // Already validated ASCII, so this is always a lossless decode.
                text: String::from_utf8_lossy(candidate).into_owned(),
            });
        }
    }
    Ok(Swept { answer: out, read })
}

/// Printable, non-empty ASCII — good enough to reject the overwhelming
/// majority of coincidental `len`-shaped 4-byte windows in a target's heap.
fn is_plausible_ascii(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|&b| (0x20..0x7f).contains(&b))
}

/// One contiguous run of `TValue`s in the heap that all point to a
/// `GCstr` in the caller's target set, decoded back to text.
///
/// This is how a Lua *array-of-known-strings* is found **without** needing the
/// `GCtab` header layout ([`LuaLayout`]) calibrated: a Lua array's 1-based part
/// is a flat `TValue[]`, and each element that holds an interned string is just
/// `(LJ_TSTR<<47 | gcstr_addr)`. Matching those against the (few) known string
/// object addresses recovers the sequence directly from its backing store —
/// e.g. a table `{"open","read","read","close"}` reads straight out as
/// `["open","read","read","close"]`. Coincidental single hits are filtered by
/// `min_run`, and false-positive string addresses simply never get referenced.
#[derive(Debug, Clone, Serialize)]
pub struct StringRun {
    /// Address of the first `TValue` in the run (the array element, not the
    /// `GCstr`). For a Lua array this is `array_base + 1*8` (slot 0 unused).
    pub addr: Va,
    /// The decoded sequence, one entry per consecutive matching `TValue`.
    pub values: Vec<String>,
}

/// Scan `regions` for runs of ≥`min_run` consecutive 8-byte-aligned `TValue`s
/// that each reference one of `targets` (a map of `GCstr` object base → its
/// text). Reuses [`decode_tvalue`], so it inherits the GC64 tag encoding and
/// needs no table-layout constants. `targets` may legitimately contain several
/// addresses mapping to the same text (every candidate `GCstr` the string scan
/// turned up for a token) — only the ones actually referenced form runs.
pub fn find_string_runs(
    source: &dyn MemorySource,
    regions: &[(Va, usize)],
    targets: &std::collections::HashMap<Va, String>,
    min_run: usize,
) -> Result<Swept<Vec<StringRun>>, SourceError> {
    let mut out = Vec::new();
    let mut read = RegionCoverage::default();
    for &(base, size) in regions {
        let bytes = read.read_region(source, base, size)?;
        if bytes.is_empty() {
            continue;
        }
        let words = bytes.len() / 8;
        let mut run_start: Option<usize> = None;
        let mut run: Vec<String> = Vec::new();
        for w in 0..words {
            let raw = u64::from_le_bytes(bytes[w * 8..w * 8 + 8].try_into().unwrap());
            // Try both TValue string encodings (GC64 and 32-bit GCRef); the
            // membership check against `targets` disambiguates.
            let hit = string_ref_candidates(raw)
                .into_iter()
                .flatten()
                .find_map(|addr| targets.get(&addr).cloned());
            match hit {
                Some(text) => {
                    if run_start.is_none() {
                        run_start = Some(w);
                    }
                    run.push(text);
                }
                None => {
                    if run.len() >= min_run {
                        out.push(StringRun {
                            addr: base.offset(run_start.unwrap() as u64 * 8),
                            values: std::mem::take(&mut run),
                        });
                    }
                    run.clear();
                    run_start = None;
                }
            }
        }
        if run.len() >= min_run {
            out.push(StringRun { addr: base.offset(run_start.unwrap() as u64 * 8), values: run });
        }
    }
    Ok(Swept { answer: out, read })
}

/// Like [`find_string_runs`], but for a **packed 4-byte `GCRef` array** — the
/// element layout of Bitsquid's own `array` container (and any place a build
/// stores bare 32-bit object pointers back-to-back rather than as full 8-byte
/// `TValue`s). Scans 4-byte-aligned words and matches each directly against the
/// 32-bit `targets` addresses. An 8-byte `TValue` array won't masquerade as one
/// of these: its interleaved `itype` word (`0xFFFFFFFB`) isn't a target, so it
/// can only ever produce length-1 runs, which `min_run >= 2` rejects.
pub fn find_gcref32_runs(
    source: &dyn MemorySource,
    regions: &[(Va, usize)],
    targets: &std::collections::HashMap<Va, String>,
    min_run: usize,
) -> Result<Swept<Vec<StringRun>>, SourceError> {
    let mut out = Vec::new();
    let mut read = RegionCoverage::default();
    for &(base, size) in regions {
        let bytes = read.read_region(source, base, size)?;
        if bytes.is_empty() {
            continue;
        }
        let words = bytes.len() / 4;
        let mut run_start: Option<usize> = None;
        let mut run: Vec<String> = Vec::new();
        for w in 0..words {
            let raw = u32::from_le_bytes(bytes[w * 4..w * 4 + 4].try_into().unwrap());
            match targets.get(&Va(raw as u64)).cloned() {
                Some(text) => {
                    if run_start.is_none() {
                        run_start = Some(w);
                    }
                    run.push(text);
                }
                None => {
                    if run.len() >= min_run {
                        out.push(StringRun {
                            addr: base.offset(run_start.unwrap() as u64 * 4),
                            values: std::mem::take(&mut run),
                        });
                    }
                    run.clear();
                    run_start = None;
                }
            }
        }
        if run.len() >= min_run {
            out.push(StringRun { addr: base.offset(run_start.unwrap() as u64 * 4), values: run });
        }
    }
    Ok(Swept { answer: out, read })
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_sources::Snapshot;

    const WIDE: GcstrLayout = GcstrLayout { len_offset: 0x10 };

    /// Lay out one `GCstr("up")` by hand at a chosen base, surrounded by unrelated filler bytes so the
    /// scan has to actually find it rather than trivially matching offset 0.
    fn build_region(base: Va, needle_off: usize, text: &str) -> Vec<u8> {
        let mut buf = vec![0xABu8; needle_off];
        // len field.
        buf.extend_from_slice(&(text.len() as u32).to_le_bytes());
        buf.extend_from_slice(text.as_bytes());
        buf.extend_from_slice(&[0xCDu8; 32]); // trailing filler
        let _ = base;
        buf
    }

    #[test]
    fn finds_a_known_gcstr_at_the_expected_object_base() {
        let base = Va(0x1000);
        let needle_off = 64usize; // where the `len` field starts
        let bytes = build_region(base, needle_off, "up");
        let snap = Snapshot::builder().region(base, bytes).build();

        let hits = scan_strings(&snap, &[(base, 0x1000)], WIDE, 1, 16).unwrap().answer;

        let hit = hits.iter().find(|h| h.text == "up").expect("must find the planted GCstr");
        assert_eq!(hit.len, 2);
        assert_eq!(hit.len_addr, base.offset(needle_off as u64));
        assert_eq!(hit.object_base, base.offset(needle_off as u64 - WIDE.len_offset));
        assert_eq!(hit.data_addr, base.offset(needle_off as u64 + 4));
    }

    #[test]
    fn rejects_non_ascii_and_out_of_range_lengths() {
        let base = Va(0x2000);
        // A 4-byte window that looks like len=3 but the "data" is non-ASCII.
        let mut bytes = vec![3u8, 0, 0, 0, 0x00, 0x01, 0x02];
        bytes.extend_from_slice(&[0u8; 32]);
        let snap = Snapshot::builder().region(base, bytes).build();
        let hits = scan_strings(&snap, &[(base, 0x1000)], WIDE, 1, 16).unwrap().answer;
        assert!(hits.is_empty());
    }

    #[test]
    fn min_max_len_bounds_are_enforced() {
        let base = Va(0x3000);
        let bytes = build_region(base, 16, "hello");
        let snap = Snapshot::builder().region(base, bytes).build();
        // "hello" is len 5; a max_len of 3 must exclude it.
        let hits = scan_strings(&snap, &[(base, 0x1000)], WIDE, 1, 3).unwrap().answer;
        assert!(hits.iter().all(|h| h.text != "hello"));
    }

    /// A `len` word that would put the object's base anywhere but on 8 bytes is not
    /// a string's, however good its text looks. Shown to be found once it does.
    #[test]
    fn a_base_that_is_not_8_aligned_is_not_a_string() {
        let base = Va(0x4000);
        let layout = WIDE;
        for (needle_off, found) in [(0x40, true), (0x42, false), (0x44, false), (0x48, true)] {
            let snap = Snapshot::builder().region(base, build_region(base, needle_off, "up")).build();
            let hits = scan_strings(&snap, &[(base, 0x1000)], layout, 1, 16).unwrap().answer;
            let at = base.offset(needle_off as u64 - layout.len_offset);
            assert_eq!(hits.iter().any(|h| h.text == "up" && h.object_base == at), found, "len at {needle_off:#x}: {hits:?}");
        }
    }

    /// GC64-tag a string pointer the way the VM stores it in an array `TValue`.
    fn tvstr(addr: u64) -> u64 {
        (0x1FFFBu64 << 47) | (addr & 0x0000_7FFF_FFFF_FFFF)
    }

    /// A combo array `{"up","down","down","up"}` laid out as a run of tagged
    /// `TValue`s (with an unrelated word before and after) must decode back to
    /// exactly that direction sequence — the layout-independent combo read.
    #[test]
    fn finds_a_combo_string_run_and_decodes_the_directions() {
        use std::collections::HashMap;
        let up = Va(0xA000);
        let down = Va(0xB000);
        let base = Va(0x5000);
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xDEAD_BEEFu64.to_le_bytes()); // noise / slot-0-ish
        for &a in &[up.0, down.0, down.0, up.0] {
            buf.extend_from_slice(&tvstr(a).to_le_bytes());
        }
        buf.extend_from_slice(&123.0f64.to_bits().to_le_bytes()); // a number, breaks the run
        let snap = Snapshot::builder().region(base, buf).build();

        let mut targets = HashMap::new();
        targets.insert(up, "up".to_string());
        targets.insert(down, "down".to_string());

        let runs = find_string_runs(&snap, &[(base, 0x1000)], &targets, 2).unwrap().answer;
        let combo = runs.iter().find(|r| r.values.len() == 4).expect("combo run found");
        assert_eq!(combo.values, vec!["up", "down", "down", "up"]);
        // The run starts at the second word (slot 0 was noise).
        assert_eq!(combo.addr, base.offset(8));
    }

    /// A combo stored as a packed 4-byte `GCRef` array `[up,down,down,up]` must
    /// be recovered by `find_gcref32_runs`, and an 8-byte `TValue` array of the
    /// same must NOT masquerade as a 4-byte run (its itype word breaks it).
    #[test]
    fn finds_a_packed_gcref32_combo_run() {
        use std::collections::HashMap;
        let up = Va(0x3076d914);
        let down = Va(0x3076d6d4);
        let base = Va(0x7000);
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // leading noise
        for &a in &[up.0, down.0, down.0, up.0] {
            buf.extend_from_slice(&(a as u32).to_le_bytes());
        }
        buf.extend_from_slice(&0u32.to_le_bytes());
        let snap = Snapshot::builder().region(base, buf).build();
        let mut targets = HashMap::new();
        targets.insert(up, "up".to_string());
        targets.insert(down, "down".to_string());

        let runs = find_gcref32_runs(&snap, &[(base, 0x1000)], &targets, 2).unwrap().answer;
        let combo = runs.iter().find(|r| r.values.len() == 4).expect("gcref32 combo found");
        assert_eq!(combo.values, vec!["up", "down", "down", "up"]);
        assert_eq!(combo.addr, base.offset(4));

        // The same addresses as 8-byte TValues must NOT yield a 4-byte run of
        // length >= 2 (the 0xFFFFFFFB itype words sit between the pointers).
        let mut tvbuf = Vec::new();
        for &a in &[up.0, down.0] {
            tvbuf.extend_from_slice(&tvstr(a).to_le_bytes());
        }
        let snap2 = Snapshot::builder().region(base, tvbuf).build();
        assert!(find_gcref32_runs(&snap2, &[(base, 0x1000)], &targets, 2).unwrap().answer.is_empty());
    }

    /// A lone matching `TValue` (run length 1) must be rejected by `min_run` so
    /// coincidental string pointers don't masquerade as combos.
    #[test]
    fn min_run_rejects_isolated_matches() {
        use std::collections::HashMap;
        let up = Va(0xA000);
        let base = Va(0x6000);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1.0f64.to_bits().to_le_bytes());
        buf.extend_from_slice(&tvstr(up.0).to_le_bytes()); // single hit
        buf.extend_from_slice(&2.0f64.to_bits().to_le_bytes());
        let snap = Snapshot::builder().region(base, buf).build();
        let mut targets = HashMap::new();
        targets.insert(up, "up".to_string());
        let runs = find_string_runs(&snap, &[(base, 0x1000)], &targets, 2).unwrap().answer;
        assert!(runs.is_empty());
    }
}
