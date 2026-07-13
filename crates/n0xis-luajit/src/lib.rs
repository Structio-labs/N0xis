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
//! encoding is still unconfirmed (see the project's `cheats_research.md`),
//! and this crate should not guess at a layout it hasn't verified.
//!
//! Source-agnostic like the rest of n0xis: works over any
//! [`MemorySource`], so it is unit-tested against `Snapshot` with zero OS
//! APIs linked, and runs unchanged over a live process or a static dump.

use n0xis_contracts::Va;
use n0xis_sources::MemorySource;
use serde::Serialize;

/// `GCstr` header layout, offsets from the object's base address.
///
/// Empirically confirmed against a live 64-bit Helldivers 1 process
/// (`n0xis-hud`'s combo-cheat investigation, see `cheats_research.md`): the
/// `len` field sits 0x10 bytes after the object base, with the string's raw
/// bytes immediately following it. This matches a GC64-mode LuaJIT build
/// (an 8-byte compressed `GCRef` in the header, vs. 4 bytes in the classic
/// 32-bit layout) but was *not* independently cross-checked against LuaJIT's
/// own `lj_obj.h` this session — treat it as a validated constant for this
/// game/build, not a general LuaJIT-version law. A different build may need
/// a different `GcstrLayout`.
#[derive(Debug, Clone, Copy)]
pub struct GcstrLayout {
    /// Offset of the `len` field (u32 LE) from the object base.
    pub len_offset: u64,
}

impl GcstrLayout {
    /// The layout confirmed against Helldivers 1 (GC64-mode LuaJIT).
    pub const HELLDIVERS_GC64: GcstrLayout = GcstrLayout { len_offset: 0x10 };
}

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
) -> Vec<LiveGcStr> {
    let mut out = Vec::new();
    for &(base, size) in regions {
        let Ok(bytes) = source.read(base, size) else { continue };
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
    out
}

/// Printable, non-empty ASCII — good enough to reject the overwhelming
/// majority of coincidental `len`-shaped 4-byte windows in a game's heap.
fn is_plausible_ascii(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|&b| (0x20..0x7f).contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_sources::Snapshot;

    /// Lay out one `GCstr("up")` by hand at a chosen base, using the
    /// Helldivers GC64 layout, surrounded by unrelated filler bytes so the
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

        let hits = scan_strings(&snap, &[(base, 0x1000)], GcstrLayout::HELLDIVERS_GC64, 1, 16);

        let hit = hits.iter().find(|h| h.text == "up").expect("must find the planted GCstr");
        assert_eq!(hit.len, 2);
        assert_eq!(hit.len_addr, base.offset(needle_off as u64));
        assert_eq!(hit.object_base, base.offset(needle_off as u64 - GcstrLayout::HELLDIVERS_GC64.len_offset));
        assert_eq!(hit.data_addr, base.offset(needle_off as u64 + 4));
    }

    #[test]
    fn rejects_non_ascii_and_out_of_range_lengths() {
        let base = Va(0x2000);
        // A 4-byte window that looks like len=3 but the "data" is non-ASCII.
        let mut bytes = vec![3u8, 0, 0, 0, 0x00, 0x01, 0x02];
        bytes.extend_from_slice(&[0u8; 32]);
        let snap = Snapshot::builder().region(base, bytes).build();
        let hits = scan_strings(&snap, &[(base, 0x1000)], GcstrLayout::HELLDIVERS_GC64, 1, 16);
        assert!(hits.is_empty());
    }

    #[test]
    fn min_max_len_bounds_are_enforced() {
        let base = Va(0x3000);
        let bytes = build_region(base, 16, "hello");
        let snap = Snapshot::builder().region(base, bytes).build();
        // "hello" is len 5; a max_len of 3 must exclude it.
        let hits = scan_strings(&snap, &[(base, 0x1000)], GcstrLayout::HELLDIVERS_GC64, 1, 3);
        assert!(hits.iter().all(|h| h.text != "hello"));
    }
}
