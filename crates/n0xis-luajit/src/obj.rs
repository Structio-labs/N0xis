//! LuaJIT object model — `TValue` decoding and `GCtab` (Lua table) traversal,
//! parameterized by a [`LuaLayout`] so the same logic serves different builds.
//!
//! **Why parameterized, not hardcoded.** Helldivers ships a *patched* LuaJIT
//! 2.0.3 (the `helldivers.exe` strings confirm the version) whose `GCstr`
//! header empirically has `len` at offset `0x10` / data at `0x14` — 4 bytes
//! past where a stock 32-bit-`GCRef` 2.0 build would put them (`0xC`/`0x10`).
//! That +4 is the signature of an **8-byte `GCRef`**: `nextgc(8) + marked(1) +
//! gct(1) + reserved(1) + unused(1) = 0xC`, then `hash(4)@0xC`, `len(4)@0x10`,
//! data`@0x14`. Bitsquid/Stingray is known to patch LuaJIT internals, so we do
//! not assume the stock layout; every magic offset lives in [`LuaLayout`] and
//! is meant to be *calibrated* (see [`LuaLayout::HELLDIVERS`], and the
//! calibration notes below) rather than trusted blindly.
//!
//! The `TValue` decoding here assumes a **GC64-style 8-byte tagged value**
//! (47-bit pointer + itype in the high bits) — the natural fit for a build
//! whose `GCRef` widened to 8 bytes while keeping a NaN-boxed 8-byte `TValue`.
//! This is the current best hypothesis for this build and is flagged as
//! needing live confirmation; the *decoding logic* is unit-tested against
//! synthetic data regardless, so only the constants (not the code) are at risk.

use n0xis_contracts::Va;
use n0xis_sources::MemorySource;
use serde::Serialize;

/// Every build-specific magic number the object model needs, in one place so a
/// different LuaJIT build (or a corrected calibration) is a data change, not a
/// code change.
#[derive(Debug, Clone, Copy)]
pub struct LuaLayout {
    /// Width of a `GCRef`/`MRef` pointer field inside a GC object. 8 for this
    /// build (see module docs); 4 for a stock 32-bit-`GCRef` 2.0 build.
    pub ref_size: u64,
    /// Offset of `GCstr.len` (u32) from the string object's base.
    pub gcstr_len_off: u64,
    /// Offset of `GCtab.array` (`MRef` → `TValue[]`, the 1-based array part).
    pub gctab_array_off: u64,
    /// Offset of `GCtab.node` (`MRef` → `Node[]`, the hash part).
    pub gctab_node_off: u64,
    /// Offset of `GCtab.asize` (u32): number of slots in the array part.
    pub gctab_asize_off: u64,
    /// Offset of `GCtab.hmask` (u32): `hash size - 1` (so `hmask+1` `Node`s).
    pub gctab_hmask_off: u64,
    /// Size of one hash `Node`. In LuaJIT 2.0 a `Node` is `{ TValue val;
    /// TValue key; MRef next; }`.
    pub node_size: u64,
    /// Offset of the value `TValue` within a `Node`.
    pub node_val_off: u64,
    /// Offset of the key `TValue` within a `Node`.
    pub node_key_off: u64,
}

impl LuaLayout {
    /// Best-hypothesis layout for Helldivers 1's patched LuaJIT 2.0.3 (8-byte
    /// `GCRef`, GC64-style 8-byte `TValue`). The `GCstr` offset is empirically
    /// confirmed; the `GCtab`/`Node` offsets are derived from the standard 2.0
    /// field order scaled to an 8-byte ref and **need live calibration** before
    /// being trusted (a `Node` here is `val(8) key(8) next(8)` = 24 bytes).
    pub const HELLDIVERS: LuaLayout = LuaLayout {
        ref_size: 8,
        gcstr_len_off: 0x10,
        // GCHeader(nextgc 8, marked 1, gct 1) + nomm 1 + colo 1 = 0xC, then
        // `array` MRef. These four are the standard 2.0 field order.
        gctab_array_off: 0x10,
        gctab_node_off: 0x28,
        gctab_asize_off: 0x30,
        gctab_hmask_off: 0x34,
        node_size: 24,
        node_val_off: 0,
        node_key_off: 8,
    };
}

/// A decoded LuaJIT tagged value. Only the cases we need to *navigate* the
/// object graph are distinguished; everything else is surfaced as [`Other`]
/// with its raw itype so nothing is silently misread as a known type.
///
/// [`Other`]: TValue::Other
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TValue {
    Nil,
    Bool(bool),
    Num(f64),
    /// A GC string; `addr` is the `GCstr` object base (feed to
    /// [`crate::read_gcstr`]).
    Str { addr: Va },
    /// A Lua table; `addr` is the `GCtab` object base.
    Tab { addr: Va },
    Func { addr: Va },
    /// Any other tag (thread, proto, cdata, userdata, lightuserdata, …) or an
    /// unrecognized itype — carries the raw itype and low pointer bits so a
    /// caller can still inspect/branch without this enum pretending to know it.
    Other { itype: u32, ptr: u64 },
}

// GC64-style itype tags: `itype = (u32)(raw >> 47)`, a value in `0x1FFF0..`
// for tagged (non-number) values. These mirror LuaJIT's `LJ_T*` order; they
// are the standard GC64 encoding and a prime calibration target if a live
// dump shows tables/strings decoding as `Other`.
const ITYPE_SHIFT: u32 = 47;
const LJ_TNIL: u32 = 0x1FFFF; // ~0 & mask
const LJ_TFALSE: u32 = 0x1FFFE;
const LJ_TTRUE: u32 = 0x1FFFD;
const LJ_TLIGHTUD: u32 = 0x1FFFC;
const LJ_TSTR: u32 = 0x1FFFB;
const LJ_TUPVAL: u32 = 0x1FFFA;
const LJ_TTHREAD: u32 = 0x1FFF9;
const LJ_TPROTO: u32 = 0x1FFF8;
const LJ_TFUNC: u32 = 0x1FFF7;
const LJ_TTRACE: u32 = 0x1FFF6;
const LJ_TCDATA: u32 = 0x1FFF5;
const LJ_TTAB: u32 = 0x1FFF4;
const LJ_TUDATA: u32 = 0x1FFF3;
/// 47-bit pointer mask for a GC64 tagged value.
const PTR47_MASK: u64 = 0x0000_7FFF_FFFF_FFFF;

/// Decode one 8-byte GC64-style `TValue` from its raw little-endian bits.
pub fn decode_tvalue(raw: u64) -> TValue {
    let itype = (raw >> ITYPE_SHIFT) as u32;
    // A real IEEE double has its top 13 bits below the NaN-boxed tag range, so
    // anything that isn't one of the tags is a number.
    if itype < LJ_TUDATA {
        return TValue::Num(f64::from_bits(raw));
    }
    let ptr = raw & PTR47_MASK;
    match itype {
        LJ_TNIL => TValue::Nil,
        LJ_TFALSE => TValue::Bool(false),
        LJ_TTRUE => TValue::Bool(true),
        LJ_TSTR => TValue::Str { addr: Va(ptr) },
        LJ_TTAB => TValue::Tab { addr: Va(ptr) },
        LJ_TFUNC => TValue::Func { addr: Va(ptr) },
        LJ_TLIGHTUD | LJ_TUPVAL | LJ_TTHREAD | LJ_TPROTO | LJ_TTRACE | LJ_TCDATA | LJ_TUDATA => {
            TValue::Other { itype, ptr }
        }
        _ => TValue::Other { itype, ptr },
    }
}

/// The decoded contents of a `GCtab`: its 1-based array part and its hash part.
#[derive(Debug, Clone, Serialize)]
pub struct TableDump {
    pub addr: Va,
    pub asize: u32,
    pub hmask: u32,
    /// Array part values, index 0..asize (Lua index `i` is `array[i]`; slot 0
    /// is conventionally unused but read for completeness).
    pub array: Vec<TValue>,
    /// Hash part: `(key, value)` for every non-nil node.
    pub hash: Vec<(TValue, TValue)>,
}

/// A hard cap so a corrupt `asize`/`hmask` (e.g. reading a non-table address)
/// can't try to allocate/iterate billions of entries.
const MAX_TABLE_SLOTS: u64 = 1 << 20;

fn read_u32(src: &dyn MemorySource, at: Va) -> Option<u32> {
    let b = src.read(at, 4).ok()?;
    Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
}

fn read_ptr(src: &dyn MemorySource, at: Va, ref_size: u64) -> Option<u64> {
    let b = src.read(at, ref_size as usize).ok()?;
    Some(if ref_size >= 8 {
        u64::from_le_bytes(b.get(..8)?.try_into().ok()?)
    } else {
        u32::from_le_bytes(b.get(..4)?.try_into().ok()?) as u64
    })
}

fn read_tvalue(src: &dyn MemorySource, at: Va) -> Option<TValue> {
    let b = src.read(at, 8).ok()?;
    Some(decode_tvalue(u64::from_le_bytes(b.get(..8)?.try_into().ok()?)))
}

/// Read and decode a `GCtab` at `addr` — its array part and hash part — using
/// `layout`. Returns `None` if any field read fails or the sizes exceed
/// [`MAX_TABLE_SLOTS`] (the guard against pointing this at a non-table).
pub fn read_table(src: &dyn MemorySource, addr: Va, layout: LuaLayout) -> Option<TableDump> {
    let asize = read_u32(src, addr.offset(layout.gctab_asize_off))?;
    let hmask = read_u32(src, addr.offset(layout.gctab_hmask_off))?;
    if asize as u64 > MAX_TABLE_SLOTS || hmask as u64 >= MAX_TABLE_SLOTS {
        return None;
    }
    let array_ref = read_ptr(src, addr.offset(layout.gctab_array_off), layout.ref_size)?;
    let node_ref = read_ptr(src, addr.offset(layout.gctab_node_off), layout.ref_size)?;

    let mut array = Vec::new();
    if array_ref != 0 {
        for i in 0..asize as u64 {
            match read_tvalue(src, Va(array_ref).offset(i * 8)) {
                Some(v) => array.push(v),
                None => break,
            }
        }
    }

    let mut hash = Vec::new();
    if node_ref != 0 {
        let nodes = hmask as u64 + 1;
        for i in 0..nodes {
            let node = Va(node_ref).offset(i * layout.node_size);
            let Some(key) = read_tvalue(src, node.offset(layout.node_key_off)) else { break };
            if key == TValue::Nil {
                continue;
            }
            let Some(val) = read_tvalue(src, node.offset(layout.node_val_off)) else { break };
            hash.push((key, val));
        }
    }

    Some(TableDump { addr, asize, hmask, array, hash })
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_sources::Snapshot;

    fn tagged(itype: u32, ptr: u64) -> u64 {
        ((itype as u64) << ITYPE_SHIFT) | (ptr & PTR47_MASK)
    }

    #[test]
    fn decodes_the_navigable_tvalue_kinds() {
        assert_eq!(decode_tvalue(tagged(LJ_TNIL, 0)), TValue::Nil);
        assert_eq!(decode_tvalue(tagged(LJ_TTRUE, 0)), TValue::Bool(true));
        assert_eq!(decode_tvalue(tagged(LJ_TFALSE, 0)), TValue::Bool(false));
        assert_eq!(decode_tvalue(tagged(LJ_TSTR, 0x813d914)), TValue::Str { addr: Va(0x813d914) });
        assert_eq!(decode_tvalue(tagged(LJ_TTAB, 0x8140000)), TValue::Tab { addr: Va(0x8140000) });
        // A plain double must not be mistaken for a tagged value.
        match decode_tvalue(3.5f64.to_bits()) {
            TValue::Num(n) => assert_eq!(n, 3.5),
            other => panic!("expected Num, got {other:?}"),
        }
    }

    /// Build a minimal `GCtab` (HELLDIVERS layout) with a 3-element array part
    /// holding string TValues, plus one hash entry, and confirm `read_table`
    /// recovers exactly that.
    #[test]
    fn reads_array_and_hash_parts_of_a_hand_built_table() {
        let layout = LuaLayout::HELLDIVERS;
        let tab = Va(0x1000);
        let array_base = Va(0x2000);
        let node_base = Va(0x3000);

        // The table object: fill the four fields we read.
        let mut tabbytes = vec![0u8; 0x40];
        tabbytes[layout.gctab_array_off as usize..][..8].copy_from_slice(&array_base.0.to_le_bytes());
        tabbytes[layout.gctab_node_off as usize..][..8].copy_from_slice(&node_base.0.to_le_bytes());
        tabbytes[layout.gctab_asize_off as usize..][..4].copy_from_slice(&3u32.to_le_bytes());
        tabbytes[layout.gctab_hmask_off as usize..][..4].copy_from_slice(&0u32.to_le_bytes()); // 1 node

        // Array part: [nil-slot0, str@0xAAA, str@0xBBB] as GC64 TValues.
        let mut arr = Vec::new();
        arr.extend_from_slice(&tagged(LJ_TNIL, 0).to_le_bytes());
        arr.extend_from_slice(&tagged(LJ_TSTR, 0xAAA).to_le_bytes());
        arr.extend_from_slice(&tagged(LJ_TSTR, 0xBBB).to_le_bytes());

        // One hash node: key = str@0xCCC, val = num 42.0.
        let mut node = vec![0u8; layout.node_size as usize];
        node[layout.node_val_off as usize..][..8].copy_from_slice(&42.0f64.to_bits().to_le_bytes());
        node[layout.node_key_off as usize..][..8].copy_from_slice(&tagged(LJ_TSTR, 0xCCC).to_le_bytes());

        let snap = Snapshot::builder()
            .region(tab, tabbytes)
            .region(array_base, arr)
            .region(node_base, node)
            .build();

        let dump = read_table(&snap, tab, layout).expect("table decodes");
        assert_eq!(dump.asize, 3);
        assert_eq!(dump.array.len(), 3);
        assert_eq!(dump.array[0], TValue::Nil);
        assert_eq!(dump.array[1], TValue::Str { addr: Va(0xAAA) });
        assert_eq!(dump.array[2], TValue::Str { addr: Va(0xBBB) });
        assert_eq!(dump.hash.len(), 1);
        assert_eq!(dump.hash[0].0, TValue::Str { addr: Va(0xCCC) });
        assert_eq!(dump.hash[0].1, TValue::Num(42.0));
    }

    #[test]
    fn rejects_absurd_sizes_instead_of_over_allocating() {
        let layout = LuaLayout::HELLDIVERS;
        let tab = Va(0x1000);
        let mut tabbytes = vec![0u8; 0x40];
        // A wild asize (as if pointed at a non-table): must be rejected.
        tabbytes[layout.gctab_asize_off as usize..][..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let snap = Snapshot::builder().region(tab, tabbytes).build();
        assert!(read_table(&snap, tab, layout).is_none());
    }
}
