//! MSVC RTTI / vtable class recovery — Rung 7's devirtualization down-payment.
//!
//! A C++ virtual call dispatches through a vtable slot, an edge the CFG can only
//! mark "indirect". But an MSVC binary built with RTTI (`/GR`, the default)
//! carries, right before each vtable, a pointer to a
//! `RTTICompleteObjectLocator` (COL); the COL points (by image-relative RVA) at
//! a `TypeDescriptor` whose tail is the class's decorated name (`.?AVFoo@@`).
//! Walking that chain turns an anonymous vtable address into a concrete class
//! name — the fact that makes a `(*vtable[k])()` call readable and a struct's
//! first field typeable.
//!
//! This is inherently a PE/MSVC concept: the caller supplies the image base
//! (to resolve the RVAs) and the `.rdata` range (where COLs and vtables live).
//! The scan is validated by the COL's **self-reference** — its `pSelf` RVA must
//! resolve back to the COL's own address — which is a far stronger filter than
//! the signature word alone and keeps false positives out.

use n0xis_contracts::Va;
use serde::{Deserialize, Serialize};

use crate::MemorySource;

/// One recovered vtable and the class it belongs to.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RttiVtable {
    /// Address of the vtable's first method slot.
    pub vtable: Va,
    /// Address of the `TypeDescriptor` the COL points at.
    pub type_descriptor: Va,
    /// The decorated name as stored (`.?AVFoo@@`).
    pub mangled: String,
    /// The readable class name (`Foo`, `Ns::Bar`); equals `mangled` when the
    /// name uses template/special mangling this does not safely reverse.
    pub name: String,
    /// The COL's `offset` field — this base's offset within the complete
    /// object, non-zero for a secondary base under multiple inheritance.
    pub offset: u32,
    /// The class's **base classes**, recovered from the RTTI class-hierarchy
    /// descriptor's base-class array (readable names, most-derived base first,
    /// self excluded). Empty for a class with no bases, or when the hierarchy
    /// descriptor is absent/out of `.rdata`. This is the inheritance graph the
    /// binary already carries — `class Derived : Base` reconstructed statically.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bases: Vec<String>,
}

/// Turn an MSVC RTTI decorated type name into a readable one.
///
/// `.?AVFoo@@` → `Foo`, `.?AUData@Ns@@` → `Ns::Data` (the `@`-separated
/// qualifiers are innermost-first, so they reverse into `outer::inner`). A name
/// carrying template or other special mangling (`?$`, a bare `?`) is returned
/// **verbatim** rather than mis-decoded — sound over pretty.
pub fn demangle_rtti_name(mangled: &str) -> String {
    // Prefer the real MSVC demangler — it reads the templated names
    // (`.?AV?$vector@H@std@@` → `std::vector<int>`) the hand-rolled `@`-splitter
    // below deliberately refuses. The splitter stays as a fallback for a name
    // the demangler declines, and verbatim is the final, always-sound floor.
    if let Some(full) = crate::demangle::demangle_rtti_type_descriptor(mangled) {
        return full;
    }
    let Some(rest) = mangled.strip_prefix(".?A") else {
        return mangled.to_string();
    };
    // The kind letter: V class, U struct, W enum, T union, …
    let mut chars = rest.chars();
    let _kind = chars.next();
    let body_full = chars.as_str();
    let body = body_full.strip_suffix("@@").unwrap_or(body_full);
    if body.contains('?') || body.contains('$') {
        return mangled.to_string();
    }
    let parts: Vec<&str> = body.split('@').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return mangled.to_string();
    }
    parts.into_iter().rev().collect::<Vec<_>>().join("::")
}

const COL_SIZE: usize = 24; // sig,u32 | offset,u32 | cdOffset,u32 | pTD,rva | pClass,rva | pSelf,rva
const COL_PCLASS: usize = 16; // RVA of the RTTIClassHierarchyDescriptor
// RTTIClassHierarchyDescriptor: signature,u32 | attributes,u32 | numBaseClasses,u32 | pBaseClassArray,rva
const CHD_NUM_BASES: usize = 8;
const CHD_BASE_ARRAY: usize = 12;
/// Base-class count ceiling — bounds the walk so a mis-read descriptor can
/// never drive an unbounded loop/allocation (the OOM lesson, again).
const MAX_BASES: usize = 256;
const MAX_NAME: usize = 512;
/// A hard ceiling so a mis-identified `.rdata` size can never drive an
/// unbounded allocation (the machine's OOM lesson, applied to a parsed length).
const MAX_RDATA: usize = 64 * 1024 * 1024;

fn u32_le(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64_le(b: &[u8], at: usize) -> Option<u64> {
    b.get(at..at + 8).map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// Scan `.rdata` for MSVC RTTI vtables. `image_base` resolves the COL's
/// image-relative RVAs; `text` (when known) gates a candidate on its first
/// vtable slot actually pointing into code, cutting stray matches.
pub fn scan_msvc_rtti(src: &dyn MemorySource, image_base: Va, rdata: (Va, u64), text: Option<(Va, u64)>) -> Vec<RttiVtable> {
    let (rd_base, rd_len) = (rdata.0.get(), (rdata.1 as usize).min(MAX_RDATA));
    let Ok(buf) = src.read(Va(rd_base), rd_len) else {
        return Vec::new();
    };
    let in_rdata = |va: u64| va >= rd_base && va < rd_base + buf.len() as u64;
    let in_text = |va: u64| text.is_none_or(|(t, n)| va >= t.get() && va < t.get() + n);

    let mut out = Vec::new();
    // Every aligned slot is a candidate "pointer to a COL". A vtable is the slot
    // *after* such a pointer.
    let mut off = 0usize;
    while off + 8 <= buf.len() {
        let Some(col_ptr) = u64_le(&buf, off) else { break };
        if in_rdata(col_ptr) {
            let col_off = (col_ptr - rd_base) as usize;
            if let (Some(offset), Some(p_td), Some(p_self)) =
                (u32_le(&buf, col_off + 4), u32_le(&buf, col_off + 12), u32_le(&buf, col_off + 20))
                && col_off + COL_SIZE <= buf.len()
                // The COL self-reference: pSelf's RVA must resolve to the COL.
                && image_base.get().wrapping_add(p_self as u64) == col_ptr
            {
                let vtable = rd_base + off as u64 + 8;
                let first_slot = u64_le(&buf, off + 8);
                if first_slot.is_some_and(in_text) {
                    let td_name_va = image_base.get().wrapping_add(p_td as u64) + 16;
                    if let Some(mangled) = read_cstr(src, Va(td_name_va))
                        && mangled.starts_with(".?A")
                    {
                        let name = demangle_rtti_name(&mangled);
                        let pclass = u32_le(&buf, col_off + COL_PCLASS).unwrap_or(0);
                        let bases = read_base_classes(&buf, rd_base, image_base.get(), src, pclass);
                        out.push(RttiVtable { vtable: Va(vtable), type_descriptor: Va(td_name_va - 16), mangled, name, offset, bases });
                    }
                }
            }
        }
        off += 8;
    }
    out
}

/// Ceiling on vtable slots walked per class — a mis-read vtable can never drive
/// an unbounded loop (the OOM lesson), and a real class rarely exceeds it.
const MAX_SLOTS: usize = 4096;

/// Turn recovered [`RttiVtable`]s into address→name maps for the symbol layer:
///
/// - **data**: each vtable address → `Class::vftable` (a secondary base under
///   multiple inheritance gets `Class::vftable_offN`). This is **sound** — that
///   address *is* that class's vtable — so it names every vtable constant the
///   decompiler prints and every vtable address the listing/xref shows.
/// - **functions**: each in-`.text` method slot → `Class::vfN`. A method inherited
///   by several classes points to one function from many vtables; the first class
///   to reach it keeps the name (iteration is `.rdata` order). This is a
///   decompiler **aid, not ground truth** — a user rename overrides it — so it is
///   deliberately first-writer-wins rather than guessing the defining class.
///
/// The walk of a vtable stops at the first slot that does not point into `.text`
/// (past the last virtual method) or that coincides with another known vtable's
/// start (the adjacent class), so one class never claims another's slots.
pub fn rtti_symbol_map(
    src: &dyn MemorySource,
    vtables: &[RttiVtable],
    text: Option<(Va, u64)>,
) -> (std::collections::BTreeMap<u64, String>, std::collections::BTreeMap<u64, String>) {
    use std::collections::{BTreeMap, BTreeSet};
    let in_text = |va: u64| text.is_none_or(|(t, n)| va >= t.get() && va < t.get() + n);
    let starts: BTreeSet<u64> = vtables.iter().map(|v| v.vtable.get()).collect();

    let mut functions: BTreeMap<u64, String> = BTreeMap::new();
    let mut data: BTreeMap<u64, String> = BTreeMap::new();
    for v in vtables {
        let vtable = v.vtable.get();
        let label = if v.offset != 0 {
            format!("{}::vftable_off{}", v.name, v.offset)
        } else {
            format!("{}::vftable", v.name)
        };
        data.entry(vtable).or_insert(label);

        let mut i = 0usize;
        while i < MAX_SLOTS {
            let slot_addr = vtable + (i as u64) * 8;
            // Don't run into the next class's vtable.
            if i > 0 && starts.contains(&slot_addr) {
                break;
            }
            let Ok(bytes) = src.read(Va(slot_addr), 8) else { break };
            let Some(target) = u64_le(&bytes, 0) else { break };
            if !in_text(target) {
                break; // past the last virtual method
            }
            functions.entry(target).or_insert_with(|| format!("{}::vf{}", v.name, i));
            i += 1;
        }
    }
    (functions, data)
}

/// Walk an MSVC RTTI class-hierarchy descriptor to the class's base-class
/// names. `pclass_rva` is the COL's `pClassDescriptor` RVA; the descriptor's
/// base-class array holds, most-derived first, an entry per class in the
/// hierarchy — index 0 is the class itself, so 1.. are its bases. Every
/// structure here lives in `.rdata`, so reads index the already-loaded buffer;
/// anything out of range is skipped (sound — a missing base is dropped, never
/// guessed). Bounded by [`MAX_BASES`].
fn read_base_classes(buf: &[u8], rd_base: u64, image_base: u64, src: &dyn MemorySource, pclass_rva: u32) -> Vec<String> {
    let mut bases = Vec::new();
    if pclass_rva == 0 {
        return bases;
    }
    // The `.rdata` buffer offset of an image RVA, if it lands inside `.rdata`.
    let at = |rva: u32| -> Option<usize> {
        let va = image_base.wrapping_add(rva as u64);
        (va >= rd_base && va < rd_base + buf.len() as u64).then_some((va - rd_base) as usize)
    };
    let Some(chd) = at(pclass_rva) else { return bases };
    let (Some(num), Some(bca_rva)) = (u32_le(buf, chd + CHD_NUM_BASES), u32_le(buf, chd + CHD_BASE_ARRAY)) else {
        return bases;
    };
    let Some(bca) = at(bca_rva) else { return bases };
    let num = (num as usize).min(MAX_BASES);
    // Skip index 0 (the class itself); collect the remaining bases in order.
    for i in 1..num {
        let Some(bcd_rva) = u32_le(buf, bca + i * 4) else { break };
        let Some(bcd) = at(bcd_rva) else { continue };
        // BaseClassDescriptor's first field is its TypeDescriptor RVA; the
        // decorated name sits 16 bytes into the TypeDescriptor (past its two
        // leading pointer slots), exactly as for the primary type above.
        let Some(td_rva) = u32_le(buf, bcd) else { continue };
        let td_name_va = image_base.wrapping_add(td_rva as u64) + 16;
        if let Some(m) = read_cstr(src, Va(td_name_va))
            && m.starts_with(".?A")
        {
            bases.push(demangle_rtti_name(&m));
        }
    }
    bases
}

/// Read a NUL-terminated ASCII string (bounded), the shape a `TypeDescriptor`
/// name has.
fn read_cstr(src: &dyn MemorySource, at: Va) -> Option<String> {
    let bytes = src.read(at, MAX_NAME).ok()?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    (end > 0).then(|| String::from_utf8_lossy(&bytes[..end]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangles_a_plain_and_a_namespaced_class() {
        assert_eq!(demangle_rtti_name(".?AVFoo@@"), "Foo");
        assert_eq!(demangle_rtti_name(".?AUData@Ns@@"), "Ns::Data");
        // real Havok name from the corpus
        assert_eq!(
            demangle_rtti_name(".?AUAccelerationData@hkaiGeometrySegmentCaster@@"),
            "hkaiGeometrySegmentCaster::AccelerationData",
        );
    }

    #[test]
    fn a_template_name_is_fully_demangled_via_the_msvc_demangler() {
        // `?$` is a template; the hand-rolled `@`-splitter refuses it, but the
        // real MSVC demangler (wrapping it as an `??_R0…@8` type descriptor)
        // reads it — a readable class name, never mis-decoded nonsense.
        assert_eq!(demangle_rtti_name(".?AV?$vector@H@std@@"), "std::vector<int>");
        // A real Havok template name from the corpus demangles rather than
        // falling through to verbatim.
        assert_eq!(
            demangle_rtti_name(".?AV?$basic_ios@EU?$char_traits@E@std@@@std@@"),
            "std::basic_ios<unsigned char, struct std::char_traits<unsigned char> >",
        );
    }

    #[test]
    fn a_non_rtti_string_passes_through() {
        assert_eq!(demangle_rtti_name("not a name"), "not a name");
    }

    #[test]
    fn scans_a_synthetic_vtable_and_recovers_its_base_classes() {
        use n0xis_sources::Snapshot;
        let image_base = 0x140000000u64;
        let rd_base = 0x140010000u64;
        let mut buf = vec![0u8; 0x800];
        let put_u32 = |b: &mut [u8], off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());
        let put_u64 = |b: &mut [u8], off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());
        let put_str = |b: &mut [u8], off: usize, s: &str| b[off..off + s.len()].copy_from_slice(s.as_bytes());
        let rva = |off: usize| ((rd_base + off as u64) - image_base) as u32;
        // TypeDescriptors: name sits 16 bytes in (past two pointer slots).
        put_str(&mut buf, 0x110, ".?AVDerived@@\0");
        put_str(&mut buf, 0x150, ".?AVBase1@@\0");
        put_str(&mut buf, 0x190, ".?AVBase2@@\0");
        // BaseClassDescriptors: first field is the TypeDescriptor RVA. Index 0 is
        // the class itself, 1 and 2 its bases.
        put_u32(&mut buf, 0x1e0, rva(0x100)); // BCD0 -> self TD
        put_u32(&mut buf, 0x200, rva(0x140)); // BCD1 -> Base1 TD
        put_u32(&mut buf, 0x220, rva(0x180)); // BCD2 -> Base2 TD
        // Base-class array: three BCD RVAs.
        put_u32(&mut buf, 0x260, rva(0x1e0));
        put_u32(&mut buf, 0x264, rva(0x200));
        put_u32(&mut buf, 0x268, rva(0x220));
        // ClassHierarchyDescriptor: numBaseClasses=3, pBaseClassArray.
        put_u32(&mut buf, 0x288, 3);
        put_u32(&mut buf, 0x28c, rva(0x260));
        // CompleteObjectLocator: pTD, pClassDescriptor, and the self-reference.
        put_u32(&mut buf, 0x2a0 + 12, rva(0x100)); // pTypeDescriptor
        put_u32(&mut buf, 0x2a0 + 16, rva(0x280)); // pClassHierarchyDescriptor
        put_u32(&mut buf, 0x2a0 + 20, rva(0x2a0)); // pSelf (validates the COL)
        // The vtable: a COL pointer, then a first slot pointing into "code".
        put_u64(&mut buf, 0x300, rd_base + 0x2a0); // -> COL
        put_u64(&mut buf, 0x308, 0x140001000); // first method slot

        let snap = Snapshot::builder().region(Va(rd_base), buf).build();
        let vts = scan_msvc_rtti(&snap, Va(image_base), (Va(rd_base), 0x800), None);
        assert_eq!(vts.len(), 1, "{vts:#?}");
        assert_eq!(vts[0].name, "Derived");
        assert_eq!(vts[0].vtable, Va(rd_base + 0x308));
        assert_eq!(vts[0].bases, vec!["Base1".to_string(), "Base2".to_string()]);
    }

    #[test]
    fn symbol_map_names_the_vtable_and_walks_method_slots() {
        use n0xis_sources::Snapshot;
        let text = (Va(0x140001000), 0x1000u64);
        let vt = Va(0x140010000);
        // Two in-`.text` method pointers, then a null (stops the walk).
        let mut buf = vec![0u8; 0x20];
        buf[0..8].copy_from_slice(&0x140001000u64.to_le_bytes()); // vf0
        buf[8..16].copy_from_slice(&0x140001100u64.to_le_bytes()); // vf1
        // buf[16..24] stays 0 → not in .text → walk stops after vf1.
        let snap = Snapshot::builder().region(vt, buf).build();

        let vts = vec![RttiVtable {
            vtable: vt,
            type_descriptor: Va(0),
            mangled: ".?AVFoo@@".into(),
            name: "Foo".into(),
            offset: 0,
            bases: vec![],
        }];
        let (functions, data) = rtti_symbol_map(&snap, &vts, Some(text));

        assert_eq!(data.get(&vt.get()).map(String::as_str), Some("Foo::vftable"));
        assert_eq!(functions.get(&0x140001000).map(String::as_str), Some("Foo::vf0"));
        assert_eq!(functions.get(&0x140001100).map(String::as_str), Some("Foo::vf1"));
        assert_eq!(functions.len(), 2, "the null slot must end the walk");
    }
}
