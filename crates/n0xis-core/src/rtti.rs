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
}

/// Turn an MSVC RTTI decorated type name into a readable one.
///
/// `.?AVFoo@@` → `Foo`, `.?AUData@Ns@@` → `Ns::Data` (the `@`-separated
/// qualifiers are innermost-first, so they reverse into `outer::inner`). A name
/// carrying template or other special mangling (`?$`, a bare `?`) is returned
/// **verbatim** rather than mis-decoded — sound over pretty.
pub fn demangle_rtti_name(mangled: &str) -> String {
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
                        out.push(RttiVtable { vtable: Va(vtable), type_descriptor: Va(td_name_va - 16), mangled, name, offset });
                    }
                }
            }
        }
        off += 8;
    }
    out
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
    fn a_template_name_is_returned_verbatim_never_mis_decoded() {
        // `?$` is a template; reversing the `@`-parts would be nonsense, so the
        // decorated form is kept as-is.
        let t = ".?AV?$vector@H@std@@";
        assert_eq!(demangle_rtti_name(t), t);
    }

    #[test]
    fn a_non_rtti_string_passes_through() {
        assert_eq!(demangle_rtti_name("not a name"), "not a name");
    }
}
