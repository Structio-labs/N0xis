// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

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

/// Turn an MSVC RTTI decorated type name into a readable, **bounded** one.
///
/// `.?AVFoo@@` → `Foo`, `.?AUData@Ns@@` → `Ns::Data`. The full readable form
/// ([`demangle_rtti_name_full`]) is then folded to a compact label
/// ([`shorten_type_name`]): heavily-templated code (reactive-stream template libraries, the STL
/// type-erasure helpers) demangles to multi-KiB type strings — correct but
/// useless as a list/decompiler label — and the `<lambda>`-in-a-local-scope
/// names the `msvc_demangler` cannot parse would otherwise render as the raw
/// `.?A…` decorated string. Both are bounded here so nothing ever renders a
/// 9 KiB identifier or a raw mangled blob.
pub fn demangle_rtti_name(mangled: &str) -> String {
    shorten_type_name(demangle_rtti_name_full(mangled), mangled)
}

/// The best readable form of an RTTI decorated name, **unbounded**.
///
/// The real MSVC demangler first — it reads the templated names
/// (`.?AV?$vector@H@std@@` → `std::vector<int>`) the hand-rolled `@`-splitter
/// below deliberately refuses. The splitter stays as a fallback for a name the
/// demangler declines, and the decorated string verbatim is the final,
/// always-sound floor. A name carrying template or other special mangling
/// (`?$`, a bare `?`) the splitter cannot safely decode is returned verbatim
/// rather than mis-decoded — sound over pretty.
fn demangle_rtti_name_full(mangled: &str) -> String {
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

/// Ceiling on a rendered class name. Past it a name is truncated on a `char`
/// boundary with a stable hash suffix that keeps distinct types distinct — a
/// bare prefix cut would collide the thousands of template types that share a long
/// opening (`rpl::details::consumer_handlers<struct rpl::no_value, …`).
const RENDER_NAME_MAX: usize = 160;

/// A short, stable disambiguator derived from the full decorated name.
fn type_name_hash(decorated: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    decorated.hash(&mut h);
    format!("{:08x}", h.finish() as u32)
}

/// Fold a possibly-huge or still-decorated type name into a compact, bounded,
/// collision-resistant label. `decorated` is the original `.?A…` form, used for
/// the stable hash. A name the demanglers both declined (still `.?A…`) is
/// reduced to its leading template/class identifier (`consumer_handlers<…>`)
/// rather than shown as a raw mangled blob.
fn shorten_type_name(name: String, decorated: &str) -> String {
    let name = if let Some(rest) = name.strip_prefix(".?A") {
        let body = rest.get(1..).unwrap_or(""); // drop the kind letter (V/U/W/…)
        let (is_tmpl, base_src) = match body.strip_prefix("?$") {
            Some(t) => (true, t),
            None => (false, body),
        };
        let base = base_src.split('@').next().unwrap_or("");
        if base.is_empty() || base.contains(['?', '$']) {
            format!("type_{}", type_name_hash(decorated))
        } else if is_tmpl {
            format!("{base}<…>")
        } else {
            base.to_string()
        }
    } else {
        name
    };
    if name.len() <= RENDER_NAME_MAX {
        return name;
    }
    let mut cut = RENDER_NAME_MAX;
    while cut > 0 && !name.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…#{}", &name[..cut], type_name_hash(decorated))
}

/// The class named by a `_ZTV…` symbol, as a readable, bounded name.
///
/// Demanglers do not agree on how to render a vtable symbol: `cpp_demangle`
/// produces `{vtable(std::lock_error)}` while others emit `vtable for
/// std::lock_error`. Both wrappers are peeled here; if neither matches, the
/// mangled type is demangled on its own by re-forming it as a `_ZTS` (type
/// string) symbol, which every demangler renders as a plain type name.
/// Base classes of the type whose `type_info` object begins at `zti`.
///
/// The comment this replaces said base classes "need relocation resolution to
/// read". They do not, for the ones that matter: a base pointer inside the same
/// image is supplied by a *relative* relocation — `R_X86_64_RELATIVE` or a
/// `.relr.dyn` entry — and a relative relocation's addend is stored **at the
/// target location**, so reading the eight bytes there yields the address.
/// (Measured: `readelf -r` alone, which does not expand `.relr.dyn`, found 102
/// of 211 edges on one Qt build. Reading the file found 194 of 195
/// single-inheritance classes.) A base in *another* library is a symbolic
/// relocation, reads as zero, and is simply absent — which is correct: this
/// answers "what does this image derive from", and a class it cannot see is not
/// something it can reason about.
///
/// The ABI gives no readable discriminator here — the `type_info` vptr that
/// distinguishes `__si_class_type_info` from `__vmi_class_type_info` is itself
/// a symbolic relocation into the runtime — so the structure decides: a word at
/// `+8` that names a known `type_info` is the single-base layout; otherwise it
/// is read as `flags:u32 | base_count:u32` and the array walked from `+16`.
/// A count outside a sane range means neither shape matched, and nothing is
/// reported rather than guessed.
fn itanium_bases(src: &dyn MemorySource, zti: u64, by_zti: &std::collections::HashMap<u64, String>) -> Vec<String> {
    // `zti` is the address of the `type_info` object itself.
    /// `__vmi_class_type_info::__base_info` is `{ __base_type, __offset_flags }`.
    const BASE_INFO: u64 = 16;
    /// Bounds the walk so a mis-read count can never drive an unbounded loop.
    const MAX_ITANIUM_BASES: u32 = 64;
    let rd = |va: u64| -> Option<u64> { src.read(Va(va), 8).ok().and_then(|b| u64_le(&b, 0)) };

    // A `type_info` is `{ vptr, __type_name }`; the class body follows both.
    let after_name = zti.saturating_add(16);
    let Some(word) = rd(after_name) else { return Vec::new() };
    if let Some(one) = by_zti.get(&word) {
        return vec![one.clone()];
    }
    let count = (word >> 32) as u32;
    if count == 0 || count > MAX_ITANIUM_BASES {
        return Vec::new();
    }
    (0..count as u64)
        .filter_map(|i| rd(after_name.saturating_add(8).saturating_add(BASE_INFO * i)))
        .filter_map(|p| by_zti.get(&p).cloned())
        .collect()
}

fn itanium_class_name(ztv_symbol: &str) -> String {
    let demangled = crate::demangle::demangle(ztv_symbol);
    let peeled = demangled
        .strip_prefix("vtable for ")
        .map(str::to_string)
        .or_else(|| {
            demangled.strip_prefix("{vtable(").and_then(|r| r.strip_suffix(")}")).map(str::to_string)
        })
        .or_else(|| {
            // Fall back to demangling the bare type: `_ZTVFoo` -> `_ZTSFoo`.
            let ty = ztv_symbol.strip_prefix("_ZTV")?;
            let as_type = crate::demangle::demangle(&format!("_ZTS{ty}"));
            let cleaned = as_type
                .strip_prefix("typeinfo name for ")
                .map(str::to_string)
                .or_else(|| as_type.strip_prefix("{typeinfo name(").and_then(|r| r.strip_suffix(")}")).map(str::to_string));
            cleaned.filter(|c| c != ty)
        })
        .unwrap_or(demangled);
    shorten_type_name(peeled, ztv_symbol)
}

/// Recover C++ classes from **Itanium ABI** RTTI (GCC/Clang, i.e. ELF), the
/// counterpart to [`scan_msvc_rtti`]. Returns the same [`RttiVtable`] shape, so
/// everything downstream — `rtti_symbol_map`, `Class::vfN` naming, the
/// decompiler's `this`-typing — works unchanged across both formats.
///
/// **Driven by symbols, not by a structural scan, and that is deliberate.** In an
/// ELF shared object the vtable's type-info slot is *empty in the file*: it is
/// supplied at load time by a relocation against the `_ZTI…` symbol (measured on
/// `libstdc++.so.6` — the slot reads as zeroes and carries an `R_X86_64_64`
/// against `_ZTISt10lock_error`). A byte-level walk therefore recovers almost
/// nothing without also resolving relocations: a prototype of that approach found
/// 11 of 179 vtables. The `_ZTV…` symbol names the class outright, which is both
/// exact and the cheapest source to consult first.
///
/// A fully stripped ELF has no such symbols and yields nothing here — honest, and
/// the documented follow-on (structural scan + `.rela` resolution).
///
/// `vtable` is the address an object actually stores: the `_ZTV` object begins
/// with `offset_to_top` and the type-info pointer, so the first method slot — and
/// thus the stored vptr — sits 16 bytes in.
pub fn scan_itanium_rtti(src: &dyn MemorySource, data_symbols: &[(Va, String)], text: Option<(Va, u64)>) -> Vec<RttiVtable> {
    /// `offset_to_top` (8) + `typeinfo` pointer (8).
    const VTABLE_HEADER: u64 = 16;
    let in_text = |va: u64| text.is_none_or(|(t, n)| va >= t.get() && va < t.get() + n);

    // `_ZTI` address → class name, so a base pointer read out of a type_info
    // can be named. Built first because a base may be declared after its
    // derived class in symbol order.
    let mut by_zti: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    for (va, sym) in data_symbols {
        let bare = sym.split('@').next().unwrap_or(sym);
        if let Some(rest) = bare.strip_prefix("_ZTI")
            && !rest.is_empty()
        {
            by_zti.insert(va.get(), itanium_class_name(&format!("_ZTV{rest}")));
        }
    }

    let mut out = Vec::new();
    for (va, sym) in data_symbols {
        // Strip an ELF symbol-version suffix (`_ZTVFoo@@GLIBCXX_3.4`) before it
        // reaches the demangler, which would otherwise decline the whole name.
        let bare = sym.split('@').next().unwrap_or(sym);
        let Some(rest) = bare.strip_prefix("_ZTV") else { continue };
        if rest.is_empty() {
            continue;
        }
        let vtable = va.get().saturating_add(VTABLE_HEADER);
        // Soundness gate on the first method slot. A **zero** slot is accepted:
        // in a shared object the method pointers are supplied by relocations and
        // read as zeroes from the file (`libstdc++.so.6` uses symbolic
        // `R_X86_64_64` and has no `R_X86_64_RELATIVE` at all), so requiring a
        // resolved code pointer here rejected 178 of its 179 vtables. The `_ZTV`
        // symbol is itself authoritative — it *is* the vtable, by definition —
        // so only a slot that resolves to something demonstrably NOT code is
        // treated as disqualifying.
        let first_slot = src.read(Va(vtable), 8).ok().and_then(|b| u64_le(&b, 0));
        match first_slot {
            Some(0) | None => {}                       // relocation-supplied / unreadable
            Some(target) if in_text(target) => {}      // resolved and points at code
            Some(_) => continue,                       // resolved to non-code — not a vtable we trust
        }
        let name = itanium_class_name(bare);
        out.push(RttiVtable {
            vtable: Va(vtable),
            type_descriptor: Va(va.get().saturating_add(8)),
            mangled: bare.to_string(),
            name,
            offset: 0,
            // The vtable's second word points at the class's `type_info`, and
            // that pointer is itself a relative relocation, so it reads out of
            // the file. Follow it rather than assuming the two objects are
            // adjacent — they are not.
            bases: src
                .read(Va(va.get().saturating_add(8)), 8)
                .ok()
                .and_then(|b| u64_le(&b, 0))
                .filter(|p| *p != 0)
                .map(|zti| itanium_bases(src, zti, &by_zti))
                .unwrap_or_default(),
        });
    }
    out.sort_by_key(|v| v.vtable.get());
    out
}

const COL_SIZE: usize = 24; // sig,u32 | offset,u32 | cdOffset,u32 | pTD,rva | pClass,rva | pSelf,rva
/// The 32-bit COL: the same five words **without** `pSelf`, and its pointer
/// fields are absolute VAs rather than image-relative RVAs.
const COL_SIZE_32: usize = 20;
const COL_PCLASS: usize = 16; // RVA of the RTTIClassHierarchyDescriptor
// RTTIClassHierarchyDescriptor: signature,u32 | attributes,u32 | numBaseClasses,u32 | pBaseClassArray,rva
const CHD_NUM_BASES: usize = 8;
const CHD_BASE_ARRAY: usize = 12;
/// Base-class count ceiling — bounds the walk so a mis-read descriptor can
/// never drive an unbounded loop/allocation (the OOM lesson, again).
const MAX_BASES: usize = 256;
/// Hard ceiling on a decorated type name — a mis-read pointer can never drive an
/// unbounded read (the OOM lesson). Real MSVC names, even deeply nested
/// template types, stay well under this; 512 was far too small and
/// truncated ~half of the Qt desktop PE's names mid-symbol, which then could not demangle.
const MAX_NAME: usize = 64 * 1024;
/// First read size for [`read_cstr`], doubled on each miss. Most names are short
/// and terminate inside this one small read; the long template names double their
/// way out in a few steps. A large fixed chunk would copy (and allocate) kilobytes
/// per name across tens of thousands of descriptors for no gain.
const NAME_CHUNK: usize = 256;
/// Ceiling on a single [`read_cstr`] read, so the doubling cannot request a huge
/// buffer for one pathological name.
const NAME_CHUNK_MAX: usize = 8192;
/// A hard ceiling so a mis-identified `.rdata` size can never drive an
/// unbounded allocation (the machine's OOM lesson, applied to a parsed length).
const MAX_RDATA: usize = 64 * 1024 * 1024;

fn u32_le(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64_le(b: &[u8], at: usize) -> Option<u64> {
    b.get(at..at + 8).map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// Scan `.rdata` for MSVC RTTI vtables.
///
/// **`ptr_size` is not a formality — the two MSVC RTTI dialects are different
/// structures**, and reading one as the other finds nothing rather than finding
/// something wrong:
///
/// | | 32-bit (signature 0) | 64-bit (signature 1) |
/// | --- | --- | --- |
/// | vtable/COL slots | 4 bytes | 8 bytes |
/// | COL's `pTypeDescriptor` etc. | **absolute VAs** | image-relative **RVAs** |
/// | COL size | 20 bytes | 24 bytes |
/// | `pSelf` | **absent** | present, and the strongest validity check there is |
/// | name inside the TypeDescriptor | at `+8` (two 4-byte slots) | at `+16` |
///
/// This scanner was written for 64-bit and applied to both, so on a 32-bit PE
/// it stepped 8 bytes at a time through 4-byte slots and resolved absolute
/// pointers as RVAs. It returned **0 classes for a 32-bit C++ runtime carrying
/// 95 MSVC type descriptors** — `ok: true`, an empty list, and nothing to
/// suggest the question had been asked in the wrong dialect.
///
/// **`data_ranges` is a list because the vtable is not always in `.rdata`.**
/// That is an MSVC-toolchain habit, not a property of PE: a mingw-built PE puts
/// its vtables in `.data`, and scanning only `.rdata` reported **0 classes for
/// a 32-bit C++ runtime whose COLs are laid out exactly as expected** — they
/// were simply in the section next door. Pass every initialized data range the
/// image has; a candidate still has to survive the signature, the `.?A` name
/// and the first-slot-in-code checks, so a wider search costs a scan and not
/// accuracy.
///
/// `image_base` resolves the 64-bit RVAs and is unused on 32-bit. `text` (when
/// known) gates a candidate on its first vtable slot pointing into code.
pub fn scan_msvc_rtti(
    src: &dyn MemorySource,
    image_base: Va,
    data_ranges: &[(Va, u64)],
    text: Option<(Va, u64)>,
    ptr_size: u8,
) -> Vec<RttiVtable> {
    let mut out = Vec::new();
    for &range in data_ranges {
        out.extend(scan_one_range(src, image_base, range, data_ranges, text, ptr_size));
    }
    out.sort_by_key(|v| v.vtable.get());
    out.dedup_by_key(|v| v.vtable.get());
    out
}

/// One data range's worth of the scan above. `all` is every range, because
/// **the vtable and the COL it points at need not be in the same section** — in
/// a mingw-built PE the vtable is in `.data` and its COL in `.rdata`, so a
/// membership test against the range being walked rejects every real hit.
fn scan_one_range(
    src: &dyn MemorySource,
    image_base: Va,
    rdata: (Va, u64),
    all: &[(Va, u64)],
    text: Option<(Va, u64)>,
    ptr_size: u8,
) -> Vec<RttiVtable> {
    let (rd_base, rd_len) = (rdata.0.get(), (rdata.1 as usize).min(MAX_RDATA));
    let Ok(buf) = src.read(Va(rd_base), rd_len) else {
        return Vec::new();
    };
    let wide = ptr_size >= 8;
    let step = if wide { 8usize } else { 4 };
    let col_size = if wide { COL_SIZE } else { COL_SIZE_32 };
    let td_name_at = 2 * step as u64;
    // A COL can live in any of the image's data ranges, not only this one.
    let in_data = |va: u64| all.iter().any(|(b, n)| va >= b.get() && va < b.get() + n);
    let in_text = |va: u64| text.is_none_or(|(t, n)| va >= t.get() && va < t.get() + n);
    // A pointer-sized slot, at the target's width.
    let slot = |at: usize| -> Option<u64> {
        if wide { u64_le(&buf, at) } else { u32_le(&buf, at).map(u64::from) }
    };
    // A COL field: an RVA to be rebased on 64-bit, already a VA on 32-bit.
    let field_va = |raw: u32| -> u64 {
        if wide { image_base.get().wrapping_add(raw as u64) } else { raw as u64 }
    };

    let mut out = Vec::new();
    // Every aligned slot is a candidate "pointer to a COL". A vtable is the slot
    // *after* such a pointer.
    let mut off = 0usize;
    while off + step <= buf.len() {
        let Some(col_ptr) = slot(off) else { break };
        if in_data(col_ptr) {
            // Read the COL through the source rather than out of this buffer:
            // it may be in a different section entirely.
            let col = src.read(Va(col_ptr), col_size).unwrap_or_default();
            // 64-bit's `pSelf` is the strongest check available: the COL points
            // at itself. 32-bit has no such field, so the signature word (which
            // is 0 there, by definition of the dialect) stands in — the real
            // filter for both is the type descriptor's `.?A` name below.
            let structurally_sound = if wide {
                u32_le(&col, 20).is_some_and(|p_self| field_va(p_self) == col_ptr)
            } else {
                u32_le(&col, 0).is_some_and(|sig| sig == 0)
            };
            if let (Some(offset), Some(p_td)) = (u32_le(&col, 4), u32_le(&col, 12))
                && col.len() >= col_size
                && structurally_sound
            {
                let vtable = rd_base + off as u64 + step as u64;
                if slot(off + step).is_some_and(in_text) {
                    let td_name_va = field_va(p_td) + td_name_at;
                    if let Some(mangled) = read_cstr(src, Va(td_name_va))
                        && mangled.starts_with(".?A")
                    {
                        let name = demangle_rtti_name(&mangled);
                        let pclass = u32_le(&col, COL_PCLASS).unwrap_or(0);
                        let bases = read_base_classes(&buf, rd_base, image_base.get(), src, pclass, ptr_size);
                        out.push(RttiVtable {
                            vtable: Va(vtable),
                            type_descriptor: Va(td_name_va - td_name_at),
                            mangled,
                            name,
                            offset,
                            bases,
                        });
                    }
                }
            }
        }
        off += step;
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
fn read_base_classes(
    buf: &[u8],
    rd_base: u64,
    image_base: u64,
    src: &dyn MemorySource,
    pclass_rva: u32,
    ptr_size: u8,
) -> Vec<String> {
    let mut bases = Vec::new();
    if pclass_rva == 0 {
        return bases;
    }
    // Same dialect split as the COL above: a 64-bit descriptor holds RVAs, a
    // 32-bit one holds absolute VAs.
    let wide = ptr_size >= 8;
    let to_va = |raw: u32| -> u64 { if wide { image_base.wrapping_add(raw as u64) } else { raw as u64 } };
    let at = |rva: u32| -> Option<usize> {
        let va = to_va(rva);
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
        let td_name_va = to_va(td_rva) + if wide { 16 } else { 8 };
        if let Some(m) = read_cstr(src, Va(td_name_va))
            && m.starts_with(".?A")
        {
            bases.push(demangle_rtti_name(&m));
        }
    }
    bases
}

/// Read a NUL-terminated ASCII string, the shape a `TypeDescriptor` name has.
///
/// Grows a chunk at a time until the terminator, capped by [`MAX_NAME`]. A single
/// large read would truncate long names on a source that clamps to what a section
/// physically holds ([`MemorySource::read`] returns a short/empty `Vec` at a
/// boundary, never an error), and reading `MAX_NAME` up front for every descriptor
/// would churn 64 KiB per name; growing keeps the common short name to one read
/// while still reaching the multi-KiB template names heavy C++ template code produces.
fn read_cstr(src: &dyn MemorySource, at: Va) -> Option<String> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut step = NAME_CHUNK;
    while bytes.len() < MAX_NAME {
        let want = step.min(MAX_NAME - bytes.len());
        let chunk = src.read(Va(at.get() + bytes.len() as u64), want).ok()?;
        if let Some(pos) = chunk.iter().position(|&b| b == 0) {
            bytes.extend_from_slice(&chunk[..pos]);
            break;
        }
        let short = chunk.len() < want; // clamped at the section boundary — no more to read
        bytes.extend_from_slice(&chunk);
        if short {
            break;
        }
        step = (step * 2).min(NAME_CHUNK_MAX);
    }
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lay out an Itanium `type_info` graph the way a linked shared object
    /// does: the pointers inside it are supplied by *relative* relocations,
    /// whose addend sits at the target location — so they read straight out of
    /// the image. Anything a relocation cannot supply locally (a base in
    /// another library) reads as zero.
    fn itanium_image() -> n0xis_sources::Snapshot {
        use n0xis_contracts::{SymKind, Symbol};
        const BASE: u64 = 0x10000;
        let put = |buf: &mut Vec<u8>, at: usize, v: u64| buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
        let mut data = vec![0u8; 0x200];
        // 0x10000 _ZTI4Base : { vptr, name } and no bases
        // 0x10040 _ZTI7Derived (single base) : { vptr, name, Base }
        put(&mut data, 0x50, BASE); // +0x40 +0x10 -> &_ZTI4Base
        // 0x10080 _ZTI4Both (two bases) : { vptr, name, flags|count=2, {Base,f}, {Derived,f} }
        put(&mut data, 0x90, 2u64 << 32); // flags=0, base_count=2
        put(&mut data, 0x98, BASE); //        base 0 -> Base
        put(&mut data, 0xa8, BASE + 0x40); // base 1 -> Derived
        // the three vtables, each with `type_info` in its second word
        put(&mut data, 0x108, BASE); //        _ZTV4Base    + 8
        put(&mut data, 0x128, BASE + 0x40); // _ZTV7Derived + 8
        put(&mut data, 0x148, BASE + 0x80); // _ZTV4Both    + 8
        let sym = |va: u64, n: &str| Symbol { va: Va(va), name: n.into(), kind: SymKind::Data, module: String::new() };
        n0xis_sources::Snapshot::builder()
            .region(Va(BASE), data)
            .symbol(sym(BASE, "_ZTI4Base"))
            .symbol(sym(BASE + 0x40, "_ZTI7Derived"))
            .symbol(sym(BASE + 0x80, "_ZTI4Both"))
            .symbol(sym(BASE + 0x100, "_ZTV4Base"))
            .symbol(sym(BASE + 0x120, "_ZTV7Derived"))
            .symbol(sym(BASE + 0x140, "_ZTV4Both"))
            .build()
    }

    #[test]
    fn itanium_base_classes_are_read_from_the_image() {
        // The comment this replaced said base classes "need relocation
        // resolution to read", so `bases` came back empty on every ELF and the
        // hierarchy — which is what tells a *sound* devirtualization from an
        // unsound one — did not exist.
        let snap = itanium_image();
        let syms: Vec<(Va, String)> = [
            (0x10000u64, "_ZTI4Base"), (0x10040, "_ZTI7Derived"), (0x10080, "_ZTI4Both"),
            (0x10100, "_ZTV4Base"), (0x10120, "_ZTV7Derived"), (0x10140, "_ZTV4Both"),
        ]
        .iter()
        .map(|(v, n)| (Va(*v), (*n).to_string()))
        .collect();
        let out = scan_itanium_rtti(&snap, &syms, None);
        let by: std::collections::HashMap<&str, &Vec<String>> = out.iter().map(|v| (v.name.as_str(), &v.bases)).collect();
        assert_eq!(by.get("Base").map(|b| b.len()), Some(0), "a class with no bases states none");
        assert_eq!(by.get("Derived").map(|v| v.as_slice()), Some(["Base".to_string()].as_slice()));
        let both = (*by.get("Both").expect("Both")).clone();
        assert_eq!(both.len(), 2, "multiple inheritance walks the base_info array: {both:?}");
        assert!(both.contains(&"Base".to_string()) && both.contains(&"Derived".to_string()), "{both:?}");
    }

    #[test]
    fn demangles_a_plain_and_a_namespaced_class() {
        assert_eq!(demangle_rtti_name(".?AVFoo@@"), "Foo");
        assert_eq!(demangle_rtti_name(".?AUData@Ns@@"), "Ns::Data");
        // a real third-party physics-engine class name from the corpus
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
        // A real third-party physics-engine template name from the corpus
        // demangles rather than falling through to verbatim.
        assert_eq!(
            demangle_rtti_name(".?AV?$basic_ios@EU?$char_traits@E@std@@@std@@"),
            "std::basic_ios<unsigned char, struct std::char_traits<unsigned char> >",
        );
    }

    #[test]
    fn itanium_vtable_symbol_names_its_class() {
        use n0xis_sources::Snapshot;
        // A `_ZTV` object is [offset_to_top][typeinfo][fn0…]; the pointer an
        // object stores is +16, and the ELF symbol-version suffix must not reach
        // the demangler.
        let mut vt = vec![0u8; 32];
        vt[16..24].copy_from_slice(&0x1000u64.to_le_bytes());
        let snap = Snapshot::builder().region(Va(0x1000), vec![0xC3]).region(Va(0x2000), vt).build();
        let syms = [(Va(0x2000), "_ZTVSt10lock_error@@GLIBCXX_3.4.11".to_string())];
        let vts = scan_itanium_rtti(&snap, &syms, Some((Va(0x1000), 0x100)));
        assert_eq!(vts.len(), 1);
        assert_eq!(vts[0].vtable, Va(0x2010), "the stored vptr is 16 bytes into the _ZTV object");
        assert_eq!(vts[0].name, "std::lock_error");
    }

    #[test]
    fn a_relocation_supplied_slot_does_not_disqualify_a_vtable() {
        use n0xis_sources::Snapshot;
        // In a shared object the method slots are filled by the loader and read
        // as zero from the file. Requiring a resolved code pointer here rejected
        // 178 of libstdc++'s 179 vtables; the `_ZTV` symbol is authoritative.
        let snap = Snapshot::builder().region(Va(0x2000), vec![0u8; 32]).build();
        let syms = [(Va(0x2000), "_ZTV3Foo".to_string())];
        assert_eq!(scan_itanium_rtti(&snap, &syms, Some((Va(0x1000), 0x100))).len(), 1);
    }

    #[test]
    fn a_slot_resolving_outside_code_is_rejected() {
        use n0xis_sources::Snapshot;
        let mut vt = vec![0u8; 32];
        vt[16..24].copy_from_slice(&0xDEAD_0000u64.to_le_bytes()); // not in .text
        let snap = Snapshot::builder().region(Va(0x2000), vt).build();
        let syms = [(Va(0x2000), "_ZTV3Foo".to_string())];
        assert!(scan_itanium_rtti(&snap, &syms, Some((Va(0x1000), 0x100))).is_empty());
    }

    #[test]
    fn a_non_rtti_string_passes_through() {
        assert_eq!(demangle_rtti_name("not a name"), "not a name");
    }

    #[test]
    fn a_declined_name_is_reduced_to_a_readable_label_never_a_raw_blob() {
        // Both demanglers declined → the input is still the raw decorated string
        // (the `<lambda>`-in-a-local-scope names `msvc_demangler` 0.11 cannot
        // parse). It must not render as a `.?A…` blob: reduce to the leading
        // template identifier so the listing stays readable.
        let raw = ".?AV?$consumer_handlers@VQString@@Uno_error@rpl@@V<lambda_1>@?1??".to_string();
        assert_eq!(shorten_type_name(raw.clone(), &raw), "consumer_handlers<…>");
        // A plain (non-template) decorated name keeps its identifier, no `<…>`.
        let plain = ".?AVWeird@@".to_string();
        assert_eq!(shorten_type_name(plain.clone(), &plain), "Weird");
    }

    #[test]
    fn a_giant_demangled_name_is_truncated_with_a_stable_disambiguator() {
        // A demangled STL type-erasure name runs to multiple KiB — bound it.
        let huge = format!("std::_Func_impl_no_alloc<{}>", "class rpl::details::x, ".repeat(200));
        let a = shorten_type_name(huge.clone(), ".?AVdecorated_a@@");
        assert!(a.len() <= RENDER_NAME_MAX + 12, "must be bounded, got {} bytes", a.len());
        assert!(a.starts_with("std::_Func_impl_no_alloc<") && a.contains('…'));
        // Two distinct types sharing that long opening must not collide.
        let b = shorten_type_name(huge, ".?AVdecorated_b@@");
        assert_ne!(a, b);
    }

    #[test]
    fn a_short_name_is_untouched_by_the_bound() {
        assert_eq!(shorten_type_name("Ns::Foo".to_string(), ".?AVFoo@Ns@@"), "Ns::Foo");
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
        let vts = scan_msvc_rtti(&snap, Va(image_base), &[(Va(rd_base), 0x800)], None, 8);
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
