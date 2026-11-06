// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Itanium classes by the structure of their `type_info` and vtables, for an image
//! whose `_ZTV` symbols are gone.
//!
//! `strip` removes the names and leaves everything they named. What a class's
//! `type_info` and vtable are does not depend on them:
//!
//! - a `type_info` object is a pointer to the runtime's vtable for its kind, then a
//!   pointer to its name, a C string that is a mangled type (`6Square`). So a word
//!   that points at such a string, after a word a relocation or the image states,
//!   is a `type_info`.
//! - a vtable has the `type_info`'s address in its second word, `offset_to_top`
//!   before it, a constant the file holds, and code from the word after. So a word
//!   holding a `type_info`'s address, after a zero no relocation writes and before
//!   a method, is a class's own table, and the word after it is the vptr.
//!
//! That word is where an object's vptr points whatever precedes it, so the address
//! point needs no arithmetic from a symbol. What it cannot give is a single answer
//! for a class with virtual bases: a construction table for a derived class holds
//! the same `type_info` with the same zero before it. A class with two such tables
//! is refused and not guessed at ([`VtableRefusal::SeveralTables`]).
//!
//! A word is an address when a relocation gives it one, or, on an image that runs
//! where it says, when it holds one. Elsewhere a stored number is a number.

use std::collections::{BTreeMap, HashMap, HashSet};

use n0xis_contracts::Va;
use n0xis_sources::{MemorySource, RelocatedWords};

use crate::rtti::{Bases, BasesUnknown, ItaniumScan, RefusedVtable, RttiVtable, VtableRefusal, itanium_class_name, read_pointer};

/// The longest type name read.
const MAX_NAME: usize = 4096;
/// The most slots read of one table.
const MAX_SLOTS: u64 = 4096;
/// The most direct bases a `__vmi_class_type_info` is believed to have.
const MAX_BASES: u32 = 4096;

/// What says what a word of the image holds.
pub struct ImageWords<'a> {
    /// `(word, the address a relocation gives it)`, sorted by word.
    pub relocated: &'a [(u64, u64)],
    /// The words a relocation writes, whether or not to an address of this image.
    pub written: &'a RelocatedWords,
    /// The image runs where it says, so a stored word may be an address.
    pub stored_values_are_addresses: bool,
    /// The sections to search, `(start, bytes the file holds)`.
    pub ranges: &'a [(Va, u64)],
}

impl ImageWords<'_> {
    /// The address the word at `at` holds, if it holds one this image states.
    fn address(&self, src: &dyn MemorySource, at: u64, ptr_size: u8) -> Option<u64> {
        if let Ok(i) = self.relocated.binary_search_by_key(&at, |&(w, _)| w) {
            return Some(self.relocated[i].1);
        }
        if !self.stored_values_are_addresses {
            return None;
        }
        read_pointer(src, Va(at), ptr_size).filter(|&v| v != 0)
    }

    fn is_written(&self, at: u64) -> bool {
        match self.written {
            RelocatedWords::Read { words, copies } => words.binary_search(&at).is_ok() || copies.iter().any(|&(s, e)| at >= s && at < e),
            RelocatedWords::NotRead(_) => true,
        }
    }

    /// Every word that may hold an address: what a relocation gives one to, and
    /// every aligned word on an image where a stored word may.
    fn words(&self, ptr_size: u8) -> Vec<u64> {
        let mut out: Vec<u64> = self.relocated.iter().map(|&(w, _)| w).collect();
        if self.stored_values_are_addresses {
            let ptr = u64::from(ptr_size);
            for &(start, size) in self.ranges {
                let first = start.0.next_multiple_of(ptr);
                out.extend((first..start.0.saturating_add(size)).step_by(ptr as usize));
            }
            out.sort_unstable();
            out.dedup();
        }
        out
    }
}

/// The name a `type_info` points at, when `at` is the start of a C string that is a
/// mangled class type. `None` for anything else: a pointer, a reference, a function
/// or a fundamental type is no class, and a string that does not demangle is no type.
fn class_type_name(src: &dyn MemorySource, words: &ImageWords, at: u64) -> Option<String> {
    if !words.ranges.iter().any(|&(s, n)| at >= s.0 && at - s.0 < n) {
        return None;
    }
    let bytes = src.read(Va(at), MAX_NAME).ok()?;
    let end = bytes.iter().position(|&b| b == 0)?;
    let raw = std::str::from_utf8(&bytes[..end]).ok()?;
    // gcc writes the name of a type with no linkage with a leading `*`, which
    // `type_info::operator==` reads as "compare by address".
    let name = raw.strip_prefix('*').unwrap_or(raw);
    let first = *name.as_bytes().first()?;
    if !(first.is_ascii_digit() || matches!(first, b'N' | b'S' | b'Z')) || !name.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    let mangled = format!("_ZTS{name}");
    let demangled = crate::demangle::demangle(&mangled);
    (demangled != mangled && demangled.starts_with("typeinfo name for ")).then(|| name.to_string())
}

/// A `type_info` the scan found, by its address.
struct TypeInfo {
    /// The type's mangled name, without `_ZTS`.
    name: String,
}

/// The direct bases a `type_info` states, as far as the image names them. The kind is
/// the structure: a `__si_class_type_info` has a `type_info` in its third word, and a
/// `__vmi_class_type_info` a flags word and a count there, then its bases.
fn bases_of(src: &dyn MemorySource, words: &ImageWords, infos: &BTreeMap<u64, TypeInfo>, at: u64, ptr_size: u8) -> (Bases, bool) {
    let ptr = u64::from(ptr_size);
    let third = at + 2 * ptr;
    let name_of = |b: u64| infos.get(&b).map(|i| itanium_class_name(&format!("_ZTV{}", i.name)));
    if let Some(base) = words.address(src, third, ptr_size)
        && let Some(name) = name_of(base)
    {
        return (Bases::Known { bases: vec![name] }, false);
    }
    // A word a relocation writes with no address of this image is a base defined in
    // another one: it has a base, and it is not one this image can name. Unless it is
    // the next `type_info`'s first word, and then this one ended before it.
    if infos.contains_key(&third) {
        return (Bases::Known { bases: Vec::new() }, false);
    }
    if words.is_written(third) {
        return (Bases::Unknown { bases_unknown: BasesUnknown::BaseNotNamed }, false);
    }
    let raw = src.read(Va(third), 8).ok();
    let (flags, count) = match raw.as_deref() {
        Some([a, b, c, d, e, f, g, h]) => (u32::from_le_bytes([*a, *b, *c, *d]), u32::from_le_bytes([*e, *f, *g, *h])),
        _ => (u32::MAX, 0),
    };
    // A count that is one of a plain class's next object, not its own: only a table
    // of bases whose every first word is written or an address is believed.
    let stride = 2 * ptr;
    let first = third + 8;
    let is_vmi = flags <= 3 && (1..=MAX_BASES).contains(&count) && (0..u64::from(count)).all(|i| words.is_written(first + i * stride) || words.address(src, first + i * stride, ptr_size).is_some());
    if !is_vmi {
        return (Bases::Known { bases: Vec::new() }, false);
    }
    let mut names = Vec::new();
    let mut named_all = true;
    let mut virtual_base = false;
    for i in 0..u64::from(count) {
        let word = first + i * stride;
        match words.address(src, word, ptr_size).and_then(name_of) {
            Some(name) => names.push(name),
            None => named_all = false,
        }
        // `__offset_flags`: bit 0 is `__virtual_mask`.
        if read_pointer(src, Va(word + ptr), ptr_size).is_some_and(|f| f & 1 != 0) {
            virtual_base = true;
        }
    }
    let bases = if named_all { Bases::Known { bases: names } } else { Bases::Unknown { bases_unknown: BasesUnknown::BaseNotNamed } };
    (bases, virtual_base)
}

/// The methods of a table from its first slot at `vtable`: the address each holds,
/// `None` for a word a relocation against another image's symbol fills. They run until
/// `stop` says a word starts another object, or a word is neither a method nor written.
pub fn read_slots(src: &dyn MemorySource, words: &ImageWords, code: &[(Va, u64)], vtable: u64, ptr_size: u8, stop: &dyn Fn(u64) -> bool) -> Vec<Option<Va>> {
    let ptr = u64::from(ptr_size);
    let in_code = |va: u64| code.iter().any(|(s, n)| va >= s.0 && va - s.0 < *n);
    let mut slots = Vec::new();
    for i in 0..MAX_SLOTS {
        let slot = vtable + i * ptr;
        if stop(slot) {
            break;
        }
        match words.address(src, slot, ptr_size) {
            Some(target) if in_code(target & !1) => slots.push(Some(Va(target & !1))),
            Some(_) => break,
            None if words.is_written(slot) => slots.push(None),
            None => break,
        }
    }
    slots
}

/// Which class each function in a class's own table was written in, where the tables
/// say: `(class, its bases, the table's methods)`.
///
/// A virtual method is an instance method, so its first argument is `this`, and a slot
/// says so with no symbol. What a slot does not say is the class it was written in: a
/// method a class inherits is in its table as well as its base's. So of the classes
/// listing a function, the one none of whose bases list it. Where that is not one class
/// (identical code folded into the tables of two unrelated classes) it is not said.
pub fn method_owners<'a>(tables: impl Iterator<Item = (&'a str, &'a Bases, Vec<Option<Va>>)>) -> HashMap<u64, String> {
    let mut listing: HashMap<u64, Vec<(&str, &Bases)>> = HashMap::new();
    for (class, bases, slots) in tables {
        for slot in slots.into_iter().flatten() {
            listing.entry(slot.0).or_default().push((class, bases));
        }
    }
    let mut owners = HashMap::new();
    for (function, classes) in listing {
        let mut roots = classes.iter().filter(|(_, bases)| match bases {
            Bases::Known { bases } => !bases.iter().any(|b| classes.iter().any(|(c, _)| c == b)),
            Bases::Unknown { .. } => classes.len() == 1,
        });
        if let (Some((class, _)), None) = (roots.next(), roots.next()) {
            owners.insert(function, (*class).to_string());
        }
    }
    owners
}

/// Every class of the image that is not in `known` (the `_ZTV` symbols already read),
/// from the structure of its `type_info` and vtable.
pub fn scan_itanium_structure(src: &dyn MemorySource, words: &ImageWords, code: &[(Va, u64)], ptr_size: u8, known: &HashSet<String>) -> ItaniumScan {
    let ptr = u64::from(ptr_size);
    let in_code = |va: u64| code.iter().any(|(s, n)| va >= s.0 && va - s.0 < *n);
    let all = words.words(ptr_size);

    // Each word pointing at a class's name, with one before it the runtime's vtable
    // for its kind fills.
    let mut infos: BTreeMap<u64, TypeInfo> = BTreeMap::new();
    for &word in &all {
        let Some(target) = words.address(src, word, ptr_size) else { continue };
        let Some(at) = word.checked_sub(ptr) else { continue };
        if !(words.is_written(at) || words.address(src, at, ptr_size).is_some()) {
            continue;
        }
        if let Some(name) = class_type_name(src, words, target) {
            infos.insert(at, TypeInfo { name });
        }
    }

    // Each word holding a type_info's address, with a zero no relocation writes before
    // it and a method after it. A non-zero `offset_to_top` is a secondary table of a
    // class with several bases, and is not its vptr.
    let mut tables: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    // A static image with no definition of `__cxa_pure_virtual` has a zero in a pure
    // slot, and an abstract class may then have nothing in its table: taken only where
    // no table with a method says otherwise, as it is a weaker fact.
    let mut empty_tables: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for &word in &all {
        let Some(at) = words.address(src, word, ptr_size).filter(|t| infos.contains_key(t)) else { continue };
        let Some(before) = word.checked_sub(ptr) else { continue };
        if words.is_written(before) || read_pointer(src, Va(before), ptr_size) != Some(0) {
            continue;
        }
        let first_slot = word + ptr;
        // A pure virtual slot is written by a symbol of another image: a method all
        // the same.
        let is_method = match words.address(src, first_slot, ptr_size) {
            Some(target) => in_code(target & !1),
            None => words.is_written(first_slot),
        };
        if is_method {
            tables.entry(at).or_default().push(word);
        } else if read_pointer(src, Va(first_slot), ptr_size) == Some(0) {
            empty_tables.entry(at).or_default().push(word);
        }
    }
    for (at, words_of) in empty_tables {
        tables.entry(at).or_insert(words_of);
    }

    let mut out = Vec::new();
    let mut refused = Vec::new();
    for (at, slots_of) in &tables {
        let info = &infos[at];
        let mangled = format!("_ZTV{}", info.name);
        if known.contains(&mangled) {
            continue;
        }
        let name = itanium_class_name(&mangled);
        let (bases, virtual_base) = bases_of(src, words, &infos, *at, ptr_size);
        if virtual_base {
            refused.push(RefusedVtable { mangled, name, reason: VtableRefusal::VirtualBases });
            continue;
        }
        let [word] = slots_of.as_slice() else {
            refused.push(RefusedVtable { mangled, name, reason: VtableRefusal::SeveralTables });
            continue;
        };
        let vtable = word + ptr;
        // The next object may be a `type_info`, whose first word a relocation writes
        // as it would a pure virtual slot.
        let slots = read_slots(src, words, code, vtable, ptr_size, &|slot| infos.contains_key(&slot));
        out.push(RttiVtable { vtable: Va(vtable), type_descriptor: Va(*word), name, mangled, offset: 0, bases, slots });
    }
    out.sort_by_key(|v| v.vtable.get());
    refused.sort_by(|a: &RefusedVtable, b| a.mangled.cmp(&b.mangled));
    ItaniumScan { vtables: out, refused, structure_not_read: None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_sources::Snapshot;

    const CODE: u64 = 0x1000;
    const DATA: u64 = 0x2000;
    const NAME: u64 = DATA + 0x100;

    fn scanned(name: &[u8]) -> ItaniumScan {
        let mut data = vec![0u8; 0x200];
        data[0x100..0x100 + name.len()].copy_from_slice(name);
        let snap = Snapshot::builder().region(Va(CODE), vec![0xC3; 16]).region(Va(DATA), data).build();
        // A `type_info` at +0x10: its first word written by a symbol of another image,
        // its second naming `name`. A table at +0x40: a zero, the `type_info`, a method.
        let relocated = [(DATA + 0x18, NAME), (DATA + 0x48, DATA + 0x10), (DATA + 0x50, CODE)];
        let written = RelocatedWords::Read { words: vec![DATA + 0x10, DATA + 0x18, DATA + 0x48, DATA + 0x50], copies: Vec::new() };
        let words = ImageWords { relocated: &relocated, written: &written, stored_values_are_addresses: false, ranges: &[(Va(DATA), 0x200)] };
        scan_itanium_structure(&snap, &words, &[(Va(CODE), 16)], 8, &HashSet::new())
    }

    /// Every word of the shape is planted, so that it is the name that says.
    #[test]
    fn a_class_is_named_by_a_mangled_type() {
        let scan = scanned(b"6Square\0");
        assert_eq!(scan.vtables.len(), 1);
        assert_eq!(scan.vtables[0].name, "Square");
        assert_eq!(scan.vtables[0].vtable, Va(DATA + 0x50));
        assert_eq!(scan.vtables[0].type_descriptor, Va(DATA + 0x48));
    }

    #[test]
    fn a_string_that_is_no_mangled_type_names_no_class() {
        // In a word a `type_info`'s name would be in, and each stops at another rule:
        // a phrase, a word starting as a type does, and a pointer to a class, which has
        // a `type_info` of its own and is no class.
        for name in [&b"not a type\0"[..], b"Square\0", b"Stack\0", b"12345\0", b"P6Square\0"] {
            assert!(scanned(name).vtables.is_empty(), "{}", String::from_utf8_lossy(name));
        }
    }

    /// Past a real table, a word holding the same `type_info` between two zeros: not
    /// a second table to choose between, and without the real one it would be taken.
    #[test]
    fn a_table_with_a_method_is_preferred_to_an_empty_one() {
        let mut data = vec![0u8; 0x200];
        data[0x100..0x108].copy_from_slice(b"6Square\0");
        let snap = Snapshot::builder().region(Va(CODE), vec![0xC3; 16]).region(Va(DATA), data).build();
        let relocated = [(DATA + 0x18, NAME), (DATA + 0x48, DATA + 0x10), (DATA + 0x50, CODE), (DATA + 0x88, DATA + 0x10)];
        let written = RelocatedWords::Read { words: vec![DATA + 0x10, DATA + 0x18, DATA + 0x48, DATA + 0x50, DATA + 0x88], copies: Vec::new() };
        let words = ImageWords { relocated: &relocated, written: &written, stored_values_are_addresses: false, ranges: &[(Va(DATA), 0x200)] };
        let scan = scan_itanium_structure(&snap, &words, &[(Va(CODE), 16)], 8, &HashSet::new());
        assert_eq!(scan.vtables.iter().map(|v| v.vtable).collect::<Vec<_>>(), vec![Va(DATA + 0x50)]);
        assert!(scan.refused.is_empty(), "{:?}", scan.refused);
    }

    fn known(bases: &[&str]) -> Bases {
        Bases::Known { bases: bases.iter().map(|b| b.to_string()).collect() }
    }

    #[test]
    fn a_method_belongs_to_the_class_none_of_whose_bases_list_it() {
        let (b, d, u) = (known(&[]), known(&["Base"]), known(&[]));
        let f = Some(Va(0x10));
        let g = Some(Va(0x20));
        let shared = Some(Va(0x30));
        let owners = method_owners(
            [("Base", &b, vec![f, shared]), ("Derived", &d, vec![f, g]), ("Unrelated", &u, vec![shared, None])].into_iter(),
        );
        assert_eq!(owners.get(&0x10).map(String::as_str), Some("Base"), "inherited, so written in the base");
        assert_eq!(owners.get(&0x20).map(String::as_str), Some("Derived"), "only there");
        assert_eq!(owners.get(&0x30), None, "two classes with no base between them: code folded together, which says nothing");
    }
}
