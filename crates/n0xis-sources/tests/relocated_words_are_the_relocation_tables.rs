// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The words an ELF's loader writes are the ones its relocation tables
//! name.**
//!
//! [`ImageSource::relocated_words`] is what tells the Itanium RTTI scan a zero
//! the loader fills from a zero that stays: a class built without RTTI whose
//! virtual base shares its vptr has zero offsets at `_ZTV` + two pointers, and
//! taking every zero there for a relocated method listed it, and `analyze`
//! persisted its vftable, three pointers before its vptr. A word this reader
//! missed would turn a relocated method back into a refusal, and a word it
//! invented would let the wrong address through again, so the set is checked
//! whole, against a tool that is not this crate.
//!
//! The expected set is every relocation offset `llvm-readobj --relocations`
//! printed for the fixtures in `fixtures/itanium_vtables/` (the recordings
//! beside them): `.rel(a).dyn` and `.rel(a).plt` entries, and `.relr.dyn`
//! entries, which it expands one word per line. Two fixtures are linked with
//! `-z pack-relative-relocs` (`vr-*`), one at each width, so the `RELR`
//! decoding is compared too; the static executables have no relocations, and
//! the set must be empty for them, not unread.
#![cfg(feature = "static-pe")]

use std::collections::BTreeSet;
use std::path::PathBuf;

use n0xis_contracts::Va;
use n0xis_sources::{RelocatedWords, RelocationsNotRead, ImageSource};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/itanium_vtables")
}

/// The relocation offsets `llvm-readobj -r` recorded for `image`.
fn recorded_offsets(image: &str) -> BTreeSet<u64> {
    let text = std::fs::read_to_string(fixtures().join(format!("{image}.readobj.txt"))).expect("a recording");
    text.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            let addr = w.next()?.strip_prefix("0x")?;
            w.next().filter(|k| k.starts_with("R_"))?;
            u64::from_str_radix(addr, 16).ok()
        })
        .collect()
}

#[test]
fn every_relocated_word_is_one_llvm_readobj_lists() {
    let mut images: Vec<String> = std::fs::read_dir(fixtures())
        .expect("the fixture directory")
        .filter_map(|e| e.ok()?.file_name().to_string_lossy().strip_suffix(".readobj.txt").map(str::to_string))
        .collect();
    images.sort();
    let (mut with_relocations, mut with_relr) = (0, 0);
    for image in &images {
        let elf = ImageSource::load(&fixtures().join(image)).unwrap_or_else(|e| panic!("{image}: {e}"));
        let RelocatedWords::Read { words, copies } = elf.relocated_words() else {
            panic!("{image}: an executable or shared object of a measured machine, read: {:?}", elf.relocated_words())
        };
        let read: BTreeSet<u64> = words.iter().copied().collect();
        assert_eq!(read.len(), words.len(), "{image}: sorted without repeats");
        assert_eq!(read, recorded_offsets(image), "{image}: the words llvm-readobj -r lists");
        assert!(copies.is_empty(), "{image}: no fixture has a copy relocation");
        with_relocations += usize::from(!read.is_empty());
        let recording = std::fs::read_to_string(fixtures().join(format!("{image}.readobj.txt"))).expect("a recording");
        with_relr += usize::from(recording.contains(".relr.dyn {"));
    }
    assert_eq!(images.len(), 34, "every fixture with a recording: {images:?}");
    assert_eq!(with_relr, 2, "the two packed-relocation shared objects");
    assert!(with_relocations >= 15, "the shared objects have relocations: {with_relocations}");
}

/// A word is written when a relocation starts at it or up to seven bytes
/// before it, or when a copy relocation's object covers it; where the
/// relocations were not read, any word may be.
#[test]
fn may_write_is_the_word_its_relocations_reach() {
    let read = RelocatedWords::Read { words: vec![0x1000, 0x2004], copies: vec![(0x3000, 0x3010)] };
    assert!(read.may_write(Va(0x1000), 8));
    assert!(read.may_write(Va(0x0ffc), 8), "the word ends after the relocation starts");
    assert!(read.may_write(Va(0x2000), 8) && read.may_write(Va(0x2008), 4), "a relocation at 0x2004 writes into both");
    assert!(!read.may_write(Va(0x1008), 8), "one that starts eight bytes before");
    assert!(!read.may_write(Va(0x0ff8), 8), "one that ends where it starts");
    assert!(read.may_write(Va(0x3008), 8) && !read.may_write(Va(0x3010), 8), "the copied object, and the word past it");
    assert!(RelocatedWords::NotRead(RelocationsNotRead::NoImage).may_write(Va(0x5000), 8));
}
