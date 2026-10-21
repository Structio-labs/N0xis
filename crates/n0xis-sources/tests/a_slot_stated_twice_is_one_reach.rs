// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A relocation the dynamic table states twice is one way to reach an
//! import, not two.**
//!
//! A dynamic section may give `DT_RELASZ` a size that also covers the
//! `DT_JMPREL` entries that follow `DT_RELA` (the loader accepts the layout,
//! and the reader's parser then hands every jump-slot relocation over in both
//! lists). The planted copy here is `n0xis-cli`'s
//! `fixtures/imports/imports-x86_64.so` with exactly that one change, made by
//! [`plant`] from the file's own program and dynamic headers: `DT_RELASZ`
//! grows by `DT_PLTRELSZ`, which it may only where the jump-slot table starts
//! where the other one ends, and that is checked first.
//!
//! The relocations, and so the slots and the stubs through them, are the
//! file's, unchanged, so the reach of every import must be what the
//! unmodified file answers. Before this test each import of the planted copy
//! was reached through its slot twice and its stub twice (`puts`: slot
//! `0x4000`, slot `0x4000`, stub `0x1030`, stub `0x1030`).
#![cfg(feature = "static-pe")]

use std::path::PathBuf;

use n0xis_sources::{Answer, ImageSource, Imports};

const DT_PLTRELSZ: u64 = 2;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_JMPREL: u64 = 23;
const PT_DYNAMIC: u32 = 2;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../n0xis-cli/tests/fixtures/imports/imports-x86_64.so")
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// The file with `DT_RELASZ` widened over the `DT_JMPREL` table, read from the
/// ELF64 little-endian headers by hand rather than by the parser under test.
fn plant(mut b: Vec<u8>) -> Vec<u8> {
    assert_eq!(&b[..6], b"\x7fELF\x02\x01", "an ELF64 little-endian fixture");
    let (phoff, phentsize, phnum) = (u64_at(&b, 0x20) as usize, u16_at(&b, 0x36) as usize, u16_at(&b, 0x38) as usize);
    let dynamic = (0..phnum)
        .map(|i| phoff + i * phentsize)
        .find(|&ph| u32_at(&b, ph) == PT_DYNAMIC)
        .map(|ph| (u64_at(&b, ph + 8) as usize, u64_at(&b, ph + 0x20) as usize))
        .expect("a PT_DYNAMIC segment");
    let entries: Vec<(usize, u64, u64)> = (0..dynamic.1 / 16).map(|i| dynamic.0 + 16 * i).map(|at| (at, u64_at(&b, at), u64_at(&b, at + 8))).collect();
    let tag = |t: u64| entries.iter().find(|e| e.1 == t).copied().unwrap_or_else(|| panic!("no dynamic tag {t}"));
    let (rela, relasz, jmprel, pltrelsz) = (tag(DT_RELA).2, tag(DT_RELASZ), tag(DT_JMPREL).2, tag(DT_PLTRELSZ).2);
    assert_eq!(rela + relasz.2, jmprel, "the jump-slot table starts where DT_RELA's ends, so one size may cover both");
    b[relasz.0 + 8..relasz.0 + 16].copy_from_slice(&(relasz.2 + pltrelsz).to_le_bytes());
    b
}

fn imports(img: &ImageSource) -> &Imports {
    match img.image().imports() {
        Answer::Read(imports) => imports,
        other => panic!("a shared object's imports are read: {other:?}"),
    }
}

#[test]
fn every_import_is_reached_as_the_unmodified_file_reaches_it() {
    let original_bytes = std::fs::read(fixture()).expect("the fixture");
    let planted = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("imports-x86_64-relasz-covers-jmprel.so");
    std::fs::write(&planted, plant(original_bytes)).expect("write the planted copy");

    let original = ImageSource::load(&fixture()).expect("the fixture loads");
    let overlapped = ImageSource::load(&planted).expect("the planted copy loads");
    let (want, got) = (imports(&original), imports(&overlapped));
    assert_eq!(got.references.len(), want.references.len());
    let mut reached = 0;
    for (g, w) in got.references.iter().zip(&want.references) {
        assert_eq!(g, w, "a reference of the planted copy, against the unmodified file's");
        if let Answer::Read(reach) = &g.reach {
            reached += reach.len();
            for (i, r) in reach.iter().enumerate() {
                assert!(!reach[..i].contains(r), "{:?} is reached through {r:?} twice: {reach:?}", g.name);
            }
        }
    }
    // A planted copy whose imports are reached through nothing would pass the
    // comparison above by having nothing to repeat.
    assert!(reached >= 6, "slots and stubs compared: {reached}");
    let _ = std::fs::remove_file(&planted);
}
