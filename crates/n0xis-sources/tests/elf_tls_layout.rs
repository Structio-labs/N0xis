// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A zero-filled TLS section takes no room in the image.**
//!
//! The linker gives `.tbss` the address the following sections also start at:
//! it describes each thread's zero-initialized TLS, which is allocated per
//! thread at run time, so it needs no room in the image. Until 2026-10-05 the
//! ELF source mapped it anyway, and because it comes first in the section
//! table it shadowed what lay under it: every read of `.init_array`,
//! `.fini_array`, the start of `.data.rel.ro` or `.dynamic` there came back
//! empty, with success. Measured on one system: 568 of 9 386 ELF files.
//!
//! The fixture `fixtures/tls_overlap.so` is built from `fixtures/tls_overlap.c`
//! (the command is in that file). Every number below was read from it with
//! binutils (`readelf -SW`, `readelf -x`, `nm`), not with this crate.
#![cfg(feature = "static-pe")]

use std::path::PathBuf;

use n0xis_contracts::Va;
use n0xis_sources::{MemorySource, StaticElf, SymbolProvider};

/// `.tbss`: address and size. It covers both arrays, `.data.rel.ro`, and the
/// first 0x10 bytes of `.dynamic`.
const TBSS: (u64, u64) = (0x3db0, 0x40);
const INIT_ARRAY: u64 = 0x3db0;
const FINI_ARRAY: u64 = 0x3dc0;
/// `.dynamic`: address and file offset.
const DYNAMIC: (u64, usize) = (0x3de0, 0x2de0);
/// What the arrays hold, per `nm`: the compiler's own entries, then the
/// constructor and destructor the source declares.
const FRAME_DUMMY: u64 = 0x1100;
const N0X_CTOR: u64 = 0x1144;
const DTORS_AUX: u64 = 0x10b0;
const N0X_DTOR: u64 = 0x1165;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls_overlap.so")
}

fn words(bytes: &[u8]) -> Vec<u64> {
    bytes.as_chunks::<8>().0.iter().map(|c| u64::from_le_bytes(*c)).collect()
}

#[test]
fn the_sections_under_a_tls_block_read_as_the_file_holds_them() {
    let elf = StaticElf::load(&fixture_path()).expect("the fixture loads");
    let init = elf.read(Va(INIT_ARRAY), 16).expect("readable");
    assert_eq!(words(&init), [FRAME_DUMMY, N0X_CTOR], ".init_array holds the declared constructor: {init:02x?}");
    let fini = elf.read(Va(FINI_ARRAY), 16).expect("readable");
    assert_eq!(words(&fini), [DTORS_AUX, N0X_DTOR], ".fini_array holds the declared destructor: {fini:02x?}");

    let file = std::fs::read(fixture_path()).expect("the fixture reads");
    let dynamic = elf.read(Va(DYNAMIC.0), 16).expect("readable");
    assert_eq!(dynamic, file[DYNAMIC.1..DYNAMIC.1 + 16], "the start of .dynamic, under the TLS block");

    // The numbers above are the fixture's own: its symbol table names them.
    assert_eq!(elf.symbol_at(Va(N0X_CTOR)).map(|s| s.name), Some("n0x_ctor".to_string()));
}

#[test]
fn the_tls_section_is_still_listed_as_the_table_has_it() {
    let elf = StaticElf::load(&fixture_path()).expect("the fixture loads");
    let tbss = elf.sections_detailed().into_iter().find(|s| s.0 == ".tbss").map(|s| (s.1 .0, s.2));
    assert_eq!(tbss, Some(TBSS), "a profile reports the section table as it is");
}
