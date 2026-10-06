// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! An image's CodeView record, read as `llvm-readobj --coff-debug-directory`
//! prints it: the GUID and age a PDB must carry to belong to the image, and the
//! file name the linker wrote. An image built without one says so.

#![cfg(feature = "static-pe")]

use std::path::Path;

use n0xis_sources::StaticPe;

fn repo(path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(path)
}

#[test]
fn an_image_names_the_pdb_built_with_it() {
    let pe = StaticPe::load(&repo("crates/n0xis-pdb/tests/fixtures/pdbtarget.exe")).expect("the fixture");
    let cv = pe.codeview().expect("a CodeView record");
    // {90BA008E-0CF5-2548-4C4C-44205044422E}: the first three fields
    // little-endian, the last eight bytes as printed.
    let guid = [0x8E, 0x00, 0xBA, 0x90, 0xF5, 0x0C, 0x48, 0x25, 0x4C, 0x4C, 0x44, 0x20, 0x50, 0x44, 0x42, 0x2E];
    assert_eq!((cv.guid, cv.age, cv.pdb_path.as_str()), (guid, 1, "pdbtarget.pdb"));
}

#[test]
fn an_image_built_without_debug_information_names_none() {
    let pe = StaticPe::load(&repo("crates/n0xis-cli/tests/fixtures/native_pe.dll")).expect("the fixture");
    assert_eq!(pe.codeview(), None);
}
