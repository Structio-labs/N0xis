// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A PDB whose contents are known before the reader runs (`fixtures/README.md`
//! says from where each fact comes): its identity matches the image's CodeView
//! record, and every function of the source is placed where the toolchain put
//! it, with the length the compiler stated.

use n0xis_pdb::{Function, read};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)).expect("the fixture")
}

#[test]
fn the_identity_is_the_one_the_image_records() {
    let contents = read(fixture("pdbtarget.pdb")).expect("a readable PDB");
    assert_eq!(contents.identity.guid.to_string(), "90BA008E-0CF5-2548-4C4C-44205044422E");
    assert_eq!(contents.identity.age, 1);
    assert_eq!(contents.identity.store_key(), "90BA008E0CF525484C4C44205044422E1");
    assert_eq!(n0xis_pdb::identity(fixture("pdbtarget.pdb")).expect("the identity alone"), contents.identity);
}

#[test]
fn every_function_of_the_source_is_placed_with_its_stated_length() {
    let contents = read(fixture("pdbtarget.pdb")).expect("a readable PDB");
    let at = |name: &str| -> &Function {
        contents.functions.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("{name} is not among the PDB's functions"))
    };
    for (name, rva, len) in [
        ("record_failure", 0x1580, 7),
        ("doubled_timeout", 0x1590, 10),
        ("state_of", 0x15a0, 34),
        ("main", 0x15d0, 139),
        // A static: only its module's stream holds it.
        ("helper_static", 0x1660, 6),
    ] {
        let f = at(name);
        assert_eq!((f.rva, f.len, f.aliases), (rva, Some(len), 0), "{name}");
    }
    // `llvm-pdbutil dump --publics`: 43 publics flagged as functions, at 42
    // addresses. Four of those addresses also have a procedure record (the
    // globals above); the runtime's 38 come from the public table alone, placed
    // and named with no length. Add the static, and that is 43 entries.
    let unmeasured = contents.functions.iter().filter(|f| f.len.is_none()).count();
    assert_eq!((contents.functions.len(), unmeasured), (43, 38));
    // The one address with two names: the runtime's `_fpreset`, also `fpreset`.
    let folded: Vec<&Function> = contents.functions.iter().filter(|f| f.aliases > 0).collect();
    assert_eq!(folded.len(), 1);
    assert_eq!((folded[0].rva, folded[0].name.as_str(), folded[0].aliases), (0x2230, "_fpreset", 1));
    assert_eq!(contents.skipped, Default::default(), "a well-formed PDB has nothing left out");
    // One entry per address, in order.
    assert!(contents.functions.windows(2).all(|w| w[0].rva < w[1].rva));
}
