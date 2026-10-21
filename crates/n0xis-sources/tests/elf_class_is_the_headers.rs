// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **An ELF image is as wide as its header says.**
//!
//! `e_ident[EI_CLASS]` is `ELFCLASS32` (1) or `ELFCLASS64` (2), and that is
//! the width of the image's data pointers (System V gABI, "ELF Identification").
//! The static image used to report every ELF as 64-bit with 8-byte pointers;
//! its first reader that trusted that for an ELF, the Itanium RTTI scan,
//! answered `ok: true` with no vtables on a 32-bit shared object.
//!
//! The expected width is `llvm-readobj`'s `Class` line, recorded beside each
//! fixture in `fixtures/itanium_vtables/` (built there from `vtables.cpp` for
//! i686, ARMv7 A32 and Thumb, x86-64, AArch64 and big-endian AArch64; from
//! `vbases.cpp`, `vbinline.cpp`, `external.cpp` and `vbindirect.cpp` for i686
//! and x86-64; from `vbnortti.cpp` for i686, x86-64 and ARMv7; from
//! `vtables.cpp` with packed relocations for i686 and x86-64; and from
//! `outside.cpp`, `notcode.cpp`, `flow.cpp` and `plugin.cpp` for x86-64), not
//! anything this crate reads. The byte order is checked the same way, against
//! its `DataEncoding` line, and whether the image is a program or a library
//! against its `Type` line and, where recorded, its program headers and
//! dynamic table.
#![cfg(feature = "static-pe")]

use std::path::PathBuf;

use n0xis_sources::{ByteOrder, ImageSource, Linkage, PointerWidth};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/itanium_vtables")
}

/// `(fixture, the class llvm-readobj recorded, its data encoding)`, for every
/// fixture there.
fn recorded_classes() -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(fixtures()).expect("the fixture directory") {
        let name = entry.expect("an entry").file_name().to_string_lossy().into_owned();
        let Some(image) = name.strip_suffix(".readobj.txt") else { continue };
        let text = std::fs::read_to_string(fixtures().join(&name)).expect("a recording");
        let class = text.lines().find_map(|l| l.trim().strip_prefix("Class: ")).unwrap_or_else(|| panic!("{name}: no Class line"));
        let encoding =
            text.lines().find_map(|l| l.trim().strip_prefix("DataEncoding: ")).unwrap_or_else(|| panic!("{name}: no DataEncoding line"));
        out.push((image.to_string(), class.to_string(), encoding.to_string()));
    }
    out.sort();
    out
}

#[test]
fn the_pointer_size_is_the_elf_class() {
    let recorded = recorded_classes();
    // Five targets, a shared object and an executable each; a big-endian shared
    // object; two with virtual bases; four with virtual bases and no VTT; one
    // with a method in another code section and one with a method outside the
    // code; two with a base in another image; one with constructions on
    // different paths; five built without RTTI with a virtual base; two with
    // an indirect virtual base; two with packed relative relocations; a class
    // nothing derives from as a shared object, an executable and a
    // position-independent executable: a directory that lost its recordings
    // must not pass by checking nothing.
    assert_eq!(recorded.len(), 34, "{recorded:?}");
    for (image, class, encoding) in &recorded {
        let path = fixtures().join(image);
        let want: u8 = match class.as_str() {
            "32-bit (0x1)" => 4,
            "64-bit (0x2)" => 8,
            other => panic!("{image}: llvm-readobj's Class is {other}"),
        };
        let img = ImageSource::load(&path).expect("the fixture loads");
        // The reader's own answer...
        let elf = img.image().machine();
        assert_eq!(elf.pointer_width.bytes(), want, "{image}: llvm-readobj says Class {class}");
        assert_eq!(elf.pointer_width == PointerWidth::Eight, want == 8, "{image}");
        // ...and the adapter's, which is what every front end asks.
        assert_eq!((img.pointer_size(), img.is_64()), (want, want == 8), "{image}: through ImageSource");
        let order = match encoding.as_str() {
            "LittleEndian (0x1)" => ByteOrder::Little,
            "BigEndian (0x2)" => ByteOrder::Big,
            other => panic!("{image}: llvm-readobj's DataEncoding is {other}"),
        };
        assert_eq!((elf.byte_order, img.byte_order()), (order, order), "{image}: llvm-readobj says DataEncoding {encoding}");
    }
    // The set must hold both byte orders, or the check above proves one.
    assert!(recorded.iter().any(|(_, _, e)| e.starts_with("BigEndian")), "a big-endian fixture");
}

/// **A program or a library is what the headers say.** An `ET_EXEC` is a
/// program; an `ET_DYN` is one when it says so (`DF_1_PIE`, or a `PT_INTERP`
/// and no `DT_SONAME`), and a library otherwise. The expected answer is
/// `llvm-readobj`'s `Type` line and, for the `vp-*` fixtures, whose recordings
/// hold them, the program headers and the dynamic table. Every other `ET_DYN`
/// here is one `build.sh` links `-shared` and names `.so`.
#[test]
fn a_program_or_a_library_is_what_the_headers_say() {
    let (mut checked, mut dyn_programs) = (0, 0);
    for entry in std::fs::read_dir(fixtures()).expect("the fixture directory") {
        let name = entry.expect("an entry").file_name().to_string_lossy().into_owned();
        let Some(image) = name.strip_suffix(".readobj.txt") else { continue };
        let text = std::fs::read_to_string(fixtures().join(&name)).expect("a recording");
        // The file header comes first, so its `Type` is the first.
        let kind = text.lines().find_map(|l| l.trim().strip_prefix("Type: ")).unwrap_or_else(|| panic!("{name}: no Type line"));
        let want = match kind {
            "Executable (0x2)" => Linkage::Executable,
            "SharedObject (0x3)" if text.contains("DynamicSection [") => {
                let pie = text.lines().any(|l| l.split_whitespace().nth(1) == Some("FLAGS_1") && l.split_whitespace().any(|w| w == "PIE"));
                let interp = text.lines().any(|l| l.trim() == "Type: PT_INTERP (0x3)");
                let soname = text.lines().any(|l| l.split_whitespace().nth(1) == Some("SONAME"));
                if pie || (interp && !soname) {
                    dyn_programs += 1;
                    Linkage::Executable
                } else {
                    Linkage::SharedLibrary
                }
            }
            "SharedObject (0x3)" => {
                assert!(image.ends_with(".so"), "{image}: an ET_DYN recorded without its dynamic table must be one build.sh links -shared");
                Linkage::SharedLibrary
            }
            other => panic!("{image}: llvm-readobj's Type is {other}"),
        };
        let path = fixtures().join(image);
        let img = ImageSource::load(&path).expect("the fixture loads");
        assert_eq!(img.image().linkage(), want, "{image}: llvm-readobj says Type {kind}");
        assert_eq!(img.linkage(), want, "{image}: through ImageSource");
        checked += 1;
    }
    assert_eq!(checked, 34, "every fixture");
    // Without it, a reader that took every ET_DYN for a library would pass.
    assert_eq!(dyn_programs, 1, "the position-independent executable");
}
