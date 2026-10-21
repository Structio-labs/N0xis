// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A slot whose binding was not read is answered `NotRead`, never
//! `Unbound`.**
//!
//! `binding_at` answers what the loader binds a slot to. Where the reader
//! skipped a table that binds slots, "no table I read binds it" is not "the
//! slot is unbound", and the two must be different answers (IMAGE_FORMATS.md
//! §2: "not read" and "none" are different values). Before this test both
//! images below answered `Unbound` for a slot the LLVM tools show bound,
//! while each image's own `imports()` said the same table was not read:
//!
//! - `fixtures/unmapped_machine/unmapped-riscv64.so`, built here for RISC-V,
//!   a machine whose `GLOB_DAT` and `JUMP_SLOT` relocation types the reader
//!   does not map: `llvm-readobj -r` binds one slot to `n0x_ext_fn` with an
//!   `R_RISCV_JUMP_SLOT`;
//! - `n0xis-cli`'s `fixtures/imports/not_read/delay-x86_64.dll`, whose
//!   delay-load import table (not read) binds two slots, by
//!   `llvm-readobj --coff-imports`.
//!
//! Every consumer reads both answers the same way (no import, no forwarding
//! target), so no other answer changes; what changes is that the query says
//! what it does not know.
#![cfg(feature = "static-pe")]

use std::path::PathBuf;

use n0xis_contracts::Va;
use n0xis_sources::{Answer, Binding, ImageSource, ImportName, SymbolProvider};

fn here() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/unmapped_machine")
}

fn delay_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../n0xis-cli/tests/fixtures/imports/not_read")
}

fn read(path: PathBuf) -> String {
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).unwrap_or_else(|e| panic!("{s:?}: {e}"))
}

#[test]
fn a_jump_slot_of_a_machine_whose_relocations_are_not_read_is_not_unbound() {
    let recorded = read(here().join("unmapped-riscv64.so.readobj.txt"));
    assert!(recorded.contains("Machine: EM_RISCV (0xF3)"), "the fixture is for RISC-V: {recorded}");
    // `    0x34B0 R_RISCV_JUMP_SLOT n0x_ext_fn 0x0`
    let slot = recorded
        .lines()
        .find_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            (w.len() >= 3 && w[1] == "R_RISCV_JUMP_SLOT" && w[2] == "n0x_ext_fn").then(|| hex(w[0]))
        })
        .unwrap_or_else(|| panic!("llvm-readobj binds no slot to n0x_ext_fn: {recorded}"));

    let img = ImageSource::load(&here().join("unmapped-riscv64.so")).expect("the fixture loads");
    match img.image().binding_at(Va(slot)) {
        Binding::NotRead { why } => assert!(why.contains("0xf3"), "the reason names the machine: {why}"),
        other => panic!("the slot at {slot:#x}, which llvm-readobj binds to n0x_ext_fn, answered {other:?}"),
    }
    // The image's import list says the same of the same slot, for the same
    // reason: one fact, two questions.
    let Answer::Read(imports) = img.image().imports() else { panic!("a shared object's imports are read: {:?}", img.image().imports()) };
    let reference = imports
        .references
        .iter()
        .find(|r| r.name == ImportName::Named("n0x_ext_fn".into()))
        .unwrap_or_else(|| panic!("n0x_ext_fn is not listed: {imports:?}"));
    let (Answer::NotRead { why: listed }, Binding::NotRead { why: bound }) = (&reference.reach, img.image().binding_at(Va(slot))) else {
        panic!("{reference:?}");
    };
    assert_eq!(listed, &bound, "the list and the slot give one reason");
    // And no answer built on it changed: no import is named at the slot.
    assert!(img.iat_slot(Va(slot)).is_none(), "{:?}", img.iat_slot(Va(slot)));
}

#[test]
fn a_slot_of_a_delay_load_table_that_is_not_read_is_not_unbound() {
    let recorded = read(delay_dir().join("recorded/delay-x86_64.dll.readobj.txt"));
    // The ordinary table's slot: the descriptor's IAT, first entry. Asked
    // first, at the image's own base, so a wrong base fails here, on a slot
    // the reader reads, and not as a `NotRead` below.
    let ordinary = recorded
        .lines()
        .find_map(|l| l.trim().strip_prefix("ImportAddressTableRVA:"))
        .map(hex)
        .expect("the ordinary descriptor's IAT");
    // `ImportAddressTable: 0x3008` in the `DelayImport` block (its
    // `Attributes: 0x1` says the fields are RVAs), two 8-byte entries.
    let delay_block: String = recorded.lines().skip_while(|l| !l.starts_with("DelayImport {")).map(|l| format!("{l}\n")).collect();
    assert!(delay_block.contains("Attributes: 0x1"), "RVA-based delay descriptor: {delay_block}");
    let delay_iat = delay_block.lines().find_map(|l| l.trim().strip_prefix("ImportAddressTable:")).map(hex).expect("a delay IAT");
    assert_eq!(delay_block.matches("Symbol: ").count(), 2, "{delay_block}");

    let img = ImageSource::load(&delay_dir().join("delay-x86_64.dll")).expect("the fixture loads");
    let base = img.image_base().0;
    match img.image().binding_at(Va(base + ordinary)) {
        Binding::Import(import) => assert_eq!(import.name, ImportName::Named("n0x_now".into())),
        other => panic!("the ordinary table's slot answered {other:?}"),
    }
    for i in 0..2u64 {
        let slot = base + delay_iat + 8 * i;
        match img.image().binding_at(Va(slot)) {
            Binding::NotRead { why } => assert!(why.contains("delay-load"), "the reason names the table not read: {why}"),
            other => panic!("the delay-load slot at {slot:#x} answered {other:?}"),
        }
    }
}

/// `n0xis-cli`'s `fixtures/imports/ordinals-i686.exe` with one change: the
/// `KERNEL32.dll` descriptor's import lookup table moved to the last two bytes
/// of the file, so that its first entry runs past the end. A strict parse
/// refuses that, the permissive one stops at it, and the slot that table
/// fills (`ImportAddressTableRVA`, by `llvm-readobj --coff-imports`) is bound
/// by a table that was not read. Located from the file's own headers, read by
/// hand rather than by the parser under test.
fn plant_an_import_table_that_runs_past_the_file(mut b: Vec<u8>, ilt_rva: u32) -> Vec<u8> {
    let u16_at = |b: &[u8], at: usize| u16::from_le_bytes(b[at..at + 2].try_into().unwrap());
    let u32_at = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    let lfanew = u32_at(&b, 0x3c) as usize;
    let (sections, opt_size) = (u16_at(&b, lfanew + 6) as usize, u16_at(&b, lfanew + 20) as usize);
    let opt = lfanew + 24;
    assert_eq!(u16_at(&b, opt), 0x10b, "a PE32");
    let import_rva = u32_at(&b, opt + 96 + 8);
    // (va, virtual size, raw pointer, raw size) of each section.
    let table: Vec<(u32, u32, u32, u32)> = (0..sections)
        .map(|i| opt + opt_size + 40 * i)
        .map(|s| (u32_at(&b, s + 12), u32_at(&b, s + 8), u32_at(&b, s + 20), u32_at(&b, s + 16)))
        .collect();
    let offset_of = |rva: u32| {
        table.iter().find(|(va, vs, _, rs)| rva >= *va && rva < va + (*vs).max(*rs)).map(|(va, _, rp, _)| (rva - va + rp) as usize).expect("an RVA in a section")
    };
    let last = table.iter().max_by_key(|(_, _, rp, rs)| rp + rs).expect("a section");
    assert_eq!((last.2 + last.3) as usize, b.len(), "the last section's raw data ends the file");
    let two_before_the_end = last.0 + last.3 - 2;
    let descriptors = offset_of(import_rva);
    let descriptor = (0..)
        .map(|i| descriptors + 20 * i)
        .take_while(|&d| u32_at(&b, d) != 0)
        .find(|&d| u32_at(&b, d) == ilt_rva)
        .expect("the descriptor whose lookup table llvm-readobj names");
    b[descriptor..descriptor + 4].copy_from_slice(&two_before_the_end.to_le_bytes());
    b
}

#[test]
fn a_slot_of_an_import_table_only_a_permissive_parse_opened_is_not_unbound() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../n0xis-cli/tests/fixtures/imports");
    let recorded = read(dir.join("recorded/ordinals-i686.exe.readobj.txt"));
    let base = recorded.lines().find_map(|l| l.trim().strip_prefix("ImageBase:")).map(hex).expect("an ImageBase");
    let kernel32: Vec<&str> = recorded.lines().skip_while(|l| l.trim() != "Name: KERNEL32.dll").take(4).collect();
    let field = |key: &str| kernel32.iter().find_map(|l| l.trim().strip_prefix(key)).map(hex).unwrap_or_else(|| panic!("{key} {kernel32:?}"));
    let (ilt, iat) = (field("ImportLookupTableRVA:"), field("ImportAddressTableRVA:"));
    assert!(kernel32.iter().any(|l| l.trim().starts_with("Symbol: ExitProcess")), "{kernel32:?}");

    let planted = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ordinals-i686-lookup-table-past-the-file.exe");
    let bytes = plant_an_import_table_that_runs_past_the_file(std::fs::read(dir.join("ordinals-i686.exe")).expect("the fixture"), ilt as u32);
    std::fs::write(&planted, bytes).expect("write the planted copy");
    let img = ImageSource::load(&planted).expect("a permissive parse opens it");
    assert!(img.degraded().is_some(), "the planted copy is refused by the strict parse");
    match img.image().binding_at(Va(base + iat)) {
        Binding::NotRead { why } => assert!(why.contains("strict parse"), "the reason names the refused parse: {why}"),
        other => panic!("ExitProcess's slot at {:#x}, in a table that did not parse, answered {other:?}", base + iat),
    }
    let _ = std::fs::remove_file(&planted);
}

/// The control, so that the three above are not passing because every slot is
/// now `NotRead`: an image whose tables are all read answers an address no
/// relocation names as `Unbound`.
#[test]
fn an_image_whose_tables_are_read_answers_an_unnamed_slot_unbound() {
    let so = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../n0xis-cli/tests/fixtures/imports/imports-x86_64.so");
    let img = ImageSource::load(&so).expect("the fixture loads");
    assert!(matches!(img.image().binding_at(Va(0x1)), Binding::Unbound { .. }), "{:?}", img.image().binding_at(Va(0x1)));
}

/// The recording says what the tool says now.
#[cfg(feature = "oracle")]
#[test]
fn the_recording_is_what_the_tool_prints_now() {
    let out = std::process::Command::new("llvm-readobj")
        .args(["--file-headers", "--relocations", "unmapped-riscv64.so"])
        .current_dir(here())
        .env("LC_ALL", "C")
        .output()
        .expect("llvm-readobj");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8(out.stdout).expect("UTF-8"), read(here().join("unmapped-riscv64.so.readobj.txt")));
}
