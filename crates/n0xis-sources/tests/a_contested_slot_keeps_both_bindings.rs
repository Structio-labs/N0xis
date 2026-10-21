// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A slot two relocations bind keeps both bindings.**
//!
//! `fixtures/contested_slot/contested-x86_64.so` is a shared object whose two
//! `JUMP_SLOT` relocations, one against the undefined `n0x_ext_fn` and one
//! against its own `n0x_local_fn`, were planted at one slot (`plant.py`). No
//! linker emits that, but a file can say it, and this tool reads files built
//! to mislead it. Before the format seam the ELF reader kept the two facts in
//! two maps and answered both: the PLT entry that jumps through the slot was
//! named after the import, and it forwarded to the definition. The first cut
//! of `binding_at` held one binding per slot, the import's, and the
//! forwarding answer was gone — the only answer the seam changed on a sweep
//! of planted and system images, and a step that must change none.
//!
//! The facts are the LLVM tools', recorded beside the fixture (`record.sh`):
//! `llvm-readobj -r` puts both relocations at one offset, `llvm-objdump -d`
//! names the PLT entry that jumps through it, and `llvm-nm` places
//! `n0x_local_fn`.
#![cfg(feature = "static-pe")]

use std::path::PathBuf;

use n0xis_contracts::Va;
use n0xis_sources::{Binding, Finding, ImageSource, ImportName, SymbolProvider};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/contested_slot")
}

fn recording(ext: &str) -> String {
    std::fs::read_to_string(dir().join(format!("contested-x86_64.so.{ext}.txt"))).expect("a recording")
}

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).unwrap_or_else(|e| panic!("{s:?}: {e}"))
}

/// What the tools say: the slot both relocations name, the PLT entry whose
/// jump goes through it, and the address of the definition.
struct Stated {
    slot: u64,
    stub: u64,
    definition: u64,
}

fn stated() -> Stated {
    let relocs = recording("readobj");
    let jump_slots: Vec<(u64, &str)> = relocs
        .lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            (w.len() >= 3 && w[1] == "R_X86_64_JUMP_SLOT").then(|| (hex(w[0]), w[2]))
        })
        .collect();
    let at = |name: &str| jump_slots.iter().find(|(_, n)| *n == name).map(|(s, _)| *s).unwrap_or_else(|| panic!("no JUMP_SLOT against {name}"));
    let slot = at("n0x_local_fn");
    assert_eq!(at("n0x_ext_fn"), slot, "the fixture is planted: both relocations name one slot ({relocs})");
    assert_eq!(jump_slots.len(), 2, "{relocs}");

    // `    1030:      	jmpq	*0x2fca(%rip)           # 0x4000 <...>`
    let plt = recording("plt");
    let stub = plt
        .lines()
        .find(|l| l.contains("jmpq\t*") && l.contains(&format!("# {slot:#x} ")))
        .and_then(|l| l.trim().split(':').next())
        .map(hex)
        .unwrap_or_else(|| panic!("no PLT entry jumps through {slot:#x}: {plt}"));

    let nm = recording("nm");
    let definition = nm
        .lines()
        .find_map(|l| l.strip_suffix(" T n0x_local_fn"))
        .map(hex)
        .unwrap_or_else(|| panic!("llvm-nm places no n0x_local_fn: {nm}"));
    Stated { slot, stub, definition }
}

#[test]
fn the_slot_is_bound_to_the_import_and_to_the_definition() {
    let s = stated();
    let img = ImageSource::load(&dir().join("contested-x86_64.so")).expect("the fixture loads");
    match img.image().binding_at(Va(s.slot)) {
        Binding::ImportAndSelfDefinition { import, target } => {
            assert_eq!(import.name, ImportName::Named("n0x_ext_fn".into()));
            assert_eq!(target, Va(s.definition), "the definition llvm-nm places");
        }
        other => panic!("the slot at {:#x} is bound by both relocations, answered {other:?}", s.slot),
    }
    // The answers built on it, both of them, as the reader gave them before
    // the format seam.
    assert_eq!(img.thunk_to(Va(s.stub)), Some(Va(s.definition)), "the PLT entry at {:#x} forwards to the definition", s.stub);
    assert_eq!(img.symbol_at(Va(s.stub)).map(|sym| sym.name), Some("n0x_ext_fn".to_string()), "and is named after the import");
    assert_eq!(img.iat_slot(Va(s.slot)).map(|sym| sym.name), Some("n0x_ext_fn".to_string()), "the slot is an import slot");
    // And the image says the two disagree, rather than nothing.
    let said = img.image().findings().iter().any(|f| matches!(f, Finding::Contradiction { what } if what.contains(&format!("{:#x}", s.slot))));
    assert!(said, "no finding names the contested slot: {:?}", img.image().findings());
}

/// The control: a shared object of the committed fixtures whose relocations
/// name every slot once has no contradiction to report.
#[test]
fn an_image_whose_slots_are_named_once_reports_no_contradiction() {
    let so = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../n0xis-cli/tests/fixtures/imports/imports-x86_64.so");
    let img = ImageSource::load(&so).expect("the fixture loads");
    assert!(img.image().findings().is_empty(), "{:?}", img.image().findings());
}

/// The recordings say what the tools say now.
#[cfg(feature = "oracle")]
#[test]
fn the_recordings_are_what_the_tools_print_now() {
    use std::process::Command;
    let run = |tool: &str, args: &[&str]| -> String {
        let out = Command::new(tool).args(args).current_dir(dir()).env("LC_ALL", "C").output().unwrap_or_else(|e| panic!("{tool}: {e}"));
        assert!(out.status.success(), "{tool} {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).expect("UTF-8")
    };
    let so = "contested-x86_64.so";
    assert_eq!(run("llvm-readobj", &["--relocations", so]), recording("readobj"));
    assert_eq!(run("llvm-nm", &["--defined-only", so]), recording("nm"));
    assert_eq!(run("llvm-objdump", &["-d", "--no-show-raw-insn", "-j", ".plt", so]), recording("plt"));
}
