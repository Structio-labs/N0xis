// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`imports` says `not_read` where it did not read what an image needs,
//! and never answers such an image with a list.**
//!
//! `imports_are_what_llvm_readobj_lists.rs` checks the answer where the table
//! is read. This checks the images whose needs the reader does not read, each
//! planted in `fixtures/imports/not_read/` (`build.sh`) and each needing
//! something by the LLVM tools' account (`record.sh`), so that an empty or
//! partial `read` list would be a wrong answer, not a small one:
//!
//! - **a PE with a delay-load import table**, which the reader does not read.
//!   Measured before this test: a DLL delay-loading two functions from one
//!   library answered `read` with only its other library, and a DLL whose
//!   only import was delay-loaded answered `read` with nothing at all;
//! - **an ELF relocatable object**, which has no dynamic section: what it
//!   needs is its undefined `.symtab` symbols, resolved by a link editor.
//!   Measured before: `read`, with no library and no reference.
//!
//! And one whose list is read but a library's part of it is not:
//!
//! - **a PE32 whose import lookup table holds an entry the parser skips**
//!   (`unplaced-name-i686.exe`, planted by `plant.py`: the first entry of
//!   `planted.dll`'s table names its hint/name entry at an RVA in no
//!   section). goblin returns the library's other entry alone, and numbers
//!   its slot as the skipped one's. Measured before: `read`, `planted.dll`
//!   with one reference, by ordinal 7, at `0x404050`, which `llvm-objdump -p`
//!   gives as the first entry's slot (`by_name`'s); nothing said one was
//!   missing.
//!
//! Each is asked through the CLI, the way a user asks.

use std::path::{Path, PathBuf};
use std::process::Command;

use n0xis_contracts::Va;
use n0xis_sources::{Binding, ImageSource};
use serde_json::Value;

mod support;

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/imports/not_read")
}

fn recording(name: &str) -> String {
    let path = dir().join("recorded").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// `imports --file <fixture>`, through the CLI.
fn imports(fixture: &str) -> Value {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .args(["imports", "--file"])
        .arg(dir().join(fixture))
        .arg("--quiet")
        .current_dir(support::data_home())
        .output()
        .expect("run n0xis imports");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{fixture}: {e}: {}", String::from_utf8_lossy(&out.stdout)));
    assert_eq!(v["ok"], true, "{fixture}: {v}");
    assert_eq!(v["meta"]["schema"], "n0xis.imports.v1", "{fixture}");
    v
}

/// The reason the answer gives, which must name what was not read.
fn not_read_because(v: &Value, fixture: &str) -> String {
    let imports = &v["data"]["imports"];
    assert!(imports.get("read").is_none(), "{fixture}: answered as a list: {v}");
    let why = imports["not_read"]["why"].as_str().unwrap_or_else(|| panic!("{fixture}: neither read nor not_read: {v}"));
    assert!(!why.is_empty(), "{fixture}: a reason that says nothing");
    why.to_string()
}

/// The functions `llvm-readobj --coff-imports` lists in `DelayImport` blocks.
fn delay_loaded(readobj: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in readobj.lines() {
        if line.starts_with("DelayImport {") {
            inside = true;
        } else if line.starts_with('}') {
            inside = false;
        } else if inside && let Some(sym) = line.trim().strip_prefix("Symbol: ") {
            out.push(sym.split(" (").next().unwrap_or_default().to_string());
        }
    }
    out
}

#[test]
fn a_pe_with_a_delay_load_table_is_not_answered_with_its_ordinary_table() {
    for (fixture, delayed) in [("delay-x86_64.dll", vec!["n0x_later_a", "n0x_later_b"]), ("delay-only-x86_64.dll", vec!["n0x_later_a"])] {
        // The image needs these, by the tool's account.
        assert_eq!(delay_loaded(&recording(&format!("{fixture}.readobj.txt"))), delayed, "{fixture}: the recording");
        let v = imports(fixture);
        assert_eq!(v["data"]["format"], "pe", "{fixture}");
        let why = not_read_because(&v, fixture);
        assert!(why.contains("delay-load"), "{fixture}: the reason does not name the delay-load table: {why}");
    }
}

#[test]
fn a_relocatable_object_is_not_answered_as_needing_nothing() {
    let fixture = "relocatable-x86_64.o";
    assert!(recording(&format!("{fixture}.readobj.txt")).contains("Type: Relocatable (0x1)"), "the fixture is a relocatable object");
    let nm = recording(&format!("{fixture}.nm.txt"));
    let undefined: Vec<&str> = nm.lines().filter_map(|l| l.trim().strip_prefix("U ")).collect();
    assert_eq!(undefined, ["n0x_ext_data", "n0x_ext_fn"], "what the object needs, by llvm-nm");
    let v = imports(fixture);
    assert_eq!(v["data"]["format"], "elf");
    let why = not_read_because(&v, fixture);
    assert!(why.contains("ET_REL"), "the reason does not say what kind of file this is: {why}");
}

/// One library of `llvm-objdump -p`'s import tables: its name, its `addr`
/// (the import address table's RVA) and each entry as `(hint or ordinal,
/// name)`, the name empty for an import by ordinal.
type ImportTable = (String, u64, Vec<(u64, String)>);

/// `llvm-objdump -p`'s import tables, in order.
fn objdump_import_tables(text: &str) -> Vec<ImportTable> {
    let mut out: Vec<ImportTable> = Vec::new();
    let mut addr = 0;
    for line in text.lines().skip_while(|l| !l.starts_with("The Import Tables:")) {
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.first() == Some(&"lookup") {
            let at = words.iter().position(|w| *w == "addr").expect("an addr field") + 1;
            addr = u64::from_str_radix(words[at], 16).expect("a hex addr");
        } else if let Some(dll) = line.trim().strip_prefix("DLL Name: ") {
            out.push((dll.to_string(), addr, Vec::new()));
        } else if let (Some(n), Some(last)) = (words.first().and_then(|w| w.parse::<u64>().ok()), out.last_mut()) {
            last.2.push((n, words.get(1).copied().unwrap_or_default().to_string()));
        }
    }
    out
}

#[test]
fn a_lookup_table_the_parser_reads_short_says_which_entries_it_did_not_read() {
    let fixture = "unplaced-name-i686.exe";
    // The table, by two tools: llvm-objdump lists both of planted.dll's
    // entries (from the import address table, which the plant left alone),
    // and llvm-readobj, reading the lookup table, stops at the planted one.
    let tables = objdump_import_tables(&recording(&format!("{fixture}.objdump.txt")));
    let planted: Vec<(u64, String)> = vec![(0, "by_name".into()), (7, String::new())];
    assert_eq!(tables.len(), 2, "two libraries: {tables:?}");
    assert_eq!((tables[0].0.as_str(), &tables[0].2), ("planted.dll", &planted), "the recording");
    assert_eq!((tables[1].0.as_str(), tables[1].2.len()), ("KERNEL32.dll", 1), "the recording");
    assert!(recording(&format!("{fixture}.readobj.err.txt")).contains("RVA 0x7fff0000 for import symbol name not found"));
    let base = 0x400000;
    let ordinal_slot = base + tables[0].1 + 4; // entry 1 of a PE32 table
    let exit_process_slot = base + tables[1].1;

    let v = imports(fixture);
    let read = &v["data"]["imports"]["read"];
    assert!(read.is_object(), "the rest of the table is read and served: {v}");
    let libraries = read["libraries"].as_array().expect("libraries");
    let unread = libraries[0]["references_not_read"].as_array().expect("a list");
    assert_eq!(libraries[0]["name"], "planted.dll");
    assert_eq!(unread.len(), 1, "planted.dll says part of its table was not read: {v}");
    let why = unread[0]["why"].as_str().expect("a reason");
    assert!(why.contains("holds 2 entries") && why.contains("returned 1"), "the reason does not give the counts: {why}");
    assert!(why.contains("0x7fff0000"), "the reason does not name the entry it could not place: {why}");
    assert_eq!(libraries[1]["references_not_read"].as_array().map(Vec::len), Some(0), "KERNEL32.dll's table is read whole: {v}");

    let references = read["references"].as_array().expect("references");
    // No reference of planted.dll is served with a slot: the one the parser
    // returned carries the skipped entry's.
    for r in references.iter().filter(|r| r["library"]["binds"] == 0) {
        assert!(r["reach"].get("read").is_none(), "a planted.dll reference is served with a slot the parser numbered wrong: {r}");
        assert!(r["reach"]["not_read"]["why"].as_str().is_some_and(|w| !w.is_empty()), "{r}");
    }
    let exit_process = references.iter().find(|r| r["name"] == "ExitProcess").expect("ExitProcess is listed");
    assert_eq!(exit_process["reach"]["read"][0]["slot"], format!("{exit_process_slot:#x}"), "a library read whole keeps its slots");

    // The slot of the entry the parser's list moved is not known to be
    // unbound: it is bound, to ordinal 7, by the table. (The slot before it,
    // by_name's, still answers the parser's ordinal 7 through `binding_at`,
    // as 0.3.5 did: that answer is not changed in this step.)
    let img = ImageSource::load(&dir().join(fixture)).expect("the fixture loads");
    assert!(
        matches!(img.image().binding_at(Va(ordinal_slot)), Binding::NotRead { .. }),
        "{:#x}: {:?}",
        ordinal_slot,
        img.image().binding_at(Va(ordinal_slot))
    );
}

/// The recordings say what the tools say now.
#[cfg(feature = "oracle")]
#[test]
fn the_recordings_are_what_the_tools_print_now() {
    let run = |tool: &str, args: &[&str]| -> String {
        let out = Command::new(tool).args(args).current_dir(dir()).env("LC_ALL", "C").output().unwrap_or_else(|e| panic!("{tool}: {e}"));
        assert!(out.status.success(), "{tool} {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).expect("UTF-8")
    };
    for f in ["delay-x86_64.dll", "delay-only-x86_64.dll"] {
        assert_eq!(run("llvm-readobj", &["--coff-imports", f]), recording(&format!("{f}.readobj.txt")), "{f}");
    }
    let o = "relocatable-x86_64.o";
    assert_eq!(run("llvm-readobj", &["--file-headers", o]), recording(&format!("{o}.readobj.txt")));
    assert_eq!(run("llvm-nm", &["--undefined-only", o]), recording(&format!("{o}.nm.txt")));
    let f = "unplaced-name-i686.exe";
    assert_eq!(run("llvm-objdump", &["-p", f]), recording(&format!("{f}.objdump.txt")), "{f}");
    // llvm-readobj refuses the planted entry, so it is run for its failure.
    let out = Command::new("llvm-readobj").args(["--coff-imports", f]).current_dir(dir()).env("LC_ALL", "C").output().expect("llvm-readobj");
    assert!(!out.status.success(), "llvm-readobj read {f} whole");
    assert_eq!(String::from_utf8_lossy(&out.stdout), recording(&format!("{f}.readobj.txt")), "{f}");
    assert_eq!(String::from_utf8_lossy(&out.stderr), recording(&format!("{f}.readobj.err.txt")), "{f}");
}
