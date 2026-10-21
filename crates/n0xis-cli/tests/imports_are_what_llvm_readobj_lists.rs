// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`imports` lists what `llvm-readobj` lists.**
//!
//! The command is new, and its only other test would be itself. So every
//! fixture in `fixtures/imports/fixtures.txt` — three planted for it (a PE32
//! importing by name and by ordinal only, the library it imports from, and a
//! shared object needing two libraries in a stated order, importing from each
//! by a versioned name) and
//! the committed PE and ELF fixtures of the other tests — is asked through
//! the CLI, and the answer is compared with what the LLVM tools recorded
//! beside it (`fixtures/imports/record.sh`):
//!
//! - **a PE** against `llvm-readobj --coff-imports`: each descriptor in order,
//!   each entry's name or ordinal in order, and its slot — the descriptor's
//!   import address table plus the entry's index times the pointer size, at
//!   the image base `--file-headers` states;
//! - **an ELF** against `llvm-readobj`: the libraries are its `DT_NEEDED`
//!   entries in the order the dynamic table holds them (`--needed-libs` sorts
//!   them, so it is checked as the set), and the references are the undefined
//!   dynamic symbols, each attributed to the file its version requirement
//!   names (`--version-info`), reached through the slots its `GLOB_DAT` and
//!   `JUMP_SLOT` relocations name (`--relocations`) and, on x86-64, through
//!   the PLT entries `llvm-objdump` names after it.
//!
//! **A recorded gap, which the answer states:** the engine decodes PLT stubs
//! on x86-64 only. On the other machines `llvm-objdump` names PLT entries and
//! the engine lists none as a reach, and the answer says so in
//! `reach_not_read`; both are asserted, and so is the converse (no such
//! statement where the stubs are decoded or there are none), so the day the
//! engine decodes them this test fails and the expectation is changed on
//! purpose. Every fixture's libraries say none of their entries went unread.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use n0xis_contracts::Va;
use n0xis_sources::{Answer, Binding, ImageSource, LibraryRef, Reach, SymbolProvider};
use serde_json::Value;

mod support;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures() -> Vec<String> {
    let list = std::fs::read_to_string(repo().join("crates/n0xis-cli/tests/fixtures/imports/fixtures.txt")).expect("the fixture list");
    list.lines().filter(|l| !l.trim().is_empty()).map(str::to_string).collect()
}

fn recording(fixture: &str, ext: &str) -> String {
    let name = Path::new(fixture).file_name().and_then(|n| n.to_str()).expect("a file name");
    let path = repo().join("crates/n0xis-cli/tests/fixtures/imports/recorded").join(format!("{name}.{ext}.txt"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Name {
    Named(String),
    Ordinal(u64),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Lib {
    Binds(usize),
    Named(usize),
    Unattributed,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Reference {
    name: Name,
    library: Lib,
    slots: BTreeSet<u64>,
    stubs: BTreeSet<u64>,
}

#[derive(Debug, PartialEq, Eq)]
struct Answered {
    format: String,
    binding: String,
    libraries: Vec<(String, String)>,
    references: Vec<Reference>,
}

/// What an answer says it did not read: the parts of `reach_not_read`, and
/// every library's `references_not_read` entries.
#[derive(Debug, Default)]
struct Unread {
    reach: Vec<String>,
    library_entries: usize,
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.trim().strip_prefix(key).map(str::trim)
}

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).unwrap_or_else(|e| panic!("{s:?}: {e}"))
}

/// A PE's answer, as `llvm-readobj --file-headers --coff-imports` states it.
fn pe_expected(text: &str) -> Answered {
    let ptr: u64 = if text.lines().any(|l| l.trim() == "AddressSize: 64bit") { 8 } else { 4 };
    let base = text.lines().find_map(|l| field(l, "ImageBase:")).map(hex).expect("an ImageBase line");
    assert!(!text.contains("DelayImport {"), "a delay-load import table, which the engine does not read: record it as such first");
    let mut libraries = Vec::new();
    let mut references = Vec::new();
    let mut iat = None;
    let mut index = 0u64;
    for line in text.lines() {
        if let Some(name) = field(line, "Name:")
            && line.starts_with("  Name:")
        {
            libraries.push((name.to_string(), "import_descriptor".to_string()));
            index = 0;
        } else if let Some(rva) = field(line, "ImportAddressTableRVA:") {
            iat = Some(hex(rva));
        } else if let Some(symbol) = field(line, "Symbol:") {
            // `Symbol: <name> (<hint>)`; an import by ordinal has no name and
            // prints its ordinal in the parentheses.
            let (name, n) = symbol.rsplit_once(" (").map(|(a, b)| (a.trim(), b.trim_end_matches(')'))).unwrap_or(("", symbol.trim_matches(|c| c == '(' || c == ')')));
            let name = if name.is_empty() { Name::Ordinal(n.parse().expect("an ordinal")) } else { Name::Named(name.to_string()) };
            let slot = base + iat.expect("an IAT before its symbols") + index * ptr;
            references.push(Reference { name, library: Lib::Binds(libraries.len() - 1), slots: [slot].into(), stubs: BTreeSet::new() });
            index += 1;
        }
    }
    Answered { format: "pe".into(), binding: "per_library".into(), libraries, references }
}

/// The lines of the block that starts with `head`, up to its closing `]` at
/// column 0.
fn block<'a>(text: &'a str, head: &str) -> Vec<&'a str> {
    text.lines().skip_while(|l| !l.starts_with(head)).skip(1).take_while(|l| *l != "]").collect()
}

/// An ELF's answer, as `llvm-readobj` and `llvm-objdump` state it, and whether
/// it is an x86-64 image (whose PLT stubs the engine decodes).
fn elf_expected(text: &str, plt: &str) -> (Answered, bool) {
    let x86_64 = text.lines().any(|l| field(l, "Machine:").is_some_and(|m| m.starts_with("EM_X86_64")));
    let needed: Vec<String> = block(text, "DynamicSection [")
        .iter()
        .filter_map(|l| l.split_once("Shared library: [").map(|(_, rest)| rest.trim_end_matches(']').to_string()))
        .collect();
    let mut sorted = needed.clone();
    sorted.sort();
    let listed: Vec<String> = block(text, "NeededLibraries [").iter().map(|l| l.trim().to_string()).collect();
    assert_eq!(sorted, listed, "the dynamic table's DT_NEEDED entries are the libraries --needed-libs lists");

    // Version requirements: version index → the file it names.
    let mut file_of: BTreeMap<u64, String> = BTreeMap::new();
    let mut file = String::new();
    for line in block(text, "VersionRequirements [") {
        if let Some(f) = field(line, "FileName:") {
            file = f.to_string();
        } else if let Some(i) = field(line, "Index:") {
            file_of.insert(i.parse().expect("an index"), file.clone());
        }
    }
    let mut libraries: Vec<(String, String)> = needed.iter().map(|n| (n.clone(), "needed".to_string())).collect();
    for line in block(text, "VersionRequirements [") {
        if let Some(f) = field(line, "FileName:")
            && !libraries.iter().any(|(n, _)| n == f)
        {
            libraries.push((f.to_string(), "version_requirement_only".to_string()));
        }
    }

    // Dynamic symbols and their versions, both in symbol-table order.
    let symbols: Vec<(String, bool)> = {
        let lines = block(text, "DynamicSymbols [");
        let mut out = Vec::new();
        let mut name = None;
        for line in lines {
            if let Some(n) = field(line, "Name:") {
                // `<name>[@<version>] (<string-table offset>)`; an empty name
                // leaves only the parentheses.
                let n = if n.starts_with('(') { "" } else { n.rsplit_once(" (").map_or(n, |(a, _)| a) };
                name = Some(n.split('@').next().unwrap_or_default().to_string());
            } else if let Some(s) = field(line, "Section:") {
                out.push((name.take().expect("a name before its section"), s.starts_with("Undefined")));
            }
        }
        out
    };
    let versions: Vec<u64> =
        block(text, "VersionSymbols [").iter().filter_map(|l| field(l, "Version:")).map(|v| v.parse::<u64>().expect("a version") & 0x7fff).collect();

    // The slots each symbol's GLOB_DAT and JUMP_SLOT relocations name.
    let mut slots: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    for line in block(text, "Relocations [") {
        let words: Vec<&str> = line.split_whitespace().collect();
        if let [offset, kind, symbol, ..] = words[..]
            && (kind.ends_with("_GLOB_DAT") || kind.ends_with("_JUMP_SLOT"))
        {
            slots.entry(symbol.split('@').next().unwrap_or_default().to_string()).or_default().insert(hex(offset));
        }
    }
    // The PLT entries llvm-objdump names after a symbol: `<addr> <name@plt>:`.
    let mut stubs: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    for line in plt.lines() {
        let (addr, rest) = line.split_once(' ').expect("an address and a name");
        let name = rest.trim_start_matches('<').trim_end_matches(">:").trim_end_matches("@plt");
        stubs.entry(name.to_string()).or_default().insert(hex(addr));
    }

    let mut references = Vec::new();
    for (index, (name, undefined)) in symbols.iter().enumerate().skip(1) {
        if !undefined || name.is_empty() {
            continue;
        }
        let library = match versions.get(index).and_then(|v| file_of.get(v)) {
            Some(f) => Lib::Named(libraries.iter().position(|(n, _)| n == f).expect("a listed library")),
            None => Lib::Unattributed,
        };
        let slots = slots.get(name).cloned().unwrap_or_default();
        let stubs = if x86_64 && !slots.is_empty() { stubs.get(name).cloned().unwrap_or_default() } else { BTreeSet::new() };
        references.push(Reference { name: Name::Named(name.clone()), library, slots, stubs });
    }
    (Answered { format: "elf".into(), binding: "flat".into(), libraries, references }, x86_64)
}

/// The command's answer, through the CLI.
fn engine(fixture: &str) -> (Answered, Unread) {
    let path = repo().join(fixture);
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .args(["imports", "--file"])
        .arg(&path)
        .arg("--quiet")
        .current_dir(support::data_home())
        .output()
        .expect("run n0xis imports");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{fixture}: {e}: {}", String::from_utf8_lossy(&out.stdout)));
    assert_eq!(v["ok"], true, "{fixture}: {v}");
    assert_eq!(v["meta"]["schema"], "n0xis.imports.v1", "{fixture}");
    let read = &v["data"]["imports"]["read"];
    assert!(read.is_object(), "{fixture}: every fixture's table is read: {v}");
    let parts = |v: &Value, what: &str| -> Vec<String> {
        v.as_array()
            .unwrap_or_else(|| panic!("{fixture}: `{what}` is not a list: {v}"))
            .iter()
            .map(|u| {
                let (part, why) = (u["part"].as_str().unwrap_or_default(), u["why"].as_str().unwrap_or_default());
                assert!(!part.is_empty() && !why.is_empty(), "{fixture}: `{what}` names no part or no reason: {u}");
                part.to_string()
            })
            .collect()
    };
    let unread = Unread {
        reach: parts(&read["reach_not_read"], "reach_not_read"),
        library_entries: read["libraries"].as_array().expect("libraries").iter().map(|l| parts(&l["references_not_read"], "references_not_read").len()).sum(),
    };
    let libraries = read["libraries"]
        .as_array()
        .expect("libraries")
        .iter()
        .map(|l| (l["name"].as_str().expect("a name").to_string(), l["stated_by"].as_str().expect("a source").to_string()))
        .collect();
    let references = read["references"]
        .as_array()
        .expect("references")
        .iter()
        .map(|r| {
            let name = match (r["name"].as_str(), r["ordinal"].as_u64()) {
                (Some(n), None) => Name::Named(n.to_string()),
                (None, Some(o)) => Name::Ordinal(o),
                other => panic!("{fixture}: a reference with neither or both of a name and an ordinal: {other:?}"),
            };
            let library = match (r["library"]["binds"].as_u64(), r["library"]["named"].as_u64(), r["library"]["unattributed"]["why"].as_str()) {
                (Some(i), None, None) => Lib::Binds(i as usize),
                (None, Some(i), None) => Lib::Named(i as usize),
                (None, None, Some(why)) if !why.is_empty() => Lib::Unattributed,
                _ => panic!("{fixture}: an attribution of no known shape: {}", r["library"]),
            };
            let reach = r["reach"]["read"].as_array().unwrap_or_else(|| panic!("{fixture}: reach not read: {r}"));
            let at = |key: &str| reach.iter().filter_map(|x| x[key].as_str()).map(hex).collect::<BTreeSet<u64>>();
            Reference { name, library, slots: at("slot"), stubs: at("stub") }
        })
        .collect();
    let answered = Answered {
        format: v["data"]["format"].as_str().expect("a format").to_string(),
        binding: read["binding"].as_str().expect("a binding").to_string(),
        libraries,
        references,
    };
    (answered, unread)
}

#[test]
fn every_fixture_imports_what_llvm_readobj_lists() {
    let (mut ordinals, mut second_library, mut stubs, mut empty, mut stub_gaps) = (0, 0, 0, 0, 0);
    let list = fixtures();
    for fixture in &list {
        let text = recording(fixture, "readobj");
        let (want, x86_64) = if text.contains("Format: COFF-") {
            (pe_expected(&text), true)
        } else {
            elf_expected(&text, &recording(fixture, "plt"))
        };
        let (got, unread) = engine(fixture);
        assert_eq!((&got.format, &got.binding), (&want.format, &want.binding), "{fixture}");
        assert_eq!(unread.library_entries, 0, "{fixture}: a library says entries of its table were not read");
        assert_eq!(got.libraries, want.libraries, "{fixture}: the libraries, in order");
        assert_eq!(got.references.len(), want.references.len(), "{fixture}: {:#?}\n{:#?}", got.references, want.references);
        for (g, w) in got.references.iter().zip(&want.references) {
            assert_eq!(g, w, "{fixture}: a reference, in order");
        }
        ordinals += want.references.iter().filter(|r| matches!(r.name, Name::Ordinal(_))).count();
        second_library += want.references.iter().filter(|r| matches!(r.library, Lib::Binds(i) | Lib::Named(i) if i > 0)).count();
        stubs += want.references.iter().map(|r| r.stubs.len()).sum::<usize>();
        empty += usize::from(want.libraries.is_empty() && want.references.is_empty());
        // The stubs llvm-objdump names and the engine does not decode are
        // the gap the answer states, and only they.
        let gap = !x86_64 && !recording(fixture, "plt").is_empty();
        let stated: Vec<&str> = unread.reach.iter().map(String::as_str).collect();
        assert_eq!(stated, if gap { vec!["PLT stubs"] } else { vec![] }, "{fixture}: what the answer says it did not reach through");
        // And the starts say the same of the stubs: they are not starts either.
        let img = ImageSource::load(&repo().join(fixture)).unwrap_or_else(|e| panic!("{fixture}: {e}"));
        let starts_say = img.image().declared_starts().not_read.iter().any(|u| u.part == "PLT stubs");
        assert_eq!(starts_say, gap, "{fixture}: the declared starts on the stubs not decoded");
        stub_gaps += usize::from(gap);
    }
    // A fixture set that lost a shape must not pass by checking nothing.
    assert_eq!(list.len(), 16, "the fixtures listed");
    assert_eq!(ordinals, 1, "one import by ordinal only (the planted PE32)");
    assert!(second_library >= 3, "references attributed past the first library: {second_library}");
    assert!(stubs >= 5, "x86-64 PLT stubs checked: {stubs}");
    assert!(empty >= 2, "fixtures that import nothing: {empty}");
    assert_eq!(
        stub_gaps, 4,
        "ELF images of other machines whose PLT entries llvm-objdump names, the engine does not decode, and the answer says so"
    );
}

/// What a slot is bound to is answered twice — in the `imports` list and by
/// the image's `binding_at`, which every symbol answer reads — so the two must
/// agree on every slot the list names, and every stub it names must be what
/// `symbol_at` calls it.
#[test]
fn the_import_list_and_the_slot_answers_agree() {
    let mut slots = 0;
    for fixture in fixtures() {
        let img = ImageSource::load(&repo().join(&fixture)).unwrap_or_else(|e| panic!("{fixture}: {e}"));
        let Answer::Read(imports) = img.image().imports() else { panic!("{fixture}: not read") };
        for r in &imports.references {
            let library = match &r.library {
                LibraryRef::Binds(i) | LibraryRef::Named(i) => Some(imports.libraries[*i].name.clone()),
                LibraryRef::Unattributed { .. } => None,
            };
            let Answer::Read(reach) = &r.reach else { continue };
            for at in reach {
                match *at {
                    Reach::Slot(slot) => {
                        slots += 1;
                        match img.image().binding_at(slot) {
                            Binding::Import(import) => {
                                assert_eq!((&import.name, &import.library), (&r.name, &library), "{fixture}: the slot at {slot}");
                            }
                            other => panic!("{fixture}: the list reaches {:?} through {slot}, which is bound to {other:?}", r.name),
                        }
                        let symbol = img.iat_slot(slot).unwrap_or_else(|| panic!("{fixture}: no import at {slot}"));
                        assert_eq!(symbol.name, r.name.symbol_name(), "{fixture}: {slot}");
                    }
                    Reach::Stub(stub) => {
                        let symbol = img.symbol_at(stub).unwrap_or_else(|| panic!("{fixture}: nothing names the stub at {stub}"));
                        assert_eq!(symbol.name, r.name.symbol_name(), "{fixture}: the stub at {stub}");
                    }
                    Reach::Index(_) => panic!("{fixture}: an index reach on a native image"),
                }
            }
        }
    }
    assert!(slots >= 20, "slots checked: {slots}");
    // The self-bound jump slot of the planted shared object is not an import:
    // it is bound to the image's own `n0x_self`, and its stub forwards there
    // (`R_X86_64_JUMP_SLOT n0x_self` at 0x4018 in llvm-readobj's recording,
    // `<n0x_self@plt>` at 0x1060 in llvm-objdump's).
    let so = ImageSource::load(&repo().join("crates/n0xis-cli/tests/fixtures/imports/imports-x86_64.so")).expect("the fixture");
    assert!(matches!(so.image().binding_at(Va(0x4018)), Binding::SelfDefinition { .. }), "{:?}", so.image().binding_at(Va(0x4018)));
    assert_eq!(so.thunk_to(Va(0x1060)), so.named_functions().iter().find(|(_, n)| n == "n0x_self").map(|(va, _)| *va));
}

/// The recordings say what the tools say now — those of this file and of
/// `image_layout_is_what_llvm_readobj_lists.rs`: a recording edited by hand,
/// or left behind when a fixture was rebuilt, would make a test compare the
/// engine with something no tool said.
#[cfg(feature = "oracle")]
#[test]
fn every_recording_is_what_the_tools_print_now() {
    let run = |tool: &str, args: &[&str]| -> String {
        let out = Command::new(tool).args(args).current_dir(repo()).env("LC_ALL", "C").output().unwrap_or_else(|e| panic!("{tool}: {e}"));
        assert!(out.status.success(), "{tool} {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).expect("UTF-8")
    };
    for fixture in fixtures() {
        if fixture.ends_with(".exe") || fixture.ends_with(".dll") {
            assert_eq!(run("llvm-readobj", &["--file-headers", "--coff-imports", &fixture]), recording(&fixture, "readobj"), "{fixture}");
            assert_eq!(run("llvm-readobj", &["--file-headers", "--sections", "--coff-exports", &fixture]), recording(&fixture, "layout"), "{fixture}");
        } else {
            let args = ["--file-headers", "--dynamic-table", "--needed-libs", "--dyn-syms", "--version-info", "--relocations", &fixture];
            assert_eq!(run("llvm-readobj", &args), recording(&fixture, "readobj"), "{fixture}");
            assert_eq!(run("llvm-readobj", &["--file-headers", "--program-headers", &fixture]), recording(&fixture, "layout"), "{fixture}");
            let plt = run("llvm-objdump", &["-d", "--no-show-raw-insn", "-j", ".plt", "-j", ".plt.sec", "-j", ".plt.got", &fixture]);
            let named: String = plt.lines().filter(|l| l.contains("@plt>:")).map(|l| format!("{l}\n")).collect();
            assert_eq!(named, recording(&fixture, "plt"), "{fixture}: llvm-objdump's PLT names");
        }
    }
}
