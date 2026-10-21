// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **How an image is loaded, and what a PE offers, are what `llvm-readobj`
//! says.**
//!
//! Two answers of the format seam (`n0xis_sources::Image`) that no command
//! printed before it existed, so nothing pinned them: `segments()` — the base,
//! the span and the loadable pieces — and a PE's `exports()`, with the symbols
//! and declared starts the adapter derives from them. Each is compared with
//! the recording `fixtures/imports/record.sh` made of every fixture in
//! `fixtures/imports/fixtures.txt` (`<name>.layout.txt`):
//!
//! - **an ELF** against `--program-headers`: every `PT_LOAD` in order, its
//!   address, sizes, file offset and `PF_R`/`PF_W`/`PF_X`; the base is the
//!   lowest address and the span runs to the end of the last;
//! - **a PE** against `--file-headers` and `--sections`: the base is
//!   `ImageBase` and the span `SizeOfImage`; the headers (`SizeOfHeaders` at
//!   the base, readable) and then each section-table entry as it states its
//!   address, `VirtualSize`, `PointerToRawData`, `RawDataSize` and
//!   `IMAGE_SCN_MEM_*` flags; and against `--coff-exports`: every export by
//!   ordinal, its name, its address or the module and name it forwards to.
//!   Which exports name an address is checked too: every named export that is
//!   not a forwarder, and every one by ordinal only that lands in a section
//!   marked executable, as `Ordinal<n>`.
//!
//! And what the symbols and the declared starts say they did **not** read
//! (`Partial::not_read`), against the same recordings: a PE's COFF symbol
//! table where its header states one (`SymbolCount`), the entry point where
//! the header states one (`AddressOfEntryPoint`, an ELF's `Entry`), a PE's
//! `.eh_frame` where its section table has one with bytes, and an ELF's
//! defined dynamic symbols of a type that is not read (`--dyn-syms` in
//! `<name>.readobj.txt`). Not checked against a tool: the same statement for
//! `.symtab` symbols and an ELF's `.eh_frame`, which no recording lists.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use n0xis_contracts::Va;
use n0xis_sources::{Answer, ExportTarget, ImageSource, StartReason, Unread};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures() -> Vec<String> {
    let list = std::fs::read_to_string(repo().join("crates/n0xis-cli/tests/fixtures/imports/fixtures.txt")).expect("the fixture list");
    list.lines().filter(|l| !l.trim().is_empty()).map(str::to_string).collect()
}

fn layout(fixture: &str) -> String {
    let name = Path::new(fixture).file_name().and_then(|n| n.to_str()).expect("a file name");
    let path = repo().join("crates/n0xis-cli/tests/fixtures/imports/recorded").join(format!("{name}.layout.txt"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.trim().strip_prefix(key).map(str::trim)
}

/// A number as llvm-readobj prints it: hex with `0x`, decimal without.
fn num(s: &str) -> u64 {
    let s = s.trim();
    match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).unwrap_or_else(|e| panic!("{s:?}: {e}")),
        None => s.parse().unwrap_or_else(|e| panic!("{s:?}: {e}")),
    }
}

/// Each `<head> {` … `}` block whose opening line is indented by `indent`,
/// as its lines.
fn blocks<'a>(text: &'a str, indent: &str, head: &str) -> Vec<Vec<&'a str>> {
    let (open, close) = (format!("{indent}{head} {{"), format!("{indent}}}"));
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(l) = lines.next() {
        if l == open {
            out.push(lines.by_ref().take_while(|l| *l != close).collect());
        }
    }
    out
}

/// `(va, mem_size, file_offset, file_size, (read, write, execute))`.
type Piece = (u64, u64, u64, u64, (bool, bool, bool));

#[test]
fn every_image_is_loaded_and_exports_what_llvm_readobj_lists() {
    let (mut segments, mut exports, mut forwarders, mut by_ordinal) = (0, 0, 0, 0);
    for fixture in fixtures() {
        let text = layout(&fixture);
        let img = ImageSource::load(&repo().join(&fixture)).unwrap_or_else(|e| panic!("{fixture}: {e}"));
        let got = img.image().segments();
        let got_pieces: Vec<Piece> = got
            .list
            .iter()
            .map(|s| (s.va.0, s.mem_size, s.file_offset, s.file_size, (s.access.read, s.access.write, s.access.execute)))
            .collect();
        if text.contains("Format: COFF-") {
            let header = |key: &str| text.lines().find_map(|l| field(l, key)).map(num).unwrap_or_else(|| panic!("{fixture}: no {key}"));
            let base = header("ImageBase:");
            let mut want: Vec<Piece> = vec![(base, header("SizeOfHeaders:"), 0, header("SizeOfHeaders:"), (true, false, false))];
            let mut executable: Vec<(u64, u64)> = Vec::new();
            for s in blocks(&text, "  ", "Section") {
                let get = |key: &str| s.iter().find_map(|l| field(l, key)).map(num).unwrap_or_else(|| panic!("{fixture}: a section with no {key}"));
                let flag = |name: &str| s.iter().any(|l| l.trim().starts_with(name));
                let va = base + get("VirtualAddress:");
                let access = (flag("IMAGE_SCN_MEM_READ "), flag("IMAGE_SCN_MEM_WRITE "), flag("IMAGE_SCN_MEM_EXECUTE "));
                want.push((va, get("VirtualSize:"), get("PointerToRawData:"), get("RawDataSize:"), access));
                if access.2 {
                    executable.push((va, va + get("VirtualSize:").max(get("RawDataSize:"))));
                }
            }
            assert_eq!((got.base.0, got.span), (base, header("SizeOfImage:")), "{fixture}: base and span");
            assert_eq!(got_pieces, want, "{fixture}: the headers, then the section table");

            // The export table, by ordinal: its name, and its address or what it forwards to.
            let mut want_exports: BTreeMap<u64, (Option<String>, Result<u64, String>)> = BTreeMap::new();
            for e in blocks(&text, "", "Export") {
                let ordinal = e.iter().find_map(|l| field(l, "Ordinal:")).map(num).unwrap_or_else(|| panic!("{fixture}: an export with no ordinal"));
                let name = e.iter().find_map(|l| field(l, "Name:")).filter(|n| !n.is_empty()).map(str::to_string);
                let target = match (e.iter().find_map(|l| field(l, "RVA:")), e.iter().find_map(|l| field(l, "ForwardedTo:"))) {
                    (Some(rva), None) => Ok(base + num(rva)),
                    (None, Some(to)) => Err(to.to_string()),
                    other => panic!("{fixture}: an export with {other:?}"),
                };
                want_exports.insert(ordinal, (name, target));
            }
            let Answer::Read(table) = img.image().exports() else { panic!("{fixture}: a PE's exports are read") };
            let got_exports: BTreeMap<u64, (Option<String>, Result<u64, String>)> = table
                .iter()
                .map(|e| {
                    let target = match &e.target {
                        ExportTarget::Local(va) => Ok(va.0),
                        ExportTarget::Forwarded { to, .. } => Err(to.clone()),
                    };
                    (u64::from(e.ordinal.expect("a PE numbers its exports")), (e.name.clone(), target))
                })
                .collect();
            assert_eq!(got_exports, want_exports, "{fixture}: the export table");

            // What names an address: a named export that is not a forwarder, and
            // one by ordinal only in executable code.
            let in_code = |va: u64| executable.iter().any(|&(s, e)| va >= s && va < e);
            let mut want_names: BTreeMap<u64, String> = BTreeMap::new();
            for (ordinal, (name, target)) in &want_exports {
                let Ok(va) = target else { continue };
                match name {
                    Some(name) => {
                        want_names.insert(*va, name.clone());
                    }
                    None if in_code(*va) => {
                        want_names.entry(*va).or_insert_with(|| format!("Ordinal{ordinal}"));
                    }
                    None => {}
                }
            }
            let got_names: BTreeMap<u64, String> = img.named_functions().into_iter().map(|(va, n)| (va.0, n)).collect();
            assert_eq!(got_names, want_names, "{fixture}: the names the exports give");
            let want_starts: Vec<Va> = want_names.keys().copied().filter(|&va| in_code(va)).map(Va).collect();
            let got_starts: Vec<Va> =
                img.image().declared_starts().read.iter().filter(|s| s.why == StartReason::Export).map(|s| s.va).collect();
            assert_eq!(got_starts, want_starts, "{fixture}: the exports declared as starts");
            assert_eq!(img.declared_entry_points(), want_starts, "{fixture}: and as entry points");

            exports += want_exports.len();
            forwarders += want_exports.values().filter(|(_, t)| t.is_err()).count();
            by_ordinal += want_exports.values().filter(|(n, _)| n.is_none()).count();
        } else {
            let mut want: Vec<Piece> = Vec::new();
            for p in blocks(&text, "  ", "ProgramHeader") {
                if !p.iter().any(|l| l.trim().starts_with("Type: PT_LOAD ")) {
                    continue;
                }
                let get = |key: &str| p.iter().find_map(|l| field(l, key)).map(num).unwrap_or_else(|| panic!("{fixture}: a header with no {key}"));
                let flag = |name: &str| p.iter().any(|l| l.trim().starts_with(name));
                want.push((get("VirtualAddress:"), get("MemSize:"), get("Offset:"), get("FileSize:"), (flag("PF_R "), flag("PF_W "), flag("PF_X "))));
            }
            let base = want.iter().map(|p| p.0).min().unwrap_or(0);
            let span = want.iter().map(|p| p.0 + p.1).max().unwrap_or(0).saturating_sub(base);
            assert_eq!((got.base.0, got.span), (base, span), "{fixture}: base and span");
            assert_eq!(got_pieces, want, "{fixture}: the PT_LOAD headers");
            assert!(matches!(img.image().exports(), Answer::NotRead { .. }), "{fixture}: an ELF's exports are not listed apart from its symbols");
        }
        segments += got.list.len();
    }
    // A set that lost a shape must not pass by checking nothing.
    assert!(segments >= 40, "segments checked: {segments}");
    assert_eq!((exports, forwarders, by_ordinal), (6, 1, 1), "two fixtures with one export, and the planted DLL's four");
}

fn readobj(fixture: &str) -> String {
    let name = Path::new(fixture).file_name().and_then(|n| n.to_str()).expect("a file name");
    let path = repo().join("crates/n0xis-cli/tests/fixtures/imports/recorded").join(format!("{name}.readobj.txt"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn parts(unread: &[Unread]) -> Vec<&str> {
    unread.iter().map(|u| u.part.as_str()).collect()
}

#[test]
fn what_the_symbols_and_starts_did_not_read_is_what_the_headers_state() {
    let (mut coff, mut entries, mut eh_frames, mut dynsym_types) = (0, 0, 0, 0usize);
    for fixture in fixtures() {
        let text = layout(&fixture);
        let img = ImageSource::load(&repo().join(&fixture)).unwrap_or_else(|e| panic!("{fixture}: {e}"));
        let Answer::Read(symbols) = img.image().symbols() else { panic!("{fixture}: every fixture's symbols are read") };
        let starts = parts(&img.image().declared_starts().not_read);
        let header = |key: &str| text.lines().find_map(|l| field(l, key)).map(num);
        let pe = text.contains("Format: COFF-");
        let entry = if pe { header("AddressOfEntryPoint:") } else { header("Entry:") }.unwrap_or_else(|| panic!("{fixture}: no entry field"));
        assert_eq!(starts.contains(&"the entry point"), entry != 0, "{fixture}: entry {entry:#x}; not read: {starts:?}");
        entries += usize::from(entry != 0);
        if pe {
            let count = header("SymbolCount:").unwrap_or_else(|| panic!("{fixture}: no SymbolCount"));
            let want: Vec<&str> = if count > 0 { vec!["the COFF symbol table"] } else { vec![] };
            assert_eq!(parts(&symbols.not_read), want, "{fixture}: SymbolCount {count}");
            if let Some(u) = symbols.not_read.first() {
                assert!(u.why.contains(&format!("states {count} entries")), "{fixture}: {}", u.why);
            }
            assert_eq!(starts.contains(&"the COFF symbol table"), count > 0, "{fixture}: {starts:?}");
            coff += usize::from(count > 0);
            let eh_frame = blocks(&text, "  ", "Section")
                .iter()
                .any(|s| s.iter().any(|l| field(l, "Name:").is_some_and(|n| n.starts_with(".eh_fram"))) && s.iter().any(|l| field(l, "RawDataSize:").is_some_and(|n| num(n) > 0)));
            assert_eq!(starts.contains(&"the .eh_frame unwind table"), eh_frame, "{fixture}: {starts:?}");
            eh_frames += usize::from(eh_frame);
        } else {
            let want = unread_types(&readobj(&fixture), "DynamicSymbols [", &fixture);
            assert_states(&symbols.not_read, ".dynsym", &want, &fixture);
            dynsym_types += want.values().sum::<usize>();
        }
    }
    // Each statement must be seen made, not only seen absent.
    assert_eq!(coff, 2, "PE fixtures whose header states a COFF symbol table");
    assert!(entries >= 3, "fixtures that state an entry point: {entries}");
    assert!(eh_frames >= 1, "PE fixtures with an .eh_frame: {eh_frames}");
    // No fixture of the list has one (types-x86_64.so, below, is planted for
    // it); counted so the day one does, it is seen.
    eprintln!("[not read] defined dynamic symbols of a type not read, in the listed fixtures: {dynsym_types}");
}

/// Defined, named symbols of a type the ELF reader does not read as a name,
/// by llvm-readobj's account in the `head` block (`Symbols [` or
/// `DynamicSymbols [`), per type by the specification's name. Empty where the
/// block is absent (a static executable has no `.dynsym`).
fn unread_types(recorded: &str, head: &str, fixture: &str) -> BTreeMap<&'static str, usize> {
    let table: String = recorded.lines().skip_while(|l| *l != head).skip(1).take_while(|l| *l != "]").map(|l| format!("{l}\n")).collect();
    let mut want: BTreeMap<&'static str, usize> = BTreeMap::new();
    for s in blocks(&table, "  ", "Symbol") {
        let get = |key: &str| s.iter().find_map(|l| field(l, key)).unwrap_or_else(|| panic!("{fixture}: a symbol with no {key}"));
        let named = !get("Name:").starts_with('(');
        let defined = !get("Section:").starts_with("Undefined") && num(get("Value:")) != 0;
        let ty = get("Type:").split(" (").next().unwrap_or_default();
        if named && defined && !matches!(ty, "Function" | "Object") {
            let stt = match ty {
                "None" => "STT_NOTYPE",
                "TLS" => "STT_TLS",
                "GNU_IFunc" => "STT_GNU_IFUNC",
                "Common" => "STT_COMMON",
                "Section" => "STT_SECTION",
                "File" => "STT_FILE",
                other => panic!("{fixture}: a type this test does not name: {other}"),
            };
            *want.entry(stt).or_default() += 1;
        }
    }
    want
}

/// The statement about `table` (`.symtab`, `.dynsym`) is made exactly when
/// `want` is not empty, and gives each count.
fn assert_states(not_read: &[Unread], table: &str, want: &BTreeMap<&str, usize>, fixture: &str) {
    let stated: Vec<&Unread> = not_read.iter().filter(|u| u.part.starts_with(&format!("{table} "))).collect();
    assert_eq!(stated.len(), usize::from(!want.is_empty()), "{fixture}: {table}: want {want:?}, stated {not_read:?}");
    if let Some(u) = stated.first() {
        for (stt, n) in want {
            assert!(u.why.contains(&format!("{n} {stt}")), "{fixture}: {table}: {n} {stt} not in {}", u.why);
        }
    }
}

/// A shared object planted with defined, named symbols of each type the ELF
/// reader does not read as a name, in both tables
/// (`fixtures/imports/symbol_types/`).
#[test]
fn elf_symbols_of_a_type_not_read_are_said_to_be_not_read() {
    let dir = repo().join("crates/n0xis-cli/tests/fixtures/imports/symbol_types");
    let recorded = std::fs::read_to_string(dir.join("recorded/types-x86_64.so.readobj.txt")).expect("the recording");
    let img = ImageSource::load(&dir.join("types-x86_64.so")).expect("the fixture loads");
    let Answer::Read(symbols) = img.image().symbols() else { panic!("the symbols are read") };
    for (head, table) in [("Symbols [", ".symtab"), ("DynamicSymbols [", ".dynsym")] {
        let want = unread_types(&recorded, head, "types-x86_64.so");
        for stt in ["STT_GNU_IFUNC", "STT_TLS", "STT_NOTYPE"] {
            assert!(want.get(stt).is_some_and(|&n| n > 0), "{table}: the fixture plants no {stt}: {want:?}");
        }
        assert_states(&symbols.not_read, table, &want, "types-x86_64.so");
    }
}

/// The recording says what llvm-readobj says now.
#[cfg(feature = "oracle")]
#[test]
fn the_symbol_types_recording_is_what_llvm_readobj_prints_now() {
    let dir = repo().join("crates/n0xis-cli/tests/fixtures/imports/symbol_types");
    let out = std::process::Command::new("llvm-readobj")
        .args(["--symbols", "--dyn-syms", "types-x86_64.so"])
        .current_dir(&dir)
        .env("LC_ALL", "C")
        .output()
        .expect("llvm-readobj");
    assert!(out.status.success());
    let recorded = std::fs::read_to_string(dir.join("recorded/types-x86_64.so.readobj.txt")).expect("the recording");
    assert_eq!(String::from_utf8_lossy(&out.stdout), recorded);
}
