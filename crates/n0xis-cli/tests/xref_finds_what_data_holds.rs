// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`xref to` on an address held in data.**
//!
//! A C++ virtual method and an indirect handler in a pointer table are called
//! through a word of data, so no instruction names them. `xref to` looked at
//! instructions only and answered `count: 0` with no caveat, which reads as dead
//! code, on programs nobody here had seen.
//!
//! Nothing expected below comes from this tool. `oracle/xref/held.cpp` says which
//! method is in which slot, and it is written here as an index; `nm` says where the
//! method and the vtable are; `readelf -r` (or `objdump -p`'s base relocations on a
//! PE) says a table writes that slot, and the word in the file says what a fixed
//! image holds there.
//!
//! The risk on the other side is a number that equals an address. A word is planted
//! in the built file, by hand, equal to a function's address: on an image that may
//! load anywhere it is a number and must not be listed; on a fixed image it cannot
//! be told from a pointer and must be listed as only that.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod support;

fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("n0xis")
}

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../oracle/xref/held.cpp")
}

fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis_xref_held_{}_{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// A tool's standard output, in the language this parser reads.
fn run(tool: &str, args: &[&str], file: &Path) -> String {
    let out = Command::new(tool).env("LC_ALL", "C").args(args).arg(file).output().unwrap_or_else(|e| panic!("{tool}: {e}"));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Name → address, from `nm`.
fn symbols(nm: &str, file: &Path) -> BTreeMap<String, u64> {
    run(nm, &[], file)
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let addr = u64::from_str_radix(f.next()?, 16).ok()?;
            f.next()?;
            Some((f.next()?.to_string(), addr))
        })
        .collect()
}

/// Slot address → relocation type, from `readelf -rW`.
///
/// A `RELR` table is read here as well: `readelf` prints it decoded, each line an
/// address and a symbol with no type, so it is recorded as `RELR`.
fn elf_relocations(file: &Path) -> BTreeMap<u64, String> {
    let mut map = BTreeMap::new();
    let mut in_relr = false;
    for line in run("readelf", &["-rW"], file).lines() {
        if line.starts_with("Relocation section") {
            in_relr = line.contains(".relr");
            continue;
        }
        let mut f = line.split_whitespace();
        let Some(first) = f.next() else { continue };
        if in_relr {
            // `0016:  <entry> <address>  <symbol>` where a table's entry starts,
            // and `<address>  <symbol>` for the further words of a bitmap.
            let address = if first.ends_with(':') { f.nth(1).unwrap_or("") } else { first };
            if let Ok(at) = u64::from_str_radix(address, 16)
                && address.len() >= 8
            {
                map.insert(at, "RELR".to_string());
            }
            continue;
        }
        let (Ok(at), Some(_info), Some(kind)) = (u64::from_str_radix(first, 16), f.next(), f.next()) else { continue };
        map.insert(at, kind.to_string());
    }
    map
}

/// Every word `objdump -p` lists in a PE's base relocation table.
fn pe_relocations(objdump: &str, file: &Path) -> BTreeSet<u64> {
    let text = run(objdump, &["-p"], file);
    let base = text.lines().find_map(|l| l.strip_prefix("ImageBase")).and_then(|v| u64::from_str_radix(v.trim(), 16).ok()).expect("objdump -p states ImageBase");
    let mut page = 0u64;
    let mut words = BTreeSet::new();
    for line in text.lines() {
        // `Virtual Address: 00003000 Chunk size 28 (0x1c) Number of fixups 10`
        if let Some(rest) = line.strip_prefix("Virtual Address: ") {
            page = u64::from_str_radix(rest.split_whitespace().next().unwrap_or(""), 16).expect("a page");
            continue;
        }
        // `reloc    0 offset   30 [3030] DIR64`
        let mut f = line.split_whitespace();
        if f.next() == Some("reloc") && line.trim_end().ends_with("DIR64") {
            let offset = line.split("offset").nth(1).and_then(|r| r.split_whitespace().next()).unwrap_or("");
            words.insert(base + page + u64::from_str_radix(offset, 16).expect("an offset"));
        }
    }
    words
}

/// `(section's address, file offset, size)` of an ELF section, from `readelf -SW`.
fn elf_section(file: &Path, name: &str) -> (u64, u64, u64) {
    let wanted = format!(" {name} ");
    let text = run("readelf", &["-SW"], file);
    let line = text.lines().find(|l| l.contains(&wanted)).unwrap_or_else(|| panic!("readelf names no {name}"));
    let after = line.split(&wanted).nth(1).expect("the name");
    let f: Vec<&str> = after.split_whitespace().collect();
    let hex = |s: &str| u64::from_str_radix(s, 16).expect("hex");
    (hex(f[1]), hex(f[2]), hex(f[3]))
}

/// The `xref to` answer's `data`.
fn xref_to(file: &Path, addr: u64) -> Value {
    let mut cmd = support::isolated(Command::new(n0xis_exe()));
    let out = cmd.arg("xref").arg("to").arg("--file").arg(file).arg("--addr").arg(format!("{addr:#x}")).output().expect("n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("no envelope ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    assert_eq!(v["ok"], true, "{v}");
    v["data"].clone()
}

fn hex(v: &Value) -> u64 {
    match v {
        Value::Number(n) => n.as_u64().expect("an address"),
        Value::String(s) => u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("an address"),
        other => panic!("no address: {other}"),
    }
}

/// Slot → the answer's row, for what the answer says is a word of data.
fn slots(answer: &Value) -> BTreeMap<u64, Value> {
    answer["refs"].as_array().expect("refs").iter().filter(|r| r["kind"] == "data_word").map(|r| (hex(&r["slot"]), r.clone())).collect()
}

/// Which word of which table holds which function, from `held.cpp`. Each is
/// `(function, object, index into the object in words)`. Two words of header come
/// before a vtable's first slot, and a destructor takes two slots: `Square`'s
/// `area` is at index 2 + 2.
const HELD: [(&str, &str, u64); 10] = [
    ("_ZNK6Square4areaEv", "_ZTV6Square", 4),
    ("_ZNK6Square5sidesEv", "_ZTV6Square", 5),
    ("_ZNK6Circle4areaEv", "_ZTV6Circle", 4),
    ("_ZNK5Shape5sidesEv", "_ZTV6Circle", 5),
    ("_ZN6SquareD0Ev", "_ZTV6Square", 3),
    ("_ZN6CircleD0Ev", "_ZTV6Circle", 3),
    ("handler_add", "handlers", 0),
    ("handler_mul", "handlers", 1),
    ("handler_neg", "handlers", 2),
    ("handler_hook", "hook", 0),
];

/// Assert every word of [`HELD`] is in the answer, with `evidence(slot)` and in a
/// section the image's headers put it in, and that what the answer says it searched
/// names that section.
fn every_held_word_is_found(name: &str, file: &Path, syms: &BTreeMap<String, u64>, evidence: &dyn Fn(u64) -> &'static str) -> usize {
    let mut found = 0;
    for (function, object, index) in HELD {
        let target = *syms.get(function).unwrap_or_else(|| panic!("{name}: nm has no {function}"));
        let object_at = *syms.get(object).unwrap_or_else(|| panic!("{name}: nm has no {object}"));
        let slot = object_at + index * 8;
        let answer = xref_to(file, target);
        let rows = slots(&answer);
        let row = rows.get(&slot).unwrap_or_else(|| panic!("{name}: {function} at {target:#x} is held at {slot:#x} in {object}, and the answer lists {:?}", rows.keys().collect::<Vec<_>>()));
        assert_eq!(row["evidence"], evidence(slot), "{name}: {function} at {slot:#x}: {row}");
        let section = row["section"].as_str().expect("a section");
        assert!(!section.is_empty(), "{name}: {row}");
        assert_eq!(answer["searched"]["data"]["state"], "searched", "{name}: {answer}");
        assert_eq!(answer["count"].as_u64(), answer["refs"].as_array().map(|r| r.len() as u64), "{name}");
        found += 1;
    }
    found
}

/// Plant `value` in the file over the 8-byte word at `va` of `.data`.
fn plant(file: &Path, va: u64, value: u64) {
    let (start, offset, size) = elf_section(file, ".data");
    assert!(va >= start && va + 8 <= start + size, "{va:#x} is not in .data");
    let mut bytes = std::fs::read(file).expect("read");
    let at = (offset + va - start) as usize;
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    std::fs::write(file, bytes).expect("write");
}

/// Build `held.cpp` with `compiler` and `flags`, `None` where this machine cannot.
fn build(tag: &str, compiler: &str, flags: &[&str]) -> Option<PathBuf> {
    let dir = tmp(tag);
    // A mingw linker adds `.exe` to a name with none.
    let out = dir.join(if compiler.contains("mingw") { "held.exe" } else { "held" });
    let built = Command::new(compiler).args(["-O1", "-fno-inline"]).args(flags).arg("-o").arg(&out).arg(source()).output();
    match built {
        Ok(o) if o.status.success() => Some(out),
        Ok(o) => {
            eprintln!("{tag}: skipped, {compiler} {flags:?} could not build: {}", String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or(""));
            None
        }
        Err(e) => {
            eprintln!("{tag}: skipped, no {compiler}: {e}");
            None
        }
    }
}

/// Run one ELF variant whose words a relocation writes. `kinds` maps the type
/// `readelf -r` prints for a slot to the evidence the answer must give.
fn relocated_variant(tag: &str, compiler: &str, flags: &[&str], kinds: &[(&str, &'static str)]) {
    let Some(file) = build(tag, compiler, flags) else { return };
    let syms = symbols("nm", &file);
    let relocs = elf_relocations(&file);
    let evidence = |slot: u64| -> &'static str {
        let kind = relocs.get(&slot).unwrap_or_else(|| panic!("{tag}: readelf names no relocation at {slot:#x}: the fixture did not build as this variant"));
        kinds.iter().find(|(k, _)| k == kind).unwrap_or_else(|| panic!("{tag}: {kind} at {slot:#x} is not a kind this variant expects")).1
    };
    assert_eq!(every_held_word_is_found(tag, &file, &syms, &evidence), HELD.len());

    // A number equal to an address, which no relocation writes, is a number here.
    let target = syms["handler_unused"];
    let before = xref_to(&file, target);
    assert!(slots(&before).is_empty(), "{tag}: nothing holds handler_unused: {before}");
    assert_eq!(before["searched"]["data"]["unrelocated_matches"], 0, "{tag}");
    plant(&file, syms["not_a_pointer"] + 8, target);
    let after = xref_to(&file, target);
    assert!(slots(&after).is_empty(), "{tag}: a planted number was listed as a pointer: {after}");
    assert_eq!(after["searched"]["data"]["unrelocated_matches"], 1, "{tag}: the planted word was not counted: {after}");
    assert_eq!(after["searched"]["data"]["rule"], "relocations", "{tag}");
}

#[test]
fn a_position_independent_program_with_rela() {
    relocated_variant("gcc_pie", "g++", &["-fPIE", "-pie", "-Wl,-z,nopack-relative-relocs"], &[("R_X86_64_RELATIVE", "relative_relocation")]);
}

#[test]
fn a_position_independent_program_with_relr() {
    relocated_variant("gcc_relr", "g++", &["-fPIE", "-pie", "-Wl,-z,pack-relative-relocs"], &[("RELR", "relr_relocation"), ("R_X86_64_RELATIVE", "relr_relocation")]);
}

#[test]
fn a_position_independent_program_from_clang_and_lld() {
    relocated_variant(
        "clang_lld_pie",
        "clang++",
        &["-fPIE", "-pie", "-fuse-ld=lld", "-Wl,-z,nopack-relative-relocs"],
        &[("R_X86_64_RELATIVE", "relative_relocation")],
    );
}

/// A shared object names a method a program could override by its symbol, and the
/// word in the file may be anything.
#[test]
fn a_shared_object_whose_slots_are_symbolic() {
    relocated_variant(
        "gcc_shared",
        "g++",
        &["-fPIC", "-shared"],
        &[("R_X86_64_64", "symbol_relocation"), ("R_X86_64_RELATIVE", "relative_relocation")],
    );
}

#[test]
fn a_fixed_program_where_a_pointer_is_only_a_value() {
    for (tag, compiler, flags) in [("gcc_fixed", "g++", ["-fno-pie", "-no-pie"]), ("clang_fixed", "clang++", ["-fno-pie", "-no-pie"])] {
        let Some(file) = build(tag, compiler, &flags) else { continue };
        let syms = symbols("nm", &file);
        let relocs = elf_relocations(&file);
        let evidence = |slot: u64| -> &'static str {
            assert!(!relocs.contains_key(&slot), "{tag}: readelf names a relocation at {slot:#x}, on a fixed image's own table");
            "matching_value"
        };
        assert_eq!(every_held_word_is_found(tag, &file, &syms, &evidence), HELD.len());

        // Here a planted number cannot be told from a pointer, and is listed as
        // only what it is.
        let target = syms["handler_unused"];
        assert!(slots(&xref_to(&file, target)).is_empty(), "{tag}: nothing holds handler_unused");
        let at = syms["not_a_pointer"] + 8;
        plant(&file, at, target);
        let after = xref_to(&file, target);
        assert_eq!(slots(&after).get(&at).map(|r| r["evidence"].clone()), Some(Value::from("matching_value")), "{tag}: {after}");
        assert_eq!(after["searched"]["data"]["rule"], "relocations_and_stored_values", "{tag}");
    }
}

#[test]
fn a_pe_whose_words_its_base_relocations_name() {
    let (compiler, objdump, nm) = ("x86_64-w64-mingw32-g++", "x86_64-w64-mingw32-objdump", "x86_64-w64-mingw32-nm");
    let Some(file) = build("mingw_pe", compiler, &["-static"]) else { return };
    let syms = symbols(nm, &file);
    let words = pe_relocations(objdump, &file);
    assert!(!words.is_empty(), "the reference is broken: objdump -p lists no base relocations");
    let evidence = |slot: u64| -> &'static str {
        assert!(words.contains(&slot), "objdump -p lists no base relocation at {slot:#x}");
        "base_relocation"
    };
    assert_eq!(every_held_word_is_found("mingw_pe", &file, &syms, &evidence), HELD.len());
    // Sections of a PE keep their bookkeeping out of the search for stored values.
    let answer = xref_to(&file, syms["handler_add"]);
    let searched: Vec<&str> = answer["searched"]["data"]["sections"].as_array().expect("sections").iter().filter_map(Value::as_str).collect();
    assert!(searched.contains(&".rdata") && !searched.contains(&".pdata") && !searched.contains(&".reloc"), "{searched:?}");
}

/// Rows of a table relative to its base: `(slot, base)`.
fn relative_rows(answer: &Value) -> Vec<(u64, u64)> {
    answer["refs"].as_array().expect("refs").iter().filter(|r| r["kind"] == "relative_entry").map(|r| (hex(&r["slot"]), hex(&r["relative_to"]))).collect()
}

/// An entry states an offset, so what is asserted is what `held.cpp` wrote: which
/// entry of which table lands on which function, with `nm` saying where each is.
#[test]
fn a_table_of_offsets_from_its_own_start() {
    for (tag, compiler, flags) in [("gcc_rel", "g++", ["-fPIE", "-pie"]), ("clang_rel", "clang++", ["-fPIE", "-pie"])] {
        let Some(file) = build(tag, compiler, &flags) else { continue };
        let syms = symbols("nm", &file);
        for (function, table, index) in [("rel_a", "rel_first", 0), ("rel_b", "rel_first", 1), ("rel_c", "rel_second", 0), ("rel_d", "rel_second", 1)] {
            let answer = xref_to(&file, syms[function]);
            let base = syms[table];
            assert_eq!(relative_rows(&answer), vec![(base + index * 4, base)], "{tag}: {function}: {answer}");
            let row = answer["refs"].as_array().expect("refs").iter().find(|r| r["kind"] == "relative_entry").expect("the row");
            assert_eq!(row["evidence"], "matching_value", "{tag}: only its shape says it is an entry: {row}");
            assert_eq!(row["section"], ".rodata", "{tag}: {row}");
        }
        // Past the next base, the entries are that one's: read from the first table's
        // start, `rel_second`'s first entry lands before `rel_c` by the distance
        // between the tables. That address may be another entry's, by the functions'
        // sizes, so what is asserted is that this word is not said to reach it.
        let wrong = syms["rel_c"] - (syms["rel_second"] - syms["rel_first"]);
        let answer = xref_to(&file, wrong);
        assert!(!relative_rows(&answer).contains(&(syms["rel_second"], syms["rel_first"])), "{tag}: a table's entry read from the base before it: {answer}");
        // One entry that lands in code, followed by one that does not, is no table.
        let answer = xref_to(&file, syms["rel_e"]);
        assert_eq!(relative_rows(&answer), vec![], "{tag}: a run of one: {answer}");
    }
}

/// The zero that matters: one the answer can back.
#[test]
fn a_zero_says_what_it_is_out_of() {
    let Some(file) = build("gcc_zero", "g++", &["-fPIE", "-pie"]) else { return };
    let syms = symbols("nm", &file);
    let answer = xref_to(&file, syms["handler_unused"] + 1);
    assert_eq!(answer["count"], 0, "{answer}");
    let data = &answer["searched"]["data"];
    let sections: Vec<&str> = data["sections"].as_array().expect("sections").iter().filter_map(Value::as_str).collect();
    for wanted in [".rodata", ".data.rel.ro", ".data"] {
        assert!(sections.contains(&wanted), "{wanted} is not said to be searched: {sections:?}");
    }
    for bookkeeping in [".dynsym", ".rela.dyn", ".dynamic", ".eh_frame"] {
        assert!(!sections.contains(&bookkeeping), "{bookkeeping} is bookkeeping: {sections:?}");
    }
    assert!(!answer["searched"]["code"].as_array().expect("code").is_empty(), "{answer}");
    assert!(answer["searched"]["not_searched"].as_array().is_some_and(|n| !n.is_empty()), "{answer}");
}

/// A word that says it was not searched is the answer on a source with no tables.
#[test]
fn bytes_on_the_command_line_say_no_data_was_searched() {
    let mut cmd = support::isolated(Command::new(n0xis_exe()));
    let out = cmd.args(["xref", "to", "--bytes", "e8 03 00 00 00 90 90 90 c3", "--start", "0x1000", "--addr", "0x1008"]).output().expect("n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).expect("an envelope");
    assert_eq!(v["data"]["count"], 1, "{v}");
    assert_eq!(v["data"]["searched"]["data"]["state"], "not_searched", "{v}");
}
