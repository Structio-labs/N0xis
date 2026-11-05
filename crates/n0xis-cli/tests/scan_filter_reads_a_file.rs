// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`scan filter --file` narrows a saved scan against a file.** It used to answer
//! `missing-region` whatever it was asked: the shared resolver wanted a start and a
//! size for a file, and the command has no flags for them. A filter needs neither,
//! since it reads the addresses the saved scan holds.
//!
//! The truth is worked out here from the bytes of a committed image, at the place
//! its own section table states (read with `goblin`, outside n0xis), and from one
//! byte this test changes in a copy of it.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod support;

const IMAGE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/strings_planted.so");
/// Another image, where the saved addresses are not.
const OTHER_IMAGE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/native_pe.dll");

struct Rodata {
    addr: u64,
    offset: usize,
    bytes: Vec<u8>,
}

fn rodata() -> Rodata {
    let file = std::fs::read(IMAGE).expect("read the fixture");
    let elf = goblin::elf::Elf::parse(&file).expect("an ELF");
    let s = elf.section_headers.iter().find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".rodata")).expect("a .rodata");
    let offset = s.sh_offset as usize;
    Rodata { addr: s.sh_addr, offset, bytes: file[offset..offset + s.sh_size as usize].to_vec() }
}

fn project(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis-filter-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("scratch dir");
    dir
}

fn n0x(dir: &Path, args: &[&str]) -> Value {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).current_dir(dir).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{args:?} did not print one JSON object: {e}\n{}", String::from_utf8_lossy(&out.stdout)))
}

/// A first scan of every byte of `.rodata`, saved as `first`.
fn saved_scan(dir: &Path, r: &Rodata) {
    let start = format!("{:#x}", r.addr);
    let size = r.bytes.len().to_string();
    let v = n0x(dir, &["scan", "value", "--file", IMAGE, "--start", &start, "--size", &size, "--type", "u8", "--criterion", "unknown", "--save-as", "first", "--force"]);
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["data"]["total_matches"], r.bytes.len(), "{v}");
}

fn filter(dir: &Path, file: &str, criterion: &[&str]) -> Value {
    let mut args = vec!["scan", "filter", "--file", file, "--from", "first", "--save-as", "second", "--force", "--criterion"];
    args.extend_from_slice(criterion);
    n0x(dir, &args)
}

#[test]
fn a_value_criterion_keeps_what_the_file_holds() {
    let dir = project("value");
    let r = rodata();
    saved_scan(&dir, &r);
    // The most frequent byte, so that the count is not a coincidence of one.
    let wanted = (0..=255u8).max_by_key(|b| r.bytes.iter().filter(|x| *x == b).count()).expect("a byte");
    let count = r.bytes.iter().filter(|x| **x == wanted).count();
    assert!(count > 1, "the fixture has to repeat a byte");

    let v = filter(&dir, IMAGE, &["exact", "--value", &wanted.to_string()]);
    assert_eq!(v["ok"], true, "{v}");
    let d = &v["data"];
    assert_eq!(d["total_matches"], count, "{d}");
    let first = r.bytes.iter().position(|x| *x == wanted).expect("present") as u64;
    assert_eq!(d["matches"][0]["addr"], format!("{:#x}", r.addr + first), "{d}");
    assert_eq!(d["regions_scanned"], 1, "{d}");
    assert_eq!(d["regions_not_read"], 0, "{d}");
    assert_eq!(d["exhaustive"], true, "{d}");

    // Narrowed again, from what that saved.
    let v = n0x(&dir, &["scan", "filter", "--file", IMAGE, "--from", "second", "--criterion", "unchanged", "--save-as", "third"]);
    assert_eq!(v["data"]["total_matches"], count, "{v}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same file has changed nothing, and that is an answer, not a refusal: the
/// bytes were read. A copy with one byte changed has changed that byte.
#[test]
fn changed_against_another_build_finds_the_byte_that_differs() {
    let dir = project("changed");
    let r = rodata();
    saved_scan(&dir, &r);

    let v = filter(&dir, IMAGE, &["changed"]);
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["data"]["total_matches"], 0, "{v}");
    assert_eq!(v["data"]["regions_scanned"], 1, "the bytes were read: {v}");

    let at = r.bytes.len() / 2;
    let mut file = std::fs::read(IMAGE).expect("read the fixture");
    let now = file[r.offset + at] ^ 0xFF;
    file[r.offset + at] = now;
    let patched = dir.join("patched.so");
    std::fs::write(&patched, &file).expect("write the copy");

    let v = filter(&dir, patched.to_str().expect("a path"), &["changed"]);
    assert_eq!(v["ok"], true, "{v}");
    let d = &v["data"];
    assert_eq!(d["total_matches"], 1, "{d}");
    assert_eq!(d["matches"][0]["addr"], format!("{:#x}", r.addr + at as u64), "{d}");
    assert_eq!(d["matches"][0]["value"], now, "{d}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Addresses saved from one image, read against another that does not have them.
#[test]
fn saved_addresses_the_file_does_not_have_are_refused_and_save_nothing() {
    let dir = project("other");
    let r = rodata();
    saved_scan(&dir, &r);
    let v = filter(&dir, OTHER_IMAGE, &["unchanged"]);
    assert_eq!(v["ok"], false, "{v}");
    assert_eq!(v["error"]["code"], "nothing-readable", "{v}");
    assert!(!dir.join(".n0x/dumps/scan/second.bin").exists(), "nothing was read, so nothing is saved");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A working set of two regions, the kind a scan of a process saves, one of which
/// the file has: the rescan answers for that one and says it did not read the other.
/// The set is planted through the format's own encoder, over the one a scan saved.
#[test]
fn a_saved_region_the_file_does_not_have_is_stated() {
    use n0xis_core::{RegionData, RegionState, ScanState, ValueType};
    let dir = project("partly");
    let r = rodata();
    saved_scan(&dir, &r);
    let far = 0x7000_0000_0000u64;
    let planted = ScanState {
        value_type: ValueType::U8,
        align: 1,
        regions: vec![
            RegionState { base: n0xis_contracts::Va(far), data: RegionData::Dense { bytes: vec![0; 16] } },
            RegionState { base: n0xis_contracts::Va(r.addr), data: RegionData::Dense { bytes: r.bytes.clone() } },
        ],
    };
    let saved = dir.join(".n0x/dumps/scan/first.bin");
    assert!(saved.exists(), "where a saved scan lives: {}", saved.display());
    std::fs::write(&saved, planted.encode()).expect("plant the working set");

    let v = filter(&dir, IMAGE, &["unchanged"]);
    assert_eq!(v["ok"], true, "{v}");
    let d = &v["data"];
    assert_eq!(d["total_matches"], r.bytes.len(), "the region the file has: {d}");
    assert_eq!(d["regions_scanned"], 1, "{d}");
    assert_eq!(d["regions_not_read"], 1, "{d}");
    assert_eq!(d["not_read"][0]["start"], format!("{far:#x}"), "{d}");
    assert_eq!(d["exhaustive"], false, "{d}");
    let _ = std::fs::remove_dir_all(&dir);
}
