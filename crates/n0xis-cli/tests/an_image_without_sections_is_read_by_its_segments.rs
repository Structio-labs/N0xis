// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **An image with no section headers is read where its loader places it.**
//!
//! The loader of an ELF reads its program headers and never a section header,
//! so an image whose section headers were stripped (or never written) runs all
//! the same. The reader placed only sections, and on such an image every read
//! came back empty: `mem read` said "address not mapped" inside a `PT_LOAD`,
//! `mem span` read 0 bytes, `find` and `strings` answered `count: 0` over a
//! string the file holds, `function eh` said there was no `.eh_frame` with a
//! `PT_GNU_EH_FRAME` segment present, and `profile` said nothing of it (audit
//! 2026-11-06).
//!
//! The target is the committed `strings_planted.so` with its section headers
//! taken away here (`e_shoff`, `e_shnum`, `e_shstrndx` zeroed): the bytes
//! planted in its source, and where they are loaded, are found by the small
//! program-header reader below, not by the tool.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

mod support;

const ELF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/strings_planted.so");
/// Planted in `strings_planted.c`.
const PLANTED: &[u8] = b"n0xis-planted-ascii-7f3a";

fn u16le(b: &[u8], at: usize) -> u64 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap()).into()
}
fn u32le(b: &[u8], at: usize) -> u64 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap()).into()
}
fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// `(p_type, p_offset, p_vaddr, p_filesz)` of every program header of an
/// ELF64 little-endian image.
fn program_headers(b: &[u8]) -> Vec<(u64, u64, u64, u64)> {
    assert_eq!(&b[..6], b"\x7fELF\x02\x01", "an ELF64 little-endian fixture");
    let (off, size, n) = (u64le(b, 0x20) as usize, u16le(b, 0x36) as usize, u16le(b, 0x38) as usize);
    (0..n).map(|i| off + i * size).map(|p| (u32le(b, p), u64le(b, p + 8), u64le(b, p + 16), u64le(b, p + 32))).collect()
}

/// The fixture with no section headers, and where the planted string is loaded.
fn sectionless() -> (PathBuf, PathBuf, u64) {
    let mut b = std::fs::read(ELF).expect("the fixture");
    let at = b.windows(PLANTED.len()).position(|w| w == PLANTED).expect("the planted string is in the file") as u64;
    let va = program_headers(&b)
        .into_iter()
        .find(|&(ty, off, _, filesz)| ty == 1 && (off..off + filesz).contains(&at))
        .map(|(_, off, vaddr, _)| vaddr + (at - off))
        .expect("a PT_LOAD holds the planted string");
    b[0x28..0x30].fill(0); // e_shoff
    b[0x3c..0x40].fill(0); // e_shnum, e_shstrndx
    let dir = std::env::temp_dir().join(format!("n0xis-sectionless-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("a project of its own");
    let path = dir.join("noshdr.so");
    std::fs::write(&path, &b).expect("write the sectionless copy");
    (dir, path, va)
}

fn n0x(dir: &PathBuf, args: &[&str]) -> Value {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).current_dir(dir).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{args:?}: {e}: {}", String::from_utf8_lossy(&out.stdout)))
}

#[test]
fn reads_by_address_go_through_the_loadable_segments() {
    let (dir, path, va) = sectionless();
    let file = path.to_str().unwrap();
    let addr = format!("{va:#x}");

    let read = n0x(&dir, &["mem", "read", "--file", file, "--addr", &addr, "--size", &PLANTED.len().to_string()]);
    assert_eq!(read["ok"], true, "{read}");
    let hex: String = PLANTED.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
    assert_eq!(read["data"]["hex"], hex, "{read}");

    let span = n0x(&dir, &["mem", "span", "--file", file, "--addr", &addr, "--size", "16"]);
    assert_eq!(span["data"]["read"], 16, "{span}");

    let found = n0x(&dir, &["find", "--file", file, "--string", "n0xis-planted-ascii"]);
    let at: Vec<&str> = found["data"]["matches"].as_array().into_iter().flatten().filter_map(|m| m["va"].as_str()).collect();
    assert_eq!(at, [addr.as_str()], "{found}");

    let strings = n0x(&dir, &["strings", "--file", file, "--contains", "planted-ascii"]);
    let at: Vec<&str> = strings["data"]["strings"].as_array().into_iter().flatten().filter_map(|s| s["address"].as_str()).collect();
    assert_eq!(at, [addr.as_str()], "{strings}");
}

#[test]
fn what_a_section_name_finds_is_said_to_be_not_read() {
    let (dir, path, _) = sectionless();
    let file = path.to_str().unwrap();
    let has_eh_frame_segment = program_headers(&std::fs::read(&path).unwrap()).iter().any(|&(ty, ..)| ty == 0x6474_e550);
    assert!(has_eh_frame_segment, "the fixture has a PT_GNU_EH_FRAME");

    let eh = n0x(&dir, &["function", "eh", "--file", file]);
    let message = eh["error"]["message"].as_str().unwrap_or_else(|| panic!("a refusal: {eh}"));
    assert!(message.contains("no section headers") && !message.starts_with("neither"), "{eh}");

    let profile = n0x(&dir, &["profile", "--file", file]);
    let said = profile["data"]["advisories"].as_array().into_iter().flatten().any(|a| a["reason"].as_str().is_some_and(|r| r.contains("no section headers")));
    assert!(said, "{profile}");
}
