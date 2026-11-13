// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A search for text finds it in UTF-16 too.** `concept grep` read a file as
//! UTF-8 or, failing that, as runs of ASCII bytes. A UTF-16 file holds each
//! ASCII letter followed by a zero, so no run was found and a file holding the
//! term was not listed, with nothing said; and `xref string` looked for the
//! query's UTF-8 bytes only, so a wide literal referenced by code answered
//! `count: 0, found_unreferenced: 0`, the shape of "not in this image" (audit
//! 2026-11-06). The files are written here, the term planted in each in the
//! encoding named; the image is `strings_planted.so`, whose source plants
//! `u"n0xis wide ✓"` and returns its address.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

mod support;

const TERM: &str = "PLANTED_TERM_ALPHA";

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn dir_with(files: &[(&str, Vec<u8>)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis-wide-{}-{}", files[0].0, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("a project of its own");
    let docs = dir.join("docs");
    std::fs::create_dir_all(&docs).unwrap();
    for (name, bytes) in files {
        std::fs::write(docs.join(name), bytes).unwrap();
    }
    dir
}

fn listed(dir: &PathBuf) -> Vec<String> {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .args(["concept", "grep", TERM, "--dir", "docs"])
        .current_dir(dir)
        .output()
        .expect("run n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)));
    assert_eq!(v["ok"], true, "{v}");
    let hits = v["data"]["hits"].as_array().unwrap_or_else(|| panic!("no hits list: {v}"));
    hits.iter().filter_map(|h| h["id"].as_str()).map(|id| id.rsplit(['/', '\\']).next().unwrap().to_string()).collect()
}

#[test]
fn concept_grep_reads_a_utf16_file() {
    let mut le = vec![0xFF, 0xFE];
    le.extend(utf16le(&format!("notes: {TERM} here\n")));
    let mut be = vec![0xFE, 0xFF];
    be.extend(format!("notes: {TERM} here\n").encode_utf16().flat_map(u16::to_be_bytes));
    let dir = dir_with(&[("le.txt", le), ("be.txt", be)]);
    let mut got = listed(&dir);
    got.sort();
    assert_eq!(got, ["be.txt", "le.txt"]);
}

#[test]
fn concept_grep_reads_wide_runs_in_a_binary_file() {
    // Not UTF-8 (0xFF, 0x00 bytes), with the term held only as UTF-16LE.
    let mut bin = vec![0xFF, 0x00, 0x01, 0x02];
    bin.extend(utf16le(TERM));
    bin.extend([0x00, 0x00, 0xFE, 0x10]);
    let dir = dir_with(&[("res.bin", bin)]);
    assert_eq!(listed(&dir), ["res.bin"]);
}

#[test]
fn xref_string_finds_a_referenced_wide_literal() {
    const ELF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/strings_planted.so");
    let wide: Vec<u8> = "n0xis wide".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let va = support::elf64_load_address_of(&std::fs::read(ELF).unwrap(), &wide);
    let dir = dir_with(&[("xref", Vec::new())]);
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .args(["xref", "string", "--file", ELF, "--query", "n0xis wide"])
        .current_dir(&dir)
        .output()
        .expect("run n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).expect("JSON");
    assert_eq!(v["data"]["count"], 1, "{v}");
    let hit = &v["data"]["hits"][0];
    assert_eq!(hit["address"], format!("{va:#x}"), "{v}");
    assert_eq!(hit["encoding"], "utf16le", "{v}");
    assert!(!hit["xrefs"].as_array().unwrap().is_empty(), "{v}");
}
