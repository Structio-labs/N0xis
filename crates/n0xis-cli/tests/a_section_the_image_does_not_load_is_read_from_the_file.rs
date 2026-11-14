// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A section the image does not load is read from the file.** `find` and
//! `strings` said they read "every file-backed section" and left out every
//! section without `SHF_ALLOC` (`.comment`, `.symtab`): a string the file holds
//! there was `count: 0`, and `strings --section .comment` refused as no such
//! section (audit 2026-11-06). Such a section has no address, so its hits are
//! listed apart, in `unmapped`, by file offset; the rows that were there keep
//! their shape and are only ever loaded addresses.
//!
//! The oracle is the file: where the compiler's `GCC: (` stands, and the
//! section header (read here, `support`) that holds it without `SHF_ALLOC`.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

mod support;

const ELF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/strings_planted.so");

/// Where `GCC: (` is in the file, checked to lie in a section not loaded.
fn planted() -> u64 {
    let b = std::fs::read(ELF).unwrap();
    let at = b.windows(6).position(|w| w == b"GCC: (").expect("the compiler names itself") as u64;
    // Not an SHT_NOBITS section, which holds no bytes of the file.
    let holder = support::elf64_section_headers(&b).into_iter().find(|s| s.4 != 8 && (s.2..s.2 + s.3).contains(&at)).expect("a section holds it");
    assert_eq!(holder.0 & 2, 0, "it is in a section without SHF_ALLOC");
    at
}

fn n0x(tag: &str, args: &[&str]) -> Value {
    let dir: PathBuf = std::env::temp_dir().join(format!("n0xis-unloaded-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(dir.join(".n0x")).unwrap();
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).current_dir(&dir).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{args:?}: {e}: {}", String::from_utf8_lossy(&out.stdout)))
}

fn offsets(v: &Value) -> Vec<String> {
    v["data"]["unmapped"].as_array().into_iter().flatten().filter_map(|r| r["file_offset"].as_str()).map(str::to_string).collect()
}

#[test]
fn find_lists_a_hit_in_a_section_not_loaded_by_its_file_offset() {
    let at = format!("{:#x}", planted());
    let v = n0x("find", &["find", "--file", ELF, "--string", "GCC: ("]);
    assert_eq!(offsets(&v), [at.as_str()], "{v}");
    assert_eq!(v["data"]["matches"], serde_json::json!([]), "the rows are loaded addresses only: {v}");
    let read = &v["data"]["unmapped_sections"]["read"];
    assert!(read.as_array().unwrap().iter().any(|s| s == ".comment"), "{v}");
    // A window is about itself: nothing outside memory is read.
    let w = n0x("find-window", &["find", "--file", ELF, "--string", "GCC: (", "--start", "0x2000", "--size", "0x10"]);
    assert!(w["data"].get("unmapped_sections").is_none(), "{w}");
}

#[test]
fn strings_reads_a_section_not_loaded_whole_or_named() {
    let at = format!("{:#x}", planted());
    let named = n0x("strings-named", &["strings", "--file", ELF, "--section", ".comment"]);
    assert_eq!(named["ok"], true, "{named}");
    assert_eq!(offsets(&named), [at.as_str()], "{named}");
    assert!(named["data"]["unmapped"][0]["text"].as_str().unwrap().starts_with("GCC: ("), "{named}");
    let whole = n0x("strings-whole", &["strings", "--file", ELF, "--contains", "GCC: ("]);
    assert_eq!(offsets(&whole), [at.as_str()], "{whole}");
    assert_eq!(whole["data"]["count"], 0, "no loaded address holds it: {whole}");
}
