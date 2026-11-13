// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A count of nothing says what kind of thing was not read.** `rtti scan` on a
//! PE reads MSVC's RTTI only; on a PE built for the GNU ABI, whose classes are
//! Itanium `_ZTV`/`_ZTI` objects, it answered `count: 0` and nothing else, the
//! shape of "this image has no class" (audit 2026-11-06).

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

mod support;

fn n0x(args: &[&str]) -> Value {
    let dir: PathBuf = std::env::temp_dir().join(format!("n0xis-nothing-{}", std::process::id()));
    std::fs::create_dir_all(dir.join(".n0x")).expect("a project of its own");
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).current_dir(&dir).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{args:?}: {e}: {}", String::from_utf8_lossy(&out.stdout)))
}

#[test]
fn an_rtti_scan_of_a_pe_that_finds_nothing_says_only_msvc_is_read() {
    // A mingw-built PE: no MSVC RTTI in it.
    const PE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/chained/chained.dll");
    let v = n0x(&["rtti", "scan", "--file", PE]);
    assert_eq!(v["data"]["count"], 0, "{v}");
    let said = v["data"]["not_read"].as_str().unwrap_or_else(|| panic!("nothing said of what was not read: {v}"));
    assert!(said.contains("only MSVC RTTI is read") && said.contains("Itanium"), "{v}");
}

/// `profile` named the version of the metadata beside an image and said nothing
/// when `il2cpp metadata` reads no file of that version (field report
/// 2026-11-12). The metadata is planted: the sanity word, then version 99.
#[test]
fn a_metadata_version_il2cpp_metadata_does_not_read_is_said() {
    const ELF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/strings_planted.so");
    let dir = std::env::temp_dir().join(format!("n0xis-meta-version-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let meta = dir.join("x_Data").join("il2cpp_data").join("Metadata");
    std::fs::create_dir_all(&meta).unwrap();
    std::fs::create_dir_all(dir.join(".n0x")).unwrap();
    let mut blob = 0xFAB1_1BAFu32.to_le_bytes().to_vec();
    blob.extend(99u32.to_le_bytes());
    blob.resize(256, 0);
    std::fs::write(meta.join("global-metadata.dat"), blob).unwrap();
    let image = dir.join("image.so");
    std::fs::copy(ELF, &image).unwrap();
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .args(["profile", "--file", image.to_str().unwrap()])
        .current_dir(&dir)
        .output()
        .expect("run n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).expect("JSON");
    assert_eq!(v["data"]["il2cpp"]["metadata_version"], 99, "{v}");
    let said = v["data"]["advisories"].as_array().into_iter().flatten().any(|a| {
        a["command"] == "il2cpp metadata" && a["reason"].as_str().is_some_and(|r| r.contains("version 99") && r.contains("16..=31"))
    });
    assert!(said, "{v}");
    // The metadata `il2cpp metadata` reads is not advised against.
    let mut blob = 0xFAB1_1BAFu32.to_le_bytes().to_vec();
    blob.extend(29u32.to_le_bytes());
    blob.resize(256, 0);
    std::fs::write(meta.join("global-metadata.dat"), blob).unwrap();
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .args(["profile", "--file", image.to_str().unwrap()])
        .current_dir(&dir)
        .output()
        .expect("run n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).expect("JSON");
    assert!(!v["data"]["advisories"].as_array().into_iter().flatten().any(|a| a["command"] == "il2cpp metadata"), "{v}");
}
