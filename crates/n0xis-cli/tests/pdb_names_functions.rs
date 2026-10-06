// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A matching PDB names the image's functions; any other PDB is never used.**
//!
//! The image and PDB are `n0xis-pdb`'s fixture, built from known source: its
//! static `helper_static` (RVA `0x1660`, 6 bytes) has no export, no public name
//! and no unwind entry, so only the PDB can name it or say how long it is.
//! "Another build" is made exactly: a copy of the image with one byte of its
//! CodeView GUID changed, or its age, so the PDB beside it no longer belongs.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const HELPER: &str = "0x140001660";
const MAIN: &str = "0x1400015d0";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../n0xis-pdb/tests/fixtures").join(name)).expect("the fixture")
}

/// A fresh project folder holding the image (changed by `edit`) and, if
/// `beside`, its PDB.
fn project(name: &str, beside: bool, edit: impl FnOnce(&mut Vec<u8>)) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis-pdb-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("a project folder");
    let mut image = fixture("pdbtarget.exe");
    edit(&mut image);
    std::fs::write(dir.join("pdbtarget.exe"), image).unwrap();
    if beside {
        std::fs::write(dir.join("pdbtarget.pdb"), fixture("pdbtarget.pdb")).unwrap();
    }
    dir
}

/// Where the image's CodeView record starts (`RSDS`, then the GUID, then the age).
fn codeview(image: &[u8]) -> usize {
    let at: Vec<usize> = image.windows(4).enumerate().filter(|(_, w)| *w == b"RSDS").map(|(i, _)| i).collect();
    assert_eq!(at.len(), 1, "one CodeView record");
    at[0]
}

fn run(cwd: &Path, args: &[&str]) -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_n0xis")).current_dir(cwd).args(args).arg("--quiet").output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("one envelope from {args:?}: {e}"))
}

/// The function list's entry at `va`.
fn listed(cwd: &Path, va: &str) -> Value {
    let found = run(cwd, &["function", "discover", "--file", "pdbtarget.exe"]);
    found["data"]["functions"].as_array().expect("a function list").iter().find(|f| f["va"] == va).cloned().unwrap_or(Value::Null)
}

#[test]
fn a_pdb_beside_the_image_names_its_functions_and_states_their_length() {
    let dir = project("beside", true, |_| {});
    let helper = listed(&dir, HELPER);
    assert_eq!((helper["name"].as_str(), helper["end"].as_str()), (Some("helper_static"), Some("0x140001666")), "{helper}");
    let pseudo = run(&dir, &["decomp", "pseudo", "--file", "pdbtarget.exe", "--addr", MAIN]);
    let text = pseudo["data"]["pseudo"].as_array().expect("pseudo-code").iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n");
    for callee in ["record_failure(", "doubled_timeout(", "helper_static(", "state_of("] {
        assert!(text.contains(callee), "main calls {callee}…:\n{text}");
    }
    let debug = &run(&dir, &["profile", "--file", "pdbtarget.exe"])["data"]["debug_info"];
    assert_eq!((debug["guid"].as_str(), debug["age"].as_u64()), (Some("90BA008E-0CF5-2548-4C4C-44205044422E"), Some(1)));
    assert_eq!((debug["matched"]["functions"].as_u64(), debug["matched"]["with_length"].as_u64()), (Some(43), Some(5)), "{debug}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn without_a_pdb_the_image_says_where_it_looked() {
    let dir = project("none", false, |_| {});
    let helper = listed(&dir, HELPER);
    assert_eq!((helper["name"].as_str(), helper.get("end")), (Some("sub_140001660"), None), "{helper}");
    let debug = &run(&dir, &["profile", "--file", "pdbtarget.exe"])["data"]["debug_info"];
    assert!(debug["matched"].is_null(), "{debug}");
    let looked: Vec<&str> = debug["looked"].as_array().unwrap().iter().filter_map(|l| l["found"].as_str()).collect();
    assert_eq!(looked, ["nothing", "nothing"], "beside the image and in the store: {debug}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_pdb_of_another_build_is_never_used() {
    // The GUID's first byte, or the age, no longer what the PDB carries.
    for (name, at) in [("guid", 4), ("age", 20)] {
        let dir = project(&format!("other-{name}"), true, |image| {
            let at = codeview(image) + at;
            image[at] ^= 0x01;
        });
        let helper = listed(&dir, HELPER);
        assert_eq!(helper["name"].as_str(), Some("sub_140001660"), "{name}: {helper}");
        let debug = &run(&dir, &["profile", "--file", "pdbtarget.exe"])["data"]["debug_info"];
        assert!(debug["matched"].is_null(), "{name}: {debug}");
        assert_eq!(debug["looked"][0]["found"], "the PDB of another build", "{name}: {debug}");
        assert_eq!(debug["looked"][0]["guid"], "90BA008E-0CF5-2548-4C4C-44205044422E", "the PDB's own identity is reported");
        let added = run(&dir, &["symbols", "add", "--file", "pdbtarget.exe", "--pdb", "pdbtarget.pdb"]);
        assert_eq!(added["error"]["code"], "pdb-mismatch", "{name}: {added}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn a_pdb_kept_in_the_store_is_found() {
    let elsewhere = project("store-source", true, |_| {});
    let dir = project("store", false, |_| {});
    let pdb = elsewhere.join("pdbtarget.pdb");
    let added = run(&dir, &["symbols", "add", "--file", "pdbtarget.exe", "--pdb", pdb.to_str().unwrap()]);
    assert_eq!(added["ok"], true, "{added}");
    let stored = dir.join(".n0x/symbols/pdbtarget.pdb/90BA008E0CF525484C4C44205044422E1/pdbtarget.pdb");
    assert_eq!(std::fs::read(&stored).expect("kept in the store's layout"), fixture("pdbtarget.pdb"));
    let helper = listed(&dir, HELPER);
    assert_eq!((helper["name"].as_str(), helper["end"].as_str()), (Some("helper_static"), Some("0x140001666")), "{helper}");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&elsewhere);
}
