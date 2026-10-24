// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`contradictions` on images where each kind was planted once, at a known
//! place** — the answer whole, so an empty list, a missing kind or an extra one
//! fails here (docs/design/WHY.md §6 item 1).
//!
//! What is planted, and the tools that say so (recorded beside each fixture,
//! `tests/fixtures/contradictions/plant.sh`):
//!
//! - `planted.so` (`planted.s`): `objdump --dwarf=frames` lists four FDEs,
//!   `0x1000..0x1010`, `0x1010..0x1020`, `0x1018..0x1020`, `0x1020..0x1030`
//!   (`planted.so.frames.txt`); `readelf -sW` gives `ends_twice` at `0x1000`
//!   size 8, `outer` at `0x1010` size 0, `inner` at `0x1018` size 8, and at
//!   `0x1020` `symtab_name` in `.symtab` and `exported_name` in `.dynsym`,
//!   each size 16 (`planted.so.symbols.txt`). So: one start with two ends
//!   (`0x1000`: 8 bytes by `st_size`, 16 by its FDE), one overlap (`outer`'s
//!   FDE reaches past `inner`'s start), one address two tables name with
//!   nothing in common.
//! - `same_table.so` (`same_table.s`): `objdump --dwarf=frames` lists two
//!   FDEs at `0x1000`, of 16 and 8 bytes; `readelf -sW` two symbols there,
//!   `twice` of 16 bytes and `twice_alias` of 12, in both tables. One start,
//!   three ends, each table stating two of them.
//! - `planted.wasm` (`planted.wat`): `wasm-objdump -x` names function 1
//!   `internal_name` in the name section and exports it as `exported_name`,
//!   and places data segment 0 at 65530 with 10 bytes in a memory of exactly
//!   one page (`planted.wasm.details.txt`).
//! - `n0xis-pdb`'s `pdbtarget.exe` with its PDB beside it: `llvm-readobj
//!   --unwind` gives `main`'s `RUNTIME_FUNCTION` as `0x1400015D0..0x14000165B`
//!   and `llvm-pdbutil` its procedure as 139 bytes (the fixture's README); the
//!   test moves that entry's end 4 bytes in, so `.pdata` and the PDB disagree.
//! - `n0xis-sources`' `contested-x86_64.so`: `llvm-readobj -r` puts two
//!   `JUMP_SLOT` relocations at `0x4000` (`contested-x86_64.so.readobj.txt`),
//!   which the image reader reports as a contradiction of its own.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

mod support;

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// A project of its own, holding copies of `files`.
fn project(tag: &str, files: &[PathBuf]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis_contradictions_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("project");
    for f in files {
        std::fs::copy(f, dir.join(f.file_name().expect("a file name"))).expect("copy a fixture");
    }
    dir
}

fn run(dir: &Path, args: &[&str]) -> Value {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).arg("--quiet").current_dir(dir).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("one JSON object from {args:?}: {e}"))
}

/// The answer's `data`, after checking the envelope.
fn contradictions(dir: &Path, file: &str) -> Value {
    let v = run(dir, &["contradictions", "--file", file]);
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["meta"]["schema"], "n0xis.contradictions.v1");
    assert_eq!(v["meta"]["total"], v["data"]["count"], "one page holds them all: {v}");
    v["data"].clone()
}

fn eh_frame() -> Value {
    json!({"source": "unwind", "table": "eh_frame"})
}

fn st_size() -> Value {
    json!({"source": "symbol_size", "of": "st_size"})
}

#[test]
fn an_elf_with_each_kind_planted_once_reports_each_once() {
    let dir = project("elf", &[fixture("tests/fixtures/contradictions/planted.so")]);
    let got = contradictions(&dir, "planted.so");
    let end = json!({"kind": "end", "start": "0x1000", "ends": [
        {"end": "0x1008", "by": [st_size()]},
        {"end": "0x1010", "by": [eh_frame()]},
    ]});
    assert_eq!(got["contradictions"][0], end, "the end planted at 0x1000: {got}");
    let overlap = json!({"kind": "overlap",
        "first": {"start": "0x1010", "end": "0x1020", "by": [eh_frame()]},
        "second": {"start": "0x1018", "end": "0x1020", "by": [eh_frame(), st_size()]},
    });
    assert_eq!(got["contradictions"][1], overlap, "the overlap planted at 0x1010: {got}");
    let name = json!({"kind": "name", "addr": "0x1020", "names": [
        {"source": "image", "table": "static", "name": "symtab_name", "compared_as": "symtab_name"},
        {"source": "image", "table": "dynamic", "name": "exported_name", "compared_as": "exported_name"},
    ]});
    assert_eq!(got["contradictions"][2], name, "the name planted at 0x1020: {got}");
    assert_eq!(got["count"], 3, "nothing but what was planted: {got}");
    let checked = |kind: &str| got["kinds"][kind]["checked"]["count"].clone();
    assert_eq!((checked("end"), checked("overlap"), checked("name"), checked("image")), (json!(1), json!(1), json!(1), json!(0)), "{got}");
    assert_eq!(got["kinds"]["name"]["sources"], json!([{"source": "image", "table": "static"}, {"source": "image", "table": "dynamic"}]));
    assert_eq!(got["overrides"], json!({"count": 0, "at": []}));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two FDEs for one start and two symbols of one address with different
/// sizes: the image's own tables each state two ends, and every one is kept
/// to be compared, not only the first each lookup answers with.
#[test]
fn a_table_that_states_two_ends_for_one_start_is_an_end_contradiction() {
    let dir = project("same_table", &[fixture("tests/fixtures/contradictions/same_table.so")]);
    let got = contradictions(&dir, "same_table.so");
    assert_eq!(
        got["contradictions"],
        json!([{"kind": "end", "start": "0x1000", "ends": [
            {"end": "0x1008", "by": [eh_frame()]},
            {"end": "0x100c", "by": [st_size()]},
            {"end": "0x1010", "by": [eh_frame(), st_size()]},
        ]}]),
        "{got}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A rename is the user's decision, not a disagreement: it is counted as an
/// override of the layer whose name it replaces, and the layers' own
/// disagreements stay as they were.
#[test]
fn a_rename_is_an_override_and_not_a_contradiction() {
    let dir = project("override", &[fixture("tests/fixtures/contradictions/planted.so")]);
    for (addr, value) in [("0x1018", "mine"), ("0x1020", "also_mine")] {
        assert_eq!(run(&dir, &["annotate", "name", "--file", "planted.so", "--addr", addr, "--value", value])["ok"], true);
    }
    let got = contradictions(&dir, "planted.so");
    assert_eq!(
        got["overrides"],
        json!({"count": 2, "at": [
            {"addr": "0x1018", "name": "mine", "overrode": {"source": "image", "table": "static", "name": "inner"}},
            {"addr": "0x1020", "name": "also_mine", "overrode": {"source": "image", "table": "static", "name": "symtab_name"}},
        ]})
    );
    let kinds: Vec<&str> = got["contradictions"].as_array().expect("a list").iter().filter_map(|c| c["kind"].as_str()).collect();
    assert_eq!(kinds, ["end", "overlap", "name"], "{got}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_module_with_a_name_and_an_image_contradiction_reports_both() {
    let dir = project("wasm", &[fixture("tests/fixtures/contradictions/planted.wasm")]);
    let got = contradictions(&dir, "planted.wasm");
    assert_eq!(
        got["contradictions"],
        json!([
            {"kind": "name", "addr": "0x3f", "names": [
                {"source": "image", "table": "name_section", "name": "internal_name", "compared_as": "internal_name"},
                {"source": "image", "table": "exports", "name": "exported_name", "compared_as": "exported_name"},
            ]},
            {"kind": "image", "what": "data segment 0 is placed at 0xfffa in memory 0 and ends at 0x10004, and the memory is exactly 0x10000 bytes when instantiated: instantiation traps on it"},
        ])
    );
    let checked = |kind: &str| got["kinds"][kind]["checked"]["count"].clone();
    assert_eq!((checked("end"), checked("overlap"), checked("name"), checked("image")), (json!(0), json!(0), json!(1), json!(1)), "{got}");
    // A module's bodies are one sort of source, however many there are.
    assert_eq!(got["kinds"]["end"]["sources"], json!([{"source": "body"}]));
    let _ = std::fs::remove_dir_all(&dir);
}

/// `main`'s `.pdata` end moved 4 bytes in, with the PDB beside the image: one
/// end, and the PDB's length is one of its two values. Without the PDB the
/// same image has nothing to disagree with.
#[test]
fn a_pdata_end_the_pdb_does_not_share_is_an_end_contradiction() {
    let pdb = fixture("../n0xis-pdb/tests/fixtures");
    let dir = project("pe", &[pdb.join("pdbtarget.exe"), pdb.join("pdbtarget.pdb")]);
    let image = dir.join("pdbtarget.exe");
    let mut bytes = std::fs::read(&image).expect("the image");
    let entry: Vec<u8> = [0x15d0u32, 0x165b].iter().flat_map(|v| v.to_le_bytes()).collect();
    let at: Vec<usize> = bytes.windows(8).enumerate().filter(|(_, w)| *w == entry.as_slice()).map(|(i, _)| i).collect();
    assert_eq!(at.len(), 1, "main's RUNTIME_FUNCTION is in the image once");
    bytes[at[0] + 4..at[0] + 8].copy_from_slice(&0x1657u32.to_le_bytes());
    std::fs::write(&image, bytes).expect("plant");

    let got = contradictions(&dir, "pdbtarget.exe");
    assert_eq!(
        got["contradictions"],
        json!([{"kind": "end", "start": "0x1400015d0", "ends": [
            {"end": "0x140001657", "by": [{"source": "unwind", "table": "pdata"}]},
            {"end": "0x14000165b", "by": [{"source": "symbol_size", "of": "pdb"}]},
        ]}]),
        "{got}"
    );
    std::fs::remove_file(dir.join("pdbtarget.pdb")).expect("take the PDB away");
    let alone = contradictions(&dir, "pdbtarget.exe");
    assert_eq!(alone["contradictions"], json!([]), "{alone}");
    assert_eq!(alone["kinds"]["end"], json!({"checked": {"count": 0}, "sources": [{"source": "unwind", "table": "pdata"}]}));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_image_readers_own_contradiction_is_passed_on() {
    let so = fixture("../n0xis-sources/tests/fixtures/contested_slot/contested-x86_64.so");
    let dir = project("contested", &[so]);
    let got = contradictions(&dir, "contested-x86_64.so");
    let image: Vec<&Value> = got["contradictions"].as_array().expect("a list").iter().filter(|c| c["kind"] == "image").collect();
    assert_eq!(image.len(), 1, "{got}");
    let what = image[0]["what"].as_str().unwrap_or_default();
    assert!(what.starts_with("2 GLOB_DAT or JUMP_SLOT relocations name the slot at 0x4000"), "{what}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A target with no image file has no image reader: that kind says it was not
/// checked, never "none found".
#[test]
fn a_kind_that_cannot_be_checked_says_so() {
    let dir = project("bytes", &[]);
    let v = run(&dir, &["capability", "run", "contradictions", "--args", r#"{"bytes": "c3", "start": "0x1000"}"#]);
    assert_eq!(v["ok"], true, "{v}");
    let kinds = &v["data"]["kinds"];
    for kind in ["end", "overlap", "name", "image"] {
        assert!(kinds[kind]["not_checked"]["why"].as_str().is_some_and(|w| !w.is_empty()), "{kind}: {kinds}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
