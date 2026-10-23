// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`why` on images whose tables are written down beside them** — the answer
//! whole, so CI holds its shape and its sources without an external tool.
//!
//! The truths, read with tools that are not this one when this was written:
//!
//! - `tests/fixtures/native_pe.dll` (`native_pe.c`): `llvm-readobj --unwind`
//!   lists three `RuntimeFunction`s, `0x140001000..0x14000102A` (`leaf`),
//!   `0x14000102A..0x140001051` (`mid`), `0x140001051..0x140001077`
//!   (`entry`); `--coff-exports` one export, `entry` at RVA `0x1051` with
//!   `ImageBase` `0x140000000`; `objdump -d` the first call to `0x140001000`
//!   at `0x140001035`, in `mid`. `entry` starts where `mid`'s declared extent
//!   ends, which is the after-a-declared-end rule's case by construction.
//! - `n0xis-wasm/tests/fixtures/core.wasm`: `wasm-objdump -d` puts `func[1]`'s
//!   body at `0x105` (`core.disassembly.txt`), `-x` gives it `size=7`
//!   (`core.details.txt`), and nothing names it.
//!
//! The rest of the claims, on every listed function of real images, are
//! checked against those tools by `why_names_the_tables_it_read.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

mod support;

fn why(image: &Path, addr: &str) -> Value {
    // A project of its own: the function list `why` reads is kept there.
    let dir = std::env::temp_dir().join(format!("n0xis_why_committed_{}_{}", std::process::id(), addr));
    std::fs::create_dir_all(dir.join(".n0x")).expect("project");
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .args(["why", "--quiet", "--addr", addr, "--file"])
        .arg(image)
        .current_dir(&dir)
        .output()
        .expect("run n0xis why");
    let _ = std::fs::remove_dir_all(&dir);
    let v: Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["meta"]["schema"], "n0xis.why.v1");
    v["data"].clone()
}

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

#[test]
fn an_address_inside_a_function_names_every_source_of_it() {
    let got = why(&fixture("tests/fixtures/native_pe.dll"), "0x140001010");
    assert_eq!(
        got,
        json!({
            "addr": "0x140001010",
            "function": {"found": {
                "start": "0x140001000",
                "addr_is_start": false,
                "start_sources": [
                    {"source": "unwind", "table": "pdata"},
                    {"source": "call_target", "from": "0x140001035"},
                ],
                "end": {"va": "0x14000102a", "source": "unwind", "table": "pdata"},
                "name": {"name": "sub_140001000", "source": "fallback", "also": []},
            }}
        })
    );
}

#[test]
fn an_export_is_named_by_the_export_table_and_found_by_three_sources() {
    let got = why(&fixture("tests/fixtures/native_pe.dll"), "0x140001051");
    assert_eq!(
        got["function"]["found"],
        json!({
            "start": "0x140001051",
            "addr_is_start": true,
            "start_sources": [
                {"source": "export"},
                {"source": "unwind", "table": "pdata"},
                {"source": "after_declared_end"},
            ],
            "end": {"va": "0x140001077", "source": "unwind", "table": "pdata"},
            "name": {"name": "entry", "source": "image", "table": "exports", "also": []},
        })
    );
}

#[test]
fn an_address_past_every_stated_end_is_in_no_function_and_says_why() {
    let got = why(&fixture("tests/fixtures/native_pe.dll"), "0x140001080");
    let why = got["function"]["none"]["why"].as_str().unwrap_or_else(|| panic!("not `none`: {got}"));
    assert!(why.contains("0x140001051") && why.contains("0x140001077"), "the nearest start and its end are named: {why}");
}

#[test]
fn a_module_body_is_its_own_start_and_end() {
    let got = why(&fixture("../n0xis-wasm/tests/fixtures/core.wasm"), "0x105");
    assert_eq!(
        got["function"]["found"],
        json!({
            "start": "0x105",
            "index": 1,
            "addr_is_start": true,
            "start_sources": [{"source": "body", "function": 1}],
            "end": {"va": "0x10c", "source": "body", "function": 1},
            "name": {"name": "func_1", "source": "fallback", "also": []},
        })
    );
}
