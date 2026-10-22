// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Each side of a diff is decoded as its own image declares** (the lead's
//! DECISIONS item 11, with docs/design/WASM.md stage 2's refusal sub-step).
//!
//! `diff.functions` took x86-64 for both sides whatever the files said
//! (`resolve_arch` with no flag), so an AArch64 pair was diffed as x86: on
//! this fixture's `fresh(void*)` the 0.3.5 build answered `// asm: std` and
//! `rax.1 = …` over four-byte A64 instructions, `ok: true`. The pair's lines
//! are checked against `decomp.pseudo`'s for the same function and style,
//! which reads the header and is the other door onto one decompile.

use std::path::Path;

use serde_json::{Value, json};

#[test]
fn each_side_of_a_diff_is_decoded_as_its_image_declares() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../n0xis-sources/tests/fixtures/itanium_vtables/vt-aarch64-linux-gnu");
    let file = fixture.to_str().expect("utf-8 path");
    // `fresh(void*)`, at `0x2105a4` (`llvm-nm`: `T _Z5freshPv`).
    let addr = "0x2105a4";
    // The registry reads and writes the working directory's project.
    let root = std::env::temp_dir().join(format!("n0xis-diff-header-{}", std::process::id()));
    std::fs::create_dir_all(root.join(".n0x")).expect("scratch project");
    std::env::set_current_dir(&root).expect("into the scratch project");
    let reg = n0xis_frontend::build_registry();
    let ask = |cap: &str, args: Value| serde_json::to_value(reg.dispatch(cap, &args)).expect("an envelope");

    let diff = ask("diff.functions", json!({ "a_file": file, "a_addr": addr, "b_file": file, "b_addr": addr, "style": "goto" }));
    assert_eq!(diff["ok"], true, "{diff}");
    let side_a: Vec<&str> = diff["data"]["hunks"].as_array().unwrap().iter().map(|h| h["text"].as_str().unwrap()).collect();
    assert!(side_a.iter().any(|l| l.contains("x29")), "an AArch64 function, decoded as one, saves x29: {side_a:?}");
    assert!(!side_a.iter().any(|l| l.contains("rax")), "no x86 register in an AArch64 function: {side_a:?}");
    let decomp = ask("decomp.pseudo", json!({ "file": file, "addr": addr, "style": "goto" }));
    let pseudo: Vec<&str> = decomp["data"]["pseudo"].as_array().unwrap().iter().map(|l| l.as_str().unwrap()).collect();
    assert_eq!(side_a.first(), pseudo.first(), "the same function's signature through both doors");
    assert_eq!(side_a.get(2), pseudo.get(2), "the same first instruction through both doors");
    let _ = std::env::set_current_dir(std::env::temp_dir());
    let _ = std::fs::remove_dir_all(&root);
}
