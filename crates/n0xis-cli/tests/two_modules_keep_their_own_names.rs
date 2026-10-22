// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Two WebAssembly modules in one project, one offset, two names**
//! (docs/design/WASM.md §5 decision 1: the annotation store gains a target
//! scope before any wasm annotation is written).
//!
//! A module's positions are offsets into it, so every module's code sits at
//! small numbers: keyed by the offset alone, a rename saved on one module
//! landed on whatever the other has at the same offset, and on every native
//! image with a function there. Each module's records are kept under its
//! identity; a native target's under the address alone, as before.
//!
//! The two modules here are one fixture and a copy of it with a custom section
//! appended: the same code at the same offsets, and two identities (a module
//! with no `build_id` section is identified by a hash of its bytes).

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// `mix32`'s body in the fixture (wasm-objdump -d: `0003d1 func[7] <mix32>:`).
const BODY: &str = "0x3d1";

fn run(root: &Path, args: &[&str]) -> Value {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).arg("--quiet").current_dir(root).output().expect("n0xis runs");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{args:?}: not JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)))
}

fn name_at(root: &Path, file: &str) -> String {
    let v = run(root, &["function", "discover", "--file", file, "--limit", "0"]);
    let f = v["data"]["functions"].as_array().unwrap_or_else(|| panic!("{v}")).iter().find(|f| f["va"] == BODY).cloned();
    f.and_then(|f| f["name"].as_str().map(str::to_string)).unwrap_or_else(|| panic!("no function at {BODY}: {v}"))
}

#[test]
fn two_modules_keep_two_names_at_one_offset() {
    let root: PathBuf = std::env::temp_dir().join(format!("n0xis-two-modules-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".n0x")).expect("scratch project");
    let fixture = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../n0xis-wasm/tests/fixtures/ctarget-O2.wasm")).expect("fixture");
    let mut copy = fixture.clone();
    // A custom section named `pad`: id 0, size 4, then the name.
    copy.extend_from_slice(&[0x00, 0x04, 0x03, b'p', b'a', b'd']);
    let (a, b) = (root.join("a.wasm"), root.join("b.wasm"));
    std::fs::write(&a, &fixture).expect("a");
    std::fs::write(&b, &copy).expect("b");
    let (a, b) = (a.to_str().unwrap(), b.to_str().unwrap());
    assert_eq!(name_at(&root, a), "mix32", "before any rename, the name section's");

    for (file, name) in [(a, "first"), (b, "second")] {
        let v = run(&root, &["annotate", "name", "--addr", BODY, "--value", name, "--file", file]);
        assert_eq!(v["ok"], true, "{v}");
    }
    // A native record at the same number, written with no target, as before.
    assert_eq!(run(&root, &["annotate", "name", "--addr", BODY, "--value", "native"])["ok"], true);

    assert_eq!(name_at(&root, a), "first", "the first module keeps its own rename");
    assert_eq!(name_at(&root, b), "second", "the second keeps its own");
    let native = run(&root, &["annotate", "show", "--addr", BODY]);
    assert_eq!(native["data"]["name"], "native", "the native record is the native target's: {native}");
    let one = run(&root, &["annotate", "show", "--addr", BODY, "--file", a]);
    assert_eq!(one["data"]["name"], "first", "{one}");

    // Listing the native records says the modules' are kept apart.
    let list = run(&root, &["annotate", "list"]);
    assert_eq!(list["data"]["count"], 1, "{list}");
    assert!(list["meta"]["note"].as_str().is_some_and(|n| n.contains("2 WebAssembly module")), "{list}");
    let _ = std::fs::remove_dir_all(&root);
}
