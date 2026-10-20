// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A file changed in place is a new image.**
//!
//! The project keeps CFGs and decompiles between runs (`.n0x/ir-cache/`,
//! `.n0x/decomp-cache/`), keyed on the source's label, the decoder and the
//! function's own bytes. A decompile reads more than its function: the vtable
//! slot of a devirtualized call, a string for a literal, a jump table. A file
//! rebuilt at the same path with the same function and other data was answered
//! from the old file's entry: a position-independent executable relinked so
//! that its vtable slots hold their methods in the file kept `Plugin::drive`'s
//! call unresolved, as it had been while they read zero, until the cache was
//! deleted by hand.
//!
//! Here one slot of the file is planted in place. The decompile after it, in
//! the same project, must name what the slot holds now, as a fresh project
//! does. The project is a scratch directory with its own `.n0x/`: without one
//! the engine would keep what it writes in the user's global project.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod support;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../n0xis-sources/tests/fixtures/itanium_vtables")
}

/// `llvm-nm`'s address for `symbol` in the fixture's recording.
fn nm(fixture: &str, symbol: &str) -> u64 {
    let text = std::fs::read_to_string(fixtures().join(format!("{fixture}.nm.txt"))).expect("a recording");
    text.lines()
        .find_map(|l| {
            let mut w = l.split_whitespace();
            let (addr, _kind, name) = (w.next()?, w.next()?, w.next()?);
            (name == symbol).then(|| u64::from_str_radix(addr, 16).expect("a hex address"))
        })
        .unwrap_or_else(|| panic!("{fixture}: llvm-nm lists no {symbol}"))
}

/// The methods `decomp pseudo` resolved `function`'s calls to, run in `project`.
fn devirtualized(project: &Path, file: &Path, function: u64) -> Vec<u64> {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .current_dir(project)
        .args(["decomp", "pseudo", "--quiet", "--addr", &format!("{function:#x}"), "--file"])
        .arg(file)
        .output()
        .expect("run n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).expect("one envelope");
    assert_eq!(v["ok"], true, "{v}");
    v["data"]["devirtualized"]
        .as_array()
        .map(|a| a.iter().map(|d| u64::from_str_radix(d["method"].as_str().expect("an address").trim_start_matches("0x"), 16).expect("hex")).collect())
        .unwrap_or_default()
}

#[test]
fn a_decompile_follows_what_the_file_holds_now() {
    let fixture = "vp-x86_64-linux-gnu";
    let (drive, run, code, zti) = (
        nm(fixture, "_ZNK6Plugin5driveEv"),
        nm(fixture, "_ZNK6Plugin3runEv"),
        nm(fixture, "_ZNK5Codec4codeEv"),
        nm(fixture, "_ZTI6Plugin"),
    );
    let root = std::env::temp_dir().join(format!("n0xis-changed-in-place-{}", std::process::id()));
    let fresh = root.join("fresh");
    for dir in [root.join(".n0x"), fresh.join(".n0x")] {
        std::fs::create_dir_all(dir).expect("scratch project");
    }
    let file = root.join("image");
    std::fs::copy(fixtures().join(fixture), &file).expect("copy the fixture");
    assert_eq!(devirtualized(&root, &file, drive), vec![run], "Plugin's first slot holds Plugin::run");

    // Plugin's table as the static executable holds it: offset_to_top, its
    // type_info, then the first slot. Plant Codec::code there.
    let mut bytes = std::fs::read(&file).expect("read the copy");
    let table: Vec<u8> = [0, zti, run].iter().flat_map(|w| w.to_le_bytes()).collect();
    let at: Vec<usize> = bytes.windows(table.len()).enumerate().filter(|(_, w)| *w == table.as_slice()).map(|(i, _)| i).collect();
    assert_eq!(at.len(), 1, "Plugin's table is in the file once");
    bytes[at[0] + 16..at[0] + 24].copy_from_slice(&code.to_le_bytes());
    std::fs::write(&file, &bytes).expect("write the planted copy");

    assert_eq!(devirtualized(&fresh, &file, drive), vec![code], "a fresh project reads the planted slot");
    assert_eq!(devirtualized(&root, &file, drive), vec![code], "the same project after the change: what the slot holds now");
    let _ = std::fs::remove_dir_all(&root);
}
