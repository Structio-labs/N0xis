// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What every test of this crate shares: where the fixtures are and which
//! they are. `fixtures/build.sh` builds them and records the tools' answers.

#![allow(dead_code)]

use std::path::PathBuf;

pub mod memarg;
pub mod planted;

/// Every fixture, by the stem of its file names.
pub const FIXTURES: [&str; 14] = [
    "ctarget-O0",
    "ctarget-O2",
    "core",
    "simd",
    "shapes",
    "threads",
    "refs",
    "gc",
    "eh",
    "eh-legacy",
    "relaxed",
    "cthreads-O2",
    "ceh-legacy-O2",
    "ceh-exnref-O2",
];

/// The fixtures written as text, whose every instruction the text states.
pub const TEXT_FIXTURES: [&str; 9] = ["core", "simd", "shapes", "threads", "refs", "gc", "eh", "eh-legacy", "relaxed"];

/// The fixtures wabt cannot read at all: for each, `build.sh` records what
/// wabt said (`<stem>.wabt-refuses.txt`) in place of its three recordings.
/// wabt 1.0.42 reads no garbage-collected type.
pub const WABT_REFUSES: [&str; 1] = ["gc"];

/// Whether wabt read this fixture, so that its three recordings exist.
pub fn wabt_reads(stem: &str) -> bool {
    !WABT_REFUSES.contains(&stem)
}

pub fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

pub fn bytes(stem: &str) -> Vec<u8> {
    let path = dir().join(format!("{stem}.wasm"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn text(file: &str) -> String {
    let path = dir().join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn module(stem: &str) -> n0xis_wasm::Module {
    n0xis_wasm::read(&bytes(stem)).unwrap_or_else(|e| panic!("{stem}: {e}"))
}

/// Every defined function's body, decoded, with its index.
pub fn bodies(m: &n0xis_wasm::Module) -> Vec<(n0xis_wasm::FuncIdx, n0xis_wasm::Body)> {
    let first = m.imported_functions();
    (0..m.bodies().len() as u32)
        .map(|i| {
            let func = n0xis_wasm::FuncIdx(first + i);
            let body = m.body(func).expect("a defined function").unwrap_or_else(|e| panic!("func {}: {e}", func.0));
            (func, body)
        })
        .collect()
}
