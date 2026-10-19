// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What every test of this crate shares: where the fixtures are and which
//! they are. `fixtures/build.sh` builds them and records the tools' answers.

#![allow(dead_code)]

use std::path::PathBuf;

/// Every fixture, by the stem of its file names.
pub const FIXTURES: [&str; 5] = ["ctarget-O0", "ctarget-O2", "core", "simd", "shapes"];

/// The fixtures written as text, whose every instruction the text states.
pub const TEXT_FIXTURES: [&str; 3] = ["core", "simd", "shapes"];

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
