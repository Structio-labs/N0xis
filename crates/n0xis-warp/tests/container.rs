// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Verifies the WARP container reader against Vector 35's reference `warp` crate.
//!
//! `fixtures/random.warp` is Vector 35's own fixture; `fixtures/random.expected.txt`
//! is the `name|guid` output of their `dumper` example over it. If `read_warp`
//! reproduces that output exactly, our hand-written FlatBuffers parser reads the
//! real format the reference implementation writes.
#![cfg(feature = "container")]

use n0xis_warp::read_warp;

#[test]
fn reads_the_reference_fixture_identically_to_warps_own_dumper() {
    let bytes = include_bytes!("fixtures/random.warp");
    let expected = include_str!("fixtures/random.expected.txt");

    let funcs = read_warp(bytes).expect("fixture must parse");

    let got: Vec<String> = funcs
        .iter()
        .map(|f| format!("{}|{}", f.name.as_deref().unwrap_or(""), f.guid))
        .collect();
    let want: Vec<String> = expected.lines().map(str::to_string).collect();

    assert_eq!(got.len(), want.len(), "function count must match the reference");
    assert_eq!(got, want, "every (name, guid) pair must match the reference dumper");
}

#[test]
fn a_truncated_file_returns_none_or_empty_without_panicking() {
    let bytes = include_bytes!("fixtures/random.warp");
    // Every truncation must be handled by the bounds checks — never a panic.
    for cut in [1usize, 8, 32, 100, bytes.len() / 2, bytes.len() - 1] {
        let _ = read_warp(&bytes[..cut]);
    }
}
