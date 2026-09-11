// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The Phase 1 exit test** (ROADMAP P1 / CONCEPT §4).
//!
//! Proves the seams hold: the analysis core decodes real instructions driven
//! by a mock [`Snapshot`] source and the [`X64`] arch — with **zero Windows /
//! OS APIs linked**. If a concrete OS adapter ever leaked into `n0xis-core`,
//! this test would need it to compile; that it doesn't is the boundary.

use n0xis_arch::{InsnKind, X64};
use n0xis_contracts::Va;
use n0xis_core::{Ctx, DecodeInput, DecodePass, Pass};
use n0xis_sources::Snapshot;

#[test]
fn core_decodes_over_mock_source_with_no_os() {
    // 48 89 C8 = mov rax, rcx ; 48 83 C0 04 = add rax, 4 ; C3 = ret
    let code = vec![0x48u8, 0x89, 0xC8, 0x48, 0x83, 0xC0, 0x04, 0xC3];
    let snap = Snapshot::builder()
        .region(Va(0x140001000), code)
        .label("snapshot:boundary-test")
        .build();
    let arch = X64::new();

    let ctx = Ctx::new(&snap, &arch);
    let pass = DecodePass;
    let out = pass
        .run(&ctx, DecodeInput::count(Va(0x140001000), 8))
        .expect("decode should succeed over the mock source");

    assert_eq!(out.count, 3, "three instructions decoded");
    assert_eq!(out.insns[0].mnemonic, "mov");
    assert!(out.insns[0].text.contains("rax"));
    assert_eq!(out.insns[1].mnemonic, "add");
    assert_eq!(out.insns[2].kind, InsnKind::Ret);
    assert_eq!(out.bytes_consumed, 8);
}

#[test]
fn decode_output_serializes_to_the_v1_schema_shape() {
    let snap = Snapshot::builder()
        .region(Va(0x1000), vec![0xC3u8])
        .build();
    let arch = X64::new();
    let ctx = Ctx::new(&snap, &arch);
    let out = DecodePass
        .run(&ctx, DecodeInput::count(Va(0x1000), 4))
        .unwrap();

    let v = serde_json::to_value(&out).unwrap();
    assert_eq!(v["start"], "0x1000");
    assert_eq!(v["count"], 1);
    assert_eq!(v["insns"][0]["kind"], "ret");
    // bytes render as a spaced hex string, addresses as hex strings
    assert_eq!(v["insns"][0]["bytes"], "c3");
    assert_eq!(v["insns"][0]["va"], "0x1000");
}
