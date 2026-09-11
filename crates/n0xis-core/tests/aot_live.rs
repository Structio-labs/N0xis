// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Live validation of the NativeAOT reader against a real shipped .NET
//! NativeAOT image.
//!
//! The image is **not** committed and is **not** named here: point
//! `N0XIS_AOT_TEST_DLL` at any NativeAOT-published `.dll` and the test runs;
//! leave it unset and the test skips. That keeps the check reproducible on any
//! machine without binding it to one person's disk or to a particular program.

use std::path::PathBuf;

#[test]
fn resolves_managed_names_from_a_nativeaot_image() {
    let Ok(dll) = std::env::var("N0XIS_AOT_TEST_DLL") else {
        eprintln!("skip: set N0XIS_AOT_TEST_DLL to a NativeAOT-published .dll to run this");
        return;
    };
    let dll = PathBuf::from(dll);
    if !dll.exists() {
        eprintln!("skip: N0XIS_AOT_TEST_DLL does not exist");
        return;
    }
    let pe = n0xis_sources::StaticPe::load(dll.as_path()).expect("load pe");
    let art = n0xis_core::parse_aot(&pe, pe.image_base()).expect("parse aot");

    eprintln!(
        "header_rva=0x{:x} version={} methods={} embedded=0x{:x}({}) map=0x{:x}({})",
        art.header_rva,
        art.version,
        art.method_count,
        art.embedded_metadata.rva,
        art.embedded_metadata.size,
        art.rva_to_token.rva,
        art.rva_to_token.size,
    );
    assert!(art.method_count > 100, "expected a populated map");

    if std::env::var_os("N0X_AOT_DEBUG").is_some() {
        let clip = |s: &str, n: usize| -> String { s.chars().take(n).collect() };
        let clean = art.symbols.iter().filter(|s| s.name.is_ascii()).count();
        eprintln!("[diag] returned={} clean_ascii_names={}/{}",
            art.symbols.len(), clean, art.symbols.len());
        eprintln!("[diag] sample of ASCII names:");
        for s in art.symbols.iter().filter(|s| s.name.is_ascii() && s.name.contains('.')).take(20) {
            eprintln!("  0x{:<8x} {}", s.rva, clip(&s.display, 100));
        }
    }

    // Every entry resolves to a clean, fully-qualified managed name.
    assert_eq!(
        art.symbols.iter().filter(|s| s.name.is_ascii()).count(),
        art.symbols.len(),
        "some names failed to resolve to clean ASCII"
    );
    eprintln!(
        "[diag] method_count={} stacktrace={} invoke={}",
        art.method_count, art.stacktrace_count, art.invoke_count
    );
    // Both sources resolve end to end: the stack-trace table and the invoke
    // map each contribute at least one entry, and every entry is a clean,
    // fully-qualified managed name. Asserting on *counts per source* rather
    // than on particular symbols keeps the check valid for any NativeAOT image.
    assert!(art.stacktrace_count > 0, "no stack-trace names resolved");
    assert!(art.invoke_count > 0, "no invoke-map names resolved");
    assert!(
        art.symbols.iter().any(|s| s.name.contains('.')),
        "expected fully-qualified managed names"
    );
}
