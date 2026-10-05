// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`analyze` and `function discover` must count the same functions.**
//!
//! They did not. `analyze` ran its own discovery without the functions the
//! image declares (its unwind table, its symbols), so on a Rust binary it found
//! 4 130 functions where `function discover` found 6 734 and the image's own
//! `.eh_frame` declares 6 730; on a 159 MB C++ library, 116 331 against
//! 123 208 (123 192 declared). Everything `analyze` builds from its list, from
//! signature names and propagated types to class layouts and the warm-up,
//! skipped the functions it missed.
//!
//! It drifted again on a PE: `analyze` took `.pdata` alone there and counted
//! 2 949 functions on the Windows test binary where `function discover` listed
//! 3 198 (6 681 against 8 258 on a cross-built Windows binary).
//!
//! One helper now answers for both. The fixture is this test binary's own
//! executable, a real image with an unwind table, needing no compiler: an ELF
//! on Linux and a PE on Windows, so each CI job holds one format.

use std::process::Command;

use serde_json::Value;

fn n0xis_exe() -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

fn run(cwd: &std::path::Path, args: &[&str]) -> Value {
    let out = Command::new(n0xis_exe()).current_dir(cwd).args(args).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("one envelope ({e}): {}", String::from_utf8_lossy(&out.stdout)))
}

#[test]
fn analyze_counts_the_functions_discover_lists() {
    if !n0xis_exe().exists() {
        return; // binary not built in this profile
    }
    let project = std::env::temp_dir().join(format!("n0xis-analyze-count-{}", std::process::id()));
    std::fs::create_dir_all(project.join(".n0x")).expect("temp project");
    let fixture = std::env::current_exe().expect("test exe");
    let fixture = fixture.to_str().expect("utf-8 path");

    let listed = run(&project, &["function", "discover", "--file", fixture, "--limit", "1", "--quiet"]);
    let total = listed["meta"]["total"].as_u64().unwrap_or_else(|| panic!("discover states its total: {listed}"));
    let analysed = run(&project, &["analyze", "--file", fixture, "--no-cfg", "--quiet"]);
    let counted = analysed["data"]["functions"].as_u64().unwrap_or_else(|| panic!("analyze states its count: {analysed}"));
    let _ = std::fs::remove_dir_all(&project);

    assert!(total > 100, "the fixture is a real program: {total}");
    assert_eq!(counted, total, "analyze and function discover must count the same functions in one image");
}
