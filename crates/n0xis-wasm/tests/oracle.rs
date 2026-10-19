// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The recordings the default tests compare against are what the tools say
//! today, and the planted modules' answers are what independent validators
//! give.** A local instrument, not a CI gate (`--features oracle`): it runs
//! clang, wasm-ld, wasm-tools and wabt from this machine, whose versions a CI
//! runner does not pin. A missing tool fails the test; it never skips.
//!
//! - `fixtures/build.sh` is run into a fresh directory, rebuilding every
//!   fixture from its source and recording every tool output again; each file
//!   must equal the one checked in. When a tool's version changes what it
//!   prints, run `sh fixtures/build.sh` and look at the diff.
//! - Every planted module (`common/planted.rs`) is given to `wasm-tools
//!   validate` and to wabt's `wasm-validate`, with every feature on: a module
//!   stated to break a rule must be rejected by both, and one stated to be well
//!   formed (or well formed in a proposal this crate does not read) accepted.
//!   A verdict that differs is a failure unless [`SETTLED`] names it with the
//!   third source that decides it.
#![cfg(feature = "oracle")]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::planted::{self, Tool};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis-wasm-oracle-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

#[test]
fn the_recordings_are_what_the_sources_and_the_tools_give_today() {
    let out = scratch("rebuild");
    let run = Command::new("sh").arg(common::dir().join("build.sh")).arg(&out).output().expect("sh runs");
    assert!(
        run.status.success(),
        "build.sh failed (a missing tool is a failure here):\n{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let mut checked = 0;
    let mut differ = Vec::new();
    for stem in common::FIXTURES {
        for suffix in ["wasm", "headers.txt", "details.txt", "disassembly.txt", "print.txt"] {
            let file = format!("{stem}.{suffix}");
            let fresh = std::fs::read(out.join(&file)).unwrap_or_else(|e| panic!("{file}: {e}"));
            let recorded = std::fs::read(common::dir().join(&file)).unwrap_or_else(|e| panic!("{file}: {e}"));
            checked += 1;
            if fresh != recorded {
                differ.push(file);
            }
        }
    }
    let _ = std::fs::remove_dir_all(&out);
    assert!(differ.is_empty(), "rebuilt or re-recorded differently (run build.sh and read the diff): {differ:?}");
    assert_eq!(checked, 25);
}

/// Whether `tool` accepts the module at `path`.
fn accepts(tool: &str, args: &[&str], path: &Path) -> bool {
    let out = Command::new(tool)
        .args(args)
        .arg(path)
        .env("LC_ALL", "C")
        .output()
        .unwrap_or_else(|e| panic!("{tool} could not run (a missing tool is a failure here): {e}"));
    out.status.success()
}

/// A validator's verdict that differs from the stated one, with the third
/// source that settles it: case, validator, its verdict (accepts?), why.
const SETTLED: &[(&str, &str, bool, &str)] = &[(
    "a name section before the data section",
    "wasm-validate",
    false,
    "wabt refuses a data section after the name section even when told to ignore custom-section \
     errors. The binary format's own note (Modules, Custom Section) says the placement of a custom \
     section must not invalidate the module, and wasm-tools accepts it.",
)];

#[test]
fn the_planted_answers_are_the_ones_independent_validators_give() {
    let dir = scratch("planted");
    let mut differ: Vec<(String, &str, bool)> = Vec::new();
    let mut asked = 0;
    let cases = planted::cases();
    // The format says an error in a custom section's data, or its placement,
    // must not invalidate the module; wabt applies that only when asked.
    let validators: [(&str, &[&str]); 2] = [
        ("wasm-tools", &["validate", "--features", "all"]),
        ("wasm-validate", &["--enable-all", "--ignore-custom-section-errors"]),
    ];
    for (i, case) in cases.iter().enumerate() {
        let path = dir.join(format!("case{i}.wasm"));
        std::fs::write(&path, &case.bytes).expect("written");
        let want = matches!(case.tool, Tool::Accepts | Tool::AcceptsOutsideScope);
        for (tool, args) in validators {
            asked += 1;
            let got = accepts(tool, args, &path);
            if got != want {
                differ.push((case.name.to_string(), tool, got));
            }
        }
    }
    let settled: Vec<(String, &str, bool)> = SETTLED.iter().map(|(c, t, v, _)| (c.to_string(), *t, *v)).collect();
    let unsettled: Vec<_> = differ.iter().filter(|d| !settled.contains(d)).collect();
    let gone: Vec<_> = settled.iter().filter(|s| !differ.contains(s)).collect();
    // Kept when a verdict is unsettled, so the bytes can be looked at.
    if unsettled.is_empty() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    assert!(unsettled.is_empty(), "verdicts that differ from the stated ones (files in {}):\n{unsettled:#?}", dir.display());
    assert!(gone.is_empty(), "settled differences no longer found (remove them from SETTLED):\n{gone:#?}");
    eprintln!("{} planted modules, {asked} verdicts, {} differ from the stated one, all settled", cases.len(), differ.len());
}
