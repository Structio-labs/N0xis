// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **No test runs an engine binary that can reach the user's global project.**
//!
//! An engine run where no `.n0x/` is found falls back to the global project,
//! the user's own. Tests that ran the CLI from the crate directory left
//! decompile, CFG and discovery caches there on every workspace run, and the
//! fallback is silent. Every spawn of `n0xis` or `n0xis-mcp` in a test now goes
//! through `support::isolated`, which points that fallback at a directory of
//! the test's own; this fails when one does not.
//!
//! It reads the test sources, so it recognizes a spawn by how these tests
//! spell one: `Command::new` of `n0xis_exe()`, of a `CARGO_BIN_EXE_n0xis*`
//! path, of `cli_bin`, or of `exe` in a file that binds `exe` to
//! `n0xis_exe()`. A spawn spelled another way is not seen — which is why the
//! count it recognizes is bounded below.

use std::path::{Path, PathBuf};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

/// The spawns this guard recognized when it was written; fewer means a
/// spelling changed under it, not that spawns went away.
const KNOWN_SPAWNS: usize = 49;

#[test]
fn every_engine_spawn_in_a_test_is_isolated() {
    let mut seen = 0;
    let mut bare = Vec::new();
    let crates = std::fs::read_dir(workspace().join("crates")).expect("crates/");
    for krate in crates.flatten() {
        let Ok(tests) = std::fs::read_dir(krate.path().join("tests")) else { continue };
        for file in tests.flatten() {
            let path = file.path();
            // This file spells the patterns it looks for.
            if path.extension().is_none_or(|e| e != "rs") || path.file_name() == Path::new(file!()).file_name() {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("test source");
            let exe_is_engine = text.contains("let exe = n0xis_exe()");
            for (n, line) in text.lines().enumerate() {
                let Some(at) = line.find("Command::new(") else { continue };
                let arg = &line[at..];
                let engine = arg.starts_with("Command::new(n0xis_exe())")
                    || arg.starts_with("Command::new(env!(\"CARGO_BIN_EXE_n0xis")
                    || arg.starts_with("Command::new(cli_bin)")
                    || (exe_is_engine && (arg.starts_with("Command::new(&exe)") || arg.starts_with("Command::new(exe)")));
                if !engine {
                    continue;
                }
                seen += 1;
                if !line[..at].ends_with("isolated(") {
                    bare.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
                }
            }
        }
    }
    println!("{seen} engine spawns in test sources");
    assert!(bare.is_empty(), "these run an engine binary that can reach the user's global project; wrap them in `support::isolated`:\n  {}", bare.join("\n  "));
    assert!(seen >= KNOWN_SPAWNS, "recognized {seen} engine spawns, fewer than the {KNOWN_SPAWNS} there were: a spelling changed under this guard");
}
