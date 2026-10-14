// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What every integration test that runs one of the engine's binaries shares
//! (`mod support;`; the MCP crate's tests include this file by path).
//!
//! An engine run where no `.n0x/` is found reads and writes the **global
//! project** — `dirs::data_local_dir()/n0x`, the user's own. A test that ran
//! the CLI from the crate directory, with no project of its own, left decompile,
//! CFG and discovery caches there on every workspace run. So a test never
//! spawns an engine binary bare: [`isolated`] points the global fallback at a
//! directory of the test process's own. A test that sets up its own `.n0x/`
//! is unaffected — the local project is found first.

// Every test binary compiles its own copy of this module, and one whose engine
// runs are all behind a feature (`oracle_corpus` without `oracle`) uses none of it.
#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;

/// The directory a spawned engine takes as `$XDG_DATA_HOME`: one per test
/// process, under the system temp directory.
pub fn data_home() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis-test-data-home-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// `cmd`, unable to reach the user's global project: its global fallback is
/// [`data_home`]. Set on the child only — never on this process, whose tests
/// run in parallel.
///
/// `dirs::data_local_dir()` reads `$XDG_DATA_HOME` on Linux and the BSDs. On
/// Windows and macOS it asks the OS for a known folder and ignores the
/// variable, so there this isolates nothing.
pub fn isolated(mut cmd: Command) -> Command {
    cmd.env("XDG_DATA_HOME", data_home());
    cmd
}
