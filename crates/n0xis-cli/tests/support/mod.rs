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

/// `(p_type, p_offset, p_vaddr, p_filesz)` of every program header of an
/// ELF64 little-endian image: a reader of a few lines, so a test can say where
/// a planted byte is loaded without asking the tool.
pub fn elf64_program_headers(b: &[u8]) -> Vec<(u32, u64, u64, u64)> {
    assert_eq!(&b[..6], b"\x7fELF\x02\x01", "an ELF64 little-endian image");
    let u16le = |at: usize| usize::from(u16::from_le_bytes(b[at..at + 2].try_into().unwrap()));
    let u64le = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    let (off, size, n) = (u64le(0x20) as usize, u16le(0x36), u16le(0x38));
    (0..n)
        .map(|i| off + i * size)
        .map(|p| (u32::from_le_bytes(b[p..p + 4].try_into().unwrap()), u64le(p + 8), u64le(p + 16), u64le(p + 32)))
        .collect()
}

/// Where the first occurrence of `needle` in an ELF64 file is loaded: the
/// `PT_LOAD` that holds its file offset, by [`elf64_program_headers`].
pub fn elf64_load_address_of(b: &[u8], needle: &[u8]) -> u64 {
    let at = b.windows(needle.len()).position(|w| w == needle).expect("the bytes are in the file") as u64;
    elf64_program_headers(b)
        .into_iter()
        .find(|&(ty, off, _, filesz)| ty == 1 && (off..off + filesz).contains(&at))
        .map(|(_, off, vaddr, _)| vaddr + (at - off))
        .expect("a PT_LOAD holds the bytes")
}

/// `(sh_flags, sh_addr, sh_offset, sh_size, sh_type)` of every section header
/// of an ELF64 little-endian image, by the same few lines of reading.
pub fn elf64_section_headers(b: &[u8]) -> Vec<(u64, u64, u64, u64, u32)> {
    assert_eq!(&b[..6], b"\x7fELF\x02\x01", "an ELF64 little-endian image");
    let u64le = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    let u16le = |at: usize| usize::from(u16::from_le_bytes(b[at..at + 2].try_into().unwrap()));
    let (off, size, n) = (u64le(0x28) as usize, u16le(0x3a), u16le(0x3c));
    (0..n)
        .map(|i| off + i * size)
        .map(|h| (u64le(h + 8), u64le(h + 16), u64le(h + 24), u64le(h + 32), u32::from_le_bytes(b[h + 4..h + 8].try_into().unwrap())))
        .collect()
}
