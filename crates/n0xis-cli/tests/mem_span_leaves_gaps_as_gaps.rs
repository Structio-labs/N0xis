// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`mem span`**: every readable stretch of a window, with the gaps between
//! them left as gaps. `mem read` stops where its first stretch ends and refuses
//! a window that starts in a gap; a byte view needs the whole window.
//!
//! The answers are known before the engine is asked: the section tables were
//! read with `readelf -SW` (the ELF fixture) and `llvm-readobj --sections` (the
//! PE fixture), not with this tool, and the expected bytes are each file's own
//! at the offsets those tools give.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// A shared object whose sections leave gaps: `.init` 0x1000+0x1b, `.plt`
/// 0x1020+0x20, `.text` 0x1040+0x146, `.fini` 0x1188+0xd (file offsets equal
/// the addresses); `.got.plt` runs into `.data` at 0x4008, `.bss` follows.
const ELF: &str = "../n0xis-sources/tests/fixtures/tls_overlap.so";
/// A DLL at 0x140000000: `.text` holds 0x200 bytes of raw data at 0x1000, and
/// `.rdata` (virtual size 0x40) starts at 0x2000, raw data at file offset 0x600.
const PE: &str = "tests/fixtures/native_pe.dll";

/// One expected stretch: where it is, and where its bytes are in the file.
struct Run {
    va: u64,
    file_offset: usize,
    len: usize,
}

fn span(cwd: &Path, target: &Path, addr: u64, size: usize) -> Value {
    let out = Command::new(n0xis_exe())
        .current_dir(cwd)
        .args(["mem", "span", "--file"])
        .arg(target)
        .args(["--addr", &format!("{addr:#x}"), "--size", &size.to_string()])
        .output()
        .expect("run n0xis");
    serde_json::from_slice(&out.stdout).expect("one envelope")
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    hex.split_whitespace().map(|b| u8::from_str_radix(b, 16).expect("hex byte")).collect()
}

fn va(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().expect("address").trim_start_matches("0x"), 16).expect("hex address")
}

fn check(cwd: &Path, relative: &str, addr: u64, size: usize, expected: &[Run]) {
    let target = fixture(relative);
    let file = std::fs::read(&target).expect("fixture");
    let got = span(cwd, &target, addr, size);
    assert_eq!(got["ok"], true, "{got}");
    assert_eq!(got["meta"]["schema"], "n0xis.mem.span.v1");
    let runs: Vec<(u64, Vec<u8>)> = got["data"]["runs"]
        .as_array()
        .expect("runs")
        .iter()
        .map(|r| {
            let bytes = hex_bytes(r["hex"].as_str().expect("hex"));
            assert_eq!(r["read"].as_u64(), Some(bytes.len() as u64), "a run's count is its bytes: {r}");
            (va(&r["address"]), bytes)
        })
        .collect();
    let want: Vec<(u64, Vec<u8>)> =
        expected.iter().map(|r| (r.va, file[r.file_offset..r.file_offset + r.len].to_vec())).collect();
    assert_eq!(
        runs.iter().map(|(a, b)| (*a, b.len())).collect::<Vec<_>>(),
        want.iter().map(|(a, b)| (*a, b.len())).collect::<Vec<_>>(),
        "where the stretches are, {relative} from {addr:#x}"
    );
    assert_eq!(runs, want, "and what they hold");
    let total: usize = expected.iter().map(|r| r.len).sum();
    assert_eq!(got["data"]["read"].as_u64(), Some(total as u64));
}

fn project(tag: &str) -> PathBuf {
    // A `.n0x/` here keeps anything the engine writes out of the user's global project.
    let dir = std::env::temp_dir().join(format!("n0xis-mem-span-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(dir.join(".n0x")).expect("temp project");
    dir
}

#[test]
fn a_window_across_gaps_reads_each_stretch_and_skips_each_gap() {
    if !n0xis_exe().exists() {
        return; // binary not built in this profile
    }
    let cwd = project("gaps");
    // Starts in the gap before `.init`; `.plt` and `.text` touch, so they are one run.
    check(&cwd, ELF, 0xfc0, 0x200, &[
        Run { va: 0x1000, file_offset: 0x1000, len: 0x1b },
        Run { va: 0x1020, file_offset: 0x1020, len: 0x166 },
        Run { va: 0x1188, file_offset: 0x1188, len: 0xd },
    ]);
    // `.got.plt` into `.data` is one run; `.bss` holds no bytes of the file.
    check(&cwd, ELF, 0x4000, 0x20, &[Run { va: 0x4000, file_offset: 0x3000, len: 0x10 }]);
    // Under the zero-fill TLS block: `.init_array` through the start of `.dynamic`.
    check(&cwd, ELF, 0x3da0, 0x50, &[Run { va: 0x3db0, file_offset: 0x2db0, len: 0x40 }]);
    // Past `.text`'s raw data and into `.rdata`.
    check(&cwd, PE, 0x1_4000_1f00, 0x140, &[Run { va: 0x1_4000_2000, file_offset: 0x600, len: 0x40 }]);
    let _ = std::fs::remove_dir_all(&cwd);
}

#[test]
fn a_window_with_nothing_readable_says_none_was_read() {
    if !n0xis_exe().exists() {
        return;
    }
    let cwd = project("empty");
    // Between `.rela.plt` (ends 0x6a0) and `.init` (0x1000) the image holds nothing.
    let got = span(&cwd, &fixture(ELF), 0x800, 0x100);
    assert_eq!(got["ok"], true, "{got}");
    assert_eq!(got["data"]["read"], 0, "{got}");
    assert_eq!(got["data"]["runs"].as_array().map(Vec::len), Some(0), "{got}");
    // And `mem read` at the same place refuses, as it always has.
    let out = Command::new(n0xis_exe())
        .current_dir(&cwd)
        .args(["mem", "read", "--file"])
        .arg(fixture(ELF))
        .args(["--addr", "0x800"])
        .output()
        .expect("run n0xis");
    let read: Value = serde_json::from_slice(&out.stdout).expect("one envelope");
    assert_eq!(read["ok"], false, "{read}");
    let _ = std::fs::remove_dir_all(&cwd);
}

#[test]
fn a_window_wider_than_the_limit_is_refused() {
    if !n0xis_exe().exists() {
        return;
    }
    let cwd = project("wide");
    let got = span(&cwd, &fixture(ELF), 0x1000, 64 * 1024 + 1);
    assert_eq!(got["ok"], false, "{got}");
    assert_eq!(got["error"]["code"], "bad-arg", "{got}");
    let _ = std::fs::remove_dir_all(&cwd);
}
