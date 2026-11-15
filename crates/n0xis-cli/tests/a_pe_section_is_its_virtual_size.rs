// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A PE section is `VirtualSize` bytes, as the loader maps it.**
//!
//! A section was placed over the larger of its `VirtualSize` and
//! `SizeOfRawData`, so the file's padding to `FileAlignment` was read as the
//! section's: `disasm` decoded a `.text` of 0x20 bytes on into 480 bytes of
//! zeros as `add [rax],al` (12 of 20 asked; 44 on one DLL), and `strings` and
//! `function discover` read 512 bytes where the section holds 32.
//!
//! The truth is `llvm-readobj --sections` (`VirtualSize`, `RawDataSize`) and
//! `objdump`, which stops at `VirtualSize` (its `-h` size is the same number),
//! on `oracle/pe_virtual_size.c` built with mingw.

#![cfg(feature = "oracle")]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod support;

fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

fn run(cmd: &str, args: &[&str], file: &Path) -> String {
    let out = Command::new(cmd).env("LC_ALL", "C").args(args).arg(file).output().expect(cmd);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The build in a directory of its own, or `None` where mingw is not installed.
fn build(tag: &str) -> Option<(PathBuf, PathBuf)> {
    let dir = std::env::temp_dir().join(format!("n0xis-pe-vs-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(dir.join(".n0x")).ok()?;
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../oracle/pe_virtual_size.c");
    let exe = dir.join("vs.exe");
    let ok = Command::new("x86_64-w64-mingw32-gcc")
        .args(["-O2", "-nostdlib", "-Wl,-e,start", "-o"])
        .arg(&exe)
        .arg(&src)
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("skipping: x86_64-w64-mingw32-gcc unavailable or failed");
        return None;
    }
    Some((dir, exe))
}

/// `(name, va, VirtualSize, RawDataSize)` of each section, by `llvm-readobj`,
/// each `VirtualSize` checked against `objdump -h`'s size.
fn sections(exe: &Path) -> Vec<(String, u64, u64, u64)> {
    let base = run("llvm-readobj", &["--file-headers"], exe)
        .lines()
        .find_map(|l| l.trim().strip_prefix("ImageBase: 0x").map(|h| u64::from_str_radix(h, 16).expect("hex")))
        .expect("llvm-readobj: ImageBase");
    let field = |block: &str, key: &str| {
        block.lines().find_map(|l| l.trim().strip_prefix(key).map(|v| v.trim().to_string())).unwrap_or_else(|| panic!("no {key}"))
    };
    let num = |s: String| s.strip_prefix("0x").map_or_else(|| s.parse().expect("dec"), |h| u64::from_str_radix(h, 16).expect("hex"));
    let text = run("llvm-readobj", &["--sections"], exe);
    let found: Vec<(String, u64, u64, u64)> = text
        .split("Section {")
        .skip(1)
        .map(|b| {
            let name = field(b, "Name:").split_whitespace().next().unwrap_or("").to_string();
            (name, base + num(field(b, "VirtualAddress:")), num(field(b, "VirtualSize:")), num(field(b, "RawDataSize:")))
        })
        .collect();
    let h = run("objdump", &["-h"], exe);
    for (name, _, vs, _) in &found {
        let size = h.lines().find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.get(1) == Some(&name.as_str())).then(|| u64::from_str_radix(f[2], 16).expect("hex"))
        });
        assert_eq!(size, Some(*vs), "objdump -h and llvm-readobj agree on {name}");
    }
    found
}

fn tool(dir: &Path, args: &[&str]) -> Value {
    let out = support::isolated(Command::new(n0xis_exe())).current_dir(dir).args(args).output().expect("run n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("not one JSON object ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    assert_eq!(v["ok"], Value::Bool(true), "{v}");
    v
}

#[test]
fn disasm_stops_where_a_pe_section_ends_and_says_so() {
    let Some((dir, exe)) = build("disasm") else { return };
    let (_, va, vs, raw) = sections(&exe).into_iter().find(|s| s.0 == ".text").expect(".text");
    assert!(raw > vs, "the build has padding past VirtualSize, or the test proves nothing: {vs:#x} of {raw:#x}");
    // objdump's last instruction of .text ends at its VirtualSize.
    let last = run("objdump", &["-d", "--section=.text"], &exe)
        .lines()
        .filter_map(|l| {
            let (head, rest) = l.split_once(":\t")?;
            Some((u64::from_str_radix(head.trim(), 16).ok()?, rest.split('\t').next()?.split_whitespace().count() as u64))
        })
        .last()
        .expect("objdump: an instruction");
    assert_eq!(last.0 + last.1, va + vs, "objdump stops at VirtualSize");

    let v = tool(&dir, &["disasm", "--file", exe.to_str().unwrap(), "--addr", &format!("{va:#x}"), "--count", "100"]);
    let insns = v["data"]["insns"].as_array().expect("insns");
    let end = insns.last().map(|i| u64::from_str_radix(i["va"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap() + i["len"].as_u64().unwrap());
    assert_eq!(end, Some(va + vs), "the listing ends where .text does: {v}");
    let note = v["meta"]["note"].as_str().unwrap_or_default();
    assert!(note.contains("of 100") && note.contains(&format!("{:#x}", va + vs)), "{v}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn strings_reads_each_pe_section_for_what_it_holds() {
    let Some((dir, exe)) = build("strings") else { return };
    let v = tool(&dir, &["strings", "--file", exe.to_str().unwrap()]);
    let ranges = v["data"]["ranges"].as_array().expect("ranges");
    let mut checked = 0;
    for (name, va, vs, raw) in sections(&exe) {
        let Some(r) = ranges.iter().find(|r| r["name"] == name.as_str()) else { continue };
        assert_eq!(r["address"], format!("{va:#x}").as_str(), "{name}: {r}");
        assert_eq!(r["size"].as_u64(), Some(vs.min(raw)), "{name}: the file's bytes of its VirtualSize {vs:#x} ({raw:#x} raw): {r}");
        checked += 1;
    }
    assert!(checked >= 2, "{v}");
    let _ = std::fs::remove_dir_all(&dir);
}
