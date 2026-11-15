// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **An invalid byte is one byte, and the listing goes on past it.**
//!
//! `disasm` took `06 b8` as one invalid instruction of two bytes, where the
//! processor faults on the `06` alone and `objdump` steps over it, so the
//! `mov` the `b8` begins was lost; and it stopped there, 2 instructions of
//! the 10 asked, with no word why (on a stripped executable, 20 005 of 60 000
//! asked: the listing died at the first string in the code).
//!
//! The truth is `objdump`'s listing of the same bytes, recorded below as it
//! printed it (`objdump -D -b binary -m i386:x86-64`, GNU binutils 2.47), and
//! read again from `objdump` itself where one is installed, so the record
//! cannot drift from its source unseen.

use std::process::Command;

use serde_json::Value;

mod support;

fn n0xis_exe() -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

/// `mov eax,1`, the invalid `06`, `mov eax,2`, `ret`, and the first two bytes
/// of a `mov` the bytes end inside: `private/instruments/lead-checks/disasm/bad.s`
/// with a truncated tail added.
const BYTES: [u8; 14] = [0xb8, 0x01, 0x00, 0x00, 0x00, 0x06, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3, 0x48, 0x8b];
const AT: u64 = 0x401000;

/// `objdump`'s `(address, length)` for every instruction before the
/// truncated tail, which it prints as `rex.W` and `.byte 0x8b`.
const OBJDUMP: [(u64, usize); 4] = [(0x401000, 5), (0x401005, 1), (0x401006, 5), (0x40100b, 1)];

fn disasm(count: usize) -> Option<Value> {
    let exe = n0xis_exe();
    if !exe.exists() {
        eprintln!("skipping: {} not built", exe.display());
        return None;
    }
    let hex: Vec<String> = BYTES.iter().map(|b| format!("{b:02x}")).collect();
    let out = support::isolated(Command::new(&exe))
        .args(["disasm", "--arch", "x64", "--bytes", &hex.join(" "), "--addr", &format!("{AT:#x}"), "--count", &count.to_string()])
        .output()
        .expect("run n0xis");
    Some(serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("not one JSON object ({e}): {}", String::from_utf8_lossy(&out.stdout))))
}

fn boundaries(v: &Value) -> Vec<(u64, usize)> {
    v["data"]["insns"]
        .as_array()
        .unwrap_or_else(|| panic!("no instruction list: {v}"))
        .iter()
        .map(|i| {
            let va = u64::from_str_radix(i["va"].as_str().expect("va").trim_start_matches("0x"), 16).expect("hex va");
            (va, i["len"].as_u64().expect("len") as usize)
        })
        .collect()
}

/// `objdump`'s own listing of [`BYTES`], where it is installed: the record in
/// [`OBJDUMP`] is checked against its source.
fn objdump_now() -> Option<Vec<(u64, usize)>> {
    let path = std::env::temp_dir().join(format!("n0xis-bad-byte-{}.bin", std::process::id()));
    std::fs::write(&path, BYTES).ok()?;
    let out = Command::new("objdump")
        .env("LC_ALL", "C")
        .args(["-D", "-b", "binary", "-m", "i386:x86-64", &format!("--adjust-vma={AT:#x}")])
        .arg(&path)
        .output();
    let _ = std::fs::remove_file(&path);
    let out = out.ok()?;
    if !out.status.success() {
        return None;
    }
    let mut rows = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Some((head, rest)) = line.split_once(":\t") else { continue };
        let Ok(va) = u64::from_str_radix(head.trim(), 16) else { continue };
        let bytes = rest.split('\t').next().unwrap_or("").split_whitespace().count();
        rows.push((va, bytes));
    }
    Some(rows)
}

#[test]
fn the_objdump_record_is_what_objdump_prints() {
    let Some(rows) = objdump_now() else {
        eprintln!("skipping: no objdump");
        return;
    };
    // objdump goes on to the truncated tail, one byte a line; the record stops before it.
    assert_eq!(&rows[..OBJDUMP.len()], &OBJDUMP, "objdump's listing: {rows:x?}");
    assert_eq!(rows[OBJDUMP.len()..], [(0x40100c, 1), (0x40100d, 1)], "objdump's listing: {rows:x?}");
}

#[test]
fn an_invalid_byte_is_one_byte_and_the_listing_goes_on_past_it() {
    let Some(v) = disasm(10) else { return };
    assert_eq!(v["ok"], Value::Bool(true), "{v}");
    assert_eq!(boundaries(&v), OBJDUMP, "{v}");
    assert_eq!(v["data"]["insns"][1]["kind"], "invalid", "{v}");
}

#[test]
fn a_listing_shorter_than_asked_says_why() {
    let Some(v) = disasm(10) else { return };
    let note = v["meta"]["note"].as_str().unwrap_or_else(|| panic!("4 of 10 instructions and no word why: {v}"));
    assert!(note.contains("4 of 10"), "{note}");
    assert!(note.contains("0x40100c") && note.contains("2 byte(s)"), "the tail the bytes end inside: {note}");
}

#[test]
fn a_listing_as_long_as_asked_says_nothing_of_its_length() {
    let Some(v) = disasm(3) else { return };
    assert_eq!(boundaries(&v), OBJDUMP[..3], "{v}");
    assert!(v["meta"]["note"].is_null(), "{v}");
}
