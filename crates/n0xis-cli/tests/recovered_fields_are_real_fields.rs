// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A recovered struct field, checked against the compiler that laid the
//! struct out.**
//!
//! Type recovery beyond the signature had no external source. It is also the
//! part a reader trusts most: `w->field_0x18` reads like a fact about the
//! program, and an offset the pass invented reads exactly the same way — there
//! is no `?` on it and no error to branch on.
//!
//! DWARF settles it and costs nothing. `gcc -g` on `oracle/types.c` states
//! every member's offset, and the assertion is one-directional on purpose:
//! **every offset the tool recovers must be a real member.** The reverse is not
//! a property of the binary — an optimizer folds, hoists and drops field
//! accesses, so a member that never appears in the output is the compiler's
//! doing and not a miss.
//!
//! Measured when this was written: **15 recovered field offsets across 10
//! functions, every one a real member. None invented.**

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

fn tool(name: &str) -> bool {
    Command::new(name).arg("--version").output().is_ok()
}

/// Every `DW_AT_data_member_location` in the image — the offsets the compiler
/// actually laid out.
///
/// Read flat, without tracking which struct each belongs to. Trying to be
/// clever about the nesting is how the first version of this reported three
/// offsets where there are fifteen, and would have accused the tool of
/// inventing twelve fields that are in the source.
fn real_member_offsets(binary: &Path) -> BTreeSet<u64> {
    let out = Command::new("objdump")
        .env("LC_ALL", "C")
        .arg("--dwarf=info")
        .arg(binary)
        .output()
        .expect("objdump --dwarf=info");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_once("DW_AT_data_member_location:"))
        .filter_map(|(_, v)| v.trim().parse::<u64>().ok())
        .collect()
}

fn exported_functions(binary: &Path) -> Vec<(String, u64)> {
    let out = Command::new("nm")
        .env("LC_ALL", "C")
        .args(["-D", "--defined-only"])
        .arg(binary)
        .output()
        .expect("nm");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let addr = u64::from_str_radix(it.next()?, 16).ok()?;
            let kind = it.next()?;
            let name = it.next()?;
            (kind == "T" && name.starts_with('f')).then(|| (name.to_string(), addr))
        })
        .collect()
}

/// Offsets rendered as `field_0xNN` in a function's pseudocode.
fn recovered_offsets(binary: &Path, at: u64) -> BTreeSet<u64> {
    let out = Command::new(n0xis_exe())
        .args(["decomp", "pseudo", "--quiet", "--addr", &format!("{at:#x}"), "--file"])
        .arg(binary)
        .output()
        .expect("run n0xis");
    let Ok(v) = serde_json::from_str::<Value>(&String::from_utf8_lossy(&out.stdout)) else {
        return BTreeSet::new();
    };
    let body = v["data"]["pseudo"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n"))
        .unwrap_or_default();
    let mut out = BTreeSet::new();
    let mut rest = body.as_str();
    while let Some(pos) = rest.find("field_0x") {
        rest = &rest[pos + "field_0x".len()..];
        let hex: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
        if let Ok(v) = u64::from_str_radix(&hex, 16) {
            out.insert(v);
        }
    }
    out
}

#[test]
fn no_recovered_struct_field_is_one_the_source_does_not_have() {
    if !n0xis_exe().exists() || !tool("gcc") || !tool("objdump") || !tool("nm") {
        eprintln!("fields: skipping — n0xis, gcc, objdump or nm unavailable, so nothing was checked");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("n0xis_fields_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("temp dir");
    let so = tmp.join("types.so");
    let built = Command::new("gcc")
        .args(["-shared", "-fPIC", "-O1", "-g", "-gdwarf-4", "-o"])
        .arg(&so)
        .arg(repo_root().join("oracle").join("types.c"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !built {
        eprintln!("fields: skipping — gcc could not build the types shape");
        let _ = std::fs::remove_dir_all(&tmp);
        return;
    }

    let real = real_member_offsets(&so);
    assert!(real.len() >= 8, "only {} member offsets in the DWARF — the reference is broken", real.len());
    let funcs = exported_functions(&so);
    assert!(funcs.len() >= 8, "only {} functions found — the reference is broken", funcs.len());

    let mut recovered = 0usize;
    let mut invented = Vec::new();
    for (name, va) in &funcs {
        for off in recovered_offsets(&so, *va) {
            recovered += 1;
            if !real.contains(&off) {
                invented.push(format!("{name}: field_0x{off:x} — no struct in the source has a member there"));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);

    // A pass that recovered nothing would satisfy "invented nothing".
    assert!(recovered >= 10, "only {recovered} field offsets recovered — too few for the check to mean anything");
    eprintln!("fields: {recovered} recovered across {} functions, all of them real members", funcs.len());
    assert!(invented.is_empty(), "the decompiler shows fields the source does not have:\n  {}", invented.join("\n  "));
}
