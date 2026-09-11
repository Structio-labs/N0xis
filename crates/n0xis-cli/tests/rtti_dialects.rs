// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **MSVC RTTI is two different structures, and one of them was never read.**
//!
//! The scanner was written against 64-bit PEs and applied to both widths. On a
//! 32-bit image it stepped 8 bytes at a time through 4-byte slots, resolved
//! absolute pointers as image-relative RVAs, and looked for a `pSelf` field
//! that the 32-bit dialect does not have. It also looked only in `.rdata`,
//! while a vtable can sit in `.data` with its locator a section away.
//!
//! The result was `ok: true` and an empty list — **0 classes for a 32-bit C++
//! runtime carrying 95 type descriptors**. Nothing said the question had been
//! asked in the wrong dialect. After the fix: **93 vtables, every recovered
//! name present in the image's own strings, and the 64-bit answers unchanged**
//! (97 and 152 on two other runtimes, 269 through the Itanium path on an ELF).
//!
//! No compiler emits MSVC RTTI here — mingw emits Itanium — so the fixtures are
//! **planted**: `oracle/rtti32.c` and `oracle/rtti64.S` lay the structures out
//! by hand, which puts the answer on the highest rung there is. It is known
//! because it was written, not inferred from a build.

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

/// `(compiler, source, output, the class the fixture plants)`
const DIALECTS: &[(&str, &str, &str, &str)] = &[
    ("i686-w64-mingw32-gcc", "rtti32.c", "rtti32.dll", "PlantedClass"),
    ("x86_64-w64-mingw32-gcc", "rtti64.S", "rtti64.dll", "Planted64"),
];

#[test]
fn both_msvc_rtti_dialects_are_read() {
    if !n0xis_exe().exists() {
        eprintln!("rtti dialects: skipping — {} is not built", n0xis_exe().display());
        return;
    }
    let tmp = std::env::temp_dir().join(format!("n0xis_rtti_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("temp dir");

    let mut checked = 0usize;
    let mut problems = Vec::new();
    for (cc, src, out_name, want) in DIALECTS {
        if Command::new(cc).arg("--version").output().is_err() {
            eprintln!("rtti dialects: skipping {src} — `{cc}` is not installed");
            continue;
        }
        let out = tmp.join(out_name);
        // `-nostdlib` on the assembler fixture: it has no C runtime to link and
        // the CRT would drag in RTTI of its own, which would make the count
        // ambiguous. The point of a planted fixture is that it contains exactly
        // one known answer.
        let mut cmd = Command::new(cc);
        cmd.arg("-shared").arg("-O1").arg("-o").arg(&out).arg(repo_root().join("oracle").join(src));
        if src.ends_with(".S") {
            cmd.args(["-nostdlib", "-Wl,--entry=0"]);
        }
        match cmd.output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                problems.push(format!("{src}: {cc} failed:\n{}", String::from_utf8_lossy(&o.stderr)));
                continue;
            }
            Err(e) => {
                problems.push(format!("{src}: could not run {cc}: {e}"));
                continue;
            }
        }
        let scan = Command::new(n0xis_exe())
            .args(["rtti", "scan", "--quiet", "--file"])
            .arg(&out)
            .output()
            .expect("run n0xis");
        let v: Value = serde_json::from_str(&String::from_utf8_lossy(&scan.stdout))
            .unwrap_or_else(|e| panic!("{src}: not one envelope ({e}): {}", String::from_utf8_lossy(&scan.stdout)));
        let names: Vec<&str> =
            v["data"]["vtables"].as_array().map(|a| a.iter().filter_map(|t| t["name"].as_str()).collect()).unwrap_or_default();
        checked += 1;
        if !names.contains(want) {
            problems.push(format!(
                "{src}: the fixture plants `{want}` and the scan returned {names:?} (ok={})",
                v["ok"]
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);

    if checked == 0 {
        eprintln!("rtti dialects: no mingw toolchain — neither dialect was checked");
        return;
    }
    eprintln!("rtti dialects: {checked} of {} planted, both read", DIALECTS.len());
    assert!(problems.is_empty(), "a planted class was not recovered:\n  {}", problems.join("\n  "));
}
