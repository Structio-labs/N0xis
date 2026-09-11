// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Where a function starts and ends, checked against two sources that are not
//! this tool.**
//!
//! Everything function-scoped inherits this: a wrong extent gives the CFG extra
//! blocks or truncates it, and every answer built on that is confidently wrong
//! about a function that does not exist. It had been checked by comparing one
//! n0xis command with another — which is a contract check wearing the clothes
//! of a correctness check.
//!
//! Two independent sources, each answering a different question:
//!
//! - **`objdump --dwarf=frames`** reads the image's own `.eh_frame` and gives
//!   an exact `start..end` per function. `function eh` must produce the same
//!   set — not merely the same *count*, which a systematic off-by-one would
//!   satisfy.
//! - **`nm -D`** lists the exported entry points. Every one inside the scanned
//!   window must appear in `function discover`; an exported function the
//!   discovery pass cannot see is a hole in the function list, and the list is
//!   where a user starts.
//!
//! Measured when this was written: `function eh` **exactly** equal to the FDE
//! table on three images (10, 15 467 and 14 355 entries), and **0 exported
//! functions missed** out of 10 and 7 105.

use std::collections::BTreeMap;
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

fn have(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

fn run_json(args: &[String]) -> Option<Value> {
    let out = Command::new(n0xis_exe()).args(args).output().ok()?;
    serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).ok()
}

/// `objdump --dwarf=frames`: every FDE's `pc=<start>..<end>`.
///
/// `LC_ALL=C` is mandatory — the whole listing is translated, and a parser
/// keyed on the English form silently reads zero entries.
fn fde_extents(binary: &Path) -> BTreeMap<u64, u64> {
    let out = Command::new("objdump")
        .env("LC_ALL", "C")
        .arg("--dwarf=frames")
        .arg(binary)
        .output()
        .expect("objdump");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let Some(pos) = line.find("pc=") else { continue };
        let rest = &line[pos + 3..];
        let Some((a, b)) = rest.split_once("..") else { continue };
        let b = b.split_whitespace().next().unwrap_or(b);
        if let (Ok(start), Ok(end)) = (u64::from_str_radix(a.trim(), 16), u64::from_str_radix(b.trim(), 16)) {
            map.insert(start, end);
        }
    }
    map
}

/// `nm -D`: defined exported code symbols. `T` is a text symbol, `W` a weak
/// one, `i` an ifunc resolver — all of them entry points a user expects to see.
fn exported_entries(binary: &Path) -> Vec<u64> {
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
            let addr = it.next()?;
            let kind = it.next()?;
            matches!(kind, "T" | "W" | "i").then(|| u64::from_str_radix(addr, 16).ok())?
        })
        .collect()
}

fn build_shape(dir: &Path) -> Option<PathBuf> {
    let out = dir.join("sysv.so");
    let src = repo_root().join("oracle").join("sysv.c");
    match Command::new("gcc").args(["-shared", "-O1", "-fPIC", "-o"]).arg(&out).arg(&src).output() {
        Ok(o) if o.status.success() => Some(out),
        _ => {
            eprintln!("extents: skipping — gcc could not build the oracle shape");
            None
        }
    }
}

/// A system library that is on essentially every Linux, so the check is not
/// limited to the ten functions of a purpose-built shape.
///
/// The oracle shape proves the *rule*; a real C library proves it at a size
/// where a systematic off-by-one has somewhere to hide. Measured when this was
/// written: **3 777 extents on `libc`, 1 042 on `libm`, start and end exact.**
fn a_system_library() -> Option<PathBuf> {
    ["/usr/lib/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib64/libc.so.6", "/usr/lib/libm.so.6"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

/// Compare one image's recovered extents with its own unwind table. Returns the
/// number compared, or the disagreements.
fn compare_extents(binary: &Path) -> Result<usize, Vec<String>> {
    let reference = fde_extents(binary);
    if reference.len() < 8 {
        return Err(vec![format!("only {} FDEs parsed from {} — the reference is broken, not the tool", reference.len(), binary.display())]);
    }
    let listing = run_json(&["function".into(), "eh".into(), "--quiet".into(), "--file".into(), binary.display().to_string()])
        .ok_or_else(|| vec![format!("{}: `function eh` produced no envelope", binary.display())])?;
    let mut ours = BTreeMap::new();
    for f in listing["data"]["functions"].as_array().unwrap_or(&Vec::new()) {
        let va = u64::from_str_radix(f["va"].as_str().unwrap_or("0").trim_start_matches("0x"), 16).unwrap_or(0);
        let end = u64::from_str_radix(f["end"].as_str().unwrap_or("0").trim_start_matches("0x"), 16).unwrap_or(0);
        ours.insert(va, end);
    }
    let mut problems: Vec<String> = reference
        .iter()
        .filter_map(|(start, end)| match ours.get(start) {
            None => Some(format!("{start:#x}..{end:#x} is in the unwind table and not in the answer")),
            Some(got) if got != end => Some(format!("{start:#x}: table says it ends at {end:#x}, the answer says {got:#x}")),
            _ => None,
        })
        .take(10)
        .collect();
    problems.extend(
        ours.keys().filter(|va| !reference.contains_key(va)).take(10).map(|va| format!("{va:#x} is in the answer and not in the unwind table")),
    );
    if problems.is_empty() { Ok(reference.len()) } else { Err(problems) }
}

#[test]
fn recovered_function_extents_equal_the_images_own_unwind_table() {
    if !n0xis_exe().exists() || !have("objdump") || !have("gcc") {
        eprintln!("extents: skipping — n0xis, objdump or gcc unavailable, so nothing was checked");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("n0xis_extents_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("temp dir");
    let Some(binary) = build_shape(&tmp) else { return };

    let reference = fde_extents(&binary);
    let listing = run_json(&["function".into(), "eh".into(), "--quiet".into(), "--file".into(), binary.display().to_string()])
        .expect("function eh");
    let mut ours = BTreeMap::new();
    for f in listing["data"]["functions"].as_array().expect("functions") {
        let va = u64::from_str_radix(f["va"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        let end = u64::from_str_radix(f["end"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        ours.insert(va, end);
    }
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(reference.len() >= 8, "only {} FDEs parsed — the reference is broken, not the tool", reference.len());
    let mut problems: Vec<String> = reference
        .iter()
        .filter_map(|(start, end)| match ours.get(start) {
            None => Some(format!("{start:#x}..{end:#x} is in the unwind table and not in the answer")),
            Some(got) if got != end => Some(format!("{start:#x}: table says it ends at {end:#x}, the answer says {got:#x}")),
            _ => None,
        })
        .collect();
    problems.extend(
        ours.keys().filter(|va| !reference.contains_key(va)).map(|va| format!("{va:#x} is in the answer and not in the unwind table")),
    );
    eprintln!("extents: {} FDEs compared start and end on the oracle shape", reference.len());
    assert!(problems.is_empty(), "recovered extents disagree with the image's own table:\n  {}", problems.join("\n  "));

    // The second arm: the same rule at a size where an off-by-one has somewhere
    // to hide. Skipped, loudly, when there is no system library to read.
    match a_system_library() {
        None => eprintln!("extents: no system library found — only the {} oracle functions were checked", reference.len()),
        Some(lib) => match compare_extents(&lib) {
            Ok(n) => eprintln!("extents: {n} more compared start and end on {}", lib.display()),
            Err(problems) => panic!(
                "recovered extents disagree with {}'s own unwind table:\n  {}",
                lib.display(),
                problems.join("\n  ")
            ),
        },
    }
}

#[test]
fn every_exported_function_appears_in_the_function_list() {
    if !n0xis_exe().exists() || !have("nm") || !have("gcc") {
        eprintln!("exports: skipping — n0xis, nm or gcc unavailable, so nothing was checked");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("n0xis_exports_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("temp dir");
    let Some(binary) = build_shape(&tmp) else { return };

    let exported = exported_entries(&binary);
    let listing = run_json(&[
        "function".into(),
        "discover".into(),
        "--quiet".into(),
        "--limit".into(),
        "100000".into(),
        "--file".into(),
        binary.display().to_string(),
    ])
    .expect("function discover");
    let found: std::collections::BTreeSet<u64> = listing["data"]["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .map(|f| u64::from_str_radix(f["va"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap())
        .collect();
    let _ = std::fs::remove_dir_all(&tmp);

    let (lo, hi) = (*found.iter().next().expect("non-empty"), *found.iter().last().unwrap());
    // Only what the sweep actually looked at: an export outside the scanned
    // window is not a miss, and counting it as one would accuse the subject for
    // the measurement's own bounds.
    let in_window: Vec<u64> = exported.into_iter().filter(|a| (lo..=hi).contains(a)).collect();
    assert!(in_window.len() >= 8, "only {} exports in the window — too few to mean anything", in_window.len());
    let missed: Vec<String> = in_window.iter().filter(|a| !found.contains(a)).map(|a| format!("{a:#x}")).collect();
    eprintln!("exports: {} exported entry points inside the scanned window (oracle shape)", in_window.len());
    assert!(
        missed.is_empty(),
        "the linker exports these and the function list does not have them:\n  {}",
        missed.join("\n  ")
    );

    // Again at a real size. Ten exports prove the plumbing; a C library proves
    // the sweep. Measured when this was written: 2 323 exported entry points
    // inside the window, none missed.
    let Some(lib) = a_system_library() else {
        eprintln!("exports: no system library found — only the oracle shape's {} were checked", in_window.len());
        return;
    };
    let exported = exported_entries(&lib);
    let Some(listing) = run_json(&[
        "function".into(),
        "discover".into(),
        "--quiet".into(),
        "--limit".into(),
        "200000".into(),
        "--file".into(),
        lib.display().to_string(),
    ]) else {
        panic!("`function discover` produced no envelope for {}", lib.display());
    };
    let found: std::collections::BTreeSet<u64> = listing["data"]["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .map(|f| u64::from_str_radix(f["va"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap())
        .collect();
    let (lo, hi) = (*found.iter().next().expect("non-empty"), *found.iter().last().unwrap());
    let in_window: Vec<u64> = exported.into_iter().filter(|a| (lo..=hi).contains(a)).collect();
    assert!(in_window.len() > 100, "only {} exports in {}'s window — too few to mean anything", in_window.len(), lib.display());
    let missed: Vec<String> =
        in_window.iter().filter(|a| !found.contains(a)).take(10).map(|a| format!("{a:#x}")).collect();
    eprintln!("exports: {} more inside {}'s window", in_window.len(), lib.display());
    assert!(
        missed.is_empty(),
        "{} exports these and the function list does not have them:\n  {}",
        lib.display(),
        missed.join("\n  ")
    );
}
