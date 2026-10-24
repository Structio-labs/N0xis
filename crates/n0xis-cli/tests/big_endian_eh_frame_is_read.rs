// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A big-endian `.eh_frame` is read in the order the image states, and
//! answers what `readelf` lists** — the same answer the little-endian twin of
//! the same source gives.
//!
//! The defect: the `.eh_frame` reader read every length, CIE pointer and
//! `sdata4` little-endian whatever the image said. On a big-endian image the
//! first record's length came out byte-swapped, past the section's end, so the
//! walk read no FDE at all and every consumer stated nothing — `function eh`
//! answered `ok: true` with 0 functions, `function discover` missed every
//! function only the table declares, `why` named no unwind table. "Not read"
//! looked exactly like "none".
//!
//! What is planted (`tests/fixtures/big_endian_eh/`; `plant.sh` assembles
//! `be_eh.s` for `aarch64_be` and for `aarch64` with clang and ld.lld, and
//! records `readelf --debug-dump=frames`, `readelf -sW` and the header's data
//! encoding beside each image): three FDEs, `plain` and `personality` with no
//! LSDA, `guarded` with a hand-written LSDA whose call-site table is `udata4`
//! — fixed-size fields in the image's order — holding one entry that lands at
//! `catch_here` and one with no landing pad. The addresses the answer must hold
//! are the recorded FDE ranges and the planted labels' symbols, not anything
//! this tool computed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

mod support;

const DIR: &str = "tests/fixtures/big_endian_eh";

/// The two builds of `be_eh.s`, and the byte order each header must state —
/// checked against the recording, so a fixture rebuilt for the wrong target
/// fails here rather than passing on the little-endian path twice.
const IMAGES: &[(&str, &str)] = &[("be_eh-aarch64_be.so", "big endian"), ("be_eh-aarch64.so", "little endian")];

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(DIR).join(name)
}

fn recording(name: &str) -> String {
    std::fs::read_to_string(fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// A project of its own, holding a copy of `image`; `tag` keeps the two tests,
/// which run in parallel, out of each other's directory.
fn project(tag: &str, image: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis_be_eh_{tag}_{image}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("project");
    std::fs::copy(fixture(image), dir.join(image)).expect("copy the fixture");
    dir
}

fn run(dir: &Path, args: &[&str]) -> Value {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).arg("--quiet").current_dir(dir).output().expect("run n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("one JSON object from {args:?}: {e}"));
    assert_eq!(v["ok"], true, "{args:?}: {v}");
    v["data"].clone()
}

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).unwrap_or_else(|e| panic!("{s:?}: {e}"))
}

/// The FDE ranges `readelf --debug-dump=frames` lists (`pc=<start>..<end>`).
fn fdes(image: &str) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = recording(&format!("{image}.frames.txt"))
        .lines()
        .filter_map(|l| l.split_once("pc=").map(|(_, r)| r))
        .map(|r| {
            let (s, e) = r.trim().split_once("..").expect("start..end");
            (hex(s), hex(e))
        })
        .collect();
    out.sort_unstable();
    out
}

/// Every symbol `readelf -sW` lists, by name.
fn symbols(image: &str) -> BTreeMap<String, u64> {
    recording(&format!("{image}.symbols.txt"))
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // `   6: 00000000000103e8     0 NOTYPE  LOCAL  DEFAULT    9 catch_here`;
            // the column header (`Num:`) has eight fields too.
            let numbered = f.first().and_then(|n| n.strip_suffix(':')).is_some_and(|n| n.parse::<u32>().is_ok());
            (f.len() == 8 && numbered).then(|| (f[7].to_string(), hex(f[1])))
        })
        .collect()
}

#[test]
fn function_eh_answers_what_readelf_lists_in_either_byte_order() {
    for &(image, order) in IMAGES {
        assert!(recording(&format!("{image}.data.txt")).contains(order), "{image} is not {order}: rebuild with plant.sh");
        let want = fdes(image);
        assert_eq!(want.len(), 3, "{image}: the plant has three FDEs: {want:x?}");
        let sym = symbols(image);
        let at = |name: &str| *sym.get(name).unwrap_or_else(|| panic!("{image}: no symbol {name}"));

        let dir = project("eh", image);
        let data = run(&dir, &["function", "eh", "--file", image]);
        let functions = data["functions"].as_array().expect("functions");
        let got: Vec<(u64, u64)> = functions.iter().map(|f| (hex(f["va"].as_str().unwrap()), hex(f["end"].as_str().unwrap()))).collect();
        assert_eq!(got, want, "{image}: the extents are the FDEs readelf lists");

        // One protected range, in `guarded`, landing at `catch_here`; the
        // entry with no landing pad is no edge.
        let regions: Vec<(u64, &Value)> =
            functions.iter().flat_map(|f| f["regions"].as_array().unwrap().iter().map(move |r| (hex(f["va"].as_str().unwrap()), r))).collect();
        let pad = json!({
            "try_start": format!("{:#x}", at("try_begin")),
            "try_end": format!("{:#x}", at("try_end")),
            "landing_pad": format!("{:#x}", at("catch_here")),
        });
        assert_eq!(regions, vec![(at("guarded"), &pad)], "{image}: the LSDA's one landing pad");
        assert_eq!(data["regions"], 1, "{image}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The table reaches the answers that read it: `function discover` lists each
/// FDE's function with the FDE's end, and `why` names `.eh_frame` among the
/// sources of its start. On the big-endian image `discover` had found only
/// `guarded` (by its prologue), and `why` named the prologue alone.
#[test]
fn discovery_and_why_take_the_big_endian_fdes() {
    let unwind = json!({"source": "unwind", "table": "eh_frame"});
    for &(image, _) in IMAGES {
        let dir = project("discover", image);
        let listed = run(&dir, &["function", "discover", "--file", image]);
        let listed: BTreeMap<u64, u64> = listed["functions"]
            .as_array()
            .expect("functions")
            .iter()
            .map(|f| (hex(f["va"].as_str().unwrap()), hex(f["end"].as_str().unwrap())))
            .collect();
        for (start, end) in fdes(image) {
            assert_eq!(listed.get(&start), Some(&end), "{image}: the FDE {start:#x}..{end:#x} is a listed function with that end: {listed:x?}");
            let why = run(&dir, &["why", "--addr", &format!("{start:#x}"), "--file", image]);
            let sources = why["function"]["found"]["start_sources"].as_array().cloned().unwrap_or_default();
            assert!(sources.contains(&unwind), "{image}: `why` at {start:#x} names `.eh_frame`: {why}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
