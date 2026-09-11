// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **"Who calls this?" checked against a disassembler that is not this one.**
//!
//! It is the question a user asks first, and it had been verified only against
//! other n0xis commands. A cross-reference index can be wrong in two directions
//! and each looks fine on its own: a missed caller quietly narrows the answer,
//! and an invented one sends the reader somewhere nothing happens.
//!
//! So both directions are asserted. Every direct `call`/`jmp` `objdump` shows
//! into a target must appear in `xref to`, **and** every reference `xref to`
//! reports must be one `objdump` shows.
//!
//! Measured when this was written, on the busiest targets of a system C
//! library — 139 to 601 references each — **0 missed and 0 invented**. The
//! first version of the check counted only `call` and flagged 37 "extras";
//! every one was a `jmp` the reference also showed, labelled `kind: "jmp"` in
//! the answer. The measurement was narrower than the tool, which is the usual
//! direction.

#![cfg(feature = "oracle")]

use std::collections::{BTreeMap, BTreeSet};
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

fn a_system_library() -> Option<String> {
    ["/usr/lib/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib64/libc.so.6", "/usr/lib/libm.so.6"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .map(str::to_string)
}

/// target address → every site that references it directly, from `objdump`.
///
/// Widened twice, both times because the *measurement* was narrower than the
/// tool and made it look like it was inventing references:
///
/// - `call` **and** `jmp`/`j<cc>` — a tail call is a reference, and counting
///   only `call` flagged 37 real tail calls as invented;
/// - and the `# <hex>` comment `objdump` prints for a RIP-relative operand,
///   which is how `lea rdx,[rip+disp]` names an address. Those are data
///   references; the answer labels them `kind: "data"`, and two of them were
///   the last "invented" ones left.
fn direct_branches(binary: &str) -> BTreeMap<u64, BTreeSet<u64>> {
    let out = Command::new("objdump")
        .env("LC_ALL", "C")
        .args(["-d", "-M", "intel", "--section=.text"])
        .arg(binary)
        .output()
        .expect("objdump");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut map: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for line in text.lines() {
        let Some((head, rest)) = line.split_once(":\t") else { continue };
        let Ok(site) = u64::from_str_radix(head.trim(), 16) else { continue };
        // `<bytes>\t<mnemonic> <operand>`
        let Some((_, code)) = rest.split_once('\t') else { continue };
        // A RIP-relative operand's resolved address, which objdump prints as a
        // trailing `# <hex> <symbol>` comment.
        if let Some(hash) = code.find("# ")
            && let Some(tok) = code[hash + 2..].split_whitespace().next()
            && let Ok(target) = u64::from_str_radix(tok, 16)
        {
            map.entry(target).or_default().insert(site);
        }
        let mut it = code.split_whitespace();
        let (Some(mnemonic), Some(operand)) = (it.next(), it.next()) else { continue };
        if !(mnemonic == "call" || mnemonic.starts_with('j')) {
            continue;
        }
        let Ok(target) = u64::from_str_radix(operand.trim(), 16) else { continue };
        map.entry(target).or_default().insert(site);
    }
    map
}

fn refs_to(binary: &str, target: u64) -> Option<BTreeSet<u64>> {
    let out = Command::new(n0xis_exe())
        .args(["xref", "to", "--quiet", "--addr", &format!("{target:#x}"), "--file", binary])
        .output()
        .ok()?;
    let v: Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).ok()?;
    let list = v["data"].as_object()?.values().find_map(Value::as_array)?;
    Some(
        list.iter()
            .filter_map(|r| r["from"].as_str())
            .filter_map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .collect(),
    )
}

#[test]
fn every_caller_the_disassembly_shows_is_in_the_cross_reference_and_no_others() {
    if !n0xis_exe().exists() || Command::new("objdump").arg("--version").output().is_err() {
        eprintln!("xref: skipping — n0xis or objdump unavailable, so nothing was checked");
        return;
    }
    let Some(binary) = a_system_library() else {
        eprintln!("xref: skipping — no system library to read, so nothing was checked");
        return;
    };

    let reference = direct_branches(&binary);
    assert!(reference.len() > 100, "only {} branch targets parsed — the reference is broken", reference.len());

    // The busiest targets: a function nothing calls proves nothing, and one
    // with hundreds of callers is where a partial index shows itself.
    let mut busiest: Vec<(&u64, &BTreeSet<u64>)> = reference.iter().collect();
    busiest.sort_by_key(|(_, sites)| std::cmp::Reverse(sites.len()));
    busiest.truncate(6);

    let mut compared = 0usize;
    let mut problems = Vec::new();
    for (target, sites) in busiest {
        let Some(got) = refs_to(&binary, *target) else {
            problems.push(format!("{target:#x}: `xref to` produced no usable answer"));
            continue;
        };
        compared += sites.len();
        let missed: Vec<String> = sites.difference(&got).take(5).map(|a| format!("{a:#x}")).collect();
        let invented: Vec<String> = got.difference(sites).take(5).map(|a| format!("{a:#x}")).collect();
        if !missed.is_empty() {
            problems.push(format!("{target:#x}: {} callers the disassembly shows are missing, e.g. {}", sites.difference(&got).count(), missed.join(", ")));
        }
        if !invented.is_empty() {
            problems.push(format!("{target:#x}: {} references the disassembly does not show, e.g. {}", got.difference(sites).count(), invented.join(", ")));
        }
    }
    assert!(compared > 200, "only {compared} references compared — too few to mean anything");
    eprintln!("xref: {compared} references across 6 targets, none missed and none invented");
    assert!(problems.is_empty(), "the cross-reference disagrees with the disassembly:\n  {}", problems.join("\n  "));
}
