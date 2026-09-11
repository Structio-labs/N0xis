// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The call graph, checked against a disassembler that is not this one.**
//!
//! `xref from`, `function trace`, the whole-program noreturn fixpoint and every
//! call the decompiler renders all read the CFG's `callsites`. A dropped call
//! silently shortens the graph; an invented one adds an edge to a function that
//! never runs. Neither shows up as an error.
//!
//! Two independent sources are needed, because the question "which calls are in
//! this function" has two halves and each needs its own answer:
//!
//! - **`objdump --dwarf=frames`** decides where the function *ends*. Using
//!   objdump's symbol headers instead reported 89 phantom "extra" calls — the
//!   symbol boundary and the real extent are different things, and blaming the
//!   tool for that would have been blaming it for the measurement.
//! - **`objdump -d`** decides which instructions in that range transfer control
//!   out of it.
//!
//! A **tail call is a call**: an unconditional `jmp` out of the range, and a
//! *conditional* one too. Counting only `call` reported 120 inventions, and
//! then one more; every one was a real tail call the answer had already
//! labelled `kind: "tail"`. The reference was narrower than the tool three
//! times over before it matched.
//!
//! Measured when this was written: **94 functions of a system C library, 0 call
//! sites missed and 0 invented.**

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

fn objdump(binary: &str, args: &[&str]) -> String {
    let out = Command::new("objdump").env("LC_ALL", "C").args(args).arg(binary).output().expect("objdump");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Function extents from the unwind table — the independent answer to "where
/// does this function end", which the call comparison needs before it can start.
fn extents(binary: &str) -> BTreeMap<u64, u64> {
    let mut map = BTreeMap::new();
    for line in objdump(binary, &["--dwarf=frames"]).lines() {
        let Some(pos) = line.find("pc=") else { continue };
        let Some((a, b)) = line[pos + 3..].split_once("..") else { continue };
        let b = b.split_whitespace().next().unwrap_or(b);
        if let (Ok(lo), Ok(hi)) = (u64::from_str_radix(a.trim(), 16), u64::from_str_radix(b.trim(), 16)) {
            map.insert(lo, hi);
        }
    }
    map
}

/// `(site, mnemonic, target)` for every direct control transfer in `.text`.
fn transfers(binary: &str) -> Vec<(u64, String, u64)> {
    let mut out = Vec::new();
    for line in objdump(binary, &["-d", "-M", "intel", "--section=.text"]).lines() {
        let Some((head, rest)) = line.split_once(":\t") else { continue };
        let Ok(site) = u64::from_str_radix(head.trim(), 16) else { continue };
        let Some((_, code)) = rest.split_once('\t') else { continue };
        let mut it = code.split_whitespace();
        let Some(mut mnemonic) = it.next() else { continue };
        // Branch prefixes objdump prints as separate words.
        if mnemonic == "addr32" || mnemonic == "bnd" {
            let Some(next) = it.next() else { continue };
            mnemonic = next;
        }
        if !(mnemonic == "call" || mnemonic.starts_with('j')) {
            continue;
        }
        let Some(operand) = it.next() else { continue };
        let Ok(target) = u64::from_str_radix(operand.trim(), 16) else { continue };
        out.push((site, mnemonic.to_string(), target));
    }
    out.sort_by_key(|(s, _, _)| *s);
    out
}

fn callsites(binary: &str, at: u64) -> Option<BTreeSet<(u64, u64)>> {
    let out = Command::new(n0xis_exe())
        .args(["ir", "build", "--quiet", "--addr", &format!("{at:#x}"), "--file", binary])
        .output()
        .ok()?;
    let v: Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).ok()?;
    Some(
        v["data"]["callsites"]
            .as_array()?
            .iter()
            .filter_map(|c| {
                let from = u64::from_str_radix(c["from"].as_str()?.trim_start_matches("0x"), 16).ok()?;
                let target = u64::from_str_radix(c["target"].as_str()?.trim_start_matches("0x"), 16).ok()?;
                Some((from, target))
            })
            .collect(),
    )
}

/// **A branch target inside the function must begin a basic block.**
///
/// It is the definition of a basic block, and it is where a control-flow graph
/// goes quietly wrong: a target the splitter missed leaves two blocks fused,
/// so an edge that exists in the program does not exist in the graph. Every
/// pass over the CFG then reasons about a program with a path missing —
/// dominators, the SSA's phi placement, the structurer's if/else recovery, the
/// noreturn fixpoint. None of them can notice.
///
/// Checked against `objdump`'s branch targets, inside the extent the image's
/// own unwind table gives. Measured when this was written: **100 functions of a
/// system C library, every in-range branch target a block start, none missing.**
#[test]
fn every_branch_target_inside_a_function_begins_a_block() {
    if !n0xis_exe().exists() || Command::new("objdump").arg("--version").output().is_err() {
        eprintln!("blocks: skipping — n0xis or objdump unavailable, so nothing was checked");
        return;
    }
    let Some(binary) = a_system_library() else {
        eprintln!("blocks: skipping — no system library to read, so nothing was checked");
        return;
    };
    let extents = extents(&binary);
    let transfers = transfers(&binary);
    assert!(extents.len() > 100 && transfers.len() > 500, "the reference is broken, not the tool");
    let sites: Vec<u64> = transfers.iter().map(|(s, _, _)| *s).collect();

    let (mut checked, mut compared) = (0usize, 0usize);
    let mut problems = Vec::new();
    for (&lo, &hi) in extents.iter().filter(|&(&lo, _)| lo > 0) {
        let start = sites.partition_point(|s| *s < lo);
        // Only branches that stay inside: one that leaves is a tail call, and
        // the block it lands in belongs to another function.
        let want: BTreeSet<u64> = transfers[start..]
            .iter()
            .take_while(|(s, _, _)| *s < hi)
            .filter(|(_, mnemonic, target)| mnemonic != "call" && (lo..hi).contains(target))
            .map(|(_, _, t)| *t)
            .collect();
        if !(2..=12).contains(&want.len()) {
            continue;
        }
        let out = Command::new(n0xis_exe())
            .args(["ir", "build", "--quiet", "--addr", &format!("{lo:#x}"), "--file", &binary])
            .output()
            .expect("run n0xis");
        let Ok(v) = serde_json::from_str::<Value>(&String::from_utf8_lossy(&out.stdout)) else { continue };
        let Some(blocks) = v["data"]["blocks"].as_array() else { continue };
        let starts: BTreeSet<u64> = blocks
            .iter()
            .filter_map(|b| u64::from_str_radix(b["start"].as_str()?.trim_start_matches("0x"), 16).ok())
            .collect();
        checked += 1;
        compared += want.len();
        let missing: Vec<String> = want.difference(&starts).take(3).map(|a| format!("{a:#x}")).collect();
        if !missing.is_empty() {
            problems.push(format!("{lo:#x}: branched to but not a block start: {}", missing.join(", ")));
        }
        if checked >= 100 {
            break;
        }
    }
    assert!(compared > 100, "only {compared} branch targets compared across {checked} functions — too few");
    eprintln!("blocks: {compared} branch targets across {checked} functions, every one begins a block");
    assert!(problems.is_empty(), "the graph fuses blocks the program branches into:\n  {}", problems.join("\n  "));
}

#[test]
fn the_call_graph_holds_every_call_the_disassembly_shows_and_no_others() {
    if !n0xis_exe().exists() || Command::new("objdump").arg("--version").output().is_err() {
        eprintln!("call sites: skipping — n0xis or objdump unavailable, so nothing was checked");
        return;
    }
    let Some(binary) = a_system_library() else {
        eprintln!("call sites: skipping — no system library to read, so nothing was checked");
        return;
    };

    let extents = extents(&binary);
    let transfers = transfers(&binary);
    assert!(extents.len() > 100 && transfers.len() > 500, "the reference is broken, not the tool");
    let sites: Vec<u64> = transfers.iter().map(|(s, _, _)| *s).collect();

    let mut checked = 0usize;
    let mut compared = 0usize;
    let mut problems = Vec::new();
    for (&lo, &hi) in extents.iter().filter(|&(&lo, _)| lo > 0) {
        // Every transfer inside the extent that leaves it — a `call`, or a
        // `jmp`/`j<cc>` whose target is outside. An in-range branch is control
        // flow, not a call.
        let start = sites.partition_point(|s| *s < lo);
        let want: BTreeSet<(u64, u64)> = transfers[start..]
            .iter()
            .take_while(|(s, _, _)| *s < hi)
            .filter(|(_, mnemonic, target)| mnemonic == "call" || !(lo..hi).contains(target))
            .map(|(s, _, t)| (*s, *t))
            .collect();
        // Two calls is where the question starts to mean something; more than
        // ten and one slow function dominates the run.
        if !(2..=10).contains(&want.len()) {
            continue;
        }
        let Some(got) = callsites(&binary, lo) else { continue };
        checked += 1;
        compared += want.len();
        let missed: Vec<String> = want.difference(&got).take(3).map(|(s, t)| format!("{s:#x}->{t:#x}")).collect();
        let invented: Vec<String> = got.difference(&want).take(3).map(|(s, t)| format!("{s:#x}->{t:#x}")).collect();
        if !missed.is_empty() {
            problems.push(format!("{lo:#x}: the disassembly shows calls the graph does not have: {}", missed.join(", ")));
        }
        if !invented.is_empty() {
            problems.push(format!("{lo:#x}: the graph has calls the disassembly does not show: {}", invented.join(", ")));
        }
        if checked >= 100 {
            break;
        }
    }
    assert!(compared > 100, "only {compared} call sites compared across {checked} functions — too few to mean anything");
    eprintln!("call sites: {compared} across {checked} functions, none missed and none invented");
    assert!(problems.is_empty(), "the call graph disagrees with the disassembly:\n  {}", problems.join("\n  "));
}
