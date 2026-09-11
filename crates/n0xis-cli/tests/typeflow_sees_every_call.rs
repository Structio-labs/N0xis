// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The whole-program call graph, against the disassembly.**
//!
//! Type propagation travels along call edges, so the edges are the thing to
//! check first: a pass that walks a graph which is not the program's propagates
//! nothing and reports success, which is indistinguishable from having nothing
//! to propagate.
//!
//! A call reaches that pass in **two** shapes. It is a `Call` statement until
//! the optimizer folds a single-use result into its only consumer, after which
//! the same edge lives inside an expression — `return f(x) + 1`. Reading only
//! statements saw **one** of the three calls in `oracle/typeflow.c`.
//!
//! `objdump` is the outside source: it lists the direct calls, and this counts
//! the ones whose target is a function in the same image.

#![cfg(feature = "oracle")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

fn oracle_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("oracle")
}

/// Direct calls to a **corpus function**, keyed on the name `objdump` prints in
/// the angle brackets rather than on the address.
///
/// The name is what makes both call shapes countable with one rule. A `static`
/// function is called directly (`call 10e9 <knows>`); an **exported** one in a
/// shared object is called through the PLT (`call 1040 <tf_plt_leaf@plt>`),
/// because the linker routes even a self-call that way so `LD_PRELOAD` can
/// interpose. Both are one edge in the program's call graph, and keying on the
/// address counts only the first.
///
/// `LC_ALL=C` is not optional — a localized build prints different text and this
/// silently finds nothing.
fn direct_calls_between_local_functions(so: &Path, defined: &BTreeSet<String>) -> BTreeSet<(u64, u64)> {
    let out = Command::new("objdump")
        .args(["-d", "--no-show-raw-insn"])
        .arg(so)
        .env("LC_ALL", "C")
        .output()
        .expect("objdump runs");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut edges = BTreeSet::new();
    for line in text.lines() {
        let t = line.trim();
        let Some((addr, rest)) = t.split_once(':') else { continue };
        let Ok(here) = u64::from_str_radix(addr.trim(), 16) else { continue };
        let rest = rest.trim();
        // `call   1234 <name>` — indirect calls print `*%rax` and are skipped,
        // as is a call into the PLT, whose target is not a body in this image.
        let Some(arg) = rest.strip_prefix("call") else { continue };
        let arg = arg.trim();
        // A `@plt` suffix is kept on purpose: a call to a corpus function
        // through a stub is the shape that was being dropped, and skipping
        // everything with an `@` in it skipped exactly the case under test.
        // `is_corpus` below is what keeps real imports out.
        if !arg.contains('<') || arg.starts_with('*') {
            continue;
        }
        let Some(target) = arg.split_whitespace().next() else { continue };
        let Some(name) = arg.split_once('<').and_then(|(_, r)| r.split_once('>')).map(|(n, _)| n) else {
            continue;
        };
        // `foo@plt` and `foo` are the same callee. A stub whose symbol this
        // image also **defines** is a detour to a body in this same file — the
        // edge typeflow must walk; a stub for a real import is not.
        let name = name.split('@').next().unwrap_or(name);
        if defined.contains(name)
            && let Ok(to) = u64::from_str_radix(target, 16)
        {
            edges.insert((here, to));
        }
    }
    edges.retain(|(_, to)| *to != 0);
    edges
}

/// Every function **defined** in this image, by name — `nm` is the independent
/// source, so a wrong answer from n0xis cannot change what is counted.
fn defined_function_names(so: &Path) -> BTreeSet<String> {
    let out = Command::new("nm").arg("-a").arg(so).env("LC_ALL", "C").output().expect("nm runs");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let (_addr, kind, name) = (it.next()?, it.next()?, it.next()?);
            (kind == "t" || kind == "T").then(|| name.to_string())
        })
        .collect()
}

/// A corpus function by name, in either call shape.
fn is_corpus(name: &str) -> bool {
    name.starts_with("tf_") || name == "knows" || name.starts_with("blind_")
}

/// The corpus's own function addresses, from `nm` — an independent parser, so
/// a wrong answer from n0xis's discovery cannot quietly change what is counted.
fn corpus_functions(so: &Path) -> BTreeSet<u64> {
    let out = Command::new("nm")
        .arg("-a")
        .arg(so)
        .env("LC_ALL", "C")
        .output()
        .expect("nm runs");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let (addr, kind, name) = (it.next()?, it.next()?, it.next()?);
            let is_code = kind == "t" || kind == "T";
            (is_code && is_corpus(name)).then(|| u64::from_str_radix(addr, 16).ok())?
        })
        .collect()
}

#[test]
fn type_propagation_walks_every_call_the_disassembly_shows() {
    if Command::new("gcc").arg("--version").output().is_err()
        || Command::new("objdump").arg("--version").output().is_err()
    {
        eprintln!("skip: needs gcc and objdump — nothing was checked");
        return;
    }
    let tmp = std::env::temp_dir().join("n0xis-typeflow-oracle");
    std::fs::create_dir_all(&tmp).expect("tmp dir");
    let so = tmp.join("typeflow.so");
    let built = Command::new("gcc")
        // `-fno-inline` keeps the chain; without it there is nothing to walk.
        .args(["-O1", "-fno-inline", "-fPIC", "-shared", "-o"])
        .arg(&so)
        .arg(oracle_dir().join("typeflow.c"))
        .status()
        .expect("gcc runs");
    assert!(built.success(), "gcc could not build oracle/typeflow.c");

    let bodies = corpus_functions(&so);
    assert!(bodies.len() >= 8, "nm found {} corpus functions", bodies.len());
    let defined = defined_function_names(&so);
    let corpus = direct_calls_between_local_functions(&so, &defined);
    // Three `static` calls plus three routed through the PLT: both shapes have
    // to be present, or this passes without testing the one that was broken.
    let through_plt = corpus.iter().filter(|(_, to)| !bodies.contains(to)).count();
    assert!(
        corpus.len() >= 5 && through_plt >= 2,
        "the corpus should carry both call shapes; objdump shows {} calls, {through_plt} of them \
         through a stub",
        corpus.len()
    );

    // **The floor is computed, not chosen.** Every direct call whose callee is a
    // function this image defines is an edge typeflow must walk — including one
    // routed through a PLT stub, which is how a shared object calls its own
    // exported functions so `LD_PRELOAD` can interpose. Counting only the corpus
    // left room for unrelated CRT edges to satisfy the floor while every corpus
    // edge was missing, which is what a first version of this test did.
    let out = Command::new(n0xis_exe())
        .args(["function", "typeflow", "--file"])
        .arg(&so)
        .arg("--quiet")
        .output()
        .expect("n0xis runs");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON");
    assert_eq!(v["ok"].as_bool(), Some(true), "{v}");
    let edges = v["data"]["store"]["call_edges"].as_u64().expect("call_edges");

    eprintln!(
        "typeflow saw {edges} call edge(s); objdump shows {} to functions this image defines, \
         {through_plt} of them through a stub",
        corpus.len()
    );
    assert!(
        edges >= corpus.len() as u64,
        "typeflow walks {edges} edge(s) where the disassembly shows {}. Two shapes get lost here: \
         a call whose single-use result the optimizer folded into its consumer stops being a \
         `Call` statement, and a call to this image's own function goes through a PLT stub that \
         is not a function body. Both are edges, and propagation along a graph that is not the \
         program's is not propagation",
        corpus.len()
    );
}
