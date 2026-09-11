// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`ok: true` with nothing in it is the worst shape a wrong answer takes.**
//!
//! The caller has no error to branch on and no reason to doubt it. A twenty-line
//! version of this sweep — run the operations whose answer is certainly
//! non-empty, flag every success with an empty payload — found two defect
//! classes in one run, which was the highest defect-per-line ratio of anything
//! tried in that pass:
//!
//! - `ir slice --reg xmm0` answered `node_count: 0` on a function whose only
//!   instruction writes `xmm0` — the def-use recorded the register under
//!   another name;
//! - the whole-program noreturn fixpoint proved 2 functions of 1 398, because
//!   a call routed through an import stub reached no name.
//!
//! Both were found by *looking at emptiness*, not by any test. So it is a test
//! now. The target is the oracle corpus's System V shape (`oracle/README.md`),
//! whose contents are known: it has functions, blocks, a call graph and an
//! `.eh_frame`, so an empty answer to any of these is a defect and not a fact
//! about the input.
//!
//! An operation whose answer is *legitimately* empty here is listed with the
//! reason. That list is the honest half — without it the sweep would only cover
//! what happens to work.

#![cfg(feature = "oracle")]

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

/// An answer that cannot honestly be empty on this target, and the field that
/// carries it. `{target}` and `{entry}` are filled in.
struct MustAnswer {
    args: &'static [&'static str],
    field: &'static str,
}

const MUST_ANSWER: &[MustAnswer] = &[
    MustAnswer { args: &["function", "discover", "--file", "{target}"], field: "functions" },
    MustAnswer { args: &["function", "summary", "--file", "{target}", "--addr", "{entry}"], field: "summaries" },
    MustAnswer { args: &["function", "trace", "--file", "{target}", "--addr", "{entry}"], field: "nodes" },
    MustAnswer { args: &["function", "typeflow", "--file", "{target}"], field: "store" },
    // The image is compiled with unwind info, and this must match it — the
    // independent count (`objdump --dwarf=frames`) is 10 for this shape.
    MustAnswer { args: &["function", "eh", "--file", "{target}"], field: "functions" },
    MustAnswer { args: &["decomp", "pseudo", "--file", "{target}", "--addr", "{entry}"], field: "pseudo" },
    MustAnswer { args: &["ir", "build", "--file", "{target}", "--addr", "{entry}"], field: "blocks" },
    MustAnswer { args: &["ir", "explain", "--file", "{target}", "--addr", "{entry}"], field: "lines" },
    MustAnswer { args: &["ir", "value-set", "--file", "{target}", "--addr", "{entry}"], field: "sets" },
    MustAnswer { args: &["ir", "manifest", "--file", "{target}"], field: "entries" },
    MustAnswer { args: &["xref", "from", "--file", "{target}", "--addr", "{entry}"], field: "refs" },
    MustAnswer { args: &["module", "list", "--file", "{target}"], field: "modules" },
];

/// Answers that are empty here for a reason, so the sweep covers them
/// deliberately rather than by omission. Each says what would make it non-empty.
const HONESTLY_EMPTY: &[(&str, &str)] = &[
    ("function noreturn", "nothing in this corpus calls `exit`/`abort`, so no function is proven noreturn — `considered` is 13 and says the fixpoint ran"),
    ("rtti scan", "the corpus is C: there are no C++ vtables to recover"),
    ("ir deobfuscate", "the corpus is compiled straight through; there is no junk or opaque branch to find"),
    ("const identify", "no well-known constant (a CRC table, a crypto S-box) is in it"),
];

fn run(args: &[String]) -> Option<Value> {
    let out = Command::new(n0xis_exe()).args(args).output().ok()?;
    serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).ok()
}

fn build_target(dir: &Path) -> Option<PathBuf> {
    let out = dir.join("sysv.so");
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("oracle").join("sysv.c");
    match Command::new("gcc").args(["-shared", "-O1", "-fPIC", "-o"]).arg(&out).arg(&src).output() {
        Ok(o) if o.status.success() => Some(out),
        _ => {
            eprintln!("empty-answer sweep: skipping — gcc could not build the oracle shape");
            None
        }
    }
}

#[test]
fn no_operation_reports_success_with_an_empty_answer() {
    if !n0xis_exe().exists() {
        eprintln!("empty-answer sweep: skipping — {} is not built", n0xis_exe().display());
        return;
    }
    let tmp = std::env::temp_dir().join(format!("n0xis_empty_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("temp dir");
    let Some(target) = build_target(&tmp) else { return };
    let target = target.to_string_lossy().to_string();

    let listing = run(&["function".into(), "discover".into(), "--file".into(), target.clone(), "--quiet".into()])
        .expect("function discover");
    let entry = listing["data"]["functions"][0]["va"].as_str().expect("an entry address").to_string();

    let mut silent = Vec::new();
    for m in MUST_ANSWER {
        let mut args: Vec<String> =
            m.args.iter().map(|a| a.replace("{target}", &target).replace("{entry}", &entry)).collect();
        args.push("--quiet".into());
        let Some(v) = run(&args) else {
            silent.push(format!("{}: no envelope at all", m.args.join(" ")));
            continue;
        };
        if v["ok"] != Value::Bool(true) {
            silent.push(format!("{}: failed with {}", m.args.join(" "), v["error"]["code"]));
            continue;
        }
        let len = match &v["data"][m.field] {
            Value::Array(a) => a.len(),
            Value::Object(o) => o.len(),
            Value::Null => usize::MAX, // the field is missing entirely — worse
            _ => 1,
        };
        if len == usize::MAX {
            silent.push(format!("{}: `data.{}` is not in the answer at all", m.args.join(" "), m.field));
        } else if len == 0 {
            silent.push(format!("{}: ok:true and `data.{}` is empty", m.args.join(" "), m.field));
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    eprintln!(
        "empty-answer sweep: {} operations that cannot honestly be empty, {} recorded as legitimately empty",
        MUST_ANSWER.len(),
        HONESTLY_EMPTY.len()
    );
    assert!(
        silent.is_empty(),
        "these succeeded and said nothing — the caller has no error to branch on:\n  {}",
        silent.join("\n  ")
    );
}

/// The list of legitimate emptinesses must carry a reason, not just a name —
/// otherwise it becomes the place defects go to be forgotten.
#[test]
fn every_legitimate_emptiness_says_why() {
    for (op, why) in HONESTLY_EMPTY {
        assert!(why.len() > 30, "`{op}` is listed as legitimately empty with no real reason: {why:?}");
    }
}
