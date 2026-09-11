// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **One command, one answer — whichever door it was asked through.**
//!
//! The CLI, the MCP server and `serve` are three front doors onto the same
//! capability registry. That is the design. What the design does not enforce is
//! that a CLI subcommand actually *goes* through the registry, and several did
//! not: they carried their own source selection, their own architecture choice,
//! their own checks. Two implementations of one command is two answers to one
//! question, and both of the ones measured were disagreeing:
//!
//! - `disasm` / `decode` — `--bytes` with an `--addr` decoded through the CLI
//!   and answered `decode-failed` through the registry; an address past the
//!   last section was `addr-out-of-image` here and `decode-failed` there; a
//!   user's per-address comments showed in the terminal and nowhere else.
//! - `function discover` / `function.discover` — the registry built its own
//!   `Ctx` without the symbol chain, so **0 of 4 143 functions carried a name
//!   there against 1 152 here**, with `ok: true` and nothing to say a name was
//!   even possible.
//!
//! Both are fixed. This is the guard that notices the next one. Adding a pair
//! is one row in `PAIRS`.
//!
//! The target is the oracle corpus's System V shape, built here — see
//! `oracle/README.md`. No compiler, no check, and it says so.

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

/// One question, asked two ways. `cli` is the subcommand and its flags; `cap`
/// is the capability name and the same question as JSON. `{target}` is replaced
/// with the built oracle binary's path.
struct Pair {
    what: &'static str,
    cli: &'static [&'static str],
    cap: &'static str,
    args: &'static str,
}

const PAIRS: &[Pair] = &[
    Pair {
        what: "the function list, with its names",
        cli: &["function", "discover", "--file", "{target}", "--limit", "100000"],
        cap: "function.discover",
        args: r#"{"file":"{target}","limit":100000}"#,
    },
    Pair {
        what: "linear disassembly at an address",
        cli: &["disasm", "--file", "{target}", "--addr", "{entry}", "--count", "12"],
        cap: "decode",
        args: r#"{"file":"{target}","addr":"{entry}","count":12}"#,
    },
    Pair {
        what: "linear disassembly of inline bytes",
        cli: &["disasm", "--bytes", "48 89 c8 c3", "--addr", "0x1000"],
        cap: "decode",
        args: r#"{"bytes":"48 89 c8 c3","addr":"0x1000"}"#,
    },
    Pair {
        what: "an address that is not in the image",
        cli: &["disasm", "--file", "{target}", "--addr", "0x7fffffff0000"],
        cap: "decode",
        args: r#"{"file":"{target}","addr":"0x7fffffff0000"}"#,
    },
];

fn run(args: &[String]) -> Option<Value> {
    let out = Command::new(n0xis_exe()).args(args).output().ok()?;
    serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).ok()
}

/// Build the System V oracle shape, or `None` with a printed reason.
fn build_target(dir: &Path) -> Option<PathBuf> {
    let out = dir.join("sysv.so");
    let src = repo_root().join("oracle").join("sysv.c");
    let r = Command::new("gcc").args(["-shared", "-O1", "-fPIC", "-o"]).arg(&out).arg(&src).output();
    match r {
        Ok(o) if o.status.success() => Some(out),
        Ok(o) => {
            eprintln!("front doors: gcc failed:\n{}", String::from_utf8_lossy(&o.stderr));
            None
        }
        Err(_) => {
            eprintln!("front doors: skipping — gcc is not installed");
            None
        }
    }
}

#[test]
fn a_command_gives_the_same_answer_through_the_cli_and_the_registry() {
    if !n0xis_exe().exists() {
        eprintln!("front doors: skipping — {} is not built", n0xis_exe().display());
        return;
    }
    let tmp = std::env::temp_dir().join(format!("n0xis_doors_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("temp dir");
    let Some(target) = build_target(&tmp) else { return };
    let target = target.to_string_lossy().to_string();

    // An address the image really holds, taken from the tool's own function
    // list — a wrong one would make both doors fail identically, which this
    // test would then call agreement.
    let listing = run(&["function".into(), "discover".into(), "--file".into(), target.clone(), "--quiet".into()])
        .expect("function discover");
    let entry = listing["data"]["functions"][0]["va"].as_str().expect("an entry address").to_string();

    let mut disagreements = Vec::new();
    for pair in PAIRS {
        let fill = |s: &str| s.replace("{target}", &target).replace("{entry}", &entry);
        let mut cli: Vec<String> = pair.cli.iter().map(|a| fill(a)).collect();
        cli.push("--quiet".into());
        let via_cli = run(&cli);
        let via_reg = run(&[
            "capability".into(),
            "run".into(),
            pair.cap.into(),
            "--args".into(),
            fill(pair.args),
            "--quiet".into(),
        ]);
        match (via_cli, via_reg) {
            (Some(a), Some(b)) => {
                // `meta.source` legitimately differs in shape between doors;
                // the *answer* is `data` and the failure code.
                if a["data"] != b["data"] || a["ok"] != b["ok"] || a["error"]["code"] != b["error"]["code"] {
                    disagreements.push(format!(
                        "{}:\n      cli: ok={} err={} data={}\n      reg: ok={} err={} data={}",
                        pair.what,
                        a["ok"],
                        a["error"]["code"],
                        summarize(&a["data"]),
                        b["ok"],
                        b["error"]["code"],
                        summarize(&b["data"]),
                    ));
                }
            }
            (a, b) => disagreements.push(format!("{}: one door produced no envelope (cli={}, reg={})", pair.what, a.is_some(), b.is_some())),
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    assert!(
        disagreements.is_empty(),
        "one command, two answers — the CLI is not going through the registry:\n  {}",
        disagreements.join("\n  ")
    );
}

/// A short, comparable rendering — a whole function list is unreadable in a
/// failure message and the differing part is almost never the tail.
fn summarize(v: &Value) -> String {
    match v {
        Value::Object(o) => {
            let mut parts: Vec<String> = o
                .iter()
                .map(|(k, val)| match val {
                    Value::Array(a) => format!("{k}: [{} items]", a.len()),
                    other => format!("{k}: {}", other.to_string().chars().take(40).collect::<String>()),
                })
                .collect();
            parts.sort();
            format!("{{{}}}", parts.join(", "))
        }
        other => other.to_string().chars().take(80).collect(),
    }
}
