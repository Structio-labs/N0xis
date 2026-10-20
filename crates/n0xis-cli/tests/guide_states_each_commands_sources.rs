// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The guide states which targets each command takes, and only those.**
//!
//! `guide` used to say, in one sentence for the whole catalog, that commands
//! reading a target accept any of `--pid`, `--file`, `--snapshot`,
//! `--remote-cmd` and `--bytes`. Measured on 0.3.4 against each command's
//! `--help`: 69 of 117 commands took `--pid`, 54 `--file`, 29 `--snapshot` and
//! `--remote-cmd`, and `disasm --snapshot` answered `unexpected argument`. A
//! caller that believed the guide built a call the binary refuses.
//!
//! Each command now carries `sources`, read from its own argument definitions
//! (`TargetSource` in `main.rs`). This test holds that field to two things
//! outside the generator:
//!
//! - each command's `--help`, which is clap rendering the definition the parser
//!   runs: a stated source the help does not list is the lie above, and a
//!   source flag the help lists but the guide leaves out is one too, unless it
//!   is data spelled like a source (see [`DATA_SPELLED_LIKE_A_SOURCE`]);
//! - the parser itself: a sample of commands, each run with a source it does
//!   not take, must answer a typed refusal naming that flag.
//!
//! And it holds `docs/CLI_COMMANDS.md`'s per-command "Sources" lines to the
//! guide, because the reference restates them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use serde_json::Value;

mod support;

/// The five target flags, as the guide and `--help` spell them.
const SOURCE_FLAGS: [&str; 5] = ["--pid", "--file", "--snapshot", "--remote-cmd", "--bytes"];

/// A flag spelled like a source that is not one: its argument carries an id
/// of its own, so neither a `serve` session nor the guide counts it. Each entry
/// names the command, the flag and what the value is. A stale entry fails the
/// test, so the list cannot outlive the arguments it describes.
const DATA_SPELLED_LIKE_A_SOURCE: [(&str, &str, &str); 5] = [
    ("dump save", "--file", "the file whose bytes are stored as the dump's payload"),
    ("find", "--bytes", "the byte pattern searched for, not the bytes searched"),
    ("mem write", "--bytes", "the bytes written"),
    ("patch dry-run", "--bytes", "the replacement bytes"),
    ("patch apply", "--bytes", "the replacement bytes"),
];

fn n0xis(args: &[&str]) -> std::process::Output {
    support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).output().expect("run n0xis")
}

/// `(path, stated sources)` for every command in the guide, in its order.
fn guide_sources() -> Vec<(String, Vec<String>)> {
    let out = n0xis(&["guide", "--quiet"]);
    assert!(out.status.success(), "`guide` failed: {}", String::from_utf8_lossy(&out.stdout));
    let v: Value = serde_json::from_slice(&out.stdout).expect("guide emits one JSON object");
    let commands = v["data"]["commands"].as_array().expect("guide carries a command array");
    let rows: Vec<(String, Vec<String>)> = commands
        .iter()
        .map(|c| {
            let path = c["path"].as_str().expect("every command has a path").to_string();
            // A missing field is a failure, not an empty list: "never looked"
            // and "takes none" must not read alike.
            let sources = c["sources"]
                .as_array()
                .unwrap_or_else(|| panic!("`{path}` has no `sources` array: {c}"))
                .iter()
                .map(|s| s.as_str().expect("a source is a flag name").to_string())
                .collect();
            (path, sources)
        })
        .collect();
    assert!(rows.len() > 100, "the guide lists the catalog ({} commands)", rows.len());
    rows
}

/// Every `--long` option a command's `--help` lists.
fn help_flags(path: &str) -> BTreeSet<String> {
    let mut args: Vec<&str> = path.split(' ').collect();
    args.push("--help");
    let out = n0xis(&args);
    assert!(out.status.success(), "`{path} --help` failed");
    let text = String::from_utf8_lossy(&out.stdout);
    let flags: BTreeSet<String> = text
        .lines()
        .map(str::trim_start)
        .filter(|l| l.starts_with('-'))
        .filter_map(|l| {
            // `--pid <PID>`, or `-p, --pid <PID>`. Only the option column: a
            // wrapped help line can open with `-` and name a flag in prose.
            let mut tokens = l.split_whitespace();
            let first = tokens.next()?;
            let flag = if first.starts_with("--") {
                first
            } else if first.len() == 3 && first.ends_with(',') {
                tokens.next().filter(|t| t.starts_with("--"))?
            } else {
                return None;
            };
            Some(flag.split('=').next().unwrap_or(flag).to_string())
        })
        .collect();
    // Every leaf has `--help`; a parse that missed it read nothing.
    assert!(flags.contains("--help"), "read no options from `{path} --help`:\n{text}");
    flags
}

#[test]
fn every_command_states_the_sources_its_definition_declares() {
    let mut lies = Vec::new();
    let mut omitted = Vec::new();
    let mut exempt_used = BTreeSet::new();
    let mut stated_count: BTreeMap<&str, usize> = SOURCE_FLAGS.iter().map(|f| (*f, 0)).collect();
    let mut all_five = 0usize;
    let rows = guide_sources();
    for (path, stated) in &rows {
        for s in stated {
            assert!(SOURCE_FLAGS.contains(&s.as_str()), "`{path}` states {s}, which is not a target flag");
        }
        let help = help_flags(path);
        for flag in SOURCE_FLAGS {
            let says = stated.iter().any(|s| s == flag);
            let has = help.contains(flag);
            if says {
                *stated_count.get_mut(flag).expect("a source flag") += 1;
            }
            match (says, has) {
                (true, false) => lies.push(format!("`{path}` states {flag}; its --help has no {flag}")),
                (false, true) => match DATA_SPELLED_LIKE_A_SOURCE.iter().position(|(p, f, _)| p == path && *f == flag) {
                    Some(i) => {
                        exempt_used.insert(i);
                    }
                    None => omitted.push(format!("`{path}` takes {flag} (its --help lists it); the guide leaves it out")),
                },
                _ => {}
            }
        }
        if SOURCE_FLAGS.iter().all(|f| stated.iter().any(|s| s == f)) {
            all_five += 1;
        }
    }
    eprintln!("[guide sources] {} commands; stated per source: {stated_count:?}; all five: {all_five}", rows.len());
    eprintln!("[guide sources] data spelled like a source: {} entries", DATA_SPELLED_LIKE_A_SOURCE.len());
    assert!(lies.is_empty(), "the guide states sources the command does not take:\n  {}", lies.join("\n  "));
    assert!(omitted.is_empty(), "the guide omits sources the command takes:\n  {}", omitted.join("\n  "));
    let stale: Vec<_> = DATA_SPELLED_LIKE_A_SOURCE
        .iter()
        .enumerate()
        .filter(|(i, _)| !exempt_used.contains(i))
        .map(|(_, (p, f, _))| format!("{p} {f}"))
        .collect();
    assert!(stale.is_empty(), "exemptions that no longer describe the binary: {stale:?}");
}

/// The parser's own answer to a source a command does not take: exit 2 and a
/// `bad-arguments` envelope whose message names the flag.
fn assert_refused(path: &str, flag: &str) {
    let mut args: Vec<&str> = path.split(' ').collect();
    args.extend([flag, "x", "--quiet"]);
    let out = n0xis(&args);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("`{path} {flag}`: stdout is not one envelope ({e}): {stdout:?}"));
    assert_eq!(out.status.code(), Some(2), "`{path} {flag}` exits 2: {v}");
    assert_eq!(v["ok"], Value::Bool(false), "`{path} {flag}`: {v}");
    assert_eq!(v["error"]["code"], "bad-arguments", "`{path} {flag}`: {v}");
    let msg = v["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains(&format!("unexpected argument '{flag}'")),
        "`{path} {flag}` must be refused for {flag} itself, not for something else: {msg}"
    );
}

/// For each source, the first command in the guide that reads a target but
/// does not state that source — a command a caller could plausibly expect to
/// take it — run with it. Drawn from the guide, so the sample follows the
/// catalog; plus `disasm --snapshot`, the refusal the measurement observed.
#[test]
fn a_source_a_command_does_not_state_is_refused_by_name() {
    let rows = guide_sources();
    let mut sample: Vec<(String, &str)> = vec![("disasm".to_string(), "--snapshot")];
    for flag in SOURCE_FLAGS {
        let pick = rows.iter().find(|(path, stated)| {
            !stated.is_empty()
                && !stated.iter().any(|s| s == flag)
                && !DATA_SPELLED_LIKE_A_SOURCE.iter().any(|(p, f, _)| p == path && *f == flag)
        });
        let (path, _) = pick.unwrap_or_else(|| panic!("no target-reading command lacks {flag} — the sample is empty for it"));
        sample.push((path.clone(), flag));
    }
    eprintln!("[guide sources] refusal sample: {sample:?}");
    assert_eq!(sample.len(), 1 + SOURCE_FLAGS.len());
    for (path, flag) in &sample {
        assert_refused(path, flag);
    }
}

/// The commands a `### ` heading of the reference documents: each backticked
/// segment, cut at its first argument.
fn heading_paths(heading: &str) -> Vec<String> {
    heading
        .split('`')
        .skip(1)
        .step_by(2)
        .map(|seg| {
            seg.split_whitespace()
                .take_while(|w| !w.starts_with(['-', '<', '[', '|', '"']))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|p| !p.is_empty())
        .collect()
}

#[test]
fn the_reference_states_the_sources_the_guide_does() {
    let doc_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/CLI_COMMANDS.md");
    let doc = std::fs::read_to_string(&doc_path).unwrap_or_else(|e| panic!("read {}: {e}", doc_path.display()));
    let guide: BTreeMap<String, BTreeSet<String>> =
        guide_sources().into_iter().map(|(p, s)| (p, s.into_iter().collect())).collect();
    let mut heading = String::new();
    let mut checked = 0usize;
    let mut wrong = Vec::new();
    for (n, line) in doc.lines().enumerate() {
        if let Some(h) = line.strip_prefix("### ") {
            heading = h.to_string();
            continue;
        }
        let Some(rest) = line.strip_prefix("- Sources") else { continue };
        // Up to the first sentence end: what follows may name other flags.
        let clause = rest.split(". ").next().unwrap_or(rest);
        let said: BTreeSet<String> = clause
            .split('`')
            .skip(1)
            .step_by(2)
            .filter(|t| SOURCE_FLAGS.contains(t))
            .map(str::to_string)
            .collect();
        let paths = heading_paths(&heading);
        assert!(!paths.is_empty(), "docs/CLI_COMMANDS.md:{}: a Sources line under a heading naming no command", n + 1);
        for p in paths {
            let Some(real) = guide.get(&p) else {
                wrong.push(format!("line {}: `{p}` is not a command the guide lists", n + 1));
                continue;
            };
            checked += 1;
            if &said != real {
                wrong.push(format!("line {}: `{p}` documented {said:?}, the guide states {real:?}", n + 1));
            }
        }
    }
    eprintln!("[guide sources] reference Sources lines checked against the guide: {checked} commands");
    // The reader must be shown reading: a parse that matched no line passes.
    assert!(checked >= 20, "read only {checked} documented Sources lines");
    assert!(wrong.is_empty(), "docs/CLI_COMMANDS.md disagrees with the guide:\n  {}", wrong.join("\n  "));
}
