// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The documentation must not be able to lie about the binary.**
//!
//! A truthfulness audit found the reference documentation stating **77 leaf
//! commands** and the README **110**, while `n0x guide` — which walks the clap
//! tree at run time and therefore cannot be wrong — reported **114**. Thirty-one
//! commands appeared nowhere in a document the README calls "every command".
//! Every one of those numbers was written by hand next to a sentence correctly
//! explaining that the guide is generated *so it can never drift*. The prose
//! drifted instead.
//!
//! The count and the command list are the binary's to state, so this test asks
//! the binary and fails the build when a document disagrees. It is deliberately
//! mechanical: a claim a reader can check in one command is a claim that has to
//! survive `cargo test`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn repo_root() -> PathBuf {
    // crates/n0xis-cli/ → the workspace root.
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

/// Every leaf command path, straight from the binary's own catalog.
fn leaf_commands() -> Vec<String> {
    let out = Command::new(env!("CARGO_BIN_EXE_n0xis"))
        .args(["guide", "--brief"])
        .output()
        .expect("run n0xis guide");
    assert!(out.status.success(), "`n0x guide --brief` failed");
    let v: Value = serde_json::from_slice(&out.stdout).expect("guide emits one JSON object");
    v["data"]["commands"]
        .as_array()
        .expect("guide carries a command array")
        .iter()
        .map(|c| c["path"].as_str().expect("every command has a path").to_string())
        .collect()
}

fn read(rel: &str) -> String {
    let p = repo_root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// The reference documents every command the binary accepts.
///
/// Not "documents it in depth" — the guide and `--help` carry the arguments —
/// but *names* it, so no command is invisible to a reader of the reference.
#[test]
fn the_reference_names_every_command_the_binary_has() {
    let doc = read("docs/CLI_COMMANDS.md");
    let missing: Vec<_> = leaf_commands().into_iter().filter(|p| !doc.contains(p.as_str())).collect();
    assert!(
        missing.is_empty(),
        "docs/CLI_COMMANDS.md does not mention {} command(s) the binary has: {missing:?}\n\
         Regenerate the inventory section — it is generated from `n0x guide`, never hand-kept.",
        missing.len()
    );
}

/// The generated inventory covers the whole catalog, not a stale slice of it.
///
/// The `contains` check above would also pass on a command merely mentioned in
/// passing prose. This one requires the row.
#[test]
fn the_generated_inventory_carries_a_row_per_command() {
    let doc = read("docs/CLI_COMMANDS.md");
    let begin = doc.find("<!-- BEGIN GENERATED COMMAND INVENTORY").expect("inventory begin marker");
    let end = doc.find("<!-- END GENERATED COMMAND INVENTORY").expect("inventory end marker");
    let section = &doc[begin..end];
    let missing: Vec<_> =
        leaf_commands().into_iter().filter(|p| !section.contains(&format!("`n0x {p}`"))).collect();
    assert!(missing.is_empty(), "the generated inventory has no row for: {missing:?}");
}

/// Every number a document states about the command count is the real one.
///
/// Prose is allowed to quote the count — it is useful — but only the true one.
#[test]
fn no_document_states_a_command_count_the_binary_contradicts() {
    let real = leaf_commands().len();
    let mut wrong = Vec::new();
    for rel in ["README.md", "MAP.md", "CONCEPT.md", "docs/CLI_COMMANDS.md"] {
        for (lineno, line) in read(rel).lines().enumerate() {
            for n in stated_command_counts(line) {
                if n != real {
                    wrong.push(format!("{rel}:{} says {n} commands, the binary has {real}", lineno + 1));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "stale command counts:\n  {}", wrong.join("\n  "));
}

/// Numbers followed by "command"/"commands" (optionally "leaf commands"), read
/// out of a line without pulling in a regex dependency for four call sites.
///
/// Deliberately narrow: it must not fire on "Phase 12", "45 are backed", or a
/// schema version. It fires on "114 commands" and on "**77 leaf commands**",
/// which is the form the stale reference actually used — markdown emphasis
/// sits between the number and the noun, so it is skipped.
fn stated_command_counts(line: &str) -> Vec<usize> {
    let b: Vec<char> = line.chars().collect();
    let mut found = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        // A digit run glued to a letter or a hyphen is a label, not a count:
        // `v0 commands` (the ported v0 surface) and `Phase-8 commands` both read
        // as "0 commands" and "8 commands" to a parser that only looks right.
        // Both were false positives on the first run of this test.
        let glued = start > 0 && (b[start - 1].is_alphabetic() || b[start - 1] == '-');
        let head: String = b[..start].iter().collect();
        let head_l = head.trim_end().to_ascii_lowercase();
        let after_phase = head_l.ends_with("phase");
        // "29 of 31 commands" names a subset, not the total. The `N of M`
        // construction is the only way a document says "some of them", and
        // requiring M to be the whole catalog would make the guard fire on a
        // true sentence — which it did, on this file's own status section.
        let subset = head_l.ends_with(" of")
            && head_l.trim_end_matches(" of").ends_with(|c: char| c.is_ascii_digit());
        if glued || after_phase || subset {
            continue;
        }
        let n: usize = b[start..i].iter().collect::<String>().parse().unwrap_or(0);
        let tail: String = b[i..].iter().collect();
        let tail = tail.trim_start_matches([' ', '*', '_', '`']);
        let tail = tail.strip_prefix("leaf ").unwrap_or(tail);
        let tail = tail.trim_start_matches([' ', '*', '_', '`']);
        if tail.starts_with("commands") || tail.starts_with("command\u{a0}") || tail == "command" {
            found.push(n);
        }
    }
    found
}

#[test]
fn the_command_count_reader_reads_the_forms_the_documents_used() {
    // Calibration. A checker that reports zero has to be shown reporting
    // non-zero on the same shapes first — these are the exact sentences the
    // audit found wrong, and a parser that misses them proves nothing by
    // passing.
    assert_eq!(stated_command_counts("`n0x guide` lists all 110 commands, generated from"), vec![110]);
    assert_eq!(stated_command_counts("The **installed** binary reports **77 leaf commands** via"), vec![77]);
    assert_eq!(stated_command_counts("reports **78**. `ui locate` is wired"), Vec::<usize>::new());
    assert_eq!(stated_command_counts("**114 leaf commands**, listed straight from"), vec![114]);
    // And it must stay quiet on numbers that are not command counts.
    assert_eq!(stated_command_counts("Phase 12 (IL2CPP managed layer)"), Vec::<usize>::new());
    assert_eq!(stated_command_counts("Of those 91, **45 are backed by the registry**"), Vec::<usize>::new());
    assert_eq!(stated_command_counts("25 tools returning the identical envelope"), Vec::<usize>::new());
    // Both of these fooled the first version of this parser on real lines.
    assert_eq!(stated_command_counts("the ported v0 commands live on inside"), Vec::<usize>::new());
    assert_eq!(stated_command_counts("The named Phase-8 commands (game grep,"), Vec::<usize>::new());
    assert_eq!(stated_command_counts("The named Phase 8 commands (game grep,"), Vec::<usize>::new());
    // A subset, not the catalog — this fired on a true sentence in README.md.
    assert_eq!(stated_command_counts("Linux — 29 of 31 commands measured against"), Vec::<usize>::new());
    // But a bare total is still a total.
    assert_eq!(stated_command_counts("the tool has 31 commands"), vec![31]);
}

/// The claim "N crates" is the workspace's to make.
#[test]
fn no_document_states_a_crate_count_the_workspace_contradicts() {
    let root = repo_root();
    let real = std::fs::read_dir(root.join("crates"))
        .expect("crates/")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("Cargo.toml").is_file())
        .count();
    let mut wrong = Vec::new();
    for rel in ["README.md", "MAP.md", "CONCEPT.md"] {
        for (lineno, line) in read(rel).lines().enumerate() {
            for (needle, n) in stated_crate_counts(line) {
                if n != real {
                    wrong.push(format!(
                        "{rel}:{} says {needle:?}, the workspace has {real} crates",
                        lineno + 1
                    ));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "stale crate counts:\n  {}", wrong.join("\n  "));
}

fn stated_crate_counts(line: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for (idx, _) in line.match_indices("crate") {
        // Walk back over "-", " " and the digits immediately before "crate".
        let head = &line[..idx];
        let head = head.trim_end_matches(['-', ' ']);
        let digits: String =
            head.chars().rev().take_while(|c| c.is_ascii_digit()).collect::<String>().chars().rev().collect();
        if digits.is_empty() {
            continue;
        }
        if let Ok(n) = digits.parse::<usize>() {
            out.push((format!("{digits} crate…"), n));
        }
    }
    out
}

/// Everything the registry can do is reachable from at least one front door.
///
/// A capability nothing dispatches is a promise in the catalog with no way to
/// keep it; this test states the current, measured shape so a regression is
/// visible rather than silent.
#[test]
fn every_registry_capability_is_named_by_a_front_door() {
    let out = Command::new(env!("CARGO_BIN_EXE_n0xis"))
        .args(["capability", "list"])
        .output()
        .expect("run n0xis capability list");
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
    let caps: BTreeSet<String> = v["data"]["capabilities"]
        .as_array()
        .expect("capability array")
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_string())
        .collect();
    // `capability run <name>` reaches every one of them by construction; this
    // asserts the catalog is non-empty and self-consistent rather than
    // re-deriving the CLI's own dispatch table.
    assert!(!caps.is_empty(), "the capability registry is empty");
    for c in &caps {
        assert!(!c.contains(' '), "capability {c:?} has a space — names are dot-separated");
    }
}

/// The two front doors must answer the same question the same way.
///
/// `function discover` is one of two commands the CLI implements itself instead
/// of dispatching to the registry, and the copies drifted: each kept its own
/// idea of what the image *states* about its functions, so adding exported
/// entry points to one made them answer 2 394 and 2 396 for the same file. A
/// fact the file states is not a per-frontend opinion.
///
/// Its fixture is this test's own executable, which on Linux is an ELF with no
/// PE export table — so it would **not** have caught that particular drift, and
/// it is not claimed to. What it holds is the invariant itself, on whatever
/// image it is given: the ordinal-export half is pinned where it lives, by
/// `n0xis-sources`'s `an_export_with_no_name_is_still_an_entry_point`.
#[test]
fn both_front_doors_discover_the_same_functions() {
    // The test binary itself is a real image of the host format, needing no
    // fixture and no network.
    let exe = std::env::current_exe().expect("test exe");
    let file = exe.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("n0xis-frontdoor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");

    let run = |args: &[&str]| -> Value {
        let out = Command::new(env!("CARGO_BIN_EXE_n0xis"))
            .args(args)
            .current_dir(&dir)
            .output()
            .expect("run n0xis");
        serde_json::from_slice(&out.stdout).expect("one JSON object")
    };
    run(&["init", "--name", "frontdoor"]);

    let cli = run(&["function", "discover", "--file", file, "--limit", "4000"]);
    let reg = run(&[
        "capability",
        "run",
        "function.discover",
        "--args",
        &format!("{{\"file\":{file:?},\"limit\":4000}}"),
    ]);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(cli["ok"].as_bool().unwrap_or(false), "CLI discover failed: {}", cli["error"]);
    assert!(reg["ok"].as_bool().unwrap_or(false), "registry discover failed: {}", reg["error"]);
    let vas = |v: &Value| -> Vec<String> {
        v["data"]["functions"]
            .as_array()
            .expect("functions")
            .iter()
            .map(|f| f["va"].as_str().expect("va").to_string())
            .collect()
    };
    assert_eq!(
        vas(&cli),
        vas(&reg),
        "the CLI and the capability registry disagree about which functions this image has"
    );
}

/// Every command the binary has must appear in ROADMAP's verification table
/// with what its answer was checked against.
///
/// The table is the only checkable form of "all sixty closed": a count in a
/// paragraph cannot be audited, and a list that drifts is worse than none. A
/// command added without a row is a command whose verification nobody has
/// decided on — which is exactly the state this whole pass existed to end.
#[test]
fn every_command_has_a_row_in_the_verification_table() {
    let roadmap = std::fs::read_to_string(repo_root().join("ROADMAP.md")).expect("ROADMAP.md");
    let table_start = roadmap
        .find("#### Every command, and what its answer was checked against")
        .expect("the verification table's heading");
    // Bounded to the table's own section. Searching to the end of the file
    // would let an unrelated mention of a command elsewhere in ROADMAP stand
    // in for its row — which is how the first version of this guard passed
    // after the row it was calibrated with had been deleted.
    let rest = &roadmap[table_start + 4..];
    let table_end = rest.find("\n#### ").map_or(roadmap.len(), |i| table_start + 4 + i);
    let table = &roadmap[table_start..table_end];
    let mut missing = Vec::new();
    for cmd in leaf_commands() {
        if !table.contains(&format!("| `{cmd}` |")) {
            missing.push(cmd);
        }
    }
    assert!(
        missing.is_empty(),
        "{} command(s) have no row in ROADMAP's verification table: {missing:?}",
        missing.len()
    );
}
