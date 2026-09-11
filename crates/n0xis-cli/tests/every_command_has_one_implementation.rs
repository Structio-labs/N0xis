// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A command that lives only in the CLI is a command the process seam cannot
//! reach — and one that lives in both places is one question with two answers.**
//!
//! The design says the CLI, the MCP server and `serve` are three front doors
//! onto one capability registry. Nothing enforced it, and two commands had
//! drifted into two implementations. Measured before they were unified:
//!
//! - `disasm` decoded inline bytes at an address; the registry's `decode`
//!   answered `decode-failed` for the same request;
//! - `function discover` returned 1 152 named functions of 4 143; the
//!   registry's `function.discover` returned **none named at all**.
//!
//! Behavioural agreement is checked by `front_doors_agree.rs`. This is the
//! structural half: a CLI handler either goes through the registry, or it is
//! **named here with the reason it cannot**. The list is allowed to shrink and
//! not to grow by accident — adding a handler that resolves its own source now
//! fails the build until someone writes down why.

use std::path::Path;

/// A CLI handler that does not go through a capability, and why that is
/// currently true. **The reason is the point**: an entry with no honest reason
/// is a defect waiting for its measurement.
///
/// Every one of these is a candidate for a capability — thirteen of them cannot
/// be driven by an agent at all today, which is the Process seam not holding.
const NOT_THROUGH_THE_REGISTRY: &[(&str, &str)] = &[
    ("cmd_serve", "starts the server that *hosts* the registry; it cannot be a capability of it"),
    ("cmd_remote_serve", "the same, over a pipe: it is the far side of the seam, not a user of it"),
    ("cmd_snapshot_dump", "writes a file the other commands then read; no analysis to expose"),
    ("cmd_debug_await_hit", "blocks on a live debug event — a long-poll, not a request/response"),
    ("cmd_debug_watch", "the same: it streams until interrupted"),
    // The rest are analysis and *should* become capabilities. Recorded with
    // what each would cost, so the list reads as work rather than as excuse.
    ("cmd_profile", "TODO: analysis, agent-reachable — no capability yet"),
    ("cmd_discover", "TODO: richer than `function.discover` (`--pdata`, `--flirt`); folding those in is what closes it"),
    ("cmd_analyze", "TODO: whole-program orchestration that persists into `.n0x/`; needs a project-aware capability"),
    ("cmd_find", "TODO: analysis, agent-reachable — no capability yet"),
    ("cmd_stack_backtrace", "TODO: analysis, agent-reachable — no capability yet"),
    ("cmd_provenance_trace", "TODO: analysis, agent-reachable — no capability yet"),
    ("cmd_lua_strings", "TODO: engine layer, agent-reachable — no capability yet"),
    ("cmd_lua_table", "TODO: engine layer, agent-reachable — no capability yet"),
    ("cmd_lua_combo", "TODO: engine layer, agent-reachable — no capability yet"),
    ("cmd_lua_seedscan", "TODO: engine layer, agent-reachable — no capability yet"),
    ("cmd_locate_by_transition", "TODO: analysis, agent-reachable — no capability yet"),
    ("cmd_const_identify", "TODO: analysis, agent-reachable — no capability yet"),
    ("cmd_bindings_list", "TODO: analysis, agent-reachable — no capability yet"),
    ("cmd_sig_gen", "TODO: analysis, agent-reachable — no capability yet"),
];

/// Every `fn cmd_*` in the CLI, with its body — taken as the text up to the
/// next top-level `fn`, not by brace matching. A brace inside a string literal
/// or a doc comment ends a match early and silently, which would make this
/// guard quietly stop looking. Over-reading by a few lines cannot hide a
/// `StaticImage::load`; under-reading can.
fn handlers() -> Vec<(String, String)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("main.rs");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let starts: Vec<usize> = text.match_indices("\nfn ").map(|(i, _)| i + 1).collect();
    let mut out = Vec::new();
    for (n, &start) in starts.iter().enumerate() {
        let end = starts.get(n + 1).copied().unwrap_or(text.len());
        let head = &text[start..end];
        let Some(name_end) = head.find('(') else { continue };
        let name = &head[3..name_end];
        if name.starts_with("cmd_") {
            out.push((name.to_string(), head.to_string()));
        }
    }
    assert!(out.len() > 50, "only {} handlers parsed — the scan is broken, not the code", out.len());
    out
}

/// A handler that opens the target itself has its own answer to "which source,
/// which architecture, and what is readable" — the three questions that made
/// `disasm` disagree with `decode`.
fn resolves_its_own_source(body: &str) -> bool {
    ["StaticImage::load", "attach_live(", "Snapshot::builder()", "build_source(", "source::resolve("]
        .iter()
        .any(|k| body.contains(k))
}

#[test]
fn a_cli_handler_goes_through_the_registry_or_says_why_not() {
    let exempt: std::collections::BTreeMap<&str, &str> = NOT_THROUGH_THE_REGISTRY.iter().copied().collect();
    let mut undeclared = Vec::new();
    let mut declared_but_fine = Vec::new();

    // A handler can be defined twice — one `#[cfg(unix)]`, one
    // `#[cfg(windows)]`. They are one command, so the verdict is the union: if
    // *any* platform's copy opens the source itself, the command does.
    let mut own_by_name: std::collections::BTreeMap<String, bool> = std::collections::BTreeMap::new();
    for (name, body) in handlers() {
        let own = !body.contains("run_capability(") && resolves_its_own_source(&body);
        *own_by_name.entry(name).or_insert(false) |= own;
    }

    for (name, own) in own_by_name {
        match (own, exempt.get(name.as_str())) {
            (true, None) => undeclared.push(name),
            // The list shrinks by unifying a command; when that happens the
            // entry has to go, or it becomes a false record of the codebase.
            (false, Some(_)) => declared_but_fine.push(name),
            _ => {}
        }
    }

    assert!(
        undeclared.is_empty(),
        "these CLI handlers resolve their own source and are not in NOT_THROUGH_THE_REGISTRY.\n\
         Route them through a capability, or add them with the reason they cannot be:\n  {}",
        undeclared.join("\n  ")
    );
    assert!(
        declared_but_fine.is_empty(),
        "these are listed in NOT_THROUGH_THE_REGISTRY but no longer resolve their own source — \
         remove the entry, the list is a record of the codebase and this one is stale:\n  {}",
        declared_but_fine.join("\n  ")
    );
}

/// The exemptions that are genuinely structural, versus the ones that are work
/// not yet done. Keeping the count visible is what stops "TODO" from becoming
/// the permanent answer.
#[test]
fn the_unreachable_commands_are_counted_out_loud() {
    let todo = NOT_THROUGH_THE_REGISTRY.iter().filter(|(_, why)| why.starts_with("TODO")).count();
    let structural = NOT_THROUGH_THE_REGISTRY.len() - todo;
    eprintln!(
        "process seam: {structural} handlers cannot be capabilities by their nature; \
         {todo} are analysis an agent still cannot reach"
    );
    assert!(
        todo <= 14,
        "{todo} commands are unreachable through the process seam — that number is meant to fall, \
         not rise; raise this bound only with a reason"
    );
}
