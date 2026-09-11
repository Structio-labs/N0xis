// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A capability that builds its own `Ctx` builds its own answer.**
//!
//! `with_src_ctx` and `with_cfg_ctx` are where a target becomes an analysis
//! context: the source is resolved once, the architecture is chosen from what
//! the image declares, and the symbol chain is attached — the image's exports,
//! a managed index, FLIRT matches, the user's own renames, in that order of
//! precedence. A capability that assembles a `Ctx` by hand gets whichever parts
//! its author remembered.
//!
//! `function.discover` did, and it forgot the symbols: measured on a 32-bit
//! system DLL, **0 of 4 143 functions carried a name**, against 1 152 through
//! the CLI, with `ok: true` and nothing to say a name was even possible. MCP
//! and `serve` reach the registry, so a human at the terminal saw names and an
//! agent asking the same question did not.
//!
//! Three capabilities still build their own, each for a reason written down
//! here. The list may shrink and may not grow by accident, and an entry that
//! goes stale fails — the same shape as the CLI's exemption list, for the same
//! reason: an exemption with no reason is where a defect goes to be forgotten.

use std::path::Path;

/// Capability → why it does not go through the shared context seam.
const BUILDS_ITS_OWN_CONTEXT: &[(&str, &str)] = &[
    (
        "decode",
        "linear disassembly renders the decoder's own text; it resolves no call target and \
         attaches no name, so the symbol chain would cost a scan and change nothing",
    ),
    (
        "pointer.path",
        "live-process only — it walks a chain of pointers in a running target, where there is \
         no static image and no symbol table to attach",
    ),
    (
        "diff.functions",
        "diffs two byte ranges lifted into throwaway snapshots; neither side is an image, so \
         there is nothing for a symbol provider to name",
    ),
    (
        "il2cpp.classes",
        "live-process only, and Windows-only: it reads the runtime's own class table out of a \
         running process, where there is no static image and the names come from managed \
         metadata rather than a symbol table",
    ),
    (
        "il2cpp.obj",
        "names come from the managed metadata the runtime holds, not from the binary's symbols. \
         Whether the symbol chain would add anything here has NOT been measured — that is the \
         reason it is listed rather than a claim that it would not",
    ),
    (
        "il2cpp.icalls",
        "reads registration names out of `.rdata`; those names are the managed layer's, not the \
         image's symbols. Same as `il2cpp.obj`: not measured, and said so rather than assumed",
    ),
    (
        "function.noreturn",
        "attaches the image's own symbols directly because the fixpoint is seeded from import \
         names, and runs a second, deliberately symbol-free context for the discovery sweep \
         that feeds it",
    ),
];

/// Each `Capability::new("name", …)` block's body, as source text.
fn capability_bodies() -> Vec<(String, String)> {
    // Capabilities are registered from several modules, not only `registry.rs`
    // — the managed-runtime, method and project groups each have their own.
    // Scanning one file found 32 of them and would have quietly stopped
    // looking at the rest, which is the same shape as the defects this guards.
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let marker = "Capability::new(";
    let mut out = Vec::new();
    let entries = std::fs::read_dir(&src).unwrap_or_else(|e| panic!("{}: {e}", src.display()));
    let mut files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    files.sort();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let starts: Vec<usize> = text.match_indices(marker).map(|(i, _)| i + marker.len()).collect();
        for (n, &start) in starts.iter().enumerate() {
            let end = starts.get(n + 1).copied().unwrap_or(text.len());
            let body = &text[start..end];
            let Some(open) = body.find('"') else { continue };
            let Some(close) = body[open + 1..].find('"').map(|o| open + 1 + o) else { continue };
            out.push((body[open + 1..close].to_string(), body.to_string()));
        }
    }
    assert!(out.len() > 55, "only {} capabilities parsed — the scan is broken, not the code", out.len());
    out
}

#[test]
fn a_capability_uses_the_shared_context_or_says_why_not() {
    let exempt: std::collections::BTreeMap<&str, &str> = BUILDS_ITS_OWN_CONTEXT.iter().copied().collect();
    let (mut undeclared, mut stale) = (Vec::new(), Vec::new());

    for (name, body) in capability_bodies() {
        let shared = body.contains("with_src_ctx") || body.contains("with_cfg_ctx") || body.contains("with_scan_ctx");
        let own = body.contains("Ctx::new(") && !shared;
        match (own, exempt.get(name.as_str())) {
            (true, None) => undeclared.push(name),
            (false, Some(_)) => stale.push(name),
            _ => {}
        }
    }

    assert!(
        undeclared.is_empty(),
        "these capabilities assemble a `Ctx` by hand and are not in BUILDS_ITS_OWN_CONTEXT.\n\
         Route them through `with_src_ctx`/`with_cfg_ctx`, or add them with the reason they \
         cannot be — `function.discover` did this and shipped a function list with no names:\n  {}",
        undeclared.join("\n  ")
    );
    assert!(
        stale.is_empty(),
        "these are listed in BUILDS_ITS_OWN_CONTEXT but now use the shared seam — remove the \
         entry, the list is a record of the codebase:\n  {}",
        stale.join("\n  ")
    );
}

/// An exemption without a real reason is not an exemption.
#[test]
fn every_exemption_carries_its_reason() {
    for (name, why) in BUILDS_ITS_OWN_CONTEXT {
        assert!(why.len() > 40, "`{name}` is exempt with no real reason: {why:?}");
    }
}
