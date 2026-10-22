// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A principle with no mechanical check is a comment.**
//!
//! `CONCEPT.md` and the workspace's design notes already say it: a value that
//! lives in more than one place is a value that will eventually be two
//! different values. Nothing enforced it, and every defect a verification pass
//! found had exactly that shape — the drift never surfaced as an error, it
//! surfaced as a *confident wrong answer*:
//!
//! - one physical register under two names (`zmm0` in the def-use records,
//!   `xmm0` in every line of output) made `ir slice --reg xmm0` report
//!   `node_count: 0` on a function whose only instruction writes it, and made
//!   `function summary` claim a complete and empty clobber set;
//! - three independent answers to "what is the function at this address called"
//!   gave one address two names depending on which command was asked;
//! - four copies of "pick the calling convention the source declares";
//! - the ABI's integer return register spelled `"rax.0"` inside a
//!   target-neutral pass, where on any other architecture it matches nothing.
//!
//! These are source-level guards, deliberately. They cannot prove the facts are
//! consistent — only that the *places that must agree* still go through one
//! function. That is the part a reviewer forgets and a test does not.

use n0xis_arch::Arch;
use std::path::{Path, PathBuf};

fn crate_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every `.rs` under this crate's `src/`, as `(path, contents)`.
fn sources() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs")
                && let Ok(text) = std::fs::read_to_string(&p)
            {
                out.push((p, text));
            }
        }
    }
    let mut out = Vec::new();
    walk(&crate_src(), &mut out);
    assert!(!out.is_empty(), "no sources found under {}", crate_src().display());
    out
}

/// Lines of `text` outside `#[cfg(test)]` — a test may spell a concrete
/// register, because a test's whole job is to name the exact expected answer.
fn product_lines(text: &str) -> Vec<(usize, &str)> {
    let cut = text.find("\n#[cfg(test)]").unwrap_or(text.len());
    text[..cut]
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l))
        .filter(|(_, l)| {
            let t = l.trim_start();
            !t.starts_with("//") && !t.starts_with("///") && !t.starts_with("//!")
        })
        .collect()
}

/// The ABI's return register is an *architecture's* answer, and this crate is
/// written against the [`n0xis_arch::Arch`] trait. Spelling it here compiles on
/// every target and is right on one.
#[test]
fn the_abi_return_register_is_asked_for_never_spelled() {
    let mut bad = Vec::new();
    for (path, text) in sources() {
        // The one place allowed to name it: the fallback inside the helper that
        // *is* the question, where the register file has no answer at all.
        if path.ends_with("ir.rs") {
            continue;
        }
        for (n, line) in product_lines(&text) {
            if line.contains("\"rax.0\"") || line.contains("\"x0.0\"") || line.contains("\"eax.0\"") {
                bad.push(format!("{}:{n}: {}", path.display(), line.trim()));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "the ABI's return register is spelled literally in a target-neutral pass; ask \
         `ir::abi_return_register(ctx)` instead:\n  {}",
        bad.join("\n  ")
    );
}

/// Every `.rs` under every crate's `src/`. Wider than [`sources`] on purpose:
/// the calling-convention rule below has readers in two crates, so a guard that
/// looked at one of them would pass by not looking.
fn workspace_sources() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs")
                && let Ok(text) = std::fs::read_to_string(&p)
            {
                out.push((p, text));
            }
        }
    }
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut out = Vec::new();
    for e in std::fs::read_dir(&crates).expect("crates/ is readable").flatten() {
        walk(&e.path().join("src"), &mut out);
    }
    assert!(out.len() > 50, "found only {} workspace sources", out.len());
    out
}

/// One rule for "which calling convention does this target use", not four.
/// Every copy drifts on its own schedule.
///
/// The rule lives on the `Arch` trait, because its readers are in two crates
/// that cannot share a private helper: the lift decides what a `call` forwards
/// and invalidates, the core's passes decide what a parameter is, and the
/// emulator decides what a callee sees on entry. When the last of those three
/// arrived it got a different answer from the other two, and the disagreement
/// showed up as a wrong number rather than an error.
#[test]
fn the_calling_convention_is_chosen_in_exactly_one_place() {
    let sites: Vec<String> = workspace_sources()
        .into_iter()
        .flat_map(|(path, text)| {
            product_lines(&text)
                .into_iter()
                // A `fn calling_conventions` line *declares* or *implements* the
                // list; this guard is about who **reads** it.
                .filter(|(_, l)| {
                    l.contains("calling_conventions()") && !l.contains("fn calling_conventions")
                })
                .map(|(n, l)| format!("{}:{n}: {}", path.display(), l.trim()))
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(
        sites.len(),
        1,
        "`calling_conventions()` must be read only by `Arch::calling_convention`; found {} \
         sites:\n  {}",
        sites.len(),
        sites.join("\n  ")
    );
    assert!(
        sites[0].contains("n0xis-arch") && sites[0].contains("lib.rs"),
        "the one site must be `Arch::calling_convention`: {}",
        sites[0]
    );
}

/// Every architecture that lifts declares at least one calling convention,
/// and one that only decodes states why it has none (the lead's DECISIONS
/// item 6, for the WebAssembly architecture of docs/design/WASM.md stage 2).
///
/// This is what makes `Arch::calling_convention`'s `None` unreachable for an
/// architecture the lift runs on, and so what lets the lift take its answer
/// without a second read of the list to fall back on. Stated as a test rather
/// than left as a comment, because the guard above is only worth what this
/// invariant is. A decode-only architecture is refused by every command that
/// would read a convention (`n0xis_frontend::lift_refusal`), with the reason
/// it states here.
#[test]
fn every_architecture_that_lifts_declares_a_calling_convention() {
    let module = std::sync::Arc::new(n0xis_wasm::read(b"\0asm\x01\0\0\0").expect("the empty module reads"));
    let arches: Vec<(&str, Box<dyn Arch>)> = vec![
        ("x64", Box::new(n0xis_arch::X64::new())),
        ("arm64", Box::new(n0xis_arch::Arm64::new())),
        ("arm32", Box::new(n0xis_arch::Arm32::a32())),
        ("thumb", Box::new(n0xis_arch::Arm32::thumb())),
        ("wasm", Box::new(n0xis_wasm_arch::Wasm::new(module, "test"))),
    ];
    for (name, arch) in arches {
        let ccs: Vec<&str> = arch.calling_conventions().iter().map(|c| c.name).collect();
        match arch.lifting() {
            n0xis_arch::Lifting::Lifts => assert!(!ccs.is_empty(), "{name} lifts and declares no calling convention"),
            n0xis_arch::Lifting::DecodeOnly { why } => {
                assert!(!why.trim().is_empty(), "{name} decodes only and does not say why");
                assert!(ccs.is_empty(), "{name} decodes only, so no lift reads the conventions it declares: {ccs:?}");
            }
        }
    }
}

/// "What is the function at this entry called" has one answer. It used to have
/// three, and none of the other two knew that a six-byte `jmp [rip+slot]` is
/// the import rather than an anonymous helper — so the same address was
/// `_CxxThrowException` to one command and `sub_180049BFC` to another.
///
/// Sites that ask a *different* question (a data symbol's name; the class a
/// mangled member-function name belongs to) are exempt by name, and each says
/// so where it stands.
#[test]
fn a_function_entrys_name_has_one_answer() {
    const ASKS_SOMETHING_ELSE: &[&str] = &[
        // the class of a mangled member-function name — an import has none
        "classlayout.rs",
        // data symbols whose address is taken (`&g_thing`), not function entries
        "decomp.rs",
    ];
    let mut bad = Vec::new();
    for (path, text) in sources() {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        if name == "ir.rs" || ASKS_SOMETHING_ELSE.contains(&name.as_str()) {
            continue;
        }
        for (n, line) in product_lines(&text) {
            if line.contains("symbol_at(") {
                bad.push(format!("{}:{n}: {}", path.display(), line.trim()));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "a function entry is named by `ir::symbol_on_entry`, which also resolves an import \
         stub to its import; these resolve it themselves:\n  {}",
        bad.join("\n  ")
    );
}

/// A stack local's name has one spelling rule, `typeinfer::stack_local_name`.
/// The declarations and the body computed it separately (`local_{:x}` of the
/// offset's magnitude, written twice), and that shared rule gave `rsp + 8` and
/// `rsp - 8` one name: 322 of 2 323 functions of one C library declared a local
/// twice. A second copy is how the next disagreement starts — between the name
/// a variable is declared under and the one its uses print.
///
/// Every product line that spells the prefix as a string literal has to be in
/// `typeinfer.rs`, and the renderer has to ask that function.
#[test]
fn a_stack_locals_name_is_spelled_in_one_place() {
    let mut bad = Vec::new();
    for (path, text) in workspace_sources() {
        if path.ends_with("typeinfer.rs") {
            continue;
        }
        for (n, line) in product_lines(&text) {
            if line.contains("\"local_") {
                bad.push(format!("{}:{n}: {}", path.display(), line.trim()));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "a stack local is named by `typeinfer::stack_local_name`; these spell the name themselves:\n  {}",
        bad.join("\n  ")
    );
    let render = std::fs::read_to_string(crate_src().join("render.rs")).expect("render.rs");
    assert!(
        product_lines(&render).iter().any(|(_, l)| l.contains("stack_local_name(")),
        "the renderer names stack locals without `typeinfer::stack_local_name`"
    );
}

/// An unnamed function's name has one spelling rule, `n0xis_core::unnamed_function_name`.
/// It was formatted in five places with two spellings, `sub_{:X}` in the
/// function list and `sub_{:x}` for a callee and in a decompiled signature, so
/// a function at an address with a letter in it had two names depending on
/// which command was asked (docs/design/WASM.md §5 decision 1). A WebAssembly
/// function's fallback, `func_<index>`, is the same rule's.
///
/// Every product line that spells either prefix in a string literal has to be
/// in `unnamed.rs` — not only as a format string: `format!("{}{:x}", "sub_",
/// va.0)` is the same copy, and a guard that looked for `sub_{` alone passed
/// it. And the identity the name is made from is the image's: a site that
/// builds `UnnamedFunction::Address` itself names a WebAssembly function by
/// its module offset, where `unnamed_at` names it by its index.
#[test]
fn an_unnamed_functions_name_is_spelled_in_one_place() {
    // Sites that state the address identity themselves, each because no
    // other identity exists there.
    const ADDRESS_ONLY: &[(&str, &str)] = &[
        // the `.pdata` list: a PE's exception directory, native by definition
        ("discover.rs", "discover_pdata"),
        // a callee no callsite holds, which the renderer has no context to ask about
        ("render.rs", "unwrap_or(crate::UnnamedFunction::Address(va))"),
    ];
    let mut bad = Vec::new();
    let mut exempt_seen = vec![false; ADDRESS_ONLY.len()];
    for (path, text) in workspace_sources() {
        if path.ends_with("unnamed.rs") {
            continue;
        }
        let file = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        let lines = product_lines(&text);
        for (i, (n, line)) in lines.iter().enumerate() {
            if line.contains("\"sub_") || line.contains("\"func_") {
                bad.push(format!("{}:{n}: {}", path.display(), line.trim()));
            }
            if line.contains("UnnamedFunction::Address(") {
                // The exemption names the line, or the function the line is
                // in (the nearest `fn` above it).
                let context = lines[..=i].iter().rev().find(|(_, l)| l.contains("fn ")).map_or("", |(_, l)| *l);
                match ADDRESS_ONLY.iter().position(|(f, at)| *f == file && (line.contains(at) || context.contains(at))) {
                    Some(k) => exempt_seen[k] = true,
                    None => bad.push(format!("{}:{n}: {}", path.display(), line.trim())),
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "an unnamed function is named by `n0xis_core::unnamed_function_name` of `unnamed_at`; these spell the name or the identity themselves:\n  {}",
        bad.join("\n  ")
    );
    let stale: Vec<_> = ADDRESS_ONLY.iter().zip(&exempt_seen).filter(|(_, seen)| !**seen).map(|(e, _)| e).collect();
    assert!(stale.is_empty(), "exemptions that describe no site any more: {stale:?}");
}
