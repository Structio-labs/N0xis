// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Whole-program noreturn propagation — the CFG-fidelity follow-on ROADMAP
//! Phase 10 (priority 0) left open.
//!
//! [`crate::noreturn`] names the *imports* that never return (`ExitProcess`,
//! `abort`, …). But a game binary rarely calls those directly: it wraps them in
//! its own `FatalError`/`Assert`/`Panic` helper — a stripped `sub_XXXX`, not a
//! named import — and calls *that* everywhere. Until the wrapper is itself known
//! to be noreturn, every caller keeps a dead fall-through in its CFG, and the
//! decompiler emits confidently-wrong C for the bytes after the call (the exact
//! `sound over complete` violation, CONCEPT §3 rule 6).
//!
//! This pass closes the loop with a **monotone fixpoint over the call graph**:
//!
//! 1. A function *returns* iff, in its own CFG, some reachable path reaches a
//!    returning exit (`ret`, or an exit we cannot prove non-returning — a
//!    tail-call, an unresolved indirect branch, an edge leaving the analyzed
//!    window). A function whose every reachable exit is a call to a noreturn
//!    function — or which loops forever with no exit at all — does **not**
//!    return.
//! 2. Seed with the imports (already resolved by name inside `CfgPass`), then
//!    re-derive every function's CFG with the growing noreturn set fed in via
//!    [`Ctx::with_noreturn`], so a `call` to a now-known-noreturn `sub_XXXX`
//!    ends its block like a `call ExitProcess`. Repeat until no function flips.
//!
//! The set only grows and every function flips at most once, so it converges in
//! at most *N* rounds. It is **sound over complete**: a function is flagged
//! noreturn only when *provably* so — every ambiguous exit is read as "may
//! return", so the pass never prunes a live path, only dead ones.

use std::collections::{HashMap, HashSet};

use n0xis_contracts::Va;
use serde::{Deserialize, Serialize};

use crate::{CfgArtifact, CfgInput, CfgPass, CoreError, Ctx, Pass};

/// Functions to analyze (their entry addresses) and the per-function decode
/// window. The caller supplies the entry set — typically `function discover`'s
/// output, or a hand-picked list.
pub struct NoReturnInput {
    /// Function entry addresses.
    pub functions: Vec<Va>,
    /// Byte window pulled per function (its maximum extent).
    pub max_bytes: usize,
}

/// The proven-noreturn function set, plus how the fixpoint got there.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NoReturnArtifact {
    /// Entry addresses proven never to return, ascending.
    pub noreturn: Vec<Va>,
    /// How many distinct functions were considered.
    pub considered: usize,
    /// Fixpoint rounds run (≥1; >1 means propagation across the call graph
    /// actually happened, not just direct import calls).
    pub rounds: usize,
}

/// The whole-program noreturn fixpoint as a [`Pass`].
#[derive(Clone, Copy, Debug, Default)]
pub struct NoReturnPropagatePass;

impl Pass for NoReturnPropagatePass {
    type In = NoReturnInput;
    type Out = NoReturnArtifact;

    fn name(&self) -> &'static str {
        "noreturn.propagate"
    }

    fn run(&self, ctx: &Ctx, input: NoReturnInput) -> Result<NoReturnArtifact, CoreError> {
        Ok(propagate_noreturn(ctx, &input.functions, input.max_bytes))
    }
}

/// Run the fixpoint directly. `ctx.noreturn` (if the caller already set one) is
/// used as the seed, so this composes: a prior result can be extended.
pub fn propagate_noreturn(ctx: &Ctx, functions: &[Va], max_bytes: usize) -> NoReturnArtifact {
    // De-duplicate entries while preserving determinism.
    let mut seen_fn = HashSet::new();
    let funcs: Vec<Va> = functions.iter().copied().filter(|f| seen_fn.insert(f.0)).collect();

    let mut noreturn: HashSet<Va> = ctx.noreturn.cloned().unwrap_or_default();
    let mut rounds = 0usize;

    // Jacobi iteration: each round rebuilds every not-yet-flagged function with
    // the set frozen at the round's start, collecting the ones that flip.
    // Monotone (the set only grows) and bounded (each function flips once), so
    // `funcs.len() + 1` rounds is a hard ceiling — the extra guard is defensive.
    loop {
        rounds += 1;
        let frozen = noreturn.clone();
        let sub = Ctx {
            source: ctx.source,
            arch: ctx.arch,
            symbols: ctx.symbols,
            modules: ctx.modules,
            noreturn: Some(&frozen),
            vtables: ctx.vtables,
            eh: ctx.eh,
            type_flow: ctx.type_flow,
        };

        let mut newly: Vec<Va> = Vec::new();
        for &f in &funcs {
            if noreturn.contains(&f) {
                continue;
            }
            // A function we cannot even build a CFG for is left as "may return"
            // — never flagged on missing evidence.
            if let Ok(cfg) = CfgPass.run(&sub, CfgInput::new(f, max_bytes))
                && !function_returns(&cfg, &frozen)
            {
                newly.push(f);
            }
        }

        if newly.is_empty() {
            break;
        }
        noreturn.extend(newly);

        if rounds > funcs.len() + 1 {
            break; // unreachable given monotonicity; a belt-and-braces stop
        }
    }

    let mut out: Vec<Va> = noreturn.into_iter().collect();
    out.sort_by_key(|v| v.0);
    NoReturnArtifact {
        noreturn: out,
        considered: funcs.len(),
        rounds,
    }
}

/// Does this function's CFG have a reachable **returning** exit?
///
/// Sound-over-complete: returns `true` on any doubt (a `ret`, an exit we cannot
/// prove non-returning, an edge leaving the analyzed window, an unrecognized
/// terminator, or a CFG we could not build). Only a function whose every
/// reachable exit is proven non-returning — a `call-noreturn`, or a `tail-call`
/// whose target is itself noreturn — or which has no reachable exit at all (an
/// infinite loop), returns `false`.
///
/// `noreturn` is the set proven so far, used to classify a *tail-call* exit
/// (`jmp <fn>` leaving the function): MSVC routinely compiles a throw/abort
/// wrapper as a tail-call to the noreturn helper, so a tail-call to a known
/// noreturn — by import name or by a proven address — is a non-returning exit,
/// not a return.
pub(crate) fn function_returns(cfg: &CfgArtifact, noreturn: &HashSet<Va>) -> bool {
    if cfg.blocks.is_empty() {
        return true; // no evidence → assume it returns
    }
    let by_start: HashMap<u64, usize> = cfg.blocks.iter().enumerate().map(|(i, b)| (b.start.0, i)).collect();
    let entry = by_start.get(&cfg.start.0).copied().unwrap_or(0);

    let mut seen = vec![false; cfg.blocks.len()];
    let mut stack = vec![entry];
    while let Some(i) = stack.pop() {
        if seen[i] {
            continue;
        }
        seen[i] = true;
        let b = &cfg.blocks[i];
        match b.terminator.as_str() {
            // A definite return, or an exit we cannot prove non-returning.
            "ret" | "ijmp" | "int" => return true,
            // A tail-call: non-returning iff its target is itself noreturn
            // (a known import by name, or a proven function by address);
            // otherwise it returns whatever the callee returns — assume it may.
            "tail-call" => {
                if !tail_call_is_noreturn(b, noreturn) {
                    return true;
                }
            }
            // Proven non-returning — this path dead-ends here, follow no edge.
            "call-noreturn" => {}
            // Internal edge: keep walking, but any successor we cannot place in
            // this function's own block set leaves the analyzed window, so we
            // cannot rule out a return down that path.
            "fall" | "jmp" | "cjmp" => {
                if b.successors.is_empty() {
                    return true;
                }
                for s in &b.successors {
                    match by_start.get(&s.to.0) {
                        Some(&j) => {
                            if !seen[j] {
                                stack.push(j);
                            }
                        }
                        None => return true,
                    }
                }
            }
            // Something we do not model — assume it may return.
            _ => return true,
        }
    }
    // Every reachable exit was proven non-returning, or there was no exit at all.
    false
}

/// Is a `tail-call` block's target a noreturn function? The terminating
/// instruction carries the resolved import name (`target_name`) and/or the
/// direct callee address (`target`) — a known-noreturn import by name, or an
/// address the fixpoint has already proven, makes the tail-call non-returning.
fn tail_call_is_noreturn(block: &crate::CfgBlock, noreturn: &HashSet<Va>) -> bool {
    let Some(last) = block.insns.last() else {
        return false;
    };
    let by_name = last
        .target_name
        .as_deref()
        .and_then(|n| n.rsplit('!').next())
        .map(crate::noreturn::is_known_noreturn)
        .unwrap_or(false);
    let by_addr = last.target.is_some_and(|t| noreturn.contains(&t));
    by_name || by_addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_contracts::{SymKind, Symbol};
    use n0xis_sources::Snapshot;

    /// `call rel32` bytes from `at` to `target`, followed by whatever trails.
    fn call_then(at: u64, target: u64, trailing: &[u8]) -> Vec<u8> {
        let rel = (target as i64 - (at as i64 + 5)) as i32;
        let mut v = vec![0xe8];
        v.extend_from_slice(&rel.to_le_bytes());
        v.extend_from_slice(trailing);
        v
    }

    fn exitprocess(va: u64) -> Symbol {
        Symbol {
            va: Va(va),
            module: "kernel32".into(),
            name: "ExitProcess".into(),
            kind: SymKind::Export,
        }
    }

    #[test]
    fn a_wrapper_of_exitprocess_is_noreturn_and_propagates_to_its_caller() {
        // fatal @ 0x2000:  call ExitProcess(0x9000); ret (dead)
        // caller @ 0x1000: call fatal(0x2000);       ret (dead once fatal is known)
        // normal @ 0x3000: ret                        (plainly returns)
        let snap = Snapshot::builder()
            .region(Va(0x1000), call_then(0x1000, 0x2000, &[0xc3]))
            .region(Va(0x2000), call_then(0x2000, 0x9000, &[0xc3]))
            .region(Va(0x3000), vec![0xc3])
            .symbol(exitprocess(0x9000))
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch).with_symbols(&snap);

        let art = propagate_noreturn(&ctx, &[Va(0x1000), Va(0x2000), Va(0x3000)], 64);

        assert!(art.noreturn.contains(&Va(0x2000)), "the direct ExitProcess wrapper must be noreturn");
        assert!(art.noreturn.contains(&Va(0x1000)), "its caller must be flagged by propagation");
        assert!(!art.noreturn.contains(&Va(0x3000)), "a plain `ret` function must not be flagged");
        assert_eq!(art.noreturn, vec![Va(0x1000), Va(0x2000)]);
        assert!(art.rounds >= 2, "flagging the caller needs a second round: {}", art.rounds);
        assert_eq!(art.considered, 3);
    }

    /// `jmp rel32` bytes from `at` to `target` (a tail call when `target`
    /// leaves the function).
    fn jmp_to(at: u64, target: u64) -> Vec<u8> {
        let rel = (target as i64 - (at as i64 + 5)) as i32;
        let mut v = vec![0xe9];
        v.extend_from_slice(&rel.to_le_bytes());
        v
    }

    #[test]
    fn a_tail_call_to_a_noreturn_import_is_noreturn_and_propagates() {
        // throw @ 0x2000:  jmp ExitProcess(0x9000)   — the MSVC throw/abort
        //                  wrapper shape: a tail call, not `call; ret`.
        // caller @ 0x1000: call throw(0x2000); ret    — flagged by propagation.
        let snap = Snapshot::builder()
            .region(Va(0x1000), call_then(0x1000, 0x2000, &[0xc3]))
            .region(Va(0x2000), jmp_to(0x2000, 0x9000))
            .symbol(exitprocess(0x9000))
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch).with_symbols(&snap);

        let art = propagate_noreturn(&ctx, &[Va(0x1000), Va(0x2000)], 64);
        assert!(art.noreturn.contains(&Va(0x2000)), "a tail-call to ExitProcess must be noreturn");
        assert!(art.noreturn.contains(&Va(0x1000)), "its caller must be flagged by propagation");
    }

    #[test]
    fn a_tail_call_to_a_returning_function_is_not_flagged() {
        // f @ 0x1000: jmp g(0x2000);  g @ 0x2000: ret  — g returns, so the
        // tail call returns, so f returns. Nothing is noreturn.
        let snap = Snapshot::builder()
            .region(Va(0x1000), jmp_to(0x1000, 0x2000))
            .region(Va(0x2000), vec![0xc3])
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch).with_symbols(&snap);

        let art = propagate_noreturn(&ctx, &[Va(0x1000), Va(0x2000)], 64);
        assert!(art.noreturn.is_empty(), "a tail-call to a returning function must not be flagged: {:?}", art.noreturn);
    }

    #[test]
    fn a_two_level_wrapper_chain_fully_propagates() {
        // a(0x1000) -> b(0x2000) -> c(0x3000) -> ExitProcess(0x9000)
        let snap = Snapshot::builder()
            .region(Va(0x1000), call_then(0x1000, 0x2000, &[0xc3]))
            .region(Va(0x2000), call_then(0x2000, 0x3000, &[0xc3]))
            .region(Va(0x3000), call_then(0x3000, 0x9000, &[0xc3]))
            .symbol(exitprocess(0x9000))
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch).with_symbols(&snap);

        let art = propagate_noreturn(&ctx, &[Va(0x1000), Va(0x2000), Va(0x3000)], 64);
        assert_eq!(art.noreturn, vec![Va(0x1000), Va(0x2000), Va(0x3000)], "the whole chain is noreturn");
    }

    #[test]
    fn a_function_that_returns_after_the_call_is_not_flagged() {
        // g @ 0x2000: a returning helper (just `ret`).
        // f @ 0x1000: call g; ret  — reachable ret, so f returns.
        let snap = Snapshot::builder()
            .region(Va(0x1000), call_then(0x1000, 0x2000, &[0xc3]))
            .region(Va(0x2000), vec![0xc3])
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch).with_symbols(&snap);

        let art = propagate_noreturn(&ctx, &[Va(0x1000), Va(0x2000)], 64);
        assert!(art.noreturn.is_empty(), "nothing here is noreturn: {:?}", art.noreturn);
        assert_eq!(art.rounds, 1, "a no-change run settles in one round");
    }

    #[test]
    fn the_flagged_set_prunes_a_caller_cfg_when_fed_back_in() {
        // Prove the composition the pass exists for: once `fatal` is known
        // noreturn, a caller's CFG built with the set closes the block and the
        // bytes after the call become unreachable.
        let snap = Snapshot::builder()
            .region(Va(0x1000), call_then(0x1000, 0x2000, &[0x48, 0xc7, 0xc0, 0x01, 0, 0, 0, 0xc3]))
            .region(Va(0x2000), call_then(0x2000, 0x9000, &[0xc3]))
            .symbol(exitprocess(0x9000))
            .build();
        let arch = X64::new();
        let base = Ctx::new(&snap, &arch).with_symbols(&snap);
        let art = propagate_noreturn(&base, &[Va(0x1000), Va(0x2000)], 64);

        let set: HashSet<Va> = art.noreturn.iter().copied().collect();
        let ctx = Ctx::new(&snap, &arch).with_symbols(&snap).with_noreturn(&set);
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 64)).expect("cfg builds");

        assert_eq!(cfg.blocks[0].terminator, "call-noreturn", "the call to the proven-noreturn wrapper ends the block");
        assert!(cfg.blocks[0].successors.is_empty(), "no dead fall-through after a noreturn call");
    }
}
