//! Well-known imports that never return control to their caller — used by
//! [`crate::CfgPass`] to correctly end a basic block (instead of assuming
//! normal fall-through) at a call to one of these, closing the gap ROADMAP
//! Phase 10 names: bytes after a call to `ExitProcess`/`abort`/etc. are dead
//! code, but were previously included in the CFG as if reachable — a
//! sound-over-complete violation (CONCEPT §3 rule 6).
//!
//! Sibling to [`crate::signatures`]'s known-API table: same shape (a flat
//! static array, bare-name, case-insensitive lookup — the caller strips any
//! `module!` prefix first), narrower purpose (control flow, not argument
//! typing). Deliberately scoped to Win32/CRT/MSVC-C++ — N0xis's actual corpus
//! is Windows game binaries (mostly C/C++, not Rust); Rust panic/unwind
//! symbol names are mangling/version-fragile and are an explicit non-goal
//! here, not a silent gap.

/// Bare function names that provably never return to their caller.
static KNOWN_NORETURN: &[&str] = &[
    // --- Win32 process/thread termination ---
    "ExitProcess",
    "TerminateProcess",
    "FatalExit",
    "FatalAppExitA",
    "FatalAppExitW",
    "RtlExitUserProcess",
    "RtlExitUserThread",
    "ExitThread",
    // --- CRT ---
    "abort",
    "_exit",
    "_Exit",
    "quick_exit",
    "_cexit",
    "_amsg_exit",
    "_invalid_parameter_noinfo_noreturn",
    // --- MSVC C++ exceptions: control never falls through to the next
    // instruction — it either unwinds past the call site or terminates ---
    "_CxxThrowException",
    // --- x86/x64 fail-fast ---
    "__fastfail",
];

/// Is `bare_name` a well-known function that never returns to its caller?
/// Case-insensitive; the caller is expected to have already stripped a
/// `module!` prefix (same contract as [`crate::signatures::known_signature`]).
pub fn is_known_noreturn(bare_name: &str) -> bool {
    KNOWN_NORETURN.iter().any(|n| n.eq_ignore_ascii_case(bare_name))
}

/// Strip a `module!` prefix and test the bare name — the shape callsite names
/// come in (`kernel32.dll!ExitProcess`).
fn is_known_noreturn_qualified(qualified: &str) -> bool {
    is_known_noreturn(qualified.rsplit('!').next().unwrap_or(qualified))
}

// ---------------------------------------------------------------------------
// Whole-program propagation (ROADMAP Phase 10, priority 0 — the deeper half of
// the noreturn item: the table above only knows *imports*, so a function that
// wraps `ExitProcess` — `fatal_error()`, MSVC's `_invoke_watson`, a game's
// `Crash()` — still looked like an ordinary call, and every caller kept
// decoding the dead bytes after it.)
// ---------------------------------------------------------------------------

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use n0xis_arch::InsnKind;
use n0xis_contracts::Va;
use serde::Serialize;

use crate::ir::{CfgArtifact, CfgBlock, CfgInput, CfgPass, Callsite};
use crate::{Ctx, CoreError, Pass};

/// Which functions to analyze, and the per-function decode budget.
#[derive(Clone, Debug)]
pub struct NoreturnInput {
    /// Function entry points — typically every candidate from
    /// [`DiscoverPass`](crate::DiscoverPass) or the `.pdata` table. The
    /// analysis is only as complete as this list: a caller of a noreturn
    /// function that isn't listed simply doesn't get the improvement (it is
    /// never *wrongly* claimed to be noreturn).
    pub candidates: Vec<Va>,
    /// Byte window handed to [`CfgPass`] per function.
    pub max_bytes: usize,
    /// Where `candidates` came from (`pdata` / `prologue-scan` / …), echoed
    /// into the artifact. A fixpoint's completeness is bounded by its function
    /// list, so *how* that list was built is part of the result, not trivia:
    /// `.pdata` is an exact table, a prologue scan is a heuristic that misses
    /// functions — and a missed caller is a missed propagation.
    pub discovery: String,
}

/// One function proven not to return, and why (`n0xis.ir.noreturn.v1`).
#[derive(Clone, Debug, Serialize)]
pub struct NoreturnFn {
    pub va: Va,
    /// `all-paths-call-noreturn` · `all-paths-trap` · `no-exit`.
    pub reason: &'static str,
    /// Which fixpoint round proved it — a true call-chain depth, since each
    /// round is evaluated against the previous round's frozen result. `1` =
    /// provable from the import table alone; `2` = proved only because a
    /// *discovered* callee was proved in round 1; and so on.
    pub round: usize,
    /// The callee that ends every path, when the reason is a call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<Va>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_name: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NoreturnArtifact {
    /// How the analyzed function list was obtained — see
    /// [`NoreturnInput::discovery`].
    pub discovery: String,
    /// Functions whose CFG was successfully built and evaluated.
    pub analyzed: usize,
    /// Candidates whose bytes couldn't be read/decoded — reported, not hidden,
    /// because each is a hole in the propagation, not a proven "returns".
    pub unreadable: usize,
    /// Productive fixpoint iterations (the round that changed nothing isn't
    /// counted). `>1` means propagation actually chained through the call
    /// graph rather than just re-deriving the import table.
    pub rounds: usize,
    pub count: usize,
    pub functions: Vec<NoreturnFn>,
}

/// Whole-program `noreturn` fixpoint.
///
/// **Sound over complete** (CONCEPT §3 rule 6): a function is claimed noreturn
/// only when *every* path out of it is accounted for and none of them returns.
/// Any hole — an unresolved indirect branch, a successor outside the decoded
/// body, a truncated tail, a tail call to something unproven — makes the
/// verdict `Unknown`, never `noreturn`. The cost of a false positive here is
/// the worst outcome this project recognizes: real code deleted from the CFG
/// of every caller, producing confidently-wrong C.
///
/// The fixpoint is monotone and therefore terminating: each round can only add
/// to the noreturn set, and adding to it can only cut more paths.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoreturnPass;

impl Pass for NoreturnPass {
    type In = NoreturnInput;
    type Out = NoreturnArtifact;

    fn name(&self) -> &'static str {
        "ir.noreturn"
    }

    fn run(&self, ctx: &Ctx, input: NoreturnInput) -> Result<NoreturnArtifact, CoreError> {
        let mut cfgs: Vec<(Va, CfgArtifact)> = Vec::with_capacity(input.candidates.len());
        let mut unreadable = 0usize;
        for va in &input.candidates {
            match CfgPass.run(ctx, CfgInput::new(*va, input.max_bytes)) {
                Ok(art) => cfgs.push((*va, art)),
                Err(_) => unreadable += 1,
            }
        }

        let mut proven: BTreeSet<u64> = BTreeSet::new();
        let mut functions: Vec<NoreturnFn> = Vec::new();
        let mut rounds = 0usize;
        loop {
            let round = rounds + 1;
            // Evaluate the whole set against a *frozen* `proven`, then merge.
            // Without the freeze, a function proved earlier in the same pass
            // would already be cutting paths for the ones after it, so `round`
            // would depend on candidate order instead of measuring real chain
            // depth — and "round 1" would silently include interprocedural
            // results.
            let mut discovered: Vec<NoreturnFn> = Vec::new();
            for (va, cfg) in &cfgs {
                if proven.contains(&va.get()) {
                    continue;
                }
                if let Verdict::Noreturn { reason, via, via_name } = evaluate(cfg, &proven) {
                    discovered.push(NoreturnFn { va: *va, reason, round, via, via_name });
                }
            }
            if discovered.is_empty() {
                break;
            }
            proven.extend(discovered.iter().map(|f| f.va.get()));
            functions.extend(discovered);
            rounds = round;
        }

        Ok(NoreturnArtifact {
            discovery: input.discovery,
            analyzed: cfgs.len(),
            unreadable,
            rounds,
            count: functions.len(),
            functions,
        })
    }
}

/// The set of entry addresses proven noreturn, for feeding back into CFG
/// construction via [`Ctx::with_noreturn_fns`].
pub fn proven_set(art: &NoreturnArtifact) -> BTreeSet<u64> {
    art.functions.iter().map(|f| f.va.get()).collect()
}

enum Verdict {
    /// Some path reaches a `ret` (or a tail call to something that may return).
    Returns,
    /// A path leaves the analyzed body in a way we can't follow. Never
    /// promoted to `Noreturn` — that's the whole soundness rule.
    Unknown,
    Noreturn { reason: &'static str, via: Option<Va>, via_name: Option<String> },
}

/// Where a block stops early because it calls something that never comes back.
struct Cut {
    va: Option<Va>,
    name: Option<String>,
}

/// The first call in `block` that never returns — a discovered function in
/// `proven`, or a well-known import. Everything after it in the block is dead,
/// so the walk stops here and the block's successors are not followed.
fn cut_at(block: &CfgBlock, calls: &BTreeMap<u64, &Callsite>, proven: &BTreeSet<u64>) -> Option<Cut> {
    block.insns.iter().filter(|i| i.flow == InsnKind::Call).find_map(|insn| {
        let site = calls.get(&insn.va.get())?;
        let by_addr = site.target.is_some_and(|t| proven.contains(&t.get()));
        let by_name = site.target_name.as_deref().is_some_and(is_known_noreturn_qualified);
        (by_addr || by_name).then(|| Cut { va: site.target, name: site.target_name.clone() })
    })
}

/// Does this function have a path back to its caller, given what is currently
/// proven noreturn? Walks only the blocks actually reachable from the entry —
/// dead blocks after a noreturn call must not vote.
fn evaluate(cfg: &CfgArtifact, proven: &BTreeSet<u64>) -> Verdict {
    if cfg.blocks.is_empty() {
        return Verdict::Unknown;
    }
    let index_of: BTreeMap<u64, usize> =
        cfg.blocks.iter().enumerate().map(|(i, b)| (b.start.get(), i)).collect();
    let calls: BTreeMap<u64, &Callsite> = cfg.callsites.iter().map(|c| (c.from.get(), c)).collect();

    let entry = index_of.get(&cfg.start.get()).copied().unwrap_or(0);
    let mut seen = vec![false; cfg.blocks.len()];
    let mut queue = VecDeque::from([entry]);
    seen[entry] = true;

    let mut unknown = false;
    let mut trap = false;
    let mut cut: Option<Cut> = None;

    while let Some(i) = queue.pop_front() {
        let block = &cfg.blocks[i];
        if let Some(c) = cut_at(block, &calls, proven) {
            cut = cut.or(Some(c));
            continue;
        }
        match block.terminator.as_str() {
            "ret" => return Verdict::Returns,
            // A tail call *is* this function's return, so it returns whatever
            // the callee does — unless the callee itself never returns, which
            // `cut_at` doesn't see (a tail jump is not an `InsnKind::Call`).
            "tail-call" => match tail_cut(block, &calls, proven) {
                Some(c) => cut = cut.or(Some(c)),
                None => return Verdict::Returns,
            },
            "int" => trap = true,
            // An indirect branch with no recovered cases could go anywhere,
            // including to a `ret`.
            "ijmp" if block.successors.is_empty() => unknown = true,
            // A body that just runs off the end of the decoded window tells us
            // nothing about what follows.
            "fall" | "jmp" if block.successors.is_empty() => unknown = true,
            _ => {}
        }
        for s in &block.successors {
            match index_of.get(&s.to.get()) {
                Some(&j) if !seen[j] => {
                    seen[j] = true;
                    queue.push_back(j);
                }
                Some(_) => {}
                // An edge out of the analyzed body — the same hole as above.
                None => unknown = true,
            }
        }
    }

    if unknown {
        return Verdict::Unknown;
    }
    match cut {
        Some(c) => Verdict::Noreturn {
            reason: "all-paths-call-noreturn",
            via: c.va,
            via_name: c.name,
        },
        None if trap => Verdict::Noreturn { reason: "all-paths-trap", via: None, via_name: None },
        // No return, no trap, no unresolved edge: control never leaves — an
        // infinite loop (`for(;;){}`, a scheduler, a spin on a flag).
        None => Verdict::Noreturn { reason: "no-exit", via: None, via_name: None },
    }
}

/// The tail-jump equivalent of [`cut_at`]: a tail call to a function that never
/// returns doesn't return either.
fn tail_cut(block: &CfgBlock, calls: &BTreeMap<u64, &Callsite>, proven: &BTreeSet<u64>) -> Option<Cut> {
    let site = block.insns.last().and_then(|i| calls.get(&i.va.get()))?;
    let by_addr = site.target.is_some_and(|t| proven.contains(&t.get()));
    let by_name = site.target_name.as_deref().is_some_and(is_known_noreturn_qualified);
    (by_addr || by_name).then(|| Cut { va: site.target, name: site.target_name.clone() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_case_insensitively() {
        assert!(is_known_noreturn("ExitProcess"));
        assert!(is_known_noreturn("exitprocess"));
        assert!(is_known_noreturn("EXITPROCESS"));
        assert!(is_known_noreturn("abort"));
        assert!(is_known_noreturn("_CxxThrowException"));
    }

    #[test]
    fn unknown_name_returns_false() {
        assert!(!is_known_noreturn("sub_140001063"));
        assert!(!is_known_noreturn("CloseHandle"));
        assert!(!is_known_noreturn("SomeUnknownGameFunction"));
    }

    // --- whole-program propagation ---

    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    /// `call <target>` encoded at `at`.
    fn call(at: u64, target: u64) -> Vec<u8> {
        let rel = (target as i64 - (at as i64 + 5)) as i32;
        let mut v = vec![0xE8];
        v.extend_from_slice(&rel.to_le_bytes());
        v
    }

    /// A four-function program:
    ///   0x1000 `caller`  — `call wrapper; ret`   (returns, until wrapper is proven)
    ///   0x1500 `honest`  — `ret`                 (really does return)
    ///   0x1600 `opaque`  — `jmp rax`             (unresolvable: must stay unproven)
    ///   0x2000 `wrapper` — `call ExitProcess`    (proven from the import table)
    fn program() -> Snapshot {
        let mut caller = call(0x1000, 0x2000);
        caller.push(0xC3);
        Snapshot::builder()
            .region(Va(0x1000), caller)
            .region(Va(0x1500), vec![0xC3])
            .region(Va(0x1600), vec![0xFF, 0xE0])
            .region(Va(0x2000), call(0x2000, 0x3000))
            .symbol(n0xis_contracts::Symbol {
                va: Va(0x3000),
                module: "kernel32".into(),
                name: "ExitProcess".into(),
                kind: n0xis_contracts::SymKind::Export,
            })
            .build()
    }

    fn analyze(snap: &Snapshot) -> NoreturnArtifact {
        let arch = X64::new();
        let ctx = Ctx::new(snap, &arch).with_symbols(snap);
        NoreturnPass
            .run(
                &ctx,
                NoreturnInput {
                    candidates: vec![Va(0x1000), Va(0x1500), Va(0x1600), Va(0x2000)],
                    max_bytes: 64,
                    discovery: "test".into(),
                },
            )
            .expect("the pass never fails outright")
    }

    #[test]
    fn propagates_noreturn_from_an_import_wrapper_to_its_caller() {
        let snap = program();
        let art = analyze(&snap);

        assert_eq!(art.analyzed, 4);
        assert_eq!(art.unreadable, 0);
        assert_eq!(art.count, 2, "wrapper and its caller, nothing else: {:#?}", art.functions);
        // Two productive rounds is the whole point: round 1 is what the import
        // table alone could already prove, round 2 is the interprocedural step.
        assert_eq!(art.rounds, 2);

        let wrapper = art.functions.iter().find(|f| f.va == Va(0x2000)).expect("wrapper proven");
        assert_eq!(wrapper.round, 1);
        assert_eq!(wrapper.reason, "all-paths-call-noreturn");
        assert_eq!(wrapper.via_name.as_deref(), Some("kernel32!ExitProcess"));

        let caller = art.functions.iter().find(|f| f.va == Va(0x1000)).expect("caller proven");
        assert_eq!(caller.round, 2, "only provable once the wrapper was");
        assert_eq!(caller.via, Some(Va(0x2000)));
    }

    #[test]
    fn a_function_that_really_returns_is_never_claimed() {
        let art = analyze(&program());
        assert!(art.functions.iter().all(|f| f.va != Va(0x1500)));
    }

    /// The soundness gate. An unresolved indirect branch could go anywhere,
    /// including straight to a `ret`; claiming noreturn here would delete live
    /// code from every caller — the worst outcome the project recognizes.
    #[test]
    fn an_unresolvable_indirect_branch_is_never_claimed() {
        let art = analyze(&program());
        assert!(
            art.functions.iter().all(|f| f.va != Va(0x1600)),
            "an unfollowable edge must yield Unknown, not noreturn: {:#?}",
            art.functions
        );
    }

    /// An endless loop returns to no one — but only claim it when the CFG is
    /// fully closed, which `jmp $` is.
    #[test]
    fn an_infinite_loop_is_proven_with_its_own_reason() {
        // 0x1000: jmp 0x1000  (EB FE)
        let snap = Snapshot::builder().region(Va(0x1000), vec![0xEB, 0xFE]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = NoreturnPass
            .run(
                &ctx,
                NoreturnInput {
                    candidates: vec![Va(0x1000)],
                    max_bytes: 64,
                    discovery: "test".into(),
                },
            )
            .unwrap();
        assert_eq!(art.count, 1);
        assert_eq!(art.functions[0].reason, "no-exit");
    }

    /// The feedback loop: with the proven set in the context, a caller's *own*
    /// CFG closes at the call, instead of decoding the dead bytes after it.
    #[test]
    fn feeding_the_proven_set_back_closes_the_callers_cfg() {
        let snap = program();
        let art = analyze(&snap);
        let set = proven_set(&art);
        let arch = X64::new();

        let plain = Ctx::new(&snap, &arch).with_symbols(&snap);
        let before = CfgPass.run(&plain, CfgInput::new(Va(0x1000), 64)).unwrap();
        assert_eq!(before.blocks[0].terminator, "ret", "without the set: the dead `ret` is live");

        let informed = Ctx::new(&snap, &arch).with_symbols(&snap).with_noreturn_fns(&set);
        let after = CfgPass.run(&informed, CfgInput::new(Va(0x1000), 64)).unwrap();
        assert_eq!(after.blocks[0].terminator, "call-noreturn");
        assert_eq!(after.insn_count, 1, "the byte after the call is dead code");
        assert!(after.blocks[0].successors.is_empty());
    }
}
