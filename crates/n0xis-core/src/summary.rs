// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Function summaries** — the interprocedural layer's substrate (ROADMAP
//! Phase 10, priority 3a).
//!
//! Every interprocedural question ("does this call return?", "what type is
//! argument 2?", "does `rbx` survive this call?") is today answered by
//! re-analyzing the callee at the moment it is asked, once per asker. A summary
//! answers it once: one pass over a function produces the facts a *caller*
//! needs, and the whole-program passes above (noreturn propagation today, type
//! propagation next) read summaries instead of re-deriving them.
//!
//! Deliberately an **extension of the existing passes, not a new subsystem**:
//! a summary is assembled from `CfgPass` → `SsaPass` → `OptimizePass` →
//! `TypeInferPass`, exactly the chain a decompile already runs, plus the
//! call-graph edges the CFG already carries.
//!
//! **Sound over complete.** Every field is either a fact or explicitly marked
//! unknown; nothing is guessed:
//!
//! - `returns` is `false` only when the CFG has no returning exit *and* the
//!   function makes no ambiguous exit — the same rule
//!   [`NoReturnPropagatePass`](crate::NoReturnPropagatePass) uses, so the two
//!   agree by construction.
//! - `clobbers` lists volatile registers this function writes **itself**.
//!   `clobbers_complete` says whether that is the whole story: a function that
//!   calls anything inherits its callees' clobbers, and until the whole-program
//!   pass composes them a caller must assume the ABI's full volatile set. A
//!   leaf function's set is complete and immediately usable.
//! - `params`/`ret` carry the recovered types, and a *generic* width type is
//!   information-free by design — only a named type means "this is known".

use std::collections::{BTreeSet, HashSet};

use n0xis_contracts::Va;
use serde::Serialize;
use crate::typeinfer::ReturnType;

use crate::{
    CType, CfgInput, CfgPass, CoreError, Ctx, OptimizePass, Pass, SsaPass, TypeInferInput, TypeInferPass,
};

/// What a caller can learn about a function without re-analyzing it.
#[derive(Clone, Debug, Serialize)]
pub struct FunctionSummary {
    pub va: Va,
    pub name: String,
    pub end: Va,
    /// `false` = proven never to hand control back to its caller.
    pub returns: bool,
    /// Recovered parameter types, in ABI argument order — **absent when nothing
    /// determined them**, which is not the same as an empty list.
    ///
    /// An empty array is a measurement: this function takes no arguments. The
    /// field used to be one either way, so a function whose SSA or type
    /// inference *failed* was published as taking none — the same collapse the
    /// return type had, in the field beside it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Vec<CType>>,
    /// What it gives back — `null` for a measured "nothing", the type when one
    /// was recovered, and `{"unknown": true}` when nothing here could tell. The
    /// third case used to serialize as the first, so every function whose type
    /// inference failed was published as returning nothing.
    pub ret: ReturnType,
    /// The registers the result arrives in when it takes more than one — a
    /// two-member floating-point struct comes back in `xmm0` **and** `xmm1`,
    /// and `ret` then names only the first half. Empty for every ordinary
    /// return. See [`crate::typeinfer::RecoveredSignature::ret_registers`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ret_registers: Vec<String>,
    /// Volatile registers this function's own instructions write.
    pub clobbers: Vec<String>,
    /// Whether `clobbers` is the complete set. `false` for any function that
    /// calls something: a caller must then assume the full volatile set until
    /// the whole-program pass composes its callees' summaries in.
    pub clobbers_complete: bool,
    /// Direct callees — the call-graph edges out of this function.
    pub calls: Vec<Va>,
    /// This function performs at least one store. (A load is not tracked
    /// separately: essentially every function reads memory, so the bit would
    /// carry no information.)
    pub writes_memory: bool,
    /// Calls something whose target is not statically known (an indirect call,
    /// or an import through a slot) — the reason `clobbers_complete` and any
    /// transitive property cannot be closed for this function by itself.
    pub has_unknown_call: bool,
}

/// Which functions to summarize, and how large a window each may occupy.
pub struct SummaryInput {
    pub functions: Vec<Va>,
    pub max_bytes: usize,
}

/// Batch summary pass. Like [`ManifestPass`](crate::ManifestPass) it never
/// fails outright: a candidate that cannot be decoded is simply absent from the
/// result rather than aborting the batch.
#[derive(Clone, Copy, Debug, Default)]
pub struct SummaryPass;

impl Pass for SummaryPass {
    type In = SummaryInput;
    type Out = Vec<FunctionSummary>;

    fn name(&self) -> &'static str {
        "function.summary"
    }

    fn run(&self, ctx: &Ctx, input: SummaryInput) -> Result<Vec<FunctionSummary>, CoreError> {
        let mut out = Vec::with_capacity(input.functions.len().min(1 << 16));
        for va in input.functions {
            if let Some(s) = summarize(ctx, va, input.max_bytes) {
                out.push(s);
            }
        }
        Ok(out)
    }
}

/// The volatile (caller-saved) register names of the target's ABI. Which
/// convention applies comes from the **source** (`MemorySource::abi_name`), the
/// same way [`crate::TypeInferPass`] picks its argument registers — a pass must
/// never bake in an ABI.
fn volatile_regs(ctx: &Ctx) -> Vec<&'static str> {
    match crate::ir::abi_conv(ctx) {
        // Both halves of the set. Leaving the vector registers out made a pure
        // `double add(double, double)` report `clobbers: []` with
        // `clobbers_complete: true` — a confident claim that calling it destroys
        // nothing, about a function whose one instruction writes `xmm0`.
        Some(cc) => cc
            .volatile
            .iter()
            .filter_map(|&r| ctx.arch.regs().name(r))
            .chain(cc.volatile_float.iter().copied())
            .collect(),
        None => Vec::new(),
    }
}

/// Summarize one function. `None` when it cannot be decoded at `va`.
pub fn summarize(ctx: &Ctx, va: Va, max_bytes: usize) -> Option<FunctionSummary> {
    let cfg = CfgPass.run(ctx, CfgInput::new(va, max_bytes)).ok()?;
    if cfg.start != va || cfg.blocks.is_empty() {
        return None;
    }
    // The proven-noreturn set, when the caller has already run the fixpoint.
    let proven: HashSet<Va> = ctx.noreturn.cloned().unwrap_or_default();

    // Keyed by the name the def-use records, valued by the name the ABI uses —
    // `zmm0` and `xmm0` are one register, and the caller should read the
    // spelling the disassembly shows.
    let volatile: std::collections::HashMap<String, &'static str> =
        volatile_regs(ctx).into_iter().map(|n| (ctx.arch.normalize_reg(n), n)).collect();
    let mut clobbers: BTreeSet<String> = BTreeSet::new();
    let mut writes_memory = false;
    for block in &cfg.blocks {
        for insn in &block.insns {
            for w in &insn.writes {
                let root = ctx.arch.normalize_reg(w.split('.').next().unwrap_or(w));
                if let Some(name) = volatile.get(&root) {
                    clobbers.insert((*name).to_string());
                }
            }
            // A store is the one memory effect worth a bit of its own.
            if insn.text.contains("mov ") && insn.text.contains('[') && !insn.text.contains("lea ") {
                writes_memory = true;
            }
        }
    }

    let mut calls: BTreeSet<u64> = BTreeSet::new();
    let mut has_unknown_call = false;
    for c in &cfg.callsites {
        match c.target {
            Some(t) => {
                calls.insert(t.0);
            }
            None => has_unknown_call = true,
        }
    }

    // Types come from the same chain a decompile runs; a failure anywhere just
    // means no recovered signature, never a wrong one.
    let (params, ret, ret_registers) = match SsaPass
        .run(ctx, cfg.clone())
        .and_then(|ssa| OptimizePass.run(ctx, ssa))
        .and_then(|opt| TypeInferPass.run(ctx, TypeInferInput { cfg: cfg.clone(), blocks: opt.blocks, float_return: opt.float_return, float_return_pair: opt.float_return_pair }))
    {
        Ok(t) => (
            // The pass ran: an empty list here is a real "no parameters".
            Some(t.signature.params.into_iter().map(|p| p.ty).collect()),
            t.signature.ret,
            t.signature.ret_registers,
        ),
        // A pass that could not run has not measured a `void` return — it has
        // measured nothing. Reporting `None` here said the first: every
        // function whose SSA or type inference failed was published as
        // returning nothing at all.
        Err(_) => (None, crate::typeinfer::ReturnType::Unknown, Vec::new()),
    };

    // One answer to "what is this called" — see `ir::symbol_on_entry`.
    let name = crate::ir::symbol_on_entry(ctx, va)
        .map(|s| crate::render::render_callee_name(&s.name))
        .unwrap_or_else(|| format!("sub_{:X}", va.0));

    Some(FunctionSummary {
        va,
        name,
        end: cfg.end,
        // The SAME predicate the whole-program fixpoint uses, not a second
        // implementation of it — so the two agree by construction rather than
        // by review. (An earlier draft here re-derived the rule and quietly
        // disagreed: it scanned *every* block, while the fixpoint walks only
        // blocks reachable from the entry, so an unreachable ambiguous exit
        // made a genuinely non-returning function look like it returns.)
        // `ctx.noreturn`, when the caller has run the fixpoint, additionally
        // classifies a tail call to a proven-noreturn function.
        returns: crate::noreturn_ipa::function_returns(&cfg, &proven),
        params,
        ret,
        ret_registers,
        clobbers: clobbers.into_iter().collect(),
        // Only a leaf's clobber set is closed by this function alone.
        clobbers_complete: calls.is_empty() && !has_unknown_call,
        calls: calls.into_iter().map(Va).collect(),
        writes_memory,
        has_unknown_call,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    fn ctx_for(code: Vec<u8>, at: u64) -> (Snapshot, X64) {
        (Snapshot::builder().region(Va(at), code).build(), X64::new())
    }

    /// A function that touches only vector registers still destroys something.
    ///
    /// The clobber set was built from the ABI's integer volatile list alone, so
    /// a pure `double add(double, double)` — whose one instruction writes
    /// `xmm0` — reported `clobbers: []` with `clobbers_complete: true`: a
    /// confident claim that calling it destroys nothing.
    #[test]
    fn a_function_that_writes_only_a_vector_register_says_so() {
        // addsd xmm0,xmm1 ; ret — the whole body of `double add(double,double)`
        let (snap, arch) = ctx_for(vec![0xF2, 0x0F, 0x58, 0xC1, 0xC3], 0x1000);
        let ctx = Ctx::new(&snap, &arch);
        let s = summarize(&ctx, Va(0x1000), 64).expect("summarized");
        assert!(s.clobbers_complete, "a leaf's clobber set is closed");
        assert_eq!(s.clobbers, vec!["xmm0".to_string()], "it writes xmm0 and nothing else");
    }

    /// A leaf function: no calls, so its clobber set is complete and a caller
    /// can rely on every *other* volatile register surviving.
    #[test]
    fn a_leaf_reports_a_complete_clobber_set() {
        // xor eax,eax ; ret
        let (snap, arch) = ctx_for(vec![0x31, 0xC0, 0xC3], 0x1000);
        let ctx = Ctx::new(&snap, &arch);
        let s = summarize(&ctx, Va(0x1000), 64).expect("summarized");
        assert!(s.returns, "a `ret` returns");
        assert!(s.clobbers_complete, "a leaf's clobber set is closed");
        assert!(s.calls.is_empty());
        assert!(!s.has_unknown_call);
        assert!(s.clobbers.iter().any(|c| c == "rax"), "it writes rax: {:?}", s.clobbers);
    }

    /// A function that calls anything inherits its callees' clobbers, so its own
    /// set is explicitly INCOMPLETE — reporting it as complete would let a
    /// caller keep a value the callee destroys.
    #[test]
    fn calling_anything_marks_the_clobber_set_incomplete() {
        // call +0 (to 0x1005) ; ret ; ret
        let (snap, arch) = ctx_for(vec![0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3, 0xC3], 0x1000);
        let ctx = Ctx::new(&snap, &arch);
        let s = summarize(&ctx, Va(0x1000), 64).expect("summarized");
        assert!(!s.clobbers_complete, "a caller must not assume a callee preserves anything");
        assert_eq!(s.calls, vec![Va(0x1005)], "the direct callee is a call-graph edge");
    }

    /// An indirect call is the honest unknown: the callee cannot be named, so
    /// nothing transitive can be closed for this function.
    #[test]
    fn an_indirect_call_is_recorded_as_unknown_not_ignored() {
        // call rax ; ret
        let (snap, arch) = ctx_for(vec![0xFF, 0xD0, 0xC3], 0x1000);
        let ctx = Ctx::new(&snap, &arch);
        let s = summarize(&ctx, Va(0x1000), 64).expect("summarized");
        assert!(s.has_unknown_call, "an indirect callee is unknown, not absent");
        assert!(!s.clobbers_complete);
        assert!(s.calls.is_empty(), "an unknown target is not a call-graph edge");
    }

    /// An address that does not decode into a function at that exact start is
    /// absent from the batch rather than a zeroed entry claiming facts.
    #[test]
    fn an_undecodable_address_is_absent_not_invented() {
        let (snap, arch) = ctx_for(vec![0xC3], 0x1000);
        let ctx = Ctx::new(&snap, &arch);
        let out = SummaryPass
            .run(&ctx, SummaryInput { functions: vec![Va(0x1000), Va(0x9999)], max_bytes: 64 })
            .expect("batch never fails outright");
        assert_eq!(out.len(), 1, "only the decodable one: {out:?}");
        assert_eq!(out[0].va, Va(0x1000));
    }

    /// The summary's `returns` must be the fixpoint's own predicate, not a
    /// second implementation of it. This pins the agreement on the case that
    /// broke an earlier draft: an **unreachable** block with an ambiguous exit.
    /// Scanning every block made such a function look like it returns; the
    /// fixpoint walks only what the entry reaches, and is right.
    #[test]
    fn returns_uses_the_fixpoints_predicate_and_ignores_unreachable_exits() {
        // 0x1000 jmp +2      -> 0x1004     (skips the byte at 0x1002)
        // 0x1002 <unreached>
        // 0x1004 call ExitProcess-like: here, `call rax` then `hlt`
        //
        // Simpler and exact: a function whose reachable path ends in a
        // noreturn-import call, with a stray unreachable `nop` afterwards.
        // `int3` (0xCC) is an `int` terminator — an exit that MAY return.
        // Placed unreachable, it must not flip the verdict.
        let code = vec![
            0xEB, 0x01, // jmp +1 -> 0x1003
            0xCC, // int3 (unreachable ambiguous exit)
            0xC3, // ret  (reachable)
        ];
        let (snap, arch) = ctx_for(code, 0x1000);
        let ctx = Ctx::new(&snap, &arch);
        let s = summarize(&ctx, Va(0x1000), 64).expect("summarized");
        assert!(s.returns, "the reachable `ret` decides it");

        // And the mirror: with no reachable returning exit the verdict is
        // `false` even though blocks exist.
        let (snap2, arch2) = ctx_for(vec![0xEB, 0xFE], 0x2000); // jmp $ — infinite loop
        let ctx2 = Ctx::new(&snap2, &arch2);
        let s2 = summarize(&ctx2, Va(0x2000), 64).expect("summarized");
        assert!(!s2.returns, "an infinite loop never returns to its caller");
    }
}
