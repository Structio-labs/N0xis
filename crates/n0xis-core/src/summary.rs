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

use n0xis_arch::MicroStmt;
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
    /// This function's own instructions store to an address outside its own stack
    /// frame. The frame is what the stack-pointer tracking places at an offset from
    /// the entry stack pointer, on either side of it, whatever register carries it:
    /// a `push`, a call's return address, a spill and a `-O0` local at `[rbp-4]` are
    /// in it, so the answer does not change with the optimisation level. A store
    /// whose address cannot be placed counts, and so does one through a frame
    /// address plus a variable index, which is not placed at an offset.
    ///
    /// What a callee writes is not counted: `calls` and `has_unknown_call` say that.
    ///
    /// It was a text match on `mov ` and `[` (audit 2026-11-06, row 7): `mov
    /// (%rdi),%eax` was a store and `addl $1,(%rdi)` was not, 13 of 17 wrong. (A
    /// load is not tracked separately: essentially every function reads memory, so
    /// the bit would carry no information.)
    pub writes_memory: bool,
    /// Calls something whose target is not statically known (an indirect call,
    /// or an import through a slot) — the reason `clobbers_complete` and any
    /// transitive property cannot be closed for this function by itself.
    pub has_unknown_call: bool,
    /// Where and why its graph stops before the function does
    /// ([`crate::CfgArtifact::cut`]): `end`, `calls` and `clobbers` are then
    /// those of what was read, and the clobbers are not complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cut: Option<crate::ir::Cut>,
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

/// Whether the function's own statements store to an address outside its own
/// stack frame: see [`FunctionSummary::writes_memory`].
///
/// The frame is what [`crate::ssa::Frame`] places at an offset from the
/// entry stack pointer, through whatever register carries it. The optimized form is
/// read rather than the raw one because it has forwarded what a slot held: at `-O0`
/// a pointer into the frame is kept in a slot of its own and loaded back before the
/// store through it, and only the forwarded address names the frame. An instruction
/// the lift kept verbatim says it writes but not where, so it counts.
fn stores_outside_its_frame(ctx: &Ctx, blocks: &[crate::ssa::SsaBlock]) -> bool {
    let frame = crate::ssa::Frame::of(blocks, ctx.arch);
    blocks.iter().flat_map(|b| &b.stmts).any(|s| match &s.stmt {
        MicroStmt::Store { addr, .. } => frame.offset_of(addr).is_none(),
        MicroStmt::Unlifted { mem, .. } => mem.may_write(),
        _ => false,
    })
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
        crate::ir::volatile_registers(ctx).into_iter().map(|n| (ctx.arch.normalize_reg(n), n)).collect();
    let mut clobbers: BTreeSet<String> = BTreeSet::new();
    for block in &cfg.blocks {
        for insn in &block.insns {
            for w in &insn.writes {
                let root = ctx.arch.normalize_reg(w.split('.').next().unwrap_or(w));
                if let Some(name) = volatile.get(&root) {
                    clobbers.insert((*name).to_string());
                }
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
    // A tail call through a register (`f(p)` at -O2 is `jmp *%rax`) or a computed goto:
    // what runs next is as unknown as an indirect call's callee, and counting calls only
    // said `has_unknown_call: false, clobbers_complete: true` on it (audit 2026-11-06, row 7).
    if cfg.leaves_by_an_unresolved_jump() {
        has_unknown_call = true;
    }

    // Types come from the same chain a decompile runs; a failure anywhere just
    // means no recovered signature, never a wrong one. The optimized form is kept:
    // `writes_memory` reads its stores.
    let optimized = SsaPass.run(ctx, cfg.clone()).and_then(|ssa| OptimizePass.run(ctx, ssa));
    // Nothing lifted is nothing placed: every store it may hold counts.
    let writes_memory = match &optimized {
        Ok(opt) => stores_outside_its_frame(ctx, &opt.blocks),
        Err(_) => true,
    };
    let (params, ret, ret_registers) = match optimized
        .and_then(|opt| TypeInferPass.run(ctx, TypeInferInput { cfg: cfg.clone(), blocks: opt.blocks, float_return: opt.float_return, float_return_pair: opt.float_return_pair, raw_flow: opt.raw_flow.clone() }))
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
    let name = crate::function_name(ctx, va);

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
        // Only a leaf's clobber set is closed by this function alone, and only
        // where all of it was read.
        clobbers_complete: calls.is_empty() && !has_unknown_call && !cfg.end_by.is_cut(),
        calls: calls.into_iter().map(Va).collect(),
        writes_memory,
        has_unknown_call,
        cut: cfg.cut(),
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

    /// `jmp rax` with nothing to say where: a tail call to an unknown function, as far as
    /// a caller can tell, so the clobber set is not closed. Both said otherwise.
    #[test]
    fn an_unresolved_indirect_jump_is_an_unknown_call() {
        let (snap, arch) = ctx_for(vec![0xFF, 0xE0], 0x1000);
        let ctx = Ctx::new(&snap, &arch);
        let s = summarize(&ctx, Va(0x1000), 64).expect("summarized");
        assert!(s.has_unknown_call, "{s:?}");
        assert!(!s.clobbers_complete, "{s:?}");
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

    /// The clobbers of a function read only in part are not complete, and the summary
    /// says where it was cut.
    #[test]
    fn a_cut_function_has_no_complete_clobbers() {
        let (snap, arch) = ctx_for(std::iter::repeat_n([0xb8u8, 1, 0, 0, 0], 40).flatten().collect(), 0x1000);
        let ctx = Ctx::new(&snap, &arch);
        let s = summarize(&ctx, Va(0x1000), 64).expect("summarized");
        assert!(s.cut.is_some());
        assert!(!s.clobbers_complete, "a leaf read in part");
    }

    /// `writes_memory` of a body, decoded as x64 or as i386.
    fn writes(code: &[u8], i386: bool) -> bool {
        let snap = Snapshot::builder().region(Va(0x1000), code.to_vec()).build();
        let arch = if i386 { X64::x86() } else { X64::new() };
        let ctx = Ctx::new(&snap, &arch);
        summarize(&ctx, Va(0x1000), 256).expect("summarized").writes_memory
    }

    /// A store through a parameter, a read-modify-write through one, and one through
    /// an address loaded from memory leave the frame; a load does not store.
    ///
    /// It was a text match on `mov ` and `[` (audit 2026-11-06, row 7): the load was
    /// a store and the `add` was not.
    #[test]
    fn a_store_outside_the_frame_is_a_write_and_a_load_is_not() {
        // mov [rdi], esi ; ret
        assert!(writes(&[0x89, 0x37, 0xC3], false), "through a parameter");
        // add dword [rdi], 1 ; ret
        assert!(writes(&[0x83, 0x07, 0x01, 0xC3], false), "read-modify-write through a parameter");
        // mov rax, [rip+0x100] ; mov [rax], edi ; ret
        assert!(writes(&[0x48, 0x8B, 0x05, 0x00, 0x01, 0x00, 0x00, 0x89, 0x38, 0xC3], false), "through a loaded address");
        // xchg [rdi], eax ; ret: kept verbatim by the lift, which says it writes and not where
        assert!(writes(&[0x87, 0x07, 0xC3], false), "an instruction not lifted that writes");
        // mov eax, [rdi] ; ret
        assert!(!writes(&[0x8B, 0x07, 0xC3], false), "a load");
    }

    /// A `push`, a spill of a vector register and the `-O0` shape of a pointer into
    /// the frame kept in a slot of its own and stored through: all in the frame.
    #[test]
    fn a_store_into_its_own_frame_is_not_a_write() {
        // push rbx ; sub rsp,0x10 ; movsd [rsp+8],xmm0 ; mov ebx,edi ; add rsp,0x10 ; pop rbx ; ret
        let spill = [0x53, 0x48, 0x83, 0xEC, 0x10, 0xF2, 0x0F, 0x11, 0x44, 0x24, 0x08, 0x89, 0xFB, 0x48, 0x83, 0xC4, 0x10, 0x5B, 0xC3];
        assert!(!writes(&spill, false), "a push and a spill");
        // push rbp ; mov rbp,rsp ; mov [rbp-0x34],edi ; lea rax,[rbp-0x20] ; add rax,4
        // mov [rbp-0x28],rax ; mov rax,[rbp-0x28] ; mov edx,[rbp-0x34] ; mov [rax],edx ; pop rbp ; ret
        let o0 = [
            0x55, 0x48, 0x89, 0xE5, 0x89, 0x7D, 0xCC, 0x48, 0x8D, 0x45, 0xE0, 0x48, 0x83, 0xC0, 0x04, 0x48, 0x89, 0x45, 0xD8, 0x48, 0x8B, 0x45,
            0xD8, 0x8B, 0x55, 0xCC, 0x89, 0x10, 0x5D, 0xC3,
        ];
        assert!(!writes(&o0, false), "a frame pointer kept in a slot and stored through");
    }

    /// A frame address plus a variable index is not placed at an offset, so it
    /// counts: what it reaches is not known to be in the frame.
    #[test]
    fn a_frame_address_with_a_variable_index_counts_as_a_write() {
        // sub rsp,0x28 ; mov [rsp+rsi*4],edi ; add rsp,0x28 ; ret
        assert!(writes(&[0x48, 0x83, 0xEC, 0x28, 0x89, 0x3C, 0xB4, 0x48, 0x83, 0xC4, 0x28, 0xC3], false));
    }

    /// On i386 every step of `esp` is cut to 32 bits and a displacement arrives as an
    /// unsigned word (`ebp + 0xfffffff4`): nothing was placed there at all, so every
    /// local was a write.
    #[test]
    fn an_i386_local_is_in_the_frame_and_a_store_through_an_argument_is_not() {
        // sub esp,0x10 ; mov eax,[esp+0x14] ; mov [esp+0xc],eax ; mov eax,[esp+0xc] ; add esp,0x10 ; ret
        let local = [0x83, 0xEC, 0x10, 0x8B, 0x44, 0x24, 0x14, 0x89, 0x44, 0x24, 0x0C, 0x8B, 0x44, 0x24, 0x0C, 0x83, 0xC4, 0x10, 0xC3];
        assert!(!writes(&local, true), "a local through esp");
        // push ebp ; mov ebp,esp ; sub esp,0x10 ; mov dword [ebp-0xc],0 ; lea eax,[ebp-0x10]
        // mov dword [eax],7 ; leave ; ret
        let o0 = [
            0x55, 0x89, 0xE5, 0x83, 0xEC, 0x10, 0xC7, 0x45, 0xF4, 0x00, 0x00, 0x00, 0x00, 0x8D, 0x45, 0xF0, 0xC7, 0x00, 0x07, 0x00, 0x00, 0x00,
            0xC9, 0xC3,
        ];
        assert!(!writes(&o0, true), "locals through ebp, one of them by its address");
        // mov eax,[esp+4] ; mov dword [eax],1 ; ret
        assert!(writes(&[0x8B, 0x44, 0x24, 0x04, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0xC3], true), "through the first argument");
    }
}
