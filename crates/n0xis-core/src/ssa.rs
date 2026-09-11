// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`SsaPass`] — dominance-frontier phi insertion + renaming over
//! [`LiftedFunction`](crate::LiftedFunction), producing `n0xis.ir.ssa.v1`.
//!
//! This is the pass that makes ROADMAP Phase 3's correctness claim
//! ("conditions correct under intervening flag writes") a structural fact
//! rather than a heuristic: `"flags"` is renamed exactly like any other
//! variable, so a `Jcc` reads whichever SSA value of `"flags"` the dominator
//! tree actually delivers to it. If that value is a real
//! [`MicroExpr::Compare`], [`Arch::branch_condition`] renders the exact
//! condition; if a flag-setting instruction (or a merge of two different
//! compares from different predecessors, via a phi) intervened, the SSA
//! value is provably *not* that Compare, and the renderer gets an honest
//! placeholder instead of a stale guess.

use std::collections::{BTreeSet, HashMap};

use n0xis_arch::{Arch, CallTarget, CmpKind, MicroExpr, MicroStmt, FLAGS_VAR};
use n0xis_contracts::Va;
use serde::Serialize;

use crate::dom::{block_graph, dom_children, dominance_frontier, dominators_fwd, immediate_doms};
use crate::ir::{Callsite, CfgArtifact, Successor};
use crate::lift::{LiftedFunction, LiftPass};
use crate::{Ctx, CoreError, Pass};

/// One incoming edge of a [`Phi`]: the SSA value of the phi's variable that
/// reaches the phi's block along the edge from `from_block`.
#[derive(Clone, Debug, Serialize)]
pub struct PhiInput {
    pub from_block: usize,
    pub value: String,
}

/// A phi node: `var` is the pre-SSA name (e.g. `"rax"`, `"flags"`); `dst` is
/// its fresh versioned name at this join point.
#[derive(Clone, Debug, Serialize)]
pub struct Phi {
    pub var: String,
    pub dst: String,
    pub inputs: Vec<PhiInput>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SsaStmt {
    pub va: Va,
    pub stmt: MicroStmt,
}

#[derive(Clone, Debug, Serialize)]
pub struct SsaBlock {
    pub id: usize,
    pub start: Va,
    pub end: Va,
    pub terminator: String,
    pub successors: Vec<Successor>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub phis: Vec<Phi>,
    pub stmts: Vec<SsaStmt>,
    /// The exact branch condition for a `cjmp` terminator, synthesized from
    /// the SSA value of `"flags"` reaching the end of this block. `None` for
    /// any other terminator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<MicroExpr>,
}

/// The SSA artifact (`n0xis.ir.ssa.v1`).
#[derive(Clone, Debug, Serialize)]
pub struct SsaArtifact {
    pub start: Va,
    pub end: Va,
    pub blocks: Vec<SsaBlock>,
    /// The function's call sites, carried from the [`CfgArtifact`] so downstream
    /// passes can resolve a call's *name* (an allocator, for the Rung 2c heap
    /// alias slice) without re-deriving it. In-memory metadata only — skipped in
    /// the `n0xis.ir.ssa.v1` serialization, which never carried it.
    #[serde(skip)]
    pub callsites: Vec<Callsite>,
    /// At least one `ret` in this function returns the ABI's **floating-point**
    /// return register rather than the integer one (see
    /// [`retarget_float_returns`]). Downstream that is the only surviving trace
    /// of *which register file the result came from* — expression propagation
    /// folds the register name away — and it is what tells type recovery the
    /// result is a `float`/`double` and not an integer of the same width.
    ///
    /// In-memory metadata, skipped in the `n0xis.ir.ssa.v1` serialization, which
    /// never carried it.
    #[serde(skip)]
    pub float_return: bool,
    /// The result came back in **two** vector registers — a struct of two
    /// floating-point members, which this IR has no single name for. The value
    /// returned is the first half; saying so is the difference between a
    /// partial answer and a wrong one.
    #[serde(skip)]
    pub float_return_pair: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SsaPass;

impl Pass for SsaPass {
    type In = CfgArtifact;
    type Out = SsaArtifact;

    fn name(&self) -> &'static str {
        "ir.ssa"
    }

    fn run(&self, ctx: &Ctx, cfg: CfgArtifact) -> Result<SsaArtifact, CoreError> {
        let lifted = LiftPass.run(ctx, cfg.clone())?;
        let (fr, fr2) = crate::ir::float_return_registers(ctx);
        Ok(build_ssa(ctx.arch, &cfg, &lifted, fr, fr2))
    }
}

fn stmt_dst(stmt: &MicroStmt) -> Option<&str> {
    match stmt {
        MicroStmt::Assign { dst, .. } => Some(dst.as_str()),
        MicroStmt::Call { ret: Some(r), .. } => Some(r.as_str()),
        _ => None,
    }
}

fn collect_expr_vars(e: &MicroExpr, out: &mut BTreeSet<String>) {
    match e {
        MicroExpr::Var(name) => {
            out.insert(name.clone());
        }
        MicroExpr::Load { addr, .. } => collect_expr_vars(addr, out),
        MicroExpr::Unary(_, v) => collect_expr_vars(v, out),
        MicroExpr::Binary(_, l, r) => {
            collect_expr_vars(l, out);
            collect_expr_vars(r, out);
        }
        MicroExpr::Cast { expr, .. } => collect_expr_vars(expr, out),
        MicroExpr::AddrOf(e2) => collect_expr_vars(e2, out),
        MicroExpr::Compare { lhs, rhs, .. } => {
            collect_expr_vars(lhs, out);
            collect_expr_vars(rhs, out);
        }
        MicroExpr::Select { cond, a, b } => {
            collect_expr_vars(cond, out);
            collect_expr_vars(a, out);
            collect_expr_vars(b, out);
        }
        // Never produced by `lift`/SSA renaming (only by the optimizer's
        // expression-propagation), but matched exhaustively for correctness.
        MicroExpr::Call { target, args } => {
            if let CallTarget::Indirect(e) = target {
                collect_expr_vars(e, out);
            }
            for a in args {
                collect_expr_vars(a, out);
            }
        }
        MicroExpr::Const { .. } | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => {}
    }
}

fn collect_stmt_vars(stmt: &MicroStmt, out: &mut BTreeSet<String>) {
    match stmt {
        MicroStmt::Assign { dst, value } => {
            out.insert(dst.clone());
            collect_expr_vars(value, out);
        }
        MicroStmt::Store { addr, value, .. } => {
            collect_expr_vars(addr, out);
            collect_expr_vars(value, out);
        }
        MicroStmt::Call { target, args, ret } => {
            if let CallTarget::Indirect(e) = target {
                collect_expr_vars(e, out);
            }
            for a in args {
                collect_expr_vars(a, out);
            }
            if let Some(r) = ret {
                out.insert(r.clone());
            }
        }
        MicroStmt::Return(Some(e)) => collect_expr_vars(e, out),
        MicroStmt::Return(None) | MicroStmt::Nop | MicroStmt::Unlifted { .. } => {}
    }
}

fn rename_expr(e: &MicroExpr, stacks: &HashMap<String, Vec<String>>) -> MicroExpr {
    match e {
        MicroExpr::Const { .. } | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => e.clone(),
        MicroExpr::Var(name) => {
            let top = stacks.get(name).and_then(|s| s.last()).cloned().unwrap_or_else(|| name.clone());
            MicroExpr::Var(top)
        }
        MicroExpr::Load { addr, bits, signed } => {
            MicroExpr::Load { addr: Box::new(rename_expr(addr, stacks)), bits: *bits, signed: *signed }
        }
        MicroExpr::Unary(op, v) => MicroExpr::Unary(*op, Box::new(rename_expr(v, stacks))),
        MicroExpr::Binary(op, l, r) => {
            MicroExpr::Binary(*op, Box::new(rename_expr(l, stacks)), Box::new(rename_expr(r, stacks)))
        }
        MicroExpr::Cast { signed, bits, expr } => {
            MicroExpr::Cast { signed: *signed, bits: *bits, expr: Box::new(rename_expr(expr, stacks)) }
        }
        MicroExpr::AddrOf(e2) => MicroExpr::AddrOf(Box::new(rename_expr(e2, stacks))),
        MicroExpr::Compare { kind, lhs, rhs } => {
            MicroExpr::Compare { kind: *kind, lhs: Box::new(rename_expr(lhs, stacks)), rhs: Box::new(rename_expr(rhs, stacks)) }
        }
        MicroExpr::Select { cond, a, b } => MicroExpr::Select {
            cond: Box::new(rename_expr(cond, stacks)),
            a: Box::new(rename_expr(a, stacks)),
            b: Box::new(rename_expr(b, stacks)),
        },
        MicroExpr::Call { target, args } => MicroExpr::Call {
            target: rename_call_target(target, stacks),
            args: args.iter().map(|a| rename_expr(a, stacks)).collect(),
        },
    }
}

/// Resolve a `setcc` carrier the lifter emitted (`OpaqueFlags{"setcc:<jcc>"}`)
/// into the reconstructed boolean of that condition, using the `flags` value
/// reaching this point — the mid-block twin of how a `cjmp` terminator is
/// resolved from `end_flags_name`. The soundness guarantee is identical: the
/// reaching `Compare` captured its operands at flag-set time, so the recovered
/// condition tests the right values even if a source register was reassigned
/// between the compare and the `setcc`. When the reaching flags are not a
/// precise `Compare` (an intervening opaque flag-setter), `branch_condition`
/// yields a `/*cond*/` placeholder — sound-but-vague, never a wrong guess.
/// Anything that is not a `setcc:` marker passes through untouched.
fn resolve_flag_marker(
    value: MicroExpr,
    arch: &dyn Arch,
    stacks: &HashMap<String, Vec<String>>,
    defs: &HashMap<String, MicroExpr>,
) -> MicroExpr {
    // The walk is over the **whole** expression, not just its root. `setg al`
    // writes one byte of `rax`, so the marker sits inside the read-modify-write
    // that preserves the other seven — `(rax & ~0xff) | (uint8_t)<marker>`.
    // Matching only at the root left the marker unresolved there, and an
    // unresolved marker is a variable nothing defines. Recursion costs nothing
    // and removes the structural assumption that bit it.
    let go = |e: MicroExpr| resolve_flag_marker(e, arch, stacks, defs);
    let boxed = |e: Box<MicroExpr>| Box::new(resolve_flag_marker(*e, arch, stacks, defs));
    match value {
        MicroExpr::OpaqueFlags { mnemonic } if mnemonic.starts_with("setcc:") => {
            let jcc = mnemonic.strip_prefix("setcc:").expect("just checked the prefix");
            let unknown = MicroExpr::Unknown("no-flags-reached".to_string());
            let flags = stacks.get(FLAGS_VAR).and_then(|s| s.last()).and_then(|n| defs.get(n)).unwrap_or(&unknown);
            arch.branch_condition(jcc, flags)
        }
        // A `cmovcc` select carries the marker in its condition; the operands
        // are already renamed, and walking them again is a no-op.
        MicroExpr::Select { cond, a, b } => {
            MicroExpr::Select { cond: boxed(cond), a: boxed(a), b: boxed(b) }
        }
        MicroExpr::Unary(op, e) => MicroExpr::Unary(op, boxed(e)),
        MicroExpr::Binary(op, l, r) => MicroExpr::Binary(op, boxed(l), boxed(r)),
        MicroExpr::Cast { signed, bits, expr } => {
            MicroExpr::Cast { signed, bits, expr: boxed(expr) }
        }
        MicroExpr::Load { addr, bits, signed } => {
            MicroExpr::Load { addr: boxed(addr), bits, signed }
        }
        MicroExpr::AddrOf(e) => MicroExpr::AddrOf(boxed(e)),
        MicroExpr::Compare { kind, lhs, rhs } => {
            MicroExpr::Compare { kind, lhs: boxed(lhs), rhs: boxed(rhs) }
        }
        MicroExpr::Call { target, args } => {
            MicroExpr::Call { target, args: args.into_iter().map(go).collect() }
        }
        other => other,
    }
}

fn rename_call_target(target: &CallTarget, stacks: &HashMap<String, Vec<String>>) -> CallTarget {
    match target {
        CallTarget::Direct { va } => CallTarget::Direct { va: *va },
        CallTarget::Indirect(e) => CallTarget::Indirect(Box::new(rename_expr(e, stacks))),
        CallTarget::Intrinsic(name) => CallTarget::Intrinsic(name.clone()),
    }
}

fn fresh(var: &str, counters: &mut HashMap<String, u32>) -> String {
    let c = counters.entry(var.to_string()).or_insert(0);
    *c += 1;
    format!("{var}.{c}")
}

/// Rename one statement: uses first (against the stacks as they stand), then
/// any def gets a fresh version pushed. Returns the rewritten statement;
/// pushed variable names are appended to `pushed` so the caller can restore
/// the stacks on the way back out of this block.
fn rename_stmt(
    stmt: &MicroStmt,
    arch: &dyn Arch,
    stacks: &mut HashMap<String, Vec<String>>,
    counters: &mut HashMap<String, u32>,
    defs: &mut HashMap<String, MicroExpr>,
    pushed: &mut Vec<String>,
) -> MicroStmt {
    match stmt {
        MicroStmt::Assign { dst, value } => {
            let renamed_value = resolve_flag_marker(rename_expr(value, stacks), arch, stacks, defs);
            let name = fresh(dst, counters);
            stacks.entry(dst.clone()).or_default().push(name.clone());
            defs.insert(name.clone(), renamed_value.clone());
            pushed.push(dst.clone());
            MicroStmt::Assign { dst: name, value: renamed_value }
        }
        MicroStmt::Store { addr, value, bits } => MicroStmt::Store {
            addr: rename_expr(addr, stacks),
            value: resolve_flag_marker(rename_expr(value, stacks), arch, stacks, defs),
            bits: *bits,
        },
        MicroStmt::Call { target, args, ret } => {
            let renamed_target = rename_call_target(target, stacks);
            let renamed_args = args.iter().map(|a| rename_expr(a, stacks)).collect();
            let renamed_ret = ret.as_ref().map(|r| {
                let name = fresh(r, counters);
                stacks.entry(r.clone()).or_default().push(name.clone());
                defs.insert(name.clone(), MicroExpr::Unknown("call-result".to_string()));
                pushed.push(r.clone());
                name
            });
            MicroStmt::Call { target: renamed_target, args: renamed_args, ret: renamed_ret }
        }
        MicroStmt::Return(e) => MicroStmt::Return(e.as_ref().map(|x| rename_expr(x, stacks))),
        MicroStmt::Nop => MicroStmt::Nop,
        MicroStmt::Unlifted { va, text } => MicroStmt::Unlifted { va: *va, text: text.clone() },
    }
}

/// Dominator-tree preorder renaming walk (Cytron et al.). `b` is a block
/// *index* (identical to its `CfgBlock::id` — both are assigned in the same
/// address-sorted enumeration by `CfgPass`).
#[allow(clippy::too_many_arguments)]
fn rename_block(
    b: usize,
    arch: &dyn Arch,
    cfg: &CfgArtifact,
    lifted: &LiftedFunction,
    succ: &[Vec<usize>],
    children: &[Vec<usize>],
    phis: &mut [Vec<Phi>],
    stacks: &mut HashMap<String, Vec<String>>,
    counters: &mut HashMap<String, u32>,
    defs: &mut HashMap<String, MicroExpr>,
    out_stmts: &mut [Vec<SsaStmt>],
    end_flags_name: &mut [Option<String>],
    visited: &mut [bool],
    float_ret: Option<&str>,
    float_ret2: Option<&str>,
    ret_sites: &mut Vec<RetSite>,
) {
    visited[b] = true;
    let mut pushed: Vec<String> = Vec::new();

    // 1. Phi defs at the top of the block.
    for phi in phis[b].iter_mut() {
        let name = fresh(&phi.var, counters);
        stacks.entry(phi.var.clone()).or_default().push(name.clone());
        defs.insert(name.clone(), MicroExpr::Unknown(format!("phi({})", phi.var)));
        phi.dst = name;
        pushed.push(phi.var.clone());
    }

    // 2. Straight-line statements.
    for lstmt in &lifted.blocks[b].stmts {
        let renamed = rename_stmt(&lstmt.stmt, arch, stacks, counters, defs, &mut pushed);
        // The reaching value of the ABI's *float* return register at this `ret`.
        // Reading it here is the whole reason this is recorded during renaming
        // rather than after it: `stacks` **is** the reaching-definition map, and
        // the lift's `return rax;` never mentions the other candidate, so there
        // is nothing to read it off afterwards.
        if matches!(renamed, MicroStmt::Return(Some(_)))
            && let Some(fr) = float_ret
            && let Some(reaching) = stacks.get(fr).and_then(|st| st.last())
        {
            let float2 = float_ret2.and_then(|r| stacks.get(r)).and_then(|st| st.last()).cloned();
            ret_sites.push(RetSite { block: b, stmt: out_stmts[b].len(), float: reaching.clone(), float2 });
        }
        out_stmts[b].push(SsaStmt { va: lstmt.va, stmt: renamed });
    }
    end_flags_name[b] = stacks.get(FLAGS_VAR).and_then(|s| s.last()).cloned();

    // 3. Feed this block's current values into each successor's phis.
    for &s in &succ[b] {
        for phi in phis[s].iter_mut() {
            if let Some(top) = stacks.get(&phi.var).and_then(|st| st.last()) {
                phi.inputs.push(PhiInput { from_block: cfg.blocks[b].id, value: top.clone() });
            }
        }
    }

    // 4. Recurse into the dominator-tree children.
    for &c in &children[b] {
        rename_block(
            c, arch, cfg, lifted, succ, children, phis, stacks, counters, defs, out_stmts, end_flags_name, visited,
            float_ret, float_ret2, ret_sites,
        );
    }

    // 5. Restore the stacks for siblings.
    for var in pushed.iter().rev() {
        if let Some(stack) = stacks.get_mut(var) {
            stack.pop();
        }
    }
}

/// One `ret` and the SSA value of the ABI's float return register that reaches
/// it — recorded while the reaching-definition stacks are still live.
struct RetSite {
    block: usize,
    stmt: usize,
    float: String,
    /// The reaching value of the ABI's *second* float return register, when the
    /// convention has one.
    float2: Option<String>,
}

/// Every SSA name a statement **reads**, for the purpose of "did anything in
/// this function consume this value".
///
/// Definitions (`Assign`'s `dst`, a call's `ret`) are absent because a name is
/// not a consumer of itself. So is a `Return`'s operand: being handed to the
/// caller is the opposite of being consumed here, and counting it would make
/// every candidate look consumed the moment it is the returned one.
fn stmt_uses(stmt: &MicroStmt, out: &mut BTreeSet<String>) {
    match stmt {
        MicroStmt::Assign { value, .. } => collect_expr_vars(value, out),
        MicroStmt::Store { addr, value, .. } => {
            collect_expr_vars(addr, out);
            collect_expr_vars(value, out);
        }
        MicroStmt::Call { target, args, .. } => {
            if let CallTarget::Indirect(e) = target {
                collect_expr_vars(e, out);
            }
            for a in args {
                collect_expr_vars(a, out);
            }
        }
        MicroStmt::Return(_) | MicroStmt::Nop | MicroStmt::Unlifted { .. } => {}
    }
}

/// Was `name` **computed by this function**, as opposed to arriving in the
/// register from outside it?
///
/// Three things are not a computation: the entry value of a register (the
/// caller put it there), a call's clobber (the model saying it no longer knows),
/// and a phi none of whose inputs is itself a computation. A phi *is* one when
/// every input is — that is the shared-epilogue shape, where each arm computes
/// the value and one `ret` returns the merge. Requiring *every* input keeps the
/// partial case (`if (c) xmm0 = …;`) out: a value only some paths produce is not
/// this function's answer.
fn computed_here(
    name: &str,
    defs: &HashMap<String, MicroExpr>,
    phi_inputs: &HashMap<String, Vec<String>>,
    seen: &mut BTreeSet<String>,
) -> bool {
    match defs.get(name) {
        None => false,
        Some(MicroExpr::Unknown(_)) => match phi_inputs.get(name) {
            Some(inputs) if !inputs.is_empty() => {
                // A back edge reaches its own phi; it can neither confirm nor
                // veto, so it is skipped rather than answered.
                if !seen.insert(name.to_string()) {
                    return true;
                }
                inputs.iter().all(|i| computed_here(i, defs, phi_inputs, seen))
            }
            _ => false,
        },
        Some(_) => true,
    }
}

/// Point each `ret` at the register that actually carries this function's
/// result.
///
/// The lift sees one instruction at a time, so a `ret` can only be modelled as
/// `return <integer return register>;` — it has no way to know the function
/// returns a `double`, which comes back in a different register file entirely.
/// Left there, the float result is a value nothing reads: DCE removes it and
/// everything that produced it, and the function renders as an empty body
/// returning the caller's own `rax`. Measured on a purpose-built target where
/// every return type was known in advance, that was **every** function
/// returning `float` or `double` and no others.
///
/// The rule that separates the two: at this `ret`, the float return register
/// holds a value this function **computed and nothing here reads**. A value
/// computed for no local consumer was computed for the caller. When the integer
/// register is the real result the float register fails the test either way — it
/// still holds the caller's value (nothing computed), or it holds something a
/// store or a convert consumed (something reads it), which is exactly the shape
/// of a function that returns a pointer and writes a `double` through it.
///
/// Returns `(retargeted, pair)` — whether any `ret` was retargeted, and whether
/// the result spans both vector return registers. Both are facts type recovery
/// needs and cannot re-derive once the optimizer has folded the register names
/// away.
fn retarget_float_returns(
    blocks: &mut [SsaBlock],
    sites: &[RetSite],
    defs: &HashMap<String, MicroExpr>,
) -> (bool, bool) {
    if sites.is_empty() {
        return (false, false);
    }
    // Uses by real statements only. A phi's use of its own input is not a
    // consumer — it is the merge itself — and counting it would make every
    // input look consumed.
    let mut uses: BTreeSet<String> = BTreeSet::new();
    let mut phi_inputs: HashMap<String, Vec<String>> = HashMap::new();
    for b in blocks.iter() {
        for s in &b.stmts {
            // Writing the flags is sometimes a side effect of producing the
            // value and sometimes the whole point of the instruction, and only
            // the first is a non-consumer. `add rax, 7` sets flags *from* its
            // own result — counting that as a use makes every arithmetic result
            // look consumed. `cmp a, b` and `ucomisd a, b` produce nothing but
            // flags: the operands are what they consume, and a value tested and
            // never stored was not computed for the caller.
            //
            // The two are told apart by the comparison's kind, which the lift
            // already records: `Result`/`LogicalResult` are the by-product of an
            // instruction whose real output is its destination register.
            if let MicroStmt::Assign { dst, value } = &s.stmt
                && dst.split('.').next() == Some(FLAGS_VAR)
                && matches!(value, MicroExpr::Compare { kind: CmpKind::Result | CmpKind::LogicalResult, .. })
            {
                continue;
            }
            stmt_uses(&s.stmt, &mut uses);
        }
        if let Some(c) = &b.condition {
            collect_expr_vars(c, &mut uses);
        }
        for phi in &b.phis {
            phi_inputs.insert(phi.dst.clone(), phi.inputs.iter().map(|i| i.value.clone()).collect());
        }
    }
    /// Is this value consumed by nothing in this function — **through** a phi?
    ///
    /// A phi at a join point is never itself read: each arm's use consumed that
    /// arm's own value, and the merged name exists only so later code has one
    /// name to refer to. So "nothing reads the phi" is true by construction and
    /// says nothing about whether the value was computed for the caller.
    ///
    /// Found by an independent decompiler on a Qt build: a getter that fills a
    /// caller-provided buffer stores a vector register on both paths and joins
    /// at a shared `ret`. Nothing reads the phi, so the return register was
    /// swapped and the function claimed to return a `double` — 253 functions in
    /// that image, none of which returns one. Reading through the phi to its
    /// inputs is the difference: there, both inputs *are* read, so the value was
    /// not computed for the caller; in the shape this rule exists for — each arm
    /// computing the result and one `ret` returning the merge — none of them is.
    fn unread(name: &str, uses: &BTreeSet<String>, phi_inputs: &HashMap<String, Vec<String>>, seen: &mut BTreeSet<String>) -> bool {
        if uses.contains(name) {
            return false;
        }
        match phi_inputs.get(name) {
            // A back edge cannot say anything its own cycle has not said.
            Some(inputs) if seen.insert(name.to_string()) => inputs.iter().all(|i| unread(i, uses, phi_inputs, seen)),
            _ => true,
        }
    }

    let mut retargeted = false;
    let mut pair = false;
    for site in sites {
        // A block that leaves by a tail call hands the whole register file to
        // the callee: whatever is live in the float register there is an
        // **argument**, not this function's result. Without this, an outlined
        // cold fragment ending `vpcmpeqd xmm0,xmm0,xmm0 ; jmp <back into the
        // caller>` reads as a function returning a double. Measured on a Qt
        // build, that shape alone was most of the wrong answers — and the model
        // cannot see it from the dataflow, because `call_args` carries only the
        // integer argument registers, so nothing appears to read `xmm0`.
        if blocks.get(site.block).is_some_and(|b| b.terminator == "tail-call") {
            continue;
        }
        if !unread(&site.float, &uses, &phi_inputs, &mut BTreeSet::new()) {
            continue;
        }
        if !computed_here(&site.float, defs, &phi_inputs, &mut BTreeSet::new()) {
            continue;
        }
        // The integer return register keeps the return whenever it *also* holds
        // a value this function computed and nothing here reads — it is the
        // ABI's default and only loses when it has nothing to offer.
        //
        // Without this, a dependency-breaking `vpxor xmm0,xmm0,xmm0` at the top
        // of a function decided the whole question: on a Qt build,
        // `QImage::pixelIndex` computes its `int` in `eax` and still opened with
        // that idiom, and the float register won on a value the code never
        // touched again. The integer result is a computation *for the caller*
        // by the same test the float side has to pass; when both pass, nothing
        // here says the float one is the answer, and the ABI's default stands.
        let int_ret = blocks
            .get(site.block)
            .and_then(|b| b.stmts.get(site.stmt))
            .and_then(|s| match &s.stmt {
                MicroStmt::Return(Some(MicroExpr::Var(n))) => Some(n.clone()),
                _ => None,
            });
        if let Some(n) = int_ret
            && unread(&n, &uses, &phi_inputs, &mut BTreeSet::new())
            && computed_here(&n, defs, &phi_inputs, &mut BTreeSet::new())
        {
            continue;
        }
        if let Some(s) = blocks.get_mut(site.block).and_then(|b| b.stmts.get_mut(site.stmt))
            && let MicroStmt::Return(Some(_)) = &s.stmt
        {
            s.stmt = MicroStmt::Return(Some(MicroExpr::Var(site.float.clone())));
            retargeted = true;
            // The second vector return register passing the same test is not a
            // coincidence: a struct of two floating-point members comes back in
            // both. The value returned is the first half — the answer says the
            // result is a pair so that half is not read as the whole.
            if let Some(second) = &site.float2
                && unread(second, &uses, &phi_inputs, &mut BTreeSet::new())
                && computed_here(second, defs, &phi_inputs, &mut BTreeSet::new())
            {
                pair = true;
            }
        }
    }
    (retargeted, pair)
}

fn build_ssa(
    arch: &dyn Arch,
    cfg: &CfgArtifact,
    lifted: &LiftedFunction,
    float_ret: Option<&str>,
    float_ret2: Option<&str>,
) -> SsaArtifact {
    let n = cfg.blocks.len();
    if n == 0 {
        return SsaArtifact {
            start: cfg.start,
            end: cfg.end,
            blocks: Vec::new(),
            callsites: cfg.callsites.clone(),
            float_return: false,
            float_return_pair: false,
        };
    }
    let (succ, pred) = block_graph(cfg);
    let dom = dominators_fwd(n, &pred);
    let idom = immediate_doms(&dom);
    let df = dominance_frontier(n, &pred, &idom);
    let children = dom_children(&idom);

    let mut vars: BTreeSet<String> = BTreeSet::new();
    for b in &lifted.blocks {
        for s in &b.stmts {
            collect_stmt_vars(&s.stmt, &mut vars);
        }
    }

    let mut defsites: HashMap<String, BTreeSet<usize>> = HashMap::new();
    for b in &lifted.blocks {
        for s in &b.stmts {
            if let Some(d) = stmt_dst(&s.stmt) {
                defsites.entry(d.to_string()).or_default().insert(b.id);
            }
        }
    }

    // Iterated-dominance-frontier phi placement (Cytron et al.).
    let mut phi_vars_per_block: Vec<BTreeSet<String>> = vec![BTreeSet::new(); n];
    for var in &vars {
        let sites = defsites.get(var).cloned().unwrap_or_default();
        let mut worklist: Vec<usize> = sites.iter().copied().collect();
        let mut on_worklist: BTreeSet<usize> = sites.clone();
        let mut has_phi: BTreeSet<usize> = BTreeSet::new();
        while let Some(b) = worklist.pop() {
            for &d in &df[b] {
                if has_phi.insert(d) {
                    phi_vars_per_block[d].insert(var.clone());
                    if on_worklist.insert(d) {
                        worklist.push(d);
                    }
                }
            }
        }
    }
    let mut phis: Vec<Vec<Phi>> = phi_vars_per_block
        .into_iter()
        .map(|vs| vs.into_iter().map(|var| Phi { var, dst: String::new(), inputs: Vec::new() }).collect())
        .collect();

    let mut stacks: HashMap<String, Vec<String>> = HashMap::new();
    let mut counters: HashMap<String, u32> = HashMap::new();
    let mut defs: HashMap<String, MicroExpr> = HashMap::new();
    for v in &vars {
        let v0 = format!("{v}.0");
        stacks.insert(v.clone(), vec![v0.clone()]);
        defs.insert(v0, MicroExpr::Unknown(format!("{v}@entry")));
    }

    let mut out_stmts: Vec<Vec<SsaStmt>> = vec![Vec::new(); n];
    let mut end_flags_name: Vec<Option<String>> = vec![None; n];
    let mut visited = vec![false; n];

    let mut ret_sites: Vec<RetSite> = Vec::new();
    rename_block(
        0,
        arch,
        cfg,
        lifted,
        &succ,
        &children,
        &mut phis,
        &mut stacks,
        &mut counters,
        &mut defs,
        &mut out_stmts,
        &mut end_flags_name,
        &mut visited,
        float_ret,
        float_ret2,
        &mut ret_sites,
    );

    let unknown = MicroExpr::Unknown("no-flags-reached".to_string());
    let mut blocks: Vec<SsaBlock> = cfg
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| {
            // Blocks the dominator-tree walk never reached (unreachable code)
            // still get an artifact entry — never silently dropped — just
            // without renaming applied (nothing sound to rename against).
            let stmts = if visited[i] {
                std::mem::take(&mut out_stmts[i])
            } else {
                lifted.blocks[i]
                    .stmts
                    .iter()
                    .map(|s| SsaStmt { va: s.va, stmt: s.stmt.clone() })
                    .collect()
            };
            let condition = if b.terminator == "cjmp" && visited[i] {
                let mnemonic = b.insns.last().map(|ins| ins.mnemonic.clone());
                mnemonic.map(|m| {
                    let flags_value = end_flags_name[i].as_ref().and_then(|n| defs.get(n)).unwrap_or(&unknown);
                    arch.branch_condition(&m, flags_value)
                })
            } else {
                None
            };
            SsaBlock {
                id: b.id,
                start: b.start,
                end: b.end,
                terminator: b.terminator.clone(),
                successors: b.successors.clone(),
                phis: if visited[i] { std::mem::take(&mut phis[i]) } else { Vec::new() },
                stmts,
                condition,
            }
        })
        .collect();

    let (float_return, float_return_pair) = retarget_float_returns(&mut blocks, &ret_sites, &defs);
    SsaArtifact {
        start: cfg.start,
        end: cfg.end,
        blocks,
        callsites: cfg.callsites.clone(),
        float_return,
        float_return_pair,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::{BinOp, X64};
    use n0xis_contracts::Va;
    use n0xis_sources::Snapshot;

    fn build(code: Vec<u8>) -> SsaArtifact {
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let cfg = crate::CfgPass.run(&ctx, crate::CfgInput::new(Va(0x1000), 64)).unwrap();
        SsaPass.run(&ctx, cfg).unwrap()
    }

    /// The value returned by the last statement of the only block.
    fn returned(art: &SsaArtifact) -> Option<String> {
        match &art.blocks.last()?.stmts.last()?.stmt {
            MicroStmt::Return(Some(MicroExpr::Var(n))) => Some(n.clone()),
            _ => None,
        }
    }

    #[test]
    fn a_double_computed_for_nobody_here_is_what_this_function_returns() {
        // addsd xmm0, xmm1 ; ret  — the whole body of `double add(double,double)`.
        // The lift models `ret` as `return rax;`, which is a value this function
        // never touched: left there, DCE deletes the `addsd` and the function
        // renders as an empty body. `xmm0.1` is computed here and read by
        // nothing, so it is the value the caller was given.
        let art = build(vec![0xF2, 0x0F, 0x58, 0xC1, 0xC3]);
        assert_eq!(returned(&art).as_deref(), Some("xmm0.1"));
        assert!(art.float_return);
    }

    #[test]
    fn a_double_only_loaded_into_the_return_register_counts_too() {
        // movsd xmm0, [rdi+8] ; ret — `double get(S *p) { return p->val; }`.
        // Nothing arithmetic happens; the register is still where the answer is.
        let art = build(vec![0xF2, 0x0F, 0x10, 0x47, 0x08, 0xC3]);
        assert_eq!(returned(&art).as_deref(), Some("xmm0.1"));
        assert!(art.float_return);
    }

    #[test]
    fn a_double_something_here_reads_is_not_the_return_value() {
        // movsd [rdi], xmm0 ; ret — a `void` function that stores its argument.
        // `xmm0`'s value is consumed by the store, so it was not computed for the
        // caller; the return register stays the integer one. This is the case
        // that separates "returns a double" from "writes a double through a
        // pointer and returns something else".
        let art = build(vec![0xF2, 0x0F, 0x11, 0x07, 0xC3]);
        assert_eq!(returned(&art).as_deref(), Some("rax.0"));
        assert!(!art.float_return);
    }

    #[test]
    fn a_value_both_arms_already_consumed_is_not_the_return_value() {
        // test rdi,rdi ; je L ; movsd xmm0,[rdi+8] ; movsd [rsi],xmm0 ; jmp E
        //  L: pxor xmm0,xmm0 ; movsd [rsi],xmm0
        //  E: ret
        // A getter that fills a caller-provided buffer on both paths. The `ret`
        // block's `xmm0` is a phi, and a phi is never itself read — each arm's
        // store consumed that arm's own value. Reading only the phi made this
        // look like a computed-for-the-caller double; on a Qt build that shape
        // was 253 functions, none of which returns one.
        let art = build(vec![
            0x48, 0x85, 0xFF, 0x74, 0x0B, 0xF2, 0x0F, 0x10, 0x47, 0x08, 0xF2, 0x0F, 0x11, 0x06, 0xEB, 0x08, 0x66,
            0x0F, 0xEF, 0xC0, 0xF2, 0x0F, 0x11, 0x06, 0xC3,
        ]);
        assert_eq!(returned(&art).as_deref(), Some("rax.0"));
        assert!(!art.float_return);
    }

    #[test]
    fn the_integer_register_keeps_the_return_when_it_computed_something_too() {
        // pxor xmm0,xmm0 ; mov rax,[rdi] ; add rax,7 ; ret
        // The leading `pxor` is a dependency-breaking idiom, not a value — and
        // it is indistinguishable from `return 0.0;` by itself. What separates
        // them is the other candidate: here `rax` holds a computation of this
        // function's own that nothing reads either, so the ABI's default stands.
        let art = build(vec![0x66, 0x0F, 0xEF, 0xC0, 0x48, 0x8B, 0x07, 0x48, 0x83, 0xC0, 0x07, 0xC3]);
        assert_eq!(returned(&art).as_deref(), Some("rax.2"));
        assert!(!art.float_return);
    }

    /// A value the code only *compares* was not computed for the caller.
    ///
    /// `xorps xmm0,xmm0 ; ucomiss xmm0,xmm1 ; ret` — a `void` early-out testing
    /// an argument against zero. The compare writes nothing but flags, so
    /// nothing appeared to read the constant and it looked like the result. Ten
    /// of eleven functions where this rule still answered wrongly on a Qt build
    /// traced back to exactly that: the lift dropped the compare's operands, so
    /// the use edge did not exist to be found.
    #[test]
    fn a_value_only_a_float_compare_reads_is_not_the_return_value() {
        // 0f 57 c0        xorps  xmm0,xmm0
        // 0f 2e c1        ucomiss xmm0,xmm1
        // c3              ret
        let art = build(vec![0x0F, 0x57, 0xC0, 0x0F, 0x2E, 0xC1, 0xC3]);
        assert_eq!(returned(&art).as_deref(), Some("rax.0"));
        assert!(!art.float_return);
    }

    /// …while the flags an arithmetic instruction leaves behind are still not a
    /// use: `add rax, 7` sets them *from* its own result. Only a dedicated
    /// comparison consumes what it is given.
    #[test]
    fn arithmetic_flags_are_still_a_by_product_and_not_a_use() {
        let art = build(vec![0x66, 0x0F, 0xEF, 0xC0, 0x48, 0x8B, 0x07, 0x48, 0x83, 0xC0, 0x07, 0xC3]);
        assert_eq!(returned(&art).as_deref(), Some("rax.2"));
    }

    /// A struct of two floating-point members comes back in **both** vector
    /// return registers. Naming one of them `double` answers half the question
    /// as if it were the whole; the artifact says the result is a pair so the
    /// signature can say so too.
    #[test]
    fn a_result_in_both_vector_registers_is_reported_as_a_pair() {
        // f2 0f 10 47 08   movsd xmm0,[rdi+8]
        // f2 0f 10 4f 10   movsd xmm1,[rdi+0x10]
        // c3               ret
        let art = build(vec![0xF2, 0x0F, 0x10, 0x47, 0x08, 0xF2, 0x0F, 0x10, 0x4F, 0x10, 0xC3]);
        assert_eq!(returned(&art).as_deref(), Some("xmm0.1"));
        assert!(art.float_return && art.float_return_pair);

        // One register alone is an ordinary scalar return, not a pair.
        let art = build(vec![0xF2, 0x0F, 0x10, 0x47, 0x08, 0xC3]);
        assert!(art.float_return && !art.float_return_pair);
    }

    #[test]
    fn a_return_register_the_function_never_wrote_is_left_alone() {
        // mov rax, [rdi] ; ret — no vector register appears at all, so there is
        // nothing to choose between and the integer return stands.
        let art = build(vec![0x48, 0x8B, 0x07, 0xC3]);
        assert_eq!(returned(&art).as_deref(), Some("rax.1"));
        assert!(!art.float_return);
    }

    #[test]
    fn straight_line_defs_get_distinct_versions() {
        // mov rax, rcx ; mov rax, rdx ; ret
        let art = build(vec![0x48, 0x89, 0xC8, 0x48, 0x89, 0xD0, 0xC3]);
        assert_eq!(art.blocks.len(), 1);
        let dsts: Vec<&str> = art.blocks[0]
            .stmts
            .iter()
            .filter_map(|s| match &s.stmt {
                MicroStmt::Assign { dst, .. } => Some(dst.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(dsts, vec!["rax.1", "rax.2"]);
    }

    #[test]
    fn condition_survives_intervening_add_as_a_placeholder() {
        // cmp rcx,0 ; je +5 ; add rcx,rdx ; nop(pad) -- then at 0x100a: ret
        // Layout: entry block ends at the je (cjmp); its condition must come
        // from the cmp right above it (no intervening flag write in *this*
        // block), so it should resolve to an exact `rcx == 0`.
        let code = vec![
            0x48, 0x83, 0xf9, 0x00, // cmp rcx, 0
            0x74, 0x03, // je +3 -> 0x1009
            0x48, 0xff, 0xc1, // inc rcx (only in the fallthrough block)
            0xc3, // ret
        ];
        let art = build(code);
        let entry = &art.blocks[0];
        assert_eq!(entry.terminator, "cjmp");
        let cond = entry.condition.clone().expect("cjmp block has a condition");
        assert_eq!(
            cond,
            MicroExpr::binary(BinOp::Eq, MicroExpr::var("rcx.0"), MicroExpr::constant(0, 64))
        );
    }

    fn rcx_assign_value(art: &SsaArtifact) -> MicroExpr {
        art.blocks
            .iter()
            .flat_map(|b| &b.stmts)
            .find_map(|s| match &s.stmt {
                MicroStmt::Assign { dst, value } if dst.starts_with("rcx") => Some(value.clone()),
                _ => None,
            })
            .expect("an assign to the setcc destination register")
    }

    /// The interesting sub-expression of a sub-register write.
    ///
    /// `setne cl` writes **one byte** of `rcx` and preserves the other seven,
    /// so the recovered condition is nested inside `(rcx & ~0xff) | (uint8_t)…`
    /// rather than sitting at the root. These tests are about *what was
    /// recovered*, not about how a byte write is spelled, so they dig it out.
    fn inner(e: &MicroExpr) -> &MicroExpr {
        match e {
            MicroExpr::Cast { expr, .. } => inner(expr),
            // The merge's right-hand side is the newly written field.
            MicroExpr::Binary(BinOp::Or, _, rhs) => inner(rhs),
            other => other,
        }
    }

    #[test]
    fn setcc_reconstructs_the_condition_from_the_reaching_compare() {
        // cmp eax, 5 ; setne cl ; ret  — `cl` is the boolean `eax != 5`, and it
        // must be recovered against the compare that set the flags, exactly like
        // a `jne` would be.
        //   83 F8 05  cmp eax, 5
        //   0F 95 C1  setne cl
        //   C3        ret
        let art = build(vec![0x83, 0xF8, 0x05, 0x0F, 0x95, 0xC1, 0xC3]);
        assert_eq!(
            *inner(&rcx_assign_value(&art)),
            MicroExpr::binary(
                BinOp::Ne,
                MicroExpr::Cast { signed: false, bits: 32, expr: Box::new(MicroExpr::var("rax.0")) },
                MicroExpr::constant(5, 32),
            ),
        );
    }

    #[test]
    fn setcc_without_a_preceding_compare_stays_a_placeholder_never_a_guess() {
        // setne cl ; ret  — no compare set the flags, so the reaching value is
        // the opaque entry flags. The result must be a sound `/*cond*/`
        // placeholder, not a fabricated condition.
        //   0F 95 C1  setne cl
        //   C3        ret
        let art = build(vec![0x0F, 0x95, 0xC1, 0xC3]);
        assert!(
            matches!(inner(&rcx_assign_value(&art)), MicroExpr::Unknown(_)),
            "an unreconstructable setcc must stay opaque, not guess",
        );
    }

    #[test]
    fn cmov_becomes_a_ternary_select_with_the_recovered_condition() {
        // cmp eax, 5 ; cmovb ecx, edx ; ret — `ecx = (eax < 5) ? edx : ecx`,
        // a conditional select whose condition is reconstructed from the compare.
        //   83 F8 05     cmp eax, 5
        //   0F 42 CA     cmovb ecx, edx
        //   C3           ret
        let art = build(vec![0x83, 0xF8, 0x05, 0x0F, 0x42, 0xCA, 0xC3]);
        let value = rcx_assign_value(&art);
        // `cmovb ecx, edx` writes a 32-bit destination, so the select is wrapped
        // in the zero-extension that write performs — the Select is the value,
        // the cast is the register rule around it.
        let MicroExpr::Select { cond, a, b } = inner(&value) else {
            panic!("cmovb must lower to a Select, got {value:?}");
        };
        let low32 = |n: &str| MicroExpr::Cast {
            signed: false,
            bits: 32,
            expr: Box::new(MicroExpr::var(n)),
        };
        // condition: unsigned-below from the compare (cmovb ↔ jb ↔ Ult)
        assert_eq!(**cond, MicroExpr::binary(BinOp::Ult, low32("rax.0"), MicroExpr::constant(5, 32)));
        assert_eq!(**a, low32("rdx.0"), "the moved-in source when the condition holds");
        assert_eq!(**b, low32("rcx.0"), "the kept destination otherwise");
    }

    #[test]
    fn diamond_join_gets_a_phi_for_the_merged_register() {
        // if (rcx == 0) { rax = 1; } else { rax = 2; } ret  (both arms
        // fall/jump into a shared ret block that reads rax -> must phi).
        //
        // 0x1000: cmp rcx,0        48 83 f9 00
        // 0x1004: je 0x100f        74 09
        // 0x1006: mov rax,1        48 c7 c0 01 00 00 00
        // 0x100d: jmp 0x1016       eb 07
        // 0x100f: mov rax,2        48 c7 c0 02 00 00 00
        // 0x1016: ret              c3
        let code = vec![
            0x48, 0x83, 0xf9, 0x00, // 0x1000 cmp rcx, 0
            0x74, 0x09, // 0x1004 je 0x100f
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // 0x1006 mov rax, 1
            0xeb, 0x07, // 0x100d jmp 0x1016
            0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00, // 0x100f mov rax, 2
            0xc3, // 0x1016 ret
        ];
        let art = build(code);
        let join = art.blocks.iter().find(|b| !b.phis.is_empty()).expect("a join block with a phi");
        let phi = join.phis.iter().find(|p| p.var == "rax").expect("phi for rax");
        assert_eq!(phi.inputs.len(), 2);
    }
}
