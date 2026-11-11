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

use std::collections::{BTreeMap, BTreeSet, HashMap};

use n0xis_arch::{Arch, BinOp, CallTarget, CmpKind, MicroExpr, MicroStmt, UnliftedReads, FLAGS_VAR, JUMP_TARGET_VAR};
use n0xis_contracts::Va;
use serde::Serialize;

use crate::dom::{DomTree, block_graph, dom_children, dominance_frontier};
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
    /// What the form before propagation says about the values that came in.
    /// In-memory metadata, like `float_return` and for the same reason: the
    /// optimizer folds away the copies this is read from.
    #[serde(skip)]
    pub raw_flow: RawFlow,
}

/// What happened to the values a function received, read before propagation.
///
/// `mov %rdi,%rbx; call g; mov %rbx,%rdi; call h` is a function reading its first
/// argument, and after propagation it is two calls with a bare `rdi.0`, which every
/// call shows whether or not anything was passed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RawFlow {
    /// Entry values a copy carried to the argument list of a real call: a register
    /// the compiler moved a value out of, or back into, to pass it. A phi alone is
    /// no movement, since a branch around a call merges a register nothing touched
    /// with what the call left in it.
    pub moved: BTreeSet<String>,
    /// Entry values stored to the frame and only ever loaded back into the register
    /// they came from, with nothing reading them there: a save and a restore.
    pub saved: BTreeSet<String>,
    /// Where in the frame an entry value was stored as it came, by frame offset.
    pub stored_at: BTreeMap<String, i128>,
    /// What the function's returns hold.
    pub returns: ReturnEvidence,
    /// The frame offsets loaded from and stored to, before propagation: a load whose
    /// value nothing reads is gone after it, and it read the slot all the same. On i386
    /// gcc passes a local function's arguments in registers, and the load of a
    /// parameter into one went with the register the call no longer reads.
    pub frame: FrameAccess,
}

/// See [`RawFlow::frame`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FrameAccess {
    pub loaded: BTreeSet<i128>,
    pub stored: BTreeSet<i128>,
}

/// What stands behind the return register at each `ret`, where the lift returned it
/// whether or not anything was meant. Before propagation, so that a value moved to
/// `rax` from where it was kept is told from one a call just left there.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReturnEvidence {
    /// Some path computes it, loads it or moves it there: it is a return value.
    pub value: bool,
    /// Calls whose result some path returns untouched: only the callee can say.
    pub calls: Vec<CallTarget>,
    /// Of what is computed for a return, some is computed for nothing else. A value also
    /// read on its way, `mov (%rdi),%rax; add $1,%rax; mov %rax,(%rdi); ret`, may be the
    /// result or only what was left there, and the bytes do not say.
    pub only_returned: bool,
    /// There is a `ret` at all. A function with none gives nothing to a question about
    /// what it gives, since nothing it left in a register is ever seen.
    pub any: bool,
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
        let mut ssa = build_ssa(ctx.arch, &cfg, &lifted, fr, fr2);
        ssa.raw_flow.returns = return_evidence(&ssa.blocks, crate::ir::abi_return_register(ctx).as_deref());
        Ok(ssa)
    }
}

fn stmt_dst(stmt: &MicroStmt) -> Option<&str> {
    match stmt {
        MicroStmt::Assign { dst, .. } => Some(dst.as_str()),
        MicroStmt::Call { ret: Some(r), .. } => Some(r.as_str()),
        _ => None,
    }
}

pub(crate) fn collect_expr_vars(e: &MicroExpr, out: &mut BTreeSet<String>) {
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
        // An unlifted instruction's reads are variables like any other: each
        // needs an entry version, or a read of a register nothing in the
        // function writes would have no name to be renamed to.
        MicroStmt::Unlifted { reads, .. } => out.extend(reads.regs().iter().cloned()),
        MicroStmt::Return(None) | MicroStmt::Nop => {}
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
        // The reads take the version reaching the instruction, exactly as an
        // expression's variables do — this is what makes them *uses* to every
        // pass downstream (DCE, liveness, parameter recovery).
        //
        // An instruction that may read anything reads, here, the reaching
        // version of every variable the function names: the widest set that
        // matters, since a register nothing in the function mentions has no
        // definition to keep alive. Stated as a bound, so it keeps those
        // definitions without being evidence that any one of them is read.
        // The pseudo-variables (`flags`, the jump target) are not registers.
        MicroStmt::Unlifted { va, text, reads, mem } => MicroStmt::Unlifted {
            va: *va,
            text: text.clone(),
            reads: match reads {
                UnliftedReads::Unknown => {
                    let every: BTreeSet<&String> = stacks.keys().filter(|v| *v != FLAGS_VAR && *v != JUMP_TARGET_VAR).collect();
                    UnliftedReads::Bound(every.into_iter().filter_map(|v| stacks[v].last().cloned()).collect())
                }
                known => known.map_names(|n| stacks.get(n).and_then(|s| s.last()).cloned().unwrap_or_else(|| n.to_string())),
            },
            mem: *mem,
        },
    }
}

/// Dominator-tree preorder renaming walk (Cytron et al.). `root` is a block
/// *index* (identical to its `CfgBlock::id` — both are assigned in the same
/// address-sorted enumeration by `CfgPass`). The walk keeps its own stack: a run
/// of `if`s one after another makes the tree as deep as the function is long.
#[allow(clippy::too_many_arguments)]
fn rename_tree(
    root: usize,
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
    let pushed = rename_block(
        root, arch, cfg, lifted, succ, phis, stacks, counters, defs, out_stmts, end_flags_name, visited, float_ret,
        float_ret2, ret_sites,
    );
    let mut open = vec![(root, pushed, 0usize)];
    while let Some((b, pushed, next)) = open.last_mut() {
        if let Some(&c) = children[*b].get(*next) {
            *next += 1;
            let pushed = rename_block(
                c, arch, cfg, lifted, succ, phis, stacks, counters, defs, out_stmts, end_flags_name, visited, float_ret,
                float_ret2, ret_sites,
            );
            open.push((c, pushed, 0));
        } else {
            // Restore the stacks for siblings.
            for var in pushed.iter().rev() {
                if let Some(stack) = stacks.get_mut(var) {
                    stack.pop();
                }
            }
            open.pop();
        }
    }
}

/// Renames one block; returns the variables whose stacks it pushed, for the walk
/// to pop when it leaves the block's subtree.
#[allow(clippy::too_many_arguments)]
fn rename_block(
    b: usize,
    arch: &dyn Arch,
    cfg: &CfgArtifact,
    lifted: &LiftedFunction,
    succ: &[Vec<usize>],
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
) -> Vec<String> {
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
        // The statement stays as lifted. What a later branch reads of these flags
        // can say more, once the instruction that set them is known.
        if let MicroStmt::Assign { dst, value } = &renamed
            && dst.split('.').next() == Some(FLAGS_VAR)
            && let Some(insn) = cfg.blocks[b].insns.iter().find(|i| i.va == lstmt.va)
            && let Some(known) = arch.flags_of_operation(&insn.mnemonic, value, &|name| defs.get(name).cloned())
        {
            defs.insert(dst.clone(), known);
        }
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

    pushed
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
        // An unlifted instruction consumes what it reads — a bound included:
        // "may consume" is enough to stop a value from being called unread.
        MicroStmt::Unlifted { reads, .. } => out.extend(reads.regs().iter().cloned()),
        MicroStmt::Return(_) | MicroStmt::Nop => {}
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
/// The flags an instruction sets from its own result, which read nothing it was not
/// going to produce anyway (see [`retarget_float_returns`]).
fn flags_by_product(stmt: &MicroStmt) -> bool {
    matches!(stmt, MicroStmt::Assign { dst, value: MicroExpr::Compare { kind: CmpKind::Result | CmpKind::LogicalResult, .. } } if dst.split('.').next() == Some(FLAGS_VAR))
}

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
            if flags_by_product(&s.stmt) {
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

/// The condition of a block the renaming never reached: a landing pad entered by the
/// unwinder, and what only it leads to. Its statements stay in machine order under
/// their register's bare name, and the flags set in the block itself still say what
/// its branch tests, while nothing between has changed what they read. Flags from
/// before the block are not known to anything here.
fn unrenamed_condition(arch: &dyn Arch, jcc: &str, stmts: &[SsaStmt]) -> Option<MicroExpr> {
    let at = stmts.iter().rposition(|s| matches!(&s.stmt, MicroStmt::Assign { dst, .. } if dst == FLAGS_VAR))?;
    let MicroStmt::Assign { value, .. } = &stmts[at].stmt else { return None };
    let mut read = BTreeSet::new();
    collect_expr_vars(value, &mut read);
    let reads_memory = expr_reads_memory(value);
    let undisturbed = stmts[at + 1..].iter().all(|s| match &s.stmt {
        MicroStmt::Assign { dst, .. } => !read.contains(dst),
        MicroStmt::Nop => true,
        MicroStmt::Store { .. } => !reads_memory,
        _ => false,
    });
    undisturbed.then(|| arch.branch_condition(jcc, value))
}

fn expr_reads_memory(e: &MicroExpr) -> bool {
    match e {
        MicroExpr::Load { .. } => true,
        // An intrinsic reads what its arguments do; the flags of an operation are one.
        MicroExpr::Call { target: CallTarget::Intrinsic(_), args } => args.iter().any(expr_reads_memory),
        MicroExpr::Call { .. } => true,
        MicroExpr::Binary(_, l, r) => expr_reads_memory(l) || expr_reads_memory(r),
        MicroExpr::Cast { expr: x, .. } | MicroExpr::Unary(_, x) | MicroExpr::AddrOf(x) => expr_reads_memory(x),
        MicroExpr::Compare { lhs, rhs, .. } => expr_reads_memory(lhs) || expr_reads_memory(rhs),
        MicroExpr::Select { cond, a, b } => [cond, a, b].iter().any(|x| expr_reads_memory(x)),
        MicroExpr::Var(_) | MicroExpr::Const { .. } | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => false,
    }
}

fn ssa_root(name: &str) -> &str {
    name.split('.').next().unwrap_or(name)
}

/// The value this copies, through a width change: `mov %edi,%ebx` moves a value too.
fn copied_var(e: &MicroExpr) -> Option<&str> {
    match e {
        MicroExpr::Var(v) => Some(v),
        MicroExpr::Cast { expr, .. } => copied_var(expr),
        _ => None,
    }
}

/// Reads [`RawFlow`] off the blocks as they are before propagation.
pub(crate) fn raw_flow(blocks: &[SsaBlock], stack_pointer: Option<&str>, word_bytes: Option<u8>) -> RawFlow {
    // Where each value goes by copy or merge. A name is defined once.
    let mut goes_to: HashMap<&str, Vec<&str>> = HashMap::new();
    for b in blocks {
        for p in &b.phis {
            for i in &p.inputs {
                goes_to.entry(i.value.as_str()).or_default().push(p.dst.as_str());
            }
        }
        for s in &b.stmts {
            if let MicroStmt::Assign { dst, value } = &s.stmt
                && let Some(from) = copied_var(value)
            {
                goes_to.entry(from).or_default().push(dst.as_str());
            }
        }
    }
    // Every name a real call takes bare, in any position.
    let mut passed: BTreeSet<&str> = BTreeSet::new();
    for b in blocks {
        for s in &b.stmts {
            if let MicroStmt::Call { target, args, .. } = &s.stmt
                && !matches!(target, CallTarget::Intrinsic(_))
            {
                passed.extend(args.iter().filter_map(|a| if let MicroExpr::Var(v) = a { Some(v.as_str()) } else { None }));
            }
        }
    }
    let mut moved = BTreeSet::new();
    for entry in goes_to.keys().copied().filter(|n| n.ends_with(".0")) {
        // (a name, whether the value has left its register by then): another
        // register's name on the way is what says a copy happened, also where the
        // value then comes back to its own, `mov %rdi,%rbx; ...; mov %rbx,%rdi`.
        let mut seen: BTreeSet<(&str, bool)> = BTreeSet::from([(entry, false)]);
        let mut work = vec![(entry, false)];
        while let Some((v, left)) = work.pop() {
            for &next in goes_to.get(v).into_iter().flatten() {
                let left = left || ssa_root(next) != ssa_root(entry);
                if seen.insert((next, left)) {
                    work.push((next, left));
                }
            }
        }
        if seen.iter().any(|(n, left)| *left && passed.contains(n)) {
            moved.insert(entry.to_string());
        }
    }
    let (saved, stored_at) = saved_entries(blocks, stack_pointer, word_bytes);
    let frame = stack_pointer.map(|sp| frame_offsets(blocks, sp, word_bytes)).map_or_else(FrameAccess::default, |f| FrameAccess {
        loaded: crate::stack_args::loaded_offsets(blocks, &f),
        stored: crate::stack_args::stored_offsets(blocks, &f),
    });
    RawFlow { moved, saved, stored_at, returns: ReturnEvidence::default(), frame }
}

/// See [`ReturnEvidence`]. `ret_reg` is the convention's integer return register: its
/// entry value, and a marker of what a call may have changed, are no value. A phi
/// asks each of the paths into it.
fn return_evidence(blocks: &[SsaBlock], ret_reg: Option<&str>) -> ReturnEvidence {
    enum Def<'b> {
        Phi(&'b [crate::ssa::PhiInput]),
        Call(&'b CallTarget),
        Copy(&'b str),
        Clobber,
        Other,
    }
    let mut defs: HashMap<&str, Def> = HashMap::new();
    for b in blocks {
        for p in &b.phis {
            defs.insert(p.dst.as_str(), Def::Phi(&p.inputs));
        }
        for s in &b.stmts {
            match &s.stmt {
                MicroStmt::Assign { dst, value: MicroExpr::Unknown(u) } if u == n0xis_arch::CALL_CLOBBER => {
                    defs.insert(dst.as_str(), Def::Clobber);
                }
                MicroStmt::Assign { dst, value: MicroExpr::Var(from) } => {
                    defs.insert(dst.as_str(), Def::Copy(from.as_str()));
                }
                MicroStmt::Assign { dst, .. } => {
                    defs.insert(dst.as_str(), Def::Other);
                }
                MicroStmt::Call { ret: Some(dst), target, .. } => {
                    defs.insert(dst.as_str(), Def::Call(target));
                }
                _ => {}
            }
        }
    }
    let mut out = ReturnEvidence::default();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut work: Vec<&str> = Vec::new();
    // Every read but the `ret`'s own, through the merges: a value that joins another
    // that something reads is read too.
    let mut read: BTreeSet<&str> = BTreeSet::new();
    let mut owned: BTreeSet<String> = BTreeSet::new();
    for b in blocks {
        for s in &b.stmts {
            if !matches!(s.stmt, MicroStmt::Return(_)) && !flags_by_product(&s.stmt) {
                stmt_uses(&s.stmt, &mut owned);
            }
        }
        if let Some(c) = &b.condition {
            collect_expr_vars(c, &mut owned);
        }
    }
    read.extend(owned.iter().map(String::as_str));
    loop {
        let before = read.len();
        for b in blocks {
            for p in &b.phis {
                if read.contains(p.dst.as_str()) {
                    read.extend(p.inputs.iter().map(|i| i.value.as_str()));
                }
            }
        }
        if read.len() == before {
            break;
        }
    }
    for b in blocks {
        for s in &b.stmts {
            match &s.stmt {
                MicroStmt::Return(Some(MicroExpr::Var(v))) => {
                    out.any = true;
                    work.push(v.as_str());
                }
                MicroStmt::Return(Some(_)) => {
                    out.any = true;
                    out.value = true;
                }
                MicroStmt::Return(None) => out.any = true,
                _ => {}
            }
        }
    }
    while let Some(v) = work.pop() {
        if !seen.insert(v) {
            continue;
        }
        match defs.get(v) {
            None => out.value |= v.ends_with(".0") && Some(ssa_root(v)) != ret_reg,
            Some(Def::Clobber) => {}
            Some(Def::Other) => {
                out.value = true;
                out.only_returned |= !read.contains(v);
            }
            Some(Def::Call(t)) => out.calls.push((*t).clone()),
            Some(Def::Phi(inputs)) => work.extend(inputs.iter().map(|i| i.value.as_str())),
            // One register's version of another of itself passes the question on;
            // from any other register, somebody moved it here to return it.
            Some(Def::Copy(from)) if ssa_root(from) == ssa_root(v) => work.push(from),
            Some(Def::Copy(_)) => {
                out.value = true;
                out.only_returned |= !read.contains(v);
            }
        }
    }
    out
}

/// The frame offset of every version of the stack pointer and every copy of one (a
/// frame pointer), from the stack pointer at entry, or from the root
/// [`frame_offsets_from`] is given: what the stack-pointer tracking places at an
/// offset from it, on either side of it. One notion of the frame for every reader:
/// the stack arguments a call is given and a function takes, the saves, and
/// `writes_memory`.
///
/// A version is placed when its definition is the root, a placed version plus or
/// minus a constant (any number of times: the optimizer folds a chain into one
/// expression, `&(rsp.1 - 0x20) + 4`), the address of such an expression (`lea
/// rbp, [rsp+0x20]`, `lea 0x8(%esp),%ecx`), or a phi whose every input is placed
/// at the same offset. Anything else is not placed, and neither is a phi whose
/// inputs disagree. The phi case is solved as a fixpoint over a three-step lattice
/// (not yet seen, one offset, not the frame), so a loop's phi of the stack pointer
/// with its own unchanged version is placed: it used to be left out, and with it
/// every slot addressed inside the loop.
#[derive(Clone, Debug, Default)]
pub(crate) struct Frame {
    at: HashMap<String, i128>,
    /// The target's word, in bits. A 32-bit lift computes on the canonical 64-bit
    /// registers and casts each result to 32 bits, so on i386 every address is
    /// `(uint32_t)(esp.0 + 0x4)`: a cast to the word is the value itself there, and
    /// on x86-64 a cast to 32 bits of a stack address is no address of the frame.
    /// Without it nothing on i386 was placed at all.
    word_bits: Option<u32>,
}

impl Frame {
    /// The frame of a function's SSA blocks, raw or optimized, from the stack
    /// pointer at entry. Empty for an architecture with no stack pointer.
    pub(crate) fn of(blocks: &[SsaBlock], arch: &dyn Arch) -> Frame {
        arch.stack_pointer().map(|sp| frame_offsets(blocks, sp, arch.pointer_size())).unwrap_or_default()
    }

    /// The frame offset an address names.
    pub(crate) fn offset_of(&self, e: &MicroExpr) -> Option<i128> {
        let (base, c) = self.split(e)?;
        Some(self.wrap(self.at.get(base)? + c))
    }

    /// `e` as a variable and a constant away from it, if it is one: through a
    /// constant added or taken away, on either side, any number of times, and
    /// through what [`Frame::bare`] takes off.
    fn split<'e>(&self, e: &'e MicroExpr) -> Option<(&'e str, i128)> {
        let constant = |e: &MicroExpr| match self.bare(e) {
            MicroExpr::Const { value, .. } => Some(*value),
            _ => None,
        };
        match self.bare(e) {
            MicroExpr::Var(v) => Some((v.as_str(), 0)),
            MicroExpr::Binary(BinOp::Add, l, r) => match (constant(r), constant(l)) {
                (Some(c), _) => self.split(l).map(|(v, o)| (v, o + c)),
                (None, Some(c)) => self.split(r).map(|(v, o)| (v, o + c)),
                (None, None) => None,
            },
            MicroExpr::Binary(BinOp::Sub, l, r) => {
                let c = constant(r)?;
                self.split(l).map(|(v, o)| (v, o - c))
            }
            _ => None,
        }
    }

    /// An offset as the target's address arithmetic has it: on i386 `ecx.1 + 0xfffffffc`
    /// is four bytes below `ecx.1`, not four GiB above, and read as the second, gcc's
    /// `main` asked for a billion arguments.
    fn wrap(&self, off: i128) -> i128 {
        match self.word_bits {
            Some(w) if w > 0 && w < 128 => {
                let shift = 128 - w;
                (off << shift) >> shift
            }
            _ => off,
        }
    }

    /// `e` with what changes nothing taken off: the casts to the target's word or
    /// wider, and the `lea` that makes an address a value (`AddrOf`), so `lea
    /// 0x8(%esp),%ecx` is eight bytes up the frame like `esp.0 + 0x8` is. A cut to
    /// any narrower width is not: on x86-64 `(u32)rsp` is not in the frame.
    fn bare<'e>(&self, mut e: &'e MicroExpr) -> &'e MicroExpr {
        loop {
            match e {
                MicroExpr::Cast { bits, expr, .. } if self.word_bits.is_some_and(|w| *bits >= w) => e = expr,
                MicroExpr::AddrOf(inner) => e = inner,
                _ => return e,
            }
        }
    }

    pub(crate) fn get(&self, name: &str) -> Option<i128> {
        self.at.get(name).copied()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&String, &i128)> {
        self.at.iter()
    }
}

/// See [`Frame`]. `word_bytes` is the target's pointer size.
pub(crate) fn frame_offsets(blocks: &[SsaBlock], stack_pointer: &str, word_bytes: Option<u8>) -> Frame {
    frame_offsets_from(blocks, &format!("{stack_pointer}.0"), word_bytes)
}

/// The version `v` is a constant away from, as far back as constants go. Past
/// `and $-8,%esp` the offset from entry is lost, and what a call is given is still a
/// constant away from what that left: [`frame_offsets_from`] it.
pub(crate) fn frame_root(blocks: &[SsaBlock], v: &str, word_bytes: Option<u8>) -> String {
    let probe = Frame { at: HashMap::new(), word_bits: word_bytes.map(|b| u32::from(b) * 8) };
    let defs: HashMap<&str, &MicroExpr> = blocks
        .iter()
        .flat_map(|b| &b.stmts)
        .filter_map(|s| match &s.stmt {
            MicroStmt::Assign { dst, value } => Some((dst.as_str(), value)),
            _ => None,
        })
        .collect();
    let mut cur = v;
    for _ in 0..=defs.len() {
        match defs.get(cur).and_then(|e| probe.split(e)) {
            Some((base, _)) if base != cur => cur = base,
            _ => break,
        }
    }
    cur.to_string()
}

/// Offsets from `root` rather than from the stack pointer at entry. See [`frame_root`].
pub(crate) fn frame_offsets_from(blocks: &[SsaBlock], root: &str, word_bytes: Option<u8>) -> Frame {
    #[derive(Clone, Copy, PartialEq)]
    enum Place {
        At(i128),
        NotFrame,
    }
    // `placed` is the frame so far, read by each step for the newest answer; `at`
    // beside it also knows what was decided not to be the frame. A version absent
    // from both has not been reached yet; one never reached is not placed.
    let mut frame = Frame { at: HashMap::from([(root.to_string(), 0)]), word_bits: word_bytes.map(|b| u32::from(b) * 8) };
    let mut at: HashMap<String, Place> = HashMap::from([(root.to_string(), Place::At(0))]);
    let defined: BTreeSet<&str> = blocks
        .iter()
        .flat_map(|b| {
            b.phis.iter().map(|p| p.dst.as_str()).chain(b.stmts.iter().filter_map(|s| match &s.stmt {
                MicroStmt::Assign { dst, .. } => Some(dst.as_str()),
                _ => None,
            }))
        })
        .collect();
    // Raise `var` to `p` (never lower it): a phi decided on part of its inputs is
    // raised again when the rest arrive, and what was placed through it follows.
    let raise = |at: &mut HashMap<String, Place>, frame: &mut Frame, var: &str, p: Place| -> bool {
        let next = match at.get(var) {
            None => p,
            Some(old) if *old == p => return false,
            Some(_) => Place::NotFrame,
        };
        if at.get(var) == Some(&next) {
            return false;
        }
        match next {
            Place::At(off) => frame.at.insert(var.to_string(), off),
            Place::NotFrame => frame.at.remove(var),
        };
        at.insert(var.to_string(), next);
        true
    };
    loop {
        let mut changed = false;
        for b in blocks {
            for phi in &b.phis {
                if phi.dst == root {
                    continue;
                }
                let mut joined: Option<Place> = None;
                for input in &phi.inputs {
                    let p = match at.get(&input.value) {
                        Some(p) => *p,
                        // Defined nowhere in the function: an entry value that is not the
                        // root, so not the frame.
                        None if !defined.contains(input.value.as_str()) => Place::NotFrame,
                        None => continue,
                    };
                    joined = Some(match joined {
                        None => p,
                        Some(j) if j == p => j,
                        Some(_) => Place::NotFrame,
                    });
                }
                if let Some(p) = joined {
                    changed |= raise(&mut at, &mut frame, &phi.dst, p);
                }
            }
            for s in &b.stmts {
                if let MicroStmt::Assign { dst, value } = &s.stmt
                    && dst != root
                {
                    let p = match frame.offset_of(value) {
                        Some(off) => Place::At(off),
                        // Not placeable from what is known: decided once every operand
                        // it names is decided.
                        None if frame_operands_decided(value, &at, &defined) => Place::NotFrame,
                        None => continue,
                    };
                    changed |= raise(&mut at, &mut frame, dst, p);
                }
            }
        }
        if !changed {
            return frame;
        }
    }
}

/// Every version `e` names has a decided place (or is defined nowhere), so an
/// expression [`Frame::offset_of`] cannot place now never will be.
fn frame_operands_decided<P>(e: &MicroExpr, at: &HashMap<String, P>, defined: &BTreeSet<&str>) -> bool {
    let mut vars = BTreeSet::new();
    collect_expr_vars(e, &mut vars);
    vars.iter().all(|v| at.contains_key(v) || !defined.contains(v.as_str()))
}

/// See [`RawFlow::saved`]. A store nothing loads is not a save: at `-O0` that is a
/// parameter written to its slot and not used, which the bytes do read.
fn saved_entries(blocks: &[SsaBlock], stack_pointer: Option<&str>, word_bytes: Option<u8>) -> (BTreeSet<String>, BTreeMap<String, i128>) {
    let Some(sp) = stack_pointer else { return Default::default() };
    let at = frame_offsets(blocks, sp, word_bytes);
    let mut stored: Vec<(&str, i128)> = Vec::new();
    let mut loaded: HashMap<i128, Vec<&str>> = HashMap::new();
    let mut reads: BTreeSet<String> = BTreeSet::new();
    for b in blocks {
        for s in &b.stmts {
            match &s.stmt {
                MicroStmt::Store { addr, value: MicroExpr::Var(v), .. } if v.ends_with(".0") && at.offset_of(addr).is_some() => {
                    stored.push((v.as_str(), at.offset_of(addr).expect("just checked")));
                    collect_expr_vars(addr, &mut reads);
                }
                MicroStmt::Assign { dst, value: MicroExpr::Load { addr, .. } } if at.offset_of(addr).is_some() => {
                    loaded.entry(at.offset_of(addr).expect("just checked")).or_default().push(dst.as_str());
                    collect_expr_vars(addr, &mut reads);
                }
                // What `ret` reads of the return register says nothing of a value
                // that was put back there: it reads it on every path.
                MicroStmt::Return(Some(MicroExpr::Var(_))) => {}
                other => stmt_uses(other, &mut reads),
            }
        }
        reads.extend(b.phis.iter().flat_map(|p| p.inputs.iter().map(|i| i.value.clone())));
        if let Some(c) = &b.condition {
            collect_expr_vars(c, &mut reads);
        }
    }
    let mut saved = BTreeSet::new();
    let mut not_saved = BTreeSet::new();
    let stored_at = stored.iter().map(|(e, off)| (e.to_string(), *off)).collect();
    for (entry, off) in stored {
        let back = loaded.get(&off).map(Vec::as_slice).unwrap_or_default();
        if !back.is_empty() && back.iter().all(|d| ssa_root(d) == ssa_root(entry) && !reads.contains(*d)) {
            saved.insert(entry.to_string());
        } else {
            not_saved.insert(entry);
        }
    }
    saved.retain(|e| !not_saved.contains(e.as_str()));
    (saved, stored_at)
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
            raw_flow: RawFlow::default(),
        };
    }
    let (succ, pred) = block_graph(cfg);
    let dom = DomTree::forward(n, &pred);
    let idom = dom.idom();
    let df = dominance_frontier(n, &pred, idom);
    let children = dom_children(idom);

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
    rename_tree(
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
            } else if b.terminator == "cjmp" {
                let mnemonic = b.insns.last().map(|ins| ins.mnemonic.clone());
                mnemonic.and_then(|m| unrenamed_condition(arch, &m, &stmts))
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
    let raw_flow = raw_flow(&blocks, arch.stack_pointer(), arch.pointer_size());
    SsaArtifact {
        start: cfg.start,
        end: cfg.end,
        blocks,
        callsites: cfg.callsites.clone(),
        float_return,
        float_return_pair,
        raw_flow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::{BinOp, X64};
    use n0xis_contracts::Va;
    use n0xis_sources::Snapshot;

    /// The frame offsets of an i386 body's stores, in order. Every step of `esp` is
    /// cut to 32 bits there, and a displacement arrives as its unsigned word.
    fn i386_store_offsets(code: Vec<u8>) -> Vec<Option<i128>> {
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::x86();
        let ctx = Ctx::new(&snap, &arch);
        let cfg = crate::CfgPass.run(&ctx, crate::CfgInput::new(Va(0x1000), 64)).unwrap();
        let ssa = SsaPass.run(&ctx, cfg).unwrap();
        let frame = Frame::of(&ssa.blocks, &arch);
        ssa.blocks.iter().flat_map(|b| &b.stmts).filter_map(|s| match &s.stmt {
            MicroStmt::Store { addr, .. } => Some(frame.offset_of(addr)),
            _ => None,
        }).collect()
    }

    /// `ebp - 0xc` is 0x10 below the entry `esp` after `push ebp; mov ebp, esp`, and
    /// not 4 GiB above it: the cut to 32 bits is arithmetic modulo 2^32.
    #[test]
    fn an_i386_slot_is_placed_at_its_signed_offset() {
        // push ebp ; mov ebp,esp ; mov dword [ebp-0xc],0 ; pop ebp ; ret
        let offsets = i386_store_offsets(vec![0x55, 0x89, 0xE5, 0xC7, 0x45, 0xF4, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xC3]);
        assert_eq!(offsets, vec![Some(-4), Some(-0x10)], "the push, then the local");
    }

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
    fn a_block_no_path_reaches_tests_the_flags_it_set_itself() {
        let arch = X64::new();
        let at = |stmt| SsaStmt { va: Va(0x1000), stmt };
        let flags = MicroStmt::Assign {
            dst: FLAGS_VAR.to_string(),
            value: MicroExpr::compare(CmpKind::Result, MicroExpr::var("r15"), MicroExpr::constant(0, 64)),
        };
        let cond = unrenamed_condition(&arch, "je", &[at(flags.clone())]);
        assert_eq!(cond, Some(MicroExpr::binary(n0xis_arch::BinOp::Eq, MicroExpr::var("r15"), MicroExpr::constant(0, 64))));
        // Nothing set in the block: what they say is not known here.
        assert_eq!(unrenamed_condition(&arch, "je", &[]), None);
        // What the flags read was written since, under one bare name: no version
        // tells the two apart, so the condition cannot be spelled.
        let later = at(MicroStmt::Assign { dst: "r15".to_string(), value: MicroExpr::constant(1, 64) });
        assert_eq!(unrenamed_condition(&arch, "je", &[at(flags), later]), None);
        // `lock decq (%rax); jne` in such a block: its flags are of what it read
        // before the store, and the store is after them.
        let dec = at(MicroStmt::Assign {
            dst: FLAGS_VAR.to_string(),
            value: MicroExpr::intrinsic("__flags_dec", vec![MicroExpr::var("old")]),
        });
        let store = at(MicroStmt::Store { addr: MicroExpr::var("rax"), value: MicroExpr::var("old"), bits: 64 });
        assert!(matches!(unrenamed_condition(&arch, "jne", &[dec, store]), Some(MicroExpr::Binary(n0xis_arch::BinOp::Ne, ..))));
        // A flag read from memory, past a store.
        let from_memory = MicroStmt::Assign {
            dst: FLAGS_VAR.to_string(),
            value: MicroExpr::compare(CmpKind::Cmp, MicroExpr::load(MicroExpr::var("rdi"), 64, false), MicroExpr::constant(0, 64)),
        };
        let store = at(MicroStmt::Store { addr: MicroExpr::var("rsi"), value: MicroExpr::constant(1, 64), bits: 64 });
        assert_eq!(unrenamed_condition(&arch, "je", &[at(from_memory), store]), None);
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
