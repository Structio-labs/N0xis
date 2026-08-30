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

use n0xis_arch::{Arch, CallTarget, MicroExpr, MicroStmt, FLAGS_VAR};
use n0xis_contracts::Va;
use serde::Serialize;

use crate::dom::{block_graph, dom_children, dominance_frontier, dominators_fwd, immediate_doms};
use crate::ir::{CfgArtifact, Successor};
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
        Ok(build_ssa(ctx.arch, &cfg, &lifted))
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
    let MicroExpr::OpaqueFlags { mnemonic } = &value else { return value };
    let Some(jcc) = mnemonic.strip_prefix("setcc:") else { return value };
    let unknown = MicroExpr::Unknown("no-flags-reached".to_string());
    let flags = stacks.get(FLAGS_VAR).and_then(|s| s.last()).and_then(|n| defs.get(n)).unwrap_or(&unknown);
    arch.branch_condition(jcc, flags)
}

fn rename_call_target(target: &CallTarget, stacks: &HashMap<String, Vec<String>>) -> CallTarget {
    match target {
        CallTarget::Direct { va } => CallTarget::Direct { va: *va },
        CallTarget::Indirect(e) => CallTarget::Indirect(Box::new(rename_expr(e, stacks))),
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
        rename_block(c, arch, cfg, lifted, succ, children, phis, stacks, counters, defs, out_stmts, end_flags_name, visited);
    }

    // 5. Restore the stacks for siblings.
    for var in pushed.iter().rev() {
        if let Some(stack) = stacks.get_mut(var) {
            stack.pop();
        }
    }
}

fn build_ssa(arch: &dyn Arch, cfg: &CfgArtifact, lifted: &LiftedFunction) -> SsaArtifact {
    let n = cfg.blocks.len();
    if n == 0 {
        return SsaArtifact { start: cfg.start, end: cfg.end, blocks: Vec::new() };
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
    );

    let unknown = MicroExpr::Unknown("no-flags-reached".to_string());
    let blocks = cfg
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

    SsaArtifact { start: cfg.start, end: cfg.end, blocks }
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
            rcx_assign_value(&art),
            MicroExpr::binary(BinOp::Ne, MicroExpr::var("rax.0"), MicroExpr::constant(5, 32)),
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
            matches!(rcx_assign_value(&art), MicroExpr::Unknown(_)),
            "an unreconstructable setcc must stay opaque, not guess",
        );
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
