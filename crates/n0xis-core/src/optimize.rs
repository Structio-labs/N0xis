//! [`OptimizePass`] — copy/const/expression propagation, constant folding,
//! and DCE over [`SsaArtifact`], run to a (budgeted) fixpoint. Produces
//! `n0xis.opt.delta.v1`: what each round of each sub-pass changed, so an
//! agent can ask "why did this collapse?" (KF-5, ROADMAP Phase 3) instead of
//! trusting a black-box optimizer.
//!
//! The central transform (CONCEPT §6.3): `rax.1 = f(); x = *(rax.1 + 8);`
//! collapses to `x = *(f() + 8);` via **expression propagation** — inlining a
//! single-use definition into its sole consumer. Two independent passes
//! (const-fold, copy-prop) are unrestricted since they only ever substitute
//! *pure* values; expression propagation is deliberately narrower — same
//! block, single use, no `Call`/`Store` between def and use — because a
//! `Load` or `Call` moved past a side-effecting statement could reorder
//! observable behavior, and we don't have alias analysis yet (Phase 7+) to
//! prove otherwise. Sound before pretty (CONCEPT §3 rule 6).

use std::collections::HashMap;

use n0xis_arch::{BinOp, CallTarget, MicroExpr, MicroStmt, UnOp};
use n0xis_contracts::Va;
use serde::Serialize;

use crate::ssa::{SsaArtifact, SsaBlock};
use crate::{Ctx, CoreError, Pass};

/// Cap on optimization rounds — each round is copy-prop + const-fold +
/// expr-prop + DCE to local fixpoint; a handful of rounds is enough for any
/// realistic function, and a hard cap keeps this pass from looping forever
/// on a pathological input (CONCEPT anti-hardcode note: this is a safety
/// budget, not a tuned magic constant, so it stays generous).
const MAX_ROUNDS: usize = 16;

/// One explainable change a sub-pass made. `at` anchors it to the statement's
/// original address when known (a removed statement still reports where it
/// used to live).
#[derive(Clone, Debug, Serialize)]
pub struct OptDeltaEntry {
    pub pass: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<Va>,
    pub summary: String,
}

/// The optimized SSA form (same shape as [`SsaArtifact`]) plus the delta that
/// produced it (`n0xis.opt.delta.v1`).
#[derive(Clone, Debug, Serialize)]
pub struct OptArtifact {
    pub start: Va,
    pub end: Va,
    pub blocks: Vec<SsaBlock>,
    pub rounds: usize,
    pub delta: Vec<OptDeltaEntry>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OptimizePass;

impl Pass for OptimizePass {
    type In = SsaArtifact;
    type Out = OptArtifact;

    fn name(&self) -> &'static str {
        "opt.delta"
    }

    fn run(&self, _ctx: &Ctx, ssa: SsaArtifact) -> Result<OptArtifact, CoreError> {
        let mut blocks = ssa.blocks;
        let mut delta = Vec::new();
        let mut rounds = 0;
        for _ in 0..MAX_ROUNDS {
            rounds += 1;
            let mut changed = false;
            changed |= const_fold_round(&mut blocks, &mut delta);
            changed |= copy_prop_round(&mut blocks, &mut delta);
            changed |= expr_prop_round(&mut blocks, &mut delta);
            changed |= dce_round(&mut blocks, &mut delta);
            if !changed {
                break;
            }
        }
        Ok(OptArtifact { start: ssa.start, end: ssa.end, blocks, rounds, delta })
    }
}

// ---------------------------------------------------------------------
// Generic expression rewriting: apply `f` bottom-up over every subexpr.
// ---------------------------------------------------------------------

fn map_expr(e: &MicroExpr, f: &mut impl FnMut(MicroExpr) -> MicroExpr) -> MicroExpr {
    let rebuilt = match e {
        MicroExpr::Const { .. } | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) | MicroExpr::Var(_) => {
            e.clone()
        }
        MicroExpr::Load { addr, bits, signed } => {
            MicroExpr::Load { addr: Box::new(map_expr(addr, f)), bits: *bits, signed: *signed }
        }
        MicroExpr::Unary(op, v) => MicroExpr::Unary(*op, Box::new(map_expr(v, f))),
        MicroExpr::Binary(op, l, r) => MicroExpr::Binary(*op, Box::new(map_expr(l, f)), Box::new(map_expr(r, f))),
        MicroExpr::Cast { signed, bits, expr } => {
            MicroExpr::Cast { signed: *signed, bits: *bits, expr: Box::new(map_expr(expr, f)) }
        }
        MicroExpr::AddrOf(inner) => MicroExpr::AddrOf(Box::new(map_expr(inner, f))),
        MicroExpr::Compare { kind, lhs, rhs } => {
            MicroExpr::Compare { kind: *kind, lhs: Box::new(map_expr(lhs, f)), rhs: Box::new(map_expr(rhs, f)) }
        }
        MicroExpr::Call { target, args } => {
            let target = match target {
                CallTarget::Direct { va } => CallTarget::Direct { va: *va },
                CallTarget::Indirect(inner) => CallTarget::Indirect(Box::new(map_expr(inner, f))),
            };
            MicroExpr::Call { target, args: args.iter().map(|a| map_expr(a, f)).collect() }
        }
    };
    f(rebuilt)
}

fn map_stmt_exprs(stmt: &MicroStmt, f: &mut impl FnMut(MicroExpr) -> MicroExpr) -> MicroStmt {
    match stmt {
        MicroStmt::Assign { dst, value } => MicroStmt::Assign { dst: dst.clone(), value: map_expr(value, f) },
        MicroStmt::Store { addr, value, bits } => {
            MicroStmt::Store { addr: map_expr(addr, f), value: map_expr(value, f), bits: *bits }
        }
        MicroStmt::Call { target, args, ret } => {
            let target = match target {
                CallTarget::Direct { va } => CallTarget::Direct { va: *va },
                CallTarget::Indirect(inner) => CallTarget::Indirect(Box::new(map_expr(inner, f))),
            };
            MicroStmt::Call { target, args: args.iter().map(|a| map_expr(a, f)).collect(), ret: ret.clone() }
        }
        MicroStmt::Return(e) => MicroStmt::Return(e.as_ref().map(|x| map_expr(x, f))),
        MicroStmt::Nop => MicroStmt::Nop,
        MicroStmt::Unlifted { va, text } => MicroStmt::Unlifted { va: *va, text: text.clone() },
    }
}

fn for_each_block_expr_mut(blocks: &mut [SsaBlock], mut f: impl FnMut(&MicroExpr) -> Option<MicroExpr>) -> bool {
    let mut changed = false;
    let mut apply = |e: MicroExpr| match f(&e) {
        Some(new) if new != e => {
            changed = true;
            new
        }
        _ => e,
    };
    for b in blocks.iter_mut() {
        for s in b.stmts.iter_mut() {
            s.stmt = map_stmt_exprs(&s.stmt, &mut apply);
        }
        if let Some(cond) = &b.condition {
            let new = map_expr(cond, &mut apply);
            if new != *cond {
                b.condition = Some(new);
            }
        }
    }
    changed
}

// ---------------------------------------------------------------------
// Constant folding — pure, unrestricted.
// ---------------------------------------------------------------------

fn mask_to_bits(v: i128, bits: n0xis_arch::Bits) -> i128 {
    if bits == 0 || bits >= 128 {
        return v;
    }
    let mask = (1i128 << bits) - 1;
    v & mask
}

fn fold_binary(op: BinOp, lhs: i128, rhs: i128, bits: n0xis_arch::Bits) -> Option<i128> {
    let l = mask_to_bits(lhs, bits);
    let r = mask_to_bits(rhs, bits);
    let v = match op {
        BinOp::Add => l.wrapping_add(r),
        BinOp::Sub => l.wrapping_sub(r),
        BinOp::Mul => l.wrapping_mul(r),
        BinOp::UDiv | BinOp::SDiv if r == 0 => return None,
        BinOp::UDiv => l.wrapping_div(r),
        BinOp::SDiv => l.wrapping_div(r),
        BinOp::UMod | BinOp::SMod if r == 0 => return None,
        BinOp::UMod => l.wrapping_rem(r),
        BinOp::SMod => l.wrapping_rem(r),
        BinOp::And => l & r,
        BinOp::Or => l | r,
        BinOp::Xor => l ^ r,
        BinOp::Shl => l.wrapping_shl(r as u32),
        BinOp::Shr => l.wrapping_shr(r as u32),
        BinOp::Sar => l.wrapping_shr(r as u32),
        // Comparisons never reach here — `fold_once` routes them to
        // `fold_compare` (different result width: 1 bit, not `bits`).
        _ => return None,
    };
    Some(mask_to_bits(v, bits))
}

/// Comparisons fold separately: they produce a 1-bit boolean, not a value at
/// `bits` width.
fn fold_compare(op: BinOp, lhs: i128, rhs: i128, bits: n0xis_arch::Bits) -> Option<i128> {
    let l = mask_to_bits(lhs, bits);
    let r = mask_to_bits(rhs, bits);
    let signed_l = sign_extend(l, bits);
    let signed_r = sign_extend(r, bits);
    let b = match op {
        BinOp::Eq => l == r,
        BinOp::Ne => l != r,
        BinOp::Ult => (l as u128) < (r as u128),
        BinOp::Ule => (l as u128) <= (r as u128),
        BinOp::Ugt => (l as u128) > (r as u128),
        BinOp::Uge => (l as u128) >= (r as u128),
        BinOp::Slt => signed_l < signed_r,
        BinOp::Sle => signed_l <= signed_r,
        BinOp::Sgt => signed_l > signed_r,
        BinOp::Sge => signed_l >= signed_r,
        _ => return None,
    };
    Some(b as i128)
}

fn sign_extend(v: i128, bits: n0xis_arch::Bits) -> i128 {
    if bits == 0 || bits >= 128 {
        return v;
    }
    let shift = 128 - bits;
    (v << shift) >> shift
}

fn is_comparison(op: BinOp) -> bool {
    matches!(
        op,
        BinOp::Eq | BinOp::Ne | BinOp::Ult | BinOp::Ule | BinOp::Ugt | BinOp::Uge | BinOp::Slt | BinOp::Sle | BinOp::Sgt | BinOp::Sge
    )
}

fn fold_once(e: &MicroExpr) -> Option<MicroExpr> {
    match e {
        MicroExpr::Unary(op, v) => {
            let MicroExpr::Const { value, bits } = v.as_ref() else { return None };
            let folded = match op {
                UnOp::Neg => value.wrapping_neg(),
                UnOp::Not => !value,
            };
            Some(MicroExpr::Const { value: mask_to_bits(folded, *bits), bits: *bits })
        }
        MicroExpr::Binary(op, l, r) => {
            let (MicroExpr::Const { value: lv, bits: lb }, MicroExpr::Const { value: rv, .. }) =
                (l.as_ref(), r.as_ref())
            else {
                return None;
            };
            let bits = *lb;
            if is_comparison(*op) {
                fold_compare(*op, *lv, *rv, bits).map(|v| MicroExpr::Const { value: v, bits: 1 })
            } else {
                fold_binary(*op, *lv, *rv, bits).map(|v| MicroExpr::Const { value: v, bits })
            }
        }
        MicroExpr::Cast { signed, bits, expr } => {
            let MicroExpr::Const { value, .. } = expr.as_ref() else { return None };
            let v = if *signed { sign_extend(*value, *bits) } else { mask_to_bits(*value, *bits) };
            Some(MicroExpr::Const { value: v, bits: *bits })
        }
        _ => None,
    }
}

fn const_fold_round(blocks: &mut [SsaBlock], delta: &mut Vec<OptDeltaEntry>) -> bool {
    let mut folded_any = false;
    for_each_block_expr_mut(blocks, |e| {
        fold_once(e).inspect(|folded| {
            delta.push(OptDeltaEntry {
                pass: "const-fold",
                at: None,
                summary: format!("{e:?} -> {folded:?}"),
            });
            folded_any = true;
        })
    });
    folded_any
}

// ---------------------------------------------------------------------
// Copy propagation — pure, unrestricted (chases `x = y` chains and
// single-input phis all the way to their root value).
// ---------------------------------------------------------------------

fn copy_prop_round(blocks: &mut [SsaBlock], delta: &mut Vec<OptDeltaEntry>) -> bool {
    // A "copy" is a var whose only definition is a bare `Var(other)`.
    let mut copy_of: HashMap<String, String> = HashMap::new();
    for b in blocks.iter() {
        for phi in &b.phis {
            if !phi.dst.is_empty()
                && let Some(first) = phi.inputs.first()
                && phi.inputs.iter().all(|i| i.value == first.value)
            {
                copy_of.insert(phi.dst.clone(), first.value.clone());
            }
        }
        for s in &b.stmts {
            if let MicroStmt::Assign { dst, value: MicroExpr::Var(src) } = &s.stmt {
                copy_of.insert(dst.clone(), src.clone());
            }
        }
    }
    if copy_of.is_empty() {
        return false;
    }
    // Chase transitively (a copy of a copy).
    let resolve = |mut name: String| -> String {
        let mut hops = 0;
        while let Some(next) = copy_of.get(&name) {
            if hops > copy_of.len() + 1 {
                break; // defensive: never spin on a malformed cycle
            }
            name = next.clone();
            hops += 1;
        }
        name
    };

    let mut changed = false;
    for_each_block_expr_mut(blocks, |e| {
        if let MicroExpr::Var(name) = e {
            let resolved = resolve(name.clone());
            if &resolved != name {
                delta.push(OptDeltaEntry {
                    pass: "copy-prop",
                    at: None,
                    summary: format!("{name} -> {resolved}"),
                });
                changed = true;
                return Some(MicroExpr::Var(resolved));
            }
        }
        None
    });
    // Also resolve phi inputs (they're plain strings, not expressions).
    for b in blocks.iter_mut() {
        for phi in b.phis.iter_mut() {
            for input in phi.inputs.iter_mut() {
                let resolved = resolve(input.value.clone());
                if resolved != input.value {
                    input.value = resolved;
                    changed = true;
                }
            }
        }
    }
    changed
}

// ---------------------------------------------------------------------
// Expression propagation — the readability win. Same-block, single-use,
// no intervening Call/Store between def and use.
// ---------------------------------------------------------------------

fn expr_prop_round(blocks: &mut [SsaBlock], delta: &mut Vec<OptDeltaEntry>) -> bool {
    let use_counts = count_uses(blocks);
    let mut changed = false;

    for b in blocks.iter_mut() {
        let mut i = 0;
        'stmts: while i < b.stmts.len() {
            let (dst, def_expr, is_call) = match &b.stmts[i].stmt {
                MicroStmt::Assign { dst, value } => (dst.clone(), value.clone(), false),
                MicroStmt::Call { target, args, ret: Some(r) } => {
                    (r.clone(), MicroExpr::Call { target: target.clone(), args: args.clone() }, true)
                }
                _ => {
                    i += 1;
                    continue;
                }
            };
            if use_counts.get(&dst).copied().unwrap_or(0) != 1 {
                i += 1;
                continue;
            }
            // Find the single use, restricted to this same block, after `i`,
            // with no Call/Store between.
            //
            // KNOWN BUG (surfaced by clippy::never_loop, allow kept so the
            // gate stays green without a silent behavior change): every arm
            // below leaves the loop on the FIRST iteration — the trailing
            // `break` was meant to sit after the loop, not inside it. So this
            // only ever inspects `j == i + 1`, i.e. propagation happens solely
            // when the use is the immediately next statement. Moving the
            // `break` out restores the documented "scan forward to the use"
            // behavior and changes decompiler output, so it belongs in its own
            // change with pseudo-C goldens re-checked, not in a CI commit.
            #[allow(clippy::never_loop)]
            for j in (i + 1)..b.stmts.len() {
                if stmt_is_barrier(&b.stmts[j].stmt) {
                    i += 1;
                    continue 'stmts;
                }
                if expr_uses_var(stmt_read_exprs(&b.stmts[j].stmt), &dst) {
                    let at = b.stmts[i].va;
                    let mut did_inline = false;
                    b.stmts[j].stmt = map_stmt_exprs(&b.stmts[j].stmt.clone(), &mut |e| match &e {
                        MicroExpr::Var(name) if name == &dst && !did_inline => {
                            did_inline = true;
                            def_expr.clone()
                        }
                        _ => e,
                    });
                    delta.push(OptDeltaEntry {
                        pass: "expr-prop",
                        at: Some(at),
                        summary: format!(
                            "inlined {dst} ({}) into its sole use",
                            if is_call { "call result" } else { "expression" }
                        ),
                    });
                    b.stmts.remove(i);
                    changed = true;
                    continue 'stmts;
                }
                // Var referenced somewhere we don't walk (e.g. as a phi
                // input to another block) — bail conservatively via the
                // outer use-count check already having been 1; if it wasn't
                // found by here it must be a cross-block use, so skip.
                break;
            }
            i += 1;
        }
    }
    changed
}

/// Statements that must not be crossed when sinking a definition forward:
/// both have side effects/ordering the optimizer doesn't model precisely.
fn stmt_is_barrier(stmt: &MicroStmt) -> bool {
    matches!(stmt, MicroStmt::Call { .. } | MicroStmt::Store { .. })
}

fn stmt_read_exprs(stmt: &MicroStmt) -> Vec<&MicroExpr> {
    match stmt {
        MicroStmt::Assign { value, .. } => vec![value],
        MicroStmt::Store { addr, value, .. } => vec![addr, value],
        MicroStmt::Call { args, .. } => args.iter().collect(),
        MicroStmt::Return(Some(e)) => vec![e],
        MicroStmt::Return(None) | MicroStmt::Nop | MicroStmt::Unlifted { .. } => vec![],
    }
}

fn expr_uses_var(exprs: Vec<&MicroExpr>, name: &str) -> bool {
    exprs.into_iter().any(|e| expr_contains_var(e, name))
}

fn expr_contains_var(e: &MicroExpr, name: &str) -> bool {
    match e {
        MicroExpr::Var(n) => n == name,
        MicroExpr::Load { addr, .. } => expr_contains_var(addr, name),
        MicroExpr::Unary(_, v) => expr_contains_var(v, name),
        MicroExpr::Binary(_, l, r) => expr_contains_var(l, name) || expr_contains_var(r, name),
        MicroExpr::Cast { expr, .. } => expr_contains_var(expr, name),
        MicroExpr::AddrOf(inner) => expr_contains_var(inner, name),
        MicroExpr::Compare { lhs, rhs, .. } => expr_contains_var(lhs, name) || expr_contains_var(rhs, name),
        MicroExpr::Call { target, args } => {
            let in_target = matches!(target, CallTarget::Indirect(t) if expr_contains_var(t, name));
            in_target || args.iter().any(|a| expr_contains_var(a, name))
        }
        MicroExpr::Const { .. } | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => false,
    }
}

// ---------------------------------------------------------------------
// DCE — remove Assign/phi defs with zero remaining uses. Never removes
// Call/Store/Return/Unlifted: those may have effects beyond their `dst`.
// ---------------------------------------------------------------------

fn count_uses(blocks: &[SsaBlock]) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    let bump = |e: &MicroExpr, counts: &mut HashMap<String, usize>| {
        walk_expr_vars(e, &mut |name| *counts.entry(name.to_string()).or_insert(0) += 1);
    };
    for b in blocks {
        for phi in &b.phis {
            for input in &phi.inputs {
                *counts.entry(input.value.clone()).or_insert(0) += 1;
            }
        }
        for s in &b.stmts {
            for e in stmt_read_exprs(&s.stmt) {
                bump(e, &mut counts);
            }
        }
        if let Some(cond) = &b.condition {
            bump(cond, &mut counts);
        }
    }
    counts
}

fn walk_expr_vars(e: &MicroExpr, f: &mut impl FnMut(&str)) {
    match e {
        MicroExpr::Var(name) => f(name),
        MicroExpr::Load { addr, .. } => walk_expr_vars(addr, f),
        MicroExpr::Unary(_, v) => walk_expr_vars(v, f),
        MicroExpr::Binary(_, l, r) => {
            walk_expr_vars(l, f);
            walk_expr_vars(r, f);
        }
        MicroExpr::Cast { expr, .. } => walk_expr_vars(expr, f),
        MicroExpr::AddrOf(inner) => walk_expr_vars(inner, f),
        MicroExpr::Compare { lhs, rhs, .. } => {
            walk_expr_vars(lhs, f);
            walk_expr_vars(rhs, f);
        }
        MicroExpr::Call { target, args } => {
            if let CallTarget::Indirect(t) = target {
                walk_expr_vars(t, f);
            }
            for a in args {
                walk_expr_vars(a, f);
            }
        }
        MicroExpr::Const { .. } | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => {}
    }
}

fn dce_round(blocks: &mut [SsaBlock], delta: &mut Vec<OptDeltaEntry>) -> bool {
    let use_counts = count_uses(blocks);
    let mut changed = false;

    for b in blocks.iter_mut() {
        let before = b.stmts.len();
        b.stmts.retain(|s| match &s.stmt {
            MicroStmt::Assign { dst, .. } => {
                let live = use_counts.get(dst).copied().unwrap_or(0) > 0;
                if !live {
                    delta.push(OptDeltaEntry {
                        pass: "dce",
                        at: Some(s.va),
                        summary: format!("removed dead def {dst}"),
                    });
                }
                live
            }
            // Calls, stores, returns, nops, and unlifted asm are never
            // dead — they may have effects beyond their tracked `dst`.
            _ => true,
        });
        if b.stmts.len() != before {
            changed = true;
        }

        let phi_before = b.phis.len();
        b.phis.retain(|phi| {
            let live = !phi.dst.is_empty() && use_counts.get(&phi.dst).copied().unwrap_or(0) > 0;
            if !live {
                delta.push(OptDeltaEntry {
                    pass: "dce",
                    at: None,
                    summary: format!("removed dead phi {} ({})", phi.dst, phi.var),
                });
            }
            live
        });
        if b.phis.len() != phi_before {
            changed = true;
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CfgInput, CfgPass, Ctx, SsaPass};
    use n0xis_arch::X64;
    use n0xis_contracts::Va;
    use n0xis_sources::Snapshot;

    fn optimize(code: Vec<u8>) -> OptArtifact {
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 128)).unwrap();
        let ssa = SsaPass.run(&ctx, cfg).unwrap();
        OptimizePass.run(&ctx, ssa).unwrap()
    }

    /// Every expression reachable from any statement or condition in the
    /// function — used by tests that only care "does this shape appear
    /// *somewhere*", regardless of which statement ends up hosting it after
    /// propagation/DCE (both may relocate or fully collapse a chain into a
    /// single `Return`, which is the *better* outcome, not a bug).
    fn all_exprs(art: &OptArtifact) -> Vec<&MicroExpr> {
        let mut out = Vec::new();
        fn walk<'a>(e: &'a MicroExpr, out: &mut Vec<&'a MicroExpr>) {
            out.push(e);
            match e {
                MicroExpr::Load { addr, .. } => walk(addr, out),
                MicroExpr::Unary(_, v) => walk(v, out),
                MicroExpr::Binary(_, l, r) => {
                    walk(l, out);
                    walk(r, out);
                }
                MicroExpr::Cast { expr, .. } => walk(expr, out),
                MicroExpr::AddrOf(inner) => walk(inner, out),
                MicroExpr::Compare { lhs, rhs, .. } => {
                    walk(lhs, out);
                    walk(rhs, out);
                }
                MicroExpr::Call { target, args } => {
                    if let CallTarget::Indirect(t) = target {
                        walk(t, out);
                    }
                    for a in args {
                        walk(a, out);
                    }
                }
                MicroExpr::Const { .. } | MicroExpr::Var(_) | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => {}
            }
        }
        for b in &art.blocks {
            for s in &b.stmts {
                for e in stmt_read_exprs(&s.stmt) {
                    walk(e, &mut out);
                }
            }
            if let Some(c) = &b.condition {
                walk(c, &mut out);
            }
        }
        out
    }

    #[test]
    fn folds_a_constant_add() {
        // mov rax, 2 ; add rax, 3 ; ret  ->  the whole chain collapses to a
        // folded constant 5 (propagated all the way into the `return`,
        // which is a *more* optimized result than a lone `rax.k = 5;`).
        let code = vec![
            0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00, // mov rax, 2
            0x48, 0x83, 0xc0, 0x03, // add rax, 3
            0xc3, // ret
        ];
        let art = optimize(code);
        let has_five = all_exprs(&art).into_iter().any(|e| matches!(e, MicroExpr::Const { value: 5, .. }));
        assert!(has_five, "expected a folded constant 5 somewhere: {:#?}", art.blocks);
    }

    #[test]
    fn call_result_used_once_collapses_into_its_consumer() {
        // call rel32 (+0) -> rax ; mov rdx, [rax+0x68] ; mov rax, rdx ; ret
        // The extra `mov rax, rdx` keeps the loaded value observable (via
        // the final ret) instead of being dead-code-eliminated outright —
        // this is the principal Decompile.txt shape: `rax = f(); x = *(rax+0x68);`
        // collapsing to `x = *(f()+0x68);` (CONCEPT §6.3).
        let code = vec![
            0xE8, 0x00, 0x00, 0x00, 0x00, // call +0 (direct)
            0x48, 0x8B, 0x50, 0x68, // mov rdx, [rax+0x68]
            0x48, 0x89, 0xD0, // mov rax, rdx
            0xC3, // ret
        ];
        let art = optimize(code);
        // No standalone `Call` statement should survive — its result has
        // exactly one use, so it must be inlined into that use, not left
        // as its own line.
        let still_has_call_stmt =
            art.blocks.iter().flat_map(|b| &b.stmts).any(|s| matches!(s.stmt, MicroStmt::Call { .. }));
        assert!(!still_has_call_stmt, "call should have been inlined, not left standalone: {:#?}", art.blocks);

        let inlined = all_exprs(&art).into_iter().any(|e| {
            matches!(e, MicroExpr::Load { addr, .. } if matches!(
                addr.as_ref(),
                MicroExpr::Binary(BinOp::Add, l, _) if matches!(l.as_ref(), MicroExpr::Call { .. })
            ))
        });
        assert!(inlined, "expected `*(call(...) + 0x68)` somewhere: {:#?}", art.blocks);
    }

    #[test]
    fn call_feeding_a_live_return_is_never_dropped() {
        let code = vec![
            0xE8, 0x00, 0x00, 0x00, 0x00, // call +0
            0xC3, // ret — always reads rax, so the call's result is live.
        ];
        let art = optimize(code);
        // The call must still be observable somewhere — either as its own
        // statement or inlined directly into the `Return` — never dropped
        // outright the way a plain dead `Assign` would be.
        let call_present = art.blocks.iter().flat_map(|b| &b.stmts).any(|s| match &s.stmt {
            MicroStmt::Call { .. } => true,
            MicroStmt::Return(Some(e)) => matches!(e, MicroExpr::Call { .. }),
            _ => false,
        });
        assert!(call_present, "call feeding a live ret must not be removed: {:#?}", art.blocks);
    }
}
