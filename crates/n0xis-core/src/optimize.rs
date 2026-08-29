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
            changed |= mem_forward_round(&mut blocks, &mut delta);
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
// Memory forwarding — the first Memory-SSA increment (ROADMAP Phase 10,
// priority 1). Store-to-load forwarding over recognized memory locations:
// a `Load` from an address a *dominating, un-clobbered* `Store` wrote is
// replaced by the stored value, so a spill/reload or a struct-field write
// then read reads as the value, not `*(rbp - 8)`. This is what makes the
// register SSA reach *through* memory — other tools' readable-locals win.
//
// **Sound over complete (CONCEPT §3 rule 6), and honest about what it is:**
// intra-block only (no cross-block memory phi yet), and it forwards only
// when it can *prove* the load reads exactly what the store wrote:
//   - the address is a simple `base + const` (a stack slot / field), keyed
//     by the base's *SSA* name, so a different register version is a
//     different location by construction;
//   - the access widths match exactly (no partial-overlap forwarding);
//   - the stored value is *pure* (no `Load`/`Call`) — SSA already guarantees
//     its variables are stable between the store and the load;
//   - and the availability map is conservatively **cleared on any `Call` or
//     store through an unknown address, and any store to a different base**
//     — either could alias the slot, so nothing is forwarded across it.
// A points-to oracle (priority 2) is what later relaxes the "different base
// clobbers everything" rule; until then this never forwards an unsound value.
// ---------------------------------------------------------------------

/// The static location a `base + const` address names: the base's SSA name
/// and the byte offset. `None` for anything richer (an index register, an
/// absolute/ip-relative address, a nested expression) — those stay opaque and
/// are treated as may-alias-everything.
fn mem_key(addr: &MicroExpr) -> Option<(String, i128)> {
    match addr {
        MicroExpr::Var(name) => Some((name.clone(), 0)),
        MicroExpr::Binary(BinOp::Add, l, r) => match (l.as_ref(), r.as_ref()) {
            (MicroExpr::Var(name), MicroExpr::Const { value, .. }) => Some((name.clone(), *value)),
            (MicroExpr::Const { value, .. }, MicroExpr::Var(name)) => Some((name.clone(), *value)),
            _ => None,
        },
        _ => None,
    }
}

/// A value safe to duplicate into a later load position: no memory read and no
/// call, so moving it forward cannot observe or cause a side effect. SSA makes
/// its variables stable, so the copy reads identically at the load.
fn expr_is_pure(e: &MicroExpr) -> bool {
    match e {
        MicroExpr::Const { .. } | MicroExpr::Var(_) | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => true,
        MicroExpr::Load { .. } | MicroExpr::Call { .. } => false,
        MicroExpr::Unary(_, v) => expr_is_pure(v),
        MicroExpr::Binary(_, l, r) => expr_is_pure(l) && expr_is_pure(r),
        MicroExpr::Cast { expr, .. } => expr_is_pure(expr),
        MicroExpr::AddrOf(inner) => expr_is_pure(inner),
        MicroExpr::Compare { lhs, rhs, .. } => expr_is_pure(lhs) && expr_is_pure(rhs),
    }
}

fn bytes_of(bits: n0xis_arch::Bits) -> i128 {
    (bits.max(8) / 8) as i128
}

fn ranges_overlap(a_off: i128, a_bytes: i128, b_off: i128, b_bytes: i128) -> bool {
    a_off < b_off + b_bytes && b_off < a_off + a_bytes
}

/// One available store: `base+off` (byte-`bits` wide) currently holds `value`.
/// `from_seed` records that this fact reached the block along a CFG edge (it was
/// in `cross_in`), not from a store in this same block — so a forward off it is
/// a *cross-block* forward (stage 1b), which the delta reports distinctly.
#[derive(Clone)]
struct Avail {
    base: String,
    off: i128,
    bits: n0xis_arch::Bits,
    value: MicroExpr,
    from_seed: bool,
}

/// Every `Var` in `e` is an SSA *entry* value (`name.0`), so it is defined at
/// function entry and thus valid — dominates — in every block. That is what
/// makes a fact safe to carry *across* blocks without per-value dominance
/// bookkeeping: `rcx.0` reads the same everywhere, `rax.7` does not.
fn all_vars_are_entry(e: &MicroExpr) -> bool {
    match e {
        MicroExpr::Var(name) => name.ends_with(".0"),
        MicroExpr::Const { .. } | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => true,
        MicroExpr::Load { addr, .. } => all_vars_are_entry(addr),
        MicroExpr::Unary(_, v) => all_vars_are_entry(v),
        MicroExpr::Binary(_, l, r) => all_vars_are_entry(l) && all_vars_are_entry(r),
        MicroExpr::Cast { expr, .. } => all_vars_are_entry(expr),
        MicroExpr::AddrOf(inner) => all_vars_are_entry(inner),
        MicroExpr::Compare { lhs, rhs, .. } => all_vars_are_entry(lhs) && all_vars_are_entry(rhs),
        MicroExpr::Call { .. } => false,
    }
}

/// A value that may be carried across a block boundary: pure (no load/call) and
/// built only from entry values and constants, so it is valid in any block a
/// join can reach it from.
fn is_cross_block_stable(e: &MicroExpr) -> bool {
    expr_is_pure(e) && all_vars_are_entry(e)
}

fn same_slot(a: &Avail, base: &str, off: i128, bits: n0xis_arch::Bits) -> bool {
    a.base == base && a.off == off && a.bits == bits
}

// ---------------------------------------------------------------------
// Escape analysis (Rung 2a) — which stack slots a call / foreign store
// provably cannot touch. A slot is *call-safe* when its address is never
// materialized as a value anywhere in the function: not `lea`'d (no
// `AddrOf` of it) and its base register never used as a value (only ever as
// the base of a load/store address). If the address never becomes a value,
// no callee can hold a pointer to it and no other store can be computed to
// it — so only a store to that exact slot can change it. This is the sound
// keystone that lets forwarding survive calls, foreign stores, and unknown-
// address stores for the frame locals compilers spill and reload.
// ---------------------------------------------------------------------

#[derive(Default)]
struct Escape {
    /// Base registers whose value escaped (used as anything but an address base).
    bases: std::collections::HashSet<String>,
    /// Exact slots whose address was taken (`lea`/`&`), precisely.
    slots: std::collections::HashSet<(String, i128)>,
}

impl Escape {
    /// A slot only a same-slot store can change — safe across calls / foreign
    /// / unknown-address stores.
    fn call_safe(&self, base: &str, off: i128) -> bool {
        !self.bases.contains(base) && !self.slots.contains(&(base.to_string(), off))
    }
}

/// Record escapes in `e`. `value_ctx` is true when this expression is used as a
/// *value* (so a bare base register here means its address/value flowed out);
/// false inside a load/store address, where base and index registers are
/// legitimate address uses, not escapes.
fn visit_escape(e: &MicroExpr, value_ctx: bool, esc: &mut Escape) {
    match e {
        MicroExpr::Var(name) => {
            if value_ctx {
                esc.bases.insert(name.clone());
            }
        }
        MicroExpr::Const { .. } | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => {}
        // A load yields a value, but its address is an address context.
        MicroExpr::Load { addr, .. } => visit_escape(addr, false, esc),
        // Taking an address: a clean slot is recorded precisely (its base does
        // not escape); a computed address escapes every register in it.
        MicroExpr::AddrOf(inner) => match mem_key(inner) {
            Some((base, off)) => {
                esc.slots.insert((base, off));
            }
            None => visit_escape(inner, true, esc),
        },
        MicroExpr::Unary(_, v) => visit_escape(v, value_ctx, esc),
        MicroExpr::Binary(_, l, r) => {
            visit_escape(l, value_ctx, esc);
            visit_escape(r, value_ctx, esc);
        }
        MicroExpr::Cast { expr, .. } => visit_escape(expr, value_ctx, esc),
        MicroExpr::Compare { lhs, rhs, .. } => {
            visit_escape(lhs, value_ctx, esc);
            visit_escape(rhs, value_ctx, esc);
        }
        MicroExpr::Call { target, args } => {
            if let CallTarget::Indirect(t) = target {
                visit_escape(t, true, esc);
            }
            for a in args {
                visit_escape(a, true, esc);
            }
        }
    }
}

fn escape_info(blocks: &[SsaBlock]) -> Escape {
    let mut esc = Escape::default();
    for b in blocks {
        for s in &b.stmts {
            match &s.stmt {
                MicroStmt::Assign { value, .. } => visit_escape(value, true, &mut esc),
                MicroStmt::Store { addr, value, .. } => {
                    visit_escape(addr, false, &mut esc);
                    visit_escape(value, true, &mut esc);
                }
                MicroStmt::Call { target, args, .. } => {
                    if let CallTarget::Indirect(t) = target {
                        visit_escape(t, true, &mut esc);
                    }
                    for a in args {
                        visit_escape(a, true, &mut esc);
                    }
                }
                MicroStmt::Return(Some(e)) => visit_escape(e, true, &mut esc),
                MicroStmt::Return(None) | MicroStmt::Nop | MicroStmt::Unlifted { .. } => {}
            }
        }
        if let Some(c) = &b.condition {
            visit_escape(c, true, &mut esc);
        }
    }
    esc
}

/// Apply a block's stores/calls to the entry facts, keeping only cross-block-
/// stable facts — the transfer function of the available-memory dataflow. It
/// forwards nothing; it only computes what memory a block *exports* to its
/// successors.
fn transfer_cross(entry: &[Avail], block: &SsaBlock, esc: &Escape) -> Vec<Avail> {
    let mut avail: Vec<Avail> = entry.to_vec();
    for s in &block.stmts {
        clobber_for_stmt(&mut avail, &s.stmt, esc);
        // Gen: a cross-block-stable store makes its slot available downstream.
        if let MicroStmt::Store { addr, value, bits } = &s.stmt
            && let Some((base, off)) = mem_key(addr)
            && is_cross_block_stable(value)
        {
            avail.push(Avail { base, off, bits: *bits, value: value.clone(), from_seed: false });
        }
    }
    avail
}

/// Kill the facts a statement invalidates, honouring escape analysis: a call,
/// a foreign-base store, or an unknown-address store cannot touch a *call-safe*
/// slot, so those facts survive; only a store overlapping the same slot (or any
/// non-call-safe slot the barrier could reach) is killed.
fn clobber_for_stmt(avail: &mut Vec<Avail>, stmt: &MicroStmt, esc: &Escape) {
    match stmt {
        MicroStmt::Store { addr, bits, .. } => match mem_key(addr) {
            Some((base, off)) => {
                let bytes = bytes_of(*bits);
                avail.retain(|a| {
                    if a.base == base {
                        !ranges_overlap(a.off, bytes_of(a.bits), off, bytes)
                    } else {
                        // A different base cannot alias a call-safe slot.
                        esc.call_safe(&a.base, a.off)
                    }
                });
            }
            // An unknown address cannot be a call-safe slot either.
            None => avail.retain(|a| esc.call_safe(&a.base, a.off)),
        },
        // A callee can only write slots whose address escaped to it — *plus*
        // any slot at or below the outgoing stack pointer, which the call
        // clobbers regardless of escape: the System V **red zone** (`[rsp-128
        // .. rsp]`, scratch a call overwrites) and the Win64 **home/shadow
        // space** (`[rsp .. rsp+0x20]`, which a callee may write to spill its
        // register params). Those must not survive a call.
        MicroStmt::Call { .. } => {
            avail.retain(|a| esc.call_safe(&a.base, a.off) && !call_clobbers_frame_slot(&a.base, a.off))
        }
        _ => {}
    }
}

/// A stack slot a `call` clobbers by position, independent of escape: an
/// `rsp`-relative slot below the shadow ceiling — negative offsets are the
/// System V red zone (below `rsp`, overwritten by the callee's frame), and
/// `[0, 0x20)` is the Win64 shadow space — or an `rbp`-relative slot in that low
/// window (a frame pointer set equal to `rsp` would place its shadow there).
/// Slots at higher offsets (locals proper, outgoing args a callee only reads)
/// sit above the outgoing `rsp` and survive. Sound-conservative on both ABIs.
fn call_clobbers_frame_slot(base: &str, off: i128) -> bool {
    if base.starts_with("rsp") {
        off < 0x20
    } else if base.starts_with("rbp") {
        (0..0x20).contains(&off)
    } else {
        false
    }
}

/// Meet of the available-memory lattice: a fact survives a join only if *every*
/// predecessor exports it with the identical value (a disagreement is exactly
/// where a memory-phi would be needed, so it is conservatively dropped).
fn intersect_facts(sets: &[&Vec<Avail>]) -> Vec<Avail> {
    let Some((first, rest)) = sets.split_first() else {
        return Vec::new();
    };
    first
        .iter()
        .filter(|a| rest.iter().all(|s| s.iter().any(|o| same_slot(o, &a.base, a.off, a.bits) && o.value == a.value)))
        .cloned()
        .collect()
}

fn facts_eq(a: &[Avail], b: &[Avail]) -> bool {
    a.len() == b.len()
        && a.iter().all(|x| b.iter().any(|y| same_slot(y, &x.base, x.off, x.bits) && y.value == x.value))
}

fn mem_forward_round(blocks: &mut [SsaBlock], delta: &mut Vec<OptDeltaEntry>) -> bool {
    let n = blocks.len();
    if n == 0 {
        return false;
    }

    // Predecessor map over the block Vec (indices key on each block's start VA,
    // which is how `Successor::to` addresses an edge target).
    let idx_of: HashMap<u64, usize> = blocks.iter().enumerate().map(|(i, b)| (b.start.0, i)).collect();
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, b) in blocks.iter().enumerate() {
        for s in &b.successors {
            if let Some(&j) = idx_of.get(&s.to.0) {
                preds[j].push(i);
            }
        }
    }

    // Escape analysis: which slots a call / foreign / unknown store cannot
    // touch. Stable across optimizer rounds (forwarding only removes loads),
    // recomputed here so it tracks the current SSA names.
    let esc = escape_info(blocks);

    // Forward dataflow to a fixpoint: `cross_in[b]` is the memory available on
    // *every* path into block `b`. Entry (block 0, no preds) starts empty.
    // Monotone and bounded — the fact set can only shrink toward agreement.
    let mut cross_in: Vec<Vec<Avail>> = vec![Vec::new(); n];
    for _ in 0..(n + 2) {
        let cross_out: Vec<Vec<Avail>> = (0..n).map(|b| transfer_cross(&cross_in[b], &blocks[b], &esc)).collect();
        let mut changed = false;
        for b in 0..n {
            let new_in = if preds[b].is_empty() {
                Vec::new()
            } else {
                let sets: Vec<&Vec<Avail>> = preds[b].iter().map(|&p| &cross_out[p]).collect();
                intersect_facts(&sets)
            };
            if !facts_eq(&new_in, &cross_in[b]) {
                cross_in[b] = new_in;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // Forwarding pass: seed each block with the memory that reaches its entry
    // (stage 1b), then run the intra-block walk (stage 1a) which also picks up
    // same-block stores and forwards every provable load.
    let mut changed = false;
    for b in blocks.iter_mut() {
        let mut avail: Vec<Avail> = cross_in[idx_of[&b.start.0]].clone();
        for a in avail.iter_mut() {
            a.from_seed = true; // reached this block along an edge, not a local store
        }
        for s in b.stmts.iter_mut() {
            // 1. Forward loads in this statement's read positions.
            let mut hit: Option<(String, i128, bool)> = None;
            let rewritten = map_stmt_exprs(&s.stmt, &mut |e| {
                if let MicroExpr::Load { addr, bits, .. } = &e
                    && let Some((base, off)) = mem_key(addr)
                    && let Some(a) = avail.iter().find(|a| same_slot(a, &base, off, *bits))
                {
                    hit = Some((base, off, a.from_seed));
                    return a.value.clone();
                }
                e
            });
            if let Some((base, off, cross)) = hit {
                s.stmt = rewritten;
                changed = true;
                let where_ = if cross { "across a block boundary" } else { "within its block" };
                delta.push(OptDeltaEntry {
                    pass: "mem-forward",
                    at: Some(s.va),
                    summary: format!("forwarded load of [{base}{off:+}] to its store ({where_})"),
                });
            }
            // 2. Apply this statement's effect on the availability map. The
            // barrier kill honours escape analysis (a call / foreign store can
            // keep a call-safe slot); same-block gen may add a mid-function
            // value, valid locally, while the cross-block dataflow above only
            // exports entry-stable facts.
            clobber_for_stmt(&mut avail, &s.stmt, &esc);
            if let MicroStmt::Store { addr, value, bits } = &s.stmt
                && let Some((base, off)) = mem_key(addr)
                && expr_is_pure(value)
            {
                avail.push(Avail { base, off, bits: *bits, value: value.clone(), from_seed: false });
            }
        }
    }
    changed
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

    fn has_load(art: &OptArtifact) -> bool {
        all_exprs(art).into_iter().any(|e| matches!(e, MicroExpr::Load { .. }))
    }
    fn mem_forwarded(art: &OptArtifact) -> bool {
        art.delta.iter().any(|d| d.pass == "mem-forward")
    }

    #[test]
    fn a_spill_then_reload_forwards_the_stored_value() {
        // mov [rbp-8], rcx ; mov rax, [rbp-8] ; ret
        // The reload must read `rcx`, not a load of the stack slot — the
        // register SSA reaching *through* memory (Memory-SSA increment 1).
        let code = vec![
            0x48, 0x89, 0x4d, 0xf8, // mov [rbp-8], rcx
            0x48, 0x8b, 0x45, 0xf8, // mov rax, [rbp-8]
            0xc3, // ret
        ];
        let art = optimize(code);
        assert!(mem_forwarded(&art), "the reload should have been forwarded: {:#?}", art.delta);
        assert!(!has_load(&art), "no load of the stack slot should remain after forwarding: {:#?}", art.blocks);
    }

    #[test]
    fn a_call_does_not_block_a_non_escaping_slot() {
        // mov [rbp-8], rcx ; call +0 ; mov rax, [rbp-8] ; ret
        // The slot's address is never taken, so the callee cannot hold a
        // pointer to it — escape analysis (Rung 2a) proves the reload safe to
        // forward across the call.
        let code = vec![
            0x48, 0x89, 0x4d, 0xf8, // mov [rbp-8], rcx
            0xe8, 0x00, 0x00, 0x00, 0x00, // call +0
            0x48, 0x8b, 0x45, 0xf8, // mov rax, [rbp-8]
            0xc3, // ret
        ];
        let art = optimize(code);
        assert!(mem_forwarded(&art), "a non-escaping slot must forward across a call: {:#?}", art.delta);
        assert!(!has_load(&art), "no reload should remain: {:#?}", art.blocks);
    }

    #[test]
    fn an_address_taken_slot_is_not_forwarded_across_a_call() {
        // lea rdx, [rbp-8] ; mov [rbp-8], rcx ; call +0 ; mov rax, [rbp-8] ; ret
        // The `lea` materializes the slot's address, so the callee *could* have
        // been handed a pointer to it — the reload must stay a real load.
        let code = vec![
            0x48, 0x8d, 0x55, 0xf8, // lea rdx, [rbp-8]
            0x48, 0x89, 0x4d, 0xf8, // mov [rbp-8], rcx
            0xe8, 0x00, 0x00, 0x00, 0x00, // call +0
            0x48, 0x8b, 0x45, 0xf8, // mov rax, [rbp-8]
            0xc3, // ret
        ];
        let art = optimize(code);
        assert!(!mem_forwarded(&art), "an address-taken slot must not forward across a call: {:#?}", art.delta);
        assert!(has_load(&art), "the reload must remain a load: {:#?}", art.blocks);
    }

    #[test]
    fn a_shadow_space_slot_is_not_forwarded_across_a_call() {
        // mov [rsp+8], rcx ; call +0 ; mov rax, [rsp+8] ; ret
        // [rsp+8] is in the Win64 home/shadow space, which the callee may write
        // even without a pointer — so it must not forward across the call.
        let code = vec![
            0x48, 0x89, 0x4c, 0x24, 0x08, // mov [rsp+8], rcx
            0xe8, 0x00, 0x00, 0x00, 0x00, // call +0
            0x48, 0x8b, 0x44, 0x24, 0x08, // mov rax, [rsp+8]
            0xc3, // ret
        ];
        let art = optimize(code);
        assert!(!mem_forwarded(&art), "a shadow-space slot must not forward across a call: {:#?}", art.delta);
        assert!(has_load(&art), "the reload must remain a load: {:#?}", art.blocks);
    }

    #[test]
    fn a_red_zone_slot_is_not_forwarded_across_a_call() {
        // mov [rsp-16], rcx ; call +0 ; mov rax, [rsp-16] ; ret
        // System V red zone: below rsp, so the callee's frame overwrites it —
        // it must not forward across the call even though its address is safe.
        let code = vec![
            0x48, 0x89, 0x4c, 0x24, 0xf0, // mov [rsp-16], rcx
            0xe8, 0x00, 0x00, 0x00, 0x00, // call +0
            0x48, 0x8b, 0x44, 0x24, 0xf0, // mov rax, [rsp-16]
            0xc3, // ret
        ];
        let art = optimize(code);
        assert!(!mem_forwarded(&art), "a red-zone slot must not forward across a call: {:#?}", art.delta);
        assert!(has_load(&art), "the reload must remain a load: {:#?}", art.blocks);
    }

    #[test]
    fn a_foreign_base_store_does_not_block_a_non_escaping_slot() {
        // mov [rbp-8], rcx ; mov [rax], rdx ; mov rax, [rbp-8] ; ret
        // `rax` cannot equal the address of a non-escaping slot (that address
        // was never computed), so the foreign store cannot alias it — forward.
        let code = vec![
            0x48, 0x89, 0x4d, 0xf8, // mov [rbp-8], rcx
            0x48, 0x89, 0x10, // mov [rax], rdx
            0x48, 0x8b, 0x45, 0xf8, // mov rax, [rbp-8]
            0xc3, // ret
        ];
        let art = optimize(code);
        assert!(mem_forwarded(&art), "a foreign-base store must not block a non-escaping slot: {:#?}", art.delta);
        assert!(!has_load(&art), "the reload should forward: {:#?}", art.blocks);
    }

    #[test]
    fn a_disjoint_slot_store_does_not_block_forwarding() {
        // mov [rbp-8], rcx ; mov [rbp-16], rdx ; mov rax, [rbp-8] ; ret
        // The second store is a different, non-overlapping slot on the same
        // base — it must NOT clobber [rbp-8], so the reload still forwards.
        let code = vec![
            0x48, 0x89, 0x4d, 0xf8, // mov [rbp-8], rcx
            0x48, 0x89, 0x55, 0xf0, // mov [rbp-16], rdx
            0x48, 0x8b, 0x45, 0xf8, // mov rax, [rbp-8]
            0xc3, // ret
        ];
        let art = optimize(code);
        assert!(mem_forwarded(&art), "a disjoint slot must not block forwarding: {:#?}", art.delta);
    }

    #[test]
    fn a_param_stored_before_a_branch_forwards_at_the_join() {
        // mov [rbp-8], rcx ; if (rdx) rsi=rdx else rsi=r8 ; mov rax,[rbp-8] ; ret
        // Neither arm touches the slot, so at the join [rbp-8] still holds the
        // entry value rcx on *both* paths — the cross-block (stage 1b) forward.
        let code = vec![
            0x48, 0x89, 0x4d, 0xf8, // 0x00 mov [rbp-8], rcx
            0x48, 0x85, 0xd2, // 0x04 test rdx, rdx
            0x74, 0x05, // 0x07 je 0x0e
            0x48, 0x89, 0xd6, // 0x09 mov rsi, rdx
            0xeb, 0x03, // 0x0c jmp 0x11
            0x4c, 0x89, 0xc6, // 0x0e mov rsi, r8
            0x48, 0x8b, 0x45, 0xf8, // 0x11 mov rax, [rbp-8]
            0xc3, // 0x15 ret
        ];
        let art = optimize(code);
        assert!(mem_forwarded(&art), "the join load should forward across both arms: {:#?}", art.delta);
        assert!(!has_load(&art), "no stack load should remain at the join: {:#?}", art.blocks);
    }

    #[test]
    fn a_slot_overwritten_on_one_path_is_not_forwarded_at_the_join() {
        // mov [rbp-8], rcx ; if (rdx==0) goto join ; mov [rbp-8], rdx ; join: mov rax,[rbp-8]
        // One path leaves rcx in the slot, the other rdx — the values disagree
        // at the join (a memory-phi would be needed), so nothing is forwarded.
        let code = vec![
            0x48, 0x89, 0x4d, 0xf8, // 0x00 mov [rbp-8], rcx
            0x48, 0x85, 0xd2, // 0x04 test rdx, rdx
            0x74, 0x04, // 0x07 je 0x0d
            0x48, 0x89, 0x55, 0xf8, // 0x09 mov [rbp-8], rdx
            0x48, 0x8b, 0x45, 0xf8, // 0x0d mov rax, [rbp-8]
            0xc3, // 0x11 ret
        ];
        let art = optimize(code);
        assert!(!mem_forwarded(&art), "disagreeing values at a join must not forward: {:#?}", art.delta);
        assert!(has_load(&art), "the join load must remain a load: {:#?}", art.blocks);
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
