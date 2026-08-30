//! [`ValueSetPass`] — light value-set analysis over SSA (ROADMAP Phase 7:
//! "Value-set / light alias analysis, better jump tables, pointer reasoning").
//!
//! For each SSA variable, computes a bounded set of the concrete values it
//! could hold: a small finite [`ValueSet::Values`] when every definition
//! reaching it is a constant (or a constant expression over other tracked
//! variables), [`ValueSet::Top`] the moment *anything* is unknown (a load, a
//! call result, an unlifted instruction, a variable wider than the cap) —
//! sound-but-imprecise beats a wrong guess (CONCEPT §3 rule 6), same
//! discipline as `OptimizePass`'s constant folding, just carried across phis
//! instead of only straight-line code.
//!
//! Two concrete consumers this unlocks:
//! - **Better jump tables**: a switch index reaching a small, disjoint set of
//!   constants (e.g. merged from `idx = 0`/`idx = 1`/`idx = 2` on different
//!   branches) is now visible as *that exact set*, not just "some value
//!   bounded by the last `cmp`" (`switch.rs`'s existing, narrower bound
//!   recovery).
//! - **Pointer reasoning**: [`alias`] compares two address expressions' value
//!   sets to answer "can these two memory accesses touch the same byte" —
//!   `NoAlias` when the sets are provably disjoint, `MustAlias` when both
//!   resolve to the identical singleton, `MayAlias` (the safe default)
//!   whenever either side isn't fully known.

use std::collections::{BTreeSet, HashMap};

use n0xis_arch::{BinOp, MicroExpr, MicroStmt, UnOp};
use serde::Serialize;

use crate::ssa::SsaArtifact;
use crate::{CoreError, Ctx, Pass};

/// Cap on tracked distinct values per variable — once a merge would exceed
/// this, the analysis gives up and reports [`ValueSet::Top`] rather than
/// growing without bound (the "light" in "light alias analysis").
const MAX_TRACKED_VALUES: usize = 8;
/// Fixpoint safety bound — loop-carried values (induction variables) need a
/// few passes to converge; this caps the work regardless of CFG shape.
const MAX_ITERATIONS: usize = 20;

/// What is known about one SSA variable's possible runtime values.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", content = "values", rename_all = "snake_case")]
pub enum ValueSet {
    /// Not yet analyzed (the dataflow's identity element; never in a finished result).
    Bottom,
    /// Exactly this bounded set of possible values.
    Values(BTreeSet<i128>),
    /// Could be anything — a load, a call result, an unlifted instruction, or
    /// a merge that would exceed [`MAX_TRACKED_VALUES`].
    Top,
}

impl ValueSet {
    fn join(a: &ValueSet, b: &ValueSet) -> ValueSet {
        match (a, b) {
            (ValueSet::Bottom, x) | (x, ValueSet::Bottom) => x.clone(),
            (ValueSet::Top, _) | (_, ValueSet::Top) => ValueSet::Top,
            (ValueSet::Values(x), ValueSet::Values(y)) => {
                let merged: BTreeSet<i128> = x.union(y).copied().collect();
                if merged.len() > MAX_TRACKED_VALUES { ValueSet::Top } else { ValueSet::Values(merged) }
            }
        }
    }

    fn singleton(v: i128) -> ValueSet {
        ValueSet::Values(BTreeSet::from([v]))
    }

    /// The single concrete value, if this set is exactly one value.
    pub fn as_single(&self) -> Option<i128> {
        match self {
            ValueSet::Values(s) if s.len() == 1 => s.iter().next().copied(),
            _ => None,
        }
    }
}

/// A pairwise alias query result between two address expressions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasResult {
    /// Both addresses are provably the same value.
    MustAlias,
    /// Both addresses are known and provably disjoint.
    NoAlias,
    /// Not enough information to tell — the safe default.
    MayAlias,
}

/// Every tracked variable's value set, keyed by its SSA name (`"rax.2"`).
#[derive(Clone, Debug, Serialize)]
pub struct ValueSetArtifact {
    pub sets: HashMap<String, ValueSet>,
    /// How many fixpoint passes it took to converge (capped at
    /// [`MAX_ITERATIONS`]) — reported so a caller can tell "solved" from
    /// "gave up at the safety bound", both of which are sound outcomes.
    pub iterations: usize,
}

pub(crate) fn eval(expr: &MicroExpr, env: &HashMap<String, ValueSet>) -> ValueSet {
    match expr {
        MicroExpr::Const { value, .. } => ValueSet::singleton(*value),
        MicroExpr::Var(name) => env.get(name).cloned().unwrap_or(ValueSet::Top),
        MicroExpr::Unary(op, inner) => match eval(inner, env) {
            ValueSet::Values(vs) => {
                let mapped: BTreeSet<i128> = vs
                    .iter()
                    .map(|v| match op {
                        UnOp::Neg => v.wrapping_neg(),
                        UnOp::Not => !v,
                    })
                    .collect();
                ValueSet::Values(mapped)
            }
            other => other,
        },
        MicroExpr::Binary(op, lhs, rhs) => {
            match (eval(lhs, env), eval(rhs, env)) {
                (ValueSet::Values(ls), ValueSet::Values(rs)) => {
                    let mut out = BTreeSet::new();
                    'outer: for l in &ls {
                        for r in &rs {
                            if let Some(v) = apply_binop(*op, *l, *r) {
                                out.insert(v);
                                if out.len() > MAX_TRACKED_VALUES {
                                    out.clear();
                                    break 'outer;
                                }
                            } else {
                                return ValueSet::Top; // e.g. division by zero in this pair
                            }
                        }
                    }
                    if out.is_empty() { ValueSet::Top } else { ValueSet::Values(out) }
                }
                (ValueSet::Bottom, _) | (_, ValueSet::Bottom) => ValueSet::Bottom,
                _ => ValueSet::Top,
            }
        }
        MicroExpr::Cast { signed, bits, expr } => match eval(expr, env) {
            ValueSet::Values(vs) => ValueSet::Values(vs.iter().map(|v| truncate(*v, *bits, *signed)).collect()),
            other => other,
        },
        // A select is one of its two branches, so its value set is exactly the
        // lattice join of them — precise, and sound (never narrower than the
        // real set). The condition doesn't constrain the value here.
        MicroExpr::Select { a, b, .. } => ValueSet::join(&eval(a, env), &eval(b, env)),
        // Memory, calls, addresses-of-unknown-things, and unmodeled flags are
        // all sound-but-unknown — never guessed.
        MicroExpr::Load { .. }
        | MicroExpr::Call { .. }
        | MicroExpr::AddrOf(_)
        | MicroExpr::Compare { .. }
        | MicroExpr::OpaqueFlags { .. }
        | MicroExpr::Unknown(_) => ValueSet::Top,
    }
}

fn apply_binop(op: BinOp, l: i128, r: i128) -> Option<i128> {
    Some(match op {
        BinOp::Add => l.wrapping_add(r),
        BinOp::Sub => l.wrapping_sub(r),
        BinOp::Mul => l.wrapping_mul(r),
        BinOp::UDiv | BinOp::SDiv => {
            if r == 0 {
                return None;
            }
            l.wrapping_div(r)
        }
        BinOp::UMod | BinOp::SMod => {
            if r == 0 {
                return None;
            }
            l.wrapping_rem(r)
        }
        BinOp::And => l & r,
        BinOp::Or => l | r,
        BinOp::Xor => l ^ r,
        BinOp::Shl => l.wrapping_shl(r as u32),
        BinOp::Shr => ((l as u128).wrapping_shr(r as u32)) as i128,
        BinOp::Sar => l.wrapping_shr(r as u32),
        BinOp::Eq => (l == r) as i128,
        BinOp::Ne => (l != r) as i128,
        BinOp::Ult => ((l as u128) < (r as u128)) as i128,
        BinOp::Ule => ((l as u128) <= (r as u128)) as i128,
        BinOp::Ugt => ((l as u128) > (r as u128)) as i128,
        BinOp::Uge => ((l as u128) >= (r as u128)) as i128,
        BinOp::Slt => (l < r) as i128,
        BinOp::Sle => (l <= r) as i128,
        BinOp::Sgt => (l > r) as i128,
        BinOp::Sge => (l >= r) as i128,
    })
}

fn truncate(v: i128, bits: u32, signed: bool) -> i128 {
    if bits == 0 || bits >= 128 {
        return v;
    }
    let mask = (1i128 << bits) - 1;
    let masked = v & mask;
    if signed && (masked & (1 << (bits - 1))) != 0 {
        masked - (1 << bits)
    } else {
        masked
    }
}

/// Every `(dst, definition-expr)` pair the artifact defines, phis first
/// (their "expression" is a synthetic union of their inputs' current
/// values, computed directly rather than through `eval`).
fn step(art: &SsaArtifact, env: &mut HashMap<String, ValueSet>) -> bool {
    let mut changed = false;
    for block in &art.blocks {
        for phi in &block.phis {
            let mut merged = ValueSet::Bottom;
            for input in &phi.inputs {
                let v = env.get(&input.value).cloned().unwrap_or(ValueSet::Bottom);
                merged = ValueSet::join(&merged, &v);
            }
            let slot = env.entry(phi.dst.clone()).or_insert(ValueSet::Bottom);
            if *slot != merged {
                *slot = merged;
                changed = true;
            }
        }
        for stmt in &block.stmts {
            match &stmt.stmt {
                MicroStmt::Assign { dst, value } => {
                    let v = eval(value, env);
                    let slot = env.entry(dst.clone()).or_insert(ValueSet::Bottom);
                    if *slot != v {
                        *slot = v;
                        changed = true;
                    }
                }
                MicroStmt::Call { ret: Some(dst), .. } => {
                    let slot = env.entry(dst.clone()).or_insert(ValueSet::Bottom);
                    if *slot != ValueSet::Top {
                        *slot = ValueSet::Top;
                        changed = true;
                    }
                }
                _ => {}
            }
        }
    }
    changed
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ValueSetPass;

impl Pass for ValueSetPass {
    type In = SsaArtifact;
    type Out = ValueSetArtifact;

    fn name(&self) -> &'static str {
        "value_set"
    }

    fn run(&self, _ctx: &Ctx, art: Self::In) -> Result<Self::Out, CoreError> {
        let mut env: HashMap<String, ValueSet> = HashMap::new();
        let mut iterations = 0;
        while iterations < MAX_ITERATIONS {
            iterations += 1;
            if !step(&art, &mut env) {
                break;
            }
        }
        // Bottom means "never assigned in this function" (an incoming
        // parameter or a register we never modeled) — report as Top, the
        // same "unknown" an external caller sees.
        for v in env.values_mut() {
            if *v == ValueSet::Bottom {
                *v = ValueSet::Top;
            }
        }
        Ok(ValueSetArtifact { sets: env, iterations })
    }
}

/// Resolve one address expression to a value set using already-computed
/// `sets` — handles the common `Var(base)` and `Var(base) ± Const(off)`
/// shapes directly (the same shape `typeinfer.rs` matches for struct/field
/// recovery) without needing a second dataflow pass.
fn resolve_addr(expr: &MicroExpr, sets: &HashMap<String, ValueSet>) -> ValueSet {
    match expr {
        MicroExpr::Const { value, .. } => ValueSet::singleton(*value),
        MicroExpr::Var(name) => sets.get(name).cloned().unwrap_or(ValueSet::Top),
        MicroExpr::Binary(op @ (BinOp::Add | BinOp::Sub), lhs, rhs) => {
            match (resolve_addr(lhs, sets), resolve_addr(rhs, sets)) {
                (ValueSet::Values(ls), ValueSet::Values(rs)) => {
                    let mut out = BTreeSet::new();
                    for l in &ls {
                        for r in &rs {
                            if let Some(v) = apply_binop(*op, *l, *r) {
                                out.insert(v);
                            }
                        }
                    }
                    if out.is_empty() || out.len() > MAX_TRACKED_VALUES { ValueSet::Top } else { ValueSet::Values(out) }
                }
                _ => ValueSet::Top,
            }
        }
        _ => ValueSet::Top,
    }
}

/// Can `a` and `b` (two address expressions, e.g. a `Load`/`Store`'s `addr`)
/// touch the same memory? Conservative by construction: anything not fully
/// resolved is `MayAlias`, never guessed toward `NoAlias`.
pub fn alias(a: &MicroExpr, b: &MicroExpr, sets: &HashMap<String, ValueSet>) -> AliasResult {
    match (resolve_addr(a, sets), resolve_addr(b, sets)) {
        (ValueSet::Values(x), ValueSet::Values(y)) => {
            if x.len() == 1 && x == y {
                AliasResult::MustAlias
            } else if x.is_disjoint(&y) {
                AliasResult::NoAlias
            } else {
                AliasResult::MayAlias
            }
        }
        _ => AliasResult::MayAlias,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_contracts::Va;
    use n0xis_sources::Snapshot;
    use crate::ir::CfgPass;
    use crate::CfgInput;

    fn ssa_over(code: Vec<u8>) -> SsaArtifact {
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 64)).unwrap();
        crate::ssa::SsaPass.run(&ctx, cfg).unwrap()
    }

    #[test]
    fn straight_line_constant_propagates_through_ssa() {
        // mov eax, 5 ; add eax, 3 ; ret  ->  eax should resolve to {8}.
        let code = vec![
            0xb8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
            0x83, 0xc0, 0x03, // add eax, 3
            0xc3, // ret
        ];
        let ssa = ssa_over(code);
        let arch = X64::new();
        let snap = Snapshot::builder().region(Va(0x1000), vec![]).build();
        let ctx = Ctx::new(&snap, &arch);
        let out = ValueSetPass.run(&ctx, ssa).unwrap();
        let eax_final = out
            .sets
            .iter()
            .find(|(k, v)| k.starts_with("rax") && matches!(v, ValueSet::Values(s) if s.contains(&8)))
            .map(|(k, _)| k.clone());
        assert!(eax_final.is_some(), "expected some rax.N to resolve to {{8}}: {:#?}", out.sets);
    }

    #[test]
    fn a_loaded_value_is_unknown_not_a_guess() {
        // mov eax, [rax] ; ret — a real memory read, must never be treated as constant.
        let code = vec![0x8b, 0x00, 0xc3]; // mov eax,[rax] ; ret
        let ssa = ssa_over(code);
        let arch = X64::new();
        let snap = Snapshot::builder().region(Va(0x1000), vec![]).build();
        let ctx = Ctx::new(&snap, &arch);
        let out = ValueSetPass.run(&ctx, ssa).unwrap();
        let any_finite = out.sets.values().any(|v| matches!(v, ValueSet::Values(_)));
        assert!(!any_finite, "a load must never resolve to a finite value set: {:#?}", out.sets);
    }

    #[test]
    fn disjoint_constant_addresses_are_provably_not_aliased() {
        let mut sets = HashMap::new();
        sets.insert("a".to_string(), ValueSet::singleton(0x1000));
        sets.insert("b".to_string(), ValueSet::singleton(0x2000));
        let addr_a = MicroExpr::Var("a".to_string());
        let addr_b = MicroExpr::Var("b".to_string());
        assert_eq!(alias(&addr_a, &addr_b, &sets), AliasResult::NoAlias);
        assert_eq!(alias(&addr_a, &addr_a, &sets), AliasResult::MustAlias);
    }

    #[test]
    fn unknown_address_is_conservatively_may_alias() {
        let sets = HashMap::new();
        let a = MicroExpr::Var("unknown1".to_string());
        let b = MicroExpr::Var("unknown2".to_string());
        assert_eq!(alias(&a, &b, &sets), AliasResult::MayAlias);
    }

    #[test]
    fn base_plus_offset_addresses_resolve_and_disambiguate_fields() {
        // Same base, different constant field offsets -> NoAlias (two
        // distinct struct fields never touch the same byte); same offset ->
        // MustAlias. Mirrors typeinfer.rs's Var(base) ± Const(offset) shape.
        let mut sets = HashMap::new();
        sets.insert("base".to_string(), ValueSet::singleton(0x2000));
        let field_a = MicroExpr::binary(BinOp::Add, MicroExpr::var("base"), MicroExpr::constant(0x8, 64));
        let field_b = MicroExpr::binary(BinOp::Add, MicroExpr::var("base"), MicroExpr::constant(0x10, 64));
        assert_eq!(alias(&field_a, &field_b, &sets), AliasResult::NoAlias);
        assert_eq!(alias(&field_a, &field_a, &sets), AliasResult::MustAlias);
    }
}
