// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Whole-program type propagation** (ROADMAP Phase 10, priority 3b) — the one
//! remaining *core-decompilation* gap against another tool / another tool.
//!
//! N0xis recovers types **per function**. A `struct` recovered in one function,
//! or a class recovered from RTTI, does not reach the other functions that
//! touch the same object — so a constructor knows its argument is `Widget *`
//! while every helper it hands `this` to sees `uint64_t`. other tools keep a
//! persistent, call-graph-wide type database that binds hundreds of functions
//! into one model; this is that layer.
//!
//! One direction already existed and is easy to miss:
//! `typeinfer::user_callee_arg_types` flows a **callee's parameter types into
//! its caller's arguments**, one level, lazily. This pass adds the directions
//! that were missing and closes them under a fixpoint:
//!
//! - **caller arguments → callee parameters** — the direction that carries an
//!   RTTI-recovered class into every helper the constructor passes `this` to;
//! - **return types → their consumers** — `x = make_widget()` types `x`, which
//!   then types whatever `x` is passed to;
//! - iterated to a **fixpoint**, so a type crosses a chain of functions, not one
//!   call.
//!
//! **Structure: extract once, iterate cheaply.** The expensive part is the
//! per-function analysis (`Cfg → Ssa → Optimize → infer`); running it every
//! round would be quadratic. So each function is analyzed **once** into a
//! [`FnFacts`] — its parameter names, its locally-proven types, its call sites
//! as `(callee, argument variables, result variable)` — and the rounds then walk
//! only that constraint graph.
//!
//! **Sound over complete.** Only a *named* type propagates: a generic
//! `uint64_t` carries no information, so nothing is invented from nothing. Two
//! sources that disagree about the same slot mark it **ambiguous** and it is
//! never assigned again — a wrong type is worse than none, exactly as a wrong
//! signature name is (CONCEPT §3 rule 6). A locally-proven type always wins over
//! a propagated one; propagation only fills what local inference left generic.

use std::collections::{BTreeMap, BTreeSet};

use n0xis_arch::{CallTarget, MicroExpr, MicroStmt};
use n0xis_contracts::Va;
use serde::Serialize;

use crate::{CfgInput, CfgPass, CoreError, Ctx, OptimizePass, Pass, SsaPass, TypeInferInput, TypeInferPass};

/// Rounds are bounded: the store only ever gains information or poisons a slot,
/// so it converges, but a cap keeps a pathological graph from stalling a run.
const MAX_ROUNDS: usize = 8;

/// How far a variable is followed back through plain copies. Real chains are a
/// few links; the bound exists because a phi-shaped cycle would otherwise spin.
const MAX_COPY_DEPTH: usize = 16;

/// One call site, reduced to what propagation needs.
#[derive(Clone, Debug)]
struct CallFact {
    callee: u64,
    /// Argument variables, in order. `None` where the argument is not a plain
    /// variable (a computed expression carries no single type to move).
    args: Vec<Option<String>>,
    /// The variable the result is bound to, if any.
    ret: Option<String>,
}

/// Everything one function contributes to the constraint graph, extracted once.
#[derive(Clone, Debug)]
struct FnFacts {
    va: u64,
    /// SSA names of this function's parameters, in ABI order (`rdi.0`, …).
    param_names: Vec<String>,
    /// Locally recovered named type per parameter (`None` = generic).
    seed_params: Vec<Option<String>>,
    /// Locally recovered named type for the return value.
    seed_ret: Option<String>,
    /// Locally proven named types for individual SSA variables (recovered
    /// struct bases). These are evidence *this* function holds.
    var_seed: BTreeMap<String, String>,
    calls: Vec<CallFact>,
    /// The variable this function returns, when it returns one plainly.
    ret_var: Option<String>,
    /// Plain copies (`b = a`), so a variable can be followed back to where its
    /// value came from. **Without this the pass barely moves anything**: after
    /// optimization a call site rarely passes a parameter under its own SSA name
    /// (`rcx.0`) — it passes `rcx.3`, a copy — so the type had nothing to attach
    /// to. Measured on the Qt desktop PE: 1 propagated parameter before, and the seeds
    /// were not the problem (451 parameters carried a real class name).
    copy_of: BTreeMap<String, String>,
}

/// The whole-program type store this pass produces.
#[derive(Clone, Debug, Default, Serialize)]
pub struct TypeStore {
    /// Function VA → per-parameter named type (`None` = unknown or ambiguous).
    pub params: BTreeMap<u64, Vec<Option<String>>>,
    /// Function VA → named return type.
    pub rets: BTreeMap<u64, Option<String>>,
    /// Slots two sources disagreed about. Recorded rather than silently
    /// dropped: "we know we do not know" is a different fact from "nobody
    /// looked", and it is what stops a later round re-guessing.
    pub ambiguous_params: Vec<(u64, usize)>,
    /// Rounds run before the fixpoint settled.
    pub rounds: usize,
    /// Parameters that gained a type they did not have locally — the measure of
    /// what propagation actually bought.
    pub propagated_params: usize,
    /// Returns that gained a type they did not have locally.
    pub propagated_rets: usize,
    /// Direct call sites inside the analyzed program — the edges propagation
    /// can travel along at all.
    pub call_edges: usize,
    /// Arguments at those sites that are a plain variable (a computed
    /// expression carries no single type to move).
    pub var_arguments: usize,
    /// Arguments whose variable resolved to a type — portable or not. The gap
    /// between this and `propagated_params` is where the yield is actually
    /// lost, and it is reported rather than left to be guessed at.
    pub typed_arguments: usize,
    /// Why a typed argument did not become a propagated parameter. Reported
    /// because "the pass ran and changed almost nothing" is a claim that needs
    /// an explanation, not a shrug: each of these is a *correct* refusal, and
    /// the shape of the split says which one is worth attacking next.
    pub skipped_not_portable: usize,
    pub skipped_callee_already_proved_it: usize,
    pub skipped_no_such_parameter: usize,
}

impl TypeStore {
    /// The propagated type of parameter `index` of the function at `va`, if the
    /// whole-program pass settled on one.
    pub fn param(&self, va: u64, index: usize) -> Option<&str> {
        self.params.get(&va)?.get(index)?.as_deref()
    }
    /// The propagated return type of the function at `va`.
    pub fn ret(&self, va: u64) -> Option<&str> {
        self.rets.get(&va)?.as_deref()
    }
}

impl crate::TypeFlowLookup for TypeStore {
    fn param(&self, va: u64, index: usize) -> Option<&str> {
        TypeStore::param(self, va, index)
    }
    fn ret(&self, va: u64) -> Option<&str> {
        TypeStore::ret(self, va)
    }
}

/// Which functions form the program, and how large a window each may occupy.
pub struct TypePropInput {
    pub functions: Vec<Va>,
    pub max_bytes: usize,
}

/// Whole-program type propagation over the call graph.
#[derive(Clone, Copy, Debug, Default)]
pub struct TypePropagatePass;

impl Pass for TypePropagatePass {
    type In = TypePropInput;
    type Out = TypeStore;

    fn name(&self) -> &'static str {
        "function.typeflow"
    }

    fn run(&self, ctx: &Ctx, input: TypePropInput) -> Result<TypeStore, CoreError> {
        let known: BTreeSet<u64> = input.functions.iter().map(|v| v.0).collect();
        let facts: Vec<FnFacts> =
            input.functions.iter().filter_map(|&va| extract(ctx, va, input.max_bytes, &known)).collect();
        Ok(propagate(&facts))
    }
}

/// Analyze one function once and reduce it to its constraint-graph facts.
fn extract(ctx: &Ctx, va: Va, max_bytes: usize, known: &BTreeSet<u64>) -> Option<FnFacts> {
    let cfg = CfgPass.run(ctx, CfgInput::new(va, max_bytes)).ok()?;
    if cfg.start != va || cfg.blocks.is_empty() {
        return None;
    }
    let ssa = SsaPass.run(ctx, cfg.clone()).ok()?;
    let opt = OptimizePass.run(ctx, ssa).ok()?;
    let types = TypeInferPass.run(ctx, TypeInferInput { cfg: cfg.clone(), blocks: opt.blocks.clone() }).ok()?;

    let arg_regs = crate::typeinfer::abi_arg_regs(ctx);
    let param_names: Vec<String> = arg_regs.iter().take(types.signature.params.len()).map(|r| format!("{r}.0")).collect();
    let seed_params: Vec<Option<String>> = types.signature.params.iter().map(|p| p.ty.name.clone()).collect();
    let seed_ret = types.signature.ret.as_ref().and_then(|t| t.name.clone());
    // A recovered struct is local, concrete evidence: we saw field accesses
    // through that exact base variable.
    let var_seed: BTreeMap<String, String> =
        types.structs.iter().map(|s| (s.base_var.clone(), format!("{} *", s.type_name))).collect();

    let mut calls = Vec::new();
    let mut ret_var = None;
    let mut copy_of: BTreeMap<String, String> = BTreeMap::new();
    for block in &opt.blocks {
        for stmt in &block.stmts {
            match &stmt.stmt {
                MicroStmt::Assign { dst, value } => {
                    if let Some(src) = as_var(value) {
                        copy_of.insert(dst.clone(), src);
                    }
                }
                MicroStmt::Call { target, args, ret } => {
                    let CallTarget::Direct { va: callee } = target else { continue };
                    // Only calls *inside the analyzed program* are edges; an
                    // import has a signature library, not a recovered one.
                    if !known.contains(&callee.0) || callee.0 == va.0 {
                        continue;
                    }
                    calls.push(CallFact {
                        callee: callee.0,
                        args: args.iter().map(as_var).collect(),
                        ret: ret.clone(),
                    });
                }
                MicroStmt::Return(Some(e)) => ret_var = as_var(e).or(ret_var.take()),
                _ => {}
            }
        }
    }

    Some(FnFacts { va: va.0, param_names, seed_params, seed_ret, var_seed, calls, ret_var, copy_of })
}

/// Is this type name meaningful **outside the function that produced it**?
///
/// Two filters, both load-bearing for soundness rather than taste:
///
/// - A recovered struct is named after the register its base arrived in
///   (`struct_rdi_0`), so the name is *per-function and arbitrary*. Propagating
///   it would be bad enough on its own; worse, the ambiguity check compares
///   **names**, so two unrelated callers each holding their own `struct_rdi_0`
///   would compare *equal* and silently merge two different objects into one
///   type — a wrong answer that looks like agreement.
/// - `void *` says only "this is a pointer", which every propagation target
///   already allows. Letting it travel would let the weakest possible claim win
///   the slot first and then *conflict* with the real class that arrives later,
///   poisoning a slot that was about to be answered correctly.
///
/// Both remain perfectly good **local** types; they simply carry no
/// interprocedural information.
fn is_portable_type(name: &str) -> bool {
    !name.starts_with("struct_") && name.trim_end_matches([' ', '*']) != "void"
}

/// A plain variable reference — the only expression shape that carries a single
/// type to move. A computed expression is deliberately not typed here.
fn as_var(e: &MicroExpr) -> Option<String> {
    match e {
        MicroExpr::Var(name) => Some(name.clone()),
        _ => None,
    }
}

/// Run the constraint graph to a fixpoint.
fn propagate(facts: &[FnFacts]) -> TypeStore {
    let mut store = TypeStore::default();
    // Seed with what each function proved locally.
    for f in facts {
        store.params.insert(f.va, f.seed_params.clone());
        store.rets.insert(f.va, f.seed_ret.clone());
    }
    let locally_typed_params: usize = facts.iter().flat_map(|f| &f.seed_params).filter(|p| p.is_some()).count();
    let locally_typed_rets: usize = facts.iter().filter(|f| f.seed_ret.is_some()).count();

    // Which variable each call's result is bound to, per function — so a
    // consumer of a return value can be typed once the callee's return is.
    let ret_binding: Vec<BTreeMap<String, u64>> = facts
        .iter()
        .map(|f| f.calls.iter().filter_map(|c| c.ret.clone().map(|r| (r, c.callee))).collect())
        .collect();

    // Slots a function proved for itself. Propagation never touches these: an
    // RTTI vtable store or a field access is direct evidence about the object,
    // while a caller's claim is inference about it — and a base-class pointer
    // passed to a derived-class method is a legitimate disagreement, not a bug
    // to poison the slot over.
    let locally_proven: BTreeSet<(u64, usize)> = facts
        .iter()
        .flat_map(|f| f.seed_params.iter().enumerate().filter(|(_, t)| t.is_some()).map(move |(i, _)| (f.va, i)))
        .collect();

    let mut ambiguous: BTreeSet<(u64, usize)> = BTreeSet::new();
    let call_edges: usize = facts.iter().map(|f| f.calls.len()).sum();
    let (mut var_arguments, mut typed_arguments) = (0usize, 0usize);
    let (mut skipped_not_portable, mut skipped_callee_already_proved_it, mut skipped_no_such_parameter) = (0usize, 0usize, 0usize);
    let mut rounds = 0usize;
    loop {
        rounds += 1;
        let first_round = rounds == 1;
        let mut changed = false;

        for (fi, f) in facts.iter().enumerate() {
            // The type of a variable in `f`, from the strongest evidence
            // available: local struct proof, then this function's (possibly
            // propagated) parameter type, then a call result whose callee's
            // return type is known.
            // The best *portable* type of a variable, following plain copies back
            // to the value's origin (bounded, so a phi-shaped cycle cannot spin).
            //
            // **Order is load-bearing, and getting it wrong silently disabled the
            // whole pass.** A variable is very often BOTH a recovered struct base
            // and a class-typed parameter: `rcx.0` is `struct_rcx_0` because we
            // saw field accesses through it, *and* `Ui::RpWidget *` because RTTI
            // said so. Checking the struct first returned the synthetic name,
            // which is then correctly refused as non-portable — so the class
            // never got a chance. Measured on the Qt desktop PE: of 5 722 typed arguments,
            // **5 708** were rejected that way and exactly **1** parameter
            // propagated. The class-bearing sources are consulted first.
            let type_of = |v: &str, store: &TypeStore| -> Option<String> {
                let mut cur = v.to_string();
                for _ in 0..MAX_COPY_DEPTH {
                    let candidates = [
                        // 1. This function's parameter type — where an RTTI class
                        //    or a known-API type lives.
                        f.param_names
                            .iter()
                            .position(|p| *p == cur)
                            .and_then(|i| store.params.get(&f.va).and_then(|ps| ps.get(i)).cloned().flatten()),
                        // 2. The return type of the call this value came from.
                        ret_binding[fi].get(&cur).and_then(|c| store.rets.get(c).cloned().flatten()),
                        // 3. A locally recovered aggregate. Real evidence, but its
                        //    name is per-function — it can only win if nothing
                        //    program-wide is available, and it is filtered out at
                        //    the propagation site anyway.
                        f.var_seed.get(&cur).cloned(),
                    ];
                    if let Some(t) = candidates.iter().flatten().find(|t| is_portable_type(t)) {
                        return Some(t.clone());
                    }
                    match f.copy_of.get(&cur) {
                        Some(next) if *next != cur => cur = next.clone(),
                        // Nothing portable anywhere along the chain: report the
                        // strongest thing we did see, so the skip is counted
                        // honestly as "not portable" rather than "not typed".
                        _ => return candidates.into_iter().flatten().next(),
                    }
                }
                None
            };

            for call in &f.calls {
                for (i, arg) in call.args.iter().enumerate() {
                    let Some(var) = arg else { continue };
                    if first_round {
                        var_arguments += 1;
                    }
                    let Some(t) = type_of(var, &store) else { continue };
                    if first_round {
                        typed_arguments += 1;
                    }
                    if !is_portable_type(&t) {
                        if first_round {
                            skipped_not_portable += 1;
                        }
                        continue;
                    }
                    if ambiguous.contains(&(call.callee, i)) {
                        continue;
                    }
                    if locally_proven.contains(&(call.callee, i)) {
                        if first_round {
                            skipped_callee_already_proved_it += 1;
                        }
                        continue;
                    }
                    let Some(slots) = store.params.get_mut(&call.callee) else { continue };
                    // A callee analyzed with fewer parameters than a caller
                    // passes: do not invent a slot it does not have.
                    let Some(slot) = slots.get_mut(i) else {
                        if first_round {
                            skipped_no_such_parameter += 1;
                        }
                        continue;
                    };
                    match slot {
                        None => {
                            *slot = Some(t);
                            changed = true;
                        }
                        Some(existing) if *existing != t => {
                            // Two callers disagree — poison the slot rather than
                            // pick one. `None` again, and never revisited.
                            *slot = None;
                            ambiguous.insert((call.callee, i));
                            changed = true;
                        }
                        Some(_) => {}
                    }
                }
            }

            // This function's own return type, from the variable it returns.
            if let Some(rv) = &f.ret_var
                && store.rets.get(&f.va).map(|t| t.is_none()).unwrap_or(false)
                && let Some(t) = type_of(rv, &store)
                && is_portable_type(&t)
            {
                store.rets.insert(f.va, Some(t));
                changed = true;
            }
        }

        if !changed || rounds >= MAX_ROUNDS {
            break;
        }
    }

    let now_typed_params: usize = store.params.values().flatten().filter(|p| p.is_some()).count();
    let now_typed_rets: usize = store.rets.values().filter(|r| r.is_some()).count();
    store.rounds = rounds;
    store.propagated_params = now_typed_params.saturating_sub(locally_typed_params);
    store.propagated_rets = now_typed_rets.saturating_sub(locally_typed_rets);
    store.ambiguous_params = ambiguous.into_iter().collect();
    store.call_edges = call_edges;
    store.var_arguments = var_arguments;
    store.typed_arguments = typed_arguments;
    store.skipped_not_portable = skipped_not_portable;
    store.skipped_callee_already_proved_it = skipped_callee_already_proved_it;
    store.skipped_no_such_parameter = skipped_no_such_parameter;
    store
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(va: u64, params: Vec<Option<&str>>, calls: Vec<CallFact>) -> FnFacts {
        FnFacts {
            va,
            param_names: (0..params.len()).map(|i| format!("p{i}.0")).collect(),
            seed_params: params.iter().map(|p| p.map(str::to_string)).collect(),
            seed_ret: None,
            var_seed: BTreeMap::new(),
            calls,
            ret_var: None,
            copy_of: BTreeMap::new(),
        }
    }

    fn call(callee: u64, args: Vec<Option<&str>>) -> CallFact {
        CallFact { callee, args: args.into_iter().map(|a| a.map(str::to_string)).collect(), ret: None }
    }

    /// The main case: a constructor knows its `this` is `Widget *` from
    /// RTTI; the helper it hands `this` to knew nothing. After propagation the
    /// helper's parameter is typed — and so is the helper's own helper, which is
    /// what makes this a *fixpoint* and not a one-level lookup.
    #[test]
    fn a_class_reaches_every_helper_down_the_chain() {
        let ctor = facts(0x1000, vec![Some("Widget *")], vec![call(0x2000, vec![Some("p0.0")])]);
        let helper = facts(0x2000, vec![None], vec![call(0x3000, vec![Some("p0.0")])]);
        let deeper = facts(0x3000, vec![None], vec![]);
        let store = propagate(&[ctor, helper, deeper]);
        assert_eq!(store.param(0x2000, 0), Some("Widget *"), "one call away");
        assert_eq!(store.param(0x3000, 0), Some("Widget *"), "two calls away — the fixpoint");
        assert_eq!(store.propagated_params, 2);
        assert!(store.ambiguous_params.is_empty());
    }

    /// Two callers that disagree poison the slot. A wrong type is worse than
    /// none, and it must stay poisoned however many later rounds run.
    #[test]
    fn callers_that_disagree_leave_the_parameter_unknown() {
        let a = facts(0x1000, vec![Some("Widget *")], vec![call(0x3000, vec![Some("p0.0")])]);
        let b = facts(0x2000, vec![Some("Button *")], vec![call(0x3000, vec![Some("p0.0")])]);
        let shared = facts(0x3000, vec![None], vec![]);
        let store = propagate(&[a, b, shared]);
        assert_eq!(store.param(0x3000, 0), None, "disagreement is not resolved by picking one");
        assert_eq!(store.ambiguous_params, vec![(0x3000, 0)]);
    }

    /// A locally proven type is never overwritten *or poisoned* by a caller's
    /// claim. Local evidence (an RTTI vtable store, a field access through that
    /// exact base) is direct knowledge about the object; a caller passing a
    /// base-class pointer to a derived-class method is a legitimate
    /// disagreement, not a reason to throw the callee's own proof away.
    #[test]
    fn a_locally_proven_type_survives_a_conflicting_caller() {
        let caller = facts(0x1000, vec![Some("Widget *")], vec![call(0x2000, vec![Some("p0.0")])]);
        let callee = facts(0x2000, vec![Some("Button *")], vec![]);
        let store = propagate(&[caller, callee]);
        assert_eq!(store.param(0x2000, 0), Some("Button *"), "the callee's own proof stands");
        assert!(store.ambiguous_params.is_empty(), "this is not an ambiguity, it is a hierarchy");
    }

    /// A generic parameter carries no information, so nothing propagates from
    /// it — propagation must never manufacture a type out of "unknown".
    #[test]
    fn an_untyped_argument_propagates_nothing() {
        let caller = facts(0x1000, vec![None], vec![call(0x2000, vec![Some("p0.0")])]);
        let callee = facts(0x2000, vec![None], vec![]);
        let store = propagate(&[caller, callee]);
        assert_eq!(store.param(0x2000, 0), None);
        assert_eq!(store.propagated_params, 0);
        assert!(store.ambiguous_params.is_empty(), "unknown is not a disagreement");
    }

    /// A return type reaches its consumer, and onward into what the consumer
    /// passes it to.
    #[test]
    fn a_return_type_reaches_the_consumer_and_beyond() {
        let factory = FnFacts { seed_ret: Some("Widget *".into()), ..facts(0x1000, vec![], vec![]) };
        let user = FnFacts {
            calls: vec![
                CallFact { callee: 0x1000, args: vec![], ret: Some("rax.1".into()) },
                call(0x3000, vec![Some("rax.1")]),
            ],
            ..facts(0x2000, vec![], vec![])
        };
        let sink = facts(0x3000, vec![None], vec![]);
        let store = propagate(&[factory, user, sink]);
        assert_eq!(store.param(0x3000, 0), Some("Widget *"), "the factory's result types the sink's parameter");
    }

    /// A caller that passes more arguments than the callee recovered must not
    /// invent a slot on it.
    #[test]
    fn an_extra_argument_does_not_create_a_parameter() {
        let caller = facts(0x1000, vec![Some("Widget *"), Some("Button *")], vec![call(0x2000, vec![Some("p0.0"), Some("p1.0")])]);
        let callee = facts(0x2000, vec![None], vec![]);
        let store = propagate(&[caller, callee]);
        assert_eq!(store.params[&0x2000].len(), 1, "the callee still has one parameter");
        assert_eq!(store.param(0x2000, 0), Some("Widget *"));
    }

    /// A recovered struct's name is per-function and arbitrary
    /// (`struct_rdi_0`), so it must not travel. The danger is not noise: the
    /// ambiguity check compares names, so two unrelated callers each holding
    /// their own `struct_rdi_0` would compare EQUAL and merge two different
    /// objects into one type — a wrong answer wearing the shape of agreement.
    #[test]
    fn a_synthetic_struct_name_never_leaves_its_function() {
        let a = facts(0x1000, vec![Some("struct_rdi_0 *")], vec![call(0x3000, vec![Some("p0.0")])]);
        let b = facts(0x2000, vec![Some("struct_rdi_0 *")], vec![call(0x3000, vec![Some("p0.0")])]);
        let shared = facts(0x3000, vec![None], vec![]);
        let store = propagate(&[a, b, shared]);
        assert_eq!(store.param(0x3000, 0), None, "two arbitrary local names must not agree");
        assert!(store.ambiguous_params.is_empty(), "they never claimed anything to disagree about");
        assert_eq!(store.propagated_params, 0);
    }

    /// `void *` is the "pointer, nothing more" fallback. If it could travel it
    /// would take the slot first and then conflict with the real class arriving
    /// later, poisoning a slot that was about to be answered correctly.
    #[test]
    fn void_pointer_does_not_take_a_slot_a_real_class_is_coming_for() {
        let weak = facts(0x1000, vec![Some("void *")], vec![call(0x3000, vec![Some("p0.0")])]);
        let strong = facts(0x2000, vec![Some("Widget *")], vec![call(0x3000, vec![Some("p0.0")])]);
        let shared = facts(0x3000, vec![None], vec![]);
        let store = propagate(&[weak, strong, shared]);
        assert_eq!(store.param(0x3000, 0), Some("Widget *"));
        assert!(store.ambiguous_params.is_empty());
    }

    /// A call site almost never passes a parameter under its own SSA name after
    /// optimization — it passes a copy. Following the copy chain is what makes
    /// the pass do anything at all on real code.
    #[test]
    fn a_type_follows_a_copy_chain_to_the_call_site() {
        let mut caller = facts(0x1000, vec![Some("Widget *")], vec![call(0x2000, vec![Some("v9")])]);
        // v9 = v4 ; v4 = p0.0  — the shape the optimizer leaves behind.
        caller.copy_of.insert("v9".into(), "v4".into());
        caller.copy_of.insert("v4".into(), "p0.0".into());
        let callee = facts(0x2000, vec![None], vec![]);
        let store = propagate(&[caller, callee]);
        assert_eq!(store.param(0x2000, 0), Some("Widget *"));
    }

    /// A cyclic copy chain (what a phi looks like once flattened) must
    /// terminate, not spin.
    #[test]
    fn a_cyclic_copy_chain_terminates() {
        let mut caller = facts(0x1000, vec![None], vec![call(0x2000, vec![Some("a")])]);
        caller.copy_of.insert("a".into(), "b".into());
        caller.copy_of.insert("b".into(), "a".into());
        let callee = facts(0x2000, vec![None], vec![]);
        let store = propagate(&[caller, callee]);
        assert_eq!(store.param(0x2000, 0), None);
    }
}
