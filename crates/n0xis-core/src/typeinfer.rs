// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`TypeInferPass`] — ROADMAP Phase 4: kill the blanket `uint64_t` /
//! `local_XX` / fixed 4-arg `void sub_X(...)` signature.
//!
//! Three independent recoveries, all driven off the same optimized SSA
//! blocks (a function's `OptArtifact::blocks` or plain `SsaArtifact::blocks`
//! — this pass doesn't care which, it just needs the same block shape
//! `crate::structure` already consumes):
//!
//! - **Stack-slot coalescing**: every `Load`/`Store` address that reduces to
//!   `rsp`/`rbp` ± a constant names one [`LocalVar`], sized/signed from the
//!   union of accesses at that offset.
//! - **Struct/field recovery**: every `Load`/`Store` address that reduces to
//!   *some other* named SSA value ± a constant becomes a [`RecoveredType`] —
//!   `base->field_0x68` instead of `*(uint32_t*)(rax.1+0x68)`. This only
//!   fires on a bare `Var + Const` address shape, which is exactly what
//!   survives `OptimizePass` when a pointer is dereferenced *more than
//!   once* (a single-use pointer gets inlined into its sole consumer
//!   instead — see `optimize.rs`), so it lines up precisely with the case a
//!   human would actually call a "struct pointer".
//! - **Signature recovery**: real arity (which of `rcx.0`/`rdx.0`/`r8.0`/
//!   `r9.0` are ever read — Win64 argument registers are used positionally,
//!   so the highest used one determines arity) and return type (`void`
//!   unless some `Return` carries a value other than the untouched entry
//!   `rax.0`).
//!
//! Register-passed args only — recovering stack-passed args 5+ would need
//! precise `rsp` delta tracking through `push`/`sub rsp,N` prologues, which
//! Phase 3's lift deliberately doesn't model (no stack memory-SSA yet); that
//! stays a documented follow-on rather than a guess (CONCEPT §3 rule 6).

use std::collections::{BTreeMap, BTreeSet};

use n0xis_arch::{BinOp, Bits, CallTarget, MicroExpr, MicroStmt};
use n0xis_contracts::Va;
use serde::Serialize;

use crate::ir::CfgArtifact;
use crate::signatures::{known_signature, KnownSignature};
use crate::ssa::SsaBlock;
use crate::{Ctx, CoreError, Pass};
use crate::{CfgInput, CfgPass, OptimizePass, SsaPass};

/// A display type: either a generic width/signedness or a known name (e.g.
/// `"HANDLE"` from the signature library) — this library only needs to be
/// *readable*, not drive further structural inference.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CType {
    pub bits: Bits,
    pub signed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl CType {
    fn generic(bits: Bits, signed: bool) -> Self {
        CType { bits, signed, name: None }
    }
    pub fn named(name: impl Into<String>) -> Self {
        CType { bits: 64, signed: false, name: Some(name.into()) }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LocalVar {
    pub offset: i64,
    pub name: String,
    pub size_bits: Bits,
    pub signed: bool,
    pub access_count: usize,
    /// A user-asserted C type for this local (`annotate vartype`), rendered in the
    /// declaration verbatim over the inferred width type. `None` = use the inferred
    /// `c_type(size_bits, signed)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_override: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FieldAccess {
    pub offset: i64,
    pub size_bits: Bits,
    pub signed: bool,
    pub access_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct RecoveredType {
    /// The exact SSA name of the base pointer (e.g. `"rax.1"`).
    pub base_var: String,
    /// A synthetic anonymous type name — no debug info/headers to recover a
    /// real one from; still strictly more readable than repeating raw
    /// pointer arithmetic at every access.
    pub type_name: String,
    pub fields: Vec<FieldAccess>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ParamInfo {
    pub reg: &'static str,
    pub name: String,
    pub ty: CType,
}

#[derive(Clone, Debug, Serialize)]
pub struct RecoveredSignature {
    pub params: Vec<ParamInfo>,
    /// `None` means `void`.
    pub ret: Option<CType>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TypeArtifact {
    pub locals: Vec<LocalVar>,
    pub structs: Vec<RecoveredType>,
    pub signature: RecoveredSignature,
}

pub struct TypeInferInput {
    pub cfg: CfgArtifact,
    pub blocks: Vec<SsaBlock>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TypeInferPass;

impl Pass for TypeInferPass {
    type In = TypeInferInput;
    type Out = TypeArtifact;

    fn name(&self) -> &'static str {
        "type.infer"
    }

    fn run(&self, ctx: &Ctx, input: TypeInferInput) -> Result<TypeArtifact, CoreError> {
        Ok(infer(ctx, &input.cfg, &input.blocks))
    }
}

/// The integer argument registers of the target's ABI, in order — the fact a
/// pass must never bake in. It comes from the arch's [`CallConv`] list, and the
/// **source** declares which convention applies (`MemorySource::abi_name`:
/// `"win64"` for PE, `"sysv"` for ELF), so an ELF's parameters recover from
/// `rdi`/`rsi`/… instead of the Win64 `rcx`/`rdx`/…. Falls back to the arch's
/// first convention if the ABI name isn't found (e.g. AArch64 has only its own).
pub(crate) fn abi_arg_regs(ctx: &Ctx) -> Vec<&'static str> {
    let ccs = ctx.arch.calling_conventions();
    let cc = ccs.iter().find(|c| c.name == ctx.source.abi_name()).or_else(|| ccs.first());
    match cc {
        Some(cc) => cc.int_args.iter().filter_map(|&r| ctx.arch.regs().name(r)).collect(),
        None => Vec::new(),
    }
}

fn root(name: &str) -> &str {
    name.split('.').next().unwrap_or(name)
}

fn is_stack_root(r: &str) -> bool {
    r == "rsp" || r == "rbp"
}

/// Recognize `Var(base) + Const(offset)` (either operand order) or a bare
/// `Var(base)` (offset 0) — the one address shape both locals and struct
/// fields key off. Anything else (a nested/compound address — e.g. a call
/// inlined directly into the address by `OptimizePass`) is left alone: sound
/// to render generically, nothing meaningful to name it after.
fn as_base_offset(addr: &MicroExpr) -> Option<(String, i64)> {
    match addr {
        MicroExpr::Var(name) => Some((name.clone(), 0)),
        MicroExpr::Binary(n0xis_arch::BinOp::Add, l, r) => match (l.as_ref(), r.as_ref()) {
            (MicroExpr::Var(name), MicroExpr::Const { value, .. }) => Some((name.clone(), *value as i64)),
            (MicroExpr::Const { value, .. }, MicroExpr::Var(name)) => Some((name.clone(), *value as i64)),
            _ => None,
        },
        _ => None,
    }
}

struct MemAccess {
    base: String,
    offset: i64,
    bits: Bits,
    signed: bool,
}

/// Find every `Load` anywhere in `e`'s expression tree — not just a
/// top-level `Assign.value`. After `OptimizePass` collapses a chain, a
/// `Load` routinely ends up nested inside a `Return`/`Binary`/`Call` arg
/// (e.g. `return *(f()+0x6c) - *(f()+0x68);`), so this has to walk the whole
/// tree, not pattern-match one shape.
fn walk_loads(e: &MicroExpr, out: &mut Vec<MemAccess>) {
    match e {
        MicroExpr::Load { addr, bits, signed } => {
            if let Some((base, offset)) = as_base_offset(addr) {
                out.push(MemAccess { base, offset, bits: *bits, signed: *signed });
            }
            walk_loads(addr, out); // a computed address may itself contain a load
        }
        MicroExpr::Unary(_, v) => walk_loads(v, out),
        MicroExpr::Binary(_, l, r) => {
            walk_loads(l, out);
            walk_loads(r, out);
        }
        MicroExpr::Cast { expr, .. } => walk_loads(expr, out),
        MicroExpr::AddrOf(inner) => walk_loads(inner, out),
        MicroExpr::Compare { lhs, rhs, .. } => {
            walk_loads(lhs, out);
            walk_loads(rhs, out);
        }
        MicroExpr::Select { cond, a, b } => {
            walk_loads(cond, out);
            walk_loads(a, out);
            walk_loads(b, out);
        }
        MicroExpr::Call { target, args } => {
            if let CallTarget::Indirect(t) = target {
                walk_loads(t, out);
            }
            for a in args {
                walk_loads(a, out);
            }
        }
        MicroExpr::Var(_) | MicroExpr::Const { .. } | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => {}
    }
}

fn collect_mem_accesses(blocks: &[SsaBlock]) -> Vec<MemAccess> {
    let mut out = Vec::new();
    for b in blocks {
        for s in &b.stmts {
            match &s.stmt {
                MicroStmt::Assign { value, .. } => walk_loads(value, &mut out),
                MicroStmt::Store { addr, value, bits } => {
                    // The store's own address is itself a write access.
                    if let Some((base, offset)) = as_base_offset(addr) {
                        out.push(MemAccess { base, offset, bits: *bits, signed: false });
                    }
                    walk_loads(addr, &mut out);
                    walk_loads(value, &mut out);
                }
                MicroStmt::Call { target, args, .. } => {
                    if let CallTarget::Indirect(t) = target {
                        walk_loads(t, &mut out);
                    }
                    for a in args {
                        walk_loads(a, &mut out);
                    }
                }
                MicroStmt::Return(Some(e)) => walk_loads(e, &mut out),
                MicroStmt::Return(None) | MicroStmt::Nop | MicroStmt::Unlifted { .. } => {}
            }
        }
        if let Some(c) = &b.condition {
            walk_loads(c, &mut out);
        }
    }
    out
}

/// A binary operator whose operands the ISA treats as **signed** — a signed
/// comparison (`jl`/`jg`-family), signed division/modulo, or an arithmetic
/// (sign-propagating) right shift. A value flowing into one of these is signed,
/// which is evidence the per-access `movsx`/`movzx` encoding alone does not
/// carry (a plain `mov` load reveals nothing, but comparing that value with
/// `jl` does).
fn is_signed_use(op: BinOp) -> bool {
    matches!(op, BinOp::Slt | BinOp::Sle | BinOp::Sgt | BinOp::Sge | BinOp::SDiv | BinOp::SMod | BinOp::Sar)
}

/// Collect every stack-slot offset whose `Load` appears anywhere in `e`.
fn harvest_stack_loads(e: &MicroExpr, out: &mut BTreeSet<i64>) {
    if let MicroExpr::Load { addr, .. } = e
        && let Some((base, off)) = as_base_offset(addr)
        && is_stack_root(root(&base))
    {
        out.insert(off);
    }
    for child in expr_children(e) {
        harvest_stack_loads(child, out);
    }
}

/// The immediate sub-expressions of `e`, for a generic recursive walk.
pub(crate) fn expr_children(e: &MicroExpr) -> Vec<&MicroExpr> {
    match e {
        MicroExpr::Load { addr, .. } => vec![addr],
        MicroExpr::Unary(_, v) | MicroExpr::Cast { expr: v, .. } | MicroExpr::AddrOf(v) => vec![v],
        MicroExpr::Binary(_, l, r) | MicroExpr::Compare { lhs: l, rhs: r, .. } => vec![l, r],
        MicroExpr::Select { cond, a, b } => vec![cond, a, b],
        MicroExpr::Call { args, .. } => args.iter().collect(),
        MicroExpr::Const { .. } | MicroExpr::Var(_) | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => vec![],
    }
}

/// Mark, in `signed`, the stack-slot offsets of any `Load` used as an operand of
/// a signed operator anywhere in `e` (Rung 3/5 — signedness inferred from use).
fn mark_signed_uses(e: &MicroExpr, signed: &mut BTreeSet<i64>) {
    if let MicroExpr::Binary(op, l, r) = e
        && is_signed_use(*op)
    {
        harvest_stack_loads(l, signed);
        harvest_stack_loads(r, signed);
    }
    for child in expr_children(e) {
        mark_signed_uses(child, signed);
    }
}

/// Every stack-slot offset that a signed operator consumes — the "signed by
/// use" evidence that complements the per-access load encoding. Affects only
/// the *displayed* type of the local (the IR ops are already correctly
/// signed/unsigned), so this is a readability inference, never a soundness one.
fn collect_signed_use_offsets(blocks: &[SsaBlock]) -> BTreeSet<i64> {
    let mut signed = BTreeSet::new();
    for b in blocks {
        for s in &b.stmts {
            match &s.stmt {
                MicroStmt::Assign { value, .. } => mark_signed_uses(value, &mut signed),
                MicroStmt::Store { addr, value, .. } => {
                    mark_signed_uses(addr, &mut signed);
                    mark_signed_uses(value, &mut signed);
                }
                MicroStmt::Call { args, .. } => args.iter().for_each(|a| mark_signed_uses(a, &mut signed)),
                MicroStmt::Return(Some(e)) => mark_signed_uses(e, &mut signed),
                MicroStmt::Return(None) | MicroStmt::Nop | MicroStmt::Unlifted { .. } => {}
            }
        }
        if let Some(c) = &b.condition {
            mark_signed_uses(c, &mut signed);
        }
    }
    signed
}

fn recover_locals(accesses: &[MemAccess], signed_use: &BTreeSet<i64>) -> Vec<LocalVar> {
    let mut by_offset: BTreeMap<i64, (Bits, bool, usize)> = BTreeMap::new();
    for a in accesses {
        if !is_stack_root(root(&a.base)) {
            continue;
        }
        let entry = by_offset.entry(a.offset).or_insert((a.bits, a.signed, 0));
        entry.0 = entry.0.max(a.bits);
        entry.1 |= a.signed;
        entry.2 += 1;
    }
    by_offset
        .into_iter()
        .map(|(offset, (bits, signed, count))| LocalVar {
            offset,
            name: format!("local_{:x}", offset.unsigned_abs()),
            size_bits: bits,
            // A signed use (compared with `jl`, divided with `idiv`, …) is
            // evidence the load encoding alone misses.
            signed: signed || signed_use.contains(&offset),
            access_count: count,
            type_override: None,
        })
        .collect()
}

fn recover_structs(accesses: &[MemAccess]) -> Vec<RecoveredType> {
    let mut by_base: BTreeMap<String, BTreeMap<i64, (Bits, bool, usize)>> = BTreeMap::new();
    for a in accesses {
        if is_stack_root(root(&a.base)) {
            continue;
        }
        let fields = by_base.entry(a.base.clone()).or_default();
        let entry = fields.entry(a.offset).or_insert((a.bits, a.signed, 0));
        entry.0 = entry.0.max(a.bits);
        entry.1 |= a.signed;
        entry.2 += 1;
    }
    by_base
        .into_iter()
        .map(|(base_var, fields)| {
            let type_name = format!("struct_{}", base_var.replace('.', "_"));
            let fields = fields
                .into_iter()
                .map(|(offset, (bits, signed, count))| FieldAccess { offset, size_bits: bits, signed, access_count: count })
                .collect();
            RecoveredType { base_var, type_name, fields }
        })
        .collect()
}

/// Registers (as `<reg>.0`) used in a position that *proves* they're a real
/// incoming parameter — any use that is **not** a bare pass-through argument
/// in a call's argument list.
///
/// The lift emits all four Win64 register slots (`rcx`/`rdx`/`r8`/`r9`) as
/// arguments at *every* call, regardless of the callee's real arity — it can't
/// know the callee takes fewer. So a register that appears *only* as a bare
/// `Var` call argument is indistinguishable from that injected noise, and
/// counting it would peg every calling function at arity 4 (measured on a real
/// x64 PE: nearly every function reported 4 args, real arity 1–2). Such a register is therefore left out of the arity signal — the same
/// trimming the renderer already applies to the call *display*
/// (`render.rs::render_call`). A register used even once in a non-argument
/// position (an address base, arithmetic, a branch condition, a return, a
/// store value, or *nested* inside a call argument like `g(*rcx.0)`) is a
/// definite parameter and is counted.
///
/// Known under-count: a parameter forwarded *straight through* to an unknown
/// callee (`void f(T a){ g(a); }`) has no non-argument use and is dropped;
/// fully resolving it needs Rung 4's whole-program call-site agreement (a
/// callee's arity, learned from all its call sites, back-propagated to each
/// forwarding argument). Sound-over-complete: the forwarded value still
/// renders in the body; only the signature's arity is conservative.
fn collect_definite_param_regs(blocks: &[SsaBlock]) -> BTreeSet<String> {
    fn walk(e: &MicroExpr, out: &mut BTreeSet<String>) {
        match e {
            MicroExpr::Var(n) => {
                out.insert(n.clone());
            }
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
            MicroExpr::Select { cond, a, b } => {
                walk(cond, out);
                walk(a, out);
                walk(b, out);
            }
            MicroExpr::Call { target, args } => {
                if let CallTarget::Indirect(t) = target {
                    walk(t, out);
                }
                for a in args {
                    // A bare `Var` argument is an ambiguous pass-through (see
                    // the doc above) — skip it. Any *computed* argument uses
                    // its inner vars for real, so descend into those.
                    if !matches!(a, MicroExpr::Var(_)) {
                        walk(a, out);
                    }
                }
            }
            MicroExpr::Const { .. } | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => {}
        }
    }
    let mut out = BTreeSet::new();
    for b in blocks {
        for phi in &b.phis {
            for input in &phi.inputs {
                out.insert(input.value.clone());
            }
        }
        for s in &b.stmts {
            match &s.stmt {
                MicroStmt::Assign { value, .. } => walk(value, &mut out),
                MicroStmt::Store { addr, value, .. } => {
                    walk(addr, &mut out);
                    walk(value, &mut out);
                }
                MicroStmt::Call { target, args, .. } => {
                    if let CallTarget::Indirect(t) = target {
                        walk(t, &mut out);
                    }
                    for a in args {
                        // Same pass-through rule as the expression walker: a
                        // bare `Var` argument is ambiguous injected noise.
                        if !matches!(a, MicroExpr::Var(_)) {
                            walk(a, &mut out);
                        }
                    }
                }
                MicroStmt::Return(Some(e)) => walk(e, &mut out),
                MicroStmt::Return(None) | MicroStmt::Nop | MicroStmt::Unlifted { .. } => {}
            }
        }
        if let Some(c) = &b.condition {
            walk(c, &mut out);
        }
    }
    out
}

/// Arity = the highest **positional** argument register (in the ABI's order)
/// whose entry version is used, since argument registers are filled positionally
/// (using the 3rd implies the 1st and 2nd are real slots even if unread).
fn recover_arity(used: &BTreeSet<String>, arg_regs: &[&str]) -> usize {
    arg_regs
        .iter()
        .enumerate()
        .filter(|(_, reg)| used.contains(&format!("{reg}.0")))
        .map(|(i, _)| i + 1)
        .max()
        .unwrap_or(0)
}

fn infer_expr_type(e: &MicroExpr) -> CType {
    match e {
        MicroExpr::Load { bits, signed, .. } => CType::generic(*bits, *signed),
        MicroExpr::Const { bits, value } => CType::generic(*bits, *value < 0),
        MicroExpr::Cast { bits, signed, .. } => CType::generic(*bits, *signed),
        MicroExpr::Call { target: CallTarget::Direct { .. }, .. } => CType::generic(64, false),
        _ => CType::generic(64, false),
    }
}

/// `void` unless some `Return` carries something other than the untouched
/// entry value of `rax` — i.e. the function's lift-assumed `return rax;”
/// never got redefined, so there's nothing to return.
fn recover_return_type(blocks: &[SsaBlock], callee_ret_types: &BTreeMap<Va, &'static str>) -> Option<CType> {
    for b in blocks {
        for s in &b.stmts {
            if let MicroStmt::Return(Some(e)) = &s.stmt {
                let is_untouched_entry = matches!(e, MicroExpr::Var(n) if n == "rax.0");
                if !is_untouched_entry {
                    if let MicroExpr::Call { target: CallTarget::Direct { va }, .. } = e
                        && let Some(name) = callee_ret_types.get(va)
                    {
                        return Some(CType::named(*name));
                    }
                    return Some(infer_expr_type(e));
                }
            }
        }
    }
    None
}

fn callee_return_types(cfg: &CfgArtifact) -> BTreeMap<Va, &'static str> {
    cfg.callsites
        .iter()
        .filter_map(|c| {
            let target = c.target?;
            let name = c.target_name.as_deref()?;
            let bare = name.rsplit('!').next().unwrap_or(name);
            let sig = known_signature(bare)?;
            let ret = sig.ret?;
            Some((target, ret))
        })
        .collect()
}

/// Resolve a call's known-API signature the way the renderer does
/// (`render.rs::render_call`): a direct call by target address, an indirect
/// import call by its IAT slot address (`call qword ptr [rip+disp]` lifts to
/// `Indirect(Load(Const slot))`).
fn known_sig_for_call(
    target: &CallTarget,
    by_target: &BTreeMap<u64, &'static KnownSignature>,
    by_slot: &BTreeMap<u64, &'static KnownSignature>,
) -> Option<&'static KnownSignature> {
    match target {
        CallTarget::Direct { va } => by_target.get(&va.get()).copied(),
        CallTarget::Indirect(t) => match t.as_ref() {
            MicroExpr::Load { addr, .. } => match addr.as_ref() {
                MicroExpr::Const { value, .. } => u64::try_from(*value).ok().and_then(|slot| by_slot.get(&slot).copied()),
                _ => None,
            },
            _ => None,
        },
        // Intrinsics resolve to no callable symbol.
        CallTarget::Intrinsic(_) => None,
    }
}

/// For each SSA value passed *directly* (as a bare `Var`) to a known API, the
/// parameter type that API declares for that position — the "infer types from
/// use (known-API signatures)" half of Rung 3. A value passed as
/// `CloseHandle(hObject)` is a `HANDLE`; `CreateFileW`'s first argument is an
/// `LPCWSTR`. First hit wins: this is an advisory *display* type, not a fact
/// driving further inference (sound-over-complete keeps it out of the analysis
/// substrate).
fn param_api_types(cfg: &CfgArtifact, blocks: &[SsaBlock]) -> BTreeMap<String, &'static str> {
    let sig_by = |pick: fn(&crate::ir::Callsite) -> Option<Va>| -> BTreeMap<u64, &'static KnownSignature> {
        cfg.callsites
            .iter()
            .filter_map(|c| {
                let name = c.target_name.as_deref()?;
                let bare = name.rsplit('!').next().unwrap_or(name);
                Some((pick(c)?.get(), known_signature(bare)?))
            })
            .collect()
    };
    let by_target = sig_by(|c| c.target);
    let by_slot = sig_by(|c| c.via_slot);

    let mut out: BTreeMap<String, &'static str> = BTreeMap::new();
    let mut record = |target: &CallTarget, args: &[MicroExpr]| {
        if let Some(sig) = known_sig_for_call(target, &by_target, &by_slot) {
            for (i, a) in args.iter().enumerate() {
                if let (Some(p), MicroExpr::Var(name)) = (sig.params.get(i), a) {
                    out.entry(name.clone()).or_insert(p.type_name);
                }
            }
        }
    };

    fn walk(e: &MicroExpr, record: &mut impl FnMut(&CallTarget, &[MicroExpr])) {
        match e {
            MicroExpr::Call { target, args } => {
                record(target, args);
                if let CallTarget::Indirect(t) = target {
                    walk(t, record);
                }
                for a in args {
                    walk(a, record);
                }
            }
            MicroExpr::Load { addr, .. } => walk(addr, record),
            MicroExpr::Unary(_, v) => walk(v, record),
            MicroExpr::Binary(_, l, r) => {
                walk(l, record);
                walk(r, record);
            }
            MicroExpr::Cast { expr, .. } => walk(expr, record),
            MicroExpr::AddrOf(inner) => walk(inner, record),
            MicroExpr::Compare { lhs, rhs, .. } => {
                walk(lhs, record);
                walk(rhs, record);
            }
            MicroExpr::Select { cond, a, b } => {
                walk(cond, record);
                walk(a, record);
                walk(b, record);
            }
            MicroExpr::Var(_) | MicroExpr::Const { .. } | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => {}
        }
    }

    for b in blocks {
        for s in &b.stmts {
            match &s.stmt {
                MicroStmt::Assign { value, .. } => walk(value, &mut record),
                MicroStmt::Store { addr, value, .. } => {
                    walk(addr, &mut record);
                    walk(value, &mut record);
                }
                MicroStmt::Call { target, args, .. } => {
                    record(target, args);
                    if let CallTarget::Indirect(t) = target {
                        walk(t, &mut record);
                    }
                    for a in args {
                        walk(a, &mut record);
                    }
                }
                MicroStmt::Return(Some(e)) => walk(e, &mut record),
                MicroStmt::Return(None) | MicroStmt::Nop | MicroStmt::Unlifted { .. } => {}
            }
        }
        if let Some(c) = &b.condition {
            walk(c, &mut record);
        }
    }
    out
}

/// Map an SSA var passed as **arg 0 to a C++ member function** to that method's
/// class-pointer type — whole-program `this`-type propagation:
/// a value handed to `Class::method` *is* a `Class *`. Only non-static members
/// contribute (a free function's or static member's arg 0 is not a `this`), and
/// the callee name is resolved through the same call-site table the renderer
/// uses. First hit wins (advisory display type, sound-over-complete).
fn collect_method_this_types(cfg: &CfgArtifact, blocks: &[SsaBlock]) -> BTreeMap<String, String> {
    let name_by_target: BTreeMap<u64, &str> =
        cfg.callsites.iter().filter_map(|c| Some((c.target?.get(), c.target_name.as_deref()?))).collect();
    let name_by_slot: BTreeMap<u64, &str> =
        cfg.callsites.iter().filter_map(|c| Some((c.via_slot?.get(), c.target_name.as_deref()?))).collect();
    let callee_name = move |target: &CallTarget| -> Option<&str> {
        match target {
            CallTarget::Direct { va } => name_by_target.get(&va.get()).copied(),
            CallTarget::Indirect(inner) => match inner.as_ref() {
                MicroExpr::Load { addr, .. } => match addr.as_ref() {
                    MicroExpr::Const { value, .. } => u64::try_from(*value).ok().and_then(|s| name_by_slot.get(&s).copied()),
                    _ => None,
                },
                _ => None,
            },
            CallTarget::Intrinsic(_) => None,
        }
    };

    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut record = |target: &CallTarget, args: &[MicroExpr]| {
        if let (Some(name), Some(MicroExpr::Var(a0))) = (callee_name(target), args.first()) {
            let bare = name.rsplit('!').next().unwrap_or(name);
            if let Some(class) = crate::demangle::member_function_class(bare) {
                out.entry(a0.clone()).or_insert(format!("{class} *"));
            }
        }
    };

    fn walk(e: &MicroExpr, record: &mut impl FnMut(&CallTarget, &[MicroExpr])) {
        if let MicroExpr::Call { target, args } = e {
            record(target, args);
        }
        for child in expr_children(e) {
            walk(child, record);
        }
    }
    for b in blocks {
        for s in &b.stmts {
            match &s.stmt {
                MicroStmt::Assign { value, .. } => walk(value, &mut record),
                MicroStmt::Store { addr, value, .. } => {
                    walk(addr, &mut record);
                    walk(value, &mut record);
                }
                MicroStmt::Call { target, args, .. } => {
                    record(target, args);
                    for a in args {
                        walk(a, &mut record);
                    }
                }
                MicroStmt::Return(Some(e)) => walk(e, &mut record),
                MicroStmt::Return(None) | MicroStmt::Nop | MicroStmt::Unlifted { .. } => {}
            }
        }
        if let Some(c) = &b.condition {
            walk(c, &mut record);
        }
    }
    out
}

/// Map a register parameter's entry version (`"rcx.0"`) to the C++ class whose
/// vtable a constructor installs into `*this` — the strongest possible
/// identification of the pointer's type, and what turns `struct_rcx_0 *rcx`
/// into `icu_64::GregorianCalendar *rcx` (ROADMAP Phase 10 item 7). Detects the
/// MSVC constructor idiom `*param = &Class::vtable` in either form — the store
/// value is the vtable constant directly, or a copy of an intermediate that
/// holds it (`t = &Class::vtable; *param = t`, the shape after lifting) — using
/// the RTTI vtable→class map the frontend attached. Empty without that map.
fn constructor_vtable_params(blocks: &[SsaBlock], vtables: Option<&std::collections::HashMap<u64, String>>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(vt) = vtables else { return out };
    // A constant — bare or address-of — that equals a known vtable → its class.
    let class_of = |e: &MicroExpr| -> Option<&String> {
        let value = match e {
            MicroExpr::AddrOf(inner) => match inner.as_ref() {
                MicroExpr::Const { value, .. } => *value,
                _ => return None,
            },
            MicroExpr::Const { value, .. } => *value,
            _ => return None,
        };
        vt.get(&u64::try_from(value).ok()?)
    };
    // SSA var ← a materialized vtable address (the copied-form intermediate).
    let mut var_class: BTreeMap<&str, &String> = BTreeMap::new();
    for b in blocks {
        for s in &b.stmts {
            if let MicroStmt::Assign { dst, value } = &s.stmt
                && let Some(c) = class_of(value)
            {
                var_class.insert(dst.as_str(), c);
            }
        }
    }
    // A store of such an address to offset 0 of a parameter's *entry* version
    // (`*rcx.0 = &Class::vtable`) types that parameter as the class. Keying on
    // the `.0` version keeps it to the incoming pointer — a later, reassigned
    // version storing a vtable is a different object, not this parameter.
    for b in blocks {
        for s in &b.stmts {
            if let MicroStmt::Store { addr, value, .. } = &s.stmt
                && let Some((base, 0)) = as_base_offset(addr)
                && base.ends_with(".0")
            {
                let class = class_of(value).or_else(|| match value {
                    MicroExpr::Var(x) => var_class.get(x.as_str()).copied(),
                    _ => None,
                });
                if let Some(c) = class {
                    out.insert(base, c.clone());
                }
            }
        }
    }
    out
}

/// Grow `ptrs` with every SSA value that a known pointer was copied or phi'd
/// from: the source of a pointer-valued copy, and each operand of a
/// pointer-valued phi, is itself a pointer. Iterated to a fixpoint over plain
/// `dst = Var(src)` copies and `dst = phi(srcs)` phis, so pointer-ness reaches
/// back through a loop-carried copy to the parameter it came from. Only sources
/// of already-known pointers are added, so nothing unrelated is ever widened.
fn propagate_pointerness(blocks: &[SsaBlock], ptrs: &mut BTreeSet<String>) {
    // def -> its source SSA vars (copy source, or every phi operand).
    let mut sources: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for b in blocks {
        for phi in &b.phis {
            sources.entry(phi.dst.clone()).or_default().extend(phi.inputs.iter().map(|i| i.value.clone()));
        }
        for s in &b.stmts {
            if let MicroStmt::Assign { dst, value: MicroExpr::Var(src) } = &s.stmt {
                sources.entry(dst.clone()).or_default().push(src.clone());
            }
        }
    }
    let mut work: Vec<String> = ptrs.iter().cloned().collect();
    while let Some(v) = work.pop() {
        if let Some(srcs) = sources.get(&v) {
            for s in srcs.clone() {
                if ptrs.insert(s.clone()) {
                    work.push(s);
                }
            }
        }
    }
}

/// The class of the function being analyzed, when its **own name** says it is a
/// member of one — so `this` is typed in an ordinary method, not only in a
/// constructor.
///
/// This is the seed the whole class model was missing. Before it, a `this`
/// pointer was typed only where the function *stored a vtable into it* (a
/// constructor) or where some callee's name identified it. An ordinary method —
/// which is where virtual calls are actually made — got `struct_rcx_0 *`.
/// Measured on the Qt desktop PE before this existed: **0 of 399** functions had a
/// class-typed parameter, while 48 of them made an indirect call, so
/// devirtualization had nothing to look a vtable up by.
///
/// The name test is [`crate::classlayout::this_class_of`] — one implementation
/// shared with the layout pass, so a class the signature claims and a class the
/// layout files fields under can never disagree. It reads the **demangled**
/// name: an ELF symbol table hands out `_ZNK7QPixmap6isNullEv`, in which no
/// `Class::method` test matches anything at all, and for a long time that left
/// this seed firing only on the names N0xis's own vtable walk had synthesized —
/// 69 of them on `libQt6Gui.so.6`, against 9 782 mangled method symbols sitting
/// unread in the same table.
///
/// On top of the name, one **ABI** fact that a name cannot give, and which
/// decides *which argument* is `this`: a function returning a large object by
/// value gets the caller's result buffer in the first argument register, and
/// `this` moves to the second. `QTextDocument::toPlainText() const` is spelled
/// exactly like an ordinary const method. So the answer is a class **and an
/// argument index** — 0 normally, 1 when the x64 ABI's marker for that hidden
/// return slot is present ([`crate::classlayout::returns_first_arg`]).
///
/// Naming the shifted argument rather than giving up is worth a population, not
/// a handful: every by-value getter — `pixmap()`, `toImage()`, `text()` — is
/// this shape, and refusing them threw the class away for the whole function,
/// including for the virtual calls it makes on `this`.
pub(crate) fn own_this_class(ctx: &Ctx, start: Va, blocks: &[SsaBlock], arg_regs: &[&str]) -> Option<(String, usize)> {
    let class = crate::classlayout::this_class_of(ctx, start)?;
    Some((class, crate::classlayout::this_arg_index(blocks, arg_regs)))
}

/// Every source of evidence about a parameter's type, gathered once per
/// function. A struct rather than nine arguments: the precedence ladder in
/// [`param_ctype`] is the interesting part, and burying it under a parameter
/// list nobody can read at a glance is how a precedence bug hides.
struct ParamEvidence<'a> {
    ctor_classes: &'a BTreeMap<String, String>,
    method_classes: &'a BTreeMap<String, String>,
    ptr_bases: &'a BTreeSet<&'a str>,
    struct_map: &'a BTreeMap<&'a str, &'a str>,
    api: &'a BTreeMap<String, String>,
    flow: &'a BTreeMap<String, String>,
    /// The class this function is a member of, when its own name says so.
    own_class: Option<&'a str>,
    /// The SSA name of the `this` parameter — the only one `own_class` types.
    this_param: &'a str,
}

/// The display type of one register parameter, inferred from how it is used —
/// the "recover typed variables from use" half of Rung 3, for the signature.
/// Precedence is by strength of evidence:
/// 0. a **constructor-installed vtable class** (`*this = &Class::vtable` — the
///    definitive identity of the object, RTTI item 7),
/// 1. a **C++ member-function `this`** (passed as arg 0 to `Class::method` — the
///    class is named ground truth, and beats a synthesized `struct_`; the
///    function's own class, [`own_this_class`], ranks alongside it),
/// 2. a **recovered struct pointer** (we saw concrete field accesses through
///    it — a local proof it's a pointer-to-aggregate),
/// 3. a **known-API argument type** (`HANDLE`, `LPCWSTR`, `DWORD`, …),
/// 4. a plain **`void *`** when the value is dereferenced but no struct/API
///    evidence pins a better type,
/// 5. otherwise the generic `uint64_t` (unchanged from before).
fn param_ctype(pname: &str, ev: &ParamEvidence<'_>) -> CType {
    let (ctor_classes, method_classes, ptr_bases, struct_map, api, flow, own_class, this_param) =
        (ev.ctor_classes, ev.method_classes, ev.ptr_bases, ev.struct_map, ev.api, ev.flow, ev.own_class, ev.this_param);
    if let Some(class) = ctor_classes.get(pname) {
        return CType::named(format!("{class} *"));
    }
    if let Some(ty) = method_classes.get(pname) {
        return CType::named(ty.clone());
    }
    // 1b. This function's OWN class, when its name says it is a member of one.
    //     Applies to the first parameter only — `this` — and ranks with the
    //     other name-derived class evidence.
    //
    //     Raising it *above* `method_classes` was tried and measured, on the
    //     base-vs-derived argument that a derived method calls its base's
    //     methods on the very same `this`. On `libQt6Gui` it moved nothing:
    //     `QRasterPlatformPixmap`'s methods already type `this` as the derived
    //     class either way. It is not in.
    if let Some(class) = own_class.filter(|_| pname == this_param) {
        return CType::named(format!("{class} *"));
    }
    if let Some(sty) = struct_map.get(pname) {
        return CType::named(format!("{sty} *"));
    }
    if let Some(t) = api.get(pname) {
        return CType::named(t.clone());
    }
    // 4. A type the WHOLE-PROGRAM pass propagated into this parameter. Ranked
    //    here on purpose: every source above is something *this* function
    //    proved about itself, and local proof outranks inference from callers.
    //    Ranked above `void *` because "a `Ui::RpWidget *`" is strictly more
    //    than "a pointer".
    if let Some(t) = flow.get(pname) {
        return CType::named(t.clone());
    }
    if ptr_bases.contains(pname) {
        return CType::named("void *");
    }
    CType::generic(64, false)
}

/// The byte window scanned when analyzing a callee's signature — generously
/// function-sized. A larger callee just yields a less-complete signature, never
/// an error.
const CALLEE_SCAN_SIZE: usize = 16 * 1024;

/// Recover a called function's parameter types by analyzing it *shallowly* (no
/// further interprocedural recursion — one level deep). `None` if its bytes do
/// not form an analyzable function at `va`.
/// Process memo for [`callee_param_types`].
///
/// Decompiling ONE function analyses **every** callee — a full
/// `Cfg→Ssa→Optimize→infer` each — and the de-dup cache in
/// [`user_callee_arg_types`] is local to a single decompile. So browsing
/// re-analysed the same callees (`malloc`, Qt template helpers, …) over and over:
/// profiling a warm session showed `user_callee_arg_types` plus instruction
/// decoding dominating the per-view cost.
///
/// The result is a pure function of the callee address and the analysis context,
/// so it is cached per `(context identity, va)`. The identity folds the source
/// label, the symbol fingerprint (a rename can change a matched known signature)
/// and the vtable-map size — exactly the inputs that can move a parameter type —
/// so a stale entry can never outlive a change that would alter it. Same
/// discipline as the IR cache and the vtable memo.
type CalleeTypesMemo = Option<(String, std::collections::HashMap<u64, Option<Vec<CType>>>)>;
static CALLEE_TYPES: std::sync::Mutex<CalleeTypesMemo> = std::sync::Mutex::new(None);
/// Bound on memo entries — one per distinct callee. A ceiling keeps a
/// pathological target from growing this without limit (the OOM discipline);
/// past it we simply stop adding and keep serving what is already cached.
const CALLEE_TYPES_MAX: usize = 200_000;

/// The inputs that can change a callee's inferred parameter types.
fn ctx_identity(ctx: &Ctx) -> String {
    format!(
        "{}|{}|{}",
        ctx.source.label(),
        ctx.symbols.map(|s| s.symbol_fingerprint()).unwrap_or_default(),
        ctx.vtables.map_or(0, |v| v.len()),
    )
}

/// [`callee_param_types`] served from the process memo (see [`CALLEE_TYPES`]).
fn callee_param_types_memo(ctx: &Ctx, va: Va) -> Option<Vec<CType>> {
    let id = ctx_identity(ctx);
    if let Ok(memo) = CALLEE_TYPES.lock()
        && let Some((cached_id, map)) = memo.as_ref()
        && *cached_id == id
        && let Some(hit) = map.get(&va.0)
    {
        return hit.clone();
    }
    let computed = callee_param_types(ctx, va);
    if let Ok(mut memo) = CALLEE_TYPES.lock() {
        match memo.as_mut() {
            // Same context: extend, up to the ceiling.
            Some((cached_id, map)) if *cached_id == id => {
                if map.len() < CALLEE_TYPES_MAX {
                    map.insert(va.0, computed.clone());
                }
            }
            // Context changed (or first use): start a fresh table.
            _ => {
                let mut map = std::collections::HashMap::new();
                map.insert(va.0, computed.clone());
                *memo = Some((id, map));
            }
        }
    }
    computed
}

fn callee_param_types(ctx: &Ctx, va: Va) -> Option<Vec<CType>> {
    let cfg = CfgPass.run(ctx, CfgInput::new(va, CALLEE_SCAN_SIZE)).ok()?;
    if cfg.start != va {
        return None;
    }
    let ssa = SsaPass.run(ctx, cfg.clone()).ok()?;
    let opt = OptimizePass.run(ctx, ssa).ok()?;
    let types = infer_with(ctx, &cfg, &opt.blocks, false);
    Some(types.signature.params.iter().map(|p| p.ty.clone()).collect())
}

/// Whole-program propagation: for each argument this function passes to a *user*
/// callee (a direct call that is not a known API and not itself), the specific
/// (named) type that callee recovered for the matching parameter. Only named
/// types cross — a generic `uint64_t` parameter carries no information — so the
/// caller's argument is never mistyped. Each callee is analyzed once and cached.
fn user_callee_arg_types(ctx: &Ctx, cfg: &CfgArtifact, blocks: &[SsaBlock]) -> BTreeMap<String, String> {
    let known_targets: BTreeSet<Va> = cfg
        .callsites
        .iter()
        .filter_map(|c| {
            let bare = c.target_name.as_deref()?.rsplit('!').next().unwrap_or_default();
            known_signature(bare).and(c.target)
        })
        .collect();

    let mut cache: BTreeMap<Va, Option<Vec<CType>>> = BTreeMap::new();
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut record = |target: &CallTarget, args: &[MicroExpr]| {
        let CallTarget::Direct { va } = target else { return };
        if *va == cfg.start || known_targets.contains(va) {
            return;
        }
        let ptypes = cache.entry(*va).or_insert_with(|| callee_param_types_memo(ctx, *va)).clone();
        let Some(ptypes) = ptypes else { return };
        for (i, a) in args.iter().enumerate() {
            if let (MicroExpr::Var(v), Some(cty)) = (a, ptypes.get(i))
                && let Some(tn) = &cty.name
            {
                // A synthesized `struct_<reg>_N` name is local to the callee's
                // own analysis and meaningless in the caller — carry only the
                // pointer-ness across as `void *`. A real class name (RTTI) or a
                // known-API type is portable and propagates verbatim.
                let ty = if tn.starts_with("struct_") { "void *".to_string() } else { tn.clone() };
                out.entry(v.clone()).or_insert(ty);
            }
        }
    };

    fn walk(e: &MicroExpr, record: &mut impl FnMut(&CallTarget, &[MicroExpr])) {
        match e {
            MicroExpr::Call { target, args } => {
                record(target, args);
                if let CallTarget::Indirect(t) = target {
                    walk(t, record);
                }
                args.iter().for_each(|a| walk(a, record));
            }
            MicroExpr::Load { addr, .. } => walk(addr, record),
            MicroExpr::Unary(_, v) | MicroExpr::Cast { expr: v, .. } | MicroExpr::AddrOf(v) => walk(v, record),
            MicroExpr::Binary(_, l, r) | MicroExpr::Compare { lhs: l, rhs: r, .. } => {
                walk(l, record);
                walk(r, record);
            }
            MicroExpr::Select { cond, a, b } => {
                walk(cond, record);
                walk(a, record);
                walk(b, record);
            }
            _ => {}
        }
    }

    for b in blocks {
        for s in &b.stmts {
            match &s.stmt {
                MicroStmt::Call { target, args, .. } => {
                    record(target, args);
                    args.iter().for_each(|a| walk(a, &mut record));
                }
                MicroStmt::Assign { value, .. } => walk(value, &mut record),
                MicroStmt::Store { addr, value, .. } => {
                    walk(addr, &mut record);
                    walk(value, &mut record);
                }
                MicroStmt::Return(Some(e)) => walk(e, &mut record),
                _ => {}
            }
        }
    }
    out
}

fn infer(ctx: &Ctx, cfg: &CfgArtifact, blocks: &[SsaBlock]) -> TypeArtifact {
    // Top-level analysis is interprocedural (`deep`): it consults the recovered
    // signatures of the user functions this one calls. A callee analyzed for that
    // purpose runs shallow (`deep = false`) so the walk never recurses.
    infer_with(ctx, cfg, blocks, true)
}

fn infer_with(ctx: &Ctx, cfg: &CfgArtifact, blocks: &[SsaBlock], deep: bool) -> TypeArtifact {
    let accesses = collect_mem_accesses(blocks);
    let signed_use = collect_signed_use_offsets(blocks);
    let locals = recover_locals(&accesses, &signed_use);
    let structs = recover_structs(&accesses);

    let arg_regs = abi_arg_regs(ctx);
    let used = collect_definite_param_regs(blocks);
    let arity = recover_arity(&used, &arg_regs);
    let struct_map: BTreeMap<&str, &str> = structs.iter().map(|s| (s.base_var.as_str(), s.type_name.as_str())).collect();
    // A dereferenced value is a pointer, and so is anything it was *copied from*.
    // Propagate that backward through plain copies and phi operands to a fixpoint,
    // so a parameter whose pointer reaches a dereference only after a copy (and,
    // through a loop, a phi) — `rbx = buf; … while … rbx->f` — is still recovered
    // as a pointer rather than a raw `uint64_t`. Sound: each step only ever marks
    // a *source* of an already-known pointer, never widens an unrelated value.
    let mut ptr_owned: BTreeSet<String> = accesses.iter().map(|a| a.base.clone()).collect();
    propagate_pointerness(blocks, &mut ptr_owned);
    let ptr_bases: BTreeSet<&str> = ptr_owned.iter().map(String::as_str).collect();
    // Known-API argument types, plus — for the interprocedural pass — the
    // parameter types of the *user* functions this one calls: whole-program type
    // propagation across the call boundary (a callee that takes a `void *` types
    // the caller's argument `void *`). A known signature wins on conflict.
    let mut api_types: BTreeMap<String, String> = param_api_types(cfg, blocks).into_iter().map(|(k, v)| (k, v.to_string())).collect();
    if deep {
        for (var, ty) in user_callee_arg_types(ctx, cfg, blocks) {
            api_types.entry(var).or_insert(ty);
        }
    }
    let ctor_classes = constructor_vtable_params(blocks, ctx.vtables.map(|v| v.as_ref()));
    let method_classes = collect_method_this_types(cfg, blocks);
    // Whole-program propagated types for THIS function's parameters, keyed the
    // same way local evidence is (`rcx.0`), so `param_ctype` reads one shape.
    let flow_types: BTreeMap<String, String> = match ctx.type_flow {
        Some(f) => (0..arity)
            .filter_map(|i| {
                let reg = arg_regs.get(i)?;
                f.param(cfg.start.0, i).map(|t| (format!("{reg}.0"), t.to_string()))
            })
            .collect(),
        None => BTreeMap::new(),
    };
    // `this` is an ABI argument register — the first one, or the second when the
    // function returns a large object by value; a member function's own class
    // types that parameter and no other.
    let own = own_this_class(ctx, cfg.start, blocks, &arg_regs);
    let this_param = arg_regs.get(own.as_ref().map_or(0, |(_, i)| *i)).map(|r| format!("{r}.0")).unwrap_or_default();
    let own_class = own.map(|(c, _)| c);
    let evidence = ParamEvidence {
        ctor_classes: &ctor_classes,
        method_classes: &method_classes,
        ptr_bases: &ptr_bases,
        struct_map: &struct_map,
        api: &api_types,
        flow: &flow_types,
        own_class: own_class.as_deref(),
        this_param: &this_param,
    };
    let params = arg_regs[..arity]
        .iter()
        .map(|&reg| {
            let pname = format!("{reg}.0");
            ParamInfo {
                reg,
                name: reg.to_string(),
                ty: param_ctype(&pname, &evidence),
            }
        })
        .collect();

    let callee_rets = callee_return_types(cfg);
    let ret = recover_return_type(blocks, &callee_rets);

    TypeArtifact { locals, structs, signature: RecoveredSignature { params, ret } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CfgInput, CfgPass, OptimizePass, SsaPass};
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    fn infer_code(code: Vec<u8>) -> TypeArtifact {
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 128)).unwrap();
        let ssa = SsaPass.run(&ctx, cfg.clone()).unwrap();
        let opt = OptimizePass.run(&ctx, ssa).unwrap();
        TypeInferPass.run(&ctx, TypeInferInput { cfg, blocks: opt.blocks }).unwrap()
    }

    #[test]
    fn a_parameter_inherits_its_pointer_type_from_the_user_callee_it_is_passed_to() {
        // Caller @0x1000 reads rcx (arg0), guards it, and passes it to a callee
        // that dereferences it — so the callee recovers a pointer parameter, and
        // whole-program propagation must type the caller's own rcx a pointer even
        // though the caller never dereferences it itself.
        let code = vec![
            0x48, 0x85, 0xC9, // 0x1000 test rcx, rcx      (rcx is read → a parameter)
            0x74, 0x05, // 0x1003 jz 0x100A
            0xE8, 0x01, 0x00, 0x00, 0x00, // 0x1005 call 0x100B (the callee)
            0xC3, // 0x100A ret
            0x48, 0x8B, 0x01, // 0x100B mov rax, [rcx]     (callee dereferences rcx)
            0xC3, // 0x100E ret
        ];
        let types = infer_code(code);
        assert_eq!(
            types.signature.params.first().and_then(|p| p.ty.name.as_deref()),
            Some("void *"),
            "the caller's rcx must inherit the callee's pointer parameter type: {:?}",
            types.signature.params,
        );
    }

    #[test]
    fn pointerness_flows_back_through_a_copy_and_a_phi_to_the_parameter() {
        use crate::ssa::{Phi, PhiInput, SsaBlock, SsaStmt};
        use n0xis_arch::{MicroExpr, MicroStmt};
        let blk = |id, stmts, phis| SsaBlock {
            id,
            start: Va(0x1000 + id as u64 * 0x10),
            end: Va(0x1000 + id as u64 * 0x10 + 0x8),
            terminator: "ret".into(),
            successors: Vec::new(),
            phis,
            stmts,
            condition: None,
        };
        let assign = |dst: &str, src: &str| SsaStmt {
            va: Va(0x1000),
            stmt: MicroStmt::Assign { dst: dst.into(), value: MicroExpr::var(src) },
        };
        // rbx.2 = rsi.0 ; rbx.9 = φ(rbx.2, rbx.3) ; *(rbx.9) accessed → rbx.9 is
        // the pointer base. Pointer-ness must reach rbx.2 (phi operand) then
        // rsi.0 (copy source).
        let blocks = vec![
            blk(0, vec![assign("rbx.2", "rsi.0")], vec![]),
            blk(1, vec![], vec![Phi { var: "rbx".into(), dst: "rbx.9".into(), inputs: vec![PhiInput { from_block: 0, value: "rbx.2".into() }, PhiInput { from_block: 1, value: "rbx.3".into() }] }]),
        ];
        let mut ptrs: BTreeSet<String> = ["rbx.9".to_string()].into_iter().collect();
        propagate_pointerness(&blocks, &mut ptrs);
        assert!(ptrs.contains("rbx.2"), "pointer-ness must reach the phi operand");
        assert!(ptrs.contains("rsi.0"), "and back through the copy to the parameter");
        // A value unrelated to the pointer chain is never marked.
        assert!(!ptrs.contains("rdx.0"));
    }

    fn block_with(stmts: Vec<MicroStmt>) -> SsaBlock {
        SsaBlock {
            id: 0,
            start: Va(0x1000),
            end: Va(0x1010),
            terminator: "ret".to_string(),
            successors: vec![],
            phis: vec![],
            stmts: stmts.into_iter().map(|stmt| crate::ssa::SsaStmt { va: Va(0x1000), stmt }).collect(),
            condition: None,
        }
    }

    #[test]
    fn a_constructor_vtable_store_types_this_as_the_class() {
        // Both idiom forms: inlined (`*rcx.0 = &Class::vtable`) and copied
        // (`t = &Class::vtable; *rdx.0 = t`), plus the copied form for the
        // AddrOf-wrapped constant the lift actually produces for a `lea`.
        let mut vt = std::collections::HashMap::new();
        vt.insert(0x180021548u64, "std::exception".to_string());
        vt.insert(0x147ccc5f8u64, "icu_64::GregorianCalendar".to_string());

        let inlined = block_with(vec![MicroStmt::Store {
            addr: MicroExpr::var("rcx.0"),
            value: MicroExpr::AddrOf(Box::new(MicroExpr::constant(0x180021548, 64))),
            bits: 64,
        }]);
        let copied = block_with(vec![
            MicroStmt::Assign { dst: "rax.2".into(), value: MicroExpr::AddrOf(Box::new(MicroExpr::constant(0x147ccc5f8, 64))) },
            MicroStmt::Store { addr: MicroExpr::var("rdx.0"), value: MicroExpr::var("rax.2"), bits: 64 },
        ]);

        let m = constructor_vtable_params(&[inlined, copied], Some(&vt));
        assert_eq!(m.get("rcx.0").map(String::as_str), Some("std::exception"));
        assert_eq!(m.get("rdx.0").map(String::as_str), Some("icu_64::GregorianCalendar"));
        // Precedence: the ctor class beats a recovered `struct_rcx_0`.
        let struct_map: BTreeMap<&str, &str> = [("rcx.0", "struct_rcx_0")].into_iter().collect();
        let (no_map, no_set) = (BTreeMap::new(), BTreeSet::new());
        let ty = param_ctype(
            "rcx.0",
            &ParamEvidence {
                ctor_classes: &m,
                method_classes: &no_map,
                ptr_bases: &no_set,
                struct_map: &struct_map,
                api: &no_map,
                flow: &no_map,
                own_class: None,
                this_param: "rcx.0",
            },
        );
        assert_eq!(ty.name.as_deref(), Some("std::exception *"));
    }

    #[test]
    fn a_stack_local_compared_signed_is_inferred_signed() {
        // A local at [rsp+8] loaded and compared with a signed `<` (`jl`). Even
        // with an unsigned load encoding, the signed comparison makes it signed.
        let load = || MicroExpr::load(MicroExpr::binary(BinOp::Add, MicroExpr::var("rsp"), MicroExpr::constant(8, 64)), 32, false);
        let mut blk = block_with(vec![]);
        blk.condition = Some(MicroExpr::binary(BinOp::Slt, load(), MicroExpr::constant(0, 32)));
        let signed = collect_signed_use_offsets(std::slice::from_ref(&blk));
        assert!(signed.contains(&8), "offset 8 should be flagged signed by its `<` use: {signed:?}");
        // An *unsigned* comparison of a different slot must not flag it.
        let mut ublk = block_with(vec![]);
        ublk.condition = Some(MicroExpr::binary(
            BinOp::Ult,
            MicroExpr::load(MicroExpr::binary(BinOp::Add, MicroExpr::var("rsp"), MicroExpr::constant(0x10, 64)), 32, false),
            MicroExpr::constant(0, 32),
        ));
        assert!(collect_signed_use_offsets(std::slice::from_ref(&ublk)).is_empty());
        // recover_locals honors the signed-use set even for an unsigned access.
        let acc = vec![MemAccess { base: "rsp".into(), offset: 8, bits: 32, signed: false }];
        let locals = recover_locals(&acc, &signed);
        assert_eq!(locals.len(), 1);
        assert!(locals[0].signed, "the compared-signed local should render signed");
    }

    #[test]
    fn a_non_vtable_store_and_a_missing_map_leave_the_type_untouched() {
        // Soundness: a store of an ordinary constant, or no RTTI map at all,
        // yields no class typing — the parameter types exactly as before.
        let mut vt = std::collections::HashMap::new();
        vt.insert(0x180021548u64, "std::exception".to_string());
        // A store to `*rcx.0` of a value that is NOT a vtable.
        let non_vtable = block_with(vec![MicroStmt::Store {
            addr: MicroExpr::var("rcx.0"),
            value: MicroExpr::constant(0x1234, 64),
            bits: 64,
        }]);
        assert!(constructor_vtable_params(std::slice::from_ref(&non_vtable), Some(&vt)).is_empty());
        // A real vtable store but with no map attached → still empty.
        let vtable_store = block_with(vec![MicroStmt::Store {
            addr: MicroExpr::var("rcx.0"),
            value: MicroExpr::AddrOf(Box::new(MicroExpr::constant(0x180021548, 64))),
            bits: 64,
        }]);
        assert!(constructor_vtable_params(&[vtable_store], None).is_empty());
    }

    #[test]
    fn coalesces_two_accesses_at_the_same_stack_offset_into_one_local() {
        // A store (8-byte) then a differently-sized load (4-byte) of the same
        // slot: mov [rsp+0x8], rcx ; mov eax, [rsp+0x8] ; ret
        // The width mismatch means the reload cannot be store-to-load forwarded
        // (so the load survives and the store stays live — not dead-eliminated),
        // giving two observable accesses at offset 8 to coalesce into one local.
        // (A same-width spill/reload is now fully forwarded and dead-eliminated,
        // which is the intended Memory-SSA behaviour — it is no longer a local.)
        let code = vec![
            0x48, 0x89, 0x4c, 0x24, 0x08, // mov [rsp+8], rcx
            0x8b, 0x44, 0x24, 0x08, // mov eax, [rsp+8]
            0xc3,
        ];
        let art = infer_code(code);
        assert_eq!(art.locals.len(), 1, "{:#?}", art.locals);
        assert_eq!(art.locals[0].offset, 8);
        assert_eq!(art.locals[0].access_count, 2);
    }

    #[test]
    fn recovers_a_struct_pointer_with_two_fields() {
        // call +0 ; mov rdx,[rax+0x68] ; mov rcx,[rax+0x6c] ; sub rcx,rdx ; mov rax,rcx ; ret
        let code = vec![
            0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x50, 0x68, 0x48, 0x8B, 0x48, 0x6C, 0x48, 0x29, 0xD1, 0x48, 0x89, 0xC8, 0xC3,
        ];
        let art = infer_code(code);
        assert_eq!(art.structs.len(), 1, "{:#?}", art.structs);
        let s = &art.structs[0];
        assert_eq!(s.base_var, "rax.1");
        let offsets: Vec<i64> = s.fields.iter().map(|f| f.offset).collect();
        assert!(offsets.contains(&0x68) && offsets.contains(&0x6c), "{offsets:?}");
    }

    #[test]
    fn recovers_real_arity_from_which_arg_registers_are_read() {
        // Only rcx and r8 are ever read (rdx is skipped, r9 unused) -> arity
        // must still be 3 (r8 is the 3rd Win64 int arg; ABI can't "skip" rdx).
        // mov rax, rcx ; add rax, r8 ; ret
        let code = vec![0x48, 0x89, 0xC8, 0x4C, 0x01, 0xC0, 0xC3];
        let art = infer_code(code);
        assert_eq!(art.signature.params.len(), 3, "{:#?}", art.signature.params);
    }

    #[test]
    fn a_register_only_forwarded_as_a_call_argument_is_not_a_parameter() {
        // mov rdx, [rcx] ; call +0 ; ret
        // `rcx` is a real pointer parameter (dereferenced, and the loaded value
        // survives as a *computed* call argument, so it isn't DCE'd). The lift
        // forwards all four Win64 arg registers (rcx/rdx/r8/r9) into the call as
        // bare pass-throughs, but only rcx's dereference is a real use — the
        // rest are the fixed 4-register call convention's injected noise, not
        // real parameters. Arity must be 1, not the old fixed 4.
        let code = vec![
            0x48, 0x8B, 0x11, // mov rdx, [rcx]
            0xE8, 0x00, 0x00, 0x00, 0x00, // call +0
            0xC3, // ret
        ];
        let art = infer_code(code);
        assert_eq!(art.signature.params.len(), 1, "{:#?}", art.signature.params);
        assert_eq!(art.signature.params[0].reg, "rcx");
    }

    #[test]
    fn a_register_used_in_a_real_position_is_counted_even_when_also_forwarded() {
        // and rcx, 1 ; mov rax, rcx ; call +0 ; ret
        // rcx is used in real arithmetic *and* forwarded as a call arg — the
        // real use must win, keeping it a parameter.
        let code = vec![
            0x48, 0x83, 0xE1, 0x01, // and rcx, 1
            0x48, 0x89, 0xC8, // mov rax, rcx
            0xE8, 0x00, 0x00, 0x00, 0x00, // call +0
            0xC3, // ret
        ];
        let art = infer_code(code);
        assert!(!art.signature.params.is_empty(), "rcx used in real arithmetic must stay a param: {:#?}", art.signature.params);
        assert_eq!(art.signature.params[0].reg, "rcx");
    }

    #[test]
    fn a_dereferenced_pointer_parameter_is_typed_as_a_struct_pointer() {
        // mov rdx, [rcx+8] ; mov rax, [rcx+0x10] ; add rax, rdx ; ret
        // rcx is dereferenced at two offsets -> a recovered struct, and it is
        // the first parameter, so its signature type is `struct_rcx_0 *`, not
        // the generic `uint64_t`.
        let code = vec![
            0x48, 0x8B, 0x51, 0x08, // mov rdx, [rcx+8]
            0x48, 0x8B, 0x41, 0x10, // mov rax, [rcx+0x10]
            0x48, 0x01, 0xD0, // add rax, rdx
            0xC3, // ret
        ];
        let art = infer_code(code);
        assert_eq!(art.signature.params[0].reg, "rcx");
        assert_eq!(art.signature.params[0].ty.name.as_deref(), Some("struct_rcx_0 *"), "{:#?}", art.signature.params[0].ty);
    }

    #[test]
    fn param_type_precedence_prefers_struct_then_api_then_flow_then_void_pointer() {
        // Unit-level check of the evidence precedence in `param_ctype`, so the
        // known-API-argument path (which needs a real import table to fire
        // end-to-end, hence not exercised by the byte-level tests above) is
        // still covered: struct evidence > known-API type > a WHOLE-PROGRAM
        // propagated type > bare `void *` dereference > generic `uint64_t`.
        //
        // The propagated type sits below every local source deliberately: those
        // are things this function proved about *itself*, while a propagated
        // type is inferred from its callers.
        let structs: BTreeMap<&str, &str> = [("rcx.0", "struct_rcx_0")].into_iter().collect();
        let api: BTreeMap<String, String> = [("rdx.0".to_string(), "HANDLE".to_string()), ("rcx.0".to_string(), "LPVOID".to_string())].into_iter().collect();
        let flow: BTreeMap<String, String> =
            [("rcx.0".to_string(), "Widget *".to_string()), ("rdx.0".to_string(), "Button *".to_string()), ("r8.0".to_string(), "QImage *".to_string())]
                .into_iter()
                .collect();
        let ptr: BTreeSet<&str> = ["rcx.0", "r8.0"].into_iter().collect();
        let no_ctor = BTreeMap::new();
        let no_method = BTreeMap::new();
        // rcx: deref'd struct *and* an API hit *and* a propagated type -> struct wins.
        assert_eq!(param_ctype("rcx.0", &ParamEvidence { ctor_classes: &no_ctor, method_classes: &no_method, ptr_bases: &ptr, struct_map: &structs, api: &api, flow: &flow, own_class: None, this_param: "rcx.0" }).name.as_deref(), Some("struct_rcx_0 *"));
        // rdx: an API hit outranks a propagated type.
        assert_eq!(param_ctype("rdx.0", &ParamEvidence { ctor_classes: &no_ctor, method_classes: &no_method, ptr_bases: &ptr, struct_map: &structs, api: &api, flow: &flow, own_class: None, this_param: "rcx.0" }).name.as_deref(), Some("HANDLE"));
        // r8: dereferenced, no local name — the propagated class beats `void *`,
        // because "a QImage *" is strictly more than "a pointer".
        assert_eq!(param_ctype("r8.0", &ParamEvidence { ctor_classes: &no_ctor, method_classes: &no_method, ptr_bases: &ptr, struct_map: &structs, api: &api, flow: &flow, own_class: None, this_param: "rcx.0" }).name.as_deref(), Some("QImage *"));
        // …and with nothing propagated it is still `void *`.
        assert_eq!(param_ctype("r8.0", &ParamEvidence { ctor_classes: &no_ctor, method_classes: &no_method, ptr_bases: &ptr, struct_map: &structs, api: &api, flow: &BTreeMap::new(), own_class: None, this_param: "rcx.0" }).name.as_deref(), Some("void *"));
        // r9: no evidence at all -> generic (name None, renders uint64_t).
        assert_eq!(param_ctype("r9.0", &ParamEvidence { ctor_classes: &no_ctor, method_classes: &no_method, ptr_bases: &ptr, struct_map: &structs, api: &api, flow: &flow, own_class: None, this_param: "rcx.0" }).name, None);
    }

    #[test]
    fn a_function_that_never_touches_rax_is_void() {
        // mov [rsp+8], rcx ; ret  -- writes a local, never assigns rax.
        let code = vec![0x48, 0x89, 0x4c, 0x24, 0x08, 0xc3];
        let art = infer_code(code);
        assert!(art.signature.ret.is_none(), "{:#?}", art.signature.ret);
    }

    #[test]
    fn a_function_that_computes_rax_has_a_typed_return() {
        let code = vec![
            0x48, 0x83, 0xc0, 0x03, // add rax, 3   (writes rax from the entry value)
            0xc3,
        ];
        let art = infer_code(code);
        assert!(art.signature.ret.is_some(), "{:#?}", art.signature.ret);
    }
}
