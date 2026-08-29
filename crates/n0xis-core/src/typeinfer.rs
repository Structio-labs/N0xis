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

use n0xis_arch::{Bits, CallTarget, MicroExpr, MicroStmt};
use n0xis_contracts::Va;
use serde::Serialize;

use crate::ir::CfgArtifact;
use crate::signatures::known_signature;
use crate::ssa::SsaBlock;
use crate::{Ctx, CoreError, Pass};

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
    fn named(name: impl Into<String>) -> Self {
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

    fn run(&self, _ctx: &Ctx, input: TypeInferInput) -> Result<TypeArtifact, CoreError> {
        Ok(infer(&input.cfg, &input.blocks))
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

fn recover_locals(accesses: &[MemAccess]) -> Vec<LocalVar> {
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
            signed,
            access_count: count,
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

fn collect_used_vars(blocks: &[SsaBlock]) -> BTreeSet<String> {
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
            MicroExpr::Call { target, args } => {
                if let CallTarget::Indirect(t) = target {
                    walk(t, out);
                }
                for a in args {
                    walk(a, out);
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
                        walk(a, &mut out);
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

const WIN64_INT_ARGS: [&str; 4] = ["rcx", "rdx", "r8", "r9"];

fn recover_arity(used: &BTreeSet<String>) -> usize {
    WIN64_INT_ARGS
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

fn infer(cfg: &CfgArtifact, blocks: &[SsaBlock]) -> TypeArtifact {
    let accesses = collect_mem_accesses(blocks);
    let locals = recover_locals(&accesses);
    let structs = recover_structs(&accesses);

    let used = collect_used_vars(blocks);
    let arity = recover_arity(&used);
    let params = WIN64_INT_ARGS[..arity]
        .iter()
        .map(|reg| ParamInfo { reg, name: reg.to_string(), ty: CType::generic(64, false) })
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
