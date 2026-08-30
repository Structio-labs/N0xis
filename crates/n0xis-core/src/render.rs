//! Typed-expression → pseudo-C text. Shared by every `decomp pseudo` style
//! (`goto` / `structured` / `ssa`) — they differ in *which* IR they render
//! (raw lift, SSA, or SSA+optimized) and whether a structuring pass ran, not
//! in how a [`MicroExpr`] becomes text. One renderer, one place bugs get
//! fixed (CONCEPT §3 rule 3).

use std::collections::HashMap;

use n0xis_arch::{BinOp, CallTarget, MicroExpr, MicroStmt, UnOp, FLAGS_VAR};
use n0xis_contracts::Va;

use crate::demangle::demangle;
use crate::ir::Callsite;
use crate::signatures::{known_signature, KnownSignature};
use crate::typeinfer::TypeArtifact;

/// Resolves a call target address to a human name, when known (from the
/// function's own `CfgArtifact::callsites`, which already went through the
/// symbol seam — the renderer itself never touches `Ctx`), plus (Phase 4)
/// recovered locals/struct fields and whether the function is `void`. All
/// optional: a `RenderNames` with no [`Self::with_types`] call behaves
/// exactly as it did before Phase 4 (ad hoc `local_XX` naming, generic
/// `*(type*)(addr)` field access, `return rax;` always shown).
pub struct RenderNames {
    callee_names: HashMap<u64, String>,
    /// IAT-slot address → the import reached through it. Separate from
    /// `callee_names` because the key is a *pointer to* the callee, not the
    /// callee — conflating the two would name a function by the address of a
    /// variable holding its address.
    slot_names: HashMap<u64, String>,
    locals: HashMap<i64, String>,
    structs: HashMap<String, ()>,
    /// A recovered parameter's entry SSA version (`"rcx.0"`) → its parameter
    /// name (`"rcx"`). The `.0` version of a register is uniquely its incoming
    /// value — i.e. the parameter itself — so rendering it under the parameter
    /// name (dropping the redundant `.0`) connects the body to the signature
    /// without conflating anything: `rcx.1`/`rcx.2` keep their subscripts, and
    /// there is never a bare `rcx` for this to collide with.
    param_names: HashMap<String, String>,
    void_return: bool,
}

impl RenderNames {
    pub fn new(callsites: &[Callsite]) -> Self {
        let callee_names = callsites
            .iter()
            .filter_map(|c| Some((c.target?.get(), c.target_name.clone()?)))
            .collect();
        let slot_names = callsites
            .iter()
            .filter_map(|c| Some((c.via_slot?.get(), c.target_name.clone()?)))
            .collect();
        RenderNames {
            callee_names,
            slot_names,
            locals: HashMap::new(),
            structs: HashMap::new(),
            param_names: HashMap::new(),
            void_return: false,
        }
    }

    /// Enrich with Phase 4's recovered locals/struct-fields/signature.
    pub fn with_types(mut self, types: &TypeArtifact) -> Self {
        self.locals = types.locals.iter().map(|l| (l.offset, l.name.clone())).collect();
        self.structs = types.structs.iter().map(|s| (s.base_var.clone(), ())).collect();
        self.param_names = types.signature.params.iter().map(|p| (format!("{}.0", p.reg), p.name.clone())).collect();
        self.void_return = types.signature.ret.is_none();
        self
    }

    /// Replace the variable-display map with the full SSA-coalescing result
    /// (Rung 3b): it maps each coalesced version and each parameter entry
    /// version to its single display name, and *subsumes* the parameter naming
    /// [`Self::with_types`] set. Applied only for the optimized (`ssa`) style,
    /// which is the one whose IR the coalescing was computed against.
    pub fn with_coalescing(mut self, var_names: HashMap<String, String>) -> Self {
        self.param_names = var_names;
        self
    }

    fn callee(&self, va: Va) -> String {
        match self.callee_names.get(&va.get()) {
            Some(name) => render_callee_name(name),
            None => format!("sub_{:x}", va.get()),
        }
    }

    /// A variable's display name: a recovered parameter's entry version
    /// (`"rcx.0"`) renders as the parameter name (`"rcx"`), everything else
    /// unchanged. Single source of truth so every render site — bare `Var`,
    /// struct-field base, store target — agrees.
    fn display_var(&self, name: &str) -> String {
        self.param_names.get(name).cloned().unwrap_or_else(|| name.to_string())
    }

    /// The known-API signature for a direct call target, if its resolved
    /// name (bare, `module!` prefix stripped) is in the signature library.
    fn known_sig_for(&self, va: Va) -> Option<&'static KnownSignature> {
        let name = self.callee_names.get(&va.get())?;
        let bare = name.rsplit('!').next().unwrap_or(name);
        known_signature(bare)
    }
}

/// `kernel32!CreateFileW` -> `kernel32__CreateFileW` (a valid C identifier).
/// The module half is a real file name, so it can carry characters C can't
/// (`KERNEL32.dll`, and every API-set forwarder — `api-ms-win-core-*.dll`);
/// anything outside `[A-Za-z0-9_]` becomes `_` so the rendered text stays
/// pseudo-**C**, not pseudo-C-with-arithmetic-in-the-callee.
fn mangle_call_name(name: &str) -> String {
    name.replace('!', "__")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

/// A resolved callee name as it should appear in pseudo-C. A demangled
/// C++/Rust name (`Foo::bar<T>`) is shown as-is — real decompilers don't
/// C-identifier-sanitize these, and doing so would throw away the readability
/// win. Only a plain `module!function` import name gets the identifier-safe
/// `!` -> `__` treatment.
pub(crate) fn render_callee_name(name: &str) -> String {
    let demangled = demangle(name);
    if demangled != *name { demangled } else { mangle_call_name(name) }
}

/// The slot address of a call made *through memory* — the `CallTarget` shape
/// the lifter produces for `call`/`jmp qword ptr [rip+disp]`: a load from a
/// constant address. Mirrors `x64_lift::call_target`'s RIP-relative arm; any
/// other indirect shape (a register, a computed address) has no static slot.
fn as_slot_call(target: &CallTarget) -> Option<u64> {
    let CallTarget::Indirect(expr) = target else { return None };
    match expr.as_ref() {
        MicroExpr::Load { addr, .. } => match addr.as_ref() {
            MicroExpr::Const { value, .. } => u64::try_from(*value).ok(),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn c_type(bits: n0xis_arch::Bits, signed: bool) -> &'static str {
    match (bits, signed) {
        (1 | 8, false) => "uint8_t",
        (1 | 8, true) => "int8_t",
        (16, false) => "uint16_t",
        (16, true) => "int16_t",
        (32, false) => "uint32_t",
        (32, true) => "int32_t",
        (64, true) => "int64_t",
        _ => "uint64_t",
    }
}

/// A pre-SSA or post-SSA variable name is "the flags bookkeeping var" if it's
/// `"flags"` with an optional `.N` version suffix stripped.
fn is_flags_var(name: &str) -> bool {
    name.split('.').next() == Some(FLAGS_VAR)
}

/// Recognize `base + k` (or bare `base`), the one address shape stack locals
/// and struct fields both key off (see `typeinfer.rs::as_base_offset`, the
/// same pattern by construction — single source of truth for what counts as
/// "nameable").
fn as_base_offset(addr: &MicroExpr) -> Option<(&str, i128)> {
    match addr {
        MicroExpr::Var(name) => Some((name.as_str(), 0)),
        MicroExpr::Binary(BinOp::Add, l, r) => match (l.as_ref(), r.as_ref()) {
            (MicroExpr::Var(name), MicroExpr::Const { value, .. }) => Some((name.as_str(), *value)),
            (MicroExpr::Const { value, .. }, MicroExpr::Var(name)) => Some((name.as_str(), *value)),
            _ => None,
        },
        _ => None,
    }
}

fn is_stack_root(root: &str) -> bool {
    root == "rsp" || root == "rbp"
}

/// The display text for a `Load`/`Store` address when it resolves to a named
/// local (`local_18`) or a recovered struct field (`base->field_0x68`) —
/// `None` if the address doesn't match that shape at all, in which case the
/// caller falls back to the generic `*(type*)(addr)` rendering. Stack-local
/// naming works even without [`RenderNames::with_types`] (same ad hoc
/// `local_XX` scheme `typeinfer.rs` also produces, so the two never
/// disagree); struct-field naming only fires once [`TypeArtifact`] recovered
/// that base pointer.
fn field_or_local_text(addr: &MicroExpr, names: &RenderNames) -> Option<String> {
    let (base, offset) = as_base_offset(addr)?;
    let root = base.split('.').next().unwrap_or(base);
    if is_stack_root(root) {
        let name = names.locals.get(&(offset as i64)).cloned().unwrap_or_else(|| format!("local_{:x}", offset.unsigned_abs()));
        return Some(name);
    }
    if names.structs.contains_key(base) {
        let base = names.display_var(base);
        return Some(if offset == 0 { format!("*{base}") } else { format!("{base}->field_0x{offset:x}") });
    }
    None
}

fn render_const(value: i128, bits: n0xis_arch::Bits) -> String {
    if value < 0 {
        format!("-0x{:x}", value.unsigned_abs())
    } else {
        let mask = if bits == 0 || bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 };
        format!("0x{:x}", (value as u128) & mask)
    }
}

fn cmp_op_text(op: BinOp) -> &'static str {
    match op {
        BinOp::Eq => "==",
        BinOp::Ne => "!=",
        BinOp::Ult => "< /*u*/",
        BinOp::Ule => "<= /*u*/",
        BinOp::Ugt => "> /*u*/",
        BinOp::Uge => ">= /*u*/",
        BinOp::Slt => "<",
        BinOp::Sle => "<=",
        BinOp::Sgt => ">",
        BinOp::Sge => ">=",
        _ => "?",
    }
}

fn bin_op_text(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::UDiv | BinOp::SDiv => "/",
        BinOp::UMod | BinOp::SMod => "%",
        BinOp::And => "&",
        BinOp::Or => "|",
        BinOp::Xor => "^",
        BinOp::Shl => "<<",
        BinOp::Shr | BinOp::Sar => ">>",
        _ => cmp_op_text(op),
    }
}

/// Recognize the stack-canary XOR: `x ^ <stack-pointer>` (either operand
/// order). The compiler's stack protector is the *only* thing that XORs a
/// value with the raw stack pointer — a load of `__security_cookie` XORed with
/// `rsp` on function entry (`mov rax, cookie; xor rax, rsp`) and the frame
/// copy XORed with `rsp` again before the epilogue check. No legitimate
/// arithmetic ever does this, so matching on a stack-pointer XOR operand is a
/// sound recognizer (it cannot misfire on real code). Returns the *other*
/// operand — the value being guarded — so the caller can render the idiom by
/// name instead of as opaque arithmetic on a mystery global.
fn stack_guard_operand<'a>(l: &'a MicroExpr, r: &'a MicroExpr) -> Option<&'a MicroExpr> {
    let is_stack_ptr = |e: &MicroExpr| matches!(e, MicroExpr::Var(name) if is_stack_root(name.split('.').next().unwrap_or(name)));
    if is_stack_ptr(r) {
        Some(l)
    } else if is_stack_ptr(l) {
        Some(r)
    } else {
        None
    }
}

fn is_comparison(op: BinOp) -> bool {
    matches!(
        op,
        BinOp::Eq | BinOp::Ne | BinOp::Ult | BinOp::Ule | BinOp::Ugt | BinOp::Uge | BinOp::Slt | BinOp::Sle | BinOp::Sgt | BinOp::Sge
    )
}

pub fn render_expr(e: &MicroExpr, names: &RenderNames) -> String {
    match e {
        MicroExpr::Const { value, bits } => render_const(*value, *bits),
        MicroExpr::Var(name) => names.display_var(name),
        MicroExpr::Load { addr, bits, signed } => {
            if let Some(text) = field_or_local_text(addr, names) {
                return text;
            }
            format!("*({}*)({})", c_type(*bits, *signed), render_expr(addr, names))
        }
        MicroExpr::Unary(UnOp::Neg, v) => format!("-{}", render_expr(v, names)),
        MicroExpr::Unary(UnOp::Not, v) => format!("~{}", render_expr(v, names)),
        MicroExpr::Binary(BinOp::Xor, l, r) if stack_guard_operand(l, r).is_some() => {
            let guarded = stack_guard_operand(l, r).expect("just checked is_some");
            format!("__stack_guard({})", render_expr(guarded, names))
        }
        MicroExpr::Binary(op, l, r) => {
            format!("({} {} {})", render_expr(l, names), bin_op_text(*op), render_expr(r, names))
        }
        MicroExpr::Cast { signed, bits, expr } => format!("({}){}", c_type(*bits, *signed), render_expr(expr, names)),
        MicroExpr::AddrOf(inner) => match inner.as_ref() {
            MicroExpr::Const { value, .. } => format!("(void*)0x{:x}", *value as u64),
            other => format!("&{}", render_expr(other, names)),
        },
        MicroExpr::Compare { kind, lhs, rhs } => {
            // Only reachable if a Compare survives un-consumed by
            // `Arch::branch_condition` (e.g. a dead flags def) — a sound
            // fallback, not the normal rendering path for a condition.
            format!("/*{:?}({}, {})*/", kind, render_expr(lhs, names), render_expr(rhs, names))
        }
        MicroExpr::OpaqueFlags { mnemonic } => format!("/*flags after {mnemonic}*/"),
        MicroExpr::Call { target, args } => render_call(target, args, names),
        MicroExpr::Unknown(s) => format!("/*{s}*/"),
    }
}

/// Renders a call (direct or indirect), consulting the known-signature
/// library (Phase 4) to trim the generic 4-register arg list down to the
/// real arity and name each argument inline, and to cast the result to a
/// known return type (`(HANDLE)CreateFileW(...)`) when known. Falls back to
/// the plain 4-arg rendering when the callee isn't in the library — sound,
/// just less pretty.
/// A call argument that is lift padding: the bare entry value (`rN.0`) of a
/// register that is not a recovered parameter of the current function. Such a
/// value is the uninitialized incoming register, injected only because the
/// Win64 lift passes four argument registers at every call — never a real
/// argument. A recovered parameter's entry version is in `param_names` (the
/// coalescing/parameter map), so it is *not* padding.
fn is_padding_arg(a: &MicroExpr, names: &RenderNames) -> bool {
    matches!(a, MicroExpr::Var(n) if n.ends_with(".0") && !names.param_names.contains_key(n))
}

fn render_call(target: &CallTarget, args: &[MicroExpr], names: &RenderNames) -> String {
    // An indirect call through a *known* slot (`call qword ptr [rip+disp]` to
    // an import) is only syntactically indirect: the callee has a name, and
    // printing `(*(uint64_t*)(0x14002a3e8))(...)` instead of
    // `kernel32__CloseHandle(...)` throws away information the CFG already
    // resolved — and blocks the known-API signature lookup that gives the
    // call typed parameter names.
    let slot = as_slot_call(target).and_then(|slot| names.slot_names.get(&slot));
    let callee = match (slot, target) {
        (Some(name), _) => render_callee_name(name),
        (None, CallTarget::Direct { va }) => names.callee(*va),
        (None, CallTarget::Indirect(t)) => format!("(*{})", render_expr(t, names)),
    };
    let known = match (slot, target) {
        (Some(name), _) => known_signature(name.rsplit('!').next().unwrap_or(name)),
        (None, CallTarget::Direct { va }) => names.known_sig_for(*va),
        (None, CallTarget::Indirect(_)) => None,
    };
    let args_text = match known {
        Some(sig) => {
            let n = sig.params.len().min(args.len());
            args[..n]
                .iter()
                .zip(sig.params.iter())
                .map(|(a, p)| format!("/*{}*/ {}", p.name, render_expr(a, names)))
                .collect::<Vec<_>>()
                .join(", ")
        }
        None => {
            // Drop trailing lift-padding arguments. The Win64 lift passes all
            // four argument registers (rcx/rdx/r8/r9) at *every* call — it can't
            // know the callee's arity — so a **trailing** argument that is the
            // bare entry value (`rN.0`) of a register this function neither
            // takes as a parameter nor ever writes is padding, not a real
            // argument (it's the uninitialized incoming register). Only trailing
            // padding is dropped, and only bare non-parameter entry values, so a
            // genuine forwarded value or any computed argument is always kept.
            let keep = args.iter().rposition(|a| !is_padding_arg(a, names)).map_or(0, |i| i + 1);
            args[..keep].iter().map(|a| render_expr(a, names)).collect::<Vec<_>>().join(", ")
        }
    };
    let call = format!("{callee}({args_text})");
    match known.and_then(|s| s.ret) {
        Some(type_name) => format!("({type_name}){call}"),
        None => call,
    }
}

/// The exact condition text for a `cjmp` block's terminator. `is_comparison`
/// determines whether extra parens are needed; kept simple since
/// `render_expr` already wraps every `Binary`.
pub fn render_condition(e: &MicroExpr, names: &RenderNames) -> String {
    render_expr(e, names)
}

/// A statement that's pure bookkeeping for soundness (flags dataflow,
/// call-clobber invalidation) and not something a human wrote — dropped from
/// the *text* rendering only; the underlying artifact still carries it for
/// anyone inspecting the JSON.
fn is_noise(stmt: &MicroStmt) -> bool {
    match stmt {
        MicroStmt::Assign { dst, value } => {
            is_flags_var(dst) || matches!(value, MicroExpr::Unknown(s) if s == "call-clobbered")
        }
        MicroStmt::Nop => true,
        _ => false,
    }
}

/// Render one statement to a pseudo-C line, or `None` if it's noise / a nop.
pub fn render_stmt(stmt: &MicroStmt, names: &RenderNames) -> Option<String> {
    if is_noise(stmt) {
        return None;
    }
    Some(match stmt {
        MicroStmt::Assign { dst, value } => format!("{} = {};", names.display_var(dst), render_expr(value, names)),
        MicroStmt::Store { addr, value, bits } => {
            if let Some(text) = field_or_local_text(addr, names) {
                format!("{text} = {};", render_expr(value, names))
            } else {
                format!("*({}*)({}) = {};", c_type(*bits, false), render_expr(addr, names), render_expr(value, names))
            }
        }
        MicroStmt::Call { target, args, ret } => {
            let call = render_call(target, args, names);
            match ret {
                Some(r) => format!("{} = {call};", names.display_var(r)),
                None => format!("{call};"),
            }
        }
        MicroStmt::Return(Some(e)) => {
            // A `void` function's `ret` still reads `rax` (our lift always
            // models it that way — see x64_lift.rs), but if `rax` was never
            // otherwise defined, that's the *untouched entry value*, not a
            // real return value: `TypeInferPass` marks the signature `void`
            // in exactly that case, so drop the meaningless `return rax.0;`.
            if names.void_return && matches!(e, MicroExpr::Var(n) if n == "rax.0") {
                "return;".to_string()
            } else {
                format!("return {};", render_expr(e, names))
            }
        }
        MicroStmt::Return(None) => "return;".to_string(),
        MicroStmt::Nop => return None,
        MicroStmt::Unlifted { text, .. } => format!("// asm: {text}"),
    })
}

/// Structural negation of an already-rendered condition *expression* (not
/// text) — used by the structuring pass when it needs `!cond` for a
/// `while`/`do-while` whose natural exit arm is the "true" edge. Negating the
/// typed expression (rather than string-munging rendered text, as v0 did)
/// means the result renders through the exact same `render_expr` path.
pub fn negate_condition(e: &MicroExpr) -> MicroExpr {
    match e {
        MicroExpr::Binary(op, l, r) if is_comparison(*op) => {
            let negated = match *op {
                BinOp::Eq => BinOp::Ne,
                BinOp::Ne => BinOp::Eq,
                BinOp::Ult => BinOp::Uge,
                BinOp::Uge => BinOp::Ult,
                BinOp::Ule => BinOp::Ugt,
                BinOp::Ugt => BinOp::Ule,
                BinOp::Slt => BinOp::Sge,
                BinOp::Sge => BinOp::Slt,
                BinOp::Sle => BinOp::Sgt,
                BinOp::Sgt => BinOp::Sle,
                other => other,
            };
            MicroExpr::Binary(negated, l.clone(), r.clone())
        }
        other => MicroExpr::Unary(UnOp::Not, Box::new(other.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_field_load_through_a_call_result() {
        let names = RenderNames::new(&[]);
        let expr = MicroExpr::load(
            MicroExpr::binary(
                BinOp::Add,
                MicroExpr::Call { target: CallTarget::Direct { va: Va(0x1000) }, args: vec![] },
                MicroExpr::constant(0x68, 64),
            ),
            32,
            false,
        );
        assert_eq!(render_expr(&expr, &names), "*(uint32_t*)((sub_1000() + 0x68))");
    }

    #[test]
    fn stack_relative_load_renders_as_a_local() {
        let names = RenderNames::new(&[]);
        let expr = MicroExpr::load(MicroExpr::binary(BinOp::Add, MicroExpr::var("rsp"), MicroExpr::constant(0x20, 64)), 64, false);
        assert_eq!(render_expr(&expr, &names), "local_20");
    }

    #[test]
    fn a_known_win32_call_gets_named_trimmed_args_and_a_typed_cast() {
        let callsites = vec![Callsite {
            from: Va(0x2000),
            kind: "named".to_string(),
            target: Some(Va(0x3000)),
            target_name: Some("kernel32!CloseHandle".to_string()),
            via_slot: None,
        }];
        let names = RenderNames::new(&callsites);
        // The lift always passes all 4 register slots positionally;
        // `CloseHandle` only takes one — the extra 3 must be trimmed, not
        // shown as noise, and the known `HANDLE` param should be named.
        let call = MicroExpr::Call {
            target: CallTarget::Direct { va: Va(0x3000) },
            args: vec![MicroExpr::var("rcx.0"), MicroExpr::var("rdx.0"), MicroExpr::var("r8.0"), MicroExpr::var("r9.0")],
        };
        let text = render_expr(&call, &names);
        assert_eq!(text, "(BOOL)kernel32__CloseHandle(/*hObject*/ rcx.0)");
    }

    /// The same import called the way real code calls it — through its IAT
    /// slot — must read identically. Before the slot was carried on the
    /// callsite this rendered `(*(uint64_t*)(0x3000))(rcx.0, rdx.0, …)`:
    /// syntactically honest, but it hid a name the CFG had already resolved
    /// and skipped the known-signature arg trimming.
    #[test]
    fn an_import_called_through_its_iat_slot_is_named_like_a_direct_call() {
        let callsites = vec![Callsite {
            from: Va(0x2000),
            kind: "named".to_string(),
            target: None,
            target_name: Some("kernel32!CloseHandle".to_string()),
            via_slot: Some(Va(0x3000)),
        }];
        let names = RenderNames::new(&callsites);
        let call = MicroExpr::Call {
            target: CallTarget::Indirect(Box::new(MicroExpr::load(MicroExpr::constant(0x3000, 64), 64, false))),
            args: vec![MicroExpr::var("rcx.0"), MicroExpr::var("rdx.0"), MicroExpr::var("r8.0"), MicroExpr::var("r9.0")],
        };
        assert_eq!(render_expr(&call, &names), "(BOOL)kernel32__CloseHandle(/*hObject*/ rcx.0)");
    }

    #[test]
    fn a_real_module_name_is_sanitized_into_a_valid_c_identifier() {
        // Real symbol tables give `KERNEL32.dll!X` and API-set forwarders
        // `api-ms-win-core-libraryloader-l1-2-0.dll!X` — neither is a C
        // identifier until the dots and dashes go.
        assert_eq!(mangle_call_name("KERNEL32.dll!CloseHandle"), "KERNEL32_dll__CloseHandle");
        assert_eq!(
            mangle_call_name("api-ms-win-core-version-l1-1-1.dll!GetFileVersionInfoSizeW"),
            "api_ms_win_core_version_l1_1_1_dll__GetFileVersionInfoSizeW"
        );
    }

    /// …but an indirect call through an *unknown* slot must stay honest.
    #[test]
    fn an_unknown_indirect_call_still_renders_as_a_dereference() {
        let names = RenderNames::new(&[]);
        let call = MicroExpr::Call {
            target: CallTarget::Indirect(Box::new(MicroExpr::load(MicroExpr::constant(0x3000, 64), 64, false))),
            args: vec![MicroExpr::var("rcx.0")],
        };
        assert!(render_expr(&call, &names).starts_with("(*"), "{}", render_expr(&call, &names));
    }

    #[test]
    fn trailing_lift_padding_arguments_are_dropped_from_an_unknown_call() {
        use crate::typeinfer::{CType, ParamInfo, RecoveredSignature, TypeArtifact};
        let types = TypeArtifact {
            locals: vec![],
            structs: vec![],
            signature: RecoveredSignature {
                params: vec![ParamInfo { reg: "rcx", name: "rcx".into(), ty: CType { bits: 64, signed: false, name: None } }],
                ret: None,
            },
        };
        let names = RenderNames::new(&[]).with_types(&types);
        // Unknown callee, args = (rcx.0 [parameter], rdx.1 [computed], r8.0, r9.0 [padding]).
        let call = MicroExpr::Call {
            target: CallTarget::Direct { va: Va(0x5000) },
            args: vec![MicroExpr::var("rcx.0"), MicroExpr::var("rdx.1"), MicroExpr::var("r8.0"), MicroExpr::var("r9.0")],
        };
        // Trailing non-parameter entry values r8.0/r9.0 are dropped; the
        // parameter rcx.0 renders as its name, the computed rdx.1 is kept.
        assert_eq!(render_expr(&call, &names), "sub_5000(rcx, rdx.1)");
    }

    #[test]
    fn a_parameter_entry_value_in_a_trailing_argument_is_kept() {
        use crate::typeinfer::{CType, ParamInfo, RecoveredSignature, TypeArtifact};
        let types = TypeArtifact {
            locals: vec![],
            structs: vec![],
            signature: RecoveredSignature {
                params: vec![
                    ParamInfo { reg: "rcx", name: "rcx".into(), ty: CType { bits: 64, signed: false, name: None } },
                    ParamInfo { reg: "rdx", name: "rdx".into(), ty: CType { bits: 64, signed: false, name: None } },
                ],
                ret: None,
            },
        };
        let names = RenderNames::new(&[]).with_types(&types);
        // rdx.0 is a real parameter forwarded straight through — it must NOT be
        // trimmed even though it is a trailing bare entry value.
        let call = MicroExpr::Call {
            target: CallTarget::Direct { va: Va(0x5000) },
            args: vec![MicroExpr::var("rcx.1"), MicroExpr::var("rdx.0"), MicroExpr::var("r8.0")],
        };
        assert_eq!(render_expr(&call, &names), "sub_5000(rcx.1, rdx)");
    }

    #[test]
    fn a_recovered_parameter_entry_version_renders_as_its_name() {
        use crate::typeinfer::{CType, ParamInfo, RecoveredSignature, TypeArtifact};
        let types = TypeArtifact {
            locals: vec![],
            structs: vec![],
            signature: RecoveredSignature {
                params: vec![ParamInfo { reg: "rcx", name: "rcx".into(), ty: CType { bits: 64, signed: false, name: Some("void *".into()) } }],
                ret: None,
            },
        };
        let names = RenderNames::new(&[]).with_types(&types);
        // The entry version `rcx.0` *is* the parameter -> rendered as its name.
        assert_eq!(render_expr(&MicroExpr::var("rcx.0"), &names), "rcx");
        // A later definition `rcx.1` is a different value -> keeps its subscript
        // (no conflation with the parameter).
        assert_eq!(render_expr(&MicroExpr::var("rcx.1"), &names), "rcx.1");
        // A register that isn't a recovered parameter is untouched.
        assert_eq!(render_expr(&MicroExpr::var("rbx.0"), &names), "rbx.0");
    }

    #[test]
    fn negate_flips_the_comparison_operator() {
        let cond = MicroExpr::binary(BinOp::Eq, MicroExpr::var("rcx"), MicroExpr::constant(0, 64));
        let negated = negate_condition(&cond);
        assert_eq!(negated, MicroExpr::binary(BinOp::Ne, MicroExpr::var("rcx"), MicroExpr::constant(0, 64)));
    }

    #[test]
    fn a_stack_pointer_xor_renders_as_the_named_stack_guard_idiom() {
        let names = RenderNames::new(&[]);
        // `mov rax, __security_cookie; xor rax, rsp` — the canary setup.
        let cookie = MicroExpr::load(MicroExpr::constant(0x1421173c8, 64), 64, false);
        let setup = MicroExpr::binary(BinOp::Xor, cookie, MicroExpr::var("rsp.1"));
        assert_eq!(render_expr(&setup, &names), "__stack_guard(*(uint64_t*)(0x1421173c8))");

        // The epilogue check XORs the frame copy with rsp; operand order reversed.
        let check = MicroExpr::binary(
            BinOp::Xor,
            MicroExpr::var("rsp.1"),
            MicroExpr::load(MicroExpr::binary(BinOp::Add, MicroExpr::var("rsp"), MicroExpr::constant(0x8, 64)), 64, false),
        );
        assert_eq!(render_expr(&check, &names), "__stack_guard(local_8)");
    }

    #[test]
    fn a_plain_xor_of_two_data_registers_is_never_mistaken_for_a_stack_guard() {
        // Soundness: the recognizer keys strictly on a stack-pointer operand, so
        // ordinary `xor rax, rbx` arithmetic renders as itself, not as a guard.
        let names = RenderNames::new(&[]);
        let plain = MicroExpr::binary(BinOp::Xor, MicroExpr::var("rax.2"), MicroExpr::var("rbx.1"));
        assert_eq!(render_expr(&plain, &names), "(rax.2 ^ rbx.1)");
    }
}
