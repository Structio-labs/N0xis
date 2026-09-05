// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Devirtualization** — turning `call qword ptr [rax+0x40]` into a named
//! method (ROADMAP Phase 10, the ❌ "indirect / virtual call resolution").
//!
//! A C++ virtual call is three facts the analysis holds in three different
//! places and never joined up: the object's **class** (RTTI, or a type the
//! whole-program pass propagated), that class's **vtable address** (the RTTI
//! scan), and the **slot** the call site indexes. Put together they name the
//! callee exactly — which is why this could not be built before priority 3b:
//! without a `this` type there is nothing to look the vtable up by.
//!
//! The value-set pass cannot reach this: it gives `Top` for a load through an
//! unknown pointer, because the vtable pointer is written by a constructor that
//! may be in a different function entirely.
//!
//! **Sound over complete — a wrong callee is far worse than an unresolved one**,
//! since every downstream analysis then follows the wrong function. Four refusals:
//!
//! 1. A class whose name maps to **more than one** vtable (multiple
//!    inheritance) is skipped: we cannot tell the primary base's table from a
//!    secondary one, and picking either would be a guess.
//! 2. The slot must lie **inside this vtable**, bounded by the next known
//!    vtable's start. Vtables sit end to end in `.rdata`, so an out-of-range
//!    slot silently reads the *next class's* table — which produced exactly one
//!    class of wrong answer on a real binary: `QPlatformPixmap` slot `0x88`
//!    resolving to an `rpl::details::type_erased_handlers<…>` method. The last
//!    known vtable has no next, so a slot in it is refused rather than bounded
//!    by a guess.
//! 3. The slot must read as a **code address** inside the image's executable
//!    ranges. A null slot (an abstract method, or a relocation the loader fills)
//!    resolves to nothing.
//! 4. Only the exact `*(*this + off)` shape is matched — a computed vtable, or a
//!    pointer that arrived by some route we did not follow, stays indirect.
//! 5. The `this` type must be a **class we have a vtable for**; a synthetic
//!    `struct_rcx_0` names no class and is not tried.

use n0xis_arch::{CallTarget, MicroExpr, MicroStmt};
use n0xis_contracts::Va;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

use crate::ssa::SsaBlock;
use crate::typeinfer::TypeArtifact;
use crate::Ctx;

/// One resolved virtual call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Devirtualized {
    /// The class the `this` pointer was typed as.
    pub class: String,
    /// Byte offset of the vtable slot the call site indexes.
    pub slot: u64,
    /// The method the slot points at.
    pub method: Va,
    /// What to call this dispatch. Derived from the class and slot we resolved
    /// through unless the symbol at the method agrees about the class — see
    /// [`devirtualize`] for why that matters.
    pub name: String,
    /// The name the symbol layer has for that address, when it differs. Under
    /// identical-code folding one implementation is shared by several classes
    /// and carries whichever name claimed it first, so this is kept rather than
    /// discarded: the dispatch is `QPlatformPixmap::vf17`, *and* the code at the
    /// other end is also reachable as something else.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementation: Option<String>,
}

/// `Class *` / `Class` → `Class`. A type name that is not a class we could hold
/// a vtable for (a synthetic struct, a width type) yields `None`.
fn class_of(type_name: &str) -> Option<&str> {
    let base = type_name.trim().trim_end_matches('*').trim();
    if base.is_empty() || base.starts_with("struct_") || base == "void" {
        return None;
    }
    Some(base)
}

/// How far a variable is followed back to its definition. The dispatch is at
/// most a few assignments deep; the bound stops a cyclic definition.
const MAX_DEF_DEPTH: usize = 8;

/// Follow a variable to the expression that defines it. **This is what makes
/// the pass fire on real code at all**: the optimizer does not fold the two
/// loads of a virtual dispatch into one expression, it leaves
/// `v3 = *this; call *(v3 + 0x40)`, so matching only the fully-nested shape
/// found nothing on a real binary (measured: 0 of 399 functions of the Qt desktop PE).
fn resolve<'a>(e: &'a MicroExpr, defs: &'a BTreeMap<&'a str, &'a MicroExpr>) -> &'a MicroExpr {
    let mut cur = e;
    for _ in 0..MAX_DEF_DEPTH {
        let MicroExpr::Var(name) = cur else { return cur };
        match defs.get(name.as_str()) {
            Some(next) if !std::ptr::eq(*next, cur) => cur = next,
            _ => return cur,
        }
    }
    cur
}

/// Which object a dispatch goes through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Object<'a> {
    /// A variable holding the object — `this`, or anything typed like it.
    Var(&'a str),
    /// A **field** of another object: `this->impl->method()`. Resolving these is
    /// what program-wide class layouts bought — the class of `impl` is not
    /// anywhere in this function, it is a property of `this`'s class that some
    /// *other* function proved.
    Field { base: &'a str, offset: i64 },
}

/// Split `Var ± Const` (either operand order) or a bare `Var`, resolving each
/// half through the assignments the optimizer left behind.
fn base_offset<'a>(e: &'a MicroExpr, defs: &'a BTreeMap<&'a str, &'a MicroExpr>) -> Option<(&'a str, i64)> {
    match resolve(e, defs) {
        MicroExpr::Var(name) => Some((name.as_str(), 0)),
        MicroExpr::Binary(n0xis_arch::BinOp::Add, l, r) => match (resolve(l, defs), resolve(r, defs)) {
            (MicroExpr::Var(n), MicroExpr::Const { value, .. }) => Some((n.as_str(), *value as i64)),
            (MicroExpr::Const { value, .. }, MicroExpr::Var(n)) => Some((n.as_str(), *value as i64)),
            _ => None,
        },
        _ => None,
    }
}

/// Recognize the C++ virtual-dispatch address: `*( *obj + off )`, i.e. load the
/// vtable pointer out of the object, then load a slot out of the vtable —
/// through however many intermediate assignments the optimizer left behind.
/// Returns `(the object, slot offset)`.
fn as_vtable_dispatch<'a>(expr: &'a MicroExpr, defs: &'a BTreeMap<&'a str, &'a MicroExpr>) -> Option<(Object<'a>, u64)> {
    // The outer load is the slot read.
    let MicroExpr::Load { addr, .. } = resolve(expr, defs) else { return None };
    let (inner, off) = match resolve(addr, defs) {
        MicroExpr::Binary(n0xis_arch::BinOp::Add, l, r) => match (resolve(l, defs), resolve(r, defs)) {
            (inner, MicroExpr::Const { value, .. }) => (inner, u64::try_from(*value).ok()?),
            (MicroExpr::Const { value, .. }, inner) => (inner, u64::try_from(*value).ok()?),
            // Any other addition is a computed address, not a constant slot
            // index — not a shape we can prove.
            _ => return None,
        },
        other => (other, 0),
    };
    // The inner load is the vtable pointer, read from the object itself.
    let MicroExpr::Load { addr: obj, .. } = inner else { return None };
    match resolve(obj, defs) {
        MicroExpr::Var(name) => Some((Object::Var(name.as_str()), off)),
        // One more load: the object itself came out of a field of something we
        // do have a type for.
        MicroExpr::Load { addr: field, .. } => {
            let (base, offset) = base_offset(field, defs)?;
            Some((Object::Field { base, offset }, off))
        }
        _ => None,
    }
}

/// Class name → `(vtable address, exclusive end)`. A class with several vtables
/// (multiple inheritance) is **excluded**: the map cannot say which is the
/// primary base's, and a virtual call through a `this` at offset 0 must use
/// that one.
///
/// The end is the next known vtable's start. Vtables are laid end to end, so
/// without it a slot past this table's last method reads the following class's
/// — a resolved-looking, wrong callee.
fn class_to_vtable(vtables: &HashMap<u64, String>) -> BTreeMap<&str, (u64, u64)> {
    let mut sorted: Vec<u64> = vtables.keys().copied().collect();
    sorted.sort_unstable();
    let end_of = |va: u64| -> Option<u64> {
        let i = sorted.binary_search(&va).ok()?;
        sorted.get(i + 1).copied()
    };
    let mut by_class: BTreeMap<&str, Vec<u64>> = BTreeMap::new();
    for (va, name) in vtables {
        by_class.entry(name.as_str()).or_default().push(*va);
    }
    by_class
        .into_iter()
        .filter(|(_, vs)| vs.len() == 1)
        .filter_map(|(c, vs)| end_of(vs[0]).map(|e| (c, (vs[0], e))))
        .collect()
}

/// Resolve every virtual call this function makes that can be resolved
/// *soundly*, rewriting the call target in place and returning what was
/// resolved. A no-op without a recovered vtable map.
pub fn devirtualize(ctx: &Ctx, blocks: &mut [SsaBlock], types: &TypeArtifact) -> Vec<Devirtualized> {
    let Some(vtables) = ctx.vtables else { return Vec::new() };
    if vtables.is_empty() {
        return Vec::new();
    }
    let by_class = class_to_vtable(vtables);

    // The class of each parameter, keyed by its entry SSA name (`rcx.0`) — the
    // `this` of a member function is exactly this.
    let var_class: BTreeMap<String, &str> = types
        .signature
        .params
        .iter()
        .filter_map(|p| Some((format!("{}.0", p.reg), class_of(p.ty.name.as_deref()?)?)))
        .collect();
    if var_class.is_empty() {
        return Vec::new();
    }

    let code: Vec<(u64, u64)> =
        n0xis_sources::MemorySource::code_ranges(ctx.source).into_iter().map(|(s, n)| (s.get(), s.get() + n)).collect();
    let is_code = |va: u64| code.iter().any(|(s, e)| va >= *s && va < *e);

    // Every variable's defining expression, so the two halves of a dispatch can
    // be rejoined however the optimizer split them. Built before the rewrite so
    // it borrows nothing that is about to change.
    let defs: BTreeMap<&str, &MicroExpr> = blocks
        .iter()
        .flat_map(|b| b.stmts.iter())
        .filter_map(|s| match &s.stmt {
            MicroStmt::Assign { dst, value } => Some((dst.as_str(), value)),
            _ => None,
        })
        .collect();

    let mut out = Vec::new();
    let mut plan: Vec<(usize, usize, Devirtualized)> = Vec::new();
    let mut consider = |bi: usize, si: usize, target: &CallTarget| {
        let CallTarget::Indirect(expr) = target else { return };
        let Some((object, slot)) = as_vtable_dispatch(expr, &defs) else { return };
        let class: &str = match object {
            Object::Var(v) => match var_class.get(v) {
                Some(c) => c,
                None => return,
            },
            // A dispatch on a field needs the field's type, which only the
            // program-wide layout holds — and it must be a **pointer** type: an
            // embedded sub-object's first word is its own vptr, so treating
            // `Widget` and `Widget *` alike here would resolve a slot of the
            // wrong table with full confidence.
            Object::Field { base, offset } => {
                let Some(owner) = var_class.get(base) else { return };
                let Some(ty) = ctx.layout.and_then(|l| l.field_type(owner, offset)) else { return };
                if !ty.trim_end().ends_with('*') {
                    return;
                }
                match class_of(ty) {
                    Some(c) => c,
                    None => return,
                }
            }
        };
        let Some(&(vtable, vtable_end)) = by_class.get(class) else { return };
        let Some(addr) = vtable.checked_add(slot) else { return };
        // The slot must be inside THIS class's table, or we would read the next
        // class's and report its method with full confidence.
        if addr.saturating_add(8) > vtable_end {
            return;
        }
        let Ok(bytes) = ctx.source.read(Va(addr), 8) else { return };
        if bytes.len() < 8 {
            return;
        }
        let method = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        // A null or non-code slot is an honest "unresolved", not a callee.
        if method == 0 || !is_code(method) {
            return;
        }
        // Naming, and the trap in it. The symbol layer names a method address
        // after whichever class's vtable walk claimed it first — and under
        // **identical-code folding** one implementation is shared by unrelated
        // classes. Taking that name verbatim reported a `QPlatformPixmap`
        // dispatch as an `rpl::details::type_erased_handlers<…>` method on a real
        // binary: the *resolution* was right (we read that pointer out of that
        // table), the *name* belonged to a different member of a folded set.
        // So the dispatch is named by the class and slot it actually goes
        // through, and a disagreeing symbol name is kept alongside rather than
        // dropped.
        let symbol = ctx.symbols.and_then(|s| s.symbol_at(Va(method))).filter(|s| s.va.0 == method).map(|s| s.name);
        let owned = format!("{class}::vf{}", slot / 8);
        let (name, implementation) = match symbol {
            Some(sym) if sym.starts_with(&format!("{class}::")) => (sym, None),
            Some(sym) => (owned, Some(sym)),
            None => (owned, None),
        };
        plan.push((bi, si, Devirtualized { class: class.to_string(), slot, method: Va(method), name, implementation }));
    };

    for (bi, block) in blocks.iter().enumerate() {
        for (si, stmt) in block.stmts.iter().enumerate() {
            match &stmt.stmt {
                MicroStmt::Call { target, .. } => consider(bi, si, target),
                MicroStmt::Assign { value: MicroExpr::Call { target, .. }, .. } => consider(bi, si, target),
                _ => {}
            }
        }
    }

    // Apply. Separate from the walk because the definition map borrows the
    // blocks immutably; rewriting in place while reading definitions out of
    // them is exactly the aliasing the borrow checker is right to refuse.
    for (bi, si, d) in plan {
        let target = match &mut blocks[bi].stmts[si].stmt {
            MicroStmt::Call { target, .. } => target,
            MicroStmt::Assign { value: MicroExpr::Call { target, .. }, .. } => target,
            _ => continue,
        };
        *target = CallTarget::Direct { va: d.method };
        out.push(d);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::Bits;

    fn dispatch(this: &str, off: i128) -> MicroExpr {
        let vptr = MicroExpr::load(MicroExpr::Var(this.into()), 64 as Bits, false);
        let addr = if off == 0 {
            vptr
        } else {
            MicroExpr::Binary(n0xis_arch::BinOp::Add, Box::new(vptr), Box::new(MicroExpr::constant(off, 64)))
        };
        MicroExpr::load(addr, 64 as Bits, false)
    }

    #[test]
    fn recognizes_the_dispatch_shape_and_its_slot() {
        let no_defs = BTreeMap::new();
        assert_eq!(as_vtable_dispatch(&dispatch("rcx.0", 0x40), &no_defs), Some((Object::Var("rcx.0"), 0x40)));
        assert_eq!(as_vtable_dispatch(&dispatch("rcx.0", 0), &no_defs), Some((Object::Var("rcx.0"), 0)));
        // A single load is a plain function-pointer call, not a vtable dispatch.
        let single = MicroExpr::load(MicroExpr::Var("rcx.0".into()), 64 as Bits, false);
        assert_eq!(as_vtable_dispatch(&single, &no_defs), None);
        // A computed vtable base is not the shape we can prove.
        let computed = MicroExpr::load(
            MicroExpr::load(MicroExpr::constant(0x1000, 64), 64 as Bits, false),
            64 as Bits,
            false,
        );
        assert_eq!(as_vtable_dispatch(&computed, &no_defs), None);
    }

    /// The shape real code has: the optimizer leaves `v3 = *this` as its own
    /// assignment, so the dispatch is only recognizable by following `v3` back
    /// to its definition. Matching only the fully-nested form found **0** virtual
    /// calls across 399 real functions of the Qt desktop PE.
    #[test]
    fn follows_the_vptr_through_the_assignment_the_optimizer_leaves() {
        let vptr_def = MicroExpr::load(MicroExpr::Var("rcx.0".into()), 64 as Bits, false);
        let defs: BTreeMap<&str, &MicroExpr> = [("v3", &vptr_def)].into_iter().collect();
        let split = MicroExpr::load(
            MicroExpr::Binary(
                n0xis_arch::BinOp::Add,
                Box::new(MicroExpr::Var("v3".into())),
                Box::new(MicroExpr::constant(0x40, 64)),
            ),
            64 as Bits,
            false,
        );
        assert_eq!(as_vtable_dispatch(&split, &defs), Some((Object::Var("rcx.0"), 0x40)));
    }

    /// `this->impl->method()` — the dispatch that survived the first
    /// devirtualization pass unresolved, because the class of `impl` is not
    /// stated anywhere in this function. It is a property of `this`'s class that
    /// some *other* function proved, which is exactly what the program-wide
    /// layout carries.
    #[test]
    fn recognizes_a_dispatch_through_a_field_of_the_object() {
        // v1 = *(this + 0x30)   — the field holding the sub-object
        // v2 = *v1              — its vtable pointer
        //      call *(v2 + 0x18)
        let field = MicroExpr::load(
            MicroExpr::Binary(
                n0xis_arch::BinOp::Add,
                Box::new(MicroExpr::Var("rcx.0".into())),
                Box::new(MicroExpr::constant(0x30, 64)),
            ),
            64 as Bits,
            false,
        );
        let vptr = MicroExpr::load(MicroExpr::Var("v1".into()), 64 as Bits, false);
        let defs: BTreeMap<&str, &MicroExpr> = [("v1", &field), ("v2", &vptr)].into_iter().collect();
        let call = MicroExpr::load(
            MicroExpr::Binary(
                n0xis_arch::BinOp::Add,
                Box::new(MicroExpr::Var("v2".into())),
                Box::new(MicroExpr::constant(0x18, 64)),
            ),
            64 as Bits,
            false,
        );
        assert_eq!(as_vtable_dispatch(&call, &defs), Some((Object::Field { base: "rcx.0", offset: 0x30 }, 0x18)));
    }

    /// A field at offset 0 is still a field — `this->first->method()` is as real
    /// a dispatch as one at `+0x30`, and the bare-`Var` address shape is what it
    /// lowers to.
    #[test]
    fn a_field_at_offset_zero_is_still_a_field() {
        let field = MicroExpr::load(MicroExpr::Var("rcx.0".into()), 64 as Bits, false);
        let vptr = MicroExpr::load(MicroExpr::Var("v1".into()), 64 as Bits, false);
        let defs: BTreeMap<&str, &MicroExpr> = [("v1", &field), ("v2", &vptr)].into_iter().collect();
        let call = MicroExpr::load(MicroExpr::Var("v2".into()), 64 as Bits, false);
        assert_eq!(as_vtable_dispatch(&call, &defs), Some((Object::Field { base: "rcx.0", offset: 0 }, 0)));
    }

    /// A cyclic definition must terminate rather than spin.
    #[test]
    fn a_cyclic_definition_terminates() {
        let a = MicroExpr::Var("b".into());
        let b = MicroExpr::Var("a".into());
        let defs: BTreeMap<&str, &MicroExpr> = [("a", &a), ("b", &b)].into_iter().collect();
        let e = MicroExpr::load(MicroExpr::Var("a".into()), 64 as Bits, false);
        assert_eq!(as_vtable_dispatch(&e, &defs), None);
    }

    #[test]
    fn a_class_with_several_vtables_is_excluded() {
        let mut m = HashMap::new();
        m.insert(0x1000u64, "Widget".to_string());
        m.insert(0x2000u64, "Widget".to_string()); // multiple inheritance
        m.insert(0x3000u64, "Button".to_string());
        m.insert(0x4000u64, "Label".to_string());
        let by_class = class_to_vtable(&m);
        assert_eq!(by_class.get("Button"), Some(&(0x3000, 0x4000)), "bounded by the next table");
        assert!(!by_class.contains_key("Widget"), "cannot tell primary from secondary — refuse");
        assert!(!by_class.contains_key("Label"), "the last table has no known end — refuse");
    }

    /// Vtables sit end to end, so a slot past this class's last method reads the
    /// NEXT class's table. Found on a real binary: `QPlatformPixmap` slot `0x88`
    /// resolving to an `rpl::details::type_erased_handlers<…>` method.
    #[test]
    fn the_slot_is_bounded_by_the_next_vtable() {
        let mut m = HashMap::new();
        m.insert(0x1000u64, "Small".to_string());
        m.insert(0x1010u64, "Next".to_string()); // Small holds exactly two slots
        m.insert(0x2000u64, "Last".to_string());
        let by_class = class_to_vtable(&m);
        let (base, end) = by_class["Small"];
        assert_eq!((base, end), (0x1000, 0x1010));
        // slot 0 and 8 are inside; slot 0x10 is the next class's first method.
        assert!(base + 8 <= end && base + 8 + 8 <= end);
        assert!(base + 0x10 + 8 > end, "slot 0x10 must be refused");
    }

    #[test]
    fn only_a_real_class_name_is_tried() {
        assert_eq!(class_of("Widget *"), Some("Widget"));
        assert_eq!(class_of("Ns::Widget*"), Some("Ns::Widget"));
        assert_eq!(class_of("struct_rcx_0 *"), None, "a synthetic name is not a class");
        assert_eq!(class_of("void *"), None);
        assert_eq!(class_of("  * "), None);
    }
}
