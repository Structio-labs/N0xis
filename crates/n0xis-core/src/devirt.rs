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
//! since every downstream analysis then follows the wrong function. The refusals:
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
//! 6. A class the object has only by a **declared type** — a parameter's, or
//!    a field's — is refused when the class may have a subclass
//!    ([`crate::Subclasses`]: any class of a library, which the program that
//!    loads it may derive from; any class, where any class's bases could not
//!    be read). The object may be of the subclass, whose slot holds another
//!    method. A class the object was built with (a constructor, a stored
//!    vtable) is taken for its dynamic type — at the dispatches that
//!    construction dominates in this function's graph, and only where no
//!    other construction of the same object that this pass recognizes can
//!    reach the dispatch along that graph ([`Constructions`]).
//! 7. On 32-bit ARM, a slot holding a **Thumb** code pointer (bit 0 set) is
//!    not resolved — an interim refusal, see [`crate::VtableSlots`].
//!
//! **Known wrong answers** (each measured against the processor; none is new,
//! the build before this rule gave the same answer), all in what rules 6 and
//! the `object` basis take on trust:
//!
//! - **The graph has no exception edges.** Dominance is computed over a CFG
//!   without landing-pad edges, so a vtable store inside a `try` block counts
//!   as dominating a call after the `catch`. `t_eh(mem, k)`: a `D` is
//!   rebuilt in place as an `F2` inside `try` between two calls that may throw,
//!   and `p->f()` after the `catch` resolved to `F2::f`; the processor ran
//!   `D::f` from that call for `k = 1` (wrong in 10 of 40 x86 builds: clang
//!   `-O1`/`-O2`/`-O3`/`-Os`, PIE and not, g++ `-O2`/`-O3` non-PIE). The same
//!   holds of `setjmp`/`longjmp` edges, which no graph here has.
//! - **A rebuild the graph cannot see.** A construction dominates the call,
//!   then an opaque call destroys the object and builds another class in its
//!   storage, and the caller calls through `std::launder`, which emits no
//!   instruction: `t_launder` built a `D`, `rebuild(p, k)` (another
//!   translation unit) made it a `B` when `k` was set, and the call resolved
//!   to `D::f`, where the processor ran `B::f` (11 x86-64 builds). The machine
//!   code has the shape of `built` in `flow.cpp`, which is right by the C++
//!   object model without `launder`; nothing in the code tells the two apart.
//! - **A construction this pass does not recognize.** A class the RTTI scan
//!   refuses has no vtable in the map, so its own vtable store is no
//!   construction here, and the base constructor before it wins: `struct EV :
//!   D, virtual VB`, built inline over `D`'s out-of-line constructor, resolved
//!   to `D::f` where the processor ran `EV::f` (11 x86-64 builds). A guard
//!   would treat a store at offset 0 of an address inside any `_ZTV` the map
//!   does not hold as an unknown construction and refuse the dispatch; it is
//!   not built.
//! - **The fallback branch of a compiler's own guard.** Where the compiler
//!   devirtualized speculatively (`if (slot != &X::m) call *slot; else call
//!   X::m`), the indirect call on the first branch is resolved to `X::m`, the
//!   method `X`'s table holds there. Whenever that instruction runs its target
//!   is, by the guard, *not* `X::m`: the edge named is one the program never
//!   takes there. All 3 resolutions left on `libQt6Gui.so.6` and both on
//!   `libQt6Quick.so.6` (`QQuickDefaultClipNode::update`, `0x276d38`) are this
//!   shape. Nothing marks them yet.
//!
//! **Where it runs.** It resolves calls on x86-64 code only: on i686, ARMv7
//! and AArch64 the matcher finds no dispatch on real code (0 calls in every
//! probe build, before and after the slot-width work; the i686 reasons are
//! written down in the CLI test `itanium_vtables_are_where_the_image_puts_them`),
//! so the 32-bit and ARM work on vtables changes `rtti scan` and `analyze`'s
//! names, not devirtualization.

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
    /// **How the class was established** — what the resolution rests on:
    ///
    /// - `"vtable"`: the table's address is a constant in the instruction, so
    ///   the class is read off the table itself. Nothing to be wrong about.
    /// - `"object"`: the class of the variable the object is in — from a
    ///   constructor call on it or a vtable stored into it (taken for its
    ///   dynamic type where that construction dominates the call and no other
    ///   this pass recognizes reaches it, in a graph without exception edges:
    ///   [`Constructions`]), or from a declared type that reached
    ///   it ([`ClassFrom`]). A
    ///   parameter's declared type is a *static* type: `Base::h` called on a
    ///   `Derived` runs `Derived::g` through `this`, so a class from a
    ///   parameter is refused where the class may have a subclass in the image,
    ///   the same guard as the `field` basis.
    /// - `"field"`: the *declared* type of a field of another object. Sound as
    ///   a type and **not** as a vtable: what is stored there may be a derived
    ///   class, whose slot holds a different method. Measured on one Qt build,
    ///   this basis accounts for a majority of the resolutions whose class has
    ///   subclasses at all, which is exactly where the hazard lives.
    ///
    /// Reported rather than hidden because a consumer deciding whether to act
    /// on a devirtualization needs to know which of the three it is.
    pub basis: &'static str,
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
pub(crate) fn resolve<'a>(e: &'a MicroExpr, defs: &'a BTreeMap<&'a str, &'a MicroExpr>) -> &'a MicroExpr {
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

/// Teach the definition map to see through a **phi** whose incoming values all
/// say the same thing.
///
/// A virtual dispatch is `*( *obj + slot )`, and the optimizer leaves the vptr
/// load in a variable. When the same call is reached from two paths — the shape
/// the compiler's *own* devirtualization guard produces, `if (slot != &known)
/// call *slot; else call known;` — that variable is a phi, and `defs`, built
/// only from `Assign`, cannot follow it. Measured on a Qt shared library: this
/// is why 191 dispatches stayed unresolved in functions where the class *and*
/// its vtable were both already known — the inputs were missing nothing, the
/// walk simply stopped at the join.
///
/// The fold is only taken when **every** incoming value has a defining
/// expression and they are all structurally equal — "whichever path was taken,
/// this variable was defined the same way". A phi whose inputs disagree is left
/// alone, so nothing is claimed about a value that genuinely differs per path.
///
/// What it lets through on that guard is recorded in the module doc ("The
/// fallback branch of a compiler's own guard"): the indirect call on the
/// `slot != &known` branch is named `known`, which is the one method it never
/// calls.
pub(crate) fn fold_phis<'a>(blocks: &'a [SsaBlock], defs: &mut BTreeMap<&'a str, &'a MicroExpr>) {
    // A phi may feed another phi, so run to a fixpoint under the same bound the
    // definition walk uses.
    for _ in 0..MAX_DEF_DEPTH {
        let mut changed = false;
        for phi in blocks.iter().flat_map(|b| b.phis.iter()) {
            if defs.contains_key(phi.dst.as_str()) {
                continue;
            }
            let Some(first) = phi.inputs.first().and_then(|i| defs.get(i.value.as_str()).copied()) else { continue };
            if phi.inputs.iter().all(|i| defs.get(i.value.as_str()).is_some_and(|e| *e == first)) {
                defs.insert(phi.dst.as_str(), first);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
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
    /// The **vtable address itself is a constant** — the compiler already knew
    /// the class and wrote the table's address into a register, so there is no
    /// vptr load to follow and no type to recover. It is the shape a
    /// devirtualization guard leaves (`if (slot == &Known::m) …`), and the one
    /// case where the object's class is irrelevant: the table is named.
    Vtable(u64),
}

/// The absolute address a value denotes, when it is a constant — spelled either
/// bare or behind an `&` by the lift.
fn const_addr(e: &MicroExpr, defs: &BTreeMap<&str, &MicroExpr>) -> Option<u64> {
    let inner = match resolve(e, defs) {
        MicroExpr::AddrOf(i) => resolve(i, defs),
        other => other,
    };
    let MicroExpr::Const { value, .. } = inner else { return None };
    u64::try_from(*value).ok()
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
    // The inner load is the vtable pointer, read from the object itself — or
    // there is no inner load at all, because the table's address is a constant.
    let MicroExpr::Load { addr: obj, .. } = inner else {
        return const_addr(inner, defs).map(|va| (Object::Vtable(va), off));
    };
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

/// Rounds the class closure runs. A class reaches a dispatch through a handful
/// of copies; the bound is what stops a cyclic definition.
const MAX_CLOSURE_ROUNDS: usize = 8;

/// Where the class of a variable was established — what the class closure
/// knows about *how exact* it is.
///
/// Ordered from the least exact to the most, so that where two routes meet
/// (a phi) the result keeps the weaker one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ClassFrom {
    /// The declared type of a parameter — a **static** type. The object may be
    /// of any class derived from it: the processor, running `Base::h` on a
    /// `Derived` built from `vtables.cpp`, called `Derived::g` through the slot
    /// devirtualization had resolved to `Base::g` (the source and the recorded
    /// run are beside the fixtures, `processor_run.cpp`).
    Parameter,
    /// The program-wide layout's type of the field the value was loaded from.
    Field,
    /// A direct callee's propagated return type.
    Return,
    /// The object's dynamic type as this function builds it: a constructor of
    /// the class ran on it, or this function stored the class's vtable into
    /// it. A fact of a **point** in the function, not of the variable: what
    /// devirtualization asks of it is [`Constructions::at`]; only the field
    /// typer, which asks for a declared type, takes it as the variable's
    /// ([`BuiltClasses`]). It is the dynamic type only as far as the graph and
    /// the constructions [`Constructions`] can see go: an exception edge, an
    /// opaque rebuild behind `std::launder`, and the vtable store of a class
    /// the map does not hold are each a way it is wrong (the module doc,
    /// "Known wrong answers").
    Built,
}

impl ClassFrom {
    /// Whether a dispatch through a class established this way is refused when
    /// the class may have a subclass in the image.
    ///
    /// A parameter is, by decision. A field's and a return value's types are
    /// static types too and are **not** refused here — an open item, not a
    /// claim that they are exact. In a library every class may have a
    /// subclass, in the program that loads it ([`crate::Subclasses::Open`]):
    /// `libplug.so`'s `Plugin::drive() { return run() + 1000; }` resolved
    /// `run()` through `this` to `Plugin::run` while no class of the library
    /// derived from `Plugin`, and a client's `My : Plugin` overriding `run` to
    /// return 7 made the processor print 1007 (g++ and clang `-O1`/`-O2`,
    /// linked `-Bsymbolic` or `-Bsymbolic-functions`; the build before gave
    /// the same answer). Named per variant, so a new seed has to answer.
    pub(crate) fn refused_when_subclassed(self) -> bool {
        match self {
            ClassFrom::Parameter => true,
            ClassFrom::Field | ClassFrom::Return | ClassFrom::Built => false,
        }
    }
}

/// A variable's class and how it was established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Classed {
    pub(crate) class: String,
    pub(crate) from: ClassFrom,
}

impl Classed {
    fn new(class: impl Into<String>, from: ClassFrom) -> Self {
        Classed { class: class.into(), from }
    }
}

/// Every variable that provably holds an object of a named class.
///
/// The seed — a parameter whose recovered type is a class — is where this
/// started and where it used to stop: the map was keyed on the *entry* SSA name
/// (`rdi.0`) and carried nowhere else, so a dispatch on any other version of
/// that register, or on a value the function had just loaded, found nothing.
/// Measured on a Qt shared library over 1 460 methods: of 265 virtual dispatches
/// that stayed unresolved, **235** had a base whose class the program already
/// knew somewhere — 125 in a *typed field* of an object in hand, 29 in the
/// *return type* of a named callee, 22 behind a plain copy.
///
/// So the class travels, along exactly the edges that carry a value:
/// - a **copy**, through casts;
/// - a **phi**, when every incoming value agrees (one that disagrees is left
///   alone — see [`fold_phis`], same rule, same reason);
/// - a **stack spill and reload**, tracked by the slot's address expression;
/// - a **field load**, when the program-wide layout proved that field's type —
///   and it must be a *pointer* type, because an embedded sub-object's first
///   word is its own vptr and treating `Widget` and `Widget *` alike would
///   resolve a slot of the wrong table with full confidence;
/// - a **direct call's return value**, when whole-program propagation proved the
///   callee's return type;
/// - a variable handed to a **constructor of `C`** as its `this` — the ABI
///   settles that argument 0 of a constructor is the object being built, so
///   `d = operator new(...); C::C(d, …)` names `d` with no type needed
///   anywhere first. This is the one seed that reaches a *freshly allocated*
///   object, which the class layout's own rule 1 already relies on for an
///   embedded sub-object and which nothing carried to a plain local.
///
/// Construction order settles the one ambiguity that seed has: a derived
/// constructor runs its base's first, so when both are inlined into the same
/// function the **later** call is the more derived one and it wins. A stored
/// vtable is stronger still and overrides both — it is the dynamic type as the
/// hardware sees it. That is the rule of [`BuiltClasses::Everywhere`], where
/// "later" is statement order; for a dispatch, [`Constructions`] decides by
/// the control flow instead.
///
/// Every one of those is a fact some other pass already established. Nothing
/// here infers a class; it moves one that was proven elsewhere to the place the
/// dispatch actually reads.
///
/// Each class carries how it was established ([`ClassFrom`]): a copy, a phi
/// or a spill keeps it, a phi of two routes keeps the less exact, and a stored
/// vtable makes it exact.
///
/// `built` says whether the classes a construction establishes are in the map
/// at all ([`BuiltClasses`]).
pub(crate) fn class_closure(
    ctx: &Ctx,
    blocks: &[SsaBlock],
    types: &TypeArtifact,
    defs: &BTreeMap<&str, &MicroExpr>,
    built: BuiltClasses,
) -> BTreeMap<String, Classed> {
    let mut cls: BTreeMap<String, Classed> = types
        .signature
        .params
        .iter()
        .filter_map(|p| Some((format!("{}.0", p.reg), Classed::new(class_of(p.ty.name.as_deref()?)?, ClassFrom::Parameter))))
        .collect();
    let everywhere = built == BuiltClasses::Everywhere;
    // Constructors first, in program order, so the most derived one wins — see
    // the note on construction order above. Done before the fixpoint rather than
    // inside it because the fixpoint deliberately never overwrites a class it
    // already has.
    for s in blocks.iter().flat_map(|b| b.stmts.iter()).filter(|_| everywhere) {
        if let Some((v, c)) = ctor_construction(ctx, &s.stmt, defs) {
            cls.insert(v.to_string(), Classed::new(c, ClassFrom::Built));
        }
    }
    // Stack slots a classed pointer was spilled into, by address expression.
    let mut slots: Vec<(&MicroExpr, Classed)> = Vec::new();
    let ret_class = |va: u64| ctx.type_flow.and_then(|f| f.ret(va)).and_then(class_of).map(|c| Classed::new(c, ClassFrom::Return));

    for _ in 0..MAX_CLOSURE_ROUNDS {
        let mut changed = false;
        for b in blocks {
            for phi in &b.phis {
                if cls.contains_key(phi.dst.as_str()) {
                    continue;
                }
                let Some(first) = phi.inputs.first().and_then(|i| cls.get(i.value.as_str())).cloned() else { continue };
                let incoming: Option<Vec<&Classed>> = phi.inputs.iter().map(|i| cls.get(i.value.as_str())).collect();
                if let Some(incoming) = incoming
                    && incoming.iter().all(|c| c.class == first.class)
                {
                    // The same class on every path; how exact it is, is the
                    // least exact path's.
                    let from = incoming.iter().map(|c| c.from).min().unwrap_or(first.from);
                    cls.insert(phi.dst.clone(), Classed::new(first.class, from));
                    changed = true;
                }
            }
            for s in &b.stmts {
                match &s.stmt {
                    MicroStmt::Assign { dst, value } if !cls.contains_key(dst.as_str()) => {
                        if let Some(c) = value_class(ctx, value, &cls, &slots, defs, &ret_class) {
                            cls.insert(dst.clone(), c);
                            changed = true;
                        }
                    }
                    MicroStmt::Call { target: CallTarget::Direct { va }, ret: Some(dst), .. } if !cls.contains_key(dst.as_str()) => {
                        if let Some(c) = ret_class(va.get()) {
                            cls.insert(dst.clone(), c);
                            changed = true;
                        }
                    }
                    MicroStmt::Store { addr, value, .. } => {
                        // A **known vtable written into an object** settles that
                        // object's class outright — it is the constructor idiom,
                        // and it is the only evidence that needs no other type to
                        // already exist. Qt code builds `QPixmap`s and `QImage`s
                        // as stack locals constantly, and until now the class of
                        // every one of them was lost the moment the constructor
                        // returned.
                        if everywhere
                            && let Some((base, c)) = store_construction(ctx, &s.stmt, defs)
                            && cls.get(base) != Some(&c)
                        {
                            cls.insert(base.to_string(), c);
                            changed = true;
                        }
                        if let MicroExpr::Var(v) = resolve(value, defs)
                            && let Some(c) = cls.get(v.as_str())
                            && !slots.iter().any(|(a, _)| *a == addr)
                        {
                            slots.push((addr, c.clone()));
                            changed = true;
                        }
                    }
                    _ => {}
                }
            }
        }
        if !changed {
            break;
        }
    }
    cls
}

/// Whether [`class_closure`] puts the class a **construction** establishes —
/// a constructor of the class called on the object, or the class's vtable
/// stored into it ([`ClassFrom::Built`]) — into its map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuiltClasses {
    /// As the variable's class, wherever the variable is read. For the field
    /// typer, which asks what a value *is declared as* when it is stored into a
    /// field, not which method a slot of it holds at one point.
    Everywhere,
    /// Left out: such a class is a fact of the points the construction
    /// dominates, and devirtualization asks it there ([`Constructions::at`]).
    /// In the map, a vtable stored on one path named the object on every
    /// path: `g(void *mem, int rebuild)` from `flow.cpp`, which builds a `B` in
    /// `mem` only when `rebuild` is set and otherwise calls `p->f()` on the
    /// object it was handed, had that call resolved to `B::f` — and on the `D`
    /// the processor hands it, it runs `D::f` (`g(&d, 0)` printed 42).
    AtDominatedPoints,
}

/// A place in one function's SSA: a block, and a statement in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct At {
    pub(crate) block: usize,
    pub(crate) stmt: usize,
}

/// One construction in a function: an object of `class` is built at `at` in
/// the variable `base`.
#[derive(Clone, Debug)]
struct Construction<'a> {
    at: At,
    base: &'a str,
    class: String,
}

/// What a function's constructions say about one object at one point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Constructed<'a> {
    /// The nearest construction that dominates the point built this class, and
    /// no other construction of the object can reach the point.
    Exact(&'a str),
    /// A construction of the object that does not dominate the point can reach
    /// it: on some path the object was built again, as whatever it was built as
    /// there, so no one class is the object's at this point.
    Refused,
    /// No construction of the object reaches the point.
    Unsaid,
}

/// Every construction in one function, and the control flow that decides
/// which of them a point sees — the one rule for when a [`ClassFrom::Built`]
/// class holds:
///
/// 1. A construction holds only where it **dominates** — every path from the
///    entry to the point passes it.
/// 2. Of the dominating ones, the **nearest** wins: they lie on one chain of
///    the dominator tree, and the last of them on it is the last one every
///    path runs before the point. A derived constructor stores its base's
///    vtable and then its own, so this is also the construction order, by
///    flow rather than by statement order.
/// 3. If a construction of the same object that does **not** dominate the
///    point can **reach** it, the point is refused: some path built the object
///    again. This is reachability, not "reaches without passing a nearer
///    one" — a construction later in a loop body refuses a dispatch earlier in
///    it even when a dominating one comes first on every iteration. Refusing
///    more than needed there costs a resolution; resolving it would cost a
///    wrong one if the rule were wrong.
///
/// "The same object" is the same variable, both reached through the same
/// definition map, so a copy is the variable it copies. A construction of a
/// spilled, reloaded or phi-merged copy is a construction of another variable
/// and says nothing here.
///
/// The graph is the function's CFG as built, which carries **no
/// exception-handling edges**: a construction in a `try` body is taken to
/// dominate a call after the `catch` that the landing pad also reaches, and the
/// call is resolved to the class built in the `try` (`t_eh`, wrong in 10 of 40
/// x86 builds). And only the constructions [`Self::of`] recognizes are here: a
/// rebuild in another function, or a store of a vtable the map does not hold,
/// is none (the module doc, "Known wrong answers").
pub(crate) struct Constructions<'a> {
    list: Vec<Construction<'a>>,
    /// Forward dominators of each block ([`crate::dom::dominators_fwd`]), only
    /// when there is a construction to ask about.
    dom: Vec<std::collections::BTreeSet<usize>>,
    /// For each block that holds a construction, the blocks reachable from it
    /// along at least one edge.
    reach: BTreeMap<usize, Vec<bool>>,
}

impl<'a> Constructions<'a> {
    /// The constructions of `blocks`: each constructor call on a variable and
    /// each vtable stored into one, recognized as [`class_closure`] recognizes
    /// them.
    pub(crate) fn of(ctx: &Ctx, blocks: &'a [SsaBlock], defs: &'a BTreeMap<&'a str, &'a MicroExpr>) -> Self {
        let mut list = Vec::new();
        for (block, b) in blocks.iter().enumerate() {
            for (stmt, s) in b.stmts.iter().enumerate() {
                if let Some((base, class)) = ctor_construction(ctx, &s.stmt, defs) {
                    list.push(Construction { at: At { block, stmt }, base, class });
                } else if let Some((base, c)) = store_construction(ctx, &s.stmt, defs) {
                    list.push(Construction { at: At { block, stmt }, base, class: c.class });
                }
            }
        }
        if list.is_empty() {
            return Constructions { list, dom: Vec::new(), reach: BTreeMap::new() };
        }
        let edges: Vec<(Va, &[crate::ir::Successor])> = blocks.iter().map(|b| (b.start, b.successors.as_slice())).collect();
        let (succ, pred) = crate::dom::block_graph_of(&edges);
        let dom = crate::dom::dominators_fwd(blocks.len(), &pred);
        let mut reach = BTreeMap::new();
        for c in &list {
            reach.entry(c.at.block).or_insert_with(|| {
                let mut seen = vec![false; blocks.len()];
                let mut stack: Vec<usize> = succ[c.at.block].clone();
                while let Some(b) = stack.pop() {
                    if !std::mem::replace(&mut seen[b], true) {
                        stack.extend_from_slice(&succ[b]);
                    }
                }
                seen
            });
        }
        Constructions { list, dom, reach }
    }

    /// Does `a` run before `b` on every path from the entry to `b`?
    fn dominates(&self, a: At, b: At) -> bool {
        if a.block == b.block { a.stmt < b.stmt } else { self.dom.get(b.block).is_some_and(|d| d.contains(&a.block)) }
    }

    /// Is there a path from just after `a` to `b`?
    fn reaches(&self, a: At, b: At) -> bool {
        (a.block == b.block && a.stmt < b.stmt) || self.reach.get(&a.block).is_some_and(|r| r.get(b.block).copied().unwrap_or(false))
    }

    /// The class the constructions of `base` give it at `at`, by the rule above.
    pub(crate) fn at(&self, base: &str, at: At) -> Constructed<'_> {
        let mut nearest: Option<&Construction> = None;
        for c in self.list.iter().filter(|c| c.base == base) {
            if self.dominates(c.at, at) {
                if nearest.is_none_or(|n| self.dominates(n.at, c.at)) {
                    nearest = Some(c);
                }
            } else if self.reaches(c.at, at) {
                return Constructed::Refused;
            }
        }
        nearest.map_or(Constructed::Unsaid, |c| Constructed::Exact(c.class.as_str()))
    }
}

/// A constructor of a class called with a variable as its `this` (argument
/// 0, by the ABI): the variable and the class.
fn ctor_construction<'a>(ctx: &Ctx, stmt: &'a MicroStmt, defs: &'a BTreeMap<&'a str, &'a MicroExpr>) -> Option<(&'a str, String)> {
    let (MicroStmt::Call { target: CallTarget::Direct { va }, args, .. }
    | MicroStmt::Assign { value: MicroExpr::Call { target: CallTarget::Direct { va }, args }, .. }) = stmt
    else {
        return None;
    };
    let MicroExpr::Var(v) = resolve(args.first()?, defs) else { return None };
    Some((v.as_str(), crate::classlayout::ctor_class(ctx, *va)?))
}

/// A known vtable stored at offset 0 of a variable: the variable and the class.
fn store_construction<'a>(ctx: &Ctx, stmt: &'a MicroStmt, defs: &'a BTreeMap<&'a str, &'a MicroExpr>) -> Option<(&'a str, Classed)> {
    let MicroStmt::Store { addr, value, .. } = stmt else { return None };
    let Some((base, 0)) = base_offset(addr, defs) else { return None };
    Some((base, stored_vtable_class(ctx, value, defs)?))
}

/// The class whose **vtable** this stored value is, if it is one. Accepts the
/// address either as a bare constant or behind an `&`, which is the same value
/// spelled two ways by the lift.
fn stored_vtable_class(ctx: &Ctx, value: &MicroExpr, defs: &BTreeMap<&str, &MicroExpr>) -> Option<Classed> {
    let inner = match resolve(value, defs) {
        MicroExpr::AddrOf(i) => resolve(i, defs),
        other => other,
    };
    let MicroExpr::Const { value, .. } = inner else { return None };
    let addr = u64::try_from(*value).ok()?;
    ctx.vtables?.classes.get(&addr).map(|c| Classed::new(c.as_str(), ClassFrom::Built))
}

/// The class an rvalue holds, if any — the per-expression half of
/// [`class_closure`].
fn value_class(
    ctx: &Ctx,
    e: &MicroExpr,
    cls: &BTreeMap<String, Classed>,
    slots: &[(&MicroExpr, Classed)],
    defs: &BTreeMap<&str, &MicroExpr>,
    ret_class: &impl Fn(u64) -> Option<Classed>,
) -> Option<Classed> {
    match e {
        MicroExpr::Var(v) => cls.get(v.as_str()).cloned(),
        MicroExpr::Cast { expr, .. } => value_class(ctx, expr, cls, slots, defs, ret_class),
        MicroExpr::Call { target: CallTarget::Direct { va }, .. } => ret_class(va.get()),
        MicroExpr::Load { addr, .. } => {
            if let Some((_, c)) = slots.iter().find(|(a, _)| *a == &**addr) {
                return Some(c.clone());
            }
            let (base, offset) = base_offset(addr, defs)?;
            let owner = cls.get(base)?;
            let ty = ctx.layout.and_then(|l| l.field_type(&owner.class, offset))?;
            if !ty.trim_end().ends_with('*') {
                return None;
            }
            class_of(ty).map(|c| Classed::new(c, ClassFrom::Field))
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
    let sorted = sorted_vtables(vtables);
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

/// Vtable addresses in ascending order — the basis for "where does this table
/// end", which is the same bound for a table reached by name and one reached by
/// its address.
fn sorted_vtables(vtables: &HashMap<u64, String>) -> Vec<u64> {
    let mut sorted: Vec<u64> = vtables.keys().copied().collect();
    sorted.sort_unstable();
    sorted
}

/// Resolve every virtual call this function makes that can be resolved
/// *soundly*, rewriting the call target in place and returning what was
/// resolved. A no-op without a recovered vtable map.
pub fn devirtualize(ctx: &Ctx, blocks: &mut [SsaBlock], types: &TypeArtifact) -> Vec<Devirtualized> {
    let Some(crate::Vtables { classes: vtables, slots }) = ctx.vtables else { return Vec::new() };
    if vtables.is_empty() {
        return Vec::new();
    }
    // A slot is one of the **image's** pointers. It was eight bytes whatever the
    // image was, so on a 32-bit one the slot read joined two methods into one
    // value and the bound below refused a table's last slot.
    let slot_width = u64::from(slots.pointer_size);
    let by_class = class_to_vtable(vtables);
    let sorted = sorted_vtables(vtables);


    let code: Vec<(u64, u64)> =
        n0xis_sources::MemorySource::code_ranges(ctx.source).into_iter().map(|(s, n)| (s.get(), s.get() + n)).collect();
    let is_code = |va: u64| code.iter().any(|(s, e)| va >= *s && va < *e);

    // Every variable's defining expression, so the two halves of a dispatch can
    // be rejoined however the optimizer split them. Built before the rewrite so
    // it borrows nothing that is about to change.
    let mut defs: BTreeMap<&str, &MicroExpr> = blocks
        .iter()
        .flat_map(|b| b.stmts.iter())
        .filter_map(|s| match &s.stmt {
            MicroStmt::Assign { dst, value } => Some((dst.as_str(), value)),
            _ => None,
        })
        .collect();
    fold_phis(blocks, &mut defs);
    let defs = defs;

    // Which variables hold an object of a known class — seeded from the
    // parameters and carried along every edge that carries a value.
    // No early return on an empty class map: a dispatch through a **constant**
    // vtable needs no class at all, and a function whose only dispatch is that
    // shape would have been refused before it was looked at.
    // A class a construction establishes is not in it: that is asked at each
    // dispatch, of the constructions that reach it.
    let var_class = class_closure(ctx, blocks, types, &defs, BuiltClasses::AtDominatedPoints);
    let built = Constructions::of(ctx, blocks, &defs);
    // The subclass guard's one question, asked the same way by every basis it
    // protects. No hierarchy attached is no refusal.
    let may_have_subclass = |class: &str| ctx.subclassed.is_some_and(|s| s.may_have_subclass(class));

    let mut out = Vec::new();
    let mut plan: Vec<(usize, usize, Devirtualized)> = Vec::new();
    let mut consider = |bi: usize, si: usize, target: &CallTarget| {
        let CallTarget::Indirect(expr) = target else { return };
        let Some((object, slot)) = as_vtable_dispatch(expr, &defs) else { return };
        // Where the table is, and which class it belongs to. Every route but the
        // last has to *find* the class and then look its table up; the constant
        // route already has the table and reads the class off it.
        let mut bounds = None;
        let basis;
        let class: &str = match object {
            // The table's address is in the instruction. Multiple inheritance is
            // no obstacle here — the usual refusal exists because a class name
            // cannot say *which* of its tables a dispatch goes through, and this
            // one names the table itself.
            Object::Vtable(va) => {
                basis = "vtable";
                let Some(name) = vtables.get(&va) else { return };
                let Some(end) = sorted.binary_search(&va).ok().and_then(|i| sorted.get(i + 1).copied()) else { return };
                bounds = Some((va, end));
                name.as_str()
            }
            Object::Var(v) => {
                basis = "object";
                match built.at(v, At { block: bi, stmt: si }) {
                    // The class the object was built with, at this point.
                    Constructed::Exact(c) => c,
                    Constructed::Refused => return,
                    Constructed::Unsaid => {
                        let Some(c) = var_class.get(v) else { return };
                        // A class the variable has only by a declared type is
                        // refused where the class may be derived from in this
                        // image — the object may be of the subclass, whose slot
                        // holds another method.
                        if c.from.refused_when_subclassed() && may_have_subclass(&c.class) {
                            return;
                        }
                        c.class.as_str()
                    }
                }
            }
            // A dispatch on a field needs the field's type, which only the
            // program-wide layout holds — and it must be a **pointer** type: an
            // embedded sub-object's first word is its own vptr, so treating
            // `Widget` and `Widget *` alike here would resolve a slot of the
            // wrong table with full confidence.
            Object::Field { base, offset } => {
                basis = "field";
                // The owner's class is asked the way an object's is: the
                // constructions that reach this point first.
                let owner = match built.at(base, At { block: bi, stmt: si }) {
                    Constructed::Exact(c) => c,
                    Constructed::Refused => return,
                    Constructed::Unsaid => match var_class.get(base) {
                        Some(c) => c.class.as_str(),
                        None => return,
                    },
                };
                let Some(ty) = ctx.layout.and_then(|l| l.field_type(owner, offset)) else { return };
                if !ty.trim_end().ends_with('*') {
                    return;
                }
                let Some(c) = class_of(ty) else { return };
                // The layout gives the type of something *stored into* the
                // field once, which may be a base of what is really there. A
                // base class's table is a different table, and a derived class
                // that overrides the slot holds a different method — so this
                // basis is refused for any class the image itself shows being
                // derived from. Measured on one Qt build: 5 of 88 resolutions,
                // all of them through a class with subclasses right there in
                // the same image.
                if may_have_subclass(c) {
                    return;
                }
                c
            }
        };
        if bounds.is_none() {
            bounds = by_class.get(class).copied();
        }
        let Some((vtable, vtable_end)) = bounds else { return };
        let Some(addr) = vtable.checked_add(slot) else { return };
        // The slot must be inside THIS class's table, or we would read the next
        // class's and report its method with full confidence.
        if addr.saturating_add(slot_width) > vtable_end {
            return;
        }
        let Some(value) = crate::rtti::read_pointer(ctx.source, Va(addr), slots.pointer_size) else { return };
        // A null or non-code slot is an honest "unresolved", not a callee.
        if value == 0 || !is_code(value) {
            return;
        }
        // A Thumb method on EM_ARM is not resolved to its odd address — the
        // interim refusal [`crate::VtableSlots::method`] documents.
        let Ok(method) = slots.method(value) else { return };
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
        // A vtable slot can point at an import stub — `_purecall` fills every
        // abstract slot — so this asks the same question `function discover`
        // does, through the same helper.
        let symbol = crate::ir::symbol_on_entry(ctx, Va(method)).map(|s| s.name);
        // The slot's index in its table — the `N` that `rtti_symbol_map`
        // gives the same method, counted at the same width.
        let owned = format!("{class}::vf{}", slot / slot_width);
        let (name, implementation) = match symbol {
            Some(sym) if sym.starts_with(&format!("{class}::")) => (sym, None),
            Some(sym) => (owned, Some(sym)),
            None => (owned, None),
        };
        plan.push((bi, si, Devirtualized { class: class.to_string(), slot, method: Va(method), name, implementation, basis }));
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

    /// `rax = &Widget::vtable; call *(rax + 0x10)` — the compiler already knew
    /// the class and wrote the table's address into a register, so there is no
    /// vptr load to follow and no type to recover. Measured on a Qt shared
    /// library: 7 dispatches of the 670 that stayed unresolved are this shape,
    /// and the ROADMAP claim that it "does not visibly fire here" was wrong.
    #[test]
    fn a_constant_vtable_address_is_a_dispatch_with_no_object_to_type() {
        let table = MicroExpr::AddrOf(Box::new(MicroExpr::constant(0x9000, 64)));
        let defs: BTreeMap<&str, &MicroExpr> = [("v1", &table)].into_iter().collect();
        let call = MicroExpr::load(
            MicroExpr::Binary(
                n0xis_arch::BinOp::Add,
                Box::new(MicroExpr::Var("v1".into())),
                Box::new(MicroExpr::constant(0x10, 64)),
            ),
            64 as Bits,
            false,
        );
        assert_eq!(as_vtable_dispatch(&call, &defs), Some((Object::Vtable(0x9000), 0x10)));
        // A bare constant spelled without the `&` is the same value.
        let bare = MicroExpr::constant(0x9000, 64);
        let defs2: BTreeMap<&str, &MicroExpr> = [("v1", &bare)].into_iter().collect();
        assert_eq!(as_vtable_dispatch(&call, &defs2), Some((Object::Vtable(0x9000), 0x10)));
        // A *computed* table base is still refused — only a constant is proof.
        let computed = MicroExpr::load(
            MicroExpr::Binary(
                n0xis_arch::BinOp::Add,
                Box::new(MicroExpr::Var("rcx.0".into())),
                Box::new(MicroExpr::constant(0x10, 64)),
            ),
            64 as Bits,
            false,
        );
        assert_eq!(as_vtable_dispatch(&computed, &BTreeMap::new()), None);
    }

    /// A 32-bit image: code at `0x1000..0x1100`, and three vtables laid end to
    /// end with **4-byte** slots — `Widget` at `0x2000` holding three methods,
    /// `Next` straight after it, and `Last`, which bounds `Next`.
    struct Image32(n0xis_sources::Snapshot);
    impl n0xis_sources::MemorySource for Image32 {
        fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, n0xis_sources::SourceError> {
            self.0.read(va, len)
        }
        fn contains(&self, va: Va) -> bool {
            self.0.contains(va)
        }
        fn code_range(&self) -> Option<(Va, u64)> {
            Some((Va(0x1000), 0x100))
        }
        fn label(&self) -> String {
            "test:image32".into()
        }
    }

    fn image32(methods: [u32; 4]) -> Image32 {
        let mut table = Vec::new();
        for method in methods {
            table.extend_from_slice(&method.to_le_bytes()); // Widget's three, then Next's first
        }
        Image32(n0xis_sources::Snapshot::builder().region(Va(0x1000), vec![0xC3; 0x100]).region(Va(0x2000), table).build())
    }

    const METHODS: [u32; 4] = [0x1010, 0x1020, 0x1030, 0x1040];
    const PLAIN_32: crate::VtableSlots = crate::VtableSlots { pointer_size: 4, code_pointers: crate::CodePointers::Address };

    /// One dispatch at 32 bits: `[*ecx = &Widget::vtable;] v1 = *ecx; call
    /// *(v1 + slot)`, with `ecx` declared `this_ty`.
    struct Case32 {
        methods: [u32; 4],
        slots: crate::VtableSlots,
        this_ty: &'static str,
        /// Store Widget's vtable into the object first — the constructor idiom.
        stores_vtable: bool,
        subclassed: Option<crate::Subclasses>,
        slot: i128,
        /// Dispatch on the object in `this`'s field at `+8` instead, which the
        /// layout types `Widget *` in a `this` declared `Owner *`.
        through_field: bool,
    }

    /// `Owner`'s field at `+8` is a `Widget *`.
    struct OwnerLayout;
    impl crate::ClassLayoutLookup for OwnerLayout {
        fn field_type(&self, class: &str, offset: i64) -> Option<&str> {
            (class == "Owner" && offset == 8).then_some("Widget *")
        }
    }

    impl Default for Case32 {
        fn default() -> Self {
            Case32 { methods: METHODS, slots: PLAIN_32, this_ty: "Widget *", stores_vtable: false, subclassed: None, slot: 4, through_field: false }
        }
    }

    fn devirtualize32(case: Case32) -> Vec<Devirtualized> {
        use crate::typeinfer::{CType, ParamInfo, RecoveredSignature, ReturnType};
        let img = image32(case.methods);
        let arch = n0xis_arch::X64::x86();
        let vtables: std::sync::Arc<HashMap<u64, String>> = std::sync::Arc::new(
            [(0x2000u64, "Widget".to_string()), (0x200c, "Next".to_string()), (0x3000, "Last".to_string())].into_iter().collect(),
        );
        let subclassed = case.subclassed.map(std::sync::Arc::new);
        let mut ctx = Ctx::new(&img, &arch).with_vtables(&vtables, case.slots);
        if let Some(s) = &subclassed {
            ctx = ctx.with_subclassed(s);
        }
        if case.through_field {
            ctx = ctx.with_layout(&OwnerLayout);
        }
        let this = MicroExpr::Var("ecx.0".into());
        let object = if case.through_field {
            MicroExpr::load(MicroExpr::Binary(n0xis_arch::BinOp::Add, Box::new(this), Box::new(MicroExpr::constant(8, 32))), 32 as Bits, false)
        } else {
            this
        };
        let stmt = |stmt| crate::ssa::SsaStmt { va: Va(0x1000), stmt };
        let target = MicroExpr::load(
            MicroExpr::Binary(n0xis_arch::BinOp::Add, Box::new(MicroExpr::Var("v1".into())), Box::new(MicroExpr::constant(case.slot, 32))),
            32 as Bits,
            false,
        );
        let mut stmts = Vec::new();
        if case.stores_vtable {
            stmts.push(stmt(MicroStmt::Store { addr: MicroExpr::Var("ecx.0".into()), value: MicroExpr::constant(0x2000, 32), bits: 32 as Bits }));
        }
        stmts.push(stmt(MicroStmt::Assign { dst: "v1".into(), value: MicroExpr::load(object, 32 as Bits, false) }));
        stmts.push(stmt(MicroStmt::Call { target: CallTarget::Indirect(Box::new(target)), args: Vec::new(), ret: None }));
        let mut blocks = vec![SsaBlock {
            id: 0,
            start: Va(0x1000),
            end: Va(0x1010),
            terminator: "ret".into(),
            successors: Vec::new(),
            phis: Vec::new(),
            stmts,
            condition: None,
        }];
        let types = TypeArtifact {
            locals: Vec::new(),
            structs: Vec::new(),
            signature: RecoveredSignature {
                params: vec![ParamInfo { reg: "ecx", name: "ecx".into(), ty: CType::named(case.this_ty) }],
                ret: ReturnType::Unknown,
                ret_registers: Vec::new(),
                params_known: true,
            },
        };
        devirtualize(&ctx, &mut blocks, &types)
    }

    /// `v1 = *ecx; call *(v1 + slot)` with `ecx` typed `Widget *` — the dispatch
    /// shape, at 32 bits.
    fn devirtualize_slot32(slot: i128, pointer_size: u8) -> Vec<Devirtualized> {
        devirtualize32(Case32 { slot, slots: crate::VtableSlots { pointer_size, code_pointers: crate::CodePointers::Address }, ..Case32::default() })
    }

    /// A slot is one of the **image's** pointers. Read at a fixed eight bytes,
    /// slot 1 of a 32-bit table joined methods 1 and 2 into `0x0000103000001020`
    /// — no code address, so the call stayed unresolved — and the last slot was
    /// refused because eight bytes from it ran into the next table.
    #[test]
    fn a_32_bit_slot_is_read_four_bytes_wide() {
        let one = devirtualize_slot32(4, 4);
        assert_eq!(one.len(), 1, "slot 1 of a 4-byte table: {one:?}");
        assert_eq!((one[0].method, one[0].slot, one[0].name.as_str()), (Va(0x1020), 4, "Widget::vf1"));
        let last = devirtualize_slot32(8, 4);
        assert_eq!(last.first().map(|d| (d.method, d.name.as_str())), Some((Va(0x1030), "Widget::vf2")), "the last slot is inside the table");
        // Slot 3 is `Next`'s first method: out of `Widget`'s table, refused.
        assert!(devirtualize_slot32(12, 4).is_empty(), "a slot past the table reads the next class's");
    }

    fn widget_is_derived_from() -> Option<crate::Subclasses> {
        Some(crate::Subclasses::Known(["Widget".to_string()].into_iter().collect()))
    }

    /// A parameter's declared type is a **static** type. `Base::h` calling `g`
    /// through `this` on a `Derived` runs `Derived::g` on the processor
    /// (`processor_run.cpp` beside the Itanium fixtures, printed 42), so a
    /// class that `this` has only by its declaration is refused where the
    /// image derives from it — and kept where it does not.
    #[test]
    fn a_parameters_declared_class_is_refused_when_the_class_has_a_subclass() {
        let derived = devirtualize32(Case32 { subclassed: widget_is_derived_from(), ..Case32::default() });
        assert!(derived.is_empty(), "Widget has a subclass here: the object may be one: {derived:?}");
        let alone = devirtualize32(Case32 { subclassed: Some(crate::Subclasses::Known(["Other".to_string()].into_iter().collect())), ..Case32::default() });
        assert_eq!(alone.first().map(|d| (d.method, d.basis)), Some((Va(0x1020), "object")), "no class derives from Widget: {alone:?}");
    }

    /// Where any class's bases are unknown, any class may have a subclass, and
    /// the declared class is refused for that reason alone.
    #[test]
    fn an_unknown_hierarchy_refuses_a_declared_class() {
        let out = devirtualize32(Case32 { subclassed: Some(crate::Subclasses::Unknown { classes: 1 }), ..Case32::default() });
        assert!(out.is_empty(), "one class's bases unknown: Widget may have a subclass: {out:?}");
    }

    /// A vtable this function stores into the object is its dynamic type, so
    /// the dispatch stands even though the class has a subclass — the `fresh`
    /// case, and the reason the refusal is by how the class was established
    /// rather than by class.
    #[test]
    fn a_stored_vtable_is_the_dynamic_type_and_stands() {
        for this_ty in ["void *", "Widget *"] {
            let out = devirtualize32(Case32 { this_ty, stores_vtable: true, subclassed: widget_is_derived_from(), ..Case32::default() });
            assert_eq!(out.first().map(|d| (d.method, d.name.as_str())), Some((Va(0x1020), "Widget::vf1")), "`this` declared {this_ty}: {out:?}");
        }
    }

    /// The field basis asks the same question: a class that may have a
    /// subclass is refused — and where any class's bases are unknown, that is
    /// every class. Before, an image whose bases could not be read gave the
    /// guard an empty set, and the field basis resolved through any class.
    #[test]
    fn the_field_basis_refuses_a_class_that_may_have_a_subclass() {
        let field = |subclassed| devirtualize32(Case32 { this_ty: "Owner *", through_field: true, subclassed, ..Case32::default() });
        let none = field(Some(crate::Subclasses::Known(std::collections::HashSet::new())));
        assert_eq!(none.first().map(|d| (d.method, d.basis)), Some((Va(0x1020), "field")), "nothing derives from Widget: {none:?}");
        assert!(field(widget_is_derived_from()).is_empty(), "Widget has a subclass");
        assert!(field(Some(crate::Subclasses::Unknown { classes: 1 })).is_empty(), "the hierarchy is not known");
    }

    /// On 32-bit ARM a slot holding a Thumb method holds its address with bit
    /// 0 set. Resolved as it was, the call went to the odd address. Refused on
    /// `EM_ARM` until one rule clears the bit for symbols and slots alike; the
    /// same image read as plain code pointers resolves as before.
    #[test]
    fn a_thumb_slot_is_not_resolved_on_arm() {
        let thumb = [0x1011, 0x1021, 0x1031, 0x1041];
        let arm = crate::VtableSlots { pointer_size: 4, code_pointers: crate::CodePointers::ArmInterworking };
        assert!(devirtualize32(Case32 { methods: thumb, slots: arm, ..Case32::default() }).is_empty(), "an odd slot on EM_ARM");
        let even = devirtualize32(Case32 { slots: arm, ..Case32::default() });
        assert_eq!(even.first().map(|d| d.method), Some(Va(0x1020)), "an even slot on EM_ARM is an A32 method: {even:?}");
        let plain = devirtualize32(Case32 { methods: thumb, ..Case32::default() });
        assert_eq!(plain.first().map(|d| d.method), Some(Va(0x1021)), "elsewhere the value is the address: {plain:?}");
    }

    /// A function of planted blocks at 32 bits over [`image32`]'s tables:
    /// `Widget` at `0x2000`, whose slot 0 holds `0x1010`, and `Next` at
    /// `0x200c`, whose slot 0 holds `0x1040`. Each block is its statements and
    /// the blocks it goes to; the object is `ecx`, declared `this_ty`, and no
    /// class derives from any other.
    fn devirtualize_blocks(this_ty: &str, blocks: Vec<(Vec<MicroStmt>, Vec<usize>)>) -> Vec<(u64, Va)> {
        use crate::typeinfer::{CType, ParamInfo, RecoveredSignature, ReturnType};
        let img = image32(METHODS);
        let arch = n0xis_arch::X64::x86();
        let vtables: std::sync::Arc<HashMap<u64, String>> = std::sync::Arc::new(
            [(0x2000u64, "Widget".to_string()), (0x200c, "Next".to_string()), (0x3000, "Last".to_string())].into_iter().collect(),
        );
        let none_derived = std::sync::Arc::new(crate::Subclasses::Known(std::collections::HashSet::new()));
        let ctx = Ctx::new(&img, &arch).with_vtables(&vtables, PLAIN_32).with_subclassed(&none_derived);
        let start = |i: usize| Va(0x1000 + 0x10 * i as u64);
        let mut blocks: Vec<SsaBlock> = blocks
            .into_iter()
            .enumerate()
            .map(|(i, (stmts, to))| SsaBlock {
                id: i,
                start: start(i),
                end: start(i + 1),
                terminator: if to.is_empty() { "ret".into() } else { "jmp".into() },
                successors: to.into_iter().map(|j| crate::ir::Successor { to: start(j), kind: "jmp".into(), confidence: 1.0 }).collect(),
                phis: Vec::new(),
                stmts: stmts.into_iter().map(|stmt| crate::ssa::SsaStmt { va: start(i), stmt }).collect(),
                condition: None,
            })
            .collect();
        let types = TypeArtifact {
            locals: Vec::new(),
            structs: Vec::new(),
            signature: RecoveredSignature {
                params: vec![ParamInfo { reg: "ecx", name: "ecx".into(), ty: CType::named(this_ty) }],
                ret: ReturnType::Unknown,
                ret_registers: Vec::new(),
                params_known: true,
            },
        };
        devirtualize(&ctx, &mut blocks, &types).into_iter().map(|d| (d.slot, d.method)).collect()
    }

    /// `*ecx = &table` — a construction of the object.
    fn build(table: i128) -> MicroStmt {
        MicroStmt::Store { addr: MicroExpr::Var("ecx.0".into()), value: MicroExpr::constant(table, 32), bits: 32 as Bits }
    }

    /// `v = *ecx; call *v` — a dispatch through slot 0, its vptr in `v`.
    fn call_slot0(v: &str) -> [MicroStmt; 2] {
        [
            MicroStmt::Assign { dst: v.into(), value: MicroExpr::load(MicroExpr::Var("ecx.0".into()), 32 as Bits, false) },
            MicroStmt::Call { target: CallTarget::Indirect(Box::new(MicroExpr::load(MicroExpr::Var(v.into()), 32 as Bits, false))), args: Vec::new(), ret: None },
        ]
    }

    const WIDGET_VF0: (u64, Va) = (0, Va(0x1010));
    const NEXT_VF0: (u64, Va) = (0, Va(0x1040));

    /// `flow.cpp`'s `g`: the object is built as a `Widget` on one branch and
    /// called on the other. The construction does not dominate the call (and
    /// cannot reach it), so it says nothing there. Taken as the variable's
    /// class, it resolved the call to `Widget::vf0` — `B::f` in `flow.cpp`,
    /// where the processor runs `D::f`.
    #[test]
    fn a_construction_on_another_branch_does_not_name_the_object() {
        let out = devirtualize_blocks("void *", vec![(vec![], vec![1, 2]), (vec![build(0x2000)], vec![]), (call_slot0("v1").to_vec(), vec![])]);
        assert_eq!(out, vec![], "the vtable stored on the other branch is not the object's here");
    }

    /// A construction that dominates the call names the object there, through
    /// a branch or in the same block.
    #[test]
    fn a_dominating_construction_names_the_object() {
        let across = devirtualize_blocks("void *", vec![(vec![build(0x200c)], vec![1, 2]), (vec![], vec![]), (call_slot0("v1").to_vec(), vec![])]);
        assert_eq!(across, vec![NEXT_VF0]);
        let mut same = vec![build(0x200c)];
        same.extend(call_slot0("v1"));
        assert_eq!(devirtualize_blocks("void *", vec![(same, vec![])]), vec![NEXT_VF0]);
    }

    /// Of the dominating constructions the nearest wins — by the dominator
    /// tree, not by block order: here the nearer one (`Widget`, block 1) comes
    /// first in block order, and taking the last in that order named `Next`.
    #[test]
    fn the_nearest_dominating_construction_wins() {
        let chain = vec![
            (vec![], vec![2]),
            (vec![build(0x2000)], vec![3]),
            (vec![build(0x200c)], vec![1]),
            (call_slot0("v1").to_vec(), vec![]),
        ];
        assert_eq!(devirtualize_blocks("void *", chain), vec![WIDGET_VF0], "0 -> 2 (Next) -> 1 (Widget) -> 3 (call)");
        let mut same = vec![build(0x200c), build(0x2000)];
        same.extend(call_slot0("v1"));
        assert_eq!(devirtualize_blocks("void *", vec![(same, vec![])]), vec![WIDGET_VF0], "the later store in the block");
    }

    /// A construction that does not dominate the call but can reach it refuses
    /// the call: on that path the object was built again.
    #[test]
    fn a_construction_that_reaches_without_dominating_refuses() {
        let out = devirtualize_blocks("void *", vec![(vec![build(0x200c)], vec![1, 2]), (vec![build(0x2000)], vec![2]), (call_slot0("v1").to_vec(), vec![])]);
        assert_eq!(out, vec![], "built as Next, and as Widget on one path to the call");
        // Through a loop: a construction after the call in its own block
        // reaches it on the next iteration.
        let body = |loops: bool| {
            let mut stmts = vec![build(0x200c)];
            stmts.extend(call_slot0("v1"));
            stmts.push(build(0x2000));
            devirtualize_blocks("void *", vec![(vec![], vec![1]), (stmts, if loops { vec![1, 2] } else { vec![2] }), (vec![], vec![])])
        };
        assert_eq!(body(true), vec![], "the Widget store after the call reaches it around the loop");
        assert_eq!(body(false), vec![NEXT_VF0], "without the loop it cannot reach the call");
    }

    /// Where no construction reaches the call, the object's class is the one
    /// its declaration gives, under that basis's own guard — not the class a
    /// construction elsewhere stored.
    #[test]
    fn without_a_construction_the_declared_class_answers() {
        let out = devirtualize_blocks("Widget *", vec![(vec![], vec![1, 2]), (vec![build(0x200c)], vec![]), (call_slot0("v1").to_vec(), vec![])]);
        assert_eq!(out, vec![WIDGET_VF0], "`this` is declared Widget, and nothing derives from Widget here");
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
