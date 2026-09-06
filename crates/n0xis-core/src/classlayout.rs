// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Field-layout unification across every user of a class** (ROADMAP Phase 10,
//! the remaining ⬜ of priority 3b).
//!
//! [`typeinfer`](crate::typeinfer) already recovers fields — but *per function*,
//! and it names the result after the register the pointer happened to arrive in
//! (`struct_rdi_0`). Two consequences, both measured rather than assumed:
//!
//! - **Nothing about an object survives leaving its function.** `Widget::paint`
//!   knows `+0x30` is 8 bytes; `Widget::resize` rediscovers it from scratch and
//!   learns nothing from the other. A class is described by as many disjoint
//!   half-layouts as it has methods.
//! - **Those names cannot travel.** [`typeprop`](crate::typeprop) refuses to
//!   propagate a `struct_*` name precisely because it is per-function and
//!   arbitrary — its ambiguity check compares names, so two unrelated callers
//!   each holding a `struct_rdi_0` would compare *equal* and silently merge two
//!   different objects. On the Qt desktop PE that refusal accounted for 5 628 of 5 724
//!   typed arguments.
//!
//! Both are the same missing thing: an aggregate has no **program-wide
//! identity**. This pass gives it one, and the identity is not invented — it is
//! the RTTI class name the `this` pointer already carries.
//!
//! ## What it does
//!
//! 1. For every discovered function, ask its **own symbol** which class it is a
//!    method of — a constructor/destructor (where the ABI settles that argument
//!    0 is `this`), an MSVC symbol that states non-staticness, or a
//!    `Class::method` name whose `Class` RTTI recovered a vtable for.
//! 2. Every field access through `this` (or through a plain copy of it) is an
//!    observation about **that class**, not about that function. Merge them:
//!    widest access wins the size, any signed use makes the field signed, counts
//!    add up, and the number of contributing methods is kept.
//! 3. Type the field from three kinds of evidence — an embedded sub-object
//!    (`&this->f` handed to a constructor), a pointer field (`this->f` handed to
//!    a member function as its `this`), and a class-typed value stored into it.
//!    Two sources that disagree mark the field ambiguous, permanently.
//!
//! ## Why the class comes from the symbol and never from the parameter type
//!
//! Reading the first parameter's recovered type is the obvious shortcut and it
//! is wrong, in a way that looks exactly like a result. A derived class's method
//! has a `this` that legitimately *is* a base-class pointer, and a derived
//! class's constructor legitimately stores the *base's* vtable into `this`
//! before installing its own. Both name a base class, so every field of the
//! derived object gets filed under the base. Measured on libQt6Gui:
//!
//! - `QRasterPlatformPixmap::toImage`, whose `this` types as `QPlatformPixmap *`,
//!   put a `QImage` at `+0x30` of a `QPlatformPixmap` the header says is `0x28`
//!   bytes long;
//! - the QRhi backend classes export no vtable of their own, so their
//!   constructors read as `QRhiResource` and inflated that base to an extent of
//!   `0x1e20` across 145 "methods".
//!
//! A symbol says which class the code was *written in*. Where there is no
//! symbol, base and derived genuinely cannot be told apart, and the honest
//! answer is to contribute nothing.
//!
//! ## The hidden return slot, and what is still not caught
//!
//! Nothing in an Itanium symbol says a function returns a large object by value
//! — and such a function does not receive `this` in the first argument register
//! at all: the caller passes a pointer to its own result buffer there.
//! `QTextDocument::toPlainText() const` looks exactly like an ordinary const
//! method, and reading its first argument as `this` filed `QString`'s fields
//! under `QTextDocument`. The ABI gives a precise marker — such a function must
//! hand that buffer back in `rax` — so a function that returns its own first
//! argument is refused ([`returns_first_arg`]).
//!
//! What remains, stated rather than hidden: a **static member function** has no
//! `this` and nothing local distinguishes it — `QTextDocument::setDefault…`
//! contributes its argument's fields to `QTextDocument`. Against 21 public Qt
//! classes checked with `sizeof` from the real headers, 19 layouts came out
//! inside the true size and 2 exceeded it by one field each — and in both the
//! false field carried `methods: 1`-`4` against `methods: 66` for the real ones.
//! The
//! per-field `methods` count is the confidence signal, and it is reported for
//! exactly this reason.
//!
//! ## What it unblocks
//!
//! A field with a known class type is a `this` for the object it points at, so
//! `this->impl->method()` — a dispatch on a **field** rather than on `this` —
//! becomes resolvable. That is the shape 33 of 199 sampled methods of the Qt desktop PE were
//! left holding after devirtualization landed.

use std::collections::{BTreeMap, BTreeSet};

use n0xis_arch::{Bits, CallTarget, MicroExpr, MicroStmt};
use n0xis_contracts::Va;
use serde::Serialize;

use crate::ssa::SsaBlock;
use crate::{CfgInput, CfgPass, CoreError, Ctx, OptimizePass, Pass, SsaPass, TypeInferInput, TypeInferPass};

/// How far a stored value is followed back through plain copies before giving
/// up. Real chains are a link or two; the bound is what stops a phi-shaped cycle
/// from spinning.
const MAX_COPY_DEPTH: usize = 16;

/// How many rounds the `this`-alias set is closed over. Copies form a chain, not
/// a cycle, so this converges immediately in practice.
const MAX_ALIAS_ROUNDS: usize = 8;

/// One field of one class, as every method that touches it agrees.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FieldObs {
    pub offset: i64,
    /// The **widest** access seen anywhere. A field read as a byte in one method
    /// and as a qword in another is a qword field with a narrow read, not two
    /// fields. `0` means no method ever loaded or stored it — the field is known
    /// only from its type (an embedded sub-object constructed in place).
    pub size_bits: Bits,
    /// True if *any* method used the value in a signed position.
    pub signed: bool,
    /// Accesses summed over every method.
    pub access_count: usize,
    /// How many distinct methods touched this offset — the confidence signal
    /// that separates a real field from one function's scratch arithmetic.
    pub methods: usize,
    /// The field's type, when something stored into it proved one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ty: Option<String>,
    /// Two sources disagreed about the type. Kept rather than dropped: "we know
    /// we do not know" is a different fact from "nobody looked", and it is what
    /// stops a later method re-answering it wrongly.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub ty_ambiguous: bool,
}

/// One class's unified layout.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct ClassLayout {
    /// Distinct methods that contributed observations.
    pub methods: usize,
    /// Fields, ascending by offset.
    pub fields: Vec<FieldObs>,
    /// Highest observed `offset + size`, i.e. a lower bound on the object's
    /// size. A *bound*, never the size: nothing here can see a field no method
    /// ever touches.
    pub extent: u64,
}

/// Every class the program describes, plus what the pass had to refuse.
#[derive(Clone, Debug, Default, Serialize)]
pub struct LayoutStore {
    /// Class name → unified layout.
    pub classes: BTreeMap<String, ClassLayout>,
    /// Functions the pass could analyze at all.
    pub functions_analyzed: usize,
    /// …of which had a first parameter typed as a class with a known vtable.
    pub methods_matched: usize,
    /// Field observations merged, across every method.
    pub observations: usize,
    /// Fields that came out with a type.
    pub typed_fields: usize,
    /// Fields two methods disagreed about.
    pub ambiguous_fields: usize,
    /// Field types that only the fixpoint could answer: the callee's return type
    /// was itself recovered from a field.
    pub fields_typed_by_fixpoint: usize,
    /// Per-method claims only source 4 could make — the value class closure,
    /// which sees an agreeing phi, a stack spill and a stored vtable that the
    /// plain copy walk does not.
    pub claims_by_value_closure: usize,
}

impl LayoutStore {
    /// The recovered type of `class`'s field at `offset`, if one was proven and
    /// nothing contradicted it.
    pub fn field_type(&self, class: &str, offset: i64) -> Option<&str> {
        let layout = self.classes.get(class)?;
        let f = layout.fields.iter().find(|f| f.offset == offset)?;
        if f.ty_ambiguous { None } else { f.ty.as_deref() }
    }
}

impl crate::ClassLayoutLookup for LayoutStore {
    fn field_type(&self, class: &str, offset: i64) -> Option<&str> {
        LayoutStore::field_type(self, class, offset)
    }
}

/// Which functions form the program, and how large a window each may occupy.
pub struct ClassLayoutInput {
    pub functions: Vec<Va>,
    pub max_bytes: usize,
}

/// Unify per-function field recovery into one layout per class.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClassLayoutPass;

impl Pass for ClassLayoutPass {
    type In = ClassLayoutInput;
    type Out = LayoutStore;

    fn name(&self) -> &'static str {
        "function.layout"
    }

    fn run(&self, ctx: &Ctx, input: ClassLayoutInput) -> Result<LayoutStore, CoreError> {
        Ok(unify(ctx, &input.functions, input.max_bytes))
    }
}

/// The symbol at `va`, demangled and cut back to its **qualified name**:
/// `_ZN7QPixmapC1Ev` → `QPixmap::QPixmap`, `?isNull@QPixmap@@QEBA_NXZ` →
/// `QPixmap::isNull`.
///
/// Demangling first is not cosmetic. An ELF symbol table hands out the mangled
/// form, so every `Class::method` test below sees `_ZN7QPixmapC1Ev` and matches
/// nothing at all — which is exactly how this pass first measured zero typed
/// fields on a binary full of them.
fn qualified_name(ctx: &Ctx, va: Va) -> Option<String> {
    let sym = ctx.symbols?.symbol_at(va).filter(|s| s.va == va)?;
    let bare = sym.name.rsplit('!').next().unwrap_or(&sym.name).to_string();
    let full = crate::demangle::demangle(&bare);
    let name = full.split('(').next().unwrap_or(&full).trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// Strip template arguments from a name's tail: `QList<int>` → `QList`.
fn stem(name: &str) -> &str {
    name.split_once('<').map(|(a, _)| a).unwrap_or(name).trim()
}

/// The class a function is a **constructor or destructor** of, read off its own
/// symbol.
///
/// This is the one class fact that needs no vtable and no inference: a symbol
/// whose last component repeats its own class (`QPixmap::QPixmap`,
/// `QPixmap::~QPixmap`) *is* a constructor, and a constructor's first argument
/// is `this` by the ABI. It is what lets a **non-polymorphic** class — `QPixmap`
/// has no vtable, so RTTI never names it — have a layout at all, and a
/// constructor is precisely the method that knows the most about one.
///
/// Template arguments are stripped on both sides before comparing, so
/// `QList<int>::QList` is recognized as readily as `QPixmap::QPixmap`.
pub(crate) fn ctor_class(ctx: &Ctx, va: Va) -> Option<String> {
    Some(ctor_class_of(&qualified_name(ctx, va)?)?.to_string())
}

/// The name half of [`ctor_class`], split out so the rule is testable without a
/// binary: is `qualified` the name of a constructor or destructor, and of what?
fn ctor_class_of(qualified: &str) -> Option<&str> {
    let (class, method) = qualified.rsplit_once("::")?;
    if class.is_empty() {
        return None;
    }
    let own = stem(class.rsplit("::").next().unwrap_or(class));
    let m = stem(method.strip_prefix('~').unwrap_or(method));
    (!own.is_empty() && own == m).then_some(class)
}

/// The class the function at `va` has a `this` pointer **to**, read off its own
/// symbol — for a direct callee's first argument, and equally for the function
/// under analysis ([`crate::typeinfer::own_this_class`]).
///
/// Three grounds, every one of them ground truth rather than inference:
///
/// - the symbol is a **constructor or destructor**, where the ABI settles it;
/// - the mangling **states** the function is a non-static member — MSVC's
///   access specifier, or an Itanium cv-qualifier, which a static member can
///   never carry ([`crate::demangle::member_function_class`]);
/// - the qualified name is `Class::method` and RTTI recovered a **vtable** for
///   `Class`. The vtable requirement is what keeps a namespaced free function
///   (`Ui::doSomething`) out where the mangling says nothing.
///
/// Only the first two survive a stripped-of-RTTI binary, and only the second
/// distinguishes a static member from an instance one — which is why the
/// vtable-keyed third ground stays last.
pub(crate) fn this_class_of(ctx: &Ctx, va: Va) -> Option<String> {
    if let Some(c) = ctor_class(ctx, va) {
        return Some(c);
    }
    if let Some(sym) = ctx.symbols.and_then(|s| s.symbol_at(va)).filter(|s| s.va == va) {
        let bare = sym.name.rsplit('!').next().unwrap_or(&sym.name).to_string();
        if let Some(c) = crate::demangle::member_function_class(&bare) {
            return Some(c);
        }
    }
    let name = qualified_name(ctx, va)?;
    let (class, _) = name.rsplit_once("::")?;
    let vtables = ctx.vtables?;
    (!class.is_empty() && vtables.values().any(|c| c == class)).then(|| class.to_string())
}

/// Peel casts off a value: `(uint64_t)w` stores the same object `w` does.
fn peel(e: &MicroExpr) -> &MicroExpr {
    let mut cur = e;
    for _ in 0..MAX_COPY_DEPTH {
        match cur {
            MicroExpr::Cast { expr, .. } => cur = expr,
            other => return other,
        }
    }
    cur
}

/// Recognize `Var(base) + Const(offset)` (either order) or a bare `Var(base)` —
/// the one address shape a field access takes after optimization. Mirrors
/// `typeinfer::as_base_offset`, kept local so the two can diverge without a
/// silent coupling.
fn as_base_offset(addr: &MicroExpr) -> Option<(&str, i64)> {
    match peel(addr) {
        MicroExpr::Var(name) => Some((name.as_str(), 0)),
        MicroExpr::Binary(n0xis_arch::BinOp::Add, l, r) => match (peel(l), peel(r)) {
            (MicroExpr::Var(name), MicroExpr::Const { value, .. }) => Some((name.as_str(), *value as i64)),
            (MicroExpr::Const { value, .. }, MicroExpr::Var(name)) => Some((name.as_str(), *value as i64)),
            _ => None,
        },
        _ => None,
    }
}

/// Every SSA name that holds the same pointer `this` does — `this` itself plus
/// whatever a plain copy carried it into. Without this the pass sees only the
/// accesses the optimizer happened to leave keyed on `rdi.0`.
pub(crate) fn alias_set(blocks: &[SsaBlock], this: &str) -> BTreeSet<String> {
    let mut set: BTreeSet<String> = [this.to_string()].into_iter().collect();
    for _ in 0..MAX_ALIAS_ROUNDS {
        let mut changed = false;
        for b in blocks {
            for s in &b.stmts {
                let MicroStmt::Assign { dst, value } = &s.stmt else { continue };
                let MicroExpr::Var(src) = peel(value) else { continue };
                if set.contains(src.as_str()) && set.insert(dst.clone()) {
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    set
}

/// Does the function **return its own first argument**?
///
/// The precise marker of the x64 hidden return slot. The ABI *requires* a
/// function that returns a large object by value to hand the caller's result
/// buffer back in `rax`, so returning argument 0 unchanged is not a stylistic
/// choice — it is what an `sret` function must do, and no ordinary method that
/// merely operates on `this` does it.
///
/// That matters because nothing in an Itanium symbol name says a function
/// returns by value: `QTextDocument::toPlainText() const` looks exactly like an
/// ordinary const method, but its first argument is a `QString` buffer, not
/// `this`, and reading it as `this` filed `QString`'s three fields under
/// `QTextDocument` — a 16-byte class reported with an extent of `0x20`.
///
/// It also refuses the handful of methods that genuinely return `*this`
/// (`operator=` and friends). That is a refusal, not a wrong answer, and it is
/// the trade this codebase makes everywhere else.
///
/// The match is on the returned value's **root register**, not on SSA identity,
/// and that is not laxity — it is what makes the test work at all on real code.
/// `QScreen::manufacturer() const` spills the buffer to the stack across a
/// virtual call and reloads it, so the value it returns is a join of `rdi.0` and
/// a stack reload; no copy chain connects the two, and matching SSA names alone
/// let a `QString` buffer through as a `QScreen *`. A returned value living in
/// the *first argument register* is the ABI marker regardless of how many
/// versions of that register the function went through.
pub(crate) fn returns_first_arg(blocks: &[SsaBlock], aliases: &BTreeSet<String>, this: &str) -> bool {
    let reg = root_reg(this);
    // A closure wider than `alias_set`'s, and deliberately so: this one also
    // crosses **phis**, because the buffer is routinely returned out of a join.
    // `QAction::toolTip() const` sets the result register from `this` on one arm
    // and from a stack reload on the other, so the value it returns is a phi
    // that no copy chain reaches. Widening here is safe in a way that widening
    // `alias_set` would not be: a false positive costs one refused method,
    // while the same looseness in the field-observation set would file a field
    // under a class that has none.
    let mut reach: BTreeSet<&str> = aliases.iter().map(String::as_str).collect();
    // Stack slots the buffer was spilled into. A large-object getter routinely
    // parks the result buffer on the stack for the length of the function and
    // reloads it at the end — `QFontIconEngine::scaledPixmap` does exactly that,
    // and returns the reload, so nothing in the copy graph connects the returned
    // value to the argument register. Tracking the *slot* is what crosses that.
    let mut slots: Vec<&MicroExpr> = Vec::new();
    let known = |set: &BTreeSet<&str>, v: &str| set.contains(v) || root_reg(v) == reg;
    for _ in 0..MAX_ALIAS_ROUNDS {
        let mut changed = false;
        for b in blocks {
            for phi in &b.phis {
                if phi.inputs.iter().any(|i| known(&reach, &i.value)) && reach.insert(phi.dst.as_str()) {
                    changed = true;
                }
            }
            for s in &b.stmts {
                match &s.stmt {
                    MicroStmt::Assign { dst, value } => match peel(value) {
                        MicroExpr::Var(src) if known(&reach, src) => {
                            changed |= reach.insert(dst.as_str());
                        }
                        MicroExpr::Load { addr, .. } if slots.contains(&&**addr) => {
                            changed |= reach.insert(dst.as_str());
                        }
                        _ => {}
                    },
                    MicroStmt::Store { addr, value, .. }
                        if matches!(peel(value), MicroExpr::Var(v) if known(&reach, v)) && !slots.contains(&addr) =>
                    {
                        slots.push(addr);
                        changed = true;
                    }
                    _ => {}
                }
            }
        }
        if !changed {
            break;
        }
    }
    blocks.iter().flat_map(|b| b.stmts.iter()).any(|s| match &s.stmt {
        MicroStmt::Return(Some(e)) => match peel(e) {
            MicroExpr::Var(v) => known(&reach, v),
            // The reload itself, returned without an intervening copy.
            MicroExpr::Load { addr, .. } => slots.contains(&&**addr),
            _ => false,
        },
        _ => false,
    })
}

/// The machine register an SSA name versions: `rdi.0`, `rdi.7`, `rdi` → `rdi`.
fn root_reg(name: &str) -> &str {
    name.split_once('.').map(|(r, _)| r).unwrap_or(name)
}

/// **Which** argument register holds `this`: `0` normally, `1` when the function
/// returns a large object by value.
///
/// The x64 ABI puts the caller's result buffer in the first argument register
/// and shifts `this` to the second, and requires the buffer to be handed back in
/// `rax` — [`returns_first_arg`] is that marker. Reading it as a *shift* rather
/// than as a reason to give up is what lets a by-value getter contribute at all:
/// `QFontIconEngine::pixmap()` is `pixmap(QPixmap *ret, QFontIconEngine *this,
/// …)`, and treating it as unanalyzable lost the class for every virtual call
/// the function makes on that `this`.
///
/// The known false positive is `operator=` and friends, which genuinely return
/// `*this`; there `this` really is argument 0 and argument 1 is a parameter. The
/// layout oracle is what keeps that honest — a class credited with a field it
/// does not have shows up as an extent past its true `sizeof`.
pub(crate) fn this_arg_index(blocks: &[SsaBlock], arg_regs: &[&str]) -> usize {
    let Some(arg0) = arg_regs.first().map(|r| format!("{r}.0")) else { return 0 };
    if arg_regs.len() < 2 {
        return 0;
    }
    let aliases = alias_set(blocks, &arg0);
    usize::from(returns_first_arg(blocks, &aliases, &arg0))
}

/// What one method contributes: `offset → (bits, signed, count)` plus the types
/// it proved for individual offsets.
struct MethodFacts {
    class: String,
    fields: BTreeMap<i64, (Bits, bool, usize)>,
    types: BTreeMap<i64, String>,
    /// `this->f = callee(...)` where the callee's return type was not known at
    /// the time. Kept so the fixpoint in [`unify`] can answer it once a return
    /// type is recovered — the field and the return type feed each other, and
    /// resolving them together costs one pass over facts rather than a second
    /// pass over code.
    pending: Vec<(i64, u64)>,
    /// Claims only the value class closure could make — see [`FieldFacts`].
    closure_typed: usize,
}

/// What one method says about the fields of its own object.
struct FieldFacts {
    types: BTreeMap<i64, String>,
    pending: Vec<(i64, u64)>,
    /// Claims only source 4 (the value class closure) could make — reported so
    /// each source's yield can be read separately rather than assumed.
    closure_typed: usize,
}

/// Analyze one function and, if it is a method of a known class, reduce it to
/// what it says about that class.
fn extract(ctx: &Ctx, va: Va, max_bytes: usize) -> Option<MethodFacts> {
    let cfg = CfgPass.run(ctx, CfgInput::new(va, max_bytes)).ok()?;
    if cfg.start != va || cfg.blocks.is_empty() {
        return None;
    }
    let ssa = SsaPass.run(ctx, cfg.clone()).ok()?;
    let opt = OptimizePass.run(ctx, ssa).ok()?;
    let types = TypeInferPass.run(ctx, TypeInferInput { cfg, blocks: opt.blocks.clone() }).ok()?;
    // Devirtualizing *before* reading the field types was tried here, on the
    // argument that a resolved `this->d->method()` names a class and would feed
    // rule 2 below. Measured on a Qt shared library: typed fields **90 → 90**,
    // and a third more wall-clock. The circularity is real; breaking it this way
    // buys nothing, because the dispatches that resolve are not the ones whose
    // result is handed on as a `this`.

    // `this` is the first ABI argument register, and it is a class only when
    // RTTI knows that class — the whole soundness bar, in one line.
    let arg_regs = crate::typeinfer::abi_arg_regs(ctx);
    let this = format!("{}.0", arg_regs.get(this_arg_index(&opt.blocks, &arg_regs))?);
    // Which class's layout does this function describe? **Only** what the
    // function's own symbol says — never the recovered type of its first
    // parameter.
    //
    // That restriction is the whole soundness of this pass, and it was arrived
    // at by measurement, not taste. A derived class's method has a `this` that
    // legitimately *is* a base-class pointer, and a derived class's constructor
    // legitimately stores the *base's* vtable into `this` before installing its
    // own. Both make the parameter type name a base class, so every field of the
    // derived object gets filed under the base:
    //
    // - `QRasterPlatformPixmap::toImage`, whose `this` types as
    //   `QPlatformPixmap *`, put a `QImage` at `+0x30` of a `QPlatformPixmap`
    //   that the header says is `0x28` bytes long;
    // - the QRhi backend classes carry no exported vtable of their own, so their
    //   constructors were read as `QRhiResource` and inflated that 0x20-byte
    //   base to an extent of `0x1e20` over 145 "methods".
    //
    // Both are real fields of real objects filed under the wrong name — the one
    // failure mode that looks exactly like a result. A symbol says which class
    // the code was *written in*; nothing else does, and where there is no symbol
    // the honest answer is that base and derived cannot be told apart.
    let class = this_class_of(ctx, va)?;

    let aliases = alias_set(&opt.blocks, &this);

    // Field observations: exactly the recovered aggregates whose base is `this`.
    let mut fields: BTreeMap<i64, (Bits, bool, usize)> = BTreeMap::new();
    for s in types.structs.iter().filter(|s| aliases.contains(&s.base_var)) {
        for f in &s.fields {
            let e = fields.entry(f.offset).or_insert((f.size_bits, f.signed, 0));
            e.0 = e.0.max(f.size_bits);
            e.1 |= f.signed;
            e.2 += f.access_count;
        }
    }
    let FieldFacts { types: types_by_offset, pending, closure_typed } =
        field_types(ctx, &opt.blocks, &types, &aliases, &arg_regs);
    // A field known only by its type is still a field — and a stronger sighting
    // than a bare access. `&this->f` handed to `QPixmap::QPixmap` proves an
    // embedded `QPixmap` at `f` in a function that never loads or stores it, so
    // keying the field set on accesses alone would drop exactly the offsets this
    // pass is best at.
    for &off in types_by_offset.keys() {
        fields.entry(off).or_insert((0, false, 0));
    }
    if fields.is_empty() {
        return None;
    }
    Some(MethodFacts { class, fields, types: types_by_offset, pending, closure_typed })
}

/// Type each field of the object this method operates on.
///
/// Three sources, in the order they actually pay off on real code. Each is
/// evidence rather than inference — nothing here guesses from a name or a size.
///
/// 1. **An embedded sub-object.** `&this->f` passed as argument 0 to a
///    constructor of `C` says `f` **is** a `C`, stored by value. This is the
///    single most productive shape in C++ and it is unambiguous: a constructor's
///    first argument is `this` by the ABI, so no naming heuristic is involved.
/// 2. **A pointer field.** A value *loaded from* `this->f` and passed as
///    argument 0 to a member function of `C` makes `f` a `C *`. This is the one
///    that unblocks devirtualization of `this->impl->method()`, which is the
///    shape that survived the first devirtualization pass unresolved.
/// 3. **A stored typed value.** A class-typed parameter, or the result of a call
///    whose return type whole-program propagation settled, written into `this->f`.
/// 4. **A stored value whose class the *value* closure knows.** Source 3 follows
///    plain copies back to a parameter or a call; [`crate::devirt::class_closure`]
///    already carries a class along strictly more edges — an agreeing phi, a
///    stack spill and reload, and a known **vtable written into an object**,
///    which is the constructor idiom and needs no other type to exist first.
///    Reusing it here rather than restating it is the point: one definition of
///    "what class does this value hold", read by both the dispatch resolver and
///    the field typer.
///
/// A generic width type says nothing about the object and is never recorded.
///
/// Two things this also collects, both **structural** — they are facts about
/// shape that only the *unified* layout can turn into types, so they are handed
/// back for [`unify`] to settle:
///
/// - `return this->f`, the offset a method hands back. Measured on a Qt shared
///   library over a 1 460-method sample: **82** methods return a field of their
///   own object, **33** of them a field the layout had already typed — and a
///   recovered return type is the scarcer half of the seed problem (315 of
///   22 413 functions had one, against 90 of 2 468 typed fields).
/// - `this->f = callee(...)` where the callee's return type is not known *yet*.
///   The two feed each other: a return type recovered from a field types another
///   field, whose type gives another return type. Kept as a fact and resolved in
///   a fixpoint over facts, which costs nothing next to a second pass over code.
fn field_types<'a>(
    ctx: &Ctx,
    blocks: &'a [SsaBlock],
    types: &crate::typeinfer::TypeArtifact,
    aliases: &BTreeSet<String>,
    arg_regs: &[&'static str],
) -> FieldFacts {
    // Parameter types, keyed the way SSA names them.
    let param_ty: BTreeMap<String, String> = types
        .signature
        .params
        .iter()
        .zip(arg_regs.iter())
        .filter_map(|(p, r)| p.ty.name.clone().map(|t| (format!("{r}.0"), t)))
        .collect();

    let mut copy_of: BTreeMap<&str, &MicroExpr> = BTreeMap::new();
    let mut call_ret: BTreeMap<&str, u64> = BTreeMap::new();
    for b in blocks {
        for s in &b.stmts {
            match &s.stmt {
                MicroStmt::Assign { dst, value } => {
                    copy_of.insert(dst.as_str(), value);
                }
                MicroStmt::Call { target: CallTarget::Direct { va }, ret: Some(r), .. } => {
                    call_ret.insert(r.as_str(), va.0);
                }
                _ => {}
            }
        }
    }
    let ret_type = |callee: u64| -> Option<String> { ctx.type_flow?.ret(callee).map(str::to_string) };

    // Where a stored value's type comes from: a name we already have, or a
    // callee whose return type may or may not be settled yet. Splitting the two
    // is what lets an unanswered call become a *pending* claim instead of
    // nothing at all.
    let value_src = |e: &MicroExpr| -> Option<ValueSrc> {
        let mut cur = e;
        for _ in 0..MAX_COPY_DEPTH {
            match peel(cur) {
                MicroExpr::Var(name) => {
                    if let Some(t) = param_ty.get(name.as_str()) {
                        return Some(ValueSrc::Named(t.clone()));
                    }
                    if let Some(callee) = call_ret.get(name.as_str()).copied() {
                        return Some(ValueSrc::Callee(callee));
                    }
                    match copy_of.get(name.as_str()) {
                        // A definition that is the variable itself would loop.
                        Some(next) if !matches!(peel(next), MicroExpr::Var(n) if n == name) => cur = next,
                        _ => return None,
                    }
                }
                // The optimizer inlines a single-use call straight into the store.
                MicroExpr::Call { target: CallTarget::Direct { va }, .. } => return Some(ValueSrc::Callee(va.0)),
                _ => return None,
            }
        }
        None
    };


    let mut out: BTreeMap<i64, String> = BTreeMap::new();
    let mut poisoned: BTreeSet<i64> = BTreeSet::new();
    let mut claim = |offset: i64, ty: String| match out.get(&offset) {
        Some(prev) if *prev != ty => {
            poisoned.insert(offset);
        }
        _ => {
            out.insert(offset, ty);
        }
    };

    // Follow a value to the expression that defines it. **Load-bearing**: after
    // optimization a call argument is almost never the interesting expression
    // itself — it is `rdi.1`, whose definition two statements earlier is the
    // `lea`. Matching the argument in place found nothing on real code.
    let resolve_def = |e: &'a MicroExpr| -> &'a MicroExpr {
        let mut cur = e;
        for _ in 0..MAX_COPY_DEPTH {
            match peel(cur) {
                MicroExpr::Var(name) => match copy_of.get(name.as_str()) {
                    Some(next) if !matches!(peel(next), MicroExpr::Var(n) if n == name) => cur = next,
                    _ => return peel(cur),
                },
                other => return other,
            }
        }
        peel(cur)
    };

    // `&this->f` — the interior pointer a compiler forms with one `lea`, either
    // as an explicit address-of or as the bare arithmetic it lowers to.
    let interior = |e: &'a MicroExpr| -> Option<i64> {
        let inner = match resolve_def(e) {
            MicroExpr::AddrOf(i) => resolve_def(i),
            other => other,
        };
        // A bare `this` is offset 0 — but so is every plain `this` argument of
        // every ordinary method call, which would type the object as its own
        // first field. Only a *displaced* interior pointer is evidence.
        let MicroExpr::Binary(n0xis_arch::BinOp::Add, l, r) = inner else { return None };
        let (base, off) = match (peel(l), peel(r)) {
            (MicroExpr::Var(n), MicroExpr::Const { value, .. }) => (n.as_str(), *value as i64),
            (MicroExpr::Const { value, .. }, MicroExpr::Var(n)) => (n.as_str(), *value as i64),
            _ => return None,
        };
        (aliases.contains(base) && off != 0).then_some(off)
    };

    // `*(this + off)` reaching a call as its `this` — a pointer field, resolved
    // through however many copies the optimizer left between the load and the use.
    let loaded_field = |e: &'a MicroExpr| -> Option<i64> {
        let MicroExpr::Load { addr, .. } = resolve_def(e) else { return None };
        let (base, off) = as_base_offset(resolve_def(addr))?;
        aliases.contains(base).then_some(off)
    };

    let mut pending: Vec<(i64, u64)> = Vec::new();
    let mut unresolved: Vec<(i64, &MicroExpr)> = Vec::new();
    let mut closure_typed = 0usize;
    for b in blocks {
        for s in &b.stmts {
            match &s.stmt {
                MicroStmt::Store { addr, value, .. } => {
                    // Sources 3 and 4.
                    let Some((base, offset)) = as_base_offset(addr) else { continue };
                    if !aliases.contains(base) {
                        continue;
                    }
                    let portable = |t: String| Some(t).filter(|t| crate::typeprop::is_portable_type(t));
                    match value_src(value) {
                        Some(ValueSrc::Named(t)) => {
                            if let Some(t) = portable(t) {
                                claim(offset, t);
                            }
                        }
                        Some(ValueSrc::Callee(callee)) => match ret_type(callee).and_then(portable) {
                            Some(t) => claim(offset, t),
                            // Not known *yet* — the fixpoint in `unify` gets a
                            // second chance at it once return types are in.
                            None => pending.push((offset, callee)),
                        },
                        // Source 4 — deferred, so the closure is only built for
                        // a function that has a store nothing else could type.
                        None => unresolved.push((offset, value)),
                    }
                }
                // Sources 1 and 2, both keyed on the callee's own `this`. A call
                // reaches here in either of the two shapes the pipeline emits —
                // its own statement, or folded into the assignment that binds
                // its result.
                MicroStmt::Call { target, args, .. }
                | MicroStmt::Assign { value: MicroExpr::Call { target, args }, .. } => {
                    let CallTarget::Direct { va } = target else { continue };
                    let Some(arg0) = args.first() else { continue };
                    if let Some(off) = interior(arg0) {
                        // Only a constructor proves an *embedded* sub-object:
                        // an ordinary method could have been handed an interior
                        // pointer to something else entirely.
                        if let Some(c) = ctor_class(ctx, *va) {
                            claim(off, c);
                        }
                    } else if let Some(off) = loaded_field(arg0)
                        && let Some(c) = this_class_of(ctx, *va)
                    {
                        claim(off, format!("{c} *"));
                    }
                }
                _ => {}
            }
        }
    }
    // Source 4 — the same class closure the dispatch resolver runs on, over its
    // own definition map (this one sees through an agreeing phi, which the plain
    // copy map above deliberately does not). Built only when there is a store it
    // could answer: it is a fixpoint over every block, and most methods store
    // nothing into their object that the three sources above cannot already
    // account for.
    if !unresolved.is_empty() {
        let mut defs = copy_of.clone();
        crate::devirt::fold_phis(blocks, &mut defs);
        let var_class = crate::devirt::class_closure(ctx, blocks, types, &defs);
        for (offset, value) in unresolved {
            let MicroExpr::Var(v) = crate::devirt::resolve(value, &defs) else { continue };
            // A class the closure holds is the class of an object *pointer* —
            // that is what every one of its seeds is — so the field it lands in
            // is a pointer field. Spelling it `C` instead would claim an
            // embedded sub-object, the one confusion this pass cannot afford.
            let Some(c) = var_class.get(v.as_str()) else { continue };
            let ty = format!("{c} *");
            if crate::typeprop::is_portable_type(&ty) {
                claim(offset, ty);
                closure_typed += 1;
            }
        }
    }

    // A field this method could not make up its own mind about contributes
    // nothing rather than a coin flip.
    out.retain(|off, _| !poisoned.contains(off));
    pending.retain(|(off, _)| !poisoned.contains(off) && !out.contains_key(off));
    FieldFacts { types: out, pending, closure_typed }
}

/// Where a stored value's type is to be found.
enum ValueSrc {
    /// A type name already in hand.
    Named(String),
    /// The direct callee whose return type it is — which may not be known yet.
    Callee(u64),
}

/// What one class accumulates while every method that touches it is folded in:
/// `offset → (widest bits, signed, accesses, methods)`, how many methods
/// contributed at all, and the type claimed per offset (`None` once two methods
/// disagreed — a poisoning that is never undone).
#[derive(Default)]
struct Accum {
    fields: BTreeMap<i64, (Bits, bool, usize, usize)>,
    methods: usize,
    types: BTreeMap<i64, Option<String>>,
}

/// Fold one method's type claim into a class, poisoning the offset when a second
/// method disagrees. The poisoning is never undone: "two methods disagree" is a
/// stronger fact than either claim.
fn merge_type(entry: &mut Accum, off: i64, ty: String) {
    match entry.types.get(&off) {
        // Already poisoned, or a second method disagrees: stay unknown.
        Some(None) => {}
        Some(Some(prev)) if *prev != ty => {
            entry.types.insert(off, None);
        }
        Some(Some(_)) => {}
        None => {
            entry.types.insert(off, Some(ty));
        }
    }
}

/// Merge every method's view into one layout per class.
fn unify(ctx: &Ctx, functions: &[Va], max_bytes: usize) -> LayoutStore {
    let mut store = LayoutStore::default();
    let mut acc: BTreeMap<String, Accum> = BTreeMap::new();
    // The structural facts the fixpoint below settles, kept per method so no
    // function has to be analyzed twice.
    let mut pending: Vec<(String, i64, u64)> = Vec::new();

    for &va in functions {
        let Some(facts) = extract(ctx, va, max_bytes) else {
            store.functions_analyzed += 1;
            continue;
        };
        store.functions_analyzed += 1;
        store.methods_matched += 1;

        pending.extend(facts.pending.into_iter().map(|(off, callee)| (facts.class.clone(), off, callee)));
        store.claims_by_value_closure += facts.closure_typed;

        let entry = acc.entry(facts.class).or_default();
        entry.methods += 1;
        for (off, (bits, signed, count)) in facts.fields {
            let e = entry.fields.entry(off).or_insert((bits, signed, 0, 0));
            e.0 = e.0.max(bits);
            e.1 |= signed;
            e.2 += count;
            e.3 += 1;
            store.observations += 1;
        }
        for (off, ty) in facts.types {
            merge_type(entry, off, ty);
        }
    }

    // The seed fixpoint. A method that returns a typed field of its own object
    // has that field's type as its **return type**; a field filled with such a
    // method's result has that type. Each answers the other, so they are run
    // together until nothing new appears.
    //
    // A field type is only carried out as a return type when it is a **pointer**
    // — an embedded sub-object's first word is its own vptr, and `return this->f`
    // on an embedded `QPixmap` hands back that word, not a `QPixmap`. The same
    // distinction devirtualization makes, for the same reason.
    // The field/return fixpoint that used to sit here is gone, and the
    // measurement that removed it is worth more than the code was.
    //
    // A method's `pending` claims — `this->f = callee(...)` where the callee's
    // return type is not known yet — were to be answered by return types
    // recovered from `return this->f`. Two independent checks killed that:
    //
    // 1. **The Qt headers.** Of 118 return types so recovered, **55 were on
    //    functions that return `void` or a struct by value** — `QWindow::opacity`
    //    returns a `qreal` in `xmm0` and merely leaves `d` in `rax`;
    //    `QPixmap::rect` returns a `QRect` in `rax:rdx`. Nothing *inside* a
    //    function distinguishes a returned pointer from a scratch value the ABI
    //    leaves in the return register.
    // 2. **Caller-side evidence.** Gating the claim on some caller actually
    //    dereferencing the result — the only local proof there was a value —
    //    admitted **0 of 118**: the accessors this can read (`d_func` and its
    //    kind) are `inline` in the headers, so the out-of-line copies exist as
    //    weak symbols that nothing calls.
    //
    // Wrong where it fires, unused where it is right. `pending` is kept because
    // it costs one `Vec` and states the shape honestly; it resolved **0** fields
    // on the target either way.
    let _ = &pending;
    for (class, Accum { fields: merged, methods, types: tys }) in acc {
        let mut extent = 0u64;
        let fields: Vec<FieldObs> = merged
            .into_iter()
            .map(|(offset, (size_bits, signed, access_count, m))| {
                if offset >= 0 {
                    extent = extent.max(offset as u64 + (size_bits as u64).div_ceil(8));
                }
                let claimed = tys.get(&offset);
                let ty_ambiguous = matches!(claimed, Some(None));
                let ty = claimed.and_then(|t| t.clone());
                if ty.is_some() {
                    store.typed_fields += 1;
                }
                if ty_ambiguous {
                    store.ambiguous_fields += 1;
                }
                FieldObs { offset, size_bits, signed, access_count, methods: m, ty, ty_ambiguous }
            })
            .collect();
        store.classes.insert(class, ClassLayout { methods, fields, extent });
    }
    store
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::BinOp;

    fn var(n: &str) -> MicroExpr {
        MicroExpr::Var(n.into())
    }

    fn block(assigns: Vec<(&str, MicroExpr)>) -> SsaBlock {
        SsaBlock {
            id: 0,
            start: Va(0x1000),
            end: Va(0x1000 + 4 * assigns.len() as u64),
            terminator: "ret".into(),
            successors: vec![],
            phis: vec![],
            condition: None,
            stmts: assigns
                .into_iter()
                .enumerate()
                .map(|(i, (dst, value))| crate::ssa::SsaStmt {
                    va: Va(0x1000 + 4 * i as u64),
                    stmt: MicroStmt::Assign { dst: dst.into(), value },
                })
                .collect(),
        }
    }

    #[test]
    fn a_field_address_is_recognized_in_either_operand_order_and_through_casts() {
        let plus = MicroExpr::Binary(BinOp::Add, Box::new(var("rdi.0")), Box::new(MicroExpr::constant(0x30, 64)));
        assert_eq!(as_base_offset(&plus), Some(("rdi.0", 0x30)));
        let swapped = MicroExpr::Binary(BinOp::Add, Box::new(MicroExpr::constant(0x30, 64)), Box::new(var("rdi.0")));
        assert_eq!(as_base_offset(&swapped), Some(("rdi.0", 0x30)));
        assert_eq!(as_base_offset(&var("rdi.0")), Some(("rdi.0", 0)));
        // A computed offset is not a field.
        let computed = MicroExpr::Binary(BinOp::Add, Box::new(var("rdi.0")), Box::new(var("rax.1")));
        assert_eq!(as_base_offset(&computed), None);
    }

    /// The copy the optimizer leaves is exactly why per-function recovery keyed
    /// on `rdi.0` misses half a method's accesses.
    #[test]
    fn this_aliases_follow_plain_copies() {
        let blocks = vec![block(vec![
            ("rbx.1", var("rdi.0")),
            ("rbx.2", var("rbx.1")),
            ("rcx.1", var("rsi.0")),
        ])];
        let set = alias_set(&blocks, "rdi.0");
        assert!(set.contains("rdi.0") && set.contains("rbx.1") && set.contains("rbx.2"));
        assert!(!set.contains("rcx.1"), "an unrelated copy is not an alias of this");
    }

    #[test]
    fn a_cyclic_copy_terminates() {
        let blocks = vec![block(vec![("a", var("b")), ("b", var("a"))])];
        // Terminates, and pulls the whole cycle in — both names really do hold
        // the value once one of them does.
        let set = alias_set(&blocks, "a");
        assert!(set.contains("a") && set.contains("b"));
    }

    #[test]
    fn a_constructor_is_recognized_by_its_own_name_and_nothing_else_is() {
        assert_eq!(ctor_class_of("QPixmap::QPixmap"), Some("QPixmap"));
        assert_eq!(ctor_class_of("QPixmap::~QPixmap"), Some("QPixmap"), "a destructor is as certain as a constructor");
        assert_eq!(ctor_class_of("Ui::Widget::Widget"), Some("Ui::Widget"), "the class keeps its namespace");
        assert_eq!(ctor_class_of("QList<int>::QList"), Some("QList<int>"), "template arguments are stripped only to compare");
        assert_eq!(ctor_class_of("QPixmap::isNull"), None, "an ordinary method is not a constructor");
        assert_eq!(ctor_class_of("Ui::doSomething"), None, "a namespaced free function has no this");
        assert_eq!(ctor_class_of("main"), None);
        assert_eq!(ctor_class_of("::foo"), None);
    }

    #[test]
    fn a_function_returning_its_own_first_argument_is_refused() {
        let aliases: BTreeSet<String> = ["rdi.0".to_string(), "rax.3".to_string()].into_iter().collect();
        let mut b = block(vec![("rax.3", var("rdi.0"))]);
        // An sret function hands the caller's buffer back — that is the ABI, and
        // it is the only thing that separates it from an ordinary method.
        b.stmts.push(crate::ssa::SsaStmt { va: Va(0x1010), stmt: MicroStmt::Return(Some(var("rax.3"))) });
        assert!(returns_first_arg(&[b], &aliases, "rdi.0"));

        let mut c = block(vec![("rax.3", var("rsi.0"))]);
        c.stmts.push(crate::ssa::SsaStmt { va: Va(0x1010), stmt: MicroStmt::Return(Some(var("rax.3"))) });
        assert!(
            !returns_first_arg(&[c], &BTreeSet::from(["rdi.0".to_string()]), "rdi.0"),
            "returning something else is an ordinary method"
        );

        // The shape that actually occurs: the buffer is spilled across a call
        // and reloaded, so the returned name shares no copy chain with `rdi.0` —
        // only the register. `QScreen::manufacturer() const` is exactly this,
        // and matching SSA names alone filed `QString`'s `+0x10` under `QScreen`.
        let mut d = block(vec![("rax.3", var("rsi.0"))]);
        d.stmts.push(crate::ssa::SsaStmt { va: Va(0x1010), stmt: MicroStmt::Return(Some(var("rdi.9"))) });
        assert!(returns_first_arg(&[d], &BTreeSet::from(["rdi.0".to_string()]), "rdi.0"));

        // …and the shape after that: the buffer reaches the result register
        // through a **join**, so only following phis connects the two.
        // `QAction::toolTip() const`, exactly.
        let mut e = block(vec![("rdx.4", var("rdi.0"))]);
        e.phis.push(crate::ssa::Phi {
            var: "rdx".to_string(),
            dst: "rdx.6".to_string(),
            inputs: vec![
                crate::ssa::PhiInput { from_block: 0, value: "rdx.4".to_string() },
                crate::ssa::PhiInput { from_block: 1, value: "rdx.5".to_string() },
            ],
        });
        e.stmts.push(crate::ssa::SsaStmt { va: Va(0x1010), stmt: MicroStmt::Return(Some(var("rdx.6"))) });
        assert!(returns_first_arg(&[e], &BTreeSet::from(["rdi.0".to_string(), "rdx.4".to_string()]), "rdi.0"));
    }

    /// The three field-typing rules, on the exact statement shapes real code
    /// produces — an embedded sub-object constructed through an interior
    /// pointer, a pointer field handed to a member function, and a class-typed
    /// parameter stored in. Anything else must stay untyped.
    #[test]
    fn the_three_field_typing_rules_fire_and_nothing_else_does() {
        use n0xis_arch::{BinOp, Bits, CallTarget};
        use n0xis_contracts::{SymKind, Symbol};
        use n0xis_sources::{MemorySource, SymbolProvider};

        struct Syms;
        impl SymbolProvider for Syms {
            fn symbol_at(&self, va: Va) -> Option<Symbol> {
                let name = match va.0 {
                    0x2000 => "_ZN7QPixmapC1Ev",     // a constructor
                    0x3000 => "_ZN6Widget5paintEv",  // a member of a vtable class
                    0x4000 => "_Z8helper_fv",        // a free function: no `this`
                    _ => return None,
                };
                Some(Symbol { va, module: String::new(), name: name.into(), kind: SymKind::Export })
            }
        }
        let snap = n0xis_sources::Snapshot::builder().region(Va(0x1000), vec![0xC3]).build();
        let arch = n0xis_arch::X64::new();
        let vtables: std::sync::Arc<std::collections::HashMap<u64, String>> =
            std::sync::Arc::new([(0x9000u64, "Widget".to_string())].into_iter().collect());
        let syms = Syms;
        let ctx = Ctx::new(&snap as &dyn MemorySource, &arch).with_symbols(&syms).with_vtables(&vtables);

        let this = "rdi.0";
        let cnst = |v: i128| MicroExpr::constant(v, 64);
        let plus = |b: &str, o: i128| MicroExpr::Binary(BinOp::Add, Box::new(var(b)), Box::new(cnst(o)));
        let call = |va: u64, arg: MicroExpr| MicroStmt::Call {
            target: CallTarget::Direct { va: Va(va) },
            args: vec![arg],
            ret: None,
        };
        let stmt = |st: MicroStmt| crate::ssa::SsaStmt { va: Va(0x1000), stmt: st };

        let mut b = block(vec![
            // &this->0x30, handed to a constructor → an embedded QPixmap.
            ("v1", MicroExpr::AddrOf(Box::new(plus(this, 0x30)))),
            // *(this + 0x40), handed to Widget::paint → a Widget *.
            ("v2", MicroExpr::load(plus(this, 0x40), 64 as Bits, false)),
            // &this->0x50, handed to a free function → nothing.
            ("v3", MicroExpr::AddrOf(Box::new(plus(this, 0x50)))),
        ]);
        b.stmts.push(stmt(call(0x2000, var("v1"))));
        b.stmts.push(stmt(call(0x3000, var("v2"))));
        b.stmts.push(stmt(call(0x4000, var("v3"))));
        // A class-typed parameter stored into a field.
        b.stmts.push(stmt(MicroStmt::Store { addr: plus(this, 0x60), value: var("rsi.0"), bits: 64 as Bits }));
        // A value nothing types, stored into a field: stays unknown.
        b.stmts.push(stmt(MicroStmt::Store { addr: plus(this, 0x68), value: cnst(7), bits: 64 as Bits }));
        // Source 4: `v4` is named by the constructor it is handed to — no copy
        // chain, no parameter, no propagated return type reaches it — and
        // storing it into a field types that field.
        b.stmts.push(stmt(call(0x2000, var("v4"))));
        b.stmts.push(stmt(MicroStmt::Store { addr: plus(this, 0x70), value: var("v4"), bits: 64 as Bits }));

        let types = crate::typeinfer::TypeArtifact {
            locals: vec![],
            structs: vec![],
            signature: crate::typeinfer::RecoveredSignature {
                params: vec![
                    crate::typeinfer::ParamInfo { reg: "rdi", name: "rdi".into(), ty: crate::typeinfer::CType::named("Widget *") },
                    crate::typeinfer::ParamInfo { reg: "rsi", name: "rsi".into(), ty: crate::typeinfer::CType::named("QFont *") },
                ],
                ret: None,
            },
        };
        let blocks = vec![b];
        let aliases = alias_set(&blocks, this);
        let got = field_types(&ctx, &blocks, &types, &aliases, &["rdi", "rsi"]);

        assert_eq!(got.types.get(&0x30).map(String::as_str), Some("QPixmap"), "an interior pointer into a constructor is an embedded sub-object");
        assert_eq!(got.types.get(&0x40).map(String::as_str), Some("Widget *"), "a loaded field used as a `this` is a pointer field");
        assert_eq!(got.types.get(&0x50), None, "a free function's argument proves nothing");
        assert_eq!(got.types.get(&0x60).map(String::as_str), Some("QFont *"), "a class-typed parameter stored in types the field");
        assert_eq!(got.types.get(&0x68), None, "a constant carries no type to move");
        assert_eq!(
            got.types.get(&0x70).map(String::as_str),
            Some("QPixmap *"),
            "a value the class closure names by the constructor it was handed to types the field"
        );
    }

    #[test]
    fn lookup_refuses_an_ambiguous_field_and_answers_a_proven_one() {
        let mut store = LayoutStore::default();
        store.classes.insert(
            "Widget".into(),
            ClassLayout {
                methods: 3,
                fields: vec![
                    FieldObs { offset: 0x30, size_bits: 64, signed: false, access_count: 9, methods: 3, ty: Some("QImage *".into()), ty_ambiguous: false },
                    FieldObs { offset: 0x38, size_bits: 64, signed: false, access_count: 2, methods: 2, ty: None, ty_ambiguous: true },
                ],
                extent: 0x40,
            },
        );
        assert_eq!(store.field_type("Widget", 0x30), Some("QImage *"));
        assert_eq!(store.field_type("Widget", 0x38), None, "a contested field answers nothing");
        assert_eq!(store.field_type("Widget", 0x99), None);
        assert_eq!(store.field_type("Button", 0x30), None);
    }
}
