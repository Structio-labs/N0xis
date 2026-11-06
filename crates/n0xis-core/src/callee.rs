// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What a function called from here takes, asked of its own body.
//!
//! The lift passes every argument register at every call, because a call in the
//! bytes does not say how many are meant. Each question here has the same three
//! answers: the callee is known and says so; it is known only in part, or stands
//! behind something unknown, and says so; or nothing can be said. A function that
//! forwards a register it never touched to something unknown takes at least what
//! it reads, and that is all that can be claimed of it.
//!
//! The answers are a pure function of the callee and of how far down it is asked,
//! so they are memoised on both: [`DEPTH`] ends a cycle as well, without a set of
//! functions on the way down whose contents would make the answer depend on who
//! asked first.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use n0xis_arch::{CallTarget, MicroExpr, MicroStmt};
use n0xis_contracts::Va;

use crate::ir::{CfgArtifact, CfgInput, CfgPass};
use crate::signatures::{KnownSignature, known_signature};
use crate::ssa::{RawFlow, SsaBlock};
use crate::typeinfer::{CALLEE_SCAN_SIZE, abi_arg_regs, collect_definite_param_regs, ctx_identity};
use crate::{Ctx, OptimizePass, Pass, SsaPass};

/// How many calls down a question goes.
const DEPTH: u8 = 4;

/// How many arguments a function takes, in the positions of the integer argument
/// registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Takes {
    /// Exactly this many: every path through it was read and nothing it forwards
    /// to is unknown.
    Exactly(usize),
    /// This many read here; beyond that its body does not say.
    AtLeast(usize),
}

impl Takes {
    fn floor(self) -> usize {
        match self {
            Takes::Exactly(n) | Takes::AtLeast(n) => n,
        }
    }
}

/// Who a call goes to, as far as the image says.
#[derive(Clone, Copy, Debug)]
enum Callee {
    Known(&'static KnownSignature),
    Body(Va),
    Unknown,
}

/// What a function's own body says, before anything it calls is asked.
#[derive(Clone, Debug, Default)]
struct Shape {
    /// Positions read by this body itself.
    read: usize,
    /// A position whose register a call takes as it came in, and who that call is to.
    forwards: Vec<(usize, Callee)>,
    /// Something in it reads what cannot be listed: an unresolved jump, an instruction
    /// not lifted whose reads are only a bound, a body cut by the window.
    open: bool,
    /// Whether a path computes what it returns.
    returns_value: bool,
    /// And computes it for nothing else.
    only_returned: bool,
    /// Whose result a path returns untouched.
    returns_of: Vec<Callee>,
    /// It has a `ret`.
    returns_at_all: bool,
}

/// What a function gives back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gives {
    Value,
    Nothing,
    /// A path returns what something unknown left in the register.
    Unknown,
}

#[derive(Default)]
struct Memo {
    shapes: HashMap<u64, Option<Arc<Shape>>>,
    takes: HashMap<(u64, u8), Takes>,
    gives: HashMap<(u64, u8), Gives>,
    comes_back: HashMap<(u64, u8), bool>,
}

static MEMO: Mutex<Option<(String, Memo)>> = Mutex::new(None);

/// Bound on memo entries, one a question; past it, an answer is worked out each time.
const MEMO_MAX: usize = 200_000;

fn with_memo<R>(id: &str, f: impl FnOnce(&mut Memo) -> R) -> R {
    let mut guard = MEMO.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.as_ref().is_none_or(|(have, _)| have != id) {
        *guard = Some((id.to_string(), Memo::default()));
    }
    f(&mut guard.as_mut().expect("just set").1)
}

/// A call's callee, by the names the graph resolved for it. A call through a PLT to a
/// function this image defines is that function.
fn callee_of(ctx: &Ctx, cfg: &CfgArtifact, target: &CallTarget) -> Callee {
    let (name, va) = match target {
        CallTarget::Direct { va } => (cfg.callsites.iter().find(|c| c.target == Some(*va)).and_then(|c| c.target_name.as_deref()), Some(*va)),
        CallTarget::Indirect(t) => match t.as_ref() {
            MicroExpr::Load { addr, .. } => match addr.as_ref() {
                MicroExpr::Const { value, .. } => {
                    let slot = u64::try_from(*value).ok();
                    let site = cfg.callsites.iter().find(|c| c.via_slot.map(|s| s.0) == slot);
                    (site.and_then(|c| c.target_name.as_deref()), site.and_then(|c| c.target))
                }
                _ => (None, None),
            },
            _ => (None, None),
        },
        CallTarget::Intrinsic(_) => (None, None),
    };
    if let Some(sig) = name.and_then(|n| known_signature(n.rsplit('!').next().unwrap_or(n))) {
        return Callee::Known(sig);
    }
    match va {
        Some(va) => Callee::Body(ctx.symbols.and_then(|s| s.thunk_to(va)).unwrap_or(va)),
        None => Callee::Unknown,
    }
}

/// Every real call in these blocks, statement or folded into an expression.
pub(crate) fn for_each_call<'b>(blocks: &'b [SsaBlock], f: &mut impl FnMut(&'b CallTarget, &'b [MicroExpr])) {
    fn walk<'b>(e: &'b MicroExpr, f: &mut impl FnMut(&'b CallTarget, &'b [MicroExpr])) {
        if let MicroExpr::Call { target, args } = e
            && !matches!(target, CallTarget::Intrinsic(_))
        {
            f(target, args);
        }
        for c in crate::typeinfer::expr_children(e) {
            walk(c, f);
        }
    }
    for b in blocks {
        for s in &b.stmts {
            if let MicroStmt::Call { target, args, .. } = &s.stmt
                && !matches!(target, CallTarget::Intrinsic(_))
            {
                f(target, args);
            }
            for e in crate::optimize::stmt_read_exprs(&s.stmt) {
                walk(e, f);
            }
        }
        if let Some(c) = &b.condition {
            walk(c, f);
        }
    }
}

/// Is this bare argument the register of its own position as it came in?
fn own_slot(pos: usize, a: &MicroExpr, arg_regs: &[&str]) -> bool {
    matches!(a, MicroExpr::Var(v) if arg_regs.get(pos).is_some_and(|r| v.strip_suffix(".0") == Some(*r)))
}

/// What the function itself reads, and what it passes on untouched.
fn read_here(ctx: &Ctx, cfg: &CfgArtifact, blocks: &[SsaBlock], flow: &RawFlow, arg_regs: &[&str]) -> (BTreeSet<String>, Vec<(usize, Callee)>) {
    let mut used = collect_definite_param_regs(blocks, flow);
    used.extend(flow.moved.iter().cloned());
    // Propagation drops a store nothing loads, and storing it did read the register.
    used.extend(flow.stored_at.keys().filter(|e| !flow.saved.contains(*e)).cloned());
    let mut forwards = Vec::new();
    for_each_call(blocks, &mut |target, args| {
        let callee = callee_of(ctx, cfg, target);
        for (pos, a) in args.iter().enumerate() {
            if own_slot(pos, a, arg_regs) {
                forwards.push((pos, callee));
            }
        }
    });
    forwards.sort_by_key(|(pos, _)| std::cmp::Reverse(*pos));
    (used, forwards)
}

fn highest_read(used: &BTreeSet<String>, arg_regs: &[&str]) -> usize {
    arg_regs.iter().enumerate().filter(|(_, r)| used.contains(&format!("{r}.0"))).map(|(i, _)| i + 1).max().unwrap_or(0)
}

fn takes_of(ctx: &Ctx, id: Option<&str>, callee: Callee, depth: u8) -> Takes {
    match callee {
        Callee::Known(sig) if sig.variadic => Takes::AtLeast(sig.params.len()),
        Callee::Known(sig) => Takes::Exactly(sig.params.len()),
        Callee::Unknown => Takes::AtLeast(0),
        Callee::Body(va) => takes_of_body(ctx, id, va, depth),
    }
}

fn takes_of_body(ctx: &Ctx, id: Option<&str>, va: Va, depth: u8) -> Takes {
    if depth == 0 {
        return Takes::AtLeast(0);
    }
    if let Some(id) = id
        && let Some(t) = with_memo(id, |m| m.takes.get(&(va.0, depth)).copied())
    {
        return t;
    }
    let answer = match shape_of(ctx, id, va) {
        None => Takes::AtLeast(0),
        Some(shape) => resolve(ctx, id, &shape, depth),
    };
    if let Some(id) = id {
        with_memo(id, |m| {
            if m.takes.len() < MEMO_MAX {
                m.takes.insert((va.0, depth), answer);
            }
        });
    }
    answer
}

fn resolve(ctx: &Ctx, id: Option<&str>, shape: &Shape, depth: u8) -> Takes {
    let mut n = shape.read;
    let mut exact = !shape.open;
    for &(pos, callee) in &shape.forwards {
        if pos < n {
            continue;
        }
        match takes_of(ctx, id, callee, depth - 1) {
            t if t.floor() > pos => n = pos + 1,
            Takes::Exactly(_) => {}
            Takes::AtLeast(_) => exact = false,
        }
    }
    if exact { Takes::Exactly(n) } else { Takes::AtLeast(n) }
}

fn shape_of(ctx: &Ctx, id: Option<&str>, va: Va) -> Option<Arc<Shape>> {
    if let Some(id) = id
        && let Some(s) = with_memo(id, |m| m.shapes.get(&va.0).cloned())
    {
        return s;
    }
    let shape = analyse(ctx, va).map(Arc::new);
    if let Some(id) = id {
        with_memo(id, |m| {
            if m.shapes.len() < MEMO_MAX {
                m.shapes.insert(va.0, shape.clone());
            }
        });
    }
    shape
}

fn analyse(ctx: &Ctx, va: Va) -> Option<Shape> {
    let cfg = CfgPass.run(ctx, CfgInput::new(va, CALLEE_SCAN_SIZE)).ok()?;
    if cfg.start != va {
        return None;
    }
    let ssa = SsaPass.run(ctx, cfg.clone()).ok()?;
    let opt = OptimizePass.run(ctx, ssa).ok()?;
    let arg_regs = abi_arg_regs(ctx);
    let (mut used, forwards) = read_here(ctx, &cfg, &opt.blocks, &opt.raw_flow, &arg_regs);
    let unnamed_from = unnamed_arguments_from(&opt.raw_flow, &arg_regs, ctx.arch.pointer_size());
    if let Some(from) = unnamed_from {
        // What it keeps there it may or may not read, by what the caller said.
        let copied: BTreeSet<&str> = opt.raw_flow.moved.iter().map(String::as_str).collect();
        for r in &arg_regs[from..] {
            let entry = format!("{r}.0");
            if !copied.contains(entry.as_str()) {
                used.remove(&entry);
            }
        }
    }
    let shares = crate::ir::float_args_share_position(ctx);
    let float = highest_read(&used, crate::ir::float_arg_registers(ctx));
    let read = highest_read(&used, &arg_regs).max(if shares { float } else { 0 });
    let open = unnamed_from.is_some() || reads_what_cannot_be_listed(&cfg, &opt.blocks);
    let returns = &opt.raw_flow.returns;
    let returns_of = returns.calls.iter().map(|t| callee_of(ctx, &cfg, t)).filter(|c| !matches!(c, Callee::Body(b) if *b == va)).collect();
    Some(Shape { read, forwards, open, returns_value: returns.value, only_returned: returns.only_returned, returns_of, returns_at_all: returns.any })
}

/// The position a variadic function's unnamed arguments start at, from its register
/// save area: the last argument registers stored as they came, each in the word after
/// the one before. `luaL_error(L, fmt, ...)` stores `rdx`, `rcx`, `r8`, `r9` so, and
/// read as parameters they gave it six, and with it everything that passes it along.
/// A function at `-O0` on an ABI whose home slots ascend looks the same, and it only
/// costs that function its exact count. Two registers at the least: one is any spill.
fn unnamed_arguments_from(flow: &RawFlow, arg_regs: &[&str], word: Option<u8>) -> Option<usize> {
    let word = i128::from(word?);
    let at = |pos: usize| flow.stored_at.get(&format!("{}.0", arg_regs[pos])).copied();
    let last = arg_regs.len().checked_sub(1)?;
    let mut from = last;
    let mut off = at(last)?;
    while from > 0 && at(from - 1) == Some(off - word) {
        from -= 1;
        off -= word;
    }
    (from < last).then_some(from)
}

fn reads_what_cannot_be_listed(cfg: &CfgArtifact, blocks: &[SsaBlock]) -> bool {
    let window = cfg.end.0.saturating_sub(cfg.start.0) >= CALLEE_SCAN_SIZE as u64;
    let jump = cfg.blocks.iter().any(|b| b.terminator == "ijmp" && b.successors.is_empty());
    let unlifted = blocks.iter().any(|b| b.stmts.iter().any(|s| matches!(&s.stmt, MicroStmt::Unlifted { reads, .. } if reads.exact().is_none())));
    window || jump || unlifted
}

/// The entry values of the function in hand that are its parameters: what it reads
/// ([`collect_definite_param_regs`]), what a copy carried to a call
/// ([`RawFlow::moved`]), and a register passed on as it came to a callee known to
/// read that position. A register a call takes untouched, on its way to something
/// unknown, stays out: the lift passes every register at every call, and counting
/// those made nearly every function take all of them.
pub(crate) fn params_read(ctx: &Ctx, cfg: &CfgArtifact, blocks: &[SsaBlock], flow: &RawFlow, arg_regs: &[&str]) -> BTreeSet<String> {
    let (mut used, forwards) = read_here(ctx, cfg, blocks, flow, arg_regs);
    let id = ctx_identity(ctx);
    // A source with no identity (a live process) keeps no memo, and asking further
    // down would analyse the same callees again for every path to them.
    let depth = if id.is_some() { DEPTH } else { 1 };
    for (pos, callee) in forwards {
        if takes_of(ctx, id.as_deref(), callee, depth).floor() > pos {
            used.insert(format!("{}.0", arg_regs[pos]));
        }
    }
    used
}

fn gives_of(ctx: &Ctx, id: Option<&str>, callee: Callee, depth: u8) -> Gives {
    match callee {
        Callee::Known(sig) if sig.ret.is_some() => Gives::Value,
        Callee::Known(_) => Gives::Nothing,
        Callee::Unknown => Gives::Unknown,
        Callee::Body(_) if depth == 0 => Gives::Unknown,
        Callee::Body(va) => {
            if let Some(id) = id
                && let Some(g) = with_memo(id, |m| m.gives.get(&(va.0, depth)).copied())
            {
                return g;
            }
            let answer = match shape_of(ctx, id, va) {
                None => Gives::Unknown,
                // It never comes back, so a caller's `return f();` says nothing of a
                // value: `int g() { return error(); }` has one in its source.
                Some(s) if !s.returns_at_all => Gives::Unknown,
                Some(s) => weigh(s.returns_value, s.only_returned, || join_gives(ctx, id, &s.returns_of, depth - 1)),
            };
            if let Some(id) = id {
                with_memo(id, |m| {
                    if m.gives.len() < MEMO_MAX {
                        m.gives.insert((va.0, depth), answer);
                    }
                });
            }
            answer
        }
    }
}

/// One path that gives a value makes it a function that does; one that nothing can
/// say about makes it unknown, and not void, since a void answer here is a claim
/// that no caller reads a result, about a function that may well have one.
fn join_gives(ctx: &Ctx, id: Option<&str>, callees: &[Callee], depth: u8) -> Gives {
    let mut unknown = false;
    for &c in callees {
        match gives_of(ctx, id, c, depth) {
            Gives::Value => return Gives::Value,
            Gives::Unknown => unknown = true,
            Gives::Nothing => {}
        }
    }
    if unknown { Gives::Unknown } else { Gives::Nothing }
}

/// What the function in hand gives back, from what its returns hold: a computed value
/// is a return; an entry value or a call's marker is none; a call's result is what
/// that callee gives.
pub(crate) fn function_gives(ctx: &Ctx, cfg: &CfgArtifact, flow: &RawFlow) -> Gives {
    let id = ctx_identity(ctx);
    let depth = if id.is_some() { DEPTH } else { 1 };
    let callees: Vec<Callee> = flow.returns.calls.iter().map(|t| callee_of(ctx, cfg, t)).filter(|c| !matches!(c, Callee::Body(b) if *b == cfg.start)).collect();
    weigh(flow.returns.value, flow.returns.only_returned, || join_gives(ctx, id.as_deref(), &callees, depth))
}

/// A value computed for the return and nothing else is one. One that something else
/// reads as well, and a callee's value is as good as its own answer, may be what was
/// left in the register: the rule "computed means returned" read 210 of 212 void
/// functions of one C image as returning a value, and "read elsewhere means void" would
/// say void of functions that return what they just stored. So it says it cannot tell.
fn weigh(value: bool, only_returned: bool, callees: impl FnOnce() -> Gives) -> Gives {
    if only_returned {
        return Gives::Value;
    }
    match callees() {
        Gives::Nothing if value => Gives::Unknown,
        other => other,
    }
}

/// A function that gives nothing: its `ret` returns nothing, whatever the lift said it
/// read, and a result folded into the `ret` is a call that still has to happen.
pub(crate) fn settle_void_returns(blocks: &mut [SsaBlock]) {
    for b in blocks.iter_mut() {
        let mut stmts = Vec::with_capacity(b.stmts.len());
        for mut s in std::mem::take(&mut b.stmts) {
            match &s.stmt {
                MicroStmt::Return(Some(MicroExpr::Call { target, args })) => {
                    let call = MicroStmt::Call { target: target.clone(), args: args.clone(), ret: None };
                    stmts.push(crate::ssa::SsaStmt { stmt: call, ..s.clone() });
                    s.stmt = MicroStmt::Return(None);
                }
                MicroStmt::Return(Some(MicroExpr::Var(_))) => s.stmt = MicroStmt::Return(None),
                _ => {}
            }
            stmts.push(s);
        }
        b.stmts = stmts;
    }
}

/// `rax.1 = f();` with nothing reading `rax.1` is `f();`: a call whose result this body
/// does not use says so, and it is no assignment to look for a reader of.
pub(crate) fn drop_unread_results(blocks: &mut [SsaBlock]) {
    let mut read = BTreeSet::new();
    for b in blocks.iter() {
        for p in &b.phis {
            read.extend(p.inputs.iter().map(|i| i.value.clone()));
        }
        for s in &b.stmts {
            for e in crate::optimize::stmt_read_exprs(&s.stmt) {
                crate::ssa::collect_expr_vars(e, &mut read);
            }
        }
        if let Some(c) = &b.condition {
            crate::ssa::collect_expr_vars(c, &mut read);
        }
    }
    for b in blocks.iter_mut() {
        for s in &mut b.stmts {
            if let MicroStmt::Call { ret, target, .. } = &mut s.stmt
                && !matches!(target, CallTarget::Intrinsic(_))
                && ret.as_ref().is_some_and(|r| !read.contains(r))
            {
                *ret = None;
            }
        }
    }
}

thread_local! {
    /// How far down a graph being built may still ask. Held here and not in `Ctx`
    /// because the question is asked from inside the graph builder, of which a
    /// callee's graph is another run: one more argument through all of it for a value
    /// only this function reads.
    static NORETURN_DEPTH: std::cell::Cell<u8> = const { std::cell::Cell::new(DEPTH) };
}

/// Does the function at `va` provably never come back? From its own graph, whose calls
/// are asked the same one level further down. The answer is global to the function and
/// so has to be proof: any exit that cannot be shown to end means it may return, and so
/// do running out of depth and a cycle, which runs out of depth.
pub(crate) fn never_returns(ctx: &Ctx, va: Va) -> bool {
    let depth = NORETURN_DEPTH.get();
    // A source with no identity keeps no memo, and this would rebuild every graph on
    // the way down for every call.
    let Some(id) = ctx_identity(ctx).filter(|_| depth > 0) else { return false };
    let va = ctx.symbols.and_then(|s| s.thunk_to(va)).unwrap_or(va);
    if let Some(back) = with_memo(&id, |m| m.comes_back.get(&(va.0, depth)).copied()) {
        return !back;
    }
    NORETURN_DEPTH.set(depth - 1);
    let back = comes_back(ctx, va);
    NORETURN_DEPTH.set(depth);
    with_memo(&id, |m| {
        if m.comes_back.len() < MEMO_MAX {
            m.comes_back.insert((va.0, depth), back);
        }
    });
    !back
}

fn comes_back(ctx: &Ctx, va: Va) -> bool {
    let Ok(cfg) = CfgPass.run(ctx, CfgInput::new(va, CALLEE_SCAN_SIZE)) else { return true };
    if cfg.start != va {
        return true;
    }
    let ending_tails: std::collections::HashSet<Va> = cfg
        .blocks
        .iter()
        .filter(|b| b.terminator == "tail-call")
        .filter_map(|b| b.insns.last()?.target)
        .filter(|t| never_returns(ctx, *t))
        .collect();
    crate::noreturn_ipa::function_returns(&cfg, &ending_tails)
}

/// What stands behind a name in these blocks, for the question "did anything put a
/// value here for this call".
enum Def<'b> {
    /// The marker a call writes over what it may have changed: no value.
    Clobber,
    Copy(&'b str),
    Phi(Vec<&'b str>),
    Real,
}

fn defs_of(blocks: &[SsaBlock]) -> HashMap<&str, Def<'_>> {
    let mut defs = HashMap::new();
    for b in blocks {
        for p in &b.phis {
            defs.insert(p.dst.as_str(), Def::Phi(p.inputs.iter().map(|i| i.value.as_str()).collect()));
        }
        for s in &b.stmts {
            match &s.stmt {
                MicroStmt::Assign { dst, value: MicroExpr::Unknown(u) } if u == n0xis_arch::CALL_CLOBBER => {
                    defs.insert(dst.as_str(), Def::Clobber);
                }
                MicroStmt::Assign { dst, value: MicroExpr::Var(from) } => {
                    defs.insert(dst.as_str(), Def::Copy(from.as_str()));
                }
                MicroStmt::Assign { dst, .. } | MicroStmt::Call { ret: Some(dst), .. } => {
                    defs.insert(dst.as_str(), Def::Real);
                }
                _ => {}
            }
        }
    }
    defs
}

/// Does a value stand behind this name? An entry value does only if it is a parameter:
/// otherwise it is whatever the caller left in the register. A phi does if one of the
/// paths into it brings one.
fn holds_a_value(name: &str, defs: &HashMap<&str, Def<'_>>, params: &BTreeSet<String>) -> bool {
    let mut seen = BTreeSet::new();
    let mut work = vec![name];
    while let Some(n) = work.pop() {
        if !seen.insert(n) {
            continue;
        }
        match defs.get(n) {
            Some(Def::Real) => return true,
            Some(Def::Clobber) => {}
            Some(Def::Copy(from)) => work.push(from),
            Some(Def::Phi(inputs)) => work.extend(inputs.iter().copied()),
            None => {
                if params.contains(n) {
                    return true;
                }
            }
        }
    }
    false
}

/// How many of a call's arguments to keep. A callee that says how many it takes says
/// it; otherwise all up to the last one a value stands behind, and at least what the
/// callee is known to read. Below the last one kept a hole stays a hole, since a
/// position means a register: `f(rdi, rsi.3, rdx.2)` with `rsi.3` unset says the
/// second register was passed and nothing here set it.
fn args_kept(takes: Takes, args: &[MicroExpr], defs: &HashMap<&str, Def<'_>>, params: &BTreeSet<String>) -> usize {
    match takes {
        Takes::Exactly(n) => n.min(args.len()),
        Takes::AtLeast(n) => {
            let real = args.iter().rposition(|a| !matches!(a, MicroExpr::Var(v) if !holds_a_value(v, defs, params))).map_or(0, |i| i + 1);
            real.max(n).min(args.len())
        }
    }
}

/// Cut every call's arguments in these blocks to what it is passed. The lift gave each
/// the whole convention, because the instruction does not say, and on one C image 2 659
/// of 3 121 calls printed more arguments than their callee has. In the IR the body is
/// rendered from and not at print, so that every style and everything read off the
/// rendered blocks agree; a pass that wants the convention reads the blocks before this.
pub(crate) fn settle_call_args(ctx: &Ctx, cfg: &CfgArtifact, blocks: &mut [SsaBlock], params: &BTreeSet<String>) {
    let id = ctx_identity(ctx);
    let depth = if id.is_some() { DEPTH } else { 1 };
    let snapshot = blocks.to_vec();
    let defs = defs_of(&snapshot);
    let settle = |target: &CallTarget, args: &mut Vec<MicroExpr>| {
        if !matches!(target, CallTarget::Intrinsic(_)) {
            let takes = takes_of(ctx, id.as_deref(), callee_of(ctx, cfg, target), depth);
            args.truncate(args_kept(takes, args, &defs, params));
        }
    };
    for b in blocks.iter_mut() {
        for s in &mut b.stmts {
            if let MicroStmt::Call { target, args, .. } = &mut s.stmt {
                settle(target, args);
            }
            s.stmt = crate::optimize::map_stmt_exprs(&s.stmt, &mut |e| match e {
                MicroExpr::Call { target, mut args } => {
                    settle(&target, &mut args);
                    MicroExpr::Call { target, args }
                }
                other => other,
            });
        }
        if let Some(c) = b.condition.take() {
            b.condition = Some(crate::optimize::map_expr(&c, &mut |e| match e {
                MicroExpr::Call { target, mut args } => {
                    settle(&target, &mut args);
                    MicroExpr::Call { target, args }
                }
                other => other,
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DecompInput, DecompPass, DecompStyle};
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    const F: u64 = 0x1000;
    const G: u64 = 0x1100;
    const H: u64 = 0x1200;

    /// `call G`, from where this instruction lands in `code` of the function at `F`.
    fn call(code: &mut Vec<u8>, to: u64) {
        let rel = to as i64 - (F as i64 + code.len() as i64 + 5);
        code.push(0xe8);
        code.extend_from_slice(&(rel as i32).to_le_bytes());
    }

    fn image(f: Vec<u8>, g: &[u8], h: &[u8]) -> Snapshot {
        let mut bytes = vec![0xcc; 0x300];
        bytes[..f.len()].copy_from_slice(&f);
        bytes[0x100..0x100 + g.len()].copy_from_slice(g);
        bytes[0x200..0x200 + h.len()].copy_from_slice(h);
        Snapshot::builder().region(Va(F), bytes).build()
    }

    fn body(snap: &Snapshot) -> crate::PseudoFunction {
        let arch = X64::new();
        let ctx = Ctx::new(snap, &arch);
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(F), 0x100)).unwrap();
        DecompPass
            .run(&ctx, DecompInput { cfg, style: DecompStyle::Ssa, explain: false, strip_block_labels: true, var_names: Default::default(), var_types: Default::default(), struct_defs: Default::default() })
            .unwrap()
    }

    fn param_count(snap: &Snapshot) -> usize {
        let sig = body(snap).signature;
        let inner = &sig[sig.find('(').unwrap() + 1..sig.rfind(')').unwrap()];
        if inner.trim().is_empty() || inner.trim() == "void" { 0 } else { inner.split(',').count() }
    }

    const RET: &[u8] = &[0xc3];
    // mov eax,[rcx]; ret
    const READS_FIRST: &[u8] = &[0x8b, 0x01, 0xc3];

    /// `mov rbx,rcx; call g; mov rcx,rbx; call g` reads its first argument, and after
    /// propagation it is two calls with a bare `rcx.0`, which proves nothing there.
    /// `g` reads nothing, so what says so is the copy and not the callee.
    #[test]
    fn a_value_moved_to_a_call_is_a_parameter() {
        let mut f = vec![0x53, 0x48, 0x89, 0xcb];
        call(&mut f, G);
        f.extend([0x48, 0x89, 0xd9]);
        call(&mut f, G);
        f.extend([0x5b, 0xc3]);
        assert_eq!(param_count(&image(f, RET, RET)), 1);
    }

    /// `sub rsp,0x28; call g; add rsp,0x28; ret`: the register stands in its own slot
    /// and only the callee can say whether that is a value.
    #[test]
    fn a_register_passed_on_as_it_came_is_a_parameter_when_the_callee_reads_it() {
        let forwards = || {
            let mut f = vec![0x48, 0x83, 0xec, 0x28];
            call(&mut f, G);
            f.extend([0x48, 0x83, 0xc4, 0x28, 0xc3]);
            f
        };
        assert_eq!(param_count(&image(forwards(), READS_FIRST, RET)), 1, "the callee reads it");
        assert_eq!(param_count(&image(forwards(), RET, RET)), 0, "the callee does not");
    }

    /// The same question, two calls down: `f` calls `g`, which only forwards to `h`.
    #[test]
    fn the_question_goes_down_through_a_function_that_only_passes_it_on() {
        let mut f = vec![0x48, 0x83, 0xec, 0x28];
        call(&mut f, G);
        f.extend([0x48, 0x83, 0xc4, 0x28, 0xc3]);
        // g: sub rsp,0x28; call h; add rsp,0x28; ret
        let mut g = vec![0x48, 0x83, 0xec, 0x28, 0xe8];
        g.extend_from_slice(&((H as i64 - (G as i64 + 9)) as i32).to_le_bytes());
        g.extend([0x48, 0x83, 0xc4, 0x28, 0xc3]);
        assert_eq!(param_count(&image(f, &g, READS_FIRST)), 1);
    }

    /// `push rcx; call g; pop rcx; ret`, and `g` reads nothing: a save and a restore.
    #[test]
    fn a_register_merely_saved_and_restored_is_not_a_parameter() {
        let mut f = vec![0x51];
        call(&mut f, G);
        f.extend([0x59, 0xc3]);
        assert_eq!(param_count(&image(f, RET, RET)), 0);
    }

    /// `mov [rsp+8],rcx; ret` stores it and nothing loads it back: what `-O0` does
    /// with a parameter nothing uses, and the bytes do read the register.
    #[test]
    fn a_store_nothing_loads_is_not_a_save() {
        assert_eq!(param_count(&image(vec![0x48, 0x89, 0x4c, 0x24, 0x08, 0xc3], RET, RET)), 1);
    }

    /// A branch around a call merges the register nothing touched with what the call
    /// left in it. No copy happened, and the second call's argument is no read.
    #[test]
    fn a_phi_is_no_movement() {
        // test eax,eax; je over; call g; over: call g; ret
        let mut f = vec![0x85, 0xc0, 0x74, 0x05];
        call(&mut f, G);
        call(&mut f, G);
        f.push(0xc3);
        assert_eq!(param_count(&image(f, RET, RET)), 0);
    }

    /// `mov [rsp+0x10],rdx; mov [rsp+0x18],r8; mov [rsp+0x20],r9; ret`, the way a
    /// variadic function keeps what it was not told about, does not read them for a
    /// caller that passes its own registers along.
    #[test]
    fn a_register_save_area_is_no_read_for_who_calls_it() {
        let save = [0x48, 0x89, 0x54, 0x24, 0x10, 0x4c, 0x89, 0x44, 0x24, 0x18, 0x4c, 0x89, 0x4c, 0x24, 0x20, 0xc3];
        let mut f = vec![0x48, 0x83, 0xec, 0x28];
        call(&mut f, G);
        f.extend([0x48, 0x83, 0xc4, 0x28, 0xc3]);
        assert_eq!(param_count(&image(f, &save, RET)), 0);
    }

    /// `mov rax,[rax]; ret` reads a register that is no parameter on this ABI. It says
    /// so where it is read, and the body does not claim to have said everything.
    #[test]
    fn a_register_read_that_is_no_parameter_is_marked() {
        let snap = image(vec![0x48, 0x8b, 0x00, 0xc3], RET, RET);
        let b = body(&snap);
        assert!(b.pseudo.iter().any(|l| l.contains("/*from caller*/rax.0")), "{:?}", b.pseudo);
        assert!(b.quality < 1.0, "{}", b.quality);
    }

    fn line_with<'b>(b: &'b crate::PseudoFunction, what: &str) -> &'b str {
        b.pseudo.iter().find(|l| l.contains(what)).unwrap_or_else(|| panic!("no line with {what}: {:#?}", b.pseudo))
    }

    /// `call g; call rax; ret`: nothing here set a register for the second call, and
    /// what the first left behind is no argument of it.
    #[test]
    fn what_a_call_left_behind_is_no_argument() {
        let mut f = vec![];
        call(&mut f, G);
        f.extend([0xff, 0xd0, 0xc3]);
        let snap = image(f, RET, RET);
        let b = body(&snap);
        assert!(line_with(&b, "(*").contains(")()"), "{:#?}", b.pseudo);
    }

    /// `mov ecx,1; mov edx,2; call g; ret`, and `g` reads only its first: it is given one.
    #[test]
    fn a_call_is_cut_to_what_the_callee_in_this_image_takes() {
        let mut f = vec![0xb9, 1, 0, 0, 0, 0xba, 2, 0, 0, 0];
        call(&mut f, G);
        f.push(0xc3);
        let snap = image(f, READS_FIRST, RET);
        let b = body(&snap);
        let l = line_with(&b, "sub_1100(");
        assert!(l.contains("sub_1100(0x1)"), "{l}");
    }

    /// `mov edx,2; call rax; ret`. Nothing says how many the target takes, and the
    /// last register with a value is the second: the first stays, as what it is.
    #[test]
    fn a_hole_below_a_value_stays_and_says_what_it_is() {
        let snap = image(vec![0xba, 2, 0, 0, 0, 0xff, 0xd0, 0xc3], RET, RET);
        let b = body(&snap);
        let l = line_with(&b, "(*");
        assert!(l.contains("(/*from caller*/rcx.0, 0x2)"), "{l}");
    }

    /// A callee that forwards a register to something unknown has told nothing of
    /// that position, so what its caller put there stays.
    #[test]
    fn a_callee_that_stands_before_something_unknown_does_not_cut() {
        // g: mov rax,[rax]; jmp rax
        let g = [0x48, 0x8b, 0x00, 0xff, 0xe0];
        let mut f = vec![0xb9, 1, 0, 0, 0];
        call(&mut f, G);
        f.push(0xc3);
        let snap = image(f, &g, RET);
        let b = body(&snap);
        let l = line_with(&b, "sub_1100(");
        assert!(l.contains("sub_1100(0x1)"), "{l}");
    }

    fn asked(snap: &Snapshot) -> crate::PseudoFunction {
        let arch = X64::new();
        let ctx = Ctx::new(snap, &arch).with_noreturn_on_demand();
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(F), 0x100)).unwrap();
        DecompPass
            .run(&ctx, DecompInput { cfg, style: DecompStyle::Ssa, explain: false, strip_block_labels: true, var_names: Default::default(), var_types: Default::default(), struct_defs: Default::default() })
            .unwrap()
    }

    const SPINS: &[u8] = &[0xeb, 0xfe];

    /// `mov ecx,1; call g; mov eax,7; ret` with `g` a `jmp` to itself. Nothing after the
    /// call happens, and only `g`'s own body can say so.
    #[test]
    fn a_body_stops_at_a_call_that_does_not_come_back() {
        let then_more = || {
            let mut f = vec![0xb9, 1, 0, 0, 0];
            call(&mut f, G);
            f.extend([0xb8, 7, 0, 0, 0, 0xc3]);
            f
        };
        let snap = image(then_more(), SPINS, RET);
        let b = asked(&snap);
        assert!(!b.pseudo.iter().any(|l| l.contains("0x7")), "{:#?}", b.pseudo);
        let snap = image(then_more(), RET, RET);
        assert!(asked(&snap).pseudo.iter().any(|l| l.contains("0x7")), "a callee that returns does not stop it");
    }

    /// Through a function that only calls the one that does not come back.
    #[test]
    fn the_proof_goes_through_a_wrapper() {
        let mut f = vec![];
        call(&mut f, G);
        f.extend([0xb8, 7, 0, 0, 0, 0xc3]);
        // g: call h; nop; ret
        let mut g = vec![0xe8];
        g.extend_from_slice(&((H as i64 - (G as i64 + 5)) as i32).to_le_bytes());
        g.extend([0x90, 0xc3]);
        let snap = image(f, &g, SPINS);
        assert!(!asked(&snap).pseudo.iter().any(|l| l.contains("0x7")));
    }

    /// `g` calls `h` and `h` calls `g`, with a `ret` nowhere. A proof would need a step
    /// past where the depth ends, and without one it may return.
    #[test]
    fn a_cycle_is_no_proof() {
        let mut f = vec![];
        call(&mut f, G);
        f.extend([0xb8, 7, 0, 0, 0, 0xc3]);
        let mut g = vec![0xe8];
        g.extend_from_slice(&((H as i64 - (G as i64 + 5)) as i32).to_le_bytes());
        g.push(0xc3);
        let mut h = vec![0xe8];
        h.extend_from_slice(&((G as i64 - (H as i64 + 5)) as i32).to_le_bytes());
        h.push(0xc3);
        let snap = image(f, &g, &h);
        assert!(asked(&snap).pseudo.iter().any(|l| l.contains("0x7")));
    }

    /// A stub at `G` whose slot the image's relocations bind to its own `H`.
    struct ThroughPlt;
    impl n0xis_sources::SymbolProvider for ThroughPlt {
        fn slot_target(&self, _va: Va) -> Option<Va> {
            None
        }
        fn symbol_at(&self, va: Va) -> Option<n0xis_contracts::Symbol> {
            (va.0 == H).then(|| n0xis_contracts::Symbol { va: Va(H), module: String::new(), name: "the_export".into(), kind: n0xis_contracts::SymKind::Function })
        }
        fn thunk_to(&self, va: Va) -> Option<Va> {
            (va.0 == G).then_some(Va(H))
        }
    }

    /// `mov ecx,1; mov edx,2; call stub; ret`, the stub's slot bound to `h`, which reads
    /// its first argument: the call has `h`'s name and `h`'s count.
    #[test]
    fn a_call_through_the_plt_to_the_images_own_export_has_its_name_and_count() {
        let mut f = vec![0xb9, 1, 0, 0, 0, 0xba, 2, 0, 0, 0];
        call(&mut f, G);
        f.push(0xc3);
        // The stub: jmp *0x2000(%rip), which no name resolves here.
        let snap = image(f, &[0xff, 0x25, 0, 0, 0, 0], READS_FIRST);
        let arch = X64::new();
        let syms = ThroughPlt;
        let ctx = Ctx::new(&snap, &arch).with_symbols(&syms);
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(F), 0x100)).unwrap();
        let b = DecompPass
            .run(&ctx, DecompInput { cfg, style: DecompStyle::Ssa, explain: false, strip_block_labels: true, var_names: Default::default(), var_types: Default::default(), struct_defs: Default::default() })
            .unwrap();
        let l = line_with(&b, "the_export(");
        assert!(l.contains("the_export(0x1)"), "{l}");
    }

    fn says_void(snap: &Snapshot) -> String {
        body(snap).signature
    }

    /// `ret` alone: the register is what came in.
    #[test]
    fn a_function_that_touches_nothing_gives_nothing() {
        assert!(says_void(&image(vec![0xc3], RET, RET)).starts_with("void "));
    }

    /// `mov eax,1; ret`: computed here.
    #[test]
    fn a_computed_value_is_a_return() {
        assert!(!says_void(&image(vec![0xb8, 1, 0, 0, 0, 0xc3], RET, RET)).starts_with("void "));
    }

    /// `mov rax,[rcx]; add rax,1; mov [rcx],rax; ret`: stored, and left in the register.
    /// `*p += 1` and `return *p += 1` are these same bytes.
    #[test]
    fn a_value_also_read_on_its_way_cannot_be_told_from_a_leftover() {
        let snap = image(vec![0x48, 0x8b, 0x01, 0x48, 0x83, 0xc0, 0x01, 0x48, 0x89, 0x01, 0xc3], RET, RET);
        let sig = says_void(&snap);
        assert!(sig.starts_with("/*unknown*/"), "{sig}");
    }

    /// `test ecx,ecx; je over; mov eax,1; over: ret`: one path is enough.
    #[test]
    fn one_path_with_a_value_makes_a_return() {
        assert!(!says_void(&image(vec![0x85, 0xc9, 0x74, 0x05, 0xb8, 1, 0, 0, 0, 0xc3], RET, RET)).starts_with("void "));
    }

    /// `call g; ret`: what `g` left. Void if `g` gives nothing, and it prints no
    /// result, read or returned; a value if `g` gives one.
    #[test]
    fn a_value_out_of_a_call_asks_the_callee() {
        let calls = || {
            let mut f = vec![0x48, 0x83, 0xec, 0x28];
            call(&mut f, G);
            f.extend([0x48, 0x83, 0xc4, 0x28, 0xc3]);
            f
        };
        let snap = image(calls(), RET, RET);
        let b = body(&snap);
        assert!(b.signature.starts_with("void "), "{}", b.signature);
        assert!(b.pseudo.iter().any(|l| l.trim() == "sub_1100();"), "{:#?}", b.pseudo);
        assert!(!b.pseudo.iter().any(|l| l.contains("return rax")), "{:#?}", b.pseudo);
        let b = body(&image(calls(), &[0xb8, 1, 0, 0, 0, 0xc3], RET));
        assert!(!b.signature.starts_with("void "), "{}", b.signature);
    }

    /// `call rax; ret`: nothing can be asked, and that is said. A false void would
    /// tell the reader no result exists.
    #[test]
    fn a_callee_that_cannot_be_asked_leaves_the_return_unknown() {
        let snap = image(vec![0xff, 0xd0, 0xc3], RET, RET);
        let b = body(&snap);
        assert!(b.signature.starts_with("/*unknown*/"), "{}", b.signature);
        assert!(b.quality < 1.0, "{}", b.quality);
    }

    /// `call g; mov rax,rbx; ret` moves a value to the register to return it, and what
    /// `g` left there does not matter.
    #[test]
    fn a_value_moved_to_the_register_is_a_return() {
        let mut f = vec![];
        call(&mut f, G);
        f.extend([0x48, 0x89, 0xd8, 0xc3]);
        assert!(!says_void(&image(f, RET, RET)).starts_with("void "));
    }

    /// `g` calls itself on one path and otherwise returns nothing: no value and nothing
    /// unknown, whichever way the recursion goes.
    #[test]
    fn recursion_is_not_a_reason_to_stop_knowing() {
        // f: test ecx,ecx; je over; call f; over: ret
        let mut f = vec![0x85, 0xc9, 0x74, 0x05];
        call(&mut f, F);
        f.push(0xc3);
        assert!(says_void(&image(f, RET, RET)).starts_with("void "));
    }

    /// The save of a register into the frame is a read of the caller's value, kept to
    /// give back, and where it goes says so.
    #[test]
    fn the_save_of_a_register_is_not_marked() {
        // push rbx; mov eax,1; pop rbx; ret
        let snap = image(vec![0x53, 0xb8, 1, 0, 0, 0, 0x5b, 0xc3], RET, RET);
        let b = body(&snap);
        assert!(!b.pseudo.iter().any(|l| l.contains("/*from caller*/")), "{:?}", b.pseudo);
    }
}
