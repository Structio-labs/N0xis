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
use crate::ssa::{EntryFlow, SsaBlock};
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
}

#[derive(Default)]
struct Memo {
    shapes: HashMap<u64, Option<Arc<Shape>>>,
    takes: HashMap<(u64, u8), Takes>,
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
fn read_here(ctx: &Ctx, cfg: &CfgArtifact, blocks: &[SsaBlock], flow: &EntryFlow, arg_regs: &[&str]) -> (BTreeSet<String>, Vec<(usize, Callee)>) {
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
    let (mut used, forwards) = read_here(ctx, &cfg, &opt.blocks, &opt.entry_flow, &arg_regs);
    let unnamed_from = unnamed_arguments_from(&opt.entry_flow, &arg_regs, ctx.arch.pointer_size());
    if let Some(from) = unnamed_from {
        // What it keeps there it may or may not read, by what the caller said.
        let copied: BTreeSet<&str> = opt.entry_flow.moved.iter().map(String::as_str).collect();
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
    Some(Shape { read, forwards, open })
}

/// The position a variadic function's unnamed arguments start at, from its register
/// save area: the last argument registers stored as they came, each in the word after
/// the one before. `luaL_error(L, fmt, ...)` stores `rdx`, `rcx`, `r8`, `r9` so, and
/// read as parameters they gave it six, and with it everything that passes it along.
/// A function at `-O0` on an ABI whose home slots ascend looks the same, and it only
/// costs that function its exact count. Two registers at the least: one is any spill.
fn unnamed_arguments_from(flow: &EntryFlow, arg_regs: &[&str], word: Option<u8>) -> Option<usize> {
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
/// ([`EntryFlow::moved`]), and a register passed on as it came to a callee known to
/// read that position. A register a call takes untouched, on its way to something
/// unknown, stays out: the lift passes every register at every call, and counting
/// those made nearly every function take all of them.
pub(crate) fn params_read(ctx: &Ctx, cfg: &CfgArtifact, blocks: &[SsaBlock], flow: &EntryFlow, arg_regs: &[&str]) -> BTreeSet<String> {
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
