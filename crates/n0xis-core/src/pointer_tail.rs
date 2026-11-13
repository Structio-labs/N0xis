//! An indirect jump with the frame given back is a call through a pointer.
//!
//! `mov rax,[rcx]; mov r9,[rax+0x18]; mov edx,5; add rsp,0x28; pop rbx; jmp r9` hands
//! the callee this function's caller's return address and its arguments in the
//! registers: it is `return (*slot)(this, 5);`. Read as a jump the graph has no
//! targets for, the body said `// indirect jump (unrecovered)`, and every argument
//! written before it was dead and went: a whole band of a method on unfamiliar code
//! printed as nothing (a real task, 2026-11-13).
//!
//! The graph cannot see this by itself: whether the frame is given back is a question
//! about the stack pointer's value, which only the SSA answers. So a body asks here,
//! before it builds its own, and only when the graph has a jump to ask about.

use std::collections::HashMap;

use n0xis_arch::{BinOp, MicroExpr, MicroStmt, JUMP_TARGET_VAR};

use crate::ir::Callsite;
use crate::{CfgArtifact, CoreError, Ctx, Pass, SsaPass};

/// How many definitions back the jump's address is followed to see whether it is
/// read out of a table. Past it, the answer is "a table", which keeps the mark.
/// Counted in definitions, not in the nodes of an expression: counted in nodes, an
/// i386 object pointer loaded from its argument slot ran out of depth on the way
/// down the stack pointer's versions, and every such jump stayed a mark.
const MAX_DEFS: usize = 16;

/// `cfg` with each unresolved jump that is a tail call through a pointer made one:
/// terminator `tail-call` and a `tail` call site with no target, so the lift makes
/// the jump `call` + `return` and every pass that knows a tail call knows this one.
///
/// A jump is one when all of these hold, and is left alone otherwise:
/// - the graph found no targets for it ([`CfgArtifact::unresolved_jumps`]);
/// - its address is not read through an index (`[base + idx*8]`, at the jump or
///   anywhere up its definitions): a switch whose table was not read, a computed
///   `goto` and a table with no bound are that shape, and their targets are in this
///   function. The switch reader's word is not asked: it reports a dispatch on a
///   `jmp rax` whenever any instruction before it in the block has an index, and
///   did on `lea (,%rsi,8)` computing `x * 7` before a call through an object's slot;
/// - its address is not a constant: one is somewhere the graph could have gone;
/// - the stack pointer there is where it was at entry, so on top of it is the
///   return address this function was called with: the frame is given back, and
///   whatever runs next returns to this function's caller.
///
/// The last is the proof only where the return address is on the stack. On a
/// machine that keeps it in a register (`lr`) the register would have to be shown
/// intact as well, which nothing here does, so those keep the mark.
pub(crate) fn with_tail_calls_through_pointers(ctx: &Ctx, mut cfg: CfgArtifact) -> Result<CfgArtifact, CoreError> {
    if ctx.arch.name() != "x86-64" {
        return Ok(cfg);
    }
    let Some(sp) = ctx.arch.stack_pointer() else { return Ok(cfg) };
    let candidates: Vec<usize> = cfg.unresolved_jumps().map(|b| b.id).collect();
    if candidates.is_empty() {
        return Ok(cfg);
    }
    let ssa = SsaPass.run(ctx, cfg.clone())?;
    let frame = crate::ssa::frame_offsets(&ssa.blocks, sp, ctx.arch.pointer_size());
    let defs: HashMap<&str, &MicroExpr> = ssa
        .blocks
        .iter()
        .flat_map(|b| &b.stmts)
        .filter_map(|s| match &s.stmt {
            MicroStmt::Assign { dst, value } => Some((dst.as_str(), value)),
            _ => None,
        })
        .collect();
    let tails: Vec<usize> = candidates
        .into_iter()
        .filter(|&id| {
            let Some(b) = ssa.blocks.get(id).filter(|b| b.id == id) else { return false };
            let Some((si, target)) = b.stmts.iter().enumerate().rev().find_map(|(i, s)| match &s.stmt {
                MicroStmt::Assign { dst, value } if dst.split('.').next() == Some(JUMP_TARGET_VAR) => Some((i, value)),
                _ => None,
            }) else {
                return false;
            };
            let at = crate::callee::version_before(&ssa.blocks, &cfg, id, si, sp).and_then(|v| frame.get(&v));
            let defs = Defs { of: &defs, sp };
            at == Some(0) && !is_constant(target, defs.of) && !read_through_an_index(target, &defs, 0)
        })
        .collect();
    for id in tails {
        let block = &mut cfg.blocks[id];
        let Some(from) = block.insns.last().map(|i| i.va) else { continue };
        block.terminator = "tail-call".into();
        cfg.stats.tail_calls += 1;
        cfg.callsites.push(Callsite { from, kind: "tail".into(), target: None, target_name: None, via_slot: None });
    }
    cfg.callsites.sort_by_key(|c| c.from.0);
    Ok(cfg)
}

fn is_constant(e: &MicroExpr, defs: &HashMap<&str, &MicroExpr>) -> bool {
    match e {
        MicroExpr::Const { .. } => true,
        MicroExpr::Var(v) => defs.get(v.as_str()).is_some_and(|d| matches!(d, MicroExpr::Const { .. })),
        _ => false,
    }
}

/// The definitions of the SSA, and the stack pointer, whose versions are the frame
/// and never a table: they are not followed.
struct Defs<'a> {
    of: &'a HashMap<&'a str, &'a MicroExpr>,
    sp: &'a str,
}

impl<'a> Defs<'a> {
    fn get(&self, v: &str) -> Option<&'a MicroExpr> {
        if v.split('.').next() == Some(self.sp) {
            return None;
        }
        self.of.get(v).copied()
    }
}

/// Whether `e` reads memory at an address with an index in it: two values added
/// that are not constants, or one scaled. An object's slot (`[rax+0x18]`, `[[rcx]+8]`)
/// is a value and a constant; a table entry is not.
fn read_through_an_index(e: &MicroExpr, defs: &Defs, depth: usize) -> bool {
    if depth > MAX_DEFS {
        return true;
    }
    match e {
        MicroExpr::Var(v) => defs.get(v).is_some_and(|d| read_through_an_index(d, defs, depth + 1)),
        MicroExpr::Load { addr, .. } => indexed(addr, defs, depth) || read_through_an_index(addr, defs, depth),
        MicroExpr::Unary(_, x) | MicroExpr::Cast { expr: x, .. } | MicroExpr::AddrOf(x) => read_through_an_index(x, defs, depth),
        MicroExpr::Binary(_, l, r) | MicroExpr::Compare { lhs: l, rhs: r, .. } => {
            read_through_an_index(l, defs, depth) || read_through_an_index(r, defs, depth)
        }
        // Either of two values, one of which may be a table's: the mark stays.
        MicroExpr::Select { .. } => true,
        MicroExpr::Const { .. } | MicroExpr::OpaqueFlags { .. } | MicroExpr::Call { .. } | MicroExpr::Unknown(_) => false,
    }
}

/// An address with an index: a product, or a sum of two terms neither of which is a
/// constant, looking through the definitions of the variables it names.
fn indexed(addr: &MicroExpr, defs: &Defs, depth: usize) -> bool {
    if depth > MAX_DEFS {
        return true;
    }
    match addr {
        MicroExpr::Binary(BinOp::Mul | BinOp::Shl, ..) => true,
        MicroExpr::Binary(BinOp::Add, l, r) => {
            let varying = |e: &MicroExpr| !is_constant(e, defs.of);
            (varying(l) && varying(r)) || indexed(l, defs, depth) || indexed(r, defs, depth)
        }
        MicroExpr::Var(v) => defs.get(v).is_some_and(|d| indexed(d, defs, depth + 1)),
        MicroExpr::Cast { expr, .. } => indexed(expr, defs, depth),
        _ => false,
    }
}
