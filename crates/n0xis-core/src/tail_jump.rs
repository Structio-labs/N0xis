// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! An unresolved jump with the frame given back is a tail call through a pointer.
//!
//! `return f(x);` through a register compiles to `jmp *%rax` with the stack pointer
//! where it came in: whatever runs next returns to this function's caller, as a tail
//! call does. `__longjmp`'s `mov %r8,%rsp; jmp *%rdx` is a jump too, and goes nowhere
//! a caller can see. Telling the two apart is a question about the stack pointer's
//! value, which only the SSA answers, so the graph asks here, and only when it has a
//! jump to ask about. The one rule for it: `function summary`'s `returns` reads it, and
//! a body is to read the same.

use std::collections::{BTreeSet, HashMap};

use n0xis_arch::{BinOp, MicroExpr, MicroStmt, JUMP_TARGET_VAR};

use crate::{CfgArtifact, Ctx, Pass, SsaPass};

/// How many definitions back the jump's address is followed to see whether it is
/// read out of a table. Past it, the answer is "a table": not a tail call.
const MAX_DEFS: usize = 16;

impl CfgArtifact {
    /// The blocks whose unresolved jump ([`CfgArtifact::unresolved_jumps`]) is a tail
    /// call through a pointer, by id. A jump is one when all of these hold:
    /// - the stack pointer there is where it was at entry, so on top of it is the
    ///   return address this function was called with: the frame is given back, and
    ///   whatever runs next returns to this function's caller;
    /// - its address is not read out of a table, through an index (`[base + idx*8]`,
    ///   at the jump or anywhere up its definitions): a switch whose table was not
    ///   read and a computed `goto` through a table of label addresses are that shape,
    ///   and their targets are in this function;
    /// - its address is not a constant: one is somewhere the graph could have gone.
    ///
    /// The first is the proof only where the return address is on the stack, as on
    /// x86 of either width. A machine that keeps it in a register (`lr`) would need
    /// the register shown intact as well, which nothing here does: none is one there.
    pub(crate) fn tail_calls_through_pointers(&self, ctx: &Ctx) -> BTreeSet<usize> {
        let candidates: Vec<usize> = self.unresolved_jumps().map(|b| b.id).collect();
        let Some(sp) = ctx.arch.stack_pointer() else { return BTreeSet::new() };
        if candidates.is_empty() || ctx.arch.name() != "x86-64" {
            return BTreeSet::new();
        }
        let Ok(ssa) = SsaPass.run(ctx, self.clone()) else { return BTreeSet::new() };
        let frame = crate::ssa::frame_offsets(&ssa.blocks, sp, ctx.arch.pointer_size());
        let idom = crate::dom::idom_of(self);
        let of: HashMap<&str, &MicroExpr> = ssa
            .blocks
            .iter()
            .flat_map(|b| &b.stmts)
            .filter_map(|s| match &s.stmt {
                MicroStmt::Assign { dst, value } => Some((dst.as_str(), value)),
                _ => None,
            })
            .collect();
        let defs = Defs { of: &of, sp };
        candidates
            .into_iter()
            .filter(|&id| {
                let Some(b) = ssa.blocks.get(id).filter(|b| b.id == id) else { return false };
                let Some((si, target)) = b.stmts.iter().enumerate().rev().find_map(|(i, s)| match &s.stmt {
                    MicroStmt::Assign { dst, value } if dst.split('.').next() == Some(JUMP_TARGET_VAR) => Some((i, value)),
                    _ => None,
                }) else {
                    return false;
                };
                let at = crate::callee::version_before(&ssa.blocks, &idom, id, si, sp).and_then(|v| frame.get(&v));
                at == Some(0) && !is_constant(target, &of) && !read_through_an_index(target, &defs, 0)
            })
            .collect()
    }
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

/// Whether `e` reads memory at an address with an index in it: two values added that
/// are not constants, or one scaled. An object's slot (`[rax+0x18]`, `[[rcx]+8]`) is a
/// value and a constant; a table entry is not.
fn read_through_an_index(e: &MicroExpr, defs: &Defs, depth: usize) -> bool {
    if depth > MAX_DEFS {
        return true;
    }
    match e {
        MicroExpr::Var(v) => defs.get(v).is_some_and(|d| read_through_an_index(d, defs, depth + 1)),
        MicroExpr::Load { addr, .. } => indexed(addr, defs, depth) || read_through_an_index(addr, defs, depth),
        MicroExpr::Unary(_, x) | MicroExpr::Cast { expr: x, .. } | MicroExpr::AddrOf(x) => read_through_an_index(x, defs, depth),
        MicroExpr::Binary(_, l, r) | MicroExpr::Compare { lhs: l, rhs: r, .. } => read_through_an_index(l, defs, depth) || read_through_an_index(r, defs, depth),
        // Either of two values, one of which may be a table's.
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

#[cfg(test)]
mod tests {
    use crate::ir::{CfgInput, CfgPass};
    use crate::{Ctx, Pass};
    use n0xis_arch::X64;
    use n0xis_contracts::Va;
    use n0xis_sources::Snapshot;

    fn tails(bytes: Vec<u8>) -> usize {
        let n = bytes.len();
        let snap = Snapshot::builder().region(Va(0x1000), bytes).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), n)).expect("cfg builds");
        assert_eq!(cfg.unresolved_jumps().count(), 1, "{:?}", cfg.blocks);
        cfg.tail_calls_through_pointers(&ctx).len()
    }

    /// `return f(x);` through a register: `mov rax,[rdi]; jmp rax`, the frame given back.
    #[test]
    fn a_jump_through_a_pointer_with_the_frame_given_back_is_a_tail_call() {
        assert_eq!(tails(vec![0x48, 0x8b, 0x07, 0xff, 0xe0]), 1);
    }

    /// `__longjmp`: `mov rsp,r8; jmp rdx`, the stack pointer is not the one it came in with.
    #[test]
    fn a_jump_with_another_stack_is_no_tail_call() {
        assert_eq!(tails(vec![0x4c, 0x89, 0xc4, 0xff, 0xe2]), 0);
    }

    /// A computed `goto` through a table of label addresses: `jmp [rdi*8+0x2000]`, and the
    /// same read into a register first. Its targets are in the function.
    #[test]
    fn a_jump_read_out_of_a_table_is_no_tail_call() {
        assert_eq!(tails(vec![0xff, 0x24, 0xfd, 0x00, 0x20, 0x00, 0x00]), 0);
        assert_eq!(tails(vec![0x48, 0x8b, 0x04, 0xfd, 0x00, 0x20, 0x00, 0x00, 0xff, 0xe0]), 0);
    }
}
