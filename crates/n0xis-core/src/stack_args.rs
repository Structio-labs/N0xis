// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The stack convention: where a function's own arguments are, and a call's.
//!
//! On i386 `cdecl` no register carries an argument. A caller stores its arguments
//! at the stack pointer it calls with, one word a slot; the call pushes the return
//! address over them, so the function finds argument `k` a word above that, at
//! `esp.0 + word * (k + 1)`. Read through the registers alone, every 32-bit
//! function took nothing and every call was passed nothing: `function summary`
//! said `params: []` on 14 of 14 functions with stack arguments, and the body
//! printed `*(esp.0 + 0x4)` where the source has `a`.
//!
//! Everything here is in frame offsets, from the stack pointer at entry
//! ([`crate::ssa::frame_offsets`]), so a slot has one offset whichever version of
//! the stack pointer, or copy of it, the instruction names it by.

use std::collections::BTreeSet;

use n0xis_arch::{CallTarget, MicroExpr, MicroStmt};
use n0xis_contracts::Va;

use crate::Ctx;
use crate::ir::CfgArtifact;
use crate::ssa::{Frame, SsaBlock, frame_offsets};

/// The bytes a stack argument slot takes, where the convention passes every
/// argument on the stack: one with no integer argument register. `None` on a
/// register convention, whose few stack arguments this does not read yet.
pub(crate) fn stack_word(ctx: &Ctx) -> Option<i128> {
    let cc = crate::ir::abi_conv(ctx)?;
    if !cc.int_args.is_empty() {
        return None;
    }
    ctx.arch.stack_pointer()?;
    ctx.arch.pointer_size().map(i128::from).filter(|w| *w > 0)
}

/// The argument a frame offset names in the function's own frame: the word over
/// the return address is the first. A narrower read inside a slot (`movzbl 0x4(%esp)`
/// of a `char` passed as a word) is that slot.
pub(crate) fn param_slot(word: i128, offset: i128) -> Option<usize> {
    let slot = usize::try_from((offset - word) / word).ok().filter(|_| offset >= word)?;
    (slot < MAX_SLOTS).then_some(slot)
}

/// Past this many slots an offset is no argument: C asks a compiler for 127
/// parameters, and a slot found further up is a misread offset, not a parameter.
const MAX_SLOTS: usize = 256;

/// The frame offset of every version of the stack pointer and every copy of one.
pub(crate) fn frame_of(ctx: &Ctx, blocks: &[SsaBlock]) -> Frame {
    ctx.arch.stack_pointer().map(|sp| frame_offsets(blocks, sp, ctx.arch.pointer_size())).unwrap_or_default()
}

/// Every load address in `e`, an indirect call's target included: `call *0x4(%esp)`
/// reads the first argument.
fn each_load<'e>(e: &'e MicroExpr, f: &mut impl FnMut(&'e MicroExpr, n0xis_arch::Bits)) {
    if let MicroExpr::Load { addr, bits, .. } = e {
        f(addr, *bits);
    }
    if let MicroExpr::Call { target: CallTarget::Indirect(t), .. } = e {
        each_load(t, f);
    }
    for c in crate::typeinfer::expr_children(e) {
        each_load(c, f);
    }
}

fn each_stmt_load<'b>(blocks: &'b [SsaBlock], f: &mut impl FnMut(&'b MicroExpr, n0xis_arch::Bits)) {
    for b in blocks {
        for s in &b.stmts {
            for e in crate::optimize::stmt_read_exprs(&s.stmt) {
                each_load(e, f);
            }
        }
        if let Some(c) = &b.condition {
            each_load(c, f);
        }
    }
}

/// The first and the last byte of an access of `bits` at frame offset `off`: a
/// `long long` or a `double` parameter is read in one 64-bit load, and it is two
/// slots on a 32-bit stack.
fn ends(off: i128, bits: n0xis_arch::Bits) -> [i128; 2] {
    [off, off + (i128::from(bits) / 8).max(1) - 1]
}

/// The frame offsets a load reads anywhere in these blocks: the first and the last
/// byte of each.
pub(crate) fn loaded_offsets(blocks: &[SsaBlock], frame: &Frame) -> BTreeSet<i128> {
    let mut out = BTreeSet::new();
    each_stmt_load(blocks, &mut |addr, bits| {
        if let Some(off) = frame.offset_of(addr) {
            out.extend(ends(off, bits));
        }
    });
    out
}

/// The frame offsets a store writes anywhere in these blocks: the first and the
/// last byte of each.
pub(crate) fn stored_offsets(blocks: &[SsaBlock], frame: &Frame) -> BTreeSet<i128> {
    blocks
        .iter()
        .flat_map(|b| &b.stmts)
        .filter_map(|s| match &s.stmt {
            MicroStmt::Store { addr, bits, .. } => frame.offset_of(addr).map(|off| ends(off, *bits)),
            _ => None,
        })
        .flatten()
        .collect()
}

/// What a function's own body says of its stack arguments.
pub(crate) struct OwnArgs<'b> {
    /// One past the highest argument slot a load reads.
    pub read: usize,
    /// A pointer into the arguments is taken (`lea 0x8(%esp)`, a `va_list`, or gcc's
    /// `main` realigning its stack through `ecx`): what is read through it is not
    /// listed here.
    pub open: bool,
    /// Calls that leave with this function's own arguments where they came: a tail
    /// jump with the stack pointer back at entry. Each takes, of this function's
    /// slots, every one not in `written`.
    pub tails: Vec<&'b CallTarget>,
    /// The argument slots this body stores to.
    pub written: BTreeSet<usize>,
}

/// `flow` is the function's, read before propagation ([`crate::ssa::RawFlow::frame`]):
/// what was loaded and stored there is what the bytes do.
pub(crate) fn own_args<'b>(ctx: &Ctx, cfg: &CfgArtifact, blocks: &'b [SsaBlock], flow: &crate::ssa::RawFlow) -> Option<OwnArgs<'b>> {
    let word = stack_word(ctx)?;
    let sp = ctx.arch.stack_pointer()?;
    let frame = frame_offsets(blocks, sp, ctx.arch.pointer_size());
    let slots = |offsets: &BTreeSet<i128>| -> BTreeSet<usize> { offsets.iter().filter_map(|off| param_slot(word, *off)).collect() };
    let read = slots(&flow.frame.loaded).last().map_or(0, |k| k + 1);
    // A copy, not the stack pointer itself: what a `ret` leaves it at says nothing.
    let open = frame.iter().any(|(v, off)| *off >= word && v.split('.').next() != Some(sp));
    let written = slots(&flow.frame.stored);
    let mut tails = Vec::new();
    let idom = crate::dom::idom_of(cfg);
    for (bi, b) in blocks.iter().enumerate() {
        if cfg.blocks.get(bi).is_none_or(|c| c.terminator != "tail-call") {
            continue;
        }
        let Some((si, target)) = b.stmts.iter().enumerate().rev().find_map(|(i, s)| crate::callee::call_target_of(&s.stmt).map(|t| (i, t))) else { continue };
        let at = crate::callee::version_before(blocks, &idom, bi, si, sp).and_then(|v| frame.get(&v));
        if at == Some(0) {
            tails.push(target);
        }
    }
    Some(OwnArgs { read, open, tails, written })
}

/// Where a call's argument `k` is, in the caller's frame: at the stack pointer it
/// calls with, or, for a tail jump, a word above it, where the caller's own
/// arguments were.
pub(crate) fn call_slot(word: i128, call_sp: i128, tail: bool, k: usize) -> i128 {
    call_sp + if tail { word } else { 0 } + word * k as i128
}

/// The last store to frame offset `want` before statement `at` of `block`, and the
/// statement's address. None past a call: a callee owns its arguments and may have
/// changed them, so what was stored before it is not what the next call is given.
pub(crate) fn slot_store(block: &SsaBlock, at: usize, frame: &Frame, want: i128) -> Option<(Va, MicroExpr, n0xis_arch::Bits)> {
    for st in block.stmts[..at.min(block.stmts.len())].iter().rev() {
        match &st.stmt {
            MicroStmt::Store { addr, value, bits } if frame.offset_of(addr) == Some(want) => return Some((st.va, value.clone(), *bits)),
            s if crate::callee::call_target_of(s).is_some() => return None,
            _ => {}
        }
    }
    None
}

/// Name the function's own arguments where they are read: a load of slot `k`
/// prints as `arg<k>`, at the width it was read. Only a slot nothing here stores
/// to: one that is written holds the caller's value only until then.
pub(crate) fn name_params(ctx: &Ctx, blocks: &mut [SsaBlock], count: usize) {
    let Some(word) = stack_word(ctx) else { return };
    let frame = frame_of(ctx, blocks);
    let written: BTreeSet<usize> = stored_offsets(blocks, &frame).into_iter().filter_map(|off| param_slot(word, off)).collect();
    let bits = n0xis_arch::Bits::try_from(word * 8).unwrap_or(32);
    let mut rename = |e: MicroExpr| match &e {
        MicroExpr::Load { addr, bits: read, signed } => match frame.offset_of(addr) {
            Some(off) if (off - word) % word == 0 && param_slot(word, off).is_some_and(|k| k < count && !written.contains(&k)) => {
                let k = param_slot(word, off).expect("just checked");
                let arg = MicroExpr::Var(arg_entry(k));
                if *read == bits { arg } else { MicroExpr::Cast { signed: *signed, bits: *read, expr: Box::new(arg) } }
            }
            _ => e,
        },
        _ => e,
    };
    for b in blocks.iter_mut() {
        for s in &mut b.stmts {
            s.stmt = crate::optimize::map_stmt_exprs(&s.stmt, &mut rename);
        }
        if let Some(c) = b.condition.take() {
            b.condition = Some(crate::optimize::map_expr(&c, &mut rename));
        }
    }
}

/// The name stack argument `k` prints as, in the signature and in the body.
pub(crate) fn arg_name(k: usize) -> String {
    format!("arg{k}")
}

/// Stack argument `k` as the body holds it: the slot's value at entry, which is
/// what `rdi.0` is of a register.
pub(crate) fn arg_entry(k: usize) -> String {
    format!("{}.0", arg_name(k))
}

#[cfg(test)]
mod tests {
    use crate::ir::{CfgInput, CfgPass};
    use crate::{Ctx, DecompInput, DecompPass, DecompStyle, Pass};
    use n0xis_arch::X64;
    use n0xis_contracts::Va;
    use n0xis_sources::Snapshot;

    const F: u64 = 0x1000;
    const G: u64 = 0x1100;

    /// `rel32` of a `call`/`jmp` at `code.len()` of the function at `F`, to `to`.
    fn branch(code: &mut Vec<u8>, op: u8, to: u64) {
        let rel = to as i64 - (F as i64 + code.len() as i64 + 5);
        code.push(op);
        code.extend_from_slice(&(rel as i32).to_le_bytes());
    }

    fn body(f: &[u8], g: &[u8]) -> crate::PseudoFunction {
        let mut bytes = vec![0xcc; 0x200];
        bytes[..f.len()].copy_from_slice(f);
        bytes[0x100..0x100 + g.len()].copy_from_slice(g);
        let snap = Snapshot::builder().region(Va(F), bytes).build();
        let arch = X64::x86();
        let ctx = Ctx::new(&snap, &arch);
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(F), 0x100)).unwrap();
        DecompPass
            .run(&ctx, DecompInput { cfg, style: DecompStyle::Ssa, explain: false, strip_block_labels: true, var_names: Default::default(), var_types: Default::default(), struct_defs: Default::default() })
            .unwrap()
    }

    // mov eax,[esp+4]; add eax,[esp+8]; ret
    const ADDS_TWO: &[u8] = &[0x8b, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x08, 0xc3];

    /// `int f(int a, int b) { return a + b; }` at `-O2 -m32`: both read off the stack,
    /// which the register convention said nothing of (`uint32_t f()`, `*(esp.0 + 0x4)`).
    #[test]
    fn a_stack_slot_read_is_a_parameter() {
        let p = body(ADDS_TWO, &[]);
        assert!(p.signature.contains("(uint32_t arg0, uint32_t arg1)"), "{}", p.signature);
        let text = p.pseudo.join("\n");
        assert!(text.contains("arg0") && text.contains("arg1") && !text.contains("esp"), "{text}");
        // A parameter read is no value the body leaves unsaid, and it prints by its
        // name, not as the slot's entry value.
        assert_eq!(p.quality, 1.0, "{text}");
        assert!(!text.contains("arg0.0") && !text.contains("arg1.0"), "{text}");
    }

    /// `lea ecx,[esp+8]; mov eax,[ecx-4]` reads the first argument: the lift's
    /// displacement is `0xfffffffc`, and on a 32-bit target that is four bytes down.
    /// Taken as four GiB up, gcc's `main` (`lea 0x4(%esp),%ecx` ... `push -0x4(%ecx)`)
    /// was given a billion arguments and the run its memory ceiling.
    #[test]
    fn a_displacement_wraps_at_the_word() {
        let p = body(&[0x8d, 0x4c, 0x24, 0x08, 0x8b, 0x41, 0xfc, 0xc3], &[]);
        assert!(p.signature.contains("(uint32_t arg0)"), "{}", p.signature);
    }

    /// clang's i386 PIC code reads its own address with `call 1f; 1: pop %eax`, which
    /// leaves the stack pointer where it was: the argument after it is still the first.
    /// On a 32-bit Lua built by clang, 346 functions were given one argument too many.
    #[test]
    fn a_call_to_the_next_instruction_is_a_push() {
        let p = body(&[0xe8, 0, 0, 0, 0, 0x58, 0x8b, 0x44, 0x24, 0x04, 0xc3], &[]);
        assert!(p.signature.contains("(uint32_t arg0)"), "{}", p.signature);
    }

    /// mingw realigns the stack under a `double` (`and $-8,%esp`), and from there the
    /// offset from entry is unknown: `movl $5,(%esp); call g` still gives `g` the 5.
    #[test]
    fn a_realigned_stack_still_passes_what_was_stored() {
        let mut f = vec![0x55, 0x89, 0xe5, 0x83, 0xe4, 0xf8, 0x83, 0xec, 0x08, 0xc7, 0x04, 0x24, 0x05, 0, 0, 0];
        branch(&mut f, 0xe8, G);
        f.extend([0xc9, 0xc3]);
        let p = body(&f, &[0x8b, 0x44, 0x24, 0x04, 0xc3]);
        let text = p.pseudo.join("\n");
        assert!(text.contains("(0x5)"), "{text}");
    }

    /// `int f(int a, int b) { return g(a, b); }` as gcc gives it, `jmp g`: nothing read,
    /// both passed on where they came, and `g` reads both.
    #[test]
    fn a_tail_jump_passes_its_own_arguments_on() {
        let mut f = Vec::new();
        branch(&mut f, 0xe9, G);
        let p = body(&f, ADDS_TWO);
        assert!(p.signature.contains("(uint32_t arg0, uint32_t arg1)"), "{}", p.signature);
        assert!(p.pseudo.join("\n").contains("(arg0, arg1)"), "{}", p.pseudo.join("\n"));
    }

    /// `movl $8,(%esp); call g` after a join both of whose paths leave the stack pointer
    /// where it was: SSA puts no phi there, and the version is the dominator's. Up
    /// single predecessors only, the call was given nothing (gcc's CRT main,
    /// `__amsg_exit(8)`, objdump `movl $0x8,(%esp)`).
    #[test]
    fn a_call_after_a_join_is_given_what_was_stored() {
        // sub esp,0xc; cmp dword [esp+0x10],0; je +5; mov eax,1;
        let mut f = vec![0x83, 0xec, 0x0c, 0x83, 0x7c, 0x24, 0x10, 0x00, 0x74, 0x05, 0xb8, 1, 0, 0, 0];
        // mov dword [esp],8; call g; add esp,0xc; ret
        f.extend([0xc7, 0x04, 0x24, 0x08, 0, 0, 0]);
        branch(&mut f, 0xe8, G);
        f.extend([0x83, 0xc4, 0x0c, 0xc3]);
        let p = body(&f, &[0x8b, 0x44, 0x24, 0x04, 0xc3]);
        let text = p.pseudo.join("\n");
        assert!(text.contains("(0x8)"), "{text}");
    }

    /// `push [esp+8]; push [esp+8]; call g`: the two pushes are `g`'s arguments, the
    /// second pushed first, and they stop printing as two writes to one local.
    #[test]
    fn what_is_pushed_before_a_call_is_its_arguments() {
        let mut f = vec![0xff, 0x74, 0x24, 0x08, 0xff, 0x74, 0x24, 0x08];
        branch(&mut f, 0xe8, G);
        f.extend([0x83, 0xc4, 0x08, 0xc3]);
        let p = body(&f, ADDS_TWO);
        let text = p.pseudo.join("\n");
        assert!(text.contains("(arg0, arg1)"), "{text}");
        assert!(!text.contains("local_"), "{text}");
    }
}
