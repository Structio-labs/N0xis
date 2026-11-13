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
//!
//! Which jumps are such a call is decided in one place,
//! [`CfgArtifact::tail_calls_through_pointers`] (`tail_jump.rs`), which `function summary`'s
//! `returns` reads too. This module only makes the graph say what that rule found.

use crate::ir::Callsite;
use crate::{CfgArtifact, CoreError, Ctx};

/// `cfg` with each unresolved jump that the one rule
/// ([`CfgArtifact::tail_calls_through_pointers`]) calls a tail call through a pointer made
/// one: terminator `tail-call` and a `tail` call site with no target, so the lift makes
/// the jump `call` + `return` and every pass that knows a tail call knows this one.
///
/// The switch reader's word is not asked: it reports a dispatch on a `jmp rax` whenever
/// any instruction before it in the block has an index, and did on `lea (,%rsi,8)`
/// computing `x * 7` before a call through an object's slot. The rule reads the jump's
/// own address instead.
pub(crate) fn with_tail_calls_through_pointers(ctx: &Ctx, mut cfg: CfgArtifact) -> Result<CfgArtifact, CoreError> {
    for id in cfg.tail_calls_through_pointers(ctx) {
        let block = &mut cfg.blocks[id];
        let Some(from) = block.insns.last().map(|i| i.va) else { continue };
        block.terminator = "tail-call".into();
        cfg.stats.tail_calls += 1;
        cfg.callsites.push(Callsite { from, kind: "tail".into(), target: None, target_name: None, via_slot: None });
    }
    cfg.callsites.sort_by_key(|c| c.from.0);
    Ok(cfg)
}
