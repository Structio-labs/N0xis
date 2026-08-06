//! [`LiftPass`] — turns a built [`CfgArtifact`] into per-block micro-IR.
//!
//! Re-decodes each already-known instruction (`ctx.source.read` +
//! `ctx.arch.decode`, both pure/deterministic given the same bytes) rather
//! than threading raw bytes through [`CfgArtifact`] — keeps that artifact's
//! shape stable and this pass composable on its own (an agent can ask for the
//! lifted IR of a function it already ran `ir build` on, without redoing CFG
//! construction). The extra decode is cheap; caching belongs to the
//! `PassManager` in Phase 6, not here.

use n0xis_arch::MicroStmt;
use n0xis_contracts::Va;
use serde::Serialize;

use crate::ir::CfgArtifact;
use crate::{Ctx, CoreError, Pass};

/// One micro-IR statement anchored to the instruction that produced it (an
/// instruction may produce zero, one, or several statements).
#[derive(Clone, Debug, Serialize)]
pub struct LiftedStmt {
    pub va: Va,
    pub stmt: MicroStmt,
}

#[derive(Clone, Debug, Serialize)]
pub struct LiftedBlock {
    pub id: usize,
    pub stmts: Vec<LiftedStmt>,
}

/// The lifted-but-pre-SSA form of a function — straight-line micro-IR per
/// block, still addressed by raw register/flag names. [`crate::SsaPass`]
/// consumes this.
#[derive(Clone, Debug, Serialize)]
pub struct LiftedFunction {
    pub start: Va,
    pub end: Va,
    pub blocks: Vec<LiftedBlock>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LiftPass;

impl Pass for LiftPass {
    type In = CfgArtifact;
    type Out = LiftedFunction;

    fn name(&self) -> &'static str {
        "ir.lift"
    }

    fn run(&self, ctx: &Ctx, cfg: CfgArtifact) -> Result<LiftedFunction, CoreError> {
        let mut blocks = Vec::with_capacity(cfg.blocks.len());
        for block in &cfg.blocks {
            let mut stmts = Vec::new();
            // A `tail-call` block ends in a branch that leaves the function;
            // its last instruction is lowered as `call + return` rather than
            // as the structural no-op an intra-function `jmp` lifts to
            // (ROADMAP Phase 10, priority 0 — tail-call promotion). Only the
            // *terminating* instruction gets this treatment: an earlier `jmp`
            // in the same block is impossible by construction (a jump ends a
            // block), but the index check keeps that assumption explicit.
            let tail_index =
                (block.terminator == "tail-call").then(|| block.insns.len().saturating_sub(1));
            for (idx, insn) in block.insns.iter().enumerate() {
                // A byte the linear decoder marked invalid (padding, an embedded
                // jump table, data misread as code near a function's tail) must
                // not sink the whole function: re-decoding it here would error.
                // Emit it as an unlifted marker instead — sound (the byte is
                // shown verbatim, never dropped) and lets the rest decompile.
                let decoded = match ctx.source.read(insn.va, insn.len as usize) {
                    Ok(bytes) => ctx.arch.decode(&bytes, insn.va).ok(),
                    Err(_) => None,
                };
                match decoded {
                    Some(decoded) => {
                        let lowered = if tail_index == Some(idx) {
                            ctx.arch.lift_tail_call(&decoded)
                        } else {
                            ctx.arch.lift(&decoded)
                        };
                        for stmt in lowered {
                            stmts.push(LiftedStmt { va: insn.va, stmt });
                        }
                    }
                    None => stmts.push(LiftedStmt {
                        va: insn.va,
                        stmt: MicroStmt::Unlifted { va: insn.va, text: insn.text.clone() },
                    }),
                }
            }
            blocks.push(LiftedBlock { id: block.id, stmts });
        }
        Ok(LiftedFunction { start: cfg.start, end: cfg.end, blocks })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    #[test]
    fn lifts_a_cmp_je_inc_ret_function() {
        // 0x1000 cmp rcx,0   48 83 f9 00
        // 0x1004 je 0x1009   74 03
        // 0x1006 inc rcx     48 ff c1
        // 0x1009 ret         c3
        let code = vec![0x48, 0x83, 0xf9, 0x00, 0x74, 0x03, 0x48, 0xff, 0xc1, 0xc3];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let cfg = crate::CfgPass.run(&ctx, crate::CfgInput::new(Va(0x1000), 64)).unwrap();

        let lifted = LiftPass.run(&ctx, cfg).unwrap();
        assert_eq!(lifted.blocks.len(), 3);
        // Entry block: the cmp becomes one "flags" assign.
        assert_eq!(lifted.blocks[0].stmts.len(), 1);
        matches!(
            &lifted.blocks[0].stmts[0].stmt,
            MicroStmt::Assign { dst, .. } if dst == n0xis_arch::FLAGS_VAR
        );
        // The `inc rcx` block: one statement (dst = dst + 1) plus the opaque
        // flags invalidation.
        let inc_block = &lifted.blocks[1];
        assert_eq!(inc_block.stmts.len(), 2);
        // The ret block returns rax.
        let ret_block = lifted.blocks.last().unwrap();
        assert!(matches!(ret_block.stmts.last().unwrap().stmt, MicroStmt::Return(_)));
    }
}
