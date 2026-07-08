//! [`DecodePass`] — linear decode of a byte window into instructions. The first
//! and simplest pass; it exercises the whole seam stack (source → arch) and is
//! the foundation `disasm` and, later, CFG construction build on.

use n0xis_arch::DecodedInsn;
use n0xis_contracts::Va;
use serde::Serialize;

use crate::{Ctx, CoreError, Pass};

/// What to decode: a start address and a budget in both bytes and instructions.
#[derive(Clone, Copy, Debug)]
pub struct DecodeInput {
    pub start: Va,
    /// Upper bound on bytes to pull from the source in one read.
    pub max_bytes: usize,
    /// Upper bound on instructions to emit.
    pub max_insns: usize,
}

impl DecodeInput {
    /// Decode roughly `count` instructions, sizing the byte window generously
    /// (x64 instructions are ≤ 15 bytes).
    pub fn count(start: Va, count: usize) -> Self {
        DecodeInput {
            start,
            max_bytes: count.saturating_mul(16).max(16),
            max_insns: count,
        }
    }
}

/// The decode artifact (`n0xis.decode.v1`).
#[derive(Clone, Debug, Serialize)]
pub struct DecodeOutput {
    pub start: Va,
    pub count: usize,
    pub bytes_consumed: usize,
    pub insns: Vec<DecodedInsn>,
}

/// Linear disassembly pass.
#[derive(Clone, Copy, Debug, Default)]
pub struct DecodePass;

impl Pass for DecodePass {
    type In = DecodeInput;
    type Out = DecodeOutput;

    fn name(&self) -> &'static str {
        "decode"
    }

    fn run(&self, ctx: &Ctx, input: DecodeInput) -> Result<DecodeOutput, CoreError> {
        let bytes = ctx.source.read(input.start, input.max_bytes)?;
        let insns = ctx.arch.decode_stream(&bytes, input.start, input.max_insns);
        let bytes_consumed = insns.iter().map(|i| i.len as usize).sum();
        Ok(DecodeOutput {
            start: input.start,
            count: insns.len(),
            bytes_consumed,
            insns,
        })
    }
}
