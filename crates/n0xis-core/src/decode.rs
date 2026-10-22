// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

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
    /// The index of the function whose body holds `start` — every
    /// instruction of the window, since a stream ends with its body — beside
    /// the position, on an architecture that identifies functions by index (a
    /// WebAssembly module's: docs/design/WASM.md §5 decision 1). Absent on
    /// every other architecture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<u32>,
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
        let function = ctx.arch.indexed_function(input.start);
        // An instruction of an indexed code space (a WebAssembly module's) is
        // as long as its immediates, and a `br_table` is as long as its
        // target list (525 bytes in a real module), so a byte budget sized
        // for x64's 15 cut a window off inside one and the stream stopped
        // there, short of the count asked, with no word. Its body is where
        // the stream ends anyway: read to its end, which is bytes of the image.
        let max_bytes = match function {
            Some(f) => input.max_bytes.max(f.end.0.saturating_sub(input.start.0) as usize),
            None => input.max_bytes,
        };
        let bytes = ctx.source.read(input.start, max_bytes)?;
        let insns = ctx.arch.decode_stream(&bytes, input.start, input.max_insns);
        // Bytes were read, an instruction was asked for, and none decoded,
        // where the architecture says no instruction is at `start`: an
        // architecture that knows where its instructions are (a WebAssembly
        // module's, inside an instruction, a locals declaration's runs, or
        // between two bodies) decodes nothing there rather than an `invalid`
        // the module does not hold. An empty list beside `ok` would read as
        // "nothing there", where the answer is "not an instruction's start".
        // A native decoder that decodes nothing does so only for a window
        // shorter than its instruction (`Truncated`), which stays an empty
        // answer, as it was.
        if insns.is_empty()
            && !bytes.is_empty()
            && input.max_insns > 0
            && let Err(n0xis_arch::DecodeError::Invalid(_)) = ctx.arch.decode(&bytes, input.start)
        {
            return Err(CoreError::Other(match function {
                Some(f) => format!(
                    "no instruction starts at {}: it is inside function {} (its body starts at {}), in an instruction or the locals declaration",
                    input.start, f.index, f.body
                ),
                None => format!("no instruction starts at {}: it is in no function's body", input.start),
            }));
        }
        let bytes_consumed = insns.iter().map(|i| i.len as usize).sum();
        Ok(DecodeOutput {
            start: input.start,
            function: function.map(|f| f.index),
            count: insns.len(),
            bytes_consumed,
            insns,
        })
    }
}
