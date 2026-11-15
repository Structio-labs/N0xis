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
    /// Why `insns` holds fewer instructions than were asked for, and `None`
    /// exactly when it holds as many. Not part of the artifact: the front
    /// door says it beside the answer, as it says the other remarks of a
    /// listing ([`Shortfall`]'s `Display` is that sentence).
    #[serde(skip)]
    pub short: Option<Shortfall>,
}

/// Why a listing ended before the count asked for.
///
/// It used to end at the first invalid instruction with no word: 20 005 of
/// 60 000 instructions asked on a stripped executable (2026-10-20), and on a
/// five-instruction fixture 2 of 10, where `objdump` steps over the one
/// invalid byte and lists the rest. An invalid instruction no longer ends a
/// listing; these are what still can, each said where it happens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shortfall {
    /// The source holds no more bytes from `at`: the end of what the image
    /// has at that address (a section's bytes in the file, a mapped region).
    BytesEnd { at: Va },
    /// The read window ended at `at`, with bytes the source could still give.
    WindowEnd { at: Va },
    /// The last `left` bytes, at `at`, begin an instruction the bytes end
    /// inside.
    Truncated { at: Va, left: usize },
    /// The body of function `function` ends at `at` (an architecture that
    /// identifies functions by index decodes one body, from its start).
    BodyEnd { function: u32, at: Va },
    /// The instruction at `at` is invalid, on an architecture that decodes a
    /// body from its start and so has no place after it to go on from.
    InvalidInBody { at: Va },
}

impl std::fmt::Display for Shortfall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Shortfall::BytesEnd { at } => write!(f, "the listing ends at {at}, where the source has no more bytes"),
            Shortfall::WindowEnd { at } => write!(f, "the listing ends at {at}, where the bytes read for it end"),
            Shortfall::Truncated { at, left } => {
                write!(f, "the listing ends at {at}: the {left} byte(s) there begin an instruction the source's bytes end inside")
            }
            Shortfall::BodyEnd { function, at } => write!(f, "the listing ends at {at}, the end of function {function}'s body"),
            Shortfall::InvalidInBody { at } => {
                write!(f, "the listing ends at the invalid instruction at {at}: a body is decoded from its start, and there is no place after it to go on from")
            }
        }
    }
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
        let (insns, short) = listing(ctx, &bytes, input, function, max_bytes);
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
            short,
        })
    }
}

/// Up to `input.max_insns` instructions from the front of `bytes`, as a linear
/// listing reads them, and why there are fewer where there are.
///
/// An invalid instruction is listed, as long as the instruction set says it is
/// ([`Arch::resync_step`](n0xis_arch::Arch::resync_step): one byte on x86),
/// and the listing goes on after it, as `objdump` does. A function walk stops
/// there ([`Arch::decode_stream`](n0xis_arch::Arch::decode_stream)'s rule); a
/// listing does not, since what follows is what was asked for. Not on an
/// architecture that identifies functions by index: it decodes one body from
/// its start, and a step past a byte it could not read lands in its operands.
fn listing(
    ctx: &Ctx,
    bytes: &[u8],
    input: DecodeInput,
    function: Option<n0xis_arch::IndexedFunction>,
    window: usize,
) -> (Vec<DecodedInsn>, Option<Shortfall>) {
    let max = input.max_insns;
    let va_at = |at: usize| Va(input.start.0.wrapping_add(at as u64));
    let mut insns: Vec<DecodedInsn> = Vec::new();
    let mut at = 0usize;
    while insns.len() < max && at < bytes.len() {
        let run = ctx.arch.decode_stream(&bytes[at..], va_at(at), max - insns.len());
        let ended_invalid = run.last().is_some_and(|i| i.kind == n0xis_arch::InsnKind::Invalid);
        let before = insns.len();
        for insn in run {
            at += insn.len as usize;
            insns.push(insn);
        }
        if insns.len() == before {
            break;
        }
        if ended_invalid {
            // The bytes ended inside an instruction: not an invalid one, and
            // nothing to step past.
            let last = insns.last().map(|i| (i.va, i.len as usize));
            if let Some((va, len)) = last {
                let from = at - len;
                if let Err(n0xis_arch::DecodeError::Truncated(_)) = ctx.arch.decode(&bytes[from..], va) {
                    insns.pop();
                    return (insns, Some(Shortfall::Truncated { at: va, left: bytes.len() - from }));
                }
            }
            if function.is_none() {
                continue;
            }
            if insns.len() < max
                && let Some(bad) = insns.last().map(|i| i.va)
            {
                return (insns, Some(Shortfall::InvalidInBody { at: bad }));
            }
        }
        break;
    }
    if insns.len() >= max {
        return (insns, None);
    }
    let short = match function {
        Some(f) => Shortfall::BodyEnd { function: f.index, at: va_at(at) },
        None if at < bytes.len() => Shortfall::Truncated { at: va_at(at), left: bytes.len() - at },
        None if bytes.len() < window => Shortfall::BytesEnd { at: va_at(at) },
        None => Shortfall::WindowEnd { at: va_at(at) },
    };
    (insns, Some(short))
}
