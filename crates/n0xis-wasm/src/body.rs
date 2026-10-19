// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Expressions and function bodies: instructions up to the `end` that closes
//! the outermost block, with `block`/`loop`/`if`/`else`/`end` balanced.

use std::ops::Range;

use crate::error::{Error, Problem};
use crate::instr::{self, Instr, Located};
use crate::reader::Reader;
use crate::types::ValType;

/// `count` locals of one type, as a body declares them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LocalRun {
    pub count: u32,
    pub ty: ValType,
}

/// A function body, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    /// The bytes of the body in the file: its locals, then its expression.
    pub range: Range<usize>,
    /// The locals it declares, after the function's parameters, as declared:
    /// runs of one type, never expanded (a run may state billions).
    pub locals: Vec<LocalRun>,
    /// Every instruction, the final `end` included.
    pub instructions: Vec<Located>,
}

impl Body {
    /// How many locals the body declares (parameters not included).
    pub fn local_count(&self) -> u64 {
        self.locals.iter().map(|run| u64::from(run.count)).sum()
    }
}

/// Whether a data index may appear: the format requires a data count section
/// before any code that names a data segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DataIndices {
    Allowed,
    NeedDataCount,
}

/// What encloses an instruction, innermost last.
#[derive(Clone, Copy)]
enum Frame {
    Block,
    If { has_else: bool },
}

/// Decode an expression up to and including its final `end`, handing each
/// instruction to `each`. Every instruction takes at least one byte and every
/// frame is opened by one, so both the loop and the frame stack are bounded
/// by the reader's bytes.
pub(crate) fn expression(
    r: &mut Reader,
    data_indices: DataIndices,
    mut each: impl FnMut(Located),
) -> Result<(), Error> {
    let mut frames: Vec<Frame> = Vec::new();
    loop {
        if r.at_end() {
            return Err(r.error(r.offset(), Problem::NotEnded));
        }
        let offset = r.offset();
        let instr = instr::decode(r)?;
        match &instr {
            Instr::Block(_) | Instr::Loop(_) => frames.push(Frame::Block),
            Instr::If(_) => frames.push(Frame::If { has_else: false }),
            Instr::Else => match frames.last_mut() {
                Some(Frame::If { has_else }) if !*has_else => *has_else = true,
                _ => return Err(r.error(offset, Problem::ElseWithoutIf)),
            },
            Instr::MemoryInit(_) | Instr::DataDrop(_) if data_indices == DataIndices::NeedDataCount => {
                return Err(r.error(offset, Problem::DataIndexWithoutDataCount));
            }
            _ => {}
        }
        let closes_expression = matches!(instr, Instr::End) && frames.pop().is_none();
        each(Located { offset, instr });
        if closes_expression {
            return Ok(());
        }
    }
}

/// A constant expression (a global's initial value, a segment's offset or
/// item), decoded as any expression is; whether it is constant is validation.
pub(crate) fn const_expression(r: &mut Reader) -> Result<Vec<Located>, Error> {
    let mut out = Vec::new();
    expression(r, DataIndices::Allowed, |l| out.push(l))?;
    Ok(out)
}

/// A function body over exactly `r`'s bytes: locals, an expression, and
/// nothing after its final `end`.
pub(crate) fn body(mut r: Reader, data_indices: DataIndices, each: impl FnMut(Located)) -> Result<Vec<LocalRun>, Error> {
    // Each run is a count and a type: at least two bytes.
    let runs = r.count(2)?;
    let mut locals = Vec::new();
    let mut total: u64 = 0;
    for _ in 0..runs {
        let at = r.offset();
        let count = r.u32()?;
        let ty = ValType::read(&mut r)?;
        total += u64::from(count);
        if total > u64::from(u32::MAX) {
            return Err(r.error(at, Problem::TooManyLocals));
        }
        locals.push(LocalRun { count, ty });
    }
    expression(&mut r, data_indices, each)?;
    if !r.at_end() {
        return Err(r.error(r.offset(), Problem::BytesAfterEnd(r.remaining())));
    }
    Ok(locals)
}
