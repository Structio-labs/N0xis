// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`Wasm`] — WebAssembly as an [`Arch`] that decodes and does not lift yet
//! (docs/design/WASM.md stage 2; the stack-machine lift is stage 3).
//!
//! **Built from the module, not from a name.** The same bytes decode
//! differently by where they are: a body begins with its locals declaration,
//! which reads as instructions if decoded as one, and a `call 3` names a
//! function by its index, whose body is wherever the module put it. So the
//! architecture holds the module, and decodes an offset by the body that
//! holds it: the instruction at that offset if one starts there, the locals
//! declaration at a body's start (decision 1: a function starts at its body,
//! and its decoded stream begins with that declaration), and nothing anywhere
//! else — between two bodies are their sizes, inside an instruction are its
//! immediates, and neither is an instruction.
//!
//! **The bytes it is handed must be the module's.** A decoder is given bytes
//! and an address; this one checks that the bytes at that address are the
//! module's own, and refuses otherwise, so it can never describe one module's
//! code with another's.
//!
//! What a decoded instruction carries: the stage-1 decoder's instruction, its
//! text as that crate renders it (the canonical spelling its tests compare
//! with two independent tools), and for a direct call, a tail call or a
//! `ref.func` the callee's index (`target_function`), with its body as the
//! target where it has one: an imported function has an index and no body,
//! so a call to one names its index alone, and is still a call. A branch's
//! target is a label depth, which only the structure around it turns into a
//! position — the CFG of stage 3 — so it has none here.
//!
//! **An offset where no instruction starts decodes to nothing**: inside an
//! instruction, between two bodies (their sizes), or outside the code
//! section. A native decoder reads some instruction from any bytes; this one
//! knows where every instruction is, and an `invalid` there would state that
//! the module holds an invalid instruction, which it does not.

use std::ops::Range;
use std::sync::{Arc, Mutex};

use n0xis_contracts::Va;
use n0xis_wasm::{Body, FuncIdx, Instr, Module};

use crate::{Arch, CallConv, DecodeError, DecodedInsn, InsnKind, Lifting, RegisterFile};

/// What a command that needs the lift says when it refuses a module.
pub const WASM_NOT_LIFTED: &str = "the WebAssembly stack-machine lift is stage 3 of docs/design/WASM.md; this build decodes a module's \
                                   instructions and lifts none of them";

/// WebAssembly, decoded from one module.
#[derive(Debug)]
pub struct Wasm {
    module: Arc<Module>,
    /// The module's identity, part of the decoder's: two modules with the same
    /// code section but different imports number their functions differently,
    /// so the same `call` reaches different bodies.
    identity: String,
    /// The last body decoded. Decoding is asked one body at a time, almost
    /// always in order, so one is all it keeps.
    last: Mutex<Option<Arc<Decoded>>>,
}

/// One body, decoded.
#[derive(Debug)]
struct Decoded {
    func: FuncIdx,
    range: Range<usize>,
    body: Body,
}

/// The register file of an architecture that has none: values live on an
/// operand stack and in typed locals.
static NO_REGISTERS: RegisterFile = RegisterFile::new(&[]);

impl Wasm {
    /// The architecture of `module`, which is known by `identity`.
    pub fn new(module: Arc<Module>, identity: impl Into<String>) -> Self {
        Wasm { module, identity: identity.into(), last: Mutex::new(None) }
    }

    /// The body that holds `offset`, decoded. `None` when no body holds it, or
    /// the body cannot be decoded (the module's findings say which).
    fn body_at(&self, offset: usize) -> Option<Arc<Decoded>> {
        let (func, range) = self.module.function_containing(offset)?;
        {
            let last = self.last.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(d) = last.as_ref()
                && d.func == func
            {
                return Some(Arc::clone(d));
            }
        }
        let body = self.module.body(func)?.ok()?;
        let decoded = Arc::new(Decoded { func, range, body });
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&decoded));
        Some(decoded)
    }

    /// The instructions of `d` from the one at `offset` on, the body's start
    /// meaning its locals declaration, as decoded instructions: at most `max`
    /// of them, and none that starts at or past `upto`. `None` when nothing
    /// starts at `offset`. Bounded so that decoding one instruction, or a short
    /// window, costs that and not the rest of the body.
    fn from(&self, d: &Decoded, offset: usize, upto: usize, max: usize) -> Option<Vec<DecodedInsn>> {
        let first = d.body.instructions.first()?.offset;
        let mut out = Vec::new();
        let from = if offset == d.range.start {
            if max > 0 && offset < upto {
                out.push(self.locals(d, first));
            }
            0
        } else {
            d.body.instructions.binary_search_by_key(&offset, |l| l.offset).ok()?
        };
        for (i, l) in d.body.instructions.iter().enumerate().skip(from) {
            if out.len() >= max || l.offset >= upto {
                break;
            }
            let end = d.body.instructions.get(i + 1).map_or(d.range.end, |n| n.offset);
            out.push(self.insn(l.offset, end, &l.instr));
        }
        Some(out)
    }

    fn bytes_of(&self, start: usize, end: usize) -> Vec<u8> {
        self.module.bytes(start..end).map(<[u8]>::to_vec).unwrap_or_default()
    }

    /// The locals declaration that opens body `d`, ending where its first
    /// instruction starts.
    fn locals(&self, d: &Decoded, end: usize) -> DecodedInsn {
        let runs: Vec<String> = d.body.locals.iter().map(|r| format!("{} {}", r.count, r.ty)).collect();
        let text = if runs.is_empty() { "locals".to_string() } else { format!("locals {}", runs.join(", ")) };
        DecodedInsn {
            va: Va(d.range.start as u64),
            len: (end - d.range.start) as u32,
            bytes: self.bytes_of(d.range.start, end),
            mnemonic: "locals".into(),
            text,
            kind: InsnKind::Seq,
            target: None,
            rip_target: None,
            cond: None,
            stack_adjust: None,
            target_function: None,
        }
    }

    fn insn(&self, start: usize, end: usize, instr: &Instr) -> DecodedInsn {
        let callee = |f: &FuncIdx| self.module.body_start(*f).map(|b| Va(b as u64));
        let target_function = match instr {
            Instr::Call(f) | Instr::ReturnCall(f) | Instr::RefFunc(f) => Some(crate::IndexedTarget { index: f.0, body: callee(f) }),
            _ => None,
        };
        let (kind, target) = match instr {
            Instr::Call(f) => (InsnKind::Call, callee(f)),
            // A tail call leaves this function for the callee's body.
            Instr::ReturnCall(f) => (InsnKind::Jump, callee(f)),
            Instr::CallIndirect(_) | Instr::CallRef(_) => (InsnKind::Call, None),
            Instr::ReturnCallIndirect(_) | Instr::ReturnCallRef(_) => (InsnKind::Jump, None),
            Instr::Br(_) => (InsnKind::Jump, None),
            Instr::BrIf(_) | Instr::BrTable(_) | Instr::If(_) | Instr::BrOnNull(_) | Instr::BrOnNonNull(_) | Instr::BrOnCast(_) | Instr::BrOnCastFail(_) => {
                (InsnKind::CondJump, None)
            }
            Instr::Return => (InsnKind::Ret, None),
            // A trap or a throw hands control to the runtime, as an interrupt
            // does; neither falls through.
            Instr::Unreachable | Instr::Throw(_) | Instr::Rethrow(_) | Instr::ThrowRef => (InsnKind::Int, None),
            _ => (InsnKind::Seq, None),
        };
        DecodedInsn {
            va: Va(start as u64),
            len: (end - start) as u32,
            bytes: self.bytes_of(start, end),
            mnemonic: instr.name().to_string(),
            text: instr.to_string(),
            kind,
            target,
            rip_target: None,
            cond: None,
            stack_adjust: None,
            target_function,
        }
    }

    /// Whether `bytes` begins with `insn`'s bytes: what a caller handed is the
    /// module's own code at that offset.
    fn handed(bytes: &[u8], insn: &DecodedInsn) -> Result<(), DecodeError> {
        match bytes.get(..insn.bytes.len()) {
            None => Err(DecodeError::Truncated(insn.va)),
            Some(b) if b == insn.bytes.as_slice() => Ok(()),
            Some(_) => Err(DecodeError::Invalid(insn.va)),
        }
    }

    fn invalid(bytes: &[u8], va: Va) -> DecodedInsn {
        DecodedInsn {
            va,
            len: 1,
            bytes: bytes.first().map(|b| vec![*b]).unwrap_or_default(),
            mnemonic: "invalid".into(),
            text: "invalid".into(),
            kind: InsnKind::Invalid,
            target: None,
            rip_target: None,
            cond: None,
            stack_adjust: None,
            target_function: None,
        }
    }
}

impl Arch for Wasm {
    fn name(&self) -> &'static str {
        "wasm"
    }

    fn decoder_id(&self) -> String {
        format!("wasm/{}", self.identity)
    }

    fn pointer_size(&self) -> Option<u8> {
        None
    }

    fn lifting(&self) -> Lifting {
        Lifting::DecodeOnly { why: WASM_NOT_LIFTED }
    }

    fn indexed_function(&self, va: Va) -> Option<crate::IndexedFunction> {
        let (func, range) = self.module.function_containing(usize::try_from(va.0).ok()?)?;
        Some(crate::IndexedFunction { index: func.0, body: Va(range.start as u64), end: Va(range.end as u64) })
    }

    fn decode(&self, bytes: &[u8], va: Va) -> Result<DecodedInsn, DecodeError> {
        let offset = usize::try_from(va.0).map_err(|_| DecodeError::Invalid(va))?;
        let d = self.body_at(offset).ok_or(DecodeError::Invalid(va))?;
        let insn = self.from(&d, offset, usize::MAX, 1).and_then(|v| v.into_iter().next()).ok_or(DecodeError::Invalid(va))?;
        Self::handed(bytes, &insn)?;
        Ok(insn)
    }

    /// From `va` to the end of the body that holds it: a body's stream ends
    /// with its final `end`, and what follows is the next body's size.
    fn decode_stream(&self, bytes: &[u8], va: Va, max: usize) -> Vec<DecodedInsn> {
        let upto = (va.0 as usize).saturating_add(bytes.len());
        let found = usize::try_from(va.0).ok().and_then(|o| self.body_at(o).and_then(|d| self.from(&d, o, upto, max)));
        // Nothing starts here (see the module comment): no instruction, where
        // a native decoder would read one.
        let Some(insns) = found else { return Vec::new() };
        let mut out = Vec::new();
        for insn in insns {
            let at = (insn.va.0 - va.0) as usize;
            match Self::handed(&bytes[at.min(bytes.len())..], &insn) {
                Ok(()) => out.push(insn),
                // The window ends inside the instruction: the stream stops
                // there, as any decoder's does at the end of its bytes.
                Err(DecodeError::Truncated(_)) => break,
                Err(DecodeError::Invalid(_)) => {
                    out.push(Self::invalid(&bytes[at.min(bytes.len())..], insn.va));
                    break;
                }
            }
        }
        out
    }

    /// Exact, not resynchronizing: every body in `[va, va + bytes.len())`
    /// decoded from its start (or, for one the range starts inside, from its
    /// first instruction in the range), and nothing between the bodies, which
    /// is their sizes. A body that does not decode is left out; the image's
    /// findings name it.
    fn decode_range(&self, bytes: &[u8], va: Va, max: usize) -> Vec<DecodedInsn> {
        let (Ok(lo), Ok(len)) = (usize::try_from(va.0), u64::try_from(bytes.len())) else { return Vec::new() };
        let Some(hi) = va.0.checked_add(len).and_then(|h| usize::try_from(h).ok()) else { return Vec::new() };
        let mut out = Vec::new();
        let mut at = lo;
        while at < hi && out.len() < max {
            // The body that holds `at`, or the next one after it.
            let next_body = match self.module.function_containing(at) {
                Some((_, range)) => Some(range),
                None => {
                    let i = self.module.bodies().partition_point(|r| r.start < at);
                    self.module.bodies().get(i).cloned()
                }
            };
            let Some(range) = next_body.filter(|r| r.start < hi) else { break };
            if let Some(d) = self.body_at(range.start.max(at)) {
                let first = if at <= d.range.start {
                    Some(d.range.start)
                } else {
                    d.body.instructions.iter().map(|l| l.offset).find(|&o| o >= at)
                };
                if let Some(insns) = first.and_then(|f| self.from(&d, f, hi, max - out.len())) {
                    for insn in insns {
                        if out.len() >= max || insn.va.0 + u64::from(insn.len) > hi as u64 {
                            break;
                        }
                        let rel = (insn.va.0 - va.0) as usize;
                        if Self::handed(&bytes[rel..], &insn).is_err() {
                            break;
                        }
                        out.push(insn);
                    }
                }
            }
            // Past the body, and never not forward: a corrupted module can
            // state a body of size 0, whose end is its start, and stepping to
            // that end stood still (found by the corrupted-module test, a
            // sweep that never returned).
            at = range.end.max(at + 1);
        }
        out
    }

    fn regs(&self) -> &RegisterFile {
        &NO_REGISTERS
    }

    /// None: a function's parameters are typed values on the operand stack,
    /// which no register carries, and no lift reads a convention yet
    /// ([`Lifting::DecodeOnly`] says why).
    fn calling_conventions(&self) -> &[CallConv] {
        &[]
    }
}
