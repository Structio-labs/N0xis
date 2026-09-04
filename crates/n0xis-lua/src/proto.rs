// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Prototype (function) parsing — the `pdata`/`phead` shape from
//! `lj_bcdump.h`, read exactly as `lj_bcread.c: bcread_proto` reads it (field
//! order and constant encoding cross-checked against that function directly,
//! not just the format comment).

use serde::Serialize;

use crate::opcodes::{opdef, BC_FUNCF, BC_FUNCV};
use crate::reader::Reader;
use crate::LuaError;

/// `PROTO_VARARG`, the one `phead.flags` bit this crate needs (to synthesize
/// the same implicit `bc[0]` the real reader adds — `FUNCF` vs `FUNCV`).
const PROTO_VARARG: u8 = 0x02;

/// One decoded bytecode instruction.
#[derive(Debug, Clone, Serialize)]
pub struct Instruction {
    /// Index within the prototype's bytecode array; `0` is the synthesized
    /// `FUNCF`/`FUNCV` entry point the dump doesn't store explicitly.
    pub idx: u32,
    pub raw: u32,
    pub op: &'static str,
    pub a: u16,
    /// `None` for AD-format opcodes (all the operand lives in `d`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub b: Option<u16>,
    pub d: u16,
    /// Human-readable rendering, e.g. `GGET r0, "some_global"` — resolves
    /// string/number/child-proto operands where this prototype's own
    /// constant pools make that possible.
    pub text: String,
}

/// A GC constant (`kgc` pool) — backward-indexed from bytecode operands, see
/// [`crate::opcodes::Mode::Str`].
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum GcConst {
    /// A nested prototype, resolved to its index in the enclosing
    /// [`crate::LuaChunk::protos`].
    Child(usize),
    Str(String),
    Table(TableConst),
    I64 { lo: u32, hi: u32 },
    U64 { lo: u32, hi: u32 },
    Complex { re_lo: u32, re_hi: u32, im_lo: u32, im_hi: u32 },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum TableValue {
    Nil,
    False,
    True,
    Int(i32),
    Num(f64),
    Str(String),
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct TableConst {
    pub array: Vec<TableValue>,
    pub hash: Vec<(TableValue, TableValue)>,
}

/// A numeric constant (`knum` pool) — forward-indexed directly by operand
/// value, see [`crate::opcodes::Mode::Num`].
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum NumConst {
    Int(i32),
    Num(f64),
}

/// One parsed prototype (Lua calls this a "function").
#[derive(Debug, Clone, Serialize)]
pub struct Proto {
    pub numparams: u8,
    pub framesize: u8,
    pub is_vararg: bool,
    pub upvalues: Vec<u16>,
    pub gc_constants: Vec<GcConst>,
    pub num_constants: Vec<NumConst>,
    pub instructions: Vec<Instruction>,
    /// Absolute byte offset, in the *original whole chunk buffer* passed to
    /// [`crate::disassemble`], of instruction index `1` (index `0` is the
    /// synthesized `FUNCF`/`FUNCV` entry point — it has no real file bytes
    /// and can never be patched). `#[serde(skip)]`: an offset into a buffer
    /// the caller already has is implementation detail, not analysis output.
    #[serde(skip)]
    pub bytecode_file_offset: usize,
}

fn read_ktabk(r: &mut Reader) -> Result<TableValue, LuaError> {
    let tp = r.uleb128()?;
    const KTAB_NIL: u32 = 0;
    const KTAB_FALSE: u32 = 1;
    const KTAB_TRUE: u32 = 2;
    const KTAB_INT: u32 = 3;
    const KTAB_NUM: u32 = 4;
    const KTAB_STR: u32 = 5;
    Ok(if tp >= KTAB_STR {
        let len = (tp - KTAB_STR) as usize;
        TableValue::Str(String::from_utf8_lossy(r.take(len)?).into_owned())
    } else {
        match tp {
            KTAB_NIL => TableValue::Nil,
            KTAB_FALSE => TableValue::False,
            KTAB_TRUE => TableValue::True,
            KTAB_INT => TableValue::Int(r.uleb128()? as i32),
            KTAB_NUM => {
                let lo = r.uleb128()?;
                let hi = r.uleb128()?;
                TableValue::Num(f64::from_bits((lo as u64) | ((hi as u64) << 32)))
            }
            _ => return Err(LuaError::Malformed("bad ktabk type tag")),
        }
    })
}

fn read_ktab(r: &mut Reader) -> Result<TableConst, LuaError> {
    let narray = r.uleb128()? as usize;
    let nhash = r.uleb128()? as usize;
    let mut array = Vec::with_capacity(narray.min(1 << 20));
    for _ in 0..narray {
        array.push(read_ktabk(r)?);
    }
    let mut hash = Vec::with_capacity(nhash.min(1 << 20));
    for _ in 0..nhash {
        let key = read_ktabk(r)?;
        let val = read_ktabk(r)?;
        hash.push((key, val));
    }
    Ok(TableConst { array, hash })
}

/// Read one prototype's GC constants (`kgc`), resolving `BCDUMP_KGC_CHILD`
/// entries against `already_parsed` — the flat list of every prototype parsed
/// *before* this one in the dump, treated as a shared LIFO stack of
/// not-yet-claimed children, exactly matching `bcread_kgc`'s `L->top--`
/// popping (children are always dumped immediately before the parent that
/// references them).
fn read_kgc(r: &mut Reader, count: usize, available_children: &mut Vec<usize>) -> Result<Vec<GcConst>, LuaError> {
    const KGC_CHILD: u32 = 0;
    const KGC_TAB: u32 = 1;
    const KGC_I64: u32 = 2;
    const KGC_U64: u32 = 3;
    const KGC_COMPLEX: u32 = 4;
    const KGC_STR: u32 = 5;

    // Constants are stored back-to-front relative to how instructions
    // reference them (operand 0 = last-read constant), but we read them in
    // file order here and let the caller's index math (`sizekgc-1-d`) handle
    // the reversal — this vec stays in read order.
    let mut out = Vec::with_capacity(count.min(1 << 20));
    for _ in 0..count {
        let tp = r.uleb128()?;
        let c = if tp >= KGC_STR {
            let len = (tp - KGC_STR) as usize;
            GcConst::Str(String::from_utf8_lossy(r.take(len)?).into_owned())
        } else {
            match tp {
                KGC_CHILD => {
                    let idx = available_children.pop().ok_or(LuaError::Malformed("child proto reference with no available child"))?;
                    GcConst::Child(idx)
                }
                KGC_TAB => GcConst::Table(read_ktab(r)?),
                KGC_I64 => {
                    let lo = r.uleb128()?;
                    let hi = r.uleb128()?;
                    GcConst::I64 { lo, hi }
                }
                KGC_U64 => {
                    let lo = r.uleb128()?;
                    let hi = r.uleb128()?;
                    GcConst::U64 { lo, hi }
                }
                KGC_COMPLEX => {
                    let re_lo = r.uleb128()?;
                    let re_hi = r.uleb128()?;
                    let im_lo = r.uleb128()?;
                    let im_hi = r.uleb128()?;
                    GcConst::Complex { re_lo, re_hi, im_lo, im_hi }
                }
                _ => return Err(LuaError::Malformed("bad kgc type tag")),
            }
        };
        out.push(c);
    }
    Ok(out)
}

fn read_knum(r: &mut Reader, count: usize) -> Result<Vec<NumConst>, LuaError> {
    let mut out = Vec::with_capacity(count.min(1 << 20));
    for _ in 0..count {
        let (lo, is_num) = r.uleb128_33()?;
        if is_num {
            let hi = r.uleb128()?;
            out.push(NumConst::Num(f64::from_bits((lo as u64) | ((hi as u64) << 32))));
        } else {
            out.push(NumConst::Int(lo as i32));
        }
    }
    Ok(out)
}

/// Parse one length-prefixed prototype blob (the bytes *after* the `lengthU`
/// varint, exactly `len` bytes). `strip` comes from the chunk header's
/// `BCDUMP_F_STRIP` flag (debug info is absent when set). `body_file_offset`
/// is where `body` sits in the original whole-chunk buffer, so the returned
/// `Proto` can record an absolute, patchable byte offset for its bytecode.
fn parse_proto_body(body: &[u8], body_file_offset: usize, strip: bool, available_children: &mut Vec<usize>) -> Result<Proto, LuaError> {
    let mut r = Reader::new(body);
    let flags = r.byte()?;
    let numparams = r.byte()?;
    let framesize = r.byte()?;
    let sizeuv = r.byte()? as usize;
    let sizekgc = r.uleb128()? as usize;
    let sizekn = r.uleb128()? as usize;
    let sizebc = r.uleb128()? as usize + 1; // dump stores count-1; bc[0] is synthesized

    if !strip {
        let sizedbg = r.uleb128()?;
        if sizedbg > 0 {
            let _firstline = r.uleb128()?;
            let _numline = r.uleb128()?;
        }
        // Debug info's own byte length isn't separately re-derivable from
        // sizedbg alone without replicating lineinfo-width heuristics; since
        // this crate doesn't render source lines/var names, the simplest
        // sound move is to require STRIP for now rather than guess at debug
        // blob length. Real Bitsquid/Stingray-engine script dumps are
        // stripped (verified), so this isn't in the way of the target use case.
        if sizedbg > 0 {
            return Err(LuaError::Malformed("non-stripped debug info is not decoded (documented follow-on)"));
        }
    }

    // Instructions: bc[0] is synthesized (FUNCF/FUNCV, A=framesize, D=0); the
    // dump stores bc[1..sizebc) as raw little-endian u32 words, starting here.
    let bytecode_file_offset = body_file_offset + r.pos();
    let is_vararg = flags & PROTO_VARARG != 0;
    let mut raw_words = Vec::with_capacity(sizebc.min(1 << 20));
    let synth_op = if is_vararg { BC_FUNCV } else { BC_FUNCF };
    raw_words.push(synth_op as u32 | ((framesize as u32) << 8));
    for _ in 1..sizebc {
        raw_words.push(r.u32le()?);
    }

    let mut upvalues = Vec::with_capacity(sizeuv.min(1 << 20));
    for _ in 0..sizeuv {
        upvalues.push(r.u16le()?);
    }

    let gc_constants = read_kgc(&mut r, sizekgc, available_children)?;
    let num_constants = read_knum(&mut r, sizekn)?;

    let instructions = raw_words
        .iter()
        .enumerate()
        .map(|(idx, &raw)| decode_instruction(idx as u32, raw, &gc_constants, &num_constants))
        .collect();

    Ok(Proto { numparams, framesize, is_vararg, upvalues, gc_constants, num_constants, instructions, bytecode_file_offset })
}

fn decode_instruction(idx: u32, raw: u32, gc: &[GcConst], num: &[NumConst]) -> Instruction {
    let op_byte = (raw & 0xff) as u8;
    let a = ((raw >> 8) & 0xff) as u16;
    let Some(def) = opdef(op_byte) else {
        return Instruction { idx, raw, op: "???", a, b: None, d: ((raw >> 16) & 0xffff) as u16, text: format!("<unknown opcode {op_byte}>") };
    };
    let has_d = def.b == crate::opcodes::Mode::None;
    let (b, d) = if has_d { (None, ((raw >> 16) & 0xffff) as u16) } else { (Some((raw >> 24) as u16), ((raw >> 16) & 0xff) as u16) };
    let text = crate::render::render(def, idx, a, b, d, gc, num);
    Instruction { idx, raw, op: def.name, a, b, d, text }
}

/// Parse an entire dump body (the bytes right after the header) into every
/// prototype it contains, in file order — the last one is the chunk's
/// top-level function.
pub(crate) fn parse_all_protos(r: &mut Reader, strip: bool) -> Result<Vec<Proto>, LuaError> {
    let mut protos = Vec::new();
    let mut available_children: Vec<usize> = Vec::new();
    loop {
        // Single 0x00 byte marks end-of-dump.
        if r.peek_byte() == Some(0) {
            r.byte()?;
            break;
        }
        if r.remaining() == 0 {
            break;
        }
        let len = r.uleb128()? as usize;
        if len == 0 {
            break;
        }
        let body_file_offset = r.pos();
        let body = r.take(len)?;
        let proto = parse_proto_body(body, body_file_offset, strip, &mut available_children)?;
        protos.push(proto);
        available_children.push(protos.len() - 1);
    }
    Ok(protos)
}
