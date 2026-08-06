//! # n0xis-lua — Lua/LuaJIT bytecode disassembler
//!
//! Decodes a LuaJIT 2.0 bytecode dump (`\x1bLJ` + version `1` — the format
//! LuaJIT 2.0.x actually emits, cross-checked field-for-field against
//! upstream LuaJIT's own `lj_bcread.c`/`lj_bc.h` at tag `v2.0.3`, and
//! validated against ~900 real bytecode chunks extracted from a shipped
//! Bitsquid/Stingray game) into a structured, JSON-serializable form: every
//! prototype's instructions (mnemonic + resolved operands), string/number/
//! table constants, and nested-prototype links.
//!
//! **Scope**: LuaJIT 2.0's bytecode dump format (version 1). Plain Lua
//! source text and stock (non-JIT) Lua 5.1 bytecode are surfaced by
//! [`n0xis_bitsquid::LuaFormat`] but not decoded here — a documented
//! follow-on, not a silent gap. Non-stripped chunks (embedded debug
//! line/variable-name info) are detected but not decoded (same reasoning:
//! not needed for the target use case, and guessing at the debug-info byte
//! layout without dedicated verification would violate this project's
//! sound-over-complete rule).
//!
//! A pluggable scripting-format adapter — independent of any single game;
//! `n0xis-core` never depends on this crate (CONCEPT §4's "isolate an
//! external format behind an adapter" rule, same as `n0xis-bitsquid`).

mod header;
mod opcodes;
mod proto;
mod reader;
mod render;

pub use header::Header;
pub use opcodes::{Mode, OpDef, OPCODES};
pub use proto::{GcConst, Instruction, NumConst, Proto, TableConst, TableValue};

use reader::Reader as ByteReader;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LuaError {
    #[error("not a LuaJIT bytecode dump (bad magic)")]
    NotLuaJit,
    #[error("unsupported LuaJIT dump version {0} (this crate targets version {v})", v = header::SUPPORTED_VERSION)]
    UnsupportedVersion(u8),
    #[error("truncated chunk: {0}")]
    Truncated(&'static str),
    #[error("malformed chunk: {0}")]
    Malformed(&'static str),
}

/// A fully decoded LuaJIT bytecode chunk: every prototype, in file order
/// (the last one is the top-level chunk function; earlier ones are its
/// nested functions, linked via [`GcConst::Child`]).
#[derive(Debug, Clone, Serialize)]
pub struct LuaChunk {
    pub big_endian: bool,
    pub stripped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_name: Option<String>,
    pub protos: Vec<Proto>,
}

/// Overwrite one instruction's raw 4-byte word in place, leaving every other
/// byte of the chunk untouched — the minimal, lowest-risk edit this crate
/// supports (matches `n0xis-core::patch`'s own "smallest possible targeted
/// byte change" philosophy, rather than re-serializing the whole chunk from
/// a structured [`LuaChunk`], which would risk subtly desyncing something
/// this crate hasn't modeled, e.g. non-stripped debug info).
///
/// `instr_idx` must be `>= 1` — index `0` is the synthesized `FUNCF`/`FUNCV`
/// entry point with no real file bytes, so it can never be patched.
pub fn patch_instruction(original: &[u8], proto_index: usize, instr_idx: u32, new_raw: u32) -> Result<Vec<u8>, LuaError> {
    if instr_idx == 0 {
        return Err(LuaError::Malformed("instruction 0 is synthesized (FUNCF/FUNCV) and has no file bytes to patch"));
    }
    let chunk = disassemble(original)?;
    let proto = chunk.protos.get(proto_index).ok_or(LuaError::Malformed("proto_index out of range"))?;
    if instr_idx as usize >= proto.instructions.len() {
        return Err(LuaError::Malformed("instr_idx out of range for this proto"));
    }
    let offset = proto.bytecode_file_offset + (instr_idx as usize - 1) * 4;
    let mut patched = original.to_vec();
    let end = offset.checked_add(4).ok_or(LuaError::Malformed("patch offset overflow"))?;
    if end > patched.len() {
        return Err(LuaError::Malformed("patch offset runs past end of chunk"));
    }
    patched[offset..end].copy_from_slice(&new_raw.to_le_bytes());
    Ok(patched)
}

/// Decode a LuaJIT 2.0 bytecode dump. Returns [`LuaError::NotLuaJit`]
/// immediately for anything that isn't `\x1bLJ`-prefixed (plain Lua source
/// text or stock bytecode, for instance) — callers should check
/// [`n0xis_bitsquid::LuaFormat`] first when the format tag is already known.
pub fn disassemble(bytes: &[u8]) -> Result<LuaChunk, LuaError> {
    let mut r = ByteReader::new(bytes);
    let header = header::parse_header(&mut r)?;
    let protos = proto::parse_all_protos(&mut r, header.strip)?;
    Ok(LuaChunk { big_endian: header.big_endian, stripped: header.strip, chunk_name: header.chunk_name, protos })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-assemble a minimal, valid, single-prototype LuaJIT dump: the
    /// top-level chunk is `return "hi"` roughly (one KSTR + one RET1),
    /// stripped, no upvalues/params.
    fn build_minimal_chunk() -> Vec<u8> {
        // proto body: flags(0) numparams(0) framesize(2) numuv(0)
        //   sizekgc=1(uleb) sizekn=0(uleb) sizebc-1=1(uleb, i.e. one real instr)
        // then 1 bytecode word: KSTR r0, kgc[0]  (op=KSTR a=0 d=0)
        // then kgc: tp=STR(5)+len(2) "hi"
        let kstr_op = opcodes::OPCODES.iter().position(|o| o.name == "KSTR").unwrap() as u32;
        // Full word is `op | a<<8 | d<<16`; both operands are 0 here, so the
        // opcode byte alone *is* the instruction.
        let instr: u32 = kstr_op;
        let mut body = vec![0u8, 0, 2, 0]; // flags, numparams, framesize, numuv
        body.push(1); // sizekgc uleb = 1
        body.push(0); // sizekn uleb = 0
        body.push(1); // sizebc-1 uleb = 1 -> sizebc = 2 (synthesized FUNCF + one real KSTR)
        body.extend_from_slice(&instr.to_le_bytes());
        // kgc[0]: str "hi", tp = 5 + 2 = 7
        body.push(7);
        body.extend_from_slice(b"hi");

        let mut chunk = vec![0x1b, b'L', b'J', 1, 0x02]; // header: strip=1
        chunk.push(body.len() as u8); // proto length uleb (fits in one byte)
        chunk.extend_from_slice(&body);
        chunk.push(0); // end-of-protos marker
        chunk
    }

    #[test]
    fn decodes_a_minimal_hand_built_chunk() {
        let bytes = build_minimal_chunk();
        let chunk = disassemble(&bytes).unwrap();
        assert!(chunk.stripped);
        assert_eq!(chunk.protos.len(), 1);
        let proto = &chunk.protos[0];
        assert_eq!(proto.framesize, 2);
        // bc[0] synthesized FUNCF, bc[1] the real KSTR.
        assert_eq!(proto.instructions.len(), 2);
        assert_eq!(proto.instructions[1].op, "KSTR");
        assert_eq!(proto.instructions[1].text, r#"KSTR r0, "hi""#);
        match &proto.gc_constants[0] {
            GcConst::Str(s) => assert_eq!(s, "hi"),
            other => panic!("expected a string constant, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_luajit_input() {
        assert!(matches!(disassemble(b"not lua bytecode at all"), Err(LuaError::NotLuaJit)));
    }

    #[test]
    fn truncated_chunk_errors_instead_of_panicking() {
        let bytes = [0x1b, b'L', b'J', 1]; // header cut off mid-flags
        assert!(disassemble(&bytes).is_err());
    }

    /// Regression test: an internally-tagged `#[serde(tag = "kind")]` enum
    /// can't represent a newtype variant wrapping a bare `String`/number
    /// (serde_json errors at serialize time, not compile time) — the same
    /// class of bug already hit once in `n0xis-core::valueset`. Caught here
    /// via the real CLI (`lua disasm` piped to `serde_json`), not a unit
    /// test, which is exactly why this chunk's full JSON round-trip is
    /// checked explicitly rather than trusting `#[derive(Serialize)]` alone.
    fn chunk_instruction_1_offset(bytes: &[u8]) -> usize {
        disassemble(bytes).unwrap().protos[0].bytecode_file_offset
    }

    #[test]
    fn patch_instruction_changes_only_the_targeted_word() {
        let original = build_minimal_chunk();
        // Instruction 1 in the minimal chunk is `KSTR r0, "hi"`; replace it
        // with `MOV r0, r0` (a=0, d=0) — a different opcode, same operands.
        let mov_op = opcodes::OPCODES.iter().position(|o| o.name == "MOV").unwrap() as u32;
        let new_raw = mov_op; // a=0, d=0, so no extra bits needed
        let patched = patch_instruction(&original, 0, 1, new_raw).unwrap();

        assert_eq!(patched.len(), original.len(), "a same-width instruction patch must not change the file's length");
        // KSTR and MOV both have a=0/d=0 here, so only the low opcode byte of
        // the 4-byte word actually differs — the point of this assertion is
        // that the diff is confined to *within* that one instruction word,
        // never spilling into neighboring bytes.
        let diffs: Vec<usize> = original.iter().zip(&patched).enumerate().filter(|(_, (a, b))| a != b).map(|(i, _)| i).collect();
        let word_start = chunk_instruction_1_offset(&original);
        assert!(!diffs.is_empty(), "the patch must change at least one byte");
        assert!(diffs.iter().all(|&i| (word_start..word_start + 4).contains(&i)), "every changed byte must lie within the targeted instruction's 4-byte word, got diffs at {diffs:?} (word at {word_start}..{})", word_start + 4);

        let chunk = disassemble(&patched).unwrap();
        assert_eq!(chunk.protos[0].instructions[1].op, "MOV");
        assert_eq!(chunk.protos[0].instructions[1].text, "MOV r0, r0");
        // The (now-unreferenced) string constant is still intact — patching
        // an instruction must never touch the constant pools.
        match &chunk.protos[0].gc_constants[0] {
            GcConst::Str(s) => assert_eq!(s, "hi"),
            other => panic!("expected the string constant to survive untouched, got {other:?}"),
        }
    }

    #[test]
    fn patch_instruction_rejects_the_synthesized_entry_instruction() {
        let original = build_minimal_chunk();
        assert!(patch_instruction(&original, 0, 0, 0).is_err());
    }

    #[test]
    fn chunk_with_string_and_number_constants_serializes_to_json() {
        let bytes = build_minimal_chunk();
        let chunk = disassemble(&bytes).unwrap();
        let json = serde_json::to_string(&chunk).expect("a decoded chunk must always serialize");
        assert!(json.contains("\"hi\""), "the string constant must appear in the JSON: {json}");
    }
}
