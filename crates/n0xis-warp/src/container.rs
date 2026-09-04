// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Reading the WARP `.warp` container (feature `container`).
//!
//! A `.warp` file is a FlatBuffers `File → [Chunk]`; a signature chunk's payload
//! is itself a FlatBuffers `SignatureChunk → [Function]`, optionally
//! zlib-compressed. This module hand-parses exactly the slice of that schema
//! needed to recover the **`(function GUID, symbol name)`** table — the interop
//! payload — with strict bounds checks so a malformed file yields `None`, never
//! a panic or an over-large allocation (per the project's OOM-safety rule: never
//! trust a length read from parsed bytes).
//!
//! Only `flate2` (already in the workspace tree) is pulled in, and only behind
//! this feature, so the crate's core GUID math stays dependency-free.
//!
//! Verified against Vector 35's reference `warp` crate: reading their
//! `random.warp` fixture reproduces its `dumper` output `(name | guid)` exactly.

use crate::format_guid;
use std::io::Read;

/// One function entry recovered from a WARP file: its structural GUID and the
/// symbol name to apply when that GUID matches a target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WarpFunction {
    /// Canonical lowercase UUID string of the function GUID.
    pub guid: String,
    /// The symbol name, if the entry carries one.
    pub name: Option<String>,
}

/// The FlatBuffers `ChunkType` enum — only `Signatures` carries functions.
const CHUNK_TYPE_SIGNATURES: u8 = 0;
/// `CompressionType`: `None` is verbatim; the `Zstd` variant is, despite its
/// name, zlib in the reference implementation (it uses `flate2`).
const COMPRESSION_NONE: u8 = 0;

/// Parse a `.warp` file's bytes into its function table. `None` on any malformed
/// structure. Chunks that are not signature chunks (e.g. type chunks) are
/// skipped; a file with none yields an empty vector.
pub fn read_warp(bytes: &[u8]) -> Option<Vec<WarpFunction>> {
    let fb = Fb::new(bytes);
    let file = fb.root()?; // table File
    let mut out = Vec::new();
    // File.chunks is field 1 (field 0 is header).
    if let Some(chunks) = fb.field(file, 1) {
        let (elems, len) = fb.vector(chunks)?;
        for i in 0..len {
            let chunk = fb.indirect(elems.checked_add(i.checked_mul(4)?)?)?; // vector of table offsets
            read_chunk(&fb, chunk, &mut out)?;
        }
    }
    Some(out)
}

fn read_chunk(fb: &Fb, chunk: usize, out: &mut Vec<WarpFunction>) -> Option<()> {
    // Chunk { header:ChunkHeader (0), data:[ubyte] (1) }
    let header = fb.field(chunk, 0).and_then(|p| fb.indirect(p))?;
    // ChunkHeader { version(0), type(1), compression_type(2), size(3), target(4) }
    let chunk_type = fb.field(header, 1).map(|p| fb.u8(p)).unwrap_or(CHUNK_TYPE_SIGNATURES);
    if chunk_type != CHUNK_TYPE_SIGNATURES {
        return Some(()); // not a signature chunk — nothing to name
    }
    let compression = fb.field(header, 2).map(|p| fb.u8(p)).unwrap_or(COMPRESSION_NONE);
    let declared_size = fb.field(header, 3).map(|p| fb.u32(p)).unwrap_or(0) as usize;

    let data = fb.field(chunk, 1)?;
    let (dstart, dlen) = fb.vector(data)?;
    let raw = fb.slice(dstart, dlen)?;

    let decompressed = if compression == COMPRESSION_NONE {
        raw.to_vec()
    } else {
        // zlib inflate. Cap the pre-allocation at the header's declared size (and
        // a sane ceiling) so a bogus `size` cannot drive an over-large alloc.
        let cap = declared_size.min(64 * 1024 * 1024);
        let mut dec = flate2::read::ZlibDecoder::new(raw);
        let mut buf = Vec::with_capacity(cap);
        dec.read_to_end(&mut buf).ok()?;
        buf
    };

    let inner = Fb::new(&decompressed);
    let sc = inner.root()?; // table SignatureChunk
    // SignatureChunk { functions:[Function] (0) }
    let functions = inner.field(sc, 0)?;
    let (felems, flen) = inner.vector(functions)?;
    for i in 0..flen {
        let func = inner.indirect(felems.checked_add(i.checked_mul(4)?)?)?;
        // Function { guid:FunctionGUID struct (0), symbol:Symbol (1), ... }
        let guid_pos = inner.field(func, 0)?; // struct is inline at the field position
        let guid_bytes = inner.slice(guid_pos, 16)?;
        let mut g = [0u8; 16];
        g.copy_from_slice(guid_bytes);
        let name = inner
            .field(func, 1)
            .and_then(|p| inner.indirect(p))
            .and_then(|sym| inner.field(sym, 0)) // Symbol.name (0)
            .and_then(|p| inner.string(p));
        out.push(WarpFunction { guid: format_guid(&g), name });
    }
    Some(())
}

/// A minimal, bounds-checked FlatBuffers reader over a byte buffer. Every
/// accessor validates against the buffer length and returns `None` past the end,
/// so untrusted input cannot index out of range or allocate on a bogus length.
struct Fb<'a> {
    buf: &'a [u8],
}

impl<'a> Fb<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Fb { buf }
    }

    fn u8(&self, pos: usize) -> u8 {
        self.buf.get(pos).copied().unwrap_or(0)
    }

    fn u16(&self, pos: usize) -> u16 {
        let b = self.buf.get(pos..pos + 2);
        b.map(|b| u16::from_le_bytes([b[0], b[1]])).unwrap_or(0)
    }

    fn u32(&self, pos: usize) -> u32 {
        let b = self.buf.get(pos..pos + 4);
        b.map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).unwrap_or(0)
    }

    fn i32(&self, pos: usize) -> i32 {
        self.u32(pos) as i32
    }

    /// Follow a `uoffset` (relative, forward) at `pos` to its absolute target.
    fn indirect(&self, pos: usize) -> Option<usize> {
        let off = self.u32(pos) as usize;
        let target = pos.checked_add(off)?;
        (target < self.buf.len()).then_some(target)
    }

    /// The root table offset lives at buffer start.
    fn root(&self) -> Option<usize> {
        self.indirect(0)
    }

    /// Absolute position of table `field_index`'s value, or `None` when the
    /// field is absent (vtable slot 0) or out of the vtable's range.
    fn field(&self, table_pos: usize, field_index: usize) -> Option<usize> {
        let soffset = self.i32(table_pos);
        // vtable sits *before* the table by `soffset` (which may be signed).
        let vtable = (table_pos as i64).checked_sub(soffset as i64)?;
        if vtable < 0 {
            return None;
        }
        let vtable = vtable as usize;
        let vtable_len = self.u16(vtable) as usize;
        let slot = 4 + field_index * 2;
        if slot + 2 > vtable_len {
            return None;
        }
        let field_off = self.u16(vtable + slot) as usize;
        if field_off == 0 {
            return None;
        }
        let value = table_pos.checked_add(field_off)?;
        (value <= self.buf.len()).then_some(value)
    }

    /// A vector referenced by the uoffset at `pos`: `(elements_start, len)`. The
    /// length is validated to fit the buffer so it can never drive an oversized
    /// loop or allocation.
    fn vector(&self, pos: usize) -> Option<(usize, usize)> {
        let v = self.indirect(pos)?;
        let len = self.u32(v) as usize;
        let start = v.checked_add(4)?;
        // Every element is at least one byte, so a vector can never hold more
        // elements than the file has bytes. Rejecting a larger count caps the
        // per-element loop (each element is then bounds-checked on access), so a
        // bogus length cannot spin a billion-iteration loop.
        (start <= self.buf.len() && len <= self.buf.len()).then_some((start, len))
    }

    /// The `len` bytes at `pos`, or `None` if they run past the buffer.
    fn slice(&self, pos: usize, len: usize) -> Option<&'a [u8]> {
        self.buf.get(pos..pos.checked_add(len)?)
    }

    /// A UTF-8 string referenced by the uoffset at `pos`.
    fn string(&self, pos: usize) -> Option<String> {
        let s = self.indirect(pos)?;
        let len = self.u32(s) as usize;
        let bytes = self.slice(s.checked_add(4)?, len)?;
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}
