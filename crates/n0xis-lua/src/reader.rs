// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A bounds-checked byte reader with LuaJIT's two ULEB128 flavors. Every read
//! returns `Result`, never panics on a short/malformed chunk — the same
//! discipline as `n0xis-sources::unwind`'s `Cursor` and
//! `n0xis-bitsquid::Cursor`.

use crate::LuaError;

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], LuaError> {
        let end = self.pos.checked_add(n).ok_or(LuaError::Truncated("length overflow"))?;
        if end > self.buf.len() {
            return Err(LuaError::Truncated("unexpected end of chunk"));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn byte(&mut self) -> Result<u8, LuaError> {
        Ok(self.take(1)?[0])
    }

    /// Peek the next byte without consuming it (used to check for the
    /// single-`0x00`-byte end-of-prototypes marker).
    pub fn peek_byte(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Standard ULEB128 (`lj_bcread.c: bcread_uleb128`): 7 payload bits per
    /// byte, continue while the high bit is set.
    pub fn uleb128(&mut self) -> Result<u32, LuaError> {
        let mut v = self.byte()? as u32;
        if v >= 0x80 {
            let mut sh = 0u32;
            v &= 0x7f;
            loop {
                let b = self.byte()?;
                sh += 7;
                v |= ((b & 0x7f) as u32) << sh;
                if b < 0x80 {
                    break;
                }
            }
        }
        Ok(v)
    }

    /// LuaJIT's packed "33-bit" encoding used only for number constants
    /// (`lj_bcread.c: bcread_uleb128_33`): the low bit of the first byte is a
    /// separate `is_num` tag, and the remaining bits are a normal ULEB128
    /// payload shifted right by one. Returns `(value, is_num)`.
    pub fn uleb128_33(&mut self) -> Result<(u32, bool), LuaError> {
        let b0 = self.byte()?;
        let is_num = (b0 & 1) != 0;
        let mut v = (b0 >> 1) as u32;
        if v >= 0x40 {
            let mut sh = -1i32;
            v &= 0x3f;
            loop {
                let b = self.byte()?;
                sh += 7;
                v |= ((b & 0x7f) as u32) << sh;
                if b < 0x80 {
                    break;
                }
            }
        }
        Ok((v, is_num))
    }

    pub fn u16le(&mut self) -> Result<u16, LuaError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub fn u32le(&mut self) -> Result<u32, LuaError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
}
