// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A tiny bounds-checked byte-slice reader shared by [`crate::archive`] and
//! [`crate::package`] — every read either returns exactly what was asked for
//! or an error; nothing here ever panics or silently substitutes a placeholder
//! for a short/malformed input (the same discipline `n0xis-sources::unwind`'s
//! `Cursor`/`MemReader` holds for cross-process reads).

pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// Read-past-the-end marker; callers convert this to a [`BitsquidError`] with
/// whatever field name they were reading, so the error message stays specific.
pub struct CursorError;

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], CursorError> {
        let end = self.pos.checked_add(n).ok_or(CursorError)?;
        if end > self.buf.len() {
            return Err(CursorError);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn skip(&mut self, n: usize) -> Result<(), CursorError> {
        self.take(n).map(|_| ())
    }

    pub fn u32(&mut self) -> Result<u32, CursorError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64, CursorError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

/// Labels a [`CursorError`] with the field being read, turning it into a
/// [`crate::BitsquidError::Truncated`] whose message says what went missing.
pub trait Field<T> {
    fn field(self, name: &'static str) -> Result<T, crate::BitsquidError>;
}

impl<T> Field<T> for Result<T, CursorError> {
    fn field(self, name: &'static str) -> Result<T, crate::BitsquidError> {
        self.map_err(|_| crate::BitsquidError::Truncated(name))
    }
}
