// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The one way bytes are read: a cursor over the whole file with a limit, so
//! every position it reports is an offset into the file and nothing can read
//! past the limit it was given.
//!
//! LEB128 follows the format's own bound (binary format, "Integers"): an
//! `N`-bit integer takes at most `ceil(N / 7)` bytes, and in the last of them
//! the bits beyond `N` must be zero (unsigned) or copies of the sign bit
//! (signed). Padding up to that length is allowed and real: the linker pads
//! every relocated index to five bytes, so `0x80 0x80 0x80 0x80 0x00` is a
//! well-formed zero and must read as one.

use crate::error::{Error, Problem};

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0, end: bytes.len() }
    }

    /// A reader over `range` of the same file. The caller has checked that
    /// `range` lies inside it; nothing is read if it does not.
    pub(crate) fn over(bytes: &'a [u8], range: std::ops::Range<usize>) -> Self {
        let end = range.end.min(bytes.len());
        Reader { bytes, pos: range.start.min(end), end }
    }

    pub(crate) fn offset(&self) -> usize {
        self.pos
    }

    pub(crate) fn end(&self) -> usize {
        self.end
    }

    pub(crate) fn remaining(&self) -> usize {
        self.end - self.pos
    }

    pub(crate) fn at_end(&self) -> bool {
        self.pos == self.end
    }

    pub(crate) fn error(&self, offset: usize, problem: Problem) -> Error {
        Error::Unreadable { offset, problem }
    }

    fn short(&self, needed: usize) -> Error {
        Error::Unreadable { offset: self.pos, problem: Problem::End { needed, available: self.remaining() } }
    }

    pub(crate) fn byte(&mut self) -> Result<u8, Error> {
        if self.pos >= self.end {
            return Err(self.short(1));
        }
        let b = self.bytes[self.pos];
        self.pos += 1;
        Ok(b)
    }

    pub(crate) fn peek(&self) -> Result<u8, Error> {
        if self.pos >= self.end {
            return Err(self.short(1));
        }
        Ok(self.bytes[self.pos])
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.remaining() {
            return Err(self.short(n));
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// The next `len` bytes as a reader of their own; this one moves past them.
    pub(crate) fn sub(&mut self, len: usize) -> Result<Reader<'a>, Error> {
        if len > self.remaining() {
            return Err(self.short(len));
        }
        let sub = Reader { bytes: self.bytes, pos: self.pos, end: self.pos + len };
        self.pos += len;
        Ok(sub)
    }

    /// An unsigned LEB128 of at most `bits` bits.
    fn unsigned(&mut self, bits: u32) -> Result<u64, Error> {
        let start = self.pos;
        let max_bytes = bits.div_ceil(7);
        // How many bits of the value the last permitted byte may carry.
        let last_bits = bits - 7 * (max_bytes - 1);
        let mut value: u64 = 0;
        for i in 0..max_bytes {
            let b = self.byte()?;
            let payload = u64::from(b & 0x7f);
            if i == max_bytes - 1 {
                if b & 0x80 != 0 {
                    return Err(self.error(start, Problem::LebTooLong { bits }));
                }
                if payload >> last_bits != 0 {
                    return Err(self.error(start, Problem::LebTooBig { bits }));
                }
            }
            value |= payload << (7 * i);
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        // The last permitted byte either ended the number or was refused.
        Err(self.error(start, Problem::LebTooLong { bits }))
    }

    /// A signed LEB128 of at most `bits` bits, sign-extended to 64.
    fn signed(&mut self, bits: u32) -> Result<i64, Error> {
        let start = self.pos;
        let max_bytes = bits.div_ceil(7);
        let last_bits = bits - 7 * (max_bytes - 1);
        let mut value: u64 = 0;
        for i in 0..max_bytes {
            let b = self.byte()?;
            let payload = u64::from(b & 0x7f);
            if i == max_bytes - 1 {
                if b & 0x80 != 0 {
                    return Err(self.error(start, Problem::LebTooLong { bits }));
                }
                // The sign bit and every unused bit above it must agree.
                let upper = payload >> (last_bits - 1);
                let all_ones = (1u64 << (8 - last_bits)) - 1;
                if upper != 0 && upper != all_ones {
                    return Err(self.error(start, Problem::LebTooBig { bits }));
                }
            }
            let shift = 7 * i;
            value |= payload << shift;
            if b & 0x80 == 0 {
                let used = shift + 7;
                if used < 64 && payload & 0x40 != 0 {
                    value |= u64::MAX << used;
                }
                return Ok(value as i64);
            }
        }
        Err(self.error(start, Problem::LebTooLong { bits }))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        // At most 32 bits by the check above.
        Ok(self.unsigned(32)? as u32)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        self.unsigned(64)
    }

    pub(crate) fn s32(&mut self) -> Result<i32, Error> {
        Ok(self.signed(32)? as i32)
    }

    pub(crate) fn s33(&mut self) -> Result<i64, Error> {
        self.signed(33)
    }

    pub(crate) fn s64(&mut self) -> Result<i64, Error> {
        self.signed(64)
    }

    /// A count of entries that each take at least `min_entry_bytes`: refused
    /// at once when the bytes left cannot hold that many, so no loop runs on
    /// a count the file merely claims.
    pub(crate) fn count(&mut self, min_entry_bytes: usize) -> Result<u32, Error> {
        let at = self.pos;
        let n = self.u32()?;
        let needed = (n as usize).saturating_mul(min_entry_bytes);
        if needed > self.remaining() {
            return Err(self.error(at, Problem::CountTooLarge { count: n, available: self.remaining() }));
        }
        Ok(n)
    }

    /// A `name`: a length, then that many bytes of UTF-8.
    pub(crate) fn name(&mut self) -> Result<String, Error> {
        let len = self.u32()? as usize;
        let at = self.pos;
        let bytes = self.take(len)?;
        match std::str::from_utf8(bytes) {
            Ok(s) => Ok(s.to_string()),
            Err(_) => Err(self.error(at, Problem::Utf8)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Reader;
    use crate::error::{Error, Problem};

    fn problem<T: std::fmt::Debug>(r: Result<T, Error>) -> Problem {
        match r {
            Err(Error::Unreadable { problem, .. }) => problem,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    // Values worked by hand from the rule in the binary format's "Integers"
    // section; the oracle test asks wasm-tools the same questions.
    #[test]
    fn unsigned_32_reads_padding_and_refuses_what_the_format_refuses() {
        let read = |b: &[u8]| Reader::new(b).u32();
        assert_eq!(read(&[0x00]).unwrap(), 0);
        assert_eq!(read(&[0xe5, 0x8e, 0x26]).unwrap(), 624_485);
        assert_eq!(read(&[0x80, 0x80, 0x80, 0x80, 0x00]).unwrap(), 0, "padded to the full five bytes");
        assert_eq!(read(&[0xff, 0xff, 0xff, 0xff, 0x0f]).unwrap(), u32::MAX);
        assert_eq!(problem(read(&[0xff, 0xff, 0xff, 0xff, 0x1f])), Problem::LebTooBig { bits: 32 });
        assert_eq!(problem(read(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00])), Problem::LebTooLong { bits: 32 });
        assert!(matches!(problem(read(&[0x80, 0x80])), Problem::End { .. }));
    }

    #[test]
    fn signed_32_needs_its_unused_bits_to_copy_the_sign() {
        let read = |b: &[u8]| Reader::new(b).s32();
        assert_eq!(read(&[0x7f]).unwrap(), -1);
        assert_eq!(read(&[0x3f]).unwrap(), 63);
        assert_eq!(read(&[0x40]).unwrap(), -64);
        assert_eq!(read(&[0xc0, 0x00]).unwrap(), 64);
        assert_eq!(read(&[0xff, 0xff, 0xff, 0xff, 0x07]).unwrap(), i32::MAX);
        assert_eq!(read(&[0x80, 0x80, 0x80, 0x80, 0x78]).unwrap(), i32::MIN);
        assert_eq!(read(&[0xff, 0xff, 0xff, 0xff, 0x7f]).unwrap(), -1, "-1 padded to five bytes");
        // Bit 31 says positive, bit 32 says negative.
        assert_eq!(problem(read(&[0xff, 0xff, 0xff, 0xff, 0x0f])), Problem::LebTooBig { bits: 32 });
        assert_eq!(problem(read(&[0x80, 0x80, 0x80, 0x80, 0x70])), Problem::LebTooBig { bits: 32 });
        assert_eq!(problem(read(&[0xff, 0xff, 0xff, 0xff, 0xff, 0x7f])), Problem::LebTooLong { bits: 32 });
    }

    #[test]
    fn signed_33_and_64_bounds() {
        assert_eq!(Reader::new(&[0xff, 0xff, 0xff, 0xff, 0x0f]).s33().unwrap(), 0xffff_ffff);
        assert_eq!(Reader::new(&[0x80, 0x80, 0x80, 0x80, 0x70]).s33().unwrap(), -(1i64 << 32));
        assert_eq!(problem(Reader::new(&[0x80, 0x80, 0x80, 0x80, 0x10]).s33()), Problem::LebTooBig { bits: 33 });
        let max = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];
        assert_eq!(Reader::new(&max).s64().unwrap(), i64::MAX);
        let min = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f];
        assert_eq!(Reader::new(&min).s64().unwrap(), i64::MIN);
        let bad = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
        assert_eq!(problem(Reader::new(&bad).s64()), Problem::LebTooBig { bits: 64 });
        let all = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        assert_eq!(Reader::new(&all).u64().unwrap(), u64::MAX);
        let over = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert_eq!(problem(Reader::new(&over).u64()), Problem::LebTooBig { bits: 64 });
    }

    #[test]
    fn a_count_the_bytes_cannot_hold_is_refused_before_any_loop() {
        // Claims 2^32 - 1 entries with three bytes left.
        let mut r = Reader::new(&[0xff, 0xff, 0xff, 0xff, 0x0f, 1, 2, 3]);
        assert_eq!(problem(r.count(1)), Problem::CountTooLarge { count: u32::MAX, available: 3 });
        let mut r = Reader::new(&[0x03, 1, 2, 3]);
        assert_eq!(r.count(1).unwrap(), 3);
    }
}
