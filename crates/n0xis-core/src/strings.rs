// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Strings in an image's bytes: runs of printable text, read as UTF-8 or as
//! UTF-16LE, each with the address it starts at.
//!
//! In ASCII, "printable" is what binutils `strings` takes it to be (tab and
//! 0x20–0x7e), and line breaks besides: a C literal `"done\n"` is one string,
//! not a string and a break. Cut at its line breaks, a string is what binutils
//! reports, so the two can still be held against each other byte for byte. Past
//! ASCII, a UTF-8 character counts when it is one text carries (not a control
//! character, not private use, not a noncharacter), which is how text in other
//! scripts is found whole instead of as the ASCII fragments between its
//! letters. UTF-16 is read in fewer characters ([`utf16_text`]): almost any two
//! bytes of binary data are a character that prints.

use n0xis_contracts::Va;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StringEncoding {
    Utf8,
    Utf16le,
}

impl StringEncoding {
    pub fn name(self) -> &'static str {
        match self {
            Self::Utf8 => "utf8",
            Self::Utf16le => "utf16le",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundString {
    pub address: Va,
    pub encoding: StringEncoding,
    /// Characters in the string.
    pub length: usize,
    /// Bytes it takes in the image, without a terminator.
    pub size: usize,
    pub text: String,
}

/// Whether `c` belongs in a string: tab, a line break or printable ASCII, or a
/// character past ASCII that text carries.
fn printable(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || (' '..='~').contains(&c) || (!c.is_ascii() && !c.is_control() && !carried_by_no_text(c))
}

/// Private use, noncharacters and the specials block: code points that text
/// does not carry, and that binary data read as text does.
fn carried_by_no_text(c: char) -> bool {
    let c = c as u32;
    matches!(c, 0xe000..=0xf8ff | 0xfdd0..=0xfdef | 0xfff0..=0xffff | 0xf0000..) || c & 0xfffe == 0xfffe
}

/// The characters a UTF-16 string is read in: ASCII, the Latin, Greek and
/// Cyrillic letters, and common punctuation, currency, letterlike signs,
/// arrows and dingbats. With every printable character allowed, two bytes of
/// binary data almost always read as one: on one library 10 614 of 10 625
/// UTF-16 "strings" were runs of CJK and Hangul from hash tables and
/// relocations, where binutils, which reads only ASCII, found 11. So UTF-16
/// text in CJK and other scripts is not found.
fn utf16_text(c: char) -> bool {
    printable(c) && matches!(c as u32, 0x09 | 0x0a | 0x0d | 0x20..=0x7e | 0xa0..=0x24f | 0x370..=0x52f | 0x2010..=0x205e | 0x20a0..=0x20bf | 0x2100..=0x21ff | 0x2700..=0x27bf)
}

/// One UTF-8 character at the start of `b` and its length, if `b` starts with
/// a valid one. The standard library decides validity (overlong forms and
/// surrogates are not characters).
fn next_utf8(b: &[u8]) -> Option<(char, usize)> {
    let n = match *b.first()? {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return None,
    };
    let c = std::str::from_utf8(b.get(..n)?).ok()?.chars().next()?;
    Some((c, n))
}

/// A run being collected: where it starts, its text, and its length.
struct Run {
    start: usize,
    text: String,
    chars: usize,
}

impl Run {
    fn new() -> Self {
        Self { start: 0, text: String::new(), chars: 0 }
    }

    fn push(&mut self, at: usize, c: char) {
        if self.chars == 0 {
            self.start = at;
        }
        self.text.push(c);
        self.chars += 1;
    }

    /// End the run at byte `end`; keep it when it is long enough.
    fn end(&mut self, end: usize, base: Va, min: usize, encoding: StringEncoding, out: &mut Vec<FoundString>) {
        if self.chars >= min.max(1) {
            out.push(FoundString {
                address: Va(base.0 + self.start as u64),
                encoding,
                length: self.chars,
                size: end - self.start,
                text: std::mem::take(&mut self.text),
            });
        }
        self.text.clear();
        self.chars = 0;
    }
}

/// UTF-8 runs of at least `min` printable characters in `bytes`, which start
/// at `base`.
pub fn utf8_strings(bytes: &[u8], base: Va, min: usize) -> Vec<FoundString> {
    let mut out = Vec::new();
    let mut run = Run::new();
    let mut i = 0;
    while i < bytes.len() {
        match next_utf8(&bytes[i..]) {
            Some((c, n)) if printable(c) => {
                run.push(i, c);
                i += n;
            }
            _ => {
                run.end(i, base, min, StringEncoding::Utf8, &mut out);
                i += 1;
            }
        }
    }
    run.end(bytes.len(), base, min, StringEncoding::Utf8, &mut out);
    out
}

/// Whether a UTF-16 code unit is two characters of ASCII text: both bytes
/// printable ASCII, the high one not zero. Read two bytes at a time, ASCII text
/// is nothing but such units (`n0xis` turns into `の楸…`, or, in the scripts
/// UTF-16 is read in, into a `Ⅵ` glued to the start of a real wide string), so
/// they are never taken for a character. A wide string of ASCII characters has
/// every high byte zero and is unaffected; `…`, `•` and `™` are such units too,
/// and a wide string holding one is found in pieces.
fn ascii_pair(unit: u16) -> bool {
    let ascii_text = |b: u8| matches!(b, b'\t' | b'\n' | b'\r' | 0x20..=0x7e);
    let (lo, hi) = (unit as u8, (unit >> 8) as u8);
    hi != 0 && ascii_text(lo) && ascii_text(hi)
}

/// UTF-16LE runs of at least `min` printable characters in `bytes`, which
/// start at `base`. Read at even addresses only: compilers align wide strings
/// to two bytes, and read from an odd address an ASCII wide string turns into
/// a run of CJK characters that is not there. Two bytes of ASCII text are
/// never one character ([`ascii_pair`]).
pub fn utf16_strings(bytes: &[u8], base: Va, min: usize) -> Vec<FoundString> {
    let mut out = Vec::new();
    let mut run = Run::new();
    let unit = |i: usize| bytes.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let mut i = (base.0 % 2) as usize;
    while let Some(u) = unit(i) {
        let decoded = match u {
            0xd800..=0xdbff => match unit(i + 2) {
                Some(low @ 0xdc00..=0xdfff) => {
                    char::from_u32(0x10000 + ((u32::from(u) - 0xd800) << 10) + (u32::from(low) - 0xdc00)).map(|c| (c, 4))
                }
                _ => None,
            },
            0xdc00..=0xdfff => None,
            _ if ascii_pair(u) => None,
            _ => char::from_u32(u32::from(u)).map(|c| (c, 2)),
        };
        match decoded {
            Some((c, n)) if utf16_text(c) => {
                run.push(i, c);
                i += n;
            }
            _ => {
                run.end(i, base, min, StringEncoding::Utf16le, &mut out);
                i += 2;
            }
        }
    }
    run.end(i.min(bytes.len()), base, min, StringEncoding::Utf16le, &mut out);
    out
}

/// Every string of at least `min` characters in `bytes` (which start at
/// `base`) in the encodings asked for, in address order.
pub fn find_strings(bytes: &[u8], base: Va, min: usize, encodings: &[StringEncoding]) -> Vec<FoundString> {
    let mut out = Vec::new();
    if encodings.contains(&StringEncoding::Utf8) {
        out.extend(utf8_strings(bytes, base, min));
    }
    if encodings.contains(&StringEncoding::Utf16le) {
        out.extend(utf16_strings(bytes, base, min));
    }
    out.sort_by_key(|s| (s.address.0, s.encoding.name()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(found: &[FoundString]) -> Vec<(u64, &str, usize, usize)> {
        found.iter().map(|s| (s.address.0, s.text.as_str(), s.length, s.size)).collect()
    }

    #[test]
    fn ascii_runs_end_where_binutils_ends_them() {
        // A tab belongs; BEL, DEL and NUL end a run; three characters are too few.
        let bytes = b"\x00ab\tcd\x07wxyz\x7fabc\x00long enough\x00";
        let found = utf8_strings(bytes, Va(0x1000), 4);
        assert_eq!(texts(&found), [(0x1001, "ab\tcd", 5, 5), (0x1007, "wxyz", 4, 4), (0x1010, "long enough", 11, 11)]);
    }

    #[test]
    fn line_breaks_belong_to_the_string() {
        let found = find_strings(b"\0usage: x\n  -f\tforce\r\n\0", Va(0), 4, &[StringEncoding::Utf8]);
        assert_eq!(texts(&found), [(1, "usage: x\n  -f\tforce\r\n", 21, 21)]);
    }

    #[test]
    fn text_in_another_script_is_one_string() {
        let mut bytes = b"\x00".to_vec();
        bytes.extend("Привіт, світ".as_bytes());
        bytes.push(0);
        let found = utf8_strings(&bytes, Va(0x20), 4);
        assert_eq!(texts(&found), [(0x21, "Привіт, світ", 12, 22)]);
    }

    #[test]
    fn an_invalid_sequence_ends_a_run_and_is_not_taken_for_text() {
        // 0xc0 0xaf is an overlong '/', 0xed 0xa0 0x80 a surrogate: neither is a character.
        let bytes = b"abcd\xc0\xafefgh\xed\xa0\x80ijkl";
        let found = utf8_strings(bytes, Va(0), 4);
        assert_eq!(texts(&found), [(0, "abcd", 4, 4), (6, "efgh", 4, 4), (13, "ijkl", 4, 4)]);
    }

    #[test]
    fn wide_strings_are_read_at_even_addresses() {
        let mut bytes: Vec<u8> = vec![0, 0];
        bytes.extend("Wide ✓ — «текст»".encode_utf16().flat_map(u16::to_le_bytes));
        bytes.extend([0, 0]);
        let found = utf16_strings(&bytes, Va(0x400), 4);
        assert_eq!(texts(&found), [(0x402, "Wide ✓ — «текст»", 16, 32)]);
        // The same bytes one address higher: the string now sits at an odd
        // address, and the even-address reading does not invent another one.
        let shifted = utf16_strings(&bytes, Va(0x401), 4);
        assert!(shifted.iter().all(|s| s.address.0 % 2 == 0), "{shifted:?}");
        assert!(shifted.iter().all(|s| !s.text.contains("Wide")), "{shifted:?}");
    }

    #[test]
    fn a_wide_ascii_string_is_not_also_reported_as_narrow() {
        let bytes: Vec<u8> = "Settings\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let found = find_strings(&bytes, Va(0x10), 4, &[StringEncoding::Utf8, StringEncoding::Utf16le]);
        assert_eq!(texts(&found), [(0x10, "Settings", 8, 16)]);
        assert_eq!(found[0].encoding, StringEncoding::Utf16le);
    }

    #[test]
    fn ascii_text_is_not_read_again_as_utf16() {
        // Planted as a C compiler lays out string literals: NUL after each.
        let bytes = b"\0\0n0xis-planted-ascii-7f3a\0abcd\0efgh\0";
        let found = find_strings(bytes, Va(0x2000), 4, &[StringEncoding::Utf8, StringEncoding::Utf16le]);
        assert!(found.iter().all(|s| s.encoding == StringEncoding::Utf8), "{found:?}");
        assert_eq!(texts(&found), [(0x2002, "n0xis-planted-ascii-7f3a", 24, 24), (0x201b, "abcd", 4, 4), (0x2020, "efgh", 4, 4)]);
        // Pairs that land in a script UTF-16 is read in: `& ` is U+2026, `…`.
        let found = find_strings(b"& & & & \0\0", Va(0x10), 4, &[StringEncoding::Utf8, StringEncoding::Utf16le]);
        assert_eq!(texts(&found), [(0x10, "& & & & ", 8, 8)]);
        assert_eq!(found[0].encoding, StringEncoding::Utf8);
    }

    #[test]
    fn a_wide_string_right_after_ascii_text_is_found_whole() {
        // Measured on a real DLL: ASCII text ending `rvice!\n`, a NUL, then a
        // wide string. The pair `e!` reads as U+2165, a character UTF-16 is read
        // in, and once took the wide string down with it.
        let mut bytes = b"rvice!\n\0".to_vec();
        bytes.extend("WineDdeServerName\0".encode_utf16().flat_map(u16::to_le_bytes));
        let found = utf16_strings(&bytes, Va(0x1800a5128), 4);
        assert_eq!(texts(&found), [(0x1800a512e, "\nWineDdeServerName", 18, 36)]);
    }

    #[test]
    fn wide_text_is_read_in_the_latin_greek_and_cyrillic_scripts_only() {
        let bytes: Vec<u8> = "中文字符串测试\0Привіт\0Ελλάδα\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let found = utf16_strings(&bytes, Va(0), 4);
        assert_eq!(texts(&found), [(16, "Привіт", 6, 12), (30, "Ελλάδα", 6, 12)]);
    }

    #[test]
    fn utf8_from_another_reading_of_binary_data_is_not_text() {
        // UTF-8 Cyrillic read as UTF-16 is CJK; private use and noncharacters
        // are not text in either encoding.
        let bytes = "Привіт, n0xis".as_bytes();
        assert!(utf16_strings(bytes, Va(0), 4).is_empty());
        let odd: Vec<u8> = [0xe339u16, 0xfffe, 0xffff, 0xe000].iter().flat_map(|u| u.to_le_bytes()).collect();
        assert!(utf16_strings(&odd, Va(0), 2).is_empty());
        assert!(utf8_strings("ab\u{e339}\u{fdd0}cd".as_bytes(), Va(0), 3).is_empty());
    }

    #[test]
    fn a_run_at_the_end_of_the_bytes_is_kept() {
        let found = utf8_strings(b"\x00tail", Va(0), 4);
        assert_eq!(texts(&found), [(1, "tail", 4, 4)]);
    }
}
