// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Argument parsing every frontend needs: addresses, sizes, and hex byte
//! strings. Acceptance is defined here once, so `--size 0x1000` on the CLI and
//! `"size": "0x1000"` through MCP can never disagree about what they take.

use n0xis_contracts::{NumberLiteral, Va};

/// Parse an optional hex/decimal address argument into a [`Va`].
pub fn opt_hex(s: &Option<String>) -> Result<Option<Va>, String> {
    s.as_deref().map(Va::parse).transpose().map_err(|e| e.to_string())
}

/// Split `"0x…"`/`"0X…"`/`"…h"`/`"…H"` off a hex-formatted number, same
/// acceptance as [`Va::parse`]; returns the bare digits, or `None` for a plain
/// decimal string.
pub fn strip_hex_marker(t: &str) -> Option<&str> {
    t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).or_else(|| t.strip_suffix('h').or_else(|| t.strip_suffix('H')))
}

/// Value parser for byte-count-like `usize` fields (`--size`, `--max-bytes`,
/// `--len`, `--cave-size`, …): accepts hex (`0x1000`) or decimal, the same
/// acceptance `--addr`/`--start` get via [`Va::parse`]. Sizes read off a PE
/// section header or a `dump`/`scan` report are routinely in hex; forcing a
/// hand conversion is the ergonomics gap RE_METHOD F7 called out for
/// `--min`/`--max` ("burned two scan rounds on a range that wasn't even
/// close").
pub fn parse_hex_or_decimal_usize(s: &str) -> Result<usize, String> {
    let t = s.trim();
    let v = match strip_hex_marker(t) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => t.parse::<u64>(),
    };
    v.map(|v| v as usize).map_err(|_| format!("invalid size {s:?} (want decimal or 0x-prefixed hex)"))
}

/// Same acceptance as [`parse_hex_or_decimal_usize`], for `u64`-typed fields
/// (e.g. `--max-offset`).
pub fn parse_hex_or_decimal_u64(s: &str) -> Result<u64, String> {
    let t = s.trim();
    match strip_hex_marker(t) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => t.parse::<u64>(),
    }
    .map_err(|_| format!("invalid value {s:?} (want decimal or 0x-prefixed hex)"))
}

/// A value on its way into a target (`--value`, `--min`, `--max`, a group field):
/// hex, decimal, or a float, kept as written until the target's type is known.
/// See [`NumberLiteral`] for what went wrong when this was an `f64`.
pub fn parse_number(s: &str) -> Result<NumberLiteral, String> {
    let t = s.trim();
    let parsed = match strip_hex_marker(t) {
        Some(hex) => NumberLiteral::from_hex_digits(hex),
        None => NumberLiteral::parse_decimal(t),
    };
    parsed.map_err(|why| format!("invalid value {s:?}: {why} (want decimal, float, or 0x-prefixed hex)"))
}

/// [`parse_number`] for a flag that hands its text on to a capability: refused at the
/// flag, as any bad flag is, and carried as the text so that nothing rounds it on the way.
pub fn number_text(s: &str) -> Result<String, String> {
    parse_number(s).map(|_| s.trim().to_string())
}

/// Parse a hex byte string in either accepted form: token-per-byte
/// (`"48 89 c8"`, commas allowed) or contiguous (`"4889c8"`).
pub fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .replace("0x", " ")
        .replace("0X", " ")
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || c.is_whitespace() || *c == ',')
        .collect();
    let tokens: Vec<&str> = cleaned.split([' ', ',', '\t', '\n']).filter(|t| !t.is_empty()).collect();

    let mut out = Vec::new();
    if tokens.iter().all(|t| t.len() <= 2) && !tokens.is_empty() {
        // Token-per-byte form ("48 89 c8").
        for t in tokens {
            out.push(u8::from_str_radix(t, 16).map_err(|_| format!("invalid byte: {t:?}"))?);
        }
    } else {
        // Contiguous form ("4889c8") — join and split into pairs.
        let joined: String = tokens.concat();
        if !joined.len().is_multiple_of(2) {
            return Err("odd number of hex digits".to_string());
        }
        let mut i = 0;
        while i < joined.len() {
            let pair = &joined[i..i + 2];
            out.push(u8::from_str_radix(pair, 16).map_err(|_| format!("invalid byte: {pair:?}"))?);
            i += 2;
        }
    }
    if out.is_empty() {
        // The filter above silently drops non-hex characters, so a fully
        // invalid input like "zz" ends up empty. Distinguish that from a
        // genuinely empty string, or the error misleadingly reads "no bytes
        // provided" when bytes *were* given, just not as hex.
        let stripped = s.replace("0x", "").replace("0X", "");
        let has_non_hex = stripped.chars().any(|c| !c.is_ascii_hexdigit() && !c.is_whitespace() && c != ',');
        return Err(if has_non_hex {
            format!("no valid hex bytes in {s:?} (want hex pairs like \"48 89 c8\")")
        } else {
            "no bytes provided".to_string()
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_take_hex_and_decimal_alike() {
        assert_eq!(parse_hex_or_decimal_usize("0x1000").unwrap(), 4096);
        assert_eq!(parse_hex_or_decimal_usize("1000h").unwrap(), 4096);
        assert_eq!(parse_hex_or_decimal_usize("4096").unwrap(), 4096);
        assert!(parse_hex_or_decimal_usize("zzz").is_err());
    }

    // `3.14` is a user-typed scan bound that happens to approximate PI; the
    // point is that it round-trips as a float, not that it is a constant.
    #[allow(clippy::approx_constant)]
    #[test]
    fn scan_bounds_also_take_floats() {
        assert_eq!(parse_number("0x10").unwrap().to_f64().unwrap(), 16.0);
        assert_eq!(parse_number("3.14").unwrap().to_f64().unwrap(), 3.14);
    }

    #[test]
    fn hex_past_two_to_the_63_is_the_integer_written() {
        assert_eq!(parse_number("0xFFFFFFFFFFFFFFFD").unwrap().to_int(64, false), Ok((u64::MAX - 2) as i128));
    }

    #[test]
    fn both_hex_byte_forms_parse_identically() {
        let spaced = parse_hex_bytes("48 89 c8").unwrap();
        let contiguous = parse_hex_bytes("4889c8").unwrap();
        assert_eq!(spaced, vec![0x48, 0x89, 0xc8]);
        assert_eq!(spaced, contiguous);
        // A one-digit token is an unambiguous byte in the spaced form...
        assert_eq!(parse_hex_bytes("48 89 c").unwrap(), vec![0x48, 0x89, 0x0c]);
        // ...but an odd digit count in the contiguous form is not, and must
        // not silently truncate or shift.
        assert!(parse_hex_bytes("4889c8a").is_err(), "odd digit count must be rejected");
        assert!(parse_hex_bytes("").is_err());
    }
}
