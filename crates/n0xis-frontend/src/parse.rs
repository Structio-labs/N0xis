//! Argument parsing every frontend needs: addresses, sizes, and hex byte
//! strings. Acceptance is defined here once, so `--size 0x1000` on the CLI and
//! `"size": "0x1000"` through MCP can never disagree about what they take.

use n0xis_contracts::Va;

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

/// Value parser for scan value/bound fields (`--value`, `--min`, `--max`):
/// accepts hex, decimal, or a float. Falls through to `f64::from_str` when
/// there is no hex marker, since a scan criterion can compare against a
/// genuine float (`3.14`), which plain hex cannot represent.
pub fn parse_hex_or_decimal_f64(s: &str) -> Result<f64, String> {
    let t = s.trim();
    if let Some(hex) = strip_hex_marker(t) {
        return u64::from_str_radix(hex, 16)
            .map(|v| v as f64)
            .map_err(|_| format!("invalid value {s:?} (want decimal, float, or 0x-prefixed hex)"));
    }
    t.parse::<f64>().map_err(|_| format!("invalid value {s:?} (want decimal, float, or 0x-prefixed hex)"))
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
        return Err("no bytes provided".to_string());
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
        assert_eq!(parse_hex_or_decimal_f64("0x10").unwrap(), 16.0);
        assert_eq!(parse_hex_or_decimal_f64("3.14").unwrap(), 3.14);
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
