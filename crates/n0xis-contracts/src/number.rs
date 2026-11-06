// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A number as the person wrote it, before it has a type.
//!
//! Every number on its way into a target used to pass through `f64`: `--value
//! 16045690984503111693` reached the scanner as 16045690984503111680, which the
//! target does not hold, and the answer was "0 matches, exhaustive" about a value
//! it does. Past 2^53 a double cannot name each integer, so the fix is not a
//! wider tolerance: the value stays what was written until the target's type is
//! known, and then it either is that type exactly or it is refused.
//!
//! A float literal is the exception a float literal always is. `0.1` has no exact
//! binary form, and asking for an `f32` of `0.1` means the nearest `f32`, as it
//! does to a compiler. That is what the notation says, so it is not rounding the
//! caller's number. An integer written for a float type gets no such reading:
//! `16777217` as an `f32` would silently be 16777216, and is refused.

/// The largest magnitude below which every integer has its own `f64`. A double at
/// or past this may be one of several integers, so it no longer says which.
const F64_EXACT_INTEGERS_BELOW: f64 = 9_007_199_254_740_992.0;

/// A number with no type yet. Bind it with [`to_int`](Self::to_int),
/// [`to_f32`](Self::to_f32) or [`to_f64`](Self::to_f64): those are the only ways
/// out, and each refuses what its type cannot hold.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NumberLiteral {
    /// Written as an integer, decimal or hex.
    Integer(i128),
    /// Written with a point or an exponent, or a JSON number that was already a
    /// double when it reached us. `integer` is the integer it is exactly, when the
    /// notation or the double can say so.
    Decimal { value: f64, integer: Option<i128> },
}

impl NumberLiteral {
    /// A decimal integer or a float in decimal notation. Hex is the frontends' to
    /// strip, since which markers count is theirs; see [`from_hex_digits`](Self::from_hex_digits).
    pub fn parse_decimal(text: &str) -> Result<Self, String> {
        let t = text.trim();
        if let Ok(v) = t.parse::<i128>() {
            return Ok(NumberLiteral::Integer(v));
        }
        let value = t.parse::<f64>().map_err(|_| format!("{t:?} is not a number"))?;
        // `inf` and `nan` parse, and no comparison a scan makes can ever match
        // them: an answer of "0 matches" would be a fact about the comparison.
        if !value.is_finite() {
            return Err(format!("{t:?} is not a finite number"));
        }
        Ok(NumberLiteral::Decimal { value, integer: exact_integer_of_decimal(t) })
    }

    pub fn from_hex_digits(digits: &str) -> Result<Self, String> {
        i128::from_str_radix(digits, 16).map(NumberLiteral::Integer).map_err(|_| format!("{digits:?} is not hex, or is too long"))
    }

    /// A number that is a double already: a JSON number too large for an integer,
    /// or one a table file stored. At or past 2^53 the double no longer says which
    /// integer it was, so it binds to a float type and to no integer type.
    pub fn from_double(value: f64) -> Self {
        let integer = (value.is_finite() && value.fract() == 0.0 && value.abs() < F64_EXACT_INTEGERS_BELOW).then_some(value as i128);
        NumberLiteral::Decimal { value, integer }
    }

    /// This number in an integer type of `bits` bits, refused unless it is exactly
    /// that. A value that does not fit is refused rather than read as a bit pattern:
    /// `0xFFFFFFFF` as an `i32` is written `-1`.
    pub fn to_int(self, bits: u32, signed: bool) -> Result<i128, String> {
        let v = match self {
            NumberLiteral::Integer(v) => v,
            NumberLiteral::Decimal { integer: Some(v), .. } => v,
            NumberLiteral::Decimal { value, integer: None } => {
                return Err(if value.fract() != 0.0 {
                    format!("{value} is not an integer")
                } else {
                    format!("{value} came through a double, which past 2^53 cannot say which integer it was; write it as an integer")
                });
            }
        };
        let (lo, hi) = if signed { (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1) } else { (0, (1i128 << bits) - 1) };
        if v < lo || v > hi {
            let t = format!("{}{bits}", if signed { 'i' } else { 'u' });
            return Err(format!("{v} does not fit {t} ({lo} to {hi})"));
        }
        Ok(v)
    }

    pub fn to_f64(self) -> Result<f64, String> {
        match self {
            NumberLiteral::Integer(v) => {
                let f = v as f64;
                if f as i128 == v { Ok(f) } else { Err(format!("{v} has no exact f64")) }
            }
            NumberLiteral::Decimal { value, .. } => Ok(value),
        }
    }

    pub fn to_f32(self) -> Result<f32, String> {
        match self {
            NumberLiteral::Integer(v) => {
                let f = v as f32;
                if f as i128 == v { Ok(f) } else { Err(format!("{v} has no exact f32")) }
            }
            NumberLiteral::Decimal { value, .. } => {
                let f = value as f32;
                // The nearest `f32` is what a float literal means; infinity and
                // zero are not near, they are a different number.
                if f.is_infinite() || (f == 0.0 && value != 0.0) { Err(format!("{value} is outside f32")) } else { Ok(f) }
            }
        }
    }
}

/// As a JSON number when one can hold it, an integer as an integer: an answer that
/// echoes a value says what was written, and `1002855686537490445.0` would not.
impl serde::Serialize for NumberLiteral {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match *self {
            NumberLiteral::Integer(v) => match (i64::try_from(v), u64::try_from(v)) {
                (Ok(v), _) => s.serialize_i64(v),
                (_, Ok(v)) => s.serialize_u64(v),
                _ => s.serialize_str(&v.to_string()),
            },
            NumberLiteral::Decimal { value, .. } => s.serialize_f64(value),
        }
    }
}

/// The integer a text in decimal notation is exactly, from its digits and not from
/// the double: `1002855686537490445.0` is an integer the double cannot hold, and
/// `4.0000000000000000001` is not an integer although its double is.
fn exact_integer_of_decimal(t: &str) -> Option<i128> {
    let (negative, unsigned) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let (mantissa, exponent) = match unsigned.split_once(['e', 'E']) {
        Some((m, e)) => (m, e.parse::<i32>().ok()?),
        None => (unsigned, 0),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits: String = whole.chars().chain(fraction.chars()).collect();
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let significant = digits.trim_start_matches('0');
    let kept = significant.trim_end_matches('0');
    let dropped = i32::try_from(significant.len() - kept.len()).ok()?;
    let scale = exponent.checked_sub(i32::try_from(fraction.len()).ok()?)?.checked_add(dropped)?;
    if kept.is_empty() {
        return Some(0);
    }
    if scale < 0 {
        return None;
    }
    let mut v = kept.parse::<i128>().ok()?;
    for _ in 0..scale {
        v = v.checked_mul(10)?;
    }
    Some(if negative { -v } else { v })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The value the sweep failed on, planted in its target.
    const PLANTED: i128 = 0xDEAD_BEEF_CAFE_F00D;

    #[test]
    fn an_integer_past_two_to_the_53_stays_itself() {
        let lit = NumberLiteral::parse_decimal(&PLANTED.to_string()).unwrap();
        assert_eq!(lit.to_int(64, false), Ok(PLANTED));
        assert!(lit.to_int(64, true).is_err(), "past i64::MAX");
        assert_ne!(PLANTED as f64 as i128, PLANTED, "calibration: this value does not survive a double");
    }

    #[test]
    fn the_ends_of_every_integer_type_are_exact_and_one_past_them_refused() {
        for (bits, signed, lo, hi) in [
            (8, true, i8::MIN as i128, i8::MAX as i128),
            (8, false, 0, u8::MAX as i128),
            (16, true, i16::MIN as i128, i16::MAX as i128),
            (16, false, 0, u16::MAX as i128),
            (32, true, i32::MIN as i128, i32::MAX as i128),
            (32, false, 0, u32::MAX as i128),
            (64, true, i64::MIN as i128, i64::MAX as i128),
            (64, false, 0, u64::MAX as i128),
        ] {
            assert_eq!(NumberLiteral::Integer(lo).to_int(bits, signed), Ok(lo));
            assert_eq!(NumberLiteral::Integer(hi).to_int(bits, signed), Ok(hi));
            assert!(NumberLiteral::Integer(lo - 1).to_int(bits, signed).is_err(), "{bits} {signed} below");
            assert!(NumberLiteral::Integer(hi + 1).to_int(bits, signed).is_err(), "{bits} {signed} above");
        }
    }

    #[test]
    fn decimal_notation_binds_to_an_integer_only_when_it_is_that_integer() {
        let int = |t: &str| NumberLiteral::parse_decimal(t).unwrap().to_int(64, true);
        assert_eq!(int("1e3"), Ok(1000));
        assert_eq!(int("3.0"), Ok(3));
        assert_eq!(int("-2.50e1"), Ok(-25));
        assert_eq!(int("0.0"), Ok(0));
        assert_eq!(int("9007199254740993.0"), Ok(9_007_199_254_740_993));
        assert!(int("1.5").is_err());
        assert!(int("4.0000000000000000001").is_err(), "its double is 4.0, and it is not 4");
        assert!(int("1e30").is_err());
    }

    #[test]
    fn a_double_past_two_to_the_53_binds_to_no_integer() {
        assert_eq!(NumberLiteral::from_double(4242.0).to_int(32, true), Ok(4242));
        assert!(NumberLiteral::from_double(9_007_199_254_740_992.0).to_int(64, true).is_err());
        assert!(NumberLiteral::from_double(1.5).to_int(64, true).is_err());
        assert_eq!(NumberLiteral::from_double(1e300).to_f64(), Ok(1e300));
    }

    #[test]
    fn a_float_type_takes_the_nearest_of_a_float_literal_and_only_the_exact_of_an_integer() {
        let f32_of = |t: &str| NumberLiteral::parse_decimal(t).unwrap().to_f32();
        assert_eq!(f32_of("0.1"), Ok(0.1f32));
        assert_eq!(f32_of("16777216"), Ok(16_777_216.0));
        assert!(f32_of("16777217").is_err());
        assert!(f32_of("1e39").is_err());
        assert!(f32_of("1e-60").is_err());
        let f64_of = |t: &str| NumberLiteral::parse_decimal(t).unwrap().to_f64();
        assert_eq!(f64_of("9007199254740992"), Ok(9_007_199_254_740_992.0));
        assert!(f64_of("9007199254740993").is_err());
        assert_eq!(f64_of("0.1"), Ok(0.1));
    }

    #[test]
    fn what_no_scan_could_match_is_not_a_number_here() {
        for t in ["inf", "-inf", "nan", "NaN", "", "abc", "1e", "0x10"] {
            assert!(NumberLiteral::parse_decimal(t).is_err(), "{t}");
        }
    }
}
