// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Shared value types that cross every boundary: [`Va`], [`Reg`], [`Symbol`],
//! [`Module`]. These are pure data — no behavior tied to an OS or an ISA.

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A typed **virtual address**. Wire form is a hex string (`"0x1400010a0"`) so
/// that agents and humans read the same value RE tools display, without the
/// ambiguity of a bare JSON number. Accepts hex (`0x…`), decimal, or a JSON
/// integer on the way in.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Va(pub u64);

impl Va {
    pub const fn new(v: u64) -> Self {
        Va(v)
    }
    pub const fn get(self) -> u64 {
        self.0
    }
    /// Address `self + delta`, saturating at `u64::MAX`.
    pub const fn offset(self, delta: u64) -> Va {
        Va(self.0.saturating_add(delta))
    }
    /// Signed distance `self - other` (may be negative).
    pub const fn delta(self, other: Va) -> i64 {
        self.0.wrapping_sub(other.0) as i64
    }
    /// Parse from `"0x…"`, `"…h"`, or a decimal string.
    pub fn parse(s: &str) -> Result<Va, ParseVaError> {
        let t = s.trim();
        let v = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16)
        } else if let Some(hex) = t.strip_suffix('h').or_else(|| t.strip_suffix('H')) {
            u64::from_str_radix(hex, 16)
        } else {
            t.parse::<u64>()
        };
        v.map(Va).map_err(|_| ParseVaError(s.to_string()))
    }
}

/// Error returned by [`Va::parse`] when the string is not a valid address.
#[derive(Debug, Clone)]
pub struct ParseVaError(pub String);

impl fmt::Display for ParseVaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid virtual address: {:?}", self.0)
    }
}
impl std::error::Error for ParseVaError {}

impl fmt::Display for Va {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}
impl fmt::Debug for Va {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Va(0x{:x})", self.0)
    }
}

impl Serialize for Va {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{:x}", self.0))
    }
}

impl<'de> Deserialize<'de> for Va {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Va, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Va;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a virtual address as a hex/decimal string or an integer")
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Va, E> {
                Ok(Va(v))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Va, E> {
                Ok(Va(v as u64))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Va, E> {
                Va::parse(v).map_err(|e| E::custom(e.to_string()))
            }
        }
        d.deserialize_any(V)
    }
}

/// An interned **register identifier**. The number is meaningful only relative
/// to an [`Arch`](../../n0xis_arch/index.html) `RegisterFile`, which owns the
/// id→name mapping — register *names* never leak into the analysis passes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct Reg(pub u16);

/// A loaded module (image) — live module or a static PE mapped at its base.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Module {
    pub name: String,
    pub base: Va,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl Module {
    pub fn contains(&self, va: Va) -> bool {
        va.0 >= self.base.0 && va.0 < self.base.0.saturating_add(self.size)
    }
    /// Address relative to the module base (RVA).
    pub fn rva(&self, va: Va) -> Option<u64> {
        self.contains(va).then(|| va.0 - self.base.0)
    }
}

/// A resolved symbol at an address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Symbol {
    pub va: Va,
    pub module: String,
    pub name: String,
    pub kind: SymKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymKind {
    Function,
    Import,
    Export,
    Data,
    Label,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn va_roundtrips_as_hex_string() {
        let va = Va(0x1400010a0);
        let json = serde_json::to_string(&va).unwrap();
        assert_eq!(json, "\"0x1400010a0\"");
        let back: Va = serde_json::from_str(&json).unwrap();
        assert_eq!(back, va);
    }

    #[test]
    fn va_parses_hex_decimal_and_int() {
        assert_eq!(Va::parse("0x40").unwrap(), Va(64));
        assert_eq!(Va::parse("40h").unwrap(), Va(64));
        assert_eq!(Va::parse("64").unwrap(), Va(64));
        assert_eq!(serde_json::from_str::<Va>("64").unwrap(), Va(64));
    }

    #[test]
    fn module_rva_and_containment() {
        let m = Module {
            name: "game.exe".into(),
            base: Va(0x140000000),
            size: 0x1000,
            path: None,
        };
        assert!(m.contains(Va(0x140000abc)));
        assert_eq!(m.rva(Va(0x140000abc)), Some(0xabc));
        assert!(!m.contains(Va(0x140001001)));
    }
}
