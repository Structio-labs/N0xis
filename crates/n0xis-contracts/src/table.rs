// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The `.n0xt` table entry format (CONCEPT §10) — a superset of Cheat
//! Engine's `.CT`. Lives here (not `n0xis-project`) because it's a shared
//! wire contract like every other schema'd type: `n0xis-core`'s scan passes
//! produce data that becomes a [`TableEntry`], `n0xis-project` persists it,
//! `n0xis-cli`/`n0xis-mcp` both read and write it — one shape, one place.
//!
//! **The N0xis superset** over a plain address/value/description entry:
//! each entry can carry [`Provenance`] — a link to the recovered function,
//! struct, and field a value came from — and a [`VerificationState`]
//! recording when it was last confirmed live and against which module
//! build. Both are `Default`/optional: an entry doesn't need them to be
//! useful, and today (pre-Phase-4c) nothing populates `Provenance`
//! automatically yet — the fields exist so the format doesn't need a
//! breaking change once the provenance graph lands.
//!
//! Deliberately **not** included: scriptable "enable/disable" hooks on an
//! entry. That's real functionality this format's `groups` /
//! `hotkey` fields leave room to grow toward later, but a script is
//! arbitrary code execution in the target process — out of scope for a
//! first cut, and not required by ROADMAP Phase 4b's own bullet list.

use serde::{Deserialize, Serialize};

use crate::Va;

/// How to (re-)locate an entry's address — in increasing order of
/// restart/ASLR resilience.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TableLocator {
    /// A fixed address. Least stable — breaks across a restart if the
    /// target rebases; fine for a single live session or a non-ASLR target.
    Address { va: Va },
    /// A multi-level pointer chain rooted at `module + root_offset` — see
    /// `n0xis-core::PointerPath`. Survives ASLR rebases: only the module
    /// base moves, the offset within it doesn't.
    PointerPath { module: String, root_offset: u64, offsets: Vec<i64> },
    /// An AOB signature plus a fixed offset from the match — survives a
    /// patch/recompile that moves the address but keeps the surrounding
    /// bytes recognizable.
    Aob { pattern: String, offset_from_match: i64, module: Option<String> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TableValueType {
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
    /// A raw byte blob of `size` bytes (freeze/write not meaningful; used
    /// for AOB-anchored data regions).
    Aob,
}

impl TableValueType {
    /// Encode a freeze/write value as little-endian bytes for this entry's
    /// type — shared by any frontend that writes a `TableEntry`'s value into
    /// a live process (the CLI's `table freeze`, n0xis-hud's menu toggles).
    pub fn encode_value(self, v: f64) -> Result<Vec<u8>, String> {
        Ok(match self {
            TableValueType::I8 => (v as i8).to_le_bytes().to_vec(),
            TableValueType::U8 => (v as u8).to_le_bytes().to_vec(),
            TableValueType::I16 => (v as i16).to_le_bytes().to_vec(),
            TableValueType::U16 => (v as u16).to_le_bytes().to_vec(),
            TableValueType::I32 => (v as i32).to_le_bytes().to_vec(),
            TableValueType::U32 => (v as u32).to_le_bytes().to_vec(),
            TableValueType::I64 => (v as i64).to_le_bytes().to_vec(),
            TableValueType::U64 => (v as u64).to_le_bytes().to_vec(),
            TableValueType::F32 => (v as f32).to_le_bytes().to_vec(),
            TableValueType::F64 => v.to_le_bytes().to_vec(),
            TableValueType::Aob => return Err("cannot freeze an Aob-typed entry as a scalar value".to_string()),
        })
    }
}

/// Has this entry actually been confirmed live, and against which build?
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VerificationState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_confirmed_unix: Option<u64>,
    /// Free-form module identity (e.g. a hash or version string) the entry
    /// was last confirmed against — lets a rescan flag "this entry hasn't
    /// been checked since the target updated."
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_build: Option<String>,
}

/// The N0xis superset (see module docs) — all optional, all `None`/empty
/// until something populates them.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_va: Option<Va>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub struct_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_offset: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TableEntry {
    pub name: String,
    pub locator: TableLocator,
    pub value_type: TableValueType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hotkey: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default)]
    pub frozen: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freeze_value: Option<f64>,
    #[serde(default, skip_serializing_if = "is_default_provenance")]
    pub provenance: Provenance,
    #[serde(default, skip_serializing_if = "is_default_verification")]
    pub verification: VerificationState,
}

fn is_default_provenance(p: &Provenance) -> bool {
    p == &Provenance::default()
}
fn is_default_verification(v: &VerificationState) -> bool {
    v == &VerificationState::default()
}

/// A named collection of entries — one `.n0xt` file.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Table {
    pub name: String,
    #[serde(default)]
    pub entries: Vec<TableEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_entry_roundtrips_through_json() {
        let entry = TableEntry {
            name: "hp".to_string(),
            locator: TableLocator::PointerPath { module: "game.exe".to_string(), root_offset: 0x1234, offsets: vec![0x10, -0x8] },
            value_type: TableValueType::I32,
            description: Some("player HP".to_string()),
            hotkey: None,
            groups: vec!["player".to_string()],
            frozen: true,
            freeze_value: Some(999.0),
            provenance: Provenance::default(),
            verification: VerificationState::default(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: TableEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entry);
        // Defaulted provenance/verification are omitted from the wire form.
        assert!(!json.contains("provenance"));
        assert!(!json.contains("verification"));
    }
}
