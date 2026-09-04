// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `global-metadata.dat` — the managed half, read natively (Phase 12, item 1).
//!
//! ## Why this starts with a deliberately small slice
//!
//! The format is version-fragile in a way that punishes optimism. Metadata
//! versions 16–31 exist in the wild, and **Unity did not always bump the
//! version when the layout changed** — files claiming version 24 come in six
//! distinct formats, and the sub-version is *not recorded anywhere in the
//! header*. Every tool in this space is fragile here, and the failure mode is
//! not a crash: it is a table decoded at the wrong stride, producing confident
//! wrong names in every downstream command at once. On this corpus that is
//! worse than no names (CONCEPT §3 rule 6, sound over complete).
//!
//! So this module reads only what is **structurally version-independent**, and
//! refuses the rest until per-version layouts are tabulated as data:
//!
//! - The header's **fixed prefix**: `sanity`, `version`, and the first twenty
//!   offset/size pairs, through `typeDefinitions`. Verified against
//!   Il2CppDumper's own `Il2CppGlobalMetadataHeader`: the first version-
//!   conditional field is `rgctxEntries` (`[Version(Max = 24.1)]`), which comes
//!   *after* every pair read here. Everything in this module therefore sits at
//!   a byte offset that does not move between versions.
//! - **String literals**, whose entry shape is two 32-bit fields — and which
//!   this module still refuses to trust on faith: every entry must lie inside
//!   the literal data blob, or the whole table is rejected. A layout mismatch
//!   shows up as out-of-range indices long before it shows up as bad names.
//!
//! What is deliberately *not* here: methods, types, fields, generics. Their
//! entry layouts are exactly the version-dependent part, and guessing them is
//! the mistake this module exists to avoid making.

use serde::{Deserialize, Serialize};

use crate::Il2CppError;

/// `0xFAB11BAF`, little-endian, at file offset 0.
pub const SANITY: u32 = 0xFAB1_1BAF;

/// `sanity` + `version` + twenty offset/size pairs.
const FIXED_PREFIX: usize = 8 + 20 * 8;

/// Entry shape of the string-literal index: `{ length: u32, dataIndex: u32 }`.
const LITERAL_ENTRY: usize = 8;

/// The twenty offset/size pairs that sit at fixed positions, **in file order**.
///
/// Held as data rather than as twenty struct fields for the reason the ROADMAP
/// gives for the per-version layouts to come: one table to extend, never an
/// `if version == 29` scattered through the code.
const FIXED_TABLES: [&str; 20] = [
    "string_literal",
    "string_literal_data",
    "string",
    "events",
    "properties",
    "methods",
    "parameter_default_values",
    "field_default_values",
    "field_and_parameter_default_value_data",
    "field_marshaled_sizes",
    "parameters",
    "fields",
    "generic_parameters",
    "generic_parameter_constraints",
    "generic_containers",
    "nested_types",
    "interfaces",
    "vtable_methods",
    "interface_offsets",
    "type_definitions",
];

/// One `(offset, size)` pair from the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Table {
    pub offset: u32,
    pub size: u32,
}

impl Table {
    fn end(self) -> u64 {
        u64::from(self.offset) + u64::from(self.size)
    }
}

/// The version-independent part of `Il2CppGlobalMetadataHeader`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataHeader {
    pub version: i32,
    /// The twenty fixed tables, by the names in [`FIXED_TABLES`].
    pub tables: Vec<(String, Table)>,
}

impl MetadataHeader {
    pub fn table(&self, name: &str) -> Option<Table> {
        self.tables.iter().find(|(n, _)| n == name).map(|(_, t)| *t)
    }
}

/// A string literal and where its bytes live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Literal {
    /// Index into the literal table — the number the emitted code uses.
    pub index: u32,
    pub value: String,
}

/// What was read out of a `global-metadata.dat`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub header: MetadataHeader,
    pub literals: Vec<Literal>,
    /// Literal entries skipped because their bytes were not valid UTF-8. Counted
    /// rather than silently dropped: a high count is itself evidence that the
    /// entry stride is wrong for this version.
    pub literals_not_utf8: usize,
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Read the version-independent part of a `global-metadata.dat`.
pub fn parse(bytes: &[u8]) -> Result<Metadata, Il2CppError> {
    if bytes.len() < FIXED_PREFIX {
        return Err(Il2CppError::Malformed(format!(
            "file is {} bytes, shorter than the version-independent header prefix ({FIXED_PREFIX})",
            bytes.len()
        )));
    }
    let sanity = u32_at(bytes, 0).expect("length checked");
    if sanity != SANITY {
        return Err(Il2CppError::Malformed(format!("magic is 0x{sanity:08X}, not 0x{SANITY:08X} — this is not a global-metadata.dat")));
    }
    let version = u32_at(bytes, 4).expect("length checked") as i32;
    // 16 is the oldest shipped format; anything outside the known band is far
    // more likely a mis-identified file than a version worth guessing at.
    if !(16..=31).contains(&version) {
        return Err(Il2CppError::Malformed(format!("metadata version {version} is outside the known range 16..=31")));
    }

    let mut tables = Vec::with_capacity(FIXED_TABLES.len());
    for (i, name) in FIXED_TABLES.iter().enumerate() {
        let at = 8 + i * 8;
        let t = Table { offset: u32_at(bytes, at).expect("length checked"), size: u32_at(bytes, at + 4).expect("length checked") };
        // Self-validation, not decoration: a table running past the end of the
        // file means this is not the layout we think it is, and every later
        // read would be reading someone else's bytes.
        if t.size > 0 && t.end() > bytes.len() as u64 {
            return Err(Il2CppError::Malformed(format!(
                "table '{name}' claims {}..{} but the file is {} bytes — the header does not describe this file",
                t.offset,
                t.end(),
                bytes.len()
            )));
        }
        tables.push(((*name).to_string(), t));
    }
    let header = MetadataHeader { version, tables };

    let (literals, literals_not_utf8) = read_literals(bytes, &header)?;
    Ok(Metadata { header, literals, literals_not_utf8 })
}

/// Decode the string-literal table, refusing it wholesale on any structural
/// inconsistency.
///
/// The entry shape (`length`, `dataIndex`) is the one assumption here, and it
/// is checked rather than trusted: every entry must name a range inside the
/// literal data blob. A wrong stride produces indices scattered far outside it
/// almost immediately, so this rejects a mis-read table long before it can turn
/// into plausible-looking text.
fn read_literals(bytes: &[u8], header: &MetadataHeader) -> Result<(Vec<Literal>, usize), Il2CppError> {
    let index = header.table("string_literal").expect("fixed table");
    let data = header.table("string_literal_data").expect("fixed table");
    if index.size == 0 {
        return Ok((Vec::new(), 0));
    }
    if !index.size.is_multiple_of(LITERAL_ENTRY as u32) {
        return Err(Il2CppError::Malformed(format!(
            "string-literal table is {} bytes, not a multiple of the {LITERAL_ENTRY}-byte entry — the layout does not match",
            index.size
        )));
    }

    let count = (index.size as usize) / LITERAL_ENTRY;
    let data_start = data.offset as usize;
    let data_len = data.size as usize;
    let mut literals = Vec::with_capacity(count);
    let mut not_utf8 = 0usize;

    for i in 0..count {
        let at = index.offset as usize + i * LITERAL_ENTRY;
        let len = u32_at(bytes, at).ok_or_else(|| Il2CppError::Malformed(format!("string-literal entry {i} runs past the end of the file")))? as usize;
        let data_index =
            u32_at(bytes, at + 4).ok_or_else(|| Il2CppError::Malformed(format!("string-literal entry {i} runs past the end of the file")))? as usize;

        if data_index.saturating_add(len) > data_len {
            return Err(Il2CppError::Malformed(format!(
                "string-literal entry {i} names bytes {data_index}..{} of a {data_len}-byte blob — the entry layout is wrong for this file, so the whole table is refused rather than half-decoded",
                data_index + len
            )));
        }
        let from = data_start + data_index;
        let slice = bytes.get(from..from + len).ok_or_else(|| Il2CppError::Malformed(format!("string-literal {i} points outside the file")))?;
        match std::str::from_utf8(slice) {
            Ok(s) => literals.push(Literal { index: i as u32, value: s.to_string() }),
            Err(_) => not_utf8 += 1,
        }
    }
    Ok((literals, not_utf8))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but structurally valid `global-metadata.dat`.
    fn build(version: i32, literals: &[&str]) -> Vec<u8> {
        let mut blob = Vec::new();
        let mut entries: Vec<(u32, u32)> = Vec::new();
        for s in literals {
            entries.push((s.len() as u32, blob.len() as u32));
            blob.extend_from_slice(s.as_bytes());
        }
        let index_bytes: Vec<u8> = entries.iter().flat_map(|(len, idx)| [len.to_le_bytes(), idx.to_le_bytes()].concat()).collect();

        let index_off = FIXED_PREFIX;
        let data_off = index_off + index_bytes.len();

        let mut out = Vec::new();
        out.extend_from_slice(&SANITY.to_le_bytes());
        out.extend_from_slice(&(version as u32).to_le_bytes());
        // Twenty pairs: the first two are the literal index and its data blob;
        // the rest are empty, which is legal and keeps the fixture honest.
        out.extend_from_slice(&(index_off as u32).to_le_bytes());
        out.extend_from_slice(&(index_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data_off as u32).to_le_bytes());
        out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        for _ in 2..20 {
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
        }
        assert_eq!(out.len(), FIXED_PREFIX);
        out.extend_from_slice(&index_bytes);
        out.extend_from_slice(&blob);
        out
    }

    #[test]
    fn reads_the_version_and_the_twenty_fixed_tables() {
        let m = parse(&build(29, &["You died", "Press any key"])).unwrap();
        assert_eq!(m.header.version, 29);
        assert_eq!(m.header.tables.len(), 20);
        assert_eq!(m.header.tables[0].0, "string_literal");
        assert_eq!(m.header.tables[19].0, "type_definitions", "the fixed prefix ends at type_definitions — the next field is version-conditional");
        assert_eq!(m.header.table("string").unwrap(), Table { offset: 0, size: 0 });
    }

    #[test]
    fn decodes_string_literals_with_their_indices() {
        let m = parse(&build(24, &["You died", "Press any key"])).unwrap();
        assert_eq!(m.literals.len(), 2);
        assert_eq!(m.literals[0], Literal { index: 0, value: "You died".into() });
        assert_eq!(m.literals[1].index, 1, "the index is the number the emitted code uses, so it must be the position in the table");
        assert_eq!(m.literals_not_utf8, 0);
    }

    #[test]
    fn a_file_without_the_magic_is_refused_by_name() {
        let mut bytes = build(29, &["x"]);
        bytes[0] = 0;
        let err = parse(&bytes).unwrap_err();
        assert!(err.to_string().contains("not a global-metadata.dat"), "{err}");
    }

    #[test]
    fn a_version_outside_the_known_band_is_refused_rather_than_guessed_at() {
        let err = parse(&build(99, &["x"])).unwrap_err();
        assert!(err.to_string().contains("16..=31"), "{err}");
        // And the oldest/newest known ones are accepted.
        assert_eq!(parse(&build(16, &["x"])).unwrap().header.version, 16);
        assert_eq!(parse(&build(31, &["x"])).unwrap().header.version, 31);
    }

    #[test]
    fn a_table_running_past_the_end_of_the_file_is_refused() {
        let mut bytes = build(29, &["x"]);
        // Point the `string` table somewhere impossible.
        bytes[8 + 2 * 8..8 + 2 * 8 + 4].copy_from_slice(&0u32.to_le_bytes());
        bytes[8 + 2 * 8 + 4..8 + 2 * 8 + 8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let err = parse(&bytes).unwrap_err();
        assert!(err.to_string().contains("does not describe this file"), "{err}");
    }

    #[test]
    fn a_wrong_entry_stride_is_caught_by_range_checking_not_by_bad_text() {
        // This is the whole safety argument: a mis-read literal table produces
        // indices outside the blob almost immediately, and the table is refused
        // wholesale rather than half-decoded into plausible-looking strings.
        let mut bytes = build(29, &["You died", "Press any key"]);
        let at = FIXED_PREFIX + 4; // the first entry's dataIndex
        bytes[at..at + 4].copy_from_slice(&0x0010_0000u32.to_le_bytes());
        let err = parse(&bytes).unwrap_err();
        assert!(err.to_string().contains("refused rather than half-decoded"), "{err}");
    }

    #[test]
    fn a_truncated_file_is_refused_before_any_table_is_read() {
        let err = parse(&[0u8; 32]).unwrap_err();
        assert!(err.to_string().contains("version-independent header prefix"), "{err}");
    }

    #[test]
    fn an_index_table_of_a_bad_length_is_refused() {
        let mut bytes = build(29, &["x"]);
        // Literal index size that is not a multiple of the entry size.
        bytes[12..16].copy_from_slice(&7u32.to_le_bytes());
        let err = parse(&bytes).unwrap_err();
        assert!(err.to_string().contains("not a multiple of the 8-byte entry"), "{err}");
    }

    #[test]
    fn non_utf8_literals_are_counted_rather_than_dropped_in_silence() {
        let mut bytes = build(29, &["ok", "xx"]);
        // Corrupt the second literal's bytes into invalid UTF-8.
        let n = bytes.len();
        bytes[n - 2..].copy_from_slice(&[0xff, 0xfe]);
        let m = parse(&bytes).unwrap();
        assert_eq!(m.literals.len(), 1);
        assert_eq!(m.literals_not_utf8, 1, "a high count here is itself evidence the stride is wrong for this version");
    }

    #[test]
    fn a_metadata_with_no_literals_is_empty_not_an_error() {
        let m = parse(&build(29, &[])).unwrap();
        assert!(m.literals.is_empty());
        assert_eq!(m.header.version, 29);
    }
}
