// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Reader for **Il2CppDumper**'s `script.json` — the interop path into the
//! IL2CPP tooling that already exists.
//!
//! Deliberately tolerant about *shape* and strict about *substance*. Field
//! names are accepted in either casing and every array is optional, because
//! dumper versions differ and a missing `ScriptMetadata` is not a reason to
//! reject a file full of methods. But a file that parses to **no symbols at
//! all** is refused by name rather than imported as an empty index — an empty
//! index that binds successfully is worse than a failure, because every later
//! command then silently reports "no name" as if that were the answer.
//!
//! The one thing this reader deliberately does **not** decide is what the
//! addresses are relative to. See [`AddressSpace`](crate::AddressSpace).

use serde::Deserialize;

use crate::{Il2CppError, RawSymbol, StringLiteral, SymbolKind};

/// One `ScriptMethod` entry: a transpiled C# method.
#[derive(Debug, Deserialize)]
struct ScriptMethod {
    #[serde(alias = "address")]
    #[serde(rename = "Address")]
    address: u64,
    #[serde(alias = "name", default)]
    #[serde(rename = "Name")]
    name: String,
    #[serde(alias = "signature", default)]
    #[serde(rename = "Signature")]
    signature: Option<String>,
}

/// A `ScriptString`: a literal and the `.data` slot it is materialized into.
#[derive(Debug, Deserialize)]
struct ScriptString {
    #[serde(alias = "address")]
    #[serde(rename = "Address")]
    address: u64,
    #[serde(alias = "value", default)]
    #[serde(rename = "Value")]
    value: String,
}

/// A `ScriptMetadata` entry: a metadata-usage slot in `.data`.
#[derive(Debug, Deserialize)]
struct ScriptMetadata {
    #[serde(alias = "address")]
    #[serde(rename = "Address")]
    address: u64,
    #[serde(alias = "name", default)]
    #[serde(rename = "Name")]
    name: String,
}

/// A `ScriptMetadataMethod`: a slot holding a `MethodInfo*`.
#[derive(Debug, Deserialize)]
struct ScriptMetadataMethod {
    #[serde(alias = "address")]
    #[serde(rename = "Address")]
    address: u64,
    #[serde(alias = "name", default)]
    #[serde(rename = "Name")]
    name: String,
}

#[derive(Debug, Deserialize)]
struct ScriptJson {
    #[serde(alias = "scriptMethod", default)]
    #[serde(rename = "ScriptMethod")]
    methods: Vec<ScriptMethod>,
    #[serde(alias = "scriptString", default)]
    #[serde(rename = "ScriptString")]
    strings: Vec<ScriptString>,
    #[serde(alias = "scriptMetadata", default)]
    #[serde(rename = "ScriptMetadata")]
    metadata: Vec<ScriptMetadata>,
    #[serde(alias = "scriptMetadataMethod", default)]
    #[serde(rename = "ScriptMetadataMethod")]
    metadata_methods: Vec<ScriptMetadataMethod>,
}

/// What a parsed `script.json` yielded, before any address space is decided.
#[derive(Debug)]
pub struct Parsed {
    pub symbols: Vec<RawSymbol>,
    pub strings: Vec<StringLiteral>,
    /// Per-section counts, so the import report can say what the dump actually
    /// contained rather than one opaque total.
    pub counts: Counts,
}

#[derive(Debug, Default, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct Counts {
    pub methods: usize,
    pub metadata: usize,
    pub metadata_methods: usize,
    pub strings: usize,
}

/// Parse an Il2CppDumper `script.json`.
pub fn parse(bytes: &[u8]) -> Result<Parsed, Il2CppError> {
    let text = std::str::from_utf8(bytes).map_err(|e| Il2CppError::Malformed(format!("script.json is not UTF-8: {e}")))?;
    // Strip a UTF-8 BOM: .NET writes one by default and serde_json rejects it.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let raw: ScriptJson = serde_json::from_str(text).map_err(|e| Il2CppError::Malformed(format!("script.json: {e}")))?;

    let counts =
        Counts { methods: raw.methods.len(), metadata: raw.metadata.len(), metadata_methods: raw.metadata_methods.len(), strings: raw.strings.len() };

    let mut symbols: Vec<RawSymbol> = Vec::with_capacity(counts.methods + counts.metadata + counts.metadata_methods);
    for m in raw.methods {
        if m.name.is_empty() {
            continue;
        }
        symbols.push(RawSymbol { addr: m.address, name: m.name, signature: m.signature, kind: SymbolKind::Method });
    }
    for m in raw.metadata {
        if m.name.is_empty() {
            continue;
        }
        symbols.push(RawSymbol { addr: m.address, name: m.name, signature: None, kind: SymbolKind::Metadata });
    }
    for m in raw.metadata_methods {
        if m.name.is_empty() {
            continue;
        }
        symbols.push(RawSymbol { addr: m.address, name: m.name, signature: None, kind: SymbolKind::MetadataMethod });
    }
    let strings: Vec<StringLiteral> = raw.strings.into_iter().map(|s| StringLiteral { addr: s.address, value: s.value }).collect();

    if symbols.is_empty() {
        return Err(Il2CppError::Empty(format!(
            "the file parsed as script.json but yielded no named symbols (methods {}, metadata {}, metadata-methods {})",
            counts.methods, counts.metadata, counts.metadata_methods
        )));
    }

    Ok(Parsed { symbols, strings, counts })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "ScriptMethod": [
        {"Address": 4096, "Name": "PlayerHealth$$ApplyDamage", "Signature": "void PlayerHealth_ApplyDamage(PlayerHealth *, float, MethodInfo *)"},
        {"Address": 8192, "Name": "CombatResolver$$Resolve", "Signature": "void CombatResolver_Resolve(CombatResolver *, MethodInfo *)"}
      ],
      "ScriptString": [
        {"Address": 65536, "Value": "You died"}
      ],
      "ScriptMetadata": [
        {"Address": 131072, "Name": "PlayerHealth_TypeInfo"}
      ],
      "ScriptMetadataMethod": [
        {"Address": 196608, "Name": "PlayerHealth$$ApplyDamage_MethodInfo", "MethodAddress": 4096}
      ]
    }"#;

    #[test]
    fn parses_every_section_and_counts_them_separately() {
        let p = parse(SAMPLE.as_bytes()).unwrap();
        assert_eq!(p.counts.methods, 2);
        assert_eq!(p.counts.metadata, 1);
        assert_eq!(p.counts.metadata_methods, 1);
        assert_eq!(p.counts.strings, 1);
        assert_eq!(p.symbols.len(), 4, "methods + metadata + metadata-methods all become symbols");
        assert_eq!(p.strings[0].value, "You died");
    }

    #[test]
    fn method_signatures_survive_because_the_hidden_argument_lives_in_them() {
        let p = parse(SAMPLE.as_bytes()).unwrap();
        let m = p.symbols.iter().find(|s| s.name.contains("ApplyDamage") && s.kind == SymbolKind::Method).unwrap();
        assert!(m.signature.as_deref().unwrap().contains("MethodInfo *"), "the trailing MethodInfo* is the thing a recovered signature always gets wrong");
    }

    #[test]
    fn missing_sections_are_fine_but_an_empty_file_is_refused() {
        let only_methods = r#"{"ScriptMethod":[{"Address":16,"Name":"A$$b"}]}"#;
        assert_eq!(parse(only_methods.as_bytes()).unwrap().symbols.len(), 1);

        let err = parse(br#"{"ScriptString":[{"Address":1,"Value":"x"}]}"#).unwrap_err();
        assert!(matches!(err, Il2CppError::Empty(_)), "{err}");
        assert!(err.to_string().contains("no named symbols"), "{err}");
    }

    #[test]
    fn a_utf8_bom_does_not_defeat_the_parse() {
        let with_bom = format!("\u{feff}{SAMPLE}");
        assert_eq!(parse(with_bom.as_bytes()).unwrap().counts.methods, 2, ".NET writes a BOM by default");
    }

    #[test]
    fn lowercase_field_names_are_accepted_too() {
        let alt = r#"{"scriptMethod":[{"address":32,"name":"Alt$$m","signature":"void x()"}]}"#;
        let p = parse(alt.as_bytes()).unwrap();
        assert_eq!(p.symbols[0].addr, 32);
        assert_eq!(p.symbols[0].name, "Alt$$m");
    }

    #[test]
    fn unnamed_entries_are_dropped_rather_than_indexed_as_blanks() {
        let blanks = r#"{"ScriptMethod":[{"Address":1,"Name":""},{"Address":2,"Name":"Real$$m"}]}"#;
        let p = parse(blanks.as_bytes()).unwrap();
        assert_eq!(p.symbols.len(), 1);
        assert_eq!(p.counts.methods, 2, "the count reports what the file held, the index holds what is usable");
    }

    #[test]
    fn a_non_json_file_is_refused_as_malformed() {
        assert!(matches!(parse(b"MZ\x90\x00"), Err(Il2CppError::Malformed(_))));
    }
}
