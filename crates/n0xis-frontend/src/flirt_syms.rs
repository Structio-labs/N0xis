// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`FlirtSymbols`] — a [`SymbolProvider`] backed by an [`n0xis_flirt::Db`]:
//! names a function by matching its **bytes** against a signature database, the
//! way another tool FLIRT / another tool FunctionID name the statically-linked CRT/STL that a
//! stripped release build otherwise leaves `sub_XXXX`.
//!
//! It reads a small window at the queried address and looks it up; a hit is a
//! [`SymKind::Function`] symbol at exactly that address (a signature matches a
//! *function start*, so it never mis-attributes an interior address). Chained
//! **below** the real symbol sources (exports, imports, an IL2CPP index), so a
//! genuine symbol always wins and FLIRT only fills the anonymous gaps.

use n0xis_contracts::{SymKind, Symbol, Va};
use n0xis_flirt::Db;
use n0xis_sources::{MemorySource, SymbolProvider};

/// The byte window read at a candidate function start to fingerprint it. Longer
/// than any single signature's pattern is expected to need; a short read near
/// the end of a section simply yields fewer bytes and still matches a short
/// pattern.
const WINDOW: usize = 128;

/// A signature-database symbol provider over a memory source.
pub struct FlirtSymbols<'a> {
    db: &'a Db,
    source: &'a dyn MemorySource,
    module: String,
    /// A stable identity for this database, so cached analysis artifacts do not
    /// serve names from a stale (or absent) database after it changes.
    fingerprint: String,
}

impl<'a> FlirtSymbols<'a> {
    /// `fingerprint` should identify *which* database this is (e.g. its file
    /// path + signature count) so the artifact cache invalidates when it changes.
    pub fn new(db: &'a Db, source: &'a dyn MemorySource, module: impl Into<String>, fingerprint: impl Into<String>) -> Self {
        FlirtSymbols { db, source, module: module.into(), fingerprint: fingerprint.into() }
    }
}

impl SymbolProvider for FlirtSymbols<'_> {
    fn symbol_at(&self, va: Va) -> Option<Symbol> {
        if self.db.is_empty() {
            return None;
        }
        let bytes = self.source.read(va, WINDOW).ok()?;
        let name = self.db.lookup(&bytes)?;
        Some(Symbol { va, module: self.module.clone(), name: name.to_string(), kind: SymKind::Function })
    }

    fn symbol_fingerprint(&self) -> String {
        self.fingerprint.clone()
    }
}

/// Load and merge a **chain of corpora** into one lookup, returning the database
/// and a fingerprint identifying it (so a cached artifact does not serve names
/// from a database that has since changed).
///
/// A path that cannot be read or parsed is skipped and named in the returned
/// warning list rather than failing the whole run: a triage pass over four
/// corpora should not abort because one is missing. `None` when nothing loaded.
///
/// Merging is sound without ordering rules — [`Db::lookup`] refuses a name when
/// two equally-specific signatures disagree, so a conflict between corpora
/// yields no name instead of whichever loaded first.
pub fn load_chain(paths: &[String]) -> (Option<(Db, String)>, Vec<String>) {
    let mut db = Db::new();
    let mut warnings = Vec::new();
    let mut loaded: Vec<String> = Vec::new();
    for path in paths {
        match std::fs::read_to_string(path) {
            Ok(text) => match db.extend_npat(&text) {
                Ok(()) => loaded.push(path.clone()),
                Err(e) => warnings.push(format!("parse {path}: {e}")),
            },
            Err(e) => warnings.push(format!("read {path}: {e}")),
        }
    }
    if loaded.is_empty() {
        return (None, warnings);
    }
    let fingerprint = format!("flirt:{}:{}", loaded.join(","), db.len());
    (Some((db, fingerprint)), warnings)
}

/// The paths a `flirt` argument names. Accepts a JSON array of strings, or a
/// single string holding one path — the CLI's repeatable `--flirt` becomes the
/// array form, while a hand-written capability call may pass just one.
pub fn paths_from_arg(v: Option<&serde_json::Value>) -> Vec<String> {
    match v {
        Some(serde_json::Value::Array(items)) => {
            items.iter().filter_map(|i| i.as_str()).map(str::to_string).collect()
        }
        Some(serde_json::Value::String(s)) if !s.is_empty() => vec![s.clone()],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_corpus_warns_instead_of_failing_the_chain() {
        let dir = std::env::temp_dir().join(format!("n0xis-flirt-chain-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.npat");
        std::fs::write(&good, "55 48 89 E5 41 57 zlib_deflate\n").unwrap();
        let missing = dir.join("nope.npat");

        let (db, warns) = load_chain(&[good.to_string_lossy().into(), missing.to_string_lossy().into()]);
        let (db, fp) = db.expect("the readable corpus still loads");
        assert_eq!(db.len(), 1);
        assert!(fp.contains("good.npat") && !fp.contains("nope.npat"), "fingerprint names only what loaded: {fp}");
        assert_eq!(warns.len(), 1, "the unreadable one is reported: {warns:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn nothing_loadable_yields_no_database() {
        let (db, warns) = load_chain(&["/nonexistent/a.npat".to_string()]);
        assert!(db.is_none());
        assert_eq!(warns.len(), 1);
        assert!(load_chain(&[]).0.is_none());
    }

    #[test]
    fn arg_accepts_both_a_list_and_a_lone_string() {
        use serde_json::json;
        assert_eq!(paths_from_arg(Some(&json!(["a.npat", "b.npat"]))), vec!["a.npat", "b.npat"]);
        assert_eq!(paths_from_arg(Some(&json!("a.npat"))), vec!["a.npat"]);
        assert!(paths_from_arg(Some(&json!(""))).is_empty());
        assert!(paths_from_arg(None).is_empty());
    }
}
