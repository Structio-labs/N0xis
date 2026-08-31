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
