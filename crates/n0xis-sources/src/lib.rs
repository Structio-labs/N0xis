//! # n0xis-sources — the source seam
//!
//! Replaces v0's `enum IrSource { Live, Static }` with traits. Whether bytes
//! come from a **live process**, a **static PE**, a cached **snapshot**, or a
//! **remote agent** stops being an `if` in the analysis — it becomes a choice
//! of adapter behind these traits. That is what lets the same SSA→opt→types
//! pipeline run byte-for-byte identically on a running game and a file on disk
//! (CONCEPT §5.1).
//!
//! Phase 1 ships only [`Snapshot`], a pure in-memory implementation with **no
//! OS dependency** — the test double the whole core is validated against. The
//! `LiveProcess` (Win32) and `StaticPe` (goblin) adapters arrive in Phase 2,
//! gated behind features so this crate stays OS-free by default.

mod snapshot;

pub use snapshot::{Snapshot, SnapshotBuilder};

use n0xis_contracts::{Module, Symbol, Va};

/// Something went wrong reading/writing a source.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("address {0} is not mapped in this source")]
    Unmapped(Va),
    #[error("this source is read-only (write not supported)")]
    ReadOnly,
    #[error("os error: {0}")]
    Os(String),
}

/// Byte-level access to an address space.
///
/// **Read semantics:** [`read`](MemorySource::read) returns *up to* `len` bytes
/// starting at `va`, truncated where the mapped region ends. It errors only
/// when `va` itself is unmapped. This matches how a live `ReadProcessMemory`
/// and a static section both behave at a boundary, and lets a disassembler ask
/// for a generous window without knowing the region size in advance. Callers
/// needing an exact count check the returned length.
pub trait MemorySource {
    fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, SourceError>;

    /// Is `va` backed by this source?
    fn contains(&self, va: Va) -> bool;

    /// Write bytes at `va`. Default: [`SourceError::ReadOnly`] — only live
    /// sources override this. `StaticPe`/`Snapshot` stay read-only.
    fn write(&self, _va: Va, _bytes: &[u8]) -> Result<(), SourceError> {
        Err(SourceError::ReadOnly)
    }

    /// Provenance label for `meta.source`, e.g. `"snapshot:test"`.
    fn label(&self) -> String;
}

/// Resolve symbols by address (exports, imports, IAT slots, recovered names).
pub trait SymbolProvider {
    fn symbol_at(&self, va: Va) -> Option<Symbol>;

    /// If `va` is an IAT slot, the imported symbol it resolves to.
    fn iat_slot(&self, _va: Va) -> Option<Symbol> {
        None
    }
}

/// Enumerate the modules mapped in an address space and locate an owner.
pub trait ModuleProvider {
    fn modules(&self) -> &[Module];

    fn owner_of(&self, va: Va) -> Option<&Module> {
        self.modules().iter().find(|m| m.contains(va))
    }
}
