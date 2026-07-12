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

mod remote;

pub use remote::{RemoteAgent, serve_stdio as remote_serve_stdio, split_command_line};

#[cfg(feature = "static-pe")]
mod static_pe;
#[cfg(feature = "static-pe")]
pub use static_pe::StaticPe;

#[cfg(feature = "live")]
mod live;
#[cfg(feature = "live")]
pub use live::{LiveProcess, MemRegion, ProcInfo, list_processes};

#[cfg(feature = "live")]
mod debug;
#[cfg(feature = "live")]
pub use debug::{AwaitHitOutcome, BreakpointHit, Registers, WatchKind, await_breakpoint_hit, await_watchpoint_hit};

#[cfg(feature = "live")]
mod unwind;
#[cfg(feature = "live")]
pub use unwind::{Frame, MemReader, ModuleRange, UnwindRegs, unwind};

use n0xis_contracts::{Module, Symbol, Va};

/// Something went wrong reading/writing a source.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("address {0} is not mapped in this source")]
    Unmapped(Va),
    #[error("this source is read-only (write not supported)")]
    ReadOnly,
    #[error("failed to load source: {0}")]
    Load(String),
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

    /// Executable code extent `(start, size)`, when the source knows it (a
    /// PE's `.text`, a live module's code section). Lets passes tell code from
    /// data through the seam — e.g. the switch resolver rejects jump-table
    /// entries that don't land in code. Default `None`: unknown, so callers
    /// fall back to [`contains`](MemorySource::contains).
    fn code_range(&self) -> Option<(Va, u64)> {
        None
    }

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
