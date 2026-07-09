//! # n0xis-contracts
//!
//! The **single source of truth** for everything that crosses a boundary in
//! N0xis: wire schemas (the `ok/data/meta` envelope), schema identifiers, and
//! the shared value types (`Va`, `Reg`, `Symbol`, `Module`).
//!
//! This crate depends on **nothing but `serde`**. It is the base of the graph in
//! [`CONCEPT.md`](../../../CONCEPT.md) §4 — every other crate depends on it, and
//! it depends on none of them. A type or constant duplicated across two sides of
//! a boundary is a bug: it belongs here.
//!
//! ## Project law (CONCEPT §3) enforced here
//! - **Single source of truth** — schemas + shared types live only here.
//! - **Anti-hardcode** — the tool name, version, and every schema id are named
//!   constants ([`schema`], [`TOOL`], [`tool_version`]), never inline literals.

pub mod envelope;
pub mod schema;
pub mod table;
pub mod types;

pub use envelope::{ErrorBody, Failure, Meta, Response, Success};
pub use table::{Provenance, Table, TableEntry, TableLocator, TableValueType, VerificationState};
pub use types::{Module, Reg, SymKind, Symbol, Va};

/// Brand token used in every `meta.tool` field. See naming policy in CONCEPT §12.
pub const TOOL: &str = "n0xis";

/// Version of the contracts crate — the wire-compat anchor for agents.
pub fn tool_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
