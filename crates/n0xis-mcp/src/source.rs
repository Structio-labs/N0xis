// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The MCP frontend's thin adaptation of the shared source seam.
//!
//! The resolution logic itself lives in [`n0xis_frontend::source`] — this file
//! used to be a second, hand-maintained copy of it, which is precisely the
//! duplicated contract CONCEPT §3 rule 3 calls a bug. What remains here is the
//! shape adaptation: MCP tool arguments arrive as four loose `Option`s, and
//! tool calls never carry an inline `bytes` source (an agent driving live
//! analysis always names a real target).

pub use n0xis_frontend::source::{FrontendError, Src};
use n0xis_frontend::source::{SourceSpec, resolve as resolve_spec};

/// Resolve a tool call's `pid`/`file`/`snapshot`/`remote_cmd` arguments,
/// falling back to the `.n0x/session.json` default recorded by `attach` when
/// all four are omitted.
pub fn resolve(pid: Option<u32>, file: Option<&str>, snapshot: Option<&str>, remote_cmd: Option<&str>) -> Result<Src, FrontendError> {
    resolve_spec(SourceSpec { pid, file, snapshot, remote_cmd, ..Default::default() }).map(|r| r.src)
}
