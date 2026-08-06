//! The MCP frontend's thin adaptation of the shared source seam.
//!
//! The resolution logic itself lives in [`n0xis_frontend::source`] — this file
//! used to be a second, hand-maintained copy of it, which is precisely the
//! duplicated contract CONCEPT §3 rule 3 calls a bug. What remains here is the
//! shape adaptation: MCP tool arguments arrive as four loose `Option`s, and
//! tool calls never carry an inline `bytes` source (an agent driving live
//! analysis always names a real target).

use n0xis_contracts::Va;
pub use n0xis_frontend::source::{FrontendError, Src};
use n0xis_frontend::source::{SourceSpec, resolve as resolve_spec};

/// Resolve a tool call's `pid`/`file`/`snapshot`/`remote_cmd` arguments,
/// falling back to the `.n0x/session.json` default recorded by `attach` when
/// all four are omitted.
pub fn resolve(pid: Option<u32>, file: Option<&str>, snapshot: Option<&str>, remote_cmd: Option<&str>) -> Result<Src, FrontendError> {
    resolve_spec(SourceSpec { pid, file, snapshot, remote_cmd, ..Default::default() }).map(|r| r.src)
}

/// Choose a scan `(start, size)`: explicit arguments win, else `default`
/// (typically the module's `.text`, or `.rdata` for a string-data window).
pub fn scan_range(default: Option<(Va, u64)>, explicit_start: Option<Va>, explicit_size: Option<usize>) -> Option<(Va, usize)> {
    n0xis_frontend::source::scan_range(default, None, explicit_start, explicit_size)
}
