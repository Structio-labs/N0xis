//! # n0xis-frontend — the shared frontend seam
//!
//! Everything a frontend must do *before* it can call a pass: turn
//! `--pid`/`--file`/`--snapshot`/`--remote-cmd`/`--bytes` into a source, pick
//! an ISA, and parse the address/size/byte-string arguments that every command
//! takes. None of it is analysis, all of it is identical for every frontend —
//! which is exactly why it belongs in one crate.
//!
//! Before this crate existed, `n0xis-cli` and `n0xis-mcp` each carried their
//! own copy of the source seam (`build_source` vs `source::resolve`), and the
//! copies had already drifted: the CLI never consulted the `.n0x/` session
//! default that `attach` writes, so `attach` then a bare `decomp pseudo`
//! worked through MCP and failed through the CLI, despite the docs promising
//! both. CONCEPT §3 rule 3 calls a contract duplicated across two sides a bug;
//! this is that bug's fix.
//!
//! ```text
//!   n0xis-cli ─┐
//!   n0xis-mcp ─┼─▶ n0xis-frontend ─▶ n0xis-pipeline ─▶ n0xis-core
//!   n0xis-hud ─┘   (source + arch + argument parsing)
//! ```
//!
//! Frontends stay free to differ where they genuinely differ (clap flags vs
//! JSON tool arguments, text vs structured output) — but never on what `--pid`
//! *means*.

pub mod arch;
pub mod flirt_syms;
pub mod il2cpp_caps;
pub mod method_caps;
pub mod parse;
pub mod project_caps;
pub mod registry;
pub mod source;

pub use arch::{pick_arch, resolve_arch};
pub use registry::{Capability, Origin, Plugin, Registry, build_registry};
pub use parse::{opt_hex, parse_hex_bytes, parse_hex_or_decimal_f64, parse_hex_or_decimal_u64, parse_hex_or_decimal_usize, strip_hex_marker};
pub use source::{FrontendError, ResolvedSource, SourceSpec, Src, base_for_module, load_snapshot, module_base_of, scan_range};
