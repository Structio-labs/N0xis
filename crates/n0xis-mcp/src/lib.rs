//! # n0xis-mcp — the agent-native frontend (Phase 5)
//!
//! An MCP (Model Context Protocol) server exposing the same
//! `n0xis-core`/`n0xis-sources` capabilities the CLI drives, as MCP tools
//! returning the **same `ok/data/meta` envelope and schema ids** as
//! `n0xis-cli` (CONCEPT §3 rule 5 — CLI and MCP are equal frontends, no
//! analysis logic lives in either). An agent parses a tool's JSON content the
//! same way whether it called the CLI or MCP.
//!
//! Built on the official [`rmcp`] SDK's macro-based server pattern
//! (`#[tool_router]` / `#[tool_handler]`) over stdio transport. Tool argument
//! resolution (`pid`/`file` → a live/static source) lives in [`source`] — a
//! scoped-down sibling of the CLI's `build_source`, not a shared crate, since
//! `n0xis-cli` is a binary (no lib target to depend on); worth hoisting into
//! `n0xis-pipeline` if a third frontend ever needs the same seam (CONCEPT's
//! single-source-of-truth rule, applied when the duplication actually bites,
//! not preemptively).
//!
//! **Session/attach state is shared with the CLI** via `n0xis-project`'s
//! `session` module (`.n0x/session.json`): calling `attach` here writes it, so
//! a later tool call can omit `pid`/`file`, and the CLI reads the same file if
//! pointed at the same `.n0x/` project.
//!
//! **Scope of this pass**: the tool set below covers the Phase 5 exit test
//! (attach → discover → decompile → explain, end-to-end through MCP only)
//! plus the core read-only RE workflow (process/module inspection, disasm,
//! xrefs, memory read/write, provenance). Stateful multi-call
//! workflows that need cross-call state on the CLI side today (`scan
//! value`/`scan filter`, `.n0xt` tables, `patch`/`debug watch`) are a
//! documented follow-on: an MCP server is a long-lived process, so they
//! deserve in-memory session state rather than a straight port of the CLI's
//! file-based bridging — a separate design decision from wiring the
//! transport up in the first place.

pub mod source;
mod tools;

pub use n0xis_contracts as contracts;
pub use n0xis_core as core;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, ServiceExt, tool_handler};

/// The N0xis MCP server. Stateless in memory beyond what `.n0x/session.json`
/// persists on disk — every tool call re-resolves its own source, matching
/// the CLI's "fresh process per call" semantics even though this process
/// itself stays up across calls.
#[derive(Clone, Default)]
pub struct N0xisServer {
    tool_router: ToolRouter<Self>,
}

impl N0xisServer {
    pub fn new() -> Self {
        Self { tool_router: Self::tool_router() }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for N0xisServer {
    fn get_info(&self) -> ServerInfo {
        // `ServerInfo::new` fills `server_info` via `Implementation::from_build_env()`,
        // whose `env!("CARGO_CRATE_NAME")` expands *inside rmcp* — so the default
        // announces the SDK ("rmcp" 2.2.0) rather than this server. Declare ours.
        let mut info =
            ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "N0xis: reverse-engineering and live-memory toolkit. Tools mirror the `n0xis` CLI's \
             verbs and return the identical `{ok,data,meta}` envelope (meta.schema names the \
             payload shape). Typical flow: `attach` (pid or file) to set the session default, \
             `function_discover` to find candidates, `decomp_pseudo` to decompile one, \
             `explain_opt_delta` or `provenance_trace` to see *why* the decompiler produced \
             what it did.",
        );
        info.server_info = Implementation::new("n0xis", env!("CARGO_PKG_VERSION"));
        info
    }
}

/// Run the server over stdio until the client disconnects.
pub async fn serve_stdio() -> anyhow::Result<()> {
    let server = N0xisServer::new().serve(rmcp::transport::stdio()).await?;
    server.waiting().await?;
    Ok(())
}
