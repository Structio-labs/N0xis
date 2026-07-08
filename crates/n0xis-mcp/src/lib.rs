//! # n0xis-mcp — the agent-native frontend (Phase 5)
//!
//! **Placeholder.** N0xis's biggest capability is exposing the *same*
//! pipeline the CLI drives as MCP tools that return the *same* versioned
//! schemas, plus "explain" tools that surface the decompiler's reasoning
//! (`n0xis.opt.delta.v1`, SSA) to an agent (CONCEPT §4, ROADMAP Phase 5).
//!
//! The crate exists now so the workspace graph matches CONCEPT §4 and the
//! boundary is reserved; the server lands once the core API stabilizes after
//! Phase 3. It intentionally pulls in no MCP SDK yet.

/// Tools this server will expose, mirroring the CLI verbs. Declared as a
/// manifest now so the CLI↔MCP parity contract is written down from day one.
pub const PLANNED_TOOLS: &[&str] = &[
    "doctor",
    "guide",
    "disasm",
    "decode",
    // Phase 2+: ir_build, decomp_pseudo, xref, function_discover, mem_read,
    // scan_value, pointer_scan, aob_scan, provenance, explain_opt_delta, ...
];

/// Phase 5 entry point — not yet implemented.
pub fn serve() -> Result<(), &'static str> {
    Err("n0xis-mcp: MCP server is scheduled for ROADMAP Phase 5")
}
