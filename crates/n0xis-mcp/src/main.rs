// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `n0xis-mcp` — stdio MCP server entry point. An MCP client (Claude Desktop,
//! an agent harness, ...) spawns this binary and speaks JSON-RPC over its
//! stdin/stdout; see [`n0xis_mcp`] for the tool set and design notes.

fn main() -> anyhow::Result<()> {
    n0xis_core::on_analysis_stack(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_stack_size(n0xis_core::ANALYSIS_STACK_BYTES)
            .build()?
            .block_on(n0xis_mcp::serve_stdio())
    })
}
