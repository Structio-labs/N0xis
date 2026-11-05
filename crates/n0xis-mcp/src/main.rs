// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `n0xis-mcp` — stdio MCP server entry point. An MCP client (Claude Desktop,
//! an agent harness, ...) spawns this binary and speaks JSON-RPC over its
//! stdin/stdout; see [`n0xis_mcp`] for the tool set and design notes.

#[global_allocator]
static ALLOCATOR: n0xis_core::CeilingAlloc = n0xis_core::CeilingAlloc;

fn main() -> anyhow::Result<()> {
    let stated = std::env::var("N0X_MEMORY_MAX").ok().and_then(|v| n0xis_core::parse_memory_size(&v));
    n0xis_core::set_memory_ceiling(n0xis_sources::memory_ceiling(stated), |ceiling| {
        // Standard output is the protocol, and a request it answers is mid-flight.
        eprintln!("n0xis-mcp: stopped: this run needs more memory than its ceiling of {} MiB", ceiling >> 20);
    });
    n0xis_core::on_analysis_stack(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_stack_size(n0xis_core::ANALYSIS_STACK_BYTES)
            .build()?
            .block_on(n0xis_mcp::serve_stdio())
    })
}
