// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `n0xis-mcp` — stdio MCP server entry point. An MCP client (Claude Desktop,
//! an agent harness, ...) spawns this binary and speaks JSON-RPC over its
//! stdin/stdout; see [`n0xis_mcp`] for the tool set and design notes.
//!
//! With no arguments this is the parent ([`n0xis_mcp::supervisor`]), and the server
//! is a worker it starts, so that a query past the memory ceiling does not end the
//! client's session.

use n0xis_mcp::supervisor;

#[global_allocator]
static ALLOCATOR: n0xis_core::CeilingAlloc = n0xis_core::CeilingAlloc;

fn main() {
    // Before the server: `scripts/release.py` runs what it built, with nothing on standard input, and
    // this once answered that with `connection closed` and exit 1. Not a command, so no parser for it.
    let first = std::env::args_os().nth(1);
    if first.as_ref().is_some_and(|a| a == "--version") {
        println!("n0xis-mcp {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if first.as_ref().is_some_and(|a| a == supervisor::WORKER_ARG) {
        worker();
    }
    std::process::exit(supervisor::run());
}

/// The server proper, until the client's input closes. It does not return: a query
/// still running then would hold the runtime open past its parent, who may be gone.
fn worker() -> ! {
    let stated = std::env::var("N0X_MEMORY_MAX").ok().and_then(|v| n0xis_core::parse_memory_size(&v));
    n0xis_core::set_memory_ceiling(n0xis_sources::memory_ceiling(stated), |ceiling| {
        // Standard output is the protocol, and a request it answers is mid-flight. The
        // parent reads the exit code, and answers.
        eprintln!("n0xis-mcp: stopped: this run needs more memory than its ceiling of {} MiB", ceiling >> 20);
        std::process::exit(supervisor::EXIT_PAST_THE_CEILING);
    });
    n0xis_core::on_analysis_stack(|| {
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().thread_stack_size(n0xis_core::ANALYSIS_STACK_BYTES).build();
        let served = match &runtime {
            Ok(runtime) => runtime.block_on(n0xis_mcp::serve_stdio()),
            Err(e) => Err(anyhow::anyhow!("{e}")),
        };
        // With the runtime still here: dropping it waits for a query that is still running.
        match served {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("Error: {e:?}");
                std::process::exit(1)
            }
        }
    })
}
