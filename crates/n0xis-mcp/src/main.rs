//! `n0xis-mcp` — stdio MCP server entry point. An MCP client (Claude Desktop,
//! an agent harness, ...) spawns this binary and speaks JSON-RPC over its
//! stdin/stdout; see [`n0xis_mcp`] for the tool set and design notes.

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    n0xis_mcp::serve_stdio().await
}
