//! # n0xis — CLI frontend
//!
//! A thin clap frontend over `n0xis-pipeline`. It parses arguments, calls the
//! pipeline, and prints the `ok/data/meta` envelope from `n0xis-contracts`.
//! **No analysis logic lives here** — the CLI is one of two equal frontends
//! (the other is `n0xis-mcp`), both over the same core API (CONCEPT §3 rule 5).
//!
//! Phase 1 surface: `doctor`, `guide`, `init`, `project info`, and a `disasm`
//! demo (`--bytes`) that drives the full source→arch→pass pipeline with no OS
//! code. `--pid` / `--file` sources are reserved and return a Phase-2 error so
//! the v0 command shape is preserved without pretending to implement it yet.

mod emit;

use clap::{Args, Parser, Subcommand};
use n0xis_arch::X64;
use n0xis_contracts::{Response, Va, schema};
use n0xis_pipeline::Pipeline;
use n0xis_sources::Snapshot;
use serde_json::json;

use emit::emit;

/// N0xis — reverse-engineering and live-memory toolkit.
#[derive(Parser)]
#[command(name = "n0xis", version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    global: GlobalArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct GlobalArgs {
    /// Strict JSON-only stdout (this is the default; kept for compatibility).
    #[arg(long, global = true)]
    json: bool,
    /// Pretty-print the JSON envelope.
    #[arg(long, global = true)]
    pretty: bool,
    /// Suppress `[n0x]` stderr progress (stdout stays machine-parseable).
    #[arg(long, global = true)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Environment / readiness check.
    Doctor,
    /// Built-in quick reference.
    Guide,
    /// Create a `.n0x/` project (config, dirs, `n0x.cmd` shim).
    Init(InitArgs),
    /// Project introspection.
    #[command(subcommand)]
    Project(ProjectCmd),
    /// Linear disassembly.
    Disasm(DisasmArgs),
}

#[derive(Args)]
struct InitArgs {
    /// Directory to initialize (defaults to cwd).
    #[arg(long)]
    dir: Option<String>,
    /// Human-readable project name (defaults to the directory name).
    #[arg(long)]
    name: Option<String>,
    /// Override the bound core binary path baked into the shim.
    #[arg(long)]
    core: Option<String>,
}

#[derive(Subcommand)]
enum ProjectCmd {
    /// Show the resolved project root, config, and storage paths.
    Info,
}

#[derive(Args)]
struct DisasmArgs {
    /// Start address (hex `0x…`, `…h`, or decimal).
    #[arg(long)]
    addr: String,
    /// Number of instructions to decode.
    #[arg(long, default_value_t = 20)]
    count: usize,
    /// Raw bytes to disassemble, e.g. "48 89 c8 c3" (Phase-1 source).
    #[arg(long)]
    bytes: Option<String>,
    /// Live process id (Phase 2 — reserved).
    #[arg(long)]
    pid: Option<u32>,
    /// PE file on disk (Phase 2 — reserved).
    #[arg(long)]
    file: Option<String>,
}

fn main() {
    let cli = Cli::parse();
    let pretty = cli.global.pretty;
    let ok = match cli.command {
        Command::Doctor => cmd_doctor(pretty),
        Command::Guide => cmd_guide(pretty),
        Command::Init(a) => cmd_init(a, pretty),
        Command::Project(ProjectCmd::Info) => cmd_project_info(pretty),
        Command::Disasm(a) => cmd_disasm(a, pretty),
    };
    // Non-zero exit when the response is a failure, so scripts can branch on it.
    if !ok {
        std::process::exit(2);
    }
}

fn cmd_doctor(pretty: bool) -> bool {
    let arch = X64::new();
    let project = n0xis_project::resolve();
    let (proj_ok, proj_dir, proj_local) = match &project {
        Ok(p) => (true, p.dir.display().to_string(), p.is_local),
        Err(_) => (false, String::new(), false),
    };
    let data = json!({
        "status": "ready",
        "checks": {
            "arch_x64": { "ok": true, "name": <X64 as n0xis_arch::Arch>::name(&arch) },
            "decoder": { "ok": true, "engine": "iced-x86" },
            "project_resolves": { "ok": proj_ok, "dir": proj_dir, "local": proj_local },
        },
        "phase": "1 — workspace skeleton & seams",
        "note": "live-process / static-PE sources arrive in Phase 2",
    });
    emit(&Response::success(schema::v1::DOCTOR, data), pretty)
}

fn cmd_guide(pretty: bool) -> bool {
    let data = json!({
        "tool": "n0xis",
        "tagline": "reverse-engineering — static + live, contract-first, GUI-never.",
        "phase": "1",
        "commands": {
            "doctor": "environment / readiness check",
            "guide": "this quick reference",
            "init": "create a .n0x/ project",
            "project info": "resolved project paths & config",
            "disasm --addr <hex> --bytes \"<hex>\" [--count N]": "linear disassembly (Phase 1 uses --bytes)",
        },
        "reserved": {
            "disasm --pid/--file": "live & static sources — Phase 2",
            "ir / decomp / xref / scan / table": "ported & built across Phases 2–4",
        },
        "envelope": "every command emits { ok, data, meta } or { ok:false, error }",
        "docs": ["CONCEPT.md", "ROADMAP.md", "docs/KILLER_FEATURES.md"],
    });
    emit(&Response::success(schema::v1::GUIDE, data), pretty)
}

fn cmd_init(a: InitArgs, pretty: bool) -> bool {
    let dir = a.dir.as_ref().map(std::path::Path::new);
    match n0xis_project::init(dir, a.name, a.core) {
        Ok(report) => {
            let data = json!({
                "dir": report.dir.display().to_string(),
                "already_existed": report.already_existed,
                "wrote_config": report.wrote_config,
                "wrote_shim": report.wrote_shim,
                "core_path": report.core_path,
            });
            emit(&Response::success(schema::v1::PROJECT_INIT, data), pretty)
        }
        Err(e) => emit(
            &Response::<serde_json::Value>::error("init-failed", e.to_string()),
            pretty,
        ),
    }
}

fn cmd_project_info(pretty: bool) -> bool {
    match n0xis_project::resolve() {
        Ok(root) => {
            let config = n0xis_project::load_config(&root).ok().flatten();
            let data = json!({
                "dir": root.dir.display().to_string(),
                "is_local": root.is_local,
                "paths": {
                    "project_toml": root.project_toml_path().display().to_string(),
                    "session": root.session_path().display().to_string(),
                    "selections": root.selections_path().display().to_string(),
                    "dumps": root.dumps_dir().display().to_string(),
                    "tables": root.tables_dir().display().to_string(),
                    "shim": root.shim_path().display().to_string(),
                },
                "config": config.map(|c| json!({
                    "name": c.name,
                    "core_path": c.core_path,
                    "created_at": c.created_at,
                    "targets": c.targets.len(),
                })),
            });
            emit(&Response::success(schema::v1::PROJECT_INFO, data), pretty)
        }
        Err(e) => emit(
            &Response::<serde_json::Value>::error("project-unresolved", e.to_string()),
            pretty,
        ),
    }
}

fn cmd_disasm(a: DisasmArgs, pretty: bool) -> bool {
    if a.pid.is_some() || a.file.is_some() {
        return emit(
            &Response::<serde_json::Value>::error(
                "source-not-implemented",
                "live (--pid) and static-PE (--file) sources are not yet implemented",
            )
            .with_hint("Phase 1 supports --bytes; --pid/--file land in Phase 2 (see ROADMAP.md)"),
            pretty,
        );
    }
    let Some(bytes_str) = a.bytes else {
        return emit(
            &Response::<serde_json::Value>::error(
                "missing-source",
                "provide --bytes \"<hex>\" (Phase 1) — or --pid/--file once implemented",
            ),
            pretty,
        );
    };
    let start = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => {
            return emit(
                &Response::<serde_json::Value>::error("bad-addr", e.to_string()),
                pretty,
            );
        }
    };
    let bytes = match parse_hex_bytes(&bytes_str) {
        Ok(b) => b,
        Err(e) => {
            return emit(&Response::<serde_json::Value>::error("bad-bytes", e), pretty);
        }
    };

    let label = format!("bytes:{}@{}", bytes.len(), start);
    let snap = Snapshot::builder()
        .region(start, bytes)
        .label(label.clone())
        .build();
    let arch = X64::new();
    let pipe = Pipeline::new(&snap, &arch);

    match pipe.disassemble(start, a.count) {
        Ok(out) => emit(
            &Response::success(schema::v1::DECODE, out).with_source(label),
            pretty,
        ),
        Err(e) => emit(
            &Response::<serde_json::Value>::error("decode-failed", e.to_string()),
            pretty,
        ),
    }
}

/// Parse a hex byte string: accepts spaces, commas and `0x` prefixes, e.g.
/// `"48 89 c8"`, `"4889c8"`, or `"0x48,0x89,0xc8"`.
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .replace("0x", " ")
        .replace("0X", " ")
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || c.is_whitespace() || *c == ',')
        .collect();
    let tokens: Vec<&str> = cleaned.split([' ', ',', '\t', '\n']).filter(|t| !t.is_empty()).collect();

    let mut out = Vec::new();
    if tokens.iter().all(|t| t.len() <= 2) && !tokens.is_empty() {
        // Token-per-byte form ("48 89 c8").
        for t in tokens {
            out.push(u8::from_str_radix(t, 16).map_err(|_| format!("invalid byte: {t:?}"))?);
        }
    } else {
        // Contiguous form ("4889c8") — join and split into pairs.
        let joined: String = tokens.concat();
        if !joined.len().is_multiple_of(2) {
            return Err("odd number of hex digits".to_string());
        }
        let mut i = 0;
        while i < joined.len() {
            let pair = &joined[i..i + 2];
            out.push(u8::from_str_radix(pair, 16).map_err(|_| format!("invalid byte: {pair:?}"))?);
            i += 2;
        }
    }
    if out.is_empty() {
        return Err("no bytes provided".to_string());
    }
    Ok(out)
}
