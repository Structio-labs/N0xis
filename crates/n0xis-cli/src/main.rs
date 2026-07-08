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
use n0xis_core::{
    CfgInput, CfgPass, Ctx, DiscoverInput, DiscoverPass, Pass, XrefDir, XrefInput, XrefPass,
};
use n0xis_pipeline::Pipeline;
use n0xis_sources::{LiveProcess, MemorySource, Snapshot, StaticPe, list_processes};
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
    /// Live process inspection.
    #[command(subcommand)]
    Process(ProcessCmd),
    /// Module inspection (live process or static PE).
    #[command(subcommand)]
    Module(ModuleCmd),
    /// Linear disassembly.
    Disasm(DisasmArgs),
    /// Intermediate representation (CFG + block/def-use).
    #[command(subcommand)]
    Ir(IrCmd),
    /// Function-level analysis.
    #[command(subcommand)]
    Function(FunctionCmd),
    /// Cross-references.
    #[command(subcommand)]
    Xref(XrefCmd),
}

#[derive(Subcommand)]
enum FunctionCmd {
    /// Discover functions by prologue scanning (`.text` by default).
    Discover(DiscoverArgs),
}

#[derive(Args)]
struct DiscoverArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Inline bytes source; requires `--start` for the base address.
    #[arg(long)]
    bytes: Option<String>,
    /// Scan range start (defaults to the module's `.text`).
    #[arg(long)]
    start: Option<String>,
    /// Scan range size in bytes (defaults to the `.text` size).
    #[arg(long)]
    size: Option<usize>,
    #[arg(long, default_value_t = 200)]
    limit: usize,
}

#[derive(Subcommand)]
enum XrefCmd {
    /// Who references `--addr`.
    To(XrefArgs),
    /// What `--addr` references.
    From(XrefArgs),
}

#[derive(Args)]
struct XrefArgs {
    /// The address of interest.
    #[arg(long)]
    addr: String,
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    #[arg(long)]
    bytes: Option<String>,
    /// Code window start to scan (defaults to the module's `.text`).
    #[arg(long)]
    start: Option<String>,
    /// Code window size (defaults to the `.text` size).
    #[arg(long)]
    size: Option<usize>,
}

#[derive(Subcommand)]
enum IrCmd {
    /// Build the CFG + block/def-use IR artifact.
    Build(IrArgs),
    /// Human-readable IR summary.
    Explain(IrArgs),
}

#[derive(Args)]
struct IrArgs {
    /// Function start address (hex `0x…`, `…h`, or decimal).
    #[arg(long)]
    addr: String,
    /// Byte window to analyze (the function's max extent).
    #[arg(long, default_value_t = 4096)]
    size: usize,
    /// Disable auto end-of-function detection (decode the whole window).
    #[arg(long)]
    no_auto_end: bool,
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Inline bytes source, e.g. "48 89 c8 c3".
    #[arg(long)]
    bytes: Option<String>,
}

#[derive(Subcommand)]
enum ModuleCmd {
    /// List modules of a live process (`--pid`) or a single PE (`--file`).
    List(ModuleListArgs),
}

#[derive(Args)]
struct ModuleListArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Case-insensitive substring filter on the module name.
    #[arg(long)]
    filter: Option<String>,
}

#[derive(Subcommand)]
enum ProcessCmd {
    /// List running processes.
    Ps(PsArgs),
}

#[derive(Args)]
struct PsArgs {
    /// Case-insensitive substring filter on the process name.
    #[arg(long)]
    filter: Option<String>,
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
        Command::Process(ProcessCmd::Ps(a)) => cmd_process_ps(a, pretty),
        Command::Module(ModuleCmd::List(a)) => cmd_module_list(a, pretty),
        Command::Disasm(a) => cmd_disasm(a, pretty),
        Command::Ir(IrCmd::Build(a)) => cmd_ir(a, false, pretty),
        Command::Ir(IrCmd::Explain(a)) => cmd_ir(a, true, pretty),
        Command::Function(FunctionCmd::Discover(a)) => cmd_discover(a, pretty),
        Command::Xref(XrefCmd::To(a)) => cmd_xref(a, XrefDir::To, pretty),
        Command::Xref(XrefCmd::From(a)) => cmd_xref(a, XrefDir::From, pretty),
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

fn cmd_process_ps(a: PsArgs, pretty: bool) -> bool {
    match list_processes() {
        Ok(mut procs) => {
            if let Some(f) = a.filter.as_deref() {
                let needle = f.to_lowercase();
                procs.retain(|p| p.name.to_lowercase().contains(&needle));
            }
            procs.sort_by_key(|p| p.name.to_lowercase());
            let list: Vec<_> = procs
                .iter()
                .map(|p| json!({ "pid": p.pid, "name": p.name }))
                .collect();
            let data = json!({ "count": list.len(), "processes": list });
            emit(&Response::success(schema::v1::PROCESS_PS, data), pretty)
        }
        Err(e) => emit(
            &Response::<serde_json::Value>::error("ps-failed", e.to_string()),
            pretty,
        ),
    }
}

fn cmd_ir(a: IrArgs, explain_mode: bool, pretty: bool) -> bool {
    let start = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => {
            return emit(
                &Response::<serde_json::Value>::error("bad-addr", e.to_string()),
                pretty,
            );
        }
    };
    let arch = X64::new();
    let auto_end = !a.no_auto_end;

    // Each source is built, wired into a Ctx (with symbols where the adapter
    // provides them), and run through the one CfgPass — the seam in action.
    if let Some(pid) = a.pid {
        let live = match LiveProcess::attach(pid) {
            Ok(l) => l,
            Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
        };
        let ctx = Ctx::new(&live, &arch);
        return finish_ir(&ctx, start, a.size, auto_end, explain_mode, live.label(), pretty);
    }
    if let Some(file) = a.file.as_deref() {
        let pe = match StaticPe::load(std::path::Path::new(file)) {
            Ok(p) => p,
            Err(e) => return ir_err("load-failed", &e.to_string(), pretty),
        };
        // StaticPe is also a SymbolProvider + ModuleProvider — feed the seams so
        // call targets resolve to names.
        let ctx = Ctx::new(&pe, &arch).with_symbols(&pe).with_modules(&pe);
        return finish_ir(&ctx, start, a.size, auto_end, explain_mode, pe.label(), pretty);
    }
    let Some(bytes_str) = a.bytes else {
        return ir_err("missing-source", "provide --pid, --file, or --bytes", pretty);
    };
    let bytes = match parse_hex_bytes(&bytes_str) {
        Ok(b) => b,
        Err(e) => return ir_err("bad-bytes", &e, pretty),
    };
    let snap = Snapshot::builder()
        .region(start, bytes)
        .label(format!("bytes@{start}"))
        .build();
    let ctx = Ctx::new(&snap, &arch);
    finish_ir(&ctx, start, a.size, auto_end, explain_mode, snap.label(), pretty)
}

fn ir_err(code: &str, msg: &str, pretty: bool) -> bool {
    emit(&Response::<serde_json::Value>::error(code, msg), pretty)
}

fn opt_hex(s: &Option<String>) -> Result<Option<Va>, String> {
    s.as_deref().map(Va::parse).transpose().map_err(|e| e.to_string())
}

/// A resolved analysis source. Kept as an enum so the range-resolution and
/// symbol wiring can differ per adapter while the passes stay uniform.
enum Src {
    Live(Box<LiveProcess>),
    Static(Box<StaticPe>),
    Snap(Snapshot),
}

/// Resolve `--pid` / `--file` / `--bytes` into a source. Returns the source, a
/// provenance label, and (for inline bytes) the mapped region length.
fn build_source(
    pid: Option<u32>,
    file: Option<&str>,
    bytes: Option<&str>,
    bytes_base: Va,
) -> Result<(Src, String, Option<usize>), (String, String)> {
    if let Some(pid) = pid {
        let live = LiveProcess::attach(pid).map_err(|e| ("attach-failed".into(), e.to_string()))?;
        let label = live.label();
        return Ok((Src::Live(Box::new(live)), label, None));
    }
    if let Some(file) = file {
        let pe = StaticPe::load(std::path::Path::new(file))
            .map_err(|e| ("load-failed".into(), e.to_string()))?;
        let label = pe.label();
        return Ok((Src::Static(Box::new(pe)), label, None));
    }
    if let Some(b) = bytes {
        let parsed = parse_hex_bytes(b).map_err(|e| ("bad-bytes".into(), e))?;
        let len = parsed.len();
        let snap = Snapshot::builder()
            .region(bytes_base, parsed)
            .label(format!("bytes@{bytes_base}"))
            .build();
        let label = snap.label();
        return Ok((Src::Snap(snap), label, Some(len)));
    }
    Err(("missing-source".into(), "provide --pid, --file, or --bytes".into()))
}

/// Choose a scan `(start, size)`: explicit flags win, else the module's `.text`,
/// else the inline region.
fn scan_range(
    default_text: Option<(Va, u64)>,
    region_len: Option<usize>,
    explicit_start: Option<Va>,
    explicit_size: Option<usize>,
    fallback_start: Va,
) -> (Va, usize) {
    let start = explicit_start
        .or(default_text.map(|d| d.0))
        .unwrap_or(fallback_start);
    let size = explicit_size
        .or(default_text.map(|d| d.1 as usize))
        .or(region_len)
        .unwrap_or(0);
    (start, size)
}

fn finish_ir(
    ctx: &Ctx,
    start: Va,
    size: usize,
    auto_end: bool,
    explain_mode: bool,
    label: String,
    pretty: bool,
) -> bool {
    let input = CfgInput {
        start,
        max_bytes: size,
        auto_end,
    };
    match CfgPass.run(ctx, input) {
        Ok(art) => {
            if explain_mode {
                let lines = n0xis_core::explain(&art);
                emit(
                    &Response::success(schema::v1::IR_EXPLAIN, json!({ "lines": lines }))
                        .with_source(label),
                    pretty,
                )
            } else {
                emit(
                    &Response::success(schema::v1::IR_CFG, art).with_source(label),
                    pretty,
                )
            }
        }
        Err(e) => ir_err("ir-failed", &e.to_string(), pretty),
    }
}

fn cmd_discover(a: DiscoverArgs, pretty: bool) -> bool {
    let explicit_start = match opt_hex(&a.start) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e, pretty),
    };
    let bytes_base = explicit_start.unwrap_or(Va(0));
    let (src, label, region_len) =
        match build_source(a.pid, a.file.as_deref(), a.bytes.as_deref(), bytes_base) {
            Ok(x) => x,
            Err((c, m)) => return ir_err(&c, &m, pretty),
        };
    let arch = X64::new();
    let default_text = match &src {
        Src::Static(pe) => pe.text_range(),
        Src::Live(l) => l.text_range(),
        Src::Snap(_) => None,
    };
    let (start, size) = scan_range(default_text, region_len, explicit_start, a.size, bytes_base);
    if size == 0 {
        return ir_err("no-range", "could not resolve a scan range; pass --start and --size", pretty);
    }

    let run = |ctx: &Ctx| -> bool {
        match DiscoverPass.run(ctx, DiscoverInput { start, size, limit: a.limit }) {
            Ok(art) => emit(
                &Response::success(schema::v1::FUNCTION_DISCOVER, art).with_source(label.clone()),
                pretty,
            ),
            Err(e) => ir_err("discover-failed", &e.to_string(), pretty),
        }
    };
    match &src {
        Src::Static(pe) => run(&Ctx::new(pe.as_ref(), &arch).with_symbols(pe.as_ref())),
        Src::Live(l) => run(&Ctx::new(l.as_ref(), &arch)),
        Src::Snap(s) => run(&Ctx::new(s, &arch)),
    }
}

fn cmd_xref(a: XrefArgs, dir: XrefDir, pretty: bool) -> bool {
    let addr = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let explicit_start = match opt_hex(&a.start) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e, pretty),
    };
    let bytes_base = explicit_start.unwrap_or(Va(0));
    let (src, label, region_len) =
        match build_source(a.pid, a.file.as_deref(), a.bytes.as_deref(), bytes_base) {
            Ok(x) => x,
            Err((c, m)) => return ir_err(&c, &m, pretty),
        };
    let arch = X64::new();
    let default_text = match &src {
        Src::Static(pe) => pe.text_range(),
        Src::Live(l) => l.text_range(),
        Src::Snap(_) => None,
    };
    let (scan_start, size) =
        scan_range(default_text, region_len, explicit_start, a.size, bytes_base);
    if size == 0 {
        return ir_err("no-range", "could not resolve a scan range; pass --start and --size", pretty);
    }

    let run = |ctx: &Ctx| -> bool {
        match XrefPass.run(ctx, XrefInput { scan_start, size, addr, dir }) {
            Ok(art) => emit(
                &Response::success(schema::v1::XREF, art).with_source(label.clone()),
                pretty,
            ),
            Err(e) => ir_err("xref-failed", &e.to_string(), pretty),
        }
    };
    match &src {
        Src::Static(pe) => run(&Ctx::new(pe.as_ref(), &arch).with_symbols(pe.as_ref())),
        Src::Live(l) => run(&Ctx::new(l.as_ref(), &arch)),
        Src::Snap(s) => run(&Ctx::new(s, &arch)),
    }
}

fn cmd_module_list(a: ModuleListArgs, pretty: bool) -> bool {
    use n0xis_contracts::Module;
    use n0xis_sources::ModuleProvider;

    let mut modules: Vec<Module> = if let Some(pid) = a.pid {
        match LiveProcess::attach(pid) {
            Ok(l) => l.modules().to_vec(),
            Err(e) => {
                return emit(
                    &Response::<serde_json::Value>::error("attach-failed", e.to_string()),
                    pretty,
                );
            }
        }
    } else if let Some(file) = a.file.as_deref() {
        match StaticPe::load(std::path::Path::new(file)) {
            Ok(pe) => pe.modules().to_vec(),
            Err(e) => {
                return emit(
                    &Response::<serde_json::Value>::error("load-failed", e.to_string()),
                    pretty,
                );
            }
        }
    } else {
        return emit(
            &Response::<serde_json::Value>::error("missing-source", "provide --pid or --file"),
            pretty,
        );
    };

    if let Some(f) = a.filter.as_deref() {
        let needle = f.to_lowercase();
        modules.retain(|m| m.name.to_lowercase().contains(&needle));
    }
    let modules_v = serde_json::to_value(&modules).unwrap_or(serde_json::Value::Null);
    let data = json!({ "count": modules.len(), "modules": modules_v });
    emit(&Response::success(schema::v1::MODULE_LIST, data), pretty)
}

fn cmd_disasm(a: DisasmArgs, pretty: bool) -> bool {
    let start = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => {
            return emit(
                &Response::<serde_json::Value>::error("bad-addr", e.to_string()),
                pretty,
            );
        }
    };

    // Source selection: --pid (live) XOR --file (static PE) XOR --bytes (inline).
    if let Some(pid) = a.pid {
        let live = match LiveProcess::attach(pid) {
            Ok(l) => l,
            Err(e) => {
                return emit(
                    &Response::<serde_json::Value>::error("attach-failed", e.to_string()),
                    pretty,
                );
            }
        };
        if !live.contains(start) {
            return emit(
                &Response::<serde_json::Value>::error(
                    "addr-not-committed",
                    format!("{start} is not a committed/readable region in pid {pid}"),
                )
                .with_hint("use a runtime VA (respecting ASLR); `n0xis process ps` finds the pid"),
                pretty,
            );
        }
        return run_disasm(&live, start, a.count, pretty);
    }

    if let Some(file) = a.file.as_deref() {
        let pe = match StaticPe::load(std::path::Path::new(file)) {
            Ok(pe) => pe,
            Err(e) => {
                return emit(
                    &Response::<serde_json::Value>::error("load-failed", e.to_string()),
                    pretty,
                );
            }
        };
        if !pe.contains(start) {
            return emit(
                &Response::<serde_json::Value>::error(
                    "addr-out-of-image",
                    format!("{start} is outside any section of the image"),
                )
                .with_hint(format!(
                    "pass a VA at the preferred image base {} (ASLR'd modules need --pid)",
                    pe.image_base()
                )),
                pretty,
            );
        }
        return run_disasm(&pe, start, a.count, pretty);
    }

    let Some(bytes_str) = a.bytes else {
        return emit(
            &Response::<serde_json::Value>::error(
                "missing-source",
                "provide --file <PE> or --bytes \"<hex>\"",
            ),
            pretty,
        );
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
        .label(label)
        .build();
    run_disasm(&snap, start, a.count, pretty)
}

/// Disassemble ~`count` instructions from `start` over any memory source and
/// emit the `n0xis.decode.v1` envelope. The single place all `disasm` sources
/// converge — proving the "one pipeline, any source" thesis at the frontend.
fn run_disasm(source: &dyn MemorySource, start: Va, count: usize, pretty: bool) -> bool {
    let arch = X64::new();
    let label = source.label();
    let pipe = Pipeline::new(source, &arch);
    match pipe.disassemble(start, count) {
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
