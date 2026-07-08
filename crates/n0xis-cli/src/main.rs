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
    CfgInput, CfgPass, Ctx, DiscoverInput, DiscoverPass, ManifestCandidate, ManifestInput,
    ManifestPass, Pass, StringXrefInput, StringXrefPass, TraceInput, TracePass, XrefDir,
    XrefInput, XrefPass,
};
use n0xis_pipeline::Pipeline;
use n0xis_sources::{LiveProcess, MemorySource, Snapshot, StaticPe, await_breakpoint_hit, list_processes};
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
    /// Raw memory access.
    #[command(subcommand)]
    Mem(MemCmd),
    /// Memory patching with a persisted undo journal.
    #[command(subcommand)]
    Patch(PatchCmd),
    /// Named memory-range anchors, persisted under `.n0x/selections.json`.
    #[command(subcommand)]
    Selection(SelectionCmd),
    /// Persistent artifact store under `.n0x/dumps/<kind>/`.
    #[command(subcommand)]
    Dump(DumpCmd),
    /// Live execution control (software breakpoints).
    #[command(subcommand)]
    Debug(DebugCmd),
}

#[derive(Subcommand)]
enum DebugCmd {
    /// Arm a software breakpoint and block until it fires (or times out).
    AwaitHit(DebugAwaitHitArgs),
}

#[derive(Args)]
struct DebugAwaitHitArgs {
    #[arg(long)]
    pid: u32,
    /// Breakpoint address (hex `0x…`). Absolute VA, unless `--addr-rva`.
    #[arg(long)]
    addr: String,
    /// Interpret `--addr` as an RVA from the main module's base.
    #[arg(long)]
    addr_rva: bool,
    #[arg(long, default_value_t = 30000)]
    timeout_ms: u64,
    /// Qwords to capture from the stack starting at RSP on a hit.
    #[arg(long, default_value_t = 16)]
    stack_qwords: usize,
}

#[derive(Subcommand)]
enum SelectionCmd {
    /// Save (or overwrite, by name) a named `[start, end)` range.
    Save(SelectionSaveArgs),
    /// List all selections.
    List,
    /// Show one selection by name.
    Show(SelectionShowArgs),
    /// Remove a selection by name.
    Clear(SelectionShowArgs),
}

#[derive(Args)]
struct SelectionSaveArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    start: String,
    #[arg(long)]
    end: String,
    #[arg(long)]
    label: Option<String>,
}

#[derive(Args)]
struct SelectionShowArgs {
    #[arg(long)]
    name: String,
}

#[derive(Subcommand)]
enum DumpCmd {
    /// Save a payload to `.n0x/dumps/<kind>/<name>.<ext>`.
    Save(DumpSaveArgs),
    /// List dumps, optionally filtered by `--kind`.
    List(DumpListArgs),
    /// Print a dump's contents (text kinds) or a hex preview (`raw`/`hex`).
    Show(DumpShowArgs),
    /// Remove a dump by name.
    Rm(DumpRmArgs),
}

#[derive(Args)]
struct DumpSaveArgs {
    #[arg(long)]
    name: String,
    /// One of: ir, pseudo, hex, raw, note.
    #[arg(long)]
    kind: String,
    /// Read the payload from this file instead of `--content`/stdin.
    #[arg(long)]
    file: Option<String>,
    /// Inline payload.
    #[arg(long)]
    content: Option<String>,
    /// Overwrite an existing dump of the same name+kind.
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct DumpListArgs {
    #[arg(long)]
    kind: Option<String>,
}

#[derive(Args)]
struct DumpShowArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    kind: Option<String>,
    /// For `raw`/`hex` kinds: cap the hex preview to N bytes.
    #[arg(long, default_value_t = 256)]
    preview: usize,
}

#[derive(Args)]
struct DumpRmArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    kind: Option<String>,
}

#[derive(Subcommand)]
enum MemCmd {
    /// Read bytes (live process, static PE, or inline).
    Read(MemReadArgs),
    /// Write bytes to a live process (flips page protection as needed).
    Write(MemWriteArgs),
    /// Dump the address-space region map of a live process.
    Map(MemMapArgs),
}

#[derive(Args)]
struct MemReadArgs {
    #[arg(long)]
    addr: String,
    #[arg(long, default_value_t = 64)]
    size: usize,
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    #[arg(long)]
    bytes: Option<String>,
}

#[derive(Args)]
struct MemWriteArgs {
    #[arg(long)]
    addr: String,
    /// Bytes to write, e.g. "90 90 c3".
    #[arg(long)]
    bytes: String,
    #[arg(long)]
    pid: u32,
}

#[derive(Args)]
struct MemMapArgs {
    #[arg(long)]
    pid: u32,
    #[arg(long, default_value_t = 256)]
    limit: usize,
}

#[derive(Subcommand)]
enum PatchCmd {
    /// Preview a patch without writing.
    DryRun(PatchWriteArgs),
    /// Apply a patch and journal the undo record under `.n0x/patches/`.
    Apply(PatchWriteArgs),
    /// List journaled patches.
    List(PatchListArgs),
    /// Show one patch record.
    Show(PatchShowArgs),
    /// Restore the original bytes of a patch.
    Undo(PatchUndoArgs),
}

#[derive(Args)]
struct PatchWriteArgs {
    #[arg(long)]
    addr: String,
    #[arg(long)]
    bytes: String,
    #[arg(long)]
    pid: u32,
}

#[derive(Args)]
struct PatchListArgs {
    #[arg(long)]
    status: Option<String>,
    #[arg(long, default_value_t = 100)]
    limit: usize,
}

#[derive(Args)]
struct PatchShowArgs {
    #[arg(long)]
    id: String,
}

#[derive(Args)]
struct PatchUndoArgs {
    /// Patch id (defaults to the most recent applied patch).
    #[arg(long)]
    id: Option<String>,
    #[arg(long)]
    pid: Option<u32>,
    /// Undo even if current bytes no longer match the patched bytes.
    #[arg(long)]
    force: bool,
}

#[derive(Subcommand)]
enum FunctionCmd {
    /// Discover functions by prologue scanning (`.text` by default).
    Discover(DiscoverArgs),
    /// Walk the call graph from a root function.
    Trace(FunctionTraceArgs),
}

#[derive(Args)]
struct FunctionTraceArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    #[arg(long)]
    bytes: Option<String>,
    /// Root address (hex `0x…`), absolute VA unless `--addr-rva`.
    #[arg(long)]
    addr: String,
    /// Interpret `--addr` as an RVA from the module base.
    #[arg(long)]
    addr_rva: bool,
    /// Maximum call-graph depth from the root (0 = only the root itself).
    #[arg(long, default_value_t = 3)]
    depth: usize,
    /// Cap on visited functions; 0 = unlimited.
    #[arg(long, default_value_t = 500)]
    max_nodes: usize,
    /// Byte window handed to `ir build` for each visited function.
    #[arg(long, default_value_t = 4096)]
    max_bytes: usize,
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
    /// Find a string literal and who references it via `lea`.
    String(XrefStringArgs),
}

#[derive(Args)]
struct XrefStringArgs {
    /// The string to search for.
    #[arg(long)]
    query: String,
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    #[arg(long)]
    bytes: Option<String>,
    /// Data window to search (defaults to `.rdata`, else `.text`).
    #[arg(long)]
    data_start: Option<String>,
    /// Data window size (defaults to the resolved section's size).
    #[arg(long)]
    data_size: Option<usize>,
    /// Code window to scan for referencing `lea` (defaults to `.text`).
    #[arg(long)]
    start: Option<String>,
    /// Code window size (defaults to the `.text` size).
    #[arg(long)]
    size: Option<usize>,
    #[arg(long, default_value_t = 50)]
    limit: usize,
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
    /// Render the CFG as Graphviz DOT (pipe to `dot -Tsvg`).
    Dot(IrArgs),
    /// Backward register slice: what computes `--reg` at `--at`.
    Slice(IrSliceArgs),
    /// Per-function index with quality scoring, over discovered candidates.
    Manifest(ManifestArgs),
}

#[derive(Args)]
struct ManifestArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Inline bytes source; requires `--start` for the base address.
    #[arg(long)]
    bytes: Option<String>,
    /// Discovery scan range start (defaults to the module's `.text`).
    #[arg(long)]
    start: Option<String>,
    /// Discovery scan range size in bytes (defaults to the `.text` size).
    #[arg(long)]
    size: Option<usize>,
    /// Cap on discovered candidates to summarize.
    #[arg(long, default_value_t = 200)]
    limit: usize,
    /// Byte window handed to `ir build` per candidate.
    #[arg(long, default_value_t = 4096)]
    max_bytes: usize,
}

#[derive(Args)]
struct IrSliceArgs {
    #[command(flatten)]
    ir: IrArgs,
    /// Register to slice backward on (any width, e.g. `rax`, `eax`, `r8d`).
    #[arg(long)]
    reg: String,
    /// Query point (hex). Defaults to the function's last instruction.
    #[arg(long)]
    at: Option<String>,
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
        Command::Ir(IrCmd::Build(a)) => cmd_ir(a, IrView::Cfg, pretty),
        Command::Ir(IrCmd::Explain(a)) => cmd_ir(a, IrView::Explain, pretty),
        Command::Ir(IrCmd::Dot(a)) => cmd_ir(a, IrView::Dot, pretty),
        Command::Ir(IrCmd::Slice(a)) => cmd_ir_slice(a, pretty),
        Command::Ir(IrCmd::Manifest(a)) => cmd_ir_manifest(a, pretty),
        Command::Function(FunctionCmd::Discover(a)) => cmd_discover(a, pretty),
        Command::Function(FunctionCmd::Trace(a)) => cmd_function_trace(a, pretty),
        Command::Xref(XrefCmd::To(a)) => cmd_xref(a, XrefDir::To, pretty),
        Command::Xref(XrefCmd::From(a)) => cmd_xref(a, XrefDir::From, pretty),
        Command::Xref(XrefCmd::String(a)) => cmd_xref_string(a, pretty),
        Command::Mem(MemCmd::Read(a)) => cmd_mem_read(a, pretty),
        Command::Mem(MemCmd::Write(a)) => cmd_mem_write(a, pretty),
        Command::Mem(MemCmd::Map(a)) => cmd_mem_map(a, pretty),
        Command::Patch(c) => cmd_patch(c, pretty),
        Command::Selection(c) => cmd_selection(c, pretty),
        Command::Dump(c) => cmd_dump(c, pretty),
        Command::Debug(DebugCmd::AwaitHit(a)) => cmd_debug_await_hit(a, pretty),
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

/// Which presentation of the CFG artifact to emit.
#[derive(Clone, Copy)]
enum IrView {
    Cfg,
    Explain,
    Dot,
}

/// Resolve `--pid`/`--file`/`--bytes` into a `Ctx` and run `work` with it — the
/// one place IR-family verbs (`build`/`explain`/`dot`/`slice`) share the source
/// wiring, so the pipeline stays identical across live + static + bytes.
fn run_ir<F>(a: &IrArgs, pretty: bool, work: F) -> bool
where
    F: FnOnce(&Ctx, CfgInput, String) -> bool,
{
    let start = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let arch = X64::new();
    let input = CfgInput {
        start,
        max_bytes: a.size,
        auto_end: !a.no_auto_end,
    };

    if let Some(pid) = a.pid {
        let live = match LiveProcess::attach(pid) {
            Ok(l) => l,
            Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
        };
        let ctx = Ctx::new(&live, &arch);
        return work(&ctx, input, live.label());
    }
    if let Some(file) = a.file.as_deref() {
        let pe = match StaticPe::load(std::path::Path::new(file)) {
            Ok(p) => p,
            Err(e) => return ir_err("load-failed", &e.to_string(), pretty),
        };
        // StaticPe is also a SymbolProvider + ModuleProvider — feed the seams so
        // call targets resolve to names.
        let ctx = Ctx::new(&pe, &arch).with_symbols(&pe).with_modules(&pe);
        return work(&ctx, input, pe.label());
    }
    let Some(bytes_str) = a.bytes.as_deref() else {
        return ir_err("missing-source", "provide --pid, --file, or --bytes", pretty);
    };
    let bytes = match parse_hex_bytes(bytes_str) {
        Ok(b) => b,
        Err(e) => return ir_err("bad-bytes", &e, pretty),
    };
    let snap = Snapshot::builder()
        .region(start, bytes)
        .label(format!("bytes@{start}"))
        .build();
    let ctx = Ctx::new(&snap, &arch);
    work(&ctx, input, snap.label())
}

fn cmd_ir(a: IrArgs, view: IrView, pretty: bool) -> bool {
    run_ir(&a, pretty, |ctx, input, label| {
        finish_ir(ctx, input, view, label, pretty)
    })
}

fn cmd_ir_slice(a: IrSliceArgs, pretty: bool) -> bool {
    let at = match &a.at {
        Some(s) => match Va::parse(s) {
            Ok(v) => Some(v),
            Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
        },
        None => None,
    };
    let reg = a.reg.clone();
    run_ir(&a.ir, pretty, move |ctx, input, label| {
        finish_slice(ctx, input, &reg, at, label, pretty)
    })
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

impl Src {
    fn as_mem(&self) -> &dyn MemorySource {
        match self {
            Src::Live(l) => l.as_ref(),
            Src::Static(p) => p.as_ref(),
            Src::Snap(s) => s,
        }
    }
}

fn to_hex_spaced(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

fn byte_diff_count(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).filter(|(x, y)| x != y).count() + a.len().abs_diff(b.len())
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

fn finish_ir(ctx: &Ctx, input: CfgInput, view: IrView, label: String, pretty: bool) -> bool {
    let art = match CfgPass.run(ctx, input) {
        Ok(a) => a,
        Err(e) => return ir_err("ir-failed", &e.to_string(), pretty),
    };
    match view {
        IrView::Cfg => emit(
            &Response::success(schema::v1::IR_CFG, art).with_source(label),
            pretty,
        ),
        IrView::Explain => {
            let lines = n0xis_core::explain(&art);
            emit(
                &Response::success(schema::v1::IR_EXPLAIN, json!({ "lines": lines }))
                    .with_source(label),
                pretty,
            )
        }
        IrView::Dot => emit(
            &Response::success(schema::v1::IR_DOT, n0xis_core::dot(&art)).with_source(label),
            pretty,
        ),
    }
}

/// Build the CFG, then take a backward register slice over it. `at` defaults to
/// the function's last instruction (slice the final value of `reg`).
fn finish_slice(
    ctx: &Ctx,
    input: CfgInput,
    reg: &str,
    at: Option<Va>,
    label: String,
    pretty: bool,
) -> bool {
    let start = input.start;
    let art = match CfgPass.run(ctx, input) {
        Ok(a) => a,
        Err(e) => return ir_err("ir-failed", &e.to_string(), pretty),
    };
    // Default the query point to the last decoded instruction.
    let query = at.unwrap_or_else(|| {
        art.blocks
            .iter()
            .flat_map(|b| &b.insns)
            .map(|i| i.va)
            .max_by_key(|v| v.get())
            .unwrap_or(start)
    });
    let sl = n0xis_core::slice(ctx.arch, &art, query, reg);
    emit(
        &Response::success(schema::v1::IR_SLICE, sl).with_source(label),
        pretty,
    )
}

fn cmd_function_trace(a: FunctionTraceArgs, pretty: bool) -> bool {
    let addr = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let (src, label, _) = match build_source(a.pid, a.file.as_deref(), a.bytes.as_deref(), addr) {
        Ok(x) => x,
        Err((c, m)) => return ir_err(&c, &m, pretty),
    };
    let arch = X64::new();
    let module_base = match &src {
        Src::Static(pe) => Some(pe.image_base()),
        Src::Live(l) => l.main_module().map(|m| m.base),
        Src::Snap(_) => None,
    };
    let root = if a.addr_rva {
        match module_base {
            Some(base) => base.offset(addr.0),
            None => return ir_err("no-module", "no module base resolved for --addr-rva", pretty),
        }
    } else {
        addr
    };

    let input = TraceInput { root, depth: a.depth, max_nodes: a.max_nodes, max_bytes: a.max_bytes };
    let run = |ctx: &Ctx| -> bool {
        match TracePass.run(ctx, input) {
            Ok(art) => emit(
                &Response::success(schema::v1::FUNCTION_TRACE, art).with_source(label.clone()),
                pretty,
            ),
            Err(e) => ir_err("trace-failed", &e.to_string(), pretty),
        }
    };
    match &src {
        Src::Static(pe) => run(&Ctx::new(pe.as_ref(), &arch).with_symbols(pe.as_ref())),
        Src::Live(l) => run(&Ctx::new(l.as_ref(), &arch)),
        Src::Snap(s) => run(&Ctx::new(s, &arch)),
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

/// Discover candidates over the scan range, then reduce each to a manifest
/// entry — the same two passes an agent would otherwise chain by hand.
fn cmd_ir_manifest(a: ManifestArgs, pretty: bool) -> bool {
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
        let discovered = match DiscoverPass.run(ctx, DiscoverInput { start, size, limit: a.limit }) {
            Ok(d) => d,
            Err(e) => return ir_err("discover-failed", &e.to_string(), pretty),
        };
        let candidates = discovered
            .functions
            .into_iter()
            .map(|f| ManifestCandidate { name: f.name, va: f.va })
            .collect();
        match ManifestPass.run(ctx, ManifestInput { candidates, max_bytes: a.max_bytes }) {
            Ok(art) => emit(
                &Response::success(schema::v1::IR_MANIFEST, art).with_source(label.clone()),
                pretty,
            ),
            Err(e) => ir_err("manifest-failed", &e.to_string(), pretty),
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

/// Search a data window for `--query` and a code window for referencing
/// `lea`s. The two windows default independently: data to `.rdata` (falling
/// back to `.text`), code to `.text` — string literals and the code that
/// points to them usually live in different sections.
fn cmd_xref_string(a: XrefStringArgs, pretty: bool) -> bool {
    let explicit_code_start = match opt_hex(&a.start) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e, pretty),
    };
    let explicit_data_start = match opt_hex(&a.data_start) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e, pretty),
    };
    let bytes_base = explicit_data_start.or(explicit_code_start).unwrap_or(Va(0));
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
    let default_data = match &src {
        Src::Static(pe) => pe.section_range(".rdata").or_else(|| pe.text_range()),
        Src::Live(l) => l.section_range(".rdata").or_else(|| l.text_range()),
        Src::Snap(_) => None,
    };
    let (code_start, code_size) =
        scan_range(default_text, region_len, explicit_code_start, a.size, bytes_base);
    let (data_start, data_size) =
        scan_range(default_data, region_len, explicit_data_start, a.data_size, bytes_base);
    if code_size == 0 || data_size == 0 {
        return ir_err(
            "no-range",
            "could not resolve a data/code range; pass --data-start/--data-size and --start/--size",
            pretty,
        );
    }

    let run = |ctx: &Ctx| -> bool {
        let input = StringXrefInput {
            data_start,
            data_size,
            code_start,
            code_size,
            query: a.query.clone(),
            limit: a.limit,
        };
        match StringXrefPass.run(ctx, input) {
            Ok(art) => emit(
                &Response::success(schema::v1::XREF_STRING, art).with_source(label.clone()),
                pretty,
            ),
            Err(e) => ir_err("xref-string-failed", &e.to_string(), pretty),
        }
    };
    match &src {
        Src::Static(pe) => run(&Ctx::new(pe.as_ref(), &arch).with_symbols(pe.as_ref())),
        Src::Live(l) => run(&Ctx::new(l.as_ref(), &arch)),
        Src::Snap(s) => run(&Ctx::new(s, &arch)),
    }
}

fn cmd_mem_read(a: MemReadArgs, pretty: bool) -> bool {
    let addr = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let (src, label, _) =
        match build_source(a.pid, a.file.as_deref(), a.bytes.as_deref(), addr) {
            Ok(x) => x,
            Err((c, m)) => return ir_err(&c, &m, pretty),
        };
    match src.as_mem().read(addr, a.size) {
        Ok(bytes) => {
            let data = json!({
                "address": addr,
                "requested": a.size,
                "read": bytes.len(),
                "hex": to_hex_spaced(&bytes),
            });
            emit(&Response::success(schema::v1::MEM_READ, data).with_source(label), pretty)
        }
        Err(e) => ir_err("read-failed", &e.to_string(), pretty),
    }
}

fn cmd_mem_write(a: MemWriteArgs, pretty: bool) -> bool {
    let addr = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let bytes = match parse_hex_bytes(&a.bytes) {
        Ok(b) => b,
        Err(e) => return ir_err("bad-bytes", &e, pretty),
    };
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    match live.write(addr, &bytes) {
        Ok(()) => {
            let data = json!({ "address": addr, "written": bytes.len(), "hex": to_hex_spaced(&bytes) });
            emit(&Response::success(schema::v1::MEM_WRITE, data).with_source(live.label()), pretty)
        }
        Err(e) => ir_err("write-failed", &e.to_string(), pretty),
    }
}

fn cmd_mem_map(a: MemMapArgs, pretty: bool) -> bool {
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    let regions = live.regions(a.limit);
    let regions_v = serde_json::to_value(&regions).unwrap_or(serde_json::Value::Null);
    let data = json!({ "count": regions.len(), "regions": regions_v });
    emit(&Response::success(schema::v1::MEM_MAP, data).with_source(live.label()), pretty)
}

fn cmd_patch(cmd: PatchCmd, pretty: bool) -> bool {
    use n0xis_project::patch as pj;
    match cmd {
        PatchCmd::DryRun(a) => patch_dry_run(a, pretty),
        PatchCmd::Apply(a) => patch_apply(a, pretty),
        PatchCmd::List(a) => {
            match pj::list(a.limit) {
                Ok(mut items) => {
                    if let Some(s) = a.status.as_deref() {
                        let q = s.to_ascii_lowercase();
                        items.retain(|r| r.status.to_ascii_lowercase() == q);
                    }
                    let items_v = serde_json::to_value(&items).unwrap_or(serde_json::Value::Null);
                    emit(
                        &Response::success(schema::v1::PATCH, json!({ "op": "list", "count": items.len(), "items": items_v })),
                        pretty,
                    )
                }
                Err(e) => ir_err("patch-list-failed", &e.to_string(), pretty),
            }
        }
        PatchCmd::Show(a) => match pj::load_by_id(&a.id) {
            Ok(rec) => {
                let rec_v = serde_json::to_value(&rec).unwrap_or(serde_json::Value::Null);
                emit(&Response::success(schema::v1::PATCH, json!({ "op": "show", "item": rec_v })), pretty)
            }
            Err(e) => ir_err("patch-show-failed", &e.to_string(), pretty),
        },
        PatchCmd::Undo(a) => patch_undo(a, pretty),
    }
}

fn patch_dry_run(a: PatchWriteArgs, pretty: bool) -> bool {
    let addr = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let desired = match parse_hex_bytes(&a.bytes) {
        Ok(b) => b,
        Err(e) => return ir_err("bad-bytes", &e, pretty),
    };
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    let current = match live.read(addr, desired.len()) {
        Ok(b) => b,
        Err(e) => return ir_err("read-failed", &e.to_string(), pretty),
    };
    let data = json!({
        "op": "dry-run",
        "pid": a.pid,
        "address": addr,
        "size": desired.len(),
        "currentHex": to_hex_spaced(&current),
        "desiredHex": to_hex_spaced(&desired),
        "wouldChange": current != desired,
        "diffBytes": byte_diff_count(&current, &desired),
    });
    emit(&Response::success(schema::v1::PATCH, data).with_source(live.label()), pretty)
}

fn patch_apply(a: PatchWriteArgs, pretty: bool) -> bool {
    use n0xis_project::patch as pj;
    let addr = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let desired = match parse_hex_bytes(&a.bytes) {
        Ok(b) => b,
        Err(e) => return ir_err("bad-bytes", &e, pretty),
    };
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    let before = match live.read(addr, desired.len()) {
        Ok(b) => b,
        Err(e) => return ir_err("read-failed", &e.to_string(), pretty),
    };
    if let Err(e) = live.write(addr, &desired) {
        return ir_err("write-failed", &e.to_string(), pretty);
    }
    // Verify the write landed.
    match live.read(addr, desired.len()) {
        Ok(after) if after == desired => {}
        Ok(_) => return ir_err("verify-failed", "post-write bytes do not match", pretty),
        Err(e) => return ir_err("verify-read-failed", &e.to_string(), pretty),
    }
    let rec = pj::PatchRecord {
        id: pj::new_patch_id(),
        pid: a.pid,
        address: addr.to_string(),
        size: desired.len(),
        before_hex: to_hex_spaced(&before),
        after_hex: to_hex_spaced(&desired),
        status: "applied".to_string(),
        created_at_unix: pj::now_unix_secs(),
        undone_at_unix: None,
    };
    let path = match pj::save(&rec) {
        Ok(p) => p,
        Err(e) => return ir_err("journal-failed", &e.to_string(), pretty),
    };
    let data = json!({
        "op": "apply",
        "id": rec.id,
        "recordPath": path.to_string_lossy(),
        "pid": a.pid,
        "address": addr,
        "size": rec.size,
        "diffBytes": byte_diff_count(&before, &desired),
    });
    emit(&Response::success(schema::v1::PATCH, data).with_source(live.label()), pretty)
}

fn patch_undo(a: PatchUndoArgs, pretty: bool) -> bool {
    use n0xis_project::patch as pj;
    let mut rec = match a.id.as_deref() {
        Some(id) => match pj::load_by_id(id) {
            Ok(r) => r,
            Err(e) => return ir_err("patch-not-found", &e.to_string(), pretty),
        },
        None => match pj::load_latest() {
            Ok(r) => r,
            Err(e) => return ir_err("no-patches", &e.to_string(), pretty),
        },
    };
    if rec.status != "applied" {
        return ir_err(
            "not-applied",
            &format!("patch {} status is '{}', nothing to undo", rec.id, rec.status),
            pretty,
        );
    }
    let addr = match Va::parse(&rec.address) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let before = match parse_hex_bytes(&rec.before_hex) {
        Ok(b) => b,
        Err(e) => return ir_err("bad-record", &e, pretty),
    };
    let after = match parse_hex_bytes(&rec.after_hex) {
        Ok(b) => b,
        Err(e) => return ir_err("bad-record", &e, pretty),
    };
    let pid = a.pid.unwrap_or(rec.pid);
    let live = match LiveProcess::attach(pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    // Safety: current bytes should still be the patched bytes unless --force.
    match live.read(addr, after.len()) {
        Ok(current) if current == after => {}
        Ok(_) if a.force => {}
        Ok(_) => {
            return ir_err(
                "undo-unsafe",
                "current bytes no longer match the applied patch; re-run with --force",
                pretty,
            );
        }
        Err(e) => return ir_err("read-failed", &e.to_string(), pretty),
    }
    if let Err(e) = live.write(addr, &before) {
        return ir_err("restore-failed", &e.to_string(), pretty);
    }
    rec.status = "undone".to_string();
    rec.undone_at_unix = Some(pj::now_unix_secs());
    if let Err(e) = pj::save(&rec) {
        return ir_err("journal-failed", &e.to_string(), pretty);
    }
    let data = json!({
        "op": "undo",
        "id": rec.id,
        "pid": pid,
        "address": addr,
        "restored": before.len(),
    });
    emit(&Response::success(schema::v1::PATCH, data).with_source(live.label()), pretty)
}

fn cmd_selection(cmd: SelectionCmd, pretty: bool) -> bool {
    use n0xis_project::selection as sel;
    match cmd {
        SelectionCmd::Save(a) => {
            let start = match Va::parse(&a.start) {
                Ok(v) => v,
                Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
            };
            let end = match Va::parse(&a.end) {
                Ok(v) => v,
                Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
            };
            match sel::save(&a.name, start, end, a.label) {
                Ok(rec) => {
                    let rec_v = serde_json::to_value(&rec).unwrap_or(serde_json::Value::Null);
                    emit(
                        &Response::success(schema::v1::SELECTION, json!({ "op": "save", "selection": rec_v })),
                        pretty,
                    )
                }
                Err(e) => ir_err("selection-save-failed", &e.to_string(), pretty),
            }
        }
        SelectionCmd::List => match sel::list() {
            Ok(items) => {
                let items_v = serde_json::to_value(&items).unwrap_or(serde_json::Value::Null);
                emit(
                    &Response::success(
                        schema::v1::SELECTION,
                        json!({ "op": "list", "count": items.len(), "selections": items_v }),
                    ),
                    pretty,
                )
            }
            Err(e) => ir_err("selection-list-failed", &e.to_string(), pretty),
        },
        SelectionCmd::Show(a) => match sel::get(&a.name) {
            Ok(rec) => {
                let rec_v = serde_json::to_value(&rec).unwrap_or(serde_json::Value::Null);
                emit(
                    &Response::success(schema::v1::SELECTION, json!({ "op": "show", "selection": rec_v })),
                    pretty,
                )
            }
            Err(e) => ir_err("selection-not-found", &e.to_string(), pretty),
        },
        SelectionCmd::Clear(a) => match sel::remove(&a.name) {
            Ok(true) => emit(
                &Response::success(schema::v1::SELECTION, json!({ "op": "clear", "name": a.name, "removed": true })),
                pretty,
            ),
            Ok(false) => ir_err("selection-not-found", &format!("no selection named '{}'", a.name), pretty),
            Err(e) => ir_err("selection-clear-failed", &e.to_string(), pretty),
        },
    }
}

fn cmd_dump(cmd: DumpCmd, pretty: bool) -> bool {
    use n0xis_project::dump as dp;
    match cmd {
        DumpCmd::Save(a) => {
            let bytes: Vec<u8> = if let Some(c) = a.content {
                c.into_bytes()
            } else if let Some(f) = a.file.as_deref() {
                match std::fs::read(f) {
                    Ok(b) => b,
                    Err(e) => return ir_err("read-failed", &e.to_string(), pretty),
                }
            } else {
                use std::io::Read;
                let mut buf = Vec::new();
                if let Err(e) = std::io::stdin().read_to_end(&mut buf) {
                    return ir_err("stdin-failed", &e.to_string(), pretty);
                }
                buf
            };
            match dp::save(&a.name, &a.kind, &bytes, a.force) {
                Ok(saved) => {
                    let v = serde_json::to_value(&saved).unwrap_or(serde_json::Value::Null);
                    emit(&Response::success(schema::v1::DUMP, json!({ "op": "save", "dump": v })), pretty)
                }
                Err(e) => ir_err("dump-save-failed", &e.to_string(), pretty),
            }
        }
        DumpCmd::List(a) => match dp::list(a.kind.as_deref()) {
            Ok(items) => {
                let v = serde_json::to_value(&items).unwrap_or(serde_json::Value::Null);
                emit(
                    &Response::success(schema::v1::DUMP, json!({ "op": "list", "count": items.len(), "items": v })),
                    pretty,
                )
            }
            Err(e) => ir_err("dump-list-failed", &e.to_string(), pretty),
        },
        DumpCmd::Show(a) => match dp::show(&a.name, a.kind.as_deref()) {
            Ok(content) => {
                let is_binaryish = content.kind == "raw" || content.kind == "hex";
                let preview = if is_binaryish {
                    let n = a.preview.min(content.bytes.len());
                    to_hex_spaced(&content.bytes[..n])
                } else {
                    String::from_utf8_lossy(&content.bytes).into_owned()
                };
                let truncated = is_binaryish && a.preview < content.bytes.len();
                emit(
                    &Response::success(
                        schema::v1::DUMP,
                        json!({
                            "op": "show",
                            "name": content.name,
                            "kind": content.kind,
                            "path": content.path,
                            "size": content.size,
                            "content": preview,
                            "truncated": truncated,
                        }),
                    ),
                    pretty,
                )
            }
            Err(e) => ir_err("dump-show-failed", &e.to_string(), pretty),
        },
        DumpCmd::Rm(a) => match dp::remove(&a.name, a.kind.as_deref()) {
            Ok(removed) => {
                let v = serde_json::to_value(&removed).unwrap_or(serde_json::Value::Null);
                emit(
                    &Response::success(schema::v1::DUMP, json!({ "op": "rm", "name": a.name, "removed": v })),
                    pretty,
                )
            }
            Err(e) => ir_err("dump-rm-failed", &e.to_string(), pretty),
        },
    }
}

fn cmd_debug_await_hit(a: DebugAwaitHitArgs, pretty: bool) -> bool {
    let addr = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    // Attach only long enough to resolve the main module (for --addr-rva and
    // the relative_rip label on a hit) — the debug session itself opens its
    // own handle and becomes the process's debugger independently.
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    let module = live.main_module().cloned();
    let label = live.label();
    drop(live);

    let bp_va = if a.addr_rva {
        match &module {
            Some(m) => m.base.offset(addr.0),
            None => {
                return ir_err("no-module", "process has no enumerated main module for --addr-rva", pretty);
            }
        }
    } else {
        addr
    };

    match await_breakpoint_hit(a.pid, bp_va, a.timeout_ms, a.stack_qwords, module.as_ref()) {
        Ok(outcome) => emit(
            &Response::success(schema::v1::DEBUG_AWAIT_HIT, outcome).with_source(label),
            pretty,
        ),
        Err(e) => ir_err("await-hit-failed", &e.to_string(), pretty),
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
