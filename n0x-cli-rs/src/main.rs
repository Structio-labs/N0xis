mod ir;
mod project;
mod pseudo;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, NasmFormatter};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;
use sysinfo::{Pid, ProcessesToUpdate, System};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE,
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_NOCACHE, PAGE_READONLY, PAGE_READWRITE,
    PAGE_TARGETS_INVALID, PAGE_WRITECOMBINE, PAGE_WRITECOPY, VirtualQueryEx,
};
use windows_sys::Win32::System::Threading::{
    IsWow64Process, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

#[derive(Parser, Debug)]
#[command(name = "n0x", version, about = "N0x RE CLI backend")]
struct Cli {
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    pretty: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Process(ProcessCommand),
    Module(ModuleCommand),
    Function(FunctionCommand),
    Selection(SelectionCommand),
    Target(TargetCommand),
    Mem(MemCommand),
    Patch(PatchCommand),
    Disasm(DisasmArgs),
    Xref(XrefCommand),
    Doctor(DoctorArgs),
    Ir(IrCommand),
    Decomp(DecompCommand),
    /// Initialize a `.n0x/` project directory at the current dir (or `--dir`).
    /// Generates `project.toml`, the per-project shim `n0x.cmd`, and the
    /// `dumps/` skeleton. Subsequent commands run from anywhere inside the
    /// project tree auto-detect this `.n0x/` and store state locally.
    Init(InitArgs),
    /// Inspect or edit project metadata.
    Project(ProjectCommand),
    /// Persistent dump store inside `.n0x/dumps/<kind>/` for AI anchors.
    Dump(DumpCommand),
}

#[derive(Args, Debug)]
struct PatchCommand {
    #[command(subcommand)]
    command: PatchSubcommand,
}

#[derive(Subcommand, Debug)]
enum PatchSubcommand {
    /// Validate a patch by reading current bytes, without writing memory.
    DryRun(PatchWriteArgs),
    /// Apply a patch and persist undo metadata under `.n0x/patches/`.
    Apply(PatchWriteArgs),
    /// List patch records from `.n0x/patches/`.
    List(PatchListArgs),
    /// Show one patch record by id.
    Show(PatchShowArgs),
    /// Undo a previously applied patch (`--id`) or the latest one.
    Undo(PatchUndoArgs),
}

#[derive(Args, Debug)]
struct PatchWriteArgs {
    #[arg(long)]
    addr: String,
    /// Target bytes as spaced hex, e.g. \"90 90 C3\".
    #[arg(long)]
    bytes: String,
    #[arg(long)]
    pid: Option<u32>,
}

#[derive(Args, Debug)]
struct PatchUndoArgs {
    /// Patch id from `.n0x/patches/patch-<id>.json`.
    #[arg(long)]
    id: Option<String>,
    #[arg(long)]
    pid: Option<u32>,
    /// Force undo even if current memory no longer matches the patch's `after` bytes.
    #[arg(long)]
    force: bool,
}

#[derive(Args, Debug)]
struct PatchListArgs {
    /// Filter by status (`applied` or `undone`).
    #[arg(long)]
    status: Option<String>,
    /// Max records to return (latest first).
    #[arg(long, default_value_t = 100)]
    limit: usize,
}

#[derive(Args, Debug)]
struct PatchShowArgs {
    /// Patch id from `.n0x/patches/patch-<id>.json`.
    #[arg(long)]
    id: String,
}

#[derive(Args, Debug)]
struct InitArgs {
    /// Directory to initialize (defaults to cwd). Created if it doesn't exist.
    #[arg(long)]
    dir: Option<String>,
    /// Project name. Defaults to the parent directory's name.
    #[arg(long)]
    name: Option<String>,
    /// Override the absolute path baked into `project.toml` and the `n0x.cmd`
    /// shim. Defaults to the path of the currently-running binary.
    #[arg(long)]
    core: Option<String>,
}

#[derive(Args, Debug)]
struct ProjectCommand {
    #[command(subcommand)]
    command: ProjectSubcommand,
}

#[derive(Subcommand, Debug)]
enum ProjectSubcommand {
    /// Show the resolved project root, config, and storage paths.
    Info,
}

#[derive(Args, Debug)]
struct DumpCommand {
    #[command(subcommand)]
    command: DumpSubcommand,
}

#[derive(Subcommand, Debug)]
enum DumpSubcommand {
    /// Save a payload to `.n0x/dumps/<kind>/<name>.<ext>`. The payload is
    /// taken from `--file <path>`, inline `--content <s>`, or stdin (default).
    Save(DumpSaveArgs),
    /// List dumps. Optionally filter by `--kind`.
    List(DumpListArgs),
    /// Print a dump's contents (text kinds) or hex preview (raw).
    Show(DumpShowArgs),
    /// Remove a dump.
    Rm(DumpRmArgs),
}

#[derive(Args, Debug)]
struct DumpSaveArgs {
    #[arg(long)]
    name: String,
    /// One of: ir, pseudo, hex, raw, note.
    #[arg(long)]
    kind: String,
    /// Read payload from this file instead of stdin.
    #[arg(long)]
    file: Option<String>,
    /// Inline payload (use sparingly — bypasses stdin / file).
    #[arg(long)]
    content: Option<String>,
    /// Overwrite if a dump with the same name+kind already exists.
    #[arg(long)]
    force: bool,
}

#[derive(Args, Debug)]
struct DumpListArgs {
    #[arg(long)]
    kind: Option<String>,
}

#[derive(Args, Debug)]
struct DumpShowArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    kind: Option<String>,
    /// For `raw`/`hex` kinds: limit hex preview to N bytes.
    #[arg(long, default_value_t = 256)]
    preview: usize,
}

#[derive(Args, Debug)]
struct DumpRmArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    kind: Option<String>,
}

#[derive(Args, Debug)]
struct DecompCommand {
    #[command(subcommand)]
    command: DecompSubcommand,
}

#[derive(Subcommand, Debug)]
enum DecompSubcommand {
    /// Render template-based pseudo-C for a function (best-effort, v0).
    Pseudo(DecompPseudoArgs),
}

#[derive(Args, Debug)]
struct DecompPseudoArgs {
    #[command(flatten)]
    build: IrBuildArgs,
    /// Output style: `goto` (always-correct labelled blocks) or `structured`
    /// (recovers `if/else/while/do-while` via dominators + natural loops;
    /// regions the reducer can't classify fall back to `goto`).
    #[arg(long, value_enum, default_value = "structured")]
    style: PseudoStyle,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum PseudoStyle {
    Goto,
    Structured,
}


#[derive(Args, Debug)]
struct IrCommand {
    #[command(subcommand)]
    command: IrSubcommand,
}

#[derive(Subcommand, Debug)]
enum IrSubcommand {
    Build(IrBuildArgs),
    Explain(IrBuildArgs),
    Cfg(IrBuildArgs),
    Dot(IrBuildArgs),
    Slice(IrSliceArgs),
    Manifest(IrManifestArgs),
}

#[derive(Args, Debug)]
struct IrSliceArgs {
    #[command(flatten)]
    build: IrBuildArgs,
    /// Register to trace backward from the seed instruction/address.
    #[arg(long)]
    reg: String,
}

#[derive(Args, Debug)]
struct IrManifestArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    module: String,
    /// Where to take function entries from: `exports`, `discover`, or `both`.
    #[arg(long, default_value = "exports")]
    source: String,
    /// Maximum number of entries to analyze (default 200; raise carefully).
    #[arg(long, default_value_t = 200)]
    limit: usize,
    /// Substring filter on the function name (case-insensitive) before analysis.
    #[arg(long)]
    filter: Option<String>,
    /// Only include entries with `quality >= min_quality` (0.0..=1.0).
    #[arg(long)]
    min_quality: Option<f32>,
    /// Per-function decoding cap in bytes (passed to `read_memory`).
    #[arg(long, default_value_t = 4096)]
    size: usize,
    /// Sort order: `quality` (default, descending) or `address` (ascending).
    #[arg(long, default_value = "quality")]
    sort: String,
}

#[derive(Args, Debug)]
struct IrBuildArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    addr: String,
    #[arg(long, default_value_t = 4096)]
    size: usize,
    /// Disable function-boundary auto-detection (decode full --size window).
    #[arg(long)]
    no_auto_end: bool,
    /// Disable export-symbol resolution for call targets.
    #[arg(long)]
    no_resolve: bool,
    /// Disable memory-side switch / jump-table resolution (skip reading the table from process memory).
    #[arg(long)]
    no_switch_resolve: bool,
    /// Hard cap on case-count per switch when resolving memory-side. Default 256.
    #[arg(long, default_value_t = 256)]
    switch_cap: usize,
    /// View detail level: full | minimal | cfg | block.
    #[arg(long, value_enum, default_value_t = IrView::Full)]
    view: IrView,
    /// Restrict output to a single block by id (with --view block, or as filter).
    #[arg(long)]
    block: Option<usize>,
    /// Restrict instructions to address range "0xSTART-0xEND" (inclusive start, exclusive end).
    #[arg(long)]
    range: Option<String>,
}

#[derive(clap::ValueEnum, Clone, Debug, Default)]
enum IrView {
    #[default]
    Full,
    Minimal,
    Cfg,
    Block,
}

#[derive(Args, Debug)]
struct ProcessCommand {
    #[command(subcommand)]
    command: ProcessSubcommand,
}

#[derive(Subcommand, Debug)]
enum ProcessSubcommand {
    Ps(ProcessPsArgs),
}

#[derive(Args, Debug)]
struct ProcessPsArgs {
    #[arg(long)]
    filter: Option<String>,
}

#[derive(Args, Debug)]
struct TargetCommand {
    #[command(subcommand)]
    command: TargetSubcommand,
}

#[derive(Args, Debug)]
struct ModuleCommand {
    #[command(subcommand)]
    command: ModuleSubcommand,
}

#[derive(Subcommand, Debug)]
enum ModuleSubcommand {
    List(ModuleListArgs),
}

#[derive(Args, Debug)]
struct ModuleListArgs {
    #[arg(long)]
    pid: Option<u32>,
}

#[derive(Args, Debug)]
struct FunctionCommand {
    #[command(subcommand)]
    command: FunctionSubcommand,
}

#[derive(Subcommand, Debug)]
enum FunctionSubcommand {
    List(FunctionListArgs),
    Info(FunctionInfoArgs),
    Discover(FunctionDiscoverArgs),
    Trace(FunctionTraceArgs),
}

#[derive(Args, Debug)]
struct FunctionListArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    module: Option<String>,
    #[arg(long)]
    query: Option<String>,
    #[arg(long, default_value_t = 200)]
    limit: usize,
}

#[derive(Args, Debug)]
struct FunctionInfoArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    name: String,
    #[arg(long)]
    module: Option<String>,
}

#[derive(Args, Debug)]
struct FunctionDiscoverArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    module: String,
    #[arg(long, default_value_t = 200)]
    limit: usize,
}

#[derive(Args, Debug)]
struct FunctionTraceArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    module: String,
    #[arg(long)]
    addr: String,
    #[arg(long, default_value_t = 2)]
    depth: usize,
}

#[derive(Subcommand, Debug)]
enum TargetSubcommand {
    Attach(TargetAttachArgs),
    Detach,
    Info,
}

#[derive(Args, Debug)]
struct TargetAttachArgs {
    #[arg(long)]
    pid: u32,
}

#[derive(Args, Debug)]
struct MemCommand {
    #[command(subcommand)]
    command: MemSubcommand,
}

#[derive(Subcommand, Debug)]
enum MemSubcommand {
    Read(MemReadArgs),
    Write(MemWriteArgs),
    Map(MemMapArgs),
}

#[derive(Args, Debug)]
struct MemReadArgs {
    #[arg(long)]
    addr: String,
    #[arg(long)]
    size: usize,
    #[arg(long)]
    pid: Option<u32>,
}

#[derive(Args, Debug)]
struct MemWriteArgs {
    #[arg(long)]
    addr: String,
    #[arg(long)]
    bytes: String,
    #[arg(long)]
    pid: Option<u32>,
}

#[derive(Args, Debug)]
struct MemMapArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long, default_value_t = 256)]
    limit: usize,
    #[arg(long)]
    state: Option<String>,
    #[arg(long, value_name = "TYPE")]
    kind: Option<String>,
    #[arg(long)]
    protect: Option<String>,
}

#[derive(Args, Debug)]
struct DisasmArgs {
    #[arg(long)]
    addr: String,
    #[arg(long, default_value_t = 20)]
    count: usize,
    #[arg(long)]
    pid: Option<u32>,
}

#[derive(Args, Debug)]
struct XrefCommand {
    #[command(subcommand)]
    command: XrefSubcommand,
}

#[derive(Subcommand, Debug)]
enum XrefSubcommand {
    To(XrefToArgs),
    From(XrefFromArgs),
    String(XrefStringArgs),
}

#[derive(Args, Debug)]
struct XrefToArgs {
    #[arg(long)]
    addr: String,
    #[arg(long)]
    start: String,
    #[arg(long)]
    size: usize,
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    kind: Option<String>,
}

#[derive(Args, Debug)]
struct XrefFromArgs {
    #[arg(long)]
    addr: String,
    #[arg(long)]
    start: String,
    #[arg(long)]
    size: usize,
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    kind: Option<String>,
}

#[derive(Args, Debug)]
struct XrefStringArgs {
    #[arg(long)]
    query: String,
    #[arg(long)]
    module: String,
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long, default_value_t = 5)]
    limit: usize,
}

#[derive(Args, Debug)]
struct DoctorArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    dll_path: Option<String>,
}

#[derive(Args, Debug)]
struct SelectionCommand {
    #[command(subcommand)]
    command: SelectionSubcommand,
}

#[derive(Subcommand, Debug)]
enum SelectionSubcommand {
    Save(SelectionSaveArgs),
    List,
    Show(SelectionShowArgs),
    Xref(SelectionXrefArgs),
    Ir(SelectionIrArgs),
}

#[derive(Args, Debug)]
struct SelectionIrArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    out: Option<String>,
    #[arg(long)]
    explain: bool,
    /// View detail level for the IR slice: full | minimal | cfg | block.
    #[arg(long, value_enum, default_value_t = IrView::Full)]
    view: IrView,
    /// Restrict output to a single block by id.
    #[arg(long)]
    block: Option<usize>,
}

#[derive(Args, Debug)]
struct SelectionSaveArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    name: String,
    #[arg(long)]
    module: String,
    #[arg(long)]
    start: String,
    #[arg(long)]
    end: String,
    #[arg(long)]
    note: Option<String>,
}

#[derive(Args, Debug)]
struct SelectionShowArgs {
    #[arg(long)]
    name: String,
}

#[derive(Args, Debug)]
struct SelectionXrefArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    out: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionState {
    attached_pid: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SelectionRecord {
    name: String,
    pid: u32,
    module: String,
    start: String,
    end: String,
    note: Option<String>,
    created_at: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PatchRecord {
    id: String,
    pid: u32,
    address: String,
    size: usize,
    before_hex: String,
    after_hex: String,
    status: String,
    created_at_unix: u64,
    undone_at_unix: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ProcessInfo {
    pid: u32,
    name: String,
    arch: String,
    cpu: f32,
    memory_mb: f64,
    status: String,
    path: String,
}

#[derive(Debug, Serialize)]
struct ModuleInfo {
    name: String,
    base_address: String,
    size: u64,
    path: String,
}

#[derive(Debug, Serialize)]
struct MemoryRegionInfo {
    base_address: String,
    region_end: String,
    size: usize,
    state: String,
    protection: String,
    kind: String,
}

#[derive(Debug, Serialize, Clone)]
struct FunctionSymbolInfo {
    name: String,
    module: String,
    module_path: String,
    relative_address: String,
    address: String,
}

fn main() {
    let cli = Cli::parse();
    let out = OutputMode {
        json: cli.json,
        pretty: cli.pretty,
    };
    if let Err(err) = run_with_cli(cli, out) {
        emit_error(out.json, out.pretty, "UNEXPECTED", &err.to_string(), None);
        std::process::exit(1);
    }
}

fn run_with_cli(cli: Cli, out: OutputMode) -> Result<()> {
    let start = Instant::now();

    match cli.command {
        Commands::Process(cmd) => handle_process(cmd, &out, start),
        Commands::Module(cmd) => handle_module(cmd, &out, start),
        Commands::Function(cmd) => handle_function(cmd, &out, start),
        Commands::Selection(cmd) => handle_selection(cmd, &out, start),
        Commands::Target(cmd) => handle_target(cmd, &out, start),
        Commands::Mem(cmd) => handle_mem(cmd, &out, start),
        Commands::Patch(cmd) => handle_patch(cmd, &out, start),
        Commands::Disasm(args) => handle_disasm(args, &out, start),
        Commands::Xref(cmd) => handle_xref(cmd, &out, start),
        Commands::Doctor(args) => handle_doctor(args, &out, start),
        Commands::Ir(cmd) => handle_ir(cmd, &out, start),
        Commands::Decomp(cmd) => handle_decomp(cmd, &out, start),
        Commands::Init(args) => handle_init(args, &out, start),
        Commands::Project(cmd) => handle_project(cmd, &out, start),
        Commands::Dump(cmd) => handle_dump(cmd, &out, start),
    }
}

fn handle_init(args: InitArgs, out: &OutputMode, start: Instant) -> Result<()> {
    let dir = args.dir.as_deref().map(Path::new);
    let report = project::init(dir, args.name, args.core)?;
    let payload = json!({
        "schema": "n0x.project.init.v1",
        "dir": report.dir.to_string_lossy(),
        "alreadyExisted": report.already_existed,
        "wroteConfig": report.wrote_config,
        "wroteShim": report.wrote_shim,
        "corePath": report.core_path,
        "shim": report.dir.join("n0x.cmd").to_string_lossy(),
    });
    emit_success(out, payload, start, None);
    Ok(())
}

fn handle_project(cmd: ProjectCommand, out: &OutputMode, start: Instant) -> Result<()> {
    match cmd.command {
        ProjectSubcommand::Info => {
            let root = project::resolve()?;
            let cfg = project::load_config(&root).ok().flatten();
            let payload = json!({
                "schema": "n0x.project.info.v1",
                "root": root.dir.to_string_lossy(),
                "isLocal": root.is_local,
                "sessionPath": root.session_path().to_string_lossy(),
                "selectionsPath": root.selections_path().to_string_lossy(),
                "dumpsDir": root.dumps_dir().to_string_lossy(),
                "shim": root.shim_path().to_string_lossy(),
                "config": cfg,
            });
            emit_success(out, payload, start, None);
            Ok(())
        }
    }
}

fn handle_dump(cmd: DumpCommand, out: &OutputMode, start: Instant) -> Result<()> {
    match cmd.command {
        DumpSubcommand::Save(args) => dump_save(args, out, start),
        DumpSubcommand::List(args) => dump_list(args, out, start),
        DumpSubcommand::Show(args) => dump_show(args, out, start),
        DumpSubcommand::Rm(args) => dump_rm(args, out, start),
    }
}

fn ensure_kind(k: &str) -> Result<()> {
    if !project::is_valid_kind(k) {
        bail!(
            "Unknown dump kind '{k}'. Valid: {}",
            project::DUMP_KINDS.join(", ")
        );
    }
    Ok(())
}

fn dump_path_for(root: &project::ProjectRoot, kind: &str, name: &str) -> Result<PathBuf> {
    if name.is_empty() || name.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|']) {
        bail!("Invalid dump name '{name}'");
    }
    let dir = root.dump_kind_dir(kind);
    fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create {}", dir.display()))?;
    Ok(dir.join(format!("{name}.{}", project::extension_for_kind(kind))))
}

fn dump_save(args: DumpSaveArgs, out: &OutputMode, start: Instant) -> Result<()> {
    ensure_kind(&args.kind)?;
    let root = project::resolve()?;
    let path = dump_path_for(&root, &args.kind, &args.name)?;
    if path.exists() && !args.force {
        bail!(
            "Dump already exists at {}. Use --force to overwrite.",
            path.display()
        );
    }
    // Source priority: --content > --file > stdin.
    let bytes: Vec<u8> = if let Some(c) = args.content {
        c.into_bytes()
    } else if let Some(f) = args.file {
        fs::read(&f).with_context(|| format!("Failed to read --file {f}"))?
    } else {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("Failed to read stdin")?;
        buf
    };
    fs::write(&path, &bytes).with_context(|| format!("Failed to write {}", path.display()))?;
    let payload = json!({
        "schema": "n0x.dump.save.v1",
        "name": args.name,
        "kind": args.kind,
        "path": path.to_string_lossy(),
        "size": bytes.len(),
        "overwrote": args.force,
    });
    emit_success(out, payload, start, None);
    Ok(())
}

fn dump_list(args: DumpListArgs, out: &OutputMode, start: Instant) -> Result<()> {
    let root = project::resolve()?;
    let kinds: Vec<&str> = match args.kind {
        Some(ref k) => {
            ensure_kind(k)?;
            vec![k.as_str()]
        }
        None => project::DUMP_KINDS.to_vec(),
    };
    let mut items: Vec<Value> = Vec::new();
    for k in kinds {
        let dir = root.dump_kind_dir(k);
        if !dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
            let entry = entry?;
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let stem = p
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let meta = entry.metadata().ok();
            items.push(json!({
                "name": stem,
                "kind": k,
                "path": p.to_string_lossy(),
                "size": meta.as_ref().map(|m| m.len()).unwrap_or(0),
            }));
        }
    }
    let payload = json!({
        "schema": "n0x.dump.list.v1",
        "root": root.dir.to_string_lossy(),
        "items": items,
    });
    emit_success(out, payload, start, None);
    Ok(())
}

fn dump_show(args: DumpShowArgs, out: &OutputMode, start: Instant) -> Result<()> {
    let root = project::resolve()?;
    // If kind not specified, search all kinds for a matching name.
    let (kind, path) = match args.kind {
        Some(k) => {
            ensure_kind(&k)?;
            let p = dump_path_for(&root, &k, &args.name)?;
            (k, p)
        }
        None => {
            let mut found: Option<(String, PathBuf)> = None;
            for k in project::DUMP_KINDS {
                let p = dump_path_for(&root, k, &args.name)?;
                if p.exists() {
                    found = Some((k.to_string(), p));
                    break;
                }
            }
            match found {
                Some(x) => x,
                None => bail!("No dump named '{}' found in any kind", args.name),
            }
        }
    };
    if !path.exists() {
        bail!("No dump at {}", path.display());
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let preview = match kind.as_str() {
        "raw" | "hex" => {
            let n = args.preview.min(bytes.len());
            to_hex_spaced(&bytes[..n])
        }
        _ => String::from_utf8_lossy(&bytes).into_owned(),
    };
    let payload = json!({
        "schema": "n0x.dump.show.v1",
        "name": args.name,
        "kind": kind,
        "path": path.to_string_lossy(),
        "size": bytes.len(),
        "content": preview,
        "truncated": (kind == "raw" || kind == "hex") && args.preview < bytes.len(),
    });
    emit_success(out, payload, start, None);
    Ok(())
}

fn dump_rm(args: DumpRmArgs, out: &OutputMode, start: Instant) -> Result<()> {
    let root = project::resolve()?;
    let kinds: Vec<&str> = match args.kind {
        Some(ref k) => {
            ensure_kind(k)?;
            vec![k.as_str()]
        }
        None => project::DUMP_KINDS.to_vec(),
    };
    let mut removed: Vec<Value> = Vec::new();
    for k in kinds {
        let p = dump_path_for(&root, k, &args.name)?;
        if p.exists() {
            fs::remove_file(&p).with_context(|| format!("remove {}", p.display()))?;
            removed.push(json!({ "kind": k, "path": p.to_string_lossy() }));
        }
    }
    if removed.is_empty() {
        bail!("No dump named '{}' found", args.name);
    }
    let payload = json!({
        "schema": "n0x.dump.rm.v1",
        "name": args.name,
        "removed": removed,
    });
    emit_success(out, payload, start, None);
    Ok(())
}

fn handle_function(cmd: FunctionCommand, out: &OutputMode, start: Instant) -> Result<()> {
    match cmd.command {
        FunctionSubcommand::List(args) => {
            let pid = resolve_pid(args.pid)?;
            let mut symbols = collect_exported_functions(pid, args.module.as_deref())?;
            if let Some(query) = args.query.as_ref() {
                let q = query.to_lowercase();
                symbols.retain(|s| {
                    s.name.to_lowercase().contains(&q) || s.module.to_lowercase().contains(&q)
                });
            }
            symbols.sort_by(|a, b| {
                a.module
                    .cmp(&b.module)
                    .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            });
            if symbols.len() > args.limit {
                symbols.truncate(args.limit);
            }
            emit_success(
                out,
                json!({
                    "pid": pid,
                    "count": symbols.len(),
                    "functions": symbols,
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
        FunctionSubcommand::Info(args) => {
            let pid = resolve_pid(args.pid)?;
            let symbols = collect_exported_functions(pid, args.module.as_deref())?;
            let needle = args.name.to_lowercase();
            let matches: Vec<FunctionSymbolInfo> = symbols
                .into_iter()
                .filter(|s| s.name.to_lowercase() == needle)
                .collect();
            emit_success(
                out,
                json!({
                    "pid": pid,
                    "name": args.name,
                    "matches": matches,
                    "found": !matches.is_empty(),
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
        FunctionSubcommand::Discover(args) => {
            let pid = resolve_pid(args.pid)?;
            let functions = discover_functions(pid, &args.module, args.limit)?;
            emit_success(
                out,
                json!({
                    "pid": pid,
                    "module": args.module,
                    "count": functions.len(),
                    "functions": functions,
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
        FunctionSubcommand::Trace(args) => {
            let pid = resolve_pid(args.pid)?;
            let addr = parse_hex_u64(&args.addr)?;
            let trace = trace_functions(pid, &args.module, addr, args.depth)?;
            emit_success(
                out,
                json!({
                    "pid": pid,
                    "module": args.module,
                    "root": format!("0x{addr:X}"),
                    "depth": args.depth,
                    "trace": trace,
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
    }
}

fn handle_selection(cmd: SelectionCommand, out: &OutputMode, start: Instant) -> Result<()> {
    match cmd.command {
        SelectionSubcommand::Save(args) => {
            let pid = resolve_pid(args.pid)?;
            let start_addr = parse_hex_u64(&args.start)?;
            let end_addr = parse_hex_u64(&args.end)?;
            if end_addr <= start_addr {
                bail!("Selection end must be greater than start");
            }

            let mut selections = load_selections()?;
            let record = SelectionRecord {
                name: args.name.clone(),
                pid,
                module: args.module,
                start: format!("0x{start_addr:X}"),
                end: format!("0x{end_addr:X}"),
                note: args.note,
                created_at: iso_now(),
            };
            selections.retain(|s| s.name.to_lowercase() != args.name.to_lowercase());
            selections.push(record.clone());
            save_selections(&selections)?;

            emit_success(
                out,
                json!({
                    "saved": true,
                    "selection": record,
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
        SelectionSubcommand::List => {
            let selections = load_selections()?;
            emit_success(
                out,
                json!({
                    "count": selections.len(),
                    "selections": selections,
                }),
                start,
                None,
            );
            Ok(())
        }
        SelectionSubcommand::Show(args) => {
            let selections = load_selections()?;
            let selection = selections
                .into_iter()
                .find(|s| s.name.to_lowercase() == args.name.to_lowercase())
                .ok_or_else(|| anyhow!("Selection '{}' not found", args.name))?;
            let pid = selection.pid;
            let start_addr = parse_hex_u64(&selection.start)?;
            let end_addr = parse_hex_u64(&selection.end)?;
            let size = end_addr.saturating_sub(start_addr) as usize;
            let bytes = read_memory(pid, start_addr, size.min(4096))?;
            let disasm = disassemble_block(start_addr, &bytes, 80);
            emit_success(
                out,
                json!({
                    "selection": selection,
                    "preview": {
                        "sizeRequested": size,
                        "sizeRead": bytes.len(),
                        "bytesHex": to_hex_spaced(&bytes[..bytes.len().min(128)]),
                        "disasm": disasm,
                    }
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
        SelectionSubcommand::Xref(args) => {
            let selections = load_selections()?;
            let selection = selections
                .into_iter()
                .find(|s| s.name.to_lowercase() == args.name.to_lowercase())
                .ok_or_else(|| anyhow!("Selection '{}' not found", args.name))?;
            let pid = selection.pid;
            let start_addr = parse_hex_u64(&selection.start)?;
            let end_addr = parse_hex_u64(&selection.end)?;
            let size = end_addr.saturating_sub(start_addr) as usize;
            let bytes = read_memory(pid, start_addr, size)?;

            let mut entries = Vec::new();
            let mut decoder = Decoder::with_ip(64, &bytes, start_addr, DecoderOptions::NONE);
            let mut formatter = NasmFormatter::new();
            let mut line = String::new();
            while decoder.can_decode() {
                let ins = decoder.decode();
                if ins.is_invalid() {
                    continue;
                }
                let flow = format!("{:?}", ins.flow_control()).to_lowercase();
                let is_lea = {
                    let mut tmp = String::new();
                    formatter.format(&ins, &mut tmp);
                    tmp.to_lowercase().starts_with("lea ")
                };
                if !flow.contains("call") && !flow.contains("branch") && !is_lea {
                    continue;
                }
                line.clear();
                formatter.format(&ins, &mut line);
                let target = ins.near_branch_target();
                let kind = if is_lea {
                    "lea"
                } else if flow.contains("call") {
                    "call"
                } else {
                    "jmp"
                };
                entries.push(json!({
                    "from": format!("0x{:X}", ins.ip()),
                    "to": if target == 0 { Value::Null } else { json!(format!("0x{target:X}")) },
                    "kind": kind,
                    "instruction": line,
                }));
            }

            let report = json!({
                "selection": selection,
                "xrefCount": entries.len(),
                "xrefs": entries,
                "generatedAt": iso_now(),
            });
            let out_path = args
                .out
                .unwrap_or_else(|| format!("selection_{}_xrefs.json", args.name));
            let out_file = std::env::current_dir()?.join(out_path);
            fs::write(
                &out_file,
                serde_json::to_string_pretty(&report).context("Failed to serialize xref report")?,
            )?;

            emit_success(
                out,
                json!({
                    "written": true,
                    "file": out_file.to_string_lossy().to_string(),
                    "xrefCount": report["xrefCount"],
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
        SelectionSubcommand::Ir(args) => {
            let selections = load_selections()?;
            let selection = selections
                .into_iter()
                .find(|s| s.name.to_lowercase() == args.name.to_lowercase())
                .ok_or_else(|| anyhow!("Selection '{}' not found", args.name))?;
            let pid = selection.pid;
            let start_addr = parse_hex_u64(&selection.start)?;
            let end_addr = parse_hex_u64(&selection.end)?;
            let size = end_addr.saturating_sub(start_addr) as usize;
            let bytes = read_memory(pid, start_addr, size)?;
            let symbols = build_symbol_map_for_addr(pid, start_addr).ok();
            let iat = build_iat_map_for_addr(pid, start_addr).ok();
            let opts = ir::BuildOptions {
                auto_end: false,
                symbols: symbols.as_ref(),
                iat: iat.as_ref(),
            };
            let mut func = ir::build_function_ir(start_addr, &bytes, opts);
            resolve_switches(pid, &mut func, 256, symbols.as_ref());

            let payload = if args.explain {
                let lines = ir::explain(&func);
                json!({
                    "selection": selection,
                    "schema": "n0x.ir.explain.v1",
                    "summary": lines,
                    "stats": {
                        "instructions": func.instruction_count,
                        "blocks": func.block_count,
                        "returns": func.returns,
                        "indirectBranches": func.indirect_branches,
                        "tailCalls": func.tail_calls,
                        "callsites": func.callsites.len(),
                    },
                })
            } else {
                let synthetic = IrBuildArgs {
                    pid: Some(pid),
                    addr: format!("0x{start_addr:X}"),
                    size: 0,
                    no_auto_end: true,
                    no_resolve: false,
                    no_switch_resolve: true,
                    switch_cap: 0,
                    view: args.view.clone(),
                    block: args.block,
                    range: None,
                };
                json!({
                    "selection": selection,
                    "ir": render_ir_view(&func, &synthetic)?,
                })
            };

            if let Some(out_name) = args.out {
                let out_file = std::env::current_dir()?.join(out_name);
                fs::write(
                    &out_file,
                    serde_json::to_string_pretty(&payload)
                        .context("Failed to serialize selection IR")?,
                )?;
                emit_success(
                    out,
                    json!({
                        "written": true,
                        "file": out_file.to_string_lossy().to_string(),
                        "blocks": func.block_count,
                        "instructions": func.instruction_count,
                    }),
                    start,
                    Some(pid),
                );
            } else {
                emit_success(out, payload, start, Some(pid));
            }
            Ok(())
        }
    }
}

fn build_ir_for_args(args: &IrBuildArgs) -> Result<(u32, u64, ir::IrFunction, Option<ir::SymbolMap>)> {
    let pid = resolve_pid(args.pid)?;
    let addr = parse_hex_u64(&args.addr)?;
    let bytes = read_memory(pid, addr, args.size)?;
    let (symbols, iat) = if args.no_resolve {
        (None, None)
    } else {
        (
            build_symbol_map_for_addr(pid, addr).ok(),
            build_iat_map_for_addr(pid, addr).ok(),
        )
    };
    let opts = ir::BuildOptions {
        auto_end: !args.no_auto_end,
        symbols: symbols.as_ref(),
        iat: iat.as_ref(),
    };
    let mut func = ir::build_function_ir(addr, &bytes, opts);
    if !args.no_switch_resolve {
        resolve_switches(pid, &mut func, args.switch_cap, symbols.as_ref());
    }
    Ok((pid, addr, func, symbols))
}

/// Memory-side switch resolution: for every detected `IrSwitch`, read the
/// dispatch table from the live process and materialize the case targets,
/// then attach them as `kind: "switch"` successors on the dispatching block.
fn resolve_switches(
    pid: u32,
    func: &mut ir::IrFunction,
    hard_cap: usize,
    symbols: Option<&ir::SymbolMap>,
) {
    if hard_cap == 0 {
        return;
    }

    let func_start = parse_hex_u64(&func.address).unwrap_or(0);
    let func_end = parse_hex_u64(&func.end_address).unwrap_or(0);

    for sw in func.switches.iter_mut() {
        let Some(table_str) = sw.table.clone() else {
            continue;
        };
        let table = match parse_hex_u64(&table_str) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let n = sw
            .bound
            .map(|b| b as usize)
            .filter(|b| *b > 0)
            .unwrap_or(hard_cap)
            .min(hard_cap);
        if n == 0 {
            continue;
        }

        let cases_u64: Vec<u64> = match sw.kind {
            "mem-indexed" => {
                let want = n.saturating_mul(8);
                let bytes = match read_memory(pid, table, want) {
                    Ok(b) if b.len() >= 8 => b,
                    _ => continue,
                };
                bytes
                    .chunks_exact(8)
                    .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
                    .collect()
            }
            "reg-rel32" => {
                let want = n.saturating_mul(4);
                let bytes = match read_memory(pid, table, want) {
                    Ok(b) if b.len() >= 4 => b,
                    _ => continue,
                };
                bytes
                    .chunks_exact(4)
                    .map(|c| {
                        let off = i32::from_le_bytes(c.try_into().unwrap());
                        table.wrapping_add(off as i64 as u64)
                    })
                    .collect()
            }
            _ => continue,
        };

        // Sanity filter: drop NULL/zero entries and obvious garbage outside the
        // function body. Stop at the first invalid entry to avoid slurping
        // adjacent unrelated data when the bound was unknown.
        let mut keep: Vec<u64> = Vec::new();
        for c in cases_u64 {
            if c == 0 {
                break;
            }
            let inside_function = func_start != 0
                && func_end != 0
                && c >= func_start
                && c < func_end;
            let known_symbol = symbols.map_or(false, |m| m.contains_key(&c));
            if !inside_function && !known_symbol && sw.bound.is_none() {
                // Without a known bound, refuse to follow targets outside the
                // current function unless they're known symbols.
                break;
            }
            keep.push(c);
        }
        if keep.is_empty() {
            continue;
        }

        sw.cases = keep.iter().map(|c| format!("0x{c:X}")).collect();

        let at_addr = parse_hex_u64(&sw.at).unwrap_or(0);
        if let Some(block) = func.blocks.iter_mut().find(|b| {
            b.instructions
                .last()
                .map_or(false, |i| parse_hex_u64(&i.address).unwrap_or(0) == at_addr)
        }) {
            for (idx, c) in keep.iter().enumerate() {
                block.successors.push(ir::IrSuccessor {
                    to: format!("0x{c:X}"),
                    kind: "switch",
                    confidence: 0.85,
                    case_index: Some(idx),
                });
            }
            block.terminator = "switch";
        }
    }
}

fn parse_addr_range(s: &str) -> Result<(u64, u64)> {
    let (lhs, rhs) = s
        .split_once('-')
        .ok_or_else(|| anyhow!("--range must look like 0xSTART-0xEND"))?;
    let from = parse_hex_u64(lhs.trim())?;
    let to = parse_hex_u64(rhs.trim())?;
    if to <= from {
        bail!("--range end (0x{to:X}) must be greater than start (0x{from:X})");
    }
    Ok((from, to))
}

fn render_ir_view(func: &ir::IrFunction, args: &IrBuildArgs) -> Result<Value> {
    let range = args.range.as_deref().map(parse_addr_range).transpose()?;
    let in_range = |addr_hex: &str| -> bool {
        let Some((from, to)) = range else { return true };
        let a = parse_hex_u64(addr_hex).unwrap_or(0);
        a >= from && a < to
    };

    match args.view {
        IrView::Cfg => Ok(serde_json::to_value(ir::cfg(func))?),
        IrView::Minimal => {
            let blocks_meta: Vec<Value> = func
                .blocks
                .iter()
                .filter(|b| args.block.map_or(true, |id| b.id == id))
                .filter(|b| in_range(&b.address))
                .map(|b| {
                    json!({
                        "id": b.id,
                        "address": b.address,
                        "endAddress": b.end_address,
                        "terminator": b.terminator,
                        "successors": b.successors,
                        "instructionCount": b.instructions.len(),
                    })
                })
                .collect();
            let callsites: Vec<&ir::IrCallsite> = func
                .callsites
                .iter()
                .filter(|c| in_range(&c.from))
                .collect();
            Ok(json!({
                "schema": "n0x.ir.minimal.v1",
                "address": func.address,
                "endAddress": func.end_address,
                "instructionCount": func.instruction_count,
                "blockCount": func.block_count,
                "returns": func.returns,
                "tailCalls": func.tail_calls,
                "indirectBranches": func.indirect_branches,
                "frame": &func.frame,
                "blocks": blocks_meta,
                "callsites": callsites,
                "switches": &func.switches,
            }))
        }
        IrView::Block => {
            let id = args
                .block
                .ok_or_else(|| anyhow!("--view block requires --block <id>"))?;
            let block = func
                .blocks
                .iter()
                .find(|b| b.id == id)
                .ok_or_else(|| anyhow!("Block id {id} not found (have {} blocks)", func.block_count))?;
            Ok(json!({
                "schema": "n0x.ir.block.v1",
                "function": func.address,
                "block": block,
            }))
        }
        IrView::Full => {
            if args.block.is_none() && range.is_none() {
                return Ok(serde_json::to_value(func)?);
            }
            let mut value = serde_json::to_value(func)?;
            if let Some(blocks) = value.get_mut("blocks").and_then(Value::as_array_mut) {
                blocks.retain(|b| {
                    let id_ok = args.block.map_or(true, |id| {
                        b.get("id").and_then(Value::as_u64) == Some(id as u64)
                    });
                    let range_ok = range.map_or(true, |(from, to)| {
                        let addr = b
                            .get("address")
                            .and_then(Value::as_str)
                            .map(|s| parse_hex_u64(s).unwrap_or(0))
                            .unwrap_or(0);
                        let end = b
                            .get("end_address")
                            .and_then(Value::as_str)
                            .map(|s| parse_hex_u64(s).unwrap_or(0))
                            .unwrap_or(0);
                        addr < to && end > from
                    });
                    id_ok && range_ok
                });
                if let Some((from, to)) = range {
                    for b in blocks.iter_mut() {
                        if let Some(instrs) =
                            b.get_mut("instructions").and_then(Value::as_array_mut)
                        {
                            instrs.retain(|i| {
                                let a = i
                                    .get("address")
                                    .and_then(Value::as_str)
                                    .map(|s| parse_hex_u64(s).unwrap_or(0))
                                    .unwrap_or(0);
                                a >= from && a < to
                            });
                        }
                    }
                }
            }
            if let Some(cs) = value.get_mut("callsites").and_then(Value::as_array_mut) {
                cs.retain(|c| {
                    range.map_or(true, |(from, to)| {
                        let a = c
                            .get("from")
                            .and_then(Value::as_str)
                            .map(|s| parse_hex_u64(s).unwrap_or(0))
                            .unwrap_or(0);
                        a >= from && a < to
                    })
                });
            }
            Ok(value)
        }
    }
}

fn handle_ir(cmd: IrCommand, out: &OutputMode, start: Instant) -> Result<()> {
    match cmd.command {
        IrSubcommand::Build(args) => {
            let (pid, _addr, func, _syms) = build_ir_for_args(&args)?;
            let payload = render_ir_view(&func, &args)?;
            emit_success(out, payload, start, Some(pid));
            Ok(())
        }
        IrSubcommand::Explain(args) => {
            let (pid, _addr, func, _syms) = build_ir_for_args(&args)?;
            let lines = ir::explain(&func);
            emit_success(
                out,
                json!({
                    "schema": "n0x.ir.explain.v1",
                    "address": func.address,
                    "endAddress": func.end_address,
                    "summary": lines,
                    "stats": {
                        "instructions": func.instruction_count,
                        "blocks": func.block_count,
                        "returns": func.returns,
                        "indirectBranches": func.indirect_branches,
                        "tailCalls": func.tail_calls,
                        "callsites": func.callsites.len(),
                        "frameSize": format!("0x{:X}", func.frame.frame_size),
                        "spilledRegs": func.frame.spilled_regs.clone(),
                    },
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
        IrSubcommand::Cfg(args) => {
            let (pid, _addr, func, _syms) = build_ir_for_args(&args)?;
            let cfg = ir::cfg(&func);
            emit_success(out, serde_json::to_value(&cfg)?, start, Some(pid));
            Ok(())
        }
        IrSubcommand::Dot(args) => {
            let (pid, _addr, func, _syms) = build_ir_for_args(&args)?;
            let dot = ir::dot(&func);
            emit_success(out, serde_json::to_value(&dot)?, start, Some(pid));
            Ok(())
        }
        IrSubcommand::Slice(args) => {
            let (pid, addr, func, _syms) = build_ir_for_args(&args.build)?;
            let sliced = ir::slice(&func, addr, &args.reg);
            emit_success(out, serde_json::to_value(&sliced)?, start, Some(pid));
            Ok(())
        }
        IrSubcommand::Manifest(args) => handle_ir_manifest(args, out, start),
    }
}

fn handle_ir_manifest(args: IrManifestArgs, out: &OutputMode, start: Instant) -> Result<()> {
    let pid = resolve_pid(args.pid)?;

    let want_exports = matches!(args.source.as_str(), "exports" | "both");
    let want_discover = matches!(args.source.as_str(), "discover" | "both");
    if !want_exports && !want_discover {
        bail!("--source must be one of: exports | discover | both");
    }

    // Collect candidate entries, tagged with their source. Discover results
    // are heuristic prologs (sub_<addr>); exports are PE export names.
    let mut candidates: Vec<(String, &'static str, u64)> = Vec::new();
    let filter = args.filter.as_ref().map(|s| s.to_lowercase());

    if want_exports {
        let exports = collect_exported_functions(pid, Some(&args.module))?;
        for s in exports {
            if let Some(f) = filter.as_ref() {
                if !s.name.to_lowercase().contains(f) {
                    continue;
                }
            }
            if let Ok(addr) = parse_hex_u64(&s.address) {
                candidates.push((s.name, "export", addr));
            }
        }
    }
    if want_discover {
        let discovered = discover_functions(pid, &args.module, args.limit.saturating_mul(2))?;
        for s in discovered {
            if let Some(f) = filter.as_ref() {
                if !s.name.to_lowercase().contains(f) {
                    continue;
                }
            }
            if let Ok(addr) = parse_hex_u64(&s.address) {
                candidates.push((s.name, "discover", addr));
            }
        }
    }

    // Deduplicate by address: prefer "export" over "discover" when both
    // surface the same entry point.
    candidates.sort_by(|a, b| a.2.cmp(&b.2).then(rank_source(a.1).cmp(&rank_source(b.1))));
    candidates.dedup_by_key(|c| c.2);

    let total = candidates.len();
    let take = candidates.len().min(args.limit);
    candidates.truncate(take);

    let mut entries: Vec<ir::IrManifestEntry> = Vec::with_capacity(take);
    let mut skipped = 0usize;

    for (name, source, addr) in candidates {
        let bytes = match read_memory(pid, addr, args.size) {
            Ok(b) if !b.is_empty() => b,
            _ => {
                skipped += 1;
                continue;
            }
        };
        let opts = ir::BuildOptions {
            auto_end: true,
            symbols: None,
            iat: None,
        };
        let func = ir::build_function_ir(addr, &bytes, opts);
        if func.instruction_count == 0 {
            skipped += 1;
            continue;
        }
        let entry = ir::manifest_entry(name, source, &func);
        if let Some(min_q) = args.min_quality {
            if entry.quality < min_q {
                continue;
            }
        }
        entries.push(entry);
    }

    match args.sort.as_str() {
        "quality" => entries.sort_by(|a, b| b.quality.partial_cmp(&a.quality).unwrap_or(std::cmp::Ordering::Equal)),
        "address" => entries.sort_by(|a, b| {
            parse_hex_u64(&a.address)
                .unwrap_or(0)
                .cmp(&parse_hex_u64(&b.address).unwrap_or(0))
        }),
        other => bail!("--sort must be one of: quality | address (got '{other}')"),
    }

    emit_success(
        out,
        json!({
            "schema": ir::SCHEMA_MANIFEST,
            "module": args.module,
            "source": args.source,
            "candidates": total,
            "analyzed": take,
            "skipped": skipped,
            "returned": entries.len(),
            "entries": entries,
        }),
        start,
        Some(pid),
    );
    Ok(())
}

fn rank_source(s: &str) -> u8 {
    match s {
        "export" => 0,
        "discover" => 1,
        _ => 2,
    }
}

fn handle_decomp(cmd: DecompCommand, out: &OutputMode, start: Instant) -> Result<()> {
    match cmd.command {
        DecompSubcommand::Pseudo(pargs) => {
            let args = &pargs.build;
            let pid = resolve_pid(args.pid)?;
            let addr = parse_hex_u64(&args.addr)?;
            let bytes = read_memory(pid, addr, args.size)?;
            let (symbols, iat) = if args.no_resolve {
                (None, None)
            } else {
                (
                    build_symbol_map_for_addr(pid, addr).ok(),
                    build_iat_map_for_addr(pid, addr).ok(),
                )
            };
            let opts = ir::BuildOptions {
                auto_end: !args.no_auto_end,
                symbols: symbols.as_ref(),
                iat: iat.as_ref(),
            };
            let mut func = ir::build_function_ir(addr, &bytes, opts);
            if !args.no_switch_resolve {
                resolve_switches(pid, &mut func, args.switch_cap, symbols.as_ref());
            }
            let style = match pargs.style {
                PseudoStyle::Goto => pseudo::Style::Goto,
                PseudoStyle::Structured => pseudo::Style::Structured,
            };
            let pseudo_fn = pseudo::render_with(
                addr,
                &bytes,
                &func,
                symbols.as_ref(),
                iat.as_ref(),
                style,
            );
            emit_success(out, serde_json::to_value(&pseudo_fn)?, start, Some(pid));
            Ok(())
        }
    }
}

/// Build a unified absolute-address -> "module!symbol" map across **every**
/// loaded module in the target process. This lets the IR layer resolve
/// cross-module direct call/jmp targets (kernel32!CreateFileW, etc.), not
/// only intra-module references.
fn build_symbol_map_for_addr(pid: u32, _addr: u64) -> Result<ir::SymbolMap> {
    let symbols = collect_exported_functions(pid, None)?;
    let mut map: ir::SymbolMap = std::collections::BTreeMap::new();
    for s in symbols {
        if let Ok(a) = parse_hex_u64(&s.address) {
            map.insert(a, format!("{}!{}", s.module, s.name));
        }
    }
    Ok(map)
}

/// Build IAT-slot-address -> "DLL!Name" map for the module that owns `addr`.
/// Resolves `call qword ptr [rip+disp]` style indirect imports by mapping the
/// IAT slot the instruction reads to the imported function name.
fn build_iat_map_for_addr(pid: u32, addr: u64) -> Result<ir::SymbolMap> {
    let modules = enumerate_modules(pid)?;
    let owner = modules
        .into_iter()
        .find(|m| {
            let base = parse_hex_u64(&m.base_address).unwrap_or(0);
            addr >= base && addr < base.saturating_add(m.size)
        })
        .ok_or_else(|| anyhow!("No module contains address 0x{addr:X}"))?;

    let base = parse_hex_u64(&owner.base_address)?;
    let path = PathBuf::from(&owner.path);
    if !path.exists() {
        bail!("Module file not found: {}", owner.path);
    }
    let bytes = fs::read(&path)
        .with_context(|| format!("Failed to read module '{}' for IAT", owner.path))?;
    let pe = PE::parse(&bytes)
        .with_context(|| format!("Failed to parse PE '{}' for IAT", owner.path))?;

    let mut map: ir::SymbolMap = std::collections::BTreeMap::new();
    for import in &pe.imports {
        let slot = base.saturating_add(import.rva as u64);
        let dll = import.dll.trim_end_matches('\0');
        let dll_short = std::path::Path::new(dll)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(dll);
        map.insert(slot, format!("{}!{}", dll_short, import.name));
    }
    Ok(map)
}

#[derive(Debug, Clone, Copy)]
struct OutputMode {
    json: bool,
    pretty: bool,
}

fn handle_process(cmd: ProcessCommand, out: &OutputMode, start: Instant) -> Result<()> {
    match cmd.command {
        ProcessSubcommand::Ps(args) => {
            let mut system = System::new_all();
            system.refresh_processes(ProcessesToUpdate::All, true);
            let filter = args.filter.as_deref().map(str::to_lowercase);

            let mut processes: Vec<ProcessInfo> = system
                .processes()
                .iter()
                .filter_map(|(pid, process)| {
                    let pid_u32 = pid.as_u32();
                    let name = process.name().to_string_lossy().to_string();
                    let exe = process
                        .exe()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let passes_filter = filter.as_ref().is_none_or(|f| {
                        name.to_lowercase().contains(f)
                            || exe.to_lowercase().contains(f)
                            || pid_u32.to_string().contains(f)
                    });
                    if !passes_filter {
                        return None;
                    }

                    Some(ProcessInfo {
                        pid: pid_u32,
                        name,
                        arch: detect_arch(pid_u32).unwrap_or_else(|_| "unknown".to_string()),
                        cpu: process.cpu_usage(),
                        memory_mb: process.memory() as f64 / 1024.0 / 1024.0,
                        status: format!("{:?}", process.status()),
                        path: exe,
                    })
                })
                .collect();

            processes.sort_by_key(|p| p.pid);
            emit_success(out, json!(processes), start, None);
            Ok(())
        }
    }
}

fn handle_target(cmd: TargetCommand, out: &OutputMode, start: Instant) -> Result<()> {
    match cmd.command {
        TargetSubcommand::Attach(args) => {
            let _handle = open_process(args.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)?;
            let mut session = load_session()?;
            session.attached_pid = Some(args.pid);
            save_session(&session)?;
            emit_success(out, json!({"attachedPid": args.pid}), start, Some(args.pid));
            Ok(())
        }
        TargetSubcommand::Detach => {
            let mut session = load_session()?;
            session.attached_pid = None;
            save_session(&session)?;
            emit_success(out, json!({"detached": true}), start, None);
            Ok(())
        }
        TargetSubcommand::Info => {
            let session = load_session()?;
            let info = if let Some(pid) = session.attached_pid {
                let mut system = System::new_all();
                system.refresh_processes(ProcessesToUpdate::All, true);
                let process = system.process(Pid::from_u32(pid));
                json!({
                    "attachedPid": pid,
                    "alive": process.is_some(),
                })
            } else {
                json!({"attachedPid": Value::Null, "alive": false})
            };
            emit_success(out, info, start, session.attached_pid);
            Ok(())
        }
    }
}

fn handle_module(cmd: ModuleCommand, out: &OutputMode, start: Instant) -> Result<()> {
    match cmd.command {
        ModuleSubcommand::List(args) => {
            let pid = resolve_pid(args.pid)?;
            let modules = enumerate_modules(pid)?;

            emit_success(
                out,
                json!({
                    "pid": pid,
                    "modules": modules,
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
    }
}

fn handle_mem(cmd: MemCommand, out: &OutputMode, start: Instant) -> Result<()> {
    match cmd.command {
        MemSubcommand::Read(args) => {
            let pid = resolve_pid(args.pid)?;
            let address = parse_hex_u64(&args.addr)?;
            let bytes = read_memory(pid, address, args.size)?;
            emit_success(
                out,
                json!({
                    "pid": pid,
                    "address": format!("0x{address:X}"),
                    "size": bytes.len(),
                    "bytesHex": to_hex_spaced(&bytes),
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
        MemSubcommand::Write(args) => {
            let pid = resolve_pid(args.pid)?;
            let address = parse_hex_u64(&args.addr)?;
            let bytes = parse_hex_bytes(&args.bytes)?;
            let written = write_memory(pid, address, &bytes)?;
            emit_success(
                out,
                json!({
                    "pid": pid,
                    "address": format!("0x{address:X}"),
                    "bytesWritten": written,
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
        MemSubcommand::Map(args) => {
            let pid = resolve_pid(args.pid)?;
            let regions = enumerate_memory_map(pid, args.limit)?;
            let state_q = args.state.as_ref().map(|s| s.to_lowercase());
            let kind_q = args.kind.as_ref().map(|s| s.to_lowercase());
            let protect_q = args.protect.as_ref().map(|s| s.to_lowercase());
            let filtered: Vec<MemoryRegionInfo> = regions
                .into_iter()
                .filter(|r| {
                    state_q
                        .as_ref()
                        .is_none_or(|q| r.state.to_lowercase().contains(q))
                        && kind_q
                            .as_ref()
                            .is_none_or(|q| r.kind.to_lowercase().contains(q))
                        && protect_q
                            .as_ref()
                            .is_none_or(|q| r.protection.to_lowercase().contains(q))
                })
                .collect();
            emit_success(
                out,
                json!({
                    "pid": pid,
                    "count": filtered.len(),
                    "regions": filtered,
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
    }
}

fn handle_patch(cmd: PatchCommand, out: &OutputMode, start: Instant) -> Result<()> {
    match cmd.command {
        PatchSubcommand::DryRun(args) => {
            let pid = resolve_pid(args.pid)?;
            let address = parse_hex_u64(&args.addr)?;
            let desired = parse_hex_bytes(&args.bytes)?;
            let current = read_memory(pid, address, desired.len())?;
            let same = current == desired;
            emit_success(
                out,
                json!({
                    "schema": "n0x.patch.dryrun.v1",
                    "pid": pid,
                    "address": format!("0x{address:X}"),
                    "size": desired.len(),
                    "currentHex": to_hex_spaced(&current),
                    "desiredHex": to_hex_spaced(&desired),
                    "wouldChange": !same,
                    "diffBytes": byte_diff_count(&current, &desired),
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
        PatchSubcommand::Apply(args) => {
            let pid = resolve_pid(args.pid)?;
            let address = parse_hex_u64(&args.addr)?;
            let desired = parse_hex_bytes(&args.bytes)?;
            let before = read_memory(pid, address, desired.len())?;
            let bytes_written = write_memory(pid, address, &desired)?;
            if bytes_written != desired.len() {
                bail!(
                    "Short write at 0x{address:X}: wrote {bytes_written} of {}",
                    desired.len()
                );
            }
            let after = read_memory(pid, address, desired.len())?;
            if after != desired {
                bail!("Post-write verification failed at 0x{address:X}");
            }
            let rec = PatchRecord {
                id: new_patch_id(),
                pid,
                address: format!("0x{address:X}"),
                size: desired.len(),
                before_hex: to_hex_spaced(&before),
                after_hex: to_hex_spaced(&desired),
                status: "applied".to_string(),
                created_at_unix: now_unix_secs(),
                undone_at_unix: None,
            };
            let rec_path = save_patch_record(&rec)?;
            emit_success(
                out,
                json!({
                    "schema": "n0x.patch.apply.v1",
                    "id": rec.id,
                    "recordPath": rec_path.to_string_lossy(),
                    "pid": pid,
                    "address": rec.address,
                    "size": rec.size,
                    "diffBytes": byte_diff_count(&before, &desired),
                    "bytesWritten": bytes_written,
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
        PatchSubcommand::List(args) => {
            let records = list_patch_records(args.limit)?;
            let status_q = args.status.as_deref().map(|s| s.to_ascii_lowercase());
            let filtered: Vec<PatchRecord> = records
                .into_iter()
                .filter(|r| status_q.as_ref().is_none_or(|q| r.status.to_ascii_lowercase() == *q))
                .collect();
            emit_success(
                out,
                json!({
                    "schema": "n0x.patch.list.v1",
                    "count": filtered.len(),
                    "items": filtered,
                }),
                start,
                None,
            );
            Ok(())
        }
        PatchSubcommand::Show(args) => {
            let rec = load_patch_record_by_id(&args.id)?;
            emit_success(
                out,
                json!({
                    "schema": "n0x.patch.show.v1",
                    "item": rec,
                }),
                start,
                None,
            );
            Ok(())
        }
        PatchSubcommand::Undo(args) => {
            let mut rec = if let Some(id) = args.id {
                load_patch_record_by_id(&id)?
            } else {
                load_latest_patch_record()?
            };
            if rec.status != "applied" {
                bail!("Patch {} status is '{}', nothing to undo", rec.id, rec.status);
            }
            let pid = resolve_pid(args.pid.or(Some(rec.pid)))?;
            let address = parse_hex_u64(&rec.address)?;
            let after_bytes = parse_hex_bytes(&rec.after_hex)?;
            let before_bytes = parse_hex_bytes(&rec.before_hex)?;
            let current = read_memory(pid, address, before_bytes.len())?;
            if current != after_bytes && !args.force {
                bail!(
                    "Undo safety check failed: current bytes at {} do not match patch-after bytes. Re-run with --force to override.",
                    rec.address
                );
            }
            let bytes_written = write_memory(pid, address, &before_bytes)?;
            if bytes_written != before_bytes.len() {
                bail!(
                    "Short undo write at {}: wrote {bytes_written} of {}",
                    rec.address,
                    before_bytes.len()
                );
            }
            let verify = read_memory(pid, address, before_bytes.len())?;
            if verify != before_bytes {
                bail!("Undo verification failed at {}", rec.address);
            }
            rec.status = "undone".to_string();
            rec.undone_at_unix = Some(now_unix_secs());
            let rec_path = save_patch_record(&rec)?;
            emit_success(
                out,
                json!({
                    "schema": "n0x.patch.undo.v1",
                    "id": rec.id,
                    "recordPath": rec_path.to_string_lossy(),
                    "pid": pid,
                    "address": rec.address,
                    "size": rec.size,
                    "bytesWritten": bytes_written,
                    "forced": args.force,
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
    }
}

fn handle_disasm(args: DisasmArgs, out: &OutputMode, start: Instant) -> Result<()> {
    let pid = resolve_pid(args.pid)?;
    let address = parse_hex_u64(&args.addr)?;
    let size = args.count.saturating_mul(16).max(16);
    let bytes = read_memory(pid, address, size)?;
    let instructions = disassemble_block(address, &bytes, args.count);
    emit_success(
        out,
        json!({
            "pid": pid,
            "start": format!("0x{address:X}"),
            "countRequested": args.count,
            "instructions": instructions,
        }),
        start,
        Some(pid),
    );
    Ok(())
}

fn handle_xref(cmd: XrefCommand, out: &OutputMode, start: Instant) -> Result<()> {
    match cmd.command {
        XrefSubcommand::To(args) => {
            let pid = resolve_pid(args.pid)?;
            let target = parse_hex_u64(&args.addr)?;
            let scan_start = parse_hex_u64(&args.start)?;
            let bytes = read_memory(pid, scan_start, args.size)?;
            let refs = collect_xrefs_to(scan_start, &bytes, target, args.kind.as_deref());
            emit_success(
                out,
                json!({
                    "pid": pid,
                    "target": format!("0x{target:X}"),
                    "scanStart": format!("0x{scan_start:X}"),
                    "scanSize": args.size,
                    "kind": args.kind,
                    "xrefs": refs,
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
        XrefSubcommand::From(args) => {
            let pid = resolve_pid(args.pid)?;
            let source = parse_hex_u64(&args.addr)?;
            let scan_start = parse_hex_u64(&args.start)?;
            let bytes = read_memory(pid, scan_start, args.size)?;
            let refs = collect_xrefs_from(scan_start, &bytes, source, args.kind.as_deref());
            emit_success(
                out,
                json!({
                    "pid": pid,
                    "source": format!("0x{source:X}"),
                    "scanStart": format!("0x{scan_start:X}"),
                    "scanSize": args.size,
                    "kind": args.kind,
                    "xrefs": refs,
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
        XrefSubcommand::String(args) => {
            let pid = resolve_pid(args.pid)?;
            let result = xref_string(pid, &args.module, &args.query, args.limit)?;
            emit_success(
                out,
                json!({
                    "pid": pid,
                    "module": args.module,
                    "query": args.query,
                    "hits": result,
                }),
                start,
                Some(pid),
            );
            Ok(())
        }
    }
}

fn handle_doctor(args: DoctorArgs, out: &OutputMode, start: Instant) -> Result<()> {
    let mut checks = Vec::new();
    checks.push(json!({
        "name": "platform",
        "ok": cfg!(windows),
        "detail": if cfg!(windows) { "Windows detected" } else { "Unsupported platform" },
    }));

    let session = load_session()?;
    checks.push(json!({
        "name": "session",
        "ok": true,
        "detail": format!("attachedPid={:?}", session.attached_pid),
    }));

    if let Some(path) = args.dll_path {
        let exists = Path::new(&path).exists();
        checks.push(json!({
            "name": "dll_path",
            "ok": exists,
            "detail": path,
        }));
    }

    if let Some(pid) = args.pid.or(session.attached_pid) {
        let open_ok = open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).is_ok();
        checks.push(json!({
            "name": "target_open",
            "ok": open_ok,
            "detail": format!("pid={pid}"),
        }));

        let module_ok = enumerate_modules(pid).is_ok();
        checks.push(json!({
            "name": "module_enum",
            "ok": module_ok,
            "detail": format!("pid={pid}"),
        }));
    }

    let all_ok = checks
        .iter()
        .all(|c| c.get("ok").and_then(Value::as_bool).unwrap_or(false));
    emit_success(
        out,
        json!({
            "healthy": all_ok,
            "checks": checks,
        }),
        start,
        session.attached_pid,
    );
    Ok(())
}

fn collect_xrefs_to(start_ip: u64, bytes: &[u8], target: u64, kind: Option<&str>) -> Vec<Value> {
    let kind_l = kind.unwrap_or("all").to_lowercase();
    let mut decoder = Decoder::with_ip(64, bytes, start_ip, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut out = String::new();
    let mut result = Vec::new();

    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            continue;
        }
        let flow = format!("{:?}", instruction.flow_control());
        let is_branch = instruction.near_branch_target() == target;
        let is_kind_ok = kind_l == "all"
            || (kind_l.contains("call") && flow.to_lowercase().contains("call"))
            || (kind_l.contains("jmp") && flow.to_lowercase().contains("branch"));
        if is_branch && is_kind_ok {
            out.clear();
            formatter.format(&instruction, &mut out);
            result.push(json!({
                "from": format!("0x{:X}", instruction.ip()),
                "to": format!("0x{:X}", target),
                "flow": flow,
                "kind": if flow.to_lowercase().contains("call") { "call" } else { "jmp" },
                "instruction": out,
            }));
        }
    }
    if kind_l == "all" || kind_l.contains("lea") {
        result.extend(collect_lea_xrefs_to(start_ip, bytes, target));
    }
    result
}

fn collect_xrefs_from(start_ip: u64, bytes: &[u8], source: u64, kind: Option<&str>) -> Vec<Value> {
    let kind_l = kind.unwrap_or("all").to_lowercase();
    let mut decoder = Decoder::with_ip(64, bytes, start_ip, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut out = String::new();
    let mut result = Vec::new();

    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            continue;
        }
        if instruction.ip() != source {
            continue;
        }
        let flow = format!("{:?}", instruction.flow_control());
        let target = instruction.near_branch_target();
        if target == 0
            || !(kind_l == "all"
                || (kind_l.contains("call") && flow.to_lowercase().contains("call"))
                || (kind_l.contains("jmp") && flow.to_lowercase().contains("branch")))
        {
            continue;
        }
        out.clear();
        formatter.format(&instruction, &mut out);
        result.push(json!({
            "from": format!("0x{:X}", source),
            "to": format!("0x{:X}", target),
            "flow": flow,
            "kind": if flow.to_lowercase().contains("call") { "call" } else { "jmp" },
            "instruction": out,
        }));
    }
    if kind_l == "all" || kind_l.contains("lea") {
        result.extend(collect_lea_xrefs_from(start_ip, bytes, source));
    }
    result
}

fn collect_lea_xrefs_to(start_ip: u64, bytes: &[u8], target: u64) -> Vec<Value> {
    let mut refs = Vec::new();
    if bytes.len() < 7 {
        return refs;
    }
    for i in 0..(bytes.len() - 6) {
        if bytes[i] == 0x48 && bytes[i + 1] == 0x8D {
            let modrm = bytes[i + 2];
            if (modrm & 0xC7) == 0x05 {
                let disp =
                    i32::from_le_bytes([bytes[i + 3], bytes[i + 4], bytes[i + 5], bytes[i + 6]]);
                let src = start_ip.saturating_add(i as u64);
                let dst = src.saturating_add(7).wrapping_add(disp as i64 as u64);
                if dst == target {
                    refs.push(json!({
                        "from": format!("0x{src:X}"),
                        "to": format!("0x{dst:X}"),
                        "flow": "DataRef",
                        "kind": "lea",
                        "instruction": "lea reg, [rip+disp32]",
                    }));
                }
            }
        }
    }
    refs
}

fn collect_lea_xrefs_from(start_ip: u64, bytes: &[u8], source: u64) -> Vec<Value> {
    let mut refs = Vec::new();
    let idx = source.saturating_sub(start_ip) as usize;
    if idx + 7 > bytes.len() {
        return refs;
    }
    if bytes[idx] == 0x48 && bytes[idx + 1] == 0x8D {
        let modrm = bytes[idx + 2];
        if (modrm & 0xC7) == 0x05 {
            let disp = i32::from_le_bytes([
                bytes[idx + 3],
                bytes[idx + 4],
                bytes[idx + 5],
                bytes[idx + 6],
            ]);
            let dst = source.saturating_add(7).wrapping_add(disp as i64 as u64);
            refs.push(json!({
                "from": format!("0x{source:X}"),
                "to": format!("0x{dst:X}"),
                "flow": "DataRef",
                "kind": "lea",
                "instruction": "lea reg, [rip+disp32]",
            }));
        }
    }
    refs
}

fn disassemble_block(start_ip: u64, bytes: &[u8], count: usize) -> Vec<Value> {
    let mut decoder = Decoder::with_ip(64, bytes, start_ip, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut line = String::new();
    let mut output = Vec::new();

    while decoder.can_decode() && output.len() < count {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            continue;
        }
        line.clear();
        formatter.format(&instruction, &mut line);
        output.push(json!({
            "address": format!("0x{:X}", instruction.ip()),
            "len": instruction.len(),
            "flow": format!("{:?}", instruction.flow_control()),
            "isBranch": instruction.flow_control() != FlowControl::Next,
            "text": line,
        }));
    }
    output
}

fn parse_hex_u64(value: &str) -> Result<u64> {
    let trimmed = value
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    u64::from_str_radix(trimmed, 16).with_context(|| format!("Invalid hex address: {value}"))
}

fn parse_hex_bytes(input: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for chunk in input.split_whitespace() {
        let b = u8::from_str_radix(chunk, 16)
            .with_context(|| format!("Invalid byte token '{chunk}', expected hex like '90'"))?;
        bytes.push(b);
    }
    if bytes.is_empty() {
        bail!("No bytes provided. Example: \"90 90 C3\"");
    }
    Ok(bytes)
}

fn to_hex_spaced(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn session_path() -> Result<PathBuf> {
    let root = project::resolve()?;
    fs::create_dir_all(&root.dir).context("Failed to create n0x state directory")?;
    Ok(root.session_path())
}

fn selections_path() -> Result<PathBuf> {
    let root = project::resolve()?;
    fs::create_dir_all(&root.dir).context("Failed to create n0x state directory")?;
    Ok(root.selections_path())
}

fn load_session() -> Result<SessionState> {
    let path = session_path()?;
    if !path.exists() {
        return Ok(SessionState { attached_pid: None });
    }
    let raw = fs::read_to_string(&path).context("Failed to read session file")?;
    let state: SessionState = serde_json::from_str(&raw).context("Failed to parse session file")?;
    Ok(state)
}

fn save_session(state: &SessionState) -> Result<()> {
    let raw = serde_json::to_string_pretty(state).context("Failed to serialize session")?;
    fs::write(session_path()?, raw).context("Failed to write session file")
}

fn load_selections() -> Result<Vec<SelectionRecord>> {
    let path = selections_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(&path).context("Failed to read selections file")?;
    let items: Vec<SelectionRecord> =
        serde_json::from_str(&raw).context("Failed to parse selections file")?;
    Ok(items)
}

fn save_selections(items: &[SelectionRecord]) -> Result<()> {
    let raw = serde_json::to_string_pretty(items).context("Failed to serialize selections")?;
    fs::write(selections_path()?, raw).context("Failed to write selections file")
}

fn patches_dir() -> Result<PathBuf> {
    let root = project::resolve()?;
    let dir = root.dir.join("patches");
    fs::create_dir_all(&dir).context("Failed to create .n0x/patches directory")?;
    Ok(dir)
}

fn patch_record_path(id: &str) -> Result<PathBuf> {
    Ok(patches_dir()?.join(format!("patch-{id}.json")))
}

fn save_patch_record(rec: &PatchRecord) -> Result<PathBuf> {
    let path = patch_record_path(&rec.id)?;
    let raw = serde_json::to_string_pretty(rec)?;
    fs::write(&path, raw).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(path)
}

fn load_patch_record_by_id(id: &str) -> Result<PatchRecord> {
    let path = patch_record_path(id)?;
    let raw = fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))?;
    let rec: PatchRecord =
        serde_json::from_str(&raw).with_context(|| format!("Invalid JSON in {}", path.display()))?;
    Ok(rec)
}

fn load_latest_patch_record() -> Result<PatchRecord> {
    let dir = patches_dir()?;
    let mut latest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in fs::read_dir(&dir).with_context(|| format!("Failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().map(|s| s.to_string_lossy().to_string()) else {
            continue;
        };
        if !name.starts_with("patch-") || !name.ends_with(".json") {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        match latest {
            None => latest = Some((mtime, path)),
            Some((t, _)) if mtime > t => latest = Some((mtime, path)),
            _ => {}
        }
    }
    let Some((_, path)) = latest else {
        bail!("No patch records found in {}", dir.display());
    };
    let raw = fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))?;
    let rec: PatchRecord =
        serde_json::from_str(&raw).with_context(|| format!("Invalid JSON in {}", path.display()))?;
    Ok(rec)
}

fn list_patch_records(limit: usize) -> Result<Vec<PatchRecord>> {
    let dir = patches_dir()?;
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("Failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().map(|s| s.to_string_lossy().to_string()) else {
            continue;
        };
        if !name.starts_with("patch-") || !name.ends_with(".json") {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        files.push((mtime, path));
    }
    files.sort_by(|a, b| b.0.cmp(&a.0));
    let mut out: Vec<PatchRecord> = Vec::new();
    for (_, path) in files.into_iter().take(limit) {
        let raw = fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))?;
        let rec: PatchRecord =
            serde_json::from_str(&raw).with_context(|| format!("Invalid JSON in {}", path.display()))?;
        out.push(rec);
    }
    Ok(out)
}

fn byte_diff_count(a: &[u8], b: &[u8]) -> usize {
    let n = a.len().min(b.len());
    let mut diff = 0usize;
    for i in 0..n {
        if a[i] != b[i] {
            diff += 1;
        }
    }
    diff + a.len().abs_diff(b.len())
}

fn now_unix_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn new_patch_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{ts_ms:013}")
}

fn resolve_pid(explicit: Option<u32>) -> Result<u32> {
    if let Some(pid) = explicit {
        return Ok(pid);
    }
    let session = load_session()?;
    session.attached_pid.ok_or_else(|| {
        anyhow!(
            "No PID provided and no attached target in session. Use `target attach --pid <pid>`."
        )
    })
}

struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn open_process(pid: u32, access: u32) -> Result<ProcessHandle> {
    let handle = unsafe { OpenProcess(access, 0, pid) };
    if handle.is_null() {
        bail!("OpenProcess failed for pid={pid}. Try running elevated.");
    }
    Ok(ProcessHandle(handle))
}

fn read_memory(pid: u32, address: u64, size: usize) -> Result<Vec<u8>> {
    let handle = open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)?;
    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            handle.0,
            address as *const core::ffi::c_void,
            buffer.as_mut_ptr() as *mut core::ffi::c_void,
            size,
            &mut bytes_read,
        )
    };
    if ok == 0 {
        bail!("ReadProcessMemory failed at 0x{address:X}");
    }
    buffer.truncate(bytes_read);
    Ok(buffer)
}

fn write_memory(pid: u32, address: u64, bytes: &[u8]) -> Result<usize> {
    let handle = open_process(
        pid,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
    )?;
    let mut bytes_written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            handle.0,
            address as *mut core::ffi::c_void,
            bytes.as_ptr() as *const core::ffi::c_void,
            bytes.len(),
            &mut bytes_written,
        )
    };
    if ok == 0 {
        bail!("WriteProcessMemory failed at 0x{address:X}");
    }
    Ok(bytes_written)
}

fn detect_arch(pid: u32) -> Result<String> {
    #[cfg(target_pointer_width = "64")]
    {
        let handle = open_process(pid, PROCESS_QUERY_INFORMATION)?;
        let mut wow64 = 0i32;
        let ok = unsafe { IsWow64Process(handle.0, &mut wow64) };
        if ok == 0 {
            return Ok("unknown".to_string());
        }
        if wow64 != 0 {
            Ok("x86".to_string())
        } else {
            Ok("x64".to_string())
        }
    }
    #[cfg(target_pointer_width = "32")]
    {
        let _ = pid;
        Ok("x86".to_string())
    }
}

fn enumerate_modules(pid: u32) -> Result<Vec<ModuleInfo>> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if snapshot == INVALID_HANDLE_VALUE {
        bail!("CreateToolhelp32Snapshot failed for pid={pid}");
    }
    let _snapshot_guard = ProcessHandle(snapshot);

    let mut entry = MODULEENTRY32W {
        dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
        ..unsafe { std::mem::zeroed() }
    };

    let mut modules = Vec::new();
    let mut has_item = unsafe { Module32FirstW(snapshot, &mut entry) };
    while has_item != 0 {
        modules.push(ModuleInfo {
            name: utf16_z_to_string(&entry.szModule),
            base_address: format!("0x{:X}", entry.modBaseAddr as usize),
            size: entry.modBaseSize as u64,
            path: utf16_z_to_string(&entry.szExePath),
        });
        has_item = unsafe { Module32NextW(snapshot, &mut entry) };
    }

    Ok(modules)
}

fn enumerate_memory_map(pid: u32, limit: usize) -> Result<Vec<MemoryRegionInfo>> {
    let handle = open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)?;
    let mut regions = Vec::new();
    let mut address = 0usize;

    while regions.len() < limit {
        let mut mbi = MEMORY_BASIC_INFORMATION {
            ..unsafe { std::mem::zeroed() }
        };
        let queried = unsafe {
            VirtualQueryEx(
                handle.0,
                address as *const core::ffi::c_void,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if queried == 0 {
            break;
        }
        let base = mbi.BaseAddress as usize;
        let size = mbi.RegionSize;
        if size == 0 {
            break;
        }
        regions.push(MemoryRegionInfo {
            base_address: format!("0x{base:X}"),
            region_end: format!("0x{:X}", base.saturating_add(size)),
            size,
            state: mem_state_to_str(mbi.State),
            protection: protection_to_str(mbi.Protect),
            kind: mem_type_to_str(mbi.Type),
        });
        address = base.saturating_add(size);
    }

    Ok(regions)
}

fn collect_exported_functions(
    pid: u32,
    module_filter: Option<&str>,
) -> Result<Vec<FunctionSymbolInfo>> {
    let modules = enumerate_modules(pid)?;
    let mut out = Vec::new();
    let filter = module_filter.map(|m| m.to_lowercase());

    for module in modules {
        if let Some(f) = filter.as_ref() {
            let module_name_l = module.name.to_lowercase();
            let module_path_l = module.path.to_lowercase();
            if !module_name_l.contains(f) && !module_path_l.contains(f) {
                continue;
            }
        }

        let path = PathBuf::from(&module.path);
        if !path.exists() {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let pe = match PE::parse(&bytes) {
            Ok(p) => p,
            Err(_) => continue,
        };

        for export in &pe.exports {
            let Some(name) = export.name else { continue };
            let base = parse_hex_u64(&module.base_address).unwrap_or(0);
            let absolute = base.saturating_add(export.rva as u64);
            out.push(FunctionSymbolInfo {
                name: name.to_string(),
                module: module.name.clone(),
                module_path: module.path.clone(),
                relative_address: format!("0x{:X}", export.rva),
                address: format!("0x{absolute:X}"),
            });
        }
    }
    Ok(out)
}

fn discover_functions(
    pid: u32,
    module_name: &str,
    limit: usize,
) -> Result<Vec<FunctionSymbolInfo>> {
    let module = find_module(pid, module_name)?;
    let base = parse_hex_u64(&module.base_address)?;
    let image_size = module.size as usize;
    let bytes = read_memory(pid, base, image_size).unwrap_or_default();
    if bytes.is_empty() {
        bail!("Could not read module memory for {}", module.name);
    }

    let pe_bytes = fs::read(&module.path)
        .with_context(|| format!("Failed to read module file '{}'", module.path))?;
    let pe = PE::parse(&pe_bytes).context("Failed to parse PE while discovering functions")?;

    let mut text_rva = 0usize;
    let mut text_size = bytes.len().min(image_size);
    for section in &pe.sections {
        let Ok(name) = section.name() else { continue };
        if name.trim_end_matches('\0') == ".text" {
            text_rva = section.virtual_address as usize;
            text_size = section.virtual_size as usize;
            break;
        }
    }

    let start = text_rva.min(bytes.len());
    let end = start.saturating_add(text_size).min(bytes.len());
    let text = &bytes[start..end];
    let mut found = Vec::new();

    // Common x64 function prolog patterns (heuristic, v1).
    let patterns: [&[u8]; 5] = [
        &[0x55, 0x48, 0x8B, 0xEC],
        &[0x40, 0x53],
        &[0x48, 0x89, 0x5C, 0x24],
        &[0x48, 0x83, 0xEC],
        &[0x4C, 0x8B, 0xDC],
    ];

    let mut i = 0usize;
    while i + 4 < text.len() && found.len() < limit {
        let window = &text[i..];
        if patterns.iter().any(|p| window.starts_with(p)) {
            let rva = (start + i) as u64;
            let absolute = base.saturating_add(rva);
            found.push(FunctionSymbolInfo {
                name: format!("sub_{absolute:X}"),
                module: module.name.clone(),
                module_path: module.path.clone(),
                relative_address: format!("0x{rva:X}"),
                address: format!("0x{absolute:X}"),
            });
            i = i.saturating_add(8);
            continue;
        }
        i = i.saturating_add(1);
    }

    Ok(found)
}

fn find_module(pid: u32, query: &str) -> Result<ModuleInfo> {
    let q = query.to_lowercase();
    enumerate_modules(pid)?
        .into_iter()
        .find(|m| m.name.to_lowercase().contains(&q) || m.path.to_lowercase().contains(&q))
        .ok_or_else(|| anyhow!("Module matching '{query}' not found in pid={pid}"))
}

fn xref_string(pid: u32, module_name: &str, query: &str, limit: usize) -> Result<Vec<Value>> {
    let module = find_module(pid, module_name)?;
    let base = parse_hex_u64(&module.base_address)?;
    let image_size = module.size as usize;
    let bytes = read_memory(pid, base, image_size)?;
    let needle = query.as_bytes();
    if needle.is_empty() {
        return Ok(Vec::new());
    }

    let pe_bytes = fs::read(&module.path)?;
    let pe = PE::parse(&pe_bytes)?;
    let (text_start, text_end) = section_range(&pe, ".text", bytes.len());
    let text = &bytes[text_start..text_end];
    let text_ip = base.saturating_add(text_start as u64);

    let mut hits = Vec::new();
    let mut pos = 0usize;
    while hits.len() < limit {
        let Some(rel) = bytes[pos..].windows(needle.len()).position(|w| w == needle) else {
            break;
        };
        let idx = pos + rel;
        let str_addr = base.saturating_add(idx as u64);
        let refs = collect_xrefs_to(text_ip, text, str_addr, Some("lea"));
        if !refs.is_empty() {
            hits.push(json!({
                "stringAddress": format!("0x{str_addr:X}"),
                "preview": preview_ascii(&bytes[idx..(idx + 64).min(bytes.len())]),
                "xrefs": refs,
            }));
        }
        pos = idx + 1;
    }
    Ok(hits)
}

fn trace_functions(pid: u32, module_name: &str, root: u64, depth: usize) -> Result<Vec<Value>> {
    let module = find_module(pid, module_name)?;
    let base = parse_hex_u64(&module.base_address)?;
    let image_size = module.size as usize;
    let bytes = read_memory(pid, base, image_size)?;
    let pe_bytes = fs::read(&module.path)?;
    let pe = PE::parse(&pe_bytes)?;
    let (text_start, text_end) = section_range(&pe, ".text", bytes.len());
    let text = &bytes[text_start..text_end];
    let text_ip = base.saturating_add(text_start as u64);
    let mut starts: Vec<u64> = discover_functions(pid, module_name, 1500)?
        .into_iter()
        .filter_map(|f| parse_hex_u64(&f.address).ok())
        .collect();
    starts.sort_unstable();
    starts.dedup();

    let mut out = Vec::new();
    let mut queue = vec![(root, 0usize)];
    let mut seen = std::collections::HashSet::new();

    while let Some((addr, d)) = queue.pop() {
        if d > depth || !seen.insert(addr) {
            continue;
        }
        let end = starts
            .iter()
            .copied()
            .find(|s| *s > addr)
            .unwrap_or(addr.saturating_add(0x200))
            .min(base.saturating_add(image_size as u64));
        let start_idx = addr.saturating_sub(text_ip) as usize;
        let end_idx = end.saturating_sub(text_ip) as usize;
        if start_idx >= text.len() {
            continue;
        }
        let body = &text[start_idx..end_idx.min(text.len())];
        let edges = collect_function_edges(addr, body);
        for e in &edges {
            if let Some(to) = e.get("to").and_then(Value::as_str) {
                if let Ok(parsed) = parse_hex_u64(to) {
                    queue.push((parsed, d + 1));
                }
            }
        }
        out.push(json!({
            "address": format!("0x{addr:X}"),
            "depth": d,
            "edges": edges,
        }));
    }
    Ok(out)
}

fn collect_function_edges(start: u64, body: &[u8]) -> Vec<Value> {
    let mut decoder = Decoder::with_ip(64, body, start, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut rendered = String::new();
    let mut out = Vec::new();
    while decoder.can_decode() {
        let ins = decoder.decode();
        if ins.is_invalid() {
            continue;
        }
        let flow = format!("{:?}", ins.flow_control()).to_lowercase();
        if !flow.contains("call") && !flow.contains("branch") {
            continue;
        }
        let to = ins.near_branch_target();
        if to == 0 {
            continue;
        }
        rendered.clear();
        formatter.format(&ins, &mut rendered);
        out.push(json!({
            "from": format!("0x{:X}", ins.ip()),
            "to": format!("0x{to:X}"),
            "kind": if flow.contains("call") { "call" } else { "jmp" },
            "instruction": rendered,
        }));
    }
    out
}

fn section_range(pe: &PE<'_>, name: &str, max_len: usize) -> (usize, usize) {
    for sec in &pe.sections {
        let Ok(sec_name) = sec.name() else { continue };
        if sec_name.trim_end_matches('\0') == name {
            let start = sec.virtual_address as usize;
            let end = start.saturating_add(sec.virtual_size as usize).min(max_len);
            return (start.min(max_len), end);
        }
    }
    (0, max_len)
}

fn preview_ascii(data: &[u8]) -> String {
    data.iter()
        .map(|b| {
            if (32..=126).contains(b) {
                *b as char
            } else {
                '.'
            }
        })
        .collect()
}

fn mem_state_to_str(state: u32) -> String {
    match state {
        MEM_COMMIT => "MEM_COMMIT".to_string(),
        MEM_RESERVE => "MEM_RESERVE".to_string(),
        MEM_FREE => "MEM_FREE".to_string(),
        _ => format!("UNKNOWN(0x{state:X})"),
    }
}

fn mem_type_to_str(kind: u32) -> String {
    match kind {
        MEM_PRIVATE => "MEM_PRIVATE".to_string(),
        MEM_MAPPED => "MEM_MAPPED".to_string(),
        MEM_IMAGE => "MEM_IMAGE".to_string(),
        0 => "NONE".to_string(),
        _ => format!("UNKNOWN(0x{kind:X})"),
    }
}

fn protection_to_str(protect: u32) -> String {
    if protect == 0 {
        return "NONE".to_string();
    }
    let mut flags = Vec::new();
    let base = protect & 0xFF;
    match base {
        PAGE_NOACCESS => flags.push("PAGE_NOACCESS"),
        PAGE_READONLY => flags.push("PAGE_READONLY"),
        PAGE_READWRITE => flags.push("PAGE_READWRITE"),
        PAGE_WRITECOPY => flags.push("PAGE_WRITECOPY"),
        PAGE_EXECUTE => flags.push("PAGE_EXECUTE"),
        PAGE_EXECUTE_READ => flags.push("PAGE_EXECUTE_READ"),
        PAGE_EXECUTE_READWRITE => flags.push("PAGE_EXECUTE_READWRITE"),
        PAGE_EXECUTE_WRITECOPY => flags.push("PAGE_EXECUTE_WRITECOPY"),
        _ => flags.push("UNKNOWN"),
    }
    if protect & PAGE_GUARD != 0 {
        flags.push("PAGE_GUARD");
    }
    if protect & PAGE_NOCACHE != 0 {
        flags.push("PAGE_NOCACHE");
    }
    if protect & PAGE_WRITECOMBINE != 0 {
        flags.push("PAGE_WRITECOMBINE");
    }
    if protect & PAGE_TARGETS_INVALID != 0 {
        flags.push("PAGE_TARGETS_INVALID");
    }
    flags.join("|")
}

fn utf16_z_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn emit_success(out: &OutputMode, data: Value, start: Instant, target_pid: Option<u32>) {
    let elapsed_ms = start.elapsed().as_millis();
    let payload = json!({
        "ok": true,
        "data": data,
        "meta": {
            "elapsedMs": elapsed_ms,
            "targetPid": target_pid,
            "timestamp": iso_now(),
        }
    });
    emit_payload(out.json, out.pretty, payload);
}

fn emit_error(json_mode: bool, pretty: bool, code: &str, message: &str, hint: Option<&str>) {
    let payload = json!({
        "ok": false,
        "error": {
            "code": code,
            "message": message,
            "hint": hint
        }
    });
    emit_payload(json_mode, pretty, payload);
}

fn emit_payload(json_mode: bool, pretty: bool, payload: Value) {
    if json_mode {
        let rendered = if pretty {
            serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
        } else {
            serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
        };
        println!("{rendered}");
    } else if payload.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        let text =
            serde_json::to_string_pretty(&payload["data"]).unwrap_or_else(|_| "{}".to_string());
        println!("{text}");
    } else {
        let msg = payload["error"]["message"]
            .as_str()
            .unwrap_or("Unknown error");
        eprintln!("error: {msg}");
    }
}

fn iso_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{now}")
}
