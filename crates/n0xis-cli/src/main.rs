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

use clap::{Args, Parser, Subcommand, ValueEnum};
use n0xis_arch::X64;
use n0xis_contracts::{Response, Va, schema};
use n0xis_contracts::{TableEntry, TableLocator, TableValueType};
use n0xis_core::{
    build_trampoline, parse_aob, resolve_pointer_path, AobInput, AobScanPass, CfgInput,
    Ctx, DecompInput, DecompPass, DecompStyle, DiscoverInput, DiscoverPass, DissectInput,
    DissectPass, FilterCriterion, FilterInput, FilterPass, ManifestCandidate, ManifestInput,
    ManifestPass, Pass, PointerPathInput, PointerPathPass, PointerRoot, ProvenanceHit,
    ProvenanceInput, ProvenancePass, ScanCriterion, ScanInput, ScanPass, ScanValue,
    StringXrefInput, StringXrefPass, TraceInput, TracePass, ValueType, XrefDir, XrefInput,
    XrefPass,
};
use n0xis_pipeline::{Pipeline, cfg_cached};
use n0xis_sources::{
    LiveProcess, MemorySource, RemoteAgent, Snapshot, StaticPe, WatchKind, await_breakpoint_hit,
    await_watchpoint_hit, list_processes, remote_serve_stdio,
};
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
    /// Pseudo-C decompilation.
    #[command(subcommand)]
    Decomp(DecompCmd),
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
    /// Live execution control (software + hardware breakpoints).
    #[command(subcommand)]
    Debug(DebugCmd),
    /// Typed value/AOB/pointer-path scanning + struct dissection (a memory scanner class).
    #[command(subcommand)]
    Scan(ScanCmd),
    /// `.n0xt` cheat/analysis tables.
    #[command(subcommand)]
    Table(TableCmd),
    /// Fuse a live watchpoint hit with the SSA decompiler: what code, in
    /// what recovered function, explains a runtime value (Phase 4c).
    #[command(subcommand)]
    Provenance(ProvenanceCmd),
    /// Names/types/comments at an address, kept as versioned truth
    /// (`.n0x/annotations.json`, Phase 6) — complements `patch`'s
    /// already-versioned byte-level journal.
    #[command(subcommand)]
    Annotate(AnnotateCmd),
    /// Capture a reproducible offline memory snapshot, or reload one as a
    /// `--snapshot` source (Phase 6).
    #[command(subcommand)]
    Snapshot(SnapshotCmd),
    /// Serve a live process over the remote-agent stdio protocol — the
    /// remote-side half of `--remote-cmd` (Phase 6). Typically invoked over
    /// SSH by the *other* machine, not run directly: e.g. locally, run
    /// `n0xis ir build --remote-cmd "ssh user@host n0xis remote-serve --pid 1234" --addr 0x...`.
    RemoteServe(RemoteServeArgs),
}

#[derive(Subcommand)]
enum DebugCmd {
    /// Arm a software breakpoint and block until it fires (or times out).
    AwaitHit(DebugAwaitHitArgs),
    /// Arm a hardware watchpoint (data read/write, or execute) and block
    /// until it fires (or times out) — no code byte is ever patched.
    Watch(DebugWatchArgs),
}

#[derive(Args)]
struct DebugWatchArgs {
    #[arg(long)]
    pid: u32,
    /// Address to watch (hex `0x…`). Absolute VA, unless `--addr-rva`.
    #[arg(long)]
    addr: String,
    #[arg(long)]
    addr_rva: bool,
    /// What to trap on. There is no hardware "read-only" mode on x86 — only
    /// `write` or `read-or-write`.
    #[arg(long, value_enum, default_value_t = WatchKindArg::Write)]
    kind: WatchKindArg,
    /// Watch width in bytes: 1, 2, 4, or 8. `addr` must be aligned to it.
    #[arg(long, default_value_t = 4)]
    len: u8,
    #[arg(long, default_value_t = 30000)]
    timeout_ms: u64,
    #[arg(long, default_value_t = 16)]
    stack_qwords: usize,
}

#[derive(Clone, Copy, ValueEnum)]
enum WatchKindArg {
    Execute,
    Write,
    ReadOrWrite,
}

#[derive(Subcommand)]
enum ProvenanceCmd {
    /// Arm a hardware watchpoint on a value's address, wait for one hit,
    /// then explain it: resolved module+function, decompiled statement.
    Trace(ProvenanceTraceArgs),
}

#[derive(Args)]
struct ProvenanceTraceArgs {
    #[arg(long)]
    pid: u32,
    /// The value's address to explain (hex `0x…`).
    #[arg(long)]
    addr: String,
    #[arg(long, value_enum, default_value_t = WatchKindArg::Write)]
    kind: WatchKindArg,
    #[arg(long, default_value_t = 4)]
    len: u8,
    #[arg(long, default_value_t = 30000)]
    timeout_ms: u64,
    /// Record the explained provenance onto an existing (or new) `.n0xt`
    /// table entry — "record with provenance" (CONCEPT §10/§11).
    #[arg(long)]
    save_to_table: Option<String>,
    #[arg(long)]
    entry: Option<String>,
}

impl From<WatchKindArg> for WatchKind {
    fn from(k: WatchKindArg) -> Self {
        match k {
            WatchKindArg::Execute => WatchKind::Execute,
            WatchKindArg::Write => WatchKind::Write,
            WatchKindArg::ReadOrWrite => WatchKind::ReadOrWrite,
        }
    }
}

#[derive(Subcommand)]
enum AnnotateCmd {
    /// Assert (or clear, with no `--value`) a function/variable name at an address.
    Name(AnnotateSetArgs),
    /// Assert (or clear) a type note at an address, e.g. `"int(char*, size_t)"`.
    Type(AnnotateSetArgs),
    /// Assert (or clear) a free-text comment at an address.
    Comment(AnnotateSetArgs),
    /// Show the current facts + full history for one address.
    Show(AnnotateShowArgs),
    /// List every annotated address.
    List,
    /// Remove all annotations (and history) at an address.
    Rm(AnnotateShowArgs),
}

#[derive(Args)]
struct AnnotateSetArgs {
    #[arg(long)]
    addr: String,
    /// New value; omit to clear the field.
    #[arg(long)]
    value: Option<String>,
}

#[derive(Args)]
struct AnnotateShowArgs {
    #[arg(long)]
    addr: String,
}

#[derive(Subcommand)]
enum SnapshotCmd {
    /// Capture a byte range (+ modules, when resolvable) from a live process
    /// or static file into a reloadable `.n0x/dumps/snapshot/<name>.json`.
    Dump(SnapshotDumpArgs),
    /// Show a captured snapshot's region/module summary.
    Info(SnapshotInfoArgs),
    /// List captured snapshots.
    List,
}

#[derive(Args)]
struct SnapshotDumpArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Region start (hex `0x…`); defaults to the module's `.text`.
    #[arg(long)]
    start: Option<String>,
    /// Region size in bytes; defaults to the `.text` size.
    #[arg(long)]
    size: Option<usize>,
    /// Name to save the snapshot under.
    #[arg(long)]
    name: String,
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct SnapshotInfoArgs {
    name: String,
}

#[derive(Args)]
struct RemoteServeArgs {
    #[arg(long)]
    pid: u32,
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
    /// Reload a captured `snapshot dump` by name.
    #[arg(long)]
    snapshot: Option<String>,
    /// Attach over a remote transport, e.g. `"ssh host n0xis remote-serve --pid 1234"`.
    #[arg(long)]
    remote_cmd: Option<String>,
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
    /// Install a detour/trampoline hook: allocate a code cave, relocate the
    /// hook site's bytes into it with a jump back, redirect the hook site
    /// into the cave. The hook-site overwrite is journaled like any other
    /// `patch apply` (`patch undo` restores the original code); the cave
    /// itself is not freed on undo (documented scope limit).
    Detour(PatchDetourArgs),
}

#[derive(Args)]
struct PatchDetourArgs {
    #[arg(long)]
    pid: u32,
    /// Address to hook (hex `0x…`).
    #[arg(long)]
    hook_at: String,
    /// Cave size in bytes; must fit the relocated hook bytes + a 5-byte jump
    /// back (the CLI reports the minimum needed if this is too small).
    #[arg(long, default_value_t = 64)]
    cave_size: usize,
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
    /// Reload a captured `snapshot dump` by name.
    #[arg(long)]
    snapshot: Option<String>,
    /// Attach over a remote transport, e.g. `"ssh host n0xis remote-serve --pid 1234"`.
    #[arg(long)]
    remote_cmd: Option<String>,
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
    /// Reload a captured `snapshot dump` by name.
    #[arg(long)]
    snapshot: Option<String>,
    /// Attach over a remote transport, e.g. `"ssh host n0xis remote-serve --pid 1234"`.
    #[arg(long)]
    remote_cmd: Option<String>,
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
    /// Reload a captured `snapshot dump` by name.
    #[arg(long)]
    snapshot: Option<String>,
    /// Attach over a remote transport, e.g. `"ssh host n0xis remote-serve --pid 1234"`.
    #[arg(long)]
    remote_cmd: Option<String>,
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
    /// Reload a captured `snapshot dump` by name.
    #[arg(long)]
    snapshot: Option<String>,
    /// Attach over a remote transport, e.g. `"ssh host n0xis remote-serve --pid 1234"`.
    #[arg(long)]
    remote_cmd: Option<String>,
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
    /// Reload a captured `snapshot dump` by name.
    #[arg(long)]
    snapshot: Option<String>,
    /// Attach over a remote transport, e.g. `"ssh host n0xis remote-serve --pid 1234"`.
    #[arg(long)]
    remote_cmd: Option<String>,
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

#[derive(Subcommand)]
enum DecompCmd {
    /// Pseudo-C for one function (`n0x.decomp.pseudo.v1`).
    Pseudo(DecompArgs),
}

#[derive(Args)]
struct DecompArgs {
    #[command(flatten)]
    ir: IrArgs,
    /// `goto` (flat + labels), `structured` (if/while, unoptimized), or
    /// `ssa` (structured *and* optimized — the ROADMAP Phase 3 target style).
    #[arg(long, value_enum, default_value_t = PseudoStyle::Ssa)]
    style: PseudoStyle,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum PseudoStyle {
    Goto,
    Structured,
    Ssa,
}

impl From<PseudoStyle> for DecompStyle {
    fn from(s: PseudoStyle) -> Self {
        match s {
            PseudoStyle::Goto => DecompStyle::Goto,
            PseudoStyle::Structured => DecompStyle::Structured,
            PseudoStyle::Ssa => DecompStyle::Ssa,
        }
    }
}

#[derive(Subcommand)]
enum ScanCmd {
    /// First scan: find every address matching a criterion.
    Value(ScanValueArgs),
    /// Rescan: narrow a previous `scan value`/`scan filter` result
    /// (loaded from a `--from` dump) by comparing new values to old.
    Filter(ScanFilterArgs),
    /// AOB (array-of-bytes) signature scan with `??` wildcards.
    Aob(ScanAobArgs),
    /// Find stable multi-level pointer chains resolving to an address.
    PointerPath(PointerPathArgs),
    /// Heuristically type each field of a live region (pointer/float/int).
    Dissect(ScanDissectArgs),
}

#[derive(Clone, Copy, ValueEnum)]
enum ValueTypeArg {
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
}

impl From<ValueTypeArg> for ValueType {
    fn from(t: ValueTypeArg) -> Self {
        match t {
            ValueTypeArg::I8 => ValueType::I8,
            ValueTypeArg::U8 => ValueType::U8,
            ValueTypeArg::I16 => ValueType::I16,
            ValueTypeArg::U16 => ValueType::U16,
            ValueTypeArg::I32 => ValueType::I32,
            ValueTypeArg::U32 => ValueType::U32,
            ValueTypeArg::I64 => ValueType::I64,
            ValueTypeArg::U64 => ValueType::U64,
            ValueTypeArg::F32 => ValueType::F32,
            ValueTypeArg::F64 => ValueType::F64,
        }
    }
}

impl From<ValueTypeArg> for TableValueType {
    fn from(t: ValueTypeArg) -> Self {
        match t {
            ValueTypeArg::I8 => TableValueType::I8,
            ValueTypeArg::U8 => TableValueType::U8,
            ValueTypeArg::I16 => TableValueType::I16,
            ValueTypeArg::U16 => TableValueType::U16,
            ValueTypeArg::I32 => TableValueType::I32,
            ValueTypeArg::U32 => TableValueType::U32,
            ValueTypeArg::I64 => TableValueType::I64,
            ValueTypeArg::U64 => TableValueType::U64,
            ValueTypeArg::F32 => TableValueType::F32,
            ValueTypeArg::F64 => TableValueType::F64,
        }
    }
}

#[derive(Args)]
struct ScanRegionArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Region start (hex). Defaults, on `--pid`, to every committed
    /// writable region (the a memory scanner-default scan set); required for `--file`.
    #[arg(long)]
    start: Option<String>,
    /// Region size in bytes (paired with `--start`).
    #[arg(long)]
    size: Option<usize>,
}

#[derive(Args)]
struct ScanValueArgs {
    #[command(flatten)]
    region: ScanRegionArgs,
    #[arg(long, value_enum)]
    r#type: ValueTypeArg,
    /// `exact` (needs `--value`), `in-range` (needs `--min`/`--max`), or
    /// `unknown` (record every value — the "unknown initial value" scan).
    #[arg(long, default_value = "exact")]
    criterion: String,
    #[arg(long)]
    value: Option<f64>,
    #[arg(long)]
    min: Option<f64>,
    #[arg(long)]
    max: Option<f64>,
    /// Byte stride between candidates; defaults to the value's natural size.
    #[arg(long)]
    align: Option<usize>,
    /// Save the result under `.n0x/dumps/scan/<name>.json` for `scan filter`
    /// to rescan later.
    #[arg(long)]
    save_as: String,
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct ScanFilterArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Name of a previous `scan value`/`scan filter` dump to narrow.
    #[arg(long)]
    from: String,
    /// `exact` (needs `--value`), `increased`, `decreased`, `changed`,
    /// `unchanged`, or `in-range` (needs `--min`/`--max`).
    #[arg(long)]
    criterion: String,
    #[arg(long)]
    value: Option<f64>,
    #[arg(long)]
    min: Option<f64>,
    #[arg(long)]
    max: Option<f64>,
    #[arg(long)]
    save_as: String,
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct ScanAobArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    #[arg(long)]
    start: String,
    #[arg(long)]
    size: usize,
    /// e.g. `"48 8B ?? 68"`.
    #[arg(long)]
    pattern: String,
}

#[derive(Args)]
struct ScanDissectArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    #[arg(long)]
    start: String,
    #[arg(long, default_value_t = 64)]
    size: usize,
}

#[derive(Args)]
struct PointerPathArgs {
    #[arg(long)]
    pid: u32,
    /// The address to find pointer chains to (hex).
    #[arg(long)]
    target: String,
    /// Module name to root chains in (its full address range is both the
    /// search space and the stable anchor); repeatable.
    #[arg(long = "module", required = true)]
    modules: Vec<String>,
    #[arg(long, default_value_t = 3)]
    max_depth: usize,
    #[arg(long, default_value_t = 0x1000)]
    max_offset: u64,
}

#[derive(Subcommand)]
enum TableCmd {
    /// Add (or overwrite, by name) an entry with a fixed-address locator.
    Add(TableAddArgs),
    /// List table names, or one table's entries with `--table`.
    List(TableListArgs),
    /// Show one entry.
    Show(TableShowArgs),
    /// Remove one entry (or the whole table with `--whole-table`).
    Rm(TableShowArgs),
    /// Repeatedly write an entry's frozen value for a bounded duration.
    Freeze(TableFreezeArgs),
}

#[derive(Args)]
struct TableAddArgs {
    #[arg(long)]
    table: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    addr: String,
    #[arg(long, value_enum)]
    r#type: ValueTypeArg,
    #[arg(long)]
    description: Option<String>,
}

#[derive(Args)]
struct TableListArgs {
    #[arg(long)]
    table: Option<String>,
}

#[derive(Args)]
struct TableShowArgs {
    #[arg(long)]
    table: String,
    #[arg(long)]
    name: Option<String>,
}

#[derive(Args)]
struct TableFreezeArgs {
    #[arg(long)]
    table: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    pid: u32,
    /// Value to (re-)write every interval — defaults to the entry's stored
    /// `freeze_value`.
    #[arg(long)]
    value: Option<f64>,
    #[arg(long, default_value_t = 100)]
    interval_ms: u64,
    #[arg(long, default_value_t = 5000)]
    duration_ms: u64,
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
    /// Reload a captured `snapshot dump` by name.
    #[arg(long)]
    snapshot: Option<String>,
    /// Attach over a remote transport, e.g. `"ssh host n0xis remote-serve --pid 1234"`.
    #[arg(long)]
    remote_cmd: Option<String>,
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
    // remote-serve is a persistent stdio server, not a single ok/data/meta
    // call — handled before the response-envelope dispatch below.
    if let Command::RemoteServe(a) = &cli.command {
        cmd_remote_serve(a);
        return;
    }
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
        Command::Decomp(DecompCmd::Pseudo(a)) => cmd_decomp(a, pretty),
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
        Command::Debug(DebugCmd::Watch(a)) => cmd_debug_watch(a, pretty),
        Command::Scan(ScanCmd::Value(a)) => cmd_scan_value(a, pretty),
        Command::Scan(ScanCmd::Filter(a)) => cmd_scan_filter(a, pretty),
        Command::Scan(ScanCmd::Aob(a)) => cmd_scan_aob(a, pretty),
        Command::Scan(ScanCmd::PointerPath(a)) => cmd_pointer_path(a, pretty),
        Command::Scan(ScanCmd::Dissect(a)) => cmd_scan_dissect(a, pretty),
        Command::Table(TableCmd::Add(a)) => cmd_table_add(a, pretty),
        Command::Table(TableCmd::List(a)) => cmd_table_list(a, pretty),
        Command::Table(TableCmd::Show(a)) => cmd_table_show(a, pretty),
        Command::Table(TableCmd::Rm(a)) => cmd_table_rm(a, pretty),
        Command::Table(TableCmd::Freeze(a)) => cmd_table_freeze(a, pretty),
        Command::Provenance(ProvenanceCmd::Trace(a)) => cmd_provenance_trace(a, pretty),
        Command::Annotate(AnnotateCmd::Name(a)) => cmd_annotate_set("name", a, pretty),
        Command::Annotate(AnnotateCmd::Type(a)) => cmd_annotate_set("type", a, pretty),
        Command::Annotate(AnnotateCmd::Comment(a)) => cmd_annotate_set("comment", a, pretty),
        Command::Annotate(AnnotateCmd::Show(a)) => cmd_annotate_show(a, pretty),
        Command::Annotate(AnnotateCmd::List) => cmd_annotate_list(pretty),
        Command::Annotate(AnnotateCmd::Rm(a)) => cmd_annotate_rm(a, pretty),
        Command::Snapshot(SnapshotCmd::Dump(a)) => cmd_snapshot_dump(a, pretty),
        Command::Snapshot(SnapshotCmd::Info(a)) => cmd_snapshot_info(a, pretty),
        Command::Snapshot(SnapshotCmd::List) => cmd_snapshot_list(pretty),
        Command::RemoteServe(_) => unreachable!("handled before this match, see main()"),
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

    let (src, label, _) = match build_source(
        a.pid,
        a.file.as_deref(),
        a.bytes.as_deref(),
        a.snapshot.as_deref(),
        a.remote_cmd.as_deref(),
        start,
    ) {
        Ok(x) => x,
        Err((c, m)) => return ir_err(&c, &m, pretty),
    };
    // StaticPe is also a SymbolProvider + ModuleProvider — feed the seams so
    // call targets resolve to names.
    match &src {
        Src::Static(pe) => work(&Ctx::new(pe.as_ref(), &arch).with_symbols(pe.as_ref()).with_modules(pe.as_ref()), input, label),
        Src::Live(l) => work(&Ctx::new(l.as_ref(), &arch), input, label),
        Src::Snap(s) => work(&Ctx::new(s, &arch), input, label),
        Src::Remote(r) => work(&Ctx::new(r.as_ref(), &arch), input, label),
    }
}

fn cmd_ir(a: IrArgs, view: IrView, pretty: bool) -> bool {
    run_ir(&a, pretty, |ctx, input, label| {
        finish_ir(ctx, input, view, label, pretty)
    })
}

fn cmd_decomp(a: DecompArgs, pretty: bool) -> bool {
    let style: DecompStyle = a.style.into();
    run_ir(&a.ir, pretty, move |ctx, input, label| finish_decomp(ctx, input, style, label, pretty))
}

fn finish_decomp(ctx: &Ctx, input: CfgInput, style: DecompStyle, label: String, pretty: bool) -> bool {
    let cfg = match cfg_cached(ctx, input) {
        Ok((a, _cached)) => a,
        Err(e) => return ir_err("ir-failed", &e.to_string(), pretty),
    };
    match DecompPass.run(ctx, DecompInput { cfg, style }) {
        Ok(pf) => emit(&Response::success(schema::v0::DECOMP_PSEUDO, pf).with_source(label), pretty),
        Err(e) => ir_err("decomp-failed", &e.to_string(), pretty),
    }
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
    Remote(Box<RemoteAgent>),
}

/// Resolve `--pid` / `--file` / `--snapshot` / `--remote-cmd` / `--bytes` into
/// a source (checked in that order). Returns the source, a provenance label,
/// and (for inline bytes) the mapped region length.
fn build_source(
    pid: Option<u32>,
    file: Option<&str>,
    bytes: Option<&str>,
    snapshot: Option<&str>,
    remote_cmd: Option<&str>,
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
    if let Some(name) = snapshot {
        let snap = load_snapshot(name).map_err(|e| ("snapshot-load-failed".into(), e))?;
        let label = snap.label();
        return Ok((Src::Snap(snap), label, None));
    }
    if let Some(cmd) = remote_cmd {
        let argv = n0xis_sources::split_command_line(cmd).map_err(|e| ("bad-remote-cmd".into(), e))?;
        if argv.is_empty() {
            return Err(("bad-remote-cmd".into(), "--remote-cmd must not be empty".into()));
        }
        let agent = RemoteAgent::connect(argv).map_err(|e| ("remote-connect-failed".into(), e.to_string()))?;
        let label = agent.label();
        return Ok((Src::Remote(Box::new(agent)), label, None));
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
    Err(("missing-source".into(), "provide --pid, --file, --snapshot, --remote-cmd, or --bytes".into()))
}

impl Src {
    fn as_mem(&self) -> &dyn MemorySource {
        match self {
            Src::Live(l) => l.as_ref(),
            Src::Static(p) => p.as_ref(),
            Src::Snap(s) => s,
            Src::Remote(r) => r.as_ref(),
        }
    }

    fn text_range(&self) -> Option<(Va, u64)> {
        match self {
            Src::Static(pe) => pe.text_range(),
            Src::Live(l) => l.text_range(),
            Src::Snap(_) | Src::Remote(_) => None,
        }
    }

    /// Modules known to this source (empty for `Snap`/`Remote`, which don't
    /// implement `ModuleProvider` yet).
    fn modules(&self) -> Vec<n0xis_contracts::Module> {
        use n0xis_sources::ModuleProvider;
        match self {
            Src::Live(l) => l.modules().to_vec(),
            Src::Static(p) => p.modules().to_vec(),
            Src::Snap(_) | Src::Remote(_) => Vec::new(),
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
    let art = match cfg_cached(ctx, input) {
        Ok((a, _cached)) => a,
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
    let art = match cfg_cached(ctx, input) {
        Ok((a, _cached)) => a,
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
    let (src, label, _) = match build_source(a.pid, a.file.as_deref(), a.bytes.as_deref(), a.snapshot.as_deref(), a.remote_cmd.as_deref(), addr) {
        Ok(x) => x,
        Err((c, m)) => return ir_err(&c, &m, pretty),
    };
    let arch = X64::new();
    let module_base = match &src {
        Src::Static(pe) => Some(pe.image_base()),
        Src::Live(l) => l.main_module().map(|m| m.base),
        Src::Snap(_) | Src::Remote(_) => None,
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
        Src::Remote(r) => run(&Ctx::new(r.as_ref(), &arch)),
    }
}

fn cmd_discover(a: DiscoverArgs, pretty: bool) -> bool {
    let explicit_start = match opt_hex(&a.start) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e, pretty),
    };
    let bytes_base = explicit_start.unwrap_or(Va(0));
    let (src, label, region_len) =
        match build_source(a.pid, a.file.as_deref(), a.bytes.as_deref(), a.snapshot.as_deref(), a.remote_cmd.as_deref(), bytes_base) {
            Ok(x) => x,
            Err((c, m)) => return ir_err(&c, &m, pretty),
        };
    let arch = X64::new();
    let default_text = match &src {
        Src::Static(pe) => pe.text_range(),
        Src::Live(l) => l.text_range(),
        Src::Snap(_) | Src::Remote(_) => None,
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
        Src::Remote(r) => run(&Ctx::new(r.as_ref(), &arch)),
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
        match build_source(a.pid, a.file.as_deref(), a.bytes.as_deref(), a.snapshot.as_deref(), a.remote_cmd.as_deref(), bytes_base) {
            Ok(x) => x,
            Err((c, m)) => return ir_err(&c, &m, pretty),
        };
    let arch = X64::new();
    let default_text = match &src {
        Src::Static(pe) => pe.text_range(),
        Src::Live(l) => l.text_range(),
        Src::Snap(_) | Src::Remote(_) => None,
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
        Src::Remote(r) => run(&Ctx::new(r.as_ref(), &arch)),
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
        match build_source(a.pid, a.file.as_deref(), a.bytes.as_deref(), a.snapshot.as_deref(), a.remote_cmd.as_deref(), bytes_base) {
            Ok(x) => x,
            Err((c, m)) => return ir_err(&c, &m, pretty),
        };
    let arch = X64::new();
    let default_text = match &src {
        Src::Static(pe) => pe.text_range(),
        Src::Live(l) => l.text_range(),
        Src::Snap(_) | Src::Remote(_) => None,
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
        Src::Remote(r) => run(&Ctx::new(r.as_ref(), &arch)),
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
        match build_source(a.pid, a.file.as_deref(), a.bytes.as_deref(), a.snapshot.as_deref(), a.remote_cmd.as_deref(), bytes_base) {
            Ok(x) => x,
            Err((c, m)) => return ir_err(&c, &m, pretty),
        };
    let arch = X64::new();
    let default_text = match &src {
        Src::Static(pe) => pe.text_range(),
        Src::Live(l) => l.text_range(),
        Src::Snap(_) | Src::Remote(_) => None,
    };
    let default_data = match &src {
        Src::Static(pe) => pe.section_range(".rdata").or_else(|| pe.text_range()),
        Src::Live(l) => l.section_range(".rdata").or_else(|| l.text_range()),
        Src::Snap(_) | Src::Remote(_) => None,
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
        Src::Remote(r) => run(&Ctx::new(r.as_ref(), &arch)),
    }
}

fn cmd_mem_read(a: MemReadArgs, pretty: bool) -> bool {
    let addr = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let (src, label, _) =
        match build_source(a.pid, a.file.as_deref(), a.bytes.as_deref(), a.snapshot.as_deref(), a.remote_cmd.as_deref(), addr) {
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
        PatchCmd::Detour(a) => patch_detour(a, pretty),
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

// ============================================================================
// scan / pointer-path / aob / dissect (ROADMAP Phase 4b)
// ============================================================================

fn to_scan_value(v: f64) -> ScanValue {
    if v.fract() == 0.0 && v.abs() < 9.2e18 { ScanValue::Int(v as i64) } else { ScanValue::Float(v) }
}

fn build_scan_criterion(name: &str, value: Option<f64>, min: Option<f64>, max: Option<f64>) -> Result<ScanCriterion, String> {
    match name {
        "exact" => Ok(ScanCriterion::Exact { value: to_scan_value(value.ok_or("exact criterion needs --value")?) }),
        "in-range" | "inrange" => Ok(ScanCriterion::InRange {
            min: to_scan_value(min.ok_or("in-range needs --min")?),
            max: to_scan_value(max.ok_or("in-range needs --max")?),
        }),
        "unknown" => Ok(ScanCriterion::Unknown),
        other => Err(format!("unknown scan criterion '{other}' (exact|in-range|unknown)")),
    }
}

fn build_filter_criterion(name: &str, value: Option<f64>, min: Option<f64>, max: Option<f64>) -> Result<FilterCriterion, String> {
    match name {
        "exact" => Ok(FilterCriterion::Exact { value: to_scan_value(value.ok_or("exact needs --value")?) }),
        "increased" => Ok(FilterCriterion::Increased),
        "decreased" => Ok(FilterCriterion::Decreased),
        "changed" => Ok(FilterCriterion::Changed),
        "unchanged" => Ok(FilterCriterion::Unchanged),
        "in-range" | "inrange" => Ok(FilterCriterion::InRange {
            min: to_scan_value(min.ok_or("in-range needs --min")?),
            max: to_scan_value(max.ok_or("in-range needs --max")?),
        }),
        other => Err(format!("unknown filter criterion '{other}' (exact|increased|decreased|changed|unchanged|in-range)")),
    }
}

/// Committed regions worth scanning by default: readable+writable data, not
/// the (usually huge, rarely value-bearing) read-only/executable code.
fn is_scan_default_protect(p: &str) -> bool {
    matches!(p, "rw-" | "rwx" | "rc-" | "rcx")
}

fn resolve_scan_regions_live(live: &LiveProcess, start: Option<&str>, size: Option<usize>) -> Result<Vec<(Va, usize)>, String> {
    if let Some(s) = start {
        let va = Va::parse(s).map_err(|e| e.to_string())?;
        let sz = size.ok_or("provide --size with --start")?;
        return Ok(vec![(va, sz)]);
    }
    let regions: Vec<(Va, usize)> = live
        .regions(1_000_000)
        .into_iter()
        .filter(|r| r.state == "commit" && is_scan_default_protect(&r.protect))
        .map(|r| (r.base, r.size as usize))
        .collect();
    if regions.is_empty() {
        return Err("no committed writable regions found (and no --start/--size given)".to_string());
    }
    Ok(regions)
}

fn cmd_scan_value(a: ScanValueArgs, pretty: bool) -> bool {
    let value_type: ValueType = a.r#type.into();
    let criterion = match build_scan_criterion(&a.criterion, a.value, a.min, a.max) {
        Ok(c) => c,
        Err(e) => return ir_err("bad-criterion", &e, pretty),
    };
    let align = a.align.unwrap_or_else(|| value_type.size());
    let arch = X64::new();

    if let Some(pid) = a.region.pid {
        let live = match LiveProcess::attach(pid) {
            Ok(l) => l,
            Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
        };
        let regions = match resolve_scan_regions_live(&live, a.region.start.as_deref(), a.region.size) {
            Ok(r) => r,
            Err(e) => return ir_err("bad-region", &e, pretty),
        };
        let label = live.label();
        let ctx = Ctx::new(&live, &arch);
        return finish_scan_value(&ctx, regions, value_type, criterion, align, label, &a.save_as, a.force, pretty);
    }
    if let Some(file) = a.region.file.as_deref() {
        let pe = match StaticPe::load(std::path::Path::new(file)) {
            Ok(p) => p,
            Err(e) => return ir_err("load-failed", &e.to_string(), pretty),
        };
        let (Some(start_s), Some(size)) = (a.region.start.as_deref(), a.region.size) else {
            return ir_err("missing-region", "provide --start and --size for --file", pretty);
        };
        let start = match Va::parse(start_s) {
            Ok(v) => v,
            Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
        };
        let label = pe.label();
        let ctx = Ctx::new(&pe, &arch);
        return finish_scan_value(&ctx, vec![(start, size)], value_type, criterion, align, label, &a.save_as, a.force, pretty);
    }
    ir_err("missing-source", "provide --pid or --file", pretty)
}

#[allow(clippy::too_many_arguments)]
fn finish_scan_value(
    ctx: &Ctx,
    regions: Vec<(Va, usize)>,
    value_type: ValueType,
    criterion: ScanCriterion,
    align: usize,
    label: String,
    save_as: &str,
    force: bool,
    pretty: bool,
) -> bool {
    let art = match ScanPass.run(ctx, ScanInput { regions, value_type, criterion, align }) {
        Ok(a) => a,
        Err(e) => return ir_err("scan-failed", &e.to_string(), pretty),
    };
    let bytes = serde_json::to_vec(&art).expect("ScanArtifact always serializes");
    if let Err(e) = n0xis_project::dump::save(save_as, "scan", &bytes, force) {
        return ir_err("save-failed", &e.to_string(), pretty);
    }
    emit(&Response::success(schema::v1::SCAN, art).with_source(label), pretty)
}

fn cmd_scan_filter(a: ScanFilterArgs, pretty: bool) -> bool {
    let criterion = match build_filter_criterion(&a.criterion, a.value, a.min, a.max) {
        Ok(c) => c,
        Err(e) => return ir_err("bad-criterion", &e, pretty),
    };
    let prev_bytes = match n0xis_project::dump::show(&a.from, Some("scan")) {
        Ok(d) => d.bytes,
        Err(e) => return ir_err("no-scan", &e.to_string(), pretty),
    };
    let prev: n0xis_core::ScanArtifact = match serde_json::from_slice(&prev_bytes) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-scan-dump", &e.to_string(), pretty),
    };
    let arch = X64::new();

    let (out, label) = if let Some(pid) = a.pid {
        let live = match LiveProcess::attach(pid) {
            Ok(l) => l,
            Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
        };
        let ctx = Ctx::new(&live, &arch);
        let out = FilterPass.run(&ctx, FilterInput { previous: prev.matches, value_type: prev.value_type, criterion });
        (out, live.label())
    } else if let Some(file) = a.file.as_deref() {
        let pe = match StaticPe::load(std::path::Path::new(file)) {
            Ok(p) => p,
            Err(e) => return ir_err("load-failed", &e.to_string(), pretty),
        };
        let ctx = Ctx::new(&pe, &arch);
        let out = FilterPass.run(&ctx, FilterInput { previous: prev.matches, value_type: prev.value_type, criterion });
        (out, pe.label())
    } else {
        return ir_err("missing-source", "provide --pid or --file", pretty);
    };
    let out = match out {
        Ok(o) => o,
        Err(e) => return ir_err("filter-failed", &e.to_string(), pretty),
    };
    let bytes = serde_json::to_vec(&out).expect("ScanArtifact always serializes");
    if let Err(e) = n0xis_project::dump::save(&a.save_as, "scan", &bytes, a.force) {
        return ir_err("save-failed", &e.to_string(), pretty);
    }
    emit(&Response::success(schema::v1::SCAN, out).with_source(label), pretty)
}

fn cmd_scan_aob(a: ScanAobArgs, pretty: bool) -> bool {
    let start = match Va::parse(&a.start) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let pattern = match parse_aob(&a.pattern) {
        Ok(p) => p,
        Err(e) => return ir_err("bad-pattern", &e, pretty),
    };
    let arch = X64::new();
    if let Some(pid) = a.pid {
        let live = match LiveProcess::attach(pid) {
            Ok(l) => l,
            Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
        };
        let label = live.label();
        let ctx = Ctx::new(&live, &arch);
        return match AobScanPass.run(&ctx, AobInput { start, size: a.size, pattern }) {
            Ok(art) => emit(&Response::success(schema::v1::AOB_SCAN, art).with_source(label), pretty),
            Err(e) => ir_err("aob-failed", &e.to_string(), pretty),
        };
    }
    if let Some(file) = a.file.as_deref() {
        let pe = match StaticPe::load(std::path::Path::new(file)) {
            Ok(p) => p,
            Err(e) => return ir_err("load-failed", &e.to_string(), pretty),
        };
        let label = pe.label();
        let ctx = Ctx::new(&pe, &arch);
        return match AobScanPass.run(&ctx, AobInput { start, size: a.size, pattern }) {
            Ok(art) => emit(&Response::success(schema::v1::AOB_SCAN, art).with_source(label), pretty),
            Err(e) => ir_err("aob-failed", &e.to_string(), pretty),
        };
    }
    ir_err("missing-source", "provide --pid or --file", pretty)
}

fn cmd_scan_dissect(a: ScanDissectArgs, pretty: bool) -> bool {
    let start = match Va::parse(&a.start) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let arch = X64::new();
    if let Some(pid) = a.pid {
        let live = match LiveProcess::attach(pid) {
            Ok(l) => l,
            Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
        };
        let label = live.label();
        let ctx = Ctx::new(&live, &arch);
        return match DissectPass.run(&ctx, DissectInput { start, size: a.size }) {
            Ok(art) => emit(&Response::success(schema::v1::DISSECT, art).with_source(label), pretty),
            Err(e) => ir_err("dissect-failed", &e.to_string(), pretty),
        };
    }
    if let Some(file) = a.file.as_deref() {
        let pe = match StaticPe::load(std::path::Path::new(file)) {
            Ok(p) => p,
            Err(e) => return ir_err("load-failed", &e.to_string(), pretty),
        };
        let label = pe.label();
        let ctx = Ctx::new(&pe, &arch);
        return match DissectPass.run(&ctx, DissectInput { start, size: a.size }) {
            Ok(art) => emit(&Response::success(schema::v1::DISSECT, art).with_source(label), pretty),
            Err(e) => ir_err("dissect-failed", &e.to_string(), pretty),
        };
    }
    ir_err("missing-source", "provide --pid or --file", pretty)
}

fn cmd_pointer_path(a: PointerPathArgs, pretty: bool) -> bool {
    use n0xis_sources::ModuleProvider;
    let target = match Va::parse(&a.target) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    let mods = live.modules();
    let mut roots = Vec::new();
    for name in &a.modules {
        let Some(m) = mods.iter().find(|m| m.name.eq_ignore_ascii_case(name)) else {
            return ir_err("no-module", &format!("no module named '{name}' in this process"), pretty);
        };
        roots.push(PointerRoot { label: m.name.clone(), start: m.base, size: m.size });
    }
    let search_regions: Vec<(Va, usize)> = live
        .regions(1_000_000)
        .into_iter()
        .filter(|r| r.state == "commit" && matches!(r.protect.as_str(), "rw-" | "rwx" | "rc-" | "rcx" | "r--" | "r-x"))
        .map(|r| (r.base, r.size as usize))
        .collect();
    let arch = X64::new();
    let label = live.label();
    let ctx = Ctx::new(&live, &arch);
    match PointerPathPass.run(
        &ctx,
        PointerPathInput { target, search_regions, roots, max_depth: a.max_depth, max_offset: a.max_offset, pointer_size: 8 },
    ) {
        Ok(art) => emit(&Response::success(schema::v1::POINTER_PATH, art).with_source(label), pretty),
        Err(e) => ir_err("pointer-path-failed", &e.to_string(), pretty),
    }
}

fn cmd_debug_watch(a: DebugWatchArgs, pretty: bool) -> bool {
    let addr = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    let module = live.main_module().cloned();
    let label = live.label();
    drop(live);

    let watch_va = if a.addr_rva {
        match &module {
            Some(m) => m.base.offset(addr.0),
            None => return ir_err("no-module", "process has no enumerated main module for --addr-rva", pretty),
        }
    } else {
        addr
    };
    let kind: WatchKind = a.kind.into();
    match await_watchpoint_hit(a.pid, watch_va, kind, a.len, a.timeout_ms, a.stack_qwords, module.as_ref()) {
        Ok(outcome) => emit(&Response::success(schema::v1::WATCHPOINT, outcome).with_source(label), pretty),
        Err(e) => ir_err("watch-failed", &e.to_string(), pretty),
    }
}

/// The principal ROADMAP Phase 4c loop, in one command: arm a hardware
/// watchpoint on a value's address (Phase 4b), and on a hit, explain it —
/// resolved module/function, decompiled statement (Phase 3's SSA
/// decompiler) — then optionally record that explanation onto a `.n0xt`
/// entry ("record with provenance", CONCEPT §10/§11).
fn cmd_provenance_trace(a: ProvenanceTraceArgs, pretty: bool) -> bool {
    use n0xis_sources::ModuleProvider;

    let addr = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    let main_module = live.main_module().cloned();
    let label = live.label();
    drop(live);

    let kind: WatchKind = a.kind.into();
    let outcome = match await_watchpoint_hit(a.pid, addr, kind, a.len, a.timeout_ms, 0, main_module.as_ref()) {
        Ok(o) => o,
        Err(e) => return ir_err("watch-failed", &e.to_string(), pretty),
    };
    let Some(hit) = outcome.hit else {
        let data = json!({ "value_addr": addr, "entries": [], "timedOut": true });
        return emit(&Response::success(schema::v1::PROVENANCE, data).with_source(label), pretty);
    };

    // Re-attach fresh: the accessing instruction (rip) may belong to a
    // different module than the one owning the watched data address, and we
    // need a live `Ctx` to decompile it.
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    let insn_module = live.modules().iter().find(|m| m.contains(hit.rip)).cloned();
    let arch = X64::new();
    let ctx = Ctx::new(&live, &arch);

    let access_kind = match a.kind {
        WatchKindArg::Execute => "execute",
        WatchKindArg::Write => "write",
        WatchKindArg::ReadOrWrite => "read-or-write",
    };
    let (code_scan_start, code_scan_size) = match insn_module.as_ref().and_then(|m| live.section_range_of(m.base, ".text")) {
        Some((start, size)) => (Some(start), size as usize),
        None => (None, 0),
    };
    let graph = match ProvenancePass.run(
        &ctx,
        ProvenanceInput {
            value_addr: addr,
            hits: vec![ProvenanceHit { instruction_va: hit.rip, access_kind: access_kind.to_string() }],
            module: insn_module,
            code_scan_start,
            code_scan_size,
        },
    ) {
        Ok(g) => g,
        Err(e) => return ir_err("provenance-failed", &e.to_string(), pretty),
    };

    let mut saved_to: Option<String> = None;
    if let (Some(table_name), Some(entry_name)) = (&a.save_to_table, &a.entry) {
        let mut entry = n0xis_project::table::load(table_name)
            .ok()
            .and_then(|t| t.entries.into_iter().find(|e| e.name.eq_ignore_ascii_case(entry_name)))
            .unwrap_or_else(|| TableEntry {
                name: entry_name.clone(),
                locator: TableLocator::Address { va: addr },
                value_type: TableValueType::U32,
                description: None,
                hotkey: None,
                groups: Vec::new(),
                frozen: false,
                freeze_value: None,
                provenance: Default::default(),
                verification: Default::default(),
            });
        if let Some(e) = graph.entries.first() {
            let note = e.decompiled_context.iter().map(|l| l.trim()).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" ");
            entry.provenance = n0xis_contracts::Provenance {
                function_va: e.function_va,
                struct_type: None,
                field_offset: None,
                note: (!note.is_empty()).then_some(note),
            };
        }
        entry.verification.last_confirmed_unix = Some(n0xis_project::patch::now_unix_secs());
        match n0xis_project::table::add_entry(table_name, entry) {
            Ok(_) => saved_to = Some(format!("{table_name}::{entry_name}")),
            Err(e) => return ir_err("table-save-failed", &e.to_string(), pretty),
        }
    }

    let mut data = serde_json::to_value(&graph).unwrap_or(serde_json::Value::Null);
    if let (Some(s), serde_json::Value::Object(map)) = (saved_to, &mut data) {
        map.insert("savedTo".to_string(), json!(s));
    }
    emit(&Response::success(schema::v1::PROVENANCE, data).with_source(label), pretty)
}

// ============================================================================
// Analysis DB: names/types/comments as versioned truth (CONCEPT/ROADMAP Phase 6)
// ============================================================================

fn cmd_annotate_set(field: &str, a: AnnotateSetArgs, pretty: bool) -> bool {
    let va = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let result = match field {
        "name" => n0xis_project::annotate::set_name(va, a.value.clone()),
        "type" => n0xis_project::annotate::set_type(va, a.value.clone()),
        "comment" => n0xis_project::annotate::set_comment(va, a.value.clone()),
        _ => unreachable!(),
    };
    match result {
        Ok(rec) => emit(&Response::success(schema::v1::ANNOTATION, rec), pretty),
        Err(e) => ir_err("annotate-failed", &e.to_string(), pretty),
    }
}

fn cmd_annotate_show(a: AnnotateShowArgs, pretty: bool) -> bool {
    let va = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    match n0xis_project::annotate::get(va) {
        Ok(Some(rec)) => emit(&Response::success(schema::v1::ANNOTATION, rec), pretty),
        Ok(None) => ir_err("not-found", &format!("no annotations recorded at {va}"), pretty),
        Err(e) => ir_err("annotate-failed", &e.to_string(), pretty),
    }
}

fn cmd_annotate_list(pretty: bool) -> bool {
    match n0xis_project::annotate::list() {
        Ok(records) => emit(&Response::success(schema::v1::ANNOTATION, json!({ "count": records.len(), "records": records })), pretty),
        Err(e) => ir_err("annotate-failed", &e.to_string(), pretty),
    }
}

fn cmd_annotate_rm(a: AnnotateShowArgs, pretty: bool) -> bool {
    let va = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    match n0xis_project::annotate::remove(va) {
        Ok(removed) => emit(&Response::success(schema::v1::ANNOTATION, json!({ "va": va, "removed": removed })), pretty),
        Err(e) => ir_err("annotate-failed", &e.to_string(), pretty),
    }
}

// ============================================================================
// Snapshot source: capture a reproducible offline dump (ROADMAP Phase 6)
// ============================================================================

fn cmd_snapshot_dump(a: SnapshotDumpArgs, pretty: bool) -> bool {
    let explicit_start = match opt_hex(&a.start) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e, pretty),
    };
    let bytes_base = explicit_start.unwrap_or(Va(0));
    let (src, label, _) = match build_source(a.pid, a.file.as_deref(), None, None, None, bytes_base) {
        Ok(x) => x,
        Err((c, m)) => return ir_err(&c, &m, pretty),
    };
    let default_text = src.text_range();
    let (start, size) = scan_range(default_text, None, explicit_start, a.size, bytes_base);
    if size == 0 {
        return ir_err("no-range", "could not resolve a capture range; pass --start and --size", pretty);
    }
    let bytes = match src.as_mem().read(start, size) {
        Ok(b) => b,
        Err(e) => return ir_err("read-failed", &e.to_string(), pretty),
    };
    let modules = src.modules();
    let mut builder = Snapshot::builder().region(start, bytes.clone()).label(format!("snapshot:{}", a.name));
    for m in &modules {
        builder = builder.module(m.clone());
    }
    let snap = builder.build();
    let json = match serde_json::to_vec_pretty(&snap) {
        Ok(j) => j,
        Err(e) => return ir_err("serialize-failed", &e.to_string(), pretty),
    };
    match n0xis_project::dump::save(&a.name, "snapshot", &json, a.force) {
        Ok(saved) => emit(
            &Response::success(
                schema::v1::SNAPSHOT,
                json!({ "name": saved.name, "path": saved.path, "start": start, "size": bytes.len(), "moduleCount": modules.len(), "overwrote": saved.overwrote }),
            )
            .with_source(label),
            pretty,
        ),
        Err(e) => ir_err("snapshot-save-failed", &e.to_string(), pretty),
    }
}

fn load_snapshot(name: &str) -> Result<Snapshot, String> {
    let content = n0xis_project::dump::show(name, Some("snapshot")).map_err(|e| e.to_string())?;
    serde_json::from_slice(&content.bytes).map_err(|e| format!("parse snapshot '{name}': {e}"))
}

fn cmd_snapshot_info(a: SnapshotInfoArgs, pretty: bool) -> bool {
    use n0xis_sources::ModuleProvider;
    match load_snapshot(&a.name) {
        Ok(snap) => {
            let data = json!({
                "name": a.name,
                "label": snap.label(),
                "regionCount": snap.region_count(),
                "totalBytes": snap.total_bytes(),
                "moduleCount": snap.modules().len(),
                "modules": snap.modules(),
            });
            emit(&Response::success(schema::v1::SNAPSHOT, data), pretty)
        }
        Err(e) => ir_err("snapshot-load-failed", &e, pretty),
    }
}

fn cmd_snapshot_list(pretty: bool) -> bool {
    match n0xis_project::dump::list(Some("snapshot")) {
        Ok(items) => emit(&Response::success(schema::v1::SNAPSHOT, json!({ "count": items.len(), "snapshots": items })), pretty),
        Err(e) => ir_err("snapshot-list-failed", &e.to_string(), pretty),
    }
}

/// The remote-serve half of `--remote-cmd`: attach to `--pid` and answer the
/// `n0xis_sources::remote` wire protocol on stdin/stdout until the caller
/// (typically an `ssh`-tunneled `RemoteAgent`) sends `quit` or hangs up. No
/// `ok/data/meta` envelope here — this is a persistent transport, not a
/// single response.
fn cmd_remote_serve(a: &RemoteServeArgs) {
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[n0xis] remote-serve: attach failed: {e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = remote_serve_stdio(&live, std::io::stdin(), std::io::stdout()) {
        eprintln!("[n0xis] remote-serve: {e}");
        std::process::exit(2);
    }
}

fn patch_detour(a: PatchDetourArgs, pretty: bool) -> bool {
    use n0xis_arch::Arch;
    use n0xis_project::patch as pj;

    let hook_at = match Va::parse(&a.hook_at) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };

    // Decode whole instructions until we've covered >= 5 bytes (a near jmp),
    // so the hook never splits an instruction mid-way.
    let arch = X64::new();
    let probe = match live.read(hook_at, 32) {
        Ok(b) => b,
        Err(e) => return ir_err("read-failed", &e.to_string(), pretty),
    };
    let insns = arch.decode_stream(&probe, hook_at, 16);
    let mut hook_len = 0usize;
    for ins in &insns {
        if hook_len >= 5 {
            break;
        }
        hook_len += ins.len as usize;
    }
    if hook_len < 5 || hook_len > probe.len() {
        return ir_err("decode-failed", "could not decode >= 5 bytes of whole instructions at --hook-at", pretty);
    }
    let original = probe[..hook_len].to_vec();

    let cave = match live.alloc_code_cave(a.cave_size) {
        Ok(c) => c,
        Err(e) => return ir_err("alloc-failed", &e.to_string(), pretty),
    };
    let (cave_bytes, hook_jmp) = match build_trampoline(&original, hook_at, cave) {
        Ok(v) => v,
        Err(e) => {
            let _ = live.free_code_cave(cave);
            return ir_err("trampoline-failed", &e, pretty);
        }
    };
    if cave_bytes.len() > a.cave_size {
        let _ = live.free_code_cave(cave);
        return ir_err(
            "cave-too-small",
            &format!("need at least {} bytes for this hook, got --cave-size {}", cave_bytes.len(), a.cave_size),
            pretty,
        );
    }
    if let Err(e) = live.write(cave, &cave_bytes) {
        let _ = live.free_code_cave(cave);
        return ir_err("cave-write-failed", &e.to_string(), pretty);
    }
    // Only the hook-site overwrite is journaled: it's the destructive part
    // (existing code replaced) and the only one `patch undo` needs to
    // reverse. The cave is freshly allocated memory with no "original state."
    if let Err(e) = live.write(hook_at, &hook_jmp) {
        return ir_err("hook-write-failed", &e.to_string(), pretty);
    }
    match live.read(hook_at, hook_jmp.len()) {
        Ok(after) if after == hook_jmp => {}
        Ok(_) => return ir_err("verify-failed", "post-write hook bytes do not match", pretty),
        Err(e) => return ir_err("verify-read-failed", &e.to_string(), pretty),
    }

    let rec = pj::PatchRecord {
        id: pj::new_patch_id(),
        pid: a.pid,
        address: hook_at.to_string(),
        size: hook_jmp.len(),
        before_hex: to_hex_spaced(&original),
        after_hex: to_hex_spaced(&hook_jmp),
        status: "applied".to_string(),
        created_at_unix: pj::now_unix_secs(),
        undone_at_unix: None,
    };
    if let Err(e) = pj::save(&rec) {
        return ir_err("journal-failed", &e.to_string(), pretty);
    }
    let data = json!({
        "op": "detour", "pid": a.pid, "hookAt": hook_at, "hookLen": hook_len,
        "cave": cave, "caveSize": a.cave_size, "patchId": rec.id,
    });
    emit(&Response::success(schema::v1::PATCH, data).with_source(live.label()), pretty)
}

// ============================================================================
// `.n0xt` tables (CONCEPT §10)
// ============================================================================

fn cmd_table_add(a: TableAddArgs, pretty: bool) -> bool {
    let va = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let entry = TableEntry {
        name: a.name.clone(),
        locator: TableLocator::Address { va },
        value_type: a.r#type.into(),
        description: a.description.clone(),
        hotkey: None,
        groups: Vec::new(),
        frozen: false,
        freeze_value: None,
        provenance: Default::default(),
        verification: Default::default(),
    };
    match n0xis_project::table::add_entry(&a.table, entry) {
        Ok(t) => emit(&Response::success(schema::v1::TABLE, t).with_source(format!("table:{}", a.table)), pretty),
        Err(e) => ir_err("table-add-failed", &e.to_string(), pretty),
    }
}

fn cmd_table_list(a: TableListArgs, pretty: bool) -> bool {
    match &a.table {
        Some(name) => match n0xis_project::table::load(name) {
            Ok(t) => emit(&Response::success(schema::v1::TABLE, t), pretty),
            Err(e) => ir_err("table-not-found", &e.to_string(), pretty),
        },
        None => match n0xis_project::table::list() {
            Ok(names) => emit(&Response::success(schema::v1::TABLE, json!({ "tables": names })), pretty),
            Err(e) => ir_err("table-list-failed", &e.to_string(), pretty),
        },
    }
}

fn cmd_table_show(a: TableShowArgs, pretty: bool) -> bool {
    let table = match n0xis_project::table::load(&a.table) {
        Ok(t) => t,
        Err(e) => return ir_err("table-not-found", &e.to_string(), pretty),
    };
    match &a.name {
        Some(name) => match table.entries.iter().find(|e| e.name.eq_ignore_ascii_case(name)) {
            Some(entry) => emit(&Response::success(schema::v1::TABLE, entry), pretty),
            None => ir_err("entry-not-found", &format!("no entry named '{name}' in table '{}'", a.table), pretty),
        },
        None => emit(&Response::success(schema::v1::TABLE, table), pretty),
    }
}

fn cmd_table_rm(a: TableShowArgs, pretty: bool) -> bool {
    match &a.name {
        Some(name) => match n0xis_project::table::remove_entry(&a.table, name) {
            Ok(removed) => emit(&Response::success(schema::v1::TABLE, json!({ "removed": removed })), pretty),
            Err(e) => ir_err("table-rm-failed", &e.to_string(), pretty),
        },
        None => match n0xis_project::table::delete(&a.table) {
            Ok(removed) => emit(&Response::success(schema::v1::TABLE, json!({ "removedTable": removed })), pretty),
            Err(e) => ir_err("table-rm-failed", &e.to_string(), pretty),
        },
    }
}

fn encode_scan_value(ty: TableValueType, v: f64) -> Result<Vec<u8>, String> {
    Ok(match ty {
        TableValueType::I8 => (v as i8).to_le_bytes().to_vec(),
        TableValueType::U8 => (v as u8).to_le_bytes().to_vec(),
        TableValueType::I16 => (v as i16).to_le_bytes().to_vec(),
        TableValueType::U16 => (v as u16).to_le_bytes().to_vec(),
        TableValueType::I32 => (v as i32).to_le_bytes().to_vec(),
        TableValueType::U32 => (v as u32).to_le_bytes().to_vec(),
        TableValueType::I64 => (v as i64).to_le_bytes().to_vec(),
        TableValueType::U64 => (v as u64).to_le_bytes().to_vec(),
        TableValueType::F32 => (v as f32).to_le_bytes().to_vec(),
        TableValueType::F64 => v.to_le_bytes().to_vec(),
        TableValueType::Aob => return Err("cannot freeze an Aob-typed entry as a scalar value".to_string()),
    })
}

fn cmd_table_freeze(a: TableFreezeArgs, pretty: bool) -> bool {
    use n0xis_sources::ModuleProvider;

    let table = match n0xis_project::table::load(&a.table) {
        Ok(t) => t,
        Err(e) => return ir_err("table-not-found", &e.to_string(), pretty),
    };
    let Some(entry) = table.entries.iter().find(|e| e.name.eq_ignore_ascii_case(&a.name)).cloned() else {
        return ir_err("entry-not-found", &format!("no entry named '{}' in table '{}'", a.name, a.table), pretty);
    };
    let value = match a.value.or(entry.freeze_value) {
        Some(v) => v,
        None => return ir_err("no-value", "provide --value or set the entry's freeze_value first", pretty),
    };
    let bytes = match encode_scan_value(entry.value_type, value) {
        Ok(b) => b,
        Err(e) => return ir_err("bad-value", &e, pretty),
    };
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };

    let addr = match &entry.locator {
        TableLocator::Address { va } => *va,
        TableLocator::PointerPath { module, root_offset, offsets } => {
            let Some(m) = live.modules().iter().find(|m| m.name.eq_ignore_ascii_case(module)) else {
                return ir_err("no-module", &format!("no module named '{module}' in this process"), pretty);
            };
            let root = PointerRoot { label: m.name.clone(), start: m.base, size: m.size };
            let core_path = n0xis_core::PointerPath { root_label: root.label.clone(), root_offset: *root_offset, offsets: offsets.clone() };
            let arch = X64::new();
            let ctx = Ctx::new(&live, &arch);
            match resolve_pointer_path(&ctx, &core_path, &[root], 8) {
                Some(va) => va,
                None => return ir_err("resolve-failed", "pointer path did not resolve (module layout changed?)", pretty),
            }
        }
        TableLocator::Aob { pattern, offset_from_match, module } => {
            let pattern_parsed = match parse_aob(pattern) {
                Ok(p) => p,
                Err(e) => return ir_err("bad-pattern", &e, pretty),
            };
            let (start, size) = match module.as_deref().and_then(|m| live.modules().iter().find(|mm| mm.name.eq_ignore_ascii_case(m))) {
                Some(m) => (m.base, m.size as usize),
                None => match live.text_range() {
                    Some((s, sz)) => (s, sz as usize),
                    None => return ir_err("no-range", "no default code range for this AOB entry; give it a --module", pretty),
                },
            };
            let arch = X64::new();
            let ctx = Ctx::new(&live, &arch);
            let art = match AobScanPass.run(&ctx, AobInput { start, size, pattern: pattern_parsed }) {
                Ok(a) => a,
                Err(e) => return ir_err("aob-failed", &e.to_string(), pretty),
            };
            match art.matches.first() {
                Some(&m) => Va((m.get() as i64 + offset_from_match) as u64),
                None => return ir_err("no-match", "the entry's AOB pattern was not found", pretty),
            }
        }
    };

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(a.duration_ms);
    let mut writes = 0usize;
    let mut errors = 0usize;
    loop {
        if std::time::Instant::now() >= deadline {
            break;
        }
        match live.write(addr, &bytes) {
            Ok(()) => writes += 1,
            Err(_) => errors += 1,
        }
        std::thread::sleep(std::time::Duration::from_millis(a.interval_ms.max(1)));
    }
    let data = json!({
        "table": a.table, "entry": a.name, "address": addr, "value": value,
        "writes": writes, "errors": errors, "durationMs": a.duration_ms, "intervalMs": a.interval_ms,
    });
    emit(&Response::success(schema::v1::FREEZE, data).with_source(live.label()), pretty)
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
