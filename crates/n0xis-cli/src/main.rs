// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

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
use n0xis_arch::{Arch, InsnKind, X64};
// The shared frontend seam (source resolution, ISA selection, argument
// parsing) — `n0xis-mcp` goes through the exact same functions, so `--pid`
// and `"pid"` cannot mean different things (CONCEPT §3 rules 3 and 5).
use n0xis_frontend::source::{Src, SourceSpec, base_for_module, load_snapshot, module_base_of, scan_range_or as scan_range};
use n0xis_frontend::{opt_hex, parse_hex_bytes, parse_hex_or_decimal_f64, parse_hex_or_decimal_u64, parse_hex_or_decimal_usize, resolve_arch};
use n0xis_contracts::{Response, Va, schema};
use n0xis_contracts::TableValueType;
use n0xis_core::{
    concept_grep_rank, identify_f64, identify_u64, parse_aob, AobByte, AobInput, AobScanPass, BindingsInput, BindingsPass,
    CfgInput, ConstMatch, Ctx, DecompInput, DecompPass, DecompStyle,
    Document,
    FilterCriterion,
    Pass, RankOptions,
    ValueType, XrefDir,
};
use n0xis_core::{CoordSpace, Rect};
// Used only by the commands that still need Win32 (table pin/locator, the
// watchpoint-driven provenance trace, detour trampolines, UI localization).
// Kept beside those rather than in the cross-platform block above, so the list
// doubles as an inventory of what a Linux adapter has yet to reach.
// Provenance (watchpoint hit → decompiled writing statement) is portable now
// that a Linux debug adapter exists, so its inputs ride the cross-platform gate.
#[cfg(any(windows, target_os = "linux", target_os = "android"))]
use n0xis_contracts::{TableEntry, TableLocator};
#[cfg(any(windows, target_os = "linux", target_os = "android"))]
use n0xis_core::{ProvenanceHit, ProvenanceInput, ProvenancePass};
// The scan and filter passes are platform-neutral in the core — they read
// through `MemorySource` and never touch an OS API. What used to be Win32-only
// was the *CLI's* import of them, which is why `locate by-transition` refused to
// run on Linux with a message blaming "LiveProcess/Win32 APIs" for a body that
// touches neither.
use n0xis_core::{FilterInput, FilterPass, ScanCriterion, ScanInput, ScanPass, ScanValue};
// Still Win32-only — the UI-locate and trampoline commands have not been routed
// through the seam yet; the list doubles as an inventory of what remains.
#[cfg(windows)]
use n0xis_core::{build_trampoline, AabbLayout, UiLocateInput, UiLocatePass};
use n0xis_pipeline::cfg_cached;
// Cross-platform sources: `MemorySource` (the trait), `Snapshot`/`StaticPe`
// (offline sources), `RemoteAgent`/`remote_serve_stdio` (the SSH/remote-serve
// transport — a Linux box can drive a *remote* Windows target over this
// without itself needing Win32) — none of these require the `live` feature.
use n0xis_sources::{MemorySource, Snapshot, StaticImage, remote_serve_stdio};
// Live-process (Win32) sources: only ever compiled in on Windows, matching
// n0xis-sources' own `#[cfg(feature = "live")]` gates (see its lib.rs) and
// this crate's Cargo.toml `[target.'cfg(windows)'.dependencies]` split.
#[cfg(windows)]
use n0xis_sources::{LiveProcess, probe_actuation, DEFAULT_PROBE_VK};
// The debug adapter's free functions + types exist on every OS that has a live
// adapter (Win32 or Linux ptrace), so the debug/provenance commands compile and
// run on both — only the register capture underneath differs.
#[cfg(any(windows, target_os = "linux", target_os = "android"))]
use n0xis_sources::{attach_and_wait, await_breakpoint_hit, await_watchpoint_hit, await_watchpoint_hit_where, RegCond, WatchKind};
#[cfg(windows)]
use n0xis_sources::{best_window, encode_png, focus as window_focus, list_windows, screenshot as window_screenshot, CaptureMethod};
use serde_json::json;

use emit::emit;

use n0xis_bitsquid::{lua_resource, open_bundle, LuaFormat};

/// N0xis — reverse-engineering and live-memory toolkit for Windows and Linux.
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

#[derive(Args)]
struct GuideArgs {
    /// Filter the catalog to commands whose path contains this substring
    /// (e.g. `scan`, `provenance`, `concept`). Omit for the full catalog.
    topic: Option<String>,
    /// Include the per-argument detail for every command (on by default; pass
    /// `--brief` to drop it for a shorter overview).
    #[arg(long)]
    brief: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Environment / readiness check.
    Doctor,
    /// Profile a target before analyzing it: image facts (sections, exports,
    /// branch stubs, folded addresses, `.pdata`), the runtime/engine it was
    /// built with, and **which commands will be ineffective on it and why**.
    /// Run this first on an unfamiliar binary — it answers in one call what is
    /// otherwise learned by a sequence of empty results.
    Profile(ProfileArgs),
    /// Agent-oriented capability catalog: every command, its arguments, and
    /// composable workflow recipes — structured JSON an AI agent can read to
    /// understand what the tool can do and how to drive it. `guide <topic>`
    /// filters to matching commands (e.g. `guide scan`).
    Guide(GuideArgs),
    /// Create a `.n0x/` project (config, dirs, `n0x.cmd` shim).
    Init(InitArgs),
    /// Project introspection.
    #[command(subcommand)]
    Project(ProjectCmd),
    /// Program databases (PDB) for the project's images.
    #[command(subcommand)]
    Symbols(SymbolsCmd),
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
    /// MSVC RTTI vtable → class-name recovery.
    #[command(subcommand)]
    Rtti(RttiCmd),
    /// Whole-program analysis: discover functions, recover MSVC RTTI class
    /// names, build the reverse-xref index, and warm the IR cache — materializing
    /// the `.n0x/` summary layer once so later `xref`/`decomp` are fast. Streams
    /// `[n0x]`-prefixed phase/progress JSON to stderr; resumable (content-
    /// addressed work already done is skipped). Static x64 PE (`--file`).
    Analyze(AnalyzeArgs),
    /// Search the image for a byte pattern, a string, or an escaped string —
    /// the "Find" a disassembler's Ctrl+F does. One of `--bytes` (with
    /// `?`/`??` wildcards), `--string` (UTF-8; `--utf16` for wide), or `--escaped`
    /// (`\xNN`, `\n`, `\t`, `\r`, `\0`, `\\`). Scans every file-backed section by
    /// default; narrow with `--section`, or `--start`/`--size`.
    Find(FindArgs),
    /// Text in the image: runs of printable UTF-8 or UTF-16LE characters, with
    /// their addresses. By default the file-backed sections that hold no code;
    /// `--section`, `--all-sections`, or `--start`/`--size` for others.
    /// `--contains` filters (any case); `--limit`/`--offset` page.
    Strings(StringsArgs),
    /// Define named struct / enum types the decompiler uses to render struct
    /// field names (`p->count` instead of `p->field_0x68`).
    #[command(subcommand)]
    Type(TypeCmd),
    /// Raw memory access.
    #[command(subcommand)]
    Mem(MemCmd),
    /// Memory patching with a persisted undo journal.
    #[command(subcommand)]
    Patch(PatchCmd),
    /// Named memory-range anchors, persisted under `.n0x/selections.json`.
    #[command(subcommand)]
    Selection(SelectionCmd),
    /// Registered analysis plugins, persisted under `.n0x/plugins.json`
    /// (`docs/COMMUNITY_ROADMAP.md`'s "Plugin system").
    #[command(subcommand)]
    Plugin(PluginCmd),
    /// The capability registry: everything this build can do, built-in and
    /// plugin-provided, through one contract (`n0xis-frontend::registry`).
    #[command(subcommand)]
    Capability(CapabilityCmd),
    /// Persistent artifact store under `.n0x/dumps/<kind>/`.
    #[command(subcommand)]
    Dump(DumpCmd),
    /// Live execution control (software + hardware breakpoints).
    #[command(subcommand)]
    Debug(DebugCmd),
    /// Call-stack recovery from a captured register set — cross-process,
    /// format-neutral (PE `.pdata` or ELF `.eh_frame` DWARF CFI, chosen per
    /// module, so native and Wine targets alike).
    #[command(subcommand)]
    Stack(StackCmd),
    /// Typed value/AOB/pointer-path scanning + struct dissection.
    #[command(subcommand)]
    Scan(ScanCmd),
    /// .NET NativeAOT metadata: recover managed method names (RVA ↔ name) that
    /// NativeAOT strips from ordinary symbols. Works on `--file` and `--pid`.
    #[command(subcommand)]
    Aot(AotCmd),
    /// `.n0xt` address/analysis tables.
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
    /// Persistent static session: load `--file` once, then read one command
    /// line per line from stdin (e.g. `decomp pseudo --addr 0x…`) and write one
    /// compact JSON envelope per line to stdout — the image is parsed once and
    /// reused, so repeated decompile/disasm/xref calls avoid the per-call file
    /// re-load. A GUI/agent front-end drives this instead of spawning the CLI
    /// per click. A line may instead be a JSON array of argument strings
    /// (`["annotate","comment","--addr","0x…","--value","…"]`), which carries
    /// any text exactly; the ready banner lists the accepted forms in
    /// `data.request_formats`. Blank line or EOF exits.
    Serve(ServeArgs),
    /// Structural diffing at the IR/pseudo level (Phase 7): agent-friendly
    /// change reports between two functions (e.g. two builds of a binary).
    #[command(subcommand)]
    Diff(DiffCmd),
    /// Bitsquid bundle files (chunked-zlib archive +
    /// exploded-package entries/variants) — reading packaged assets, not
    /// process memory.
    #[command(subcommand)]
    Bundle(BundleCmd),
    /// Lua/LuaJIT bytecode disassembly.
    #[command(subcommand)]
    Lua(LuaCmd),
    /// Spec-first RE (Phase 8): search a target's scripts/data/strings for a
    /// concept's vocabulary and rank by cluster density — the "climb the spec
    /// ladder, don't reverse runtime state" front door (RE_METHOD F2).
    // `game` is a hidden alias: this command was first published as
    // `game grep`, and scripts and recipes written against that name must keep
    // parsing to exactly this command. Hidden, so `guide` and `--help` list one
    // name and the catalog's command count does not change. The alias is read
    // from `CONCEPT_GREP`, the record that also keeps the old spelling's schema
    // id, so the name that parses and the name that is bridged are one fact.
    // A plain comment, not a doc comment: clap would print a `///` paragraph
    // as user help.
    #[command(subcommand, alias = CONCEPT_GREP.first[0])]
    Concept(ConceptCmd),
    /// Localize a value by the *transition diff* — snapshot, let the operator
    /// toggle one thing, rescan, keep only what changed (Phase 8; RE_METHOD W1,
    /// the only localization technique that ever reliably worked).
    #[command(subcommand)]
    Locate(LocateCmd),
    /// Probe the input *actuation* path before building on it — which injection
    /// methods a target will actually register (Phase 8; RE_METHOD F4).
    #[command(subcommand)]
    Input(InputCmd),
    /// Identify canonical magic constants (LCG multipliers, hash seeds, CRC
    /// polynomials, float normalizers) in a value, a function, or a Lua chunk
    /// (Phase 8; RE_METHOD W3).
    #[command(subcommand)]
    Const(ConstCmd),
    /// Enumerate a script VM's native bindings — pair each registration *name*
    /// with its C function pointer (Phase 8; RE_METHOD W2).
    #[command(subcommand)]
    Bindings(BindingsCmd),
    /// Validate a byte signature against multiple samples: report which bytes
    /// are actually invariant and refuse to bless one from <3 independent,
    /// deliberately-varied samples (Phase 8; RE_METHOD F3).
    #[command(subcommand)]
    Sig(SigCmd),
    /// NOT VALIDATED (Phase 9 is marked invalid): screen region -> memory is not
    /// implemented for real targets; `ui locate` only hit-tests one hardcoded
    /// layout. See docs/PHASE9_UI_LOCATE_BRIEF.md.
    #[command(subcommand)]
    Ui(UiCmd),
    /// IL2CPP managed layer (Phase 12): the C# names behind an IL2CPP target's
    /// addresses. Item 0 imports an index another tool produced
    /// and serves it through the same symbol seam the PE exports use, so
    /// `decomp pseudo`, `xref` and friends start naming with no changes of
    /// their own. Windows and IL2CPP WebGL dumps are both importable — and an
    /// address space is never applied to the wrong kind of target.
    #[command(subcommand)]
    Il2cpp(Il2cppCmd),
}

#[derive(Subcommand)]
enum Il2cppCmd {
    /// Import an external dump as a named index under `.n0x/il2cpp/`. With a
    /// target it also *measures* how the dump's addresses map onto it — dumper
    /// versions disagree about RVA vs VA, so both are tried against `.text` and
    /// a mismatch is refused rather than applied.
    Import(Il2cppImportArgs),
    /// Query an index by name substring, or by address with a target. Name
    /// lookups return a set: generic sharing and ICF both make one answer a lie.
    Symbols(Il2cppSymbolsArgs),
    /// Read `global-metadata.dat` natively — format version, the tables its
    /// header declares, and the string literals. Needs no external dumper, and
    /// `--file <image>` finds the blob beside the target on its own.
    Metadata(Il2cppMetadataArgs),
    /// Recover engine internal calls from the code that resolves them:
    /// the registration name and the `.data` slot its resolved pointer is
    /// cached into. Against a live target the slots are read, turning names
    /// into real addresses on a process that reports no symbols at all.
    Icalls(Il2cppIcallsArgs),
    /// Identify a live address through the runtime type system: its C# class and
    /// every field with the offset the runtime states. No metadata parse, no
    /// external dumper — the layout is discovered and validated.
    Obj(Il2cppObjArgs),
    /// Enumerate the C# classes a running process has loaded, by sampling the heap
    /// for object headers. No metadata parse, no dumper — and a sample, which
    /// the answer says plainly.
    Classes(Il2cppClassesArgs),
}

#[derive(Args)]
struct Il2cppImportArgs {
    /// Path to a `script.json` symbol dump.
    #[arg(long = "script-json")]
    script_json: String,
    /// Name to store the index under (default `default`).
    #[arg(long)]
    name: Option<String>,
    /// Address space of the dump: `native` (a PE such as `GameAssembly.dll`)
    /// or `wasm` (an IL2CPP WebGL build). A `wasm` index is importable and
    /// searchable but is never bound to a native image — its addresses are
    /// WebAssembly offsets and would name every function wrongly.
    #[arg(long)]
    space: Option<String>,
    /// The module the dump was taken from, e.g. `GameAssembly.dll`.
    #[arg(long)]
    module: Option<String>,
    /// Target to validate the binding against.
    #[arg(long)]
    pid: Option<u32>,
    /// Static target to validate the binding against.
    #[arg(long)]
    file: Option<String>,
    /// Store the index even when its addresses do not fit the target. Off by
    /// default: names from a mismatched dump are worse than no names.
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct Il2cppSymbolsArgs {
    /// Which stored index to query (default `default`).
    #[arg(long)]
    name: Option<String>,
    /// Case-insensitive substring of the symbol name.
    #[arg(long)]
    query: Option<String>,
    /// Look up the symbol owning this address instead (needs `--pid`/`--file`).
    #[arg(long)]
    addr: Option<String>,
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Maximum symbols to return (default 50, capped at 1000).
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    limit: Option<usize>,
}

#[derive(Args)]
struct Il2cppClassesArgs {
    #[arg(long)]
    pid: u32,
    /// Case-insensitive substring of the class or namespace name.
    #[arg(long)]
    query: Option<String>,
    /// Heap regions to sample, biggest first (default 8).
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    regions: Option<usize>,
    /// Bytes to read from each region (default 0x20000).
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    window: Option<usize>,
    /// Candidate pointers to probe before stopping (default 2000).
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    max_probe: Option<usize>,
    /// How often a pointer must repeat to be worth probing (default 2).
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    min_hits: Option<usize>,
    /// Accept classes with no pointer to themselves. Needed only for builds
    /// whose IL2CPP runtime predates 2018.1, and much slower — the self-pointer
    /// is what rejects candidates without reading strings.
    #[arg(long)]
    any_layout: bool,
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    limit: Option<usize>,
    #[arg(long)]
    arch: Option<String>,
}

#[derive(Args)]
struct Il2cppObjArgs {
    /// A managed object address, or an Il2CppClass address.
    #[arg(long)]
    addr: String,
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Object bytes to read for field values (default 0x100).
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    size: Option<usize>,
    /// Bytes of the class structure to probe when discovering the layout.
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    probe: Option<usize>,
    #[arg(long)]
    arch: Option<String>,
}

#[derive(Args)]
struct Il2cppIcallsArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Which module to scan, by case-insensitive substring. Required in
    /// practice on a live IL2CPP target: the main module is a thin host
    /// executable and the code is in `GameAssembly.dll`.
    #[arg(long)]
    module: Option<String>,
    /// Case-insensitive substring of the registration name.
    #[arg(long)]
    query: Option<String>,
    /// Do not read the cache slots even on a live target.
    #[arg(long)]
    no_resolve: bool,
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    limit: Option<usize>,
    #[arg(long)]
    arch: Option<String>,
}

#[derive(Args)]
struct Il2cppMetadataArgs {
    /// Path to a `global-metadata.dat`.
    #[arg(long)]
    metadata: Option<String>,
    /// Target image; the blob is looked for in a sibling `*_Data` directory.
    #[arg(long)]
    file: Option<String>,
    /// Case-insensitive substring to search the string literals for — the
    /// static answer to "is this on-screen text in the program".
    #[arg(long)]
    query: Option<String>,
    /// Maximum literals to return (default 50, capped at 1000).
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    limit: Option<usize>,
    /// Skip this many matches before the page — a big build carries tens of
    /// thousands of literals.
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    offset: Option<usize>,
}

#[derive(Subcommand)]
enum UiCmd {
    /// NOT VALIDATED (Phase 9 marked invalid): hit-test one hardcoded UI-box
    /// layout against a screen rect. Do not rely on the results.
    Locate(UiLocateArgs),
    /// List a process's top-level windows (title/class/rects/DPI) so an agent
    /// can name the target's main window before capturing or locating.
    Windows(UiWindowsArgs),
    /// Capture a window to a PNG so an agent can visually choose a rect. Honest
    /// about blank frames (GDI/PrintWindow return black for flip-model DirectX)
    /// — never reports a blank capture as a real image.
    Screenshot(UiScreenshotArgs),
    /// Bring a window to the foreground (window selector). NOT read-only — it
    /// activates a window on the target.
    Focus(UiFocusArgs),
}

#[derive(Args)]
struct UiWindowsArgs {
    #[arg(long)]
    pid: u32,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum CaptureMethodArg {
    /// Try PrintWindow (composited content), then window-DC BitBlt.
    Auto,
    /// `BitBlt` from the window DC — cheapest, occlusion-immune; blank for
    /// flip-model/DComp.
    WindowDc,
    /// `PrintWindow(PW_RENDERFULLCONTENT)` — composited content; disturbs the
    /// target's UI thread.
    Printwindow,
}

#[derive(Args)]
struct UiScreenshotArgs {
    #[arg(long)]
    pid: u32,
    /// Capture this specific window (HWND, as printed by `ui windows`);
    /// defaults to the best-guess main window for the pid.
    #[arg(long)]
    hwnd: Option<usize>,
    /// Capture path. `auto` (default) tries composited then GDI and returns the
    /// first non-blank frame.
    #[arg(long, value_enum, default_value_t = CaptureMethodArg::Auto)]
    method: CaptureMethodArg,
    /// Write the PNG here. Written even on a blank/diagnostic capture (with
    /// `blank:true` in the envelope) — never silently.
    #[arg(long)]
    out: Option<String>,
    /// Also embed the PNG as base64 in the envelope (for agents with no file
    /// access). Off by default — a full-window PNG is large.
    #[arg(long)]
    base64: bool,
}

#[derive(Args)]
struct UiFocusArgs {
    #[arg(long)]
    pid: u32,
    /// Window to focus (HWND from `ui windows`); defaults to the best-guess
    /// main window for the pid.
    #[arg(long)]
    hwnd: Option<usize>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum SpaceArg {
    Auto,
    Screen,
    Ndc,
}

impl From<SpaceArg> for CoordSpace {
    fn from(s: SpaceArg) -> Self {
        match s {
            SpaceArg::Auto => CoordSpace::Auto,
            SpaceArg::Screen => CoordSpace::Screen,
            SpaceArg::Ndc => CoordSpace::Ndc,
        }
    }
}

#[derive(Args)]
struct UiLocateArgs {
    #[arg(long)]
    pid: u32,
    /// The query rectangle as `x0,y0,x1,y1` (any corner order; normalized
    /// internally).
    #[arg(long)]
    rect: String,
    /// Coordinate space the AABBs are read in: `auto` (default, permissive
    /// bound + reports the observed range so you can tell which space it
    /// really is), `screen` (pixels), or `ndc` (normalized device coords).
    #[arg(long, value_enum, default_value_t = SpaceArg::Auto)]
    space: SpaceArg,
    /// Region start (hex). Omit (with `--size`) to scan every committed
    /// writable region — the same default `scan value`/`scan aob` use.
    #[arg(long)]
    start: Option<String>,
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    size: Option<usize>,
    /// Byte stride between candidate positions (fields are dword-aligned).
    #[arg(long, default_value_t = 4)]
    align: usize,
    /// Cap on ranked elements reported (highest overlap first).
    #[arg(long, default_value_t = 50)]
    limit: usize,
    /// Persist this query's rect + result addresses under
    /// `.n0x/dumps/ui_locate/<name>.json`, so a later query can exclude them
    /// (spatial-diff workflow: save a rect where the widget is *absent*,
    /// then exclude it from a query where it's present — anything left over
    /// is specific to the present rect, not an ambient/global structure that
    /// overlaps every rect, e.g. a coincidentally AABB-shaped shader constant
    /// buffer).
    #[arg(long)]
    save_as: Option<String>,
    #[arg(long)]
    force: bool,
    /// Exclude every address found in a previously `--save-as`d query (by
    /// name) from this result — the spatial-diff filter. Repeatable.
    #[arg(long = "exclude-from")]
    exclude_from: Vec<String>,
}

#[derive(Subcommand)]
enum ConceptCmd {
    /// Rank scripts/data/strings by how densely they cluster a concept's
    /// vocabulary. `<concept>` is the vocabulary (comma/space/pipe-separated),
    /// e.g. `"retry,backoff,timeout"`.
    Grep(ConceptGrepArgs),
}

#[derive(Args)]
struct ConceptGrepArgs {
    /// The concept vocabulary — comma / whitespace / `|`-separated terms.
    concept: String,
    /// Directory of extracted scripts/data to search (repeatable). LuaJIT
    /// bytecode files are decoded to text automatically.
    #[arg(long = "dir", required = true)]
    dirs: Vec<String>,
    /// Extra vocabulary term (repeatable), added to `<concept>`.
    #[arg(long = "term")]
    terms: Vec<String>,
    /// Require at least this many *distinct* concept terms per file (raise to
    /// 2+ to cut single-word noise).
    #[arg(long, default_value_t = 1)]
    min_distinct: usize,
    /// Max ranked files to report.
    #[arg(long, default_value_t = 40)]
    limit: usize,
    /// Max context snippets per file.
    #[arg(long, default_value_t = 3)]
    max_snippets: usize,
}

#[derive(Subcommand)]
enum LocateCmd {
    /// Snapshot → operator toggles one thing → rescan → keep only what changed.
    ByTransition(LocateByTransitionArgs),
}

#[derive(Args)]
struct LocateByTransitionArgs {
    #[arg(long)]
    pid: u32,
    #[arg(long, value_enum, default_value_t = ValueTypeArg::I32)]
    r#type: ValueTypeArg,
    /// Region start (hex). Omit (with `--size`) to snapshot every committed
    /// writable region, which is the default scan set.
    #[arg(long)]
    start: Option<String>,
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    size: Option<usize>,
    /// Byte stride between candidates; defaults to the value's natural size.
    #[arg(long)]
    align: Option<usize>,
    /// The transition to keep: `changed` (default), `increased`, or `decreased`.
    #[arg(long, default_value = "changed")]
    transition: String,
    /// Instead of pausing for the operator, wait this many milliseconds between
    /// the snapshot and the rescan (for scripted/agent use).
    #[arg(long)]
    wait_ms: Option<u64>,
    /// After the transition filter, keep only survivors whose new value equals
    /// this (a structural predicate over the survivors).
    #[arg(long)]
    expect: Option<f64>,
    /// After the transition filter, keep only survivors whose new value is in
    /// `[--min, --max]`.
    #[arg(long, value_parser = parse_hex_or_decimal_f64)]
    min: Option<f64>,
    #[arg(long, value_parser = parse_hex_or_decimal_f64)]
    max: Option<f64>,
    /// Persist the final working set under `.n0x/dumps/scan/<name>.json` so a
    /// later `scan filter` can narrow it further.
    #[arg(long)]
    save_as: String,
    #[arg(long)]
    force: bool,
}

#[derive(Subcommand)]
enum InputCmd {
    /// Try each actuation method and report which the OS input stack registers
    /// and whether each carries the `LLKHF_INJECTED` flag a target may filter.
    Probe(InputProbeArgs),
}

#[derive(Args)]
struct InputProbeArgs {
    /// Optional target pid, recorded for context (injected input routes to the
    /// foreground window, so the probe is desktop-global).
    #[arg(long)]
    pid: Option<u32>,
    /// Virtual-key code to actuate (decimal or `0x..`). Defaults to VK_F15
    /// (0x7E), an almost-never-bound key.
    #[arg(long)]
    vk: Option<String>,
    /// Per-method wait for the event, in milliseconds.
    #[arg(long, default_value_t = 400)]
    timeout_ms: u32,
}

#[derive(Subcommand)]
enum ConstCmd {
    /// Recognize magic constants. Provide `--value`, or a function
    /// (`--file/--pid/--snapshot` + `--addr`), or a Lua chunk (`--lua`).
    Identify(ConstIdentifyArgs),
}

#[derive(Args)]
struct ConstIdentifyArgs {
    /// A single constant to identify: hex (`0x5bd1e995`), decimal (`1664525`),
    /// or a float (`2.3283064e-10`).
    #[arg(long)]
    value: Option<String>,
    /// Decompile this function and identify every numeric literal in it.
    #[arg(long)]
    addr: Option<String>,
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    #[arg(long)]
    snapshot: Option<String>,
    #[arg(long)]
    remote_cmd: Option<String>,
    /// Byte window for the function decompile (with `--addr`).
    #[arg(long, default_value_t = 4096, value_parser = parse_hex_or_decimal_usize)]
    func_size: usize,
    /// Decode this Lua/LuaJIT chunk and identify its number constants.
    #[arg(long)]
    lua: Option<String>,
}

#[derive(Subcommand)]
enum BindingsCmd {
    /// List native bindings by pairing name strings with function pointers.
    List(BindingsListArgs),
}

#[derive(Args)]
struct BindingsListArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    #[arg(long)]
    snapshot: Option<String>,
    #[arg(long)]
    remote_cmd: Option<String>,
    /// On a live process, restrict the scan to this module's `.text`/`.rdata`
    /// (by name substring); defaults to the main module.
    #[arg(long)]
    module: Option<String>,
    /// Only look for these exact binding names (repeatable); default is every
    /// identifier-like string in the data window.
    #[arg(long = "name")]
    names: Vec<String>,
    /// Data window override (defaults to `.rdata`).
    #[arg(long)]
    data_start: Option<String>,
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    data_size: Option<usize>,
    /// Code window override (defaults to `.text`).
    #[arg(long)]
    start: Option<String>,
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    size: Option<usize>,
    /// Instructions on each side of a name-load to search for the paired
    /// function-pointer load.
    #[arg(long, default_value_t = 8)]
    window: usize,
    #[arg(long, default_value_t = 200)]
    limit: usize,
    /// Drop bindings below this confidence (0.0..=1.0).
    #[arg(long, default_value_t = 0.0)]
    min_confidence: f32,
    /// Instruction set to decode: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
}

#[derive(Subcommand)]
enum SigCmd {
    /// Report which bytes are invariant across samples; refuse to bless a
    /// signature from <3 deliberately-varied samples.
    Validate(SigValidateArgs),
    /// Generate a FLIRT-class `.npat` signature database from a *symbolized*
    /// image: fingerprint each named function's leading bytes, wildcarding the
    /// displacements a linker varies (relative call/jump targets, RIP-relative
    /// offsets). Feed the output back with `decomp … --flirt` to name the same
    /// functions in a *stripped* binary that statically links them.
    Gen(SigGenArgs),
}

#[derive(Args)]
struct SigValidateArgs {
    /// A concrete byte sample, hex (`"CF 01 A0 00"`); repeatable. A sample is
    /// observed reality — no wildcards.
    #[arg(long = "sample")]
    samples: Vec<String>,
    /// A file whose raw bytes are one sample (repeatable).
    #[arg(long = "sample-file")]
    sample_files: Vec<String>,
    /// Read a sample of `--len` bytes at this address from a live/static source
    /// (repeatable; needs `--pid`/`--file` and `--len`).
    #[arg(long = "at")]
    ats: Vec<String>,
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Length of each `--at` sample.
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    len: Option<usize>,
    /// The proposed signature to audit (`"48 8B ?? 68"`, `??` = wildcard).
    #[arg(long)]
    signature: Option<String>,
    /// Which axes you deliberately varied across the samples
    /// (`input,session,seed`). Required to bless — an invariant is only
    /// meaningful relative to what changed.
    #[arg(long)]
    varied: Option<String>,
    /// Independence bar (default 3).
    #[arg(long, default_value_t = 3)]
    min_independent: usize,
}

#[derive(Args)]
struct SigGenArgs {
    /// The symbolized image to learn signatures from (an ELF with a `.symtab`/
    /// `.dynsym`, or a PE with exports). A fully stripped image yields nothing.
    #[arg(long)]
    file: String,
    /// Instruction-decoder override; auto-selected from the image otherwise.
    #[arg(long)]
    arch: Option<String>,
    /// Bytes of each function to fingerprint (default 32). Longer is more
    /// specific but more likely to run past a short function into padding.
    #[arg(long, default_value_t = 32, value_parser = parse_hex_or_decimal_usize)]
    window: usize,
    /// Drop a signature with fewer than this many fixed (non-wildcard) bytes —
    /// too little concrete code to name a function without collisions. Defaults
    /// to the read side's floor ([`n0xis_flirt::DEFAULT_MIN_FIXED_BYTES`]) so the
    /// write and read sides refuse at the same specificity (one fact, one place).
    #[arg(long, default_value_t = n0xis_flirt::DEFAULT_MIN_FIXED_BYTES)]
    min_fixed: usize,
    /// Keep compiler/CRT glue (`_init`, `register_tm_clones`, `frame_dummy`, …).
    /// By default these are skipped: they are present, byte-identical, in nearly
    /// every binary, so signing them adds only noise (and would name unrelated
    /// glue in a target). A real library's own functions are always kept.
    #[arg(long)]
    include_glue: bool,
}

/// Linker/CRT scaffolding that every compiled image carries — not library code.
/// Signing it pollutes a signature library with entries that match the identical
/// boilerplate in any other binary, so `sig gen` drops it unless asked not to.
fn is_toolchain_glue(name: &str) -> bool {
    const GLUE: &[&str] = &[
        "_init", "_fini", "_start", "__libc_csu_init", "__libc_csu_fini",
        "register_tm_clones", "deregister_tm_clones", "__do_global_dtors_aux",
        "__do_global_ctors_aux", "frame_dummy", "__gmon_start__", "atexit",
        "__stack_chk_fail_local", "_dl_relocate_static_pie", "__cxa_finalize",
    ];
    GLUE.contains(&name)
        // GCC/Clang PC-thunks: `__x86.get_pc_thunk.bx`, `__i686.get_pc_thunk.cx`.
        || name.contains("get_pc_thunk")
}

#[derive(Subcommand)]
enum BundleCmd {
    /// List a bundle's entries (type/path hash, variant sizes), optionally
    /// filtered to one known type.
    List(BundleListArgs),
    /// Extract every variant of a given type to files on disk.
    Extract(BundleExtractArgs),
    /// Replace one variant's raw bytes with a same-length file and
    /// recompress — the write-back half of `extract`/`n0xis-lua::patch_instruction`.
    Repack(BundleRepackArgs),
}

#[derive(Args)]
struct BundleListArgs {
    /// The bundle (archive) file — a hash-named file under the application's
    /// `contents/` directory.
    #[arg(long)]
    file: String,
    /// The bundle's paired `.stream` file, if it has one. Defaults to
    /// `<file>.stream` when present on disk.
    #[arg(long)]
    stream: Option<String>,
    /// Only list entries of this known type (e.g. `lua`, `texture`).
    #[arg(long)]
    r#type: Option<String>,
}

#[derive(Args)]
struct BundleExtractArgs {
    #[arg(long)]
    file: String,
    #[arg(long)]
    stream: Option<String>,
    /// Only extract entries of this known type (e.g. `lua`).
    #[arg(long)]
    r#type: String,
    /// Output directory; defaults to `./<bundle-filename>_<type>/`.
    #[arg(long)]
    out: Option<String>,
}

#[derive(Args)]
struct BundleRepackArgs {
    /// The original bundle (archive) file to repack.
    #[arg(long)]
    file: String,
    #[arg(long)]
    stream: Option<String>,
    /// The entry's path_hash (hex, as printed by `bundle list`).
    #[arg(long)]
    path_hash: String,
    /// Which variant of that entry to replace (default: 0).
    #[arg(long, default_value_t = 0)]
    variant: usize,
    /// File whose bytes replace that variant's raw inline data. Must be
    /// exactly the same length as the original (a same-size patch needs no
    /// other field in the bundle updated; a different-length replacement
    /// isn't supported by this command).
    #[arg(long)]
    replacement_file: String,
    /// Output path for the repacked bundle.
    #[arg(long)]
    out: String,
}

#[derive(Subcommand)]
enum LuaCmd {
    /// Disassemble a Lua/LuaJIT bytecode chunk.
    Disasm(LuaDisasmArgs),
    /// Overwrite one instruction's raw 4-byte word in place.
    Patch(LuaPatchArgs),
    /// Find live LuaJIT GCstr objects in a running process's heap, by
    /// decoding the real object header — no hand-picked byte pattern needed
    /// per string.
    Strings(LuaStringsArgs),
    /// Decode a live LuaJIT table (`GCtab`) at an address: its array part and
    /// hash part, with string values resolved to text. Walk the object graph
    /// without a debugger (pure memory reads).
    Table(LuaTableArgs),
    /// Find live Lua *arrays of known strings* in the heap by matching runs of
    /// tagged `TValue`s against a target string set — layout-independent (needs
    /// no `GCtab` calibration). Built for reading a direction sequence
    /// `{"up","down",…}` straight out of memory, but general to any
    /// array-of-known-tokens.
    Combo(LuaComboArgs),
    /// Recover an LCG seed from an observed sequence: scan a live process for a
    /// 4-byte word whose `s'=s*a+c` LCG reproduces a known sequence, locating the
    /// seed field and validating the RNG model at once. Constants are flags
    /// (default = the commonly observed Numerical-Recipes pair).
    Seedscan(LuaSeedscanArgs),
}

#[derive(Args)]
struct LuaSeedscanArgs {
    #[arg(long)]
    pid: u32,
    /// Region start (hex); omit with `--size` to scan every committed writable
    /// region.
    #[arg(long)]
    start: Option<String>,
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    size: Option<usize>,
    /// The observed sequence as directions (`up,down,down,up`) — mapped to the
    /// script's `random(0,3)` codes `left=0,up=1,right=2,down=3`.
    #[arg(long)]
    combo: String,
    /// LCG multiplier `a` (default: Numerical Recipes).
    #[arg(long, default_value_t = 1664525)]
    lcg_a: u32,
    /// LCG increment `c` (default: Numerical Recipes).
    #[arg(long, default_value_t = 1013904223)]
    lcg_c: u32,
    /// Range size `k` for `random(0, k-1)` (4 directions).
    #[arg(long, default_value_t = 4)]
    range: u32,
    /// Constrain candidate seeds to `[1, 2^31-2]` (the target's `math.random`
    /// range) to cut coincidental matches. Pass `--no-seed-bound` to disable.
    #[arg(long = "no-seed-bound", action = clap::ArgAction::SetFalse)]
    seed_bound: bool,
}

#[derive(Args)]
struct LuaDisasmArgs {
    /// Path to a **LuaJIT 2.0 bytecode dump** (a `luajit -b` file, dump
    /// version 1, `\x1bLJ\x01` magic). Lua source text, stock `luac` output,
    /// and newer LuaJIT dump versions (2.1 = version 2) are NOT accepted — the
    /// reader targets the LuaJIT 2.0 format only.
    #[arg(long)]
    file: String,
}

#[derive(Args)]
struct LuaPatchArgs {
    #[arg(long)]
    file: String,
    /// Prototype index (as shown by `lua disasm`).
    #[arg(long)]
    proto: usize,
    /// Instruction index within that prototype (`idx` in `lua disasm`'s
    /// output). Must be `>= 1` — index 0 is synthesized, not a real word.
    #[arg(long)]
    instr: u32,
    /// The replacement instruction, as a raw hex u32 (little-endian fields:
    /// opcode in the low byte, then A, then B/D — see `n0xis-lua::opcodes`).
    #[arg(long)]
    raw: String,
    #[arg(long)]
    out: String,
}

#[derive(Args)]
struct LuaStringsArgs {
    #[arg(long)]
    pid: u32,
    /// Region start (hex). Omit (with `--size`) to scan every committed
    /// writable region, same default as `scan aob`/`scan value`.
    #[arg(long)]
    start: Option<String>,
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    size: Option<usize>,
    /// Minimum string length (bytes) to accept as a candidate.
    #[arg(long, default_value_t = 1)]
    min_len: u32,
    /// Maximum string length (bytes) to accept as a candidate.
    #[arg(long, default_value_t = 64)]
    max_len: u32,
    /// Only report strings whose text contains this substring.
    #[arg(long)]
    contains: Option<String>,
    /// Byte offset of a `GCstr`'s `len` field from the object's base, for this
    /// build. It decides where an object *begins*, so the wrong value does not
    /// merely mislabel an address — it makes every comparison against a
    /// `TValue`'s pointer fail. Measured: the Bitsquid-bundle build this was
    /// calibrated against uses `0x10`; a stock LuaJIT 2.1 GC64 build uses
    /// `0x14`, and with `0x10` there `lua combo` reports zero arrays for an
    /// array that is plainly present.
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    gcstr_len_off: Option<usize>,
}

#[derive(Args)]
struct LuaTableArgs {
    #[arg(long)]
    pid: u32,
    /// Address of the `GCtab` object (hex `0x…`).
    #[arg(long)]
    addr: String,
    /// Byte offset of a `GCstr`'s `len` field from the object's base, for this
    /// build. The default is the Bitsquid-bundle value this was calibrated
    /// against; a stock LuaJIT 2.1 GC64 build puts it at `0x14` instead, and
    /// with the wrong offset every string in the table reads back as `null`.
    ///
    /// To find it for an unknown build: the byte at base+9 is the object's
    /// type tag (`4` = string), and the `len` field is the word whose value is
    /// the string's length, with the bytes following it.
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    gcstr_len_off: Option<usize>,
}

#[derive(Args)]
struct LuaComboArgs {
    #[arg(long)]
    pid: u32,
    /// Region start (hex). Omit (with `--size`) to scan every committed
    /// writable region, same default as `lua strings`.
    #[arg(long)]
    start: Option<String>,
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    size: Option<usize>,
    /// Comma-separated token set the array elements must be drawn from. Default
    /// is the four directions.
    #[arg(long, default_value = "up,down,left,right")]
    strings: String,
    /// Minimum consecutive matching elements to report as a run (filters
    /// coincidental single string pointers).
    #[arg(long, default_value_t = 2)]
    min_run: usize,
    /// Byte offset of a `GCstr`'s `len` field from the object's base, for this
    /// build. It decides where an object *begins*, so the wrong value does not
    /// merely mislabel an address — it makes every comparison against a
    /// `TValue`'s pointer fail. Measured: the Bitsquid-bundle build this was
    /// calibrated against uses `0x10`; a stock LuaJIT 2.1 GC64 build uses
    /// `0x14`, and with `0x10` there `lua combo` reports zero arrays for an
    /// array that is plainly present.
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    gcstr_len_off: Option<usize>,
}

#[derive(Subcommand)]
enum DiffCmd {
    /// Decompile two functions (from two sources/addresses) and diff their
    /// pseudo-C line-by-line.
    Functions(DiffFunctionsArgs),
}

#[derive(Args)]
struct DiffFunctionsArgs {
    #[arg(long)]
    a_pid: Option<u32>,
    #[arg(long)]
    a_file: Option<String>,
    /// Inline bytes source for the `a` side, e.g. "48 89 c8 c3".
    #[arg(long)]
    a_bytes: Option<String>,
    /// Function start address on the `a` (baseline) side.
    #[arg(long)]
    a_addr: String,
    #[arg(long)]
    b_pid: Option<u32>,
    #[arg(long)]
    b_file: Option<String>,
    /// Inline bytes source for the `b` side.
    #[arg(long)]
    b_bytes: Option<String>,
    /// Function start address on the `b` (comparison) side.
    #[arg(long)]
    b_addr: String,
    #[arg(long, default_value_t = 4096, value_parser = parse_hex_or_decimal_usize)]
    size: usize,
    /// `goto` (default: stable/deterministic, best for diffing), `structured`, or `ssa`.
    #[arg(long, value_enum, default_value_t = PseudoStyle::Goto)]
    style: PseudoStyle,
    /// Instruction set to decode: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
}

#[derive(Subcommand)]
enum DebugCmd {
    /// Arm a software breakpoint and block until it fires (or times out).
    AwaitHit(DebugAwaitHitArgs),
    /// Arm a hardware watchpoint (data read/write, or execute) and block
    /// until it fires (or times out) — no code byte is ever patched.
    Watch(DebugWatchArgs),
    /// Become the target's debugger and hold the attach without arming
    /// anything, then detach. Diagnostic: isolates whether a target's
    /// instability comes from `DebugActiveProcess` itself (an anti-debug
    /// check reacting to being debugged) versus a specific breakpoint or
    /// watchpoint.
    Attach(DebugAttachArgs),
}

#[derive(Subcommand)]
enum StackCmd {
    /// Snapshot a thread's registers and walk its call stack. Frame 0 is the
    /// current instruction; each caller is recovered through that module's
    /// unwind data (never a raw `[rsp]` guess). Reads registers via `ptrace`
    /// and stack/unwind bytes with `process_vm_readv`; `/proc/<pid>/maps` (and
    /// `/proc/<pid>/task` for `--all-threads`) supplies only the module map.
    /// The thread is held stopped just for the duration of the walk.
    Backtrace(StackBacktraceArgs),
}

#[derive(Args)]
struct StackBacktraceArgs {
    #[arg(long)]
    pid: u32,
    /// A single thread id to walk. Defaults to the main thread (tid == pid).
    #[arg(long)]
    tid: Option<u32>,
    /// Walk every thread in the process instead of just one.
    #[arg(long)]
    all_threads: bool,
    /// Maximum frames per thread.
    #[arg(long, default_value_t = 64)]
    max: usize,
}

#[derive(Args)]
struct DebugAttachArgs {
    #[arg(long)]
    pid: u32,
    #[arg(long, default_value_t = 10000)]
    timeout_ms: u64,
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
    /// Only report a hit whose registers match, e.g. `--when r9=4` (value may be
    /// decimal or `0x`-prefixed). Non-matching hits are resumed with the
    /// watchpoint still armed. Essential on a hot function, where the first hit
    /// is simply whichever call ran first and re-arming keeps returning it.
    #[arg(long)]
    when: Option<String>,
    /// Ignore writes from an instruction-pointer range `LO-HI` (hex, half-open
    /// `[LO, HI)`), repeatable. A field that a `memcpy`/serialization helper
    /// constantly rewrites keeps surfacing the copy site instead of the setter;
    /// exclude that range and the next distinct writer — the semantic setter —
    /// is what the watchpoint returns. RVA when `--addr-rva`, else absolute VA.
    #[arg(long = "exclude-rip", value_name = "LO-HI")]
    exclude_rip: Vec<String>,
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
    /// The value's address to explain (hex `0x…`). Absolute VA unless
    /// `--addr-rva`.
    #[arg(long)]
    addr: String,
    /// Interpret `--addr` as an RVA from the main module's base — the same
    /// flag `debug watch` takes, so an address recorded from one is usable in
    /// the other without a hand conversion.
    #[arg(long)]
    addr_rva: bool,
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
    /// Instruction set to decode: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
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
    /// Rename (or clear) one decompiled variable on the function at `--addr`.
    /// `--var` is the variable's current displayed name (`local_78`, `rcx`, `v3`).
    Var(AnnotateVarArgs),
    /// Set (or clear) the C type of one variable/param/return on the function at
    /// `--addr`. `--var` is the variable's displayed name, or `@return` for the
    /// return type; `--value` is a C-type string (e.g. `int`, `char *`, `Foo *`).
    Vartype(AnnotateVarArgs),
    /// Bookmark ("favorite") an address so it shows in the Bookmarks/Notes list.
    /// `--off` removes the bookmark.
    Bookmark(AnnotateBookmarkArgs),
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

#[derive(Args)]
struct AnnotateBookmarkArgs {
    #[arg(long)]
    addr: String,
    /// Remove the bookmark instead of setting it.
    #[arg(long)]
    off: bool,
}

#[derive(Args)]
struct AnnotateVarArgs {
    /// The function's start address (the address a decompile is addressed by).
    #[arg(long)]
    addr: String,
    /// The variable's current displayed name in the decompiler (`local_78`,
    /// `rcx`, `v3`).
    #[arg(long)]
    var: String,
    /// New name; omit to clear the rename (revert to the synthesized name).
    #[arg(long)]
    value: Option<String>,
    /// The image the function is in. With one (a `serve` session supplies its
    /// own), `--var` is checked against the function's variables: a name that
    /// is not one is refused, and a name the page shows is stored under its
    /// key. Without one nothing is checked, and the answer says so.
    #[arg(long)]
    file: Option<String>,
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    snapshot: Option<String>,
    #[arg(long)]
    remote_cmd: Option<String>,
    /// Instruction set to decode the function with: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
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
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
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
struct ServeArgs {
    /// Static PE/ELF to load once and keep resident for the session.
    #[arg(long)]
    file: String,
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
enum CapabilityCmd {
    /// List every registered capability with its origin and emitted schema —
    /// the catalog an agent should read instead of guessing.
    List,
    /// Run a capability by name with JSON arguments.
    Run(CapabilityRunArgs),
}

#[derive(Args)]
struct CapabilityRunArgs {
    /// Capability name, as reported by `capability list` (e.g. `decode`).
    name: String,
    /// Arguments as a JSON object, e.g. `{"file":"app.exe","addr":"0x140001000"}`.
    #[arg(long, default_value = "{}")]
    args: String,
}

#[derive(Subcommand)]
enum PluginCmd {
    /// Register (or overwrite, by name) a plugin: an executable spawned with
    /// an artifact as JSON on stdin, expected to reply with one JSON findings
    /// object on stdout.
    Add(PluginAddArgs),
    /// List registered plugins.
    List,
    /// Remove a plugin by name.
    Rm(PluginRmArgs),
}

#[derive(Args)]
struct PluginAddArgs {
    #[arg(long)]
    name: String,
    /// The argv to spawn, as one string (parsed the same way as
    /// `--remote-cmd`; `"..."` quotes a segment containing spaces).
    #[arg(long)]
    command: String,
    /// Artifact kind(s) this plugin wants to see: `cfg`, `pseudo`, `discover`
    /// (repeatable, e.g. `--handles cfg --handles pseudo`).
    ///
    /// **Declarative only.** It is recorded and shown in the plugin's entry in
    /// `capability list`, so a caller can see what the plugin expects — but
    /// nothing dispatches on it. A registered plugin runs when it is asked for
    /// by name (`capability run plugin.<name> --args '{"kind":…,"artifact":…}'`),
    /// never automatically because a pass happened to emit a matching artifact.
    #[arg(long = "handles", required = true)]
    handles: Vec<String>,
}

#[derive(Args)]
struct PluginRmArgs {
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
    //
    // The file to *store*, not a source: id `payload_file`. A `serve` session
    // adds its own `--file` to a request whose leaf defines the source id
    // `file`, and under that id this payload was one — so `dump save --content
    // hello` in a session stored the whole session image as the note, ok:true.
    // (`//`, not `///`: a doc comment here would join the help text above.)
    #[arg(long = "file", id = "payload_file", value_name = "FILE")]
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
    /// Read every readable stretch of a window, as runs: a gap (an unmapped
    /// address, a zero-fill tail) lies between two runs instead of ending the read.
    Span(MemSpanArgs),
    /// Write bytes to a live process (flips page protection as needed).
    Write(MemWriteArgs),
    /// Dump the address-space region map of a live process.
    Map(MemMapArgs),
}

#[derive(Args)]
struct MemReadArgs {
    #[arg(long)]
    addr: String,
    #[arg(long, default_value_t = 64, value_parser = parse_hex_or_decimal_usize)]
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
struct MemSpanArgs {
    #[arg(long)]
    addr: String,
    /// Bytes in the window; at most `MAX_SPAN` (65536).
    #[arg(long, default_value_t = n0xis_frontend::registry::DEFAULT_SPAN, value_parser = parse_hex_or_decimal_usize)]
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
    // A payload, not a source: id `payload`, for the reason given on
    // `FindArgs::bytes`. (`//`, not `///` — a doc comment here is help text.)
    #[arg(long = "bytes", id = "payload", value_name = "BYTES")]
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
    #[arg(long, default_value_t = 64, value_parser = parse_hex_or_decimal_usize)]
    cave_size: usize,
    /// Instruction set to decode: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
}

#[derive(Args)]
struct PatchWriteArgs {
    #[arg(long)]
    addr: String,
    // A payload, not a source: id `payload`, for the reason given on
    // `FindArgs::bytes`.
    #[arg(long = "bytes", id = "payload", value_name = "BYTES")]
    bytes: String,
    #[arg(long)]
    pid: u32,
}

/// The states a journaled patch can be in.
///
/// This was a free-text `Option<String>` compared case-insensitively against
/// the record's status, which meant every value that was not exactly `applied`
/// or `undone` filtered the list down to nothing and returned success. A live
/// sweep asked for `--status all` — the obvious spelling for "everything" —
/// and was told there were no patches while two were journaled. A filter that
/// answers "none" to a typo is worse than one that refuses it, so the values
/// are now clap's to police, and they appear in `--help`.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PatchStatusArg {
    /// Every journaled patch, whatever its state — the same as omitting the flag.
    All,
    /// Still in effect: the bytes are patched and an undo record exists.
    Applied,
    /// Already reverted; kept for the audit trail.
    Undone,
}

impl PatchStatusArg {
    fn matches(self, status: &str) -> bool {
        match self {
            PatchStatusArg::All => true,
            PatchStatusArg::Applied => status.eq_ignore_ascii_case("applied"),
            PatchStatusArg::Undone => status.eq_ignore_ascii_case("undone"),
        }
    }
}

#[derive(Args)]
struct PatchListArgs {
    /// Keep only patches in this state. Omit for all of them.
    #[arg(long, value_enum)]
    status: Option<PatchStatusArg>,
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
    /// Whole-program noreturn analysis: discover functions, then run the
    /// call-graph fixpoint that proves which never return — including a program's
    /// own `FatalError`/`Assert` wrappers, not just named imports.
    Noreturn(FunctionNoreturnArgs),
    /// Per-function interprocedural summary — the substrate the whole-program
    /// passes read instead of re-analyzing a callee once per question: does it
    /// return, what types are its parameters and result, which volatile
    /// registers does it clobber (and is that set complete), whom does it call.
    Summary(FunctionSummaryArgs),
    /// Whole-program type propagation: flow recovered types along the call graph
    /// to a fixpoint, so a class recovered in one function (from RTTI, or from
    /// concrete field accesses) reaches every function that touches the same
    /// object — a persistent, call-graph-wide type database.
    Typeflow(FunctionTypeflowArgs),
    /// Program-wide class layouts: unify per-function field recovery into ONE
    /// field set per RTTI class. Each method sees its own slice of the object
    /// and names it after a register (`struct_rdi_0`), so nothing it learns
    /// survives leaving the function; keyed on the class instead, every method's
    /// observations merge, and a field is typed from what is stored into it.
    Layout(FunctionLayoutArgs),
    /// Exception edges: the protected ranges and landing pads an unwinder uses.
    /// A `try`/`catch` landing pad has NO incoming branch, so it is invisible to
    /// a CFG built from instructions alone — this is where that control flow is
    /// actually written down. ELF (`.eh_frame` + `.gcc_except_table`) today.
    Eh(FunctionEhArgs),
}

#[derive(Args)]
struct FunctionSummaryArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Instruction set to decode: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
    /// Reload a captured `snapshot dump` by name.
    #[arg(long)]
    snapshot: Option<String>,
    /// Attach over a remote transport.
    #[arg(long)]
    remote_cmd: Option<String>,
    /// Summarize just the function at this address (hex `0x…`). Without it the
    /// whole discovered set, capped by `--limit`.
    #[arg(long)]
    addr: Option<String>,
    /// Restrict discovery to this module, by case-insensitive name substring.
    #[arg(long)]
    module: Option<String>,
    /// Cap on functions summarized; `0` = every discovered function.
    #[arg(long, default_value_t = 200)]
    limit: usize,
    /// Byte window analyzed per function.
    #[arg(long, default_value_t = 4096, value_parser = parse_hex_or_decimal_usize)]
    max_bytes: usize,
}

#[derive(Args)]
struct FunctionTypeflowArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Instruction set to decode: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
    #[arg(long)]
    snapshot: Option<String>,
    #[arg(long)]
    remote_cmd: Option<String>,
    /// Restrict discovery to this module, by case-insensitive name substring.
    #[arg(long)]
    module: Option<String>,
    /// Cap on functions in the program considered; `0` = every function.
    #[arg(long, default_value_t = 400)]
    limit: usize,
    /// Byte window analyzed per function.
    #[arg(long, default_value_t = 4096, value_parser = parse_hex_or_decimal_usize)]
    max_bytes: usize,
}

#[derive(Args)]
struct FunctionLayoutArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Instruction set to decode: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
    #[arg(long)]
    snapshot: Option<String>,
    #[arg(long)]
    remote_cmd: Option<String>,
    /// Restrict discovery to this module, by case-insensitive name substring.
    #[arg(long)]
    module: Option<String>,
    /// Report only this class.
    #[arg(long)]
    class: Option<String>,
    /// Report what the single function at this address (hex `0x…`) contributes,
    /// instead of the whole program — the audit answer to "which method put that
    /// field there?".
    #[arg(long)]
    addr: Option<String>,
    /// Cap on functions in the program considered; `0` = every function.
    #[arg(long, default_value_t = 400)]
    limit: usize,
    /// Byte window analyzed per function.
    #[arg(long, default_value_t = 4096, value_parser = parse_hex_or_decimal_usize)]
    max_bytes: usize,
}

#[derive(Args)]
struct FunctionEhArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Reload a captured `snapshot dump` by name.
    #[arg(long)]
    snapshot: Option<String>,
    /// Attach over a remote transport.
    #[arg(long)]
    remote_cmd: Option<String>,
    /// Narrow to the function containing this address (hex `0x…`). Without it
    /// the whole image's exception map is returned.
    #[arg(long)]
    addr: Option<String>,
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
    #[arg(long, default_value_t = 4096, value_parser = parse_hex_or_decimal_usize)]
    max_bytes: usize,
    /// Instruction set to decode: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
}

#[derive(Args)]
struct ProfileArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Instruction set used to decode export stubs: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
    /// Which loaded module to profile (case-insensitive substring). Defaults
    /// to the main module — worth overriding on any target whose real code is
    /// in a DLL: an IL2CPP host EXE profiles as 2 exports and 319 functions
    /// while `--module GameAssembly.dll` is where the other 277 199 live.
    #[arg(long)]
    module: Option<String>,
    /// Include the full export table (name → address → branch target). Off by
    /// default: a runtime DLL can export hundreds of names, and the summary
    /// counts are what you usually need.
    #[arg(long)]
    exports: bool,
}

#[derive(Args)]
struct FunctionNoreturnArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Instruction set to decode: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
    /// Inline bytes source; requires `--start` for the base address.
    #[arg(long)]
    bytes: Option<String>,
    /// Reload a captured `snapshot dump` by name.
    #[arg(long)]
    snapshot: Option<String>,
    /// Attach over a remote transport, e.g. `"ssh host n0xis remote-serve --pid 1234"`.
    #[arg(long)]
    remote_cmd: Option<String>,
    /// Analysis range start (defaults to the module's `.text`).
    #[arg(long)]
    start: Option<String>,
    /// Analysis range size in bytes (defaults to the `.text` size).
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    size: Option<usize>,
    /// Cap on functions the fixpoint considers; `0` = every function, which is
    /// the default. This is a *whole-program* analysis and a cap makes it a
    /// partial one — a caller whose callee falls outside the window keeps its
    /// dead fall-through silently. On a 15 470-function image the complete run
    /// takes about four times as long as a 4 096-function one; pass a cap when
    /// that trade is wanted, and read `truncated` in the result either way.
    #[arg(long, default_value_t = 0)]
    limit: usize,
    /// Byte window decoded per function during the fixpoint (default 0x4000).
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    max_bytes: Option<usize>,
}

#[derive(Args)]
struct DiscoverArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Instruction set to decode: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
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
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    size: Option<usize>,
    /// Cap on the number of candidates returned; `0` = unlimited (default).
    /// Applies to **both** discovery modes — a large image's `.pdata` table
    /// holds hundreds of thousands of entries, so cap it unless you are
    /// redirecting the output to a file.
    #[arg(long, default_value_t = 0)]
    limit: usize,
    /// Skip this many candidates before collecting — page through a range with
    /// `--limit`. Counted from the start of the range/table, so a given page is
    /// the same set of addresses however you got there.
    #[arg(long, default_value_t = 0)]
    offset: usize,
    /// Discover from the PE `.pdata` exception table instead of prologue
    /// scanning: every function (with unwind info) with exact start+end, no
    /// heuristic. x64 PE images only (`--pid`/`--file`). Honours
    /// `--limit`/`--offset`; `meta.total` reports the true table size.
    #[arg(long)]
    pdata: bool,
    /// FLIRT-class signature database(s) (`.npat`) to name statically-linked
    /// library functions (`memcpy`, `crc32`, …) that carry no symbol. Repeatable:
    /// the corpora merge into one lookup, and two that disagree about the same
    /// bytes leave the function anonymous rather than guessing. Chained below the
    /// real symbols, so a genuine name always wins. For a durable, project-wide
    /// result use `analyze --flirt`, which persists the matches instead.
    #[arg(long = "flirt")]
    flirt: Vec<String>,
}

#[derive(Args)]
struct AnalyzeArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    /// Instruction set to decode: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
    #[arg(long)]
    snapshot: Option<String>,
    #[arg(long)]
    remote_cmd: Option<String>,
    /// Cap the IR-cache warm-up to this many functions (`0` = every function).
    /// Discovery, RTTI and the xref index always cover the whole image; this
    /// only bounds how many functions get their CFG pre-decoded and cached.
    #[arg(long, default_value_t = 0)]
    limit: usize,
    /// Skip the IR-cache warm-up phase entirely — only discover, recover RTTI
    /// names, and build the xref index (much faster; decompilation still caches
    /// lazily on first view).
    #[arg(long)]
    no_cfg: bool,
    /// FLIRT-class signature database(s) (`.npat`) to name statically-linked
    /// library functions with. Repeatable — the corpora are merged into one
    /// lookup, and two that disagree about the same bytes leave the function
    /// anonymous rather than guessing. The matches are **persisted** into
    /// `.n0x/flirt-symbols.json`, so afterwards the function list, xref, the
    /// decompiler and the GUI all render them with no flag of their own.
    #[arg(long = "flirt")]
    flirt: Vec<String>,
    /// Also run whole-program type propagation and persist it into
    /// `.n0x/type-flow.json`, so the decompiler renders a class recovered in one
    /// function wherever the same object is used. The most expensive phase (it
    /// analyzes every function once), so it is opt-in.
    #[arg(long)]
    typeflow: bool,
    /// Also unify class field layouts across every method and persist them into
    /// `.n0x/class-layout.json`, so a field typed by the constructor that fills
    /// it is typed in every method that reads it — which is what lets a dispatch
    /// through `this->impl` resolve. Implies `--typeflow`, whose propagated
    /// return types are one of the two sources a field type comes from.
    #[arg(long)]
    layout: bool,
}

#[derive(Args)]
struct StringsArgs {
    /// Fewest characters a string has.
    #[arg(long, default_value_t = n0xis_frontend::strings_caps::DEFAULT_MIN_CHARS)]
    min: usize,
    /// Which encodings to read.
    #[arg(long, default_value = "both", value_parser = ["both", "utf8", "utf16le"])]
    encoding: String,
    /// Read only this section.
    #[arg(long)]
    section: Option<String>,
    /// Read the sections that hold code too.
    #[arg(long)]
    all_sections: bool,
    /// Keep only the strings that contain this text, in any case.
    #[arg(long)]
    contains: Option<String>,
    /// How many strings to return; 0 for all.
    #[arg(long, default_value_t = n0xis_frontend::strings_caps::DEFAULT_STRINGS_LIMIT)]
    limit: usize,
    #[arg(long, default_value_t = 0)]
    offset: usize,
    /// Read this range instead of sections (with `--size`).
    #[arg(long)]
    start: Option<String>,
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    size: Option<usize>,
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
struct FindArgs {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    #[arg(long)]
    snapshot: Option<String>,
    #[arg(long)]
    remote_cmd: Option<String>,
    /// Instruction set (only affects the `Ctx`; the scan itself is arch-neutral).
    #[arg(long)]
    arch: Option<String>,
    /// Byte pattern with `?`/`??` wildcards: `"48 8B ?? C3"`.
    //
    // Spelled `--bytes` like the inline-bytes *source* other commands take,
    // but here it is the thing searched for, not the thing searched — so its
    // id is `pattern`. A `serve` session decides whether a request names its
    // own source by argument id (`SERVE_SOURCE_IDS`); under the shared id this
    // pattern counted as one, the session image was withheld, and `find`
    // searched whatever the project default named instead. (`//`, not `///`:
    // a doc comment on a clap field is its help text.)
    #[arg(long = "bytes", id = "pattern", value_name = "BYTES")]
    bytes: Option<String>,
    /// A literal string to find (UTF-8 by default; pass `--utf16` for wide).
    #[arg(long)]
    string: Option<String>,
    /// An escaped string: `\xNN` hex, plus `\n \t \r \0 \\ \"`.
    #[arg(long)]
    escaped: Option<String>,
    /// Interpret `--string` as UTF-16LE (wide) instead of UTF-8.
    #[arg(long)]
    utf16: bool,
    /// Restrict the search to one named section (e.g. `.rdata`). Default: every
    /// file-backed section of the image.
    #[arg(long)]
    section: Option<String>,
    /// Explicit start VA (with `--size`) instead of scanning sections.
    #[arg(long)]
    start: Option<String>,
    /// Byte count to scan from `--start`.
    #[arg(long)]
    size: Option<usize>,
    /// Report only matches whose address is a multiple of this (default 1).
    #[arg(long, default_value_t = 1)]
    align: usize,
    /// Cap the matches returned (0 = no cap).
    #[arg(long, default_value_t = 1000)]
    limit: usize,
}

#[derive(Subcommand)]
enum TypeCmd {
    /// Define (or replace) a struct. Repeat `--field "OFFSET:NAME[:CTYPE]"`
    /// (offset hex `0x68` or decimal). e.g. `--field 0x0:vftable:void* --field 0x68:count:int`.
    Struct(TypeStructArgs),
    /// Define (or replace) an enum. Repeat `--member "NAME=VALUE"`.
    Enum(TypeEnumArgs),
    /// List every defined struct and enum.
    List,
    /// Remove a struct or enum by name.
    Rm(TypeRmArgs),
}

#[derive(Args)]
struct TypeStructArgs {
    #[arg(long)]
    name: String,
    #[arg(long = "field")]
    fields: Vec<String>,
    /// Optional total size (hex or decimal).
    #[arg(long)]
    size: Option<String>,
}

#[derive(Args)]
struct TypeEnumArgs {
    #[arg(long)]
    name: String,
    #[arg(long = "member")]
    members: Vec<String>,
}

#[derive(Args)]
struct TypeRmArgs {
    #[arg(long)]
    name: String,
}

#[derive(Subcommand)]
enum RttiCmd {
    /// Scan `.rdata` for MSVC RTTI vtables and recover each one's class name.
    Scan(RttiScanArgs),
}

#[derive(Args)]
struct RttiScanArgs {
    /// Restrict to this module by case-insensitive name substring.
    #[arg(long)]
    module: Option<String>,
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    file: Option<String>,
    #[arg(long)]
    bytes: Option<String>,
    /// Reload a captured `snapshot dump` by name.
    #[arg(long)]
    snapshot: Option<String>,
    /// Attach over a remote transport.
    #[arg(long)]
    remote_cmd: Option<String>,
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
    /// Restrict the scan to this module, by case-insensitive name substring
    /// (e.g. `GameAssembly.dll`). Live IL2CPP targets need it: the main module is
    /// a thin host executable and the code lives in a DLL.
    #[arg(long)]
    module: Option<String>,

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
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    data_size: Option<usize>,
    /// Code window to scan for referencing `lea` (defaults to `.text`).
    #[arg(long)]
    start: Option<String>,
    /// Code window size (defaults to the `.text` size).
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    size: Option<usize>,
    #[arg(long, default_value_t = 50)]
    limit: usize,
    /// Instruction set to decode: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
}

#[derive(Args)]
struct XrefArgs {
    /// Restrict the scan to this module, by case-insensitive name substring
    /// (e.g. `GameAssembly.dll`). Live IL2CPP targets need it: the main module is
    /// a thin host executable and the code lives in a DLL.
    #[arg(long)]
    module: Option<String>,

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
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    size: Option<usize>,
    /// Instruction set to decode: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
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
    /// Light value-set / alias analysis over SSA (Phase 7): the bounded set
    /// of possible values each SSA variable can hold.
    ValueSet(IrArgs),
    /// Pattern-based deobfuscation report (Phase 7): junk instructions and
    /// value-set-provable opaque predicates.
    Deobfuscate(IrArgs),
}

#[derive(Args)]
struct ManifestArgs {
    /// Restrict the scan to this module, by case-insensitive name substring
    /// (e.g. `GameAssembly.dll`). Live IL2CPP targets need it: the main module is
    /// a thin host executable and the code lives in a DLL.
    #[arg(long)]
    module: Option<String>,

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
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    size: Option<usize>,
    /// Cap on discovered candidates to summarize.
    #[arg(long, default_value_t = 200)]
    limit: usize,
    /// Byte window handed to `ir build` per candidate.
    #[arg(long, default_value_t = 4096, value_parser = parse_hex_or_decimal_usize)]
    max_bytes: usize,
    /// Instruction set to decode: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
    /// FLIRT-class signature database(s) (`.npat`) to name statically-linked
    /// library functions (`memcpy`, `crc32`, …) that carry no symbol. Repeatable:
    /// the corpora merge into one lookup, and two that disagree about the same
    /// bytes leave the function anonymous rather than guessing. Chained below the
    /// real symbols, so a genuine name always wins. For a durable, project-wide
    /// result use `analyze --flirt`, which persists the matches instead.
    #[arg(long = "flirt")]
    flirt: Vec<String>,
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
    /// `ssa` (structured *and* optimized — the default).
    #[arg(long, value_enum, default_value_t = PseudoStyle::Ssa)]
    style: PseudoStyle,
    /// Also return the per-round optimization delta (`--style ssa` only):
    /// what each pass changed and why. Off by default because on a real
    /// function it measured **larger than the pseudocode itself** (59 KB of
    /// delta vs 42 KB of pseudo-C — 59% of the payload). Ask for it when you
    /// are auditing the decompiler; `ir explain` is the dedicated command.
    #[arg(long)]
    explain: bool,
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
    /// Group scan: find a struct by several interrelated values at once — where
    /// they co-occur within a byte window (no known layout needed). One `--field
    /// TYPE=VALUE` per value; the search anchors on the rarest.
    Group(ScanGroupArgs),
}

#[derive(Args)]
struct ScanGroupArgs {
    #[command(flatten)]
    region: ScanRegionArgs,
    /// A required field, `TYPE=VALUE` (e.g. `i32=3`). Repeat for each value —
    /// the search finds where they all co-occur; order and offsets are unknown.
    #[arg(long = "field", value_name = "TYPE=VALUE", required = true)]
    field: Vec<String>,
    /// Max byte span between the fields of one hit (the struct window).
    #[arg(long, default_value_t = 256)]
    window: usize,
    /// Candidate stride; defaults to the smallest field's size. `1` catches
    /// unaligned fields at the cost of speed.
    #[arg(long)]
    align: Option<usize>,
    /// Cap on hits returned (the true total is still reported).
    #[arg(long, default_value_t = 100)]
    limit: usize,
}

#[derive(Subcommand)]
enum AotCmd {
    /// List/resolve managed method names from NativeAOT stack-trace metadata.
    Symbols(AotSymbolsArgs),
}

#[derive(Args)]
struct AotSymbolsArgs {
    /// Static PE image to parse.
    #[arg(long)]
    file: Option<String>,
    /// Live process to parse (the first module with a ReadyToRunHeader, or the
    /// one named by `--module`).
    #[arg(long)]
    pid: Option<u32>,
    /// On `--pid`, restrict to a module whose name contains this substring.
    #[arg(long)]
    module: Option<String>,
    /// Case-insensitive substring filter over the fully-qualified name.
    #[arg(long)]
    name: Option<String>,
    /// Resolve one exact method-start RVA (hex, e.g. `0x169c4c0`).
    #[arg(long)]
    rva: Option<String>,
    /// Cap on names listed; `method_count` still reports the full total.
    #[arg(long, default_value_t = 200)]
    limit: usize,
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
    /// writable region, which is the default scan set; required for `--file`.
    #[arg(long)]
    start: Option<String>,
    /// Region size in bytes (paired with `--start`).
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
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
    #[arg(long, value_parser = parse_hex_or_decimal_f64)]
    value: Option<f64>,
    #[arg(long, value_parser = parse_hex_or_decimal_f64)]
    min: Option<f64>,
    #[arg(long, value_parser = parse_hex_or_decimal_f64)]
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
    #[arg(long, value_parser = parse_hex_or_decimal_f64)]
    value: Option<f64>,
    #[arg(long, value_parser = parse_hex_or_decimal_f64)]
    min: Option<f64>,
    #[arg(long, value_parser = parse_hex_or_decimal_f64)]
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
    /// Region start (hex). Defaults, on `--pid`, to every committed writable
    /// region (the same default `scan value` uses); required for `--file`.
    #[arg(long)]
    start: Option<String>,
    /// Region size in bytes (paired with `--start`).
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    size: Option<usize>,
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
    #[arg(long, default_value_t = 64, value_parser = parse_hex_or_decimal_usize)]
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
    #[arg(long, default_value_t = 0x1000, value_parser = parse_hex_or_decimal_u64)]
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
    /// Repeatedly write an entry's pinned value for a bounded duration.
    // `freeze` is a hidden alias: the command was first published as
    // `table freeze`, and that spelling must keep parsing to exactly this
    // command. Read from `TABLE_PIN`, which also keeps the old spelling's
    // schema id. A plain comment, not a doc comment: clap would print it.
    #[command(alias = TABLE_PIN.first[1])]
    Pin(TablePinArgs),
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
struct TablePinArgs {
    #[arg(long)]
    table: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    pid: u32,
    /// Value to (re-)write every interval — defaults to the entry's stored
    /// `freeze_value`.
    #[arg(long, value_parser = parse_hex_or_decimal_f64)]
    value: Option<f64>,
    #[arg(long, default_value_t = 100)]
    interval_ms: u64,
    #[arg(long, default_value_t = 5000)]
    duration_ms: u64,
}

#[derive(Args)]
struct IrArgs {
    /// Function start address (hex `0x…`, `…h`, or decimal). Absolute VA
    /// unless `--addr-rva`.
    #[arg(long)]
    addr: String,
    /// Interpret `--addr` as an RVA from the target module's base. An RVA is
    /// the only address form that survives a restart (live VAs move with
    /// ASLR), so it is what you should be recording and passing back in.
    #[arg(long)]
    addr_rva: bool,
    /// Which module `--addr-rva` is relative to (case-insensitive substring).
    /// Defaults to the main module — which is the *wrong* one whenever the
    /// code you care about lives in a DLL, as it does in every IL2CPP
    /// build (`--addr-module GameAssembly.dll`).
    #[arg(long)]
    addr_module: Option<String>,
    /// Instruction set to decode: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
    /// Byte window to analyze (the function's max extent).
    #[arg(long, default_value_t = 4096, value_parser = parse_hex_or_decimal_usize)]
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
    /// FLIRT-class signature database(s) (`.npat`) to name statically-linked
    /// library functions (`free`, `memcpy`, …) that carry no symbol. Repeatable:
    /// the corpora merge into one lookup, and two that disagree about the same
    /// bytes leave the function anonymous rather than guessing. Chained below the
    /// real symbols, so a genuine name always wins. For a durable, project-wide
    /// result use `analyze --flirt`, which persists the matches instead.
    #[arg(long = "flirt")]
    flirt: Vec<String>,
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
    /// How much disk the project's caches use, per kind; `--clear` removes them.
    /// Only what the engine can rebuild from the image is a cache: names,
    /// comments, types, patches and tables are never touched.
    Cache(ProjectCacheArgs),
}

#[derive(Subcommand)]
enum SymbolsCmd {
    /// Keep a PDB in the project's symbol store, after checking that it belongs
    /// to the image: its GUID and age must equal the image's CodeView record.
    /// A PDB beside the image is found without this; the store is for one kept
    /// anywhere else.
    Add(SymbolsAddArgs),
}

#[derive(Args)]
struct SymbolsAddArgs {
    /// The image the PDB belongs to.
    #[arg(long)]
    file: String,
    /// The PDB to keep.
    #[arg(long)]
    pdb: String,
}

#[derive(Args)]
struct ProjectCacheArgs {
    /// Remove every cache entry, then report what was freed.
    #[arg(long)]
    clear: bool,
}

#[derive(Args)]
struct DisasmArgs {
    /// Start address (hex `0x…`, `…h`, or decimal).
    #[arg(long)]
    addr: String,
    /// Number of instructions to decode.
    #[arg(long, default_value_t = n0xis_frontend::registry::DEFAULT_DECODE_COUNT)]
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
    /// Instruction set to decode: `x64` (default) or `arm64`.
    #[arg(long)]
    arch: Option<String>,
}

fn main() {
    // Parsed by hand rather than `Cli::parse()` so that an argument error is
    // still an **envelope**. clap's own exit prints a plain-text usage message
    // to stderr and nothing at all to stdout, which is a second failure format
    // for every consumer to handle — and the contract this tool sells is that
    // there is exactly one. `--help`/`--version` keep clap's rendering: they
    // are not failures, and a caller asking for help wants the text.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) if matches!(e.kind(), clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion) => {
            e.print().ok();
            return;
        }
        Err(e) => {
            let pretty = std::env::args().any(|a| a == "--pretty");
            let message = e.render().to_string().trim_end().replace('\n', " ").split_whitespace().collect::<Vec<_>>().join(" ");
            emit(&Response::<serde_json::Value>::error("bad-arguments", message).with_hint("run the command with --help for its usage line"), pretty);
            std::process::exit(2);
        }
    };
    let pretty = cli.global.pretty;
    // remote-serve is a persistent stdio server, not a single ok/data/meta
    // call — handled before the response-envelope dispatch below.
    if let Command::RemoteServe(a) = &cli.command {
        cmd_remote_serve(a);
        return;
    }
    if let Command::Serve(a) = &cli.command {
        cmd_serve(a);
        return;
    }
    // Lossy, because only subcommand names are read from it, and those are
    // ASCII: `std::env::args()` would panic on a non-UTF-8 path argument that
    // clap itself accepted above.
    let argv: Vec<String> = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect();
    let typed = typed_path(&<Cli as clap::CommandFactory>::command(), &argv);
    let ok = dispatch(cli.command, &typed, pretty, cli.global.quiet);
    // Non-zero exit when the response is a failure, so scripts can branch on it.
    if !ok {
        std::process::exit(2);
    }
}

/// A leaf command that shipped under one path and was renamed later.
///
/// Two promises ride on the first name, and both are read from this one record
/// so they cannot drift apart: the first spelling still *parses* — the hidden
/// clap alias on the renamed level is spelled from [`Renamed::first`] — and a
/// call spelled that way still answers with the schema id the first release
/// emitted, so a consumer dispatching on `meta.schema` keeps working ("bridge,
/// never break"). The current spelling answers with the current id.
struct Renamed {
    /// The path the catalog lists, e.g. `["concept", "grep"]`.
    // Read only through `path`, which only the off-Windows refusal of
    // `table pin` uses; on Windows that command runs and its answer names
    // itself by schema id instead.
    #[cfg_attr(windows, allow(dead_code))]
    current: &'static [&'static str],
    /// The path the command was first published under, e.g. `["game", "grep"]`.
    first: &'static [&'static str],
    current_schema: &'static str,
    first_schema: &'static str,
}

/// Which of its two names a renamed command was called by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Spelled {
    Current,
    First,
}

impl Renamed {
    /// Which spelling `typed` (from [`typed_path`]) is. Only an exact match of
    /// the first path is the first spelling: the dispatch arm that asks has
    /// already matched this command, so anything else is the current name.
    fn spelled(&self, typed: &[String]) -> Spelled {
        if typed.iter().map(String::as_str).eq(self.first.iter().copied()) { Spelled::First } else { Spelled::Current }
    }

    fn schema(&self, s: Spelled) -> &'static str {
        match s {
            Spelled::Current => self.current_schema,
            Spelled::First => self.first_schema,
        }
    }

    /// The command path in the spelling the caller used, for messages that
    /// name the command back to them.
    #[cfg_attr(windows, allow(dead_code))]
    fn path(&self, s: Spelled) -> String {
        match s {
            Spelled::Current => self.current.join(" "),
            Spelled::First => self.first.join(" "),
        }
    }
}

/// `concept grep`, first published as `game grep`.
const CONCEPT_GREP: Renamed = Renamed {
    current: &["concept", "grep"],
    first: &["game", "grep"],
    current_schema: schema::v1::CONCEPT_GREP,
    first_schema: schema::v1::GAME_GREP,
};

/// `table pin`, first published as `table freeze`.
const TABLE_PIN: Renamed = Renamed {
    current: &["table", "pin"],
    first: &["table", "freeze"],
    current_schema: schema::v1::PIN,
    first_schema: schema::v1::FREEZE,
};

/// The subcommand path exactly as the caller typed it, alias spellings kept.
///
/// clap resolves an alias to its canonical subcommand and reports only that —
/// `game grep` parses to the very `Command` that `concept grep` does, which is
/// the point of the alias, and leaves no trace of which name was used. So the
/// spelling is read from the tokens: walk the clap tree from the root, and let
/// each word that names a subcommand of the current level (by name or by
/// alias) descend, stopping at the leaf. Words starting with `-` are skipped
/// as value-less flags; that holds because no command above a leaf takes an
/// option with a value (`typed_path_premise_tests` fails if one ever does —
/// its value would be read here as a subcommand name).
///
/// `argv` includes the program name, as `std::env::args` and the `serve`
/// request line do.
fn typed_path(root: &clap::Command, argv: &[String]) -> Vec<String> {
    let mut cur = root;
    let mut path = Vec::new();
    for tok in argv.iter().skip(1) {
        if tok == "--" {
            break;
        }
        if tok.starts_with('-') {
            continue;
        }
        match cur.get_subcommands().find(|c| c.get_name() == tok || c.get_all_aliases().any(|a| a == tok)) {
            Some(next) => {
                path.push(tok.clone());
                cur = next;
            }
            None => break,
        }
    }
    path
}

/// Dispatch one parsed command to its handler, returning whether it succeeded.
/// Factored out of `main` so the persistent `serve` loop can re-run commands
/// against an already-loaded image (see `cmd_serve`). `typed` is the command
/// path as the caller spelled it ([`typed_path`]) — the parsed `command` cannot
/// say which name a renamed command was called by, and the answer differs.
fn dispatch(command: Command, typed: &[String], pretty: bool, quiet: bool) -> bool {
    match command {
        Command::Analyze(a) => cmd_analyze(a, pretty, quiet),
        Command::Find(a) => cmd_find(a, pretty),
        Command::Strings(a) => cmd_strings(a, pretty),
        Command::Type(TypeCmd::Struct(a)) => cmd_type_struct(a, pretty),
        Command::Type(TypeCmd::Enum(a)) => cmd_type_enum(a, pretty),
        Command::Type(TypeCmd::List) => run_capability("type.list", json!({}), pretty),
        Command::Type(TypeCmd::Rm(a)) => run_capability("type.rm", json!({ "name": a.name }), pretty),
        Command::Doctor => cmd_doctor(pretty),
        Command::Profile(a) => cmd_profile(a, pretty),
        Command::Guide(a) => cmd_guide(a, pretty),
        Command::Init(a) => cmd_init(a, pretty),
        Command::Project(ProjectCmd::Info) => cmd_project_info(pretty),
        Command::Project(ProjectCmd::Cache(a)) => cmd_project_cache(a, pretty),
        Command::Symbols(SymbolsCmd::Add(a)) => cmd_symbols_add(a, pretty),
        Command::Process(ProcessCmd::Ps(a)) => cmd_process_ps(a, pretty),
        Command::Module(ModuleCmd::List(a)) => cmd_module_list(a, pretty),
        Command::Disasm(a) => cmd_disasm(a, pretty),
        Command::Ir(IrCmd::Build(a)) => cmd_ir(a, IrView::Cfg, pretty),
        Command::Ir(IrCmd::Explain(a)) => cmd_ir(a, IrView::Explain, pretty),
        Command::Ir(IrCmd::Dot(a)) => cmd_ir(a, IrView::Dot, pretty),
        Command::Ir(IrCmd::Slice(a)) => cmd_ir_slice(a, pretty),
        Command::Ir(IrCmd::Manifest(a)) => cmd_ir_manifest(a, pretty),
        Command::Ir(IrCmd::ValueSet(a)) => cmd_ir_value_set(a, pretty),
        Command::Ir(IrCmd::Deobfuscate(a)) => cmd_ir_deobfuscate(a, pretty),
        Command::Function(FunctionCmd::Discover(a)) => cmd_discover(a, pretty),
        Command::Function(FunctionCmd::Trace(a)) => cmd_function_trace(a, pretty),
        Command::Function(FunctionCmd::Noreturn(a)) => cmd_function_noreturn(a, pretty),
        Command::Function(FunctionCmd::Summary(a)) => run_capability(
            "function.summary",
            json!({
                "pid": a.pid, "file": a.file, "arch": a.arch, "snapshot": a.snapshot,
                "remote_cmd": a.remote_cmd, "addr": a.addr, "module": a.module,
                "limit": a.limit, "max_bytes": a.max_bytes,
            }),
            pretty,
        ),
        Command::Function(FunctionCmd::Typeflow(a)) => run_capability(
            "function.typeflow",
            json!({
                "pid": a.pid, "file": a.file, "arch": a.arch, "snapshot": a.snapshot,
                "remote_cmd": a.remote_cmd, "module": a.module, "limit": a.limit,
                "max_bytes": a.max_bytes,
            }),
            pretty,
        ),
        Command::Function(FunctionCmd::Layout(a)) => run_capability(
            "function.layout",
            json!({
                "pid": a.pid, "file": a.file, "arch": a.arch, "snapshot": a.snapshot,
                "remote_cmd": a.remote_cmd, "module": a.module, "class": a.class,
                "addr": a.addr, "limit": a.limit, "max_bytes": a.max_bytes,
            }),
            pretty,
        ),
        Command::Function(FunctionCmd::Eh(a)) => run_capability(
            "function.eh",
            json!({ "pid": a.pid, "file": a.file, "snapshot": a.snapshot, "remote_cmd": a.remote_cmd, "addr": a.addr }),
            pretty,
        ),
        Command::Decomp(DecompCmd::Pseudo(a)) => cmd_decomp(a, pretty),
        Command::Xref(XrefCmd::To(a)) => cmd_xref(a, XrefDir::To, pretty),
        Command::Xref(XrefCmd::From(a)) => cmd_xref(a, XrefDir::From, pretty),
        Command::Xref(XrefCmd::String(a)) => cmd_xref_string(a, pretty),
        Command::Rtti(RttiCmd::Scan(a)) => cmd_rtti_scan(a, pretty),
        Command::Mem(MemCmd::Read(a)) => cmd_mem_read(a, pretty),
        Command::Mem(MemCmd::Span(a)) => cmd_mem_span(a, pretty),
        Command::Mem(MemCmd::Write(a)) => cmd_mem_write(a, pretty),
        Command::Mem(MemCmd::Map(a)) => cmd_mem_map(a, pretty),
        Command::Patch(c) => cmd_patch(c, pretty),
        Command::Selection(c) => cmd_selection(c, pretty),
        Command::Plugin(c) => cmd_plugin(c, pretty),
        Command::Capability(c) => cmd_capability(c, pretty),
        Command::Dump(c) => cmd_dump(c, pretty),
        Command::Debug(DebugCmd::AwaitHit(a)) => cmd_debug_await_hit(a, pretty),
        Command::Debug(DebugCmd::Watch(a)) => cmd_debug_watch(a, pretty),
        Command::Debug(DebugCmd::Attach(a)) => cmd_debug_attach(a, pretty),
        Command::Stack(StackCmd::Backtrace(a)) => cmd_stack_backtrace(a, pretty),
        Command::Scan(ScanCmd::Value(a)) => cmd_scan_value(a, pretty),
        Command::Scan(ScanCmd::Filter(a)) => cmd_scan_filter(a, pretty),
        Command::Scan(ScanCmd::Aob(a)) => cmd_scan_aob(a, pretty),
        Command::Scan(ScanCmd::PointerPath(a)) => cmd_pointer_path(a, pretty),
        Command::Scan(ScanCmd::Dissect(a)) => cmd_scan_dissect(a, pretty),
        Command::Scan(ScanCmd::Group(a)) => cmd_scan_group(a, pretty),
        Command::Aot(AotCmd::Symbols(a)) => cmd_aot_symbols(a, pretty),
        Command::Table(TableCmd::Add(a)) => cmd_table_add(a, pretty),
        Command::Table(TableCmd::List(a)) => cmd_table_list(a, pretty),
        Command::Table(TableCmd::Show(a)) => cmd_table_show(a, pretty),
        Command::Table(TableCmd::Rm(a)) => cmd_table_rm(a, pretty),
        Command::Table(TableCmd::Pin(a)) => cmd_table_pin(a, TABLE_PIN.spelled(typed), pretty),
        Command::Provenance(ProvenanceCmd::Trace(a)) => cmd_provenance_trace(a, pretty),
        Command::Annotate(AnnotateCmd::Name(a)) => cmd_annotate_set("name", a, pretty),
        Command::Annotate(AnnotateCmd::Type(a)) => cmd_annotate_set("type", a, pretty),
        Command::Annotate(AnnotateCmd::Comment(a)) => cmd_annotate_set("comment", a, pretty),
        Command::Annotate(AnnotateCmd::Var(a)) => cmd_annotate_var(a, pretty),
        Command::Annotate(AnnotateCmd::Vartype(a)) => cmd_annotate_vartype(a, pretty),
        Command::Annotate(AnnotateCmd::Bookmark(a)) => cmd_annotate_bookmark(a, pretty),
        Command::Annotate(AnnotateCmd::Show(a)) => cmd_annotate_show(a, pretty),
        Command::Annotate(AnnotateCmd::List) => cmd_annotate_list(pretty),
        Command::Annotate(AnnotateCmd::Rm(a)) => cmd_annotate_rm(a, pretty),
        Command::Snapshot(SnapshotCmd::Dump(a)) => cmd_snapshot_dump(a, pretty),
        Command::Snapshot(SnapshotCmd::Info(a)) => cmd_snapshot_info(a, pretty),
        Command::Snapshot(SnapshotCmd::List) => cmd_snapshot_list(pretty),
        Command::RemoteServe(_) => unreachable!("handled before this match, see main()"),
        Command::Diff(DiffCmd::Functions(a)) => cmd_diff_functions(a, pretty),
        Command::Bundle(BundleCmd::List(a)) => cmd_bundle_list(a, pretty),
        Command::Bundle(BundleCmd::Extract(a)) => cmd_bundle_extract(a, pretty),
        Command::Bundle(BundleCmd::Repack(a)) => cmd_bundle_repack(a, pretty),
        Command::Lua(LuaCmd::Disasm(a)) => cmd_lua_disasm(a, pretty),
        Command::Lua(LuaCmd::Patch(a)) => cmd_lua_patch(a, pretty),
        Command::Lua(LuaCmd::Strings(a)) => cmd_lua_strings(a, pretty),
        Command::Lua(LuaCmd::Table(a)) => cmd_lua_table(a, pretty),
        Command::Lua(LuaCmd::Combo(a)) => cmd_lua_combo(a, pretty),
        Command::Lua(LuaCmd::Seedscan(a)) => cmd_lua_seedscan(a, pretty),
        Command::Concept(ConceptCmd::Grep(a)) => cmd_concept_grep(a, CONCEPT_GREP.spelled(typed), pretty),
        Command::Locate(LocateCmd::ByTransition(a)) => cmd_locate_by_transition(a, pretty),
        Command::Input(InputCmd::Probe(a)) => cmd_input_probe(a, pretty),
        Command::Const(ConstCmd::Identify(a)) => cmd_const_identify(a, pretty),
        Command::Bindings(BindingsCmd::List(a)) => cmd_bindings_list(a, pretty),
        Command::Sig(SigCmd::Validate(a)) => cmd_sig_validate(a, pretty),
        Command::Sig(SigCmd::Gen(a)) => cmd_sig_gen(a, pretty),
        Command::Ui(UiCmd::Locate(a)) => cmd_ui_locate(a, pretty),
        Command::Ui(UiCmd::Windows(a)) => cmd_ui_windows(a, pretty),
        Command::Ui(UiCmd::Screenshot(a)) => cmd_ui_screenshot(a, pretty),
        Command::Ui(UiCmd::Focus(a)) => cmd_ui_focus(a, pretty),
        Command::Il2cpp(Il2cppCmd::Import(a)) => cmd_il2cpp_import(a, pretty),
        Command::Il2cpp(Il2cppCmd::Symbols(a)) => cmd_il2cpp_symbols(a, pretty),
        Command::Il2cpp(Il2cppCmd::Metadata(a)) => cmd_il2cpp_metadata(a, pretty),
        Command::Il2cpp(Il2cppCmd::Icalls(a)) => cmd_il2cpp_icalls(a, pretty),
        Command::Il2cpp(Il2cppCmd::Obj(a)) => cmd_il2cpp_obj(a, pretty),
        Command::Il2cpp(Il2cppCmd::Classes(a)) => cmd_il2cpp_classes(a, pretty),
        Command::Serve(_) => unreachable!("handled before this dispatch, see main()"),
    }
}

fn cmd_doctor(pretty: bool) -> bool {
    // One builder, both doors: the MCP `doctor` tool emits this exact payload.
    // See n0xis_frontend::doctor for why it reports capabilities, not phases.
    emit(&Response::success(schema::v1::DOCTOR, n0xis_frontend::doctor::payload()), pretty)
}

/// Which category a top-level command belongs to (curated grouping — clap
/// doesn't model categories, so this is the one hand-maintained mapping).
fn guide_category(top: &str) -> &'static str {
    match top {
        "doctor" | "guide" | "init" | "project" | "process" | "remote-serve" | "profile" | "capability" => "Environment & project",
        "module" | "disasm" | "ir" | "function" | "decomp" | "xref" | "diff" | "rtti" | "analyze" | "find" | "strings" | "type" | "symbols" => "Static analysis & decompilation",
        "mem" | "scan" | "patch" | "table" | "debug" | "selection" | "dump" => "Live memory",
        "provenance" | "annotate" | "snapshot" | "plugin" => "Provenance, annotations & snapshots",
        "concept" | "locate" | "input" | "const" | "bindings" | "sig" => "Spec-first method tooling (Phase 8)",
        "ui" => "UI-layer localization (Phase 9, marked invalid)",
        "il2cpp" => "IL2CPP managed layer (Phase 12)",
        "bundle" | "lua" => "Script & asset archives (Bitsquid/LuaJIT)",
        _ => "Other",
    }
}

/// Render one clap argument as an agent-readable JSON descriptor. Returns `None`
/// for the auto `help`/`version` args and for `global` flags (those are listed
/// once in the preamble, not repeated on every command).
fn guide_arg_json(arg: &clap::Arg) -> Option<serde_json::Value> {
    use clap::ArgAction;
    let id = arg.get_id().as_str();
    if id == "help" || id == "version" || arg.is_global_set() {
        return None;
    }
    let is_flag = matches!(arg.get_action(), ArgAction::SetTrue | ArgAction::SetFalse);
    let long = arg.get_long();
    let name = match long {
        Some(l) => format!("--{l}"),
        None => format!("<{id}>"),
    };
    let values: Vec<String> = arg.get_possible_values().iter().map(|p| p.get_name().to_string()).collect();
    Some(json!({
        "name": name,
        "positional": long.is_none() && !is_flag,
        "required": arg.is_required_set(),
        "takes_value": !is_flag,
        "help": arg.get_help().map(|s| s.to_string()),
        "choices": if values.is_empty() { serde_json::Value::Null } else { json!(values) },
    }))
}

/// Walk the clap command tree, emitting one entry per *leaf* command (a command
/// with no subcommands), with its full `path` (`"scan value"`), the `about` text
/// straight from the clap definition, and its arguments. Derived from the real
/// CLI definition, so the catalog can never drift from what the binary accepts.
fn guide_collect(cmd: &clap::Command, prefix: &str, brief: bool, out: &mut Vec<serde_json::Value>) {
    let subs: Vec<&clap::Command> = cmd.get_subcommands().filter(|c| c.get_name() != "help").collect();
    if subs.is_empty() {
        let path = prefix.trim().to_string();
        if path.is_empty() {
            return;
        }
        let top = path.split(' ').next().unwrap_or("");
        let mut entry = json!({
            "path": path,
            "category": guide_category(top),
            "summary": cmd.get_about().map(|s| s.to_string()),
        });
        if let Some(d) = cmd.get_long_about() {
            entry["detail"] = json!(d.to_string());
        }
        if !brief {
            let args: Vec<_> = cmd.get_arguments().filter_map(guide_arg_json).collect();
            entry["args"] = json!(args);
        }
        out.push(entry);
    } else {
        for s in subs {
            let child = if prefix.is_empty() { s.get_name().to_string() } else { format!("{prefix} {}", s.get_name()) };
            guide_collect(s, &child, brief, out);
        }
    }
}

/// Curated workflow recipes — the *method*, not the command list. This is what
/// turns "here are the commands" into "here is how to approach an RE task", each
/// traced to the RE_METHOD note it encodes. clap can't derive these; they are
/// the deliberate agent-guidance layer over the auto-generated catalog.
fn guide_workflows() -> Vec<serde_json::Value> {
    vec![
        json!({
            "name": "spec-first ladder (start here for any application feature)",
            "when": "you want to understand an application's behaviour (an input sequence, a timer, a lookup table). Climb top-down: data → scripts → native bindings → native code → memory. Each rung is cheaper and more stable than the one below.",
            "maps_to": "RE_METHOD F2/W4 — ~90% of a campaign was wasted reversing runtime state that was declaratively specified in scripts.",
            "steps": [
                "bundle list --file <archive>            # is there a script layer? extract it",
                "bundle extract --file <archive> --type lua --out ./scripts",
                "concept grep \"retry,backoff,timeout\" --dir ./scripts   # find the feature's vocabulary cluster",
                "lua disasm --file ./scripts/<hit>.luac  # read the algorithm out of the script",
                "const identify --lua ./scripts/<hit>.luac  # recognize the RNG/hash by its constants",
                "bindings list --file <app.exe> --name next_random   # only now go native, and only for what scripts call",
                "# read memory ONLY for the irreducible input (a seed/handle), never the whole object graph"
            ]
        }),
        json!({
            "name": "transition-diff localization (find an address)",
            "when": "you need the address of a value you can toggle on screen (a flag, a counter, a state). The only technique that reliably returns exactly one result.",
            "maps_to": "RE_METHOD W1 — the change is the signal; the value is not.",
            "steps": [
                "locate by-transition --pid <p> --type i32 --save-as loc   # snapshot, then toggle ONE thing when prompted (or --wait-ms N)",
                "# repeat to narrow: toggle again, then:",
                "scan filter --pid <p> --from loc --criterion changed --save-as loc2",
                "table add --table main --name found --addr <hit> --type i32   # pin the survivor"
            ]
        }),
        json!({
            "name": "explain a runtime value (what code wrote it)",
            "when": "you have an address and want the source-level statement responsible — the fusion of live watchpoint + decompiler.",
            "maps_to": "Phase 4c; RE_METHOD F1 (stop chasing view/cache indirection).",
            "steps": [
                "debug watch --pid <p> --addr <hex> --kind write   # catch the writing instruction + caller chain",
                "provenance trace --pid <p> --addr <hex> --kind write   # decompile the exact writing statement"
            ]
        }),
        json!({
            "name": "prove the write path BEFORE building on it",
            "when": "you are about to build any input/automation feature. Verify the target actually registers your actuation first.",
            "maps_to": "RE_METHOD F4 — an entire input feature was shipped that never once registered (LLKHF_INJECTED filtered).",
            "steps": [
                "input probe --pid <p>   # reports which methods carry LLKHF_INJECTED (a filtering target ignores those)"
            ]
        }),
        json!({
            "name": "validate a signature before trusting it",
            "when": "you have a candidate byte pattern / marker and want to know if it is real or an N=2 coincidence.",
            "maps_to": "RE_METHOD F3 — a marker matched two same-seed instances and shipped broken.",
            "steps": [
                "sig validate --sample <hex-a> --sample <hex-b> --sample <hex-c> --varied input,session,seed --signature \"48 8B ?? 68\"",
                "# refuses to bless <3 deliberately-varied samples; reports which bytes are actually invariant"
            ]
        }),
        json!({
            "name": "identify an algorithm from its constants",
            "when": "a function/data blob has magic numbers and you want to know the algorithm without reversing the arithmetic.",
            "maps_to": "RE_METHOD W3 — 0x5bd1e995 = MurmurHash2, 1664525 = Numerical-Recipes LCG.",
            "steps": [
                "const identify --value 0x5bd1e995            # a single constant",
                "const identify --file <pe> --addr <hex>      # every literal in a decompiled function",
                "const identify --lua <chunk.luac>            # a Lua chunk's number pool"
            ]
        }),
        json!({
            "name": "decompile a function",
            "when": "you have (or discovered) a function address and want readable pseudo-C.",
            "maps_to": "Phase 3 decompiler.",
            "steps": [
                "function discover --file <pe>                # find function entry points",
                "ir manifest --file <pe>                      # rank candidates by quality before spending a full decompile",
                "decomp pseudo --file <pe> --addr <hex> --style ssa   # optimized + structured pseudo-C"
            ]
        }),
    ]
}

fn cmd_guide(a: GuideArgs, pretty: bool) -> bool {
    let root = <Cli as clap::CommandFactory>::command();
    let mut commands = Vec::new();
    guide_collect(&root, "", a.brief, &mut commands);

    // Optional topic filter over command paths.
    if let Some(topic) = &a.topic {
        let t = topic.to_lowercase();
        commands.retain(|c| c["path"].as_str().is_some_and(|p| p.to_lowercase().contains(&t)));
    }

    // Category → command-paths index, derived from the (possibly filtered) set.
    let mut categories: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    for c in &commands {
        if let (Some(cat), Some(path)) = (c["category"].as_str(), c["path"].as_str()) {
            categories.entry(cat.to_string()).or_default().push(path.to_string());
        }
    }

    // Workflows, filtered to the topic when one was given.
    let mut workflows = guide_workflows();
    if let Some(topic) = &a.topic {
        let t = topic.to_lowercase();
        workflows.retain(|w| serde_json::to_string(w).unwrap_or_default().to_lowercase().contains(&t));
    }

    let data = json!({
        "tool": "n0xis",
        "version": env!("CARGO_PKG_VERSION"),
        "tagline": "Reverse-engineering toolkit: static PE/ELF + live memory in one contract-first pipeline — an optimizing SSA decompiler, watchpoint→decompiled-statement provenance, and journaled patching. Structured JSON from a terminal or, via MCP, an agent. Windows + Linux.",
        "usage_model": "Pick a command from `commands` (or a recipe from `workflows`). Every command emits the same { ok, data, meta } envelope on stdout; add --pretty for indented JSON; meta.schema names the payload shape. Progress goes to stderr with a [n0x] prefix (safe to ignore, or silence with --quiet). Non-zero exit on ok:false.",
        "global_flags": [
            { "name": "--pretty", "help": "indent the JSON envelope" },
            { "name": "--json", "help": "strict JSON-only stdout (already the default)" },
            { "name": "--quiet", "help": "suppress [n0x] stderr progress" }
        ],
        "sources": "commands that read a target accept exactly one of: --pid <live process>, --file <static PE>, --snapshot <name of a captured snapshot dump>, --remote-cmd \"<argv, e.g. ssh host n0xis remote-serve --pid N>\", or --bytes \"<hex>\" (inline). Live VAs respect ASLR; static VAs use the image's preferred base.",
        "envelope": "every command emits { ok, data, meta } or { ok:false, error:{code,message,hint?} }; meta.schema is the payload id (n0xis.*.v1, or the archived n0x.*.v1 for ported v0 shapes).",
        "architectures": [
            "x64 — iced-x86, full pipeline: CFG / SSA / type recovery / optimized decompile. A 32-bit PE32 auto-selects i386 (or force with --arch x86)",
            "arm64 — disarm64, CFG / discover / xref / goto+structured decompile (SSA optimization is x64-only so far); pass --arch arm64",
            "arm32 / thumb — yaxpeax-arm, AArch32/ARMv7 disassembly (decode-only so far: correct decode + CFG, lift is a follow-on). --arch arm32 (A32) or --arch thumb"
        ],
        "categories": categories,
        "command_count": commands.len(),
        "commands": commands,
        "workflows": workflows,
        "mcp": "the same pipeline is exposed as an MCP server (binary n0xis-mcp) over stdio, with the same tool names and { ok, data, meta } shapes — an agent's parsing code is identical whether it calls the CLI or MCP.",
        "docs": ["README.md", "CONCEPT.md", "ROADMAP.md"],
        "hint": "narrow with `n0x guide <topic>` (e.g. `n0x guide scan`, `n0x guide concept`); every command also has clap `--help` for the exact usage line. `n0x guide --brief` drops per-arg detail.",
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

/// Files and bytes directly in `dir` (the caches are flat).
fn dir_usage(dir: &std::path::Path) -> (u64, u64) {
    let Ok(entries) = std::fs::read_dir(dir) else { return (0, 0) };
    entries
        .filter_map(Result::ok)
        .filter_map(|e| e.metadata().ok().filter(|m| m.is_file()))
        .fold((0, 0), |(files, bytes), m| (files + 1, bytes + m.len()))
}

fn cmd_project_cache(a: ProjectCacheArgs, pretty: bool) -> bool {
    let root = match n0xis_project::resolve() {
        Ok(root) => root,
        Err(e) => return emit(&Response::<serde_json::Value>::error("project-unresolved", e.to_string()), pretty),
    };
    let mut caches = Vec::new();
    let (mut total, mut freed) = (0u64, 0u64);
    let mut failures = Vec::new();
    for (name, dir) in root.derived_caches() {
        let (files, bytes) = dir_usage(&dir);
        total += bytes;
        if a.clear && files > 0 {
            for entry in std::fs::read_dir(&dir).into_iter().flatten().filter_map(Result::ok) {
                let path = entry.path();
                let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                if path.is_file() {
                    match std::fs::remove_file(&path) {
                        Ok(()) => freed += len,
                        Err(e) => failures.push(format!("{}: {e}", path.display())),
                    }
                }
            }
        }
        caches.push(json!({ "name": name, "dir": dir.display().to_string(), "files": files, "bytes": bytes }));
    }
    let data = json!({
        "dir": root.dir.display().to_string(),
        "is_local": root.is_local,
        "caches": caches,
        "bytes": total,
        "cleared": a.clear,
        "freed": freed,
        "failures": failures,
    });
    emit(&Response::success(schema::v1::PROJECT_CACHE, data), pretty)
}

/// `symbols add`: through the registry, so `serve` and an agent reach the same check.
fn cmd_symbols_add(a: SymbolsAddArgs, pretty: bool) -> bool {
    run_capability("symbols.add", json!({ "file": a.file, "pdb": a.pdb }), pretty)
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
    run_capability("process.ps", json!({ "filter": a.filter }), pretty)
}

/// Which presentation of the CFG artifact to emit.
#[derive(Clone, Copy)]
enum IrView {
    Cfg,
    Explain,
    Dot,
}


/// The function-scoped target arguments as the capability registry's JSON.
/// One conversion, used by every command that dispatches a function-scoped
/// capability — the CLI's job here is flags-to-JSON and nothing else.
fn ir_args_json(a: &IrArgs) -> serde_json::Value {
    json!({
        "addr": a.addr,
        "addr_rva": a.addr_rva,
        "addr_module": a.addr_module,
        "arch": a.arch,
        "size": a.size,
        "no_auto_end": a.no_auto_end,
        "pid": a.pid,
        "file": a.file,
        "bytes": a.bytes,
        "snapshot": a.snapshot,
        "remote_cmd": a.remote_cmd,
        "flirt": a.flirt,
    })
}

/// Dispatch a capability and print its envelope. Every handler below is now
/// this one line plus its argument mapping; the analysis lives in
/// `n0xis-frontend::registry`, shared with MCP.
fn run_capability(name: &str, args: serde_json::Value, pretty: bool) -> bool {
    emit(&n0xis_frontend::build_registry().dispatch(name, &args), pretty)
}

fn cmd_ir(a: IrArgs, view: IrView, pretty: bool) -> bool {
    let name = match view {
        IrView::Cfg => "ir.cfg",
        IrView::Explain => "ir.explain",
        IrView::Dot => "ir.dot",
    };
    run_capability(name, ir_args_json(&a), pretty)
}

fn cmd_decomp(a: DecompArgs, pretty: bool) -> bool {
    let mut args = ir_args_json(&a.ir);
    args["style"] = json!(match DecompStyle::from(a.style) {
        DecompStyle::Goto => "goto",
        DecompStyle::Structured => "structured",
        DecompStyle::Ssa => "ssa",
    });
    args["explain"] = json!(a.explain);
    run_capability("decomp.pseudo", args, pretty)
}

fn cmd_ir_value_set(a: IrArgs, pretty: bool) -> bool {
    run_capability("ir.value-set", ir_args_json(&a), pretty)
}

fn cmd_ir_deobfuscate(a: IrArgs, pretty: bool) -> bool {
    run_capability("ir.deobfuscate", ir_args_json(&a), pretty)
}


fn cmd_diff_functions(a: DiffFunctionsArgs, pretty: bool) -> bool {
    run_capability(
        "diff.functions",
        json!({
            "a_addr": a.a_addr, "a_pid": a.a_pid, "a_file": a.a_file, "a_bytes": a.a_bytes,
            "b_addr": a.b_addr, "b_pid": a.b_pid, "b_file": a.b_file, "b_bytes": a.b_bytes,
            "size": a.size,
            "style": match DecompStyle::from(a.style) {
                DecompStyle::Goto => "goto",
                DecompStyle::Structured => "structured",
                DecompStyle::Ssa => "ssa",
            },
            "arch": a.arch,
        }),
        pretty,
    )
}


fn cmd_ir_slice(a: IrSliceArgs, pretty: bool) -> bool {
    let mut args = ir_args_json(&a.ir);
    args["reg"] = json!(a.reg);
    args["at"] = json!(a.at);
    run_capability("ir.slice", args, pretty)
}

fn ir_err(code: &str, msg: &str, pretty: bool) -> bool {
    emit(&Response::<serde_json::Value>::error(code, msg), pretty)
}

/// Resolve `--pid` / `--file` / `--snapshot` / `--remote-cmd` / `--bytes` into
/// a source. The resolution itself is [`n0xis_frontend::source::resolve`] —
/// this is only the CLI's flag shape adapted onto it, so the CLI and MCP can
/// never disagree about what a target argument means.
fn build_source(
    pid: Option<u32>,
    file: Option<&str>,
    bytes: Option<&str>,
    snapshot: Option<&str>,
    remote_cmd: Option<&str>,
    bytes_base: Va,
) -> Result<(Src, String, Option<usize>), (String, String)> {
    let spec = SourceSpec { pid, file, snapshot, remote_cmd, bytes, bytes_base: Some(bytes_base) };
    n0xis_frontend::source::resolve(spec).map(|r| (r.src, r.label, r.region_len))
}

/// Refuse a call that names more than one target.
///
/// [`n0xis_frontend::source::resolve`] enforces this for every command that
/// goes through it; `disasm` resolves its own source (it needs the image base
/// for its out-of-image hint and auto-selects the i386 decoder for a PE32), so
/// it asks here instead. Two implementations of "which target" is how the
/// question got two answers in the first place — this is the smaller of the two
/// evils until the second implementation is gone.
fn refuse_two_sources(pid: Option<u32>, file: Option<&str>, bytes: Option<&str>) -> Option<(String, String)> {
    let named: Vec<&str> =
        [pid.map(|_| "pid"), file.map(|_| "file"), bytes.map(|_| "bytes")].into_iter().flatten().collect();
    (named.len() > 1).then(|| {
        (
            "ambiguous-source".to_string(),
            format!("{} sources named ({}); a command reads exactly one", named.len(), named.join(", ")),
        )
    })
}

fn to_hex_spaced(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

fn byte_diff_count(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).filter(|(x, y)| x != y).count() + a.len().abs_diff(b.len())
}



fn cmd_function_trace(a: FunctionTraceArgs, pretty: bool) -> bool {
    run_capability(
        "function.trace",
        json!({
            "addr": a.addr,
            "addr_rva": a.addr_rva,
            "depth": a.depth,
            "max_nodes": a.max_nodes,
            "max_bytes": a.max_bytes,
            "arch": a.arch,
            "pid": a.pid,
            "file": a.file,
            "bytes": a.bytes,
            "snapshot": a.snapshot,
            "remote_cmd": a.remote_cmd,
        }),
        pretty,
    )
}

/// Locate an IL2CPP metadata blob next to `image_path`, if one exists.
///
/// The layout rule itself lives in `n0xis-frontend::il2cpp_caps` — `profile`
/// and `il2cpp metadata` must agree about where the blob is, and two copies of
/// a directory convention drift the moment the runtime changes it. It stays out of
/// `n0xis-core::profile` for the older reason: that crate's whole boundary
/// discipline is that it does not touch the filesystem.
fn find_il2cpp_metadata(image_path: &str) -> Option<String> {
    n0xis_frontend::il2cpp_caps::find_metadata_near(image_path)
}

/// The IL2CPP metadata format version, read straight from the blob's header:
/// a `0xFAB11BAF` sanity word followed by an `i32` version. Reported rather
/// than inferred — the version decides every layout question downstream, and
/// guessing it from the runtime release is exactly the kind of almost-right
/// answer this command exists to replace.
fn il2cpp_metadata_version(path: &str) -> Option<u32> {
    let bytes = std::fs::read(path).ok()?;
    let sanity = u32::from_le_bytes(bytes.get(0..4)?.try_into().ok()?);
    if sanity != 0xFAB1_1BAF {
        return None;
    }
    Some(u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?))
}

fn cmd_profile(a: ProfileArgs, pretty: bool) -> bool {
    if a.pid.is_none() && a.file.is_none() {
        return ir_err("no-source", "profile needs a PE image: pass --file <pe> or --pid <n>", pretty);
    }
    // `build_source` first so the arch pick can read the image header: a static
    // PE/ELF states its own machine, and `Src::pick_arch` honours it when no
    // explicit `--arch` is given. Neither block depends on the other's result,
    // so the reorder is behaviour-preserving.
    let (src, label, _) = match build_source(a.pid, a.file.as_deref(), None, None, None, Va(0)) {
        Ok(x) => x,
        Err((c, m)) => return ir_err(&c, &m, pretty),
    };
    let arch = match src.pick_arch(a.arch.as_deref()) {
        Ok(x) => x,
        Err(e) => return ir_err("bad-arch", &e, pretty),
    };
    let base = match base_for_module(&src, a.module.as_deref()) {
        Ok(b) => b,
        Err(e) => return ir_err("no-module", &e, pretty),
    };

    // The image path: the file we were handed, or the live module's own path.
    // The *metadata* search is deliberately anchored to the main module's
    // directory either way — an IL2CPP build's `*_Data` folder sits beside the
    // host executable, not necessarily beside whichever DLL is being
    // profiled.
    let image_path = match (&a.file, &src) {
        (Some(f), _) => Some(f.clone()),
        (None, Src::Live(l)) => l.main_module().and_then(|m| m.path.clone()),
        _ => None,
    };
    let metadata = image_path.as_deref().and_then(find_il2cpp_metadata);
    let metadata_version = metadata.as_deref().and_then(il2cpp_metadata_version);

    // `profile_image` walks a PE header (DOS stub -> `PE\0\0` -> optional header
    // -> section table). An ELF has none of that, so it used to fail at the very
    // first read — `profile` is the command everyone runs first, which made the
    // whole tool look ELF-incapable even though disasm/decomp/xref all work.
    // Whether this image needed a permissive parse — see `StaticPe::load`.
    let degraded_reason: Option<String> = match &src {
        Src::Static(img) => match img.as_ref() {
            StaticImage::Pe(pe) => pe.degraded().map(str::to_string),
            _ => None,
        },
        _ => None,
    };

    // Build the same profile from the ELF source's own parsed section table and
    // symbols, and share the format-agnostic assembly with the PE path.
    if let Src::Static(img) = &src
        && let StaticImage::Elf(elf) = img.as_ref()
    {
        let sections: Vec<n0xis_core::SectionInfo> = elf
            .sections_detailed()
            .into_iter()
            .map(|(name, va, size, executable)| n0xis_core::SectionInfo {
                name,
                va,
                // An ELF section has one size; report it as both rather than
                // inventing a distinct on-disk figure PE happens to carry.
                virtual_size: size.min(u32::MAX as u64) as u32,
                raw_size: size.min(u32::MAX as u64) as u32,
                executable,
            })
            .collect();
        // ELF defined function symbols are this format's answer to the PE export
        // table. Thunk resolution is PE-specific (no equivalent walk here), so
        // those fields stay `None` instead of being guessed. A defined function
        // symbol has its body in this image, so none is a forwarder.
        let exports: Vec<n0xis_core::ExportInfo> = elf
            .named_functions()
            .into_iter()
            .map(|(va, name)| n0xis_core::ExportInfo { name, va, forwarder: None, thunk_target: None, thunk_kind: None })
            .collect();
        let profile = n0xis_core::assemble_profile(elf.image_base(), elf.machine(), sections, exports, None, a.exports);
        let advisories = n0xis_core::advisories(&profile, metadata.as_deref(), a.pid.is_some());
        let data = json!({
            "image": profile,
            "il2cpp": metadata.as_ref().map(|p| json!({
                "metadata_path": p,
                "metadata_version": metadata_version,
            })),
            "advisories": advisories,
        });
        return emit(&Response::success(schema::v1::PROFILE, data).with_source(label.clone()), pretty);
    }

    // Which PDB the image names, where it was looked for, and what a match brought.
    let debug_info = match &src {
        Src::Static(img) => n0xis_frontend::pdb_syms::report(img.as_ref()),
        _ => serde_json::Value::Null,
    };
    let run = |ctx: &Ctx| -> bool {
        match n0xis_core::profile_image(ctx.source, ctx.arch, base, a.exports).map(|mut p| {
            // A permissive parse is a fact about the *image*, and triage is
            // where it has to appear: otherwise an import table the parser
            // could not read looks identical to one that is genuinely empty.
            p.parse_degraded = degraded_reason.clone();
            p
        }) {
            Ok(profile) => {
                let advisories = n0xis_core::advisories(&profile, metadata.as_deref(), a.pid.is_some());
                let data = json!({
                    "image": profile,
                    "il2cpp": metadata.as_ref().map(|p| json!({
                        "metadata_path": p,
                        "metadata_version": metadata_version,
                    })),
                    "debug_info": debug_info,
                    "advisories": advisories,
                });
                emit(&Response::success(schema::v1::PROFILE, data).with_source(label.clone()), pretty)
            }
            Err(e) => ir_err("profile-failed", &e.to_string(), pretty),
        }
    };
    match &src {
        Src::Static(pe) => run(&Ctx::new(pe.as_ref(), arch.as_ref())),
        Src::Live(l) => run(&Ctx::new(l.as_ref(), arch.as_ref())),
        Src::Snap(s) => run(&Ctx::new(s, arch.as_ref())),
        Src::Remote(r) => run(&Ctx::new(r.as_ref(), arch.as_ref())),
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
    // Arch is picked *after* the source and *from its header*, the same way the
    // registry and disasm do it. `resolve_arch` defaults to x64, so discovering
    // an AArch64 or i386 image without `--arch` ran an x86-64 prologue scan over
    // foreign bytes: it invents `sub_XXXX` where an x86-64 prologue pattern
    // happens to match inside ARM instructions and misses the real functions —
    // a confident wrong answer, not an error. The header states the ISA; only a
    // raw `--bytes`/live target with no declaration falls back to the default,
    // and an explicit `--arch` still wins outright.
    let arch = match n0xis_frontend::pick_arch_for(a.arch.as_deref(), src.declared_machine().as_deref(), !src.is_64()) {
        Ok(a) => a,
        Err(e) => return ir_err("bad-arch", &e, pretty),
    };
    // An ad-hoc signature corpus, if one was named. The function LIST is where
    // signature naming is worth the most — a stripped static binary is almost
    // entirely library code, so without this the list is a wall of `sub_XXXX`
    // with the one interesting function hidden in it. Chained *below* the
    // image's own symbols, so a real name always wins.
    let (flirt_db, flirt_warns) = n0xis_frontend::flirt_syms::load_chain(&a.flirt);
    for w in &flirt_warns {
        eprintln!("[n0x] {}", json!({ "warn": format!("flirt corpus: {w}") }));
    }

    // `.pdata` discovery reads the whole module (headers + exception table), not
    // a `.text` byte window — resolve the module base and dispatch before the
    // range logic the prologue scan needs.
    if a.pdata {
        let Some(base) = module_base_of(&src) else {
            return ir_err("no-module", "--pdata needs a PE image with a module base (--pid or --file)", pretty);
        };
        let run_pdata = |ctx: &Ctx| -> bool {
            match n0xis_core::discover_pdata(ctx.source, base) {
                Ok(all) => {
                    // `.pdata` is an exact table, so the total is known for
                    // free — and it *must* be reported. A 94 MB PE yields
                    // ~277k entries; handing those back whole (as this path
                    // did while silently ignoring `--limit`) is 17 MB of JSON
                    // that no caller asked for.
                    let total = all.len();
                    let mut functions: Vec<_> = all
                        .into_iter()
                        .skip(a.offset)
                        .take(if a.limit == 0 { usize::MAX } else { a.limit })
                        .collect();
                    // `.pdata` gives only addresses (`sub_…`). Name what the symbol
                    // layer knows — recovered RTTI methods and user renames — so the
                    // whole function list carries real names, not just the decompiler.
                    if let Some(syms) = ctx.symbols {
                        for f in functions.iter_mut() {
                            if let Some(sym) = syms.symbol_at(f.va)
                                && sym.va == f.va
                            {
                                f.name = sym.name;
                            }
                        }
                    }
                    let returned = functions.len();
                    let art = n0xis_core::DiscoverArtifact {
                        start: base,
                        scanned_bytes: 0,
                        count: returned,
                        functions,
                        truncated: a.offset + returned < total,
                    };
                    emit(
                        &Response::success(schema::v1::FUNCTION_DISCOVER, art)
                            .with_source(label.clone())
                            .with_page(total, returned),
                        pretty,
                    )
                }
                Err(e) => ir_err("discover-failed", &e.to_string(), pretty),
            }
        };
        // Project-local names (recovered RTTI + user renames) as the primary
        // provider, so the discovered list renders them over the PE's own names.
        let local = n0xis_frontend::annotation_syms::LocalNames::load();
        // …and the managed names, when the project holds an IL2CPP index. Every
        // command that goes through the capability registry gets this; this one
        // does not, so it had to ask. Without it a user who has just imported an
        // index sees the C# name in `decomp` and `ir manifest` and a wall of
        // `sub_` in the function list, for the same addresses.
        let il2cpp = n0xis_frontend::il2cpp_caps::attach_for(&json!({}), &src);
        let managed = il2cpp.symbols();
        return match &src {
            Src::Static(pe) => {
                let flirt = flirt_db
                    .as_ref()
                    .map(|(db, fp)| n0xis_frontend::flirt_syms::FlirtSymbols::new(db, pe.as_ref(), &label, fp.clone()));
                let pdb = n0xis_frontend::pdb_syms::lookup(pe.as_ref());
                let full = n0xis_frontend::static_names::StaticNames::new(
                    &local,
                    pdb.symbols(),
                    managed,
                    pe.as_ref(),
                    flirt.as_ref().map(|f| f as &dyn n0xis_sources::SymbolProvider),
                );
                run_pdata(&Ctx::new(pe.as_ref(), arch.as_ref()).with_symbols(&full))
            }
            Src::Live(l) => run_pdata(&Ctx::new(l.as_ref(), arch.as_ref()).with_symbols(&local)),
            Src::Snap(s) => run_pdata(&Ctx::new(s, arch.as_ref()).with_symbols(&local)),
            Src::Remote(r) => run_pdata(&Ctx::new(r.as_ref(), arch.as_ref()).with_symbols(&local)),
        };
    }

    let default_text = match &src {
        Src::Static(pe) => pe.text_range(),
        Src::Live(l) => l.text_range(),
        Src::Snap(_) | Src::Remote(_) => None,
    };
    // Every executable range, not only `.text`: the same windows `analyze` scans.
    let ranges = n0xis_frontend::discovered::image_code_ranges(&src, default_text, region_len, explicit_start, a.size, bytes_base);
    if ranges.is_empty() {
        return ir_err("no-range", "could not resolve a scan range; pass --start and --size", pretty);
    }

    let run = |ctx: &Ctx| -> bool {
        // The scan always covers the whole range (the cap only cuts what is
        // returned), so the total is known and reported. It is kept for an image
        // that cannot change: a session paging through a long list pays for it
        // once, and names are attached per page, so a rename still shows.
        match n0xis_frontend::discovered::discovered_ranges(ctx, &src, &label, &ranges) {
            Ok(found) => {
                let art = found.page(ctx, a.offset, a.limit);
                let returned = art.count;
                let resp = Response::success(schema::v1::FUNCTION_DISCOVER, art)
                    .with_source(label.clone())
                    .with_page(found.total(), returned);
                emit(&resp, pretty)
            }
            Err(e) => ir_err("discover-failed", &e.to_string(), pretty),
        }
    };
    // Same symbol chain the `.pdata` path builds: project-local names (recovered
    // RTTI, user renames) take precedence over the image's own. Without this the
    // prologue-scan path saw only the image's symbols, so a function `analyze` had
    // already named `QFSFileEngine::vf31` still listed as `sub_1166A0` — the
    // recovered classes never reached the list on any target discovered this way.
    let local = n0xis_frontend::annotation_syms::LocalNames::load();
    // The managed layer too, for the same reason as the `.pdata` path above.
    let il2cpp = n0xis_frontend::il2cpp_caps::attach_for(&json!({}), &src);
    let managed = il2cpp.symbols();
    match &src {
        Src::Static(pe) => {
            let flirt = flirt_db
                .as_ref()
                .map(|(db, fp)| n0xis_frontend::flirt_syms::FlirtSymbols::new(db, pe.as_ref(), &label, fp.clone()));
            let pdb = n0xis_frontend::pdb_syms::lookup(pe.as_ref());
            let full = n0xis_frontend::static_names::StaticNames::new(
                &local,
                pdb.symbols(),
                managed,
                pe.as_ref(),
                flirt.as_ref().map(|f| f as &dyn n0xis_sources::SymbolProvider),
            );
            // The starts the image declares outright — see `Ctx::functions`.
            // Shared with the registry rather than reimplemented: a second copy
            // of this is how the two front doors came to disagree about how
            // many functions the same image has.
            let stated = n0xis_frontend::stated_functions(&src);
            run(&Ctx::new(pe.as_ref(), arch.as_ref()).with_symbols(&full).with_stated_functions(&stated))
        }
        Src::Live(l) => run(&Ctx::new(l.as_ref(), arch.as_ref()).with_symbols(&local)),
        Src::Snap(s) => run(&Ctx::new(s, arch.as_ref()).with_symbols(&local)),
        Src::Remote(r) => run(&Ctx::new(r.as_ref(), arch.as_ref()).with_symbols(&local)),
    }
}

/// Discover candidates over the scan range, then reduce each to a manifest
/// entry — the same two passes an agent would otherwise chain by hand.
fn cmd_ir_manifest(a: ManifestArgs, pretty: bool) -> bool {
    run_capability(
        "ir.manifest",
        json!({
            "start": a.start,
            "size": a.size,
            "limit": a.limit,
            "max_bytes": a.max_bytes,
            "arch": a.arch,
            "module": a.module,
            "pid": a.pid,
            "file": a.file,
            "bytes": a.bytes,
            "snapshot": a.snapshot,
            "remote_cmd": a.remote_cmd,
            "flirt": a.flirt,
        }),
        pretty,
    )
}

/// `analyze` — one whole-program pass that materializes the `.n0x/` summary
/// layer with visible phases: discover functions (the list `function discover`
/// gives), recover MSVC RTTI
/// class names, build the reverse-xref index, and warm the IR cache. Streams
/// `[n0x] {phase,done,total}` JSON lines to stderr (silenced by `--quiet`); the
/// content-addressed caches make a re-run skip work already done, so it resumes
/// after the app is closed and reopened. Static x64 PE only — the phases that
/// make it worthwhile (exact discovery, RTTI, a stable xref index) assume an
/// immutable on-disk image.
fn cmd_analyze(a: AnalyzeArgs, pretty: bool, quiet: bool) -> bool {
    let (src, label, region_len) = match build_source(a.pid, a.file.as_deref(), None, a.snapshot.as_deref(), a.remote_cmd.as_deref(), Va(0)) {
        Ok(x) => x,
        Err((c, m)) => return ir_err(&c, &m, pretty),
    };
    let arch = match src.pick_arch(a.arch.as_deref()) {
        Ok(a) => a,
        Err(e) => return ir_err("bad-arch", &e, pretty),
    };
    let Src::Static(pe) = &src else {
        return ir_err("unsupported", "analyze needs a static PE image (--file)", pretty);
    };
    let Some(base) = module_base_of(&src) else {
        return ir_err("no-module", "analyze needs a PE image with a module base", pretty);
    };

    let progress = |phase: &str, done: usize, total: usize| {
        if !quiet {
            eprintln!("[n0x] {}", json!({ "phase": phase, "done": done, "total": total }));
        }
    };
    let ctx = Ctx::new(pe.as_ref(), arch.as_ref()).with_symbols(pe.as_ref());

    // Phase 1 — every function, as `function discover` lists them: the one
    // helper, over the image's executable ranges, with the functions the image
    // declares (`.pdata` and exports on a PE, `.eh_frame` on an ELF). A list of
    // its own here drifted twice: without the declared functions it found 4 130
    // on an ELF whose unwind table declares 6 730, and taking `.pdata` alone on
    // a PE it counted 6 681 where `function discover` lists 8 258.
    progress("discovering", 0, 0);
    let stated = n0xis_frontend::stated_functions(&src);
    let dctx = Ctx::new(pe.as_ref(), arch.as_ref()).with_symbols(pe.as_ref()).with_stated_functions(&stated);
    let ranges = n0xis_frontend::discovered::image_code_ranges(&src, pe.text_range(), region_len, None, None, Va(0));
    let funcs = match n0xis_frontend::discovered::discovered_ranges(&dctx, &src, &label, &ranges) {
        Ok(found) => found.page(&dctx, 0, 0).functions,
        Err(e) => return ir_err("discover-failed", &e.to_string(), pretty),
    };
    let total = funcs.len();
    progress("discovering", total, total);

    // Phase 2 — recover MSVC RTTI class names (one `.rdata` scan) and PERSIST them
    // as a symbol map (`.n0x/rtti-symbols.json`), so the decompiler/listing render
    // `Class::vftable` and `Class::vfN` without re-scanning on every view. A method
    // slot that the PE already exports keeps its real name (RTTI never overrides a
    // genuine symbol); user renames later override these (they load atop this).
    progress("scanning-rtti", 0, 0);
    // Two ABIs: MSVC RTTI lives in `.rdata`; an ELF's classes come from Itanium
    // `_ZTV…` symbols. Without this branch every Linux C++ target reported zero
    // classes and persisted no symbol map, so the decompiler never saw them.
    let itanium: Option<Vec<n0xis_core::RttiVtable>> = match &src {
        Src::Static(img) => match img.as_ref() {
            n0xis_sources::StaticImage::Elf(elf) => {
                Some(n0xis_core::scan_itanium_rtti(src.as_mem(), &elf.data_symbols(), src.text_range()))
            }
            _ => None,
        },
        _ => None,
    };
    let classes = match (itanium, src.section_range_in(None, ".rdata")) {
        (Some(vts), _) => {
            let n = vts.len();
            let (mut functions, data) = n0xis_core::rtti_symbol_map(src.as_mem(), &vts, src.text_range());
            functions.retain(|va, _| {
                ctx.symbols.and_then(|s| s.symbol_at(Va(*va))).is_none_or(|sym| sym.va.0 != *va)
            });
            let generation = format!("rtti:{}:{}", n, functions.len() + data.len());
            if let Err(e) = n0xis_project::rtti_syms::save(&n0xis_project::rtti_syms::from_maps(generation, functions, data)) {
                eprintln!("[n0x] {}", json!({ "warn": format!("persist rtti-symbols: {e}") }));
            }
            n
        }
        (None, Some(rd)) => {
            let _ = rd;
            let vts = n0xis_core::scan_msvc_rtti(src.as_mem(), base, &src.data_ranges_of(None), src.text_range(), src.pointer_size());
            let n = vts.len();
            let (mut functions, data) = n0xis_core::rtti_symbol_map(src.as_mem(), &vts, src.text_range());
            functions.retain(|va, _| {
                ctx.symbols.and_then(|s| s.symbol_at(Va(*va))).is_none_or(|sym| sym.va.0 != *va)
            });
            let generation = format!("rtti:{}:{}", n, functions.len() + data.len());
            if let Err(e) = n0xis_project::rtti_syms::save(&n0xis_project::rtti_syms::from_maps(generation, functions, data)) {
                eprintln!("[n0x] {}", json!({ "warn": format!("persist rtti-symbols: {e}") }));
            }
            n
        }
        (None, None) => 0,
    };
    progress("scanning-rtti", classes, classes);

    // Phase 2b — FLIRT-class signature naming, PERSISTED (ROADMAP Phase 10 item 8).
    //
    // This is the step that turns the matcher into a product feature. A stripped
    // static binary is overwhelmingly *library* code — a five-line C program
    // linked statically discovers **1 436 functions, of which one is the
    // author's** — so triage is not "read the decompiler output", it is "find
    // the 1 of 1 436". Matching is cheap; the reason it never paid off before is
    // that `--flirt` lived only on `decomp pseudo`, one function at a time, so
    // the names never reached the function list, xref, or the GUI. Persisting
    // them into `.n0x/` (exactly as the RTTI phase above does) makes every
    // consumer see them through `LocalNames`, with no flag of its own.
    //
    // Skipped entirely when no corpus is given, so `analyze` is unchanged.
    let mut flirt_named = 0usize;
    if !a.flirt.is_empty() {
        progress("matching-signatures", 0, total);
        let (loaded, warns) = n0xis_frontend::flirt_syms::load_chain(&a.flirt);
        for w in &warns {
            eprintln!("[n0x] {}", json!({ "warn": format!("flirt corpus: {w}") }));
        }
        match loaded {
            None => eprintln!("[n0x] {}", json!({ "warn": "no signature corpus loaded; skipping" })),
            Some((db, fingerprint)) => {
                // The window must cover the longest pattern any corpus holds;
                // `sig gen` defaults to 32 bytes and this leaves generous room.
                const WINDOW: usize = 128;
                let mut names: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
                for (i, f) in funcs.iter().enumerate() {
                    // A function the image itself names needs no guess — and a
                    // signature must never displace a real symbol.
                    if ctx.symbols.and_then(|s| s.symbol_at(f.va)).is_some_and(|sym| sym.va == f.va) {
                        continue;
                    }
                    let Ok(bytes) = ctx.source.read(f.va, WINDOW) else { continue };
                    if let Some(name) = db.lookup(&bytes) {
                        names.insert(f.va.0, name.to_string());
                    }
                    if i % 512 == 0 {
                        progress("matching-signatures", i + 1, total);
                    }
                }
                flirt_named = names.len();
                if let Err(e) =
                    n0xis_project::flirt_syms::save(&n0xis_project::flirt_syms::from_map(fingerprint, names))
                {
                    eprintln!("[n0x] {}", json!({ "warn": format!("persist flirt-symbols: {e}") }));
                }
            }
        }
        progress("matching-signatures", total, total);
    }

    // Everything from here on runs on an **enriched** context.
    //
    // The `ctx` above carries only what the image itself names. The RTTI phase
    // has since written `Class::vfN` for every vtable slot, and the FLIRT phase
    // names for statically-linked library code — but a `Ctx` built before them
    // cannot see either, so the whole-program passes below were reading the
    // binary as if `analyze` had not just run. Measured on `libQt6Gui.so.6`: the
    // layout pass matched **960** methods on the stale context and **2 682** on
    // one that sees the names, because a method's class is read off its own
    // symbol and most of those symbols are the ones RTTI had just persisted.
    let local = n0xis_frontend::annotation_syms::LocalNames::load();
    // The image's PDB, when one matches, names everything RTTI and FLIRT did not.
    let pdb = n0xis_frontend::pdb_syms::lookup(pe.as_ref());
    let named = n0xis_frontend::static_names::StaticNames::new(&local, pdb.symbols(), None, pe.as_ref(), None);
    let vtables = std::sync::Arc::new(n0xis_frontend::annotation_syms::persisted_vtable_map());
    let ctx = Ctx::new(pe.as_ref(), arch.as_ref()).with_symbols(&named).with_vtables(&vtables);

    // Phase 2c — whole-program type propagation, PERSISTED (priority 3b).
    //
    // Opt-in because it analyzes every function once; the pass itself then runs
    // to a fixpoint over the extracted constraint graph, which is cheap. Same
    // shape as the phases above: run once, persist, and every later view reads
    // it through `.n0x/` with no flag of its own.
    let mut typeflow_params = 0usize;
    // `--layout` reads propagated return types, so it needs the flow store to
    // exist. Implying it is honest about the dependency rather than silently
    // producing a weaker layout.
    let want_typeflow = a.typeflow || a.layout;
    let mut flow_store = None;
    if want_typeflow && total > 0 {
        progress("propagating-types", 0, total);
        let vas: Vec<Va> = funcs.iter().map(|f| f.va).collect();
        match n0xis_core::Pass::run(&n0xis_core::TypePropagatePass, &ctx, n0xis_core::TypePropInput { functions: vas, max_bytes: 4096 }) {
            Ok(store) => {
                typeflow_params = store.propagated_params;
                let generation = format!("flow:{}:{}:{}", total, store.propagated_params, store.propagated_rets);
                let flow = n0xis_project::type_flow::from_maps(generation, store.params.clone(), store.rets.clone());
                if let Err(e) = n0xis_project::type_flow::save(&flow) {
                    eprintln!("[n0x] {}", json!({ "warn": format!("persist type-flow: {e}") }));
                }
                flow_store = Some(store);
            }
            Err(e) => eprintln!("[n0x] {}", json!({ "warn": format!("type propagation: {e}") })),
        }
        progress("propagating-types", total, total);
    }

    // Phase 2d — unify class field layouts across every method (priority 3b's
    // remaining item). Runs on a `Ctx` carrying the flow store just produced, so
    // a field filled with the result of a call is typed by that call's
    // propagated return type rather than by nothing.
    let (mut layout_classes, mut layout_typed_fields) = (0usize, 0usize);
    let (mut layout_by_closure, mut layout_by_fixpoint) = (0usize, 0usize);
    if a.layout && total > 0 {
        progress("unifying-layouts", 0, total);
        let vas: Vec<Va> = funcs.iter().map(|f| f.va).collect();
        {
            let flow_ref = flow_store.as_ref();
            let lctx = match flow_ref {
                Some(f) => ctx.with_type_flow(f),
                None => ctx,
            };
            match n0xis_core::Pass::run(&n0xis_core::ClassLayoutPass, &lctx, n0xis_core::ClassLayoutInput { functions: vas, max_bytes: 4096 }) {
                Ok(store) => {
                    layout_classes = store.classes.len();
                    let generation = format!("layout:{}:{}:{}", total, store.methods_matched, store.typed_fields);
                    let persisted = n0xis_frontend::layout_to_persisted(generation, &store);
                    layout_typed_fields = persisted.typed_fields();
                    if let Err(e) = n0xis_project::class_layout::save(&persisted) {
                        eprintln!("[n0x] {}", json!({ "warn": format!("persist class-layout: {e}") }));
                    }
                    layout_by_closure = store.claims_by_value_closure;
                    layout_by_fixpoint = store.fields_typed_by_fixpoint;
                }
                Err(e) => eprintln!("[n0x] {}", json!({ "warn": format!("class layout: {e}") })),
            }
        }
        progress("unifying-layouts", total, total);
    }

    // Phase 3 — build/persist the reverse-xref index (makes `xref to` instant).
    // Over the ranges `xref to` itself indexes: the key of the stored index
    // names them, so the session finds it only if they are the same.
    progress("indexing-xrefs", 0, 0);
    let code_ranges = src.code_ranges_of(None);
    let idx = n0xis_pipeline::xref_index_for(&ctx, &code_ranges, &label);
    let xref_targets = idx.edges.len();
    progress("indexing-xrefs", xref_targets, xref_targets);

    // Phase 4 — warm the IR cache per function (content-addressed; already-built
    // functions are skipped, which is what makes the whole pass resumable).
    let mut cached = 0usize;
    if !a.no_cfg && total > 0 {
        let cap = if a.limit == 0 { total } else { a.limit.min(total) };
        progress("disassembling", 0, cap);
        for (i, f) in funcs.iter().take(cap).enumerate() {
            let span = f.end.map(|e| e.0.saturating_sub(f.va.0) as usize).unwrap_or(0x2000).clamp(0x40, 0x10000);
            if cfg_cached(&ctx, CfgInput { start: f.va, max_bytes: span, auto_end: true }).is_ok() {
                cached += 1;
            }
            if i % 64 == 0 {
                progress("disassembling", i + 1, cap);
            }
        }
        progress("disassembling", cap, cap);
    }
    progress("done", total, total);

    let data = json!({
        "functions": total,
        "rtti_classes": classes,
        "flirt_named": flirt_named,
        "typeflow_propagated_params": typeflow_params,
        "layout_classes": layout_classes,
        "layout_typed_fields": layout_typed_fields,
        "layout_claims_by_value_closure": layout_by_closure,
        "layout_fields_by_fixpoint": layout_by_fixpoint,
        "xref_targets": xref_targets,
        "cached_functions": cached,
    });
    emit(&Response::success(schema::v1::ANALYZE, data).with_source(label), pretty)
}

/// Parse an escaped byte string into raw bytes: `\xNN` (two hex digits), plus
/// `\n \t \r \0 \\ \"`. Any other `\X` keeps the backslash then `X` verbatim.
fn parse_escaped(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut ch = s.chars().peekable();
    while let Some(c) = ch.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        match ch.next() {
            Some('x') => {
                let hex: String = (0..2).map_while(|_| ch.next()).collect();
                if hex.len() != 2 {
                    return Err("`\\x` needs two hex digits".to_string());
                }
                out.push(u8::from_str_radix(&hex, 16).map_err(|_| format!("bad hex escape \\x{hex}"))?);
            }
            Some('n') => out.push(b'\n'),
            Some('t') => out.push(b'\t'),
            Some('r') => out.push(b'\r'),
            Some('0') => out.push(0),
            Some('\\') => out.push(b'\\'),
            Some('"') => out.push(b'"'),
            Some(other) => {
                out.push(b'\\');
                let mut buf = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
            None => return Err("trailing backslash".to_string()),
        }
    }
    Ok(out)
}

/// Build the search pattern from exactly one of `--bytes` / `--string` /
/// `--escaped`. A string/escaped search is an exact byte match; `--bytes` may
/// carry `?`/`??` wildcards.
fn build_find_pattern(a: &FindArgs) -> Result<Vec<AobByte>, (String, String)> {
    let modes = [a.bytes.is_some(), a.string.is_some(), a.escaped.is_some()].iter().filter(|b| **b).count();
    if modes == 0 {
        return Err(("no-pattern".into(), "provide one of --bytes, --string, or --escaped".into()));
    }
    if modes > 1 {
        return Err(("ambiguous-pattern".into(), "provide exactly one of --bytes / --string / --escaped".into()));
    }
    if let Some(b) = &a.bytes {
        return parse_aob(b).map_err(|e| ("bad-bytes".into(), e));
    }
    let raw: Vec<u8> = if let Some(s) = &a.string {
        if a.utf16 {
            s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
        } else {
            s.as_bytes().to_vec()
        }
    } else {
        parse_escaped(a.escaped.as_deref().unwrap_or_default()).map_err(|e| ("bad-escaped".into(), e))?
    };
    Ok(raw.into_iter().map(AobByte::Exact).collect())
}

fn cmd_strings(a: StringsArgs, pretty: bool) -> bool {
    run_capability(
        "strings",
        json!({
            "min": a.min,
            "encoding": a.encoding,
            "section": a.section,
            "all_sections": a.all_sections,
            "contains": a.contains,
            "limit": a.limit,
            "offset": a.offset,
            "start": a.start,
            "size": a.size,
            "pid": a.pid,
            "file": a.file,
            "bytes": a.bytes,
            "snapshot": a.snapshot,
            "remote_cmd": a.remote_cmd,
        }),
        pretty,
    )
}

/// `find` — the disassembler's Ctrl+F: locate a byte pattern / string / escaped
/// string across the image's file-backed sections (or a named section / explicit
/// range). Built on the same [`AobScanPass`] the `aob` hooking scan uses — one
/// byte-scan primitive, two front-ends.
fn cmd_find(a: FindArgs, pretty: bool) -> bool {
    let pattern = match build_find_pattern(&a) {
        Ok(p) => p,
        Err((c, m)) => return ir_err(&c, &m, pretty),
    };
    if pattern.is_empty() {
        return ir_err("empty-pattern", "the search pattern is empty", pretty);
    }
    let explicit_start = a.start.as_deref().and_then(|s| Va::parse(s).ok());
    let (src, label, _) = match build_source(a.pid, a.file.as_deref(), None, a.snapshot.as_deref(), a.remote_cmd.as_deref(), explicit_start.unwrap_or(Va(0))) {
        Ok(x) => x,
        Err((c, m)) => return ir_err(&c, &m, pretty),
    };
    let arch = match src.pick_arch(a.arch.as_deref()) {
        Ok(x) => x,
        Err(e) => return ir_err("bad-arch", &e, pretty),
    };

    // The ranges to scan: an explicit `--start`/`--size`, one `--section`, or —
    // by default — every file-backed section of a static image.
    let ranges: Vec<(String, Va, u64)> = if let (Some(st), Some(sz)) = (explicit_start, a.size) {
        vec![("range".to_string(), st, sz as u64)]
    } else if let Some(sec) = a.section.as_deref() {
        match &src {
            Src::Static(pe) => match pe.section_range(sec) {
                Some((s, z)) => vec![(sec.to_string(), s, z)],
                None => return ir_err("no-section", &format!("no section named {sec:?} in the image"), pretty),
            },
            _ => return ir_err("no-section", "--section needs a static --file image", pretty),
        }
    } else {
        match &src {
            Src::Static(pe) => pe.sections(),
            _ => return ir_err("no-range", "provide --start and --size (or --file for a whole-image search)", pretty),
        }
    };

    let limit = if a.limit == 0 { usize::MAX } else { a.limit };
    let align = a.align.max(1) as u64;
    let scan = |ctx: &Ctx| -> (Vec<(Va, String)>, usize, bool) {
        let mut matches: Vec<(Va, String)> = Vec::new();
        let mut scanned = 0usize;
        let mut truncated = false;
        for (name, start, size) in &ranges {
            if *size == 0 || matches.len() >= limit {
                if matches.len() >= limit {
                    truncated = true;
                }
                continue;
            }
            if let Ok(art) = AobScanPass.run(ctx, AobInput { start: *start, size: *size as usize, pattern: pattern.clone() }) {
                scanned += art.bytes_scanned;
                for m in art.matches {
                    if align <= 1 || (m.0.wrapping_sub(start.0)) % align == 0 {
                        matches.push((m, name.clone()));
                        if matches.len() >= limit {
                            truncated = true;
                            break;
                        }
                    }
                }
            }
        }
        (matches, scanned, truncated)
    };

    let (matches, scanned, truncated) = match &src {
        Src::Static(pe) => scan(&Ctx::new(pe.as_ref(), arch.as_ref())),
        Src::Live(l) => scan(&Ctx::new(l.as_ref(), arch.as_ref())),
        Src::Snap(s) => scan(&Ctx::new(s, arch.as_ref())),
        Src::Remote(r) => scan(&Ctx::new(r.as_ref(), arch.as_ref())),
    };

    let data = json!({
        "count": matches.len(),
        "bytes_scanned": scanned,
        "pattern_len": pattern.len(),
        "truncated": truncated,
        "matches": matches.iter().map(|(va, sec)| json!({ "va": va.to_string(), "section": sec })).collect::<Vec<_>>(),
    });
    emit(&Response::success(schema::v1::FIND, data).with_source(label), pretty)
}

/// Parse a signed offset token — `0x68`, `104`, or `-0x8`.
fn parse_offset(tok: &str) -> Result<i64, String> {
    let t = tok.trim();
    let (neg, body) = t.strip_prefix('-').map(|b| (true, b)).unwrap_or((false, t));
    let v = if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16)
    } else {
        body.parse::<i64>()
    }
    .map_err(|_| format!("bad offset {tok:?}"))?;
    Ok(if neg { -v } else { v })
}

fn cmd_type_struct(a: TypeStructArgs, pretty: bool) -> bool {
    let mut fields = Vec::new();
    for f in &a.fields {
        let parts: Vec<&str> = f.splitn(3, ':').collect();
        if parts.len() < 2 {
            return ir_err("bad-field", &format!("field {f:?} must be OFFSET:NAME[:CTYPE]"), pretty);
        }
        let offset = match parse_offset(parts[0]) {
            Ok(o) => o,
            Err(e) => return ir_err("bad-field", &e, pretty),
        };
        fields.push(json!({ "offset": offset, "name": parts[1], "ctype": parts.get(2).copied().unwrap_or("") }));
    }
    let size = a.size.as_deref().and_then(|s| parse_offset(s).ok()).filter(|v| *v >= 0).map(|v| v as u64);
    run_capability("type.struct", json!({ "name": a.name, "size": size, "fields": fields }), pretty)
}

fn cmd_type_enum(a: TypeEnumArgs, pretty: bool) -> bool {
    let mut members = Vec::new();
    for m in &a.members {
        let Some((name, val)) = m.split_once('=') else {
            return ir_err("bad-member", &format!("member {m:?} must be NAME=VALUE"), pretty);
        };
        let value = match parse_offset(val) {
            Ok(v) => v,
            Err(e) => return ir_err("bad-member", &e, pretty),
        };
        members.push(json!({ "name": name.trim(), "value": value }));
    }
    run_capability("type.enum", json!({ "name": a.name, "members": members }), pretty)
}

fn cmd_rtti_scan(a: RttiScanArgs, pretty: bool) -> bool {
    run_capability(
        "rtti.scan",
        json!({
            "module": a.module,
            "pid": a.pid,
            "file": a.file,
            "bytes": a.bytes,
            "snapshot": a.snapshot,
            "remote_cmd": a.remote_cmd,
        }),
        pretty,
    )
}

fn cmd_xref(a: XrefArgs, dir: XrefDir, pretty: bool) -> bool {
    run_capability(
        "xref",
        json!({
            "addr": a.addr,
            "dir": match dir { XrefDir::To => "to", XrefDir::From => "from" },
            "start": a.start,
            "size": a.size,
            "arch": a.arch,
            "module": a.module,
            "pid": a.pid,
            "file": a.file,
            "bytes": a.bytes,
            "snapshot": a.snapshot,
            "remote_cmd": a.remote_cmd,
        }),
        pretty,
    )
}

/// Search the data sections for `--query` and the code sections for referencing
/// `lea`s. The two default independently and each spans *all* of its sections:
/// data across every initialized/read-only range (`.rdata`/`.rodata`/`.data…`),
/// code across every executable range — string literals and the code that
/// points at them live in different sections, and neither is just one section.
fn cmd_xref_string(a: XrefStringArgs, pretty: bool) -> bool {
    run_capability(
        "xref.string",
        json!({
            "query": a.query,
            "start": a.start,
            "size": a.size,
            "data_start": a.data_start,
            "data_size": a.data_size,
            "limit": a.limit,
            "arch": a.arch,
            "module": a.module,
            "pid": a.pid,
            "file": a.file,
            "bytes": a.bytes,
            "snapshot": a.snapshot,
            "remote_cmd": a.remote_cmd,
        }),
        pretty,
    )
}

fn cmd_mem_read(a: MemReadArgs, pretty: bool) -> bool {
    run_capability(
        "mem.read",
        json!({
            "addr": a.addr,
            "size": a.size,
            "pid": a.pid,
            "file": a.file,
            "bytes": a.bytes,
            "snapshot": a.snapshot,
            "remote_cmd": a.remote_cmd,
        }),
        pretty,
    )
}

fn cmd_mem_span(a: MemSpanArgs, pretty: bool) -> bool {
    run_capability(
        "mem.span",
        json!({
            "addr": a.addr,
            "size": a.size,
            "pid": a.pid,
            "file": a.file,
            "bytes": a.bytes,
            "snapshot": a.snapshot,
            "remote_cmd": a.remote_cmd,
        }),
        pretty,
    )
}

fn cmd_mem_write(a: MemWriteArgs, pretty: bool) -> bool {
    run_capability("mem.write", json!({ "addr": a.addr, "bytes": a.bytes, "pid": a.pid }), pretty)
}

fn cmd_mem_map(a: MemMapArgs, pretty: bool) -> bool {
    run_capability("mem.map", json!({ "pid": a.pid, "limit": a.limit }), pretty)
}

fn cmd_patch(cmd: PatchCmd, pretty: bool) -> bool {
    use n0xis_project::patch as pj;
    match cmd {
        PatchCmd::DryRun(a) => patch_dry_run(a, pretty),
        PatchCmd::Apply(a) => patch_apply(a, pretty),
        PatchCmd::List(a) => {
            match pj::list(a.limit) {
                Ok(mut items) => {
                    if let Some(s) = a.status {
                        items.retain(|r| s.matches(&r.status));
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
    {
        let live = match n0xis_frontend::source::attach_live(a.pid) {
            Ok(l) => l,
            Err((c, m)) => return ir_err(&c, &m, pretty),
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
    {
        let live = match n0xis_frontend::source::attach_live(a.pid) {
            Ok(l) => l,
            Err((c, m)) => return ir_err(&c, &m, pretty),
        };
        let before = match live.read(addr, desired.len()) {
            Ok(b) => b,
            Err(e) => return ir_err("read-failed", &e.to_string(), pretty),
        };
        let rec = match pj::apply(live.as_ref(), a.pid, addr, &desired) {
            Ok(r) => r,
            Err(e) => return ir_err("patch-failed", &e.to_string(), pretty),
        };
        let path = match pj::record_path(&rec.id) {
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
    let pid = a.pid.unwrap_or(rec.pid);
    {
        let live = match n0xis_frontend::source::attach_live(pid) {
            Ok(l) => l,
            Err((c, m)) => return ir_err(&c, &m, pretty),
        };
        let restored_len = match parse_hex_bytes(&rec.before_hex) {
            Ok(b) => b.len(),
            Err(e) => return ir_err("bad-record", &e, pretty),
        };
        if let Err(e) = pj::undo(&mut rec, live.as_ref(), a.force) {
            return ir_err("undo-failed", &e.to_string(), pretty);
        }
        let addr = match Va::parse(&rec.address) {
            Ok(v) => v,
            Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
        };
        let data = json!({
            "op": "undo",
            "id": rec.id,
            "pid": pid,
            "address": addr,
            "restored": restored_len,
        });
        emit(&Response::success(schema::v1::PATCH, data).with_source(live.label()), pretty)
    }
}

fn cmd_selection(cmd: SelectionCmd, pretty: bool) -> bool {
    match cmd {
        SelectionCmd::Save(a) => run_capability(
            "selection.save",
            json!({ "name": a.name, "start": a.start, "end": a.end, "label": a.label }),
            pretty,
        ),
        SelectionCmd::List => run_capability("selection.list", json!({}), pretty),
        SelectionCmd::Show(a) => run_capability("selection.show", json!({ "name": a.name }), pretty),
        SelectionCmd::Clear(a) => run_capability("selection.clear", json!({ "name": a.name }), pretty),
    }
}

/// `capability list` / `capability run` — the frontend half of the registry.
/// Note how little there is here: the CLI does not know what capabilities
/// exist, it asks. A new capability (built-in or plugin) shows up in both
/// subcommands without this file changing at all, which is the whole point of
/// the single composition point in `n0xis-frontend::registry::build_registry`.
fn cmd_capability(cmd: CapabilityCmd, pretty: bool) -> bool {
    let reg = n0xis_frontend::build_registry();
    match cmd {
        CapabilityCmd::List => emit(
            &Response::success(schema::v1::CAPABILITY_LIST, reg.describe()),
            pretty,
        ),
        CapabilityCmd::Run(a) => {
            let args: serde_json::Value = match serde_json::from_str(&a.args) {
                Ok(v) => v,
                Err(e) => return ir_err("bad-args", &format!("--args must be a JSON object: {e}"), pretty),
            };
            let resp = reg.dispatch(&a.name, &args);
            emit(&resp, pretty)
        }
    }
}

fn cmd_plugin(cmd: PluginCmd, pretty: bool) -> bool {
    use n0xis_project::plugins as pl;
    match cmd {
        PluginCmd::Add(a) => match pl::add(&a.name, &a.command, a.handles) {
            Ok(rec) => {
                let rec_v = serde_json::to_value(&rec).unwrap_or(serde_json::Value::Null);
                emit(&Response::success(schema::v1::PLUGIN, json!({ "op": "add", "plugin": rec_v })), pretty)
            }
            Err(e) => ir_err("plugin-add-failed", &e.to_string(), pretty),
        },
        // One builder, both doors: the MCP `plugin_list` tool emits this exact
        // payload (`pl::list_payload`), so the two cannot drift on `op` again.
        PluginCmd::List => match pl::list_payload() {
            Ok(data) => emit(&Response::success(schema::v1::PLUGIN, data), pretty),
            Err(e) => ir_err("plugin-list-failed", &e.to_string(), pretty),
        },
        PluginCmd::Rm(a) => match pl::remove(&a.name) {
            Ok(true) => emit(
                &Response::success(schema::v1::PLUGIN, json!({ "op": "rm", "name": a.name, "removed": true })),
                pretty,
            ),
            Ok(false) => ir_err("plugin-not-found", &format!("no plugin named '{}'", a.name), pretty),
            Err(e) => ir_err("plugin-rm-failed", &e.to_string(), pretty),
        },
    }
}

fn cmd_dump(cmd: DumpCmd, pretty: bool) -> bool {
    match cmd {
        DumpCmd::Save(a) => {
            // stdin is the CLI's affordance, not the capability's: read it here
            // and hand the bytes over as `content`.
            let content = if let Some(c) = a.content {
                c
            } else if a.file.is_some() {
                String::new()
            } else {
                use std::io::Read;
                let mut stdin = match command_stdin() {
                    Ok(s) => s,
                    Err(e) => {
                        return ir_err(STDIN_IS_SESSION_CODE, &format!("dump save has no --content or --file, so it would read its payload from stdin; {e}. Pass --content or --file."), pretty);
                    }
                };
                let mut buf = String::new();
                if let Err(e) = stdin.read_to_string(&mut buf) {
                    return ir_err("stdin-failed", &e.to_string(), pretty);
                }
                buf
            };
            let mut args = json!({ "name": a.name, "kind": a.kind, "force": a.force });
            if let Some(f) = a.file {
                args["file"] = json!(f);
            } else {
                args["content"] = json!(content);
            }
            run_capability("dump.save", args, pretty)
        }
        DumpCmd::List(a) => run_capability("dump.list", json!({ "kind": a.kind }), pretty),
        DumpCmd::Show(a) => {
            run_capability("dump.show", json!({ "name": a.name, "kind": a.kind, "preview": a.preview }), pretty)
        }
        DumpCmd::Rm(a) => run_capability("dump.rm", json!({ "name": a.name, "kind": a.kind }), pretty),
    }
}

fn cmd_debug_await_hit(a: DebugAwaitHitArgs, pretty: bool) -> bool {
    let addr = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
    {
        let _ = (addr, &a);
        ir_err("live-unsupported", "debug await-hit has no live adapter for this OS (Windows and Linux/Android are implemented)", pretty)
    }
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    {
        // Attach through the seam only long enough to resolve the main module
        // (for --addr-rva and the relative_rip label on a hit) — the debug
        // session itself attaches independently (its own handle / ptrace seize).
        let live = match n0xis_frontend::source::attach_live(a.pid) {
            Ok(l) => l,
            Err((c, m)) => return ir_err(&c, &m, pretty),
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
}

fn cmd_module_list(a: ModuleListArgs, pretty: bool) -> bool {
    run_capability(
        "module.list",
        json!({ "pid": a.pid, "file": a.file, "filter": a.filter }),
        pretty,
    )
}

fn cmd_disasm(a: DisasmArgs, pretty: bool) -> bool {
    // The CLI used to carry its own copy of this command: its own source
    // selection, its own architecture choice, its own out-of-image check and
    // its own comment attachment. Measured against the registry's `decode`,
    // which is what MCP and `serve` reach, the two disagreed three ways on the
    // same input — `--bytes` with an `--addr` worked here and answered
    // `decode-failed` there; an address past the last section was
    // `addr-out-of-image` here and `decode-failed` there; an address in a data
    // section was flagged there and silent here. One command now has one
    // implementation, and every front door gets all four behaviours.
    if let Some((code, msg)) = refuse_two_sources(a.pid, a.file.as_deref(), a.bytes.as_deref()) {
        return emit(&Response::<serde_json::Value>::error(&code, msg), pretty);
    }
    run_capability(
        "decode",
        json!({ "addr": a.addr, "count": a.count, "arch": a.arch, "pid": a.pid, "file": a.file, "bytes": a.bytes }),
        pretty,
    )
}

// ============================================================================
// scan / pointer-path / aob / dissect (ROADMAP Phase 4b)
// ============================================================================

/// Turn a CLI number into a typed scan value. `table pin` still needs Win32,
/// but `locate by-transition` does not — the conversion itself is arithmetic.
fn to_scan_value(v: f64) -> ScanValue {
    if v.fract() == 0.0 && v.abs() < 9.2e18 { ScanValue::Int(v as i64) } else { ScanValue::Float(v) }
}


/// The region set a live scan covers, for whichever adapter the OS supplied.
///
/// This was a byte-for-byte copy of `n0xis_frontend::source::
/// live_scan_regions` — exactly the duplication the frontend seam exists to
/// prevent, and the kind that had already let the CLI and MCP answers drift
/// apart once. It now delegates, and takes `&dyn LiveTarget` rather than a
/// concrete Win32 `LiveProcess`.
fn resolve_scan_regions_live(
    live: &dyn n0xis_sources::LiveTarget,
    start: Option<&str>,
    size: Option<usize>,
) -> Result<Vec<(Va, usize)>, String> {
    n0xis_frontend::source::live_scan_regions(live, start, size)
}


/// `ValueTypeArg` as the capability registry's type name. The clap enum and
/// the JSON name are deliberately the same spelling.
fn scan_type_name(t: ValueTypeArg) -> &'static str {
    match t {
        ValueTypeArg::I8 => "i8",
        ValueTypeArg::U8 => "u8",
        ValueTypeArg::I16 => "i16",
        ValueTypeArg::U16 => "u16",
        ValueTypeArg::I32 => "i32",
        ValueTypeArg::U32 => "u32",
        ValueTypeArg::I64 => "i64",
        ValueTypeArg::U64 => "u64",
        ValueTypeArg::F32 => "f32",
        ValueTypeArg::F64 => "f64",
    }
}
fn cmd_scan_value(a: ScanValueArgs, pretty: bool) -> bool {
    run_capability(
        "scan.value",
        json!({
            "type": scan_type_name(a.r#type),
            "criterion": a.criterion,
            "value": a.value,
            "min": a.min,
            "max": a.max,
            "align": a.align,
            "save_as": a.save_as,
            "force": a.force,
            "start": a.region.start,
            "size": a.region.size,
            "pid": a.region.pid,
            "file": a.region.file,
        }),
        pretty,
    )
}

fn cmd_scan_filter(a: ScanFilterArgs, pretty: bool) -> bool {
    run_capability(
        "scan.filter",
        json!({
            "from": a.from,
            "criterion": a.criterion,
            "value": a.value,
            "min": a.min,
            "max": a.max,
            "save_as": a.save_as,
            "force": a.force,
            "pid": a.pid,
            "file": a.file,
        }),
        pretty,
    )
}

fn cmd_scan_aob(a: ScanAobArgs, pretty: bool) -> bool {
    run_capability(
        "scan.aob",
        json!({
            "pattern": a.pattern,
            "start": a.start,
            "size": a.size,
            "pid": a.pid,
            "file": a.file,
        }),
        pretty,
    )
}

fn cmd_scan_group(a: ScanGroupArgs, pretty: bool) -> bool {
    run_capability(
        "scan.group",
        json!({
            "fields": a.field,
            "window": a.window,
            "align": a.align,
            "limit": a.limit,
            "start": a.region.start,
            "size": a.region.size,
            "pid": a.region.pid,
            "file": a.region.file,
        }),
        pretty,
    )
}

fn cmd_function_noreturn(a: FunctionNoreturnArgs, pretty: bool) -> bool {
    run_capability(
        "function.noreturn",
        json!({
            "pid": a.pid,
            "file": a.file,
            "bytes": a.bytes,
            "snapshot": a.snapshot,
            "remote_cmd": a.remote_cmd,
            "arch": a.arch,
            "start": a.start,
            "size": a.size,
            "limit": a.limit,
            "max_bytes": a.max_bytes,
        }),
        pretty,
    )
}

fn cmd_aot_symbols(a: AotSymbolsArgs, pretty: bool) -> bool {
    run_capability(
        "aot.symbols",
        json!({
            "file": a.file,
            "pid": a.pid,
            "module": a.module,
            "name": a.name,
            "rva": a.rva,
            "limit": a.limit,
        }),
        pretty,
    )
}

fn cmd_scan_dissect(a: ScanDissectArgs, pretty: bool) -> bool {
    run_capability(
        "scan.dissect",
        json!({ "start": a.start, "size": a.size, "pid": a.pid, "file": a.file }),
        pretty,
    )
}

fn cmd_pointer_path(a: PointerPathArgs, pretty: bool) -> bool {
    run_capability(
        "pointer.path",
        json!({
            "target": a.target,
            "modules": a.modules,
            "max_depth": a.max_depth,
            "max_offset": a.max_offset,
            "pid": a.pid,
        }),
        pretty,
    )
}

fn cmd_debug_watch(a: DebugWatchArgs, pretty: bool) -> bool {
    let addr = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
    {
        let _ = addr;
        ir_err("live-unsupported", "debug watch has no live adapter for this OS (Windows and Linux/Android are implemented)", pretty)
    }
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    {
        let live = match n0xis_frontend::source::attach_live(a.pid) {
            Ok(l) => l,
            Err((c, m)) => return ir_err(&c, &m, pretty),
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
        let cond = match a.when.as_deref().map(RegCond::parse).transpose() {
            Ok(c) => c,
            Err(e) => return ir_err("bad-when", &e, pretty),
        };
        // Parse `LO-HI` exclusion ranges, rebasing each end like the watch
        // address so `--addr-rva` makes both the address and the ranges RVAs.
        let mut exclude_rip: Vec<(u64, u64)> = Vec::with_capacity(a.exclude_rip.len());
        for spec in &a.exclude_rip {
            let Some((lo_s, hi_s)) = spec.split_once('-') else {
                return ir_err("bad-exclude-rip", &format!("expected LO-HI, got '{spec}'"), pretty);
            };
            let (lo, hi) = match (Va::parse(lo_s.trim()), Va::parse(hi_s.trim())) {
                (Ok(lo), Ok(hi)) => (lo.0, hi.0),
                _ => return ir_err("bad-exclude-rip", &format!("bad hex range '{spec}'"), pretty),
            };
            let (lo, hi) = if a.addr_rva {
                match &module {
                    Some(m) => (m.base.offset(lo).0, m.base.offset(hi).0),
                    None => return ir_err("no-module", "process has no enumerated main module for --addr-rva", pretty),
                }
            } else {
                (lo, hi)
            };
            if hi <= lo {
                return ir_err("bad-exclude-rip", &format!("range '{spec}' is empty (HI must exceed LO)"), pretty);
            }
            exclude_rip.push((lo, hi));
        }
        match await_watchpoint_hit_where(a.pid, watch_va, kind, a.len, a.timeout_ms, a.stack_qwords, module.as_ref(), &exclude_rip, cond.as_ref())
        {
            Ok(outcome) => emit(&Response::success(schema::v1::WATCHPOINT, outcome).with_source(label), pretty),
            Err(e) => ir_err("watch-failed", &e.to_string(), pretty),
        }
    }
}

fn cmd_debug_attach(a: DebugAttachArgs, pretty: bool) -> bool {
    #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
    {
        let _ = &a;
        ir_err("live-unsupported", "debug attach has no live adapter for this OS (Windows and Linux/Android are implemented)", pretty)
    }
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    match attach_and_wait(a.pid, a.timeout_ms) {
        Ok(()) => emit(
            &Response::success(schema::v1::DEBUG_ATTACH, json!({ "pid": a.pid, "timeout_ms": a.timeout_ms, "detached": true })),
            pretty,
        ),
        Err(e) => ir_err("attach-failed", &e.to_string(), pretty),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn cmd_stack_backtrace(a: StackBacktraceArgs, pretty: bool) -> bool {
    // `stack_unwind` resolves through the `Box<dyn LiveTarget>` directly, so the
    // trait need not be imported here.
    use n0xis_sources::{list_thread_ids, StoppedThread};

    #[derive(serde::Serialize)]
    struct BtFrame {
        rip: Va,
        #[serde(skip_serializing_if = "Option::is_none")]
        module: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rva: Option<Va>,
        #[serde(skip_serializing_if = "Option::is_none")]
        symbol: Option<String>,
    }
    #[derive(serde::Serialize)]
    struct BtThread {
        tid: u32,
        rip: Va,
        frame_count: usize,
        frames: Vec<BtFrame>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    }
    #[derive(serde::Serialize)]
    struct BtOut {
        pid: u32,
        thread_count: usize,
        threads: Vec<BtThread>,
    }

    let tids = match (a.tid, a.all_threads) {
        (Some(t), _) => vec![t],
        (None, true) => list_thread_ids(a.pid),
        (None, false) => vec![a.pid],
    };
    if tids.is_empty() {
        return ir_err("no-threads", &format!("no threads found for pid {} (process gone or /proc unreadable)", a.pid), pretty);
    }

    let live = match n0xis_frontend::source::attach_live(a.pid) {
        Ok(l) => l,
        Err((c, m)) => return ir_err(&c, &m, pretty),
    };
    let label = live.label();

    let mut threads = Vec::new();
    for tid in tids {
        // Hold the thread stopped across BOTH the register read and the stack
        // walk, so the frames are coherent; the guard resumes it on drop.
        let result = StoppedThread::attach(tid).and_then(|stop| {
            let regs = stop.registers()?;
            let frames = live.stack_unwind(regs, a.max);
            Ok((regs.rip, frames))
        });
        match result {
            Ok((rip, frames)) => {
                let frames = frames
                    .into_iter()
                    .map(|f| BtFrame { rip: Va(f.rip), module: f.module, rva: f.rva.map(|v| Va(v as u64)), symbol: f.symbol })
                    .collect::<Vec<_>>();
                threads.push(BtThread { tid, rip: Va(rip), frame_count: frames.len(), frames, error: None });
            }
            Err(e) => {
                threads.push(BtThread { tid, rip: Va(0), frame_count: 0, frames: Vec::new(), error: Some(e.to_string()) });
            }
        }
    }

    let out = BtOut { pid: a.pid, thread_count: threads.len(), threads };
    emit(&Response::success(schema::v1::STACK_BACKTRACE, out).with_source(label), pretty)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn cmd_stack_backtrace(a: StackBacktraceArgs, pretty: bool) -> bool {
    let _ = &a;
    ir_err(
        "live-unsupported",
        "stack backtrace currently needs the Linux ptrace register-capture path; on Windows use `debug watch` / `debug await-hit`, which already return frames",
        pretty,
    )
}

/// The ROADMAP Phase 4c loop, in one command: arm a hardware
/// watchpoint on a value's address (Phase 4b), and on a hit, explain it —
/// resolved module/function, decompiled statement (Phase 3's SSA
/// decompiler) — then optionally record that explanation onto a `.n0xt`
/// entry ("record with provenance", CONCEPT §10/§11).
fn cmd_provenance_trace(a: ProvenanceTraceArgs, pretty: bool) -> bool {
    let addr = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
    {
        let _ = addr;
        ir_err("live-unsupported", "provenance trace has no live adapter for this OS (Windows and Linux/Android are implemented)", pretty)
    }
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    {
        let live = match n0xis_frontend::source::attach_live(a.pid) {
            Ok(l) => l,
            Err((c, m)) => return ir_err(&c, &m, pretty),
        };
        let main_module = live.main_module().cloned();
        let label = live.label();
        drop(live);

        let addr = if a.addr_rva {
            match &main_module {
                Some(m) => m.base.offset(addr.0),
                None => return ir_err("no-module", "process has no enumerated main module for --addr-rva", pretty),
            }
        } else {
            addr
        };
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
        let live = match n0xis_frontend::source::attach_live(a.pid) {
            Ok(l) => l,
            Err((c, m)) => return ir_err(&c, &m, pretty),
        };
        let insn_module = live.modules().iter().find(|m| m.contains(hit.rip)).cloned();
        let arch = match resolve_arch(a.arch.as_deref()) {
            Ok(x) => x,
            Err(e) => return ir_err("bad-arch", &e, pretty),
        };
        // Upcast the live target to the byte-source `Ctx` wants; the decompiler
        // never learns it is a Linux `/proc` process vs a Win32 handle.
        let source: &dyn MemorySource = &*live;
        let ctx = Ctx::new(source, arch.as_ref());

        let access_kind = match a.kind {
            WatchKindArg::Execute => "execute",
            WatchKindArg::Write => "write",
            WatchKindArg::ReadOrWrite => "read-or-write",
        };
        // The code window the static half of provenance searches for the function
        // containing the hit. `.text` from section headers is the precise answer,
        // but it is not always reachable — a stripped ELF, or a module whose
        // headers aren't mapped — and `section_range_of` has no fallback, so it
        // returned `None` and the whole chain (containing function -> decompiled
        // statement) was skipped, degrading the answer to a bare address — which
        // is the whole result this command exists to add to.
        // `code_ranges_of` already falls back to the module's executable mappings,
        // so use it and take the range that actually contains the instruction.
        let code_ranges = insn_module.as_ref().map(|m| live.code_ranges_of(m.base)).unwrap_or_default();
        let (code_scan_start, code_scan_size) = code_ranges
            .iter()
            .find(|(start, size)| hit.rip.get() >= start.get() && hit.rip.get() < start.get().saturating_add(*size))
            .or_else(|| code_ranges.first())
            .map(|(start, size)| (Some(*start), *size as usize))
            .unwrap_or((None, 0));
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
}

// ============================================================================
// Analysis DB: names/types/comments as versioned truth (CONCEPT/ROADMAP Phase 6)
// ============================================================================

fn cmd_annotate_set(field: &str, a: AnnotateSetArgs, pretty: bool) -> bool {
    run_capability("annotate.set", json!({ "field": field, "addr": a.addr, "value": a.value }), pretty)
}

fn annotate_var_json(a: &AnnotateVarArgs) -> serde_json::Value {
    json!({
        "addr": a.addr, "var": a.var, "value": a.value,
        "file": a.file, "pid": a.pid, "snapshot": a.snapshot, "remote_cmd": a.remote_cmd, "arch": a.arch,
    })
}

fn cmd_annotate_var(a: AnnotateVarArgs, pretty: bool) -> bool {
    run_capability("annotate.var", annotate_var_json(&a), pretty)
}

fn cmd_annotate_vartype(a: AnnotateVarArgs, pretty: bool) -> bool {
    run_capability("annotate.vartype", annotate_var_json(&a), pretty)
}

fn cmd_annotate_bookmark(a: AnnotateBookmarkArgs, pretty: bool) -> bool {
    run_capability("annotate.bookmark", json!({ "addr": a.addr, "on": !a.off }), pretty)
}

fn cmd_annotate_show(a: AnnotateShowArgs, pretty: bool) -> bool {
    run_capability("annotate.show", json!({ "addr": a.addr }), pretty)
}

fn cmd_annotate_list(pretty: bool) -> bool {
    run_capability("annotate.list", json!({}), pretty)
}

fn cmd_annotate_rm(a: AnnotateShowArgs, pretty: bool) -> bool {
    run_capability("annotate.rm", json!({ "addr": a.addr }), pretty)
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
/// Serve this machine's live process to a driver on the other end of stdio.
///
/// Now that a Linux/Android adapter exists, this direction matters as much as
/// the one it was written for: a Linux box can be the *target* an operator
/// drives from elsewhere (`--remote-cmd "ssh box n0xis remote-serve --pid N"`),
/// and the same path is how an Android device is reached over `adb`.
/// The request forms a `serve` session reads, announced in its ready banner so
/// a client learns them from the server instead of assuming them.
const SERVE_REQUEST_FORMATS: [&str; 2] = ["text", "json-argv"];

/// One session request line → argv. A line that opens with `[` is a JSON array
/// of strings (`json-argv`), which carries every argument exactly. The text form
/// has no escape: `"` only toggles quoting and a newline ends the request, so an
/// argument holding either cannot be written in it at all.
fn serve_request_tokens(line: &str) -> Result<Vec<String>, String> {
    if line.starts_with('[') {
        serde_json::from_str::<Vec<String>>(line)
            .map_err(|e| format!("a request starting with `[` must be a JSON array of strings: {e}"))
    } else {
        n0xis_sources::split_command_line(line)
    }
}

/// Set by [`cmd_serve`] before it reads its first request, and never cleared:
/// for the rest of the process stdin is the session's request channel.
static STDIN_IS_SESSION_CHANNEL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The error code a command answers with when it would read stdin inside a
/// `serve` session.
const STDIN_IS_SESSION_CODE: &str = "stdin-is-session-channel";

/// Why a command may not read its stdin: inside a session it carries requests.
struct StdinIsSessionChannel;

impl std::fmt::Display for StdinIsSessionChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("inside a `serve` session stdin carries the session's requests, so it cannot be read as input")
    }
}

/// The only way a command reaches its own stdin.
///
/// Inside a `serve` session stdin is the request channel, and the session
/// holds its lock while a request runs. A command reading stdin there waits on
/// that lock forever: measured with `dump save` and no payload, the session
/// answered neither that request nor any after it, and stored nothing. Even
/// unlocked, what it read would be the session's next requests. So the read is
/// refused, and the command answers with an error naming what to pass
/// instead. Every stdin reader goes through here; the `stdin_has_one_gate`
/// test fails on one that does not.
fn command_stdin() -> Result<std::io::Stdin, StdinIsSessionChannel> {
    if STDIN_IS_SESSION_CHANNEL.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(StdinIsSessionChannel);
    }
    Ok(std::io::stdin())
}

/// The argument ids that make a request name its own source: a session adds its
/// `--file` only to a request that names none of these (and whose leaf takes a
/// `file` at all — see [`serve_leaf_takes_file`]).
///
/// Ids, not flag spellings. The spelling `--bytes` is a source in `disasm`,
/// `ir` or `xref` and data in `find` (a pattern) and `mem write`/`patch` (a
/// payload); a token list could not tell them apart, so `find --bytes …` in a
/// session was dispatched without the session's file and searched whatever
/// the project default named. Those data arguments carry ids of their own, so
/// the one question — "is this a source?" — has one answer, clap's.
const SERVE_SOURCE_IDS: [&str; 5] = ["file", "pid", "snapshot", "remote_cmd", "bytes"];

/// The deepest subcommand's matches: where a request's own arguments live.
fn serve_leaf(matches: &clap::ArgMatches) -> &clap::ArgMatches {
    let mut leaf = matches;
    while let Some((_, sub)) = leaf.subcommand() {
        leaf = sub;
    }
    leaf
}

/// Whether a request's leaf subcommand takes the session's image: it defines
/// an argument with the source id `file`. A session adds its `--file` to such
/// a request, and to no other.
///
/// Asked of the id, not of the spelling `--file`: `dump save --file` is the
/// file to store, so it lives under an id of its own, and a request that only
/// *accepts* a `--file` no longer has the session image put in it. Before
/// this, the session's `--file` was appended to any request naming no source
/// and kept wherever it parsed — and in `dump save` it parsed as the payload.
///
/// The leaf's *definition* is asked — clap's command tree, walked by the
/// subcommand names the line parsed to — not its matches. `ArgMatches` only
/// knows which ids a leaf defines in a debug build: clap's unknown-id check is
/// compiled under `debug_assertions`, and a release build answers `Ok(None)`
/// for any id at all. A first version asked the matches, passed every test (a
/// debug build), and in the release binary put the session image back into
/// `dump save`.
fn serve_leaf_takes_file(matches: &clap::ArgMatches) -> bool {
    let root = <Cli as clap::CommandFactory>::command();
    let mut cmd = &root;
    let mut m = matches;
    while let Some((name, sub)) = m.subcommand() {
        let Some(next) = cmd.find_subcommand(name) else { return false };
        cmd = next;
        m = sub;
    }
    cmd.get_arguments().any(|arg| arg.get_id() == "file")
}

/// Whether a parsed request line names its own source: one of
/// [`SERVE_SOURCE_IDS`] given on the command line of its leaf subcommand.
fn serve_names_source(matches: &clap::ArgMatches) -> bool {
    let leaf = serve_leaf(matches);
    SERVE_SOURCE_IDS.iter().any(|id| {
        // `try_get_raw` first: in a debug build it answers `Err` for an id this
        // leaf does not define, where `value_source` would panic (a release
        // build answers `Ok(None)` and does not panic — either way the id is
        // not counted). Then only a value the caller typed counts — a default
        // is not the caller naming a source.
        matches!(leaf.try_get_raw(id), Ok(Some(_))) && leaf.value_source(id) == Some(clap::parser::ValueSource::CommandLine)
    })
}

/// Persistent static session (see `Command::Serve`). Loads `--file` once to prime
/// the resident image cache, then reads one command line per stdin line and
/// dispatches it — the image is reused, so repeated calls skip the file re-load.
fn cmd_serve(a: &ServeArgs) {
    use std::io::{BufRead, Write};
    // From here on stdin is the request channel; no command may read it.
    STDIN_IS_SESSION_CHANNEL.store(true, std::sync::atomic::Ordering::SeqCst);
    let spec = SourceSpec { file: Some(a.file.as_str()), ..Default::default() };
    let ready = match n0xis_frontend::source::resolve(spec) {
        Ok(r) => serde_json::json!({
            "ok": true,
            "data": { "ready": true, "label": r.label, "request_formats": SERVE_REQUEST_FORMATS },
            // Every response carries a schema; the banner is a response.
            "meta": { "schema": schema::v1::SERVE_READY, "tool": "n0xis", "tool_version": env!("CARGO_PKG_VERSION") },
        }),
        Err(e) => serde_json::json!({ "ok": false, "error": { "code": e.0, "message": e.1 } }),
    };
    println!("{ready}");
    let _ = std::io::stdout().flush();

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        let emit_err = |code: &str, msg: String| {
            println!("{}", serde_json::json!({ "ok": false, "error": { "code": code, "message": msg } }));
            let _ = std::io::stdout().flush();
        };
        let tokens = match serve_request_tokens(line) {
            Ok(t) => t,
            Err(e) => {
                emit_err("bad-command", e);
                continue;
            }
        };
        // The session's whole promise is "load `--file` once, then send
        // commands" — but each line was parsed and dispatched on its own, so a
        // line that named no source got `missing-source` and the caller had to
        // repeat `--file` on every one. Supply it here when the line names no
        // source of its own; an explicit one on the line still wins.
        //
        // Both questions are clap's, asked by argument id. Does the line name
        // a source (`serve_names_source`)? And does its leaf subcommand take
        // the session's image at all — define the source id `file`
        // (`serve_leaf_takes_file`)? Only a line that names none and takes one
        // gets the session's `--file`. A `--file` that is data under another
        // id (`dump save`'s payload) is never filled in with the image.
        //
        // The leaf is read from the bare line; when that does not parse (a
        // command whose `--file` is required), from the augmented one, which
        // still has to define `file` to be used. A parse error is reported
        // from the bare line, so the message never mentions a flag the caller
        // did not type.
        let bare: Vec<String> = std::iter::once("n0xis".to_string()).chain(tokens.iter().cloned()).collect();
        let augmented: Vec<String> = bare.iter().cloned().chain(["--file".to_string(), a.file.clone()]).collect();
        let cli = <Cli as clap::CommandFactory>::command();
        // The spelling is the line's own, read from the bare tokens: the
        // `--file` the session may append sits after the leaf and cannot change
        // the path. A renamed command answers per spelling (see `Renamed`).
        let typed = typed_path(&cli, &bare);
        let bare_matches = cli.clone().try_get_matches_from(&bare);
        let names_source = bare_matches.as_ref().is_ok_and(serve_names_source);
        let takes_file = !names_source
            && match &bare_matches {
                Ok(m) => serve_leaf_takes_file(m),
                Err(_) => cli.try_get_matches_from(&augmented).is_ok_and(|m| serve_leaf_takes_file(&m)),
            };
        let parsed = if takes_file {
            Cli::try_parse_from(&augmented).or_else(|_| Cli::try_parse_from(&bare))
        } else {
            Cli::try_parse_from(&bare)
        };
        match parsed {
            Ok(cli) => match cli.command {
                // guard against re-entrancy / another server on the same channel
                Command::Serve(_) | Command::RemoteServe(_) => emit_err("unsupported", "serve/remote-serve not allowed inside a session".into()),
                cmd => {
                    // force compact output so every response is exactly one line;
                    // suppress [n0x] progress so it can't interleave a session line
                    let _ = dispatch(cmd, &typed, false, true);
                }
            },
            Err(e) => emit_err("parse-error", e.to_string()),
        }
        let _ = std::io::stdout().flush();
    }
}

fn cmd_remote_serve(a: &RemoteServeArgs) {
    let live = match n0xis_frontend::source::attach_live(a.pid) {
        Ok(l) => l,
        Err((c, m)) => {
            eprintln!("[n0xis] remote-serve: {c}: {m}");
            std::process::exit(2);
        }
    };
    if let Err(e) = remote_serve_stdio(live.as_ref(), std::io::stdin(), std::io::stdout()) {
        eprintln!("[n0xis] remote-serve: {e}");
        std::process::exit(2);
    }
}

fn patch_detour(a: PatchDetourArgs, pretty: bool) -> bool {
    let hook_at = match Va::parse(&a.hook_at) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    #[cfg(not(windows))]
    {
        let _ = hook_at;
        ir_err("live-unsupported", "patch detour requires a Windows build (needs LiveProcess/Win32 APIs)", pretty)
    }
    #[cfg(windows)]
    {
        use n0xis_project::patch as pj;

        let live = match LiveProcess::attach(a.pid) {
            Ok(l) => l,
            Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
        };

        // Decode whole instructions until we've covered >= 5 bytes (a near jmp),
        // so the hook never splits an instruction mid-way.
        let arch = match resolve_arch(a.arch.as_deref()) {
            Ok(x) => x,
            Err(e) => return ir_err("bad-arch", &e, pretty),
        };
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

        // The cave has to be within a near jump's ±2 GB of the hook site, and
        // letting the OS pick never satisfied that on a 64-bit Windows image —
        // measured 29 GB apart, so every detour on an ordinary target was
        // refused. Ask for it near the hook.
        let cave = match live.alloc_code_cave_near(hook_at, a.cave_size) {
            Ok(c) => c,
            Err(e) => return ir_err("alloc-failed", &e.to_string(), pretty),
        };
        let (cave_bytes, hook_jmp) = match build_trampoline(arch.as_ref(), &original, hook_at, cave) {
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
}

// ============================================================================
// `.n0xt` tables (CONCEPT §10)
// ============================================================================

fn cmd_table_add(a: TableAddArgs, pretty: bool) -> bool {
    run_capability(
        "table.add",
        json!({
            "table": a.table,
            "name": a.name,
            "addr": a.addr,
            "type": scan_type_name(a.r#type),
            "description": a.description,
        }),
        pretty,
    )
}

fn cmd_table_list(a: TableListArgs, pretty: bool) -> bool {
    run_capability("table.list", json!({ "table": a.table }), pretty)
}

fn cmd_table_show(a: TableShowArgs, pretty: bool) -> bool {
    run_capability("table.show", json!({ "table": a.table, "name": a.name }), pretty)
}

fn cmd_table_rm(a: TableShowArgs, pretty: bool) -> bool {
    run_capability("table.rm", json!({ "table": a.table, "name": a.name }), pretty)
}

fn cmd_table_pin(a: TablePinArgs, spelled: Spelled, pretty: bool) -> bool {
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
    let bytes = match entry.value_type.encode_value(value) {
        Ok(b) => b,
        Err(e) => return ir_err("bad-value", &e, pretty),
    };
    #[cfg(not(windows))]
    {
        let _ = &bytes;
        let msg = format!("{} requires a Windows build (needs LiveProcess/Win32 APIs)", TABLE_PIN.path(spelled));
        ir_err("live-unsupported", &msg, pretty)
    }
    #[cfg(windows)]
    {
        let live = match LiveProcess::attach(a.pid) {
            Ok(l) => l,
            Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
        };

        let addr = match n0xis_project::locator::resolve_table_locator(&live, &entry.locator) {
            Ok(va) => va,
            Err(e) => return ir_err("resolve-failed", &e, pretty),
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
        emit(&Response::success(TABLE_PIN.schema(spelled), data).with_source(live.label()), pretty)
    }
}

/// Parse a hex byte string: accepts spaces, commas and `0x` prefixes, e.g.
/// `"48 89 c8"`, `"4889c8"`, or `"0x48,0x89,0xc8"`.
/// Read a bundle file plus its paired `.stream` companion (if present) and
/// parse it — shared by `bundle list`/`bundle extract`.
fn load_bundle(file: &str, stream: Option<&str>) -> Result<n0xis_bitsquid::ExplodedPackage, String> {
    let bytes = std::fs::read(file).map_err(|e| format!("read {file}: {e}"))?;
    let stream_path = stream.map(str::to_string).unwrap_or_else(|| format!("{file}.stream"));
    let stream_bytes = std::fs::read(&stream_path).ok();
    open_bundle(&bytes, stream_bytes.as_deref()).map_err(|e| e.to_string())
}

fn cmd_bundle_list(a: BundleListArgs, pretty: bool) -> bool {
    let pkg = match load_bundle(&a.file, a.stream.as_deref()) {
        Ok(p) => p,
        Err(e) => return ir_err("bundle-load-failed", &e, pretty),
    };
    let entries: Vec<_> = pkg
        .entries
        .iter()
        .filter(|e| a.r#type.as_deref().is_none_or(|t| e.type_name == Some(t)))
        .map(|e| {
            json!({
                "type_hash": format!("{:016x}", e.type_hash),
                "type_name": e.type_name,
                "path_hash": format!("{:016x}", e.path_hash),
                "variants": e.variants.iter().map(|v| json!({
                    "inline_size": v.inline_size,
                    "stream_size": v.stream_size,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let data = json!({ "count": entries.len(), "entries": entries });
    emit(&Response::success(schema::v1::BUNDLE_LIST, data).with_source(a.file), pretty)
}

fn cmd_bundle_extract(a: BundleExtractArgs, pretty: bool) -> bool {
    let pkg = match load_bundle(&a.file, a.stream.as_deref()) {
        Ok(p) => p,
        Err(e) => return ir_err("bundle-load-failed", &e, pretty),
    };
    let bundle_stem = std::path::Path::new(&a.file).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "bundle".to_string());
    let out_dir = a.out.clone().unwrap_or_else(|| format!("{bundle_stem}_{}", a.r#type));
    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        return ir_err("mkdir-failed", &format!("create {out_dir}: {e}"), pretty);
    }

    let mut extracted = Vec::new();
    for entry in pkg.entries.iter().filter(|e| e.type_name == Some(a.r#type.as_str())) {
        for (vi, variant) in entry.variants.iter().enumerate() {
            let (bytes, format, ext) = if a.r#type == "lua" {
                match lua_resource(variant) {
                    Some(lr) => {
                        let ext = match lr.format {
                            LuaFormat::Source => "lua",
                            LuaFormat::GenericBytecode | LuaFormat::LuaJit2 => "luac",
                            LuaFormat::Bad(_) => "bin",
                        };
                        (lr.data, Some(format!("{:?}", lr.format)), ext)
                    }
                    None => (variant.inline_data.clone(), None, "bin"),
                }
            } else {
                (variant.inline_data.clone(), None, "bin")
            };
            // One file per variant. The name used to be the path hash alone,
            // so every variant of an entry wrote to the same path and only the
            // last survived — while the count reported one extraction per
            // variant. The command said it had written files it had not.
            // A single-variant entry keeps the old name, so nothing that
            // already works moves.
            let out_path = if entry.variants.len() > 1 {
                format!("{out_dir}/{:016x}.v{vi}.{ext}", entry.path_hash)
            } else {
                format!("{out_dir}/{:016x}.{ext}", entry.path_hash)
            };
            if let Err(e) = std::fs::write(&out_path, &bytes) {
                return ir_err("write-failed", &format!("write {out_path}: {e}"), pretty);
            }
            extracted.push(json!({
                "path_hash": format!("{:016x}", entry.path_hash),
                "variant": vi,
                "out_path": out_path,
                "size": bytes.len(),
                "format": format,
            }));
        }
    }
    // `files` is what is on disk; `count` stays the number of variants written
    // so the two can never silently be assumed equal again.
    let files: std::collections::BTreeSet<&str> =
        extracted.iter().filter_map(|e| e.get("out_path").and_then(|p| p.as_str())).collect();
    let data = json!({ "count": extracted.len(), "files": files.len(), "out_dir": out_dir, "extracted": extracted });
    emit(&Response::success(schema::v1::BUNDLE_EXTRACT, data).with_source(a.file), pretty)
}

fn cmd_lua_disasm(a: LuaDisasmArgs, pretty: bool) -> bool {
    let bytes = match std::fs::read(&a.file) {
        Ok(b) => b,
        Err(e) => return ir_err("read-failed", &format!("read {}: {e}", a.file), pretty),
    };
    match n0xis_lua::disassemble(&bytes) {
        Ok(chunk) => emit(&Response::success(schema::v1::LUA_DISASM, chunk).with_source(a.file), pretty),
        Err(e) => ir_err("lua-disasm-failed", &e.to_string(), pretty),
    }
}

fn cmd_lua_patch(a: LuaPatchArgs, pretty: bool) -> bool {
    let bytes = match std::fs::read(&a.file) {
        Ok(b) => b,
        Err(e) => return ir_err("read-failed", &format!("read {}: {e}", a.file), pretty),
    };
    let raw_str = a.raw.strip_prefix("0x").unwrap_or(&a.raw);
    let raw = match u32::from_str_radix(raw_str, 16) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-raw", &format!("invalid hex u32 {:?}: {e}", a.raw), pretty),
    };
    let patched = match n0xis_lua::patch_instruction(&bytes, a.proto, a.instr, raw) {
        Ok(p) => p,
        Err(e) => return ir_err("patch-failed", &e.to_string(), pretty),
    };
    if let Err(e) = std::fs::write(&a.out, &patched) {
        return ir_err("write-failed", &format!("write {}: {e}", a.out), pretty);
    }
    let data = json!({ "out": a.out, "size": patched.len(), "proto": a.proto, "instr": a.instr, "raw": format!("0x{raw:08x}") });
    emit(&Response::success(schema::v1::LUA_DISASM, data).with_source(a.file), pretty)
}

fn cmd_lua_strings(a: LuaStringsArgs, pretty: bool) -> bool {
    // No cfg pair any more: `n0xis-luajit` reads through `MemorySource`, so it
    // never knew which OS it was on — only the attach did, and that is now the
    // seam's job.
    {
        let live = match n0xis_frontend::source::attach_live(a.pid) {
            Ok(l) => l,
            Err((c, m)) => return ir_err(&c, &m, pretty),
        };
        let regions = match resolve_scan_regions_live(live.as_ref(), a.start.as_deref(), a.size) {
            Ok(r) => r,
            Err(e) => return ir_err("bad-region", &e, pretty),
        };
        let label = live.label();
        let mut hits = n0xis_luajit::scan_strings(live.as_ref(), &regions, gcstr_layout(a.gcstr_len_off), a.min_len, a.max_len);
        if let Some(needle) = &a.contains {
            hits.retain(|h| h.text.contains(needle.as_str()));
        }
        let data = json!({ "matches": hits, "count": hits.len() });
        emit(&Response::success(schema::v1::LUA_STRINGS, data).with_source(label), pretty)
    }
}

/// Render one decoded `TValue` as JSON, resolving a string's text from the
/// live process so the dump is readable (`{"kind":"str","text":"up"}`) rather
/// than just an address to chase by hand.
/// The `GCstr` header layout to read a live LuaJIT heap with: the calibrated
/// Bitsquid-bundle default, or the operator's own offset for another build.
fn gcstr_layout(len_off: Option<usize>) -> n0xis_luajit::GcstrLayout {
    match len_off {
        Some(off) => n0xis_luajit::GcstrLayout { len_offset: off as u64 },
        None => n0xis_luajit::GcstrLayout::BITSQUID_GC64,
    }
}

fn tvalue_json(v: &n0xis_luajit::TValue, live: &dyn n0xis_sources::MemorySource, layout: n0xis_luajit::LuaLayout) -> serde_json::Value {
    use n0xis_luajit::TValue;
    match v {
        TValue::Nil => json!({ "kind": "nil" }),
        TValue::Bool(b) => json!({ "kind": "bool", "value": b }),
        TValue::Num(n) => json!({ "kind": "num", "value": n }),
        TValue::Str { addr } => {
            let text = n0xis_luajit::read_gcstr(live, *addr, layout);
            json!({ "kind": "str", "addr": addr.to_string(), "text": text })
        }
        TValue::Tab { addr } => json!({ "kind": "tab", "addr": addr.to_string() }),
        TValue::Func { addr } => json!({ "kind": "func", "addr": addr.to_string() }),
        TValue::Other { itype, ptr } => json!({ "kind": "other", "itype": format!("0x{itype:x}"), "ptr": format!("0x{ptr:x}") }),
    }
}

fn cmd_lua_table(a: LuaTableArgs, pretty: bool) -> bool {
    let addr = match Va::parse(&a.addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    {
        let live = match n0xis_frontend::source::attach_live(a.pid) {
            Ok(l) => l,
            Err((c, m)) => return ir_err(&c, &m, pretty),
        };
        let mut layout = n0xis_luajit::LuaLayout::BITSQUID_LUAJIT;
        if let Some(off) = a.gcstr_len_off {
            layout.gcstr_len_off = off as u64;
        }
        let Some(dump) = n0xis_luajit::read_table(live.as_ref(), addr, layout) else {
            return ir_err("not-a-table", "could not decode a GCtab at this address (wrong address or layout needs calibration)", pretty);
        };
        let array: Vec<serde_json::Value> = dump.array.iter().map(|v| tvalue_json(v, live.as_ref(), layout)).collect();
        let hash: Vec<serde_json::Value> = dump
            .hash
            .iter()
            .map(|(k, v)| json!({ "key": tvalue_json(k, live.as_ref(), layout), "value": tvalue_json(v, live.as_ref(), layout) }))
            .collect();
        let label = live.label();
        let data = json!({
            "addr": dump.addr.to_string(),
            "asize": dump.asize,
            "hmask": dump.hmask,
            "array": array,
            "hash": hash,
        });
        emit(&Response::success(schema::v1::LUA_TABLE, data).with_source(label), pretty)
    }
}

fn cmd_lua_combo(a: LuaComboArgs, pretty: bool) -> bool {
    {
        let live = match n0xis_frontend::source::attach_live(a.pid) {
            Ok(l) => l,
            Err((c, m)) => return ir_err(&c, &m, pretty),
        };
        let regions = match resolve_scan_regions_live(live.as_ref(), a.start.as_deref(), a.size) {
            Ok(r) => r,
            Err(e) => return ir_err("bad-region", &e, pretty),
        };
        let wanted: Vec<String> = a.strings.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        if wanted.is_empty() {
            return ir_err("no-strings", "--strings must list at least one token", pretty);
        }
        let layout = gcstr_layout(a.gcstr_len_off);
        // Longest token bounds the GCstr scan; the wanted tokens are short ASCII.
        let max_len = wanted.iter().map(|s| s.len()).max().unwrap_or(0) as u32;
        // Every candidate GCstr whose text is one of the wanted tokens becomes a
        // target address — the run cross-check discards any that aren't referenced.
        let strs = n0xis_luajit::scan_strings(live.as_ref(), &regions, layout, 1, max_len.max(1));
        let mut targets: std::collections::HashMap<Va, String> = std::collections::HashMap::new();
        for s in &strs {
            if wanted.iter().any(|w| w == &s.text) {
                targets.insert(s.object_base, s.text.clone());
            }
        }
        if targets.is_empty() {
            let data = json!({ "runs": [], "count": 0, "note": "none of the target strings were found as GCstr objects in the scanned regions" });
            return emit(&Response::success(schema::v1::LUA_COMBO, data).with_source(live.label()), pretty);
        }
        // A token array may be laid out as 8-byte Lua `TValue`s or as a packed
        // 4-byte `GCRef` array (Bitsquid's `array`); scan for both and tag which.
        let mut runs_json: Vec<serde_json::Value> = Vec::new();
        let tv = n0xis_luajit::find_string_runs(live.as_ref(), &regions, &targets, a.min_run);
        for r in &tv {
            runs_json.push(json!({ "addr": r.addr.to_string(), "kind": "tvalue8", "len": r.values.len(), "values": r.values }));
        }
        let gr = n0xis_luajit::find_gcref32_runs(live.as_ref(), &regions, &targets, a.min_run);
        for r in &gr {
            runs_json.push(json!({ "addr": r.addr.to_string(), "kind": "gcref4", "len": r.values.len(), "values": r.values }));
        }
        let count = tv.len() + gr.len();
        let label = live.label();
        let data = json!({
            "targets": targets.iter().map(|(a, t)| json!({ "addr": a.to_string(), "text": t })).collect::<Vec<_>>(),
            "runs": runs_json,
            "count": count,
        });
        emit(&Response::success(schema::v1::LUA_COMBO, data).with_source(label), pretty)
    }
}

/// `random(0,3)` direction codes, from the target script's direction randomizer:
/// `0=left, 1=up, 2=right, 3=down`.
fn dir_to_code(d: &str) -> Option<u32> {
    match d.trim() {
        "left" => Some(0),
        "up" => Some(1),
        "right" => Some(2),
        "down" => Some(3),
        _ => None,
    }
}

fn cmd_lua_seedscan(a: LuaSeedscanArgs, pretty: bool) -> bool {
    let target: Result<Vec<u32>, String> = a
        .combo
        .split(',')
        .map(|d| dir_to_code(d).ok_or_else(|| format!("unknown direction '{}'; use up/down/left/right", d.trim())))
        .collect();
    let target = match target {
        Ok(t) if !t.is_empty() => t,
        Ok(_) => return ir_err("empty-combo", "--combo must list at least one direction", pretty),
        Err(e) => return ir_err("bad-combo", &e, pretty),
    };
    {
        let live = match n0xis_frontend::source::attach_live(a.pid) {
            Ok(l) => l,
            Err((c, m)) => return ir_err(&c, &m, pretty),
        };
        let regions = match resolve_scan_regions_live(live.as_ref(), a.start.as_deref(), a.size) {
            Ok(r) => r,
            Err(e) => return ir_err("bad-region", &e, pretty),
        };
        let lcg = n0xis_luajit::Lcg { a: a.lcg_a, c: a.lcg_c };
        let bounds = if a.seed_bound { Some((1u32, 0x7FFF_FFFEu32)) } else { None };
        let hits = n0xis_luajit::find_seeds(live.as_ref(), &regions, &lcg, a.range, &target, bounds);
        let label = live.label();
        let data = json!({
            "combo": a.combo,
            "codes": target,
            "lcg": { "a": a.lcg_a, "c": a.lcg_c, "range": a.range },
            "seed_bounded": a.seed_bound,
            "count": hits.len(),
            "hits": hits.iter().map(|h| json!({ "addr": h.addr.to_string(), "seed": h.seed })).collect::<Vec<_>>(),
        });
        emit(&Response::success(schema::v1::LUA_SEEDSCAN, data).with_source(label), pretty)
    }
}

fn cmd_bundle_repack(a: BundleRepackArgs, pretty: bool) -> bool {
    let bytes = match std::fs::read(&a.file) {
        Ok(b) => b,
        Err(e) => return ir_err("read-failed", &format!("read {}: {e}", a.file), pretty),
    };
    let decompressed = match n0xis_bitsquid::decompress_archive(&bytes) {
        Ok(d) => d,
        Err(e) => return ir_err("decompress-failed", &e.to_string(), pretty),
    };
    let stream_path = a.stream.clone().unwrap_or_else(|| format!("{}.stream", a.file));
    let stream_bytes = std::fs::read(&stream_path).ok();
    let pkg = match n0xis_bitsquid::parse_exploded_package(&decompressed, stream_bytes.as_deref()) {
        Ok(p) => p,
        Err(e) => return ir_err("parse-failed", &e.to_string(), pretty),
    };

    let target_hash = match u64::from_str_radix(a.path_hash.trim_start_matches("0x"), 16) {
        Ok(h) => h,
        Err(e) => return ir_err("bad-path-hash", &format!("invalid hex path_hash {:?}: {e}", a.path_hash), pretty),
    };
    let Some(entry) = pkg.entries.iter().find(|e| e.path_hash == target_hash) else {
        return ir_err("no-such-entry", &format!("no entry with path_hash {:016x} in this bundle", target_hash), pretty);
    };
    let Some(variant) = entry.variants.get(a.variant) else {
        return ir_err("no-such-variant", &format!("entry {:016x} has no variant {}", target_hash, a.variant), pretty);
    };

    let replacement = match std::fs::read(&a.replacement_file) {
        Ok(r) => r,
        Err(e) => return ir_err("read-failed", &format!("read {}: {e}", a.replacement_file), pretty),
    };
    if replacement.len() != variant.inline_data.len() {
        return ir_err(
            "length-mismatch",
            &format!("replacement is {} bytes, original variant inline data is {} bytes — repack only supports same-length replacement", replacement.len(), variant.inline_data.len()),
            pretty,
        );
    }

    let new_archive = match n0xis_bitsquid::patch_and_recompress(&decompressed, variant.inline_data_offset, &replacement) {
        Ok(a) => a,
        Err(e) => return ir_err("repack-failed", &e.to_string(), pretty),
    };
    if let Err(e) = std::fs::write(&a.out, &new_archive) {
        return ir_err("write-failed", &format!("write {}: {e}", a.out), pretty);
    }
    let data = json!({
        "out": a.out,
        "size": new_archive.len(),
        "path_hash": format!("{:016x}", target_hash),
        "variant": a.variant,
        "patched_bytes": replacement.len(),
    });
    emit(&Response::success(schema::v1::BUNDLE_EXTRACT, data).with_source(a.file), pretty)
}

// ============================================================================
// Phase 8 — spec-first method tooling
// ============================================================================

/// Split a `<concept>` argument into vocabulary terms on commas, `|`, or
/// whitespace — so `"retry,backoff|timeout"` and `"retry backoff"` both work.
fn split_concept(raw: &str) -> Vec<String> {
    raw.split(|c: char| c == ',' || c == '|' || c.is_whitespace())
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Flatten a decoded LuaJIT chunk into searchable text: its name, every string
/// constant, and every instruction's rendered text (which carries operands and
/// the referenced constant names).
fn lua_chunk_to_text(chunk: &n0xis_lua::LuaChunk) -> String {
    use n0xis_lua::GcConst;
    let mut out = String::new();
    if let Some(name) = &chunk.chunk_name {
        out.push_str(name);
        out.push('\n');
    }
    for p in &chunk.protos {
        for gc in &p.gc_constants {
            if let GcConst::Str(s) = gc {
                out.push_str(s);
                out.push('\n');
            }
        }
        for ins in &p.instructions {
            out.push_str(&ins.text);
            out.push('\n');
        }
    }
    out
}

/// Extract printable-ASCII runs (>= `min_len`) from a binary blob, one per line
/// — the fallback for a file that isn't UTF-8 text or Lua bytecode.
fn extract_ascii_runs(bytes: &[u8], min_len: usize) -> String {
    let mut out = String::new();
    let mut run = String::new();
    for &b in bytes {
        if (32..=126).contains(&b) {
            run.push(b as char);
        } else {
            if run.len() >= min_len {
                out.push_str(&run);
                out.push('\n');
            }
            run.clear();
        }
    }
    if run.len() >= min_len {
        out.push_str(&run);
    }
    out
}

/// Turn one file into a searchable [`Document`], decoding Lua bytecode and
/// falling back to UTF-8 text or ASCII-string extraction.
fn file_to_document(path: &std::path::Path) -> Option<Document> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.is_empty() {
        return None;
    }
    let id = path.to_string_lossy().to_string();
    if bytes.starts_with(&[0x1b, b'L', b'J'])
        && let Ok(chunk) = n0xis_lua::disassemble(&bytes)
    {
        return Some(Document { id, kind: "lua".into(), text: lua_chunk_to_text(&chunk) });
    }
    match std::str::from_utf8(&bytes) {
        Ok(s) => Some(Document { id, kind: "text".into(), text: s.to_string() }),
        Err(_) => {
            let text = extract_ascii_runs(&bytes, 4);
            if text.is_empty() { None } else { Some(Document { id, kind: "strings".into(), text }) }
        }
    }
}

/// Recursively collect files under `dir` into `docs` (bounded so a pathological
/// tree can't run away).
fn collect_documents(dir: &std::path::Path, docs: &mut Vec<Document>, budget: &mut usize) {
    if *budget == 0 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        if *budget == 0 {
            return;
        }
        let path = entry.path();
        if path.is_dir() {
            collect_documents(&path, docs, budget);
        } else if let Some(doc) = file_to_document(&path) {
            docs.push(doc);
            *budget -= 1;
        }
    }
}

fn cmd_concept_grep(a: ConceptGrepArgs, spelled: Spelled, pretty: bool) -> bool {
    let mut terms = split_concept(&a.concept);
    terms.extend(a.terms.iter().cloned());
    if terms.is_empty() {
        return ir_err("empty-concept", "provide at least one vocabulary term in <concept>", pretty);
    }

    let mut docs = Vec::new();
    let mut budget = 200_000usize; // hard ceiling on files scanned
    for dir in &a.dirs {
        let p = std::path::Path::new(dir);
        if !p.exists() {
            return ir_err("no-dir", &format!("directory not found: {dir}"), pretty);
        }
        collect_documents(p, &mut docs, &mut budget);
    }

    let opts = RankOptions { limit: a.limit, max_snippets: a.max_snippets, min_distinct: a.min_distinct.max(1) };
    let art = concept_grep_rank(&terms, &docs, &opts);
    emit(
        &Response::success(CONCEPT_GREP.schema(spelled), art).with_source(a.dirs.join(",")),
        pretty,
    )
}

fn cmd_locate_by_transition(a: LocateByTransitionArgs, pretty: bool) -> bool {
    let value_type: ValueType = a.r#type.into();
    let align = a.align.unwrap_or_else(|| value_type.size());
    let transition = match a.transition.as_str() {
        "changed" => FilterCriterion::Changed,
        "increased" => FilterCriterion::Increased,
        "decreased" => FilterCriterion::Decreased,
        other => return ir_err("bad-transition", &format!("unknown --transition '{other}' (changed|increased|decreased)"), pretty),
    };
    // Without `--wait-ms` the operator's Enter on stdin ends the pause. Claim it
    // before attaching or snapshotting anything: inside a `serve` session stdin
    // is the request channel (see `command_stdin`), so it is refused here,
    // while nothing has been done yet.
    let operator = match a.wait_ms {
        Some(_) => None,
        None => match command_stdin() {
            Ok(s) => Some(s),
            Err(e) => {
                return ir_err(STDIN_IS_SESSION_CODE, &format!("locate by-transition without --wait-ms waits for Enter on stdin; {e}. Pass --wait-ms."), pretty);
            }
        },
    };
    {
        // Data-side command: nothing here decodes an instruction, so the ISA is
        // only what `Ctx` requires structurally — not a bypassed seam.
        let arch = X64::new();
        // Through the platform seam, not `LiveProcess::attach`. Reaching for the
        // Win32 type directly is what made this command refuse to run anywhere
        // else — with a message blaming "LiveProcess/Win32 APIs" for a body that
        // touches neither: every step below is `ScanPass`/`FilterPass` over a
        // `Ctx`, and `resolve_scan_regions_live` already takes `&dyn LiveTarget`.
        let live = match n0xis_frontend::source::attach_live(a.pid) {
            Ok(l) => l,
            Err((c, m)) => return ir_err(&c, &m, pretty),
        };
        let regions = match resolve_scan_regions_live(live.as_ref(), a.start.as_deref(), a.size) {
            Ok(r) => r,
            Err(e) => return ir_err("bad-region", &e, pretty),
        };
        let label = n0xis_sources::MemorySource::label(live.as_ref());
        let ctx = Ctx::new(live.as_ref(), &arch);

        // 1) Snapshot the region set (unknown = capture every value densely).
        let before = match ScanPass.run(&ctx, ScanInput { regions, value_type, criterion: ScanCriterion::Unknown, align }) {
            Ok(s) => s,
            Err(e) => return ir_err("snapshot-failed", &e.to_string(), pretty),
        };
        let snapshot_count = before.total();
        eprintln!("[n0x] snapshot: {snapshot_count} candidate values captured across the region set");

        // 2) Let the operator toggle exactly one thing (or wait a fixed delay).
        if let Some(ms) = a.wait_ms {
            eprintln!("[n0x] toggle exactly one thing in the target now — rescanning in {ms}ms");
            std::thread::sleep(std::time::Duration::from_millis(ms));
        } else if let Some(stdin) = &operator {
            eprintln!("[n0x] toggle exactly one thing in the target, then press Enter to rescan…");
            let mut _line = String::new();
            let _ = stdin.read_line(&mut _line);
        }

        // 3) Rescan and keep only what changed (the transition = the signal).
        let mut state = match FilterPass.run(&ctx, FilterInput { previous: before, criterion: transition }) {
            Ok(s) => s,
            Err(e) => return ir_err("rescan-failed", &e.to_string(), pretty),
        };
        let after_transition = state.total();

        // 4) Optional structural predicate over the survivors (a second filter).
        let predicate = if let Some(v) = a.expect {
            Some(FilterCriterion::Exact { value: to_scan_value(v) })
        } else if a.min.is_some() || a.max.is_some() {
            match (a.min, a.max) {
                (Some(min), Some(max)) => Some(FilterCriterion::InRange { min: to_scan_value(min), max: to_scan_value(max) }),
                _ => return ir_err("bad-predicate", "--min and --max must be given together", pretty),
            }
        } else {
            None
        };
        let predicate_label = predicate.as_ref().map(|_| if a.expect.is_some() { "expect" } else { "in-range" });
        if let Some(crit) = predicate {
            state = match FilterPass.run(&ctx, FilterInput { previous: state, criterion: crit }) {
                Ok(s) => s,
                Err(e) => return ir_err("predicate-failed", &e.to_string(), pretty),
            };
        }
        let final_count = state.total();

        // 5) Persist the working set so `scan filter` can continue narrowing it.
        if let Err(e) = n0xis_project::dump::save(&a.save_as, "scan", &state.encode(), a.force) {
            return ir_err("save-failed", &e.to_string(), pretty);
        }

        let report = state.report();
        let report_v = serde_json::to_value(&report).unwrap_or(serde_json::Value::Null);
        let note = if final_count == 1 {
            "exactly one survivor — the transition diff localized the value (RE_METHOD W1)".to_string()
        } else if final_count == 0 {
            "zero survivors — either nothing toggled, the wrong value type, or the change was outside the scanned regions".to_string()
        } else {
            format!("{final_count} survivors — toggle again and run `scan filter --from {} --criterion changed` to narrow further", a.save_as)
        };
        let data = json!({
            "snapshot_count": snapshot_count,
            "after_transition": after_transition,
            "final_count": final_count,
            "transition": a.transition,
            "predicate": predicate_label,
            "saved_as": a.save_as,
            "report": report_v,
            "note": note,
        });
        emit(&Response::success(schema::v1::LOCATE_TRANSITION, data).with_source(label), pretty)
    }
}

fn cmd_input_probe(a: InputProbeArgs, pretty: bool) -> bool {
    #[cfg(not(windows))]
    {
        let _ = &a;
        ir_err("live-unsupported", "input probe requires a Windows build (needs Win32 input APIs)", pretty)
    }
    #[cfg(windows)]
    {
        let vk = match a.vk.as_deref() {
            Some(s) => {
                let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    u16::from_str_radix(hex, 16)
                } else {
                    s.parse::<u16>()
                };
                match parsed {
                    Ok(v) => v,
                    Err(_) => return ir_err("bad-vk", &format!("invalid --vk '{s}' (decimal or 0x..)"), pretty),
                }
            }
            None => DEFAULT_PROBE_VK,
        };
        match probe_actuation(vk, a.pid, a.timeout_ms) {
            Ok(report) => emit(&Response::success(schema::v1::INPUT_PROBE, report), pretty),
            Err(e) => ir_err("probe-failed", &e, pretty),
        }
    }
}

/// One numeric literal pulled from text, tagged by how to identify it.
enum NumLiteral {
    Int(u64),
    Float(f64),
}

/// Parse a single `--value` (hex `0x..`, decimal, or float).
fn parse_const_value(s: &str) -> Result<NumLiteral, String> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).map(NumLiteral::Int).map_err(|e| format!("bad hex {t:?}: {e}"));
    }
    // A float only if it has a fractional/exponent form with a dot.
    if t.contains('.') {
        return t.parse::<f64>().map(NumLiteral::Float).map_err(|e| format!("bad float {t:?}: {e}"));
    }
    if let Ok(u) = t.parse::<u64>() {
        return Ok(NumLiteral::Int(u));
    }
    if let Ok(i) = t.parse::<i64>() {
        return Ok(NumLiteral::Int(i as u64));
    }
    t.parse::<f64>().map(NumLiteral::Float).map_err(|e| format!("unrecognized value {t:?}: {e}"))
}

/// Scan free text for distinct numeric literals (hex, decimal, float). Used to
/// pull constants out of decompiled pseudo-C.
fn extract_numbers(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        // Hex literal.
        if c == '0' && i + 1 < bytes.len() && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
            let start = i;
            i += 2;
            while i < bytes.len() && (bytes[i] as char).is_ascii_hexdigit() {
                i += 1;
            }
            if i > start + 2 {
                out.push(text[start..i].to_string());
            }
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            let mut is_float = false;
            while i < bytes.len() {
                let d = bytes[i] as char;
                if d.is_ascii_digit() {
                    i += 1;
                } else if d == '.' && !is_float {
                    is_float = true;
                    i += 1;
                } else if (d == 'e' || d == 'E') && is_float {
                    i += 1;
                    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
                        i += 1;
                    }
                } else {
                    break;
                }
            }
            out.push(text[start..i].to_string());
            continue;
        }
        i += 1;
    }
    out.sort();
    out.dedup();
    out
}

/// Build the `matches` array for a batch of literals; only literals that
/// identify something are included.
fn identify_literals(literals: &[String]) -> Vec<serde_json::Value> {
    let mut hits = Vec::new();
    for lit in literals {
        let Ok(parsed) = parse_const_value(lit) else { continue };
        let matches: Vec<ConstMatch> = match parsed {
            NumLiteral::Int(u) => identify_u64(u),
            NumLiteral::Float(f) => identify_f64(f),
        };
        if matches.is_empty() {
            continue;
        }
        let m_v = serde_json::to_value(&matches).unwrap_or(serde_json::Value::Null);
        hits.push(json!({ "literal": lit, "matches": m_v }));
    }
    hits
}

fn cmd_const_identify(a: ConstIdentifyArgs, pretty: bool) -> bool {
    // Mode A: a single --value.
    if let Some(v) = &a.value {
        let parsed = match parse_const_value(v) {
            Ok(p) => p,
            Err(e) => return ir_err("bad-value", &e, pretty),
        };
        let matches = match parsed {
            NumLiteral::Int(u) => identify_u64(u),
            NumLiteral::Float(f) => identify_f64(f),
        };
        let m_v = serde_json::to_value(&matches).unwrap_or(serde_json::Value::Null);
        let data = json!({ "value": v, "match_count": matches.len(), "matches": m_v });
        return emit(&Response::success(schema::v1::CONST_IDENTIFY, data), pretty);
    }

    // Mode C: a Lua chunk's number constants.
    if let Some(luapath) = &a.lua {
        let bytes = match std::fs::read(luapath) {
            Ok(b) => b,
            Err(e) => return ir_err("read-failed", &format!("read {luapath}: {e}"), pretty),
        };
        let chunk = match n0xis_lua::disassemble(&bytes) {
            Ok(c) => c,
            Err(e) => return ir_err("lua-disasm-failed", &e.to_string(), pretty),
        };
        use n0xis_lua::NumConst;
        let mut literals = Vec::new();
        for p in &chunk.protos {
            for nc in &p.num_constants {
                match nc {
                    NumConst::Int(i) => literals.push(i.to_string()),
                    NumConst::Num(f) => literals.push(format!("{f}")),
                }
            }
        }
        literals.sort();
        literals.dedup();
        let hits = identify_literals(&literals);
        let data = json!({ "source": luapath, "literals_scanned": literals.len(), "identified": hits.len(), "hits": hits });
        return emit(&Response::success(schema::v1::CONST_IDENTIFY, data).with_source(luapath.clone()), pretty);
    }

    // Mode B: decompile a function and identify its literals.
    let Some(addr_s) = &a.addr else {
        return ir_err("missing-input", "provide --value, --lua <chunk>, or a function (--addr with --file/--pid/--snapshot)", pretty);
    };
    let addr = match Va::parse(addr_s) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let (src, label, _) = match build_source(a.pid, a.file.as_deref(), None, a.snapshot.as_deref(), a.remote_cmd.as_deref(), addr) {
        Ok(x) => x,
        Err((c, m)) => return ir_err(&c, &m, pretty),
    };
    // This `--addr` path decompiles the function to enumerate its literals:
    // `cfg_cached` -> `CfgPass` decodes the instructions, so the ISA is a real
    // decode fact, not a structural placeholder. Honour the image header (no
    // `--arch` flag on this command) so an AArch64/i386 image is not read as
    // x86-64 — the same B1 footgun `Src::pick_arch` exists to close.
    let arch = match src.pick_arch(None) {
        Ok(x) => x,
        Err(e) => return ir_err("bad-arch", &e, pretty),
    };
    let input = CfgInput { start: addr, max_bytes: a.func_size, auto_end: true };
    let run = |ctx: &Ctx| -> Result<Vec<String>, (String, String)> {
        let (cfg, _cached) = cfg_cached(ctx, input).map_err(|e| ("ir-failed".to_string(), e.to_string()))?;
        let pf = DecompPass
            .run(ctx, DecompInput { cfg, style: DecompStyle::Goto, explain: false, strip_block_labels: false, var_names: Default::default(), var_types: Default::default(), struct_defs: Default::default() })
            .map_err(|e| ("decomp-failed".to_string(), e.to_string()))?;
        Ok(pf.pseudo)
    };
    let pseudo = match &src {
        Src::Static(pe) => run(&Ctx::new(pe.as_ref(), arch.as_ref()).with_symbols(pe.as_ref())),
        Src::Live(l) => run(&Ctx::new(l.as_ref(), arch.as_ref())),
        Src::Snap(s) => run(&Ctx::new(s, arch.as_ref())),
        Src::Remote(r) => run(&Ctx::new(r.as_ref(), arch.as_ref())),
    };
    let pseudo = match pseudo {
        Ok(p) => p,
        Err((c, m)) => return ir_err(&c, &m, pretty),
    };
    let literals = extract_numbers(&pseudo.join("\n"));
    let hits = identify_literals(&literals);
    let data = json!({ "addr": addr, "literals_scanned": literals.len(), "identified": hits.len(), "hits": hits });
    emit(&Response::success(schema::v1::CONST_IDENTIFY, data).with_source(label), pretty)
}

fn cmd_bindings_list(a: BindingsListArgs, pretty: bool) -> bool {
    let explicit_code_start = match opt_hex(&a.start) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e, pretty),
    };
    let explicit_data_start = match opt_hex(&a.data_start) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e, pretty),
    };
    let bytes_base = explicit_data_start.or(explicit_code_start).unwrap_or(Va(0));
    let (src, label, region_len) = match build_source(a.pid, a.file.as_deref(), None, a.snapshot.as_deref(), a.remote_cmd.as_deref(), bytes_base) {
        Ok(x) => x,
        Err((c, m)) => return ir_err(&c, &m, pretty),
    };
    let arch = match src.pick_arch(a.arch.as_deref()) {
        Ok(x) => x,
        Err(e) => return ir_err("bad-arch", &e, pretty),
    };

    let default_text = match &src {
        Src::Static(pe) => pe.text_range(),
        Src::Live(l) => {
            if let Some(modname) = &a.module {
                // No `use ModuleProvider` needed: it is a supertrait of
                // LiveTarget, so `modules()` is in scope through the seam.
                let needle = modname.to_lowercase();
                match l.modules().iter().find(|m| m.name.to_lowercase().contains(&needle)).map(|m| m.base) {
                    Some(base) => l.section_range_of(base, ".text"),
                    None => return ir_err("no-module", &format!("no loaded module name contains '{modname}'"), pretty),
                }
            } else {
                l.text_range()
            }
        }
        Src::Snap(_) | Src::Remote(_) => None,
    };
    // The name strings a binding registers live in read-only/initialized data;
    // its primary window is `.rdata` on a PE, `.rodata` on an ELF — both come
    // from the one shared enumerator. The old `.rdata`->`.text` fallback scanned
    // *code* as the name window and so found nothing on any ELF.
    let default_data = src.data_ranges_of(a.module.as_deref()).first().copied();
    let (code_start, code_size) = scan_range(default_text, region_len, explicit_code_start, a.size, bytes_base);
    let (data_start, data_size) = scan_range(default_data, region_len, explicit_data_start, a.data_size, bytes_base);
    if code_size == 0 || data_size == 0 {
        return ir_err("no-range", "could not resolve a data/code range; pass --data-start/--data-size and --start/--size", pretty);
    }

    let min_conf = a.min_confidence;
    let names = a.names.clone();
    let run = |ctx: &Ctx| -> bool {
        let input = BindingsInput {
            data_start,
            data_size,
            code_start,
            code_size,
            names: names.clone(),
            window: a.window,
            limit: a.limit,
        };
        match BindingsPass.run(ctx, input) {
            Ok(mut art) => {
                if min_conf > 0.0 {
                    art.bindings.retain(|b| b.confidence >= min_conf);
                    art.count = art.bindings.len();
                    art.named = art.bindings.iter().map(|b| b.name.as_str()).collect::<std::collections::HashSet<_>>().len();
                }
                emit(&Response::success(schema::v1::BINDINGS, art).with_source(label.clone()), pretty)
            }
            Err(e) => ir_err("bindings-failed", &e.to_string(), pretty),
        }
    };
    match &src {
        Src::Static(pe) => run(&Ctx::new(pe.as_ref(), arch.as_ref()).with_symbols(pe.as_ref())),
        Src::Live(l) => run(&Ctx::new(l.as_ref(), arch.as_ref())),
        Src::Snap(s) => run(&Ctx::new(s, arch.as_ref())),
        Src::Remote(r) => run(&Ctx::new(r.as_ref(), arch.as_ref())),
    }
}

fn cmd_sig_validate(a: SigValidateArgs, pretty: bool) -> bool {
    run_capability(
        "sig.validate",
        json!({
            "samples": a.samples,
            "sample_files": a.sample_files,
            "ats": a.ats,
            "pid": a.pid,
            "file": a.file,
            "len": a.len,
            "signature": a.signature,
            "varied": a.varied,
            "min_independent": a.min_independent,
        }),
        pretty,
    )
}

/// The byte range within one instruction that a linker fills in and so must
/// become a wildcard: a relative branch's displacement, or a RIP-relative
/// memory displacement. Returns `None` when the instruction carries no
/// relocation, and `Err(())` when it carries one we cannot locate soundly (the
/// caller then truncates the pattern rather than leave a varying byte fixed).
fn reloc_span(ins: &n0xis_arch::DecodedInsn) -> Result<Option<(usize, usize)>, ()> {
    let len = ins.len as usize;
    // A relative near-branch (`e8`/`e9` rel32, `7x`/`eb` rel8, `0f 8x` rel32):
    // the displacement is the instruction's trailing bytes — 1 for a 2-byte
    // short branch, 4 otherwise. Confirm by reconstructing the target from them.
    if matches!(ins.kind, InsnKind::Call | InsnKind::Jump | InsnKind::CondJump)
        && let Some(target) = ins.target
    {
        let dlen = if len <= 2 { 1 } else { 4 };
        if dlen > len {
            return Err(());
        }
        let off = len - dlen;
        let disp = target.0.wrapping_sub(ins.va.0.wrapping_add(len as u64));
        let bytes = &ins.bytes[off..off + dlen];
        // Sign-extend the trailing bytes and check they encode this target; if
        // not, the branch is not simple-relative and we can't wildcard it.
        let mut val = 0i64;
        for (i, &b) in bytes.iter().enumerate() {
            val |= (b as i64) << (8 * i);
        }
        let sign = 1i64 << (8 * dlen - 1);
        let signed = (val ^ sign) - sign;
        if (signed as u64) == disp {
            return Ok(Some((off, dlen)));
        }
        return Err(());
    }
    // A RIP-relative memory operand: `disp32 = rip_target - (va + len)`, located
    // by finding that little-endian value inside the instruction bytes. Unique
    // occurrence → wildcard it; otherwise we cannot place it soundly.
    if let Some(rt) = ins.rip_target {
        if len < 4 {
            return Err(());
        }
        let disp = rt.0.wrapping_sub(ins.va.0.wrapping_add(len as u64)) as u32;
        let le = disp.to_le_bytes();
        let mut found: Option<usize> = None;
        for w in 0..=len - 4 {
            if ins.bytes[w..w + 4] == le {
                if found.is_some() {
                    return Err(()); // ambiguous placement — refuse to guess
                }
                found = Some(w);
            }
        }
        return found.map(|p| Some((p, 4))).ok_or(());
    }
    Ok(None)
}

/// Fingerprint one function: decode its leading `window` bytes, wildcard the
/// relocated displacements, and stop at the first `ret`/invalid byte or a
/// relocation we cannot place. Returns the `.npat` pattern token string and its
/// fixed-byte count, or `None` when too little decodable code is present.
fn generate_pattern(window: &[u8], window_va: Va, arch: &dyn Arch) -> Option<(String, usize)> {
    let insns = arch.decode_stream(window, window_va, window.len());
    let mut wild: Vec<(usize, usize)> = Vec::new();
    let mut covered = 0usize;
    for ins in &insns {
        let off = (ins.va.0 - window_va.0) as usize;
        let len = ins.len as usize;
        if matches!(ins.kind, InsnKind::Invalid) || off + len > window.len() {
            break;
        }
        match reloc_span(ins) {
            Ok(Some((rel_off, rel_len))) => wild.push((off + rel_off, rel_len)),
            Ok(None) => {}
            // A relocation we cannot place soundly: end the pattern *before* this
            // instruction so no varying byte is ever left fixed.
            Err(()) => break,
        }
        covered = off + len;
        // A `ret` is a natural, stable pattern boundary — stop after it.
        if matches!(ins.kind, InsnKind::Ret) {
            break;
        }
    }
    if covered == 0 {
        return None;
    }
    let pat = n0xis_flirt::Pattern::from_window(&window[..covered], &wild);
    Some((pat.to_npat(), pat.fixed_count()))
}

fn cmd_sig_gen(a: SigGenArgs, pretty: bool) -> bool {
    let img = match StaticImage::load(std::path::Path::new(&a.file)) {
        Ok(i) => i,
        Err(e) => return emit(&Response::<serde_json::Value>::error("load-failed", e.to_string()), pretty),
    };
    // Honour the image's own machine field, not just its bitness: a signature
    // library must fingerprint an AArch64 image with the AArch64 decoder, never
    // x86-64. `StaticImage` lives below the frontend, so thread its declared
    // machine into `pick_arch_for` directly (an explicit `--arch` still wins).
    let declared = img.machine();
    let arch = match n0xis_frontend::pick_arch_for(a.arch.as_deref(), Some(declared.as_str()), !img.is_64()) {
        Ok(x) => x,
        Err(e) => return ir_err("bad-arch", &e, pretty),
    };

    let funcs = img.named_functions();
    let mut lines: Vec<String> = Vec::new();
    let mut sigs: Vec<serde_json::Value> = Vec::new();
    let mut skipped_short = 0usize;
    let mut skipped_unreadable = 0usize;
    let mut skipped_glue = 0usize;

    // Pass 1 — fingerprint every named function, filtering nothing yet. The
    // window bytes are kept: pass 2 replays the matcher against them.
    let mut built: Vec<(Va, &String, String, usize, Vec<u8>)> = Vec::new();
    for (va, name) in &funcs {
        let window = match img.read(*va, a.window) {
            Ok(b) if !b.is_empty() => b,
            _ => {
                skipped_unreadable += 1;
                continue;
            }
        };
        let Some((pattern, fixed)) = generate_pattern(&window, *va, arch.as_ref()) else {
            skipped_unreadable += 1;
            continue;
        };
        built.push((*va, name, pattern, fixed, window));
    }

    // Pass 2 — SELF-VALIDATE THE CORPUS, then drop every signature that fails.
    //
    // The invariant a signature database must hold is not "no two patterns are
    // equal"; it is: **looking up any function of the reference must never
    // return another function's name.** Nothing weaker is sound, and this is
    // checkable here because the reference is fully symbolized — it is `sig
    // validate`'s invariance idea applied to the corpus as a whole.
    //
    // Both halves of this were found by an exit test against ground truth, and
    // both are instructive:
    //
    // 1. glibc's `__chk_fail` and `__stack_chk_fail` differ *only* in the
    //    RIP-relative message pointer and the relative `call __fortify_fail`,
    //    both correctly wildcarded as linker-varying — identical patterns. The
    //    matcher's own ambiguity rule could not save us: it refuses only when
    //    both are in the database, and `__stack_chk_fail` shares its address
    //    with the alias `__stack_chk_fail_local`, which the glue filter removes.
    //    So `__chk_fail` was left alone holding a pattern matching both, and
    //    every `__stack_chk_fail` in every target was named `__chk_fail`.
    //
    // 2. Dropping merely-equal patterns then made things *worse*. The ifunc
    //    variants `__strcasecmp_l_avx2` and `__strcasecmp_l_avx2_rtm` have equal
    //    patterns and were dropped — but `__strcasecmp_l_evex`, whose pattern
    //    `generate_pattern` had TRUNCATED to 23 bytes (its next instruction ran
    //    past the window), is a strict *prefix* of theirs and survived. Removing
    //    the specific signatures handed the match to the over-broad one.
    //
    // Hence: replay the real matcher. Build a database from the candidates, look
    // each reference function up by its own bytes, and drop whichever signature
    // answered with the wrong name — the one making the false claim, not its
    // victim. Dropping can expose a next-best, so iterate to a fixpoint; the set
    // only ever shrinks, so it terminates.
    // The set that would ship, before validation: everything the ordinary
    // filters keep. Validation runs over THIS set (a signature the glue filter
    // removed cannot shadow anything) but is checked against EVERY reference
    // function, filtered-out ones included — their bytes are ground truth
    // regardless of whether they earn a signature. That asymmetry is the whole
    // point: it is exactly the `__chk_fail` hole, where the shadowed function
    // was the one the filter removed.
    let mut alive: Vec<bool> = Vec::with_capacity(built.len());
    for (_, name, _, fixed, _) in &built {
        let ship = !(!a.include_glue && is_toolchain_glue(name)) && *fixed >= a.min_fixed;
        if !ship {
            if !a.include_glue && is_toolchain_glue(name) {
                skipped_glue += 1;
            } else {
                skipped_short += 1;
            }
        }
        alive.push(ship);
    }

    let mut skipped_ambiguous = 0usize;
    loop {
        let mut db = n0xis_flirt::Db::new();
        for (i, (_, name, pattern, _, _)) in built.iter().enumerate() {
            if alive[i] {
                let _ = db.add_pat(pattern, name);
            }
        }
        // Every name the shipping database would claim wrongly this round.
        let mut guilty: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for (_, name, _, _, window) in built.iter() {
            // Validate at exactly the specificity the corpus will ship/trust at,
            // not the hardcoded default: identical at the default `min_fixed`,
            // but honours a user who lowered `--min-fixed`.
            if let Some(got) = db.lookup_min_fixed(window, a.min_fixed)
                && got != name.as_str()
            {
                guilty.insert(got);
            }
        }
        if guilty.is_empty() {
            break;
        }
        for (i, (_, name, _, _, _)) in built.iter().enumerate() {
            if alive[i] && guilty.contains(name.as_str()) {
                alive[i] = false;
                skipped_ambiguous += 1;
            }
        }
    }

    for (i, (va, name, pattern, fixed, _)) in built.iter().enumerate() {
        if !alive[i] {
            continue;
        }
        lines.push(format!("{pattern} {name}"));
        sigs.push(json!({ "va": format!("{va}"), "name": name, "pattern": pattern, "fixed": fixed }));
    }

    let header = format!(
        "# n0xis {} signatures generated from {} ({} functions, {} emitted)\n",
        schema::v1::SIG_GEN,
        a.file,
        funcs.len(),
        lines.len()
    );
    let npat = format!("{header}{}\n", lines.join("\n"));

    emit(
        &Response::success(
            schema::v1::SIG_GEN,
            json!({
                "source": a.file,
                "functions_total": funcs.len(),
                "emitted": lines.len(),
                "skipped_below_min_fixed": skipped_short,
                // Patterns that two differently-named functions of the reference
                // share: dropped, because such a pattern names neither.
                // Signatures the corpus self-check proved would name the
                // wrong function. Dropped: a wrong name is worse than none.
                "skipped_ambiguous": skipped_ambiguous,
                "skipped_unreadable": skipped_unreadable,
                "skipped_toolchain_glue": skipped_glue,
                "window": a.window,
                "min_fixed": a.min_fixed,
                "npat": npat,
                "signatures": sigs,
            }),
        )
        .with_source(img.module().name.clone()),
        pretty,
    )
}

// ============================================================================
// Phase 12 — IL2CPP managed layer (item 0: import an external index)
// ============================================================================

fn cmd_il2cpp_import(a: Il2cppImportArgs, pretty: bool) -> bool {
    run_capability(
        "il2cpp.import",
        json!({
            "script_json": a.script_json,
            "name": a.name,
            "space": a.space,
            "module": a.module,
            "pid": a.pid,
            "file": a.file,
            "force": a.force,
        }),
        pretty,
    )
}

fn cmd_il2cpp_symbols(a: Il2cppSymbolsArgs, pretty: bool) -> bool {
    run_capability(
        "il2cpp.symbols",
        json!({
            "name": a.name,
            "query": a.query,
            "addr": a.addr,
            "pid": a.pid,
            "file": a.file,
            "limit": a.limit,
        }),
        pretty,
    )
}

fn cmd_il2cpp_classes(a: Il2cppClassesArgs, pretty: bool) -> bool {
    run_capability(
        "il2cpp.classes",
        json!({ "pid": a.pid, "query": a.query, "regions": a.regions, "window": a.window, "max_probe": a.max_probe, "min_hits": a.min_hits, "any_layout": a.any_layout, "limit": a.limit, "arch": a.arch }),
        pretty,
    )
}

fn cmd_il2cpp_obj(a: Il2cppObjArgs, pretty: bool) -> bool {
    run_capability(
        "il2cpp.obj",
        json!({ "addr": a.addr, "pid": a.pid, "file": a.file, "size": a.size, "probe": a.probe, "arch": a.arch }),
        pretty,
    )
}

fn cmd_il2cpp_icalls(a: Il2cppIcallsArgs, pretty: bool) -> bool {
    run_capability(
        "il2cpp.icalls",
        json!({
            "pid": a.pid,
            "file": a.file,
            "module": a.module,
            "query": a.query,
            "resolve": !a.no_resolve,
            "limit": a.limit,
            "arch": a.arch,
        }),
        pretty,
    )
}

fn cmd_il2cpp_metadata(a: Il2cppMetadataArgs, pretty: bool) -> bool {
    run_capability(
        "il2cpp.metadata",
        json!({
            "metadata": a.metadata,
            "file": a.file,
            "query": a.query,
            "limit": a.limit,
            "offset": a.offset,
        }),
        pretty,
    )
}

// ============================================================================
// Phase 9 — UI-layer localization (docs/PHASE9_UI_LOCATE_BRIEF.md)
// ============================================================================

/// Parse `"x0,y0,x1,y1"` into a [`Rect`] (any corner order — `Rect::new`
/// normalizes).
fn parse_rect(s: &str) -> Result<Rect, String> {
    let parts: Vec<&str> = s.split(',').map(|t| t.trim()).collect();
    let [a, b, c, d] = parts.as_slice() else {
        return Err(format!("--rect needs exactly 4 comma-separated numbers, got {:?}", s));
    };
    let p = |t: &str| t.parse::<f32>().map_err(|e| format!("invalid --rect coordinate {t:?}: {e}"));
    Ok(Rect::new(p(a)?, p(b)?, p(c)?, p(d)?))
}

/// Load every `--exclude-from`d save's address set up front, before running
/// the (potentially tens-of-seconds) full-region scan — a bad/missing name
/// should fail immediately, not after the expensive part already ran.
fn load_excluded_addresses(names: &[String]) -> Result<std::collections::HashSet<Va>, (String, String)> {
    let mut excluded = std::collections::HashSet::new();
    for name in names {
        let saved = n0xis_project::dump::show(name, Some("ui_locate"))
            .map_err(|e| ("no-such-save".to_string(), format!("--exclude-from {name:?}: {e}")))?;
        let parsed: serde_json::Value = serde_json::from_slice(&saved.bytes)
            .map_err(|e| ("bad-save".to_string(), format!("{name:?} is not a valid ui_locate save: {e}")))?;
        for e in parsed.get("elements").and_then(|v| v.as_array()).into_iter().flatten() {
            if let Some(addr) = e.get("address").and_then(|v| v.as_str()).and_then(|s| Va::parse(s).ok()) {
                excluded.insert(addr);
            }
        }
    }
    Ok(excluded)
}

fn cmd_ui_locate(a: UiLocateArgs, pretty: bool) -> bool {
    let rect = match parse_rect(&a.rect) {
        Ok(r) => r,
        Err(e) => return ir_err("bad-rect", &e, pretty),
    };
    let excluded = match load_excluded_addresses(&a.exclude_from) {
        Ok(e) => e,
        Err((c, m)) => return ir_err(&c, &m, pretty),
    };
    #[cfg(not(windows))]
    {
        let _ = (&a, rect, &excluded);
        ir_err("live-unsupported", "ui locate requires a Windows build (needs LiveProcess/Win32 APIs)", pretty)
    }
    #[cfg(windows)]
    {
        let live = match LiveProcess::attach(a.pid) {
            Ok(l) => l,
            Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
        };
        let regions = match resolve_scan_regions_live(&live, a.start.as_deref(), a.size) {
            Ok(r) => r,
            Err(e) => return ir_err("bad-region", &e, pretty),
        };
        let label = live.label();
        // Data-side command: nothing here decodes an instruction, so the ISA is
        // only what `Ctx` requires structurally — not a bypassed seam.
        let arch = X64::new();
        let ctx = Ctx::new(&live, &arch);

        let input = UiLocateInput {
            regions,
            rect,
            space: a.space.into(),
            layout: AabbLayout::BITSQUID,
            align: a.align.max(1),
        };
        let mut art = match UiLocatePass.run(&ctx, input) {
            Ok(a) => a,
            Err(e) => return ir_err("ui-locate-failed", &e.to_string(), pretty),
        };

        // Spatial-diff filter: exclude anything also found in a previously
        // `--save-as`d query (typically one over a rect where the widget is
        // known to be *absent*) — what's left is specific to this rect, not an
        // ambient/global structure whose (mis)computed box happens to overlap
        // everything (e.g. a coincidentally AABB-shaped shader constant buffer).
        if !excluded.is_empty() {
            art.elements.retain(|e| !excluded.contains(&e.address));
            // The exclusion is a real filter, not a display cap — `count` reflects
            // it immediately.
            art.count = art.elements.len();
        }

        if let Some(name) = &a.save_as {
            let bytes = match serde_json::to_vec(&art) {
                Ok(b) => b,
                Err(e) => return ir_err("serialize-failed", &e.to_string(), pretty),
            };
            if let Err(e) = n0xis_project::dump::save(name, "ui_locate", &bytes, a.force) {
                return ir_err("save-failed", &e.to_string(), pretty);
            }
        }

        // `count` stays the true total (sound-over-complete: a `--limit` cap must
        // never look like "that's everything") — only the reported list is capped.
        art.elements.truncate(a.limit);
        emit(&Response::success(schema::v1::UI_LOCATE, art).with_source(label), pretty)
    }
}

fn cmd_ui_windows(a: UiWindowsArgs, pretty: bool) -> bool {
    #[cfg(not(windows))]
    {
        let _ = &a;
        ir_err("live-unsupported", "ui windows requires a Windows build (needs Win32 window enumeration)", pretty)
    }
    #[cfg(windows)]
    {
        let windows = list_windows(a.pid);
        let data = json!({
            "pid": a.pid,
            "count": windows.len(),
            "windows": windows,
            "coords": "physical",
            "note": "rect_frame is the canonical visible bounds for capture/input; rect_window includes the DWM shadow; rect_client is where the application renders. Pass an hwnd to `ui screenshot`/`ui focus`.",
        });
        emit(&Response::success(schema::v1::UI_WINDOWS, data).with_source(format!("pid:{}", a.pid)), pretty)
    }
}

/// Resolve the target window: an explicit `--hwnd` (verified to actually belong
/// to `pid`, so a stale/foreign handle can't silently screenshot another
/// process while the envelope reports this pid), else the best-guess main
/// window for the pid. Returns the HWND integer or an error payload.
#[cfg(windows)]
fn resolve_ui_window(pid: u32, hwnd: Option<usize>, pretty: bool) -> Result<usize, bool> {
    if let Some(h) = hwnd {
        let owner = n0xis_sources::window_pid(h);
        if owner == 0 {
            return Err(ir_err("bad-hwnd", &format!("hwnd 0x{h:x} is not a valid window"), pretty));
        }
        if owner != pid {
            return Err(ir_err(
                "hwnd-pid-mismatch",
                &format!("hwnd 0x{h:x} belongs to pid {owner}, not the requested pid {pid}"),
                pretty,
            ));
        }
        return Ok(h);
    }
    match best_window(pid) {
        Some(w) => Ok(w.hwnd),
        None => Err(ir_err(
            "no-window",
            &format!("no visible top-level window found for pid {pid}; run `ui windows --pid {pid}` to inspect (it may be minimized, cloaked, or borderless-fullscreen)"),
            pretty,
        )),
    }
}

fn cmd_ui_screenshot(a: UiScreenshotArgs, pretty: bool) -> bool {
    #[cfg(not(windows))]
    {
        let _ = &a;
        ir_err("live-unsupported", "ui screenshot requires a Windows build (needs Win32 GDI/window capture)", pretty)
    }
    #[cfg(windows)]
    {
        let hwnd = match resolve_ui_window(a.pid, a.hwnd, pretty) {
            Ok(h) => h,
            Err(rc) => return rc,
        };
        let methods: Vec<CaptureMethod> = match a.method {
            CaptureMethodArg::Auto => vec![CaptureMethod::PrintWindow, CaptureMethod::WindowDc],
            CaptureMethodArg::WindowDc => vec![CaptureMethod::WindowDc],
            CaptureMethodArg::Printwindow => vec![CaptureMethod::PrintWindow],
        };
        let shot = match window_screenshot(hwnd, &methods) {
            Ok(s) => s,
            // A hard pre-flight failure (minimized / display-affinity / offscreen):
            // an honest, specific reason, not a black image.
            Err(e) => {
                return emit(
                    &Response::<serde_json::Value>::error("capture-failed", e.reason)
                        .with_hint("run `ui windows` to check the window is visible and on-screen"),
                    pretty,
                );
            }
        };

        let mut out_path_written: Option<String> = None;
        let mut png_b64: Option<String> = None;
        if a.out.is_some() || a.base64 {
            match encode_png(&shot.rgba, shot.width, shot.height) {
                Ok(png) => {
                    if let Some(path) = &a.out {
                        if let Err(e) = std::fs::write(path, &png) {
                            return ir_err("write-failed", &format!("write {path}: {e}"), pretty);
                        }
                        out_path_written = Some(path.clone());
                    }
                    if a.base64 {
                        png_b64 = Some(n0xis_sources::b64_encode(&png));
                    }
                }
                Err(e) => return ir_err("png-failed", &e, pretty),
            }
        }

        // Confidence is derived from the winning frame's verdict, surfaced at the
        // top level so an agent told to "key on blank" also sees a low-confidence
        // near-blank (Suspect) frame for what it is, instead of trusting it as crisp.
        let confidence = match shot.verdict {
            n0xis_sources::FrameVerdict::Ok => "ok",
            n0xis_sources::FrameVerdict::Suspect => "low",
            _ => "blank",
        };
        let data = json!({
            "pid": a.pid,
            "hwnd": hwnd,
            "width": shot.width,
            "height": shot.height,
            "method": shot.method,
            "blank": shot.blank,
            "confidence": confidence,
            "reason": shot.reason,
            "attempts": shot.attempts,
            "client_rect": shot.client_rect,
            "dpi": shot.dpi,
            "out": out_path_written,
            "png_base64": png_b64,
            "coords": "physical",
            "note": if shot.blank {
                "BLANK capture — do NOT treat this as an empty UI. GDI/PrintWindow return black for flip-model DirectX windows; the real answer needs Windows.Graphics.Capture (a documented follow-on). Key on data.blank, not on ok. The image (if written) is a diagnostic artifact only."
            } else if confidence == "low" {
                "LOW-CONFIDENCE capture (near-blank: very few distinct colors). A rect picked from this may be unreliable — confirm the window is really showing content, or try --method window-dc/printwindow explicitly."
            } else {
                "pick a rect from this image (physical pixels, origin at the window's top-left) and pass it to `ui locate --rect`."
            },
        });
        // The envelope's failure arm carries no data, and the per-method
        // diagnostics (attempts/stats/reason) are exactly what an operator needs to
        // understand a blank result — so a blank capture is emitted as a success
        // envelope with a prominent `blank: true` (brief §E's sanctioned option: an
        // agent keys on `data.blank`, never mistaking it for a real screenshot),
        // rather than a data-less error that would throw the diagnostics away.
        emit(&Response::success(schema::v1::UI_SCREENSHOT, data).with_source(format!("pid:{}", a.pid)), pretty)
    }
}

fn cmd_ui_focus(a: UiFocusArgs, pretty: bool) -> bool {
    #[cfg(not(windows))]
    {
        let _ = &a;
        ir_err("live-unsupported", "ui focus requires a Windows build (needs Win32 window APIs)", pretty)
    }
    #[cfg(windows)]
    {
        let hwnd = match resolve_ui_window(a.pid, a.hwnd, pretty) {
            Ok(h) => h,
            Err(rc) => return rc,
        };
        let result = window_focus(hwnd);
        let data = json!({
            "pid": a.pid,
            "hwnd": result.hwnd,
            "foreground": result.foreground,
            "method": result.method,
            "note": if result.foreground { "window is now foreground" } else { "focus was denied or only partial (Z-order/taskbar flash) — Windows blocks foreground stealing while the user is active" },
        });
        emit(&Response::success(schema::v1::UI_FOCUS, data).with_source(format!("pid:{}", a.pid)), pretty)
    }
}

/// The guide is generated from the clap tree, so the *command list* can never
/// drift. Its `workflows` recipes are hand-written prose, and they drifted:
/// one shipped `table add --name f --pid <p> --address <hit>` when the real
/// command takes `--addr`, has no `--pid`, and requires `--table`. An agent
/// following that recipe gets a usage error from the tool that is supposed to
/// be teaching it.
///
/// These tests hold the recipes to the same standard as everything else the
/// guide emits: every command path in a step must exist, and every long flag
/// must be one that command actually accepts.
#[cfg(test)]
mod guide_recipe_tests {
    use super::*;
    use clap::CommandFactory;

    /// Longest-prefix match of a step's leading words against the clap tree,
    /// so `scan filter` resolves to the subcommand and `bundle list` doesn't
    /// stop at `bundle`. Returns the resolved leaf and how many words it ate.
    fn resolve<'a>(root: &'a clap::Command, words: &[&str]) -> Option<(&'a clap::Command, usize)> {
        let mut cur = root;
        let mut eaten = 0;
        for w in words {
            match cur.get_subcommands().find(|c| c.get_name() == *w || c.get_all_aliases().any(|a| a == *w)) {
                Some(next) => {
                    cur = next;
                    eaten += 1;
                }
                None => break,
            }
        }
        (eaten > 0).then_some((cur, eaten))
    }

    fn accepts_flag(cmd: &clap::Command, flag: &str) -> bool {
        cmd.get_arguments().any(|a| {
            a.get_long() == Some(flag) || a.get_all_aliases().is_some_and(|al| al.contains(&flag))
        })
    }

    /// Strip the trailing `# …` explanation every recipe step carries.
    fn code_of(step: &str) -> &str {
        step.split('#').next().unwrap_or("").trim()
    }

    #[test]
    fn every_recipe_step_names_a_real_command_with_real_flags() {
        let root = Cli::command();
        let mut problems: Vec<String> = Vec::new();

        for wf in guide_workflows() {
            let name = wf["name"].as_str().unwrap_or("<unnamed>").to_string();
            for step in wf["steps"].as_array().into_iter().flatten() {
                let step = step.as_str().unwrap_or_default();
                let code = code_of(step);
                if code.is_empty() {
                    continue; // a pure `# commentary` line
                }
                let words: Vec<&str> = code.split_whitespace().collect();
                let Some((cmd, eaten)) = resolve(&root, &words) else {
                    problems.push(format!("[{name}] no such command: `{code}`"));
                    continue;
                };
                // Required args must appear, or the recipe cannot run as written.
                for arg in cmd.get_arguments() {
                    if arg.is_required_set()
                        && let Some(long) = arg.get_long()
                        && !words.iter().any(|w| *w == format!("--{long}"))
                    {
                        problems.push(format!("[{name}] `{code}` omits required --{long}"));
                    }
                }
                for w in words.iter().skip(eaten) {
                    let Some(flag) = w.strip_prefix("--") else { continue };
                    let flag = flag.split('=').next().unwrap_or(flag);
                    if !accepts_flag(cmd, flag) {
                        problems.push(format!("[{name}] `{code}` passes --{flag}, which that command does not accept"));
                    }
                }
            }
        }

        assert!(problems.is_empty(), "guide recipes drifted from the command tree:\n  {}", problems.join("\n  "));
    }

    /// A cheap guard on the other half of the contract: a recipe that names no
    /// runnable command is documentation, not a recipe.
    #[test]
    fn every_recipe_has_at_least_one_runnable_step() {
        let root = Cli::command();
        for wf in guide_workflows() {
            let name = wf["name"].as_str().unwrap_or("<unnamed>");
            let runnable = wf["steps"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|s| s.as_str())
                .any(|s| {
                    let words: Vec<&str> = code_of(s).split_whitespace().collect();
                    !words.is_empty() && resolve(&root, &words).is_some()
                });
            assert!(runnable, "recipe `{name}` has no runnable step");
        }
    }
}

/// `concept grep` was first published as `game grep`, and scripts and recipes
/// written against that name are in the field. The rename is only safe if the
/// old spelling still reaches *this* command with *these* arguments — a hidden
/// alias that parsed to a neighbour, or dropped an argument on the way, would
/// turn every old script into a confident wrong answer instead of an error.
#[cfg(test)]
mod concept_alias_tests {
    use super::*;

    /// Every argument set to a non-default value, so a field the alias failed
    /// to carry cannot hide behind its default.
    const GREP_ARGS: &[&str] = &[
        "grep", "retry,backoff", "--dir", "a", "--dir", "b", "--term", "timeout",
        "--min-distinct", "2", "--limit", "7", "--max-snippets", "1",
    ];

    fn parse_grep(top: &str) -> ConceptGrepArgs {
        let argv: Vec<&str> = ["n0xis", top].into_iter().chain(GREP_ARGS.iter().copied()).collect();
        let cli = Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("`{top} grep` must parse: {e}"));
        match cli.command {
            Command::Concept(ConceptCmd::Grep(a)) => a,
            _ => panic!("`{top} grep` parsed to a different command than `concept grep`"),
        }
    }

    #[test]
    fn the_first_name_parses_to_the_same_command_with_the_same_arguments() {
        // Exhaustive destructuring: a field added to the arguments must be
        // compared here too, or this stops compiling.
        let ConceptGrepArgs { concept, dirs, terms, min_distinct, limit, max_snippets } = parse_grep("concept");
        let old = parse_grep("game");
        assert_eq!(concept, "retry,backoff");
        assert_eq!((&dirs, &terms, min_distinct, limit, max_snippets), (&vec!["a".to_string(), "b".to_string()], &vec!["timeout".to_string()], 2, 7, 1));
        assert_eq!(
            (concept, dirs, terms, min_distinct, limit, max_snippets),
            (old.concept, old.dirs, old.terms, old.min_distinct, old.limit, old.max_snippets),
            "`game grep` and `concept grep` must carry identical arguments"
        );
    }
}

/// `table pin` was first published as `table freeze`; the same promise as
/// `concept_alias_tests`, for the second renamed command.
#[cfg(test)]
mod table_pin_alias_tests {
    use super::*;

    /// Every argument set to a non-default value, so a field the alias failed
    /// to carry cannot hide behind its default.
    const PIN_ARGS: &[&str] = &[
        "--table", "t", "--name", "n", "--pid", "4242", "--value", "7",
        "--interval-ms", "11", "--duration-ms", "13",
    ];

    fn parse_pin(sub: &str) -> TablePinArgs {
        let argv: Vec<&str> = ["n0xis", "table", sub].into_iter().chain(PIN_ARGS.iter().copied()).collect();
        let cli = Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("`table {sub}` must parse: {e}"));
        match cli.command {
            Command::Table(TableCmd::Pin(a)) => a,
            _ => panic!("`table {sub}` parsed to a different command than `table pin`"),
        }
    }

    #[test]
    fn the_first_name_parses_to_the_same_command_with_the_same_arguments() {
        // Exhaustive destructuring: a field added to the arguments must be
        // compared here too, or this stops compiling.
        let TablePinArgs { table, name, pid, value, interval_ms, duration_ms } = parse_pin("pin");
        let old = parse_pin("freeze");
        assert_eq!((table.as_str(), name.as_str(), pid, value, interval_ms, duration_ms), ("t", "n", 4242, Some(7.0), 11, 13));
        assert_eq!(
            (table, name, pid, value, interval_ms, duration_ms),
            (old.table, old.name, old.pid, old.value, old.interval_ms, old.duration_ms),
            "`table freeze` and `table pin` must carry identical arguments"
        );
    }
}

/// The schema bridge for renamed commands: which name the caller typed decides
/// which id the answer carries, and clap cannot say which name that was.
#[cfg(test)]
mod renamed_command_tests {
    use super::*;
    use clap::CommandFactory;

    const RENAMES: &[&Renamed] = &[&CONCEPT_GREP, &TABLE_PIN];

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    /// Follow `path` down the clap tree, by canonical name only or also by
    /// alias. `None` when a word names no subcommand at its level.
    fn node<'a>(root: &'a clap::Command, path: &[&str], by_alias: bool) -> Option<&'a clap::Command> {
        let mut cur = root;
        for w in path {
            cur = cur.get_subcommands().find(|c| c.get_name() == *w || (by_alias && c.get_all_aliases().any(|a| a == *w)))?;
        }
        Some(cur)
    }

    /// The ids are wire contracts, so they are written out here rather than
    /// read back from the constants under test: the first ids are the ones the
    /// first release emitted, and a change to either must fail this line.
    #[test]
    fn each_spelling_maps_to_its_own_schema_id() {
        assert_eq!(CONCEPT_GREP.schema(Spelled::First), "n0xis.game.grep.v1");
        assert_eq!(CONCEPT_GREP.schema(Spelled::Current), "n0xis.concept.grep.v1");
        assert_eq!(TABLE_PIN.schema(Spelled::First), "n0xis.freeze.v1");
        assert_eq!(TABLE_PIN.schema(Spelled::Current), "n0xis.pin.v1");
    }

    #[test]
    fn the_typed_path_keeps_the_spelling_clap_resolves_away() {
        let root = Cli::command();
        // Global flags before, between and after the words, and an argument
        // after the leaf that happens to spell a command name: none of them may
        // move the path.
        let cases: &[(&[&str], &[&str])] = &[
            (&["n0xis", "game", "grep", "x", "--dir", "d"], &["game", "grep"]),
            (&["n0xis", "--pretty", "concept", "--quiet", "grep", "table", "--dir", "game"], &["concept", "grep"]),
            (&["n0xis", "table", "freeze", "--table", "t", "--name", "pin", "--pid", "1"], &["table", "freeze"]),
            (&["n0xis", "--quiet", "table", "pin", "--table", "freeze"], &["table", "pin"]),
        ];
        for (input, want) in cases {
            assert_eq!(typed_path(&root, &argv(input)), argv(want), "typed path of {input:?}");
        }
        // And the spelling each yields.
        assert_eq!(CONCEPT_GREP.spelled(&argv(&["game", "grep"])), Spelled::First);
        assert_eq!(CONCEPT_GREP.spelled(&argv(&["concept", "grep"])), Spelled::Current);
        assert_eq!(TABLE_PIN.spelled(&argv(&["table", "freeze"])), Spelled::First);
        assert_eq!(TABLE_PIN.spelled(&argv(&["table", "pin"])), Spelled::Current);
    }

    /// The record and the clap definition must describe the same command: the
    /// current path is a real leaf under its canonical names, the first path
    /// reaches that same leaf only through an alias, and the alias is hidden —
    /// a visible one would print a second name in `--help`.
    #[test]
    fn every_rename_record_matches_the_command_tree() {
        let root = Cli::command();
        for r in RENAMES {
            let current = node(&root, r.current, false).unwrap_or_else(|| panic!("{:?} is not a command", r.current));
            assert!(current.get_subcommands().next().is_none(), "{:?} must be a leaf", r.current);
            let first = node(&root, r.first, true).unwrap_or_else(|| panic!("{:?} does not parse", r.first));
            assert!(std::ptr::eq(first, current), "{:?} reaches a different command than {:?}", r.first, r.current);
            assert!(node(&root, r.first, false).is_none(), "{:?} is a canonical name, not an alias", r.first);
            let mut level = &root;
            for w in r.first {
                let next = level.get_subcommands().find(|c| c.get_name() == *w || c.get_all_aliases().any(|a| a == *w)).expect("resolved above");
                assert!(!next.get_visible_aliases().any(|a| a == *w), "`{w}` in {:?} is a visible alias", r.first);
                level = next;
            }
        }
    }
}

/// [`typed_path`] skips every `-`-prefixed token as a value-less flag. That is
/// only sound while no command above a leaf takes an option with a value: if
/// one did, its value would be read as a subcommand name and a renamed command
/// could be answered under the wrong schema id.
#[cfg(test)]
mod typed_path_premise_tests {
    use super::*;
    use clap::CommandFactory;

    fn collect_valued(cmd: &clap::Command, path: &str, out: &mut Vec<String>) {
        if cmd.get_subcommands().next().is_none() {
            return; // a leaf: `typed_path` has stopped before its arguments
        }
        for a in cmd.get_arguments() {
            let takes_value = !matches!(
                a.get_action(),
                clap::ArgAction::SetTrue | clap::ArgAction::SetFalse | clap::ArgAction::Count | clap::ArgAction::Help | clap::ArgAction::HelpShort | clap::ArgAction::HelpLong | clap::ArgAction::Version
            );
            if takes_value {
                out.push(format!("`{path}` --{}", a.get_id()));
            }
        }
        for s in cmd.get_subcommands() {
            collect_valued(s, format!("{path} {}", s.get_name()).trim(), out);
        }
    }

    #[test]
    fn no_command_above_a_leaf_takes_an_option_with_a_value() {
        let root = Cli::command();
        let mut valued = Vec::new();
        collect_valued(&root, "", &mut valued);
        assert!(valued.is_empty(), "options with values above a leaf break `typed_path`: {valued:?}");
    }
}

#[cfg(test)]
mod serve_source_tests {
    use super::*;
    use clap::CommandFactory;

    fn names_source(argv: &[&str]) -> bool {
        let full: Vec<&str> = std::iter::once("n0xis").chain(argv.iter().copied()).collect();
        let m = Cli::command().try_get_matches_from(full).expect("the request parses");
        serve_names_source(&m)
    }

    /// The defect: `find --bytes` was taken for an inline-bytes source because
    /// it is spelled like one, so a session withheld its own image.
    #[test]
    fn a_search_pattern_is_not_a_source_but_inline_bytes_are() {
        assert!(!names_source(&["find", "--bytes", "48 8B ?? C3"]), "a find pattern is data, not a source");
        assert!(names_source(&["disasm", "--bytes", "48 89 c8 c3", "--addr", "0x1000"]), "disasm's --bytes is the source itself");
        assert!(names_source(&["find", "--file", "x.bin", "--bytes", "48"]), "an explicit --file still names one");
        assert!(names_source(&["xref", "string", "--bytes", "48 89 c8 c3", "--query", "x"]), "a nested leaf is reached");
        assert!(!names_source(&["module", "list"]));
    }

    /// The renamed ids must still land in the same fields, or the fix would
    /// trade a misrouted session for a command that silently loses its input.
    #[test]
    fn data_arguments_under_their_own_ids_still_reach_their_fields() {
        let cli = Cli::try_parse_from(["n0xis", "find", "--bytes", "48 8B ?? C3"]).expect("parse find");
        let Command::Find(f) = cli.command else { panic!("not find") };
        assert_eq!(f.bytes.as_deref(), Some("48 8B ?? C3"));

        let cli = Cli::try_parse_from(["n0xis", "mem", "write", "--addr", "0x10", "--bytes", "90 c3", "--pid", "1"]).expect("parse mem write");
        let Command::Mem(MemCmd::Write(w)) = cli.command else { panic!("not mem write") };
        assert_eq!(w.bytes, "90 c3");

        let cli = Cli::try_parse_from(["n0xis", "patch", "dry-run", "--addr", "0x10", "--bytes", "90 c3", "--pid", "1"]).expect("parse patch");
        let Command::Patch(PatchCmd::DryRun(w)) = cli.command else { panic!("not patch dry-run") };
        assert_eq!(w.bytes, "90 c3");
    }

    fn takes_file(argv: &[&str]) -> bool {
        let full: Vec<&str> = std::iter::once("n0xis").chain(argv.iter().copied()).collect();
        let m = Cli::command().try_get_matches_from(full).expect("the request parses");
        serve_leaf_takes_file(&m)
    }

    /// The defect: `dump save`'s `--file` is the file to store, and a session
    /// filled it with its own image.
    #[test]
    fn the_file_to_store_is_not_where_a_session_puts_its_image() {
        assert!(!takes_file(&["dump", "save", "--name", "t", "--kind", "note", "--content", "hello"]), "a payload file is not a source");
        assert!(takes_file(&["module", "list"]), "a command that reads a target takes the session's");
        assert!(takes_file(&["xref", "string", "--query", "x"]), "a nested leaf is reached");
        assert!(!takes_file(&["doctor"]), "a command with no --file at all takes nothing");
    }

    /// clap answers "is this id defined here?" only in a debug build: its
    /// unknown-id check is compiled under `debug_assertions`, and a release
    /// build returns `Ok(None)` for any id. So `try_get_*`'s `Err` must never
    /// stand for "not defined" — the test suite (a debug build) would pass and
    /// the release binary would answer differently. It happened here once: the
    /// session's leaf test asked `try_get_raw("file").is_ok()`, passed every
    /// test, and in release put the session image back into `dump save`.
    #[test]
    fn definedness_is_never_read_from_a_matches_error() {
        let src = include_str!("main.rs");
        let product = &src[..src.find("\n#[cfg(test)]").expect("test modules follow the product code")];
        let bad: Vec<&str> = product
            .lines()
            .filter(|l| {
                let code = l.split("//").next().unwrap_or("");
                ["try_get_raw(", "try_get_one", "try_get_many", "try_contains_id("].iter().any(|f| code.contains(f))
                    && [".is_ok()", ".is_err()", "Err("].iter().any(|r| code.contains(r))
            })
            .collect();
        assert!(bad.is_empty(), "a clap `try_get_*` error read as an answer (debug-only): {bad:?}");
    }

    /// The payload's new id must still land in its field.
    #[test]
    fn the_file_to_store_still_reaches_its_field() {
        let cli = Cli::try_parse_from(["n0xis", "dump", "save", "--name", "t", "--kind", "raw", "--file", "x.bin"]).expect("parse dump save");
        let Command::Dump(DumpCmd::Save(d)) = cli.command else { panic!("not dump save") };
        assert_eq!(d.file.as_deref(), Some("x.bin"));
    }
}

#[cfg(test)]
mod stdin_gate_tests {
    use std::path::{Path, PathBuf};

    /// Where a direct `stdin()` call is allowed, as `(file, enclosing fn, why)`.
    /// Everything else must go through `command_stdin`.
    const ALLOWED: &[(&str, &str, &str)] = &[
        ("n0xis-cli/src/main.rs", "command_stdin", "the gate itself"),
        ("n0xis-cli/src/main.rs", "cmd_serve", "the session's own request channel"),
        ("n0xis-cli/src/main.rs", "cmd_remote_serve", "a request channel of its own; refused inside a session"),
    ];

    fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                rs_files(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// A `serve` session reads its requests from stdin, so a command that read
    /// stdin itself consumed requests as input. `command_stdin` refuses inside
    /// a session; this keeps every reader behind it. Product code only — every
    /// crate's `src/`, up to its first `#[cfg(test)]`.
    #[test]
    fn stdin_has_one_gate() {
        let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("crates/").to_path_buf();
        let mut files = Vec::new();
        for c in std::fs::read_dir(&crates).expect("read crates/").flatten() {
            rs_files(&c.path().join("src"), &mut files);
        }
        assert!(files.len() > 20, "the walk found the workspace's sources ({} files)", files.len());

        let mut found: Vec<(String, String)> = Vec::new();
        for f in &files {
            let text = std::fs::read_to_string(f).expect("read source");
            let product = &text[..text.find("\n#[cfg(test)]").unwrap_or(text.len())];
            let rel = f.strip_prefix(&crates).expect("under crates/").to_string_lossy().replace('\\', "/");
            let mut current_fn = String::new();
            for line in product.lines() {
                let code = line.split("//").next().unwrap_or("");
                // `fn name(`, after any qualifiers (`pub(crate)`, `const`, …).
                let mut words = code.split_whitespace().skip_while(|w| *w != "fn");
                if words.next().is_some()
                    && let Some(name) = words.next()
                {
                    current_fn = name.split(['(', '<']).next().unwrap_or("").to_string();
                }
                // `stdin()` as its own name (`io::stdin()`), not the tail of
                // another (`command_stdin()`).
                let direct = code.match_indices("stdin()").any(|(i, _)| {
                    !code[..i].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_')
                });
                if direct {
                    found.push((rel.clone(), current_fn.clone()));
                }
            }
        }
        let stray: Vec<&(String, String)> =
            found.iter().filter(|(f, func)| !ALLOWED.iter().any(|(af, afn, _)| af == f && afn == func)).collect();
        assert!(stray.is_empty(), "stdin read outside `command_stdin` (inside a session it is the request channel): {stray:?}");
        for (f, func, why) in ALLOWED {
            assert!(
                found.iter().any(|(ff, fun)| ff == f && fun == func),
                "stale exemption {f}::{func} ({why}) — it no longer reads stdin; remove it"
            );
        }
        eprintln!("stdin readers: {} allowed, {} in all", ALLOWED.len(), found.len());
    }
}

#[cfg(test)]
mod sig_gen_tests {
    use super::*;

    /// A relative `call`'s 4 displacement bytes vary between builds, so the
    /// generator must wildcard exactly them and keep every other byte fixed.
    #[test]
    fn wildcards_a_relative_call_displacement() {
        // sub rsp,0x28 ; call rel32 ; add rsp,0x28 ; ret
        let window = [0x48, 0x83, 0xec, 0x28, 0xe8, 0x11, 0x22, 0x33, 0x44, 0x48, 0x83, 0xc4, 0x28, 0xc3];
        let arch = X64::default();
        let (pat, fixed) = generate_pattern(&window, Va(0x1000), &arch).unwrap();
        assert_eq!(pat, "48 83 ec 28 e8 .. .. .. .. 48 83 c4 28 c3");
        assert_eq!(fixed, 10); // 14 bytes − 4 wildcarded displacement bytes
    }

    /// A RIP-relative `lea` displacement is `rip_target − (va + len)`, located
    /// by its little-endian value inside the instruction; it too is wildcarded.
    #[test]
    fn wildcards_a_rip_relative_displacement() {
        // lea rax,[rip+0x0] ; ret  → disp32 = 0, at instruction bytes [3..7]
        let window = [0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, 0xc3];
        let arch = X64::default();
        let (pat, _fixed) = generate_pattern(&window, Va(0x2000), &arch).unwrap();
        assert_eq!(pat, "48 8d 05 .. .. .. .. c3");
    }

    /// A trailing relocated displacement (a tail-call/jump ending the window) is
    /// trimmed, not left as dangling wildcards.
    #[test]
    fn trims_a_trailing_relocated_tail_call() {
        // xor eax,eax ; jmp rel32  → the jump's disp is the window's tail
        let window = [0x31, 0xc0, 0xe9, 0xaa, 0xbb, 0xcc, 0xdd];
        let arch = X64::default();
        let (pat, _fixed) = generate_pattern(&window, Va(0x3000), &arch).unwrap();
        assert_eq!(pat, "31 c0 e9");
    }

    /// CRT/linker scaffolding is recognized as glue (so the default corpus omits
    /// it), while a genuine library function is not.
    #[test]
    fn recognizes_toolchain_glue_but_not_library_code() {
        for g in ["_init", "_fini", "register_tm_clones", "frame_dummy", "__x86.get_pc_thunk.bx"] {
            assert!(is_toolchain_glue(g), "{g} should be glue");
        }
        for real in ["crc32", "deflate", "std::vector", "memcpy", "SSL_connect"] {
            assert!(!is_toolchain_glue(real), "{real} is library code, not glue");
        }
    }
}
