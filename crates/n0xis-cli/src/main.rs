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
use n0xis_arch::{Arch, Arm64, X64};
use n0xis_contracts::{Response, Va, schema};
use n0xis_contracts::{TableEntry, TableLocator, TableValueType};
use n0xis_core::{
    build_trampoline, game_grep_rank, identify_f64, identify_u64, parse_aob, parse_mask,
    parse_sample, sig_validate, AobArtifact, AobInput, AobScanPass, BindingsInput, BindingsPass,
    CfgInput, ConstMatch, CoreError, Ctx, DecompInput, DecompPass, DecompStyle, DeobfuscatePass,
    DiffInput, DiffPass, DiscoverInput, DiscoverPass, DissectInput, DissectPass, Document,
    FilterCriterion, FilterInput, FilterPass, ManifestCandidate, ManifestInput, ManifestPass,
    MaskByte, Pass, PointerPathInput, PointerPathPass, PointerRoot, ProvenanceHit, ProvenanceInput,
    ProvenancePass, RankOptions, ScanCriterion, ScanInput, ScanPass, ScanState, ScanValue,
    SigValidateInput, SsaPass, StringXrefInput, StringXrefPass, TraceInput, TracePass, ValueSetPass,
    ValueType, XrefDir, XrefInput, XrefPass,
};
use n0xis_core::{AabbLayout, CoordSpace, Rect, UiLocateInput, UiLocatePass};
use n0xis_pipeline::{Pipeline, cfg_cached};
use n0xis_sources::{
    LiveProcess, MemorySource, RemoteAgent, Snapshot, StaticPe, WatchKind, attach_and_wait, await_breakpoint_hit,
    await_watchpoint_hit, await_watchpoint_hit_where, list_processes, probe_actuation, remote_serve_stdio, RegCond, DEFAULT_PROBE_VK,
};
use n0xis_sources::{best_window, encode_png, focus as window_focus, list_windows, screenshot as window_screenshot, CaptureMethod};
use serde_json::json;

use emit::emit;

use n0xis_bitsquid::{lua_resource, open_bundle, LuaFormat};

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

#[derive(Args)]
struct GuideArgs {
    /// Filter the catalog to commands whose path contains this substring
    /// (e.g. `scan`, `provenance`, `game`). Omit for the full catalog.
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
    /// Structural diffing at the IR/pseudo level (Phase 7): agent-friendly
    /// change reports between two functions (e.g. two builds of a binary).
    #[command(subcommand)]
    Diff(DiffCmd),
    /// Bitsquid/Stingray game-engine bundle files (chunked-zlib archive +
    /// exploded-package entries/variants) — reading game assets, not process
    /// memory.
    #[command(subcommand)]
    Bundle(BundleCmd),
    /// Lua/LuaJIT bytecode disassembly.
    #[command(subcommand)]
    Lua(LuaCmd),
    /// Spec-first game RE (Phase 8): search a target's scripts/data/strings
    /// for a feature's vocabulary and rank by cluster density — the "climb the
    /// spec ladder, don't reverse runtime state" front door (RE_METHOD F2).
    #[command(subcommand)]
    Game(GameCmd),
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
    /// Screen region -> memory addresses, by hit-testing a live target's own
    /// retained scene graph from outside (Phase 9). No graphics-API hooking,
    /// no frame capture, no pixels — see docs/PHASE9_UI_LOCATE_BRIEF.md.
    #[command(subcommand)]
    Ui(UiCmd),
}

#[derive(Subcommand)]
enum UiCmd {
    /// Enumerate live UI elements whose bounding box intersects a screen rect.
    Locate(UiLocateArgs),
    /// List a process's top-level windows (title/class/rects/DPI) so an agent
    /// can name the game window before capturing or locating.
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
    /// defaults to the best-guess game window for the pid.
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
    /// game window for the pid.
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
enum GameCmd {
    /// Rank scripts/data/strings by how densely they cluster a concept's
    /// vocabulary. `<concept>` is the vocabulary (comma/space/pipe-separated),
    /// e.g. `"combo,interact,stratagem"`.
    Grep(GameGrepArgs),
}

#[derive(Args)]
struct GameGrepArgs {
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
    /// writable region — the default a memory scanner scan set.
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
}

#[derive(Subcommand)]
enum SigCmd {
    /// Report which bytes are invariant across samples; refuse to bless a
    /// signature from <3 deliberately-varied samples.
    Validate(SigValidateArgs),
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
    /// (`map,mission,seed`). Required to bless — an invariant is only
    /// meaningful relative to what changed.
    #[arg(long)]
    varied: Option<String>,
    /// Independence bar (default 3).
    #[arg(long, default_value_t = 3)]
    min_independent: usize,
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
    /// The bundle (archive) file — a hash-named file under the game's
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
    /// no `GCtab` calibration). Built for reading an interact-combo
    /// `{"up","down",…}` straight out of memory, but general to any
    /// array-of-known-tokens.
    Combo(LuaComboArgs),
    /// Recover an LCG seed from an observed sequence: scan a live process for a
    /// 4-byte word whose `s'=s*a+c` LCG reproduces a known combo, locating the
    /// seed field and validating the RNG model at once. Constants are flags
    /// (default = the Helldivers/Numerical-Recipes pair).
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
    /// The observed combo as directions (`up,down,down,up`) — mapped to the
    /// engine's `random(0,3)` codes `left=0,up=1,right=2,down=3`.
    #[arg(long)]
    combo: String,
    /// LCG multiplier `a` (default: Numerical Recipes / Helldivers).
    #[arg(long, default_value_t = 1664525)]
    lcg_a: u32,
    /// LCG increment `c` (default: Numerical Recipes / Helldivers).
    #[arg(long, default_value_t = 1013904223)]
    lcg_c: u32,
    /// Range size `k` for `random(0, k-1)` (4 directions).
    #[arg(long, default_value_t = 4)]
    range: u32,
    /// Constrain candidate seeds to `[1, 2^31-2]` (the game's `math.random`
    /// range) to cut coincidental matches. Pass `--no-seed-bound` to disable.
    #[arg(long = "no-seed-bound", action = clap::ArgAction::SetFalse)]
    seed_bound: bool,
}

#[derive(Args)]
struct LuaDisasmArgs {
    /// Path to a Lua chunk file (source text, stock bytecode, or LuaJIT
    /// bytecode — auto-detected from its header).
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
}

#[derive(Args)]
struct LuaTableArgs {
    #[arg(long)]
    pid: u32,
    /// Address of the `GCtab` object (hex `0x…`).
    #[arg(long)]
    addr: String,
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
    /// is the four interact-combo directions.
    #[arg(long, default_value = "up,down,left,right")]
    strings: String,
    /// Minimum consecutive matching elements to report as a run (filters
    /// coincidental single string pointers).
    #[arg(long, default_value_t = 2)]
    min_run: usize,
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
    #[arg(long, default_value_t = 64, value_parser = parse_hex_or_decimal_usize)]
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
    #[arg(long, default_value_t = 4096, value_parser = parse_hex_or_decimal_usize)]
    max_bytes: usize,
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
    /// Cap on the number of prologue-scan candidates; `0` = unlimited (default).
    #[arg(long, default_value_t = 0)]
    limit: usize,
    /// Discover from the PE `.pdata` exception table instead of prologue
    /// scanning: every function (with unwind info) with exact start+end, no
    /// heuristic and no cap. x64 PE images only (`--pid`/`--file`).
    #[arg(long)]
    pdata: bool,
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
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
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
    /// Light value-set / alias analysis over SSA (Phase 7): the bounded set
    /// of possible values each SSA variable can hold.
    ValueSet(IrArgs),
    /// Pattern-based deobfuscation report (Phase 7): junk instructions and
    /// value-set-provable opaque predicates.
    Deobfuscate(IrArgs),
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
    #[arg(long, value_parser = parse_hex_or_decimal_usize)]
    size: Option<usize>,
    /// Cap on discovered candidates to summarize.
    #[arg(long, default_value_t = 200)]
    limit: usize,
    /// Byte window handed to `ir build` per candidate.
    #[arg(long, default_value_t = 4096, value_parser = parse_hex_or_decimal_usize)]
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
    #[arg(long, value_parser = parse_hex_or_decimal_f64)]
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
        Command::Guide(a) => cmd_guide(a, pretty),
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
        Command::Ir(IrCmd::ValueSet(a)) => cmd_ir_value_set(a, pretty),
        Command::Ir(IrCmd::Deobfuscate(a)) => cmd_ir_deobfuscate(a, pretty),
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
        Command::Debug(DebugCmd::Attach(a)) => cmd_debug_attach(a, pretty),
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
        Command::Game(GameCmd::Grep(a)) => cmd_game_grep(a, pretty),
        Command::Locate(LocateCmd::ByTransition(a)) => cmd_locate_by_transition(a, pretty),
        Command::Input(InputCmd::Probe(a)) => cmd_input_probe(a, pretty),
        Command::Const(ConstCmd::Identify(a)) => cmd_const_identify(a, pretty),
        Command::Bindings(BindingsCmd::List(a)) => cmd_bindings_list(a, pretty),
        Command::Sig(SigCmd::Validate(a)) => cmd_sig_validate(a, pretty),
        Command::Ui(UiCmd::Locate(a)) => cmd_ui_locate(a, pretty),
        Command::Ui(UiCmd::Windows(a)) => cmd_ui_windows(a, pretty),
        Command::Ui(UiCmd::Screenshot(a)) => cmd_ui_screenshot(a, pretty),
        Command::Ui(UiCmd::Focus(a)) => cmd_ui_focus(a, pretty),
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
            "arch_arm64": { "ok": true, "name": Arm64::new().name() },
            "decoder": { "ok": true, "engines": ["iced-x86 (x64)", "disarm64 (arm64)"] },
            "project_resolves": { "ok": proj_ok, "dir": proj_dir, "local": proj_local },
        },
        "roadmap": "Phases 1-7 complete — see ROADMAP.md",
    });
    emit(&Response::success(schema::v1::DOCTOR, data), pretty)
}

/// Which category a top-level command belongs to (curated grouping — clap
/// doesn't model categories, so this is the one hand-maintained mapping).
fn guide_category(top: &str) -> &'static str {
    match top {
        "doctor" | "guide" | "init" | "project" | "process" | "remote-serve" => "Environment & project",
        "module" | "disasm" | "ir" | "function" | "decomp" | "xref" | "diff" => "Static analysis & decompilation",
        "mem" | "scan" | "patch" | "table" | "debug" | "selection" | "dump" => "Live memory (a memory scanner class)",
        "provenance" | "annotate" | "snapshot" => "Provenance, annotations & snapshots",
        "game" | "locate" | "input" | "const" | "bindings" | "sig" => "Spec-first method tooling (Phase 8)",
        "ui" => "UI-layer localization (Phase 9)",
        "bundle" | "lua" => "Game-engine assets (Bitsquid/LuaJIT)",
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
            "name": "spec-first ladder (start here for any game feature)",
            "when": "you want to understand a game mechanic (a combo, a timer, a drop table). Climb top-down: data → scripts → native bindings → native code → memory. Each rung is cheaper and more stable than the one below.",
            "maps_to": "RE_METHOD F2/W4 — ~90% of a campaign was wasted reversing runtime state that was declaratively specified in scripts.",
            "steps": [
                "bundle list --file <archive>            # is there a script layer? extract it",
                "bundle extract --file <archive> --type lua --out ./scripts",
                "game grep \"combo,interact,stratagem\" --dir ./scripts   # find the feature's vocabulary cluster",
                "lua disasm --file ./scripts/<hit>.luac  # read the algorithm out of the script",
                "const identify --lua ./scripts/<hit>.luac  # recognize the RNG/hash by its constants",
                "bindings list --file <game.exe> --name next_random   # only now go native, and only for what scripts call",
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
                "table add --name found --pid <p> --address <hit> --type i32   # pin the survivor"
            ]
        }),
        json!({
            "name": "explain a runtime value (what code wrote it)",
            "when": "you have an address and want the source-level statement responsible — the fusion of live watchpoint + decompiler.",
            "maps_to": "Phase 4c principal; RE_METHOD F1 (stop chasing view/cache indirection).",
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
                "input probe --pid <p>   # reports which methods carry LLKHF_INJECTED (a filtering game ignores those)"
            ]
        }),
        json!({
            "name": "validate a signature before trusting it",
            "when": "you have a candidate byte pattern / marker and want to know if it is real or an N=2 coincidence.",
            "maps_to": "RE_METHOD F3 — a marker matched two same-seed instances and shipped broken.",
            "steps": [
                "sig validate --sample <hex-a> --sample <hex-b> --sample <hex-c> --varied map,mission,seed --signature \"48 8B ?? 68\"",
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
        "tagline": "Agent-native reverse-engineering + live-memory toolkit — contract-first CLI and MCP over the same pipeline, static PE and live process alike.",
        "usage_model": "Pick a command from `commands` (or a recipe from `workflows`). Every command emits the same { ok, data, meta } envelope on stdout; add --pretty for indented JSON; meta.schema names the payload shape. Progress goes to stderr with a [n0x] prefix (safe to ignore, or silence with --quiet). Non-zero exit on ok:false.",
        "global_flags": [
            { "name": "--pretty", "help": "indent the JSON envelope" },
            { "name": "--json", "help": "strict JSON-only stdout (already the default)" },
            { "name": "--quiet", "help": "suppress [n0x] stderr progress" }
        ],
        "sources": "commands that read a target accept exactly one of: --pid <live process>, --file <static PE>, --snapshot <name of a captured snapshot dump>, --remote-cmd \"<argv, e.g. ssh host n0xis remote-serve --pid N>\", or --bytes \"<hex>\" (inline). Live VAs respect ASLR; static VAs use the image's preferred base.",
        "envelope": "every command emits { ok, data, meta } or { ok:false, error:{code,message,hint?} }; meta.schema is the payload id (n0xis.*.v1, or the archived n0x.*.v1 for ported v0 shapes).",
        "architectures": [
            "x64 — iced-x86, full pipeline: CFG / SSA / type recovery / optimized decompile",
            "arm64 — disarm64, CFG / discover / xref / goto+structured decompile (SSA optimization is x64-only so far); pass --arch arm64"
        ],
        "categories": categories,
        "command_count": commands.len(),
        "commands": commands,
        "workflows": workflows,
        "mcp": "the same pipeline is exposed as an MCP server (binary n0xis-mcp) over stdio, with the same tool names and { ok, data, meta } shapes — an agent's parsing code is identical whether it calls the CLI or MCP.",
        "docs": ["README.md", "CONCEPT.md", "ROADMAP.md", "docs/RE_METHOD.md"],
        "hint": "narrow with `n0x guide <topic>` (e.g. `n0x guide scan`, `n0x guide game`); every command also has clap `--help` for the exact usage line. `n0x guide --brief` drops per-arg detail.",
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
    let arch = match resolve_arch(a.arch.as_deref()) {
        Ok(a) => a,
        Err(e) => return ir_err("bad-arch", &e, pretty),
    };
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
        Src::Static(pe) => work(&Ctx::new(pe.as_ref(), arch.as_ref()).with_symbols(pe.as_ref()).with_modules(pe.as_ref()), input, label),
        Src::Live(l) => work(&Ctx::new(l.as_ref(), arch.as_ref()), input, label),
        Src::Snap(s) => work(&Ctx::new(s, arch.as_ref()), input, label),
        Src::Remote(r) => work(&Ctx::new(r.as_ref(), arch.as_ref()), input, label),
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

fn cmd_ir_value_set(a: IrArgs, pretty: bool) -> bool {
    run_ir(&a, pretty, |ctx, input, label| {
        let cfg = match cfg_cached(ctx, input) {
            Ok((c, _cached)) => c,
            Err(e) => return ir_err("ir-failed", &e.to_string(), pretty),
        };
        let ssa = match SsaPass.run(ctx, cfg) {
            Ok(s) => s,
            Err(e) => return ir_err("ssa-failed", &e.to_string(), pretty),
        };
        match ValueSetPass.run(ctx, ssa) {
            Ok(art) => emit(&Response::success(schema::v1::VALUE_SET, art).with_source(label), pretty),
            Err(e) => ir_err("value-set-failed", &e.to_string(), pretty),
        }
    })
}

fn cmd_ir_deobfuscate(a: IrArgs, pretty: bool) -> bool {
    run_ir(&a, pretty, |ctx, input, label| {
        let cfg = match cfg_cached(ctx, input) {
            Ok((c, _cached)) => c,
            Err(e) => return ir_err("ir-failed", &e.to_string(), pretty),
        };
        match DeobfuscatePass.run(ctx, cfg) {
            Ok(art) => emit(&Response::success(schema::v1::DEOBFUSCATE, art).with_source(label), pretty),
            Err(e) => ir_err("deobfuscate-failed", &e.to_string(), pretty),
        }
    })
}

/// Decompile one function (`goto` style by default — stable/deterministic,
/// the best shape to diff) and return its pseudo-C lines + provenance label.
fn decompile_one(
    pid: Option<u32>,
    file: Option<&str>,
    bytes: Option<&str>,
    addr: Va,
    size: usize,
    style: DecompStyle,
    arch: &dyn Arch,
) -> Result<(Vec<String>, String), (String, String)> {
    let (src, label, _) = build_source(pid, file, bytes, None, None, addr)?;
    let input = CfgInput { start: addr, max_bytes: size, auto_end: true };
    let run = |ctx: &Ctx| -> Result<Vec<String>, (String, String)> {
        let (cfg, _cached) = cfg_cached(ctx, input).map_err(|e| ("ir-failed".to_string(), e.to_string()))?;
        let pf = DecompPass
            .run(ctx, DecompInput { cfg, style })
            .map_err(|e| ("decomp-failed".to_string(), e.to_string()))?;
        Ok(pf.pseudo)
    };
    let pseudo = match &src {
        Src::Static(pe) => run(&Ctx::new(pe.as_ref(), arch).with_symbols(pe.as_ref())),
        Src::Live(l) => run(&Ctx::new(l.as_ref(), arch)),
        Src::Snap(s) => run(&Ctx::new(s, arch)),
        Src::Remote(r) => run(&Ctx::new(r.as_ref(), arch)),
    }?;
    Ok((pseudo, label))
}

fn cmd_diff_functions(a: DiffFunctionsArgs, pretty: bool) -> bool {
    let a_addr = match Va::parse(&a.a_addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let b_addr = match Va::parse(&a.b_addr) {
        Ok(v) => v,
        Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
    };
    let style: DecompStyle = a.style.into();
    let arch = match resolve_arch(a.arch.as_deref()) {
        Ok(a) => a,
        Err(e) => return ir_err("bad-arch", &e, pretty),
    };

    let (pseudo_a, label_a) = match decompile_one(a.a_pid, a.a_file.as_deref(), a.a_bytes.as_deref(), a_addr, a.size, style, arch.as_ref()) {
        Ok(x) => x,
        Err((c, m)) => return ir_err(&format!("a-{c}"), &m, pretty),
    };
    let (pseudo_b, label_b) = match decompile_one(a.b_pid, a.b_file.as_deref(), a.b_bytes.as_deref(), b_addr, a.size, style, arch.as_ref()) {
        Ok(x) => x,
        Err((c, m)) => return ir_err(&format!("b-{c}"), &m, pretty),
    };

    let snap = Snapshot::builder().build();
    let ctx = Ctx::new(&snap, arch.as_ref());
    match DiffPass.run(&ctx, DiffInput { a: pseudo_a, b: pseudo_b }) {
        Ok(art) => emit(
            &Response::success(schema::v1::DIFF, art).with_source(format!("a={label_a} b={label_b}")),
            pretty,
        ),
        Err(e) => ir_err("diff-failed", &e.to_string(), pretty),
    }
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

/// Split `"0x…"`/`"0X…"`/`"…h"`/`"…H"` off a hex-formatted number, same
/// acceptance as [`Va::parse`]; returns the bare digits, or `None` for a plain
/// decimal string.
fn strip_hex_marker(t: &str) -> Option<&str> {
    t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).or_else(|| t.strip_suffix('h').or_else(|| t.strip_suffix('H')))
}

/// clap `value_parser` for byte-count-like `usize` fields (`--size`,
/// `--*-size`, `--max-bytes`, `--len`, `--cave-size`, …): accepts hex
/// (`0x1000`) or decimal, the same acceptance `--addr`/`--start` already get
/// via `Va::parse`. Sizes taken from a PE section header or a `dump`/`scan`
/// report are routinely read off in hex; forcing a hand hex→decimal
/// conversion is exactly the ergonomics gap RE_METHOD F7 called out for
/// `--min`/`--max` ("burned two scan rounds on a range that wasn't even
/// close") — the same fix, applied everywhere a byte length is taken.
fn parse_hex_or_decimal_usize(s: &str) -> Result<usize, String> {
    let t = s.trim();
    let v = match strip_hex_marker(t) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => t.parse::<u64>(),
    };
    v.map(|v| v as usize).map_err(|_| format!("invalid size {s:?} (want decimal or 0x-prefixed hex)"))
}

/// Same acceptance as [`parse_hex_or_decimal_usize`], for `u64`-typed fields
/// (e.g. `--max-offset`).
fn parse_hex_or_decimal_u64(s: &str) -> Result<u64, String> {
    let t = s.trim();
    match strip_hex_marker(t) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => t.parse::<u64>(),
    }
    .map_err(|_| format!("invalid value {s:?} (want decimal or 0x-prefixed hex)"))
}

/// clap `value_parser` for scan value/bound fields (`--value`, `--min`,
/// `--max`): accepts hex, decimal, or a float. Falls through to
/// `f64::from_str` when there's no hex marker, since a scan criterion can
/// compare against a genuine float (`3.14`), which plain hex can't represent.
fn parse_hex_or_decimal_f64(s: &str) -> Result<f64, String> {
    let t = s.trim();
    if let Some(hex) = strip_hex_marker(t) {
        return u64::from_str_radix(hex, 16)
            .map(|v| v as f64)
            .map_err(|_| format!("invalid value {s:?} (want decimal, float, or 0x-prefixed hex)"));
    }
    t.parse::<f64>().map_err(|_| format!("invalid value {s:?} (want decimal, float, or 0x-prefixed hex)"))
}

/// Resolve `--arch` (default `x64`) into a concrete [`Arch`] (ROADMAP Phase 7:
/// multi-arch via the ISA seam). `n0xis_core` never sees which one was
/// picked — it only ever runs against `&dyn Arch`.
fn resolve_arch(name: Option<&str>) -> Result<Box<dyn Arch>, String> {
    match name.unwrap_or("x64").to_ascii_lowercase().as_str() {
        "x64" | "x86-64" | "x86_64" => Ok(Box::new(X64::new())),
        "arm64" | "aarch64" => Ok(Box::new(Arm64::new())),
        other => Err(format!("unknown --arch '{other}', expected x64|arm64")),
    }
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
    let arch = match resolve_arch(a.arch.as_deref()) {
        Ok(a) => a,
        Err(e) => return ir_err("bad-arch", &e, pretty),
    };
    // `.pdata` discovery reads the whole module (headers + exception table), not
    // a `.text` byte window — resolve the module base and dispatch before the
    // range logic the prologue scan needs.
    if a.pdata {
        let module_base = match &src {
            Src::Static(pe) => Some(pe.image_base()),
            Src::Live(l) => l.main_module().map(|m| m.base),
            Src::Snap(_) | Src::Remote(_) => None,
        };
        let Some(base) = module_base else {
            return ir_err("no-module", "--pdata needs a PE image with a module base (--pid or --file)", pretty);
        };
        let run_pdata = |ctx: &Ctx| -> bool {
            match n0xis_core::discover_pdata(ctx.source, base) {
                Ok(functions) => {
                    let art = n0xis_core::DiscoverArtifact { start: base, scanned_bytes: 0, count: functions.len(), functions };
                    emit(&Response::success(schema::v1::FUNCTION_DISCOVER, art).with_source(label.clone()), pretty)
                }
                Err(e) => ir_err("discover-failed", &e.to_string(), pretty),
            }
        };
        return match &src {
            Src::Static(pe) => run_pdata(&Ctx::new(pe.as_ref(), arch.as_ref()).with_symbols(pe.as_ref())),
            Src::Live(l) => run_pdata(&Ctx::new(l.as_ref(), arch.as_ref())),
            Src::Snap(s) => run_pdata(&Ctx::new(s, arch.as_ref())),
            Src::Remote(r) => run_pdata(&Ctx::new(r.as_ref(), arch.as_ref())),
        };
    }

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
        Src::Static(pe) => run(&Ctx::new(pe.as_ref(), arch.as_ref()).with_symbols(pe.as_ref())),
        Src::Live(l) => run(&Ctx::new(l.as_ref(), arch.as_ref())),
        Src::Snap(s) => run(&Ctx::new(s, arch.as_ref())),
        Src::Remote(r) => run(&Ctx::new(r.as_ref(), arch.as_ref())),
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
    let rec = match pj::apply(&live, a.pid, addr, &desired) {
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
    let live = match LiveProcess::attach(pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    let restored_len = match parse_hex_bytes(&rec.before_hex) {
        Ok(b) => b.len(),
        Err(e) => return ir_err("bad-record", &e, pretty),
    };
    if let Err(e) = pj::undo(&mut rec, &live, a.force) {
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

fn resolve_scan_regions_live(live: &LiveProcess, start: Option<&str>, size: Option<usize>) -> Result<Vec<(Va, usize)>, String> {
    if let Some(s) = start {
        let va = Va::parse(s).map_err(|e| e.to_string())?;
        let sz = size.ok_or("provide --size with --start")?;
        // Clip the requested window to the process's committed regions: a live
        // range often spans unmapped gaps (e.g. LuaJIT's arena is many small
        // committed blocks), and a single `ReadProcessMemory` across a gap
        // fails *wholesale* — silently yielding zero hits. Intersecting with
        // the region map turns one doomed read into per-block reads that
        // actually land, and keeps a narrowed scan fast.
        let lo = va.0;
        let hi = va.0.saturating_add(sz as u64);
        let mut clipped: Vec<(Va, usize)> = Vec::new();
        for (rb, rs) in live.default_writable_regions() {
            let a = rb.0.max(lo);
            let b = (rb.0 + rs as u64).min(hi);
            if a < b {
                clipped.push((Va(a), (b - a) as usize));
            }
        }
        if clipped.is_empty() {
            // No committed writable page in the window — fall back to the raw
            // range so a deliberate single-region read (e.g. an RX/RO area not
            // in the writable set) still works as before.
            return Ok(vec![(va, sz)]);
        }
        return Ok(clipped);
    }
    let regions = live.default_writable_regions();
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
    let state = match ScanPass.run(ctx, ScanInput { regions, value_type, criterion, align }) {
        Ok(s) => s,
        Err(e) => return ir_err("scan-failed", &e.to_string(), pretty),
    };
    // Persist the full working set compactly; emit only the bounded report.
    if let Err(e) = n0xis_project::dump::save(save_as, "scan", &state.encode(), force) {
        return ir_err("save-failed", &e.to_string(), pretty);
    }
    emit(&Response::success(schema::v1::SCAN, state.report()).with_source(label), pretty)
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
    let prev: ScanState = match ScanState::decode(&prev_bytes) {
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
        let out = FilterPass.run(&ctx, FilterInput { previous: prev, criterion });
        (out, live.label())
    } else if let Some(file) = a.file.as_deref() {
        let pe = match StaticPe::load(std::path::Path::new(file)) {
            Ok(p) => p,
            Err(e) => return ir_err("load-failed", &e.to_string(), pretty),
        };
        let ctx = Ctx::new(&pe, &arch);
        let out = FilterPass.run(&ctx, FilterInput { previous: prev, criterion });
        (out, pe.label())
    } else {
        return ir_err("missing-source", "provide --pid or --file", pretty);
    };
    let out = match out {
        Ok(o) => o,
        Err(e) => return ir_err("filter-failed", &e.to_string(), pretty),
    };
    // Persist the narrowed working set; emit only the bounded report.
    if let Err(e) = n0xis_project::dump::save(&a.save_as, "scan", &out.encode(), a.force) {
        return ir_err("save-failed", &e.to_string(), pretty);
    }
    emit(&Response::success(schema::v1::SCAN, out.report()).with_source(label), pretty)
}

fn cmd_scan_aob(a: ScanAobArgs, pretty: bool) -> bool {
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
        // Explicit --start/--size scans exactly that one region; omitting
        // both falls back to every committed writable region (the same
        // default `scan value` uses) since a hit could be anywhere in the
        // process's dynamically-allocated memory (e.g. a scripting VM's heap).
        let regions = match resolve_scan_regions_live(&live, a.start.as_deref(), a.size) {
            Ok(r) => r,
            Err(e) => return ir_err("bad-region", &e, pretty),
        };
        let mut matches = Vec::new();
        let mut bytes_scanned = 0usize;
        for (start, size) in regions {
            match AobScanPass.run(&ctx, AobInput { start, size, pattern: pattern.clone() }) {
                Ok(art) => {
                    matches.extend(art.matches);
                    bytes_scanned += art.bytes_scanned;
                }
                // A region enumerated a moment ago can be freed/decommitted
                // by the target process before this scan reaches it — skip
                // it and keep scanning the rest, rather than aborting the
                // whole multi-gigabyte sweep over one stale region.
                Err(CoreError::Source(n0xis_sources::SourceError::Unmapped(_))) => continue,
                Err(e) => return ir_err("aob-failed", &e.to_string(), pretty),
            }
        }
        let art = AobArtifact { matches, bytes_scanned };
        return emit(&Response::success(schema::v1::AOB_SCAN, art).with_source(label), pretty);
    }
    if let Some(file) = a.file.as_deref() {
        let (Some(start_s), Some(size)) = (a.start.as_deref(), a.size) else {
            return ir_err("missing-region", "provide --start and --size for --file", pretty);
        };
        let start = match Va::parse(start_s) {
            Ok(v) => v,
            Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
        };
        let pe = match StaticPe::load(std::path::Path::new(file)) {
            Ok(p) => p,
            Err(e) => return ir_err("load-failed", &e.to_string(), pretty),
        };
        let label = pe.label();
        let ctx = Ctx::new(&pe, &arch);
        return match AobScanPass.run(&ctx, AobInput { start, size, pattern }) {
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
    let cond = match a.when.as_deref().map(RegCond::parse).transpose() {
        Ok(c) => c,
        Err(e) => return ir_err("bad-when", &e, pretty),
    };
    match await_watchpoint_hit_where(a.pid, watch_va, kind, a.len, a.timeout_ms, a.stack_qwords, module.as_ref(), cond.as_ref())
    {
        Ok(outcome) => emit(&Response::success(schema::v1::WATCHPOINT, outcome).with_source(label), pretty),
        Err(e) => ir_err("watch-failed", &e.to_string(), pretty),
    }
}

fn cmd_debug_attach(a: DebugAttachArgs, pretty: bool) -> bool {
    match attach_and_wait(a.pid, a.timeout_ms) {
        Ok(()) => emit(
            &Response::success(schema::v1::DEBUG_ATTACH, json!({ "pid": a.pid, "timeout_ms": a.timeout_ms, "detached": true })),
            pretty,
        ),
        Err(e) => ir_err("attach-failed", &e.to_string(), pretty),
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

fn cmd_table_freeze(a: TableFreezeArgs, pretty: bool) -> bool {
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
        for variant in &entry.variants {
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
            let out_path = format!("{out_dir}/{:016x}.{ext}", entry.path_hash);
            if let Err(e) = std::fs::write(&out_path, &bytes) {
                return ir_err("write-failed", &format!("write {out_path}: {e}"), pretty);
            }
            extracted.push(json!({
                "path_hash": format!("{:016x}", entry.path_hash),
                "out_path": out_path,
                "size": bytes.len(),
                "format": format,
            }));
        }
    }
    let data = json!({ "count": extracted.len(), "out_dir": out_dir, "extracted": extracted });
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
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    let regions = match resolve_scan_regions_live(&live, a.start.as_deref(), a.size) {
        Ok(r) => r,
        Err(e) => return ir_err("bad-region", &e, pretty),
    };
    let label = live.label();
    let mut hits = n0xis_luajit::scan_strings(&live, &regions, n0xis_luajit::GcstrLayout::HELLDIVERS_GC64, a.min_len, a.max_len);
    if let Some(needle) = &a.contains {
        hits.retain(|h| h.text.contains(needle.as_str()));
    }
    let data = json!({ "matches": hits, "count": hits.len() });
    emit(&Response::success(schema::v1::LUA_STRINGS, data).with_source(label), pretty)
}

/// Render one decoded `TValue` as JSON, resolving a string's text from the
/// live process so the dump is readable (`{"kind":"str","text":"up"}`) rather
/// than just an address to chase by hand.
fn tvalue_json(v: &n0xis_luajit::TValue, live: &LiveProcess, layout: n0xis_luajit::LuaLayout) -> serde_json::Value {
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
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    let layout = n0xis_luajit::LuaLayout::HELLDIVERS;
    let Some(dump) = n0xis_luajit::read_table(&live, addr, layout) else {
        return ir_err("not-a-table", "could not decode a GCtab at this address (wrong address or layout needs calibration)", pretty);
    };
    let array: Vec<serde_json::Value> = dump.array.iter().map(|v| tvalue_json(v, &live, layout)).collect();
    let hash: Vec<serde_json::Value> = dump
        .hash
        .iter()
        .map(|(k, v)| json!({ "key": tvalue_json(k, &live, layout), "value": tvalue_json(v, &live, layout) }))
        .collect();
    let label = live.label();
    let data = json!({
        "addr": dump.addr.to_string(),
        "asize": dump.asize,
        "hmask": dump.hmask,
        "array": array,
        "hash": hash,
    });
    emit(&Response::success(schema::v1::LUA_STRINGS, data).with_source(label), pretty)
}

fn cmd_lua_combo(a: LuaComboArgs, pretty: bool) -> bool {
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    let regions = match resolve_scan_regions_live(&live, a.start.as_deref(), a.size) {
        Ok(r) => r,
        Err(e) => return ir_err("bad-region", &e, pretty),
    };
    let wanted: Vec<String> = a.strings.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if wanted.is_empty() {
        return ir_err("no-strings", "--strings must list at least one token", pretty);
    }
    let layout = n0xis_luajit::GcstrLayout::HELLDIVERS_GC64;
    // Longest token bounds the GCstr scan; the combo tokens are short ASCII.
    let max_len = wanted.iter().map(|s| s.len()).max().unwrap_or(0) as u32;
    // Every candidate GCstr whose text is one of the wanted tokens becomes a
    // target address — the run cross-check discards any that aren't referenced.
    let strs = n0xis_luajit::scan_strings(&live, &regions, layout, 1, max_len.max(1));
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
    // A combo array may be laid out as 8-byte Lua `TValue`s or as a packed
    // 4-byte `GCRef` array (Bitsquid's `array`); scan for both and tag which.
    let mut runs_json: Vec<serde_json::Value> = Vec::new();
    let tv = n0xis_luajit::find_string_runs(&live, &regions, &targets, a.min_run);
    for r in &tv {
        runs_json.push(json!({ "addr": r.addr.to_string(), "kind": "tvalue8", "len": r.values.len(), "values": r.values }));
    }
    let gr = n0xis_luajit::find_gcref32_runs(&live, &regions, &targets, a.min_run);
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

/// `random(0,3)` direction codes, from the game's `modify_random_combo_inputs`:
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
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    let regions = match resolve_scan_regions_live(&live, a.start.as_deref(), a.size) {
        Ok(r) => r,
        Err(e) => return ir_err("bad-region", &e, pretty),
    };
    let lcg = n0xis_luajit::Lcg { a: a.lcg_a, c: a.lcg_c };
    let bounds = if a.seed_bound { Some((1u32, 0x7FFF_FFFEu32)) } else { None };
    let hits = n0xis_luajit::find_seeds(&live, &regions, &lcg, a.range, &target, bounds);
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
/// whitespace — so `"combo,interact|stratagem"` and `"combo interact"` both work.
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
    if bytes.starts_with(&[0x1b, b'L', b'J']) {
        if let Ok(chunk) = n0xis_lua::disassemble(&bytes) {
            return Some(Document { id, kind: "lua".into(), text: lua_chunk_to_text(&chunk) });
        }
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

fn cmd_game_grep(a: GameGrepArgs, pretty: bool) -> bool {
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
    let art = game_grep_rank(&terms, &docs, &opts);
    emit(
        &Response::success(schema::v1::GAME_GREP, art).with_source(a.dirs.join(",")),
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
    let arch = X64::new();
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    let regions = match resolve_scan_regions_live(&live, a.start.as_deref(), a.size) {
        Ok(r) => r,
        Err(e) => return ir_err("bad-region", &e, pretty),
    };
    let label = live.label();
    let ctx = Ctx::new(&live, &arch);

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
    } else {
        eprintln!("[n0x] toggle exactly one thing in the target, then press Enter to rescan…");
        let mut _line = String::new();
        let _ = std::io::stdin().read_line(&mut _line);
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

fn cmd_input_probe(a: InputProbeArgs, pretty: bool) -> bool {
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
    let arch = X64::new();
    let input = CfgInput { start: addr, max_bytes: a.func_size, auto_end: true };
    let run = |ctx: &Ctx| -> Result<Vec<String>, (String, String)> {
        let (cfg, _cached) = cfg_cached(ctx, input).map_err(|e| ("ir-failed".to_string(), e.to_string()))?;
        let pf = DecompPass
            .run(ctx, DecompInput { cfg, style: DecompStyle::Goto })
            .map_err(|e| ("decomp-failed".to_string(), e.to_string()))?;
        Ok(pf.pseudo)
    };
    let pseudo = match &src {
        Src::Static(pe) => run(&Ctx::new(pe.as_ref(), &arch).with_symbols(pe.as_ref())),
        Src::Live(l) => run(&Ctx::new(l.as_ref(), &arch)),
        Src::Snap(s) => run(&Ctx::new(s, &arch)),
        Src::Remote(r) => run(&Ctx::new(r.as_ref(), &arch)),
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
    let arch = X64::new();

    let (default_text, default_data) = match &src {
        Src::Static(pe) => (pe.text_range(), pe.section_range(".rdata").or_else(|| pe.text_range())),
        Src::Live(l) => {
            if let Some(modname) = &a.module {
                use n0xis_sources::ModuleProvider;
                let needle = modname.to_lowercase();
                match l.modules().iter().find(|m| m.name.to_lowercase().contains(&needle)).map(|m| m.base) {
                    Some(base) => (
                        l.section_range_of(base, ".text"),
                        l.section_range_of(base, ".rdata").or_else(|| l.section_range_of(base, ".text")),
                    ),
                    None => return ir_err("no-module", &format!("no loaded module name contains '{modname}'"), pretty),
                }
            } else {
                (l.text_range(), l.section_range(".rdata").or_else(|| l.text_range()))
            }
        }
        Src::Snap(_) | Src::Remote(_) => (None, None),
    };
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
        Src::Static(pe) => run(&Ctx::new(pe.as_ref(), &arch).with_symbols(pe.as_ref())),
        Src::Live(l) => run(&Ctx::new(l.as_ref(), &arch)),
        Src::Snap(s) => run(&Ctx::new(s, &arch)),
        Src::Remote(r) => run(&Ctx::new(r.as_ref(), &arch)),
    }
}

fn cmd_sig_validate(a: SigValidateArgs, pretty: bool) -> bool {
    let mut samples: Vec<Vec<u8>> = Vec::new();

    // Inline hex samples.
    for s in &a.samples {
        match parse_sample(s) {
            Ok(b) => samples.push(b),
            Err(e) => return ir_err("bad-sample", &e, pretty),
        }
    }
    // File samples.
    for f in &a.sample_files {
        match std::fs::read(f) {
            Ok(b) => samples.push(b),
            Err(e) => return ir_err("read-failed", &format!("read {f}: {e}"), pretty),
        }
    }
    // Read-at samples from a live/static source.
    if !a.ats.is_empty() {
        let Some(len) = a.len else {
            return ir_err("missing-len", "--at needs --len <bytes>", pretty);
        };
        for at in &a.ats {
            let addr = match Va::parse(at) {
                Ok(v) => v,
                Err(e) => return ir_err("bad-addr", &e.to_string(), pretty),
            };
            let (src, _label, _) = match build_source(a.pid, a.file.as_deref(), None, None, None, addr) {
                Ok(x) => x,
                Err((c, m)) => return ir_err(&c, &m, pretty),
            };
            match src.as_mem().read(addr, len) {
                Ok(b) => samples.push(b),
                Err(e) => return ir_err("read-failed", &format!("read {addr}: {e}"), pretty),
            }
        }
    }

    if samples.is_empty() {
        return ir_err("no-samples", "provide samples via --sample, --sample-file, or --at (with --pid/--file and --len)", pretty);
    }

    let proposed: Option<Vec<MaskByte>> = match &a.signature {
        Some(sig) => match parse_mask(sig) {
            Ok(m) => Some(m),
            Err(e) => return ir_err("bad-signature", &e, pretty),
        },
        None => None,
    };
    let varied_axes: Vec<String> = a
        .varied
        .as_deref()
        .map(|s| s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect())
        .unwrap_or_default();

    let input = SigValidateInput { samples, proposed, varied_axes, min_independent: a.min_independent };
    let art = sig_validate(&input);
    emit(&Response::success(schema::v1::SIG_VALIDATE, art), pretty)
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
    let live = match LiveProcess::attach(a.pid) {
        Ok(l) => l,
        Err(e) => return ir_err("attach-failed", &e.to_string(), pretty),
    };
    let regions = match resolve_scan_regions_live(&live, a.start.as_deref(), a.size) {
        Ok(r) => r,
        Err(e) => return ir_err("bad-region", &e, pretty),
    };
    let label = live.label();
    let arch = X64::new();
    let ctx = Ctx::new(&live, &arch);

    let input = UiLocateInput {
        regions,
        rect,
        space: a.space.into(),
        layout: AabbLayout::HELLDIVERS,
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

fn cmd_ui_windows(a: UiWindowsArgs, pretty: bool) -> bool {
    let windows = list_windows(a.pid);
    let data = json!({
        "pid": a.pid,
        "count": windows.len(),
        "windows": windows,
        "coords": "physical",
        "note": "rect_frame is the canonical visible bounds for capture/input; rect_window includes the DWM shadow; rect_client is where the game renders. Pass an hwnd to `ui screenshot`/`ui focus`.",
    });
    emit(&Response::success(schema::v1::UI_WINDOWS, data).with_source(format!("pid:{}", a.pid)), pretty)
}

/// Resolve the target window: an explicit `--hwnd` (verified to actually belong
/// to `pid`, so a stale/foreign handle can't silently screenshot another
/// process while the envelope reports this pid), else the best-guess game
/// window for the pid. Returns the HWND integer or an error payload.
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

fn cmd_ui_focus(a: UiFocusArgs, pretty: bool) -> bool {
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
