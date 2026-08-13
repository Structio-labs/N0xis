//! The MCP tool set: one method per tool, registered via `#[tool_router]`.
//! Every tool returns the serialized `n0xis_contracts::Response` envelope as
//! a `String` — byte-for-byte the same shape `n0xis-cli`'s `emit()` prints —
//! so an agent's parsing code is identical across both frontends. Domain
//! failures (bad address, attach failed, ...) are `Response::error(...)`
//! returned as an *MCP-successful* tool call; only truly can't-happen
//! failures (serialization) would need the MCP-level error path, and none of
//! these tools hit that in practice.

use n0xis_arch::X64;
use n0xis_contracts::{Response, Va, schema};
use n0xis_core::{
    AabbLayout, CfgInput, CoordSpace, Ctx, DecodeInput, DecodePass, DecompInput, DecompPass,
    DecompStyle, DiscoverInput, DiscoverPass, Pass, ProvenanceHit, ProvenanceInput, ProvenancePass,
    Rect, UiLocateInput, UiLocatePass,
};
use n0xis_sources::{plugin_call_once, split_command_line, MemorySource};
#[cfg(windows)]
use n0xis_sources::{
    LiveProcess, ModuleProvider, WatchKind, await_watchpoint_hit, best_window,
    encode_png, focus, list_processes, list_windows, screenshot, CaptureMethod,
};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::N0xisServer;
use crate::source::{self, Src};

fn emit<T: serde::Serialize>(resp: Response<T>) -> String {
    serde_json::to_string(&resp)
        .unwrap_or_else(|e| format!("{{\"ok\":false,\"error\":{{\"code\":\"serialize\",\"message\":{e:?}}}}}"))
}

fn err(code: &str, msg: impl Into<String>) -> String {
    emit(Response::<serde_json::Value>::error(code, msg))
}

fn bad_addr(e: impl std::fmt::Display) -> String {
    err("bad-addr", e.to_string())
}

/// Build a `Ctx` for whichever source `resolve()` picked and hand it to `work`.
///
/// `arch` is a parameter, not a constant: this frontend used to name
/// `X64::new()` inline here, which quietly made every MCP tool x64-only while
/// the CLI had an `--arch` flag — the ISA seam existing in the core but being
/// bypassed at the edge (CONCEPT §3 rule 4).
fn with_ctx<R>(src: &Src, arch: &dyn n0xis_arch::Arch, work: impl FnOnce(&Ctx) -> R) -> R {
    match src {
        Src::Live(l) => work(&Ctx::new(l.as_ref(), arch)),
        Src::Static(p) => work(&Ctx::new(p.as_ref(), arch).with_symbols(p.as_ref()).with_modules(p.as_ref())),
        Src::Snap(s) => work(&Ctx::new(s, arch)),
        Src::Remote(r) => work(&Ctx::new(r.as_ref(), arch)),
    }
}

/// Resolve a tool's `arch` argument or bail with the shared error envelope.
macro_rules! arch_or_return {
    ($a:expr) => {
        match n0xis_frontend::resolve_arch($a.arch.as_deref()) {
            Ok(a) => a,
            Err(e) => return err("bad-arch", e),
        }
    };
}

macro_rules! resolve_or_return {
    ($a:expr) => {
        match source::resolve($a.pid, $a.file.as_deref(), $a.snapshot.as_deref(), $a.remote_cmd.as_deref()) {
            Ok(s) => s,
            Err((c, m)) => return err(&c, m),
        }
    };
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AttachRequest {
    /// PID of a running process to attach to (live source).
    #[serde(default)]
    pub pid: Option<u32>,
    /// Path to a PE file to load (static source). Provide exactly one of `pid`/`file`.
    #[serde(default)]
    pub file: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProcessPsRequest {
    #[serde(default)]
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ModuleListRequest {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub file: Option<String>,
    /// Reload a captured `snapshot dump` by name.
    #[serde(default)]
    pub snapshot: Option<String>,
    /// Attach over a remote transport, e.g. `"ssh host n0xis remote-serve --pid 1234"`.
    #[serde(default)]
    pub remote_cmd: Option<String>,
    #[serde(default)]
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisasmRequest {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub file: Option<String>,
    /// Reload a captured `snapshot dump` by name.
    #[serde(default)]
    pub snapshot: Option<String>,
    /// Attach over a remote transport, e.g. `"ssh host n0xis remote-serve --pid 1234"`.
    #[serde(default)]
    pub remote_cmd: Option<String>,
    /// Address to start disassembling at, e.g. `"0x140001000"`.
    pub addr: String,
    #[serde(default = "default_count")]
    pub count: usize,
    /// Instruction set to decode: `"x64"` (default) or `"arm64"`.
    #[serde(default)]
    pub arch: Option<String>,
}
fn default_count() -> usize {
    16
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DiscoverRequest {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub file: Option<String>,
    /// Reload a captured `snapshot dump` by name.
    #[serde(default)]
    pub snapshot: Option<String>,
    /// Attach over a remote transport, e.g. `"ssh host n0xis remote-serve --pid 1234"`.
    #[serde(default)]
    pub remote_cmd: Option<String>,
    /// Start of the scan range; defaults to the module's `.text`.
    #[serde(default)]
    pub start: Option<String>,
    #[serde(default)]
    pub size: Option<usize>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Skip this many candidates before collecting — page through a range
    /// together with `limit`.
    #[serde(default)]
    pub offset: Option<usize>,
    /// Instruction set to decode: `"x64"` (default) or `"arm64"`.
    #[serde(default)]
    pub arch: Option<String>,
}
fn default_limit() -> usize {
    64
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FunctionTraceRequest {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub file: Option<String>,
    /// Reload a captured `snapshot dump` by name.
    #[serde(default)]
    pub snapshot: Option<String>,
    /// Attach over a remote transport, e.g. `"ssh host n0xis remote-serve --pid 1234"`.
    #[serde(default)]
    pub remote_cmd: Option<String>,
    /// Root address (or RVA if `addr_rva` is set) to walk the call graph from.
    pub addr: String,
    #[serde(default)]
    pub addr_rva: bool,
    #[serde(default = "default_depth")]
    pub depth: usize,
    #[serde(default)]
    pub max_nodes: usize,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,
    /// Instruction set to decode: `"x64"` (default) or `"arm64"`.
    #[serde(default)]
    pub arch: Option<String>,
}
fn default_depth() -> usize {
    3
}
fn default_max_bytes() -> usize {
    4096
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DecompRequest {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub file: Option<String>,
    /// Reload a captured `snapshot dump` by name.
    #[serde(default)]
    pub snapshot: Option<String>,
    /// Attach over a remote transport, e.g. `"ssh host n0xis remote-serve --pid 1234"`.
    #[serde(default)]
    pub remote_cmd: Option<String>,
    /// Function start address, e.g. `"0x140001000"`.
    pub addr: String,
    #[serde(default = "default_max_bytes")]
    pub size: usize,
    #[serde(default)]
    pub no_auto_end: bool,
    /// One of `"goto"`, `"structured"`, `"ssa"` (default: `"ssa"`, the optimized + structured style).
    #[serde(default = "default_style")]
    pub style: String,
    /// Also return the per-round optimization delta (`ssa` style only). Off by
    /// default: measured larger than the pseudocode itself (59% of the
    /// payload). The `ir_opt_delta` tool is the dedicated way to ask for it.
    #[serde(default)]
    pub explain: Option<bool>,
    /// Instruction set to decode: `"x64"` (default) or `"arm64"`.
    #[serde(default)]
    pub arch: Option<String>,
}
fn default_style() -> String {
    "ssa".to_string()
}

/// A `DecompRequest` as the capability registry's JSON. The tool argument
/// names and the capability argument names are deliberately identical, so this
/// is a straight projection — no translation table to drift.
fn decomp_args_json(a: &DecompRequest) -> serde_json::Value {
    json!({
        "addr": a.addr,
        "size": a.size,
        "no_auto_end": a.no_auto_end,
        "style": a.style,
        "explain": a.explain.unwrap_or(false),
        "arch": a.arch,
        "pid": a.pid,
        "file": a.file,
        "snapshot": a.snapshot,
        "remote_cmd": a.remote_cmd,
    })
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct XrefRequest {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub file: Option<String>,
    /// Reload a captured `snapshot dump` by name.
    #[serde(default)]
    pub snapshot: Option<String>,
    /// Attach over a remote transport, e.g. `"ssh host n0xis remote-serve --pid 1234"`.
    #[serde(default)]
    pub remote_cmd: Option<String>,
    /// The address of interest.
    pub addr: String,
    /// `"to"` (who references `addr`) or `"from"` (what `addr` references).
    #[serde(default = "default_dir")]
    pub dir: String,
    #[serde(default)]
    pub start: Option<String>,
    #[serde(default)]
    pub size: Option<usize>,
    /// Instruction set to decode: `"x64"` (default) or `"arm64"`.
    #[serde(default)]
    pub arch: Option<String>,
}
fn default_dir() -> String {
    "to".to_string()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct XrefStringRequest {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub file: Option<String>,
    /// Reload a captured `snapshot dump` by name.
    #[serde(default)]
    pub snapshot: Option<String>,
    /// Attach over a remote transport, e.g. `"ssh host n0xis remote-serve --pid 1234"`.
    #[serde(default)]
    pub remote_cmd: Option<String>,
    /// The string literal to search for.
    pub query: String,
    #[serde(default)]
    pub data_start: Option<String>,
    #[serde(default)]
    pub data_size: Option<usize>,
    #[serde(default)]
    pub code_start: Option<String>,
    #[serde(default)]
    pub code_size: Option<usize>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Instruction set to decode: `"x64"` (default) or `"arm64"`.
    #[serde(default)]
    pub arch: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemReadRequest {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub file: Option<String>,
    /// Reload a captured `snapshot dump` by name.
    #[serde(default)]
    pub snapshot: Option<String>,
    /// Attach over a remote transport, e.g. `"ssh host n0xis remote-serve --pid 1234"`.
    #[serde(default)]
    pub remote_cmd: Option<String>,
    pub addr: String,
    pub size: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemWriteRequest {
    /// Live-process only (writing a static file's on-disk bytes isn't a thing).
    pub pid: u32,
    pub addr: String,
    /// Space- or contiguous-hex bytes, e.g. `"90 90 C3"` or `"9090C3"`.
    pub bytes: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProvenanceTraceRequest {
    pub pid: u32,
    /// Address of the value to watch.
    pub addr: String,
    /// `"execute"`, `"write"`, or `"read-or-write"`.
    #[serde(default = "default_watch_kind")]
    pub kind: String,
    #[serde(default = "default_watch_len")]
    pub len: u8,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}
fn default_watch_kind() -> String {
    "write".to_string()
}
fn default_watch_len() -> u8 {
    4
}
fn default_timeout_ms() -> u64 {
    5000
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnnotateSetRequest {
    pub addr: String,
    /// `"name"`, `"type"`, or `"comment"`.
    pub field: String,
    /// New value; omit to clear the field.
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnnotateShowRequest {
    pub addr: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PluginRunRequest {
    /// Which registered plugin (`.n0x/plugins.json`) to invoke.
    pub name: String,
    /// Artifact kind label sent to the plugin alongside `artifact`
    /// (`"cfg"`/`"pseudo"`/`"discover"`, or any caller-chosen string for a
    /// manual test invocation).
    pub kind: String,
    /// The artifact JSON to send on the plugin's stdin.
    pub artifact: serde_json::Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CapabilityRunRequest {
    /// Capability name, as reported by `capability_list` (e.g. `"decode"`).
    pub name: String,
    /// Arguments object, passed through to the capability unchanged.
    #[serde(default)]
    pub args: serde_json::Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UiLocateRequest {
    /// Live process to hit-test. `ui locate` is live-only: it reads the
    /// target's current retained scene graph.
    pub pid: u32,
    /// Query rectangle as `"x0,y0,x1,y1"` (any corner order).
    pub rect: String,
    /// `"auto"` (default), `"screen"`, or `"ndc"`. `auto` uses a permissive
    /// bound and reports the observed coordinate range, so you can tell which
    /// space the target's boxes are actually in instead of guessing.
    #[serde(default = "default_space")]
    pub space: String,
    /// Region start (hex). Omit (with `size`) to scan every committed
    /// writable region.
    #[serde(default)]
    pub start: Option<String>,
    #[serde(default)]
    pub size: Option<usize>,
    /// Byte stride between candidate positions (fields are dword-aligned).
    #[serde(default = "default_ui_align")]
    pub align: usize,
    #[serde(default = "default_ui_limit")]
    pub limit: usize,
    /// Persist this query's addresses under `.n0x/dumps/ui_locate/<name>.json`
    /// so a later query can `exclude_from` it (spatial-diff workflow).
    #[serde(default)]
    pub save_as: Option<String>,
    #[serde(default)]
    pub force: bool,
    /// Exclude every address found in these previously-saved queries — the
    /// spatial-diff filter (save a rect where the widget is absent, exclude it
    /// from one where it is present).
    #[serde(default)]
    pub exclude_from: Vec<String>,
}
fn default_space() -> String {
    "auto".to_string()
}
fn default_ui_align() -> usize {
    4
}
fn default_ui_limit() -> usize {
    50
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UiWindowsRequest {
    pub pid: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UiScreenshotRequest {
    pub pid: u32,
    /// Specific window HWND (from `ui_windows`); defaults to the best-guess
    /// game window for the pid.
    #[serde(default)]
    pub hwnd: Option<usize>,
    /// `"auto"` (default), `"window-dc"`, or `"printwindow"`.
    #[serde(default = "default_capture_method")]
    pub method: String,
    /// Write the PNG here (server-side path). Written even on a blank capture.
    #[serde(default)]
    pub out: Option<String>,
    /// Embed the PNG as base64 in the response. Off by default — a full-window
    /// PNG can be large.
    #[serde(default)]
    pub base64: bool,
}
fn default_capture_method() -> String {
    "auto".to_string()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UiFocusRequest {
    pub pid: u32,
    #[serde(default)]
    pub hwnd: Option<usize>,
}

/// Accepts exactly the CLI's canonical method names (kept in lock-step so the
/// two frontends never diverge on valid input).
#[cfg(windows)]
fn parse_capture_methods(s: &str) -> Result<Vec<CaptureMethod>, String> {
    match s.to_ascii_lowercase().as_str() {
        "auto" => Ok(vec![CaptureMethod::PrintWindow, CaptureMethod::WindowDc]),
        "window-dc" => Ok(vec![CaptureMethod::WindowDc]),
        "printwindow" => Ok(vec![CaptureMethod::PrintWindow]),
        other => Err(format!("unknown method '{other}', expected auto|window-dc|printwindow")),
    }
}

/// Resolve `hwnd` (verified to belong to `pid`) or the best-guess game window
/// for `pid`. Mirrors the CLI's `resolve_ui_window`.
#[cfg(windows)]
fn resolve_ui_hwnd(pid: u32, hwnd: Option<usize>) -> Result<usize, String> {
    if let Some(h) = hwnd {
        let owner = n0xis_sources::window_pid(h);
        if owner == 0 {
            return Err(format!("hwnd 0x{h:x} is not a valid window"));
        }
        if owner != pid {
            return Err(format!("hwnd 0x{h:x} belongs to pid {owner}, not the requested pid {pid}"));
        }
        return Ok(h);
    }
    best_window(pid)
        .map(|w| w.hwnd)
        .ok_or_else(|| format!("no visible top-level window for pid {pid} (run ui_windows to inspect)"))
}

fn parse_space(s: &str) -> Result<CoordSpace, String> {
    match s.to_ascii_lowercase().as_str() {
        "auto" => Ok(CoordSpace::Auto),
        "screen" => Ok(CoordSpace::Screen),
        "ndc" => Ok(CoordSpace::Ndc),
        other => Err(format!("unknown space '{other}', expected auto|screen|ndc")),
    }
}

fn parse_rect(s: &str) -> Result<Rect, String> {
    let parts: Vec<&str> = s.split(',').map(|t| t.trim()).collect();
    let [a, b, c, d] = parts.as_slice() else {
        return Err(format!("rect needs exactly 4 comma-separated numbers, got {s:?}"));
    };
    let p = |t: &str| t.parse::<f32>().map_err(|e| format!("invalid rect coordinate {t:?}: {e}"));
    Ok(Rect::new(p(a)?, p(b)?, p(c)?, p(d)?))
}

/// The live scan set, mirroring the CLI's `resolve_scan_regions_live`: an
/// explicit `start`/`size` window clipped to committed regions (a single read
/// spanning an unmapped gap fails wholesale), else every committed writable
/// region.
#[cfg(windows)]
fn ui_scan_regions(live: &LiveProcess, start: Option<&str>, size: Option<usize>) -> Result<Vec<(Va, usize)>, String> {
    if let Some(s) = start {
        let va = Va::parse(s).map_err(|e| e.to_string())?;
        let sz = size.ok_or("provide size with start")?;
        let lo = va.0;
        let hi = va.0.saturating_add(sz as u64);
        let mut clipped = Vec::new();
        for (rb, rs) in live.default_writable_regions() {
            let a = rb.0.max(lo);
            let b = (rb.0 + rs as u64).min(hi);
            if a < b {
                clipped.push((Va(a), (b - a) as usize));
            }
        }
        if clipped.is_empty() {
            return Ok(vec![(va, sz)]);
        }
        return Ok(clipped);
    }
    let regions = live.default_writable_regions();
    if regions.is_empty() {
        return Err("no committed writable regions found (and no start/size given)".to_string());
    }
    Ok(regions)
}

/// Load the address sets of previously-saved `ui locate` queries, up front —
/// a missing/corrupt name must fail before the (tens-of-seconds) scan runs.
fn ui_excluded_addresses(names: &[String]) -> Result<std::collections::HashSet<Va>, (String, String)> {
    let mut excluded = std::collections::HashSet::new();
    for name in names {
        let saved = n0xis_project::dump::show(name, Some("ui_locate"))
            .map_err(|e| ("no-such-save".to_string(), format!("exclude_from {name:?}: {e}")))?;
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

#[cfg(windows)]
fn parse_watch_kind(s: &str) -> Result<WatchKind, String> {
    match s.to_ascii_lowercase().as_str() {
        "execute" => Ok(WatchKind::Execute),
        "write" => Ok(WatchKind::Write),
        "read-or-write" | "readorwrite" => Ok(WatchKind::ReadOrWrite),
        other => Err(format!("unknown kind '{other}', expected execute|write|read-or-write")),
    }
}

#[tool_router(vis = "pub")]
impl N0xisServer {
    #[tool(description = "Environment / readiness check (arch decoder, project resolution).")]
    fn doctor(&self) -> String {
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
        });
        emit(Response::success(schema::v1::DOCTOR, data))
    }

    #[tool(description = "List running processes, optionally filtered by name substring.")]
    fn process_ps(&self, Parameters(a): Parameters<ProcessPsRequest>) -> String {
        #[cfg(not(windows))]
        {
            let _ = &a;
            return err("live-unsupported", "process_ps requires a Windows build (needs Win32 process enumeration)");
        }
        #[cfg(windows)]
        match list_processes() {
            Ok(mut procs) => {
                if let Some(f) = a.filter.as_deref() {
                    let needle = f.to_lowercase();
                    procs.retain(|p| p.name.to_lowercase().contains(&needle));
                }
                procs.sort_by_key(|p| p.name.to_lowercase());
                let list: Vec<_> = procs.iter().map(|p| json!({ "pid": p.pid, "name": p.name })).collect();
                emit(Response::success(schema::v1::PROCESS_PS, json!({ "count": list.len(), "processes": list })))
            }
            Err(e) => err("ps-failed", e.to_string()),
        }
    }

    #[tool(
        description = "Attach to a pid or load a static PE file, and record it as the session \
                        default in `.n0x/session.json` so later tool calls can omit pid/file. \
                        Shared with the CLI (same project directory)."
    )]
    fn attach(&self, Parameters(a): Parameters<AttachRequest>) -> String {
        if a.pid.is_none() && a.file.is_none() {
            return err("missing-source", "provide pid or file");
        }
        let src = match source::resolve(a.pid, a.file.as_deref(), None, None) {
            Ok(s) => s,
            Err((c, m)) => return err(&c, m),
        };
        let session = if let Some(pid) = a.pid {
            n0xis_project::session::attach_pid(pid)
        } else {
            n0xis_project::session::attach_file(a.file.as_deref().unwrap_or_default())
        };
        if let Err(e) = session {
            return err("session-save-failed", e.to_string());
        }
        let modules = src.modules().len();
        let data = json!({ "label": src.label(), "moduleCount": modules });
        emit(Response::success(schema::v1::PROJECT_INFO, data).with_source(src.label()))
    }

    #[tool(description = "List loaded modules of a live process or a static PE's imports/module table.")]
    fn module_list(&self, Parameters(a): Parameters<ModuleListRequest>) -> String {
        let src = resolve_or_return!(a);
        let mut modules: Vec<n0xis_contracts::Module> = src.modules();
        if let Some(f) = a.filter.as_deref() {
            let needle = f.to_lowercase();
            modules.retain(|m| m.name.to_lowercase().contains(&needle));
        }
        emit(Response::success(schema::v1::MODULE_LIST, json!({ "count": modules.len(), "modules": modules })))
    }

    #[tool(description = "Linear disassembly of `count` instructions starting at `addr`.")]
    fn disasm(&self, Parameters(a): Parameters<DisasmRequest>) -> String {
        let start = match Va::parse(&a.addr) {
            Ok(v) => v,
            Err(e) => return bad_addr(e),
        };
        let src = resolve_or_return!(a);
        let arch = arch_or_return!(a);
        let out = with_ctx(&src, arch.as_ref(), |ctx| DecodePass.run(ctx, DecodeInput::count(start, a.count)));
        match out {
            Ok(o) => emit(Response::success(schema::v1::DECODE, o).with_source(src.label())),
            Err(e) => err("decode-failed", e.to_string()),
        }
    }

    #[tool(description = "Heuristic function discovery over a code range (defaults to `.text`).")]
    fn function_discover(&self, Parameters(a): Parameters<DiscoverRequest>) -> String {
        let explicit_start = match a.start.as_deref().map(Va::parse).transpose() {
            Ok(v) => v,
            Err(e) => return bad_addr(e),
        };
        let src = resolve_or_return!(a);
        let Some((start, size)) = source::scan_range(src.text_range(), explicit_start, a.size) else {
            return err("no-range", "could not resolve a scan range; pass start and size");
        };
        let arch = arch_or_return!(a);
        let out = with_ctx(&src, arch.as_ref(), |ctx| DiscoverPass.run(ctx, DiscoverInput { start, size, limit: a.limit, offset: a.offset.unwrap_or(0) }));
        match out {
            Ok(art) => {
                let (returned, truncated) = (art.count, art.truncated);
                let resp = Response::success(schema::v1::FUNCTION_DISCOVER, art).with_source(src.label());
                emit(if truncated { resp.with_cap(returned) } else { resp })
            }
            Err(e) => err("discover-failed", e.to_string()),
        }
    }

    #[tool(description = "Call-graph walk (BFS) from a root function address.")]
    fn function_trace(&self, Parameters(a): Parameters<FunctionTraceRequest>) -> String {
        emit(n0xis_frontend::build_registry().dispatch(
            "function.trace",
            &json!({
                "addr": a.addr,
                "addr_rva": a.addr_rva,
                "depth": a.depth,
                "max_nodes": a.max_nodes,
                "max_bytes": a.max_bytes,
                "arch": a.arch,
                "pid": a.pid,
                "file": a.file,
                "snapshot": a.snapshot,
                "remote_cmd": a.remote_cmd,
            }),
        ))
    }

    #[tool(
        description = "Decompile a function to pseudo-C. style=ssa (default) is the main \
                        path: optimized + structured, and its response includes `delta` — the \
                        per-pass optimization log (also available standalone via explain_opt_delta)."
    )]
    fn decomp_pseudo(&self, Parameters(a): Parameters<DecompRequest>) -> String {
        // Dispatched through the shared registry — the exact same code path
        // `n0x decomp pseudo` takes. This method is argument mapping only.
        emit(n0xis_frontend::build_registry().dispatch("decomp.pseudo", &decomp_args_json(&a)))
    }

    #[tool(
        description = "Explain *why* the decompiler produced what it did: runs the same \
                        pipeline as decomp_pseudo(style=ssa) and returns only the per-pass \
                        optimization delta (n0xis.opt.delta.v1) — copy/const/expr propagation \
                        and dead-code elimination, each entry naming the pass, the address, \
                        and a summary of what changed."
    )]
    fn explain_opt_delta(&self, Parameters(a): Parameters<DecompRequest>) -> String {
        let start = match Va::parse(&a.addr) {
            Ok(v) => v,
            Err(e) => return bad_addr(e),
        };
        let src = resolve_or_return!(a);
        let cfg_input = CfgInput { start, max_bytes: a.size, auto_end: !a.no_auto_end };
        let arch = arch_or_return!(a);
        let out = with_ctx(&src, arch.as_ref(), |ctx| -> Result<_, String> {
            let (cfg, _cached) = n0xis_pipeline::cfg_cached(ctx, cfg_input).map_err(|e| e.to_string())?;
            // This tool *is* the delta, so it always asks for it.
            DecompPass.run(ctx, DecompInput { cfg, style: DecompStyle::Ssa, explain: true }).map_err(|e| e.to_string())
        });
        match out {
            Ok(pf) => emit(
                Response::success(schema::v1::OPT_DELTA, json!({ "address": start, "rounds": pf.delta.len(), "entries": pf.delta }))
                    .with_source(src.label()),
            ),
            Err(e) => err("decomp-failed", e),
        }
    }

    #[tool(description = "Cross-references to (dir=to) or from (dir=from) an address, scanned over a code range.")]
    fn xref(&self, Parameters(a): Parameters<XrefRequest>) -> String {
        emit(n0xis_frontend::build_registry().dispatch(
            "xref",
            &json!({
                "addr": a.addr,
                "dir": a.dir,
                "start": a.start,
                "size": a.size,
                "arch": a.arch,
                "pid": a.pid,
                "file": a.file,
                "snapshot": a.snapshot,
                "remote_cmd": a.remote_cmd,
            }),
        ))
    }

    #[tool(description = "Search a data window for a string literal and find the code that references it (lea xref).")]
    fn xref_string(&self, Parameters(a): Parameters<XrefStringRequest>) -> String {
        emit(n0xis_frontend::build_registry().dispatch(
            "xref.string",
            &json!({
                "query": a.query,
                "start": a.code_start,
                "size": a.code_size,
                "data_start": a.data_start,
                "data_size": a.data_size,
                "limit": a.limit,
                "arch": a.arch,
                "pid": a.pid,
                "file": a.file,
                "snapshot": a.snapshot,
                "remote_cmd": a.remote_cmd,
            }),
        ))
    }

    #[tool(description = "Read raw bytes from a live process or static file at an address.")]
    fn mem_read(&self, Parameters(a): Parameters<MemReadRequest>) -> String {
        emit(n0xis_frontend::build_registry().dispatch(
            "mem.read",
            &json!({
                "addr": a.addr,
                "size": a.size,
                "pid": a.pid,
                "file": a.file,
                "snapshot": a.snapshot,
                "remote_cmd": a.remote_cmd,
            }),
        ))
    }

    #[tool(description = "Write raw bytes into a live process's memory at an address.")]
    fn mem_write(&self, Parameters(a): Parameters<MemWriteRequest>) -> String {
        emit(n0xis_frontend::build_registry().dispatch(
            "mem.write",
            &json!({ "addr": a.addr, "bytes": a.bytes, "pid": a.pid }),
        ))
    }

    #[tool(
        description = "The principal 'explain a live memory access' tool: arms a hardware \
                        watchpoint on addr, waits for one real hit, then fuses it with the SSA \
                        decompiler to resolve the containing function and return the exact \
                        decompiled statement responsible — provenance, not just an address."
    )]
    fn provenance_trace(&self, Parameters(a): Parameters<ProvenanceTraceRequest>) -> String {
        let addr = match Va::parse(&a.addr) {
            Ok(v) => v,
            Err(e) => return bad_addr(e),
        };
        #[cfg(not(windows))]
        {
            let _ = addr;
            return err("live-unsupported", "provenance_trace requires a Windows build (needs LiveProcess/debug APIs)");
        }
        #[cfg(windows)]
        {
            let kind = match parse_watch_kind(&a.kind) {
                Ok(k) => k,
                Err(e) => return err("bad-kind", e),
            };
            let live = match LiveProcess::attach(a.pid) {
                Ok(l) => l,
                Err(e) => return err("attach-failed", e.to_string()),
            };
            let main_module = live.main_module().cloned();
            let label = live.label();
            drop(live);

            let outcome = match await_watchpoint_hit(a.pid, addr, kind, a.len, a.timeout_ms, 0, main_module.as_ref()) {
                Ok(o) => o,
                Err(e) => return err("watch-failed", e.to_string()),
            };
            let Some(hit) = outcome.hit else {
                return emit(Response::success(schema::v1::PROVENANCE, json!({ "value_addr": addr, "entries": [], "timedOut": true })).with_source(label));
            };

            let live = match LiveProcess::attach(a.pid) {
                Ok(l) => l,
                Err(e) => return err("attach-failed", e.to_string()),
            };
            let insn_module = live.modules().iter().find(|m| m.contains(hit.rip)).cloned();
            let arch = X64::new();
            let ctx = Ctx::new(&live, &arch);
            let (code_scan_start, code_scan_size) = match insn_module.as_ref().and_then(|m| live.section_range_of(m.base, ".text")) {
                Some((start, size)) => (Some(start), size as usize),
                None => (None, 0),
            };
            let graph = ProvenancePass.run(
                &ctx,
                ProvenanceInput {
                    value_addr: addr,
                    hits: vec![ProvenanceHit { instruction_va: hit.rip, access_kind: a.kind.clone() }],
                    module: insn_module,
                    code_scan_start,
                    code_scan_size,
                },
            );
            match graph {
                Ok(g) => emit(Response::success(schema::v1::PROVENANCE, g).with_source(label)),
                Err(e) => err("provenance-failed", e.to_string()),
            }
        }
    }

    #[tool(
        description = "Assert (or clear, with no value) a name/type/comment at an address — the \
                        analysis DB, kept as versioned truth: every change is appended to that \
                        address's history rather than overwriting it. field is one of \
                        \"name\", \"type\", or \"comment\"."
    )]
    fn annotate_set(&self, Parameters(a): Parameters<AnnotateSetRequest>) -> String {
        let va = match Va::parse(&a.addr) {
            Ok(v) => v,
            Err(e) => return bad_addr(e),
        };
        let result = match a.field.as_str() {
            "name" => n0xis_project::annotate::set_name(va, a.value.clone()),
            "type" => n0xis_project::annotate::set_type(va, a.value.clone()),
            "comment" => n0xis_project::annotate::set_comment(va, a.value.clone()),
            other => return err("bad-field", format!("unknown field '{other}', expected name|type|comment")),
        };
        match result {
            Ok(rec) => emit(Response::success(schema::v1::ANNOTATION, rec)),
            Err(e) => err("annotate-failed", e.to_string()),
        }
    }

    #[tool(description = "The current name/type/comment + full history recorded at an address, if any.")]
    fn annotate_get(&self, Parameters(a): Parameters<AnnotateShowRequest>) -> String {
        let va = match Va::parse(&a.addr) {
            Ok(v) => v,
            Err(e) => return bad_addr(e),
        };
        match n0xis_project::annotate::get(va) {
            Ok(Some(rec)) => emit(Response::success(schema::v1::ANNOTATION, rec)),
            Ok(None) => err("not-found", format!("no annotations recorded at {va}")),
            Err(e) => err("annotate-failed", e.to_string()),
        }
    }

    #[tool(description = "Every annotated address, va-sorted.")]
    fn annotate_list(&self) -> String {
        match n0xis_project::annotate::list() {
            Ok(records) => emit(Response::success(schema::v1::ANNOTATION, json!({ "count": records.len(), "records": records }))),
            Err(e) => err("annotate-failed", e.to_string()),
        }
    }

    #[tool(description = "Every registered analysis plugin (name -> spawn command + declared artifact kinds), from .n0x/plugins.json.")]
    fn plugin_list(&self) -> String {
        match n0xis_project::plugins::list() {
            Ok(items) => emit(Response::success(schema::v1::PLUGIN, json!({ "count": items.len(), "plugins": items }))),
            Err(e) => err("plugin-list-failed", e.to_string()),
        }
    }

    #[tool(
        description = "Manually invoke one registered plugin by name against an arbitrary JSON artifact and return its response. Fails visibly (never panics) if the plugin isn't registered, its command can't spawn, or it crashes/times out — matching PluginHost's own fail-open-but-visible posture."
    )]
    fn plugin_run(&self, Parameters(a): Parameters<PluginRunRequest>) -> String {
        let record = match n0xis_project::plugins::get(&a.name) {
            Ok(r) => r,
            Err(e) => return err("plugin-not-found", e.to_string()),
        };
        let argv = match split_command_line(&record.command) {
            Ok(argv) => argv,
            Err(e) => return err("bad-plugin-command", e),
        };
        let request = json!({ "kind": a.kind, "artifact": a.artifact });
        match plugin_call_once(&argv, &request, std::time::Duration::from_secs(10)) {
            Ok(resp) => emit(Response::success(schema::v1::PLUGIN, json!({ "plugin": a.name, "findings": resp }))),
            Err(e) => err("plugin-run-failed", e),
        }
    }

    #[tool(
        description = "List every capability this build can run — built-in analysis and user-registered plugins alike, each with its origin and the schema it emits. Read this instead of guessing what exists; a plugin the user registered shows up here exactly like a built-in does."
    )]
    fn capability_list(&self) -> String {
        let reg = n0xis_frontend::build_registry();
        emit(Response::success(schema::v1::CAPABILITY_LIST, reg.describe()))
    }

    #[tool(
        description = "Run a capability by name (see `capability_list`) with JSON arguments. Target arguments are the usual pid/file/snapshot/remote_cmd/bytes. Dispatching a built-in and dispatching a plugin are the same call — that is the point of the registry."
    )]
    fn capability_run(&self, Parameters(a): Parameters<CapabilityRunRequest>) -> String {
        let reg = n0xis_frontend::build_registry();
        emit(reg.dispatch(&a.name, &a.args))
    }

    #[tool(
        description = "Screen region -> memory addresses: hit-test a live target's own UI bounding boxes and report the elements drawing inside a rectangle. Read-only (no breakpoints, no writes). Use `space:\"auto\"` first and read `observed_range` to learn which coordinate space the target's boxes are in. For noisy results, run once over a rect where the widget is ABSENT with `save_as`, then re-run over the rect where it is PRESENT with `exclude_from` — the spatial diff drops structures that overlap every rect."
    )]
    fn ui_locate(&self, Parameters(a): Parameters<UiLocateRequest>) -> String {
        let rect = match parse_rect(&a.rect) {
            Ok(r) => r,
            Err(e) => return err("bad-rect", e),
        };
        let space = match parse_space(&a.space) {
            Ok(s) => s,
            Err(e) => return err("bad-space", e),
        };
        let excluded = match ui_excluded_addresses(&a.exclude_from) {
            Ok(e) => e,
            Err((c, m)) => return err(&c, m),
        };
        #[cfg(not(windows))]
        {
            let _ = (&a, rect, space, &excluded);
            return err("live-unsupported", "ui_locate requires a Windows build (needs LiveProcess/Win32 APIs)");
        }
        #[cfg(windows)]
        {
            let live = match LiveProcess::attach(a.pid) {
                Ok(l) => l,
                Err(e) => return err("attach-failed", e.to_string()),
            };
            let regions = match ui_scan_regions(&live, a.start.as_deref(), a.size) {
                Ok(r) => r,
                Err(e) => return err("bad-region", e),
            };
            let label = live.label();
            let arch = X64::new();
            let ctx = Ctx::new(&live, &arch);
            let input = UiLocateInput {
                regions,
                rect,
                space,
                layout: AabbLayout::STINGRAY,
                align: a.align.max(1),
            };
            let mut art = match UiLocatePass.run(&ctx, input) {
                Ok(v) => v,
                Err(e) => return err("ui-locate-failed", e.to_string()),
            };
            if !excluded.is_empty() {
                art.elements.retain(|e| !excluded.contains(&e.address));
                art.count = art.elements.len();
            }
            if let Some(name) = &a.save_as {
                let bytes = match serde_json::to_vec(&art) {
                    Ok(b) => b,
                    Err(e) => return err("serialize-failed", e.to_string()),
                };
                if let Err(e) = n0xis_project::dump::save(name, "ui_locate", &bytes, a.force) {
                    return err("save-failed", e.to_string());
                }
            }
            // `count` stays the true total; only the reported list is capped.
            art.elements.truncate(a.limit);
            emit(Response::success(schema::v1::UI_LOCATE, art).with_source(label))
        }
    }

    #[tool(
        description = "List a target process's top-level windows (title, class, visibility, rects, DPI), best-guess game window first. Read-only. Use it to pick an hwnd for ui_screenshot / ui_focus, or to see why a capture is blank (minimized / cloaked / off-screen). rect_frame is the canonical visible bounds; rect_client is where the game renders."
    )]
    fn ui_windows(&self, Parameters(a): Parameters<UiWindowsRequest>) -> String {
        #[cfg(not(windows))]
        {
            let _ = &a;
            return err("live-unsupported", "ui_windows requires a Windows build (needs Win32 window enumeration)");
        }
        #[cfg(windows)]
        {
            let windows = list_windows(a.pid);
            emit(Response::success(
                schema::v1::UI_WINDOWS,
                json!({ "pid": a.pid, "count": windows.len(), "windows": windows, "coords": "physical" }),
            )
            .with_source(format!("pid:{}", a.pid)))
        }
    }

    #[tool(
        description = "Capture a target window to a PNG so you can visually choose a rect for ui_locate. Read-only-ish (window-dc is fully read-only; printwindow makes the target's UI thread render). CRITICAL: GDI/PrintWindow return an all-black frame for flip-model DirectX windows — this tool detects that and sets data.blank=true with a reason; NEVER treat a blank capture as an empty UI. Key on data.blank, not on ok. Pass out=<path> to write the PNG, base64=true to embed it."
    )]
    fn ui_screenshot(&self, Parameters(a): Parameters<UiScreenshotRequest>) -> String {
        #[cfg(not(windows))]
        {
            let _ = &a;
            return err("live-unsupported", "ui_screenshot requires a Windows build (needs Win32 GDI/window capture)");
        }
        #[cfg(windows)]
        {
            let hwnd = match resolve_ui_hwnd(a.pid, a.hwnd) {
                Ok(h) => h,
                Err(e) => return err("no-window", e),
            };
            let methods = match parse_capture_methods(&a.method) {
                Ok(m) => m,
                Err(e) => return err("bad-method", e),
            };
            let shot = match screenshot(hwnd, &methods) {
                Ok(s) => s,
                Err(e) => {
                    return emit(
                        Response::<serde_json::Value>::error("capture-failed", e.reason)
                            .with_hint("run ui_windows to check the window is visible and on-screen"),
                    );
                }
            };
            let confidence = match shot.verdict {
                n0xis_sources::FrameVerdict::Ok => "ok",
                n0xis_sources::FrameVerdict::Suspect => "low",
                _ => "blank",
            };
            let mut out_written: Option<String> = None;
            let mut png_b64: Option<String> = None;
            if a.out.is_some() || a.base64 {
                match encode_png(&shot.rgba, shot.width, shot.height) {
                    Ok(png) => {
                        if let Some(path) = &a.out {
                            if let Err(e) = std::fs::write(path, &png) {
                                return err("write-failed", format!("write {path}: {e}"));
                            }
                            out_written = Some(path.clone());
                        }
                        if a.base64 {
                            png_b64 = Some(n0xis_sources::b64_encode(&png));
                        }
                    }
                    Err(e) => return err("png-failed", e),
                }
            }
            emit(Response::success(
                schema::v1::UI_SCREENSHOT,
                json!({
                    "pid": a.pid, "hwnd": hwnd, "width": shot.width, "height": shot.height,
                    "method": shot.method, "blank": shot.blank, "confidence": confidence,
                    "reason": shot.reason, "attempts": shot.attempts, "client_rect": shot.client_rect,
                    "dpi": shot.dpi, "out": out_written, "png_base64": png_b64, "coords": "physical",
                    "note": if shot.blank {
                        "BLANK — key on data.blank, not ok. GDI/PrintWindow can't capture flip-model DirectX; diagnostic artifact only."
                    } else if confidence == "low" {
                        "LOW-CONFIDENCE (near-blank, few distinct colors) — a rect from this may be unreliable; confirm the window shows content."
                    } else {
                        "pick a rect (physical px, window top-left origin) for ui_locate."
                    },
                }),
            )
            .with_source(format!("pid:{}", a.pid)))
        }
    }

    #[tool(
        description = "Bring a window to the foreground (window selector). NOT read-only — it activates a window on the target. Verifies success via GetForegroundWindow (data.foreground), since the OS often only flashes the taskbar instead of truly focusing."
    )]
    fn ui_focus(&self, Parameters(a): Parameters<UiFocusRequest>) -> String {
        #[cfg(not(windows))]
        {
            let _ = &a;
            return err("live-unsupported", "ui_focus requires a Windows build (needs Win32 window APIs)");
        }
        #[cfg(windows)]
        {
            let hwnd = match resolve_ui_hwnd(a.pid, a.hwnd) {
                Ok(h) => h,
                Err(e) => return err("no-window", e),
            };
            let r = focus(hwnd);
            emit(Response::success(
                schema::v1::UI_FOCUS,
                json!({ "pid": a.pid, "hwnd": r.hwnd, "foreground": r.foreground, "method": r.method }),
            )
            .with_source(format!("pid:{}", a.pid)))
        }
    }
}

