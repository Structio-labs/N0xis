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
    CfgInput, CfgPass, Ctx, DecodeInput, DecodePass, DecompInput, DecompPass, DecompStyle,
    DiscoverInput, DiscoverPass, Pass, ProvenanceHit, ProvenanceInput, ProvenancePass, TraceInput,
    TracePass, XrefDir, XrefInput, XrefPass, StringXrefInput, StringXrefPass,
};
use n0xis_sources::{
    LiveProcess, MemorySource, ModuleProvider, WatchKind, await_watchpoint_hit, list_processes,
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
fn with_ctx<R>(src: &Src, work: impl FnOnce(&Ctx) -> R) -> R {
    let arch = X64::new();
    match src {
        Src::Live(l) => work(&Ctx::new(l.as_ref(), &arch)),
        Src::Static(p) => work(&Ctx::new(p.as_ref(), &arch).with_symbols(p.as_ref()).with_modules(p.as_ref())),
    }
}

macro_rules! resolve_or_return {
    ($a:expr) => {
        match source::resolve($a.pid, $a.file.as_deref()) {
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
    #[serde(default)]
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisasmRequest {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub file: Option<String>,
    /// Address to start disassembling at, e.g. `"0x140001000"`.
    pub addr: String,
    #[serde(default = "default_count")]
    pub count: usize,
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
    /// Start of the scan range; defaults to the module's `.text`.
    #[serde(default)]
    pub start: Option<String>,
    #[serde(default)]
    pub size: Option<usize>,
    #[serde(default = "default_limit")]
    pub limit: usize,
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
    /// Function start address, e.g. `"0x140001000"`.
    pub addr: String,
    #[serde(default = "default_max_bytes")]
    pub size: usize,
    #[serde(default)]
    pub no_auto_end: bool,
    /// One of `"goto"`, `"structured"`, `"ssa"` (default: `"ssa"`, the optimized + structured style).
    #[serde(default = "default_style")]
    pub style: String,
}
fn default_style() -> String {
    "ssa".to_string()
}

fn parse_style(s: &str) -> Result<DecompStyle, String> {
    match s.to_ascii_lowercase().as_str() {
        "goto" => Ok(DecompStyle::Goto),
        "structured" => Ok(DecompStyle::Structured),
        "ssa" => Ok(DecompStyle::Ssa),
        other => Err(format!("unknown style '{other}', expected goto|structured|ssa")),
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct XrefRequest {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub file: Option<String>,
    /// The address of interest.
    pub addr: String,
    /// `"to"` (who references `addr`) or `"from"` (what `addr` references).
    #[serde(default = "default_dir")]
    pub dir: String,
    #[serde(default)]
    pub start: Option<String>,
    #[serde(default)]
    pub size: Option<usize>,
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
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemReadRequest {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub file: Option<String>,
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
        let src = resolve_or_return!(a);
        let session = if let Some(pid) = a.pid {
            n0xis_project::session::attach_pid(pid)
        } else {
            n0xis_project::session::attach_file(a.file.as_deref().unwrap_or_default())
        };
        if let Err(e) = session {
            return err("session-save-failed", e.to_string());
        }
        let modules = match &src {
            Src::Live(l) => l.modules().len(),
            Src::Static(p) => p.modules().len(),
        };
        let data = json!({ "label": src.label(), "moduleCount": modules });
        emit(Response::success(schema::v1::PROJECT_INFO, data).with_source(src.label()))
    }

    #[tool(description = "List loaded modules of a live process or a static PE's imports/module table.")]
    fn module_list(&self, Parameters(a): Parameters<ModuleListRequest>) -> String {
        let src = resolve_or_return!(a);
        let mut modules: Vec<n0xis_contracts::Module> = match &src {
            Src::Live(l) => l.modules().to_vec(),
            Src::Static(p) => p.modules().to_vec(),
        };
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
        let out = with_ctx(&src, |ctx| DecodePass.run(ctx, DecodeInput::count(start, a.count)));
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
        let out = with_ctx(&src, |ctx| DiscoverPass.run(ctx, DiscoverInput { start, size, limit: a.limit }));
        match out {
            Ok(art) => emit(Response::success(schema::v1::FUNCTION_DISCOVER, art).with_source(src.label())),
            Err(e) => err("discover-failed", e.to_string()),
        }
    }

    #[tool(description = "Call-graph walk (BFS) from a root function address.")]
    fn function_trace(&self, Parameters(a): Parameters<FunctionTraceRequest>) -> String {
        let addr = match Va::parse(&a.addr) {
            Ok(v) => v,
            Err(e) => return bad_addr(e),
        };
        let src = resolve_or_return!(a);
        let root = if a.addr_rva {
            match src.module_base() {
                Some(base) => base.offset(addr.0),
                None => return err("no-module", "no module base resolved for addr_rva"),
            }
        } else {
            addr
        };
        let input = TraceInput { root, depth: a.depth, max_nodes: a.max_nodes, max_bytes: a.max_bytes };
        let out = with_ctx(&src, |ctx| TracePass.run(ctx, input));
        match out {
            Ok(art) => emit(Response::success(schema::v1::FUNCTION_TRACE, art).with_source(src.label())),
            Err(e) => err("trace-failed", e.to_string()),
        }
    }

    #[tool(
        description = "Decompile a function to pseudo-C. style=ssa (default) is the main \
                        path: optimized + structured, and its response includes `delta` — the \
                        per-pass optimization log (also available standalone via explain_opt_delta)."
    )]
    fn decomp_pseudo(&self, Parameters(a): Parameters<DecompRequest>) -> String {
        let start = match Va::parse(&a.addr) {
            Ok(v) => v,
            Err(e) => return bad_addr(e),
        };
        let style = match parse_style(&a.style) {
            Ok(s) => s,
            Err(e) => return err("bad-style", e),
        };
        let src = resolve_or_return!(a);
        let cfg_input = CfgInput { start, max_bytes: a.size, auto_end: !a.no_auto_end };
        let out = with_ctx(&src, |ctx| -> Result<_, String> {
            let cfg = CfgPass.run(ctx, cfg_input).map_err(|e| e.to_string())?;
            DecompPass.run(ctx, DecompInput { cfg, style }).map_err(|e| e.to_string())
        });
        match out {
            Ok(pf) => emit(Response::success(schema::v0::DECOMP_PSEUDO, pf).with_source(src.label())),
            Err(e) => err("decomp-failed", e),
        }
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
        let out = with_ctx(&src, |ctx| -> Result<_, String> {
            let cfg = CfgPass.run(ctx, cfg_input).map_err(|e| e.to_string())?;
            DecompPass.run(ctx, DecompInput { cfg, style: DecompStyle::Ssa }).map_err(|e| e.to_string())
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
        let addr = match Va::parse(&a.addr) {
            Ok(v) => v,
            Err(e) => return bad_addr(e),
        };
        let dir = match a.dir.to_ascii_lowercase().as_str() {
            "to" => XrefDir::To,
            "from" => XrefDir::From,
            other => return err("bad-dir", format!("unknown dir '{other}', expected to|from")),
        };
        let explicit_start = match a.start.as_deref().map(Va::parse).transpose() {
            Ok(v) => v,
            Err(e) => return bad_addr(e),
        };
        let src = resolve_or_return!(a);
        let Some((scan_start, size)) = source::scan_range(src.text_range(), explicit_start, a.size) else {
            return err("no-range", "could not resolve a scan range; pass start and size");
        };
        let out = with_ctx(&src, |ctx| XrefPass.run(ctx, XrefInput { scan_start, size, addr, dir }));
        match out {
            Ok(art) => emit(Response::success(schema::v1::XREF, art).with_source(src.label())),
            Err(e) => err("xref-failed", e.to_string()),
        }
    }

    #[tool(description = "Search a data window for a string literal and find the code that references it (lea xref).")]
    fn xref_string(&self, Parameters(a): Parameters<XrefStringRequest>) -> String {
        let explicit_code_start = match a.code_start.as_deref().map(Va::parse).transpose() {
            Ok(v) => v,
            Err(e) => return bad_addr(e),
        };
        let explicit_data_start = match a.data_start.as_deref().map(Va::parse).transpose() {
            Ok(v) => v,
            Err(e) => return bad_addr(e),
        };
        let src = resolve_or_return!(a);
        let default_data = src.section_range(".rdata").or_else(|| src.text_range());
        let Some((code_start, code_size)) = source::scan_range(src.text_range(), explicit_code_start, a.code_size) else {
            return err("no-range", "could not resolve a code range; pass code_start/code_size");
        };
        let Some((data_start, data_size)) = source::scan_range(default_data, explicit_data_start, a.data_size) else {
            return err("no-range", "could not resolve a data range; pass data_start/data_size");
        };
        let input = StringXrefInput { data_start, data_size, code_start, code_size, query: a.query.clone(), limit: a.limit };
        let out = with_ctx(&src, |ctx| StringXrefPass.run(ctx, input));
        match out {
            Ok(art) => emit(Response::success(schema::v1::XREF_STRING, art).with_source(src.label())),
            Err(e) => err("xref-string-failed", e.to_string()),
        }
    }

    #[tool(description = "Read raw bytes from a live process or static file at an address.")]
    fn mem_read(&self, Parameters(a): Parameters<MemReadRequest>) -> String {
        let addr = match Va::parse(&a.addr) {
            Ok(v) => v,
            Err(e) => return bad_addr(e),
        };
        let src = resolve_or_return!(a);
        match src.as_mem().read(addr, a.size) {
            Ok(bytes) => {
                let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
                let data = json!({ "address": addr, "requested": a.size, "read": bytes.len(), "hex": hex });
                emit(Response::success(schema::v1::MEM_READ, data).with_source(src.label()))
            }
            Err(e) => err("read-failed", e.to_string()),
        }
    }

    #[tool(description = "Write raw bytes into a live process's memory at an address.")]
    fn mem_write(&self, Parameters(a): Parameters<MemWriteRequest>) -> String {
        let addr = match Va::parse(&a.addr) {
            Ok(v) => v,
            Err(e) => return bad_addr(e),
        };
        let bytes = match parse_hex_bytes(&a.bytes) {
            Ok(b) => b,
            Err(e) => return err("bad-bytes", e),
        };
        let live = match LiveProcess::attach(a.pid) {
            Ok(l) => l,
            Err(e) => return err("attach-failed", e.to_string()),
        };
        match live.write(addr, &bytes) {
            Ok(()) => {
                let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
                let data = json!({ "address": addr, "written": bytes.len(), "hex": hex });
                emit(Response::success(schema::v1::MEM_WRITE, data).with_source(live.label()))
            }
            Err(e) => err("write-failed", e.to_string()),
        }
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

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err("hex byte string must have an even number of digits".to_string());
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
