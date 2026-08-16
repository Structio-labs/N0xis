//! The capability registry — one contract for built-in and external
//! functionality alike.
//!
//! The problem it solves: adding a capability used to mean surgery inside
//! `n0xis-cli`'s 6000-line `main.rs` (a new `clap` variant plus a new arm in a
//! 767-arm `match`), and *separately* a new `#[tool]` method in `n0xis-mcp`.
//! Meanwhile an external plugin — the thing a third party actually writes —
//! reached the system through a completely different door (a JSON process
//! spawned by `PluginHost`). Two mechanisms, and the built-in one privileged.
//!
//! Here there is one: a [`Capability`] is a name, a description, and a handler
//! from JSON arguments to the standard envelope. A [`Plugin`] registers
//! capabilities into a [`Registry`]. Built-in analysis and a third-party
//! process register through the identical trait, which is why
//! [`build_registry`] — the single composition point — reads as a list of
//! registration calls and nothing else:
//!
//! ```no_run
//! # use n0xis_frontend::registry::{build_registry};
//! let reg = build_registry();
//! let resp = reg.dispatch("decode", &serde_json::json!({
//!     "file": "game.exe", "addr": "0x140001000", "count": 8
//! }));
//! ```
//!
//! Adding a capability is "add another registration call" — never surgery in
//! a frontend. Frontends stay what they are: `n0xis-cli` maps flags to JSON,
//! `n0xis-mcp` maps tool arguments to JSON, both then ask the registry.

use std::collections::BTreeMap;

use n0xis_contracts::{Response, Va};
use serde_json::{Value, json};

use crate::source::{SourceSpec, Src, resolve};

/// A handler: JSON arguments in, the standard `{ok,data,meta}` envelope out.
/// Deliberately the same shape a process plugin speaks over stdio, so the two
/// are interchangeable at the call site.
pub type Handler = Box<dyn Fn(&Value) -> Response<Value> + Send + Sync>;

/// Where a capability came from. Agents care: a built-in has been tested with
/// the release, a plugin is whatever the user registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    Builtin,
    /// An external process speaking the plugin protocol, spawned from `argv`.
    Plugin { command: String },
}

/// One capability: what it is called, what it does, and how to run it.
pub struct Capability {
    pub name: String,
    pub summary: String,
    /// The `n0xis.*.vN` schema its `data` payload carries, when it has a
    /// stable one.
    pub schema: Option<String>,
    pub origin: Origin,
    handler: Handler,
}

impl Capability {
    pub fn new(name: impl Into<String>, summary: impl Into<String>, schema: Option<&str>, origin: Origin, handler: Handler) -> Self {
        Capability { name: name.into(), summary: summary.into(), schema: schema.map(str::to_string), origin, handler }
    }

    pub fn run(&self, args: &Value) -> Response<Value> {
        (self.handler)(args)
    }
}

/// Anything that contributes capabilities. Built-in analysis implements it;
/// so does the loader for user-registered process plugins. There is no
/// second, privileged path.
pub trait Plugin {
    fn name(&self) -> &str;
    fn register(&self, reg: &mut Registry);
}

#[derive(Default)]
pub struct Registry {
    caps: BTreeMap<String, Capability>,
}

impl Registry {
    pub fn new() -> Self {
        Registry::default()
    }

    /// Register a capability. A later registration with the same name wins,
    /// which is what lets a user plugin deliberately shadow a built-in — and
    /// is why [`list`](Self::list) reports `origin`.
    pub fn add(&mut self, cap: Capability) -> &mut Self {
        self.caps.insert(cap.name.clone(), cap);
        self
    }

    pub fn add_plugin(&mut self, plugin: &dyn Plugin) -> &mut Self {
        plugin.register(self);
        self
    }

    pub fn get(&self, name: &str) -> Option<&Capability> {
        self.caps.get(name)
    }

    pub fn list(&self) -> impl Iterator<Item = &Capability> {
        self.caps.values()
    }

    pub fn len(&self) -> usize {
        self.caps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.caps.is_empty()
    }

    /// Run a capability by name, or return the standard not-found envelope.
    pub fn dispatch(&self, name: &str, args: &Value) -> Response<Value> {
        match self.get(name) {
            Some(c) => c.run(args),
            None => Response::error("unknown-capability", format!("no capability named '{name}'; list them with `capability list`")),
        }
    }

    /// The machine-readable catalog: what exists, where it came from, what it
    /// emits. This is what an agent should read instead of guessing.
    pub fn describe(&self) -> Value {
        let items: Vec<Value> = self
            .list()
            .map(|c| {
                json!({
                    "name": c.name,
                    "summary": c.summary,
                    "schema": c.schema,
                    "origin": match &c.origin {
                        Origin::Builtin => json!({ "kind": "builtin" }),
                        Origin::Plugin { command } => json!({ "kind": "plugin", "command": command }),
                    },
                })
            })
            .collect();
        json!({ "count": items.len(), "capabilities": items })
    }
}

// ---------------------------------------------------------------------------
// Shared argument handling for capabilities that analyze a target.
// ---------------------------------------------------------------------------

/// Pull the standard target arguments out of a capability's JSON. Every
/// analysis capability takes the same five, by the same names the CLI flags
/// and MCP tool arguments already use.
fn spec_of(args: &Value) -> SourceSpec<'_> {
    SourceSpec {
        pid: args.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32),
        file: args.get("file").and_then(|v| v.as_str()),
        snapshot: args.get("snapshot").and_then(|v| v.as_str()),
        remote_cmd: args.get("remote_cmd").and_then(|v| v.as_str()),
        bytes: args.get("bytes").and_then(|v| v.as_str()),
        bytes_base: args.get("bytes_base").and_then(|v| v.as_str()).and_then(|s| Va::parse(s).ok()),
    }
}

/// `(code, message)` on failure — the same pair shape [`FrontendError`] uses,
/// rather than a whole `Response` (a 200-byte `Err` variant on every call).
///
/// [`FrontendError`]: crate::source::FrontendError
fn required_addr(args: &Value, key: &str) -> Result<Va, (&'static str, String)> {
    let raw = args.get(key).and_then(|v| v.as_str()).ok_or(("missing-arg", format!("'{key}' is required")))?;
    Va::parse(raw).map_err(|e| ("bad-addr", e.to_string()))
}

fn usize_arg(args: &Value, key: &str, default: usize) -> usize {
    args.get(key).and_then(|v| v.as_u64()).map(|v| v as usize).unwrap_or(default)
}

fn bool_arg(args: &Value, key: &str) -> bool {
    args.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

/// Everything a function-scoped analysis needs: the target resolved, the ISA
/// picked, `addr` turned into a real VA (honoring `addr_rva`/`addr_module`),
/// and a `Ctx` wired with symbols/modules when the source has them.
///
/// This is the JSON twin of `n0xis-cli`'s `run_ir` — and the reason the CLI's
/// copy is now four lines that call `dispatch`. `Ctx` borrows the source, so
/// this hands it to a closure rather than returning it.
fn with_cfg_ctx(args: &Value, work: impl FnOnce(&n0xis_core::Ctx, n0xis_core::CfgInput, &str) -> Response<Value>) -> Response<Value> {
    let addr = match required_addr(args, "addr") {
        Ok(v) => v,
        Err((code, msg)) => return Response::error(code, msg),
    };
    let arch = match crate::resolve_arch(args.get("arch").and_then(|v| v.as_str())) {
        Ok(a) => a,
        Err(e) => return Response::error("bad-arch", e),
    };
    let addr_rva = bool_arg(args, "addr_rva");

    // With `addr_rva` the real address is not known until the source is open
    // (the module base comes from it), so inline bytes fall back to base 0 —
    // they have no module and are rejected below anyway.
    let mut spec = spec_of(args);
    if addr_rva {
        spec.bytes_base = Some(Va(0));
    } else if spec.bytes_base.is_none() {
        spec.bytes_base = Some(addr);
    }
    let resolved = match resolve(spec) {
        Ok(r) => r,
        Err((c, m)) => return Response::error(&c, m),
    };
    let start = if addr_rva {
        match crate::source::base_for_module(&resolved.src, args.get("addr_module").and_then(|v| v.as_str())) {
            Ok(base) => base.offset(addr.0),
            Err(e) => return Response::error("no-module", e),
        }
    } else {
        addr
    };
    let input = n0xis_core::CfgInput { start, max_bytes: usize_arg(args, "size", 4096), auto_end: !bool_arg(args, "no_auto_end") };
    let label = resolved.label.clone();

    // A StaticPe is also a SymbolProvider + ModuleProvider — feed those seams
    // so call targets resolve to names.
    match &resolved.src {
        Src::Static(pe) => work(
            &n0xis_core::Ctx::new(pe.as_ref(), arch.as_ref()).with_symbols(pe.as_ref()).with_modules(pe.as_ref()),
            input,
            &label,
        ),
        Src::Live(l) => work(&n0xis_core::Ctx::new(l.as_ref(), arch.as_ref()), input, &label),
        Src::Snap(s) => work(&n0xis_core::Ctx::new(s, arch.as_ref()), input, &label),
        Src::Remote(r) => work(&n0xis_core::Ctx::new(r.as_ref(), arch.as_ref()), input, &label),
    }
}

/// Resolve the target and ISA, then hand the caller a `Ctx` plus the resolved
/// source itself — for range-scoped analysis (xref, string xref, call-graph
/// trace), which derives its own `.text`/`.rdata` windows from the source
/// rather than taking a single function address.
///
/// `bytes_base` is where an inline `bytes` source gets mapped; each capability
/// picks it from whichever explicit start it honors, so `--bytes` behaves the
/// same here as it did in the CLI's hand-written handlers.
fn with_src_ctx(
    args: &Value,
    bytes_base: Va,
    work: impl FnOnce(&n0xis_core::Ctx, &Src, Option<usize>, &str) -> Response<Value>,
) -> Response<Value> {
    let arch = match crate::resolve_arch(args.get("arch").and_then(|v| v.as_str())) {
        Ok(a) => a,
        Err(e) => return Response::error("bad-arch", e),
    };
    let mut spec = spec_of(args);
    spec.bytes_base = Some(bytes_base);
    let resolved = match resolve(spec) {
        Ok(r) => r,
        Err((c, m)) => return Response::error(&c, m),
    };
    let (src, label, region_len) = (resolved.src, resolved.label, resolved.region_len);
    match &src {
        Src::Static(pe) => {
            let ctx = n0xis_core::Ctx::new(pe.as_ref(), arch.as_ref()).with_symbols(pe.as_ref());
            work(&ctx, &src, region_len, &label)
        }
        Src::Live(l) => {
            let ctx = n0xis_core::Ctx::new(l.as_ref(), arch.as_ref());
            work(&ctx, &src, region_len, &label)
        }
        Src::Snap(s) => {
            let ctx = n0xis_core::Ctx::new(s, arch.as_ref());
            work(&ctx, &src, region_len, &label)
        }
        Src::Remote(r) => {
            let ctx = n0xis_core::Ctx::new(r.as_ref(), arch.as_ref());
            work(&ctx, &src, region_len, &label)
        }
    }
}

/// The data-side twin of [`with_src_ctx`]: resolve a `pid` (live, regions
/// clipped to what is actually committed) or a `file` (explicit start+size)
/// and hand over the regions to scan.
///
/// Deliberately narrower than [`SourceSpec`]: a value scan over a snapshot or
/// a remote agent is not supported, and quietly accepting one would scan
/// nothing and report success. The ISA comes from [`crate::resolve_arch`]
/// rather than a hardcoded `X64` — nothing here decodes an instruction, but
/// the default belongs in one place either way.
fn with_scan_ctx(
    args: &Value,
    start: Option<&str>,
    size: Option<usize>,
    work: impl FnOnce(&n0xis_core::Ctx, Vec<(Va, usize)>, &str) -> Response<Value>,
) -> Response<Value> {
    let arch = match crate::resolve_arch(args.get("arch").and_then(|v| v.as_str())) {
        Ok(a) => a,
        Err(e) => return Response::error("bad-arch", e),
    };
    if let Some(pid) = args.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32) {
        let live = match crate::source::attach_live(pid) {
            Ok(l) => l,
            Err((c, m)) => return Response::error(&c, m),
        };
        let regions = match crate::source::live_scan_regions(live.as_ref(), start, size) {
            Ok(r) => r,
            Err(e) => return Response::error("bad-region", e),
        };
        let label = n0xis_sources::MemorySource::label(live.as_ref());
        let ctx = n0xis_core::Ctx::new(live.as_ref(), arch.as_ref());
        return work(&ctx, regions, &label);
    }
    if let Some(file) = args.get("file").and_then(|v| v.as_str()) {
        let (Some(start_s), Some(size)) = (start, size) else {
            return Response::error("missing-region", "provide start and size for a file source");
        };
        let start_va = match Va::parse(start_s) {
            Ok(v) => v,
            Err(e) => return Response::error("bad-addr", e.to_string()),
        };
        let pe = match n0xis_sources::StaticPe::load(std::path::Path::new(file)) {
            Ok(p) => p,
            Err(e) => return Response::error("load-failed", e.to_string()),
        };
        let label = n0xis_sources::MemorySource::label(&pe);
        let ctx = n0xis_core::Ctx::new(&pe, arch.as_ref());
        return work(&ctx, vec![(start_va, size)], &label);
    }
    Response::error("missing-source", "provide pid or file")
}

/// Decompile one side of a diff: resolve its own target, build the CFG, render
/// pseudo-C. Returns `(lines, provenance label)`.
fn decompile_side(
    spec: SourceSpec<'_>,
    addr: Va,
    size: usize,
    style: n0xis_core::DecompStyle,
    arch: &dyn n0xis_arch::Arch,
) -> Result<(Vec<String>, String), (String, String)> {
    let mut spec = spec;
    spec.bytes_base = Some(addr);
    let resolved = resolve(spec)?;
    let input = n0xis_core::CfgInput { start: addr, max_bytes: size, auto_end: true };
    let run = |ctx: &n0xis_core::Ctx| -> Result<Vec<String>, (String, String)> {
        let (cfg, _cached) = n0xis_pipeline::cfg_cached(ctx, input).map_err(|e| ("ir-failed".to_string(), e.to_string()))?;
        let pf = n0xis_core::Pass::run(&n0xis_core::DecompPass, ctx, n0xis_core::DecompInput { cfg, style, explain: false })
            .map_err(|e| ("decomp-failed".to_string(), e.to_string()))?;
        Ok(pf.pseudo)
    };
    let pseudo = match &resolved.src {
        Src::Static(pe) => run(&n0xis_core::Ctx::new(pe.as_ref(), arch).with_symbols(pe.as_ref())),
        Src::Live(l) => run(&n0xis_core::Ctx::new(l.as_ref(), arch)),
        Src::Snap(s) => run(&n0xis_core::Ctx::new(s, arch)),
        Src::Remote(r) => run(&n0xis_core::Ctx::new(r.as_ref(), arch)),
    }?;
    Ok((pseudo, resolved.label))
}

fn to_hex_spaced(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

fn f64_arg(args: &Value, key: &str) -> Option<f64> {
    args.get(key).and_then(|v| v.as_f64())
}

fn to_scan_value(v: f64) -> n0xis_core::ScanValue {
    if v.fract() == 0.0 && v.abs() < 9.2e18 { n0xis_core::ScanValue::Int(v as i64) } else { n0xis_core::ScanValue::Float(v) }
}

fn parse_value_type(name: &str) -> Result<n0xis_core::ValueType, String> {
    use n0xis_core::ValueType as T;
    Ok(match name.to_ascii_lowercase().as_str() {
        "i8" => T::I8,
        "u8" => T::U8,
        "i16" => T::I16,
        "u16" => T::U16,
        "i32" => T::I32,
        "u32" => T::U32,
        "i64" => T::I64,
        "u64" => T::U64,
        "f32" => T::F32,
        "f64" => T::F64,
        other => return Err(format!("unknown value type '{other}' (i8|u8|i16|u16|i32|u32|i64|u64|f32|f64)")),
    })
}

fn opt_addr_arg(args: &Value, key: &str) -> Result<Option<Va>, (&'static str, String)> {
    match args.get(key).and_then(|v| v.as_str()) {
        Some(s) => Va::parse(s).map(Some).map_err(|e| ("bad-addr", e.to_string())),
        None => Ok(None),
    }
}

fn ok_json<T: serde::Serialize>(schema: &str, value: T, label: &str) -> Response<Value> {
    match serde_json::to_value(value) {
        Ok(v) => Response::success(schema, v).with_source(label.to_string()),
        Err(e) => Response::error("serialize", e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Built-in capabilities.
// ---------------------------------------------------------------------------

/// The analysis passes, registered exactly the way a third party would
/// register theirs.
pub struct AnalysisPasses;

impl Plugin for AnalysisPasses {
    fn name(&self) -> &str {
        "n0xis.analysis"
    }

    fn register(&self, reg: &mut Registry) {
        reg.add(Capability::new(
            "decode",
            "Linear disassembly of `count` instructions from `addr`.",
            Some(n0xis_contracts::schema::v1::DECODE),
            Origin::Builtin,
            Box::new(|args| {
                let addr = match required_addr(args, "addr") {
                    Ok(v) => v,
                    Err((code, msg)) => return Response::error(code, msg),
                };
                let arch = match crate::resolve_arch(args.get("arch").and_then(|v| v.as_str())) {
                    Ok(a) => a,
                    Err(e) => return Response::error("bad-arch", e),
                };
                let resolved = match resolve(spec_of(args)) {
                    Ok(r) => r,
                    Err((c, m)) => return Response::error(&c, m),
                };
                let ctx = n0xis_core::Ctx::new(resolved.src.as_mem(), arch.as_ref());
                let input = n0xis_core::DecodeInput::count(addr, usize_arg(args, "count", 16));
                match n0xis_core::Pass::run(&n0xis_core::DecodePass, &ctx, input) {
                    Ok(out) => match serde_json::to_value(out) {
                        Ok(v) => Response::success(n0xis_contracts::schema::v1::DECODE, v).with_source(resolved.label),
                        Err(e) => Response::error("serialize", e.to_string()),
                    },
                    Err(e) => Response::error("decode-failed", e.to_string()),
                }
            }),
        ));

        // --- function-scoped analysis, all sharing `with_cfg_ctx` ---

        reg.add(Capability::new(
            "ir.cfg",
            "Control-flow graph + block/def-use IR for the function at `addr`.",
            Some(n0xis_contracts::schema::v1::IR_CFG),
            Origin::Builtin,
            Box::new(|args| {
                with_cfg_ctx(args, |ctx, input, label| match n0xis_pipeline::cfg_cached(ctx, input) {
                    Ok((art, _cached)) => ok_json(n0xis_contracts::schema::v1::IR_CFG, art, label),
                    Err(e) => Response::error("ir-failed", e.to_string()),
                })
            }),
        ));

        reg.add(Capability::new(
            "ir.explain",
            "Human-readable summary of the function's CFG (blocks, returns, calls, indirect branches).",
            Some(n0xis_contracts::schema::v1::IR_EXPLAIN),
            Origin::Builtin,
            Box::new(|args| {
                with_cfg_ctx(args, |ctx, input, label| match n0xis_pipeline::cfg_cached(ctx, input) {
                    Ok((art, _)) => ok_json(n0xis_contracts::schema::v1::IR_EXPLAIN, json!({ "lines": n0xis_core::explain(&art) }), label),
                    Err(e) => Response::error("ir-failed", e.to_string()),
                })
            }),
        ));

        reg.add(Capability::new(
            "ir.dot",
            "Graphviz DOT rendering of the function's CFG.",
            Some(n0xis_contracts::schema::v1::IR_DOT),
            Origin::Builtin,
            Box::new(|args| {
                with_cfg_ctx(args, |ctx, input, label| match n0xis_pipeline::cfg_cached(ctx, input) {
                    Ok((art, _)) => ok_json(n0xis_contracts::schema::v1::IR_DOT, n0xis_core::dot(&art), label),
                    Err(e) => Response::error("ir-failed", e.to_string()),
                })
            }),
        ));

        reg.add(Capability::new(
            "ir.value-set",
            "Value-set analysis over the function's SSA form: what each value can be.",
            Some(n0xis_contracts::schema::v1::VALUE_SET),
            Origin::Builtin,
            Box::new(|args| {
                with_cfg_ctx(args, |ctx, input, label| {
                    let cfg = match n0xis_pipeline::cfg_cached(ctx, input) {
                        Ok((a, _)) => a,
                        Err(e) => return Response::error("ir-failed", e.to_string()),
                    };
                    let ssa = match n0xis_core::Pass::run(&n0xis_core::SsaPass, ctx, cfg) {
                        Ok(s) => s,
                        Err(e) => return Response::error("ssa-failed", e.to_string()),
                    };
                    match n0xis_core::Pass::run(&n0xis_core::ValueSetPass, ctx, ssa) {
                        Ok(art) => ok_json(n0xis_contracts::schema::v1::VALUE_SET, art, label),
                        Err(e) => Response::error("value-set-failed", e.to_string()),
                    }
                })
            }),
        ));

        reg.add(Capability::new(
            "ir.deobfuscate",
            "Junk-instruction and opaque-predicate detection over the function.",
            Some(n0xis_contracts::schema::v1::DEOBFUSCATE),
            Origin::Builtin,
            Box::new(|args| {
                with_cfg_ctx(args, |ctx, input, label| {
                    let cfg = match n0xis_pipeline::cfg_cached(ctx, input) {
                        Ok((a, _)) => a,
                        Err(e) => return Response::error("ir-failed", e.to_string()),
                    };
                    match n0xis_core::Pass::run(&n0xis_core::DeobfuscatePass, ctx, cfg) {
                        Ok(art) => ok_json(n0xis_contracts::schema::v1::DEOBFUSCATE, art, label),
                        Err(e) => Response::error("deobfuscate-failed", e.to_string()),
                    }
                })
            }),
        ));

        reg.add(Capability::new(
            "ir.slice",
            "Backward register slice: what computed `reg` at `at` (defaults to the function's last instruction).",
            Some(n0xis_contracts::schema::v1::IR_SLICE),
            Origin::Builtin,
            Box::new(|args| {
                let Some(reg_name) = args.get("reg").and_then(|v| v.as_str()).map(str::to_string) else {
                    return Response::error("missing-arg", "'reg' is required (the register to slice on)");
                };
                let at = match opt_addr_arg(args, "at") {
                    Ok(v) => v,
                    Err((c, m)) => return Response::error(c, m),
                };
                with_cfg_ctx(args, |ctx, input, label| {
                    let start = input.start;
                    let art = match n0xis_pipeline::cfg_cached(ctx, input) {
                        Ok((a, _)) => a,
                        Err(e) => return Response::error("ir-failed", e.to_string()),
                    };
                    // Default the query point to the last decoded instruction —
                    // "the final value of `reg`" is what you usually want.
                    let query = at.unwrap_or_else(|| {
                        art.blocks.iter().flat_map(|b| &b.insns).map(|i| i.va).max_by_key(|v| v.get()).unwrap_or(start)
                    });
                    ok_json(n0xis_contracts::schema::v1::IR_SLICE, n0xis_core::slice(ctx.arch, &art, query, &reg_name), label)
                })
            }),
        ));

        reg.add(Capability::new(
            "decomp.pseudo",
            "Decompile the function at `addr` to pseudo-C. `style`: goto | structured | ssa (default, optimized).",
            Some(n0xis_contracts::schema::v0::DECOMP_PSEUDO),
            Origin::Builtin,
            Box::new(|args| {
                let style = match args.get("style").and_then(|v| v.as_str()).unwrap_or("ssa").to_ascii_lowercase().as_str() {
                    "goto" => n0xis_core::DecompStyle::Goto,
                    "structured" => n0xis_core::DecompStyle::Structured,
                    "ssa" => n0xis_core::DecompStyle::Ssa,
                    other => return Response::error("bad-style", format!("unknown style '{other}', expected goto|structured|ssa")),
                };
                let explain = bool_arg(args, "explain");
                with_cfg_ctx(args, |ctx, input, label| {
                    let cfg = match n0xis_pipeline::cfg_cached(ctx, input) {
                        Ok((a, _)) => a,
                        Err(e) => return Response::error("ir-failed", e.to_string()),
                    };
                    match n0xis_core::Pass::run(&n0xis_core::DecompPass, ctx, n0xis_core::DecompInput { cfg, style, explain }) {
                        Ok(pf) => {
                            let resp = ok_json(n0xis_contracts::schema::v0::DECOMP_PSEUDO, pf, label);
                            // The optimizer delta used to ride along on `ssa`
                            // unconditionally; say where it went rather than
                            // letting a caller find it silently missing.
                            if style == n0xis_core::DecompStyle::Ssa && !explain {
                                resp.with_note("optimizer delta omitted (it measured larger than the pseudocode); pass explain:true, or use `ir.explain`")
                            } else {
                                resp
                            }
                        }
                        Err(e) => Response::error("decomp-failed", e.to_string()),
                    }
                })
            }),
        ));

        // --- raw memory access ---

        reg.add(Capability::new(
            "mem.read",
            "Read `size` bytes at `addr` from any source; returns spaced hex.",
            Some(n0xis_contracts::schema::v1::MEM_READ),
            Origin::Builtin,
            Box::new(|args| {
                let addr = match required_addr(args, "addr") {
                    Ok(v) => v,
                    Err((c, m)) => return Response::error(c, m),
                };
                let size = usize_arg(args, "size", 64);
                let mut spec = spec_of(args);
                if spec.bytes_base.is_none() {
                    spec.bytes_base = Some(addr);
                }
                let resolved = match resolve(spec) {
                    Ok(r) => r,
                    Err((c, m)) => return Response::error(&c, m),
                };
                match resolved.src.as_mem().read(addr, size) {
                    Ok(bytes) => ok_json(
                        n0xis_contracts::schema::v1::MEM_READ,
                        json!({ "address": addr, "requested": size, "read": bytes.len(), "hex": to_hex_spaced(&bytes) }),
                        &resolved.label,
                    ),
                    Err(e) => Response::error("read-failed", e.to_string()),
                }
            }),
        ));

        reg.add(Capability::new(
            "mem.write",
            "Write hex `bytes` at `addr` in a live process. Prefer `patch apply` — it journals for undo; this does not.",
            Some(n0xis_contracts::schema::v1::MEM_WRITE),
            Origin::Builtin,
            Box::new(|args| {
                let addr = match required_addr(args, "addr") {
                    Ok(v) => v,
                    Err((c, m)) => return Response::error(c, m),
                };
                let Some(hex) = args.get("bytes").and_then(|v| v.as_str()) else {
                    return Response::error("missing-arg", "'bytes' is required (hex)");
                };
                let bytes = match crate::parse::parse_hex_bytes(hex) {
                    Ok(b) => b,
                    Err(e) => return Response::error("bad-bytes", e),
                };
                let Some(pid) = args.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32) else {
                    return Response::error("missing-source", "'pid' is required — writes only apply to a live process");
                };
                let live = match crate::source::attach_live(pid) {
                    Ok(l) => l,
                    Err((c, m)) => return Response::error(&c, m),
                };
                match n0xis_sources::MemorySource::write(live.as_ref(), addr, &bytes) {
                    Ok(()) => ok_json(
                        n0xis_contracts::schema::v1::MEM_WRITE,
                        json!({ "address": addr, "written": bytes.len(), "hex": to_hex_spaced(&bytes) }),
                        &n0xis_sources::MemorySource::label(live.as_ref()),
                    ),
                    Err(e) => Response::error("write-failed", e.to_string()),
                }
            }),
        ));

        reg.add(Capability::new(
            "mem.map",
            "The live process's address-space region map (base, size, state, protection).",
            Some(n0xis_contracts::schema::v1::MEM_MAP),
            Origin::Builtin,
            Box::new(|args| {
                let limit = usize_arg(args, "limit", 200);
                let Some(pid) = args.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32) else {
                    return Response::error("missing-source", "'pid' is required — only a live process has a region map");
                };
                let live = match crate::source::attach_live(pid) {
                    Ok(l) => l,
                    Err((c, m)) => return Response::error(&c, m),
                };
                let regions = live.regions(limit);
                let regions_v = serde_json::to_value(&regions).unwrap_or(Value::Null);
                ok_json(
                    n0xis_contracts::schema::v1::MEM_MAP,
                    json!({ "count": regions.len(), "regions": regions_v }),
                    &n0xis_sources::MemorySource::label(live.as_ref()),
                )
            }),
        ));

        // --- data-side scanning (a memory scanner class), sharing `with_scan_ctx` ---

        reg.add(Capability::new(
            "scan.value",
            "Value scan over a live process (or a file window): `type`, `criterion` (exact|in-range|unknown), saved under `save_as` for `scan.filter` to narrow.",
            Some(n0xis_contracts::schema::v1::SCAN),
            Origin::Builtin,
            Box::new(|args| {
                let Some(type_name) = args.get("type").and_then(|v| v.as_str()) else {
                    return Response::error("missing-arg", "'type' is required (i32, f32, ...)");
                };
                let value_type = match parse_value_type(type_name) {
                    Ok(t) => t,
                    Err(e) => return Response::error("bad-type", e),
                };
                let criterion = match args.get("criterion").and_then(|v| v.as_str()).unwrap_or("exact") {
                    "exact" => match f64_arg(args, "value") {
                        Some(v) => n0xis_core::ScanCriterion::Exact { value: to_scan_value(v) },
                        None => return Response::error("bad-criterion", "exact criterion needs 'value'"),
                    },
                    "in-range" | "inrange" => match (f64_arg(args, "min"), f64_arg(args, "max")) {
                        (Some(min), Some(max)) => {
                            n0xis_core::ScanCriterion::InRange { min: to_scan_value(min), max: to_scan_value(max) }
                        }
                        _ => return Response::error("bad-criterion", "in-range needs 'min' and 'max'"),
                    },
                    "unknown" => n0xis_core::ScanCriterion::Unknown,
                    other => return Response::error("bad-criterion", format!("unknown scan criterion '{other}' (exact|in-range|unknown)")),
                };
                let Some(save_as) = args.get("save_as").and_then(|v| v.as_str()).map(str::to_string) else {
                    return Response::error("missing-arg", "'save_as' is required — the working set is what `scan.filter` narrows");
                };
                let force = bool_arg(args, "force");
                let align = args.get("align").and_then(|v| v.as_u64()).map(|v| v as usize).unwrap_or_else(|| value_type.size());
                let start = args.get("start").and_then(|v| v.as_str()).map(str::to_string);
                let size = args.get("size").and_then(|v| v.as_u64()).map(|v| v as usize);
                with_scan_ctx(args, start.as_deref(), size, move |ctx, regions, label| {
                    let input = n0xis_core::ScanInput { regions, value_type, criterion, align };
                    let state = match n0xis_core::Pass::run(&n0xis_core::ScanPass, ctx, input) {
                        Ok(s) => s,
                        Err(e) => return Response::error("scan-failed", e.to_string()),
                    };
                    // Persist the full working set compactly; emit only the
                    // bounded report (a full hit list is routinely millions).
                    if let Err(e) = n0xis_project::dump::save(&save_as, "scan", &state.encode(), force) {
                        return Response::error("save-failed", e.to_string());
                    }
                    ok_json(n0xis_contracts::schema::v1::SCAN, state.report(), label)
                })
            }),
        ));

        reg.add(Capability::new(
            "scan.filter",
            "Narrow a saved scan (`from`) by a criterion: exact|increased|decreased|changed|unchanged|in-range.",
            Some(n0xis_contracts::schema::v1::SCAN),
            Origin::Builtin,
            Box::new(|args| {
                let Some(from) = args.get("from").and_then(|v| v.as_str()) else {
                    return Response::error("missing-arg", "'from' is required (a previous scan's save_as name)");
                };
                let criterion = match args.get("criterion").and_then(|v| v.as_str()).unwrap_or("") {
                    "exact" => match f64_arg(args, "value") {
                        Some(v) => n0xis_core::FilterCriterion::Exact { value: to_scan_value(v) },
                        None => return Response::error("bad-criterion", "exact needs 'value'"),
                    },
                    "increased" => n0xis_core::FilterCriterion::Increased,
                    "decreased" => n0xis_core::FilterCriterion::Decreased,
                    "changed" => n0xis_core::FilterCriterion::Changed,
                    "unchanged" => n0xis_core::FilterCriterion::Unchanged,
                    "in-range" | "inrange" => match (f64_arg(args, "min"), f64_arg(args, "max")) {
                        (Some(min), Some(max)) => {
                            n0xis_core::FilterCriterion::InRange { min: to_scan_value(min), max: to_scan_value(max) }
                        }
                        _ => return Response::error("bad-criterion", "in-range needs 'min' and 'max'"),
                    },
                    other => {
                        return Response::error(
                            "bad-criterion",
                            format!("unknown filter criterion '{other}' (exact|increased|decreased|changed|unchanged|in-range)"),
                        );
                    }
                };
                let prev_bytes = match n0xis_project::dump::show(from, Some("scan")) {
                    Ok(d) => d.bytes,
                    Err(e) => return Response::error("no-scan", e.to_string()),
                };
                let previous = match n0xis_core::ScanState::decode(&prev_bytes) {
                    Ok(v) => v,
                    Err(e) => return Response::error("bad-scan-dump", e.to_string()),
                };
                let save_as = args.get("save_as").and_then(|v| v.as_str()).unwrap_or(from).to_string();
                let force = args.get("force").and_then(|v| v.as_bool()).unwrap_or(true);
                // A filter rescans the addresses it already holds, so it needs
                // no region resolution — only the source they live in.
                with_scan_ctx(args, None, None, move |ctx, _regions, label| {
                    let input = n0xis_core::FilterInput { previous, criterion };
                    let state = match n0xis_core::Pass::run(&n0xis_core::FilterPass, ctx, input) {
                        Ok(s) => s,
                        Err(e) => return Response::error("filter-failed", e.to_string()),
                    };
                    if let Err(e) = n0xis_project::dump::save(&save_as, "scan", &state.encode(), force) {
                        return Response::error("save-failed", e.to_string());
                    }
                    ok_json(n0xis_contracts::schema::v1::SCAN, state.report(), label)
                })
            }),
        ));

        reg.add(Capability::new(
            "scan.aob",
            "Array-of-bytes pattern scan (`pattern`, `??` wildcards). Live: every committed writable region unless start/size given.",
            Some(n0xis_contracts::schema::v1::AOB_SCAN),
            Origin::Builtin,
            Box::new(|args| {
                let Some(pattern_str) = args.get("pattern").and_then(|v| v.as_str()) else {
                    return Response::error("missing-arg", "'pattern' is required");
                };
                let pattern = match n0xis_core::parse_aob(pattern_str) {
                    Ok(p) => p,
                    Err(e) => return Response::error("bad-pattern", e),
                };
                let start = args.get("start").and_then(|v| v.as_str()).map(str::to_string);
                let size = args.get("size").and_then(|v| v.as_u64()).map(|v| v as usize);
                with_scan_ctx(args, start.as_deref(), size, move |ctx, regions, label| {
                    let mut matches = Vec::new();
                    let mut bytes_scanned = 0usize;
                    for (start, size) in regions {
                        match n0xis_core::Pass::run(&n0xis_core::AobScanPass, ctx, n0xis_core::AobInput { start, size, pattern: pattern.clone() }) {
                            Ok(art) => {
                                matches.extend(art.matches);
                                bytes_scanned += art.bytes_scanned;
                            }
                            // A region enumerated a moment ago can be freed by
                            // the target before the scan reaches it — skip it
                            // rather than aborting a multi-gigabyte sweep.
                            Err(n0xis_core::CoreError::Source(n0xis_sources::SourceError::Unmapped(_))) => continue,
                            Err(e) => return Response::error("aob-failed", e.to_string()),
                        }
                    }
                    ok_json(n0xis_contracts::schema::v1::AOB_SCAN, n0xis_core::AobArtifact { matches, bytes_scanned }, label)
                })
            }),
        ));

        reg.add(Capability::new(
            "scan.dissect",
            "Classify the bytes at `start` as a struct: pointers, floats, ints, strings.",
            Some(n0xis_contracts::schema::v1::DISSECT),
            Origin::Builtin,
            Box::new(|args| {
                let start = match required_addr(args, "start") {
                    Ok(v) => v,
                    Err((c, m)) => return Response::error(c, m),
                };
                let size = usize_arg(args, "size", 64);
                // Pass the window through as the file-source region so a static
                // dissect needs no separate start/size argument pair.
                let start_s = args.get("start").and_then(|v| v.as_str()).map(str::to_string);
                with_scan_ctx(args, start_s.as_deref(), Some(size), move |ctx, _regions, label| {
                    match n0xis_core::Pass::run(&n0xis_core::DissectPass, ctx, n0xis_core::DissectInput { start, size }) {
                        Ok(art) => ok_json(n0xis_contracts::schema::v1::DISSECT, art, label),
                        Err(e) => Response::error("dissect-failed", e.to_string()),
                    }
                })
            }),
        ));

        reg.add(Capability::new(
            "scan.group",
            "Group scan: find struct bases where several interrelated values co-occur within `window` bytes — `fields` is a list of `TYPE=VALUE` (e.g. i32=3), no layout needed. Anchors on the rarest value, so one distinctive field carries the search.",
            Some(n0xis_contracts::schema::v1::SCAN_GROUP),
            Origin::Builtin,
            Box::new(|args| {
                let Some(field_specs) = args.get("fields").and_then(|v| v.as_array()) else {
                    return Response::error("missing-arg", "'fields' is required — a list of \"TYPE=VALUE\" (e.g. [\"i32=3\",\"i32=1\",\"i32=0\"])");
                };
                if field_specs.is_empty() {
                    return Response::error("bad-fields", "'fields' must not be empty");
                }
                let mut fields = Vec::with_capacity(field_specs.len());
                for spec in field_specs {
                    let Some(s) = spec.as_str() else {
                        return Response::error("bad-fields", "each field must be a string \"TYPE=VALUE\"");
                    };
                    let Some((ty_s, val_s)) = s.split_once('=').or_else(|| s.split_once(':')) else {
                        return Response::error("bad-fields", format!("field '{s}' must be TYPE=VALUE (e.g. i32=3)"));
                    };
                    let value_type = match parse_value_type(ty_s.trim()) {
                        Ok(t) => t,
                        Err(e) => return Response::error("bad-type", e),
                    };
                    let value = match val_s.trim().parse::<f64>() {
                        Ok(v) => to_scan_value(v),
                        Err(_) => return Response::error("bad-value", format!("field '{s}': '{}' is not a number", val_s.trim())),
                    };
                    fields.push(n0xis_core::GroupField { value_type, value });
                }
                let window = args.get("window").and_then(|v| v.as_u64()).map(|v| v as usize).unwrap_or(256);
                // Default stride = the smallest field's natural size (fine for the
                // usual dword struct fields); `align=1` to catch unaligned ones.
                let min_size = fields.iter().map(|f| f.value_type.size()).min().unwrap_or(1);
                let align = args.get("align").and_then(|v| v.as_u64()).map(|v| v as usize).unwrap_or(min_size);
                let limit = args.get("limit").and_then(|v| v.as_u64()).map(|v| v as usize).unwrap_or(100);
                let start = args.get("start").and_then(|v| v.as_str()).map(str::to_string);
                let size = args.get("size").and_then(|v| v.as_u64()).map(|v| v as usize);
                with_scan_ctx(args, start.as_deref(), size, move |ctx, regions, label| {
                    let input = n0xis_core::GroupScanInput { regions, fields, window, align, limit };
                    match n0xis_core::Pass::run(&n0xis_core::GroupScanPass, ctx, input) {
                        Ok(art) => ok_json(n0xis_contracts::schema::v1::SCAN_GROUP, art, label),
                        Err(e) => Response::error("group-failed", e.to_string()),
                    }
                })
            }),
        ));

        reg.add(Capability::new(
            "pointer.path",
            "Find stable pointer chains from a module's address range to `target` (live process only).",
            Some(n0xis_contracts::schema::v1::POINTER_PATH),
            Origin::Builtin,
            Box::new(|args| {
                let target = match required_addr(args, "target") {
                    Ok(v) => v,
                    Err((c, m)) => return Response::error(c, m),
                };
                let modules: Vec<String> = match args.get("modules").and_then(|v| v.as_array()) {
                    Some(a) if !a.is_empty() => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
                    _ => return Response::error("missing-arg", "'modules' is required (array of module names to root chains in)"),
                };
                let max_depth = usize_arg(args, "max_depth", 3);
                let max_offset = args.get("max_offset").and_then(|v| v.as_u64()).unwrap_or(0x1000);
                let Some(pid) = args.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32) else {
                    return Response::error("missing-source", "'pid' is required — pointer chains only exist in a live process");
                };
                {
                    let arch = match crate::resolve_arch(args.get("arch").and_then(|v| v.as_str())) {
                        Ok(a) => a,
                        Err(e) => return Response::error("bad-arch", e),
                    };
                    let live = match crate::source::attach_live(pid) {
                        Ok(l) => l,
                        Err((c, m)) => return Response::error(&c, m),
                    };
                    let mods = n0xis_sources::ModuleProvider::modules(live.as_ref()).to_vec();
                    let mut roots = Vec::new();
                    for name in &modules {
                        let Some(m) = mods.iter().find(|m| m.name.eq_ignore_ascii_case(name)) else {
                            return Response::error("no-module", format!("no module named '{name}' in this process"));
                        };
                        roots.push(n0xis_core::PointerRoot { label: m.name.clone(), start: m.base, size: m.size });
                    }
                    let search_regions: Vec<(Va, usize)> = live
                        .regions(1_000_000)
                        .into_iter()
                        .filter(|r| r.state == "commit" && matches!(r.protect.as_str(), "rw-" | "rwx" | "rc-" | "rcx" | "r--" | "r-x"))
                        .map(|r| (r.base, r.size as usize))
                        .collect();
                    let label = n0xis_sources::MemorySource::label(live.as_ref());
                    let ctx = n0xis_core::Ctx::new(live.as_ref(), arch.as_ref());
                    let input = n0xis_core::PointerPathInput { target, search_regions, roots, max_depth, max_offset, pointer_size: 8 };
                    match n0xis_core::Pass::run(&n0xis_core::PointerPathPass, &ctx, input) {
                        Ok(art) => ok_json(n0xis_contracts::schema::v1::POINTER_PATH, art, &label),
                        Err(e) => Response::error("pointer-path-failed", e.to_string()),
                    }
                }
            }),
        ));

        // --- range-scoped analysis, all sharing `with_src_ctx` ---

        reg.add(Capability::new(
            "xref",
            "Cross-references to (`dir`:\"to\") or from (`dir`:\"from\") `addr`, scanned over a code range.",
            Some(n0xis_contracts::schema::v1::XREF),
            Origin::Builtin,
            Box::new(|args| {
                let addr = match required_addr(args, "addr") {
                    Ok(v) => v,
                    Err((c, m)) => return Response::error(c, m),
                };
                let dir = match args.get("dir").and_then(|v| v.as_str()).unwrap_or("to").to_ascii_lowercase().as_str() {
                    "to" => n0xis_core::XrefDir::To,
                    "from" => n0xis_core::XrefDir::From,
                    other => return Response::error("bad-dir", format!("unknown dir '{other}', expected to|from")),
                };
                let explicit_start = match opt_addr_arg(args, "start") {
                    Ok(v) => v,
                    Err((c, m)) => return Response::error(c, m),
                };
                let explicit_size = args.get("size").and_then(|v| v.as_u64()).map(|v| v as usize);
                let base = explicit_start.unwrap_or(Va(0));
                with_src_ctx(args, base, |ctx, src, region_len, label| {
                    let (scan_start, size) = crate::source::scan_range_or(src.text_range(), region_len, explicit_start, explicit_size, base);
                    if size == 0 {
                        return Response::error("no-range", "could not resolve a scan range; pass start and size");
                    }
                    match n0xis_core::Pass::run(&n0xis_core::XrefPass, ctx, n0xis_core::XrefInput { scan_start, size, addr, dir }) {
                        Ok(art) => ok_json(n0xis_contracts::schema::v1::XREF, art, label),
                        Err(e) => Response::error("xref-failed", e.to_string()),
                    }
                })
            }),
        ));

        reg.add(Capability::new(
            "xref.string",
            "Find a string literal in a data window and the instructions that reference it.",
            Some(n0xis_contracts::schema::v1::XREF_STRING),
            Origin::Builtin,
            Box::new(|args| {
                let Some(query) = args.get("query").and_then(|v| v.as_str()).map(str::to_string) else {
                    return Response::error("missing-arg", "'query' is required");
                };
                let explicit_code_start = match opt_addr_arg(args, "start") {
                    Ok(v) => v,
                    Err((c, m)) => return Response::error(c, m),
                };
                let explicit_data_start = match opt_addr_arg(args, "data_start") {
                    Ok(v) => v,
                    Err((c, m)) => return Response::error(c, m),
                };
                let code_size_arg = args.get("size").and_then(|v| v.as_u64()).map(|v| v as usize);
                let data_size_arg = args.get("data_size").and_then(|v| v.as_u64()).map(|v| v as usize);
                let limit = usize_arg(args, "limit", 50);
                // Data window wins as the inline-bytes base: a `--bytes` run of
                // this capability is looking for the string, not the code.
                let base = explicit_data_start.or(explicit_code_start).unwrap_or(Va(0));
                with_src_ctx(args, base, move |ctx, src, region_len, label| {
                    // String literals and the code pointing at them usually sit
                    // in different sections, so the two windows default
                    // independently: data to `.rdata` (falling back to `.text`).
                    let default_data = src.section_range(".rdata").or_else(|| src.text_range());
                    let (code_start, code_size) =
                        crate::source::scan_range_or(src.text_range(), region_len, explicit_code_start, code_size_arg, base);
                    let (data_start, data_size) =
                        crate::source::scan_range_or(default_data, region_len, explicit_data_start, data_size_arg, base);
                    if code_size == 0 || data_size == 0 {
                        return Response::error("no-range", "could not resolve a data/code range; pass data_start/data_size and start/size");
                    }
                    let input = n0xis_core::StringXrefInput { data_start, data_size, code_start, code_size, query, limit };
                    match n0xis_core::Pass::run(&n0xis_core::StringXrefPass, ctx, input) {
                        Ok(art) => ok_json(n0xis_contracts::schema::v1::XREF_STRING, art, label),
                        Err(e) => Response::error("xref-string-failed", e.to_string()),
                    }
                })
            }),
        ));

        reg.add(Capability::new(
            "ir.manifest",
            "Per-function index over a code range with quality scoring — discover, then measure how well each decompiles.",
            Some(n0xis_contracts::schema::v1::IR_MANIFEST),
            Origin::Builtin,
            Box::new(|args| {
                let explicit_start = match opt_addr_arg(args, "start") {
                    Ok(v) => v,
                    Err((c, m)) => return Response::error(c, m),
                };
                let explicit_size = args.get("size").and_then(|v| v.as_u64()).map(|v| v as usize);
                let limit = usize_arg(args, "limit", 200);
                let max_bytes = usize_arg(args, "max_bytes", 4096);
                let base = explicit_start.unwrap_or(Va(0));
                with_src_ctx(args, base, move |ctx, src, region_len, label| {
                    let (start, size) = crate::source::scan_range_or(src.text_range(), region_len, explicit_start, explicit_size, base);
                    if size == 0 {
                        return Response::error("no-range", "could not resolve a scan range; pass start and size");
                    }
                    let discovered = match n0xis_core::Pass::run(
                        &n0xis_core::DiscoverPass,
                        ctx,
                        n0xis_core::DiscoverInput { start, size, limit, offset: 0 },
                    ) {
                        Ok(d) => d,
                        Err(e) => return Response::error("discover-failed", e.to_string()),
                    };
                    let candidates = discovered
                        .functions
                        .into_iter()
                        .map(|f| n0xis_core::ManifestCandidate { name: f.name, va: f.va })
                        .collect();
                    match n0xis_core::Pass::run(&n0xis_core::ManifestPass, ctx, n0xis_core::ManifestInput { candidates, max_bytes }) {
                        Ok(art) => ok_json(n0xis_contracts::schema::v1::IR_MANIFEST, art, label),
                        Err(e) => Response::error("manifest-failed", e.to_string()),
                    }
                })
            }),
        ));

        reg.add(Capability::new(
            "function.trace",
            "Walk the call graph from `addr` to `depth`, naming what each function calls.",
            Some(n0xis_contracts::schema::v1::FUNCTION_TRACE),
            Origin::Builtin,
            Box::new(|args| {
                let addr = match required_addr(args, "addr") {
                    Ok(v) => v,
                    Err((c, m)) => return Response::error(c, m),
                };
                let addr_rva = bool_arg(args, "addr_rva");
                let depth = usize_arg(args, "depth", 3);
                let max_nodes = usize_arg(args, "max_nodes", 500);
                let max_bytes = usize_arg(args, "max_bytes", 4096);
                with_src_ctx(args, addr, move |ctx, src, _region_len, label| {
                    let root = if addr_rva {
                        match src.module_base() {
                            Some(base) => base.offset(addr.0),
                            None => return Response::error("no-module", "no module base resolved for addr_rva"),
                        }
                    } else {
                        addr
                    };
                    let input = n0xis_core::TraceInput { root, depth, max_nodes, max_bytes };
                    match n0xis_core::Pass::run(&n0xis_core::TracePass, ctx, input) {
                        Ok(art) => ok_json(n0xis_contracts::schema::v1::FUNCTION_TRACE, art, label),
                        Err(e) => Response::error("trace-failed", e.to_string()),
                    }
                })
            }),
        ));

        reg.add(Capability::new(
            "diff.functions",
            "Decompile two functions (each with its own target: `a_pid`/`a_file`/`a_bytes`, `b_*`) and diff the pseudo-C.",
            Some(n0xis_contracts::schema::v1::DIFF),
            Origin::Builtin,
            Box::new(|args| {
                let a_addr = match required_addr(args, "a_addr") {
                    Ok(v) => v,
                    Err((c, m)) => return Response::error(c, m),
                };
                let b_addr = match required_addr(args, "b_addr") {
                    Ok(v) => v,
                    Err((c, m)) => return Response::error(c, m),
                };
                let style = match args.get("style").and_then(|v| v.as_str()).unwrap_or("goto").to_ascii_lowercase().as_str() {
                    "goto" => n0xis_core::DecompStyle::Goto,
                    "structured" => n0xis_core::DecompStyle::Structured,
                    "ssa" => n0xis_core::DecompStyle::Ssa,
                    other => return Response::error("bad-style", format!("unknown style '{other}', expected goto|structured|ssa")),
                };
                let arch = match crate::resolve_arch(args.get("arch").and_then(|v| v.as_str())) {
                    Ok(a) => a,
                    Err(e) => return Response::error("bad-arch", e),
                };
                let size = usize_arg(args, "size", 4096);
                // Each side names its own target — the whole point is comparing
                // two builds, so they are rarely the same source.
                let side = |prefix: &str| SourceSpec {
                    pid: args.get(format!("{prefix}_pid")).and_then(|v| v.as_u64()).map(|v| v as u32),
                    file: args.get(format!("{prefix}_file")).and_then(|v| v.as_str()),
                    bytes: args.get(format!("{prefix}_bytes")).and_then(|v| v.as_str()),
                    ..Default::default()
                };
                let (pseudo_a, label_a) = match decompile_side(side("a"), a_addr, size, style, arch.as_ref()) {
                    Ok(x) => x,
                    Err((c, m)) => return Response::error(format!("a-{c}"), m),
                };
                let (pseudo_b, label_b) = match decompile_side(side("b"), b_addr, size, style, arch.as_ref()) {
                    Ok(x) => x,
                    Err((c, m)) => return Response::error(format!("b-{c}"), m),
                };
                // The diff itself reads no memory; an empty snapshot satisfies
                // `Ctx` without pretending either side is "the" source.
                let snap = n0xis_sources::Snapshot::builder().build();
                let ctx = n0xis_core::Ctx::new(&snap, arch.as_ref());
                match n0xis_core::Pass::run(&n0xis_core::DiffPass, &ctx, n0xis_core::DiffInput { a: pseudo_a, b: pseudo_b }) {
                    Ok(art) => ok_json(n0xis_contracts::schema::v1::DIFF, art, &format!("a={label_a} b={label_b}")),
                    Err(e) => Response::error("diff-failed", e.to_string()),
                }
            }),
        ));

        reg.add(Capability::new(
            "function.discover",
            "Heuristic function discovery over a code range (defaults to `.text`).",
            Some(n0xis_contracts::schema::v1::FUNCTION_DISCOVER),
            Origin::Builtin,
            Box::new(|args| {
                let arch = match crate::resolve_arch(args.get("arch").and_then(|v| v.as_str())) {
                    Ok(a) => a,
                    Err(e) => return Response::error("bad-arch", e),
                };
                let resolved = match resolve(spec_of(args)) {
                    Ok(r) => r,
                    Err((c, m)) => return Response::error(&c, m),
                };
                let explicit_start = args.get("start").and_then(|v| v.as_str()).and_then(|s| Va::parse(s).ok());
                let explicit_size = args.get("size").and_then(|v| v.as_u64()).map(|v| v as usize);
                let Some((start, size)) =
                    crate::source::scan_range(resolved.src.text_range(), resolved.region_len, explicit_start, explicit_size)
                else {
                    return Response::error("no-range", "could not resolve a scan range; pass start and size");
                };
                let ctx = n0xis_core::Ctx::new(resolved.src.as_mem(), arch.as_ref());
                let input = n0xis_core::DiscoverInput { start, size, limit: usize_arg(args, "limit", 64), offset: usize_arg(args, "offset", 0) };
                match n0xis_core::Pass::run(&n0xis_core::DiscoverPass, &ctx, input) {
                    Ok(out) => match serde_json::to_value(out) {
                        Ok(v) => Response::success(n0xis_contracts::schema::v1::FUNCTION_DISCOVER, v).with_source(resolved.label),
                        Err(e) => Response::error("serialize", e.to_string()),
                    },
                    Err(e) => Response::error("discover-failed", e.to_string()),
                }
            }),
        ));
    }
}

/// The user's registered process plugins (`.n0x/plugins.json`), exposed as
/// capabilities with the same shape as the built-ins above. This is the whole
/// point of the trait: from a frontend's side, `reg.dispatch("acme.scan", …)`
/// and `reg.dispatch("decode", …)` are the same call.
pub struct ProcessPlugins;

/// How long a plugin gets before it is treated as wedged.
const PLUGIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

impl Plugin for ProcessPlugins {
    fn name(&self) -> &str {
        "n0xis.process-plugins"
    }

    fn register(&self, reg: &mut Registry) {
        let Ok(records) = n0xis_project::plugins::list() else {
            return; // No project, or an unreadable registry: no plugins, not an error.
        };
        for rec in records {
            let command = rec.command.clone();
            let handles = rec.handles.join(", ");
            let spawn = command.clone();
            reg.add(Capability::new(
                format!("plugin.{}", rec.name),
                format!("External plugin `{}` (handles: {handles}).", rec.name),
                None,
                Origin::Plugin { command },
                Box::new(move |args| {
                    let argv = match n0xis_sources::split_command_line(&spawn) {
                        Ok(v) if !v.is_empty() => v,
                        Ok(_) => return Response::error("bad-plugin-command", "plugin command is empty"),
                        Err(e) => return Response::error("bad-plugin-command", e),
                    };
                    match n0xis_sources::plugin_call_once(&argv, args, PLUGIN_TIMEOUT) {
                        Ok(v) => Response::success("n0xis.plugin.v1", v),
                        // Fail-open-but-visible: a wedged plugin is reported,
                        // never a panic and never a silent empty result.
                        Err(e) => Response::error("plugin-failed", e),
                    }
                }),
            ));
        }
    }
}

/// **The single composition point.** Everything the process can do is listed
/// here, built-in and external through the identical `Plugin` trait. Adding a
/// capability means adding a registration call — in a plugin's `register`, or
/// one more line here — never editing a frontend's dispatch.
pub fn build_registry() -> Registry {
    let mut reg = Registry::new();
    reg.add_plugin(&AnalysisPasses);
    reg.add_plugin(&crate::project_caps::ProjectOps);
    reg.add_plugin(&crate::method_caps::MethodTools);
    reg.add_plugin(&ProcessPlugins);
    reg
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake;
    impl Plugin for Fake {
        fn name(&self) -> &str {
            "fake"
        }
        fn register(&self, reg: &mut Registry) {
            reg.add(Capability::new(
                "fake.echo",
                "Echo the arguments back.",
                None,
                Origin::Builtin,
                Box::new(|args| Response::success("test.echo.v1", args.clone())),
            ));
        }
    }

    #[test]
    fn a_plugin_registers_and_dispatches() {
        let mut reg = Registry::new();
        reg.add_plugin(&Fake);
        let resp = reg.dispatch("fake.echo", &json!({ "hello": 1 }));
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["data"]["hello"], 1);
    }

    #[test]
    fn an_unknown_capability_is_an_envelope_not_a_panic() {
        let reg = Registry::new();
        let v = serde_json::to_value(reg.dispatch("nope", &json!({}))).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], "unknown-capability");
    }

    #[test]
    fn builtins_are_registered_through_the_same_trait_as_plugins() {
        let reg = build_registry();
        let decode = reg.get("decode").expect("decode is registered");
        assert_eq!(decode.origin, Origin::Builtin);
        assert_eq!(decode.schema.as_deref(), Some("n0xis.decode.v1"));
        // The catalog is machine-readable and names the origin of each entry.
        let d = reg.describe();
        assert!(d["count"].as_u64().unwrap() >= 2);
        assert!(d["capabilities"].as_array().unwrap().iter().any(|c| c["name"] == "decode"));
    }

    #[test]
    fn a_builtin_runs_end_to_end_over_inline_bytes() {
        let reg = build_registry();
        // 48 89 c8 = mov rax, rcx ; c3 = ret
        let resp = reg.dispatch(
            "decode",
            &json!({ "bytes": "48 89 c8 c3", "bytes_base": "0x140001000", "addr": "0x140001000", "count": 4 }),
        );
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["data"]["count"], 2);
        assert_eq!(v["data"]["insns"][0]["mnemonic"], "mov");
    }

    #[test]
    fn a_capability_reports_a_bad_arch_instead_of_defaulting() {
        let reg = build_registry();
        let v = serde_json::to_value(reg.dispatch("decode", &json!({ "bytes": "c3", "addr": "0x0", "arch": "mips" }))).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], "bad-arch");
    }
}
