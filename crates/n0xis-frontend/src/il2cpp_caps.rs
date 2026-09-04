// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! IL2CPP managed-layer capabilities (Phase 12, item 0): `il2cpp.import` and
//! `il2cpp.symbols`.
//!
//! Item 0 buys named decompilation before a metadata parser exists, by
//! importing an index another tool already produced. The two things this layer
//! adds over "read a JSON file" are both refusals:
//!
//! - **A Unity WebGL index can never bind to a native target.** The addresses
//!   are numerically indistinguishable and semantically unrelated; binding one
//!   to the other names every function wrongly. The index is still importable
//!   and searchable — it is just not a `SymbolProvider`.
//! - **A native index binds only if it measurably fits.** Dumper versions
//!   disagree on whether `Address` is an RVA or a based VA, so both conventions
//!   are tried against the target's own `.text` and the winner must clear
//!   `MIN_BIND_CONFIDENCE`. A dump from a different build is refused rather
//!   than applied — confident wrong names are the worst outcome on this corpus.

use n0xis_contracts::{Response, Va, schema};
use n0xis_il2cpp::{AddressSpace, Index, metadata, script_json};
use serde_json::{Value, json};

use crate::registry::{Capability, Origin, Plugin, Registry};
use crate::source::{SourceSpec, resolve as resolve_src};

/// Symbols returned by one `il2cpp.symbols` call unless asked otherwise. An
/// index holds six figures of names; a bare query must not return them all.
const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 1_000;

fn ok<T: serde::Serialize>(schema_id: &str, data: T) -> Response<Value> {
    match serde_json::to_value(data) {
        Ok(v) => Response::success(schema_id, v),
        Err(e) => Response::error("serialize", e.to_string()),
    }
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn usize_arg(args: &Value, key: &str) -> Option<usize> {
    args.get(key).and_then(Value::as_u64).map(|v| v as usize)
}

/// Where a named index is persisted. One JSON file per index under `.n0x/`.
fn index_path(name: &str) -> Result<std::path::PathBuf, Box<Response<Value>>> {
    if name.is_empty() || name.contains(['/', '\\', ':']) || name == ".." {
        return Err(Box::new(Response::error("bad-name", format!("index name {name:?} must be a plain file-safe name"))));
    }
    let root = n0xis_project::resolve().map_err(|e| Box::new(Response::error("no-project", format!("{e}; run `n0x init` first"))))?;
    Ok(root.il2cpp_dir().join(format!("{name}.json")))
}

fn load_index(name: &str) -> Result<Index, Box<Response<Value>>> {
    let path = index_path(name)?;
    let bytes = std::fs::read(&path)
        .map_err(|e| Box::new(Response::error("no-index", format!("read {}: {e}; import one with `il2cpp import`", path.display()))))?;
    serde_json::from_slice(&bytes).map_err(|e| Box::new(Response::error("bad-index", format!("parse {}: {e}", path.display()))))
}

/// The target facts a binding measurement needs: where the image sits and
/// where its code is. Three bare `u64`s would be indistinguishable at every
/// call site.
#[derive(Debug, Clone, Copy)]
struct TargetRanges {
    module_base: u64,
    text_start: u64,
    text_len: u64,
}

/// Resolve the target's module base and `.text` range, for binding detection.
/// `None` when no target was named — importing without one is legal, it just
/// cannot be validated yet.
fn target_ranges(args: &Value) -> Result<Option<TargetRanges>, Box<Response<Value>>> {
    let spec = SourceSpec {
        pid: args.get("pid").and_then(Value::as_u64).map(|v| v as u32),
        file: str_arg(args, "file"),
        ..Default::default()
    };
    if spec.pid.is_none() && spec.file.is_none() {
        return Ok(None);
    }
    let resolved = resolve_src(spec).map_err(|(c, m)| Box::new(Response::error(&c, m)))?;
    let Some((text_start, text_len)) = resolved.src.text_range() else {
        return Err(Box::new(Response::error("no-text-range", "this target exposes no .text range, so a binding cannot be measured against it")));
    };
    let base = crate::source::module_base_of(&resolved.src).map(|v| v.0).unwrap_or(0);
    Ok(Some(TargetRanges { module_base: base, text_start: text_start.0, text_len }))
}

/// Locate a Unity IL2CPP metadata blob next to `image_path`, if one exists.
///
/// Unity's layout is `<Game>/<Game>_Data/il2cpp_data/Metadata/global-metadata.dat`,
/// with the executable and `GameAssembly.dll` beside the `*_Data` directory —
/// so the search is "any sibling directory ending in `_Data`", never a
/// hardcoded game name.
///
/// Lives in the frontend rather than in `n0xis-il2cpp` because that crate is
/// deliberately byte-pure (bytes in, structures out, no filesystem), and in one
/// place rather than two because the CLI's `profile` needs the same answer —
/// two copies of a layout rule drift the moment Unity changes it.
pub fn find_metadata_near(image_path: &str) -> Option<String> {
    // `Path::new("GameAssembly.dll").parent()` is `""`, not the current
    // directory — reading that fails, and the metadata would be silently
    // "absent" whenever the target was passed as a bare filename.
    let dir = match std::path::Path::new(image_path).parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    for entry in std::fs::read_dir(dir).ok()? {
        let Ok(entry) = entry else { continue };
        if !entry.file_name().to_string_lossy().ends_with("_Data") {
            continue;
        }
        let candidate = entry.path().join("il2cpp_data").join("Metadata").join("global-metadata.dat");
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

/// Whether an analysis command got managed names, and why not when it did not.
///
/// The middle case is the one that needs a name of its own: an index that is
/// *present but unusable* must not look like no index at all, or a user stares
/// at unnamed pseudo-C wondering why the import they just ran did nothing.
pub(crate) enum IndexAttach {
    /// No index in the project — the ordinary case for a non-Unity target.
    None,
    Attached(Box<n0xis_il2cpp::Il2CppSymbols>, String),
    /// Found, and deliberately not used. Carries the reason.
    Skipped(String),
}

impl IndexAttach {
    pub(crate) fn symbols(&self) -> Option<&dyn n0xis_sources::SymbolProvider> {
        match self {
            IndexAttach::Attached(s, _) => Some(s.as_ref()),
            _ => None,
        }
    }

    /// Say which layer the names came from — or why they did not come.
    /// `meta.note` exists for exactly this: a result that is easy to misread.
    pub(crate) fn annotate(&self, resp: Response<Value>) -> Response<Value> {
        match self {
            IndexAttach::None => resp,
            IndexAttach::Attached(_, note) | IndexAttach::Skipped(note) => resp.with_note(note.clone()),
        }
    }
}

/// Load and bind the project's IL2CPP index for an already-resolved target.
///
/// Deliberately non-fatal in every failure mode: an analysis command must not
/// stop working because an index is missing, stale or from another build. It
/// reports instead.
pub(crate) fn attach_for(args: &Value, src: &crate::source::Src) -> IndexAttach {
    let name = str_arg(args, "il2cpp_index").unwrap_or("default");
    let Ok(path) = index_path(name) else { return IndexAttach::None };
    if !path.exists() {
        return IndexAttach::None;
    }
    let Ok(bytes) = std::fs::read(&path) else {
        return IndexAttach::Skipped(format!("il2cpp index '{name}' exists but could not be read; names are from the binary only"));
    };
    let Ok(index) = serde_json::from_slice::<Index>(&bytes) else {
        return IndexAttach::Skipped(format!("il2cpp index '{name}' is unreadable; names are from the binary only"));
    };
    if matches!(index.space, AddressSpace::Wasm { .. }) {
        return IndexAttach::Skipped(format!(
            "il2cpp index '{name}' is a WebGL (wasm) index and cannot be bound to a native target; query it with `il2cpp symbols`"
        ));
    }
    let Some((text_start, text_len)) = src.text_range() else {
        return IndexAttach::Skipped(format!("il2cpp index '{name}' was not applied: this target exposes no .text range to bind against"));
    };
    let base = crate::source::module_base_of(src).map(|v| v.0).unwrap_or(0);
    let report = index.detect_binding(base, text_start.0, text_len);
    if !report.accepted {
        return IndexAttach::Skipped(format!(
            "il2cpp index '{name}' was NOT applied: only {:.1}% of sampled method addresses land in .text — it looks like a different build. Names below are from the binary only.",
            report.confidence * 100.0
        ));
    }
    let module = index.space.module().unwrap_or("GameAssembly.dll").to_string();
    let count = index.len();
    match index.bind(module, base, &report) {
        Ok(bound) => IndexAttach::Attached(
            Box::new(bound),
            format!("managed names from il2cpp index '{name}' ({count} symbols, {} binding); names not in it come from the binary", report.kind.as_str()),
        ),
        Err(e) => IndexAttach::Skipped(format!("il2cpp index '{name}' was not applied: {e}")),
    }
}

/// The managed layer.
pub struct Il2CppTools;

impl Plugin for Il2CppTools {
    fn name(&self) -> &str {
        "n0xis.il2cpp"
    }

    fn register(&self, reg: &mut Registry) {
        reg.add(Capability::new(
            "il2cpp.import",
            "Import an external IL2CPP dump (Il2CppDumper script.json) as a named symbol index under .n0x/. \
             With a target (pid/file) it also measures how the dump's addresses map onto it and refuses a mismatch. \
             Unity WebGL dumps import as searchable name tables and are never bound to a native image.",
            Some(schema::v1::IL2CPP_IMPORT),
            Origin::Builtin,
            Box::new(|args| {
                let Some(dump) = str_arg(args, "script_json") else {
                    return Response::error("missing-script-json", "'script_json' is required: the path to an Il2CppDumper script.json");
                };
                let name = str_arg(args, "name").unwrap_or("default");
                let path = match index_path(name) {
                    Ok(p) => p,
                    Err(r) => return *r,
                };

                let module = str_arg(args, "module").map(str::to_string);
                let space = match AddressSpace::parse(str_arg(args, "space").unwrap_or("native"), module.clone()) {
                    Ok(s) => s,
                    Err(e) => return Response::error("bad-space", e),
                };

                let bytes = match std::fs::read(dump) {
                    Ok(b) => b,
                    Err(e) => return Response::error("read-failed", format!("read {dump}: {e}")),
                };
                let parsed = match script_json::parse(&bytes) {
                    Ok(p) => p,
                    Err(e) => return Response::error("bad-dump", format!("{dump}: {e}")),
                };
                let index = Index::from_parsed(parsed, space, format!("Il2CppDumper script.json ({dump})"));

                // Measure the binding when a target is available. A WebGL index
                // is never bound, so it is not measured either — saying "0%
                // confidence" about a mapping that is categorically wrong would
                // imply a better dump could fix it.
                let is_wasm = matches!(index.space, AddressSpace::Wasm { .. });
                let binding = if is_wasm {
                    None
                } else {
                    match target_ranges(args) {
                        Ok(Some(t)) => Some((index.detect_binding(t.module_base, t.text_start, t.text_len), t.module_base)),
                        Ok(None) => None,
                        Err(r) => return *r,
                    }
                };
                if let Some((report, _)) = &binding
                    && !report.accepted
                    && args.get("force").and_then(Value::as_bool) != Some(true)
                {
                    return Response::error(
                        "binding-rejected",
                        format!(
                            "only {:.1}% of {} sampled method addresses land inside .text (rva {} vs va {}) — \
                             the dump and the binary look like different builds. Re-dump, or pass force to store it anyway.",
                            report.confidence * 100.0,
                            report.sampled,
                            report.hits_rva,
                            report.hits_va
                        ),
                    );
                }

                if let Some(parent) = path.parent()
                    && let Err(e) = std::fs::create_dir_all(parent)
                {
                    return Response::error("write-failed", format!("create {}: {e}", parent.display()));
                }
                let encoded = match serde_json::to_vec(&index) {
                    Ok(v) => v,
                    Err(e) => return Response::error("serialize", e.to_string()),
                };
                if let Err(e) = std::fs::write(&path, &encoded) {
                    return Response::error("write-failed", format!("write {}: {e}", path.display()));
                }

                ok(
                    schema::v1::IL2CPP_IMPORT,
                    json!({
                        "name": name,
                        "stored": path.display().to_string(),
                        "bytes_written": encoded.len(),
                        "space": index.space.as_str(),
                        "module": index.space.module(),
                        "source": index.source,
                        "symbols": index.len(),
                        "strings": index.strings.len(),
                        "counts": index.counts,
                        // The evidence, not just the verdict: an agent getting
                        // names should be able to see how sound the mapping is.
                        "binding": binding.map(|(r, base)| json!({
                            "kind": r.kind.as_str(),
                            "module_base": Va(base).to_string(),
                            "sampled": r.sampled,
                            "hits_rva": r.hits_rva,
                            "hits_va": r.hits_va,
                            "confidence": r.confidence,
                            "accepted": r.accepted,
                        })),
                        "bindable": !is_wasm,
                        "note": if is_wasm {
                            "a WebGL index is a searchable name table: its addresses are WebAssembly offsets, \
                             and this build has no WASM front end to bind them to"
                        } else if binding.is_none() {
                            "no target given, so the address convention was not measured; pass pid or file to validate it"
                        } else {
                            "bound and validated against the target's .text"
                        },
                    }),
                )
            }),
        ));

        reg.add(Capability::new(
            "il2cpp.symbols",
            "Query an imported index: by name substring, or by address (needs a target so the binding can be applied). \
             Name lookups return a set — generic sharing and ICF both make a single answer a lie.",
            Some(schema::v1::IL2CPP_SYMBOLS),
            Origin::Builtin,
            Box::new(|args| {
                let name = str_arg(args, "name").unwrap_or("default");
                let index = match load_index(name) {
                    Ok(i) => i,
                    Err(r) => return *r,
                };
                let requested = usize_arg(args, "limit").unwrap_or(DEFAULT_LIMIT);
                let limit = requested.min(MAX_LIMIT);

                // Address lookup: needs the same binding the import measured.
                if let Some(at) = str_arg(args, "addr") {
                    let va = match Va::parse(at) {
                        Ok(v) => v,
                        Err(e) => return Response::error("bad-addr", e.to_string()),
                    };
                    let Some(t) = (match target_ranges(args) {
                        Ok(t) => t,
                        Err(r) => return *r,
                    }) else {
                        return Response::error("no-target", "an address lookup needs a target (pid or file) so the dump's addresses can be mapped onto it");
                    };
                    let report = index.detect_binding(t.module_base, t.text_start, t.text_len);
                    let module = index.space.module().unwrap_or("GameAssembly.dll").to_string();
                    let bound = match index.bind(module, t.module_base, &report) {
                        Ok(b) => b,
                        Err(e) => return Response::error("unbindable", e.to_string()),
                    };
                    use n0xis_sources::SymbolProvider;
                    let hit = bound.symbol_at(va);
                    return ok(
                        schema::v1::IL2CPP_SYMBOLS,
                        json!({
                            "index": name,
                            "query": { "addr": va.to_string() },
                            "binding": { "kind": report.kind.as_str(), "confidence": report.confidence },
                            "count": usize::from(hit.is_some()),
                            "symbols": hit.map(|s| vec![json!({ "va": s.va.to_string(), "name": s.name, "kind": format!("{:?}", s.kind).to_lowercase() })]).unwrap_or_default(),
                        }),
                    );
                }

                let needle = str_arg(args, "query").unwrap_or("");
                let all = index.find_by_name(needle);
                let matched = all.len();
                let page: Vec<Value> = all
                    .iter()
                    .take(limit)
                    .map(|s| json!({ "addr": Va(s.addr).to_string(), "name": s.name, "kind": s.kind.as_str(), "signature": s.signature }))
                    .collect();
                let returned = page.len();
                ok(
                    schema::v1::IL2CPP_SYMBOLS,
                    json!({
                        "index": name,
                        "space": index.space.as_str(),
                        "query": { "name": needle },
                        "total": index.len(),
                        "matched": matched,
                        "count": returned,
                        "more": returned < matched,
                        "limit_clamped": (requested > limit).then_some(limit),
                        // Addresses here are in the index's own space, unbound:
                        // saying so stops them being pasted into a live target.
                        "addresses_are": index.space.as_str(),
                        "symbols": page,
                    }),
                )
            }),
        ));

        reg.add(Capability::new(
            "il2cpp.classes",
            "Enumerate the C# classes a running game has loaded, by the one property every managed object has: its first word is \
             its Il2CppClass*. Samples heap regions, ranks pointers by how often they repeat, and keeps only candidates whose field \
             array points back at them. Needs no metadata parse and no dumper.",
            Some(schema::v1::IL2CPP_CLASSES),
            Origin::Builtin,
            Box::new(|args| {
                let Some(pid) = args.get("pid").and_then(Value::as_u64).map(|v| v as u32) else {
                    return Response::error("no-source", "pass pid=<n>: classes only exist in a running process");
                };
                #[cfg(not(windows))]
                {
                    let _ = pid;
                    Response::error("live-unsupported", "il2cpp classes requires a Windows build (needs LiveProcess)")
                }
                #[cfg(windows)]
                {
                    let live = match n0xis_sources::LiveProcess::attach(pid) {
                        Ok(l) => l,
                        Err(e) => return Response::error("attach-failed", e.to_string()),
                    };
                    // Sample the biggest writable private regions — the GC heap.
                    // Biggest first because that is where instances are, and a
                    // partial sample of the right memory beats a complete one of
                    // the wrong memory.
                    let per_region = usize_arg(args, "window").unwrap_or(0x20000);
                    let region_cap = usize_arg(args, "regions").unwrap_or(8);
                    let mut regions = live.default_writable_regions();
                    regions.sort_by_key(|(_, size)| std::cmp::Reverse(*size));
                    let windows: Vec<(Va, usize)> = regions.into_iter().take(region_cap).map(|(base, size)| (base, size.min(per_region))).collect();
                    if windows.is_empty() {
                        return Response::error("no-regions", "the process exposes no writable regions to sample");
                    }
                    let sampled_regions = windows.len();

                    let arch = match crate::resolve_arch(args.get("arch").and_then(Value::as_str)) {
                        Ok(a) => a,
                        Err(e) => return Response::error("bad-arch", e),
                    };
                    let ctx = n0xis_core::Ctx::new(&live, arch.as_ref());
                    let input = n0xis_core::ClassScanInput {
                        windows,
                        probe: usize_arg(args, "probe").unwrap_or(0),
                        max_probe: usize_arg(args, "max_probe").unwrap_or(0),
                        limit: 0,
                        min_hits: usize_arg(args, "min_hits").unwrap_or(0),
                        // A class points to itself since Unity 2018.1; requiring
                        // that rejects almost everything on arithmetic alone,
                        // before any string read. Off for older targets.
                        require_self_pointer: args.get("any_layout").and_then(Value::as_bool) != Some(true),
                    };
                    let art = match n0xis_core::Pass::run(&n0xis_core::ClassScanPass, &ctx, input) {
                        Ok(a) => a,
                        Err(e) => return Response::error("class-scan-failed", e.to_string()),
                    };

                    let query = str_arg(args, "query").unwrap_or("").to_lowercase();
                    let requested = usize_arg(args, "limit").unwrap_or(DEFAULT_LIMIT);
                    let limit = requested.min(MAX_LIMIT);
                    let matched: Vec<&n0xis_core::ClassSummary> = if query.is_empty() {
                        art.classes.iter().collect()
                    } else {
                        art.classes
                            .iter()
                            .filter(|c| c.name.to_lowercase().contains(&query) || c.namespace.to_lowercase().contains(&query))
                            .collect()
                    };
                    let matched_count = matched.len();
                    let page: Vec<Value> = matched
                        .into_iter()
                        .take(limit)
                        .map(|c| {
                            json!({
                                "klass": c.klass.to_string(),
                                "namespace": c.namespace,
                                "name": c.name,
                                "field_count": c.field_count,
                                "hits": c.hits,
                            })
                        })
                        .collect();
                    let returned = page.len();

                    ok(
                        schema::v1::IL2CPP_CLASSES,
                        json!({
                            "sampled_regions": sampled_regions,
                            "bytes_read": art.bytes_read,
                            "candidates": art.candidates,
                            "probed": art.probed,
                            "weak_rejected": art.weak_rejected,
                            "no_self_pointer": art.no_self_pointer,
                            "found": art.count,
                            "query": query,
                            "matched": matched_count,
                            "count": returned,
                            "more": returned < matched_count,
                            "classes": page,
                        }),
                    )
                    .with_page(matched_count, returned)
                    .with_source(format!("live:{pid}"))
                    // This is a *sample*, and the difference between "these are
                    // the classes" and "these are the classes I saw in the
                    // memory I looked at" is the whole honesty of the result.
                    .with_note(format!(
                        "a sample, not an inventory: {} bytes across {sampled_regions} regions, {} of {} distinct pointers probed, {} dropped for having no back-referencing field array. Raise regions/window/max_probe to see more",
                        art.bytes_read, art.probed, art.candidates, art.weak_rejected
                    ))
                }
            }),
        ));

        reg.add(Capability::new(
            "il2cpp.obj",
            "Identify a live address: read its Il2CppClass, name the C# type, and list every field with the offset the runtime states \
             (and its current bytes). Needs no metadata parse and no external dumper — the layout is discovered and validated against \
             the FieldInfo back-reference, and a target that does not validate is refused rather than decoded into plausible nonsense.",
            Some(schema::v1::IL2CPP_OBJ),
            Origin::Builtin,
            Box::new(|args| {
                let Some(addr) = str_arg(args, "addr") else {
                    return Response::error("missing-addr", "'addr' is required: a managed object address, or an Il2CppClass address");
                };
                let addr = match Va::parse(addr) {
                    Ok(v) => v,
                    Err(e) => return Response::error("bad-addr", e.to_string()),
                };
                let spec = SourceSpec {
                    pid: args.get("pid").and_then(Value::as_u64).map(|v| v as u32),
                    file: str_arg(args, "file"),
                    ..Default::default()
                };
                if spec.pid.is_none() && spec.file.is_none() {
                    return Response::error(
                        "no-source",
                        "pass pid=<n>: the runtime type system only exists in a running process — a static image has no Il2CppClass structures at all",
                    );
                }
                let resolved = match resolve_src(spec) {
                    Ok(r) => r,
                    Err((c, m)) => return Response::error(&c, m),
                };
                let arch = match crate::resolve_arch(args.get("arch").and_then(Value::as_str)) {
                    Ok(a) => a,
                    Err(e) => return Response::error("bad-arch", e),
                };
                let ctx = n0xis_core::Ctx::new(resolved.src.as_mem(), arch.as_ref());
                let read_values = usize_arg(args, "size").unwrap_or(0x100);
                let input = n0xis_core::KlassInput { addr, read_values, probe: usize_arg(args, "probe").unwrap_or(0) };
                match n0xis_core::Pass::run(&n0xis_core::KlassPass, &ctx, input) {
                    Ok(art) => ok(schema::v1::IL2CPP_OBJ, art)
                        .with_source(resolved.label.clone())
                        // The offsets are *discovered*, so the reader is told to
                        // look at the evidence rather than take the names on
                        // faith — that is the whole safety argument here.
                        .with_note(
                            "type and field names come from the runtime's own structures; `layout` reports the offsets that were discovered and how many \
                             field entries satisfied the parent back-reference. Field offsets are from the object start, and an Il2CppObject header is 16 bytes",
                        ),
                    Err(e) => Response::error("klass-failed", e.to_string()),
                }
            }),
        ));

        reg.add(Capability::new(
            "il2cpp.icalls",
            "Recover Unity's engine internal calls from the code that resolves them: the registration name, and the .data slot \
             the resolved pointer is cached into. With a live target the slots are read, turning names into real function addresses \
             on a process that reports no symbols at all.",
            Some(schema::v1::IL2CPP_ICALLS),
            Origin::Builtin,
            Box::new(|args| {
                let module = str_arg(args, "module").map(str::to_string);
                let limit = usize_arg(args, "limit").unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
                let query = str_arg(args, "query").unwrap_or("").to_lowercase();
                let resolve = args.get("resolve").and_then(Value::as_bool).unwrap_or(true);

                let spec = SourceSpec {
                    pid: args.get("pid").and_then(Value::as_u64).map(|v| v as u32),
                    file: str_arg(args, "file"),
                    ..Default::default()
                };
                if spec.pid.is_none() && spec.file.is_none() {
                    return Response::error("no-source", "pass file=<GameAssembly.dll> or pid=<n> (with module=GameAssembly.dll)");
                }
                let resolved = match resolve_src(spec) {
                    Ok(r) => r,
                    Err((c, m)) => return Response::error(&c, m),
                };
                let src = &resolved.src;

                let code_ranges = src.code_ranges_of(module.as_deref());
                if code_ranges.is_empty() {
                    return Response::error(
                        "no-module",
                        match &module {
                            Some(name) => format!("no loaded module matches {name:?}; run `module list` to see what is loaded"),
                            None => "this target reports no executable ranges to scan".to_string(),
                        },
                    );
                }
                let Some((data_start, data_size)) = src.section_range_in(module.as_deref(), ".rdata") else {
                    return Response::error("no-rdata", "no `.rdata` section resolved; the registration names live there");
                };
                // `.data` bounds the caching store. Absent is not fatal — the
                // pass then accepts any non-code store target, which is weaker
                // and says so rather than refusing outright.
                let slots = src.section_range_in(module.as_deref(), ".data").unwrap_or((Va(0), 0));

                let arch = match crate::resolve_arch(args.get("arch").and_then(Value::as_str)) {
                    Ok(a) => a,
                    Err(e) => return Response::error("bad-arch", e),
                };
                let ctx = n0xis_core::Ctx::new(src.as_mem(), arch.as_ref());

                let mut all: Vec<n0xis_core::Icall> = Vec::new();
                let mut resolvers: Vec<n0xis_core::ResolverCount> = Vec::new();
                let mut names_in_data = 0usize;
                for (code_start, code_size) in code_ranges {
                    let input = n0xis_core::IcallInput {
                        data_start,
                        data_size: data_size as usize,
                        code_start,
                        code_size: code_size as usize,
                        slot_start: slots.0,
                        slot_size: slots.1 as usize,
                        window: 0,
                        limit: 0,
                    };
                    match n0xis_core::Pass::run(&n0xis_core::IcallPass, &ctx, input) {
                        Ok(art) => {
                            // Same data window every time, so take it once
                            // rather than multiplying it by the code windows.
                            names_in_data = names_in_data.max(art.names_in_data);
                            all.extend(art.icalls);
                            resolvers.extend(art.resolvers);
                        }
                        Err(e) => return Response::error("icalls-failed", e.to_string()),
                    }
                }

                let sites_scanned = all.len();
                // One icall is resolved from several call sites — measured: 1074
                // sites for far fewer distinct calls. Reporting each site as its
                // own row buries the answer under repeats, so rows are keyed on
                // (name, slot) and carry how many sites produced them. The raw
                // site count is still reported, because collapsing it silently
                // would make a 1074-site scan look like a 500-entry table.
                let mut order: Vec<(String, Option<u64>)> = Vec::new();
                let mut grouped: std::collections::HashMap<(String, Option<u64>), (n0xis_core::Icall, usize)> = std::collections::HashMap::new();
                for c in all {
                    let key = (c.name.clone(), c.slot.map(|v| v.0));
                    match grouped.get_mut(&key) {
                        Some((_, n)) => *n += 1,
                        None => {
                            order.push(key.clone());
                            grouped.insert(key, (c, 1));
                        }
                    }
                }
                let all: Vec<(n0xis_core::Icall, usize)> = order.into_iter().filter_map(|k| grouped.remove(&k)).collect();
                let with_slot = all.iter().filter(|(c, _)| c.slot.is_some()).count();
                let total = all.len();
                let matched: Vec<&(n0xis_core::Icall, usize)> =
                    if query.is_empty() { all.iter().collect() } else { all.iter().filter(|(c, _)| c.name.to_lowercase().contains(&query)).collect() };
                let matched_count = matched.len();

                // The live half: read each slot and report the pointer the
                // process actually resolved. A zero slot means the game has not
                // called that icall yet — reported as such, never as an address.
                let page: Vec<Value> = matched
                    .into_iter()
                    .take(limit)
                    .map(|(c, sites)| {
                        let resolved_fn = if resolve {
                            c.slot.and_then(|s| src.as_mem().read(s, 8).ok()).and_then(|b| b.get(..8).map(|w| u64::from_le_bytes(w.try_into().expect("8 bytes"))))
                        } else {
                            None
                        };
                        json!({
                            "name": c.name,
                            "name_addr": c.name_addr.to_string(),
                            "site": c.site.to_string(),
                            "slot": c.slot.map(|v| v.to_string()),
                            "resolver": c.resolver.map(|v| v.to_string()),
                            "distance_insns": c.distance_insns,
                            "sites": sites,
                            // Present and non-zero = the process resolved it.
                            "function": resolved_fn.filter(|v| *v != 0).map(|v| Va(v).to_string()),
                        })
                    })
                    .collect();
                let returned = page.len();

                // Merge across code windows before ranking: each window reports
                // its own tally, and truncating the concatenation listed the
                // same resolver twice with its site count split in half.
                let mut by_va: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
                for r in &resolvers {
                    *by_va.entry(r.va.0).or_default() += r.sites;
                }
                let mut resolvers: Vec<(u64, usize)> = by_va.into_iter().collect();
                resolvers.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                resolvers.truncate(4);

                ok(
                    schema::v1::IL2CPP_ICALLS,
                    json!({
                        "module": module,
                        "total": total,
                        "sites_scanned": sites_scanned,
                        "names_in_data": names_in_data,
                        "with_slot": with_slot,
                        "query": query,
                        "matched": matched_count,
                        "count": returned,
                        "more": returned < matched_count,
                        // Thousands of sites calling one address is the evidence
                        // the shape matched; several means it matched something
                        // else too, and the caller should look before trusting.
                        "resolvers": resolvers.iter().map(|(va, sites)| json!({ "va": Va(*va).to_string(), "sites": sites })).collect::<Vec<_>>(),
                        "icalls": page,
                    }),
                )
                .with_page(matched_count, returned)
                .with_source(resolved.label.clone())
                // Three different zeros are possible here and they mean
                // opposite things, so the note has to distinguish them.
                // Measured across three Unity builds: one had 1764 icall names
                // in `.rdata` that **nothing in the image references** — no
                // `lea`, no absolute pointer, no RVA — so the site scan
                // correctly found none. Reporting that as a bare `count: 0`
                // would read as "not an IL2CPP target".
                .with_note(if total == 0 && names_in_data > 0 {
                    format!(
                        "{names_in_data} icall names are present in the data window, but no resolution site matched. This build does not use the \
                         load-name / call-resolver / cache-slot shape, so the live-address route is unavailable here — the names are still real"
                    )
                } else if total == 0 {
                    "no icall names in the data window and no resolution sites: either not an IL2CPP image, or the wrong module/section was scanned (pass module=GameAssembly.dll on a live target)"
                        .to_string()
                } else if resolve && resolved.label.starts_with("live:") {
                    "`function` is what this process has resolved so far: an icall the game has not called yet still has a null slot, and is reported without one rather than as address 0"
                        .to_string()
                } else {
                    "static read: slots hold no pointer until the process resolves them, so `function` is absent. Re-run against a running target to fill it in"
                        .to_string()
                })
            }),
        ));

        reg.add(Capability::new(
            "il2cpp.metadata",
            "Read a Unity global-metadata.dat natively: format version, the tables its header declares, and the string \
             literals — the managed half that needs no external dumper. Pass a target image and the blob is found beside it. \
             Literals carry a metadata index, not an address: this answers 'is this text in the game', not yet 'who uses it'.",
            Some(schema::v1::IL2CPP_METADATA),
            Origin::Builtin,
            Box::new(|args| {
                // Two ways in, and the second is the one that matters in
                // practice: an agent holding `--file GameAssembly.dll` should
                // not have to know Unity's directory layout to read the blob
                // sitting next to it.
                let explicit = str_arg(args, "metadata").map(str::to_string);
                let path = match explicit {
                    Some(p) => p,
                    None => match str_arg(args, "file") {
                        Some(image) => match find_metadata_near(image) {
                            Some(p) => p,
                            None => {
                                return Response::error(
                                    "no-metadata",
                                    format!(
                                        "no global-metadata.dat found beside {image} (looked for <sibling>_Data/il2cpp_data/Metadata/) — \
                                         pass metadata=<path> explicitly, or this target is not an IL2CPP build"
                                    ),
                                );
                            }
                        },
                        None => {
                            return Response::error(
                                "no-metadata",
                                "pass metadata=<path to global-metadata.dat>, or file=<image> to find it beside the target",
                            );
                        }
                    },
                };

                let bytes = match std::fs::read(&path) {
                    Ok(b) => b,
                    Err(e) => return Response::error("read-failed", format!("read {path}: {e}")),
                };
                let file_bytes = bytes.len();
                // The parser refuses rather than half-decodes, and its errors
                // already name what did not line up — pass them through intact
                // instead of flattening them into "bad metadata".
                let meta = match metadata::parse(&bytes) {
                    Ok(m) => m,
                    Err(e) => return Response::error("bad-metadata", format!("{path}: {e}")),
                };

                let requested = usize_arg(args, "limit").unwrap_or(DEFAULT_LIMIT);
                let limit = requested.min(MAX_LIMIT);
                let offset = usize_arg(args, "offset").unwrap_or(0);
                let needle = str_arg(args, "query").unwrap_or("").to_lowercase();

                let hits: Vec<&metadata::Literal> =
                    if needle.is_empty() { meta.literals.iter().collect() } else { meta.literals.iter().filter(|l| l.value.to_lowercase().contains(&needle)).collect() };
                let matched = hits.len();
                let page: Vec<Value> =
                    hits.iter().skip(offset).take(limit).map(|l| json!({ "index": l.index, "value": l.value })).collect();
                let returned = page.len();

                let tables: Vec<Value> = meta
                    .header
                    .tables
                    .iter()
                    .map(|(name, t)| json!({ "name": name, "offset": t.offset, "size": t.size }))
                    .collect();

                // A high non-UTF-8 count is the module's own tripwire for a
                // stride that is wrong for this version. Report the ratio where
                // it is visible, not buried three fields down.
                let total_entries = meta.literals.len() + meta.literals_not_utf8;
                let suspicious = total_entries > 0 && meta.literals_not_utf8 * 10 > total_entries;

                let note = if suspicious {
                    format!(
                        "{} of {total_entries} literal entries were not valid UTF-8 — high enough to suspect the entry stride is wrong for version {}; treat these strings as unverified",
                        meta.literals_not_utf8, meta.header.version
                    )
                } else {
                    // Say what this layer cannot do yet, in the same breath as
                    // what it can. A literal index is not an address, and the
                    // obvious next move (xref it) does not work until the
                    // metadata-usage slots are read.
                    "literals carry their metadata index, not an address; mapping one to the .data slot the code loads it from is not implemented, so these are not yet xref-able".to_string()
                };

                ok(
                    schema::v1::IL2CPP_METADATA,
                    json!({
                        "metadata": path,
                        "file_bytes": file_bytes,
                        "version": meta.header.version,
                        // Only the version-independent prefix is read, and
                        // saying so stops the table list being mistaken for the
                        // whole header.
                        "tables_are": "the twenty offset/size pairs that sit at version-independent positions, through type_definitions",
                        "tables": tables,
                        "literals_total": meta.literals.len(),
                        "literals_not_utf8": meta.literals_not_utf8,
                        "query": needle,
                        "matched": matched,
                        "offset": offset,
                        "count": returned,
                        "more": offset + returned < matched,
                        "limit_clamped": (requested > limit).then_some(limit),
                        "literals": page,
                    }),
                )
                .with_page(matched, returned)
                .with_source(format!("metadata:{path}"))
                .with_note(note)
            }),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Registry;

    fn reg() -> Registry {
        let mut r = Registry::new();
        r.add_plugin(&Il2CppTools);
        r
    }

    #[test]
    fn il2cpp_tools_register() {
        let r = reg();
        for name in ["il2cpp.import", "il2cpp.symbols"] {
            assert!(r.get(name).is_some(), "{name} should be registered");
        }
    }

    #[test]
    fn missing_arguments_get_named_errors() {
        let v = serde_json::to_value(reg().dispatch("il2cpp.import", &json!({}))).unwrap();
        assert_eq!(v["error"]["code"], "missing-script-json");

        let v = serde_json::to_value(reg().dispatch("il2cpp.import", &json!({ "script_json": "x.json", "space": "elf" }))).unwrap();
        assert_eq!(v["error"]["code"], "bad-space");
    }

    #[test]
    fn an_index_name_that_could_escape_the_project_is_refused() {
        for bad in ["../evil", "sub/dir", "C:evil"] {
            let v = serde_json::to_value(reg().dispatch("il2cpp.symbols", &json!({ "name": bad }))).unwrap();
            assert_eq!(v["error"]["code"], "bad-name", "{bad} should be refused");
        }
    }
}
