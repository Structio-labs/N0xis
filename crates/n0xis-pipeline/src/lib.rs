// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! # n0xis-pipeline — wiring the core to concrete inputs
//!
//! Binds a [`MemorySource`](n0xis_sources::MemorySource) and an
//! [`Arch`](n0xis_arch::Arch) into a [`Ctx`](n0xis_core::Ctx) and runs
//! [`Pass`](n0xis_core::Pass)es over it. This is the single place the frontends
//! (`n0xis-cli`, `n0xis-mcp`) call into — they never touch analysis internals,
//! only this façade and the contracts.
//!
//! Phase 1 is deliberately thin: run a pass, get its artifact. **Phase 6**
//! adds [`cfg_cached`] — content-addressed artifact caching so a repeated
//! `ir build`/`decomp pseudo` call over unchanged bytes doesn't re-run
//! decode→CFG→def-use from scratch; see its docs for the invalidation story.

pub use n0xis_arch as arch;
pub use n0xis_contracts as contracts;
pub use n0xis_core as core;
pub use n0xis_project as project;
pub use n0xis_sources as sources;

use std::hash::{Hash, Hasher};

use n0xis_arch::Arch;
use n0xis_contracts::Va;
use n0xis_core::{CfgArtifact, CfgInput, CfgPass, Ctx, CoreError, DecodeInput, DecodeOutput, DecodePass, DecompInput, DecompPass, DecompStyle, Pass};
use n0xis_sources::MemorySource;

/// A ready-to-run analysis context over one source + arch.
pub struct Pipeline<'a> {
    ctx: Ctx<'a>,
}

impl<'a> Pipeline<'a> {
    pub fn new(source: &'a dyn MemorySource, arch: &'a dyn Arch) -> Self {
        Pipeline {
            ctx: Ctx::new(source, arch),
        }
    }

    /// Build from a pre-configured context (e.g. one carrying symbols/modules).
    pub fn from_ctx(ctx: Ctx<'a>) -> Self {
        Pipeline { ctx }
    }

    /// The source's provenance label, for `meta.source`.
    pub fn source_label(&self) -> String {
        self.ctx.source.label()
    }

    /// Run any pass against this pipeline's context.
    pub fn run<P: Pass>(&self, pass: &P, input: P::In) -> Result<P::Out, CoreError> {
        pass.run(&self.ctx, input)
    }

    /// Convenience: linear disassembly of ~`count` instructions from `start`.
    pub fn disassemble(&self, start: Va, count: usize) -> Result<DecodeOutput, CoreError> {
        self.run(&DecodePass, DecodeInput::count(start, count))
    }
}

/// Content-addressed key: a hash of everything that determines `CfgPass`'s
/// output — the source's provenance label (two sources can have identical
/// bytes at the same address but resolve call-target names differently, e.g.
/// a live process vs. a static file), the input, and **the actual bytes**
/// `CfgPass` would decode, read once up front so the key is bytes-derived
/// rather than address-derived. That last part is what makes the cache safe
/// to use against a live process: if the target's code changed since the
/// last call (self-modifying code, a hot-patched function, a redeployed
/// DLL...), the hash changes and the cache misses — it never hands back an
/// artifact for bytes that aren't there anymore.
fn cfg_cache_key(source_label: &str, input: CfgInput, probe: &[u8]) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    "cfg".hash(&mut h);
    source_label.hash(&mut h);
    input.start.0.hash(&mut h);
    input.max_bytes.hash(&mut h);
    input.auto_end.hash(&mut h);
    probe.hash(&mut h);
    format!("{}{:016x}", cfg_cache_generation(), h.finish())
}

/// Key prefix shared by every entry this build may read: `cfg-<fingerprint>-`.
/// Carried *in the key* rather than mixed into the hash so the store can sweep
/// other generations by name (see [`n0xis_project::ir_cache::retain_prefix`]) —
/// a content-addressed cache has no expiry of its own, and a per-build
/// fingerprint without a sweep would just pile up unreachable generations.
fn cfg_cache_generation() -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    analysis_fingerprint().hash(&mut h);
    format!("cfg-{:08x}-", h.finish() as u32)
}

/// Identity of the **analyzer**, not the target — the other half of a sound
/// cache key. Identical bytes analyzed by a *different build* can legitimately
/// produce a different `CfgArtifact` (a new terminator class, a tail call the
/// old build called an indirect branch, a noreturn callee it didn't know), so
/// a key made only of target facts hands back pre-upgrade artifacts forever.
/// That is exactly the stale-data failure CONCEPT §3 rule 6 forbids, and it
/// bites hardest during development, where the analysis changes hourly.
///
/// The fingerprint is the crate version plus the running executable's own
/// mtime: stable for a released binary (so the cache still works across runs),
/// and automatically different after every rebuild (so a changed pass can
/// never be masked by its own cache). Best-effort — if the exe can't be
/// stat'ed, the version alone still separates releases.
fn analysis_fingerprint() -> String {
    let build = std::env::current_exe()
        .and_then(|p| p.metadata())
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{}+{build}", env!("CARGO_PKG_VERSION"))
}

/// Drop cache entries left by *other* builds — once per process, on the first
/// cached run. Best-effort: a failed sweep (no project, read-only dir, a file
/// held open) is not a reason to fail an analysis.
fn sweep_stale_generations_once() {
    static SWEPT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    SWEPT.get_or_init(|| {
        let _ = n0xis_project::ir_cache::retain_prefix(&cfg_cache_generation());
    });
}

/// Run [`CfgPass`] through the disk-backed `.n0x/ir-cache/` cache (ROADMAP
/// Phase 6). Returns `(artifact, true)` on a cache hit, `(artifact, false)`
/// on a miss (freshly computed and stored). A cache-read/parse failure is
/// always treated as a miss — the cache is a fast path only, never a
/// correctness dependency (CONCEPT §3 rule 6: never silently give stale
/// data). Requires a resolvable `.n0x/` project; falls back to an uncached
/// run when none exists (e.g. an inline `--bytes` one-off with no project).
pub fn cfg_cached(ctx: &Ctx, input: CfgInput) -> Result<(CfgArtifact, bool), CoreError> {
    let probe = ctx.source.read(input.start, input.max_bytes).unwrap_or_default();
    // The symbol provider is part of the key, not just the bytes: a CFG
    // artifact embeds *resolved* call names, so keying on bytes alone made an
    // imported IL2CPP index invisible on every function already analyzed
    // (measured — the fix needed deleting `.n0x/ir-cache/` by hand). Providers
    // whose names derive from the same bytes return an empty fingerprint, so
    // this leaves existing keys untouched.
    let fingerprint = ctx.symbols.map(|s| s.symbol_fingerprint()).unwrap_or_default();
    let scope = if fingerprint.is_empty() { ctx.source.label() } else { format!("{}|{fingerprint}", ctx.source.label()) };
    let key = cfg_cache_key(&scope, input, &probe);
    sweep_stale_generations_once();

    if let Ok(Some(json)) = n0xis_project::ir_cache::get(&key)
        && let Ok(art) = serde_json::from_str::<CfgArtifact>(&json)
    {
        return Ok((art, true));
    }
    let art = CfgPass.run(ctx, input)?;
    if let Ok(json) = serde_json::to_string(&art) {
        let _ = n0xis_project::ir_cache::put(&key, &json);
    }
    Ok((art, false))
}

/// Key prefix shared by every decomp-cache entry this build may read. Its own
/// generation (separate directory, separate sweep) so upgrading the renderer
/// invalidates decomp results without touching the CFG cache and vice-versa.
fn decomp_cache_generation() -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    analysis_fingerprint().hash(&mut h);
    format!("decomp-{:08x}-", h.finish() as u32)
}

fn sweep_stale_decomp_once() {
    static SWEPT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    SWEPT.get_or_init(|| {
        let _ = n0xis_project::decomp_cache::retain_prefix(&decomp_cache_generation());
    });
}

/// The cache key for a decompiled function: the same content basis as
/// [`cfg_cache_key`] (source scope incl. symbol fingerprint, input, the actual
/// probed bytes) plus the render `style` and the user variable renames — the
/// three things beyond the CFG that change the pseudo-C. Renames are folded in
/// directly (not only via the symbol fingerprint) so the key is correct even for
/// a source that carries no fingerprint.
fn hash_map_sorted(h: &mut std::collections::hash_map::DefaultHasher, map: &std::collections::HashMap<String, String>) {
    let mut pairs: Vec<(&String, &String)> = map.iter().collect();
    pairs.sort();
    for (k, v) in pairs {
        k.hash(h);
        v.hash(h);
    }
}

fn decomp_cache_key(
    scope: &str,
    input: CfgInput,
    probe: &[u8],
    style: DecompStyle,
    var_names: &std::collections::HashMap<String, String>,
    var_types: &std::collections::HashMap<String, String>,
    struct_defs: &std::collections::HashMap<String, std::collections::BTreeMap<i64, String>>,
) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    "decomp".hash(&mut h);
    scope.hash(&mut h);
    input.start.0.hash(&mut h);
    input.max_bytes.hash(&mut h);
    input.auto_end.hash(&mut h);
    probe.hash(&mut h);
    let style_tag: u8 = match style {
        DecompStyle::Goto => 0,
        DecompStyle::Structured => 1,
        DecompStyle::Ssa => 2,
    };
    style_tag.hash(&mut h);
    hash_map_sorted(&mut h, var_names);
    "types".hash(&mut h); // separator so {a:b}+{} differs from {}+{a:b}
    hash_map_sorted(&mut h, var_types);
    "structs".hash(&mut h);
    let mut sd: Vec<(&String, &std::collections::BTreeMap<i64, String>)> = struct_defs.iter().collect();
    sd.sort_by(|a, b| a.0.cmp(b.0));
    for (name, fields) in sd {
        name.hash(&mut h);
        for (off, fname) in fields {
            off.hash(&mut h);
            fname.hash(&mut h);
        }
    }
    format!("{}{:016x}", decomp_cache_generation(), h.finish())
}

/// Decompile the function at `input.start` through the disk-backed
/// `.n0x/decomp-cache/` — the display-shaped result (`explain=false`,
/// `strip_block_labels=true`), returned as its JSON envelope-`data`. `(v, true)`
/// on a cache hit, `(v, false)` on a miss (built via [`cfg_cached`] +
/// [`DecompPass`], stored). Returns the artifact as a [`serde_json::Value`]
/// because [`PseudoFunction`] holds `&'static str` fields it cannot deserialize
/// into — and the caller only needs to read/adjust the JSON (e.g. prepend a
/// comment header) before emitting it. Read/parse failure is a miss, never stale;
/// no project → an uncached run. The `explain=true` delta path is intentionally
/// not cached (rare, and its payload dwarfs the pseudo-C) — call the pass directly.
pub fn decomp_cached(
    ctx: &Ctx,
    input: CfgInput,
    style: DecompStyle,
    var_names: &std::collections::HashMap<String, String>,
    var_types: &std::collections::HashMap<String, String>,
    struct_defs: &std::collections::HashMap<String, std::collections::BTreeMap<i64, String>>,
) -> Result<(serde_json::Value, bool), CoreError> {
    let probe = ctx.source.read(input.start, input.max_bytes).unwrap_or_default();
    let fingerprint = ctx.symbols.map(|s| s.symbol_fingerprint()).unwrap_or_default();
    let scope = if fingerprint.is_empty() { ctx.source.label() } else { format!("{}|{fingerprint}", ctx.source.label()) };
    let key = decomp_cache_key(&scope, input, &probe, style, var_names, var_types, struct_defs);
    sweep_stale_decomp_once();

    if let Ok(Some(json)) = n0xis_project::decomp_cache::get(&key)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&json)
    {
        return Ok((v, true));
    }
    let (cfg, _) = cfg_cached(ctx, input)?;
    let pf = DecompPass.run(ctx, DecompInput { cfg, style, explain: false, strip_block_labels: true, var_names: var_names.clone(), var_types: var_types.clone(), struct_defs: struct_defs.clone() })?;
    let json = serde_json::to_string(&pf).map_err(|e| CoreError::Other(e.to_string()))?;
    let _ = n0xis_project::decomp_cache::put(&key, &json);
    let v = serde_json::from_str(&json).map_err(|e| CoreError::Other(e.to_string()))?;
    Ok((v, false))
}

/// Generation prefix for the reverse-xref index — the analyzer fingerprint, so a
/// rebuilt decoder never reads a previous build's index (same discipline as
/// [`cfg_cache_generation`]). Carried in the key so [`retain_prefix`] can sweep
/// stale generations by name.
fn xref_cache_generation() -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    analysis_fingerprint().hash(&mut h);
    format!("xref-{:08x}-", h.finish() as u32)
}

fn sweep_stale_xref_once() {
    static SWEPT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    SWEPT.get_or_init(|| {
        let _ = n0xis_project::xref_index::retain_prefix(&xref_cache_generation());
    });
}

/// Process-wide memo of the last built/loaded index: `(source label, key, index)`.
/// Reused only when the label matches — the frontend calls [`xref_index_for`]
/// exclusively for *immutable* sources (static PE/ELF, snapshot), so a label
/// uniquely identifies a fixed byte image for the life of the process and we can
/// skip re-hashing the whole code section on every query.
static XREF_MEMO: std::sync::Mutex<Option<(String, String, std::sync::Arc<n0xis_core::XrefIndex>)>> =
    std::sync::Mutex::new(None);

/// The reverse-xref index over `ranges`, memoized in-process and cached on disk
/// under `.n0x/xref-index/`. The first call for a target builds it (one decode
/// pass over all code — the cost `xref to` used to pay *every* time); every later
/// call this session, and future sessions on unchanged bytes, is a map lookup.
///
/// Soundness follows the IR cache: the disk key hashes the analyzer generation
/// **and the actual code bytes**, so changed bytes miss (never a stale hit). The
/// caller must only pass *immutable* sources — the in-process memo keys on the
/// source label alone, which is a fixed image only when the bytes cannot change
/// under it (static/snapshot, not a live process).
pub fn xref_index_for(ctx: &Ctx, ranges: &[(Va, u64)], label: &str) -> std::sync::Arc<n0xis_core::XrefIndex> {
    if let Ok(memo) = XREF_MEMO.lock()
        && let Some((l, _k, idx)) = memo.as_ref()
        && l == label
    {
        return idx.clone();
    }
    // Sound key: analyzer generation + label + range shape + a hash of the actual
    // code bytes (read once). Hashing the section is far cheaper than the decode
    // pass a scan would do, and it's paid at most once per session (memo above).
    let mut h = std::collections::hash_map::DefaultHasher::new();
    "xref".hash(&mut h);
    label.hash(&mut h);
    for (start, size) in ranges {
        start.0.hash(&mut h);
        size.hash(&mut h);
        if let Ok(bytes) = ctx.source.read(*start, *size as usize) {
            bytes.hash(&mut h);
        }
    }
    let key = format!("{}{:016x}", xref_cache_generation(), h.finish());
    sweep_stale_xref_once();

    let idx = if let Ok(Some(json)) = n0xis_project::xref_index::get(&key)
        && let Ok(idx) = serde_json::from_str::<n0xis_core::XrefIndex>(&json)
    {
        idx
    } else {
        let built = n0xis_core::build_xref_index(ctx, ranges);
        if let Ok(json) = serde_json::to_string(&built) {
            let _ = n0xis_project::xref_index::put(&key, &json);
        }
        built
    };
    let arc = std::sync::Arc::new(idx);
    if let Ok(mut memo) = XREF_MEMO.lock() {
        *memo = Some((label.to_string(), key, arc.clone()));
    }
    arc
}

/// One registered plugin's response to an artifact, or why it didn't produce
/// one. Fail-open-but-visible (`docs/COMMUNITY_ROADMAP.md`'s "Plugin
/// system"): a crashing or timed-out plugin never blocks the underlying
/// analysis — it just shows up here with `error` set instead of `findings`.
#[derive(Debug, serde::Serialize)]
pub struct PluginFinding {
    pub plugin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// How long any single plugin gets before it's treated as wedged and killed.
const PLUGIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Run every plugin registered (in `.n0x/plugins.json`) for `kind`
/// (`"cfg"`/`"pseudo"`/`"discover"`) against `artifact`. Never returns `Err`
/// itself: an unresolvable project, an unreadable registry, a bad `command`
/// string, or an individual plugin crashing/timing out all degrade to an
/// entry with `error` set, never a failure of the pass that already ran.
/// Callers (CLI/MCP) layer the result under a `plugins` key, additive to the
/// existing response schema — never authoritative over the core artifact
/// (CONCEPT §3 rule 6).
pub fn run_plugins_for<T: serde::Serialize>(kind: &str, artifact: &T) -> Vec<PluginFinding> {
    let Ok(plugins) = n0xis_project::plugins::for_kind(kind) else {
        return Vec::new();
    };
    let Ok(artifact_json) = serde_json::to_value(artifact) else {
        return Vec::new();
    };
    let request = serde_json::json!({ "kind": kind, "artifact": artifact_json });

    plugins
        .into_iter()
        .map(|p| match n0xis_sources::split_command_line(&p.command) {
            Ok(argv) => match n0xis_sources::plugin_call_once(&argv, &request, PLUGIN_TIMEOUT) {
                Ok(resp) => PluginFinding { plugin: p.name, findings: Some(resp), error: None },
                Err(e) => PluginFinding { plugin: p.name, findings: None, error: Some(e) },
            },
            Err(e) => PluginFinding { plugin: p.name, findings: None, error: Some(e) },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;
    use std::sync::Mutex;

    // Serializes every test in THIS file that changes cwd (n0xis_project's
    // resolve() walks up from the process cwd) — a sibling lock to
    // n0xis-project's own CWD_TEST_LOCK, needed here too since cargo runs a
    // crate's tests as one multi-threaded binary.
    static CWD_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn in_temp_project<T>(f: impl FnOnce() -> T) -> T {
        let _guard = CWD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "n0xis-pluginhost-test-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(tmp.join(".n0x")).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&tmp).unwrap();
        let result = f();
        std::env::set_current_dir(prev).unwrap();
        std::fs::remove_dir_all(&tmp).ok();
        result
    }

    #[test]
    fn no_registered_plugins_yields_an_empty_vec_not_an_error() {
        in_temp_project(|| {
            let findings = run_plugins_for("cfg", &serde_json::json!({"blocks": []}));
            assert!(findings.is_empty());
        });
    }

    #[test]
    fn a_real_plugin_process_returns_findings_under_the_registered_kind_only() {
        let Ok(_) = std::process::Command::new("python3").arg("--version").output() else {
            eprintln!("skipping: no python3 on PATH");
            return;
        };
        in_temp_project(|| {
            let script = "import sys,json; req=json.loads(sys.stdin.readline()); \
                           print(json.dumps({'saw_kind': req['kind']}))";
            let command = format!("python3 -c \"{}\"", script.replace('"', "\\\""));
            n0xis_project::plugins::add("echo-plugin", &command, vec!["cfg".to_string()]).unwrap();

            let cfg_findings = run_plugins_for("cfg", &serde_json::json!({"blocks": []}));
            assert_eq!(cfg_findings.len(), 1);
            assert_eq!(cfg_findings[0].plugin, "echo-plugin");
            assert_eq!(cfg_findings[0].findings.as_ref().unwrap()["saw_kind"], "cfg");

            // Not registered for "pseudo" — must not fire.
            let pseudo_findings = run_plugins_for("pseudo", &serde_json::json!({}));
            assert!(pseudo_findings.is_empty());
        });
    }

    #[test]
    fn a_nonexistent_plugin_binary_is_reported_as_an_error_finding_not_a_panic() {
        in_temp_project(|| {
            n0xis_project::plugins::add(
                "broken",
                "n0xis-this-binary-does-not-exist",
                vec!["cfg".to_string()],
            )
            .unwrap();
            let findings = run_plugins_for("cfg", &serde_json::json!({}));
            assert_eq!(findings.len(), 1);
            assert!(findings[0].findings.is_none());
            assert!(findings[0].error.is_some());
        });
    }

    #[test]
    fn pipeline_disassembles_through_the_facade() {
        let snap = Snapshot::builder()
            .region(Va(0x1000), vec![0x90u8, 0x90, 0xC3]) // nop; nop; ret
            .label("snapshot:pipe")
            .build();
        let arch = X64::new();
        let pipe = Pipeline::new(&snap, &arch);
        let out = pipe.disassemble(Va(0x1000), 8).unwrap();
        assert_eq!(out.count, 3);
        assert_eq!(pipe.source_label(), "snapshot:pipe");
    }
}
