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
use n0xis_core::{CfgArtifact, CfgInput, CfgPass, Ctx, CoreError, DecodeInput, DecodeOutput, DecodePass, Pass};
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
    format!("cfg-{:016x}", h.finish())
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
    let key = cfg_cache_key(&ctx.source.label(), input, &probe);

    if let Ok(Some(json)) = n0xis_project::ir_cache::get(&key) {
        if let Ok(art) = serde_json::from_str::<CfgArtifact>(&json) {
            return Ok((art, true));
        }
    }
    let art = CfgPass.run(ctx, input)?;
    if let Ok(json) = serde_json::to_string(&art) {
        let _ = n0xis_project::ir_cache::put(&key, &json);
    }
    Ok((art, false))
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
