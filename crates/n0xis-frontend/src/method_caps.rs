//! Method-tooling capabilities: target inventory (`process.ps`,
//! `module.list`) and the Phase 8 evidence tools (`sig.validate`).
//!
//! These are the commands an agent reaches for *before* it knows what it is
//! looking at, which is exactly why they belong in the registry — an agent
//! that can only decompile but cannot list processes is stuck at step zero.

use n0xis_contracts::{Response, Va, schema};
use serde_json::{Value, json};

use crate::registry::{Capability, Origin, Plugin, Registry};
use crate::source::{SourceSpec, resolve};

fn ok<T: serde::Serialize>(schema_id: &str, data: T) -> Response<Value> {
    match serde_json::to_value(data) {
        Ok(v) => Response::success(schema_id, v),
        Err(e) => Response::error("serialize", e.to_string()),
    }
}

/// Target inventory and evidence tooling.
pub struct MethodTools;

impl Plugin for MethodTools {
    fn name(&self) -> &str {
        "n0xis.method-tools"
    }

    fn register(&self, reg: &mut Registry) {
        reg.add(Capability::new(
            "process.ps",
            "Running processes (pid + name), optionally filtered by a `filter` substring.",
            Some(schema::v1::PROCESS_PS),
            Origin::Builtin,
            Box::new(|args| {
                let filter = args.get("filter").and_then(|v| v.as_str()).map(str::to_lowercase);
                match crate::source::list_processes() {
                    Ok(mut procs) => {
                        if let Some(needle) = filter {
                            procs.retain(|p| p.name.to_lowercase().contains(&needle));
                        }
                        procs.sort_by_key(|p| p.name.to_lowercase());
                        let list: Vec<Value> = procs.iter().map(|p| json!({ "pid": p.pid, "name": p.name })).collect();
                        ok(schema::v1::PROCESS_PS, json!({ "count": list.len(), "processes": list }))
                    }
                    Err((c, m)) => Response::error(&c, m),
                }
            }),
        ));

        reg.add(Capability::new(
            "module.list",
            "Loaded modules of a live process, or a static PE's module table.",
            Some(schema::v1::MODULE_LIST),
            Origin::Builtin,
            Box::new(|args| {
                let spec = SourceSpec {
                    pid: args.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32),
                    file: args.get("file").and_then(|v| v.as_str()),
                    snapshot: args.get("snapshot").and_then(|v| v.as_str()),
                    remote_cmd: args.get("remote_cmd").and_then(|v| v.as_str()),
                    ..Default::default()
                };
                let resolved = match resolve(spec) {
                    Ok(r) => r,
                    Err((c, m)) => return Response::error(&c, m),
                };
                let mut modules = resolved.src.modules();
                if let Some(f) = args.get("filter").and_then(|v| v.as_str()) {
                    let needle = f.to_lowercase();
                    modules.retain(|m| m.name.to_lowercase().contains(&needle));
                }
                ok(schema::v1::MODULE_LIST, json!({ "count": modules.len(), "modules": modules }))
            }),
        ));

        reg.add(Capability::new(
            "sig.validate",
            "Score a byte signature against independent samples: which offsets actually vary, and whether the evidence supports the mask.",
            Some(schema::v1::SIG_VALIDATE),
            Origin::Builtin,
            Box::new(|args| {
                let mut samples: Vec<Vec<u8>> = Vec::new();

                // Inline hex samples.
                if let Some(list) = args.get("samples").and_then(|v| v.as_array()) {
                    for s in list.iter().filter_map(|v| v.as_str()) {
                        match n0xis_core::parse_sample(s) {
                            Ok(b) => samples.push(b),
                            Err(e) => return Response::error("bad-sample", e),
                        }
                    }
                }
                // Samples read from files on disk.
                if let Some(list) = args.get("sample_files").and_then(|v| v.as_array()) {
                    for f in list.iter().filter_map(|v| v.as_str()) {
                        match std::fs::read(f) {
                            Ok(b) => samples.push(b),
                            Err(e) => return Response::error("read-failed", format!("read {f}: {e}")),
                        }
                    }
                }
                // Samples read from a live/static source at given addresses.
                // An *empty* `ats` is not a request to read anything — the CLI
                // always sends the array, so only a non-empty one needs `len`.
                if let Some(list) = args.get("ats").and_then(|v| v.as_array()).filter(|l| !l.is_empty()) {
                    let Some(len) = args.get("len").and_then(|v| v.as_u64()).map(|v| v as usize) else {
                        return Response::error("missing-len", "'ats' needs 'len' (bytes to read at each address)");
                    };
                    for at in list.iter().filter_map(|v| v.as_str()) {
                        let addr = match Va::parse(at) {
                            Ok(v) => v,
                            Err(e) => return Response::error("bad-addr", e.to_string()),
                        };
                        let spec = SourceSpec {
                            pid: args.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32),
                            file: args.get("file").and_then(|v| v.as_str()),
                            bytes_base: Some(addr),
                            ..Default::default()
                        };
                        let resolved = match resolve(spec) {
                            Ok(r) => r,
                            Err((c, m)) => return Response::error(&c, m),
                        };
                        match resolved.src.as_mem().read(addr, len) {
                            Ok(b) => samples.push(b),
                            Err(e) => return Response::error("read-failed", format!("read {addr}: {e}")),
                        }
                    }
                }

                if samples.is_empty() {
                    return Response::error("no-samples", "provide samples via 'samples', 'sample_files', or 'ats' (with pid/file and len)");
                }

                let proposed = match args.get("signature").and_then(|v| v.as_str()) {
                    Some(sig) => match n0xis_core::parse_mask(sig) {
                        Ok(m) => Some(m),
                        Err(e) => return Response::error("bad-signature", e),
                    },
                    None => None,
                };
                let varied_axes: Vec<String> = args
                    .get("varied")
                    .and_then(|v| v.as_str())
                    .map(|s| s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect())
                    .unwrap_or_default();
                let min_independent = args
                    .get("min_independent")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(n0xis_core::MIN_INDEPENDENT_SAMPLES);

                let input = n0xis_core::SigValidateInput { samples, proposed, varied_axes, min_independent };
                ok(schema::v1::SIG_VALIDATE, n0xis_core::sig_validate(&input))
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
        r.add_plugin(&MethodTools);
        r
    }

    #[test]
    fn method_tools_register() {
        let r = reg();
        for name in ["process.ps", "module.list", "sig.validate"] {
            assert!(r.get(name).is_some(), "{name} should be registered");
        }
    }

    #[test]
    fn sig_validate_scores_two_identical_samples() {
        let v = serde_json::to_value(reg().dispatch(
            "sig.validate",
            &json!({ "samples": ["48 89 c8 c3", "48 89 c8 c3"], "min_independent": 2 }),
        ))
        .unwrap();
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["data"]["sample_count"], 2);
        // Nothing varies across identical samples, so the derived signature is
        // fully fixed — and the pass still refuses to bless it, because two
        // identical samples are not evidence of independence.
        assert_eq!(v["data"]["varying_bytes"], 0);
        assert_eq!(v["data"]["blessed"], false);
    }

    #[test]
    fn sig_validate_without_samples_says_so() {
        let v = serde_json::to_value(reg().dispatch("sig.validate", &json!({}))).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], "no-samples");
    }
}
