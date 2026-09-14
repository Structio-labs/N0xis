// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The `doctor` environment/readiness report, in one place.
//!
//! Both front doors ask the same question — "is this build ready, and what can
//! it decode?" — and must give the same answer. They did not: the MCP door
//! carried a hand-written copy that reported one decoder engine (x64 only) and
//! omitted the arm64 check and the `roadmap` field the CLI emits, so an agent
//! got a less-capable answer than a human at the CLI. This is the single
//! builder both doors now call, so the report cannot drift again.
//!
//! It reports *capabilities* (both decoders, both arches) rather than a phase
//! list on purpose — same reasoning as `guide`, which is generated from the
//! clap tree rather than hand-maintained: a status baked into a binary drifts
//! from the document that owns it (ROADMAP.md).

use n0xis_arch::{Arch, Arm64, X64};
use serde_json::{Value, json};

/// The canonical `n0xis.doctor.v1` data payload. Callers wrap it in
/// `Response::success(schema::v1::DOCTOR, ...)` and emit it their own way.
pub fn payload() -> Value {
    let x64 = X64::new();
    let arm64 = Arm64::new();
    let project = n0xis_project::resolve();
    let (proj_ok, proj_dir, proj_local) = match &project {
        Ok(p) => (true, p.dir.display().to_string(), p.is_local),
        Err(_) => (false, String::new(), false),
    };
    json!({
        "status": "ready",
        "checks": {
            "arch_x64": { "ok": true, "name": x64.name() },
            "arch_arm64": { "ok": true, "name": arm64.name() },
            "decoder": { "ok": true, "engines": ["iced-x86 (x64)", "disarm64 (arm64)"] },
            "project_resolves": { "ok": proj_ok, "dir": proj_dir, "local": proj_local },
        },
        // Deliberately not a phase list. The previous value ("Phases 1-7
        // complete") was stale the moment Phase 8 landed and stayed stale for
        // four more phases, because a status baked into a binary drifts from
        // the document that owns it. Same reasoning as `guide`, which is
        // generated from the clap tree rather than hand-maintained.
        "roadmap": "ROADMAP.md is the authority on phase status; this build reports its own capabilities via `guide` and `capability list`",
    })
}
