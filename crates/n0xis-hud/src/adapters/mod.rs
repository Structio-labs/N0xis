//! Generic plugin dispatch for `[[adapters]]` bindings
//! (`docs/COMMUNITY_ROADMAP.md`'s "Plugin system"). `n0xis-hud` itself never
//! compiles in game-specific logic: a binding's `command` spawns a
//! persistent `n0xis_sources::PluginSession` (owned by [`crate::engine::Engine`],
//! one per binding name, lazily spawned on first use — see
//! `Engine::ensure_plugin_session`), and `on_launch`/`toggle_on`/`toggle_off`
//! become JSON ops on that session instead of an in-binary Rust match. This
//! mirrors `--remote-cmd`'s exact shape (argv spawned, JSON over stdio) —
//! the same transport `n0xis-pipeline::PluginHost` uses for analysis plugins,
//! just a different, persistent-session lifecycle (see
//! `n0xis_sources::plugin`'s module doc for why the two differ).

use n0xis_contracts::Va;
use n0xis_project::patch::PatchRecord;
use n0xis_sources::PluginSession;
use serde_json::json;

/// Parse a plugin's JSON response into the `Result<PatchRecord, String>`
/// contract every caller already expects: `{"ok":true,"record":{...}}` (a
/// `PatchRecord`, same shape `n0xis_project::patch` produces) or
/// `{"ok":false,"error":"..."}`.
fn parse_patch_response(resp: serde_json::Value) -> Result<PatchRecord, String> {
    if resp["ok"].as_bool() != Some(true) {
        return Err(resp["error"].as_str().unwrap_or("plugin op failed").to_string());
    }
    serde_json::from_value(resp["record"].clone()).map_err(|e| format!("bad plugin response: {e}"))
}

/// `{"op":"on_launch","pid":<pid>}` — the plugin's own auto-detect/apply path
/// (e.g. scanning for a signature and patching it), run when a target first
/// attaches and no known address is recorded yet.
pub fn on_launch(session: &PluginSession, pid: u32) -> Result<PatchRecord, String> {
    let resp = session.call(&json!({ "op": "on_launch", "pid": pid }))?;
    parse_patch_response(resp)
}

/// `{"op":"toggle_on","pid":<pid>,"known_addr":"0x..."}` — re-apply at an
/// address already recorded from a prior `on_launch`/`toggle_on` (no rescan).
pub fn toggle_on(session: &PluginSession, known_addr: Va, pid: u32) -> Result<PatchRecord, String> {
    let resp = session.call(&json!({ "op": "toggle_on", "pid": pid, "known_addr": known_addr.to_string() }))?;
    parse_patch_response(resp)
}

/// `{"op":"toggle_off","pid":<pid>,"record":{...}}` — undo a previously
/// applied patch. On success, `rec.status` is updated to `"undone"` in place
/// (the caller keeps the record around so a later `toggle_on` is fast).
pub fn toggle_off(session: &PluginSession, rec: &mut PatchRecord, pid: u32) -> Result<(), String> {
    let record_json = serde_json::to_value(&*rec).map_err(|e| e.to_string())?;
    let resp = session.call(&json!({ "op": "toggle_off", "pid": pid, "record": record_json }))?;
    if resp["ok"].as_bool() == Some(true) {
        rec.status = "undone".to_string();
        Ok(())
    } else {
        Err(resp["error"].as_str().unwrap_or("plugin toggle_off failed").to_string())
    }
}

/// `{"op":"poll","pid":<pid>}` — a periodic background tick for a binding
/// that declared `poll_ms` (see [`crate::plugin_poll`]). The plugin owns
/// whatever state it needs between polls (it's a persistent session, not
/// respawned) and returns an optional human-readable status line to surface
/// in the HUD's footer log — nothing else; the host never interprets
/// plugin-internal state.
pub fn poll(session: &PluginSession, pid: u32) -> Result<Option<String>, String> {
    let resp = session.call(&json!({ "op": "poll", "pid": pid }))?;
    if resp["ok"].as_bool() != Some(true) {
        return Err(resp["error"].as_str().unwrap_or("plugin poll failed").to_string());
    }
    Ok(resp["note"].as_str().map(|s| s.to_string()))
}
