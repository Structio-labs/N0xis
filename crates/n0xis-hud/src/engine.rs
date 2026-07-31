//! The shared cheat state + toggle logic, behind one `Arc<Mutex<Engine>>` so
//! the UI thread, the global-hotkey hook thread, and the process watcher all
//! act on the same source of truth. Putting the logic here (not in the egui
//! `App`) is what lets an in-game hotkey toggle a cheat even while the N0xHUD
//! window is hidden — the hook thread mutates the engine directly, no UI tick
//! required.

use std::collections::HashMap;
use std::path::PathBuf;

use n0xis_contracts::{Table, TableEntry, Va};
use n0xis_project::patch::PatchRecord;
use serde::{Deserialize, Serialize};

use crate::adapters;
use crate::config::{AdapterBinding, HudConfig};
use crate::freeze::FreezeWorker;
use crate::{input, sequence, sound};

pub type EntryKey = (String, String); // (table name, entry name)

/// How many recent status lines to keep for the footer log.
/// Lines kept in the footer log. Generous because the log is the only record of
/// what the background solver did: at the old value of 6 a single combo solve
/// scrolled its own detection line out of existence before it could be read.
/// The footer scrolls, so a large buffer costs nothing but memory.
const LOG_CAPACITY: usize = 500;

/// Per-combo user overrides, persisted to `.n0x/sequences.json` so the shipped
/// combo definitions in `hud.toml` stay untouched.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeqOverride {
    /// `Some(key)` bound, `None` explicitly unbound (distinct from "no
    /// override" — a missing map entry falls back to the config's hotkey).
    #[serde(default)]
    pub hotkey: Option<String>,
    #[serde(default)]
    pub delay_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SeqState {
    #[serde(default)]
    combos: HashMap<String, SeqOverride>,
}

/// Runtime speed override for stratagem macros, persisted to
/// `.n0x/stratagem_speed.json` — independent of the combo-solver's timing
/// (see `StratagemSpeedConfig`'s doc comment).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StratagemSpeedOverride {
    #[serde(default)]
    pub hold_ms: Option<u64>,
    #[serde(default)]
    pub gap_ms: Option<u64>,
}

/// What currently owns a hotkey — for conflict messages during rebind.
pub enum HotkeyOwner {
    Window,
    Cheat(String),
    Sequence(String),
    Stratagem(String),
}

pub struct Engine {
    config: HudConfig,
    /// Pinned `.n0x` dir — table load/save never go through the ambient cwd
    /// (eframe/GL init can change it at startup).
    project_dir: PathBuf,
    tables: Vec<Table>,
    pid: Option<u32>,
    freeze_workers: HashMap<EntryKey, FreezeWorker>,
    adapter_records: HashMap<EntryKey, PatchRecord>,
    /// One persistent plugin process per `[[adapters]]` binding name, lazily
    /// spawned on first use (`ensure_plugin_session`) and held open for the
    /// lifetime of the HUD — see `crate::adapters`' module doc for why a
    /// persistent session, not a spawn-per-call.
    plugin_sessions: HashMap<String, n0xis_sources::PluginSession>,
    /// Set by the UI when the gear button is clicked; consumed by the rebind
    /// popup. Lives here so it survives across frames.
    pub rebind_capture: Option<EntryKey>,
    /// Set when rebinding a *sequence* (combo name) rather than a cheat entry.
    pub seq_rebind_capture: Option<String>,
    /// Set (to the macro name) when rebinding a stratagem macro's hotkey.
    pub stratagem_rebind: Option<String>,
    /// A conflict message for the entry currently being rebound (cleared each
    /// time a new key is offered).
    pub rebind_conflict: Option<String>,
    /// Per-combo overrides (hotkey/delay), persisted to `.n0x/sequences.json`.
    seq_overrides: HashMap<String, SeqOverride>,
    /// Runtime speed override for stratagem macros, persisted to
    /// `.n0x/stratagem_speed.json`.
    stratagem_speed: StratagemSpeedOverride,
    /// Per-macro hotkey overrides, persisted to `.n0x/stratagem_hotkeys.json`
    /// (same "shipped config stays untouched" pattern as `SeqOverride`).
    stratagem_hotkeys: HashMap<String, Option<String>>,
    log: Vec<String>,
}

impl Engine {
    pub fn new(config: HudConfig, project_dir: PathBuf) -> Self {
        let tables = config
            .tables
            .iter()
            .filter_map(|name| match n0xis_project::table::load_at(&project_dir, name) {
                Ok(t) => Some(t),
                Err(e) => {
                    eprintln!("[n0xis-hud] failed to load table '{name}': {e}");
                    None
                }
            })
            .collect();
        let seq_overrides = Self::load_seq_state(&project_dir);
        let stratagem_speed = Self::load_stratagem_speed_state(&project_dir);
        let stratagem_hotkeys = Self::load_stratagem_hotkey_state(&project_dir);
        Self {
            config,
            project_dir,
            tables,
            pid: None,
            freeze_workers: HashMap::new(),
            adapter_records: HashMap::new(),
            plugin_sessions: HashMap::new(),
            rebind_capture: None,
            seq_rebind_capture: None,
            stratagem_rebind: None,
            rebind_conflict: None,
            seq_overrides,
            stratagem_speed,
            stratagem_hotkeys,
            log: Vec::new(),
        }
    }

    // -------- stratagem macro speed + hotkey overrides --------

    fn stratagem_speed_state_path(project_dir: &std::path::Path) -> PathBuf {
        project_dir.join("stratagem_speed.json")
    }
    fn load_stratagem_speed_state(project_dir: &std::path::Path) -> StratagemSpeedOverride {
        std::fs::read_to_string(Self::stratagem_speed_state_path(project_dir))
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }
    fn save_stratagem_speed_state(&self) {
        if let Ok(json) = serde_json::to_string_pretty(&self.stratagem_speed) {
            let _ = std::fs::write(Self::stratagem_speed_state_path(&self.project_dir), json);
        }
    }
    pub fn stratagem_hold_ms(&self) -> u64 {
        self.stratagem_speed.hold_ms.unwrap_or(self.config.stratagem_speed.hold_ms)
    }
    pub fn stratagem_gap_ms(&self) -> u64 {
        self.stratagem_speed.gap_ms.unwrap_or(self.config.stratagem_speed.gap_ms)
    }
    pub fn set_stratagem_hold_ms(&mut self, ms: u64) {
        self.stratagem_speed.hold_ms = Some(ms);
        self.save_stratagem_speed_state();
    }
    pub fn set_stratagem_gap_ms(&mut self, ms: u64) {
        self.stratagem_speed.gap_ms = Some(ms);
        self.save_stratagem_speed_state();
    }

    fn stratagem_hotkey_state_path(project_dir: &std::path::Path) -> PathBuf {
        project_dir.join("stratagem_hotkeys.json")
    }
    fn load_stratagem_hotkey_state(project_dir: &std::path::Path) -> HashMap<String, Option<String>> {
        std::fs::read_to_string(Self::stratagem_hotkey_state_path(project_dir))
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }
    fn save_stratagem_hotkey_state(&self) {
        if let Ok(json) = serde_json::to_string_pretty(&self.stratagem_hotkeys) {
            let _ = std::fs::write(Self::stratagem_hotkey_state_path(&self.project_dir), json);
        }
    }
    /// Effective hotkey for a stratagem macro: runtime override (including an
    /// explicit unbind) wins over the `hud.toml` definition.
    pub fn stratagem_hotkey(&self, name: &str) -> Option<String> {
        match self.stratagem_hotkeys.get(name) {
            Some(over) => over.clone(),
            None => self.config.stratagem.iter().find(|m| m.name == name).and_then(|m| m.hotkey.clone()),
        }
    }
    pub fn try_set_stratagem_hotkey(&mut self, name: &str, key: String) -> Result<(), String> {
        let vk = input::parse_vk(&key);
        match self.hotkey_owner(vk) {
            Some(HotkeyOwner::Window) => return Err(format!("{key} is the N0xHUD show/hide key — pick another")),
            Some(HotkeyOwner::Cheat(c)) => return Err(format!("{key} is already bound to cheat \"{c}\"")),
            Some(HotkeyOwner::Sequence(s)) => return Err(format!("{key} is already bound to combo \"{s}\"")),
            Some(HotkeyOwner::Stratagem(s)) if s != name => return Err(format!("{key} is already bound to \"{s}\"")),
            _ => {}
        }
        self.stratagem_hotkeys.insert(name.to_string(), Some(key));
        self.save_stratagem_hotkey_state();
        Ok(())
    }
    pub fn clear_stratagem_hotkey(&mut self, name: &str) {
        self.stratagem_hotkeys.insert(name.to_string(), None);
        self.save_stratagem_hotkey_state();
    }

    fn seq_state_path(project_dir: &std::path::Path) -> PathBuf {
        project_dir.join("sequences.json")
    }

    fn load_seq_state(project_dir: &std::path::Path) -> HashMap<String, SeqOverride> {
        std::fs::read_to_string(Self::seq_state_path(project_dir))
            .ok()
            .and_then(|raw| serde_json::from_str::<SeqState>(&raw).ok())
            .map(|s| s.combos)
            .unwrap_or_default()
    }

    fn save_seq_state(&self) {
        let state = SeqState { combos: self.seq_overrides.clone() };
        if let Ok(json) = serde_json::to_string_pretty(&state) {
            let _ = std::fs::write(Self::seq_state_path(&self.project_dir), json);
        }
    }

    pub fn config(&self) -> &HudConfig {
        &self.config
    }
    pub fn tables(&self) -> &[Table] {
        &self.tables
    }
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }
    /// Most recent status lines, oldest first.
    pub fn log(&self) -> &[String] {
        &self.log
    }

    pub fn clear_log(&mut self) {
        self.log.clear();
    }

    /// Append a status line from a background subsystem (the combo-solver
    /// watcher) that has no `TableEntry`/adapter-result shape to report
    /// through — same footer log as everything else.
    pub fn note(&mut self, line: String) {
        self.push_log(line);
    }

    fn push_log(&mut self, line: String) {
        self.log.push(line);
        if self.log.len() > LOG_CAPACITY {
            self.log.remove(0);
        }
    }

    pub fn set_pid(&mut self, pid: u32) {
        self.pid = Some(pid);
    }

    /// The watched process exited: drop all live state (freezes stop via their
    /// `Drop`, adapter records are stale — the addresses die with the process).
    pub fn clear_live(&mut self) {
        self.pid = None;
        self.freeze_workers.clear();
        self.adapter_records.clear();
    }

    /// Record an adapter's apply result (from the watcher's auto-apply or a
    /// manual toggle). A fresh success is an activation, so it beeps.
    pub fn set_adapter_result(&mut self, table: &str, entry: &str, result: Result<PatchRecord, String>) {
        match result {
            Ok(rec) => {
                self.adapter_records.insert((table.to_string(), entry.to_string()), rec);
                self.push_log(format!("{entry}: applied"));
                sound::activate();
            }
            Err(e) => self.push_log(format!("{entry}: {e}")),
        }
    }

    pub fn is_on(&self, table_name: &str, entry: &TableEntry) -> bool {
        let key: EntryKey = (table_name.to_string(), entry.name.clone());
        if self.config.adapter_for(table_name, &entry.name).is_some() {
            self.adapter_records.get(&key).map(|r| r.status == "applied").unwrap_or(false)
        } else {
            self.freeze_workers.contains_key(&key)
        }
    }

    /// Lazily spawn (once per binding name) and hold open the plugin process
    /// `binding.command` names. A binding with no `command` (nothing
    /// configured for this entry) is silently a no-op, same as an
    /// unrecognized adapter name was before this became generic.
    fn ensure_plugin_session(&mut self, binding: &AdapterBinding) {
        let Some(command) = binding.command.as_deref() else { return };
        if self.plugin_sessions.contains_key(&binding.name) {
            return;
        }
        let spawned = n0xis_sources::split_command_line(command).and_then(|argv| n0xis_sources::PluginSession::spawn(&argv));
        match spawned {
            Ok(session) => {
                self.plugin_sessions.insert(binding.name.clone(), session);
            }
            Err(e) => self.push_log(format!("{}: plugin unavailable ({e})", binding.name)),
        }
    }

    /// One `{"op":"poll"}` round trip for the named binding, for
    /// `crate::plugin_poll`'s periodic loop. `None` if the binding doesn't
    /// exist or has no `command` configured — nothing to poll.
    pub fn poll_adapter(&mut self, name: &str) -> Option<Result<Option<String>, String>> {
        let pid = self.pid?;
        let binding = self.config.adapters.iter().find(|a| a.name == name)?.clone();
        self.ensure_plugin_session(&binding);
        let session = self.plugin_sessions.get(&binding.name)?;
        Some(adapters::poll(session, pid))
    }

    /// One `{"op":"on_launch"}` round trip for the named binding, for
    /// `crate::watcher`'s attach-retry loop. `None` if the binding doesn't
    /// exist or has no `command` configured — nothing to retry.
    pub fn run_adapter_on_launch(&mut self, name: &str, pid: u32) -> Option<Result<PatchRecord, String>> {
        let binding = self.config.adapters.iter().find(|a| a.name == name)?.clone();
        self.ensure_plugin_session(&binding);
        let session = self.plugin_sessions.get(&binding.name)?;
        Some(adapters::on_launch(session, pid))
    }

    /// Turn one entry on/off — the single funnel for the checkbox, an in-game
    /// hotkey, and (via `set_adapter_result`) the watcher. No-op with no target.
    pub fn apply_toggle(&mut self, table_name: &str, entry: &TableEntry, want_on: bool) {
        let Some(pid) = self.pid else { return };
        let key: EntryKey = (table_name.to_string(), entry.name.clone());

        if let Some(binding) = self.config.adapter_for(table_name, &entry.name).cloned() {
            self.ensure_plugin_session(&binding);
            if want_on {
                // Re-enable at the already-known address if we have one (fast);
                // only fall back to a full rescan the very first time.
                let result = match self.adapter_records.get(&key).cloned() {
                    Some(rec) => match (Va::parse(&rec.address), self.plugin_sessions.get(&binding.name)) {
                        (Ok(addr), Some(session)) => Some(adapters::toggle_on(session, addr, pid)),
                        (Err(e), _) => Some(Err(e.to_string())),
                        (_, None) => None,
                    },
                    None => self.plugin_sessions.get(&binding.name).map(|session| adapters::on_launch(session, pid)),
                };
                if let Some(result) = result {
                    self.set_adapter_result(table_name, &entry.name, result);
                }
            } else if let Some(mut rec) = self.adapter_records.get(&key).cloned() {
                // Keep the record (now status "undone") so re-enable is fast.
                let outcome = self.plugin_sessions.get(&binding.name).map(|session| adapters::toggle_off(session, &mut rec, pid));
                match outcome {
                    Some(Ok(())) => {
                        self.adapter_records.insert(key, rec);
                        self.push_log(format!("{}: off", entry.name));
                        sound::deactivate();
                    }
                    Some(Err(e)) => self.push_log(format!("{}: {e}", entry.name)),
                    None => {}
                }
            }
        } else if want_on {
            match entry.value_type.encode_value(entry.freeze_value.unwrap_or(0.0)) {
                Ok(bytes) => {
                    self.freeze_workers.insert(key, FreezeWorker::spawn(pid, entry.locator.clone(), bytes));
                    self.push_log(format!("{}: on", entry.name));
                    sound::activate();
                }
                Err(e) => self.push_log(format!("{}: {e}", entry.name)),
            }
        } else if self.freeze_workers.remove(&key).is_some() {
            self.push_log(format!("{}: off", entry.name));
            sound::deactivate();
        }
    }

    /// Dispatch an in-game hotkey press: run a bound combo if one matches,
    /// otherwise toggle a bound cheat entry. (The window show/hide key is
    /// intercepted earlier in `input.rs` and never reaches here.)
    pub fn handle_hotkey(&mut self, vk: u32) {
        if let Some(name) = self.stratagem_bound_to(vk) {
            self.run_stratagem_macro(&name);
            return;
        }
        if let Some(name) = self.sequence_bound_to(vk) {
            self.run_sequence(&name);
            return;
        }
        if let Some((table_name, entry)) = self.entry_bound_to(vk, None) {
            let on = self.is_on(&table_name, &entry);
            self.apply_toggle(&table_name, &entry, !on);
        }
    }

    // -------- stratagem macros (Ctrl-held direction code via Interception) --------

    fn stratagem_bound_to(&self, vk: u32) -> Option<String> {
        if vk == 0 {
            return None;
        }
        self.config
            .stratagem
            .iter()
            .map(|m| m.name.clone())
            .find(|name| self.stratagem_hotkey(name).map(|h| input::parse_vk(&h) == vk).unwrap_or(false))
    }

    /// Fire a stratagem macro through the Interception driver (the game ignores
    /// SendInput). Runs off-thread so the input hook never blocks for the whole
    /// sequence.
    pub fn run_stratagem_macro(&mut self, name: &str) {
        let Some(m) = self.config.stratagem.iter().find(|m| m.name == name).cloned() else { return };
        let dll = self.config.interception.dll.clone();
        if dll.trim().is_empty() {
            self.push_log(format!("{name}: no interception dll set (needs [interception] dll)"));
            return;
        }
        let device = self.config.interception.device;
        let hold = self.stratagem_hold_ms();
        let gap = self.stratagem_gap_ms();
        let steps = m.steps.clone();
        let name = name.to_string();
        self.push_log(format!("{name}: {}", steps.join(" ")));
        std::thread::spawn(move || match crate::interception::KeySender::open(&dll, device, hold, gap) {
            Ok(sender) => {
                sender.run_stratagem(crate::interception::LEFT_CTRL, &steps);
            }
            Err(e) => eprintln!("[n0xis-hud] stratagem '{name}': Interception unavailable ({e})"),
        });
    }

    // -------- sequences (variant A: replay a fixed direction combo) --------

    /// The effective hotkey for a combo: user override wins over the config
    /// definition.
    pub fn seq_hotkey(&self, name: &str) -> Option<String> {
        match self.seq_overrides.get(name) {
            Some(ov) => ov.hotkey.clone(),
            None => self.config.sequences.combo.iter().find(|c| c.name == name).and_then(|c| c.hotkey.clone()),
        }
    }

    /// The effective per-step delay (ms): override → config combo → global default.
    pub fn seq_delay(&self, name: &str) -> u64 {
        if let Some(ms) = self.seq_overrides.get(name).and_then(|o| o.delay_ms) {
            return ms;
        }
        let cfg = &self.config.sequences;
        cfg.combo.iter().find(|c| c.name == name).and_then(|c| c.delay_ms).unwrap_or(cfg.default_delay_ms)
    }

    /// Is `vk` bound to any HUD action (a combo or a cheat)? Used by the hook
    /// to swallow the key so it never also reaches the game.
    pub fn hotkey_bound(&self, vk: u32) -> bool {
        self.stratagem_bound_to(vk).is_some()
            || self.sequence_bound_to(vk).is_some()
            || self.entry_bound_to(vk, None).is_some()
    }

    fn sequence_bound_to(&self, vk: u32) -> Option<String> {
        if vk == 0 {
            return None;
        }
        self.config
            .sequences
            .combo
            .iter()
            .find(|c| self.seq_hotkey(&c.name).map(|h| input::parse_vk(&h) == vk).unwrap_or(false))
            .map(|c| c.name.clone())
    }

    /// Resolve a combo's direction tokens to VKs via the configured keymap and
    /// fire it through `SendInput`. Reports (and refuses) unmapped directions.
    pub fn run_sequence(&mut self, name: &str) {
        let cfg = &self.config.sequences;
        let Some(combo) = cfg.combo.iter().find(|c| c.name == name) else { return };
        let mut vks: Vec<u16> = Vec::new();
        for step in &combo.steps {
            match cfg.keys.key_for(step).map(input::parse_vk) {
                Some(vk) if vk != 0 => vks.push(vk as u16),
                _ => {
                    self.push_log(format!("{name}: no key mapped for '{step}' — set [sequences.keys]"));
                    return;
                }
            }
        }
        let delay = self.seq_delay(name);
        let press = cfg.press_ms;
        sequence::run(vks, delay, press);
        self.push_log(format!("{name}: sent {} steps @ {delay}ms", combo.steps.len()));
        sound::activate();
    }

    /// Who currently owns `vk`, if anyone (for rebind conflict messages).
    fn hotkey_owner(&self, vk: u32) -> Option<HotkeyOwner> {
        if vk == 0 {
            return None;
        }
        if vk == input::window_toggle_vk() {
            return Some(HotkeyOwner::Window);
        }
        for t in &self.tables {
            for e in &t.entries {
                if e.hotkey.as_deref().map(|h| input::parse_vk(h) == vk).unwrap_or(false) {
                    return Some(HotkeyOwner::Cheat(e.name.clone()));
                }
            }
        }
        for c in &self.config.sequences.combo {
            if self.seq_hotkey(&c.name).map(|h| input::parse_vk(&h) == vk).unwrap_or(false) {
                return Some(HotkeyOwner::Sequence(c.name.clone()));
            }
        }
        for m in &self.config.stratagem {
            if self.stratagem_hotkey(&m.name).map(|h| input::parse_vk(&h) == vk).unwrap_or(false) {
                return Some(HotkeyOwner::Stratagem(m.name.clone()));
            }
        }
        None
    }

    /// Bind (or reject) a combo's hotkey. `self_name` is excluded so a combo
    /// doesn't conflict with its own current key.
    pub fn try_set_seq_hotkey(&mut self, name: &str, key: String) -> Result<(), String> {
        let vk = input::parse_vk(&key);
        match self.hotkey_owner(vk) {
            Some(HotkeyOwner::Window) => return Err(format!("{key} is the N0xHUD show/hide key — pick another")),
            Some(HotkeyOwner::Cheat(c)) => return Err(format!("{key} is already bound to cheat \"{c}\"")),
            Some(HotkeyOwner::Sequence(s)) if s != name => return Err(format!("{key} is already bound to \"{s}\"")),
            Some(HotkeyOwner::Stratagem(s)) => return Err(format!("{key} is already bound to stratagem \"{s}\"")),
            _ => {}
        }
        self.seq_overrides.entry(name.to_string()).or_default().hotkey = Some(key);
        self.save_seq_state();
        Ok(())
    }

    pub fn clear_seq_hotkey(&mut self, name: &str) {
        self.seq_overrides.entry(name.to_string()).or_default().hotkey = None;
        self.save_seq_state();
    }

    pub fn set_seq_delay(&mut self, name: &str, delay_ms: u64) {
        self.seq_overrides.entry(name.to_string()).or_default().delay_ms = Some(delay_ms);
        self.save_seq_state();
    }

    /// The `.n0xt` entry currently bound to `vk`, if any, optionally
    /// excluding one specific entry (used by conflict-checking during rebind
    /// so an entry doesn't "conflict" with its own current key).
    fn entry_bound_to(&self, vk: u32, exclude: Option<&EntryKey>) -> Option<(String, TableEntry)> {
        if vk == 0 {
            return None;
        }
        self.tables
            .iter()
            .flat_map(|t| t.entries.iter().map(move |e| (t.name.clone(), e.clone())))
            .find(|(tn, e)| {
                exclude.map(|(et, en)| tn != et || &e.name != en).unwrap_or(true)
                    && e.hotkey.as_deref().map(|h| crate::input::parse_vk(h) == vk).unwrap_or(false)
            })
    }

    /// Try to bind `key` to an entry. Refuses (returning the reason) if it's
    /// already the window show/hide key, another cheat's, or a combo's hotkey —
    /// a silent double-bind would mean only one of them ever actually fires.
    pub fn try_set_hotkey(&mut self, table_name: &str, entry_name: &str, key: String) -> Result<(), String> {
        let vk = input::parse_vk(&key);
        match self.hotkey_owner(vk) {
            Some(HotkeyOwner::Window) => return Err(format!("{key} is the N0xHUD show/hide key — pick another")),
            Some(HotkeyOwner::Cheat(c)) if c != entry_name => return Err(format!("{key} is already bound to \"{c}\"")),
            Some(HotkeyOwner::Sequence(s)) => return Err(format!("{key} is already bound to combo \"{s}\"")),
            Some(HotkeyOwner::Stratagem(s)) => return Err(format!("{key} is already bound to stratagem \"{s}\"")),
            _ => {}
        }
        self.set_hotkey_unchecked(table_name, entry_name, Some(key));
        Ok(())
    }

    /// Remove an entry's hotkey binding.
    pub fn clear_hotkey(&mut self, table_name: &str, entry_name: &str) {
        self.set_hotkey_unchecked(table_name, entry_name, None);
    }

    fn set_hotkey_unchecked(&mut self, table_name: &str, entry_name: &str, key: Option<String>) {
        if let Some(table) = self.tables.iter_mut().find(|t| t.name == table_name)
            && let Some(e) = table.entries.iter_mut().find(|e| e.name == entry_name)
        {
            e.hotkey = key;
            let _ = n0xis_project::table::save_at(&self.project_dir, table);
        }
    }
}
