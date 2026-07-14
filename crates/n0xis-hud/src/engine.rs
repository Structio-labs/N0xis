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
use crate::config::HudConfig;
use crate::freeze::FreezeWorker;
use crate::{input, sequence, sound};

pub type EntryKey = (String, String); // (table name, entry name)

/// How many recent status lines to keep for the footer log.
const LOG_CAPACITY: usize = 6;

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

/// Runtime overrides for the Helldivers combo auto-solver, layered over the
/// `hud.toml` `[combo_solver]` defaults and persisted to
/// `.n0x/combo_solver.json` (so the shipped config stays untouched, same
/// pattern as `SeqOverride`). A `None` field means "use the config default".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComboSolverOverride {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub hold_ms: Option<u64>,
    #[serde(default)]
    pub gap_ms: Option<u64>,
    /// A hotkey that toggles the solver on/off from in-game.
    #[serde(default)]
    pub hotkey: Option<String>,
}

/// What currently owns a hotkey — for conflict messages during rebind.
pub enum HotkeyOwner {
    Window,
    Cheat(String),
    Sequence(String),
    ComboSolver,
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
    /// Set by the UI when the gear button is clicked; consumed by the rebind
    /// popup. Lives here so it survives across frames.
    pub rebind_capture: Option<EntryKey>,
    /// Set when rebinding a *sequence* (combo name) rather than a cheat entry.
    pub seq_rebind_capture: Option<String>,
    /// Set when rebinding the combo-solver's on/off toggle hotkey.
    pub combo_solver_rebind: bool,
    /// A conflict message for the entry currently being rebound (cleared each
    /// time a new key is offered).
    pub rebind_conflict: Option<String>,
    /// Per-combo overrides (hotkey/delay), persisted to `.n0x/sequences.json`.
    seq_overrides: HashMap<String, SeqOverride>,
    /// Runtime overrides for the combo auto-solver, persisted to
    /// `.n0x/combo_solver.json`.
    combo_solver: ComboSolverOverride,
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
        let combo_solver = Self::load_combo_solver_state(&project_dir);
        Self {
            config,
            project_dir,
            tables,
            pid: None,
            freeze_workers: HashMap::new(),
            adapter_records: HashMap::new(),
            rebind_capture: None,
            seq_rebind_capture: None,
            combo_solver_rebind: false,
            rebind_conflict: None,
            seq_overrides,
            combo_solver,
            log: Vec::new(),
        }
    }

    // -------- combo auto-solver runtime settings --------

    fn combo_solver_state_path(project_dir: &std::path::Path) -> PathBuf {
        project_dir.join("combo_solver.json")
    }

    fn load_combo_solver_state(project_dir: &std::path::Path) -> ComboSolverOverride {
        std::fs::read_to_string(Self::combo_solver_state_path(project_dir))
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }

    fn save_combo_solver_state(&self) {
        if let Ok(json) = serde_json::to_string_pretty(&self.combo_solver) {
            let _ = std::fs::write(Self::combo_solver_state_path(&self.project_dir), json);
        }
    }

    /// Effective solver settings (runtime override → `hud.toml` default).
    pub fn combo_solver_enabled(&self) -> bool {
        self.combo_solver.enabled.unwrap_or(self.config.combo_solver.enabled)
    }
    pub fn combo_solver_hold_ms(&self) -> u64 {
        self.combo_solver.hold_ms.unwrap_or(self.config.combo_solver.hold_ms)
    }
    pub fn combo_solver_gap_ms(&self) -> u64 {
        self.combo_solver.gap_ms.unwrap_or(self.config.combo_solver.gap_ms)
    }
    pub fn combo_solver_hotkey(&self) -> Option<String> {
        self.combo_solver.hotkey.clone()
    }
    /// Static settings that stay config-only (no in-UI control for these).
    pub fn combo_solver_dll(&self) -> &str {
        &self.config.combo_solver.interception_dll
    }
    pub fn combo_solver_device(&self) -> Option<i32> {
        self.config.combo_solver.device
    }
    pub fn combo_solver_poll_ms(&self) -> u64 {
        self.config.combo_solver.poll_ms
    }
    pub fn combo_solver_max_steps(&self) -> u32 {
        self.config.combo_solver.max_steps
    }

    pub fn set_combo_solver_enabled(&mut self, on: bool) {
        self.combo_solver.enabled = Some(on);
        self.save_combo_solver_state();
        self.push_log(format!("combo-solver: {}", if on { "enabled" } else { "disabled" }));
    }
    pub fn set_combo_solver_hold_ms(&mut self, ms: u64) {
        self.combo_solver.hold_ms = Some(ms);
        self.save_combo_solver_state();
    }
    pub fn set_combo_solver_gap_ms(&mut self, ms: u64) {
        self.combo_solver.gap_ms = Some(ms);
        self.save_combo_solver_state();
    }
    pub fn try_set_combo_solver_hotkey(&mut self, key: String) -> Result<(), String> {
        let vk = input::parse_vk(&key);
        match self.hotkey_owner(vk) {
            Some(HotkeyOwner::Window) => return Err(format!("{key} is the N0xHUD show/hide key — pick another")),
            Some(HotkeyOwner::Cheat(c)) => return Err(format!("{key} is already bound to cheat \"{c}\"")),
            Some(HotkeyOwner::Sequence(s)) => return Err(format!("{key} is already bound to combo \"{s}\"")),
            _ => {}
        }
        self.combo_solver.hotkey = Some(key);
        self.save_combo_solver_state();
        Ok(())
    }
    pub fn clear_combo_solver_hotkey(&mut self) {
        self.combo_solver.hotkey = None;
        self.save_combo_solver_state();
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

    /// Turn one entry on/off — the single funnel for the checkbox, an in-game
    /// hotkey, and (via `set_adapter_result`) the watcher. No-op with no target.
    pub fn apply_toggle(&mut self, table_name: &str, entry: &TableEntry, want_on: bool) {
        let Some(pid) = self.pid else { return };
        let key: EntryKey = (table_name.to_string(), entry.name.clone());

        if let Some(binding) = self.config.adapter_for(table_name, &entry.name).cloned() {
            if want_on {
                // Re-enable at the already-known address if we have one (fast);
                // only fall back to a full rescan the very first time.
                let result = match self.adapter_records.get(&key) {
                    Some(rec) => match Va::parse(&rec.address) {
                        Ok(addr) => adapters::toggle_on(&binding.name, addr, pid),
                        Err(e) => Some(Err(e.to_string())),
                    },
                    None => adapters::run_on_launch(&binding.name, pid),
                };
                if let Some(result) = result {
                    self.set_adapter_result(table_name, &entry.name, result);
                }
            } else if let Some(rec) = self.adapter_records.get_mut(&key) {
                // Keep the record (now status "undone") so re-enable is fast.
                match adapters::toggle_off(&binding.name, rec, pid) {
                    Some(Ok(())) => {
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
        if vk != 0 && self.combo_solver_hotkey().map(|h| input::parse_vk(&h) == vk).unwrap_or(false) {
            let on = self.combo_solver_enabled();
            self.set_combo_solver_enabled(!on);
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
        if vk != 0 && self.combo_solver_hotkey().map(|h| input::parse_vk(&h) == vk).unwrap_or(false) {
            return true;
        }
        self.sequence_bound_to(vk).is_some() || self.entry_bound_to(vk, None).is_some()
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
        if self.combo_solver_hotkey().map(|h| input::parse_vk(&h) == vk).unwrap_or(false) {
            return Some(HotkeyOwner::ComboSolver);
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
            Some(HotkeyOwner::ComboSolver) => return Err(format!("{key} is already the combo-solver toggle")),
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
            Some(HotkeyOwner::ComboSolver) => return Err(format!("{key} is already the combo-solver toggle")),
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
