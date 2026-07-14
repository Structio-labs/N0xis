//! `.n0x/hud.toml` — the per-game HUD config (CONCEPT.md's "everything runs
//! through `.n0x/`"). No key, cheat, or process name is ever hardcoded in the
//! binary; it all comes from here.

use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct HudConfig {
    #[serde(default)]
    pub menu: MenuConfig,
    #[serde(default)]
    pub overlay: OverlayConfig,
    pub watch: WatchConfig,
    #[serde(default)]
    pub tables: Vec<String>,
    #[serde(default)]
    pub adapters: Vec<AdapterBinding>,
    #[serde(default)]
    pub sequences: SequencesConfig,
    #[serde(default)]
    pub combo_solver: ComboSolverConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MenuConfig {
    pub toggle_key: String,
    pub isolate_input: bool,
}

impl Default for MenuConfig {
    fn default() -> Self {
        Self { toggle_key: "F2".to_string(), isolate_input: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct OverlayConfig {
    pub opacity: f32,
    pub theme: String,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self { opacity: 0.92, theme: "dark".to_string() }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WatchConfig {
    /// Executable name to poll for (e.g. `"helldivers.exe"`), matched
    /// case-insensitively against `n0xis_sources::list_processes()`.
    pub process_name: String,
}

/// Maps one `.n0xt` entry to a native adapter (CONCEPT.md's "for anything
/// needing logic, the profile declares a plugin/adapter") instead of the
/// plain locator-based freeze path.
#[derive(Debug, Clone, Deserialize)]
pub struct AdapterBinding {
    pub name: String,
    pub table: String,
    pub entry: String,
}

/// Input-macro combos (variant A: replay a fixed direction sequence via
/// SendInput). The combo *definitions* live here; per-combo user overrides
/// (rebound hotkey, tweaked delay) persist separately in `.n0x/sequences.json`
/// so this file stays the shipped/shared definition.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SequencesConfig {
    /// Group label shown in the HUD for these combos.
    pub group: String,
    /// Default per-step delay (ms) when a combo doesn't specify its own.
    pub default_delay_ms: u64,
    /// How long each simulated key is held down (ms).
    pub press_ms: u64,
    /// Which physical key produces each combo direction — set these to your
    /// in-game stratagem/combo binds.
    pub keys: DirectionKeys,
    #[serde(default)]
    pub combo: Vec<ComboDef>,
}

impl Default for SequencesConfig {
    fn default() -> Self {
        Self {
            group: "Combinations".to_string(),
            default_delay_ms: 60,
            press_ms: 20,
            keys: DirectionKeys::default(),
            combo: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DirectionKeys {
    pub up: String,
    pub down: String,
    pub left: String,
    pub right: String,
}

impl Default for DirectionKeys {
    fn default() -> Self {
        // Arrow keys by default — override in [sequences.keys] to match your binds.
        Self { up: "Up".into(), down: "Down".into(), left: "Left".into(), right: "Right".into() }
    }
}

impl DirectionKeys {
    /// The configured key name for a direction token (`"up"/"down"/…`).
    pub fn key_for(&self, direction: &str) -> Option<&str> {
        match direction.to_ascii_lowercase().as_str() {
            "up" => Some(&self.up),
            "down" => Some(&self.down),
            "left" => Some(&self.left),
            "right" => Some(&self.right),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ComboDef {
    pub name: String,
    /// Ordered direction tokens: `"up" | "down" | "left" | "right"`.
    pub steps: Vec<String>,
    #[serde(default)]
    pub hotkey: Option<String>,
    /// Per-step delay override (ms); falls back to `default_delay_ms`.
    #[serde(default)]
    pub delay_ms: Option<u64>,
}

/// The Helldivers combo auto-solver (seed→LCG read + Interception replay —
/// see `adapters::helldivers_combo`). Off by default: it needs the
/// Interception driver installed, so a profile must opt in with a real DLL
/// path rather than the solver silently no-op'ing on a machine without it.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ComboSolverConfig {
    pub enabled: bool,
    /// Path to `interception.dll` (x64), loaded dynamically at runtime — see
    /// `src/interception.rs` for why this is never a build-time link.
    pub interception_dll: String,
    /// Explicit Interception keyboard device (`INTERCEPTION_KEYBOARD(n)`,
    /// 1-based); omit to auto-pick the first keyboard device found.
    #[serde(default)]
    pub device: Option<i32>,
    pub hold_ms: u64,
    pub gap_ms: u64,
    /// How often (ms) the background loop rescans for a newly-activated
    /// interact object while the game is running.
    pub poll_ms: u64,
    /// Safety cap on taps sent to one instance before giving up (protects
    /// against a signature false-positive spinning forever).
    pub max_steps: u32,
}

impl Default for ComboSolverConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interception_dll: String::new(),
            device: None,
            hold_ms: 60,
            gap_ms: 160,
            poll_ms: 700,
            max_steps: 24,
        }
    }
}

impl HudConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let cfg: HudConfig = toml::from_str(&raw)?;
        Ok(cfg)
    }

    /// Look up the adapter bound to a given table/entry pair, if any.
    pub fn adapter_for(&self, table: &str, entry: &str) -> Option<&AdapterBinding> {
        self.adapters
            .iter()
            .find(|a| a.table.eq_ignore_ascii_case(table) && a.entry.eq_ignore_ascii_case(entry))
    }
}
