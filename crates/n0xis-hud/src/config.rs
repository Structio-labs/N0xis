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
    /// Interception driver settings, shared by every feature that needs
    /// driver-level input (some games' anti-cheat/input filtering ignores
    /// `SendInput`) — stratagem macros today; any adapter plugin needing a
    /// `KeySender` in the future reads the same section rather than each
    /// carrying its own DLL-path/device config.
    #[serde(default)]
    pub interception: InterceptionConfig,
    /// Hotkey-bound stratagem macros (hold a modifier, tap a direction code) —
    /// run through the Interception driver, since some games ignore SendInput.
    #[serde(default)]
    pub stratagem: Vec<StratagemMacro>,
    /// Default speed for stratagem macros. Adjustable live from the HUD's
    /// "Stratagems" panel.
    #[serde(default)]
    pub stratagem_speed: StratagemSpeedConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StratagemSpeedConfig {
    pub hold_ms: u64,
    pub gap_ms: u64,
}

impl Default for StratagemSpeedConfig {
    fn default() -> Self {
        Self { hold_ms: 20, gap_ms: 20 }
    }
}

/// Where to load the Interception driver from and which device to use —
/// generic (no per-feature copy), see [`HudConfig::interception`].
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct InterceptionConfig {
    /// Path to `interception.dll` (x64), loaded dynamically at runtime — see
    /// `src/interception.rs` for why this is never a build-time link.
    pub dll: String,
    /// Explicit Interception keyboard device (`INTERCEPTION_KEYBOARD(n)`,
    /// 1-based); omit to auto-pick the first keyboard device found.
    #[serde(default)]
    pub device: Option<i32>,
}

impl Default for InterceptionConfig {
    fn default() -> Self {
        Self { dll: String::new(), device: None }
    }
}

/// One stratagem input macro: a name, the direction sequence, an optional
/// in-game hotkey, and the held modifier key (default Left-Ctrl). Directions
/// use the same `up/down/left/right` tokens and WASD scancodes as the combo
/// solver.
#[derive(Debug, Clone, Deserialize)]
pub struct StratagemMacro {
    pub name: String,
    pub steps: Vec<String>,
    #[serde(default)]
    pub hotkey: Option<String>,
    /// Held modifier key name; only `"ctrl"` supported today (default).
    #[serde(default)]
    pub modifier: Option<String>,
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
    /// Executable name to poll for (e.g. `"mygame.exe"`), matched
    /// case-insensitively against `n0xis_sources::list_processes()`.
    pub process_name: String,
}

/// Maps one `.n0xt` entry to a process-based plugin (CONCEPT.md's "for
/// anything needing logic, the profile declares a plugin/adapter") instead of
/// the plain locator-based freeze path. `n0xis-hud` never compiles in
/// game-specific logic itself — `command` is the plugin's spawn argv (parsed
/// the same way as `--remote-cmd`), speaking the `on_launch`/`toggle_on`/
/// `toggle_off`/`poll` JSON protocol over its stdio
/// (`docs/COMMUNITY_ROADMAP.md`'s "Plugin system").
#[derive(Debug, Clone, Deserialize)]
pub struct AdapterBinding {
    pub name: String,
    pub table: String,
    pub entry: String,
    /// The plugin's spawn command. `None` disables the binding (no adapter
    /// configured for this entry — the menu still shows the row, toggling
    /// it is just a no-op, same as an unrecognized name was before).
    #[serde(default)]
    pub command: Option<String>,
    /// How often (ms) the background poller should call this plugin's
    /// `"poll"` op while a target is attached. `None` means never polled —
    /// only `on_launch`/`toggle_on`/`toggle_off` fire, driven by the menu/
    /// watcher as before.
    #[serde(default)]
    pub poll_ms: Option<u64>,
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
