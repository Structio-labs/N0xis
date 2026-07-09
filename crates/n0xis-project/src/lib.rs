//! # n0xis-project — the `.n0x/` analysis database
//!
//! N0xis is a single global binary that operates on many projects. Each project
//! gets its own `.n0x/` directory (the "door"), discovered via walk-up from the
//! current working directory the same way `git` finds `.git/`. When no `.n0x/`
//! is found we fall back to a single global directory inside the user's local
//! app data.
//!
//! **Back-compat (naming policy, CONCEPT §12):** the directory stays `.n0x/`,
//! the per-project shim stays `n0x.cmd`, and the global dir stays `n0x` — so
//! existing installs and the global `n0x` command keep working after the
//! rename to N0xis. Ported from the sound v0 `project.rs`.
//!
//! Layout inside `.n0x/`:
//!
//! ```text
//! .n0x/
//!   project.toml      # project name, optional core_path override, targets
//!   session.json      # which PID is currently attached (per-project)
//!   selections.json   # named memory ranges (per-project)
//!   dumps/{ir,pseudo,hex,raw,note}/
//!   tables/           # .n0xt cheat/analysis tables (CONCEPT §10)
//!   ir-cache/         # reserved for the PassManager artifact cache (Phase 6)
//!   n0x.cmd           # generated shim that calls back into the global build
//! ```

pub mod dump;
pub mod patch;
pub mod selection;
pub mod table;

/// Guards `std::env::set_current_dir` across every test in this crate.
/// `resolve()` walks up from the process-wide cwd, so any test that pins cwd
/// to a temp project must serialize with every other such test, in `dump`,
/// `selection`, or here — not just within its own module.
#[cfg(test)]
pub(crate) static CWD_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// The per-project directory name. **Kept as `.n0x` for back-compat.**
pub const DIR_NAME: &str = ".n0x";
/// The per-project shim filename. **Kept as `n0x.cmd` for back-compat.**
pub const SHIM_NAME: &str = "n0x.cmd";
/// Global fallback directory name under local app data. **Kept as `n0x`.**
pub const GLOBAL_DIR_NAME: &str = "n0x";

pub const DUMP_KINDS: &[&str] = &["ir", "pseudo", "hex", "raw", "note", "scan"];

/// A resolved project root.
#[derive(Debug, Clone)]
pub struct ProjectRoot {
    /// Path to the `.n0x/` directory itself.
    pub dir: PathBuf,
    /// `true` when discovered via walk-up; `false` when we fell back to the
    /// global directory.
    pub is_local: bool,
}

impl ProjectRoot {
    pub fn session_path(&self) -> PathBuf {
        self.dir.join("session.json")
    }
    pub fn selections_path(&self) -> PathBuf {
        self.dir.join("selections.json")
    }
    pub fn project_toml_path(&self) -> PathBuf {
        self.dir.join("project.toml")
    }
    pub fn dumps_dir(&self) -> PathBuf {
        self.dir.join("dumps")
    }
    pub fn dump_kind_dir(&self, kind: &str) -> PathBuf {
        self.dumps_dir().join(kind)
    }
    pub fn tables_dir(&self) -> PathBuf {
        self.dir.join("tables")
    }
    pub fn shim_path(&self) -> PathBuf {
        self.dir.join(SHIM_NAME)
    }
}

/// Walk up from `start` looking for a `.n0x/` directory. Closest ancestor wins.
pub fn find_local(start: &Path) -> Option<PathBuf> {
    let mut cur = start.to_path_buf();
    loop {
        let candidate = cur.join(DIR_NAME);
        if candidate.is_dir() {
            return Some(candidate);
        }
        if !cur.pop() {
            return None;
        }
    }
}

/// Resolve which directory to read/write per-project state from.
pub fn resolve() -> Result<ProjectRoot> {
    let cwd = env::current_dir().context("Failed to read current directory")?;
    if let Some(dir) = find_local(&cwd) {
        return Ok(ProjectRoot { dir, is_local: true });
    }
    Ok(ProjectRoot {
        dir: global_dir()?,
        is_local: false,
    })
}

pub fn global_dir() -> Result<PathBuf> {
    let base =
        dirs::data_local_dir().ok_or_else(|| anyhow!("Unable to determine local data directory"))?;
    let dir = base.join(GLOBAL_DIR_NAME);
    fs::create_dir_all(&dir).context("Failed to create n0x global directory")?;
    Ok(dir)
}

/// Project-level configuration persisted as `project.toml`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProjectConfig {
    /// Human-readable label, defaults to the parent directory name.
    pub name: String,
    /// Absolute path to the global binary this project was bound to at `init`.
    pub core_path: String,
    /// ISO-8601-ish timestamp of when this project was initialized.
    pub created_at: String,
    /// Optional named targets the agent can address by name.
    #[serde(default)]
    pub targets: BTreeMap<String, ProjectTarget>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProjectTarget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InitReport {
    pub dir: PathBuf,
    pub already_existed: bool,
    pub wrote_config: bool,
    pub wrote_shim: bool,
    pub core_path: String,
}

/// Initialize a `.n0x/` directory at `target_dir` (defaults to cwd).
pub fn init(
    target_dir: Option<&Path>,
    name: Option<String>,
    core_override: Option<String>,
) -> Result<InitReport> {
    let cwd = env::current_dir().context("Failed to read current directory")?;
    let base = match target_dir {
        Some(p) if p.is_absolute() => p.to_path_buf(),
        Some(p) => cwd.join(p),
        None => cwd.clone(),
    };
    let n0x_dir = base.join(DIR_NAME);
    let already_existed = n0x_dir.is_dir();

    fs::create_dir_all(&n0x_dir)
        .with_context(|| format!("Failed to create {}", n0x_dir.display()))?;
    for kind in DUMP_KINDS {
        fs::create_dir_all(n0x_dir.join("dumps").join(kind))
            .with_context(|| format!("Failed to create dumps/{kind}"))?;
    }
    fs::create_dir_all(n0x_dir.join("tables")).ok();
    fs::create_dir_all(n0x_dir.join("ir-cache")).ok();

    let core_path = match core_override {
        Some(p) => p,
        None => env::current_exe()
            .context("Failed to resolve current_exe() for shim")?
            .to_string_lossy()
            .to_string(),
    };

    let config_path = n0x_dir.join("project.toml");
    let mut wrote_config = false;
    if !config_path.exists() {
        let cfg = ProjectConfig {
            name: name.unwrap_or_else(|| {
                base.file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "n0xis-project".to_string())
            }),
            core_path: core_path.clone(),
            created_at: now_iso8601(),
            targets: Default::default(),
        };
        fs::write(&config_path, toml_serialize(&cfg)).context("Failed to write project.toml")?;
        wrote_config = true;
    }

    let shim_path = n0x_dir.join(SHIM_NAME);
    let mut wrote_shim = false;
    if !shim_path.exists() {
        let shim = format!(
            "@echo off\r\nrem n0x project shim — generated by `n0xis init`\r\n\"{core_path}\" %*\r\n",
        );
        fs::write(&shim_path, shim).context("Failed to write n0x.cmd shim")?;
        wrote_shim = true;
    }

    Ok(InitReport {
        dir: n0x_dir,
        already_existed,
        wrote_config,
        wrote_shim,
        core_path,
    })
}

pub fn is_valid_kind(k: &str) -> bool {
    DUMP_KINDS.contains(&k)
}

pub fn extension_for_kind(k: &str) -> &'static str {
    match k {
        "ir" | "pseudo" | "scan" => "json",
        "hex" => "hex",
        "raw" => "bin",
        "note" => "txt",
        _ => "dat",
    }
}

pub fn load_config(root: &ProjectRoot) -> Result<Option<ProjectConfig>> {
    let path = root.project_toml_path();
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path).context("Failed to read project.toml")?;
    Ok(Some(toml_deserialize(&raw)))
}

// ---------- minimal TOML codec (no toml crate; tiny hand-edited file) ---------

fn toml_serialize(cfg: &ProjectConfig) -> String {
    let mut out = String::new();
    out.push_str("# n0xis project descriptor — edit by hand or via `n0xis project ...`.\n");
    out.push_str(&format!("name       = {}\n", quote_toml(&cfg.name)));
    out.push_str(&format!("core_path  = {}\n", quote_toml(&cfg.core_path)));
    out.push_str(&format!("created_at = {}\n", quote_toml(&cfg.created_at)));
    for (tname, t) in &cfg.targets {
        out.push_str(&format!("\n[targets.{tname}]\n"));
        if let Some(p) = &t.process {
            out.push_str(&format!("process = {}\n", quote_toml(p)));
        }
        if let Some(m) = &t.module {
            out.push_str(&format!("module  = {}\n", quote_toml(m)));
        }
        if let Some(n) = &t.notes {
            out.push_str(&format!("notes   = {}\n", quote_toml(n)));
        }
    }
    out
}

fn quote_toml(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn toml_deserialize(raw: &str) -> ProjectConfig {
    let mut name = String::new();
    let mut core_path = String::new();
    let mut created_at = String::new();
    let mut targets: BTreeMap<String, ProjectTarget> = Default::default();
    let mut current_target: Option<String> = None;

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(stripped) = line.strip_prefix("[targets.")
            && let Some(close) = stripped.find(']')
        {
            let tname = stripped[..close].to_string();
            targets.entry(tname.clone()).or_insert(ProjectTarget {
                process: None,
                module: None,
                notes: None,
            });
            current_target = Some(tname);
            continue;
        }
        if line.starts_with('[') {
            current_target = None;
            continue;
        }
        let Some(eq) = line.find('=') else { continue };
        let key = line[..eq].trim();
        let val = unquote_toml(line[eq + 1..].trim());
        match (current_target.as_deref(), key) {
            (None, "name") => name = val,
            (None, "core_path") => core_path = val,
            (None, "created_at") => created_at = val,
            (Some(t), "process") => {
                if let Some(x) = targets.get_mut(t) {
                    x.process = Some(val);
                }
            }
            (Some(t), "module") => {
                if let Some(x) = targets.get_mut(t) {
                    x.module = Some(val);
                }
            }
            (Some(t), "notes") => {
                if let Some(x) = targets.get_mut(t) {
                    x.notes = Some(val);
                }
            }
            _ => {}
        }
    }

    ProjectConfig {
        name,
        core_path,
        created_at,
        targets,
    }
}

fn unquote_toml(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        return s[1..s.len() - 1].replace("\\\"", "\"").replace("\\\\", "\\");
    }
    s.to_string()
}

fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, mo, d, h, mi, se) = epoch_to_ymdhms(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{se:02}Z")
}

fn epoch_to_ymdhms(s: u64) -> (u32, u32, u32, u32, u32, u32) {
    let se = (s % 60) as u32;
    let m = s / 60;
    let mi = (m % 60) as u32;
    let h = m / 60;
    let hr = (h % 24) as u32;
    let mut days = (h / 24) as i64;
    let mut y = 1970u32;
    loop {
        let dy = if is_leap(y) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        y += 1;
    }
    let dim = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mo = 1u32;
    for (idx, &dm) in dim.iter().enumerate() {
        let dm = if idx == 1 && is_leap(y) { 29 } else { dm };
        if days < dm as i64 {
            break;
        }
        days -= dm as i64;
        mo += 1;
    }
    let d = (days + 1) as u32;
    (y, mo, d, hr, mi, se)
}

fn is_leap(y: u32) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_roundtrips_config() {
        let mut targets = BTreeMap::new();
        targets.insert(
            "game".to_string(),
            ProjectTarget {
                process: Some("game.exe".into()),
                module: Some("game.exe".into()),
                notes: None,
            },
        );
        let cfg = ProjectConfig {
            name: "demo".into(),
            core_path: r"C:\bin\n0xis.exe".into(),
            created_at: "2026-07-08T00:00:00Z".into(),
            targets,
        };
        let back = toml_deserialize(&toml_serialize(&cfg));
        assert_eq!(back.name, "demo");
        assert_eq!(back.core_path, r"C:\bin\n0xis.exe");
        assert_eq!(back.targets["game"].process.as_deref(), Some("game.exe"));
    }
}
