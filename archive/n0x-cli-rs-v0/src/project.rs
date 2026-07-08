//! Per-project state layout.
//!
//! N0x is a single global binary that operates on many projects. Each project
//! gets its own `.n0x/` directory (the "door"), discovered via walk-up from
//! the current working directory the same way `git` finds `.git/`. When no
//! `.n0x/` is found we fall back to a single global directory inside the
//! user's local app data, preserving the original v0 behaviour.
//!
//! Layout inside `.n0x/`:
//!
//! ```text
//! .n0x/
//!   project.toml      # project name, optional core_path override, targets
//!   session.json      # which PID is currently attached (per-project)
//!   selections.json   # named memory ranges (per-project)
//!   dumps/
//!     ir/             # `n0x dump save --kind ir`
//!     pseudo/         # `n0x dump save --kind pseudo`
//!     hex/            # `n0x dump save --kind hex`
//!     raw/            # `n0x dump save --kind raw` (binary)
//!     note/           # `n0x dump save --kind note` (free-form text)
//!   ir-cache/         # reserved for future opt-in IR disk cache
//!   n0x.cmd           # generated shim that calls back into the global build
//! ```
//!
//! The shim is *one* per project (not one per command) and contains the
//! absolute path to the global `n0x-cli-rs.exe` resolved at `init` time.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub const DIR_NAME: &str = ".n0x";

#[derive(Debug, Clone)]
pub struct ProjectRoot {
    /// Path to the `.n0x/` directory itself.
    pub dir: PathBuf,
    /// `true` when discovered via walk-up; `false` when we fell back to the
    /// global `%LocalAppData%/n0x/` directory.
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
    pub fn shim_path(&self) -> PathBuf {
        self.dir.join("n0x.cmd")
    }
}

/// Walk up from `start` looking for a `.n0x/` directory. Returns the deepest
/// match (closest ancestor wins).
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

/// Resolve which directory to read/write per-project state from. If a
/// `.n0x/` exists at-or-above cwd, that's the project root. Otherwise we
/// fall back to the global `%LocalAppData%/n0x/` directory so legacy / unbound
/// invocations still work.
pub fn resolve() -> Result<ProjectRoot> {
    let cwd = env::current_dir().context("Failed to read current directory")?;
    if let Some(dir) = find_local(&cwd) {
        return Ok(ProjectRoot {
            dir,
            is_local: true,
        });
    }
    Ok(ProjectRoot {
        dir: global_dir()?,
        is_local: false,
    })
}

pub fn global_dir() -> Result<PathBuf> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| anyhow!("Unable to determine local data directory"))?;
    let dir = base.join("n0x");
    fs::create_dir_all(&dir).context("Failed to create n0x global directory")?;
    Ok(dir)
}

/// Project-level configuration persisted as `project.toml`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProjectConfig {
    /// Human-readable label, defaults to the parent directory name.
    pub name: String,
    /// Absolute path to the global `n0x-cli-rs.exe` this project was bound
    /// to at `init` time. The generated shim hard-codes the same path.
    pub core_path: String,
    /// ISO-8601-ish timestamp of when this project was initialized.
    pub created_at: String,
    /// Optional named targets — pre-baked `process` / `module` shortcuts the
    /// agent can address by name (consumed by future `target use <name>`).
    #[serde(default)]
    pub targets: std::collections::BTreeMap<String, ProjectTarget>,
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

/// Initialize a `.n0x/` directory at `target_dir` (defaults to cwd).
/// Creates the skeleton folders, writes `project.toml`, and generates the
/// per-project shim that proxies into the global core binary.
pub fn init(target_dir: Option<&Path>, name: Option<String>, core_override: Option<String>) -> Result<InitReport> {
    let cwd = env::current_dir().context("Failed to read current directory")?;
    let base = match target_dir {
        Some(p) => {
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                cwd.join(p)
            }
        }
        None => cwd.clone(),
    };
    let n0x_dir = base.join(DIR_NAME);
    let already_existed = n0x_dir.is_dir();

    fs::create_dir_all(&n0x_dir).with_context(|| format!("Failed to create {}", n0x_dir.display()))?;
    for kind in DUMP_KINDS {
        fs::create_dir_all(n0x_dir.join("dumps").join(kind))
            .with_context(|| format!("Failed to create dumps/{kind}"))?;
    }
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
                    .unwrap_or_else(|| "n0x-project".to_string())
            }),
            core_path: core_path.clone(),
            created_at: now_iso8601(),
            targets: Default::default(),
        };
        let serialized =
            toml_serialize(&cfg).context("Failed to serialize project.toml")?;
        fs::write(&config_path, serialized).context("Failed to write project.toml")?;
        wrote_config = true;
    }

    let shim_path = n0x_dir.join("n0x.cmd");
    let mut wrote_shim = false;
    if !shim_path.exists() {
        let shim = format!(
            "@echo off\r\nrem n0x project shim — generated by `n0x init`\r\n\"{}\" %*\r\n",
            core_path
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

#[derive(Debug, Serialize)]
pub struct InitReport {
    pub dir: PathBuf,
    pub already_existed: bool,
    pub wrote_config: bool,
    pub wrote_shim: bool,
    pub core_path: String,
}

pub const DUMP_KINDS: &[&str] = &["ir", "pseudo", "hex", "raw", "note"];

pub fn is_valid_kind(k: &str) -> bool {
    DUMP_KINDS.contains(&k)
}

pub fn extension_for_kind(k: &str) -> &'static str {
    match k {
        "ir" | "pseudo" => "json",
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
    let cfg: ProjectConfig =
        toml_deserialize(&raw).context("Failed to parse project.toml")?;
    Ok(Some(cfg))
}

// ---------- minimal TOML codec wrappers --------------------------------------
// We avoid pulling a full toml crate dep; project.toml is a tiny human-edited
// file. We hand-roll a tolerant serializer/deserializer for our exact schema.

fn toml_serialize(cfg: &ProjectConfig) -> Result<String> {
    let mut out = String::new();
    out.push_str("# n0x project descriptor — edit by hand or via `n0x project ...` commands.\n");
    out.push_str(&format!("name       = {}\n", quote_toml(&cfg.name)));
    out.push_str(&format!("core_path  = {}\n", quote_toml(&cfg.core_path)));
    out.push_str(&format!("created_at = {}\n", quote_toml(&cfg.created_at)));
    for (tname, t) in &cfg.targets {
        out.push_str(&format!("\n[targets.{}]\n", tname));
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
    Ok(out)
}

fn quote_toml(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn toml_deserialize(raw: &str) -> Result<ProjectConfig> {
    let mut name = String::new();
    let mut core_path = String::new();
    let mut created_at = String::new();
    let mut targets: std::collections::BTreeMap<String, ProjectTarget> =
        Default::default();
    let mut current_target: Option<String> = None;

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(stripped) = line.strip_prefix("[targets.") {
            if let Some(close) = stripped.find(']') {
                let tname = stripped[..close].to_string();
                targets.entry(tname.clone()).or_insert(ProjectTarget {
                    process: None,
                    module: None,
                    notes: None,
                });
                current_target = Some(tname);
                continue;
            }
        }
        if line.starts_with('[') {
            current_target = None;
            continue;
        }
        let Some(eq) = line.find('=') else { continue };
        let key = line[..eq].trim();
        let val = line[eq + 1..].trim();
        let val = unquote_toml(val);
        match (current_target.as_deref(), key) {
            (None, "name") => name = val,
            (None, "core_path") => core_path = val,
            (None, "created_at") => created_at = val,
            (Some(t), "process") => {
                targets.get_mut(t).map(|x| x.process = Some(val));
            }
            (Some(t), "module") => {
                targets.get_mut(t).map(|x| x.module = Some(val));
            }
            (Some(t), "notes") => {
                targets.get_mut(t).map(|x| x.notes = Some(val));
            }
            _ => {}
        }
    }

    Ok(ProjectConfig {
        name,
        core_path,
        created_at,
        targets,
    })
}

fn unquote_toml(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        let inner = &s[1..s.len() - 1];
        return inner.replace("\\\"", "\"").replace("\\\\", "\\");
    }
    s.to_string()
}

fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Cheap UTC formatting (no chrono dep): convert seconds → Y-M-D h:m:s.
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
    // Days since 1970-01-01.
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
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}
