//! Resolve a tool call's `pid`/`file`/`snapshot`/`remote_cmd` arguments
//! (falling back to the session default recorded by `attach`,
//! `.n0x/session.json`, when all four are omitted) into a source — the same
//! four-way split `n0xis-cli`'s `build_source` makes. Deliberately
//! independent of the CLI (a binary crate, not a lib) — this is the MCP
//! frontend's own copy of that seam, scoped down: no inline `--bytes` source
//! (tool calls always name a real target; an agent driving live analysis has
//! no use for it).

use n0xis_contracts::Va;
use n0xis_sources::{LiveProcess, MemorySource, RemoteAgent, Snapshot, StaticPe, split_command_line};

pub enum Src {
    Live(Box<LiveProcess>),
    Static(Box<StaticPe>),
    Snap(Snapshot),
    Remote(Box<RemoteAgent>),
}

impl Src {
    pub fn as_mem(&self) -> &dyn MemorySource {
        match self {
            Src::Live(l) => l.as_ref(),
            Src::Static(p) => p.as_ref(),
            Src::Snap(s) => s,
            Src::Remote(r) => r.as_ref(),
        }
    }

    pub fn text_range(&self) -> Option<(Va, u64)> {
        match self {
            Src::Live(l) => l.text_range(),
            Src::Static(p) => p.text_range(),
            Src::Snap(_) | Src::Remote(_) => None,
        }
    }

    pub fn section_range(&self, name: &str) -> Option<(Va, u64)> {
        match self {
            Src::Live(l) => l.section_range(name),
            Src::Static(p) => p.section_range(name),
            Src::Snap(_) | Src::Remote(_) => None,
        }
    }

    pub fn label(&self) -> String {
        self.as_mem().label()
    }

    pub fn module_base(&self) -> Option<Va> {
        match self {
            Src::Live(l) => l.main_module().map(|m| m.base),
            Src::Static(p) => Some(p.image_base()),
            Src::Snap(_) | Src::Remote(_) => None,
        }
    }
}

fn load_snapshot(name: &str) -> Result<Snapshot, String> {
    let content = n0xis_project::dump::show(name, Some("snapshot")).map_err(|e| e.to_string())?;
    serde_json::from_slice(&content.bytes).map_err(|e| format!("parse snapshot '{name}': {e}"))
}

/// Resolve `pid`/`file`/`snapshot`/`remote_cmd` (checked in that order),
/// falling back to `.n0x/session.json` when all are omitted. Returns a
/// stable `(code, message)` pair on failure, mirroring the CLI's `ir_err`
/// shape so every tool can turn it into the same `{ ok: false, error }`
/// envelope.
pub fn resolve(pid: Option<u32>, file: Option<&str>, snapshot: Option<&str>, remote_cmd: Option<&str>) -> Result<Src, (String, String)> {
    let (pid, file, snapshot, remote_cmd) = if pid.is_none() && file.is_none() && snapshot.is_none() && remote_cmd.is_none() {
        match n0xis_project::session::current() {
            Ok(Some(s)) => (s.pid, s.file, None, None),
            _ => (None, None, None, None),
        }
    } else {
        (pid, file.map(|f| f.to_string()), snapshot.map(|s| s.to_string()), remote_cmd.map(|s| s.to_string()))
    };

    if let Some(pid) = pid {
        let live = LiveProcess::attach(pid).map_err(|e| ("attach-failed".to_string(), e.to_string()))?;
        return Ok(Src::Live(Box::new(live)));
    }
    if let Some(file) = file {
        let pe = StaticPe::load(std::path::Path::new(&file))
            .map_err(|e| ("load-failed".to_string(), e.to_string()))?;
        return Ok(Src::Static(Box::new(pe)));
    }
    if let Some(name) = snapshot {
        let snap = load_snapshot(&name).map_err(|e| ("snapshot-load-failed".to_string(), e))?;
        return Ok(Src::Snap(snap));
    }
    if let Some(cmd) = remote_cmd {
        let argv = split_command_line(&cmd).map_err(|e| ("bad-remote-cmd".to_string(), e))?;
        if argv.is_empty() {
            return Err(("bad-remote-cmd".to_string(), "remote_cmd must not be empty".to_string()));
        }
        let agent = RemoteAgent::connect(argv).map_err(|e| ("remote-connect-failed".to_string(), e.to_string()))?;
        return Ok(Src::Remote(Box::new(agent)));
    }
    Err((
        "missing-source".to_string(),
        "provide pid, file, snapshot, or remote_cmd, or call attach first".to_string(),
    ))
}

/// Choose a scan `(start, size)`: explicit args win, else `default` (typically
/// the module's `.text`, or `.rdata` for a string-data window).
pub fn scan_range(default: Option<(Va, u64)>, explicit_start: Option<Va>, explicit_size: Option<usize>) -> Option<(Va, usize)> {
    let start = explicit_start.or_else(|| default.map(|d| d.0))?;
    let size = explicit_size.or_else(|| default.map(|d| d.1 as usize))?;
    if size == 0 { None } else { Some((start, size)) }
}
