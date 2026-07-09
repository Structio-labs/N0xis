//! Resolve a tool call's `pid`/`file` arguments (falling back to the session
//! default recorded by `attach`, `.n0x/session.json`) into a live/static
//! source, the same three-way split `n0xis-cli`'s `build_source` makes.
//! Deliberately independent of the CLI (a binary crate, not a lib) — this is
//! the MCP frontend's own copy of that seam, scoped down: no inline `--bytes`
//! source (tool calls always name a real pid/file; an agent driving live
//! analysis has no use for it), and it consults the shared session so a tool
//! call can omit `pid`/`file` after an `attach`.

use n0xis_contracts::Va;
use n0xis_sources::{LiveProcess, MemorySource, StaticPe};

pub enum Src {
    Live(Box<LiveProcess>),
    Static(Box<StaticPe>),
}

impl Src {
    pub fn as_mem(&self) -> &dyn MemorySource {
        match self {
            Src::Live(l) => l.as_ref(),
            Src::Static(p) => p.as_ref(),
        }
    }

    pub fn text_range(&self) -> Option<(Va, u64)> {
        match self {
            Src::Live(l) => l.text_range(),
            Src::Static(p) => p.text_range(),
        }
    }

    pub fn section_range(&self, name: &str) -> Option<(Va, u64)> {
        match self {
            Src::Live(l) => l.section_range(name),
            Src::Static(p) => p.section_range(name),
        }
    }

    pub fn label(&self) -> String {
        self.as_mem().label()
    }

    pub fn module_base(&self) -> Option<Va> {
        match self {
            Src::Live(l) => l.main_module().map(|m| m.base),
            Src::Static(p) => Some(p.image_base()),
        }
    }
}

/// Resolve `pid`/`file`, falling back to `.n0x/session.json` when both are
/// omitted. Returns a stable `(code, message)` pair on failure, mirroring the
/// CLI's `ir_err` shape so every tool can turn it into the same
/// `{ ok: false, error }` envelope.
pub fn resolve(pid: Option<u32>, file: Option<&str>) -> Result<Src, (String, String)> {
    let (pid, file) = if pid.is_none() && file.is_none() {
        match n0xis_project::session::current() {
            Ok(Some(s)) => (s.pid, s.file),
            _ => (None, None),
        }
    } else {
        (pid, file.map(|f| f.to_string()))
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
    Err((
        "missing-source".to_string(),
        "provide pid or file, or call attach first".to_string(),
    ))
}

/// Choose a scan `(start, size)`: explicit args win, else `default` (typically
/// the module's `.text`, or `.rdata` for a string-data window).
pub fn scan_range(default: Option<(Va, u64)>, explicit_start: Option<Va>, explicit_size: Option<usize>) -> Option<(Va, usize)> {
    let start = explicit_start.or_else(|| default.map(|d| d.0))?;
    let size = explicit_size.or_else(|| default.map(|d| d.1 as usize))?;
    if size == 0 { None } else { Some((start, size)) }
}
