//! The source seam as every frontend sees it: five ways to name a target,
//! one resolution path.
//!
//! This replaces the two hand-maintained copies that used to live in
//! `n0xis-cli` (`build_source`) and `n0xis-mcp` (`source::resolve`). They had
//! already drifted — see [`resolve`]'s note on the session default.

use n0xis_contracts::Va;
use n0xis_sources::{LiveTarget, MemorySource, ModuleProvider, RemoteAgent, Snapshot, StaticPe, split_command_line};

/// A stable `(code, message)` pair. Frontends turn it into their own error
/// shape — `{ok:false,error:{code,message}}` for both the CLI and MCP, which
/// is why the codes are part of the contract and not free text.
pub type FrontendError = (String, String);

fn err(code: &str, message: impl Into<String>) -> FrontendError {
    (code.to_string(), message.into())
}

/// A resolved analysis source. An enum rather than a boxed trait object
/// because range resolution and symbol wiring legitimately differ per adapter,
/// while the passes above stay uniform.
///
/// `Live` holds `Box<dyn LiveTarget>` and — unlike every other arm here once
/// did — carries **no `cfg`**. The trait is OS-free and always compiled, so the
/// variant is nameable on every platform; only the concrete adapter behind it
/// (Win32 `LiveProcess`, `/proc` `LinuxProcess`) comes and goes with the
/// target, and that choice is confined to [`resolve`]. This is what removed the
/// `#[cfg(windows)]` that used to sit on ~20 match arms across this crate and
/// the two frontends: adding an OS is now an adapter, not an edit to every
/// `match`.
pub enum Src {
    Live(Box<dyn LiveTarget>),
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

    /// The live target behind this source, if it is one. Lets a caller reach
    /// the live-only surface (regions, code caves, pid) without matching on the
    /// variant — and without knowing which OS adapter is underneath.
    pub fn as_live(&self) -> Option<&dyn LiveTarget> {
        match self {
            Src::Live(l) => Some(l.as_ref()),
            _ => None,
        }
    }

    pub fn label(&self) -> String {
        self.as_mem().label()
    }

    /// The `.text` range, when the source is a mapped image.
    pub fn text_range(&self) -> Option<(Va, u64)> {
        match self {
            Src::Live(l) => l.text_range(),
            Src::Static(p) => p.text_range(),
            Src::Snap(_) | Src::Remote(_) => None,
        }
    }

    /// A named section's range (`.rdata`, `.data`, …), when the source is a
    /// mapped image.
    pub fn section_range(&self, name: &str) -> Option<(Va, u64)> {
        match self {
            Src::Live(l) => l.section_range(name),
            Src::Static(p) => p.section_range(name),
            Src::Snap(_) | Src::Remote(_) => None,
        }
    }

    /// Modules known to this source (empty for `Snap`/`Remote`, which do not
    /// implement `ModuleProvider`).
    pub fn modules(&self) -> Vec<n0xis_contracts::Module> {
        match self {
            Src::Live(l) => ModuleProvider::modules(l.as_ref()).to_vec(),
            Src::Static(p) => ModuleProvider::modules(p.as_ref()).to_vec(),
            Src::Snap(_) | Src::Remote(_) => Vec::new(),
        }
    }

    /// The base an RVA is measured from: a static image's preferred base, or a
    /// live process's main module base. `None` for sources that are not a
    /// mapped image (inline bytes, a bare snapshot region, a remote agent) —
    /// there is no module to be relative *to*, and guessing one would silently
    /// produce addresses wrong by a whole image base.
    pub fn module_base(&self) -> Option<Va> {
        match self {
            Src::Live(l) => l.main_module().map(|m| m.base),
            Src::Static(p) => Some(p.image_base()),
            Src::Snap(_) | Src::Remote(_) => None,
        }
    }
}

/// How a frontend names its target. All fields optional: what is left after
/// parsing flags (CLI) or tool arguments (MCP).
#[derive(Default, Clone, Copy)]
pub struct SourceSpec<'a> {
    pub pid: Option<u32>,
    pub file: Option<&'a str>,
    pub snapshot: Option<&'a str>,
    pub remote_cmd: Option<&'a str>,
    /// Inline hex bytes. Not every frontend offers this (MCP tool calls always
    /// name a real target), which is fine — it is simply left `None`.
    pub bytes: Option<&'a str>,
    /// Address the inline `bytes` region is mapped at. `None` means 0.
    pub bytes_base: Option<Va>,
}

/// A resolved source plus the provenance label that goes into `meta.source`,
/// and (for inline bytes only) the mapped region length.
pub struct ResolvedSource {
    pub src: Src,
    pub label: String,
    pub region_len: Option<usize>,
}

/// Attach to `pid` and hand back the live target behind `trait LiveTarget`.
///
/// **The only place a frontend chooses an OS adapter.** Every caller that used
/// to carry its own `#[cfg(windows)] … #[cfg(not(windows))] return
/// live-unsupported` pair now calls this and handles one `Result`, which is why
/// those paired blocks disappeared from ~20 sites: the "no adapter here" case
/// is a runtime error from one function, not a compile-time fork repeated at
/// every command.
pub fn attach_live(pid: u32) -> Result<Box<dyn LiveTarget>, FrontendError> {
    #[cfg(windows)]
    {
        let live = n0xis_sources::LiveProcess::attach(pid).map_err(|e| err("attach-failed", e.to_string()))?;
        Ok(Box::new(live))
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let live = n0xis_sources::LinuxProcess::attach(pid).map_err(|e| err("attach-failed", e.to_string()))?;
        Ok(Box::new(live))
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
    {
        let _ = pid;
        Err(err(
            "live-unsupported",
            "live-process analysis has no adapter for this OS yet (Windows and Linux/Android are implemented); \
             drive a remote target with --remote-cmd instead",
        ))
    }
}

/// Enumerate running processes, per OS. Same rationale as [`attach_live`]: one
/// dispatch point, callers stay cfg-free.
pub fn list_processes() -> Result<Vec<n0xis_sources::ProcInfo>, FrontendError> {
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    {
        n0xis_sources::list_processes().map_err(|e| err("ps-failed", e.to_string()))
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
    {
        Err(err("live-unsupported", "process enumeration has no adapter for this OS yet"))
    }
}

pub fn load_snapshot(name: &str) -> Result<Snapshot, String> {
    let content = n0xis_project::dump::show(name, Some("snapshot")).map_err(|e| e.to_string())?;
    serde_json::from_slice(&content.bytes).map_err(|e| format!("parse snapshot '{name}': {e}"))
}

/// Resolve a [`SourceSpec`] into a source, checking `pid` → `file` →
/// `snapshot` → `remote_cmd` → `bytes` in that order.
///
/// When the spec names nothing at all, the `.n0x/session.json` default written
/// by `attach` is used. **That fallback is why this function exists.** The MCP
/// frontend had it, the CLI did not, so `attach` followed by a bare
/// `decomp pseudo` succeeded through an agent and failed at the terminal —
/// with the docs claiming both behaved the same. One resolution path, one
/// answer.
pub fn resolve(spec: SourceSpec<'_>) -> Result<ResolvedSource, FrontendError> {
    let names_nothing =
        spec.pid.is_none() && spec.file.is_none() && spec.snapshot.is_none() && spec.remote_cmd.is_none() && spec.bytes.is_none();

    // The session default is only consulted when nothing was named — an
    // explicit flag always wins over it.
    let session = if names_nothing { n0xis_project::session::current().ok().flatten() } else { None };
    let (pid, file) = match &session {
        Some(s) => (s.pid, s.file.as_deref()),
        None => (spec.pid, spec.file),
    };

    if let Some(pid) = pid {
        let live = attach_live(pid)?;
        let label = live.label();
        return Ok(ResolvedSource { src: Src::Live(live), label, region_len: None });
    }
    if let Some(file) = file {
        let pe = StaticPe::load(std::path::Path::new(file)).map_err(|e| err("load-failed", e.to_string()))?;
        let label = pe.label();
        return Ok(ResolvedSource { src: Src::Static(Box::new(pe)), label, region_len: None });
    }
    if let Some(name) = spec.snapshot {
        let snap = load_snapshot(name).map_err(|e| err("snapshot-load-failed", e))?;
        let label = snap.label();
        return Ok(ResolvedSource { src: Src::Snap(snap), label, region_len: None });
    }
    if let Some(cmd) = spec.remote_cmd {
        let argv = split_command_line(cmd).map_err(|e| err("bad-remote-cmd", e))?;
        if argv.is_empty() {
            return Err(err("bad-remote-cmd", "remote-cmd must not be empty"));
        }
        let agent = RemoteAgent::connect(argv).map_err(|e| err("remote-connect-failed", e.to_string()))?;
        let label = agent.label();
        return Ok(ResolvedSource { src: Src::Remote(Box::new(agent)), label, region_len: None });
    }
    if let Some(b) = spec.bytes {
        let parsed = crate::parse::parse_hex_bytes(b).map_err(|e| err("bad-bytes", e))?;
        let len = parsed.len();
        let base = spec.bytes_base.unwrap_or(Va(0));
        let snap = Snapshot::builder().region(base, parsed).label(format!("bytes@{base}")).build();
        let label = snap.label();
        return Ok(ResolvedSource { src: Src::Snap(snap), label, region_len: Some(len) });
    }
    Err(err("missing-source", "provide pid, file, snapshot, remote-cmd or bytes, or attach first"))
}

/// The base an RVA is measured from, honoring an explicit module name.
///
/// The main-module default is wrong for the most common real target there is:
/// in a Unity game the executable is a thin player and every interesting
/// address lives in `GameAssembly.dll`. Measured on a live target — an RVA
/// resolved against the 319-function player EXE landed on unmapped memory when
/// it belonged to a 96 MB DLL loaded elsewhere. Matching is case-insensitive
/// and accepts a substring, so `gameassembly` is enough.
pub fn base_for_module(src: &Src, name: Option<&str>) -> Result<Va, String> {
    let Some(name) = name else {
        return src.module_base().ok_or_else(|| {
            "no module base in this source (inline bytes, snapshots and remote agents have none); pass a file or pid".to_string()
        });
    };
    let needle = name.to_lowercase();
    let modules = src.modules();
    if modules.is_empty() {
        return Err("a module name needs a source with a module table (pid or file)".to_string());
    }
    match modules.iter().find(|m| m.name.to_lowercase().contains(&needle)) {
        Some(m) => Ok(m.base),
        None => match src {
            // A static PE is one image; naming a different one is a mistake
            // worth reporting rather than silently ignoring.
            Src::Static(_) => Err(format!(
                "this file is `{}`, which does not match module `{name}`",
                modules.first().map(|m| m.name.as_str()).unwrap_or("<unnamed>")
            )),
            _ => Err(format!("no loaded module matches `{name}`; list them with `module list`")),
        },
    }
}

/// Same as [`Src::module_base`], as a free function for call sites that read
/// better that way.
pub fn module_base_of(src: &Src) -> Option<Va> {
    src.module_base()
}

/// The regions a value/AOB scan should cover in a live process.
///
/// With an explicit window, the window is **clipped to the process's committed
/// regions**, and that clipping is the whole point: a live range routinely
/// spans unmapped gaps (LuaJIT's arena is many small committed blocks), and a
/// single `ReadProcessMemory` across a gap fails *wholesale* — silently
/// yielding zero hits. Intersecting with the region map turns one doomed read
/// into per-block reads that actually land. With no window, it is every
/// committed writable region: a memory scanner's default scan set.
pub fn live_scan_regions(live: &dyn LiveTarget, start: Option<&str>, size: Option<usize>) -> Result<Vec<(Va, usize)>, String> {
    if let Some(s) = start {
        let va = Va::parse(s).map_err(|e| e.to_string())?;
        let sz = size.ok_or("provide size with start")?;
        let lo = va.0;
        let hi = va.0.saturating_add(sz as u64);
        let mut clipped: Vec<(Va, usize)> = Vec::new();
        for (rb, rs) in live.default_writable_regions() {
            let a = rb.0.max(lo);
            let b = (rb.0 + rs as u64).min(hi);
            if a < b {
                clipped.push((Va(a), (b - a) as usize));
            }
        }
        if clipped.is_empty() {
            // No committed writable page in the window — fall back to the raw
            // range so a deliberate single-region read (an RX/RO area outside
            // the writable set) still works.
            return Ok(vec![(va, sz)]);
        }
        return Ok(clipped);
    }
    let regions = live.default_writable_regions();
    if regions.is_empty() {
        return Err("no committed writable regions found (and no start/size given)".to_string());
    }
    Ok(regions)
}

/// Choose a scan `(start, size)`: explicit values win, else `default`
/// (typically the module's `.text`, or `.rdata` for a string-data window),
/// else the inline region's length. `None` when nothing determines a range.
pub fn scan_range(
    default: Option<(Va, u64)>,
    region_len: Option<usize>,
    explicit_start: Option<Va>,
    explicit_size: Option<usize>,
) -> Option<(Va, usize)> {
    let start = explicit_start.or_else(|| default.map(|d| d.0))?;
    let size = explicit_size.or_else(|| default.map(|d| d.1 as usize)).or(region_len)?;
    if size == 0 { None } else { Some((start, size)) }
}

/// [`scan_range`] with a frontend-supplied fallback start, for commands whose
/// contract is "always produce a range, even a zero-length one".
pub fn scan_range_or(
    default: Option<(Va, u64)>,
    region_len: Option<usize>,
    explicit_start: Option<Va>,
    explicit_size: Option<usize>,
    fallback_start: Va,
) -> (Va, usize) {
    match scan_range(default, region_len, explicit_start, explicit_size) {
        Some(r) => r,
        None => (explicit_start.or_else(|| default.map(|d| d.0)).unwrap_or(fallback_start), explicit_size.unwrap_or(0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_values_beat_the_default_range() {
        let default = Some((Va(0x1000), 0x200));
        assert_eq!(scan_range(default, None, Some(Va(0x4000)), Some(16)), Some((Va(0x4000), 16)));
        assert_eq!(scan_range(default, None, None, None), Some((Va(0x1000), 0x200)));
        assert_eq!(scan_range(None, Some(8), Some(Va(0x10)), None), Some((Va(0x10), 8)));
        assert_eq!(scan_range(None, None, None, None), None, "nothing determines a range");
    }

    #[test]
    fn a_zero_size_range_is_no_range() {
        assert_eq!(scan_range(Some((Va(0x1000), 0)), None, None, None), None);
        // ...but the "always produce one" variant still answers.
        assert_eq!(scan_range_or(None, None, None, None, Va(0x7000)), (Va(0x7000), 0));
    }

    #[test]
    fn an_empty_spec_without_a_session_is_a_missing_source_error() {
        // No `.n0x/` project in the test's cwd → no session default → the
        // error a frontend surfaces as `{ok:false,error:{code:"missing-source"}}`.
        let Err(e) = resolve(SourceSpec::default()) else {
            panic!("an empty spec must not resolve to a source");
        };
        assert_eq!(e.0, "missing-source");
    }

    #[test]
    fn inline_bytes_resolve_to_a_snapshot_at_the_requested_base() {
        let spec = SourceSpec { bytes: Some("48 89 c8 c3"), bytes_base: Some(Va(0x140001000)), ..Default::default() };
        let r = resolve(spec).expect("inline bytes resolve");
        assert_eq!(r.region_len, Some(4));
        assert!(r.label.contains("bytes@"));
        assert_eq!(r.src.as_mem().read(Va(0x140001000), 4).unwrap(), vec![0x48, 0x89, 0xc8, 0xc3]);
    }

    #[test]
    fn a_bad_remote_command_names_its_own_error_code() {
        let spec = SourceSpec { remote_cmd: Some("   "), ..Default::default() };
        let Err(e) = resolve(spec) else { panic!("a blank remote command must not resolve") };
        assert_eq!(e.0, "bad-remote-cmd");
    }
}
