// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The source seam as every frontend sees it: five ways to name a target,
//! one resolution path.
//!
//! This replaces the two hand-maintained copies that used to live in
//! `n0xis-cli` (`build_source`) and `n0xis-mcp` (`source::resolve`). They had
//! already drifted — see [`resolve`]'s note on the session default.

use n0xis_contracts::Va;
use n0xis_sources::{LiveTarget, MemorySource, ModuleProvider, RemoteAgent, Snapshot, StaticImage, split_command_line};

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
    // `Arc` (not `Box`) so a persistent `serve` process can keep the parsed image
    // in memory and hand out cheap clones — re-loading a 233 MB PE per call is
    // the ~90 ms click latency; the in-process cache in `resolve` removes it.
    Static(std::sync::Arc<StaticImage>),
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

    /// **Every** executable range of the source, in address order — the honest
    /// answer to "where is the code", which `.text` alone is not on an IL2CPP
    /// IL2CPP image (measured: `.text` 7 247 840 bytes, `il2cpp` 61 303 411,
    /// identical characteristics). Empty when the source cannot say.
    pub fn code_ranges(&self) -> Vec<(Va, u64)> {
        self.as_mem().code_ranges()
    }

    /// [`code_ranges`](Self::code_ranges) for a named module, by case-insensitive
    /// substring.
    ///
    /// Without this a live IL2CPP target cannot be scanned at all: the main
    /// module is a thin player executable (measured: 2 exports, 319 functions)
    /// and every fact worth having is in `GameAssembly.dll` (386 exports,
    /// 277 199). Defaulting to the main module is right for ordinary targets and
    /// exactly wrong for this one, so the caller gets to say which.
    ///
    /// An unmatched name yields an empty list rather than silently falling back
    /// to the main module — asking for a module that is not loaded and being
    /// handed a different one's code is the kind of quiet substitution that
    /// makes a wrong answer look right.
    pub fn code_ranges_of(&self, module: Option<&str>) -> Vec<(Va, u64)> {
        let Some(needle) = module.map(str::to_lowercase) else {
            return self.code_ranges();
        };
        let Some(m) = self.modules().into_iter().find(|m| m.name.to_lowercase().contains(&needle)) else {
            return Vec::new();
        };
        match self {
            Src::Live(l) => l.code_ranges_of(m.base),
            // A static image is one module; if the name matched it, its own
            // ranges are the answer.
            Src::Static(_) => self.code_ranges(),
            Src::Snap(_) | Src::Remote(_) => Vec::new(),
        }
    }

    /// A named section's range in a named module.
    ///
    /// The data-side twin of [`code_ranges_of`](Self::code_ranges_of), and it
    /// exists because fixing only the code side is worse than fixing neither:
    /// pointing `xref string` at `GameAssembly.dll`'s code while it searched
    /// the *player executable's* `.rdata` scanned 61 MB to find nothing, slowly
    /// and convincingly.
    pub fn section_range_in(&self, module: Option<&str>, name: &str) -> Option<(Va, u64)> {
        let Some(needle) = module.map(str::to_lowercase) else {
            return self.section_range(name);
        };
        let m = self.modules().into_iter().find(|m| m.name.to_lowercase().contains(&needle))?;
        match self {
            Src::Live(l) => l.section_range_of(m.base, name),
            Src::Static(_) => self.section_range(name),
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

    /// Every initialized / read-only data range a string literal, a vtable, or
    /// a binding name can live in — enumerated across formats in ONE place so no
    /// caller has to remember the section list. This is *the* single statement
    /// of "where initialized data lives"; every data-window default routes
    /// through it.
    ///
    /// A PE keeps read-only data in `.rdata` (and a mingw build sometimes in
    /// `.data`); an ELF keeps read-only data in `.rodata`, relocated-then-
    /// readonly constants in `.data.rel.ro`, and writable initialized data in
    /// `.data`. Naming only `.rdata` — the PE section — returned nothing for
    /// every ELF: `xref string` reported `count: 0` for a C string plainly
    /// present in `.rodata`, and the MSVC RTTI list missed the same section, one
    /// section over from where it looked. Absent sections are skipped, so the
    /// full list is safe to state for every format (a PE has no `.rodata`, an ELF
    /// no `.rdata`).
    ///
    /// `.rdata` leads so it is the primary window for single-window callers on a
    /// PE; `.rodata` leads on an ELF (whose `.rdata` is absent) — the section
    /// each format actually keeps its string literals in.
    pub fn data_ranges_of(&self, module: Option<&str>) -> Vec<(Va, u64)> {
        [".rdata", ".rodata", ".data.rel.ro", ".data"].iter().filter_map(|s| self.section_range_in(module, s)).collect()
    }

    /// Pointer width in bytes, derived from [`Src::is_64`] so the two can never
    /// disagree.
    ///
    /// A *structural* fact, not a formatting one: MSVC's RTTI is a different
    /// layout at each width — 4-byte slots and absolute pointers on 32-bit
    /// against 8-byte slots and image-relative RVAs on 64-bit — so reading one
    /// as the other finds nothing at all rather than something slightly wrong.
    pub fn pointer_size(&self) -> u8 {
        if self.is_64() { 8 } else { 4 }
    }

    /// Whether the source is 64-bit. A 32-bit **static PE32** returns `false`
    /// (so the frontend picks the i386 arch); everything else defaults to `true`
    /// (64-bit ELF, and live/snapshot/remote whose bitness this seam does not
    /// yet carry — those stay x64 as today).
    pub fn is_64(&self) -> bool {
        match self {
            Src::Static(img) => img.is_64(),
            _ => true,
        }
    }

    /// What instruction set the target says it holds, when it can say.
    ///
    /// A static image states its machine in its own header; a live process,
    /// snapshot or remote agent is whatever the host is running, which the
    /// caller already knows. `None` therefore means "no declaration", not
    /// "unknown architecture" — see [`crate::pick_arch`].
    pub fn declared_machine(&self) -> Option<String> {
        match self {
            Src::Static(img) => Some(img.machine()),
            _ => None,
        }
    }

    /// Pick the decoder architecture for this source, honouring the image
    /// header. An explicit `--arch` wins; otherwise the declared machine
    /// decides; otherwise bitness. This is the header-aware path every
    /// file-analyzing command must use — prefer it over the raw
    /// [`crate::resolve_arch`]/[`crate::pick_arch`], which ignore the header and
    /// so decode a non-x64 image as x86-64 whenever `--arch` is omitted.
    pub fn pick_arch(&self, explicit: Option<&str>) -> Result<Box<dyn n0xis_arch::Arch>, String> {
        crate::arch::pick_arch_for(explicit, self.declared_machine().as_deref(), !self.is_64())
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
/// A single-slot, mtime-validated cache of the last-loaded static image. In a
/// one-shot CLI call it is harmless (one lock + Arc); in a persistent `serve`
/// process it is the whole point — the 233 MB PE is parsed once and every later
/// command reuses it, turning ~90 ms/call into a few ms.
static LAST_IMAGE: std::sync::Mutex<Option<(std::path::PathBuf, u64, std::sync::Arc<StaticImage>)>> = std::sync::Mutex::new(None);

fn file_mtime(path: &std::path::Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_image_cached(path: &std::path::Path) -> Result<std::sync::Arc<StaticImage>, FrontendError> {
    let mtime = file_mtime(path);
    let mut slot = LAST_IMAGE.lock().unwrap_or_else(|e| e.into_inner());
    match slot.as_ref() {
        Some((p, mt, arc)) if p == path && *mt == mtime => return Ok(arc.clone()),
        _ => {} // slot empty or file changed → (re)load below
    }
    let img = std::sync::Arc::new(StaticImage::load(path).map_err(|e| err("load-failed", e.to_string()))?);
    *slot = Some((path.to_path_buf(), mtime, img.clone()));
    Ok(img)
}

pub fn resolve(spec: SourceSpec<'_>) -> Result<ResolvedSource, FrontendError> {
    // A command reads exactly one target, and naming two was neither an error
    // nor a merge — the first one in this function's order won and the rest
    // were dropped without a word. `--bytes "48 89 c8 c3" --file lib.so`
    // disassembled the *file*; `--file x --snapshot nonexistent` succeeded on
    // the file while the snapshot alone fails, which is what proved the second
    // source was accepted and discarded rather than validated. A caller who
    // passes two is asking a question this function cannot answer, and
    // answering a different one is the worst of the three options.
    let named: Vec<&str> = [
        spec.pid.map(|_| "pid"),
        spec.file.map(|_| "file"),
        spec.snapshot.map(|_| "snapshot"),
        spec.remote_cmd.map(|_| "remote-cmd"),
        spec.bytes.map(|_| "bytes"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if named.len() > 1 {
        return Err(err(
            "ambiguous-source",
            format!("{} sources named ({}); a command reads exactly one", named.len(), named.join(", ")),
        ));
    }

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
        let arc = load_image_cached(std::path::Path::new(file))?;
        let label = arc.label();
        return Ok(ResolvedSource { src: Src::Static(arc), label, region_len: None });
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
/// in an IL2CPP game the executable is a thin player and every interesting
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
/// committed writable region — the conventional default scan set.
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

/// Every code window a range-scoped command should cover.
///
/// The plural of [`scan_range_or`], and the reason it exists: `.text` is not
/// "the code" on every image. An IL2CPP build keeps its transpiled C# in a
/// second executable section, so a command that scans one default window covers
/// a tenth of the binary and reports the rest as containing nothing.
///
/// An explicit `--start`/`--size` still wins and still yields exactly **one**
/// window: a caller who named a range asked for that range, and quietly
/// scanning more would be its own kind of wrong.
pub fn scan_ranges_or(
    src_ranges: &[(Va, u64)],
    default: Option<(Va, u64)>,
    region_len: Option<usize>,
    explicit_start: Option<Va>,
    explicit_size: Option<usize>,
    fallback_start: Va,
) -> Vec<(Va, usize)> {
    if explicit_start.is_some() || explicit_size.is_some() || src_ranges.len() < 2 {
        let one = scan_range_or(default, region_len, explicit_start, explicit_size, fallback_start);
        return vec![one];
    }
    src_ranges.iter().filter(|(_, size)| *size > 0).map(|(va, size)| (*va, *size as usize)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Naming two targets is a question this function cannot answer, and it
    /// used to answer a different one: the first branch in `resolve`'s order
    /// won and the rest were dropped silently. `--file x --snapshot <missing>`
    /// succeeded on the file while the snapshot alone fails, which is what
    /// proved the second source was accepted rather than validated.
    #[test]
    fn naming_two_targets_is_refused_rather_than_resolved_by_precedence() {
        let two = SourceSpec {
            pid: None,
            file: Some("/nonexistent"),
            snapshot: Some("also-nonexistent"),
            remote_cmd: None,
            bytes: None,
            bytes_base: None,
        };
        let (code, msg) = resolve(two).err().expect("two sources is an error");
        assert_eq!(code, "ambiguous-source");
        assert!(msg.contains("file") && msg.contains("snapshot"), "{msg}");

        // One source still resolves — the error must be about the *count*, not
        // about naming a source at all.
        let one = SourceSpec {
            pid: None,
            file: None,
            snapshot: None,
            remote_cmd: None,
            bytes: Some("48 89 c8 c3"),
            bytes_base: None,
        };
        let r = resolve(one).expect("inline bytes are a source");
        assert_eq!(r.region_len, Some(4));
    }

    #[test]
    fn several_code_sections_all_get_scanned_unless_one_was_named() {
        let ranges = [(Va(0x1000), 0x200u64), (Va(0x8000), 0x4000)];
        // Nothing named → cover every executable section, not just the first.
        assert_eq!(scan_ranges_or(&ranges, Some((Va(0x1000), 0x200)), None, None, None, Va(0)), vec![(Va(0x1000), 0x200), (Va(0x8000), 0x4000)]);
        // An explicit window is honored exactly, and alone.
        assert_eq!(scan_ranges_or(&ranges, Some((Va(0x1000), 0x200)), None, Some(Va(0x9000)), Some(16), Va(0)), vec![(Va(0x9000), 16)]);
        // A single-code-section image behaves precisely as it did before.
        assert_eq!(scan_ranges_or(&ranges[..1], Some((Va(0x1000), 0x200)), None, None, None, Va(0)), vec![(Va(0x1000), 0x200)]);
        // And a source that cannot report ranges falls back to the default.
        assert_eq!(scan_ranges_or(&[], Some((Va(0x1000), 0x200)), None, None, None, Va(0)), vec![(Va(0x1000), 0x200)]);
    }

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

    /// A minimal but goblin-parseable 64-bit little-endian ELF header carrying
    /// `e_machine`. Header-only (no program/section headers) is a valid ELF, and
    /// it is bytes planted on purpose: the machine field is the one fact under
    /// test, so nothing else needs to be real. `StaticImage::machine` reads
    /// `e_machine` at offset 0x12 directly, and `StaticImage::is_64` reports true
    /// for any ELF, so this exercises the real `declared_machine()`/`is_64()`
    /// path that `Src::pick_arch` delegates through.
    fn elf64_header(e_machine: u16) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2; // EI_CLASS = ELFCLASS64
        b[5] = 1; // EI_DATA  = ELFDATA2LSB (little-endian)
        b[6] = 1; // EI_VERSION
        b[0x10..0x12].copy_from_slice(&3u16.to_le_bytes()); // e_type = ET_DYN
        b[0x12..0x14].copy_from_slice(&e_machine.to_le_bytes()); // e_machine
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // e_version
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b
    }

    /// Wrap a hand-built ELF header as a real static `Src` so the test drives the
    /// same `declared_machine()` -> `pick_arch_for` path the CLI does.
    fn static_src(e_machine: u16) -> Src {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("n0xis_pick_arch_{}_{n}.elf", std::process::id()));
        std::fs::write(&path, elf64_header(e_machine)).expect("write temp elf");
        let img = StaticImage::load(&path).expect("minimal elf header parses");
        let _ = std::fs::remove_file(&path);
        Src::Static(std::sync::Arc::new(img))
    }

    /// `Src::pick_arch` must decode a source with the ISA its header declares —
    /// the B1 defect class: an AArch64 image analysed without `--arch` was
    /// decoded as x86-64 (`jnp`, `div dword ptr` over four-byte ARM), a confident
    /// wrong answer with no error anywhere.
    ///
    /// CALIBRATION: revert `Src::pick_arch`'s body to `resolve_arch(explicit)`
    /// (dropping the declared machine, the pre-fix footgun) and assertion (a)
    /// below fails on its own line — `"arm64"` becomes `"x86-64"`. That is the
    /// exact regression this guards.
    #[test]
    fn src_pick_arch_honours_the_header_the_image_declares() {
        // 0xB7 = EM_AARCH64, which StaticImage::machine reports as "arm64".
        let arm = static_src(0xB7);
        // (a) No --arch: the declared machine decides, NOT the x64 default.
        assert_eq!(arm.pick_arch(None).unwrap().name(), "arm64");
        // (b) An explicit --arch overrides the declared machine.
        assert_eq!(arm.pick_arch(Some("x64")).unwrap().name(), "x86-64");
        // (c) An x64 image (0x3E = EM_X86_64) still decodes as x64.
        let x64 = static_src(0x3E);
        assert_eq!(x64.pick_arch(None).unwrap().name(), "x86-64");
    }

    /// Write one 64-byte ELF section header.
    #[allow(clippy::too_many_arguments)]
    fn put_shdr(b: &mut [u8], sh_base: usize, idx: usize, name: u32, sh_type: u32, flags: u64, addr: u64, offset: u64, size: u64) {
        let o = sh_base + idx * 64;
        b[o..o + 4].copy_from_slice(&name.to_le_bytes());
        b[o + 4..o + 8].copy_from_slice(&sh_type.to_le_bytes());
        b[o + 8..o + 16].copy_from_slice(&flags.to_le_bytes());
        b[o + 16..o + 24].copy_from_slice(&addr.to_le_bytes());
        b[o + 24..o + 32].copy_from_slice(&offset.to_le_bytes());
        b[o + 32..o + 40].copy_from_slice(&size.to_le_bytes());
        b[o + 48..o + 56].copy_from_slice(&1u64.to_le_bytes()); // sh_addralign
    }

    /// A minimal but goblin-parseable ELF64 carrying the allocated data
    /// sections `.rodata`, `.data.rel.ro`, `.data` (and a `.text`), named by a
    /// `.shstrtab`. Bytes planted on purpose: [`Src::data_ranges_of`] reads only
    /// each header's name/address/size, so no section *content* is needed and the
    /// addresses are the one fact under test.
    fn elf64_with_sections() -> Vec<u8> {
        // Index 0 is the empty name; each section's `sh_name` indexes into this.
        let shstr: &[u8] = b"\0.text\0.rodata\0.data.rel.ro\0.data\0.shstrtab\0";
        let (n_text, n_rodata, n_relro, n_data, n_shstr) = (1u32, 7u32, 15u32, 28u32, 34u32);
        const SHOFF: usize = 0x80;
        const STROFF: usize = 0x40;
        let mut b = vec![0u8; SHOFF + 6 * 64];
        b[STROFF..STROFF + shstr.len()].copy_from_slice(shstr);

        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2; // ELFCLASS64
        b[5] = 1; // ELFDATA2LSB
        b[6] = 1; // EI_VERSION
        b[0x10..0x12].copy_from_slice(&3u16.to_le_bytes()); // e_type = ET_DYN
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes()); // e_machine = EM_X86_64
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // e_version
        b[0x28..0x30].copy_from_slice(&(SHOFF as u64).to_le_bytes()); // e_shoff
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        b[0x3c..0x3e].copy_from_slice(&6u16.to_le_bytes()); // e_shnum
        b[0x3e..0x40].copy_from_slice(&5u16.to_le_bytes()); // e_shstrndx

        // [0] SHT_NULL stays zero.
        put_shdr(&mut b, SHOFF, 1, n_text, 1, 0x2 | 0x4, 0x1000, 0x40, 0x100); // ALLOC|EXECINSTR
        put_shdr(&mut b, SHOFF, 2, n_rodata, 1, 0x2, 0x2000, 0x40, 0x100); // ALLOC
        put_shdr(&mut b, SHOFF, 3, n_relro, 1, 0x2 | 0x1, 0x3000, 0x40, 0x100); // ALLOC|WRITE
        put_shdr(&mut b, SHOFF, 4, n_data, 1, 0x2 | 0x1, 0x4000, 0x40, 0x100); // ALLOC|WRITE
        put_shdr(&mut b, SHOFF, 5, n_shstr, 3, 0, 0, STROFF as u64, shstr.len() as u64); // STRTAB, not allocated
        b
    }

    /// `data_ranges_of` is the single source of "where initialized data lives".
    /// The shipped defect was that it named only the PE section `.rdata` and so
    /// returned *nothing* for an ELF, where string literals sit in `.rodata` —
    /// which is how `xref string` reported `count: 0` for a string plainly
    /// present. It must now enumerate `.rodata` (the ELF's primary read-only
    /// section) first, then the other initialized ranges, and never `.text`.
    ///
    /// CALIBRATION: revert the helper's list to `[".rdata", ".data",
    /// ".data.rel.ro"]` (the shipped version, no `.rodata`) and this equality
    /// fails on its own line — the `.rodata` range vanishes and the order shifts.
    #[test]
    fn data_ranges_of_covers_every_read_only_and_initialized_elf_section() {
        let path = std::env::temp_dir().join(format!("n0xis_data_ranges_{}.elf", std::process::id()));
        std::fs::write(&path, elf64_with_sections()).expect("write temp elf");
        let img = StaticImage::load(&path).expect("synthetic sectioned elf parses");
        let _ = std::fs::remove_file(&path);
        let src = Src::Static(std::sync::Arc::new(img));

        assert_eq!(
            src.data_ranges_of(None),
            vec![(Va(0x2000), 0x100), (Va(0x3000), 0x100), (Va(0x4000), 0x100)],
            ".rodata must lead the ELF data window, followed by .data.rel.ro and .data",
        );
    }

    /// No-regression twin: on a PE the primary read-only section is `.rdata`,
    /// and it must stay first so single-window callers still default to it. The
    /// committed `native_pe.dll` is a real mingw PE with a genuine `.rdata`.
    #[test]
    fn data_ranges_of_still_leads_with_rdata_on_a_pe() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../n0xis-cli/tests/fixtures/native_pe.dll");
        if !fixture.exists() {
            eprintln!("data_ranges: skipping the PE side — fixture {fixture:?} is absent, so nothing was checked");
            return;
        }
        let img = StaticImage::load(&fixture).expect("committed native_pe.dll parses");
        let src = Src::Static(std::sync::Arc::new(img));
        let rdata = src.section_range(".rdata").expect("native_pe.dll has a .rdata section");
        assert_eq!(
            src.data_ranges_of(None).first().copied(),
            Some(rdata),
            "a PE's data window must lead with .rdata",
        );
    }
}
