//! The Linux/Android side of the live-target seam — `/proc/<pid>/maps` for the
//! address-space model, `process_vm_readv`/`writev` for the bytes.
//!
//! This is the second implementation of [`crate::target::LiveTarget`], and it
//! exists to make the "a second OS is an adapter, not a rewrite" claim in
//! CONCEPT §4 true rather than aspirational. Everything above the seam — the
//! decompiler, the SSA passes, the scanner, the LuaJIT reader — is reached
//! unchanged; only this file knows what a mapping is.
//!
//! `target_os = "android"` rides along deliberately: Android is a Linux kernel,
//! so `/proc/<pid>/maps` and `process_vm_readv` are the same primitives. The
//! usual blocker there is permission (a non-rooted device cannot attach to
//! another app's process), not API shape.
//!
//! ## What differs from the Win32 adapter, and why
//!
//! * **Sections come from the file, not from memory.** The Win32 adapter reads
//!   a PE's section table straight out of the mapped image, because Windows
//!   maps the whole file including headers. ELF does not: only `PT_LOAD`
//!   segments are mapped, and the section header table normally is not. So a
//!   named-section lookup here re-reads the on-disk module and rebases it by
//!   the load bias. `.text` additionally has a memory-only fallback (the
//!   executable mapping), so a deleted or `memfd`-backed binary still resolves.
//! * **No code caves.** `VirtualAllocEx` has no portable equivalent; allocating
//!   inside another process on Linux means hijacking one of its threads via
//!   ptrace to run `mmap`. The trait default (unsupported) stands, so a detour
//!   attempt fails with a clear message instead of corrupting the target.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io::{Seek, SeekFrom, Write as _};
use std::path::Path;

use n0xis_contracts::{Module, SymKind, Symbol, Va};

use crate::target::{LiveTarget, MemRegion, ProcInfo};
use crate::{MemorySource, ModuleProvider, SourceError, SymbolProvider};

/// One line of `/proc/<pid>/maps`.
#[derive(Debug, Clone)]
struct MapEntry {
    start: u64,
    end: u64,
    /// Raw 4-char `rwxp`/`r-xs` field, kept verbatim for `perms_to_protect`.
    perms: String,
    path: Option<String>,
}

impl MapEntry {
    fn readable(&self) -> bool {
        self.perms.starts_with('r')
    }
    fn executable(&self) -> bool {
        self.perms.as_bytes().get(2) == Some(&b'x')
    }
    /// File-backed by a real path — `[heap]`, `[stack]`, `[vdso]` and anonymous
    /// mappings are not modules.
    fn is_module_backed(&self) -> bool {
        self.path.as_deref().is_some_and(|p| p.starts_with('/'))
    }
}

/// `rwxp` → the 3-char protect vocabulary the `n0xis.mem.map.v1` schema already
/// uses on Windows. One wire vocabulary across OSes, not one per OS.
fn perms_to_protect(perms: &str) -> String {
    let b = perms.as_bytes();
    let g = |i: usize, c: u8| if b.get(i) == Some(&c) { c as char } else { '-' };
    let s: String = [g(0, b'r'), g(1, b'w'), g(2, b'x')].iter().collect();
    if s == "---" { "-".into() } else { s }
}

/// Windows reports `image`/`mapped`/`private`; map Linux's model onto the same
/// three words so an agent's `mem map` parsing is OS-independent.
fn perms_to_kind(entry: &MapEntry) -> &'static str {
    let shared = entry.perms.ends_with('s');
    match (entry.is_module_backed(), shared) {
        (true, _) => "image",
        (false, true) => "mapped",
        (false, false) => "private",
    }
}

fn parse_maps(pid: u32) -> Result<Vec<MapEntry>, SourceError> {
    let path = format!("/proc/{pid}/maps");
    let text = fs::read_to_string(&path).map_err(|e| {
        SourceError::Os(format!("read {path}: {e} — process may be gone, or owned by another user (try sudo)"))
    })?;
    Ok(text.lines().filter_map(parse_maps_line).collect())
}

/// `7f8e0c000000-7f8e0c021000 r-xp 00000000 08:01 1234    /usr/lib/libc.so.6`
///
/// Split on whitespace with a cap of 6 so a pathname containing spaces (common
/// enough on games shipped in `~/My Games/...`) survives intact.
fn parse_maps_line(line: &str) -> Option<MapEntry> {
    let mut it = line.splitn(6, char::is_whitespace).filter(|s| !s.is_empty());
    let range = it.next()?;
    let perms = it.next()?.to_string();
    let _offset = it.next()?;
    let _dev = it.next()?;
    let _inode = it.next()?;
    let path = it.next().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);

    let (s, e) = range.split_once('-')?;
    Some(MapEntry {
        start: u64::from_str_radix(s, 16).ok()?,
        end: u64::from_str_radix(e, 16).ok()?,
        perms,
        path,
    })
}

/// Enumerate running processes (pid + image name) by walking `/proc`.
///
/// The name comes from `/proc/<pid>/comm`, which is the 15-char-truncated
/// thread name; where the full binary name matters (matching `--process
/// SomeGame.x86_64`) the basename of `/proc/<pid>/exe` is preferred and
/// `comm` is the fallback for processes whose `exe` link is unreadable.
pub fn list_processes() -> Result<Vec<ProcInfo>, SourceError> {
    let dir = fs::read_dir("/proc").map_err(|e| SourceError::Os(format!("read /proc: {e}")))?;
    let mut out = Vec::new();
    for entry in dir.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
        let name = fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned()))
            .or_else(|| fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|s| s.trim().to_string()))
            .unwrap_or_default();
        if !name.is_empty() {
            out.push(ProcInfo { pid, name });
        }
    }
    out.sort_by_key(|p| p.pid);
    Ok(out)
}

/// An attached, live Linux/Android process address space.
pub struct LinuxProcess {
    pid: u32,
    modules: Vec<Module>,
    /// Cached `/proc/<pid>/maps`. Refreshed on a lookup miss, because a live
    /// target maps and unmaps as it runs and a stale cache would report a real
    /// address as unmapped.
    maps: RefCell<Vec<MapEntry>>,
    /// Lazily parsed ELF symbol tables, keyed by module base. Parsing every
    /// `.so` a game loads at attach time would make attach cost seconds; most
    /// sessions only ever ask about one or two modules.
    symbols: RefCell<HashMap<u64, std::rc::Rc<Vec<Symbol>>>>,
}

// Mirrors `LiveProcess`: the /proc handles are used from the owning thread only.
// `LinuxProcess` deliberately does not implement Send/Sync.

impl LinuxProcess {
    /// Attach to `pid`: verify it exists and is reachable, then snapshot its
    /// module list from `/proc/<pid>/maps`.
    pub fn attach(pid: u32) -> Result<Self, SourceError> {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            return Err(SourceError::Os(format!("no such process: {pid}")));
        }
        let entries = parse_maps(pid)?;
        if entries.is_empty() {
            return Err(SourceError::Os(format!(
                "/proc/{pid}/maps is empty or unreadable — the process is likely owned by another user, \
                 or is a kernel thread"
            )));
        }
        let modules = build_modules(pid, &entries);
        let me = LinuxProcess {
            pid,
            modules,
            maps: RefCell::new(entries),
            symbols: RefCell::new(HashMap::new()),
        };
        // Prove readability now rather than at first analysis: on a stock
        // Ubuntu/Kali kernel `ptrace_scope=1` lets this open succeed and the
        // *read* fail, and a clear message here beats an EPERM surfacing later
        // out of the middle of a decompile.
        if let Some(base) = me.modules.first().map(|m| m.base) {
            me.read(base, 4)?;
        }
        Ok(me)
    }

    /// Cached lookup of the mapping containing `va`, refreshing once on a miss.
    fn entry_containing(&self, va: u64) -> Option<MapEntry> {
        if let Some(e) = self.maps.borrow().iter().find(|e| va >= e.start && va < e.end) {
            return Some(e.clone());
        }
        let fresh = parse_maps(self.pid).ok()?;
        let hit = fresh.iter().find(|e| va >= e.start && va < e.end).cloned();
        *self.maps.borrow_mut() = fresh;
        hit
    }

    /// The on-disk path backing `module_base`, if any.
    fn module_path(&self, module_base: Va) -> Option<String> {
        self.modules.iter().find(|m| m.base == module_base).and_then(|m| m.path.clone())
    }

    /// Parse (and cache) the ELF symbol table of the module based at
    /// `module_base`, rebased to runtime addresses.
    fn module_symbols(&self, module_base: Va) -> Option<std::rc::Rc<Vec<Symbol>>> {
        if let Some(hit) = self.symbols.borrow().get(&module_base.0) {
            return Some(hit.clone());
        }
        let path = self.module_path(module_base)?;
        let module = self.modules.iter().find(|m| m.base == module_base)?;
        let syms = std::rc::Rc::new(parse_elf_symbols(&path, module_base, &module.name).unwrap_or_default());
        self.symbols.borrow_mut().insert(module_base.0, syms.clone());
        Some(syms)
    }
}

/// Group file-backed mappings into modules: base = lowest mapped address for a
/// path, size = highest end minus that base.
///
/// The main executable is placed **first** so `main_module()` matches the Win32
/// adapter's contract (`modules.first()` is the process image), which several
/// callers rely on for `text_range()`.
fn build_modules(pid: u32, entries: &[MapEntry]) -> Vec<Module> {
    let exe = fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| p.to_string_lossy().into_owned());

    let mut by_path: HashMap<String, (u64, u64)> = HashMap::new();
    for e in entries.iter().filter(|e| e.is_module_backed()) {
        let path = e.path.clone().unwrap();
        let slot = by_path.entry(path).or_insert((u64::MAX, 0));
        slot.0 = slot.0.min(e.start);
        slot.1 = slot.1.max(e.end);
    }

    let mut modules: Vec<Module> = by_path
        .into_iter()
        .map(|(path, (base, end))| Module {
            name: Path::new(&path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| path.clone()),
            base: Va(base),
            size: end - base,
            path: Some(path),
        })
        .collect();

    modules.sort_by_key(|m| m.base.0);
    if let Some(exe) = exe
        && let Some(i) = modules.iter().position(|m| m.path.as_deref() == Some(exe.as_str()))
    {
        modules.swap(0, i);
    }
    modules
}

/// Read an ELF's section header table from disk and return `name`'s runtime
/// `(start, size)`, rebased by the module's load bias.
fn elf_section_range(path: &str, module_base: Va, name: &str) -> Option<(Va, u64)> {
    let bytes = fs::read(path).ok()?;
    let elf = goblin::elf::Elf::parse(&bytes).ok()?;
    let bias = load_bias(&elf, module_base);
    let sh = elf.section_headers.iter().find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(name))?;
    // SHT_NOBITS (.bss) and unallocated sections have no meaningful runtime
    // address; sh_addr == 0 means "not loaded".
    if sh.sh_addr == 0 {
        return None;
    }
    Some((Va(bias.wrapping_add(sh.sh_addr)), sh.sh_size))
}

/// Runtime base minus link-time base. Zero for a non-PIE executable (whose
/// `PT_LOAD` already carries its absolute address), non-zero for PIE and every
/// shared library.
fn load_bias(elf: &goblin::elf::Elf, module_base: Va) -> u64 {
    let min_vaddr = elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD)
        .map(|ph| ph.p_vaddr)
        .min()
        .unwrap_or(0);
    module_base.0.wrapping_sub(min_vaddr)
}

/// Both `.symtab` (stripped in release builds) and `.dynsym` (kept, since the
/// dynamic linker needs it), rebased to runtime addresses.
fn parse_elf_symbols(path: &str, module_base: Va, module_name: &str) -> Option<Vec<Symbol>> {
    let bytes = fs::read(path).ok()?;
    let elf = goblin::elf::Elf::parse(&bytes).ok()?;
    let bias = load_bias(&elf, module_base);
    let mut out = Vec::new();

    let mut push = |name: &str, value: u64, is_func: bool| {
        if name.is_empty() || value == 0 {
            return;
        }
        out.push(Symbol {
            va: Va(bias.wrapping_add(value)),
            module: module_name.to_string(),
            name: name.to_string(),
            kind: if is_func { SymKind::Function } else { SymKind::Data },
        });
    };

    for sym in elf.syms.iter() {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            push(name, sym.st_value, sym.is_function());
        }
    }
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            push(name, sym.st_value, sym.is_function());
        }
    }
    out.sort_by_key(|s| s.va.0);
    out.dedup_by_key(|s| s.va.0);
    Some(out)
}

/// `process_vm_readv` one contiguous chunk.
fn vm_read(pid: u32, va: u64, len: usize) -> Result<Vec<u8>, SourceError> {
    let mut buf = vec![0u8; len];
    let local = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: len };
    let remote = libc::iovec { iov_base: va as *mut libc::c_void, iov_len: len };
    let n = unsafe { libc::process_vm_readv(pid as libc::pid_t, &local, 1, &remote, 1, 0) };
    if n < 0 {
        return Err(read_errno(pid, va));
    }
    buf.truncate(n as usize);
    Ok(buf)
}

/// Turn an errno into something that names the actual fix. `EPERM` here is
/// overwhelmingly Yama `ptrace_scope`, which is 1 by default on Ubuntu/Debian
/// derivatives (Kali included) and silently blocks attaching to any process
/// that is not a descendant — the single most common first-run failure.
fn read_errno(pid: u32, va: u64) -> SourceError {
    let err = std::io::Error::last_os_error();
    let scope = fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope").ok().map(|s| s.trim().to_string());
    match err.raw_os_error() {
        Some(libc::EPERM) => {
            let hint = match scope.as_deref() {
                Some("0") => "ptrace_scope is 0, so this is a uid/capability mismatch — run as the target's user, or with sudo".to_string(),
                Some(other) => format!(
                    "yama ptrace_scope is {other}: a non-descendant process cannot be read. \
                     Fix for this boot with `sudo sysctl kernel.yama.ptrace_scope=0`, \
                     or grant the binary CAP_SYS_PTRACE, or run n0xis as root"
                ),
                None => "run as the target's user or with CAP_SYS_PTRACE".to_string(),
            };
            SourceError::Os(format!("process_vm_readv(pid={pid}) denied: {hint}"))
        }
        Some(libc::ESRCH) => SourceError::Os(format!("process {pid} exited while being read")),
        _ => SourceError::Os(format!("process_vm_readv(pid={pid}, va={:#x}) failed: {err}", va)),
    }
}

impl MemorySource for LinuxProcess {
    /// Read *up to* `len` bytes, truncated at the end of the containing
    /// mapping — the same contract the Win32 adapter and `StaticPe` honour.
    fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, SourceError> {
        let Some(entry) = self.entry_containing(va.0) else {
            return Err(SourceError::Unmapped(va));
        };
        if !entry.readable() {
            return Err(SourceError::Unmapped(va));
        }
        let avail = (entry.end - va.0) as usize;
        let want = len.min(avail);
        if want == 0 {
            return Ok(Vec::new());
        }
        vm_read(self.pid, va.0, want)
    }

    fn contains(&self, va: Va) -> bool {
        self.entry_containing(va.0).is_some_and(|e| e.readable())
    }

    fn code_range(&self) -> Option<(Va, u64)> {
        LiveTarget::text_range(self)
    }

    /// Write via `process_vm_writev`, falling back to `/proc/<pid>/mem`.
    ///
    /// The fallback is not redundant: `process_vm_writev` honours page
    /// protection, so it cannot patch a read-only code page, while a write
    /// through `/proc/<pid>/mem` bypasses it. That is precisely the case that
    /// matters for patching, so a failure of the first is retried rather than
    /// reported.
    fn write(&self, va: Va, bytes: &[u8]) -> Result<(), SourceError> {
        let local = libc::iovec { iov_base: bytes.as_ptr() as *mut libc::c_void, iov_len: bytes.len() };
        let remote = libc::iovec { iov_base: va.0 as *mut libc::c_void, iov_len: bytes.len() };
        let n = unsafe { libc::process_vm_writev(self.pid as libc::pid_t, &local, 1, &remote, 1, 0) };
        if n as usize == bytes.len() {
            return Ok(());
        }
        let first = std::io::Error::last_os_error();

        let path = format!("/proc/{}/mem", self.pid);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(|e| SourceError::Os(format!("process_vm_writev failed ({first}) and open {path} failed: {e}")))?;
        f.seek(SeekFrom::Start(va.0))
            .map_err(|e| SourceError::Os(format!("seek {path} to {va}: {e}")))?;
        f.write_all(bytes)
            .map_err(|e| SourceError::Os(format!("write {} bytes at {va}: {e} (first attempt: {first})", bytes.len())))?;
        Ok(())
    }

    fn label(&self) -> String {
        let name = self.modules.first().map(|m| m.name.as_str()).unwrap_or("?");
        format!("live:{}:{}", self.pid, name)
    }
}

impl ModuleProvider for LinuxProcess {
    fn modules(&self) -> &[Module] {
        &self.modules
    }
}

impl SymbolProvider for LinuxProcess {
    fn symbol_at(&self, va: Va) -> Option<Symbol> {
        let module = self.owner_of(va)?;
        let base = module.base;
        let syms = self.module_symbols(base)?;
        syms.iter().find(|s| s.va == va).cloned()
    }
}

impl LiveTarget for LinuxProcess {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn main_module(&self) -> Option<&Module> {
        self.modules.first()
    }

    /// `.text` from the ELF section table, falling back to the module's
    /// executable mapping when the file is unreadable, stripped of section
    /// headers, or `memfd`/deleted-backed.
    fn text_range(&self) -> Option<(Va, u64)> {
        let base = self.main_module()?.base;
        LiveTarget::section_range_of(self, base, ".text").or_else(|| {
            let m = self.main_module()?;
            self.maps
                .borrow()
                .iter()
                .find(|e| e.executable() && e.start >= m.base.0 && e.start < m.base.0 + m.size)
                .map(|e| (Va(e.start), e.end - e.start))
        })
    }

    fn section_range(&self, name: &str) -> Option<(Va, u64)> {
        LiveTarget::section_range_of(self, self.main_module()?.base, name)
    }

    fn section_range_of(&self, module_base: Va, name: &str) -> Option<(Va, u64)> {
        elf_section_range(&self.module_path(module_base)?, module_base, name)
    }

    fn regions(&self, limit: usize) -> Vec<MemRegion> {
        let fresh = parse_maps(self.pid).unwrap_or_default();
        let out: Vec<MemRegion> = fresh
            .iter()
            .take(limit)
            .map(|e| MemRegion {
                base: Va(e.start),
                end: Va(e.end),
                size: e.end - e.start,
                // Everything listed in /proc/<pid>/maps is mapped and backed;
                // Linux has no "reserved but uncommitted" state to report.
                state: "commit".into(),
                protect: perms_to_protect(&e.perms),
                kind: perms_to_kind(e).into(),
            })
            .collect();
        *self.maps.borrow_mut() = fresh;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_file_backed_maps_line() {
        let e = parse_maps_line("7f8e0c000000-7f8e0c021000 r-xp 00001000 08:01 1234 /usr/lib/libc.so.6").unwrap();
        assert_eq!(e.start, 0x7f8e0c000000);
        assert_eq!(e.end, 0x7f8e0c021000);
        assert_eq!(e.perms, "r-xp");
        assert_eq!(e.path.as_deref(), Some("/usr/lib/libc.so.6"));
        assert!(e.is_module_backed() && e.executable() && e.readable());
    }

    #[test]
    fn parses_an_anonymous_line_with_no_path() {
        let e = parse_maps_line("00400000-00452000 rw-p 00000000 00:00 0").unwrap();
        assert_eq!(e.path, None);
        assert!(!e.is_module_backed());
        assert_eq!(perms_to_kind(&e), "private");
    }

    /// Pseudo-paths are not modules — a `[heap]` grouped as one would give the
    /// process a bogus module and, being first by address on some layouts,
    /// could displace the real executable as `main_module()`.
    #[test]
    fn bracketed_pseudo_paths_are_not_modules() {
        let e = parse_maps_line("7ffd1000-7ffd2000 rw-p 00000000 00:00 0 [stack]").unwrap();
        assert_eq!(e.path.as_deref(), Some("[stack]"));
        assert!(!e.is_module_backed());
    }

    /// Games do ship under paths with spaces; splitn(6) keeps them whole.
    #[test]
    fn a_path_containing_spaces_survives() {
        let e = parse_maps_line("400000-401000 r-xp 00000000 08:01 99 /home/t/My Games/a b.x86_64").unwrap();
        assert_eq!(e.path.as_deref(), Some("/home/t/My Games/a b.x86_64"));
    }

    #[test]
    fn perms_map_onto_the_windows_protect_vocabulary() {
        assert_eq!(perms_to_protect("r-xp"), "r-x");
        assert_eq!(perms_to_protect("rw-p"), "rw-");
        assert_eq!(perms_to_protect("rwxp"), "rwx");
        assert_eq!(perms_to_protect("---p"), "-");
        // and the scan default must accept what Linux actually reports
        assert!(crate::target::is_default_scan_region(&perms_to_protect("rw-p")));
        assert!(crate::target::is_default_scan_region(&perms_to_protect("rwxp")));
        assert!(!crate::target::is_default_scan_region(&perms_to_protect("r-xp")));
    }

    #[test]
    fn shared_anonymous_is_mapped_file_backed_is_image() {
        let shared = parse_maps_line("1000-2000 rw-s 00000000 00:00 0").unwrap();
        assert_eq!(perms_to_kind(&shared), "mapped");
        let image = parse_maps_line("1000-2000 r--p 00000000 08:01 5 /lib/x.so").unwrap();
        assert_eq!(perms_to_kind(&image), "image");
    }

    /// The one thing that must hold for this adapter to be usable at all: the
    /// process running these tests can read its own memory, and what comes back
    /// is what is actually there.
    #[test]
    fn reads_its_own_memory_through_the_seam() {
        let pid = std::process::id();
        let live = LinuxProcess::attach(pid).expect("attach to self");
        assert_eq!(LiveTarget::pid(&live), pid);

        let needle: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x0B, 0xAD, 0xF0, 0x0D];
        let addr = Va(needle.as_ptr() as u64);
        let got = live.read(addr, 8).expect("read own stack");
        assert_eq!(got, needle, "bytes read back through /proc must match the real ones");

        assert!(live.contains(addr));
        assert!(!live.modules().is_empty(), "self must have at least the test binary mapped");
        assert!(LiveTarget::main_module(&live).is_some());
    }

    /// `read` must clamp at the end of a mapping rather than erroring, and must
    /// error only when the address itself is unmapped.
    #[test]
    fn read_clamps_at_region_end_and_rejects_unmapped() {
        let live = LinuxProcess::attach(std::process::id()).expect("attach to self");
        let x: u64 = 0x1122334455667788;
        let addr = Va(&x as *const u64 as u64);
        // Ask for far more than any single mapping holds; must truncate, not fail.
        let got = live.read(addr, 1 << 30).expect("oversized read is clamped, not an error");
        assert!(!got.is_empty() && got.len() < (1 << 30));
        assert_eq!(&got[..8], &x.to_le_bytes());

        assert!(matches!(live.read(Va(0), 4), Err(SourceError::Unmapped(_))));
    }

    #[test]
    fn regions_and_text_range_are_sane() {
        let live = LinuxProcess::attach(std::process::id()).expect("attach to self");
        let regions = LiveTarget::regions(&live, 100_000);
        assert!(!regions.is_empty());
        assert!(regions.iter().all(|r| r.end.0 > r.base.0 && r.state == "commit"));
        assert!(regions.iter().any(|r| r.kind == "image"), "the test binary itself is a file-backed image");

        let (start, size) = LiveTarget::text_range(&live).expect("self has a .text");
        assert!(size > 0);
        // .text must land inside an executable mapping.
        let regions = LiveTarget::regions(&live, 100_000);
        assert!(
            regions.iter().any(|r| r.protect.contains('x') && start.0 >= r.base.0 && start.0 < r.end.0),
            "text_range must point at executable memory"
        );
    }

    #[test]
    fn writes_land_in_the_target() {
        let live = LinuxProcess::attach(std::process::id()).expect("attach to self");
        let mut cell: u64 = 0;
        let addr = Va(&mut cell as *mut u64 as u64);
        live.write(addr, &0xFEEDFACEu32.to_le_bytes()).expect("write to own memory");
        assert_eq!(cell as u32, 0xFEEDFACE);
    }

    #[test]
    fn lists_processes_including_this_one() {
        let procs = list_processes().expect("walk /proc");
        assert!(procs.iter().any(|p| p.pid == std::process::id()));
        assert!(procs.iter().all(|p| !p.name.is_empty()));
    }
}
