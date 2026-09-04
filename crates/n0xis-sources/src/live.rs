// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`LiveProcess`] — a Win32-backed [`MemorySource`] over a running process.
//!
//! The **only** OS-linked adapter, gated behind the `live` feature so the
//! analysis core never links Windows APIs (the boundary exit test). It reads
//! through `ReadProcessMemory`, clamps requests to committed regions via
//! `VirtualQueryEx` (giving the documented read-up-to semantics), writes via
//! `WriteProcessMemory`, and enumerates modules via ToolHelp. To the pipeline
//! it is indistinguishable from [`StaticPe`](crate::StaticPe) — same seams,
//! same passes. That is the "one pipeline, live + static" thesis in code.

use std::ffi::c_void;
use std::mem;

use n0xis_contracts::{Module, Symbol, Va};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W,
    Process32FirstW, Process32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RELEASE, MEM_RESERVE,
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOPY, VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, VirtualQueryEx,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

use crate::{MemorySource, ModuleProvider, SourceError, SymbolProvider};

// `ProcInfo`, `MemRegion` and `is_default_scan_region` used to be defined here.
// They are the *shape* of a live target's answers, not Win32 facts, so they now
// live in `crate::target` alongside `trait LiveTarget` and are shared with the
// Linux adapter — one wire vocabulary, not one per OS.
use crate::target::{LiveTarget, MemRegion, ProcInfo, is_default_scan_region};

fn state_str(s: u32) -> &'static str {
    match s {
        x if x == MEM_COMMIT => "commit",
        x if x == MEM_RESERVE => "reserve",
        x if x == MEM_FREE => "free",
        _ => "unknown",
    }
}

fn type_str(t: u32) -> &'static str {
    match t {
        x if x == MEM_IMAGE => "image",
        x if x == MEM_MAPPED => "mapped",
        x if x == MEM_PRIVATE => "private",
        _ => "-",
    }
}

fn protect_str(p: u32) -> String {
    if p == 0 {
        return "-".into();
    }
    let base = p & 0xFF;
    let mut s = match base {
        x if x == PAGE_NOACCESS => "---",
        x if x == PAGE_READONLY => "r--",
        x if x == PAGE_READWRITE => "rw-",
        x if x == PAGE_WRITECOPY => "rc-",
        x if x == PAGE_EXECUTE => "--x",
        x if x == PAGE_EXECUTE_READ => "r-x",
        x if x == PAGE_EXECUTE_READWRITE => "rwx",
        x if x == PAGE_EXECUTE_WRITECOPY => "rcx",
        _ => "???",
    }
    .to_string();
    if p & PAGE_GUARD != 0 {
        s.push_str("+guard");
    }
    s
}

fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

/// Enumerate running processes (pid + image name) via a ToolHelp snapshot.
pub fn list_processes() -> Result<Vec<ProcInfo>, SourceError> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return Err(SourceError::Os(format!(
                "CreateToolhelp32Snapshot failed (GLE {})",
                GetLastError()
            )));
        }
        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                out.push(ProcInfo {
                    pid: entry.th32ProcessID,
                    name: wide_to_string(&entry.szExeFile),
                });
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    Ok(out)
}

/// An attached, live process address space.
pub struct LiveProcess {
    pid: u32,
    handle: HANDLE,
    modules: Vec<Module>,
}

// The process handle is only ever used from the owning thread; the raw pointer
// is not shared. `LiveProcess` deliberately does not implement Send/Sync.

impl LiveProcess {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Open the process for read/write/query and snapshot its module list.
    pub fn attach(pid: u32) -> Result<Self, SourceError> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                0,
                pid,
            )
        };
        if handle.is_null() {
            let gle = unsafe { GetLastError() };
            return Err(SourceError::Os(format!(
                "OpenProcess({pid}) failed (GLE {gle}) — process may be elevated/protected or gone"
            )));
        }
        let modules = snapshot_modules(pid).unwrap_or_default();
        Ok(LiveProcess { pid, handle, modules })
    }

    /// The process's main module (its executable image), if enumerated.
    pub fn main_module(&self) -> Option<&Module> {
        self.modules.first()
    }

    /// Locate the `.text` section `(start, size)` of the main module. See
    /// [`section_range`](Self::section_range).
    pub fn text_range(&self) -> Option<(Va, u64)> {
        self.section_range(".text")
    }

    /// Locate a named section's `(start, size)` in the main module by reading
    /// its PE headers straight from live memory (the full image is mapped, so
    /// unlike `StaticPe` we parse the section table from RAM). `name` is any
    /// section, not just `.text` — e.g. `.rdata` for string-literal scanning.
    pub fn section_range(&self, name: &str) -> Option<(Va, u64)> {
        self.section_range_of(self.main_module()?.base, name)
    }

    /// Same as [`section_range`](Self::section_range), but for *any* loaded
    /// module by its base — not just the main one. Needed once an address
    /// (e.g. a watchpoint hit's `rip`) can fall in a DLL rather than the
    /// main image (ROADMAP Phase 4c: function resolution must scan the
    /// *code* section, never the module base — that's the header page, a
    /// separate, much smaller VAD region that `MemorySource::read`'s
    /// read-up-to-region-end semantics would silently clamp to).
    pub fn section_range_of(&self, module_base: Va, name: &str) -> Option<(Va, u64)> {
        let hdr = self.read(module_base, 0x1000).ok()?;
        parse_section_range(&hdr, module_base.0, name)
    }

    /// Every executable section of an arbitrary loaded module.
    ///
    /// The plural, module-scoped twin of [`section_range_of`](Self::section_range_of),
    /// and the one a Unity target needs: the main module of a running Unity
    /// game is a thin player executable, while the code is in
    /// `GameAssembly.dll` — so "the code ranges of this process" and "the code
    /// ranges of the module you mean" are different answers.
    pub fn code_ranges_of(&self, module_base: Va) -> Vec<(Va, u64)> {
        match self.read(module_base, 0x1000) {
            Ok(hdr) => parse_code_sections(&hdr, module_base.0),
            Err(_) => Vec::new(),
        }
    }

    /// Walk the process address space via `VirtualQueryEx`, up to `limit`
    /// regions (`mem map`).
    pub fn regions(&self, limit: usize) -> Vec<MemRegion> {
        let mut out = Vec::new();
        let mut addr = 0u64;
        while out.len() < limit {
            let Some(mbi) = self.query(addr) else { break };
            let base = mbi.BaseAddress as u64;
            let size = mbi.RegionSize as u64;
            if size == 0 {
                break;
            }
            out.push(MemRegion {
                base: Va(base),
                end: Va(base + size),
                size,
                state: state_str(mbi.State).into(),
                protect: protect_str(mbi.Protect),
                kind: type_str(mbi.Type).into(),
            });
            let Some(next) = base.checked_add(size) else { break };
            addr = next;
        }
        out
    }

    /// All committed, writable regions — the default region set a scan/AOB
    /// search covers when no explicit `--start`/`--size` (or equivalent) is
    /// given, since a value or pattern could be anywhere in the process's
    /// dynamically-allocated memory. Shared by the CLI's `scan value`/
    /// `scan aob` and by any other frontend driving a live-process search
    /// (e.g. n0xis-hud's adapters) — one definition of "the default region
    /// set", not a copy per caller.
    pub fn default_writable_regions(&self) -> Vec<(Va, usize)> {
        self.regions(1_000_000)
            .into_iter()
            .filter(|r| r.state == "commit" && is_default_scan_region(&r.protect))
            .map(|r| (r.base, r.size as usize))
            .collect()
    }

    /// Allocate `size` bytes of `RWX` memory in the target — a "code cave"
    /// for a detour/trampoline hook (ROADMAP Phase 4b). The OS picks the
    /// address (no `lpAddress` hint): on 64-bit Windows this is *usually*
    /// within a `jmp rel32`'s reach of a nearby module, but never guaranteed
    /// — `build_trampoline`-style callers must still range-check before
    /// writing a near jump, not assume proximity.
    pub fn alloc_code_cave(&self, size: usize) -> Result<Va, SourceError> {
        let addr = unsafe {
            VirtualAllocEx(self.handle, std::ptr::null(), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        };
        if addr.is_null() {
            return Err(SourceError::Os(format!("VirtualAllocEx(size={size}) failed (GLE {})", unsafe { GetLastError() })));
        }
        Ok(Va(addr as u64))
    }

    /// Release a previously allocated code cave.
    pub fn free_code_cave(&self, addr: Va) -> Result<(), SourceError> {
        let ok = unsafe { VirtualFreeEx(self.handle, addr.0 as *mut c_void, 0, MEM_RELEASE) };
        if ok == 0 {
            return Err(SourceError::Os(format!("VirtualFreeEx({addr}) failed (GLE {})", unsafe { GetLastError() })));
        }
        Ok(())
    }

    /// Query the committed region covering `va`, if any (base, size, protect).
    fn query(&self, va: u64) -> Option<MEMORY_BASIC_INFORMATION> {
        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();
            let n = VirtualQueryEx(
                self.handle,
                va as *const c_void,
                &mut mbi,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if n == 0 { None } else { Some(mbi) }
        }
    }
}

fn is_readable(protect: u32) -> bool {
    protect & PAGE_GUARD == 0 && protect != PAGE_NOACCESS
}

/// Parse a PE header blob (read at the image base) and return the `.text`
/// section's absolute `(start, size)`. Hand-rolled — we only need three fields
/// and avoid pulling goblin into the `live` build.
fn parse_section_range(hdr: &[u8], base: u64, name: &str) -> Option<(Va, u64)> {
    let rd_u32 = |off: usize| -> Option<u32> {
        hdr.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let rd_u16 = |off: usize| -> Option<u16> {
        hdr.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    // DOS header: e_lfanew at 0x3C → offset of the NT headers ('PE\0\0').
    let e_lfanew = rd_u32(0x3C)? as usize;
    if hdr.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4; // IMAGE_FILE_HEADER
    let num_sections = rd_u16(coff + 2)? as usize;
    let size_opt_hdr = rd_u16(coff + 16)? as usize;
    let sec_table = coff + 20 + size_opt_hdr; // section headers follow the optional header
    let wanted = name.as_bytes();
    for i in 0..num_sections {
        let s = sec_table + i * 40; // IMAGE_SECTION_HEADER is 40 bytes
        let sec_name = hdr.get(s..s + 8)?;
        let sec_name = &sec_name[..sec_name.iter().position(|&c| c == 0).unwrap_or(8)];
        if sec_name == wanted {
            let virtual_size = rd_u32(s + 8)? as u64;
            let virtual_address = rd_u32(s + 12)? as u64;
            return Some((Va(base + virtual_address), virtual_size));
        }
    }
    None
}

/// `IMAGE_SCN_MEM_EXECUTE`.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Every executable section in a PE header blob, in address order.
///
/// The name-matching twin above answers "where is `.text`"; this one answers
/// "where is the code", which on a Unity IL2CPP image is a different question:
/// the transpiled C# lives in a section named `il2cpp` carrying the same
/// characteristics and 8.5× the bytes.
fn parse_code_sections(hdr: &[u8], base: u64) -> Vec<(Va, u64)> {
    let rd_u32 = |off: usize| -> Option<u32> { hdr.get(off..off + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])) };
    let rd_u16 = |off: usize| -> Option<u16> { hdr.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]])) };
    let mut out = Vec::new();
    let Some(e_lfanew) = rd_u32(0x3C).map(|v| v as usize) else { return out };
    if hdr.get(e_lfanew..e_lfanew + 4) != Some(&b"PE\0\0"[..]) {
        return out;
    }
    let coff = e_lfanew + 4;
    let (Some(num_sections), Some(size_opt_hdr)) = (rd_u16(coff + 2), rd_u16(coff + 16)) else { return out };
    let sec_table = coff + 20 + size_opt_hdr as usize;
    for i in 0..num_sections as usize {
        let s = sec_table + i * 40;
        let (Some(vsize), Some(rva), Some(chars)) = (rd_u32(s + 8), rd_u32(s + 12), rd_u32(s + 36)) else { break };
        if chars & IMAGE_SCN_MEM_EXECUTE != 0 && vsize > 0 {
            out.push((Va(base + rva as u64), vsize as u64));
        }
    }
    out.sort_by_key(|(va, _)| va.0);
    out
}

fn snapshot_modules(pid: u32) -> Result<Vec<Module>, SourceError> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap == INVALID_HANDLE_VALUE {
            return Err(SourceError::Os(format!(
                "module snapshot failed (GLE {})",
                GetLastError()
            )));
        }
        let mut entry: MODULEENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;
        if Module32FirstW(snap, &mut entry) != 0 {
            loop {
                out.push(Module {
                    name: wide_to_string(&entry.szModule),
                    base: Va(entry.modBaseAddr as u64),
                    size: entry.modBaseSize as u64,
                    path: Some(wide_to_string(&entry.szExePath)),
                });
                if Module32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    Ok(out)
}

/// Raw `WriteProcessMemory`, returning whether the full buffer was written.
fn wpm(handle: HANDLE, va: Va, bytes: &[u8]) -> bool {
    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            handle,
            va.0 as *const c_void,
            bytes.as_ptr() as *const c_void,
            bytes.len(),
            &mut written,
        )
    };
    ok != 0 && written == bytes.len()
}

/// The Win32 adapter's side of the live-target seam.
///
/// Deliberately thin forwards to the inherent methods above rather than a move
/// of the bodies: every existing caller holds a concrete `LiveProcess` and
/// resolves these names inherently (inherent methods take precedence over
/// trait ones), so this adds the polymorphic entry point without touching a
/// single call site or changing what any of them do.
impl LiveTarget for LiveProcess {
    fn pid(&self) -> u32 {
        LiveProcess::pid(self)
    }
    fn main_module(&self) -> Option<&Module> {
        LiveProcess::main_module(self)
    }
    fn text_range(&self) -> Option<(Va, u64)> {
        LiveProcess::text_range(self)
    }
    fn section_range(&self, name: &str) -> Option<(Va, u64)> {
        LiveProcess::section_range(self, name)
    }
    fn section_range_of(&self, module_base: Va, name: &str) -> Option<(Va, u64)> {
        LiveProcess::section_range_of(self, module_base, name)
    }
    fn code_ranges_of(&self, module_base: Va) -> Vec<(Va, u64)> {
        LiveProcess::code_ranges_of(self, module_base)
    }
    fn regions(&self, limit: usize) -> Vec<MemRegion> {
        LiveProcess::regions(self, limit)
    }
    fn default_writable_regions(&self) -> Vec<(Va, usize)> {
        LiveProcess::default_writable_regions(self)
    }
    fn alloc_code_cave(&self, size: usize) -> Result<Va, SourceError> {
        LiveProcess::alloc_code_cave(self, size)
    }
    fn free_code_cave(&self, addr: Va) -> Result<(), SourceError> {
        LiveProcess::free_code_cave(self, addr)
    }
}

impl Drop for LiveProcess {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { CloseHandle(self.handle) };
        }
    }
}

impl MemorySource for LiveProcess {
    fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, SourceError> {
        let mbi = self.query(va.0).ok_or(SourceError::Unmapped(va))?;
        if mbi.State != MEM_COMMIT || !is_readable(mbi.Protect) {
            return Err(SourceError::Unmapped(va));
        }
        // Clamp to the end of this committed region — read-up-to semantics.
        let region_end = (mbi.BaseAddress as u64).saturating_add(mbi.RegionSize as u64);
        let avail = region_end.saturating_sub(va.0) as usize;
        let take = len.min(avail);
        if take == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; take];
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                va.0 as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                take,
                &mut read,
            )
        };
        if ok == 0 && read == 0 {
            return Err(SourceError::Os(format!(
                "ReadProcessMemory at {va} failed (GLE {})",
                unsafe { GetLastError() }
            )));
        }
        buf.truncate(read);
        Ok(buf)
    }

    fn contains(&self, va: Va) -> bool {
        self.query(va.0)
            .map(|mbi| mbi.State == MEM_COMMIT && is_readable(mbi.Protect))
            .unwrap_or(false)
    }

    fn write(&self, va: Va, bytes: &[u8]) -> Result<(), SourceError> {
        // Fast path: the page is already writable.
        if wpm(self.handle, va, bytes) {
            return Ok(());
        }
        // Slow path: flip protection to RWX, write, then restore — needed to
        // patch read-only/executable code pages. Best-effort restore.
        let mut old_protect: u32 = 0;
        let flipped = unsafe {
            VirtualProtectEx(
                self.handle,
                va.0 as *const c_void,
                bytes.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
        };
        if flipped == 0 {
            return Err(SourceError::Os(format!(
                "VirtualProtectEx at {va} failed (GLE {})",
                unsafe { GetLastError() }
            )));
        }
        let wrote = wpm(self.handle, va, bytes);
        let mut restore_scratch: u32 = 0;
        unsafe {
            VirtualProtectEx(
                self.handle,
                va.0 as *const c_void,
                bytes.len(),
                old_protect,
                &mut restore_scratch,
            );
        }
        if wrote {
            Ok(())
        } else {
            Err(SourceError::Os(format!(
                "WriteProcessMemory at {va} failed after unprotect (GLE {})",
                unsafe { GetLastError() }
            )))
        }
    }

    fn code_range(&self) -> Option<(Va, u64)> {
        self.text_range()
    }

    /// Every executable section of the **main module**, read from its mapped
    /// headers. Falls back to `code_range` when the headers cannot be read, so
    /// a process that refuses the read behaves as it did rather than reporting
    /// no code at all.
    fn code_ranges(&self) -> Vec<(Va, u64)> {
        let ranges = self
            .main_module()
            .and_then(|m| self.read(m.base, 0x1000).ok().map(|hdr| parse_code_sections(&hdr, m.base.0)))
            .unwrap_or_default();
        if ranges.is_empty() { self.code_range().into_iter().collect() } else { ranges }
    }

    fn label(&self) -> String {
        format!("live:{}", self.pid)
    }
}

impl ModuleProvider for LiveProcess {
    fn modules(&self) -> &[Module] {
        &self.modules
    }
}

impl SymbolProvider for LiveProcess {
    // Live export/IAT recovery (parsing each module's PE headers from memory)
    // is a later slice; a live process has no symbols on its own.
    fn symbol_at(&self, _va: Va) -> Option<Symbol> {
        None
    }
}
