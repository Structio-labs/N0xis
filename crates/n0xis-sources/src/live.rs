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
    MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE, MEMORY_BASIC_INFORMATION,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, VirtualProtectEx, VirtualQueryEx,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

use crate::{MemorySource, ModuleProvider, SourceError, SymbolProvider};

/// One process in a listing.
#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
}

/// One region from the process address-space map (`mem map`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct MemRegion {
    pub base: Va,
    pub end: Va,
    pub size: u64,
    pub state: String,
    pub protect: String,
    pub kind: String,
}

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
        let base = self.main_module()?.base;
        let hdr = self.read(base, 0x1000).ok()?;
        parse_section_range(&hdr, base.0, name)
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
