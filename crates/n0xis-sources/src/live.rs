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
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQueryEx,
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

    /// Locate the `.text` section `(start, size)` of the main module by reading
    /// its PE headers straight from live memory (the full image is mapped, so
    /// unlike `StaticPe` we parse the section table from RAM).
    pub fn text_range(&self) -> Option<(Va, u64)> {
        let base = self.main_module()?.base;
        let hdr = self.read(base, 0x1000).ok()?;
        parse_text_range(&hdr, base.0)
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
fn parse_text_range(hdr: &[u8], base: u64) -> Option<(Va, u64)> {
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
    for i in 0..num_sections {
        let s = sec_table + i * 40; // IMAGE_SECTION_HEADER is 40 bytes
        let name = hdr.get(s..s + 8)?;
        let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(8)];
        if name == b".text" {
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
        // Note: assumes the target pages are already writable. Protection
        // flipping (VirtualProtectEx) belongs to the patch layer, which owns
        // save/restore of the original protection + bytes.
        let mut written = 0usize;
        let ok = unsafe {
            WriteProcessMemory(
                self.handle,
                va.0 as *const c_void,
                bytes.as_ptr() as *const c_void,
                bytes.len(),
                &mut written,
            )
        };
        if ok == 0 {
            return Err(SourceError::Os(format!(
                "WriteProcessMemory at {va} failed (GLE {})",
                unsafe { GetLastError() }
            )));
        }
        Ok(())
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
