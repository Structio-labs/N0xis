//! File-backed PE source: lets `ir` / `decomp` operate without a running
//! process. Loads a PE from disk, exposes `read_va` (translates a virtual
//! address back to a file offset via the section table, using the PE's
//! preferred image base), and builds export / IAT name maps the same way
//! the live path does — just sourced from the on-disk image instead of
//! `ReadProcessMemory`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use goblin::pe::PE;

use crate::ir;

#[derive(Debug)]
pub(crate) struct StaticPe {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub image_base: u64,
    pub module_name: String,
    sections: Vec<SectionRange>,
    exports: BTreeMap<u64, String>,
    iat: BTreeMap<u64, String>,
}

#[derive(Debug, Clone)]
struct SectionRange {
    #[allow(dead_code)]
    name: String,
    va_start: u64,
    va_end: u64,
    file_offset: usize,
    file_size: usize,
}

impl StaticPe {
    /// SizeOfImage from the optional header (virtual size of the loaded module layout).
    pub fn size_of_image(&self) -> Result<u32> {
        let pe = PE::parse(&self.bytes)
            .with_context(|| format!("Failed to parse PE '{}'", self.path.display()))?;
        let oh = pe
            .header
            .optional_header
            .ok_or_else(|| anyhow!("PE has no optional header"))?;
        Ok(oh.windows_fields.size_of_image)
    }

    /// Build a contiguous byte array for `[image_base, image_base + SizeOfImage)` like the
    /// in-process module view: zeros for gaps/BSS; on-disk bytes copied per section raw data.
    pub fn contiguous_virtual_image(&self) -> Result<Vec<u8>> {
        let size = self.size_of_image()? as usize;
        let mut buf = vec![0u8; size];
        for s in &self.sections {
            if s.file_size == 0 || s.file_offset >= self.bytes.len() {
                continue;
            }
            let rva0 = s
                .va_start
                .checked_sub(self.image_base)
                .unwrap_or(0) as usize;
            for i in 0..s.file_size {
                let src = s.file_offset.saturating_add(i);
                if src >= self.bytes.len() {
                    break;
                }
                let dst = rva0.saturating_add(i);
                if dst < buf.len() {
                    buf[dst] = self.bytes[src];
                }
            }
        }
        Ok(buf)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read PE '{}'", path.display()))?;
        let pe = PE::parse(&bytes)
            .with_context(|| format!("Failed to parse PE '{}'", path.display()))?;

        let image_base = pe
            .header
            .optional_header
            .ok_or_else(|| anyhow!("PE has no optional header — cannot determine image base"))?
            .windows_fields
            .image_base;

        let mut sections = Vec::with_capacity(pe.sections.len());
        for s in &pe.sections {
            let name = s
                .name()
                .map(|n| n.trim_end_matches('\0').to_string())
                .unwrap_or_default();
            let rva = s.virtual_address as u64;
            // Live size in memory; raw size on disk may be smaller (BSS-style padding).
            let virtual_size = s.virtual_size as u64;
            let file_offset = s.pointer_to_raw_data as usize;
            let file_size = s.size_of_raw_data as usize;
            let va_start = image_base.saturating_add(rva);
            let va_end = va_start.saturating_add(virtual_size.max(file_size as u64));
            sections.push(SectionRange {
                name,
                va_start,
                va_end,
                file_offset,
                file_size,
            });
        }

        let module_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("module")
            .to_string();

        let mut exports: BTreeMap<u64, String> = BTreeMap::new();
        for export in &pe.exports {
            if let Some(name) = export.name {
                let va = image_base.saturating_add(export.rva as u64);
                exports.insert(va, format!("{}!{}", module_name, name));
            }
        }

        let mut iat: BTreeMap<u64, String> = BTreeMap::new();
        for import in &pe.imports {
            let slot_va = image_base.saturating_add(import.rva as u64);
            let dll = import.dll.trim_end_matches('\0');
            let dll_short = std::path::Path::new(dll)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(dll);
            iat.insert(slot_va, format!("{}!{}", dll_short, import.name));
        }

        Ok(StaticPe {
            path: path.to_path_buf(),
            bytes,
            image_base,
            module_name,
            sections,
            exports,
            iat,
        })
    }

    /// Translate a virtual address to bytes from the on-disk image, mirroring
    /// `read_memory` semantics: returns up to `size` bytes; may be shorter
    /// when the request runs past the section's raw data (uninitialized tail
    /// in `.bss`-style ranges is not synthesized — caller treats short reads
    /// the same as a short `ReadProcessMemory`).
    pub fn read_va(&self, va: u64, size: usize) -> Result<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }
        let section = self
            .sections
            .iter()
            .find(|s| va >= s.va_start && va < s.va_end)
            .ok_or_else(|| {
                anyhow!(
                    "VA 0x{va:X} is not inside any section of '{}'",
                    self.module_name
                )
            })?;

        let in_section = (va - section.va_start) as usize;
        if in_section >= section.file_size {
            // The VA falls in a section but past its raw data (e.g. BSS).
            return Ok(Vec::new());
        }
        let file_start = section.file_offset.saturating_add(in_section);
        let avail = section.file_size.saturating_sub(in_section);
        let take = size.min(avail);
        let end = file_start.saturating_add(take).min(self.bytes.len());
        if file_start >= end {
            return Ok(Vec::new());
        }
        Ok(self.bytes[file_start..end].to_vec())
    }

    pub fn symbol_map(&self) -> ir::SymbolMap {
        self.exports.clone()
    }

    pub fn iat_map(&self) -> ir::SymbolMap {
        self.iat.clone()
    }

    pub fn contains_va(&self, va: u64) -> bool {
        self.sections
            .iter()
            .any(|s| va >= s.va_start && va < s.va_end)
    }

    /// Validate that an address is inside *some* section before we attempt to
    /// read. Gives a clearer error than `read_va`'s generic miss.
    pub fn ensure_va(&self, va: u64) -> Result<()> {
        if !self.contains_va(va) {
            bail!(
                "VA 0x{va:X} is outside the static image '{}' (file `{}`, image_base 0x{:X}).
hint: pass the *preferred* image base address. For ASLR'd modules in a live process you must use --pid instead.",
                self.module_name,
                self.path.display(),
                self.image_base
            );
        }
        Ok(())
    }
}
