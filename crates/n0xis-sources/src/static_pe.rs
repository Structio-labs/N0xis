// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`StaticPe`] — a file-backed PE [`MemorySource`] (+ symbols + module).
//!
//! Loads a PE from disk and exposes it through the *same* seams a live process
//! uses: [`read`](MemorySource::read) translates a virtual address back to a
//! file offset via the section table (at the PE's **preferred image base**),
//! and export / IAT names are surfaced through [`SymbolProvider`]. This is what
//! makes "one pipeline, live + static" true — the analysis never knows whether
//! its bytes came from `ReadProcessMemory` or a section on disk.
//!
//! Ported from the proven v0 `static_pe.rs`, refit to the trait seams.

use std::collections::BTreeMap;
use std::path::Path;

use goblin::pe::PE;
use n0xis_contracts::{Module, SymKind, Symbol, Va};

use crate::{MemorySource, ModuleProvider, SourceError, SymbolProvider};

#[derive(Debug, Clone)]
struct SectionRange {
    #[allow(dead_code)]
    name: String,
    va_start: u64,
    va_end: u64,
    file_offset: usize,
    file_size: usize,
    /// `IMAGE_SCN_MEM_EXECUTE`. See [`MemorySource::code_ranges`] for why one
    /// `.text` is not enough on this corpus.
    executable: bool,
}

/// `IMAGE_SCN_MEM_EXECUTE`.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// A PE image on disk, mapped at its preferred base.
#[derive(Debug)]
pub struct StaticPe {
    bytes: Vec<u8>,
    image_base: u64,
    module_name: String,
    /// Exactly one module — the image itself (kept as a slice for the trait).
    modules: Vec<Module>,
    sections: Vec<SectionRange>,
    exports: BTreeMap<u64, Symbol>,
    /// IAT slot VA → the imported symbol it resolves to.
    iat: BTreeMap<u64, Symbol>,
    /// 64-bit PE32+ (`true`) vs 32-bit PE32 (`false`).
    is_64: bool,
}

impl StaticPe {
    /// Preferred image base from the optional header.
    pub fn image_base(&self) -> Va {
        Va(self.image_base)
    }

    /// The single module descriptor for this image.
    pub fn module(&self) -> &Module {
        &self.modules[0]
    }

    /// Virtual address range of the `.text` section `(start, size)`, for
    /// function discovery / code scanning. See [`section_range`](Self::section_range).
    pub fn text_range(&self) -> Option<(Va, u64)> {
        self.section_range(".text")
    }

    /// Every section that carries on-disk bytes, as `(name, va, size)` — the
    /// ranges a byte/string search (`find`) can actually read. Uninitialized
    /// (`.bss`-style) sections that occupy virtual space but hold no file bytes
    /// are skipped; the readable size is the on-disk size (padding excluded).
    pub fn sections(&self) -> Vec<(String, Va, u64)> {
        self.sections
            .iter()
            .filter(|s| s.file_size > 0)
            .map(|s| (s.name.clone(), Va(s.va_start), s.file_size as u64))
            .collect()
    }

    /// Virtual address range of a named section `(start, size)` — e.g.
    /// `.rdata` for string-literal scanning, not just `.text`.
    pub fn section_range(&self, name: &str) -> Option<(Va, u64)> {
        self.sections
            .iter()
            .find(|s| s.name == name)
            .map(|s| (Va(s.va_start), s.va_end - s.va_start))
    }

    /// Load and parse a PE file, building the section map and symbol tables.
    pub fn load(path: &Path) -> Result<Self, SourceError> {
        let bytes = std::fs::read(path)
            .map_err(|e| SourceError::Load(format!("read '{}': {e}", path.display())))?;
        let pe = PE::parse(&bytes)
            .map_err(|e| SourceError::Load(format!("parse '{}': {e}", path.display())))?;

        // 64-bit (PE32+, magic 0x20b) vs 32-bit (PE32, 0x10b). This drives the
        // whole pipeline's bitness: decoding a PE32 with the x86-64 decoder
        // desyncs at the first differently-encoded opcode (`A1 mov moffs`: 4
        // address bytes vs 8) and yields confident garbage. The frontend reads
        // this to select the 32-bit (`X64::x86`) arch and the `cdecl` ABI, so a
        // PE32 decodes correctly instead of being mis-read as x64 — no longer a
        // load-time rejection, now a first-class (if register-arg-conservative)
        // target.
        let is_64 = pe.is_64;

        let oh = pe
            .header
            .optional_header
            .ok_or_else(|| SourceError::Load("PE has no optional header".into()))?;
        let image_base = oh.windows_fields.image_base;
        let size_of_image = oh.windows_fields.size_of_image as u64;
        let size_of_headers = oh.windows_fields.size_of_headers as u64;

        let module_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("module")
            .to_string();

        let mut sections = Vec::with_capacity(pe.sections.len() + 1);
        // The PE headers (DOS + NT + section table) map at the image base in a
        // real process but aren't one of the enumerated sections. Serve them as
        // a pseudo-section (RVA 0 → file offset 0) so header-driven passes
        // (`.pdata`/exception-table discovery, section walks) read identically
        // on a static image and a live module — the whole point of the seam.
        if size_of_headers > 0 {
            sections.push(SectionRange {
                name: String::new(),
                va_start: image_base,
                va_end: image_base.saturating_add(size_of_headers),
                file_offset: 0,
                file_size: size_of_headers as usize,
                executable: false,
            });
        }
        for s in &pe.sections {
            let name = s
                .name()
                .map(|n| n.trim_end_matches('\0').to_string())
                .unwrap_or_default();
            let rva = s.virtual_address as u64;
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
                executable: s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
            });
        }

        let mut exports: BTreeMap<u64, Symbol> = BTreeMap::new();
        for export in &pe.exports {
            if let Some(name) = export.name {
                let va = image_base.saturating_add(export.rva as u64);
                exports.insert(
                    va,
                    Symbol {
                        va: Va(va),
                        module: module_name.clone(),
                        name: name.to_string(),
                        kind: SymKind::Export,
                    },
                );
            }
        }

        let mut iat: BTreeMap<u64, Symbol> = BTreeMap::new();
        for import in &pe.imports {
            // The IAT **slot** RVA is goblin's `Import::offset` — despite the
            // name it is an RVA (`import_address_table_rva + i * word_size`),
            // not a file offset. `Import::rva` is the hint/name-table entry
            // (the `IMAGE_IMPORT_BY_NAME` struct), which is *not* what a
            // `call qword ptr [rip+disp]` points at — keying this map by it
            // meant no real import call ever resolved a name, silently
            // defeating every analysis that depends on callee names
            // (noreturn-call CFG closure, thunk tail calls, known-API
            // signatures). Ordinal-only imports have no hint/name entry at
            // all, so they were doubly invisible; they resolve fine here.
            let slot_va = image_base.saturating_add(import.offset as u64);
            let dll = import.dll.trim_end_matches('\0');
            let dll_short = Path::new(dll)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(dll)
                .to_string();
            iat.insert(
                slot_va,
                Symbol {
                    va: Va(slot_va),
                    module: dll_short,
                    name: import.name.to_string(),
                    kind: SymKind::Import,
                },
            );
        }

        let modules = vec![Module {
            name: module_name.clone(),
            base: Va(image_base),
            size: size_of_image,
            path: Some(path.to_string_lossy().to_string()),
        }];

        Ok(StaticPe {
            bytes,
            image_base,
            module_name,
            modules,
            sections,
            exports,
            iat,
            is_64,
        })
    }

    /// `true` for a 64-bit PE32+, `false` for a 32-bit PE32. The frontend uses
    /// this to pick the decoder bitness / arch.
    pub fn is_64(&self) -> bool {
        self.is_64
    }

    /// Native pointer size in bytes (8 for PE32+, 4 for PE32).
    pub fn pointer_size(&self) -> u8 {
        if self.is_64 { 8 } else { 4 }
    }

    fn section_for(&self, va: u64) -> Option<&SectionRange> {
        self.sections.iter().find(|s| va >= s.va_start && va < s.va_end)
    }

    /// The exported functions, address-ordered — the `(va, name)` list a
    /// signature generator fingerprints. A static CRT `.lib` linked into a DLL
    /// that re-exports it is one bootstrap source for a signature library.
    pub fn named_functions(&self) -> Vec<(Va, String)> {
        self.exports.values().map(|s| (s.va, s.name.clone())).collect()
    }
}

impl MemorySource for StaticPe {
    fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, SourceError> {
        let Some(section) = self.section_for(va.0) else {
            return Err(SourceError::Unmapped(va));
        };
        let in_section = (va.0 - section.va_start) as usize;
        // Inside a section but past its raw data (BSS-style tail): not synthesized
        // — a short read, exactly as a live RPM at the same spot would give.
        if in_section >= section.file_size {
            return Ok(Vec::new());
        }
        let file_start = section.file_offset + in_section;
        let avail = section.file_size - in_section;
        let take = len.min(avail);
        let end = (file_start + take).min(self.bytes.len());
        if file_start >= end {
            return Ok(Vec::new());
        }
        Ok(self.bytes[file_start..end].to_vec())
    }

    fn contains(&self, va: Va) -> bool {
        self.section_for(va.0).is_some()
    }

    fn code_range(&self) -> Option<(Va, u64)> {
        self.text_range()
    }

    /// Every section the image marks executable, in address order — not just
    /// `.text`. On a Unity IL2CPP build that is the difference between covering
    /// 10 % of the code and covering all of it.
    fn code_ranges(&self) -> Vec<(Va, u64)> {
        let mut out: Vec<(Va, u64)> =
            self.sections.iter().filter(|s| s.executable && s.va_end > s.va_start).map(|s| (Va(s.va_start), s.va_end - s.va_start)).collect();
        out.sort_by_key(|(va, _)| va.0);
        out
    }

    fn label(&self) -> String {
        format!("static:{}", self.module_name)
    }
    fn abi_name(&self) -> &'static str {
        // 64-bit PE → Win64 register ABI; 32-bit PE → cdecl (stack-based args).
        if self.is_64 { "win64" } else { "cdecl" }
    }
}

impl SymbolProvider for StaticPe {
    fn symbol_at(&self, va: Va) -> Option<Symbol> {
        self.exports.get(&va.0).cloned()
    }
    fn iat_slot(&self, va: Va) -> Option<Symbol> {
        self.iat.get(&va.0).cloned()
    }
}

impl ModuleProvider for StaticPe {
    fn modules(&self) -> &[Module] {
        &self.modules
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Build a syntactically minimal PE whose optional-header `magic` selects
    /// PE32 (`0x10b`) or PE32+ (`0x20b`) — enough for `goblin` to set `is_64`,
    /// with no sections. Just the bytes the bitness guard keys on.
    fn minimal_pe(magic: u16) -> Vec<u8> {
        let opt_size: u16 = if magic == 0x20b { 240 } else { 224 };
        let mut b = vec![0u8; 0x58 + opt_size as usize + 16];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes()); // e_lfanew -> PE header
        b[0x40..0x44].copy_from_slice(b"PE\0\0");
        let machine: u16 = if magic == 0x20b { 0x8664 } else { 0x14c };
        b[0x44..0x46].copy_from_slice(&machine.to_le_bytes()); // machine
        // num_sections = 0, timestamp/symtab/num_symbols = 0
        b[0x54..0x56].copy_from_slice(&opt_size.to_le_bytes()); // size_of_optional_header
        b[0x56..0x58].copy_from_slice(&0x102u16.to_le_bytes()); // characteristics (executable)
        b[0x58..0x5a].copy_from_slice(&magic.to_le_bytes()); // optional-header magic
        b
    }

    fn temp(tag: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("n0xis_static_pe_{}_{}.bin", std::process::id(), tag));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn a_pe32_loads_and_reports_32bit_so_the_frontend_picks_the_i386_arch() {
        // The bitness must be detected and surfaced (not rejected): the frontend
        // keys on it to select the 32-bit decoder, which is what stops a PE32
        // from being silently mis-decoded as x64. `is_64 == false`, 4-byte
        // pointers, and a `cdecl` ABI.
        let p = temp("pe32", &minimal_pe(0x10b));
        let pe = StaticPe::load(&p).expect("a PE32 now loads");
        assert!(!pe.is_64(), "a PE32 must report 32-bit");
        assert_eq!(pe.pointer_size(), 4);
        assert_eq!(MemorySource::abi_name(&pe), "cdecl");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_pe32plus_reports_64bit_and_win64() {
        let p = temp("pe32plus", &minimal_pe(0x20b));
        let pe = StaticPe::load(&p).expect("a PE32+ loads");
        assert!(pe.is_64());
        assert_eq!(pe.pointer_size(), 8);
        assert_eq!(MemorySource::abi_name(&pe), "win64");
        let _ = std::fs::remove_file(&p);
    }
}
