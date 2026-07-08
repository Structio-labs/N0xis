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
}

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

    /// Load and parse a PE file, building the section map and symbol tables.
    pub fn load(path: &Path) -> Result<Self, SourceError> {
        let bytes = std::fs::read(path)
            .map_err(|e| SourceError::Load(format!("read '{}': {e}", path.display())))?;
        let pe = PE::parse(&bytes)
            .map_err(|e| SourceError::Load(format!("parse '{}': {e}", path.display())))?;

        let oh = pe
            .header
            .optional_header
            .ok_or_else(|| SourceError::Load("PE has no optional header".into()))?;
        let image_base = oh.windows_fields.image_base;
        let size_of_image = oh.windows_fields.size_of_image as u64;

        let module_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("module")
            .to_string();

        let mut sections = Vec::with_capacity(pe.sections.len());
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
            let slot_va = image_base.saturating_add(import.rva as u64);
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
        })
    }

    fn section_for(&self, va: u64) -> Option<&SectionRange> {
        self.sections.iter().find(|s| va >= s.va_start && va < s.va_end)
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

    fn label(&self) -> String {
        format!("static:{}", self.module_name)
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
