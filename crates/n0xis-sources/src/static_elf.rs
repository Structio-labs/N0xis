// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`StaticElf`] — a file-backed ELF [`MemorySource`] (+ symbols + module),
//! the ELF twin of [`StaticPe`](crate::StaticPe).
//!
//! Loads an ELF (executable or PIE shared object) from disk and exposes it
//! through the same seams a live process uses: [`read`](MemorySource::read)
//! translates a virtual address back to a file offset via the section table
//! (at the image's preferred base), and defined function symbols from
//! `.symtab`/`.dynsym` are surfaced through [`SymbolProvider`]. So the whole
//! "one pipeline, live + static" property extends to Linux-native binaries —
//! Bevy/Rust, GCC/System V, Godot — not just PE.
//!
//! Scope: static code + symbols. DWARF type/line recovery (`.debug_info`) is a
//! documented follow-on; a not-stripped ELF still yields real function names
//! here, which is the bulk of the readability win.

use std::collections::BTreeMap;
use std::path::Path;

use goblin::elf::Elf;
use n0xis_contracts::{Module, SymKind, Symbol, Va};

use crate::{MemorySource, ModuleProvider, SourceError, SymbolProvider};

/// `SHF_EXECINSTR` — the section holds executable machine code.
const SHF_EXECINSTR: u64 = 0x4;
/// `SHT_NOBITS` — occupies no file space (`.bss`); reads short, like a PE BSS tail.
const SHT_NOBITS: u32 = 8;
/// `STT_FUNC` — the symbol names a function.
const STT_FUNC: u8 = 2;
/// `STT_OBJECT` — the symbol names a data object (a global / static variable).
const STT_OBJECT: u8 = 1;
/// `PT_LOAD` — a loadable segment; the minimum `p_vaddr` is the preferred base.
const PT_LOAD: u32 = 1;

#[derive(Debug, Clone)]
struct SectionRange {
    name: String,
    va_start: u64,
    va_end: u64,
    file_offset: usize,
    file_size: usize,
    executable: bool,
}

/// An ELF image on disk, mapped at its preferred base.
#[derive(Debug)]
pub struct StaticElf {
    bytes: Vec<u8>,
    image_base: u64,
    module_name: String,
    modules: Vec<Module>,
    sections: Vec<SectionRange>,
    /// Defined function symbols, keyed by virtual address.
    symbols: BTreeMap<u64, Symbol>,
}

impl StaticElf {
    /// Preferred image base: the minimum `PT_LOAD` virtual address (0 for a
    /// position-independent executable, the first segment's `p_vaddr` for a
    /// classic `ET_EXEC`).
    pub fn image_base(&self) -> Va {
        Va(self.image_base)
    }

    /// The single module descriptor for this image.
    pub fn module(&self) -> &Module {
        &self.modules[0]
    }

    /// Virtual address range of the `.text` section `(start, size)`.
    pub fn text_range(&self) -> Option<(Va, u64)> {
        self.section_range(".text")
    }

    /// Every section that carries on-disk bytes, as `(name, va, size)` — the
    /// ranges a byte/string search (`find`) can read. `SHT_NOBITS` (`.bss`) is
    /// skipped (it has no file bytes); the readable size is the on-disk size.
    pub fn sections(&self) -> Vec<(String, Va, u64)> {
        self.sections
            .iter()
            .filter(|s| s.file_size > 0)
            .map(|s| (s.name.clone(), Va(s.va_start), s.file_size as u64))
            .collect()
    }

    /// Virtual address range of a named section `(start, size)`.
    /// Defined data/object symbols (`STT_OBJECT`) — where an ELF keeps its C++
    /// vtables (`_ZTV…`) and type-info objects (`_ZTI…`). [`Self::named_functions`]
    /// deliberately excludes these; Itanium RTTI recovery needs exactly them.
    pub fn data_symbols(&self) -> Vec<(Va, String)> {
        self.symbols.values().filter(|s| s.kind == SymKind::Data).map(|s| (s.va, s.name.clone())).collect()
    }

    /// Every section with its `SHF_EXECINSTR` flag — the shape `profile` needs.
    ///
    /// Separate from [`Self::sections`] (which `find` uses to bound a byte
    /// search and therefore wants only file-backed ranges) because a profile
    /// must report the section table as it is, executability included: `.text`
    /// is not always where the code lives.
    pub fn sections_detailed(&self) -> Vec<(String, Va, u64, bool)> {
        self.sections
            .iter()
            .map(|s| (s.name.clone(), Va(s.va_start), s.va_end.saturating_sub(s.va_start), s.executable))
            .collect()
    }

    /// The ELF `e_machine`, mapped onto the same names the PE profile reports
    /// (`x64`, `arm64`, …) so one consumer reads both formats. An unrecognized
    /// or big-endian machine is returned as raw hex rather than guessed into a
    /// wrong name.
    pub fn machine(&self) -> String {
        // e_ident[EI_DATA] = 1 little-endian, 2 big-endian; e_machine at 0x12.
        let Some(raw) = self.bytes.get(0x12..0x14) else { return "unknown".to_string() };
        let em = match self.bytes.get(5) {
            Some(1) => u16::from_le_bytes([raw[0], raw[1]]),
            Some(2) => u16::from_be_bytes([raw[0], raw[1]]),
            _ => return "unknown".to_string(),
        };
        match em {
            0x3E => "x64".to_string(),
            0xB7 => "arm64".to_string(),
            0x03 => "x86".to_string(),
            0x28 => "arm".to_string(),
            other => format!("0x{other:x}"),
        }
    }

    pub fn section_range(&self, name: &str) -> Option<(Va, u64)> {
        self.sections.iter().find(|s| s.name == name).map(|s| (Va(s.va_start), s.va_end - s.va_start))
    }

    /// Load and parse an ELF file, building the section map and symbol table.
    pub fn load(path: &Path) -> Result<Self, SourceError> {
        let bytes = std::fs::read(path).map_err(|e| SourceError::Load(format!("read '{}': {e}", path.display())))?;
        let elf = Elf::parse(&bytes).map_err(|e| SourceError::Load(format!("parse '{}': {e}", path.display())))?;

        let module_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("module").to_string();

        // Preferred base = min PT_LOAD p_vaddr. A PIE loads at 0, so its VAs are
        // already the section vaddrs; a fixed ET_EXEC keeps its absolute vaddrs.
        let image_base = elf.program_headers.iter().filter(|ph| ph.p_type == PT_LOAD).map(|ph| ph.p_vaddr).min().unwrap_or(0);

        // Allocated sections carry the memory layout (like PE sections). An
        // unallocated section (sh_addr == 0: debug info, symbol tables) isn't
        // part of the address space and is skipped for `read`.
        let mut sections = Vec::with_capacity(elf.section_headers.len());
        for sh in &elf.section_headers {
            if sh.sh_addr == 0 {
                continue;
            }
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
            let va_start = sh.sh_addr;
            let va_end = va_start.saturating_add(sh.sh_size);
            // A NOBITS (.bss) section occupies no file bytes — reads inside it
            // return short, exactly as a live read of zero-initialized memory.
            let file_size = if sh.sh_type == SHT_NOBITS { 0 } else { sh.sh_size as usize };
            sections.push(SectionRange {
                name,
                va_start,
                va_end,
                file_offset: sh.sh_offset as usize,
                file_size,
                executable: sh.sh_flags & SHF_EXECINSTR != 0,
            });
        }

        // Defined function symbols from `.symtab` (full, when not stripped) and
        // `.dynsym` (exported dynamic symbols; the only ones on a stripped ELF).
        // A symbol with `st_value == 0` or `st_shndx == SHN_UNDEF` is an import
        // reference, not a definition — skip it.
        let mut symbols: BTreeMap<u64, Symbol> = BTreeMap::new();
        let mut collect = |syms: &goblin::elf::Symtab, strtab: &goblin::strtab::Strtab| {
            for sym in syms.iter() {
                // Functions become named code targets; data objects (globals /
                // statics) become named data references (`&crc_table`). A symbol
                // with `st_value == 0` or `st_shndx == SHN_UNDEF` is an import
                // reference, not a definition — skip it.
                let kind = match sym.st_type() {
                    STT_FUNC => SymKind::Export,
                    STT_OBJECT => SymKind::Data,
                    _ => continue,
                };
                if sym.st_value == 0 || sym.st_shndx == 0 {
                    continue;
                }
                let Some(name) = strtab.get_at(sym.st_name) else { continue };
                if name.is_empty() {
                    continue;
                }
                symbols.entry(sym.st_value).or_insert_with(|| Symbol {
                    va: Va(sym.st_value),
                    module: module_name.clone(),
                    name: name.to_string(),
                    kind,
                });
            }
        };
        collect(&elf.syms, &elf.strtab);
        collect(&elf.dynsyms, &elf.dynstrtab);

        // Image size: span from the base to the end of the last loadable segment.
        let size = elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .map(|ph| ph.p_vaddr.saturating_add(ph.p_memsz))
            .max()
            .unwrap_or(0)
            .saturating_sub(image_base);

        let modules = vec![Module { name: module_name.clone(), base: Va(image_base), size, path: Some(path.to_string_lossy().to_string()) }];

        Ok(StaticElf { bytes, image_base, module_name, modules, sections, symbols })
    }

    fn section_for(&self, va: u64) -> Option<&SectionRange> {
        self.sections.iter().find(|s| va >= s.va_start && va < s.va_end)
    }

    /// The defined function symbols (`.symtab`/`.dynsym`), address-ordered — the
    /// `(va, name)` list a signature generator fingerprints. Empty on a stripped
    /// binary, which is exactly why signatures are needed in the first place.
    pub fn named_functions(&self) -> Vec<(Va, String)> {
        self.symbols.values().filter(|s| s.kind != SymKind::Data).map(|s| (s.va, s.name.clone())).collect()
    }
}

impl MemorySource for StaticElf {
    fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, SourceError> {
        let Some(section) = self.section_for(va.0) else {
            return Err(SourceError::Unmapped(va));
        };
        let in_section = (va.0 - section.va_start) as usize;
        if in_section >= section.file_size {
            return Ok(Vec::new()); // BSS-style tail: short read, not synthesized.
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

    /// Every executable section in address order (`.text`, `.plt`, `.init`, …),
    /// not just `.text` — the same breadth [`StaticPe`](crate::StaticPe) needs.
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
        "sysv" // ELF → System V AMD64.
    }
}

impl SymbolProvider for StaticElf {
    fn symbol_at(&self, va: Va) -> Option<Symbol> {
        self.symbols.get(&va.0).cloned()
    }
    fn iat_slot(&self, _va: Va) -> Option<Symbol> {
        // ELF import resolution goes through the PLT/GOT; not yet mapped here
        // (a documented follow-on, like DWARF). No slot naming for now.
        None
    }
}

impl ModuleProvider for StaticElf {
    fn modules(&self) -> &[Module] {
        &self.modules
    }
}
