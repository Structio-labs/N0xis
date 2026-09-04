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

/// The two dynamic-relocation types that bind a **GOT slot** to an imported
/// symbol, per architecture: `(GLOB_DAT, JUMP_SLOT)`.
///
/// `JUMP_SLOT` is the classic lazily-bound PLT entry; `GLOB_DAT` is the slot
/// `-fno-plt` / `-z now` code calls through *directly*
/// (`call qword ptr [rip+disp]`) — the dominant shape in modern distro builds
/// (`libQt6Core.so.6` has no `.plt` at all), so recognizing only `JUMP_SLOT`
/// would miss the majority of real import calls. Everything else in
/// `.rela.dyn` (`RELATIVE`, `64`, `COPY`, `IRELATIVE`, TLS) either has no
/// symbol or does not name a callable slot.
fn got_reloc_types(e_machine: u16) -> Option<(u32, u32)> {
    match e_machine {
        // x86-64 and i386 share the numbering: GLOB_DAT 6, JUMP_SLOT 7.
        0x3E | 0x03 => Some((6, 7)),
        0xB7 => Some((1025, 1026)), // AArch64
        0x28 => Some((21, 22)),     // ARM (32-bit)
        _ => None,
    }
}

/// Module name recorded for an import whose provider library cannot be
/// determined (the binary carries no `.gnu.version_r` entry for it). ELF
/// resolution is a *flat* namespace, so an unversioned import genuinely has no
/// named provider — this says so instead of guessing one from `DT_NEEDED`.
const UNKNOWN_PROVIDER: &str = "extern";

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
    /// Imported symbols keyed by the **GOT slot** that holds them — the ELF
    /// twin of the PE IAT map. This is what a `call qword ptr [rip+disp]`
    /// points at, so it is the map [`SymbolProvider::iat_slot`] answers from.
    got: BTreeMap<u64, Symbol>,
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

        // --- Imports: GOT slot -> imported symbol (the ELF twin of the PE IAT) ---
        //
        // A dynamic relocation of type GLOB_DAT/JUMP_SLOT stores "the address of
        // symbol S" into the slot at `r_offset`; the loader fills it. So the
        // slot address is exactly what an indirect call goes *through*, and the
        // relocation's symbol is the callee's name. Without this map every
        // import call decompiled as `(**(uint64_t*)(0x6e1a78))(…)` — and, worse,
        // silently defeated everything keyed on a callee *name*: the known-API
        // signature table, thunk/tail-call recognition, and noreturn CFG
        // closure. (The same class of bug the PE side hit in 2026-08 by keying
        // its IAT map on the wrong RVA.)
        let mut got: BTreeMap<u64, Symbol> = BTreeMap::new();
        if let Some((glob_dat, jump_slot)) = got_reloc_types(elf.header.e_machine) {
            // Symbol-version index -> the library that is expected to provide it
            // (`.gnu.version_r`: `getenv@GLIBC_2.2.5` -> `libc.so.6`). This is the
            // only per-symbol provider attribution an ELF carries; binding is
            // flat at run time, so it is informative, not authoritative.
            let mut provider: BTreeMap<u16, String> = BTreeMap::new();
            if let Some(verneed) = elf.verneed.as_ref() {
                for need in verneed.iter() {
                    let Some(file) = elf.dynstrtab.get_at(need.vn_file) else { continue };
                    for aux in need.iter() {
                        provider.insert(aux.vna_other, file.to_string());
                    }
                }
            }

            let mut add = |reloc: &goblin::elf::Reloc| {
                if reloc.r_type != glob_dat && reloc.r_type != jump_slot {
                    return;
                }
                let Some(sym) = elf.dynsyms.get(reloc.r_sym) else { return };
                // `st_shndx == SHN_UNDEF` is what makes it an *import*. A
                // GLOB_DAT against a symbol this image defines itself is the
                // linker routing an internal reference through the GOT (PIE
                // interposition) — naming it `extern!foo` would be a lie, and
                // `symbol_at` already names it correctly at its real address.
                if sym.st_shndx != 0 {
                    return;
                }
                let Some(name) = elf.dynstrtab.get_at(sym.st_name) else { return };
                if name.is_empty() {
                    return;
                }
                let module = elf
                    .versym
                    .as_ref()
                    .and_then(|vs| vs.get_at(reloc.r_sym))
                    .and_then(|v| provider.get(&v.version()).cloned())
                    .unwrap_or_else(|| UNKNOWN_PROVIDER.to_string());
                let slot = Va(reloc.r_offset);
                got.insert(reloc.r_offset, Symbol { va: slot, module, name: name.to_string(), kind: SymKind::Import });
            };
            for r in elf.pltrelocs.iter() {
                add(&r);
            }
            for r in elf.dynrelas.iter() {
                add(&r);
            }
            for r in elf.dynrels.iter() {
                add(&r);
            }
        }

        // --- PLT stubs: name the *stub* after the import it jumps to ---
        //
        // With lazy binding (the default, and what a stripped ELF executable
        // almost always uses) a call to an import is a **direct** `call` to a
        // PLT stub, not an indirect call through the GOT — so `iat_slot` above
        // never sees it and the callee stays `sub_1030`. other tools name the
        // stub after its import for exactly this reason; so do we, which makes
        // one entry in `symbols` serve every consumer at once (discovery list,
        // xref, decompiler) instead of each re-deriving the thunk.
        //
        // Every x86-64 PLT variant contains exactly one `jmp qword ptr
        // [rip+disp]` (`FF 25`) whose target is the import's GOT slot, so the
        // stub is identified by that instruction rather than by assuming an
        // entry size: `.plt` entries are 16 bytes, `.plt.got` are 8, and
        // `.plt.sec` prefixes an `endbr64`. **The match is self-validating** —
        // the slot must already be in the import map built above, which is what
        // keeps `.plt`'s resolver stub (PLT0, whose `jmp` goes through
        // `GOT+0x10`, not a symbol) and any non-PLT `FF 25` out.
        if elf.header.e_machine == 0x3E {
            for sec in sections.iter().filter(|s| s.executable && s.name.starts_with(".plt") && s.file_size > 0) {
                let bytes = &bytes[sec.file_offset..(sec.file_offset + sec.file_size).min(bytes.len())];
                let mut i = 0usize;
                while i + 6 <= bytes.len() {
                    if bytes[i] != 0xFF || bytes[i + 1] != 0x25 {
                        i += 1;
                        continue;
                    }
                    let disp = i32::from_le_bytes([bytes[i + 2], bytes[i + 3], bytes[i + 4], bytes[i + 5]]);
                    // RIP is the address of the *next* instruction (`FF 25` + rel32 = 6 bytes).
                    let jmp_va = sec.va_start + i as u64;
                    let slot = jmp_va.wrapping_add(6).wrapping_add(disp as i64 as u64);
                    let Some(sym) = got.get(&slot) else {
                        i += 1;
                        continue;
                    };
                    // Back up over the prefixes the IBT/MPX variants put in
                    // front of the jump, so the recorded address is the one a
                    // `call` actually targets — the entry's first byte.
                    let mut start = i;
                    if start > 0 && bytes[start - 1] == 0xF2 {
                        start -= 1; // `bnd` prefix (`-z now` + `.plt.sec`)
                    }
                    if start >= 4 && bytes[start - 4..start] == [0xF3, 0x0F, 0x1E, 0xFA] {
                        start -= 4; // `endbr64` (CET)
                    }
                    let stub_va = sec.va_start + start as u64;
                    // A real symbol for this address (an unstripped `foo@plt`)
                    // always wins; this only fills a hole.
                    symbols.entry(stub_va).or_insert_with(|| Symbol {
                        va: Va(stub_va),
                        module: sym.module.clone(),
                        name: sym.name.clone(),
                        kind: SymKind::Import,
                    });
                    i += 6;
                }
            }
        }

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

        Ok(StaticElf { bytes, image_base, module_name, modules, sections, symbols, got })
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
    /// The imported symbol a GOT slot resolves to. Named `iat_slot` for the PE
    /// term the trait was born with; on ELF the same seam is the GOT, and the
    /// consumers (`ir::resolved_target_name`, thunk recognition, the known-API
    /// and noreturn tables) are format-neutral.
    fn iat_slot(&self, va: Va) -> Option<Symbol> {
        self.got.get(&va.0).cloned()
    }
}

impl ModuleProvider for StaticElf {
    fn modules(&self) -> &[Module] {
        &self.modules
    }
}
