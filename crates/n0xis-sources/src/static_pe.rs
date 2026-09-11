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
    /// `.pdata` `RUNTIME_FUNCTION` entries: begin VA → exclusive end VA.
    /// A PE's stated function extents — see [`StaticPe::symbol_size`].
    pdata: BTreeMap<u64, u64>,
    /// `Some(reason)` when a strict parse refused this image and it was opened
    /// permissively — so a caller can say "the import table did not parse"
    /// instead of reporting an empty one as fact. See [`StaticPe::load`].
    degraded: Option<String>,
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
        // A strict parse first, then a permissive one. An RE target is often
        // exactly the image a strict parser refuses — packed, self-modifying,
        // or carrying a deliberately hostile import table — and refusing to
        // open it at all is the wrong answer for a tool whose job is to look at
        // it. goblin's permissive mode recovers what it can; what it cannot
        // parse (usually the imports) simply comes back empty, which every
        // consumer already handles. `degraded` records that this happened so
        // nothing downstream reports an empty import table as a fact.
        let (pe, degraded) = match PE::parse(&bytes) {
            Ok(pe) => (pe, None),
            Err(strict) => {
                let mut opts = goblin::pe::options::ParseOptions::default();
                opts.parse_mode = goblin::options::ParseMode::Permissive;
                match PE::parse_with_opts(&bytes, &opts) {
                    Ok(pe) => (pe, Some(strict.to_string())),
                    Err(e) => {
                        return Err(SourceError::Load(format!("parse '{}': {e}", path.display())));
                    }
                }
            }
        };

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

        // Exports **by ordinal** have no name, and the parser only yields named
        // ones — so on this corpus 853 of 1216 exported functions were invisible
        // to symbol resolution, discovery and cross-references alike. A DLL that
        // exports mostly by ordinal is not unusual; it is the norm for system
        // and shipped-game libraries. The export address table states them, so
        // it is read here directly.
        for (va, ordinal) in ordinal_exports(&bytes, &sections, image_base) {
            exports.entry(va).or_insert_with(|| Symbol {
                va: Va(va),
                module: module_name.clone(),
                // The file gives an ordinal, not a name; say exactly that
                // rather than inventing one that looks like a symbol.
                name: format!("Ordinal{ordinal}"),
                kind: SymKind::Export,
            });
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

        let pdata = parse_pdata(&bytes, &sections, image_base);

        Ok(StaticPe {
            bytes,
            image_base,
            module_name,
            modules,
            sections,
            exports,
            iat,
            is_64,
            pdata,
            degraded,
        })
    }

    /// Why a strict parse refused this image, when it had to be opened
    /// permissively. `None` on a well-formed PE.
    pub fn degraded(&self) -> Option<&str> {
        self.degraded.as_deref()
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

    /// The addresses this image **declares** as entry points: every named
    /// export that lands in an executable section.
    ///
    /// A PE for i386 has no `.pdata`, so exports are the only thing the file
    /// states about where its functions begin — and discovery was not using
    /// them. Measured on a 32-bit system DLL: 6 of 422 exported entry points
    /// were missed, and two of those were reported five bytes into the
    /// function, because the hot-patch prologue `mov edi,edi; push ebp; mov
    /// ebp,esp` is not in the scanned pattern set. A declaration beats a
    /// pattern; this is the declaration.
    ///
    /// Forwarders (`KERNEL32.HeapAlloc`) point inside the export directory
    /// rather than at code, and are excluded by the executable-section test.
    pub fn export_entry_points(&self) -> Vec<Va> {
        self.exports
            .keys()
            .copied()
            .filter(|va| self.sections.iter().any(|s| s.executable && *va >= s.va_start && *va < s.va_end))
            .map(Va)
            .collect()
    }

    /// The COFF `Machine` field, mapped onto the same names `StaticElf::machine`
    /// reports so one consumer reads both formats. An unrecognized machine is
    /// returned as raw hex rather than guessed into a wrong name — a wrong
    /// answer here silently decodes one instruction set as another.
    pub fn machine(&self) -> String {
        let rd = |o: usize| -> Option<u16> {
            self.bytes.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
        };
        let Some(e_lfanew) = self.bytes.get(0x3c..0x40).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
        else {
            return "unknown".to_string();
        };
        if self.bytes.get(e_lfanew..e_lfanew + 4) != Some(&b"PE\0\0"[..]) {
            return "unknown".to_string();
        }
        match rd(e_lfanew + 4) {
            Some(0x8664) => "x64".to_string(),
            Some(0x014c) => "x86".to_string(),
            Some(0xAA64) => "arm64".to_string(),
            Some(0x01c0 | 0x01c4) => "arm".to_string(),
            Some(other) => format!("0x{other:x}"),
            None => "unknown".to_string(),
        }
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
    /// `.text`. On an IL2CPP build that is the difference between covering
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
    /// A PE states a function's extent in `.pdata`, not in a symbol table:
    /// each `RUNTIME_FUNCTION` carries `BeginAddress`/`EndAddress`. That is as
    /// authoritative as an ELF `st_size` and it is what the CFG builder needs
    /// to stop walking — without it a `jmp` to another function reads as an
    /// intra-function branch and the extent swallows everything in between.
    ///
    /// Only an exact hit on `BeginAddress` answers. A leaf function with no
    /// unwind info has no entry, and the caller falls back to the heuristic.
    fn symbol_size(&self, va: Va) -> Option<u64> {
        self.pdata.get(&va.0).map(|end| end.saturating_sub(va.0))
    }
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


/// Read the `.pdata` exception table into `begin VA → exclusive end VA`.
///
/// The table is found through the optional header's exception data directory
/// (index 3), and each `RUNTIME_FUNCTION` is three RVAs: begin, end, unwind.
/// Every bound comes from the bytes actually present — nothing is sized from a
/// value read out of the file — so a truncated or hostile table yields a short
/// map rather than a large allocation.
///
/// Absent (`0` RVA, no unwind info, 32-bit PE, ARM64's different record shape)
/// leaves the map empty, which is exactly the previous behaviour.
/// Every exported RVA the export address table lists, paired with its ordinal.
///
/// Named exports are already covered by the parsed export list; this exists for
/// the ones with no name at all, which that list omits entirely. Forwarders
/// (`KERNEL32.HeapAlloc`) are excluded: their "RVA" points inside the export
/// directory at a string, not at code.
///
/// Every count here comes out of the file, so every count is bounded by what
/// the file can physically hold before it is used for anything.
fn ordinal_exports(bytes: &[u8], sections: &[SectionRange], image_base: u64) -> Vec<(u64, u32)> {
    // Every step below is "the header may simply not be there"; a missing field
    // means no ordinal exports, never an error and never a guess.
    read_ordinal_exports(bytes, sections, image_base).unwrap_or_default()
}

fn read_ordinal_exports(bytes: &[u8], sections: &[SectionRange], image_base: u64) -> Option<Vec<(u64, u32)>> {
    let mut out = Vec::new();
    let rd32 = |off: usize| -> Option<u32> {
        bytes.get(off..off + 4).map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
    };
    let rd16 = |off: usize| -> Option<u16> {
        bytes.get(off..off + 2).map(|b| u16::from_le_bytes(b.try_into().expect("2 bytes")))
    };
    let rva_to_off = |rva: u64| -> Option<usize> {
        let va = image_base.checked_add(rva)?;
        let s = sections.iter().find(|s| va >= s.va_start && va < s.va_end)?;
        let inside = (va - s.va_start) as usize;
        (inside < s.file_size).then(|| s.file_offset + inside)
    };

    let e_lfanew = rd32(0x3c)? as usize;
    if bytes.get(e_lfanew..e_lfanew + 4) != Some(&b"PE\0\0"[..]) {
        return None;
    }
    // The export directory is entry 0 of the data directory, which sits at +96
    // in a PE32 optional header and +112 in a PE32+ one.
    let magic = rd16(e_lfanew + 24)?;
    let dd = e_lfanew + 24 + if magic == 0x10b { 96 } else { 112 };
    let (dir_rva, dir_size) = (rd32(dd)? as u64, rd32(dd + 4)? as u64);
    if dir_rva == 0 || dir_size == 0 {
        return None;
    }
    let dir = rva_to_off(dir_rva)?;

    let ordinal_base = rd32(dir + 16)?;
    let count = rd32(dir + 20)? as usize;
    let addr_table = rd32(dir + 28)? as u64;
    let table = rva_to_off(addr_table)?;
    // `NumberOfFunctions` is a number in an untrusted file: cap it at the
    // entries the table could actually contain before it sizes anything.
    let count = count.min(bytes.len().saturating_sub(table) / 4);
    out.reserve(count.min(1 << 16));

    for i in 0..count {
        let Some(rva) = rd32(table + i * 4) else { break };
        if rva == 0 {
            continue; // an unused ordinal slot
        }
        let rva = rva as u64;
        // A forwarder's RVA lands inside the export directory itself.
        if rva >= dir_rva && rva < dir_rva + dir_size {
            continue;
        }
        let Some(va) = image_base.checked_add(rva) else { continue };
        if !sections.iter().any(|s| s.executable && va >= s.va_start && va < s.va_end) {
            continue; // a data export, not an entry point
        }
        out.push((va, ordinal_base.wrapping_add(i as u32)));
    }
    Some(out)
}

fn parse_pdata(bytes: &[u8], sections: &[SectionRange], image_base: u64) -> BTreeMap<u64, u64> {
    let mut out = BTreeMap::new();
    let rd32 = |off: usize| -> Option<u32> {
        bytes.get(off..off + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    let Some(e_lfanew) = rd32(0x3c).map(|v| v as usize) else { return out };
    if bytes.get(e_lfanew..e_lfanew + 4) != Some(&b"PE\0\0"[..]) {
        return out;
    }
    // IMAGE_NT_HEADERS64: signature(4) + IMAGE_FILE_HEADER(20) puts the optional
    // header at e_lfanew+24; its PE32+ DataDirectory array starts at offset 112,
    // and entry 3 is IMAGE_DIRECTORY_ENTRY_EXCEPTION.
    let magic = rd32(e_lfanew + 24).map(|v| (v & 0xffff) as u16);
    if magic != Some(0x20b) {
        return out; // PE32 has no RUNTIME_FUNCTION table in this shape
    }
    let dir = e_lfanew + 24 + 112 + 3 * 8;
    let (Some(rva), Some(size)) = (rd32(dir), rd32(dir + 4)) else { return out };
    if rva == 0 || size == 0 {
        return out;
    }
    let va = image_base.saturating_add(rva as u64);
    let Some(sec) = sections.iter().find(|s| va >= s.va_start && va < s.va_end) else {
        return out;
    };
    let in_sec = (va - sec.va_start) as usize;
    if in_sec >= sec.file_size {
        return out;
    }
    let start = sec.file_offset + in_sec;
    let avail = (sec.file_size - in_sec).min(size as usize);
    let end = (start + avail).min(bytes.len());
    let table = match bytes.get(start..end) {
        Some(t) => t,
        None => return out,
    };
    let mut off = 0usize;
    while off + 12 <= table.len() {
        let begin = u32::from_le_bytes(table[off..off + 4].try_into().unwrap());
        let fend = u32::from_le_bytes(table[off + 4..off + 8].try_into().unwrap());
        off += 12;
        if begin == 0 && fend == 0 {
            break; // the table's terminator
        }
        if fend <= begin {
            continue; // a malformed entry states no extent
        }
        out.insert(image_base.saturating_add(begin as u64), image_base.saturating_add(fend as u64));
    }
    out
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

    /// An export directory holding one named and one ordinal-only function,
    /// mapped by a single executable section — the exact shape the parser was
    /// blind to.
    #[test]
    fn an_export_with_no_name_is_still_an_entry_point() {
        let base = 0x10000000u64;
        let mut b = minimal_pe(0x10b);
        b.resize(0x2000, 0);
        // One section covering rva 0x1000.., executable, file-backed at 0x1000.
        let sections = vec![SectionRange {
            name: ".text".into(),
            va_start: base + 0x1000,
            va_end: base + 0x2000,
            file_offset: 0x1000,
            file_size: 0x1000,
            executable: true,
        }];
        // Export directory at rva 0x1100 (file 0x1100), address table at 0x1200.
        let dir_rva = 0x1100u32;
        let tbl_rva = 0x1200u32;
        let dd = 0x40 + 24 + 96; // PE32 data directory
        b[dd..dd + 4].copy_from_slice(&dir_rva.to_le_bytes());
        b[dd + 4..dd + 8].copy_from_slice(&0x80u32.to_le_bytes()); // directory size
        let dir = 0x1100usize;
        b[dir + 16..dir + 20].copy_from_slice(&1u32.to_le_bytes()); // ordinal base
        b[dir + 20..dir + 24].copy_from_slice(&4u32.to_le_bytes()); // NumberOfFunctions
        b[dir + 24..dir + 28].copy_from_slice(&1u32.to_le_bytes()); // NumberOfNames
        b[dir + 28..dir + 32].copy_from_slice(&tbl_rva.to_le_bytes());
        let tbl = 0x1200usize;
        // 0: a real function. 1: an empty slot. 2: a forwarder (points into the
        // export directory). 3: a second real function.
        b[tbl..tbl + 4].copy_from_slice(&0x1300u32.to_le_bytes());
        b[tbl + 4..tbl + 8].copy_from_slice(&0u32.to_le_bytes());
        b[tbl + 8..tbl + 12].copy_from_slice(&(dir_rva + 0x10).to_le_bytes());
        b[tbl + 12..tbl + 16].copy_from_slice(&0x1400u32.to_le_bytes());

        let got = ordinal_exports(&b, &sections, base);
        assert_eq!(
            got,
            vec![(base + 0x1300, 1), (base + 0x1400, 4)],
            "the address table lists four slots: two functions, one empty, one forwarder"
        );
    }

    /// A count read out of the file can never size an allocation.
    #[test]
    fn an_absurd_export_count_is_capped_by_the_bytes_present() {
        let base = 0x10000000u64;
        let mut b = minimal_pe(0x10b);
        b.resize(0x2000, 0);
        let sections = vec![SectionRange {
            name: ".text".into(),
            va_start: base + 0x1000,
            va_end: base + 0x2000,
            file_offset: 0x1000,
            file_size: 0x1000,
            executable: true,
        }];
        let dd = 0x40 + 24 + 96;
        b[dd..dd + 4].copy_from_slice(&0x1100u32.to_le_bytes());
        b[dd + 4..dd + 8].copy_from_slice(&0x80u32.to_le_bytes());
        let dir = 0x1100usize;
        b[dir + 16..dir + 20].copy_from_slice(&1u32.to_le_bytes());
        // NumberOfFunctions claims four billion.
        b[dir + 20..dir + 24].copy_from_slice(&u32::MAX.to_le_bytes());
        b[dir + 28..dir + 32].copy_from_slice(&0x1200u32.to_le_bytes());
        // Must return promptly with at most what the file can hold, not try to
        // reserve four billion entries.
        let got = ordinal_exports(&b, &sections, base);
        assert!(got.len() <= b.len() / 4, "the count is bounded by the bytes present");
    }

    /// A PE32+ header plus one section that maps the `.pdata` table, so
    /// `parse_pdata` can be exercised on exactly the bytes it will meet.
    fn pe_with_pdata(entries: &[(u32, u32)], declared_size: u32) -> (Vec<u8>, Vec<SectionRange>) {
        let mut b = minimal_pe(0x20b);
        let dir = 0x40 + 24 + 112 + 3 * 8;
        let table_rva = 0x1000u32;
        b[dir..dir + 4].copy_from_slice(&table_rva.to_le_bytes());
        b[dir + 4..dir + 8].copy_from_slice(&declared_size.to_le_bytes());
        let file_offset = b.len();
        for (begin, end) in entries {
            b.extend_from_slice(&begin.to_le_bytes());
            b.extend_from_slice(&end.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes()); // UnwindInfo, unread
        }
        let file_size = b.len() - file_offset;
        let sections = vec![SectionRange {
            name: ".pdata".into(),
            va_start: 0x180000000 + table_rva as u64,
            va_end: 0x180000000 + table_rva as u64 + file_size as u64,
            file_offset,
            file_size,
            executable: false,
        }];
        (b, sections)
    }

    #[test]
    fn a_pe_states_its_function_extents_in_pdata() {
        // Without this the CFG builder has no stated end on a PE and walks a
        // `jmp` into the next function, swallowing it whole.
        let (b, secs) = pe_with_pdata(&[(0x2000, 0x2100), (0x2100, 0x2180)], 24);
        let pd = parse_pdata(&b, &secs, 0x180000000);
        assert_eq!(pd.get(&0x180002000), Some(&0x180002100));
        assert_eq!(pd.get(&0x180002100), Some(&0x180002180));
        assert_eq!(pd.get(&0x180002050), None, "only an exact entry start answers");
    }

    #[test]
    fn a_pdata_size_larger_than_the_file_reads_only_what_is_there() {
        // The declared directory size is attacker-controlled data. Every bound
        // must come from the bytes present, never from the number in the file.
        let (b, secs) = pe_with_pdata(&[(0x2000, 0x2100)], 0xffff_ff00);
        let pd = parse_pdata(&b, &secs, 0x180000000);
        assert_eq!(pd.len(), 1, "one entry is all the file holds");
    }

    #[test]
    fn a_pdata_entry_that_states_no_extent_is_dropped() {
        let (b, secs) = pe_with_pdata(&[(0x2000, 0x2000), (0x2100, 0x2000), (0x2200, 0x2280)], 36);
        let pd = parse_pdata(&b, &secs, 0x180000000);
        assert_eq!(pd.keys().copied().collect::<Vec<_>>(), vec![0x180002200]);
    }

    #[test]
    fn a_pe32_has_no_runtime_function_table() {
        let p = temp("pe32_nopdata", &minimal_pe(0x10b));
        let pe = StaticPe::load(&p).expect("a PE32 loads");
        assert_eq!(pe.symbol_size(Va(0x401000)), None);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn an_image_a_strict_parse_refuses_still_opens() {
        // An RE target is often exactly the image a strict parser rejects —
        // packed, damaged, or carrying a deliberately hostile directory.
        // Refusing to open it at all is the wrong answer for a tool whose job
        // is to look at it: what did not parse comes back absent, and
        // `degraded()` says so rather than letting an unreadable import table
        // pass for an empty one.
        let mut b = minimal_pe(0x20b);
        // Import table = data directory 1; point it far outside the file.
        let dir = 0x40 + 24 + 112 + 8;
        b[dir..dir + 4].copy_from_slice(&0x0080_0000u32.to_le_bytes());
        b[dir + 4..dir + 8].copy_from_slice(&0x1000u32.to_le_bytes());
        let p = temp("permissive", &b);
        match StaticPe::load(&p) {
            Ok(pe) => {
                assert!(pe.is_64(), "the image still opens and reports its bitness");
                // Whether goblin's strict pass rejects this exact shape is its
                // business; what must hold is that a rejection is *recorded*,
                // never silently turned into an empty result.
                if let Some(why) = pe.degraded() {
                    assert!(!why.is_empty(), "a degraded parse must say what failed");
                }
            }
            Err(e) => panic!("a permissive parse should have opened this image: {e}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_well_formed_image_is_never_reported_as_degraded() {
        let p = temp("not_degraded", &minimal_pe(0x20b));
        let pe = StaticPe::load(&p).expect("a well-formed PE32+ loads");
        assert_eq!(pe.degraded(), None);
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
