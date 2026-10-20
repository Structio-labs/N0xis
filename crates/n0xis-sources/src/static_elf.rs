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
//! Rust and GCC/System V C++ alike — not just PE.
//!
//! Scope: static code + symbols. DWARF type/line recovery (`.debug_info`) is a
//! documented follow-on; a not-stripped ELF still yields real function names
//! here, which is the bulk of the readability win.

use std::collections::BTreeMap;
use std::path::Path;

use goblin::elf::Elf;
use n0xis_contracts::{Module, SymKind, Symbol, Va};

use crate::{MemorySource, ModuleProvider, SourceError, SourceId, SymbolProvider};

/// `SHF_EXECINSTR` — the section holds executable machine code.
const SHF_EXECINSTR: u64 = 0x4;
/// `SHT_NOBITS` — occupies no file space (`.bss`); reads short, like a PE BSS tail.
const SHT_NOBITS: u32 = 8;
/// `SHF_TLS` — the section is a thread-local storage template.
const SHF_TLS: u64 = 0x400;
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

/// The `COPY` relocation type of each machine whose relocations are read
/// ([`read_relocated_words`]): it fills a whole object, of its symbol's size,
/// from the image that defines it, so it writes more than the one word at its
/// address. `None` for a machine whose relocations were not measured.
fn copy_reloc_type(e_machine: u16) -> Option<u32> {
    match e_machine {
        0x3E | 0x03 => Some(5), // R_X86_64_COPY, R_386_COPY
        0xB7 => Some(1024),     // R_AARCH64_COPY
        0x28 => Some(20),       // R_ARM_COPY
        _ => None,
    }
}

/// `ET_EXEC` and `ET_DYN`: what a loader loads.
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
/// `SHF_ALLOC`: the section is in the image, so a relocation table with it is
/// one the loader (or a static executable's start-up code) applies.
const SHF_ALLOC: u64 = 0x2;
/// `SHT_RELR` and `DT_RELR`/`DT_RELRSZ`: packed relative relocations
/// (`-z pack-relative-relocs`), which goblin does not decode.
const SHT_RELR: u32 = 19;
const DT_RELRSZ: u64 = 35;
const DT_RELR: u64 = 36;
/// Android's packed formats: `SHT_ANDROID_REL`, `SHT_ANDROID_RELA`,
/// `SHT_ANDROID_RELR`, and the dynamic tags `DT_ANDROID_REL`,
/// `DT_ANDROID_RELA`, `DT_ANDROID_RELR`.
const ANDROID_SECTION_TYPES: [u32; 3] = [0x6000_0001, 0x6000_0002, 0x6fff_ff00];
const ANDROID_DYNAMIC_TAGS: [u64; 3] = [0x6000_000f, 0x6000_0011, 0x6fff_e000];

/// A program or a library ([`crate::Linkage`]), from the header's `e_type`
/// and, for an `ET_DYN`, its dynamic section and program headers.
fn linkage_of(elf: &Elf) -> crate::Linkage {
    use crate::Linkage;
    if elf.header.e_type == ET_EXEC {
        return Linkage::Executable;
    }
    let pie = elf.dynamic.as_ref().is_some_and(|d| d.info.flags_1 & goblin::elf::dynamic::DF_1_PIE != 0);
    if pie || (elf.interpreter.is_some() && elf.soname.is_none()) { Linkage::Executable } else { Linkage::SharedLibrary }
}

/// Every word the loader writes in this image ([`crate::RelocatedWords`]):
/// the addresses of the `REL`/`RELA` entries of the dynamic section
/// (`DT_REL`, `DT_RELA`, `DT_JMPREL`) and of every allocated relocation section
/// (a static executable applies its `.rela.iplt` itself and has no dynamic
/// section), the words a `RELR` table encodes, and the objects a `COPY`
/// relocation fills.
///
/// Read only where the set is known to be the whole of it: an executable or a
/// shared object, of one of the four machines measured, with no packed format
/// this does not decode.
fn read_relocated_words(elf: &Elf, bytes: &[u8]) -> crate::RelocatedWords {
    use crate::{RelocatedWords, RelocationsNotRead};
    if !matches!(elf.header.e_type, ET_EXEC | ET_DYN) {
        return RelocatedWords::NotRead(RelocationsNotRead::NotLoadable);
    }
    let Some(copy) = copy_reloc_type(elf.header.e_machine) else {
        return RelocatedWords::NotRead(RelocationsNotRead::MachineNotMeasured);
    };
    let dyns: &[goblin::elf::dynamic::Dyn] = elf.dynamic.as_ref().map(|d| d.dyns.as_slice()).unwrap_or_default();
    if elf.section_headers.iter().any(|s| ANDROID_SECTION_TYPES.contains(&s.sh_type)) || dyns.iter().any(|d| ANDROID_DYNAMIC_TAGS.contains(&d.d_tag)) {
        return RelocatedWords::NotRead(RelocationsNotRead::PackedFormatNotRead);
    }
    let mut words: Vec<u64> = Vec::new();
    let mut copies: Vec<(u64, u64)> = Vec::new();
    let mut add = |r: goblin::elf::Reloc, symbols: &goblin::elf::Symtab| {
        if r.r_type == copy
            && let Some(size) = symbols.get(r.r_sym).map(|s| s.st_size).filter(|&n| n > 0)
        {
            copies.push((r.r_offset, r.r_offset.saturating_add(size)));
        }
        words.push(r.r_offset);
    };
    for r in elf.dynrelas.iter().chain(elf.dynrels.iter()).chain(elf.pltrelocs.iter()) {
        add(r, &elf.dynsyms);
    }
    for (idx, relocs) in &elf.shdr_relocs {
        let Some(sh) = elf.section_headers.get(*idx) else { continue };
        if sh.sh_flags & SHF_ALLOC == 0 {
            continue;
        }
        // An allocated table links the dynamic symbols (`.rela.dyn`) or none
        // (`.rela.iplt`); a copy relocation is only ever a dynamic one.
        for r in relocs.iter() {
            add(r, &elf.dynsyms);
        }
    }
    // RELR tables: by section, and by the dynamic section's address where the
    // section headers are gone. The same table read twice repeats its words,
    // which the dedup below removes.
    let mut relr: Vec<(usize, usize)> =
        elf.section_headers.iter().filter(|s| s.sh_type == SHT_RELR).map(|s| (s.sh_offset as usize, s.sh_size as usize)).collect();
    let tag = |t: u64| dyns.iter().find(|d| d.d_tag == t).map(|d| d.d_val);
    if let (Some(va), Some(size)) = (tag(DT_RELR), tag(DT_RELRSZ)) {
        let offset = elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .find(|ph| va >= ph.p_vaddr && va.saturating_add(size) <= ph.p_vaddr.saturating_add(ph.p_filesz))
            .map(|ph| (va - ph.p_vaddr + ph.p_offset) as usize);
        match offset {
            Some(o) => relr.push((o, size as usize)),
            None => return RelocatedWords::NotRead(RelocationsNotRead::Malformed),
        }
    }
    let ptr: usize = if elf.is_64 { 8 } else { 4 };
    let word = |at: usize| -> Option<u64> {
        let b = bytes.get(at..at.checked_add(ptr)?)?;
        Some(match (ptr, elf.little_endian) {
            (8, true) => u64::from_le_bytes(b.try_into().ok()?),
            (8, false) => u64::from_be_bytes(b.try_into().ok()?),
            (_, true) => u64::from(u32::from_le_bytes(b.try_into().ok()?)),
            (_, false) => u64::from(u32::from_be_bytes(b.try_into().ok()?)),
        })
    };
    for (offset, size) in relr {
        // An address entry (bit 0 clear) names one word and sets where the next
        // bitmap starts; a bitmap entry (bit 0 set) names, by its other bits,
        // which of the next `8 * ptr - 1` words are relocated.
        let mut next = 0u64;
        let step = ptr as u64;
        for i in 0..size / ptr {
            let Some(entry) = offset.checked_add(i * ptr).and_then(word) else {
                return RelocatedWords::NotRead(RelocationsNotRead::Malformed);
            };
            if entry & 1 == 0 {
                words.push(entry);
                next = entry.saturating_add(step);
            } else {
                let bits = 8 * step - 1;
                for b in 0..bits {
                    if (entry >> (b + 1)) & 1 != 0 {
                        words.push(next.saturating_add(b * step));
                    }
                }
                next = next.saturating_add(bits * step);
            }
        }
    }
    words.sort_unstable();
    words.dedup();
    copies.sort_unstable();
    RelocatedWords::Read { words, copies }
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
    /// Whether the section takes room in the image's address space; see
    /// [`takes_image_space`]. Only such sections answer an address lookup.
    in_image: bool,
}

/// Whether a section of this type and these flags takes room in the image.
///
/// A TLS zero-fill section (`.tbss`: `SHT_NOBITS` and `SHF_TLS`) does not. It
/// describes each thread's zero-initialized TLS, allocated per thread at run
/// time, and the linker gives it the address the following sections also
/// start at. Mapped, it shadows them: on one system 568 of 9 386 ELF files had
/// a `.tbss` over `.init_array`, `.fini_array`, `.data.rel.ro`, `.dynamic`,
/// `.got` or `.data`, and every read there came back empty.
fn takes_image_space(sh_type: u32, sh_flags: u64) -> bool {
    !(sh_type == SHT_NOBITS && sh_flags & SHF_TLS != 0)
}

/// The byte order an image states for its multi-byte data: ELF
/// `e_ident[EI_DATA]` 1 (`ELFDATA2LSB`) or 2 (`ELFDATA2MSB`). A PE is always
/// little-endian.
///
/// Stated so a reader that only reads one order can refuse the other by name
/// rather than read it wrongly. Today the Itanium RTTI paths do
/// (`n0xis_core::RttiRefusal`); every other reader of image data still reads
/// little-endian whatever this says — an open item, not a decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    /// `ELFDATA2LSB`, and every PE.
    Little,
    /// `ELFDATA2MSB`.
    Big,
}

/// An ELF image on disk, mapped at its preferred base.
#[derive(Debug)]
pub struct StaticElf {
    /// What the file holds, for keying what is kept between requests.
    id: SourceId,
    bytes: Vec<u8>,
    /// `e_ident[EI_CLASS]`: `ELFCLASS64` (2) → `true`, `ELFCLASS32` (1) →
    /// `false`. The class is the width of the image's **data** pointers, which is
    /// not the decoder's register width: the x32 ABI and arm64_32 run 64-bit code
    /// with 4-byte pointers. Every ELF used to report `true` here, so a 32-bit
    /// image's vtables were read with 8-byte slots and a 16-byte header, and
    /// `rtti scan` answered `ok: true` with no class or with the wrong address.
    is_64: bool,
    /// `e_ident[EI_DATA]`, the byte order of every multi-byte field the image
    /// holds. goblin reads the headers in either; what this image's readers do
    /// with the data is theirs to say (see [`ByteOrder`]).
    byte_order: ByteOrder,
    /// A program or a library, as the headers say ([`crate::Linkage`]).
    linkage: crate::Linkage,
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
    /// `Elf64_Sym.st_size` for every defined function that declares one — the
    /// linker's own answer to "where does this function end", which beats any
    /// end-of-function heuristic outright.
    sizes: BTreeMap<u64, u64>,
    /// `st_size` of every defined data object that declares one, for the
    /// symbol [`Self::symbols`] keeps at that address. Apart from [`Self::sizes`]
    /// because that one is read as "where a *function* ends".
    data_sizes: BTreeMap<u64, u64>,
    /// PLT stub → the **local definition** it ends up at, for the symbols this
    /// image both imports through its own PLT and defines. See
    /// [`SymbolProvider::thunk_to`]: without this a shared object's calls to its
    /// own functions are edges into a stub, and every whole-program pass loses
    /// them.
    plt_to_local: BTreeMap<u64, u64>,
    /// The words the loader writes ([`read_relocated_words`]).
    relocated: crate::RelocatedWords,
}

impl StaticElf {
    /// Preferred image base: the minimum `PT_LOAD` virtual address (0 for a
    /// position-independent executable, the first segment's `p_vaddr` for a
    /// classic `ET_EXEC`).
    pub fn image_base(&self) -> Va {
        Va(self.image_base)
    }

    /// Whether the image's class is `ELFCLASS64` — see the field.
    pub fn is_64(&self) -> bool {
        self.is_64
    }

    /// A program or a library — see [`crate::Linkage`].
    pub fn linkage(&self) -> crate::Linkage {
        self.linkage
    }

    /// The image's byte order, from `e_ident[EI_DATA]` — see the field.
    pub fn byte_order(&self) -> ByteOrder {
        self.byte_order
    }

    /// The image's data pointer size in bytes, from its class: 8 for
    /// `ELFCLASS64`, 4 for `ELFCLASS32`.
    pub fn pointer_size(&self) -> u8 {
        if self.is_64 { 8 } else { 4 }
    }

    /// The words a load-time relocation writes, or why they were not read
    /// ([`crate::RelocatedWords`]).
    pub fn relocated_words(&self) -> &crate::RelocatedWords {
        &self.relocated
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
    /// Each with the size its symbol states ([`crate::DataSymbol`]).
    pub fn data_symbols(&self) -> Vec<crate::DataSymbol> {
        self.symbols
            .values()
            .filter(|s| s.kind == SymKind::Data)
            .map(|s| crate::DataSymbol { va: s.va, name: s.name.clone(), size: self.data_sizes.get(&s.va.get()).copied() })
            .collect()
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
                in_image: takes_image_space(sh.sh_type, sh.sh_flags),
            });
        }

        // Defined function symbols from `.symtab` (full, when not stripped) and
        // `.dynsym` (exported dynamic symbols; the only ones on a stripped ELF).
        // A symbol with `st_value == 0` or `st_shndx == SHN_UNDEF` is an import
        // reference, not a definition — skip it.
        let mut symbols: BTreeMap<u64, Symbol> = BTreeMap::new();
        let mut sizes: BTreeMap<u64, u64> = BTreeMap::new();
        let mut data_sizes: BTreeMap<u64, u64> = BTreeMap::new();
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
                if kind == SymKind::Export && sym.st_size > 0 {
                    // Aliases at one address agree on the size; `or_insert` keeps
                    // the first, and disagreement would mean a malformed table.
                    sizes.entry(sym.st_value).or_insert(sym.st_size);
                }
                if let std::collections::btree_map::Entry::Vacant(slot) = symbols.entry(sym.st_value) {
                    slot.insert(Symbol { va: Va(sym.st_value), module: module_name.clone(), name: name.to_string(), kind });
                    // The size of the symbol kept here, and of no other: a size
                    // is a fact about one object, read with its name.
                    if kind == SymKind::Data && sym.st_size > 0 {
                        data_sizes.insert(sym.st_value, sym.st_size);
                    }
                }
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
        // GOT slot → the address of the definition **in this image** it binds
        // to. Populated only for `JUMP_SLOT` relocations against symbols this
        // object defines, which is exactly the self-call-through-the-PLT case.
        let mut local_slot: BTreeMap<u64, u64> = BTreeMap::new();
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

            let add_local = &mut local_slot;
            let mut add = |reloc: &goblin::elf::Reloc| {
                let local_slot = &mut *add_local;
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
                    // Defined **here**. Naming it `extern!foo` would be a lie —
                    // but the slot still says where the call ends up, and that
                    // is the fact a whole-program pass needs: a shared object
                    // routes even a call to its own function through the PLT so
                    // `LD_PRELOAD` can interpose. `st_value` is the linker's own
                    // answer, so no name matching and no guessing.
                    if reloc.r_type == jump_slot && sym.st_value != 0 {
                        local_slot.insert(reloc.r_offset, sym.st_value);
                    }
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

        let mut plt_to_local: BTreeMap<u64, u64> = BTreeMap::new();
        // --- PLT stubs: name the *stub* after the import it jumps to ---
        //
        // With lazy binding (the default, and what a stripped ELF executable
        // almost always uses) a call to an import is a **direct** `call` to a
        // PLT stub, not an indirect call through the GOT — so `iat_slot` above
        // never sees it and the callee stays `sub_1030`. Naming the
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
                    let sym = got.get(&slot);
                    let local = local_slot.get(&slot).copied();
                    if sym.is_none() && local.is_none() {
                        i += 1;
                        continue;
                    }
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
                    // The stub forwards into this same image: record where, so
                    // a whole-program pass can follow the program's own call
                    // graph instead of stopping at a thunk.
                    if let Some(target) = local
                        && target != stub_va
                    {
                        plt_to_local.insert(stub_va, target);
                    }
                    let Some(sym) = sym else {
                        i += 1;
                        continue;
                    };
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

        // goblin reads `e_ident[EI_CLASS]` and refuses any value but
        // `ELFCLASS32`/`ELFCLASS64`, so this is the header's own answer.
        let is_64 = elf.is_64;
        // The same for `e_ident[EI_DATA]`: goblin accepts `ELFDATA2LSB` and
        // `ELFDATA2MSB` only, and parses the headers in the one it finds.
        let byte_order = if elf.little_endian { ByteOrder::Little } else { ByteOrder::Big };
        let linkage = linkage_of(&elf);
        let relocated = read_relocated_words(&elf, &bytes);
        Ok(StaticElf {
            id: SourceId::of(&bytes),
            bytes,
            is_64,
            byte_order,
            linkage,
            image_base,
            module_name,
            modules,
            sections,
            symbols,
            got,
            sizes,
            data_sizes,
            plt_to_local,
            relocated,
        })
    }

    /// The section that holds `va` in the image: the one address lookup, which
    /// `read` and `contains` both go through.
    fn section_for(&self, va: u64) -> Option<&SectionRange> {
        self.sections.iter().find(|s| s.in_image && va >= s.va_start && va < s.va_end)
    }

    /// The **defined** function symbols (`.symtab`/`.dynsym`), address-ordered —
    /// the `(va, name)` list a signature generator fingerprints and `profile`
    /// reports as this format's answer to a PE export table. Empty on a stripped
    /// binary, which is exactly why signatures are needed in the first place.
    ///
    /// Excludes the **PLT stubs** named after their imports: a stub is a thunk
    /// into another library, not code this image defines. Signing one is both
    /// useless and unsafe — every x86-64 lazy PLT entry embeds its own
    /// relocation index (`push <n>`), a value specific to *this* binary's link
    /// order, so the pattern either matches nothing elsewhere or matches an
    /// unrelated stub that happens to share the index.
    pub fn named_functions(&self) -> Vec<(Va, String)> {
        self.symbols.values().filter(|s| s.kind == SymKind::Export).map(|s| (s.va, s.name.clone())).collect()
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

    /// An image on disk cannot change under the loaded copy; everything the
    /// source answers comes from its bytes.
    fn identity(&self) -> Option<SourceId> {
        Some(self.id)
    }

    /// A readable stretch starts where a section starts or another ends.
    fn next_readable(&self, va: Va, end: Va) -> Result<Option<Va>, SourceError> {
        let bounds = self.sections.iter().filter(|s| s.in_image).flat_map(|s| [s.va_start, s.va_end]);
        crate::next_readable_at(self, va, end, bounds)
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
    fn thunk_to(&self, va: Va) -> Option<Va> {
        self.plt_to_local.get(&va.0).copied().map(Va)
    }

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

    /// `st_size` — the linker's own extent for this function. Only for a symbol
    /// this image *defines* (a PLT stub is a thunk, and carries the size of the
    /// stub, not of the function it reaches).
    fn symbol_size(&self, va: Va) -> Option<u64> {
        self.sizes.get(&va.0).copied()
    }
}

impl ModuleProvider for StaticElf {
    fn modules(&self) -> &[Module] {
        &self.modules
    }
}
