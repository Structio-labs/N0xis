// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The ELF reader behind [`Image`], the twin of the PE one: an executable or
//! a shared object, as its headers, symbol tables and dynamic section state
//! it.
//!
//! Commands read it through [`ImageSource`](crate::ImageSource), which serves
//! it at its preferred base through the same seams a live process uses, so the
//! whole "one pipeline, live + static" property extends to Linux-native
//! binaries — Rust and GCC/System V C++ alike — not just PE. This file only
//! parses; every lookup is computed once, in the adapter.
//!
//! Scope: static code + symbols. DWARF type/line recovery (`.debug_info`) is a
//! documented follow-on; a not-stripped ELF still yields real function names
//! here, which is the bulk of the readability win.

use std::collections::BTreeMap;

use goblin::elf::Elf;
use n0xis_contracts::Va;

use crate::image::{
    Access, AddressModel, Answer, Binding, ByteOrder, CodeView, DeclaredStart, Export, Extent, Finding, FormatTables, Image, ImageSymbol,
    ImportBinding, ImportName, ImportRef, ImportReference, Imports, Isa, ItemKind, Library, LibraryRef, LibrarySource, LoadedBytes, Machine,
    OpenError, OpenOptions, Opened, Partial, Placement, PointerWidth, Reach, Section, Segment, Segments, StartCoverage, StartReason, SymbolKind,
    SymbolTable, UnlistedSlot, Unread,
};


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

/// Whether this reader decodes the PLT stubs of a machine: x86-64 only. **The
/// one statement of it**, read by the decoder's gate and by the answers that
/// say the stubs were not read ([`plt_stubs_unread`]), so the two cannot
/// drift apart.
fn decodes_plt_stubs(e_machine: u16) -> bool {
    e_machine == 0x3E
}

/// The sections a PLT stub lives in: executable, named `.plt…` (`.plt`,
/// `.plt.got`, `.plt.sec`), with bytes in the file.
fn plt_sections(sections: &[SectionRange]) -> impl Iterator<Item = &SectionRange> {
    sections.iter().filter(|s| s.executable && s.name.starts_with(".plt") && s.file_size > 0)
}

/// What is said where an image has PLT stubs this reader does not decode:
/// they are neither starts nor a reach of the import their slot is bound to.
/// `None` where there are none, or where they are decoded.
fn plt_stubs_unread(e_machine: u16, sections: &[SectionRange]) -> Option<Unread> {
    let names: Vec<&str> = plt_sections(sections).map(|s| s.name.as_str()).collect();
    (!decodes_plt_stubs(e_machine) && !names.is_empty()).then(|| Unread {
        part: "PLT stubs".into(),
        why: format!(
            "the image has {}, and the PLT stubs of machine {e_machine:#x} are not decoded (x86-64's are), so no stub is a start or a \
             reach of the import its slot is bound to",
            names.join(", ")
        ),
    })
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

/// Every ELF file starts with `\x7fELF`.
pub(crate) fn sniff(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x7fELF")
}

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

/// `PF_X`, `PF_W`, `PF_R`.
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// An ELF image's answers, read from its file.
#[derive(Debug)]
pub(crate) struct StaticElf {
    bytes: Vec<u8>,
    machine: Machine,
    /// A program or a library, as the headers say ([`crate::Linkage`]).
    linkage: crate::Linkage,
    segments: Segments,
    sections: Vec<Section>,
    placed: Vec<Placement>,
    symbols: Answer<Partial<Vec<ImageSymbol>>>,
    exports: Answer<Vec<Export>>,
    imports: Answer<Imports>,
    starts: Partial<Vec<DeclaredStart>>,
    /// Import slots and self-bound jump slots, by slot address.
    bindings: BTreeMap<u64, Binding>,
    /// The answer for a slot [`Self::bindings`] does not list.
    unlisted: UnlistedSlot,
    /// The words the loader writes ([`read_relocated_words`]).
    relocated: crate::RelocatedWords,
    /// Statements of the image that disagree ([`bindings_of`]).
    findings: Vec<Finding>,
}

/// Parse an ELF file's bytes.
pub(crate) fn open(bytes: Vec<u8>, _opts: &OpenOptions) -> Result<Opened, OpenError> {
    StaticElf::parse(bytes).map(|elf| Opened::Thin { image: Box::new(elf), tables: FormatTables::Native })
}

/// The ELF `e_machine`, mapped onto the same names the PE reader reports
/// (`x64`, `arm64`, …) so one consumer reads both formats. An unrecognized
/// machine is returned as its raw value rather than guessed into a wrong name.
fn elf_machine(bytes: &[u8]) -> Isa {
    // e_ident[EI_DATA] = 1 little-endian, 2 big-endian; e_machine at 0x12.
    let Some(raw) = bytes.get(0x12..0x14) else { return Isa::Unreadable };
    let em = match bytes.get(5) {
        Some(1) => u16::from_le_bytes([raw[0], raw[1]]),
        Some(2) => u16::from_be_bytes([raw[0], raw[1]]),
        _ => return Isa::Unreadable,
    };
    match em {
        0x3E => Isa::X64,
        0xB7 => Isa::Arm64,
        0x03 => Isa::X86,
        0x28 => Isa::Arm,
        raw => Isa::Unrecognized { raw },
    }
}

impl StaticElf {
    fn parse(bytes: Vec<u8>) -> Result<Self, OpenError> {
        let elf = Elf::parse(&bytes).map_err(|e| OpenError::Parse(e.to_string()))?;

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

        // Defined function and data symbols from `.symtab` (full, when not
        // stripped) and `.dynsym` (exported dynamic symbols; the only ones on a
        // stripped ELF), in that order, every one listed: which of several at
        // one address names it is the adapter's rule, not a choice made here.
        let mut symbols: Vec<ImageSymbol> = Vec::new();
        // Defined, named symbols of a type not read, per table: said, so the
        // list is not taken for every name the image gives an address.
        let mut symbols_unread: Vec<Unread> = Vec::new();
        let mut collect = |syms: &goblin::elf::Symtab, strtab: &goblin::strtab::Strtab, table: SymbolTable, table_name: &str| {
            let mut other: BTreeMap<u8, usize> = BTreeMap::new();
            for sym in syms.iter() {
                // A symbol with `st_value == 0` or `st_shndx == SHN_UNDEF` is
                // an import reference, not a definition — skip it.
                if sym.st_value == 0 || sym.st_shndx == 0 {
                    continue;
                }
                let Some(name) = strtab.get_at(sym.st_name) else { continue };
                if name.is_empty() {
                    continue;
                }
                // Functions become named code targets; data objects (globals /
                // statics) become named data references (`&crc_table`).
                let kind = match sym.st_type() {
                    STT_FUNC => SymbolKind::Function,
                    STT_OBJECT => SymbolKind::Object,
                    other_type => {
                        *other.entry(other_type).or_default() += 1;
                        continue;
                    }
                };
                let extent = if sym.st_size > 0 { Extent::Stated(sym.st_size) } else { Extent::Unknown };
                symbols.push(ImageSymbol { va: Va(sym.st_value), name: name.to_string(), kind, extent, table });
            }
            if !other.is_empty() {
                let counts: Vec<String> = other.iter().map(|(&ty, n)| format!("{n} {}", symbol_type_name(ty))).collect();
                symbols_unread.push(Unread {
                    part: format!("{table_name} symbols of a type other than STT_FUNC and STT_OBJECT"),
                    why: format!("{} defined and named, and only STT_FUNC and STT_OBJECT symbols are read", counts.join(", ")),
                });
            }
        };
        collect(&elf.syms, &elf.strtab, SymbolTable::Static, ".symtab");
        collect(&elf.dynsyms, &elf.dynstrtab, SymbolTable::Dynamic, ".dynsym");
        // `Elf64_Sym.st_size` of a defined function is the linker's own answer
        // to "where does this function end", which beats any end-of-function
        // heuristic outright.
        let mut starts: Vec<DeclaredStart> = symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Function)
            .map(|s| DeclaredStart { va: s.va, why: StartReason::Symbol, extent: s.extent })
            .collect();

        // Symbol-version index -> the library that is expected to provide it
        // (`.gnu.version_r`: `getenv@GLIBC_2.2.5` -> `libc.so.6`). This is the
        // only per-symbol provider attribution an ELF carries; binding is flat
        // at run time, so it is informative, not authoritative.
        let mut provider: BTreeMap<u16, String> = BTreeMap::new();
        if let Some(verneed) = elf.verneed.as_ref() {
            for need in verneed.iter() {
                let Some(file) = elf.dynstrtab.get_at(need.vn_file) else { continue };
                for aux in need.iter() {
                    provider.insert(aux.vna_other, file.to_string());
                }
            }
        }
        let provider_of = |sym_index: usize| -> Option<String> {
            elf.versym.as_ref().and_then(|vs| vs.get_at(sym_index)).and_then(|v| provider.get(&v.version()).cloned())
        };

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
        let mut got: BTreeMap<u64, ImportRef> = BTreeMap::new();
        // Every relocation here that names a slot, as (slot, type, symbol), so
        // that two naming one slot are seen ([`bindings_of`]).
        let mut named_slots: Vec<(u64, u32, usize)> = Vec::new();
        // GOT slot → the address of the definition **in this image** it binds
        // to. Populated only for `JUMP_SLOT` relocations against symbols this
        // object defines, which is exactly the self-call-through-the-PLT case.
        let mut local_slot: BTreeMap<u64, u64> = BTreeMap::new();
        // The import slots each imported dynamic symbol is bound through, by
        // symbol index, in relocation order.
        let mut slots_of: BTreeMap<usize, Vec<u64>> = BTreeMap::new();
        let reloc_types = got_reloc_types(elf.header.e_machine);
        // Why the slots were not read, once, for both answers that say so: an
        // import's reach and what a slot is bound to.
        let slots_not_read = reloc_types
            .is_none()
            .then(|| format!("the GLOB_DAT and JUMP_SLOT relocations of machine {:#x} are not read", elf.header.e_machine));
        if let Some((glob_dat, jump_slot)) = reloc_types {
            let mut add = |reloc: &goblin::elf::Reloc| {
                if reloc.r_type != glob_dat && reloc.r_type != jump_slot {
                    return;
                }
                let Some(sym) = elf.dynsyms.get(reloc.r_sym) else { return };
                named_slots.push((reloc.r_offset, reloc.r_type, reloc.r_sym));
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
                got.insert(reloc.r_offset, ImportRef { name: ImportName::Named(name.to_string()), library: provider_of(reloc.r_sym) });
                // A slot is one way to reach the import however many times a
                // table states it. One relocation read twice — a `DT_RELASZ`
                // that also covers the `DT_JMPREL` entries, a layout the
                // loader accepts — listed each slot, and each stub through
                // it, twice ([`bindings_of`] dedups the same entries).
                let slots = slots_of.entry(reloc.r_sym).or_default();
                if !slots.contains(&reloc.r_offset) {
                    slots.push(reloc.r_offset);
                }
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

        // --- PLT stubs: the stubs that jump through a bound slot ---
        //
        // With lazy binding (the default, and what a stripped ELF executable
        // almost always uses) a call to an import is a **direct** `call` to a
        // PLT stub, not an indirect call through the GOT — so the slot map
        // above never sees it and the callee stays `sub_1030`. The stub is a
        // declared start of its own, and the adapter names it after the import
        // its slot is bound to, which makes one symbol serve every consumer at
        // once (discovery list, xref, decompiler) instead of each re-deriving
        // the thunk.
        //
        // Every x86-64 PLT variant contains exactly one `jmp qword ptr
        // [rip+disp]` (`FF 25`) whose target is the import's GOT slot, so the
        // stub is identified by that instruction rather than by assuming an
        // entry size: `.plt` entries are 16 bytes, `.plt.got` are 8, and
        // `.plt.sec` prefixes an `endbr64`. **The match is self-validating** —
        // the slot must already be bound above, which is what keeps `.plt`'s
        // resolver stub (PLT0, whose `jmp` goes through `GOT+0x10`, not a
        // symbol) and any non-PLT `FF 25` out.
        let mut stub_of_slot: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        if decodes_plt_stubs(elf.header.e_machine) {
            for sec in plt_sections(&sections) {
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
                    let import = got.contains_key(&slot);
                    if !import && !local_slot.contains_key(&slot) {
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
                    starts.push(DeclaredStart { va: Va(stub_va), why: StartReason::Stub { slot: Va(slot) }, extent: Extent::Unknown });
                    stub_of_slot.entry(slot).or_default().push(stub_va);
                    i += if import { 6 } else { 1 };
                }
            }
        }

        let libraries = libraries_of(&elf);
        let library_ref = |name: Option<String>| match name {
            Some(name) => match libraries.iter().position(|l| l.name == name) {
                Some(i) => LibraryRef::Named(i),
                None => LibraryRef::Unattributed { why: "the version requirement names no library this image lists" },
            },
            None => LibraryRef::Unattributed { why: "no version requirement names a library for it, and ELF binding is flat" },
        };
        // Every undefined dynamic symbol is something the image needs, whether
        // or not a slot above is bound to it.
        let references: Vec<ImportReference> = elf
            .dynsyms
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(_, sym)| sym.st_shndx == 0)
            .filter_map(|(index, sym)| {
                let name = elf.dynstrtab.get_at(sym.st_name).filter(|n| !n.is_empty())?;
                let reach = if let Some(why) = &slots_not_read {
                    Answer::NotRead { why: why.clone() }
                } else {
                    let slots = slots_of.get(&index).map(Vec::as_slice).unwrap_or_default();
                    let stubs = slots.iter().flat_map(|s| stub_of_slot.get(s).into_iter().flatten());
                    Answer::Read(slots.iter().map(|&s| Reach::Slot(Va(s))).chain(stubs.map(|&s| Reach::Stub(Va(s)))).collect())
                };
                Some(ImportReference {
                    name: ImportName::Named(name.to_string()),
                    kind: import_kind(sym.st_type()),
                    library: library_ref(provider_of(index)),
                    reach,
                })
            })
            .collect();

        let (bindings, findings) = bindings_of(got, local_slot, named_slots);
        let unlisted = match slots_not_read {
            Some(why) => UnlistedSlot::NotRead { why },
            None => UnlistedSlot::Unbound {
                why: "no GLOB_DAT or JUMP_SLOT relocation binds this slot to an import, nor a JUMP_SLOT to a definition here",
            },
        };

        let loads = || elf.program_headers.iter().filter(|ph| ph.p_type == PT_LOAD);
        // Image size: span from the base to the end of the last loadable segment.
        let span = loads().map(|ph| ph.p_vaddr.saturating_add(ph.p_memsz)).max().unwrap_or(0).saturating_sub(image_base);
        let segments = Segments {
            base: Va(image_base),
            span,
            list: loads()
                .map(|ph| Segment {
                    va: Va(ph.p_vaddr),
                    mem_size: ph.p_memsz,
                    file_offset: ph.p_offset,
                    file_size: ph.p_filesz,
                    access: Access { read: ph.p_flags & PF_R != 0, write: ph.p_flags & PF_W != 0, execute: ph.p_flags & PF_X != 0 },
                })
                .collect(),
        };

        // goblin reads `e_ident[EI_CLASS]` and refuses any value but
        // `ELFCLASS32`/`ELFCLASS64`, so the width is the header's own answer.
        // The class is the width of the image's **data** pointers, which is not
        // the decoder's register width: the x32 ABI and arm64_32 run 64-bit
        // code with 4-byte pointers. Every ELF used to report 8 here, so a
        // 32-bit image's vtables were read with 8-byte slots and a 16-byte
        // header, and `rtti scan` answered `ok: true` with no class or with the
        // wrong address. The same for `e_ident[EI_DATA]`: goblin accepts
        // `ELFDATA2LSB` and `ELFDATA2MSB` only, and parses the headers in the
        // one it finds.
        let machine = Machine {
            isa: elf_machine(&bytes),
            address_model: AddressModel::Native(PointerWidth::of_64_bit(elf.is_64)),
            byte_order: if elf.little_endian { ByteOrder::Little } else { ByteOrder::Big },
            abi: "sysv", // ELF → System V.
        };
        let linkage = linkage_of(&elf);
        // What a relocatable object needs is its undefined `.symtab` symbols,
        // resolved by a link editor, not by a loader from other images; it has
        // no dynamic symbols, so the list above is empty whatever it needs (a
        // `crt1.o` needs `__libc_start_main` and `main`). Not read, rather
        // than answered as "nothing".
        let stubs_unread = plt_stubs_unread(elf.header.e_machine, &sections);
        let imports = if matches!(elf.header.e_type, ET_EXEC | ET_DYN) {
            Answer::Read(Imports { binding: ImportBinding::Flat, libraries, references, reach_not_read: stubs_unread.iter().cloned().collect() })
        } else {
            Answer::NotRead {
                why: format!(
                    "an ELF of type {} is not an executable or a shared object: what it needs is resolved by a link editor from its \
                     undefined .symtab symbols, which are not read",
                    elf_type_name(elf.header.e_type)
                ),
            }
        };
        let relocated = read_relocated_words(&elf, &bytes);
        let placed = sections
            .iter()
            .filter(|s| s.in_image)
            .map(|s| Placement { va: s.va_start, end: s.va_end, file_offset: s.file_offset, file_size: s.file_size })
            .collect();
        let public_sections = sections
            .iter()
            .map(|s| Section {
                name: s.name.clone(),
                va: Va(s.va_start),
                size: s.va_end - s.va_start,
                file_offset: s.file_offset as u64,
                file_size: s.file_size as u64,
                executable: s.executable,
                in_image: s.in_image,
            })
            .collect();
        // What the image states about where code starts that is not read
        // here: the entry point, the PLT stubs of a machine whose stubs are
        // not decoded, and `.eh_frame`'s frame descriptions.
        let mut starts_unread: Vec<Unread> = Vec::new();
        if elf.header.e_entry != 0 {
            starts_unread.push(Unread {
                part: "the entry point".into(),
                why: format!("e_entry ({:#x}) is a header field this reader does not make a start of", elf.header.e_entry),
            });
        }
        starts_unread.extend(stubs_unread);
        starts_unread.extend(crate::static_pe::eh_frame_unread(sections.iter().map(|s| (s.name.as_str(), s.file_size))));
        // The parse borrows the bytes the image keeps.
        drop(elf);
        Ok(StaticElf {
            bytes,
            machine,
            linkage,
            segments,
            sections: public_sections,
            placed,
            symbols: Answer::Read(Partial { read: symbols, not_read: symbols_unread }),
            exports: Answer::NotRead { why: "an ELF's exports are its defined dynamic symbols, which are read as symbols and not listed apart".into() },
            imports,
            starts: Partial { read: starts, not_read: starts_unread },
            bindings,
            unlisted,
            relocated,
            findings,
        })
    }
}

/// What an undefined dynamic symbol's `st_type` says it is: code
/// (`STT_FUNC`, `STT_GNU_IFUNC`, whose resolver yields a function), data
/// (`STT_OBJECT`, `STT_COMMON`, `STT_TLS` — a thread-local variable is still a
/// variable), and nothing for `STT_NOTYPE` or a type this reader does not name.
fn import_kind(st_type: u8) -> ItemKind {
    match st_type {
        2 | 10 => ItemKind::Function,
        1 | 5 | 6 => ItemKind::Data,
        _ => ItemKind::NotStated,
    }
}

/// A symbol's `st_type` as the specification names it.
fn symbol_type_name(st_type: u8) -> String {
    match st_type {
        0 => "STT_NOTYPE".into(),
        1 => "STT_OBJECT".into(),
        2 => "STT_FUNC".into(),
        3 => "STT_SECTION".into(),
        4 => "STT_FILE".into(),
        5 => "STT_COMMON".into(),
        6 => "STT_TLS".into(),
        10 => "STT_GNU_IFUNC".into(),
        other => format!("type {other}"),
    }
}

/// `e_type` as the specification names it.
fn elf_type_name(e_type: u16) -> String {
    match e_type {
        0 => "ET_NONE".into(),
        1 => "ET_REL".into(),
        2 => "ET_EXEC".into(),
        3 => "ET_DYN".into(),
        4 => "ET_CORE".into(),
        other => format!("{other:#x}"),
    }
}

/// What each slot is bound to, from the import slots (`got`) and the jump
/// slots bound to this image's own definitions (`local`), and a finding for
/// every slot two relocations name.
///
/// Each map keeps the last relocation it read at a slot, as the reader always
/// has. A slot in both maps is both — the answers built on it name its stub
/// after the import and forward the stub to the definition, as they did before
/// the format seam — and neither is dropped: on such a planted file the 0.3.5
/// reader answered both, and a binding that picked one lost the other.
/// `named` is every `GLOB_DAT` and `JUMP_SLOT` relocation read, as (slot,
/// type, symbol index). One relocation read twice is one statement, not two:
/// a dynamic table whose `DT_RELASZ` also covers the `DT_JMPREL` entries
/// hands the same entry to both lists.
fn bindings_of(
    got: BTreeMap<u64, ImportRef>,
    mut local: BTreeMap<u64, u64>,
    mut named: Vec<(u64, u32, usize)>,
) -> (BTreeMap<u64, Binding>, Vec<Finding>) {
    let mut bindings: BTreeMap<u64, Binding> = BTreeMap::new();
    for (slot, import) in got {
        let binding = match local.remove(&slot) {
            Some(target) => Binding::ImportAndSelfDefinition { import, target: Va(target) },
            None => Binding::Import(import),
        };
        bindings.insert(slot, binding);
    }
    bindings.extend(local.into_iter().map(|(slot, target)| (slot, Binding::SelfDefinition { target: Va(target) })));
    named.sort_unstable();
    named.dedup();
    let mut findings = Vec::new();
    for pair in named.chunk_by(|a, b| a.0 == b.0).filter(|run| run.len() > 1) {
        let slot = pair[0].0;
        let then = match bindings.get(&slot) {
            Some(Binding::ImportAndSelfDefinition { .. }) => "one binds it to an import and one to a definition here, and both are kept",
            Some(Binding::Import(_)) => "it is answered as the slot of one import, the last read",
            Some(Binding::SelfDefinition { .. }) => "it is answered as bound to one definition here, the last read",
            Some(Binding::Unbound { .. } | Binding::NotRead { .. }) | None => "neither binds it to an import or to a jump target here",
        };
        findings.push(Finding::Contradiction { what: format!("{} GLOB_DAT or JUMP_SLOT relocations name the slot at {slot:#x}: {then}", pair.len()) });
    }
    (bindings, findings)
}

/// The libraries an ELF needs: its `DT_NEEDED` entries in order, then, in
/// the order `.gnu.version_r` holds them, any library a version requirement
/// names that no `DT_NEEDED` entry does.
fn libraries_of(elf: &Elf) -> Vec<Library> {
    let mut out: Vec<Library> =
        elf.libraries.iter().map(|l| Library { name: l.to_string(), stated_by: LibrarySource::Needed, references_not_read: Vec::new() }).collect();
    for need in elf.verneed.iter().flat_map(|v| v.iter()) {
        let Some(name) = elf.dynstrtab.get_at(need.vn_file) else { continue };
        if !out.iter().any(|l| l.name == name) {
            out.push(Library { name: name.to_string(), stated_by: LibrarySource::VersionRequirementOnly, references_not_read: Vec::new() });
        }
    }
    out
}

impl Image for StaticElf {
    fn machine(&self) -> &Machine {
        &self.machine
    }
    fn linkage(&self) -> crate::Linkage {
        self.linkage
    }
    fn segments(&self) -> &Segments {
        &self.segments
    }
    fn sections(&self) -> &[Section] {
        &self.sections
    }
    fn symbols(&self) -> &Answer<Partial<Vec<ImageSymbol>>> {
        &self.symbols
    }
    fn imports(&self) -> &Answer<Imports> {
        &self.imports
    }
    fn exports(&self) -> &Answer<Vec<Export>> {
        &self.exports
    }
    fn declared_starts(&self) -> &Partial<Vec<DeclaredStart>> {
        &self.starts
    }
    /// Function symbols and stubs are some functions: a stripped image has
    /// none, and a static function may have no symbol.
    fn start_coverage(&self) -> StartCoverage {
        StartCoverage::Some
    }
    fn loaded_bytes(&self) -> LoadedBytes<'_> {
        LoadedBytes { file: &self.bytes, placed: &self.placed, written_by_loader: &self.relocated }
    }
    fn findings(&self) -> &[Finding] {
        &self.findings
    }
    fn binding_at(&self, slot: Va) -> Binding {
        match self.bindings.get(&slot.0) {
            Some(binding) => binding.clone(),
            None => self.unlisted.binding(),
        }
    }
    fn codeview(&self) -> Option<&CodeView> {
        None
    }
}
