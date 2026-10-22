// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The PE reader behind [`Image`]: what a PE file states, as the trait asks
//! for it.
//!
//! Commands read it through [`ImageSource`](crate::ImageSource), which serves
//! it at the PE's **preferred image base** through the same seams a live
//! process uses — so the analysis never knows whether its bytes came from
//! `ReadProcessMemory` or a section on disk. This file only parses; every
//! lookup an analysis makes (symbols, import slots, sizes) is computed once,
//! in the adapter, from these answers.
//!
//! Ported from the proven v0 `static_pe.rs`, refit to the trait seams, and
//! then to [`Image`] (IMAGE_FORMATS.md §5 step 3) without changing what it
//! parses.

use std::collections::BTreeMap;
use std::path::Path;

use goblin::pe::PE;
use n0xis_contracts::Va;

use crate::image::{
    Access, AddressModel, Answer, Binding, ByteOrder, CodeView, DeclaredStart, Export, Extent, Finding, FormatTables, Image, ImageSymbol,
    ImportBinding, ImportName, ImportRef, ImportReference, Imports, Isa, ItemKind, Library, LibraryRef, LibrarySource, LoadedBytes, Machine,
    OpenError, OpenOptions, Opened, Partial, Placement, PointerWidth, Reach, Section, Segment, Segments, StartCoverage, StartReason, SymbolKind,
    SymbolTable, UnlistedSlot, Unread,
};
use crate::MemorySource;
use crate::{try_read_export_table, ExportDirectory, ExportTarget, PeExport, RelocatedWords, RelocationsNotRead};

#[derive(Debug, Clone)]
struct SectionRange {
    name: String,
    va_start: u64,
    va_end: u64,
    file_offset: usize,
    file_size: usize,
    /// `IMAGE_SCN_MEM_EXECUTE`. See [`crate::MemorySource::code_ranges`] for why one
    /// `.text` is not enough on this corpus.
    executable: bool,
}

/// `IMAGE_SCN_MEM_EXECUTE`, `_READ`, `_WRITE`.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Every PE file starts with the DOS header's `MZ`.
pub(crate) fn sniff(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MZ")
}

/// A PE image's answers, read from its file.
#[derive(Debug)]
pub(crate) struct StaticPe {
    bytes: Vec<u8>,
    machine: Machine,
    /// `IMAGE_FILE_DLL` in the COFF characteristics: a library
    /// ([`crate::Linkage`]).
    linkage: crate::Linkage,
    segments: Segments,
    sections: Vec<Section>,
    placed: Vec<Placement>,
    symbols: Answer<Partial<Vec<ImageSymbol>>>,
    exports: Answer<Vec<Export>>,
    imports: Answer<Imports>,
    starts: Partial<Vec<DeclaredStart>>,
    /// IAT slot VA → the import it resolves to.
    iat: BTreeMap<u64, ImportRef>,
    /// The answer for a slot [`Self::iat`] does not list.
    unlisted: UnlistedSlot,
    /// A strict parse that refused this image, when it was opened
    /// permissively — so a caller can say "the import table did not parse"
    /// instead of reporting an empty one as fact. See [`open`].
    findings: Vec<Finding>,
    /// Which PDB was built with this image, as its debug directory says.
    codeview: Option<CodeView>,
    /// A PE's base relocations are not read.
    relocated: RelocatedWords,
}

/// The longest PDB path kept from a CodeView record; past it the record is
/// not believed to be a path at all.
const MAX_PDB_PATH: usize = 4096;

/// Parse a PE file's bytes.
pub(crate) fn open(bytes: Vec<u8>, _opts: &OpenOptions) -> Result<Opened, OpenError> {
    StaticPe::parse(bytes).map(|pe| Opened::Thin { image: Box::new(pe), tables: FormatTables::Native })
}

impl StaticPe {
    fn parse(bytes: Vec<u8>) -> Result<Self, OpenError> {
        // A strict parse first, then a permissive one. An RE target is often
        // exactly the image a strict parser refuses — packed, self-modifying,
        // or carrying a deliberately hostile import table — and refusing to
        // open it at all is the wrong answer for a tool whose job is to look at
        // it. goblin's permissive mode recovers what it can; what it cannot
        // parse (usually the imports) simply comes back empty, which every
        // consumer already handles. The finding records that this happened so
        // nothing downstream reports an empty import table as a fact.
        let (pe, degraded) = match PE::parse(&bytes) {
            Ok(pe) => (pe, None),
            Err(strict) => {
                let mut opts = goblin::pe::options::ParseOptions::default();
                opts.parse_mode = goblin::options::ParseMode::Permissive;
                match PE::parse_with_opts(&bytes, &opts) {
                    Ok(pe) => (pe, Some(strict.to_string())),
                    Err(e) => return Err(OpenError::Parse(e.to_string())),
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
        let linkage = if pe.is_lib { crate::Linkage::SharedLibrary } else { crate::Linkage::Executable };

        let oh = pe.header.optional_header.ok_or_else(|| OpenError::Refused("PE has no optional header".into()))?;
        let image_base = oh.windows_fields.image_base;
        let size_of_image = oh.windows_fields.size_of_image as u64;
        let size_of_headers = oh.windows_fields.size_of_headers as u64;

        let mut sections = Vec::with_capacity(pe.sections.len() + 1);
        let mut segments = Vec::with_capacity(pe.sections.len() + 1);
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
            segments.push(Segment {
                va: Va(image_base),
                mem_size: size_of_headers,
                file_offset: 0,
                file_size: size_of_headers,
                access: Access { read: true, write: false, execute: false },
            });
        }
        for s in &pe.sections {
            let name = s.name().map(|n| n.trim_end_matches('\0').to_string()).unwrap_or_default();
            let rva = s.virtual_address as u64;
            let virtual_size = s.virtual_size as u64;
            let file_offset = s.pointer_to_raw_data as usize;
            let file_size = s.size_of_raw_data as usize;
            let va_start = image_base.saturating_add(rva);
            let va_end = va_start.saturating_add(virtual_size.max(file_size as u64));
            sections.push(SectionRange { name, va_start, va_end, file_offset, file_size, executable: s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 });
            segments.push(Segment {
                va: Va(va_start),
                mem_size: virtual_size,
                file_offset: s.pointer_to_raw_data as u64,
                file_size: s.size_of_raw_data as u64,
                access: Access {
                    read: s.characteristics & IMAGE_SCN_MEM_READ != 0,
                    write: s.characteristics & IMAGE_SCN_MEM_WRITE != 0,
                    execute: s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
                },
            });
        }

        let placed: Vec<Placement> = sections
            .iter()
            .map(|s| Placement { va: s.va_start, end: s.va_end, file_offset: s.file_offset, file_size: s.file_size })
            .collect();
        // A PE's base relocations are not read.
        let relocated = RelocatedWords::NotRead(RelocationsNotRead::FormatNotRead);
        // The export table is read through the image's own read view, the one
        // the adapter serves once the image is built.
        let view = LoadedBytes { file: &bytes, placed: &placed, written_by_loader: &relocated };
        let table = export_table(&view, &bytes, image_base);
        // The COFF symbol table, where the header states one (a mingw image
        // not stripped), is not read: its names are not among the symbols,
        // and its functions are not among the starts. Said where the header
        // states it, so an image with none is not told it has one.
        let coff = &pe.header.coff_header;
        let coff_symbols = (coff.number_of_symbol_table > 0).then(|| Unread {
            part: "the COFF symbol table".into(),
            why: format!(
                "the header states {} entries at file offset {:#x}, and this reader reads only the export table",
                coff.number_of_symbol_table, coff.pointer_to_symbol_table
            ),
        });
        // A directory the header states and nobody could read is not an empty
        // export table, and the symbols, which are the exports, are not read
        // either; the names the adapter serves are the same nothing as before.
        let exports_unread = table.as_ref().err().map(|why| Unread { part: "the exports".into(), why: why.to_string() });
        let (exports, symbols, named) = match table {
            Ok(table) => {
                let named = export_symbols(&table, &sections);
                let symbols = named
                    .iter()
                    .map(|(&va, name)| ImageSymbol {
                        va: Va(va),
                        name: name.clone(),
                        kind: SymbolKind::NotStated,
                        extent: Extent::Unknown,
                        table: SymbolTable::Exports,
                    })
                    .collect();
                // A PE export names an address, code or a variable alike.
                let exports = table
                    .into_iter()
                    .map(|e| Export { name: e.name, ordinal: Some(e.ordinal), kind: ItemKind::NotStated, target: e.target.into() })
                    .collect();
                (Answer::Read(exports), Answer::Read(Partial { read: symbols, not_read: coff_symbols.iter().cloned().collect() }), named)
            }
            Err(why) => (Answer::NotRead { why: why.to_string() }, Answer::NotRead { why: why.to_string() }, BTreeMap::new()),
        };

        let delay_loads = oh.data_directories.get_delay_import_descriptor().is_some();
        let (iat, imports, unlisted) = read_imports(&pe, &view, image_base, degraded.as_deref(), delay_loads);

        // Where code starts, as the image states it: every export that lands
        // in an executable section, then every `.pdata` entry with its extent.
        //
        // A PE for i386 has no `.pdata`, so exports are the only thing the file
        // states about where its functions begin — and discovery was not using
        // them. Measured on a 32-bit system DLL: 6 of 422 exported entry points
        // were missed, and two of those were reported five bytes into the
        // function, because the hot-patch prologue `mov edi,edi; push ebp; mov
        // ebp,esp` is not in the scanned pattern set. A declaration beats a
        // pattern; this is the declaration. Forwarders are not in the export
        // map at all — see [`export_symbols`] — so the executable-section test
        // is about data exports, not about them.
        let mut starts: Vec<DeclaredStart> = named
            .keys()
            .copied()
            .map(Va)
            .filter(|va| in_executable_section(&sections, *va))
            .map(|va| DeclaredStart { va, why: StartReason::Export, extent: Extent::Unknown })
            .collect();
        // A PE states a function's extent in `.pdata`, not in a symbol table:
        // each `RUNTIME_FUNCTION` carries `BeginAddress`/`EndAddress`. That is
        // as authoritative as an ELF `st_size` and it is what the CFG builder
        // needs to stop walking — without it a `jmp` to another function reads
        // as an intra-function branch and the extent swallows everything in
        // between. A leaf function with no unwind info has no entry.
        starts.extend(parse_pdata(&bytes, &sections, image_base).into_iter().map(|(begin, end)| DeclaredStart {
            va: Va(begin),
            why: StartReason::UnwindEntry,
            extent: Extent::Stated(end.saturating_sub(begin)),
        }));
        // What the image states about where code starts that is not read
        // here: the entry point (a header field no start is made from), the
        // exports where their table was not read, the COFF symbol table, and
        // the DWARF unwind table a mingw image carries in `.eh_frame`.
        let mut starts_unread: Vec<Unread> = Vec::new();
        if oh.standard_fields.address_of_entry_point != 0 {
            starts_unread.push(Unread {
                part: "the entry point".into(),
                why: format!(
                    "AddressOfEntryPoint ({:#x}) is a header field this reader does not make a start of",
                    oh.standard_fields.address_of_entry_point
                ),
            });
        }
        starts_unread.extend(exports_unread);
        starts_unread.extend(coff_symbols);
        starts_unread.extend(eh_frame_unread(sections.iter().map(|s| (s.name.as_str(), s.file_size))));
        let starts = Partial { read: starts, not_read: starts_unread };

        let codeview = pe.debug_data.as_ref().and_then(|d| d.codeview_pdb70_debug_info.as_ref()).and_then(|cv| {
            let path = cv.filename.split(|&b| b == 0).next().unwrap_or_default();
            (path.len() <= MAX_PDB_PATH).then(|| CodeView { guid: cv.signature, age: cv.age, pdb_path: String::from_utf8_lossy(path).into_owned() })
        });

        let machine = Machine {
            isa: coff_machine(&bytes),
            address_model: AddressModel::Native(PointerWidth::of_64_bit(is_64)),
            byte_order: ByteOrder::Little,
            // 64-bit PE → Win64 register ABI; 32-bit PE → cdecl (stack-based args).
            abi: if is_64 { "win64" } else { "cdecl" },
        };
        let public_sections = sections
            .iter()
            .map(|s| Section {
                name: s.name.clone(),
                va: Va(s.va_start),
                size: s.va_end - s.va_start,
                file_offset: s.file_offset as u64,
                file_size: s.file_size as u64,
                executable: s.executable,
                in_image: true,
            })
            .collect();
        Ok(StaticPe {
            bytes,
            machine,
            linkage,
            segments: Segments { base: Va(image_base), span: size_of_image, list: segments },
            sections: public_sections,
            placed,
            symbols,
            exports,
            imports,
            starts,
            iat,
            unlisted,
            findings: degraded.map(|why| Finding::StrictParseRefused { why }).into_iter().collect(),
            codeview,
            relocated,
        })
    }
}

/// `.eh_frame`, where the image has one with bytes in the file: a mingw PE
/// carries DWARF unwind there as an ELF does, and neither reader reads its
/// entries as starts (§5 step 4 brings one `.eh_frame` parser). A PE section
/// table holds eight bytes of a name, so a stripped mingw image names it
/// `.eh_fram` (`llvm-readobj --sections` on `ordinals-i686.exe`); only an
/// ELF's or an unstripped PE's carries the whole name.
pub(crate) fn eh_frame_unread<'a>(mut sections: impl Iterator<Item = (&'a str, usize)>) -> Option<Unread> {
    sections.any(|(name, file_size)| matches!(name, ".eh_frame" | ".eh_fram") && file_size > 0).then(|| Unread {
        part: "the .eh_frame unwind table".into(),
        why: "its frame descriptions state where functions start and end, and this reader does not read them".into(),
    })
}

/// The COFF `Machine` field, mapped onto the same names the ELF reader
/// reports so one consumer reads both formats. An unrecognized machine is
/// returned as its raw value rather than guessed into a wrong name — a wrong
/// answer here silently decodes one instruction set as another.
fn coff_machine(bytes: &[u8]) -> Isa {
    let rd = |o: usize| -> Option<u16> { bytes.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]])) };
    let Some(e_lfanew) = bytes.get(0x3c..0x40).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize) else {
        return Isa::Unreadable;
    };
    if bytes.get(e_lfanew..e_lfanew + 4) != Some(&b"PE\0\0"[..]) {
        return Isa::Unreadable;
    }
    match rd(e_lfanew + 4) {
        Some(0x8664) => Isa::X64,
        Some(0x014c) => Isa::X86,
        Some(0xAA64) => Isa::Arm64,
        Some(0x01c0 | 0x01c4) => Isa::Arm,
        Some(raw) => Isa::Unrecognized { raw },
        None => Isa::Unreadable,
    }
}

/// The import directory: the IAT slot map every symbol answer reads, and the
/// imports grouped by descriptor.
///
/// The IAT **slot** RVA is goblin's `Import::offset` — despite the name it is
/// an RVA (`import_address_table_rva + i * word_size`), not a file offset.
/// `Import::rva` is the hint/name-table entry (the `IMAGE_IMPORT_BY_NAME`
/// struct), which is *not* what a `call qword ptr [rip+disp]` points at —
/// keying the map by it meant no real import call ever resolved a name,
/// silently defeating every analysis that depends on callee names
/// (noreturn-call CFG closure, thunk tail calls, known-API signatures).
/// Ordinal-only imports have no hint/name entry at all, so they were doubly
/// invisible; they resolve fine here.
///
/// After a degraded parse the slots goblin recovered are still served, as
/// they always were, but the grouped answer is not read: what did not parse
/// is missing, and a list of what did would read as the whole table.
///
/// **The same for an image with a delay-load import table** (data directory
/// 13), which is not read: its libraries and names are as much what the image
/// needs as the ordinary table's, and a list of the ordinary table alone read
/// as all of them — a planted DLL delay-loading two functions from one
/// library answered `read` with only its other library, and one whose only
/// import was delay-loaded answered `read` with nothing. Reading the delay
/// table belongs with what its slots are bound to: a delay slot holds the
/// address of a loader stub inside the image until its first call, and
/// answering it as an import would rename every call through it, which this
/// step must not do.
///
/// Either way a slot the map does not list is not known to be unbound, and
/// [`Image::binding_at`] says it was not read, for the reason the grouped
/// answer gives: a delay-load slot of a planted DLL answered `Unbound` while
/// the image's imports said the table binding it was not read.
///
/// **Each descriptor's lookup table is also walked here, through the image's
/// own read view, and counted** ([`lookup_entries`]), because the parser
/// returns fewer entries than a table holds without saying so: it skips an
/// entry whose hint/name entry it cannot place (its RVA in no section) even
/// in a strict parse, and numbers the slots of the entries after it from the
/// skipped one's. On a PE32 planted from `ordinals-i686.exe` with its first
/// lookup entry's name RVA set to `0x7fff0000`, the list held one reference
/// of the library's two, by ordinal 7, at the slot `llvm-objdump -p` gives
/// the skipped `by_name`. Where the walk and the parser disagree, the
/// library says which entries were not read and why, and the references
/// from the first disagreeing entry on say that their slot was not read.
/// What [`Image::binding_at`] answers for the slots is left as it was, the
/// parser's: this step changes no answer.
fn read_imports(
    pe: &PE,
    view: &LoadedBytes<'_>,
    image_base: u64,
    degraded: Option<&str>,
    delay_loads: bool,
) -> (BTreeMap<u64, ImportRef>, Answer<Imports>, UnlistedSlot) {
    let descriptors: &[goblin::pe::import::SyntheticImportDirectoryEntry] = pe.import_data.as_ref().map(|d| d.import_data.as_slice()).unwrap_or_default();
    // The file-name part of a descriptor's name, NULs trimmed: how the slot's
    // symbol has always spelled its module.
    let label = |dll: &str| {
        let dll = dll.trim_end_matches('\0');
        Path::new(dll).file_name().and_then(|s| s.to_str()).unwrap_or(dll).to_string()
    };
    let mut libraries: Vec<Library> = descriptors
        .iter()
        .map(|d| Library { name: label(d.name), stated_by: LibrarySource::ImportDescriptor, references_not_read: Vec::new() })
        .collect();
    let width = if pe.is_64 { 8 } else { 4 };
    // Per descriptor, the index of its first entry the parser's list does not
    // hold as the table holds it, and why; `None` where they agree.
    let short: Vec<Option<(usize, String)>> = descriptors
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let parsed: Vec<LookupEntry> = pe
                .imports
                .iter()
                .filter(|imp| std::ptr::eq(imp.dll, d.name))
                .map(|imp| if imp.rva == 0 { LookupEntry::Ordinal(imp.ordinal) } else { LookupEntry::Name(imp.rva as u32) })
                .collect();
            let dir = &d.import_directory_entry;
            let walked = lookup_entries(view, image_base, dir.import_lookup_table_rva, dir.import_address_table_rva, width);
            let disagreement = lookup_disagreement(view, image_base, &walked, &parsed);
            if let Some((_, why)) = &disagreement {
                libraries[i].references_not_read.push(Unread { part: "the import lookup table".into(), why: why.clone() });
            }
            disagreement
        })
        .collect();
    // How many of each descriptor's entries were handed out so far.
    let mut handed = vec![0usize; descriptors.len()];
    let mut iat: BTreeMap<u64, ImportRef> = BTreeMap::new();
    let mut references: Vec<ImportReference> = Vec::new();
    for import in &pe.imports {
        let slot_va = image_base.saturating_add(import.offset as u64);
        // goblin gives an import by ordinal no hint/name entry (`rva` 0) and
        // the name `ORDINAL <n>`; a named import always has one.
        let name = if import.rva == 0 { ImportName::Ordinal(import.ordinal) } else { ImportName::Named(import.name.to_string()) };
        iat.insert(slot_va, ImportRef { name: name.clone(), library: Some(label(import.dll)) });
        // The descriptor this import came from: goblin hands each import the
        // descriptor's own name slice, so the slice says which, even where two
        // descriptors name the same library.
        let descriptor = descriptors.iter().position(|d| std::ptr::eq(d.name, import.dll));
        let library = match descriptor {
            Some(i) => LibraryRef::Binds(i),
            None => LibraryRef::Unattributed { why: "the parser gave an import of no descriptor it read" },
        };
        // From the first entry the parser's list does not hold as the table
        // does, its slots are numbered from the wrong entry.
        let reach = match descriptor.and_then(|i| {
            let index = handed[i];
            handed[i] += 1;
            short[i].as_ref().filter(|(first, _)| index >= *first)
        }) {
            Some((first, _)) => Answer::NotRead {
                why: format!(
                    "the parser's entries for this library are not its lookup table's from entry {first} on, and the parser numbers \
                     each entry's slot by its own count, so this slot is not read"
                ),
            },
            None => Answer::Read(vec![Reach::Slot(Va(slot_va))]),
        };
        // An import descriptor's entry names a function or a variable alike.
        references.push(ImportReference { name, kind: ItemKind::NotStated, library, reach });
    }
    let partly = libraries.iter().any(|l| !l.references_not_read.is_empty());
    let not_read = match degraded {
        Some(why) => Some(format!("a strict parse refused the image ({why}); the import table is not taken from the permissive one")),
        None if delay_loads => Some(
            "the image has a delay-load import table (data directory 13), which is not read, so the import table alone is not \
             everything it imports"
                .to_string(),
        ),
        None => None,
    };
    match not_read {
        Some(why) => (iat, Answer::NotRead { why: why.clone() }, UnlistedSlot::NotRead { why }),
        None => {
            let unlisted = if partly {
                UnlistedSlot::NotRead {
                    why: "an import lookup table of the image was not read whole (its library says which), so a slot no entry read \
                          names may still be bound"
                        .into(),
                }
            } else {
                UnlistedSlot::Unbound { why: "no import descriptor names this slot" }
            };
            (iat, Answer::Read(Imports { binding: ImportBinding::PerLibrary, libraries, references, reach_not_read: Vec::new() }), unlisted)
        }
    }
}

/// One entry of an import lookup table: by ordinal, or the RVA of its
/// hint/name entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LookupEntry {
    Ordinal(u16),
    Name(u32),
}

/// What one import lookup table holds, read through the image's own view.
#[derive(Debug, PartialEq, Eq)]
struct Walked {
    rva: u32,
    entries: Vec<LookupEntry>,
    /// Whether the zero entry that ends the table was read; `false` when the
    /// bytes the file holds ran out first.
    terminated: bool,
}

/// The entries of the lookup table a descriptor names, up to its zero entry,
/// read through `view` — the table at `OriginalFirstThunk` where it is set
/// and mapped, else the one at `FirstThunk`, which holds the same entries in
/// an unbound file (and is the table the parser reads in that case too).
/// `None` when neither is mapped.
///
/// **Bounded by the file:** each entry is read from the bytes present, a
/// short read ends the walk, and there are never more entries than the file
/// has `width`-byte words, whatever the table claims.
fn lookup_entries(view: &LoadedBytes<'_>, image_base: u64, lookup_rva: u32, address_rva: u32, width: usize) -> Option<Walked> {
    let mapped = |rva: u32| rva != 0 && view.contains(Va(image_base.saturating_add(u64::from(rva))));
    let rva = if mapped(lookup_rva) {
        lookup_rva
    } else if mapped(address_rva) {
        address_rva
    } else {
        return None;
    };
    let ordinal_bit = 1u64 << (width * 8 - 1);
    let mut entries = Vec::new();
    for i in 0..=view.file.len() / width {
        let at = image_base.saturating_add(u64::from(rva)).saturating_add((i * width) as u64);
        let word = match view.read(Va(at), width) {
            Ok(b) if b.len() == width => b.iter().rev().fold(0u64, |acc, &x| (acc << 8) | u64::from(x)),
            _ => return Some(Walked { rva, entries, terminated: false }),
        };
        if word == 0 {
            return Some(Walked { rva, entries, terminated: true });
        }
        entries.push(if word & ordinal_bit != 0 { LookupEntry::Ordinal(word as u16) } else { LookupEntry::Name((word & 0x7fff_ffff) as u32) });
    }
    Some(Walked { rva, entries, terminated: false })
}

/// Where the parser's entries for one descriptor (`parsed`, in its order)
/// stop being the table's: the index of the first entry that differs, and
/// what to say about it. `None` when the two are the same list.
fn lookup_disagreement(view: &LoadedBytes<'_>, image_base: u64, walked: &Option<Walked>, parsed: &[LookupEntry]) -> Option<(usize, String)> {
    let Some(walked) = walked else {
        return Some((
            0,
            "neither the lookup table nor the address table the descriptor names lies in a section, so its entries are not read".into(),
        ));
    };
    let first = walked.entries.iter().zip(parsed).position(|(w, p)| w != p).unwrap_or(walked.entries.len().min(parsed.len()));
    if first == walked.entries.len() && first == parsed.len() && walked.terminated {
        return None;
    }
    let (held, got) = (walked.entries.len(), parsed.len());
    let mut why = if walked.terminated {
        format!("the table at RVA {:#x} holds {held} entries and the PE parser returned {got}, the same up to entry {first}", walked.rva)
    } else {
        format!(
            "the table at RVA {:#x} runs past the bytes the file holds after {held} entries, and the PE parser returned {got}, the same up \
             to entry {first}",
            walked.rva
        )
    };
    if let Some(LookupEntry::Name(rva)) = walked.entries.get(first)
        && !view.contains(Va(image_base.saturating_add(u64::from(*rva))))
    {
        why.push_str(&format!(
            ": entry {first} names its hint/name entry at RVA {rva:#x}, which lies in no section, and the parser skips such an entry"
        ));
    }
    why.push_str(&format!("; entries from {first} on are not listed, or listed without their slot"));
    Some((first, why))
}

impl Image for StaticPe {
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
    /// Exports and `.pdata` entries are some functions: a leaf function has
    /// no unwind entry and a static no export.
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
        match self.iat.get(&slot.0) {
            Some(import) => Binding::Import(import.clone()),
            None => self.unlisted.binding(),
        }
    }
    fn codeview(&self) -> Option<&CodeView> {
        self.codeview.as_ref()
    }
}

/// Whether `va` lies in a section the image marks executable.
fn in_executable_section(sections: &[SectionRange], va: Va) -> bool {
    sections.iter().any(|s| s.executable && va.0 >= s.va_start && va.0 < s.va_end)
}

/// The image's export table, classified by the one reader every consumer
/// shares ([`read_export_table`](crate::read_export_table)) — so this loader
/// and `profile` cannot disagree about which entries are forwarders — and read
/// through the image's own read view (`view`), so it reads what every later
/// read of the image reads. `Err` says why a directory the header states was
/// not read at all.
fn export_table(view: &LoadedBytes<'_>, bytes: &[u8], image_base: u64) -> Result<Vec<PeExport>, &'static str> {
    let Some(dir) = ExportDirectory::from_header(bytes) else { return Ok(Vec::new()) };
    try_read_export_table(view, Va(image_base), dir)
}

/// The names the image gives its addresses, from the classified export table.
///
/// - A **named** export is a symbol wherever it lands — code or an exported
///   variable. Two names on one address: the later in name order wins, as it
///   always has.
/// - An export **by ordinal only** is a symbol when it lands in executable
///   code. The third-party parser's export list, which this loader once took
///   its exports from, holds named exports only, so on this corpus 853 of
///   1216 exported functions were invisible to symbol resolution, discovery
///   and cross-references alike; a DLL that exports mostly by ordinal is the
///   norm for system and shipped-application libraries. A name never yields to one:
///   the file gives an ordinal, and `Ordinal<n>` says exactly that rather than
///   inventing a name.
/// - A **forwarder** is not a symbol at all. Its table address is the
///   `MODULE.Function` string the OS loader follows into another module, and
///   naming that address made the decompiler title a string after a function
///   and `sig gen` fingerprint the text as code.
fn export_symbols(table: &[PeExport], sections: &[SectionRange]) -> BTreeMap<u64, String> {
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    // `read_export_table` lists every named entry before any unnamed one, so a
    // name is always in place before an ordinal could claim its address.
    for e in table {
        let ExportTarget::Local(va) = e.target else { continue };
        match &e.name {
            Some(name) => {
                out.insert(va.0, name.clone());
            }
            None if in_executable_section(sections, va) => {
                out.entry(va.0).or_insert_with(|| format!("Ordinal{}", e.ordinal));
            }
            None => {} // a data export with no name: nothing to call it
        }
    }
    out
}

/// Read the `.pdata` exception table into `begin VA → exclusive end VA`.
///
/// The table is found through the optional header's exception data directory
/// (index 3), and each `RUNTIME_FUNCTION` is three RVAs: begin, end, unwind.
/// Every bound comes from the bytes actually present — nothing is sized from a
/// value read out of the file — so a truncated or hostile table yields a short
/// map rather than a large allocation.
///
/// Absent (`0` RVA, no unwind info, 32-bit PE) leaves the map empty.
///
/// **A known wrong answer, kept because this step changes none:** an ARM64
/// PE32+ passes the magic check, and its `.pdata` holds 8-byte records (a
/// begin RVA and an unwind-data RVA or packed unwind word), which are read
/// here as 12-byte x86-64 ones. On an ARM64 DLL linked here (clang and
/// lld-link 23.1.1), `llvm-readobj --unwind` lists four functions of 60, 44,
/// 40 and 40 bytes; this map holds one, the first, ending `0x121efd9` bytes
/// past its start (`function discover --pdata` answers the same in 0.3.5).
/// It goes with §5 step 4's one `.pdata` parser.
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
    use crate::{ImageSource, MemorySource, SymbolProvider};

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

    /// The loader's by-ordinal symbols as `(va, ordinal)`, read exactly the way
    /// the reader reads them: the shared table, then the symbol map.
    fn ordinal_exports(bytes: &[u8], sections: &[SectionRange], image_base: u64) -> Vec<(u64, u32)> {
        let placed: Vec<Placement> = sections
            .iter()
            .map(|s| Placement { va: s.va_start, end: s.va_end, file_offset: s.file_offset, file_size: s.file_size })
            .collect();
        let relocated = RelocatedWords::NotRead(RelocationsNotRead::FormatNotRead);
        let view = LoadedBytes { file: bytes, placed: &placed, written_by_loader: &relocated };
        let table = export_table(&view, bytes, image_base).unwrap_or_default();
        let map = export_symbols(&table, sections);
        table
            .iter()
            .filter(|e| e.name.is_none())
            .filter_map(|e| match e.target {
                ExportTarget::Local(va) if map.get(&va.0).is_some_and(|name| *name == format!("Ordinal{}", e.ordinal)) => {
                    Some((va.0, e.ordinal))
                }
                _ => None,
            })
            .collect()
    }

    /// A PE32+ file with one executable section (RVA 0x1000, file 0x1000)
    /// holding the export directory *and* the code, and an export table of two
    /// named entries: `code_export` at RVA 0x1300 (`ret`), and `fwd_export`,
    /// whose address-table entry points inside the directory at the string
    /// `OTHERDLL.Function`.
    ///
    /// The directory sits in the executable section on purpose: there the
    /// forwarder string's address also passes the "lands in code" test that
    /// [`ImageSource::declared_entry_points`] applies, so only knowing it is a
    /// forwarder keeps it out.
    fn pe_with_a_forwarder() -> Vec<u8> {
        let mut b = vec![0u8; 0x2000];
        let put32 = |b: &mut Vec<u8>, o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        b[0..2].copy_from_slice(b"MZ");
        put32(&mut b, 0x3c, 0x40);
        b[0x40..0x44].copy_from_slice(b"PE\0\0");
        b[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes()); // machine
        b[0x46..0x48].copy_from_slice(&1u16.to_le_bytes()); // one section
        b[0x54..0x56].copy_from_slice(&240u16.to_le_bytes()); // SizeOfOptionalHeader
        b[0x56..0x58].copy_from_slice(&0x2022u16.to_le_bytes()); // DLL | executable | large-address
        let opt = 0x58;
        b[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        b[opt + 24..opt + 32].copy_from_slice(&0x1_8000_0000u64.to_le_bytes()); // ImageBase
        put32(&mut b, opt + 32, 0x1000); // SectionAlignment
        put32(&mut b, opt + 36, 0x200); // FileAlignment
        put32(&mut b, opt + 56, 0x2000); // SizeOfImage
        put32(&mut b, opt + 60, 0x400); // SizeOfHeaders
        put32(&mut b, opt + 108, 16); // NumberOfRvaAndSizes
        put32(&mut b, opt + 112, 0x1100); // export directory RVA
        put32(&mut b, opt + 116, 0x100); // ... and size
        let sh = opt + 240;
        b[sh..sh + 5].copy_from_slice(b".text");
        put32(&mut b, sh + 8, 0x1000); // VirtualSize
        put32(&mut b, sh + 12, 0x1000); // VirtualAddress
        put32(&mut b, sh + 16, 0x1000); // SizeOfRawData
        put32(&mut b, sh + 20, 0x1000); // PointerToRawData
        put32(&mut b, sh + 36, 0x6000_0020); // code | execute | read
        let dir = 0x1100;
        put32(&mut b, dir + 16, 1); // ordinal base
        put32(&mut b, dir + 20, 2); // NumberOfFunctions
        put32(&mut b, dir + 24, 2); // NumberOfNames
        put32(&mut b, dir + 28, 0x1140); // AddressOfFunctions
        put32(&mut b, dir + 32, 0x1150); // AddressOfNames
        put32(&mut b, dir + 36, 0x1160); // AddressOfNameOrdinals
        put32(&mut b, 0x1140, 0x1300); // slot 0: code
        put32(&mut b, 0x1144, 0x11c0); // slot 1: inside the directory
        put32(&mut b, 0x1150, 0x1170);
        put32(&mut b, 0x1154, 0x1180);
        b[0x1160..0x1162].copy_from_slice(&0u16.to_le_bytes());
        b[0x1162..0x1164].copy_from_slice(&1u16.to_le_bytes());
        b[0x1170..0x117c].copy_from_slice(b"code_export\0");
        b[0x1180..0x118b].copy_from_slice(b"fwd_export\0");
        b[0x11c0..0x11d2].copy_from_slice(b"OTHERDLL.Function\0");
        b[0x1300] = 0xc3;
        b
    }

    /// THE DEFECT. A forwarder's table address is a string, and the loader
    /// named it: `named_functions()` handed it to `sig gen`, which built
    /// signatures out of forwarder text, and `symbol_at` titled the string
    /// after the function it forwards to.
    #[test]
    fn a_forwarder_is_not_a_function_of_this_image() {
        let p = temp("forwarder", &pe_with_a_forwarder());
        let pe = ImageSource::load(&p).expect("the image loads");
        let _ = std::fs::remove_file(&p);
        let base = 0x1_8000_0000u64;
        assert_eq!(
            pe.named_functions(),
            vec![(Va(base + 0x1300), "code_export".to_string())],
            "only the export with code here is a function; the forwarder string is not"
        );
        assert!(pe.symbol_at(Va(base + 0x11c0)).is_none(), "the forwarder string's address names nothing");
        assert_eq!(pe.declared_entry_points(), vec![Va(base + 0x1300)], "nor is it an entry point");
    }

    #[test]
    fn a_pe32_loads_and_reports_32bit_so_the_frontend_picks_the_i386_arch() {
        // The bitness must be detected and surfaced (not rejected): the frontend
        // keys on it to select the 32-bit decoder, which is what stops a PE32
        // from being silently mis-decoded as x64. `is_64 == false`, 4-byte
        // pointers, and a `cdecl` ABI.
        let p = temp("pe32", &minimal_pe(0x10b));
        let pe = ImageSource::load(&p).expect("a PE32 now loads");
        assert!(pe.pointer_size() != Some(8), "a PE32 must report 32-bit");
        assert_eq!(pe.pointer_size(), Some(4));
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
        let pe = ImageSource::load(&p).expect("a PE32 loads");
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
        match ImageSource::load(&p) {
            Ok(pe) => {
                assert!(pe.pointer_size() == Some(8), "the image still opens and reports its bitness");
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
        let pe = ImageSource::load(&p).expect("a well-formed PE32+ loads");
        assert_eq!(pe.degraded(), None);
        let _ = std::fs::remove_file(&p);
    }

    /// A PE with `IMAGE_FILE_DLL` (`0x2000`) in its COFF characteristics is a
    /// library, one without it a program: the same planted image with the bit
    /// set and clear.
    #[test]
    fn a_dll_is_a_library() {
        for (tag, characteristics, want) in [("exe", 0x0102u16, crate::Linkage::Executable), ("dll", 0x2102, crate::Linkage::SharedLibrary)] {
            let mut b = minimal_pe(0x20b);
            b[0x56..0x58].copy_from_slice(&characteristics.to_le_bytes());
            let p = temp(tag, &b);
            let pe = ImageSource::load(&p).expect("the image loads");
            assert_eq!(pe.linkage(), want, "characteristics {characteristics:#06x}");
            let _ = std::fs::remove_file(&p);
        }
    }

    /// An export directory the header states and no section maps was read as
    /// an empty export table — "exports nothing", which nobody looked at. The
    /// planted image states one at RVA 0x9000, past every byte it has; one
    /// with no directory at all is the control, and exports nothing.
    #[test]
    fn an_export_directory_that_cannot_be_read_is_not_an_empty_table() {
        let dd = 0x40 + 24 + 112; // PE32+ data directory 0
        let mut stated = minimal_pe(0x20b);
        stated[dd..dd + 4].copy_from_slice(&0x9000u32.to_le_bytes());
        stated[dd + 4..dd + 8].copy_from_slice(&0x40u32.to_le_bytes());
        for (tag, bytes, readable) in [("exports_unmapped", stated, false), ("exports_none", minimal_pe(0x20b), true)] {
            let p = temp(tag, &bytes);
            let pe = ImageSource::load(&p).expect("the image loads");
            let _ = std::fs::remove_file(&p);
            match (pe.image().exports(), readable) {
                (Answer::Read(table), true) => assert!(table.is_empty(), "{tag}: {table:?}"),
                (Answer::NotRead { why }, false) => assert!(why.contains("export directory"), "{tag}: {why}"),
                (other, _) => panic!("{tag}: {other:?}"),
            }
            // The symbols of a PE are its exports, so they are not read either.
            assert_eq!(matches!(pe.image().symbols(), Answer::Read(_)), readable, "{tag}: {:?}", pe.image().symbols());
        }
    }

    #[test]
    fn a_pe32plus_reports_64bit_and_win64() {
        let p = temp("pe32plus", &minimal_pe(0x20b));
        let pe = ImageSource::load(&p).expect("a PE32+ loads");
        assert!(pe.pointer_size() == Some(8));
        assert_eq!(pe.pointer_size(), Some(8));
        assert_eq!(MemorySource::abi_name(&pe), "win64");
        let _ = std::fs::remove_file(&p);
    }
}
