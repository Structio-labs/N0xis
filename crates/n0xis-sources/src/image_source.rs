// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`ImageSource`] — an image file as a source: the one adapter that turns
//! any [`Image`]'s answers into the seams every pass reads ([`MemorySource`],
//! [`SymbolProvider`], [`ModuleProvider`]).
//!
//! **One adapter, not one per format** (IMAGE_FORMATS.md §2). Symbol lookup,
//! import slots, function sizes and thunk targets used to be computed by each
//! reader for itself, behind an enum that forwarded every call to one of two
//! variants; a method the enum forgot to forward silently answered the trait
//! default. Here each is computed once, from the trait's facts, by one rule
//! for every format — so a third format brings its answers, not a third copy
//! of the lookups.
//!
//! The rules are the ones the readers applied before, moved, not changed; the
//! comparison of every fact on 495 images before and after the move is what
//! says so (§5 step 1).

use std::collections::BTreeMap;
use std::path::Path;

use n0xis_contracts::{Module, SymKind, Symbol, Va};

use crate::image::{
    Binding, CodeView, Extent, Finding, FormatTables, Image, ImageFormat, OpenError, OpenOptions, Opened, SNIFF_LEN, StartCoverage, StartReason,
    SymbolKind,
};
use crate::{ByteOrder, Linkage, MemorySource, ModuleProvider, RelocatedWords, SourceError, SourceId, SymbolProvider};

/// Module name a symbol carries for an import whose provider library the image
/// does not name (an ELF symbol with no `.gnu.version_r` entry). ELF
/// resolution is a *flat* namespace, so an unversioned import genuinely has no
/// named provider — this says so instead of guessing one from `DT_NEEDED`.
const UNKNOWN_PROVIDER: &str = "extern";

/// An image on disk, served at its preferred base.
#[derive(Debug)]
pub struct ImageSource {
    format: ImageFormat,
    image: Box<dyn Image>,
    /// What the format states beyond the [`Image`] questions.
    tables: FormatTables,
    /// What the file holds, for keying what is kept between requests.
    id: SourceId,
    /// The file name, the module's and the label's.
    module_name: String,
    /// Exactly one module — the image itself (kept as a slice for the trait).
    modules: Vec<Module>,
    /// The name each address answers to.
    symbols: BTreeMap<u64, Symbol>,
    /// The stated size of the function at each address.
    sizes: BTreeMap<u64, u64>,
    /// The stated size of the data object [`Self::symbols`] names at an address.
    data_sizes: BTreeMap<u64, u64>,
    /// Stub → the definition in this image its slot is bound to.
    thunks: BTreeMap<u64, u64>,
    /// Exports in executable sections, address-ordered.
    entry_points: Vec<Va>,
}

impl ImageSource {
    /// Load `path` with whichever reader of the registry ([`crate::formats`])
    /// recognizes it. Anything none recognizes is an explicit load error
    /// (rather than the old confusing "DOS header is malformed" from forcing
    /// every file through the PE parser).
    pub fn load(path: &Path) -> Result<Self, SourceError> {
        let file = std::fs::File::open(path).map_err(|e| SourceError::Load(format!("open '{}': {e}", path.display())))?;
        let (format, bytes) = match read_recognized(file) {
            Ok(Some(found)) => found,
            Ok(None) => {
                let known: Vec<&str> = crate::image::formats().iter().map(|f| f.described).collect();
                return Err(SourceError::Load(format!("'{}': not {}", path.display(), one_of(&known))));
            }
            Err(e) => return Err(SourceError::Load(format!("read '{}': {e}", path.display()))),
        };
        let id = SourceId::of(&bytes);
        let (image, tables) = match (format.open)(bytes, &OpenOptions::default()) {
            Ok(Opened::Thin { image, tables }) => (image, tables),
            Err(OpenError::Parse(e)) => return Err(SourceError::Load(format!("parse '{}': {e}", path.display()))),
            Err(OpenError::Refused(why)) => return Err(SourceError::Load(why)),
        };
        let module_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("module").to_string();
        let segments = image.segments();
        let modules =
            vec![Module { name: module_name.clone(), base: segments.base, size: segments.span, path: Some(path.to_string_lossy().to_string()) }];
        let mut source = ImageSource {
            format: format.format,
            image,
            tables,
            id,
            module_name,
            modules,
            symbols: BTreeMap::new(),
            sizes: BTreeMap::new(),
            data_sizes: BTreeMap::new(),
            thunks: BTreeMap::new(),
            entry_points: Vec::new(),
        };
        source.index();
        Ok(source)
    }

    /// Compute every lookup from the image's answers.
    fn index(&mut self) {
        let own = &self.module_name;
        // The first symbol at an address names it; its size, if it is a data
        // object, is kept with it — a size is a fact about one object, read
        // with its name.
        // What the image says was not read is not here: the lookups serve what
        // was read, and say nothing about the rest.
        if let Some(symbols) = self.image.symbols().read() {
            for s in &symbols.read {
                if let std::collections::btree_map::Entry::Vacant(slot) = self.symbols.entry(s.va.0) {
                    let kind = match s.kind {
                        SymbolKind::Function | SymbolKind::NotStated => SymKind::Export,
                        SymbolKind::Object => SymKind::Data,
                    };
                    slot.insert(Symbol { va: s.va, module: own.clone(), name: s.name.clone(), kind });
                    if let (SymbolKind::Object, Extent::Stated(n)) = (s.kind, s.extent) {
                        self.data_sizes.insert(s.va.0, n);
                    }
                }
            }
        }
        for start in &self.image.declared_starts().read {
            // Aliases at one address agree on the size; the first stated one
            // is kept, and disagreement would mean a malformed table.
            if let Extent::Stated(n) = start.extent {
                self.sizes.entry(start.va.0).or_insert(n);
            }
            match start.why {
                StartReason::Export => self.entry_points.push(start.va),
                // A stub is named after the import its slot is bound to — a
                // real symbol for its address (an unstripped `foo@plt`) always
                // wins; this only fills a hole — and one bound to a definition
                // here forwards into this same image: recorded, so a
                // whole-program pass follows the program's own call graph
                // instead of stopping at a thunk.
                //
                // A slot both relocations bind does both, as the reader did
                // before the trait: the two facts were kept apart then, and
                // dropping either changes an answer.
                StartReason::Stub { slot } => {
                    let (import, target) = match self.image.binding_at(slot) {
                        Binding::Import(import) => (Some(import), None),
                        Binding::SelfDefinition { target } => (None, Some(target)),
                        Binding::ImportAndSelfDefinition { import, target } => (Some(import), Some(target)),
                        Binding::Unbound { .. } | Binding::NotRead { .. } => (None, None),
                    };
                    if let Some(target) = target
                        && target != start.va
                    {
                        self.thunks.insert(start.va.0, target.0);
                    }
                    if let Some(import) = import {
                        self.symbols.entry(start.va.0).or_insert_with(|| Symbol {
                            va: start.va,
                            module: import.library.clone().unwrap_or_else(|| UNKNOWN_PROVIDER.to_string()),
                            name: import.name.symbol_name(),
                            kind: SymKind::Import,
                        });
                    }
                }
                StartReason::Symbol | StartReason::UnwindEntry | StartReason::Body { .. } => {}
            }
        }
        self.entry_points.sort_unstable();
        self.entry_points.dedup();
    }

    /// Which reader opened the image. **A transitional accessor**: the call
    /// sites that still ask it (`.pdata` reading, the Itanium RTTI scan, the
    /// ELF profile, the ARM vtable slot format) ask the format for a fact a
    /// role or a metadata unit will answer (§5 steps 4 and 5).
    pub fn format(&self) -> ImageFormat {
        self.format
    }

    /// What the format states beyond the [`Image`] questions: the one way
    /// to reach a WebAssembly module's own structure (its index spaces, its
    /// bodies) from an image source.
    pub fn tables(&self) -> &FormatTables {
        &self.tables
    }

    /// The identity a WebAssembly module's annotations are kept under: its
    /// `build_id` section, else a hash of its bytes (docs/design/WASM.md §5
    /// decision 1). `None` for a native image, whose annotations are keyed by
    /// address alone, as they always were.
    pub fn module_identity(&self) -> Option<&str> {
        match &self.tables {
            FormatTables::Native => None,
            #[cfg(feature = "static-wasm")]
            FormatTables::Wasm(module) => Some(module.identity()),
        }
    }

    /// Every function the image has, as `(start, exclusive end)`, where it
    /// declares them all ([`StartCoverage::Every`]: a WebAssembly module's
    /// bodies); `None` where it declares only some, and the rest are found by
    /// discovery. Native images answer `None`, so nothing they answer changes.
    ///
    /// A start whose extent is not stated is `(start, start)`, the form a
    /// declared start with no length takes in `Ctx::functions`: still a
    /// function, with no end. Leaving it out dropped a function from the
    /// list without a word — a corrupted module's body of size 0, which the
    /// image's findings name and the list did not.
    pub fn every_function(&self) -> Option<Vec<(Va, Va)>> {
        match self.image.start_coverage() {
            StartCoverage::Some => None,
            StartCoverage::Every => Some(
                self.image
                    .declared_starts()
                    .read
                    .iter()
                    .map(|s| match s.extent {
                        Extent::Stated(n) => (s.va, s.va.0.checked_add(n).map_or(s.va, Va)),
                        Extent::Unknown => (s.va, s.va),
                    })
                    .collect(),
            ),
        }
    }

    /// The reader's own answers.
    pub fn image(&self) -> &dyn Image {
        self.image.as_ref()
    }

    /// Which PDB was built with this image. An ELF carries none.
    pub fn codeview(&self) -> Option<&CodeView> {
        self.image.codeview()
    }

    /// Preferred image base: a PE's optional header; an ELF's minimum
    /// `PT_LOAD` virtual address (0 for a position-independent executable).
    pub fn image_base(&self) -> Va {
        self.image.segments().base
    }

    /// The single module descriptor for this image.
    pub fn module(&self) -> &Module {
        &self.modules[0]
    }

    /// The primary code extent `(start, size)`: a native image's `.text`
    /// section; a WebAssembly module's code section, its one section of code
    /// (whose contents hold the bodies and, between them, their sizes, which
    /// the module's architecture decodes past).
    pub fn text_range(&self) -> Option<(Va, u64)> {
        match &self.tables {
            FormatTables::Native => self.section_range(".text"),
            #[cfg(feature = "static-wasm")]
            FormatTables::Wasm(_) => self.image.sections().iter().find(|s| s.executable).map(|s| (s.va, s.size)),
        }
    }

    /// The named function symbols the image carries (`(va, name)`, address-
    /// ordered) — a signature generator's input, and what `profile` reports as
    /// an ELF's answer to a PE export table. A PE contributes its exports; an
    /// ELF its defined `.symtab`/`.dynsym` functions; a fully stripped image
    /// yields nothing.
    ///
    /// Excludes the **PLT stubs** named after their imports: a stub is a thunk
    /// into another library, not code this image defines. Signing one is both
    /// useless and unsafe — every x86-64 lazy PLT entry embeds its own
    /// relocation index (`push <n>`), a value specific to *this* binary's link
    /// order, so the pattern either matches nothing elsewhere or matches an
    /// unrelated stub that happens to share the index. A PE's forwarders are
    /// absent too: their table address is a `MODULE.Function` string, and
    /// fingerprinting it put 126 signatures made of forwarder text into a
    /// 1 554-signature library built from a 0.9 MB x64 system DLL.
    pub fn named_functions(&self) -> Vec<(Va, String)> {
        self.symbols.values().filter(|s| s.kind == SymKind::Export).map(|s| (s.va, s.name.clone())).collect()
    }

    /// A named section's range `(start, size)` — e.g. `.rdata` for
    /// string-literal scanning, not just `.text`. The first section of the
    /// name answers.
    pub fn section_range(&self, name: &str) -> Option<(Va, u64)> {
        self.image.sections().iter().find(|s| s.name == name).map(|s| (s.va, s.size))
    }

    /// Every section that carries on-disk bytes, as `(name, va, size)` — the
    /// ranges a byte/string search (`find`) can actually read. Sections that
    /// occupy address space but hold no file bytes (`.bss`) are skipped; the
    /// readable size is the on-disk size.
    pub fn sections(&self) -> Vec<(String, Va, u64)> {
        self.image.sections().iter().filter(|s| s.file_size > 0).map(|s| (s.name.clone(), s.va, s.file_size)).collect()
    }

    /// Every section with its executable flag — the shape `profile` needs.
    ///
    /// Separate from [`Self::sections`] (which `find` uses to bound a byte
    /// search and therefore wants only file-backed ranges) because a profile
    /// must report the section table as it is, executability included: `.text`
    /// is not always where the code lives.
    pub fn sections_detailed(&self) -> Vec<(String, Va, u64, bool)> {
        self.image.sections().iter().map(|s| (s.name.clone(), s.va, s.size, s.executable)).collect()
    }

    /// Defined data objects the image names — where an ELF keeps its C++
    /// vtables (`_ZTV…`) and type-info objects (`_ZTI…`), which Itanium RTTI
    /// recovery needs. Each with the size its symbol states
    /// ([`crate::DataSymbol`]).
    pub fn data_symbols(&self) -> Vec<crate::DataSymbol> {
        self.symbols
            .values()
            .filter(|s| s.kind == SymKind::Data)
            .map(|s| crate::DataSymbol { va: s.va, name: s.name.clone(), size: self.data_sizes.get(&s.va.get()).copied() })
            .collect()
    }

    /// The words a load-time relocation writes, or why they were not read
    /// ([`crate::RelocatedWords`]).
    pub fn relocated_words(&self) -> &RelocatedWords {
        self.image.loaded_bytes().written_by_loader
    }

    /// Why a strict parse refused this image, when it had to be opened
    /// permissively. `None` on a well-formed image.
    pub fn degraded(&self) -> Option<&str> {
        self.image.findings().iter().find_map(|f| match f {
            Finding::StrictParseRefused { why } => Some(why.as_str()),
            Finding::Contradiction { .. } | Finding::PartNotRead { .. } => None,
        })
    }

    /// The image's data pointer size in bytes: 4 for PE32 and `ELFCLASS32`, 8
    /// for PE32+ and `ELFCLASS64`; `None` for a WebAssembly module, which has
    /// no one address space to point into ([`crate::AddressModel`]).
    ///
    /// The format's own statement of width — not the decoder's: an x32 ELF is
    /// `ELFCLASS32` with x86-64 code, and the decoder is chosen from the machine
    /// field ([`Self::machine`]), never from this. It used to answer 8 for
    /// every ELF, a documented simplification that waited for a reader; the
    /// Itanium RTTI scan was that reader, and on a 32-bit ELF it answered
    /// `ok: true` with no classes or with the wrong vtable addresses.
    pub fn pointer_size(&self) -> Option<u8> {
        self.image.machine().address_model.pointer_width().map(crate::PointerWidth::bytes)
    }

    /// What instruction set the image says it holds (`x64`, `x86`, `arm64`,
    /// `arm`, or raw hex when the format names one this build does not map).
    ///
    /// This is the image's own statement, and it is what an analysis should
    /// decode with. Before it was consulted, an AArch64 ELF was disassembled as
    /// x86-64 by default and answered with confident nonsense — `jnp`, `div
    /// dword ptr` — over four-byte ARM instructions, with no error anywhere.
    pub fn machine(&self) -> String {
        self.image.machine().isa.name()
    }

    /// The byte order of the image's data: an ELF's `e_ident[EI_DATA]`; a PE is
    /// little-endian by its specification.
    pub fn byte_order(&self) -> ByteOrder {
        self.image.machine().byte_order
    }

    /// A program or a library, as the image's own headers say
    /// ([`crate::Linkage`]).
    pub fn linkage(&self) -> Linkage {
        self.image.linkage()
    }

    /// Addresses the image itself declares as entry points, with no extent.
    ///
    /// A PE names its exports; an ELF's `FUNC` symbols already carry sizes and
    /// reach discovery through the extent seam, so nothing is added here for
    /// one. Empty is a normal answer — a stripped image declares nothing.
    pub fn declared_entry_points(&self) -> Vec<Va> {
        self.entry_points.clone()
    }
}

/// `a`, `a or b`, `a, b or c`: the formats a refusal names.
fn one_of(names: &[&str]) -> String {
    match names {
        [] => "a format this build reads".to_string(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
    }
}

/// The format the leading bytes of `reader` carry, and then the whole of it;
/// `None`, having read at most [`SNIFF_LEN`] bytes, when no format recognizes
/// them.
///
/// **Recognition comes before the read, not after it**, so what bounds the
/// bytes read from a file no reader recognizes is a constant, not the file: a
/// device that never ends (`/dev/zero`) or a multi-gigabyte file of something
/// else is refused at once, as 0.3.5 refused it, where reading it whole first
/// ran until the memory did (`SNIFF_LEN`'s own comment has the measurement).
///
/// A prefix that cannot be read (a directory opens on Linux, and its reads
/// fail) is one no format recognizes, as it always was; a recognized file
/// whose remaining bytes cannot be read is the read error, as each reader's
/// own load gave it.
fn read_recognized(mut reader: impl std::io::Read) -> std::io::Result<Option<(&'static crate::image::Format, Vec<u8>)>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    if reader.by_ref().take(SNIFF_LEN as u64).read_to_end(&mut bytes).is_err() {
        return Ok(None);
    }
    let Some(format) = crate::image::recognize(&bytes) else { return Ok(None) };
    reader.read_to_end(&mut bytes)?;
    Ok(Some((format, bytes)))
}

impl MemorySource for ImageSource {
    /// The image's read view ([`crate::LoadedBytes`]), whose rule this is.
    fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, SourceError> {
        self.image.loaded_bytes().read(va, len)
    }

    fn contains(&self, va: Va) -> bool {
        self.image.loaded_bytes().contains(va)
    }

    /// An image on disk cannot change under the loaded copy; everything the
    /// source answers comes from its bytes.
    fn identity(&self) -> Option<SourceId> {
        Some(self.id)
    }

    /// A readable stretch starts where a placement starts or another ends.
    fn next_readable(&self, va: Va, end: Va) -> Result<Option<Va>, SourceError> {
        let bounds = self.image.loaded_bytes().placed.iter().flat_map(|p| [p.va, p.end]);
        crate::next_readable_at(self, va, end, bounds)
    }

    fn code_range(&self) -> Option<(Va, u64)> {
        self.text_range()
    }

    /// Every section the image marks executable, in address order — not just
    /// `.text`. On an IL2CPP build that is the difference between covering
    /// 10 % of the code and covering all of it.
    fn code_ranges(&self) -> Vec<(Va, u64)> {
        let mut out: Vec<(Va, u64)> = self.image.sections().iter().filter(|s| s.executable && s.size > 0).map(|s| (s.va, s.size)).collect();
        out.sort_by_key(|(va, _)| va.0);
        out
    }

    fn label(&self) -> String {
        format!("static:{}", self.module_name)
    }

    fn abi_name(&self) -> &'static str {
        self.image.machine().abi
    }
}

impl SymbolProvider for ImageSource {
    fn symbol_at(&self, va: Va) -> Option<Symbol> {
        self.symbols.get(&va.0).cloned()
    }

    /// The imported symbol a slot is bound to: a PE IAT entry, an ELF GOT
    /// slot. Named `iat_slot` for the PE term the trait was born with; the
    /// consumers (`ir::resolved_target_name`, thunk recognition, the known-API
    /// and noreturn tables) are format-neutral.
    fn iat_slot(&self, va: Va) -> Option<Symbol> {
        match self.image.binding_at(va) {
            Binding::Import(import) | Binding::ImportAndSelfDefinition { import, .. } => Some(Symbol {
                va,
                module: import.library.unwrap_or_else(|| UNKNOWN_PROVIDER.to_string()),
                name: import.name.symbol_name(),
                kind: SymKind::Import,
            }),
            Binding::SelfDefinition { .. } | Binding::Unbound { .. } | Binding::NotRead { .. } => None,
        }
    }

    /// The linker's own extent for the function at `va`: an ELF `st_size`, a
    /// PE `.pdata` entry. Only an exact hit on a start answers; a PLT stub is
    /// a thunk and states none.
    fn symbol_size(&self, va: Va) -> Option<u64> {
        self.sizes.get(&va.0).copied()
    }

    fn thunk_to(&self, va: Va) -> Option<Va> {
        self.thunks.get(&va.0).copied().map(Va)
    }
}

impl ModuleProvider for ImageSource {
    fn modules(&self) -> &[Module] {
        &self.modules
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("n0xis_static_image_{}_{}.bin", std::process::id(), tag));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    /// A source of bytes that never ends — `/dev/zero`, as a reader — and
    /// counts what was taken from it. It does stop, at 64 MiB, so that the
    /// whole-file read this test exists to catch fails on its assertion
    /// rather than taking the memory with it.
    struct Endless {
        taken: u64,
    }

    const ENDLESS_STOPS_AT: u64 = 64 << 20;

    impl std::io::Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = (buf.len() as u64).min(ENDLESS_STOPS_AT - self.taken) as usize;
            buf[..n].fill(0);
            self.taken += n as u64;
            Ok(n)
        }
    }

    #[test]
    fn bytes_no_format_recognizes_are_refused_after_the_signature_not_after_the_file() {
        let mut endless = Endless { taken: 0 };
        let found = read_recognized(&mut endless).expect("reading zeros does not fail");
        assert!(found.is_none(), "zeros are no image");
        assert!(endless.taken <= SNIFF_LEN as u64, "read {} bytes to recognize nothing; the signature is in the first {SNIFF_LEN}", endless.taken);
    }

    #[test]
    fn a_recognized_image_is_read_whole() {
        let mut file = b"\x7fELF".to_vec();
        file.resize(3 * SNIFF_LEN + 5, 0xAB);
        let (format, bytes) = read_recognized(file.as_slice()).expect("a slice reads").expect("ELF magic is recognized");
        assert_eq!(format.format, ImageFormat::Elf);
        assert_eq!(bytes, file, "the prefix and the rest, in order, once");
    }

    #[test]
    fn unknown_magic_is_rejected_with_a_clear_error() {
        let p = temp("junk", b"junkjunk");
        let err = ImageSource::load(&p).unwrap_err();
        assert!(format!("{err}").contains("not a PE"), "{err}");
        let _ = std::fs::remove_file(&p);
    }

    /// A file named like a module is recognized by its bytes, never its name:
    /// one found on this machine as `vsda_bg.wasm` begins `f0 f1 d5 26`, and
    /// is refused as no format at all, the three that exist named. A module cut
    /// short after its magic reaches the WebAssembly reader, which refuses it.
    #[test]
    fn a_module_is_recognized_by_its_magic_not_its_name() {
        let p = temp("named.wasm", &[0xf0, 0xf1, 0xd5, 0x26, 0x94, 0xd7, 0x68, 0xab]);
        let err = ImageSource::load(&p).unwrap_err().to_string();
        assert!(err.contains("not a PE (MZ), an ELF (\\x7fELF) or a WebAssembly module (\\0asm)"), "{err}");
        let _ = std::fs::remove_file(&p);
        let p = temp("cut.wasm", b"\0asm\x01\0\0");
        let err = ImageSource::load(&p).unwrap_err().to_string();
        assert!(err.contains("parse") && !err.contains("not a PE"), "the WebAssembly reader refuses it: {err}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn elf_magic_routes_to_the_elf_parser_not_the_pe_parser() {
        // A truncated ELF must fail *in the ELF parser*, not with the old
        // confusing PE "DOS header is malformed" — proving the dispatch.
        let p = temp("elf", b"\x7fELFtruncated-not-a-real-elf");
        let err = ImageSource::load(&p).unwrap_err();
        let m = format!("{err}");
        assert!(!m.contains("DOS"), "ELF magic should route to the ELF parser: {m}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn mz_magic_routes_to_the_pe_parser() {
        let p = temp("pe", b"MZ-truncated-not-a-real-pe");
        let err = ImageSource::load(&p).unwrap_err();
        // It reached the PE parser (a PE-specific complaint), not the generic
        // "not a PE or ELF" rejection.
        assert!(!format!("{err}").contains("not a PE"), "MZ magic should route to the PE parser: {err}");
        let _ = std::fs::remove_file(&p);
    }
}
