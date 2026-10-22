// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A WebAssembly module behind [`Image`] (docs/design/WASM.md stage 2): the
//! third reader of the format registry, over the stage-1 reader
//! (`n0xis-wasm`), which reads every byte of the module and this file turns
//! into the seam's answers.
//!
//! **A function is its index; its body's module offset is its position**
//! (decision 1). Every defined function is a declared start at its body —
//! the locals declaration, the first byte after the body's size — with the
//! body's exact extent, and [`StartCoverage::Every`] says that is every
//! function the module has. An imported function has an index and no
//! position: it is an import reached by [`Reach::Index`], never a start.
//!
//! **The module's positions hold no data** (decision 2, its image-wide part):
//! the image's space is module offsets, data lives in linear memories, and the
//! data segments are their initial contents, each placed at an address in one
//! memory or stated as not placed, with why ([`AddressModel::LinearMemories`]).
//! A segment whose offset reads an imported global has no static placement:
//! the format allows one, and its value is the host's.
//!
//! How each question is answered, and why, is stated where it is answered.
//! What a native image has and a module does not is answered as such, never
//! by a placeholder: a module has no loader segments (it is instantiated, not
//! mapped), no slots a loader binds, and no CodeView record.

use std::sync::Arc;

use n0xis_contracts::Va;
use n0xis_wasm::{
    AddressType, DataMode, ElementItems, ElementMode, ExportItem, FuncOrigin, GlobalOrigin, ImportItem, Instr, Located, Module, Origin,
    SectionKind,
};

use crate::image::{
    AddressModel, Answer, Binding, ByteOrder, CodeView, DataSegment, DeclaredStart, Export, ExportTo, Extent, Finding, FormatTables, Image,
    ImageSymbol, ImportBinding, ImportName, ImportReference, Imports, Isa, ItemKind, Library, LibraryRef, LibrarySource, LinearMemory,
    LoadedBytes, Machine, MemoryAddress, OpenError, OpenOptions, Opened, Partial, Placement, Reach, Section, SegmentPlacement, Segments,
    StartCoverage, StartReason, SymbolKind, SymbolTable,
};
use crate::{Linkage, RelocatedWords, RelocationsNotRead};

/// The magic every module begins with. The version after it is the reader's
/// to check: a component (version `0x0d`) is refused there by name, which a
/// sniff that read the version too would turn into "not a WebAssembly module".
const MAGIC: &[u8; 4] = b"\0asm";

/// The custom section that makes a module a side module, loaded by a main
/// module at run time (the tool conventions' dynamic linking).
const DYLINK: &str = "dylink.0";

/// The custom section a relocatable object carries: its relocations apply
/// when a linker combines it, which no loader does.
const LINKING: &str = "linking";

/// The most steps a constant offset expression is evaluated for, across the
/// globals it reads. An expression is bounded by the bytes that hold it, but
/// the globals it reads may read others, and a module the reader does not
/// validate may make that a cycle.
const EVAL_BUDGET: usize = 4096;

pub(crate) fn sniff(prefix: &[u8]) -> bool {
    prefix.starts_with(MAGIC)
}

pub(crate) fn open(bytes: Vec<u8>, _options: &OpenOptions) -> Result<Opened, OpenError> {
    let image = WasmImage::read(&bytes)?;
    let tables = FormatTables::Wasm(Arc::clone(&image.module));
    Ok(Opened::Thin { image: Box::new(image), tables })
}

/// A WebAssembly module, read: what a consumer that needs the module by name
/// reaches through [`FormatTables::Wasm`] — an architecture built for the
/// module, the profile's module block.
#[derive(Debug)]
pub struct WasmModule {
    module: Arc<Module>,
    identity: String,
    elements: Vec<ElementPlacement>,
}

impl WasmModule {
    /// The module as the stage-1 reader read it.
    pub fn module(&self) -> &Module {
        &self.module
    }

    /// The module, shared: what an architecture built for it holds.
    pub fn shared(&self) -> Arc<Module> {
        Arc::clone(&self.module)
    }

    /// What the module's annotations are kept under, and what a code
    /// position names its module by (docs/design/WASM.md §5 decision 1):
    /// `build-id:<hex>` of its `build_id` section's id, or, with no readable
    /// one, `fnv1a64:<hex>` of every byte of the module.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Each element segment and where it puts its items.
    pub fn element_segments(&self) -> &[ElementPlacement] {
        &self.elements
    }

    /// The name of imported function `index`, which has an index and no
    /// position, so no symbol at a position can carry it: the `name`
    /// section's name for it, as a defined function's is, else its import's
    /// `module.field`. `wasm-objdump -d` names a call to one the same way
    /// (`call 0 <host_report>` where the name section names it, `call 0
    /// <env.imp>` where it does not). `None` for a defined function, whose
    /// name the image's symbols carry, and for an index past the index space.
    pub fn imported_function_name(&self, index: u32) -> Option<String> {
        let m = &self.module;
        let FuncOrigin::Imported { import } = m.function(n0xis_wasm::FuncIdx(index))?.origin else { return None };
        let named = m.names().and_then(|n| n.functions.get(&n0xis_wasm::FuncIdx(index))).filter(|n| !n.is_empty());
        match named {
            Some(name) => Some(name.clone()),
            None => m.imports().get(import).map(|i| format!("{}.{}", i.module, i.name)),
        }
    }
}

/// An element segment: how many items it holds, and where instantiation
/// places them.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ElementPlacement {
    /// Its position in the element index space.
    pub index: u32,
    /// How many items it holds.
    pub items: usize,
    pub placement: ElementPlaced,
}

/// Where an element segment's items go.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ElementPlaced {
    /// Into table `table`, from element `at`.
    Placed { table: u32, at: u64 },
    /// No static placement, and why (as [`SegmentPlacement::NotPlaced`]).
    NotPlaced { why: String },
}

#[derive(Debug)]
struct WasmImage {
    module: Arc<WasmModule>,
    machine: Machine,
    linkage: Linkage,
    segments: Segments,
    sections: Vec<Section>,
    placed: Vec<Placement>,
    symbols: Answer<Partial<Vec<ImageSymbol>>>,
    imports: Answer<Imports>,
    exports: Answer<Vec<Export>>,
    starts: Partial<Vec<DeclaredStart>>,
    relocated: RelocatedWords,
    findings: Vec<Finding>,
}

impl WasmImage {
    fn read(bytes: &[u8]) -> Result<Self, OpenError> {
        let module = n0xis_wasm::read(bytes).map_err(|e| OpenError::Parse(e.to_string()))?;
        let mut findings: Vec<Finding> = module
            .findings()
            .iter()
            .map(|f| match f {
                n0xis_wasm::Finding::Name(problem) => Finding::PartNotRead { part: "the name section".into(), why: name_problem(problem) },
                n0xis_wasm::Finding::Body { func, error } => {
                    Finding::PartNotRead { part: format!("the body of function {}", func.0), why: error.to_string() }
                }
            })
            .collect();

        let identity = match module.build_id() {
            Some(Ok(id)) if !id.is_empty() => format!("build-id:{}", hex(id)),
            other => {
                if let Some(Err(e)) = &other {
                    findings.push(Finding::PartNotRead {
                        part: "the build_id section".into(),
                        why: format!("{e}; the module is identified by a hash of its bytes instead"),
                    });
                }
                format!("fnv1a64:{:016x}", fnv1a64(bytes))
            }
        };

        let has_custom = |name: &str| module.custom_sections().any(|(n, _)| n == name);
        // What a side module is to the module that loads it is what a shared
        // object is to a program; without `dylink.0` a module is instantiated
        // on its own.
        let linkage = if has_custom(DYLINK) { Linkage::SharedLibrary } else { Linkage::Executable };
        let relocated = if has_custom(LINKING) {
            RelocatedWords::NotRead(RelocationsNotRead::NotLoadable)
        } else {
            // Instantiation copies the data segments into linear memory and
            // writes nothing into the module's own bytes: there is no word of
            // the image's space a loader writes.
            RelocatedWords::Read { words: Vec::new(), copies: Vec::new() }
        };

        let memories: Vec<LinearMemory> = module
            .memories()
            .iter()
            .enumerate()
            .map(|(i, m)| LinearMemory {
                index: i as u32,
                address: memory_address(m.ty.limits.address),
                import: match m.origin {
                    Origin::Imported { import } => Some(import),
                    Origin::Defined => None,
                },
                min_pages: m.ty.limits.min,
                max_pages: m.ty.limits.max,
                shared: m.ty.shared,
            })
            .collect();
        let segments: Vec<DataSegment> = module
            .data()
            .iter()
            .enumerate()
            .map(|(i, d)| DataSegment {
                index: i as u32,
                bytes_at: Va(d.init.start as u64),
                len: d.init.len() as u64,
                placement: match &d.mode {
                    DataMode::Passive => SegmentPlacement::NotPlaced {
                        why: "a passive segment: code copies it into a memory with `memory.init`, at an address it computes when it runs".into(),
                    },
                    DataMode::Active { memory, offset } => match place(&module, memory.0, offset, Space::Memory) {
                        Ok(address) => SegmentPlacement::Placed { memory: memory.0, address },
                        Err(why) => SegmentPlacement::NotPlaced { why },
                    },
                },
            })
            .collect();
        let elements: Vec<ElementPlacement> = module
            .elements()
            .iter()
            .enumerate()
            .map(|(i, e)| ElementPlacement {
                index: i as u32,
                items: match &e.items {
                    ElementItems::Functions(f) => f.len(),
                    ElementItems::Expressions(x) => x.len(),
                },
                placement: match &e.mode {
                    ElementMode::Passive => ElementPlaced::NotPlaced { why: "a passive segment: code places it with `table.init`".into() },
                    ElementMode::Declarative => {
                        ElementPlaced::NotPlaced { why: "a declarative segment: it only declares the functions `ref.func` may name".into() }
                    }
                    ElementMode::Active { table, offset } => match place(&module, table.0, offset, Space::Table) {
                        Ok(at) => ElementPlaced::Placed { table: table.0, at },
                        Err(why) => ElementPlaced::NotPlaced { why },
                    },
                },
            })
            .collect();

        let machine = Machine {
            isa: Isa::Wasm,
            address_model: AddressModel::LinearMemories { memories, segments },
            // Every multi-byte value of the format, and of linear memory, is
            // little-endian.
            byte_order: ByteOrder::Little,
            abi: "wasm",
        };

        let len = bytes.len() as u64;
        // A module is instantiated, not mapped: no loader segment places it.
        // Its space is its own bytes, from offset 0.
        let segments = Segments { base: Va(0), span: len, list: Vec::new() };
        let sections: Vec<Section> = module
            .sections()
            .iter()
            .map(|s| Section {
                name: section_name(&s.kind),
                va: Va(s.contents.start as u64),
                size: s.contents.len() as u64,
                file_offset: s.contents.start as u64,
                file_size: s.contents.len() as u64,
                executable: s.kind == SectionKind::Code,
                in_image: true,
            })
            .collect();
        // One placement, the whole file at offset 0: a read at a module
        // offset reads the module's bytes there (the lead's DECISIONS item 8),
        // what `disasm` decodes.
        let placed = vec![Placement { va: 0, end: len, file_offset: 0, file_size: bytes.len() }];

        let defined: Vec<(u32, std::ops::Range<usize>)> = (0..module.functions().len())
            .filter_map(|i| {
                let index = n0xis_wasm::FuncIdx(i as u32);
                Some((index.0, body_range(&module, index)?))
            })
            .collect();
        let starts = Partial::whole(
            defined
                .iter()
                .map(|(index, body)| DeclaredStart {
                    va: Va(body.start as u64),
                    why: StartReason::Body { function: *index },
                    extent: extent_of(body),
                })
                .collect(),
        );

        // Names first from the `name` section, then from the exports, so an
        // exported function the name section leaves unnamed is named by its
        // export, as a PE's exports name its functions; the first name at an
        // address is the one a lookup answers. An empty name names nothing (a
        // module may export a function as `""`), as an ELF symbol with an
        // empty name names nothing.
        // By index, through the module's own table: a linear search here, once
        // per name and per export, made opening a module quadratic in its
        // functions (160 000 named functions took 13 s to open, against 0.05 s
        // without a name section).
        let body_of = |index: u32| body_range(&module, n0xis_wasm::FuncIdx(index));
        let mut symbols: Vec<ImageSymbol> = Vec::new();
        if let Some(names) = module.names() {
            for (index, name) in names.functions.iter().filter(|(_, n)| !n.is_empty()) {
                if let Some(body) = body_of(index.0) {
                    symbols.push(ImageSymbol {
                        va: Va(body.start as u64),
                        name: name.clone(),
                        kind: SymbolKind::Function,
                        extent: extent_of(&body),
                        table: SymbolTable::NameSection,
                    });
                }
            }
        }
        let mut exports = Vec::new();
        for e in module.exports() {
            let (kind, target) = match e.item {
                ExportItem::Func(f) => (ItemKind::Function, ExportTo::Function { index: f.0, body: module.body_start(f).map(|b| Va(b as u64)) }),
                ExportItem::Table(t) => (ItemKind::Table, ExportTo::Entry { index: t.0 }),
                ExportItem::Memory(m) => (ItemKind::Memory, ExportTo::Entry { index: m.0 }),
                ExportItem::Global(g) => (ItemKind::Global, ExportTo::Entry { index: g.0 }),
                ExportItem::Tag(t) => (ItemKind::Tag, ExportTo::Entry { index: t.0 }),
            };
            if let ExportItem::Func(f) = e.item
                && !e.name.is_empty()
                && let Some(body) = body_of(f.0)
            {
                symbols.push(ImageSymbol {
                    va: Va(body.start as u64),
                    name: e.name.clone(),
                    kind: SymbolKind::Function,
                    extent: extent_of(&body),
                    table: SymbolTable::Exports,
                });
            }
            exports.push(Export { name: Some(e.name.clone()), ordinal: None, kind, target });
        }

        let mut libraries: Vec<Library> = Vec::new();
        let mut references = Vec::new();
        // The position in each index space the next import of its kind takes:
        // imports come first in every space, in import order.
        let (mut funcs, mut tables, mut mems, mut globals, mut tags) = (0u32, 0u32, 0u32, 0u32, 0u32);
        for import in module.imports() {
            let library = match libraries.iter().position(|l| l.name == import.module) {
                Some(i) => i,
                None => {
                    libraries.push(Library { name: import.module.clone(), stated_by: LibrarySource::ImportModule, references_not_read: Vec::new() });
                    libraries.len() - 1
                }
            };
            let next = |n: &mut u32| {
                let at = *n;
                *n = n.saturating_add(1);
                at
            };
            let (kind, index) = match import.item {
                ImportItem::Func(_) => (ItemKind::Function, next(&mut funcs)),
                ImportItem::Table(_) => (ItemKind::Table, next(&mut tables)),
                ImportItem::Memory(_) => (ItemKind::Memory, next(&mut mems)),
                ImportItem::Global(_) => (ItemKind::Global, next(&mut globals)),
                ImportItem::Tag(_) => (ItemKind::Tag, next(&mut tags)),
            };
            references.push(ImportReference {
                name: ImportName::Named(import.name.clone()),
                kind,
                library: LibraryRef::Binds(library),
                reach: Answer::Read(vec![Reach::Index(index)]),
            });
        }
        let imports = Answer::Read(Imports { binding: ImportBinding::PerLibrary, libraries, references, reach_not_read: Vec::new() });
        findings.extend(index_contradictions(&module));
        findings.extend(placement_contradictions(&module, &machine.address_model, &elements));

        Ok(WasmImage {
            module: Arc::new(WasmModule { module: Arc::new(module), identity, elements }),
            machine,
            linkage,
            segments,
            sections,
            placed,
            symbols: Answer::Read(Partial::whole(symbols)),
            imports,
            exports: Answer::Read(exports),
            starts,
            relocated,
            findings,
        })
    }

    fn bytes(&self) -> &[u8] {
        let m = &self.module.module;
        m.bytes(0..self.segments.span as usize).unwrap_or_default()
    }
}

impl Image for WasmImage {
    fn machine(&self) -> &Machine {
        &self.machine
    }
    fn linkage(&self) -> Linkage {
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
    /// The code section holds one body for each defined function and nothing
    /// else but the bodies' sizes.
    fn start_coverage(&self) -> StartCoverage {
        StartCoverage::Every
    }
    fn loaded_bytes(&self) -> LoadedBytes<'_> {
        LoadedBytes { file: self.bytes(), placed: &self.placed, written_by_loader: &self.relocated }
    }
    fn findings(&self) -> &[Finding] {
        &self.findings
    }
    fn binding_at(&self, _slot: Va) -> Binding {
        Binding::Unbound { why: "a WebAssembly module has no slots a loader binds: it reaches each import by its index" }
    }
    fn codeview(&self) -> Option<&CodeView> {
        None
    }
}

/// A section's name, as wasm-objdump titles a standard one; a custom section
/// by its own name, after `custom:`, so that no custom section can take a
/// standard one's name (a custom section may be called anything, `Code`
/// included).
fn section_name(kind: &SectionKind) -> String {
    match kind {
        SectionKind::Custom { name } => format!("custom:{name}"),
        SectionKind::Type => "Type".into(),
        SectionKind::Import => "Import".into(),
        SectionKind::Function => "Function".into(),
        SectionKind::Table => "Table".into(),
        SectionKind::Memory => "Memory".into(),
        SectionKind::Global => "Global".into(),
        SectionKind::Export => "Export".into(),
        SectionKind::Start => "Start".into(),
        SectionKind::Element => "Elem".into(),
        SectionKind::Code => "Code".into(),
        SectionKind::Data => "Data".into(),
        SectionKind::DataCount => "DataCount".into(),
        SectionKind::Tag => "Tag".into(),
    }
}

/// A body's extent: its size, which a well-formed module states above zero (a
/// body holds at least its locals count and its `end`). A corrupted one can
/// state 0, which is no extent (`Extent::Stated` is more than zero); the
/// module's findings name the body.
fn extent_of(body: &std::ops::Range<usize>) -> Extent {
    match body.len() {
        0 => Extent::Unknown,
        n => Extent::Stated(n as u64),
    }
}

/// The body of function `index`, where in the file it is: `None` for an
/// imported function and for an index past the index space.
fn body_range(m: &Module, index: n0xis_wasm::FuncIdx) -> Option<std::ops::Range<usize>> {
    let FuncOrigin::Defined { body } = m.function(index)?.origin else { return None };
    m.bodies().get(body).cloned()
}

/// What a problem of the `name` section did to the names, said as the reader
/// handled it (`n0xis_wasm::names`). Every case is answered, with no
/// wildcard, so a new kind of problem must say what became of its names.
fn name_problem(p: &n0xis_wasm::NameProblem) -> String {
    use n0xis_wasm::NameProblem as P;
    match p {
        P::Repeated => "a second `name` section; only the first is read, and this one names nothing".into(),
        P::BeforeStandardSection { id } => {
            format!("the `name` section comes before standard section {id}, where the format places it after the data section; it is read all the same")
        }
        P::SubsectionOrder { id, after } => {
            format!("subsection {id} comes after subsection {after}, where each comes once and in increasing order; subsection {id} is left out")
        }
        P::SubsectionNotRead { id } => format!("subsection {id} is not one this reader reads; it is left out"),
        P::Subsection { id, error } => format!("subsection {id} could not be read ({error}); it is left out whole"),
        P::Framing { error } => format!("the subsections' framing broke ({error}); nothing after that point is read"),
        P::IndexOrder { subsection, within, index } => {
            let map = match within {
                None => format!("subsection {subsection}"),
                Some(n0xis_wasm::Within::Function(f)) => format!("subsection {subsection}, the map of function {}", f.0),
                Some(n0xis_wasm::Within::Type(ty)) => format!("subsection {subsection}, the map of type {}", ty.0),
            };
            // The reader keeps an out-of-order name, and leaves out a second
            // name for an index it has named: which of the two this entry was
            // is not part of the problem, so both are said.
            format!(
                "in {map}, index {index} is not above the index listed before it, where each is listed once and in increasing order; \
                 if index {index} was already named, this name is left out and the first is kept, and otherwise it is kept"
            )
        }
    }
}

/// Indices the module states that name nothing in their index space: the
/// start function, and each export's item. A validator rejects such a module
/// (`wasm-validate`: "function variable out of range"); the answers that carry
/// the index carry it as stated, and this says it names nothing.
fn index_contradictions(m: &Module) -> Vec<Finding> {
    let mut out = Vec::new();
    let functions = m.functions().len();
    if let Some(start) = m.start()
        && start.0 as usize >= functions
    {
        out.push(Finding::Contradiction {
            what: format!("the start section names function {}, and the module has {functions} functions: the start function is none of them", start.0),
        });
    }
    for e in m.exports() {
        let (noun, index, len) = match e.item {
            ExportItem::Func(f) => ("function", f.0, functions),
            ExportItem::Table(t) => ("table", t.0, m.tables().len()),
            ExportItem::Memory(x) => ("memory", x.0, m.memories().len()),
            ExportItem::Global(g) => ("global", g.0, m.globals().len()),
            ExportItem::Tag(x) => ("tag", x.0, m.tags().len()),
        };
        if index as usize >= len {
            out.push(Finding::Contradiction {
                what: format!("export {:?} names {noun} {index}, and the module has {len}: it exports nothing", e.name),
            });
        }
    }
    out
}

/// Segments placed past what instantiation gives them to fill: a data segment
/// past its memory's initial size, an element segment past its table's.
/// Instantiation traps on such a segment (WebAssembly 2.0 and later apply the
/// segments in order and trap at the first that does not fit), so the
/// placement is stated as read and this says it never happens.
///
/// Only where the size is the module's to state: a defined memory or table
/// starts at its minimum; an imported one is at least its minimum and at most
/// its maximum, so only an end past the maximum is certain to trap.
fn placement_contradictions(m: &Module, model: &AddressModel, elements: &[ElementPlacement]) -> Vec<Finding> {
    const PAGE: u128 = 65536;
    let mut out = Vec::new();
    // The largest size a memory or table has when instantiated, and whether
    // it is exactly that (defined) or at most that (imported, its maximum).
    let bound = |min: u64, max: Option<u64>, imported: bool, unit: u128| -> Option<(u128, &'static str)> {
        if imported { max.map(|x| (u128::from(x) * unit, "at most")) } else { Some((u128::from(min) * unit, "exactly")) }
    };
    if let AddressModel::LinearMemories { memories, segments } = model {
        for s in segments {
            let SegmentPlacement::Placed { memory, address } = &s.placement else { continue };
            let Some(mem) = memories.get(*memory as usize) else { continue };
            let Some((size, how)) = bound(mem.min_pages, mem.max_pages, mem.import.is_some(), PAGE) else { continue };
            let end = u128::from(*address) + u128::from(s.len);
            if end > size {
                out.push(Finding::Contradiction {
                    what: format!(
                        "data segment {} is placed at {address:#x} in memory {memory} and ends at {end:#x}, and the memory is {how} {size:#x} bytes when instantiated: instantiation traps on it",
                        s.index
                    ),
                });
            }
        }
    }
    for e in elements {
        let ElementPlaced::Placed { table, at } = &e.placement else { continue };
        let Some(t) = m.tables().get(*table as usize) else { continue };
        let imported = matches!(t.origin, n0xis_wasm::TableOrigin::Imported { .. });
        let Some((size, how)) = bound(t.ty.limits.min, t.ty.limits.max, imported, 1) else { continue };
        let end = u128::from(*at) + e.items as u128;
        if end > size {
            out.push(Finding::Contradiction {
                what: format!(
                    "element segment {} is placed at element {at} of table {table} and ends at {end}, and the table holds {how} {size} elements when instantiated: instantiation traps on it",
                    e.index
                ),
            });
        }
    }
    out
}

fn memory_address(a: AddressType) -> MemoryAddress {
    match a {
        AddressType::I32 => MemoryAddress::I32,
        AddressType::I64 => MemoryAddress::I64,
    }
}

/// Which index space a segment is placed into.
#[derive(Clone, Copy)]
enum Space {
    Memory,
    Table,
}

/// A constant's value, typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    I32(u32),
    I64(u64),
}

/// Where in memory or table `target` a segment's offset expression places
/// it, or why it has no static placement.
fn place(m: &Module, target: u32, offset: &[Located], space: Space) -> Result<u64, String> {
    let (noun, address) = match space {
        Space::Memory => ("memory", m.memories().get(target as usize).map(|x| x.ty.limits.address)),
        Space::Table => ("table", m.tables().get(target as usize).map(|x| x.ty.limits.address)),
    };
    let Some(address) = address else {
        return Err(format!("it names {noun} {target}, which the module does not have"));
    };
    let mut budget = EVAL_BUDGET;
    match (evaluate(m, offset, &mut budget)?, address) {
        (Value::I32(v), AddressType::I32) => Ok(u64::from(v)),
        (Value::I64(v), AddressType::I64) => Ok(v),
        (Value::I32(_), AddressType::I64) => Err(format!("its offset is an i32, and {noun} {target} takes i64 addresses")),
        (Value::I64(_), AddressType::I32) => Err(format!("its offset is an i64, and {noun} {target} takes i32 addresses")),
    }
}

/// The value of a constant expression: `i32.const`, `i64.const`, the extended
/// constant arithmetic (`add`, `sub`, `mul` of either width, wrapping, as the
/// format defines them), and `global.get` of a global the module defines,
/// whose initial value is evaluated the same way. A global the module imports
/// has the host's value, which no reading of the module can know.
fn evaluate(m: &Module, expr: &[Located], budget: &mut usize) -> Result<Value, String> {
    let mut stack: Vec<Value> = Vec::new();
    for l in expr {
        if *budget == 0 {
            return Err("its offset reads globals past the depth this reader evaluates".into());
        }
        *budget -= 1;
        let binary = |stack: &mut Vec<Value>, f32: fn(u32, u32) -> u32, f64: fn(u64, u64) -> u64, i64_op: bool| -> Result<(), String> {
            let (b, a) = (stack.pop(), stack.pop());
            let v = match (a, b, i64_op) {
                (Some(Value::I32(a)), Some(Value::I32(b)), false) => Value::I32(f32(a, b)),
                (Some(Value::I64(a)), Some(Value::I64(b)), true) => Value::I64(f64(a, b)),
                _ => return Err(format!("its offset's `{}` has no operands of its type", l.instr)),
            };
            stack.push(v);
            Ok(())
        };
        match &l.instr {
            Instr::I32Const(v) => stack.push(Value::I32(*v as u32)),
            Instr::I64Const(v) => stack.push(Value::I64(*v as u64)),
            Instr::I32Add => binary(&mut stack, u32::wrapping_add, u64::wrapping_add, false)?,
            Instr::I32Sub => binary(&mut stack, u32::wrapping_sub, u64::wrapping_sub, false)?,
            Instr::I32Mul => binary(&mut stack, u32::wrapping_mul, u64::wrapping_mul, false)?,
            Instr::I64Add => binary(&mut stack, u32::wrapping_add, u64::wrapping_add, true)?,
            Instr::I64Sub => binary(&mut stack, u32::wrapping_sub, u64::wrapping_sub, true)?,
            Instr::I64Mul => binary(&mut stack, u32::wrapping_mul, u64::wrapping_mul, true)?,
            Instr::GlobalGet(g) => match m.globals().get(g.0 as usize).map(|x| &x.origin) {
                Some(GlobalOrigin::Imported { import }) => {
                    let named = m.imports().get(*import).map(|i| format!(" (`{}`.`{}`)", i.module, i.name)).unwrap_or_default();
                    return Err(format!(
                        "its offset reads global {}, which the module imports{named}: its value is the host's, given at instantiation",
                        g.0
                    ));
                }
                Some(GlobalOrigin::Defined { init }) => stack.push(evaluate(m, init, budget)?),
                None => return Err(format!("its offset reads global {}, which the module does not have", g.0)),
            },
            Instr::End => break,
            other => return Err(format!("its offset is computed by `{other}`, which this reader does not evaluate")),
        }
    }
    match stack.as_slice() {
        [v] => Ok(*v),
        _ => Err(format!("its offset expression leaves {} values, not one", stack.len())),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// FNV-1a 64 (the identity n0xis-il2cpp's `TargetIdentity` uses too): stable
/// across builds and toolchains, which `SourceId`'s hasher is not, so an
/// identity written into the project still names the same module tomorrow.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FNV-1a 64's own published test vectors (the empty input and "a").
    #[test]
    fn the_hash_is_fnv1a_64() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn a_module_is_recognized_by_its_magic_alone() {
        assert!(sniff(b"\0asm\x01\0\0\0"));
        assert!(sniff(b"\0asm\x0d\0\x01\0"), "a component is recognized, and the reader refuses it by name");
        assert!(!sniff(b"\xf0\xf1\xd5\x26"));
    }

    #[test]
    fn a_component_is_refused_by_the_reader_with_its_version() {
        let Err(OpenError::Parse(why)) = open(b"\0asm\x0d\0\x01\0".to_vec(), &OpenOptions::default()) else { panic!("opened a component") };
        assert!(why.contains("version"), "{why}");
        // Said to be a component, not a core module of version 65549 (the
        // preamble's two halves read as one number).
        assert!(why.contains("a component (preamble version 0xd, layer 1)"), "{why}");
    }
}
