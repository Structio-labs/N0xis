// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The module: its sections, their entries, and the index spaces they make.

use std::ops::Range;

use crate::body::{self, Body, DataIndices};
use crate::error::{Error, Problem};
use crate::instr::Located;
use crate::names::{self, NameProblem, Names};
use crate::reader::Reader;
use crate::types::{
    AbsHeapType, CompositeType, FuncIdx, FuncType, GlobalIdx, GlobalType, HeapType, MemIdx, MemoryType, RecGroup, RecHead,
    RefType, SubType, TableIdx, TableType, TagIdx, TypeIdx, read_tag_type,
};

/// The four bytes every module begins with, then the version.
const MAGIC: [u8; 4] = *b"\0asm";
const VERSION: u32 = 1;

/// What a section is, by its id (and a custom section by its name).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SectionKind {
    Custom { name: String },
    Type,
    Import,
    Function,
    Table,
    Memory,
    Global,
    Export,
    Start,
    Element,
    Code,
    Data,
    DataCount,
    Tag,
}

impl SectionKind {
    /// The section id the binary format gives it.
    pub fn id(&self) -> u8 {
        match self {
            SectionKind::Custom { .. } => 0,
            SectionKind::Type => 1,
            SectionKind::Import => 2,
            SectionKind::Function => 3,
            SectionKind::Table => 4,
            SectionKind::Memory => 5,
            SectionKind::Global => 6,
            SectionKind::Export => 7,
            SectionKind::Start => 8,
            SectionKind::Element => 9,
            SectionKind::Code => 10,
            SectionKind::Data => 11,
            SectionKind::DataCount => 12,
            SectionKind::Tag => 13,
        }
    }

    /// A standard section from its id.
    fn standard(id: u8) -> Option<Self> {
        Some(match id {
            1 => SectionKind::Type,
            2 => SectionKind::Import,
            3 => SectionKind::Function,
            4 => SectionKind::Table,
            5 => SectionKind::Memory,
            6 => SectionKind::Global,
            7 => SectionKind::Export,
            8 => SectionKind::Start,
            9 => SectionKind::Element,
            10 => SectionKind::Code,
            11 => SectionKind::Data,
            12 => SectionKind::DataCount,
            13 => SectionKind::Tag,
            _ => return None,
        })
    }

    /// Where a standard section stands in the order the format requires,
    /// which is not the order of the ids: the data count section (12) stands
    /// between the element and code sections, the tag section (13) between
    /// the memory and global sections.
    fn rank(&self) -> u8 {
        match self {
            SectionKind::Custom { .. } => 0,
            SectionKind::Type => 1,
            SectionKind::Import => 2,
            SectionKind::Function => 3,
            SectionKind::Table => 4,
            SectionKind::Memory => 5,
            SectionKind::Tag => 6,
            SectionKind::Global => 7,
            SectionKind::Export => 8,
            SectionKind::Start => 9,
            SectionKind::Element => 10,
            SectionKind::DataCount => 11,
            SectionKind::Code => 12,
            SectionKind::Data => 13,
        }
    }
}

/// A section as the file lays it out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub kind: SectionKind,
    /// Its contents in the file, after the id and the size. A custom
    /// section's contents begin with its name.
    pub contents: Range<usize>,
}

/// What an import brings in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportItem {
    Func(TypeIdx),
    Table(TableType),
    Memory(MemoryType),
    Global(GlobalType),
    /// A tag, by the function type of its payload.
    Tag(TypeIdx),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    pub module: String,
    pub name: String,
    pub item: ImportItem,
}

/// What an export names, in its own index space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportItem {
    Func(FuncIdx),
    Table(TableIdx),
    Memory(MemIdx),
    Global(GlobalIdx),
    Tag(TagIdx),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    pub name: String,
    pub item: ExportItem,
}

/// Where a memory or a tag of an index space comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The import at this position of [`Module::imports`].
    Imported { import: usize },
    /// The module defines it.
    Defined,
}

/// An entry of the function index space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Func {
    pub ty: TypeIdx,
    pub origin: FuncOrigin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FuncOrigin {
    /// The import at this position of [`Module::imports`].
    Imported { import: usize },
    /// Defined here; its body is this entry of [`Module::bodies`].
    Defined { body: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    pub ty: TableType,
    pub origin: TableOrigin,
}

/// Where a table comes from. Only a table the module defines can state an
/// initial value for its elements, so an import has no place for one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TableOrigin {
    /// The import at this position of [`Module::imports`].
    Imported { import: usize },
    /// The module defines it: `init` is `None` in the plain form, where every
    /// element starts null, and the expression of the `0x40 0x00` form, which
    /// gives every element its initial value.
    Defined { init: Option<Vec<Located>> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Memory {
    pub ty: MemoryType,
    pub origin: Origin,
}

/// An entry of the tag index space: an exception tag, by the function type of
/// its payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag {
    pub ty: TypeIdx,
    pub origin: Origin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Global {
    pub ty: GlobalType,
    pub origin: GlobalOrigin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GlobalOrigin {
    /// The import at this position of [`Module::imports`].
    Imported { import: usize },
    /// Defined here, with this initial value.
    Defined { init: Vec<Located> },
}

/// How an element segment is used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElementMode {
    Passive,
    Declarative,
    /// Copied into `table` at `offset` when the module is instantiated.
    Active { table: TableIdx, offset: Vec<Located> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElementItems {
    /// Function indices (forms 0 to 3).
    Functions(Vec<FuncIdx>),
    /// One constant expression per element (forms 4 to 7).
    Expressions(Vec<Vec<Located>>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElementSegment {
    /// Which of the format's eight encodings the segment used (0 to 7).
    pub form: u32,
    /// The type of its elements, as WebAssembly 3.0 types it: a segment of
    /// function indices (forms 0 to 3) holds the non-null `(ref func)`, form 4
    /// the nullable `funcref`, and forms 5 to 7 state their reference type.
    pub ty: RefType,
    pub mode: ElementMode,
    pub items: ElementItems,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataMode {
    Passive,
    /// Copied into `memory` at `offset` when the module is instantiated.
    Active { memory: MemIdx, offset: Vec<Located> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataSegment {
    pub mode: DataMode,
    /// The segment's bytes in the file; [`Module::bytes`] gives them.
    pub init: Range<usize>,
}

/// Something wrong in the module that left the rest readable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Finding {
    /// In the `name` section; what it names is left out of [`Module::names`].
    Name(NameProblem),
    /// A function body that cannot be decoded. The module's other bodies
    /// can; [`Module::body`] gives this same error for this one.
    Body { func: FuncIdx, error: Error },
}

/// A WebAssembly module, read.
#[derive(Clone, Debug)]
pub struct Module {
    bytes: Vec<u8>,
    sections: Vec<Section>,
    types: Vec<SubType>,
    rec_groups: Vec<RecGroup>,
    imports: Vec<Import>,
    functions: Vec<Func>,
    tables: Vec<Table>,
    memories: Vec<Memory>,
    tags: Vec<Tag>,
    globals: Vec<Global>,
    exports: Vec<Export>,
    start: Option<FuncIdx>,
    elements: Vec<ElementSegment>,
    data_count: Option<u32>,
    bodies: Vec<Range<usize>>,
    data: Vec<DataSegment>,
    names: Option<Names>,
    findings: Vec<Finding>,
}

impl Module {
    /// Every section, in file order.
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// The custom sections with their names and contents, in file order.
    pub fn custom_sections(&self) -> impl Iterator<Item = (&str, &Section)> {
        self.sections.iter().filter_map(|s| match &s.kind {
            SectionKind::Custom { name } => Some((name.as_str(), s)),
            _ => None,
        })
    }

    /// The type index space: every subtype of every recursion group, in
    /// order. The position is the [`TypeIdx`].
    pub fn types(&self) -> &[SubType] {
        &self.types
    }

    /// The type section's entries: each recursion group and the type indices
    /// it defines.
    pub fn rec_groups(&self) -> &[RecGroup] {
        &self.rec_groups
    }

    /// The function type at `index`; `None` past the index space, or when the
    /// type there is a structure or an array type.
    pub fn func_type(&self, index: TypeIdx) -> Option<&FuncType> {
        match &self.types.get(index.0 as usize)?.composite {
            CompositeType::Func(f) => Some(f),
            CompositeType::Struct(_) | CompositeType::Array(_) => None,
        }
    }

    pub fn imports(&self) -> &[Import] {
        &self.imports
    }

    /// The function index space: imported functions in import order, then
    /// the functions the module defines. The position is the [`FuncIdx`].
    pub fn functions(&self) -> &[Func] {
        &self.functions
    }

    pub fn function(&self, index: FuncIdx) -> Option<&Func> {
        self.functions.get(index.0 as usize)
    }

    /// How many functions are imported; the first defined one has this index.
    pub fn imported_functions(&self) -> u32 {
        // The index space is at most 2^32 entries (checked as it was built).
        self.functions.iter().filter(|f| matches!(f.origin, FuncOrigin::Imported { .. })).count() as u32
    }

    /// The table index space, imports first. The position is the [`TableIdx`].
    pub fn tables(&self) -> &[Table] {
        &self.tables
    }

    /// The memory index space, imports first. The position is the [`MemIdx`].
    pub fn memories(&self) -> &[Memory] {
        &self.memories
    }

    /// The tag index space, imports first. The position is the [`TagIdx`].
    pub fn tags(&self) -> &[Tag] {
        &self.tags
    }

    /// The global index space, imports first. The position is the [`GlobalIdx`].
    pub fn globals(&self) -> &[Global] {
        &self.globals
    }

    pub fn exports(&self) -> &[Export] {
        &self.exports
    }

    pub fn start(&self) -> Option<FuncIdx> {
        self.start
    }

    pub fn elements(&self) -> &[ElementSegment] {
        &self.elements
    }

    /// What the data count section states, when there is one.
    pub fn data_count(&self) -> Option<u32> {
        self.data_count
    }

    /// Each defined function's body in the file, in code section order: the
    /// bytes after its size, locals first.
    pub fn bodies(&self) -> &[Range<usize>] {
        &self.bodies
    }

    pub fn data(&self) -> &[DataSegment] {
        &self.data
    }

    /// The `name` section's names; `None` when the module has none.
    pub fn names(&self) -> Option<&Names> {
        self.names.as_ref()
    }

    /// What was wrong but left the rest readable. Empty when nothing was
    /// found wrong. A well-formed module can still have findings about its
    /// name section, which the format says must not invalidate the module.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Bytes of the file the module was read from, such as a data segment's
    /// [`DataSegment::init`] or a section's contents.
    pub fn bytes(&self, range: Range<usize>) -> Option<&[u8]> {
        self.bytes.get(range)
    }

    /// The body of a function this module defines, decoded; `None` for an
    /// imported function or an index past the end of the index space.
    pub(crate) fn body_unguarded(&self, func: FuncIdx) -> Option<Result<Body, Error>> {
        let FuncOrigin::Defined { body } = self.function(func)?.origin else { return None };
        let range = self.bodies.get(body)?.clone();
        Some(decode_body(&self.bytes, range, self.data_indices()))
    }

    fn data_indices(&self) -> DataIndices {
        if self.data_count.is_some() { DataIndices::Allowed } else { DataIndices::NeedDataCount }
    }
}

fn decode_body(bytes: &[u8], range: Range<usize>, data_indices: DataIndices) -> Result<Body, Error> {
    let mut instructions = Vec::new();
    let locals = body::body(Reader::over(bytes, range.clone()), data_indices, |l| instructions.push(l))?;
    Ok(Body { range, locals, instructions })
}

/// The next entry of an index space.
fn next_index(len: usize, at: usize, r: &Reader) -> Result<u32, Error> {
    u32::try_from(len).map_err(|_| r.error(at, Problem::IndexSpaceOverflow))
}

pub(crate) fn read_unguarded(bytes: &[u8]) -> Result<Module, Error> {
    let mut r = Reader::new(bytes);
    if r.take(4).ok() != Some(&MAGIC[..]) {
        return Err(r.error(0, Problem::Magic));
    }
    let version = u32::from_le_bytes(r.array()?);
    if version != VERSION {
        return Err(r.error(4, Problem::Version(version)));
    }

    let mut m = Module {
        bytes: bytes.to_vec(),
        sections: Vec::new(),
        types: Vec::new(),
        rec_groups: Vec::new(),
        imports: Vec::new(),
        functions: Vec::new(),
        tables: Vec::new(),
        memories: Vec::new(),
        tags: Vec::new(),
        globals: Vec::new(),
        exports: Vec::new(),
        start: None,
        elements: Vec::new(),
        data_count: None,
        bodies: Vec::new(),
        data: Vec::new(),
        names: None,
        findings: Vec::new(),
    };
    // The function section's count, which the code section must match.
    let mut declared_functions: u32 = 0;
    let mut last_standard: Option<SectionKind> = None;
    let mut name_section_seen = false;

    while !r.at_end() {
        let header = r.offset();
        let id = r.byte()?;
        let size = r.u32()?;
        let mut s = r.sub(size as usize)?;
        let contents = s.offset()..s.end();

        if id == 0 {
            let name = s.name()?;
            if name == "name" {
                if name_section_seen {
                    m.findings.push(Finding::Name(NameProblem::Repeated));
                } else {
                    name_section_seen = true;
                    let mut problems = Vec::new();
                    let mut names = Names::default();
                    names::read(s, &mut names, &mut problems);
                    m.findings.extend(problems.into_iter().map(Finding::Name));
                    m.names = Some(names);
                }
            }
            m.sections.push(Section { kind: SectionKind::Custom { name }, contents });
            continue;
        }

        let kind = SectionKind::standard(id).ok_or_else(|| r.error(header, Problem::UnknownSection(id)))?;
        if let Some(last) = &last_standard
            && kind.rank() <= last.rank()
        {
            return Err(r.error(header, Problem::SectionOrder { id, after: last.id() }));
        }
        if name_section_seen {
            m.findings.push(Finding::Name(NameProblem::BeforeStandardSection { id }));
        }

        match kind {
            SectionKind::Type => {
                // The count is of recursion groups, each two bytes at least
                // (`0x4e 0x00` and `0x5f 0x00` are complete); the type index
                // space is every subtype of every group, in order.
                for _ in 0..s.count(2)? {
                    let head = RecGroup::read_head(&mut s)?;
                    let first = next_index(m.types.len(), s.offset(), &s)?;
                    let n = match head {
                        RecHead::Single => 1,
                        RecHead::Rec(n) => n,
                    };
                    for _ in 0..n {
                        let at = s.offset();
                        let ty = SubType::read(&mut s)?;
                        next_index(m.types.len(), at, &s)?;
                        m.types.push(ty);
                    }
                    // A subtype takes two bytes and a section at most 2^32 - 1,
                    // so the space never reaches 2^32 and the end fits.
                    let end = next_index(m.types.len(), s.offset(), &s)?;
                    m.rec_groups.push(match head {
                        RecHead::Single => RecGroup::Single(TypeIdx(first)),
                        RecHead::Rec(_) => RecGroup::Rec(first..end),
                    });
                }
            }
            SectionKind::Import => {
                for _ in 0..s.count(4)? {
                    let at = s.offset();
                    let module = s.name()?;
                    let name = s.name()?;
                    let kind_at = s.offset();
                    let item = match s.byte()? {
                        0x00 => ImportItem::Func(TypeIdx::read(&mut s)?),
                        0x01 => ImportItem::Table(TableType::read(&mut s)?),
                        0x02 => ImportItem::Memory(MemoryType::read(&mut s)?),
                        0x03 => ImportItem::Global(GlobalType::read(&mut s)?),
                        0x04 => ImportItem::Tag(read_tag_type(&mut s)?),
                        k => return Err(s.error(kind_at, Problem::UnknownImportKind(k))),
                    };
                    let import = m.imports.len();
                    match item {
                        ImportItem::Func(ty) => {
                            next_index(m.functions.len(), at, &s)?;
                            m.functions.push(Func { ty, origin: FuncOrigin::Imported { import } });
                        }
                        ImportItem::Table(ty) => {
                            next_index(m.tables.len(), at, &s)?;
                            m.tables.push(Table { ty, origin: TableOrigin::Imported { import } });
                        }
                        ImportItem::Memory(ty) => {
                            next_index(m.memories.len(), at, &s)?;
                            m.memories.push(Memory { ty, origin: Origin::Imported { import } });
                        }
                        ImportItem::Global(ty) => {
                            next_index(m.globals.len(), at, &s)?;
                            m.globals.push(Global { ty, origin: GlobalOrigin::Imported { import } });
                        }
                        ImportItem::Tag(ty) => {
                            next_index(m.tags.len(), at, &s)?;
                            m.tags.push(Tag { ty, origin: Origin::Imported { import } });
                        }
                    }
                    m.imports.push(Import { module, name, item });
                }
            }
            SectionKind::Function => {
                declared_functions = s.count(1)?;
                for body in 0..declared_functions as usize {
                    let at = s.offset();
                    let ty = TypeIdx::read(&mut s)?;
                    next_index(m.functions.len(), at, &s)?;
                    m.functions.push(Func { ty, origin: FuncOrigin::Defined { body } });
                }
            }
            SectionKind::Table => {
                for _ in 0..s.count(3)? {
                    let at = s.offset();
                    let (ty, init) = table_entry(&mut s)?;
                    next_index(m.tables.len(), at, &s)?;
                    m.tables.push(Table { ty, origin: TableOrigin::Defined { init } });
                }
            }
            SectionKind::Memory => {
                for _ in 0..s.count(2)? {
                    let at = s.offset();
                    let ty = MemoryType::read(&mut s)?;
                    next_index(m.memories.len(), at, &s)?;
                    m.memories.push(Memory { ty, origin: Origin::Defined });
                }
            }
            SectionKind::Tag => {
                // `0x00 typeidx`: two bytes at least.
                for _ in 0..s.count(2)? {
                    let at = s.offset();
                    let ty = read_tag_type(&mut s)?;
                    next_index(m.tags.len(), at, &s)?;
                    m.tags.push(Tag { ty, origin: Origin::Defined });
                }
            }
            SectionKind::Global => {
                for _ in 0..s.count(3)? {
                    let at = s.offset();
                    let ty = GlobalType::read(&mut s)?;
                    let init = body::const_expression(&mut s)?;
                    next_index(m.globals.len(), at, &s)?;
                    m.globals.push(Global { ty, origin: GlobalOrigin::Defined { init } });
                }
            }
            SectionKind::Export => {
                for _ in 0..s.count(3)? {
                    let name = s.name()?;
                    let kind_at = s.offset();
                    let kind = s.byte()?;
                    let index = s.u32()?;
                    let item = match kind {
                        0x00 => ExportItem::Func(FuncIdx(index)),
                        0x01 => ExportItem::Table(TableIdx(index)),
                        0x02 => ExportItem::Memory(MemIdx(index)),
                        0x03 => ExportItem::Global(GlobalIdx(index)),
                        0x04 => ExportItem::Tag(TagIdx(index)),
                        k => return Err(s.error(kind_at, Problem::UnknownExportKind(k))),
                    };
                    m.exports.push(Export { name, item });
                }
            }
            SectionKind::Start => m.start = Some(FuncIdx::read(&mut s)?),
            SectionKind::Element => {
                for _ in 0..s.count(3)? {
                    m.elements.push(element_segment(&mut s)?);
                }
            }
            SectionKind::DataCount => m.data_count = Some(s.u32()?),
            SectionKind::Code => {
                let at = s.offset();
                let n = s.count(1)?;
                if n != declared_functions {
                    return Err(s.error(at, Problem::BodyCount { functions: declared_functions, bodies: n }));
                }
                for _ in 0..n {
                    let size = s.u32()? as usize;
                    let body = s.sub(size)?;
                    m.bodies.push(body.offset()..body.end());
                }
            }
            SectionKind::Data => {
                let at = s.offset();
                let n = s.count(2)?;
                if let Some(declared) = m.data_count
                    && declared != n
                {
                    return Err(s.error(at, Problem::DataCount { declared, segments: n }));
                }
                for _ in 0..n {
                    m.data.push(data_segment(&mut s)?);
                }
            }
            SectionKind::Custom { .. } => unreachable!("id 0 was handled above"),
        }
        if !s.at_end() {
            let used = size as usize - s.remaining();
            return Err(s.error(s.offset(), Problem::SectionSize { id, declared: size, used }));
        }
        m.sections.push(Section { kind: kind.clone(), contents });
        last_standard = Some(kind);
    }

    // Counts that span sections: a function section with no code section, or
    // a data count with no data section.
    if m.bodies.len() as u64 != u64::from(declared_functions) {
        return Err(r.error(r.offset(), Problem::BodyCount { functions: declared_functions, bodies: 0 }));
    }
    if let Some(declared) = m.data_count
        && declared as usize != m.data.len()
    {
        return Err(r.error(r.offset(), Problem::DataCount { declared, segments: m.data.len() as u32 }));
    }

    // Every body is decoded once here, keeping nothing, so that `read`
    // answers for the module's whole structure. A body that breaks is a
    // finding about that function alone.
    let first_defined = m.imported_functions();
    let data_indices = m.data_indices();
    for (i, range) in m.bodies.iter().enumerate() {
        if let Err(error) = body::body(Reader::over(&m.bytes, range.clone()), data_indices, |_| {}) {
            // `i` is below the function section's u32 count.
            m.findings.push(Finding::Body { func: FuncIdx(first_defined + i as u32), error });
        }
    }
    Ok(m)
}

/// The type of a segment of function indices: each element is a function, so
/// none is null.
const FUNC_INDICES: RefType = RefType { nullable: false, heap: HeapType::Abstract(AbsHeapType::Func) };

/// The byte that opens a table entry with an initial value, `0x40 0x00
/// tabletype expr`; any other first byte is the reference type of a plain
/// `tabletype`.
const TABLE_WITH_INIT: u8 = 0x40;

/// A table section entry: its type, and the initial value of its elements
/// when the entry states one.
fn table_entry(s: &mut Reader) -> Result<(TableType, Option<Vec<Located>>), Error> {
    if s.peek()? != TABLE_WITH_INIT {
        return Ok((TableType::read(s)?, None));
    }
    s.byte()?;
    let at = s.offset();
    match s.byte()? {
        0x00 => {}
        b => return Err(s.error(at, Problem::ReservedByte(b))),
    }
    let ty = TableType::read(s)?;
    Ok((ty, Some(body::const_expression(s)?)))
}

fn element_segment(s: &mut Reader) -> Result<ElementSegment, Error> {
    let at = s.offset();
    let form = s.u32()?;
    // Bit 0: passive or declarative (not active). Bit 1: with bit 0, declarative;
    // without it, an explicit table index. Bit 2: expressions, not indices.
    if form > 7 {
        return Err(s.error(at, Problem::UnknownElementForm(form)));
    }
    let active = form & 1 == 0;
    let explicit_table = form & 2 != 0;
    let expressions = form & 4 != 0;
    let mode = if active {
        let table = if explicit_table { TableIdx::read(s)? } else { TableIdx(0) };
        ElementMode::Active { table, offset: body::const_expression(s)? }
    } else if explicit_table {
        ElementMode::Declarative
    } else {
        ElementMode::Passive
    };
    // Forms 0 and 4 state no type: function indices, `(ref func)`, and
    // expressions, `funcref`. The others state an element kind (indices),
    // whose one kind `0x00` is `(ref func)`, or a reference type
    // (expressions).
    let ty = match form {
        0 => FUNC_INDICES,
        4 => RefType::FUNCREF,
        _ if expressions => RefType::read(s)?,
        _ => {
            let kind_at = s.offset();
            match s.byte()? {
                0x00 => FUNC_INDICES,
                k => return Err(s.error(kind_at, Problem::UnknownElementKind(k))),
            }
        }
    };
    let n = s.count(1)?;
    let items = if expressions {
        let mut items = Vec::new();
        for _ in 0..n {
            items.push(body::const_expression(s)?);
        }
        ElementItems::Expressions(items)
    } else {
        let mut items = Vec::new();
        for _ in 0..n {
            items.push(FuncIdx::read(s)?);
        }
        ElementItems::Functions(items)
    };
    Ok(ElementSegment { form, ty, mode, items })
}

fn data_segment(s: &mut Reader) -> Result<DataSegment, Error> {
    let at = s.offset();
    let form = s.u32()?;
    let mode = match form {
        0 => DataMode::Active { memory: MemIdx(0), offset: body::const_expression(s)? },
        1 => DataMode::Passive,
        2 => {
            let memory = MemIdx::read(s)?;
            DataMode::Active { memory, offset: body::const_expression(s)? }
        }
        _ => return Err(s.error(at, Problem::UnknownDataForm(form))),
    };
    let len = s.u32()? as usize;
    let init = s.offset();
    s.take(len)?;
    Ok(DataSegment { mode, init: init..init + len })
}
