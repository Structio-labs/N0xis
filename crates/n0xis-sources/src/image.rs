// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The format seam: one [`Image`] trait every image reader implements, and
//! the one registry that chooses the reader ([`formats`]) —
//! docs/design/IMAGE_FORMATS.md §2.
//!
//! **What the trait answers is what the readers knew before it existed, and
//! nothing more** (§5 step 3): the PE and ELF readers are thin wrappers over
//! the parsing they always did, and the adapter every command reads through,
//! [`ImageSource`](crate::ImageSource), computes from these answers exactly
//! what the per-format enum it replaced computed. The answers §2 sketches that
//! today's readers do not have — roles instead of section names, the Thumb bit,
//! applied relocations, every self-bound slot — come with the steps that
//! announce them, so a reader that cannot yet answer says
//! [`Answer::NotRead`] rather than handing back an empty list, and one that
//! answers in part says which parts it did not read ([`Partial`]).
//!
//! **No method has a default.** A defaulted `SymbolProvider::thunk_to` once
//! did nothing through two wrappers that kept the default, with a green build
//! and an unchanged measurement; here a new question is a compile error at
//! every reader until each one answers it.
//!
//! **An address is a position in the image's own space** (`Va`, as
//! docs/design/WASM.md §5 decision 1 widens it): for a native image the
//! virtual address space at its preferred base, for a WebAssembly module the
//! module's own offsets. Nothing here assumes more than that one space per
//! image; linear memories, which a module may have several of, are not
//! addressed through it.

use n0xis_contracts::Va;
use serde::Serialize;

use crate::{ExportTarget, Linkage, MemorySource, RelocatedWords, SourceError};

/// A fact a reader either read, or says it did not.
///
/// "Not read" and "none" are different values: a PE whose import table did
/// not parse must not report an empty one (IMAGE_FORMATS.md §7 decision 4),
/// and a reader that never looks at a table must not report it empty either.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Answer<T> {
    Read(T),
    NotRead { why: String },
}

impl<T> Answer<T> {
    /// The answer, where it was read.
    pub fn read(&self) -> Option<&T> {
        match self {
            Answer::Read(t) => Some(t),
            Answer::NotRead { .. } => None,
        }
    }
}

/// An answer read in part: what was read, and each part of it that was not,
/// with why (IMAGE_FORMATS.md §2: "not read" and "none" are different values).
///
/// `not_read` empty means the reader read every part it knows the answer has.
/// Not an [`Answer`]: a list that misses a part is still worth serving (the
/// exports of a PE are its names even while its COFF symbol table is not
/// read), but a consumer that takes `read` for the whole answer has to be able
/// to see that it is not. Before this type the parts were left out silently,
/// and the list read as complete.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Partial<T> {
    pub read: T,
    pub not_read: Vec<Unread>,
}

impl<T> Partial<T> {
    /// A list every part of which was read.
    pub fn whole(read: T) -> Self {
        Partial { read, not_read: Vec::new() }
    }
}

/// A part of an answer that was not read: `part` names it as the image's own
/// tables name it (`the COFF symbol table`, `PLT stubs`), `why` says why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Unread {
    pub part: String,
    pub why: String,
}

/// The byte order an image states for its multi-byte data: ELF
/// `e_ident[EI_DATA]` 1 (`ELFDATA2LSB`) or 2 (`ELFDATA2MSB`). A PE is always
/// little-endian.
///
/// Stated so a reader that only reads one order can refuse the other by name
/// rather than read it wrongly. Today the Itanium RTTI paths do
/// (`n0xis_core::RttiRefusal`); every other reader of image data still reads
/// little-endian whatever this says — an open item, not a decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteOrder {
    /// `ELFDATA2LSB`, and every PE.
    Little,
    /// `ELFDATA2MSB`.
    Big,
}

/// The width of the image's **data** pointers, as its container states it
/// (PE32 / PE32+, `ELFCLASS32` / `ELFCLASS64`).
///
/// Not the decoder's register width: the x32 ABI and arm64_32 run 64-bit code
/// with 4-byte pointers, and the decoder is chosen from [`Isa`], never from
/// this.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PointerWidth {
    #[serde(rename = "4")]
    Four,
    #[serde(rename = "8")]
    Eight,
}

impl PointerWidth {
    pub fn bytes(self) -> u8 {
        match self {
            PointerWidth::Four => 4,
            PointerWidth::Eight => 8,
        }
    }
}

/// The instruction set an image's header names, as today's readers map it.
///
/// **Today's mapping, not §2's table** (IMAGE_FORMATS.md §5 step 2 replaces
/// it, on purpose and with its own list of changed answers): PE `0x01c0` and
/// `0x01c4` are both [`Isa::Arm`], and a big-endian `EM_ARM` is the same
/// [`Isa::Arm`] as a little-endian one, exactly as before.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Isa {
    X64,
    X86,
    Arm64,
    Arm,
    /// A machine value this build does not map, as the header holds it.
    Unrecognized { raw: u16 },
    /// The header's machine field could not be read at all.
    Unreadable,
}

impl Isa {
    /// The name every consumer of the machine reads: `x64`, `x86`, `arm64`,
    /// `arm`, the raw value in hex (`0x8`) for a machine this build does not
    /// map, `unknown` where there was none to read. The decoder picker
    /// (`n0xis_frontend::pick_arch_for`) keys on exactly these spellings.
    pub fn name(self) -> String {
        match self {
            Isa::X64 => "x64".into(),
            Isa::X86 => "x86".into(),
            Isa::Arm64 => "arm64".into(),
            Isa::Arm => "arm".into(),
            Isa::Unrecognized { raw } => format!("0x{raw:x}"),
            Isa::Unreadable => "unknown".into(),
        }
    }
}

/// What machine the image is for (§2's first question), as today's readers
/// answer it. The revision, and one table from the declaration to the set of
/// decoders the image can hold, are §5 step 2's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Machine {
    pub isa: Isa,
    pub pointer_width: PointerWidth,
    pub byte_order: ByteOrder,
    /// The calling convention signature recovery reads the image with, as a
    /// `CallConv::name` selector: `win64` for a PE32+, `cdecl` for a PE32,
    /// `sysv` for every ELF — the readers' own answers, unchanged.
    pub abi: &'static str,
}

/// How the loader maps the image: its preferred base, the span it reserves
/// there, and the segments as the container states them.
///
/// **Reads do not go through these yet.** In this step the read view is the
/// one it always was ([`LoadedBytes`], placed by section); the loader's
/// structures winning over the sections (§4 rule 4) is a later change of
/// answers, not this one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Segments {
    /// The preferred base: a PE's `ImageBase`; an ELF's lowest `PT_LOAD`
    /// address (0 when it has none).
    pub base: Va,
    /// Bytes from `base` the image occupies: a PE's `SizeOfImage`; the end of
    /// an ELF's last `PT_LOAD` (`p_vaddr + p_memsz`) less `base`.
    pub span: u64,
    pub list: Vec<Segment>,
}

/// One loadable piece, its fields as the container states them.
///
/// An ELF's are its `PT_LOAD` program headers. A PE has no segments of its
/// own: the loader maps its headers (`SizeOfHeaders` bytes at the base) and
/// then each section-table entry, so those are listed, the headers first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Segment {
    pub va: Va,
    /// `p_memsz`; a section's `VirtualSize` (the headers': `SizeOfHeaders`).
    pub mem_size: u64,
    pub file_offset: u64,
    /// `p_filesz`; a section's `SizeOfRawData`.
    pub file_size: u64,
    pub access: Access,
}

/// What a segment may be used for: ELF `p_flags` (`PF_R`, `PF_W`, `PF_X`), a
/// PE section's `IMAGE_SCN_MEM_READ`/`_WRITE`/`_EXECUTE` (the headers: read).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Access {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// One part of the image, by the name the container gives it.
///
/// A PE's list starts with its headers, named `""`: that is how they have
/// always been answered (`section_range("")` is the headers), and whether the
/// headers are a "part" at all is decided with roles (§5 step 4), not here. An
/// ELF's list is every section with an address (`sh_addr != 0`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Section {
    pub name: String,
    pub va: Va,
    /// Bytes of address space it covers: an ELF's `sh_size`; for a PE the
    /// larger of `VirtualSize` and `SizeOfRawData`.
    pub size: u64,
    pub file_offset: u64,
    /// Bytes the file holds for it: 0 for `SHT_NOBITS`; a PE's `SizeOfRawData`.
    pub file_size: u64,
    /// `SHF_EXECINSTR`; `IMAGE_SCN_MEM_EXECUTE`.
    pub executable: bool,
    /// Whether it takes room in the image's address space. Only an ELF TLS
    /// zero-fill section (`.tbss`) does not: it describes each thread's TLS,
    /// and mapped it shadows the sections that share its address.
    pub in_image: bool,
}

/// What a symbol names, as its table says.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    /// ELF `STT_FUNC`.
    Function,
    /// ELF `STT_OBJECT`.
    Object,
    /// The table does not say: a PE export names code or a variable alike.
    NotStated,
}

/// How long a thing is, where the image says.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Extent {
    /// Exactly this many bytes, more than zero.
    Stated(u64),
    Unknown,
}

/// The table a symbol was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolTable {
    /// ELF `.symtab`.
    Static,
    /// ELF `.dynsym`.
    Dynamic,
    /// A PE's export table: its named exports, and its unnamed ones that land
    /// in code as `Ordinal<n>`. A PE's COFF symbol table is not read.
    Exports,
}

/// A name the image gives an address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImageSymbol {
    pub va: Va,
    /// As stored: an ELF version suffix and any decoration included.
    pub name: String,
    pub kind: SymbolKind,
    pub extent: Extent,
    pub table: SymbolTable,
}

/// One entry of an export table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Export {
    /// The exported name, or `None` for an export by ordinal only.
    pub name: Option<String>,
    /// The ordinal, where the format numbers its exports.
    pub ordinal: Option<u32>,
    pub target: ExportTarget,
}

/// How an image's imports are bound to the libraries that provide them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportBinding {
    /// Each reference is bound to one library: a PE import descriptor.
    PerLibrary,
    /// One namespace: the loader looks a name up in every loaded object in
    /// order, and a library an ELF names for a symbol (its version
    /// requirement) is informative, not authoritative.
    Flat,
}

/// Why a library is in the list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LibrarySource {
    /// A PE import descriptor.
    ImportDescriptor,
    /// An ELF `DT_NEEDED` entry.
    Needed,
    /// Named only by an ELF version requirement (`.gnu.version_r`), by no
    /// `DT_NEEDED` entry: listed so the reference naming it can point at it.
    VersionRequirementOnly,
}

/// A library the image needs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Library {
    /// As the image spells it; for a PE, the file-name part of the
    /// descriptor's name, which is how every symbol answer has spelled it.
    pub name: String,
    pub stated_by: LibrarySource,
    /// The entries of this library's table that are not among
    /// [`Imports::references`], and why: a PE import lookup table holding
    /// more entries than the parser returned (the parser skips an entry whose
    /// hint/name entry it cannot place, and numbers the slots after it as if
    /// it were not there). Empty when every entry was read; always empty for
    /// an ELF, whose libraries hold no entries of their own.
    pub references_not_read: Vec<Unread>,
}

/// What a reference imports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum ImportName {
    #[serde(rename = "name")]
    Named(String),
    /// A PE import by ordinal.
    #[serde(rename = "ordinal")]
    Ordinal(u16),
}

impl ImportName {
    /// The name a symbol answer carries for it. An import by ordinal has been
    /// spelled `ORDINAL <n>` (the PE parser's spelling) in every answer that
    /// names one, and is spelled so here, in one place.
    pub fn symbol_name(&self) -> String {
        match self {
            ImportName::Named(name) => name.clone(),
            ImportName::Ordinal(n) => format!("ORDINAL {n}"),
        }
    }
}

/// Which library a reference is attributed to, by index into
/// [`Imports::libraries`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LibraryRef {
    /// The format binds the reference to this library (a PE import
    /// descriptor).
    Binds(usize),
    /// The image names this library for the reference without binding it
    /// there (an ELF version requirement).
    Named(usize),
    Unattributed { why: &'static str },
}

/// How a reference is reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reach {
    /// Code that jumps through the reference's slot (an ELF PLT stub).
    Stub(Va),
    /// The pointer the loader binds (a PE IAT entry, an ELF GOT slot).
    Slot(Va),
    /// By index, with no address at all: a WebAssembly import is function
    /// `n` of the module's function index space (docs/design/WASM.md §5
    /// decision 1).
    Index(u32),
}

/// One thing the image imports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportReference {
    #[serde(flatten)]
    pub name: ImportName,
    pub library: LibraryRef,
    /// Every way the image reaches it that the reader reads. An ELF's reach is
    /// the slots a `GLOB_DAT` or `JUMP_SLOT` relocation binds to it and the PLT
    /// stubs that jump through them; a symbol reached only through another
    /// relocation (an absolute data pointer, a copy relocation, TLS) lists
    /// none. Not read on an ELF machine whose relocation types are not mapped.
    pub reach: Answer<Vec<Reach>>,
}

/// What the image needs from other images (§2), grouped by library.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Imports {
    pub binding: ImportBinding,
    /// In the order the image states them: a PE's descriptors, an ELF's
    /// `DT_NEEDED` entries (then any library only a version requirement names).
    pub libraries: Vec<Library>,
    pub references: Vec<ImportReference>,
    /// What the image reaches its imports through that no reference's
    /// [`ImportReference::reach`] lists, for the whole image: an ELF's PLT
    /// stubs on a machine whose stubs are not decoded (every machine but
    /// x86-64). Each reference's reach is still the slots that were read; the
    /// stubs that jump through them are what this names. Empty when nothing
    /// was left out.
    pub reach_not_read: Vec<Unread>,
}

/// Why the image says code starts at an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartReason {
    /// A PE export that lands in an executable section.
    Export,
    /// An ELF `STT_FUNC` symbol, from either table.
    Symbol,
    /// A PE32+ `.pdata` `RUNTIME_FUNCTION`.
    UnwindEntry,
    /// A stub that only jumps through `slot` (an x86-64 ELF PLT entry whose
    /// slot an import or a self-bound `JUMP_SLOT` relocation names).
    Stub { slot: Va },
}

/// A place the image's own tables say code starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DeclaredStart {
    pub va: Va,
    pub why: StartReason,
    pub extent: Extent,
}

/// What a slot is bound to (§7 decision 3), as far as today's readers know.
///
/// Today that is an import slot's symbol (a PE IAT entry, an ELF `GLOB_DAT`
/// or `JUMP_SLOT` against an undefined symbol) and a `JUMP_SLOT` bound to a
/// function the image defines. Rebases, and every other self-bound slot, are
/// the announced change of answers that follows this step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Binding {
    Import(ImportRef),
    /// A slot the loader fills with this image's own definition at `target`.
    SelfDefinition { target: Va },
    /// Two relocations bind the slot, one to an import and one to a definition
    /// in this image. No linker here emits that, but a file can say it, and
    /// which value the loader leaves in the slot depends on the order it
    /// applies the two, so neither is the answer. Both are kept, as the
    /// readers kept both before this trait: the stub that jumps through the
    /// slot is named after the import and forwards to the definition. The
    /// image reports it as a [`Finding::Contradiction`].
    ///
    /// Without this variant one of the two was dropped, and a stub's
    /// forwarding target that the 0.3.5 reader answered on such a file was
    /// gone (a planted shared object, both `JUMP_SLOT` entries at one offset
    /// in `llvm-readobj -r`).
    ImportAndSelfDefinition { import: ImportRef, target: Va },
    /// None of the tables this step reads for bindings binds the slot: a PE's
    /// import descriptors, an ELF's `GLOB_DAT` and `JUMP_SLOT` relocations.
    /// A slot only another relocation names (an `R_X86_64_64` against a
    /// definition here) answers this until the announced change that follows
    /// this step reads those too (§7 decision 3).
    Unbound { why: &'static str },
    /// A table that binds slots was not read, so whether this slot is bound,
    /// and to what, is not known: an ELF of a machine whose `GLOB_DAT` and
    /// `JUMP_SLOT` relocation types are not mapped, a PE with a delay-load
    /// import table, a PE only a permissive parse opened. "Not read" is not
    /// "unbound" (§2): a slot of such an image answered `Unbound` while the
    /// same image's [`Image::imports`] said its reach was not read.
    NotRead { why: String },
}

/// What a reader answers for a slot its tables do not list: unbound when it
/// read the tables it reads for bindings, not read when one of them was
/// skipped. Two states and no third, so a reader cannot list a binding here
/// by mistake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnlistedSlot {
    Unbound { why: &'static str },
    NotRead { why: String },
}

impl UnlistedSlot {
    pub fn binding(&self) -> Binding {
        match self {
            UnlistedSlot::Unbound { why } => Binding::Unbound { why },
            UnlistedSlot::NotRead { why } => Binding::NotRead { why: why.clone() },
        }
    }
}

/// The import a slot is bound to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportRef {
    pub name: ImportName,
    /// The library the image names for it, spelled as [`Library::name`];
    /// `None` where it names none.
    pub library: Option<String>,
}

/// Something wrong with the image that the reader worked around.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Finding {
    /// A strict parse refused the image and it was opened permissively; what
    /// did not parse (usually the imports) is missing, not empty.
    StrictParseRefused { why: String },
    /// Two of the image's own statements disagree, and the reader did not
    /// pick one silently (§4 rule 4): `what` says which, and what the answers
    /// built on them do about it.
    Contradiction { what: String },
}

/// An image's CodeView record: which program database (PDB) the linker wrote
/// beside it. The GUID and the age are what a PDB must carry to belong to this
/// image; the path is only where it was written, on the machine that built it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeView {
    /// The 16 bytes as the record holds them (the first three fields little-endian).
    pub guid: [u8; 16],
    pub age: u32,
    /// The PDB's path as the linker wrote it, up to its first NUL.
    pub pdb_path: String,
}

/// Where a stretch of the image's address space comes from in the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    pub va: u64,
    /// Exclusive.
    pub end: u64,
    pub file_offset: usize,
    /// File bytes from `file_offset`; past them, up to `end`, a read is short.
    pub file_size: usize,
}

/// What memory holds when the image is loaded (§2, §7 decision 3), as the read
/// view has always served it: the file's bytes at each placement, in order —
/// the first placement that holds an address answers for it.
///
/// **The read rule lives here, once**, as this view's [`MemorySource`]: the
/// adapter serves every read through it, and so does a reader that has to
/// read its own image while it is still parsing it (the PE export table).
/// Two copies of it, one in the adapter and one in the PE reader, could drift
/// with no test failing.
#[derive(Clone, Copy, Debug)]
pub struct LoadedBytes<'a> {
    pub file: &'a [u8],
    pub placed: &'a [Placement],
    /// The words the loader writes, or why they were not read. No word is
    /// written into the view yet: applying them is the announced change that
    /// follows this step.
    pub written_by_loader: &'a RelocatedWords,
}

impl LoadedBytes<'_> {
    /// The first placement that holds `va`.
    fn placement_of(&self, va: Va) -> Option<&Placement> {
        self.placed.iter().find(|p| va.0 >= p.va && va.0 < p.end)
    }
}

impl MemorySource for LoadedBytes<'_> {
    fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, SourceError> {
        let Some(p) = self.placement_of(va) else {
            return Err(SourceError::Unmapped(va));
        };
        let in_placement = (va.0 - p.va) as usize;
        // Inside a placement but past its file bytes (a `.bss` tail): not
        // synthesized — a short read, exactly as a live read at the same spot
        // would give.
        if in_placement >= p.file_size {
            return Ok(Vec::new());
        }
        let file_start = p.file_offset + in_placement;
        let avail = p.file_size - in_placement;
        let take = len.min(avail);
        let end = (file_start + take).min(self.file.len());
        if file_start >= end {
            return Ok(Vec::new());
        }
        Ok(self.file[file_start..end].to_vec())
    }

    fn contains(&self, va: Va) -> bool {
        self.placement_of(va).is_some()
    }

    fn label(&self) -> String {
        "static:loaded-bytes".to_string()
    }
}

/// The questions every image reader answers (IMAGE_FORMATS.md §2).
pub trait Image: std::fmt::Debug + Send + Sync {
    fn machine(&self) -> Machine;
    fn linkage(&self) -> Linkage;
    fn segments(&self) -> &Segments;
    fn sections(&self) -> &[Section];
    /// The names the image gives addresses, and the tables of names that were
    /// not read (a PE's COFF symbol table, ELF symbols of a type not read).
    fn symbols(&self) -> &Answer<Partial<Vec<ImageSymbol>>>;
    fn imports(&self) -> &Answer<Imports>;
    fn exports(&self) -> &Answer<Vec<Export>>;
    /// Where the image says code starts, and the kinds of start it states
    /// that were not read (the entry point, an unwind table, PLT stubs).
    fn declared_starts(&self) -> &Partial<Vec<DeclaredStart>>;
    fn loaded_bytes(&self) -> LoadedBytes<'_>;
    fn findings(&self) -> &[Finding];
    /// What the slot at `slot` is bound to.
    fn binding_at(&self, slot: Va) -> Binding;
    /// The image's CodeView record, which names its PDB. Not one of §2's
    /// questions: it is what the PDB lookup reads until PDB becomes a metadata
    /// unit (§5 step 5). No ELF has one.
    fn codeview(&self) -> Option<&CodeView>;
}

/// Which reader opened an image.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageFormat {
    Pe,
    Elf,
}

impl ImageFormat {
    pub fn name(self) -> &'static str {
        match self {
            ImageFormat::Pe => "pe",
            ImageFormat::Elf => "elf",
        }
    }
}

/// What an opener may be told beyond the bytes. Nothing yet: the slice of a
/// universal file and the base, machine and memory map of raw firmware come
/// with the formats that need them (§5 steps 6 and 7).
#[derive(Clone, Debug, Default)]
pub struct OpenOptions {}

/// What opening gave. A universal file's `NeedsSlice` comes with Mach-O (§5
/// step 6), and every match on this then has to answer it.
#[derive(Debug)]
pub enum Opened {
    Thin(Box<dyn Image>),
}

/// Why an opener refused the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The container's parser refused them, with its message.
    Parse(String),
    /// The parse succeeded but the image lacks something every image of the
    /// format has; the message says what.
    Refused(String),
}

/// The most leading bytes a format's `sniff` is shown: recognition reads
/// this much of a file and no more, and only a file a format recognizes is
/// read whole. Reading the whole file first, to recognize it after, made
/// `profile --file /dev/zero` read until the memory ran out instead of
/// refusing in no time as 0.3.5 did, and a 3 GB file that is no image was
/// killed for its memory, with no JSON, where 0.3.5 refused it in 21 ms.
///
/// Every signature recognized today is 4 bytes or fewer (`MZ`, `\x7fELF`); a
/// WebAssembly module's magic and version are 8. A sniff that needs more than
/// this sees a short slice and recognizes nothing, which its own format's
/// tests would show.
pub const SNIFF_LEN: usize = 64;

/// One entry of the registry: how a format is recognized and opened.
pub struct Format {
    pub format: ImageFormat,
    /// How the format is named when nothing is recognized: `a PE (MZ)`.
    pub described: &'static str,
    /// Whether the file's leading bytes, at most [`SNIFF_LEN`] of them, carry
    /// the format's signature.
    pub sniff: fn(&[u8]) -> bool,
    pub open: fn(Vec<u8>, &OpenOptions) -> Result<Opened, OpenError>,
}

/// **The one place a container signature is checked to choose a reader** on
/// the static path — and only there. Other code still checks signatures of its
/// own, because it reads an image as it is mapped and an opener over the
/// mapped layout is not part of this step (IMAGE_FORMATS.md §2): the core's
/// header walks and the `.pdata` and ELF-ident checks of the unwinder, which
/// §5 step 4 removes; and three that no step of §5 names yet — the live
/// Windows adapter's two (`live.rs`), the unwinder's choice of format for a
/// mapped module (`unwind.rs`, `module_format`) and the export reader's header
/// read (`pe_exports.rs`, `ExportDirectory::from_header`). Until a step names
/// those, §6's "format detection exists once" has no step that reaches it.
pub fn formats() -> &'static [Format] {
    #[cfg(feature = "static-pe")]
    {
        &[
            Format { format: ImageFormat::Pe, described: "a PE (MZ)", sniff: crate::static_pe::sniff, open: crate::static_pe::open },
            Format { format: ImageFormat::Elf, described: "ELF (\\x7fELF)", sniff: crate::static_elf::sniff, open: crate::static_elf::open },
        ]
    }
    #[cfg(not(feature = "static-pe"))]
    {
        &[]
    }
}

/// The first format whose signature `bytes` carry. Each sniff is shown the
/// first [`SNIFF_LEN`] bytes at most, whatever it is given, so recognizing a
/// whole file and recognizing its prefix are one answer.
pub fn recognize(bytes: &[u8]) -> Option<&'static Format> {
    let prefix = &bytes[..bytes.len().min(SNIFF_LEN)];
    formats().iter().find(|f| (f.sniff)(prefix))
}
