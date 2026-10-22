// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What can be wrong with a module, as values a caller can branch on.

/// Why a module, a function body or an expression in it could not be read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The bytes break a rule of the binary format at `offset` (an offset
    /// into the file), or use a construct outside what this crate reads.
    #[error("unreadable at offset {offset:#x}: {problem}")]
    Unreadable { offset: usize, problem: Problem },
    /// The reader itself stopped. This is a defect of this crate, not a fact
    /// about the file; the corrupted-input tests count it as a failure.
    #[error("the reader stopped on this input, which is a defect of the reader: {0}")]
    Internal(String),
}

/// A rule of the binary format that the bytes break.
///
/// "Not read here" problems (an opcode, a type, a section this crate does not
/// know) say only that: the bytes may belong to a proposal this crate does not
/// read, or to nothing at all, and the reader cannot tell which.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Problem {
    #[error("the file does not begin with the module magic `\\0asm`")]
    Magic,
    #[error("binary format version {0}; the core module format is version 1")]
    Version(u32),
    /// The preamble of a component: the component model's binary format puts
    /// a version (`0x0d` for its drafts) and a layer, 1, where a core module
    /// has its version, 1 (`(version, layer)` are the two little-endian
    /// halves of what a core module reads as one `u32`).
    #[error("a component (preamble version {version:#x}, layer {layer}): the component model's format, which wraps core modules; this reader reads a core module, binary format version 1")]
    Component { version: u16, layer: u16 },
    #[error("{needed} bytes needed, {available} left in the enclosing item")]
    End { needed: usize, available: usize },
    #[error("a {bits}-bit LEB128 runs past the longest encoding the format allows")]
    LebTooLong { bits: u32 },
    #[error("a {bits}-bit LEB128 carries bits outside its range")]
    LebTooBig { bits: u32 },
    #[error("a count of {count} entries, with {available} bytes left to hold them")]
    CountTooLarge { count: u32, available: usize },
    #[error("a name that is not UTF-8")]
    Utf8,
    #[error("section id {0} is not one read here")]
    UnknownSection(u8),
    #[error("section {id} after section {after}: standard sections appear once each, in the format's order")]
    SectionOrder { id: u8, after: u8 },
    #[error("section {id} states {declared} bytes and its contents take {used}")]
    SectionSize { id: u8, declared: u32, used: usize },
    /// The same rule inside the `name` section, whose subsections each state
    /// their size; `id` is the subsection's, not a standard section's.
    #[error("name subsection {id} states {declared} bytes and its contents take {used}")]
    SubsectionSize { id: u8, declared: u32, used: usize },
    #[error("value type byte {0:#04x} is not one read here")]
    UnknownValueType(u8),
    #[error("reference type byte {0:#04x} is not one read here")]
    UnknownRefType(u8),
    #[error("heap type byte {0:#04x} is neither an abstract heap type nor a type index")]
    UnknownHeapType(u8),
    #[error("block type byte {0:#04x} is neither empty, a value type nor a type index")]
    UnknownBlockType(u8),
    /// Met where a composite type must begin: after a recursion group's head
    /// and a subtype's head have been read, so `0x4e`, `0x50` and `0x4f` land
    /// here only where they may not stand (a group inside a group, a subtype
    /// inside a subtype).
    #[error(
        "type form {0:#04x} is not a function (0x60), structure (0x5f) or array (0x5e) type, the only forms that \
         may stand here"
    )]
    UnknownTypeForm(u8),
    #[error("import kind {0:#04x} is not one read here")]
    UnknownImportKind(u8),
    #[error("export kind {0:#04x} is not one read here")]
    UnknownExportKind(u8),
    #[error("limits flags {0:#04x} are not read here")]
    UnknownLimitsFlags(u8),
    #[error("mutability byte {0:#04x} is neither 0 nor 1")]
    UnknownMutability(u8),
    #[error("element segment form {0} is not one of the eight the format defines")]
    UnknownElementForm(u32),
    #[error("element kind {0:#04x} is not `func` (0x00)")]
    UnknownElementKind(u8),
    #[error("data segment form {0} is not one of the three the format defines")]
    UnknownDataForm(u32),
    #[error("tag attribute {0:#04x} is not 0, an exception")]
    UnknownTagAttribute(u8),
    #[error("catch clause kind {0:#04x} is none of the four (0 to 3)")]
    UnknownCatchKind(u8),
    #[error("cast flags {0:#04x} set a bit other than the two nullability bits")]
    CastFlags(u8),
    #[error("a reserved byte is {0:#04x} and the format requires 0")]
    ReservedByte(u8),
    #[error("{functions} functions are declared and {bodies} bodies given")]
    BodyCount { functions: u32, bodies: u32 },
    #[error("the data count section states {declared} segments and the data section holds {segments}")]
    DataCount { declared: u32, segments: u32 },
    #[error("an index space larger than 2^32 entries")]
    IndexSpaceOverflow,
    #[error("a function declares more than 2^32 - 1 locals")]
    TooManyLocals,
    #[error("opcode {} is not one read here", opcode_text(*prefix, *code))]
    UnknownOpcode { prefix: Option<u8>, code: u32 },
    #[error("memory argument flags {0:#x} are not an alignment, with or without a memory index")]
    MemArgFlags(u32),
    #[error("`else` outside an `if`, or a second `else` in one")]
    ElseWithoutIf,
    #[error("`catch` or `catch_all` outside a `try`, or after its `catch_all`")]
    CatchOutsideTry,
    #[error("`delegate` outside a `try`, or after one of its handlers")]
    DelegateOutsideTry,
    #[error("the expression ends before its final `end`")]
    NotEnded,
    #[error("{0} bytes after the final `end` of a function body")]
    BytesAfterEnd(usize),
    #[error("{0} bytes after the item that fills a custom section")]
    BytesAfterItem(usize),
    #[error("a data index in code, and no data count section")]
    DataIndexWithoutDataCount,
}

fn opcode_text(prefix: Option<u8>, code: u32) -> String {
    match prefix {
        Some(p) => format!("{p:#04x} {code:#x}"),
        None => format!("{code:#04x}"),
    }
}
