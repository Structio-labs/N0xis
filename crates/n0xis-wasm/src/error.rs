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
    #[error("value type byte {0:#04x} is not one read here")]
    UnknownValueType(u8),
    #[error("reference type byte {0:#04x} is not one read here")]
    UnknownRefType(u8),
    #[error("block type byte {0:#04x} is neither empty, a value type nor a type index")]
    UnknownBlockType(u8),
    #[error("type form {0:#04x} is not a function type (0x60), and no other form is read here")]
    UnknownTypeForm(u8),
    #[error("import kind {0:#04x} is not one read here")]
    UnknownImportKind(u8),
    #[error("export kind {0:#04x} is not one read here")]
    UnknownExportKind(u8),
    #[error("limits flags {0:#04x} are not read here (shared memories are not)")]
    UnknownLimitsFlags(u8),
    #[error("mutability byte {0:#04x} is neither 0 nor 1")]
    UnknownMutability(u8),
    #[error("element segment form {0} is not one of the eight the format defines")]
    UnknownElementForm(u32),
    #[error("element kind {0:#04x} is not `funcref` (0x00)")]
    UnknownElementKind(u8),
    #[error("data segment form {0} is not one of the three the format defines")]
    UnknownDataForm(u32),
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
    #[error("the expression ends before its final `end`")]
    NotEnded,
    #[error("{0} bytes after the final `end` of a function body")]
    BytesAfterEnd(usize),
    #[error("a data index in code, and no data count section")]
    DataIndexWithoutDataCount,
}

fn opcode_text(prefix: Option<u8>, code: u32) -> String {
    match prefix {
        Some(p) => format!("{p:#04x} {code:#x}"),
        None => format!("{code:#04x}"),
    }
}
