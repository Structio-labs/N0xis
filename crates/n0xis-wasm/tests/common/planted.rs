// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Modules planted byte by byte, each breaking one structural rule of the
//! binary format (or none), with the answer stated before the reader runs.
//! `tests/structure.rs` checks the reader's typed answer; the oracle test asks
//! wasm-tools, wabt and V8 whether they accept the same bytes, each only about
//! the cases whose proposals it implements.

use n0xis_wasm::{Error, FuncIdx, NameProblem, Problem, TypeIdx, Within};

/// What the reader must answer.
pub enum Expect {
    /// Reads with no finding.
    Reads,
    /// `read` refuses with this problem.
    Refused(Problem),
    /// Reads, and the first defined function's body has this problem.
    Body(Problem),
    /// Reads, with this finding about the name section.
    Name(NameProblem),
}

/// What an independent validator must answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tool {
    Accepts,
    Rejects,
    /// Accepts: the bytes are well formed in a proposal this crate does not
    /// read, so its refusal is a limit of scope, not a verdict on the file.
    AcceptsOutsideScope,
    /// Rejects, by validation: the bytes are well formed and break a rule of
    /// validation, which this crate does not check.
    RejectsByValidation,
}

/// A proposal to the format whose rules decide a case. A validator that does
/// not implement a case's proposal answers about something else (wabt refuses
/// every recursion group, so its "rejects" on a malformed one is a verdict on
/// the type form, not on the rule planted), so the oracle test does not ask it;
/// which validator implements which is one table there.
///
/// Every variant is needed by a case; a proposal no case plants needs no
/// variant. The ones in WebAssembly 3.0 first, then the ones outside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proposal {
    /// Memory indices in memory arguments (flags bit 6).
    MultiMemory,
    /// 64-bit memories and tables, and the `u64` bounds of every limits form.
    Memory64,
    TailCall,
    RelaxedSimd,
    /// Typed function references: `(ref null x)`, the `0x40 0x00` table form.
    FunctionReferences,
    /// Garbage collection: recursion groups, subtypes, structures and arrays,
    /// the heap types past `func`, `extern` and `exn`, the `0xFB` opcodes.
    Gc,
    /// Exception handling with `exnref`: tags, `try_table`.
    Exceptions,
    /// Shared memories and the `0xFE` opcodes.
    Threads,
    /// The legacy exception instructions: `try`, `catch`, `catch_all`, `delegate`.
    LegacyExceptions,
    /// Shared heap types (`0x65`), shared tables.
    SharedEverythingThreads,
    /// Limits flags bit 3 and a page size.
    CustomPageSizes,
    /// `i64.add128` and the rest of `0xFC 0x13..0x16`.
    WideArithmetic,
}

pub struct Case {
    pub name: &'static str,
    pub bytes: Vec<u8>,
    pub expect: Expect,
    pub tool: Tool,
    /// The proposals beyond WebAssembly 2.0 the bytes need, every one: empty
    /// for a case of 2.0 alone, which every validator asked implements.
    pub needs: &'static [Proposal],
}

pub fn leb(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

pub fn name(s: &[u8]) -> Vec<u8> {
    [leb(s.len() as u64), s.to_vec()].concat()
}

pub fn section(id: u8, contents: &[u8]) -> Vec<u8> {
    [vec![id], leb(contents.len() as u64), contents.to_vec()].concat()
}

pub fn custom(section_name: &[u8], contents: &[u8]) -> Vec<u8> {
    section(0, &[name(section_name), contents.to_vec()].concat())
}

pub fn vector(items: &[Vec<u8>]) -> Vec<u8> {
    [leb(items.len() as u64), items.concat()].concat()
}

pub fn module(sections: &[Vec<u8>]) -> Vec<u8> {
    [b"\0asm".to_vec(), vec![1, 0, 0, 0], sections.concat()].concat()
}

/// Type 0, `() -> ()`.
pub fn types() -> Vec<u8> {
    section(1, &vector(&[vec![0x60, 0, 0]]))
}

/// One function of type 0.
pub fn functions() -> Vec<u8> {
    section(3, &vector(&[vec![0]]))
}

/// One memory of one page.
pub fn memory() -> Vec<u8> {
    section(5, &vector(&[vec![0x00, 1]]))
}

/// A code section with one body: `locals`, then `code` (which must end it).
pub fn code(locals: &[u8], code: &[u8]) -> Vec<u8> {
    let body = [locals.to_vec(), code.to_vec()].concat();
    section(10, &vector(&[[leb(body.len() as u64), body].concat()]))
}

/// A function of type `() -> ()` with this code and no locals.
pub fn with_body(code_bytes: &[u8]) -> Vec<u8> {
    module(&[types(), functions(), code(&[0], code_bytes)])
}

/// Same, with a memory.
pub fn with_body_and_memory(code_bytes: &[u8]) -> Vec<u8> {
    module(&[types(), functions(), memory(), code(&[0], code_bytes)])
}

/// One tag, of type 0 `() -> ()`.
pub fn tag_section() -> Vec<u8> {
    section(13, &vector(&[vec![0x00, 0x00]]))
}

/// A function of type `() -> ()` with this code, and one tag of that type.
pub fn with_body_and_tag(code_bytes: &[u8]) -> Vec<u8> {
    module(&[types(), functions(), tag_section(), code(&[0], code_bytes)])
}

/// A type section of one entry (one recursion group), as given.
pub fn one_type(entry: &[u8]) -> Vec<u8> {
    module(&[section(1, &vector(&[entry.to_vec()]))])
}

/// Types 0 `(struct)`, 1 `() -> ()` and 2 `(array (mut i8))`.
pub fn gc_types() -> Vec<u8> {
    section(1, &vector(&[vec![0x5f, 0x00], vec![0x60, 0x00, 0x00], vec![0x5e, 0x78, 0x01]]))
}

/// One function of type 1 of [`gc_types`].
pub fn gc_functions() -> Vec<u8> {
    section(3, &vector(&[vec![1]]))
}

/// A function of type `() -> ()` over [`gc_types`], with this code.
pub fn with_gc_body(code_bytes: &[u8]) -> Vec<u8> {
    module(&[gc_types(), gc_functions(), code(&[0], code_bytes)])
}

/// One passive data segment.
pub fn passive_data() -> Vec<u8> {
    section(11, &vector(&[[vec![1], name(b"xy")].concat()]))
}

/// A name section holding these subsections, as given.
pub fn names(subsections: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let body: Vec<u8> = subsections.iter().flat_map(|(id, c)| [vec![*id], leb(c.len() as u64), c.clone()].concat()).collect();
    custom(b"name", &body)
}

pub fn function_names(n: &[u8]) -> Vec<u8> {
    name_map(&[(0, n)])
}

/// `vec(idx name)`, as given.
pub fn name_map(entries: &[(u64, &[u8])]) -> Vec<u8> {
    vector(&entries.iter().map(|(i, n)| [leb(*i), name(n)].concat()).collect::<Vec<_>>())
}

/// A code section with `n` empty bodies.
pub fn code_n(n: usize) -> Vec<u8> {
    section(10, &vector(&vec![vec![2, 0, 0x0b]; n]))
}

pub fn cases() -> Vec<Case> {
    use Expect::*;
    use Problem as P;
    use Proposal::*;
    use Tool::*;
    let case = |name, bytes, expect, tool, needs: &'static [Proposal]| Case { name, bytes, expect, tool, needs };
    let end = 0x0b;
    let drop = 0x1a;
    vec![
        case("minimal", with_body(&[end]), Reads, Accepts, &[]),
        // i32.const 2147483647, padded to the full five bytes it may take.
        case("i32.const at its widest", with_body(&[0x41, 0xff, 0xff, 0xff, 0xff, 0x07, drop, end]), Reads, Accepts, &[]),
        case("i32.const of six bytes", with_body(&[0x41, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, drop, end]), Body(P::LebTooLong { bits: 32 }), Rejects, &[]),
        case("i32.const whose unused bits disagree with its sign", with_body(&[0x41, 0xff, 0xff, 0xff, 0xff, 0x0f, drop, end]), Body(P::LebTooBig { bits: 32 }), Rejects, &[]),
        case("i64.const at its widest", with_body(&[0x42, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f, drop, end]), Reads, Accepts, &[]),
        case("i64.const of eleven bytes", with_body(&[0x42, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, drop, end]), Body(P::LebTooLong { bits: 64 }), Rejects, &[]),
        // i32.trunc_sat_f32_s with its code padded: a prefixed opcode is a u32 LEB128.
        case("a padded 0xFC code", with_body(&[0x43, 0, 0, 0, 0, 0xfc, 0x80, 0x00, drop, end]), Reads, Accepts, &[]),
        // A padded section size.
        case("a padded section size", module(&[[vec![1, 0x84, 0x80, 0x80, 0x80, 0x00], vector(&[vec![0x60, 0, 0]])].concat(), functions(), code(&[0], &[end])]), Reads, Accepts, &[]),
        case("a section size of six bytes", module(&[[vec![1, 0x84, 0x80, 0x80, 0x80, 0x80, 0x00], vector(&[vec![0x60, 0, 0]])].concat()]), Refused(P::LebTooLong { bits: 32 }), Rejects, &[]),
        case("no magic", [b"\0asn".to_vec(), vec![1, 0, 0, 0]].concat(), Refused(P::Magic), Rejects, &[]),
        case("version 2", [b"\0asm".to_vec(), vec![2, 0, 0, 0]].concat(), Refused(P::Version(2)), Rejects, &[]),
        case("two type sections", module(&[types(), types()]), Refused(P::SectionOrder { id: 1, after: 1 }), Rejects, &[]),
        case("the function section before the type section", module(&[functions(), types()]), Refused(P::SectionOrder { id: 1, after: 3 }), Rejects, &[]),
        case(
            "the data count after the code",
            module(&[types(), functions(), memory(), code(&[0], &[end]), section(12, &[1]), passive_data()]),
            Refused(P::SectionOrder { id: 12, after: 10 }),
            Rejects,
            &[],
        ),
        case(
            "the data count between the elements and the code",
            module(&[types(), functions(), memory(), section(12, &[1]), code(&[0], &[0xfc, 0x09, 0x00, end]), passive_data()]),
            Reads,
            Accepts,
            &[],
        ),
        case(
            "a data count the data section does not match",
            module(&[types(), functions(), memory(), section(12, &[2]), code(&[0], &[end]), passive_data()]),
            Refused(P::DataCount { declared: 2, segments: 1 }),
            Rejects,
            &[],
        ),
        case(
            "data.drop and no data count",
            module(&[types(), functions(), memory(), code(&[0], &[0xfc, 0x09, 0x00, end]), passive_data()]),
            Body(P::DataIndexWithoutDataCount),
            Rejects,
            &[],
        ),
        case("a function and no code section", module(&[types(), functions()]), Refused(P::BodyCount { functions: 1, bodies: 0 }), Rejects, &[]),
        case(
            "two bodies for one function",
            module(&[types(), functions(), section(10, &vector(&[vec![2, 0, end], vec![2, 0, end]]))]),
            Refused(P::BodyCount { functions: 1, bodies: 2 }),
            Rejects,
            &[],
        ),
        case(
            "a section that ends past the file",
            module(&[[vec![1, 0x20], vector(&[vec![0x60, 0, 0]])].concat()]),
            Refused(P::End { needed: 32, available: 4 }),
            Rejects,
            &[],
        ),
        case(
            "a section with a byte its contents do not use",
            module(&[section(1, &[vector(&[vec![0x60, 0, 0]]), vec![0]].concat())]),
            Refused(P::SectionSize { id: 1, declared: 5, used: 4 }),
            Rejects,
            &[],
        ),
        case("section id 14", module(&[section(14, &[0])]), Refused(P::UnknownSection(14)), Rejects, &[]),
        case(
            "custom sections anywhere",
            module(&[custom(b"a", b""), types(), custom(b"b", b"xyz"), functions(), code(&[0], &[end]), custom(b"c", b"")]),
            Reads,
            Accepts,
            &[],
        ),
        case("a type count the section cannot hold", module(&[section(1, &[0xe8, 0x07, 0x60, 0, 0])]), Refused(P::CountTooLarge { count: 1000, available: 3 }), Rejects, &[]),
        case("else outside an if", with_body(&[0x05, end]), Body(P::ElseWithoutIf), Rejects, &[]),
        case("a second else", with_body(&[0x41, 0, 0x04, 0x40, 0x05, 0x05, end, end]), Body(P::ElseWithoutIf), Rejects, &[]),
        case("a byte after the final end", with_body(&[end, 0x01]), Body(P::BytesAfterEnd(1)), Rejects, &[]),
        case("a body with no end", with_body(&[0x01]), Body(P::NotEnded), Rejects, &[]),
        case("a block left open", with_body(&[0x02, 0x40, end]), Body(P::NotEnded), Rejects, &[]),
        case("a block type that is none of the three", with_body(&[0x02, 0x60, end, end]), Body(P::UnknownBlockType(0x60)), Rejects, &[]),
        case(
            "more than 2^32 - 1 locals",
            module(&[types(), functions(), code(&[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 0x01, 0x7f], &[end])]),
            Body(P::TooManyLocals),
            Rejects,
            &[],
        ),
        case("memory argument flags of 128", with_body_and_memory(&[0x41, 0, 0x28, 0x80, 0x01, 0x00, drop, end]), Body(P::MemArgFlags(128)), Rejects, &[MultiMemory]),
        case("a memory index in a memory argument", with_body_and_memory(&[0x41, 0, 0x28, 0x42, 0x00, 0x00, drop, end]), Reads, Accepts, &[MultiMemory]),
        // return_call 0 (tail calls).
        case("a tail call", with_body(&[0x12, 0x00, end]), Reads, Accepts, &[TailCall]),
        // i8x16.relaxed_swizzle, 0xFD 0x100.
        case(
            "relaxed SIMD",
            with_body(&[0xfd, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd, 0x80, 0x02, drop, end]),
            Reads,
            Accepts,
            &[RelaxedSimd],
        ),
        case("a shared memory", module(&[section(5, &vector(&[vec![0x03, 1, 1]]))]), Reads, Accepts, &[Threads]),
        case("a 64-bit memory", module(&[section(5, &vector(&[vec![0x05, 1, 2]]))]), Reads, Accepts, &[Memory64]),
        // The bounds of a 32-bit memory or table are u64 LEB128 in the current
        // binary format: padding past five bytes is well formed, and a bound
        // past 2^32 is a matter for validation.
        case("a 32-bit memory bound padded to six bytes", module(&[section(5, &vector(&[vec![0x00, 0x81, 0x80, 0x80, 0x80, 0x80, 0x00]]))]), Reads, Accepts, &[Memory64]),
        case("a 32-bit table bound padded to six bytes", module(&[section(4, &vector(&[vec![0x70, 0x00, 0x81, 0x80, 0x80, 0x80, 0x80, 0x00]]))]), Reads, Accepts, &[Memory64]),
        case("a 32-bit memory bound of 2^32 pages", module(&[section(5, &vector(&[vec![0x00, 0x80, 0x80, 0x80, 0x80, 0x10]]))]), Reads, RejectsByValidation, &[Memory64]),
        case("a memory bound of eleven bytes", module(&[section(5, &vector(&[vec![0x00, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]]))]), Refused(P::LebTooLong { bits: 64 }), Rejects, &[Memory64]),
        case(
            "an export name that is not UTF-8",
            module(&[types(), functions(), section(7, &vector(&[[name(&[0xff]), vec![0, 0]].concat()])), code(&[0], &[end])]),
            Refused(P::Utf8),
            Rejects,
            &[],
        ),
        case("element form 8", module(&[section(9, &vector(&[vec![8, 0, 0]]))]), Refused(P::UnknownElementForm(8)), Rejects, &[]),
        case("data form 3", module(&[memory(), section(11, &vector(&[vec![3, 0]]))]), Refused(P::UnknownDataForm(3)), Rejects, &[]),
        // A tag import (exception handling) of type 0.
        case("a tag import", module(&[types(), section(2, &vector(&[[name(b"m"), name(b"t"), vec![0x04, 0x00, 0x00]].concat()]))]), Reads, Accepts, &[Exceptions]),
        case(
            "a name section before the data section",
            module(&[types(), functions(), memory(), code(&[0], &[end]), names(&[(0, name(b"m"))]), passive_data()]),
            Name(NameProblem::BeforeStandardSection { id: 11 }),
            Accepts,
            &[],
        ),
        case(
            "two name sections",
            module(&[types(), functions(), code(&[0], &[end]), names(&[(0, name(b"m"))]), names(&[(0, name(b"n"))])]),
            Name(NameProblem::Repeated),
            Accepts,
            &[],
        ),
        case(
            "name subsections out of order",
            module(&[types(), functions(), code(&[0], &[end]), names(&[(1, function_names(b"f")), (0, name(b"m"))])]),
            Name(NameProblem::SubsectionOrder { id: 0, after: 1 }),
            Accepts,
            &[],
        ),
        case(
            "an unknown name subsection",
            module(&[types(), functions(), code(&[0], &[end]), names(&[(0, name(b"m")), (12, vec![0])])]),
            Name(NameProblem::SubsectionNotRead { id: 12 }),
            Accepts,
            &[],
        ),
        // Field names come with garbage collection, but a custom section's
        // contents never make a module invalid, so it needs no proposal.
        case("a field name subsection", module(&[types(), functions(), code(&[0], &[end]), names(&[(10, vec![0])])]), Reads, Accepts, &[]),
        // Function names for 1, then 0: the format lists indices in increasing order.
        case(
            "function names out of order",
            module(&[types(), section(3, &vector(&[vec![0], vec![0]])), code_n(2), names(&[(1, name_map(&[(1, b"b"), (0, b"a")]))])]),
            Name(NameProblem::IndexOrder { subsection: 1, within: None, index: 0 }),
            Accepts,
            &[],
        ),
        case(
            "a function named twice",
            module(&[types(), functions(), code(&[0], &[end]), names(&[(1, name_map(&[(0, b"a"), (0, b"b")]))])]),
            Name(NameProblem::IndexOrder { subsection: 1, within: None, index: 0 }),
            Accepts,
            &[],
        ),
        case(
            "local names out of order",
            module(&[types(), functions(), code(&[0], &[end]), names(&[(2, vector(&[[vec![0], name_map(&[(2, b"y"), (1, b"x")])].concat()]))])]),
            Name(NameProblem::IndexOrder { subsection: 2, within: Some(Within::Function(FuncIdx(0))), index: 1 }),
            Accepts,
            &[],
        ),
        // Field names of type 0 for field 1, then 0: the inner map is within a
        // type, not a function. A custom section's contents never make a
        // module invalid, so a field name for a function type is well formed.
        case(
            "field names out of order",
            module(&[types(), functions(), code(&[0], &[end]), names(&[(10, vector(&[[vec![0], name_map(&[(1, b"y"), (0, b"x")])].concat()]))])]),
            Name(NameProblem::IndexOrder { subsection: 10, within: Some(Within::Type(TypeIdx(0))), index: 0 }),
            Accepts,
            &[],
        ),
        // Function names `(0 "f")` and one byte more than they take. The name
        // subsection begins at offset 31 (8 of header, 6 types, 4 functions, 6
        // code, then the custom section's id, size and name, 7), its contents
        // at 33, and the byte they leave over at 37.
        case(
            "a name subsection with a byte its contents do not use",
            module(&[types(), functions(), code(&[0], &[end]), names(&[(1, [name_map(&[(0, b"f")]), vec![0]].concat())])]),
            Name(NameProblem::Subsection {
                id: 1,
                error: Error::Unreadable { offset: 37, problem: P::SubsectionSize { id: 1, declared: 5, used: 4 } },
            }),
            Accepts,
            &[],
        ),
        // Memories and tables: limits flags bit 1 is shared, for a memory only.
        case("a shared memory without a maximum", module(&[section(5, &vector(&[vec![0x02, 1]]))]), Reads, RejectsByValidation, &[Threads]),
        case("a shared 64-bit memory", module(&[section(5, &vector(&[vec![0x07, 1, 1]]))]), Reads, Accepts, &[Threads, Memory64]),
        // The threads rule: "only memories are permitted to be marked as
        // shared". wasm-tools, which implements shared-everything threads too,
        // reads a shared table and refuses it on another rule (its element
        // type `funcref` is not shared), so every validator rejects it.
        case("a shared table", module(&[section(4, &vector(&[vec![0x70, 0x03, 1, 1]]))]), Refused(P::UnknownLimitsFlags(3)), Rejects, &[Threads]),
        // Flags bit 3, then the minimum, then the page size's log2 (custom page sizes).
        case("a custom page size", module(&[section(5, &vector(&[vec![0x08, 1, 0x10]]))]), Refused(P::UnknownLimitsFlags(8)), AcceptsOutsideScope, &[CustomPageSizes]),
        // Threads.
        case("atomic.fence", with_body(&[0xfe, 0x03, 0x00, end]), Reads, Accepts, &[Threads]),
        case("atomic.fence with a non-zero byte", with_body(&[0xfe, 0x03, 0x01, end]), Body(P::ReservedByte(1)), Rejects, &[Threads]),
        case(
            "an opcode past the atomic ones",
            module(&[types(), functions(), section(5, &vector(&[vec![0x03, 1, 1]])), code(&[0], &[0xfe, 0x4f, end])]),
            Body(P::UnknownOpcode { prefix: Some(0xfe), code: 0x4f }),
            Rejects,
            &[Threads],
        ),
        // Legacy exception handling: `try bt in* (catch x in*)* (catch_all in*)? end`
        // and `try bt in* delegate l`.
        case("catch after catch_all", with_body_and_tag(&[0x06, 0x40, 0x19, 0x07, 0x00, end, end]), Body(P::CatchOutsideTry), Rejects, &[LegacyExceptions]),
        case("two catch_all", with_body_and_tag(&[0x06, 0x40, 0x19, 0x19, end, end]), Body(P::CatchOutsideTry), Rejects, &[LegacyExceptions]),
        case("catch outside a try", with_body_and_tag(&[0x07, 0x00, end]), Body(P::CatchOutsideTry), Rejects, &[LegacyExceptions]),
        case("catch_all in a block", with_body_and_tag(&[0x02, 0x40, 0x19, end, end]), Body(P::CatchOutsideTry), Rejects, &[LegacyExceptions]),
        case("delegate after a catch", with_body_and_tag(&[0x06, 0x40, 0x07, 0x00, 0x18, 0x00, end]), Body(P::DelegateOutsideTry), Rejects, &[LegacyExceptions]),
        case("delegate closing a try", with_body_and_tag(&[0x06, 0x40, 0x18, 0x00, end]), Reads, Accepts, &[LegacyExceptions]),
        case("delegate outside a try", with_body_and_tag(&[0x02, 0x40, 0x18, 0x00, end]), Body(P::DelegateOutsideTry), Rejects, &[LegacyExceptions]),
        case("a try with no handler", with_body_and_tag(&[0x06, 0x40, end, end]), Reads, Accepts, &[LegacyExceptions]),
        // try_table: a block type, then a vector of clauses of kinds 0 to 3.
        case(
            "a try_table catch kind of 4",
            with_body_and_tag(&[0x02, 0x40, 0x1f, 0x40, 0x01, 0x04, 0x00, end, end, end]),
            Body(P::UnknownCatchKind(4)),
            Rejects,
            &[Exceptions],
        ),
        case("a try_table with no clause", with_body_and_tag(&[0x1f, 0x40, 0x00, end, end]), Reads, Accepts, &[Exceptions]),
        // The tag section, between the memory and global sections.
        case("a tag attribute of 1", module(&[types(), section(13, &vector(&[vec![0x01, 0x00]]))]), Refused(P::UnknownTagAttribute(1)), Rejects, &[Exceptions]),
        case(
            "the tag section after the global section",
            module(&[types(), section(6, &vector(&[vec![0x7f, 0x00, 0x41, 0x00, end]])), tag_section()]),
            Refused(P::SectionOrder { id: 13, after: 6 }),
            Rejects,
            &[Exceptions],
        ),
        case("the tag section before the memory section", module(&[types(), tag_section(), memory()]), Refused(P::SectionOrder { id: 5, after: 13 }), Rejects, &[Exceptions]),
        case("a tag export", module(&[types(), tag_section(), section(7, &vector(&[[name(b"t"), vec![0x04, 0x00]].concat()]))]), Reads, Accepts, &[Exceptions]),
        // A table entry `0x40 0x00 tabletype expr`: an initial value for every element.
        case("a table with an initial value", module(&[section(4, &vector(&[vec![0x40, 0x00, 0x70, 0x00, 0x01, 0xd0, 0x70, end]]))]), Reads, Accepts, &[FunctionReferences]),
        case(
            "a table initializer's reserved byte of 1",
            module(&[section(4, &vector(&[vec![0x40, 0x01, 0x70, 0x00, 0x01, 0xd0, 0x70, end]]))]),
            Refused(P::ReservedByte(1)),
            Rejects,
            &[FunctionReferences],
        ),
        // The type section: recursion groups of subtypes of composite types.
        case("an empty recursion group", one_type(&[0x4e, 0x00]), Reads, Accepts, &[Gc]),
        case("a recursion group inside one", one_type(&[0x4e, 0x01, 0x4e, 0x00]), Refused(P::UnknownTypeForm(0x4e)), Rejects, &[Gc]),
        case("packed fields", one_type(&[0x5f, 0x02, 0x78, 0x00, 0x77, 0x01]), Reads, Accepts, &[Gc]),
        case("a field mutability of 2", one_type(&[0x5f, 0x01, 0x7f, 0x02]), Refused(P::UnknownMutability(2)), Rejects, &[Gc]),
        case("a non-final type with no supertype", one_type(&[0x50, 0x00, 0x5f, 0x00]), Reads, Accepts, &[Gc]),
        case("a final subtype with no supertype", one_type(&[0x4f, 0x00, 0x5f, 0x00]), Reads, Accepts, &[Gc]),
        case("an array of i8", one_type(&[0x5e, 0x78, 0x01]), Reads, Accepts, &[Gc]),
        // Heap types: an abstract one's byte, or a type index as a non-negative s33.
        case("a heap type byte of 0x40", one_type(&[0x60, 0x01, 0x64, 0x40, 0x00]), Refused(P::UnknownHeapType(0x40)), Rejects, &[FunctionReferences]),
        case("a shared heap type", one_type(&[0x60, 0x01, 0x63, 0x65, 0x70, 0x00]), Refused(P::UnknownHeapType(0x65)), AcceptsOutsideScope, &[SharedEverythingThreads]),
        case("a reference to a type past the type section", one_type(&[0x60, 0x01, 0x63, 0x05, 0x00]), Reads, RejectsByValidation, &[FunctionReferences]),
        // GC instructions, over types 0 (struct), 1 () -> () and 2 (array (mut i8)).
        // block, ref.null any, br_on_cast with flags 4, drop.
        case(
            "br_on_cast flags of 4",
            with_gc_body(&[0x02, 0x40, 0xd0, 0x6e, 0xfb, 0x18, 0x04, 0x00, 0x6e, 0x6e, drop, end, end]),
            Body(P::CastFlags(4)),
            Rejects,
            &[Gc],
        ),
        // block (result anyref), ref.null any, br_on_cast 0 anyref anyref, end, drop.
        case(
            "br_on_cast with both nullable",
            with_gc_body(&[0x02, 0x6e, 0xd0, 0x6e, 0xfb, 0x18, 0x03, 0x00, 0x6e, 0x6e, end, drop, end]),
            Reads,
            Accepts,
            &[Gc],
        ),
        // array.new_data 2 0 over a passive data segment.
        case(
            "array.new_data and no data count",
            module(&[gc_types(), gc_functions(), memory(), code(&[0], &[0x41, 0x00, 0x41, 0x00, 0xfb, 0x09, 0x02, 0x00, drop, end]), passive_data()]),
            Body(P::DataIndexWithoutDataCount),
            Rejects,
            &[Gc],
        ),
        case(
            "array.new_data and a data count",
            module(&[gc_types(), gc_functions(), memory(), section(12, &[1]), code(&[0], &[0x41, 0x00, 0x41, 0x00, 0xfb, 0x09, 0x02, 0x00, drop, end]), passive_data()]),
            Reads,
            Accepts,
            &[Gc],
        ),
        case("a GC opcode past the table", with_gc_body(&[0xfb, 0x1f, end]), Body(P::UnknownOpcode { prefix: Some(0xfb), code: 31 }), Rejects, &[Gc]),
        // 0xFD 0x114, a relaxed SIMD opcode the proposal dropped before 3.0.
        case("a relaxed SIMD opcode that was dropped", with_body(&[0xfd, 0x94, 0x02, end]), Body(P::UnknownOpcode { prefix: Some(0xfd), code: 0x114 }), Rejects, &[RelaxedSimd]),
        // i64.add128 (wide arithmetic), 0xFC 0x13, of type (i64 i64 i64 i64) -> (i64 i64).
        case(
            "wide arithmetic",
            module(&[
                section(1, &vector(&[vec![0x60, 0x04, 0x7e, 0x7e, 0x7e, 0x7e, 0x02, 0x7e, 0x7e]])),
                functions(),
                code(&[0], &[0x20, 0x00, 0x20, 0x01, 0x20, 0x02, 0x20, 0x03, 0xfc, 0x13, end]),
            ]),
            Body(P::UnknownOpcode { prefix: Some(0xfc), code: 0x13 }),
            AcceptsOutsideScope,
            &[WideArithmetic],
        ),
        case(
            "tag names",
            module(&[types(), functions(), tag_section(), code(&[0], &[end]), names(&[(11, name_map(&[(0, b"t")]))])]),
            Reads,
            Accepts,
            &[Exceptions],
        ),
    ]
}
