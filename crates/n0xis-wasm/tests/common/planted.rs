// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Modules planted byte by byte, each breaking one structural rule of the
//! binary format (or none), with the answer stated before the reader runs.
//! `tests/structure.rs` checks the reader's typed answer; the oracle test asks
//! wasm-tools and wabt whether they accept the same bytes.

use n0xis_wasm::{NameProblem, Problem};

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
}

pub struct Case {
    pub name: &'static str,
    pub bytes: Vec<u8>,
    pub expect: Expect,
    pub tool: Tool,
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
    use Tool::*;
    let case = |name, bytes, expect, tool| Case { name, bytes, expect, tool };
    let end = 0x0b;
    let drop = 0x1a;
    vec![
        case("minimal", with_body(&[end]), Reads, Accepts),
        // i32.const 2147483647, padded to the full five bytes it may take.
        case("i32.const at its widest", with_body(&[0x41, 0xff, 0xff, 0xff, 0xff, 0x07, drop, end]), Reads, Accepts),
        case("i32.const of six bytes", with_body(&[0x41, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, drop, end]), Body(P::LebTooLong { bits: 32 }), Rejects),
        case("i32.const whose unused bits disagree with its sign", with_body(&[0x41, 0xff, 0xff, 0xff, 0xff, 0x0f, drop, end]), Body(P::LebTooBig { bits: 32 }), Rejects),
        case("i64.const at its widest", with_body(&[0x42, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f, drop, end]), Reads, Accepts),
        case("i64.const of eleven bytes", with_body(&[0x42, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, drop, end]), Body(P::LebTooLong { bits: 64 }), Rejects),
        // i32.trunc_sat_f32_s with its code padded: a prefixed opcode is a u32 LEB128.
        case("a padded 0xFC code", with_body(&[0x43, 0, 0, 0, 0, 0xfc, 0x80, 0x00, drop, end]), Reads, Accepts),
        // A padded section size.
        case("a padded section size", module(&[[vec![1, 0x84, 0x80, 0x80, 0x80, 0x00], vector(&[vec![0x60, 0, 0]])].concat(), functions(), code(&[0], &[end])]), Reads, Accepts),
        case("a section size of six bytes", module(&[[vec![1, 0x84, 0x80, 0x80, 0x80, 0x80, 0x00], vector(&[vec![0x60, 0, 0]])].concat()]), Refused(P::LebTooLong { bits: 32 }), Rejects),
        case("no magic", [b"\0asn".to_vec(), vec![1, 0, 0, 0]].concat(), Refused(P::Magic), Rejects),
        case("version 2", [b"\0asm".to_vec(), vec![2, 0, 0, 0]].concat(), Refused(P::Version(2)), Rejects),
        case("two type sections", module(&[types(), types()]), Refused(P::SectionOrder { id: 1, after: 1 }), Rejects),
        case("the function section before the type section", module(&[functions(), types()]), Refused(P::SectionOrder { id: 1, after: 3 }), Rejects),
        case(
            "the data count after the code",
            module(&[types(), functions(), memory(), code(&[0], &[end]), section(12, &[1]), passive_data()]),
            Refused(P::SectionOrder { id: 12, after: 10 }),
            Rejects,
        ),
        case(
            "the data count between the elements and the code",
            module(&[types(), functions(), memory(), section(12, &[1]), code(&[0], &[0xfc, 0x09, 0x00, end]), passive_data()]),
            Reads,
            Accepts,
        ),
        case(
            "a data count the data section does not match",
            module(&[types(), functions(), memory(), section(12, &[2]), code(&[0], &[end]), passive_data()]),
            Refused(P::DataCount { declared: 2, segments: 1 }),
            Rejects,
        ),
        case(
            "data.drop and no data count",
            module(&[types(), functions(), memory(), code(&[0], &[0xfc, 0x09, 0x00, end]), passive_data()]),
            Body(P::DataIndexWithoutDataCount),
            Rejects,
        ),
        case("a function and no code section", module(&[types(), functions()]), Refused(P::BodyCount { functions: 1, bodies: 0 }), Rejects),
        case(
            "two bodies for one function",
            module(&[types(), functions(), section(10, &vector(&[vec![2, 0, end], vec![2, 0, end]]))]),
            Refused(P::BodyCount { functions: 1, bodies: 2 }),
            Rejects,
        ),
        case(
            "a section that ends past the file",
            module(&[[vec![1, 0x20], vector(&[vec![0x60, 0, 0]])].concat()]),
            Refused(P::End { needed: 32, available: 4 }),
            Rejects,
        ),
        case(
            "a section with a byte its contents do not use",
            module(&[section(1, &[vector(&[vec![0x60, 0, 0]]), vec![0]].concat())]),
            Refused(P::SectionSize { id: 1, declared: 5, used: 4 }),
            Rejects,
        ),
        case("section id 14", module(&[section(14, &[0])]), Refused(P::UnknownSection(14)), Rejects),
        case(
            "custom sections anywhere",
            module(&[custom(b"a", b""), types(), custom(b"b", b"xyz"), functions(), code(&[0], &[end]), custom(b"c", b"")]),
            Reads,
            Accepts,
        ),
        case("a type count the section cannot hold", module(&[section(1, &[0xe8, 0x07, 0x60, 0, 0])]), Refused(P::CountTooLarge { count: 1000, available: 3 }), Rejects),
        case("else outside an if", with_body(&[0x05, end]), Body(P::ElseWithoutIf), Rejects),
        case("a second else", with_body(&[0x41, 0, 0x04, 0x40, 0x05, 0x05, end, end]), Body(P::ElseWithoutIf), Rejects),
        case("a byte after the final end", with_body(&[end, 0x01]), Body(P::BytesAfterEnd(1)), Rejects),
        case("a body with no end", with_body(&[0x01]), Body(P::NotEnded), Rejects),
        case("a block left open", with_body(&[0x02, 0x40, end]), Body(P::NotEnded), Rejects),
        case("a block type that is none of the three", with_body(&[0x02, 0x60, end, end]), Body(P::UnknownBlockType(0x60)), Rejects),
        case(
            "more than 2^32 - 1 locals",
            module(&[types(), functions(), code(&[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 0x01, 0x7f], &[end])]),
            Body(P::TooManyLocals),
            Rejects,
        ),
        case("memory argument flags of 128", with_body_and_memory(&[0x41, 0, 0x28, 0x80, 0x01, 0x00, drop, end]), Body(P::MemArgFlags(128)), Rejects),
        case("a memory index in a memory argument", with_body_and_memory(&[0x41, 0, 0x28, 0x42, 0x00, 0x00, drop, end]), Reads, Accepts),
        // return_call 0: tail calls are not read here.
        case("a tail call", with_body(&[0x12, 0x00, end]), Body(P::UnknownOpcode { prefix: None, code: 0x12 }), AcceptsOutsideScope),
        // i8x16.relaxed_swizzle, 0xFD 0x100: relaxed SIMD is not read here.
        case(
            "relaxed SIMD",
            with_body(&[0xfd, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd, 0x80, 0x02, drop, end]),
            Body(P::UnknownOpcode { prefix: Some(0xfd), code: 0x100 }),
            AcceptsOutsideScope,
        ),
        case("a shared memory", module(&[section(5, &vector(&[vec![0x03, 1, 1]]))]), Refused(P::UnknownLimitsFlags(3)), AcceptsOutsideScope),
        case("a 64-bit memory", module(&[section(5, &vector(&[vec![0x05, 1, 2]]))]), Reads, Accepts),
        case(
            "an export name that is not UTF-8",
            module(&[types(), functions(), section(7, &vector(&[[name(&[0xff]), vec![0, 0]].concat()])), code(&[0], &[end])]),
            Refused(P::Utf8),
            Rejects,
        ),
        case("element form 8", module(&[section(9, &vector(&[vec![8, 0, 0]]))]), Refused(P::UnknownElementForm(8)), Rejects),
        case("data form 3", module(&[memory(), section(11, &vector(&[vec![3, 0]]))]), Refused(P::UnknownDataForm(3)), Rejects),
        // A tag import (exception handling) of type 0.
        case("a tag import", module(&[types(), section(2, &vector(&[[name(b"m"), name(b"t"), vec![0x04, 0x00, 0x00]].concat()]))]), Refused(P::UnknownImportKind(4)), AcceptsOutsideScope),
        case(
            "a name section before the data section",
            module(&[types(), functions(), memory(), code(&[0], &[end]), names(&[(0, name(b"m"))]), passive_data()]),
            Name(NameProblem::BeforeStandardSection { id: 11 }),
            Accepts,
        ),
        case(
            "two name sections",
            module(&[types(), functions(), code(&[0], &[end]), names(&[(0, name(b"m"))]), names(&[(0, name(b"n"))])]),
            Name(NameProblem::Repeated),
            Accepts,
        ),
        case(
            "name subsections out of order",
            module(&[types(), functions(), code(&[0], &[end]), names(&[(1, function_names(b"f")), (0, name(b"m"))])]),
            Name(NameProblem::SubsectionOrder { id: 0, after: 1 }),
            Accepts,
        ),
        case(
            "an unknown name subsection",
            module(&[types(), functions(), code(&[0], &[end]), names(&[(0, name(b"m")), (12, vec![0])])]),
            Name(NameProblem::SubsectionNotRead { id: 12 }),
            Accepts,
        ),
        case(
            "a field name subsection",
            module(&[types(), functions(), code(&[0], &[end]), names(&[(10, vec![0])])]),
            Name(NameProblem::SubsectionNotRead { id: 10 }),
            Accepts,
        ),
        // Function names for 1, then 0: the format lists indices in increasing order.
        case(
            "function names out of order",
            module(&[types(), section(3, &vector(&[vec![0], vec![0]])), code_n(2), names(&[(1, name_map(&[(1, b"b"), (0, b"a")]))])]),
            Name(NameProblem::IndexOrder { subsection: 1, within: None, index: 0 }),
            Accepts,
        ),
        case(
            "a function named twice",
            module(&[types(), functions(), code(&[0], &[end]), names(&[(1, name_map(&[(0, b"a"), (0, b"b")]))])]),
            Name(NameProblem::IndexOrder { subsection: 1, within: None, index: 0 }),
            Accepts,
        ),
        case(
            "local names out of order",
            module(&[types(), functions(), code(&[0], &[end]), names(&[(2, vector(&[[vec![0], name_map(&[(2, b"y"), (1, b"x")])].concat()]))])]),
            Name(NameProblem::IndexOrder { subsection: 2, within: Some(0), index: 1 }),
            Accepts,
        ),
    ]
}
