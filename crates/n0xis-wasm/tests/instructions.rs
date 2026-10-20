// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The decoder gives back every instruction the text states.** The `.wat`
//! fixtures are written one instruction per line in this crate's canonical
//! spelling (`src/instr.rs`), and `wasm-tools parse`, not this crate, turned
//! them into bytes. Decoding those bytes must give the same lines, in the same
//! order, function by function: a wrong opcode number, a wrong name or a wrong
//! immediate width each show up as a mismatched line (a width desynchronises
//! every line after it).
//!
//! And **no opcode of the decoder's table goes unexercised**: every entry of
//! [`OPCODES`] must be decoded from some text fixture, so the coverage the
//! first test speaks for cannot shrink unnoticed. Only the text fixtures count:
//! a compiled one could keep an opcode "covered" whose decoding no statement
//! independent of the decoder checks (its bytes are compared with the tools'
//! recordings, but not with a text that states them).
//!
//! And **every immediate of two values a reader could exchange is stated
//! with two different values**: an exchange of equal values changes no line,
//! so without that the first test cannot see it.
//!
//! And **each compiled fixture holds what its source and build flags state**:
//! its imports, its functions, its exports, read from the C or C++ text and
//! the flags in `build.sh`, never from the module. What neither states is
//! printed as not compared.

mod common;

use std::collections::BTreeSet;

use n0xis_wasm::{Instr, OPCODES, Opcode};

/// The instruction lines of each function of a `.wat` fixture, in order: the
/// lines between a `  (func` header and its closing `  )`.
fn stated_bodies(wat: &str) -> Vec<Vec<String>> {
    let mut bodies = Vec::new();
    let mut current: Option<Vec<String>> = None;
    for line in wat.lines() {
        if line.starts_with("  (func") {
            assert!(current.is_none(), "a function header inside a function: {line}");
            current = Some(Vec::new());
        } else if line == "  )" {
            bodies.push(current.take().expect("a closing line outside a function"));
        } else if let Some(body) = current.as_mut() {
            let instr = line.trim();
            if !instr.is_empty() && !instr.starts_with(";;") {
                body.push(without_label_name(instr));
            }
        }
    }
    assert!(current.is_none(), "an unclosed function");
    bodies
}

/// `block $outer (type 0)` is `block (type 0)` with a label name, which the
/// text format sends to the name section, not to the instruction.
fn without_label_name(line: &str) -> String {
    let mut words: Vec<&str> = line.split(' ').collect();
    if ["block", "loop", "if"].contains(&words[0]) && words.get(1).is_some_and(|w| w.starts_with('$')) {
        words.remove(1);
    }
    words.join(" ")
}

#[test]
fn every_instruction_the_text_states_decodes_as_stated() {
    let mut compared = 0;
    for stem in common::TEXT_FIXTURES {
        let before = compared;
        let stated = stated_bodies(&common::text(&format!("{stem}.wat")));
        let m = common::module(stem);
        assert!(m.findings().is_empty(), "{stem}: {:?}", m.findings());
        let decoded = common::bodies(&m);
        assert_eq!(decoded.len(), stated.len(), "{stem}: functions");
        for ((func, body), stated) in decoded.iter().zip(&stated) {
            // The text leaves the final `end` implicit; the body ends with it.
            let (last, rest) = body.instructions.split_last().expect("a body is never empty");
            assert_eq!(last.instr, Instr::End, "{stem} func {}: the final instruction", func.0);
            assert_eq!(last.offset, body.range.end - 1, "{stem} func {}: the final `end` is the last byte", func.0);
            let rendered: Vec<String> = rest.iter().map(|l| l.instr.to_string()).collect();
            for (i, (got, want)) in rendered.iter().zip(stated).enumerate() {
                assert_eq!(got, want, "{stem} func {} instruction {i} at {:#x}", func.0, rest[i].offset);
            }
            assert_eq!(rendered.len(), stated.len(), "{stem} func {}: instruction count", func.0);
            compared += rendered.len();
        }
        eprintln!("{stem}: {} instructions in {} functions", compared - before, stated.len());
    }
    eprintln!("{compared} instructions decoded as the text states them");
    // The nine fixtures hold core 766 + simd 854 + shapes 66 + threads 361 +
    // refs 74 + gc 471 + eh 109 + eh-legacy 149 + relaxed 97 = 2947
    // instruction lines, counted with awk over the body lines (every line
    // between `  (func` and `  )` that is neither empty nor a `;;` comment;
    // re-counted 2026-10-20 after refs gained its asymmetric `table.copy`, 4
    // lines, and gc its `array.copy` between two types, 8): a parse of the
    // text that found none, or stopped early, would otherwise pass.
    assert_eq!(compared, 2947);
}

#[test]
fn every_opcode_of_the_table_is_in_a_fixture() {
    let table: BTreeSet<(Option<u8>, u32)> = OPCODES.iter().map(|o| (o.prefix, o.code)).collect();
    assert_eq!(table.len(), OPCODES.len(), "an opcode listed twice");
    let mut seen: BTreeSet<(Option<u8>, u32)> = BTreeSet::new();
    // The text fixtures only, whose every instruction the first test checks
    // against the line that states it.
    for stem in common::TEXT_FIXTURES {
        for (_, body) in common::bodies(&common::module(stem)) {
            for l in &body.instructions {
                let Opcode { prefix, code, .. } = l.instr.opcode();
                seen.insert((prefix, code));
            }
        }
    }
    let missing: Vec<String> = OPCODES
        .iter()
        .filter(|o| !seen.contains(&(o.prefix, o.code)))
        .map(|o| format!("{} ({:?} {:#x})", o.name, o.prefix, o.code))
        .collect();
    assert!(missing.is_empty(), "{} opcodes in no text fixture: {}", missing.len(), missing.join(", "));
    // The counts of the opcode tables this crate reads, each from the
    // document that defines its opcodes, counted 2026-10-20 over the
    // documents themselves:
    // - the WebAssembly 3.0 core specification, appendix "Index of
    //   Instructions" (https://webassembly.github.io/spec/core/appendix/
    //   index-instructions.html, titled "Index of Instructions - WebAssembly
    //   3.0 (2026-10-13)"): 194 one-byte rows that are not "(reserved)", 31
    //   under 0xFB (0 to 30), 18 under 0xFC (0 to 17, as in 2.0) and 256 under
    //   0xFD (2.0's 236 and relaxed SIMD's 20, 0x100 to 0x113);
    // - the legacy exception handling document (WebAssembly/exception-handling,
    //   proposals/exception-handling/legacy/Exceptions.md, last changed in
    //   commit e7c7c31, 2024-11-21), its "Control flow operators" table: five
    //   one-byte opcodes the 3.0 index lists as "(reserved)", `try` 0x06,
    //   `catch` 0x07, `rethrow` 0x09, `delegate` 0x18, `catch_all` 0x19 (its
    //   sixth, `throw` 0x08, is 3.0's own), so one-byte is 194 + 5 = 199;
    // - the threads proposal's overview (WebAssembly/threads,
    //   proposals/threads/Overview.md, last changed in commit f521d7b,
    //   2026-02-10), "The instruction binary format is modified as follows":
    //   67 rows under 0xFE (0x00 to 0x03 and 0x10 to 0x4E).
    let count = |p: Option<u8>| OPCODES.iter().filter(|o| o.prefix == p).count();
    let counts = [None, Some(0xfb), Some(0xfc), Some(0xfd), Some(0xfe)].map(count);
    assert_eq!(counts, [199, 31, 18, 256, 67], "opcodes: one-byte, 0xFB, 0xFC, 0xFD, 0xFE");
    eprintln!("{} of {} opcodes exercised", seen.len(), OPCODES.len());
}

/// The immediates of the decoder's table that hold two values a reader could
/// exchange and still read a valid-looking instruction: two indices of one
/// kind (`table.copy`'s destination and source), and two of different kinds
/// read in a fixed order (`call_indirect`'s type, then its table). `TryTable`
/// is the tag and label of each `catch`/`catch_ref` clause, `CastBranch`
/// `br_on_cast`'s source and target types: neither was in the specification's
/// list, both are of the class.
const PAIRED_IMMEDIATES: [&str; 12] = [
    "TablePair",
    "MemoryPair",
    "ArrayPair",
    "IndirectCall",
    "ElemToTable",
    "DataToMemory",
    "ArrayData",
    "ArrayElem",
    "FieldRef",
    "FixedArray",
    "TryTable",
    "CastBranch",
];

/// The opcodes whose immediate is one of [`PAIRED_IMMEDIATES`], by text name,
/// read from the rows of the decoder's table in `src/instr.rs`
/// (`0x0e => TableCopy(TablePair) = "table.copy";`). The table is the one
/// place the immediate of each opcode is stated, so an opcode added with one of
/// these immediates is demanded here without anyone listing it; and an entry
/// of [`PAIRED_IMMEDIATES`] that no row carries fails, as a stale one.
fn paired_opcodes() -> Vec<(&'static str, String)> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/instr.rs");
    let table = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut out = Vec::new();
    for row in table.lines().filter_map(|l| l.trim().split_once(" => ")) {
        let Some((variant, name)) = row.1.split_once(" = \"") else { continue };
        let Some(immediate) = variant.split_once('(').and_then(|(_, i)| i.strip_suffix(')')) else { continue };
        if let Some(&known) = PAIRED_IMMEDIATES.iter().find(|p| **p == immediate) {
            out.push((known, name.strip_suffix("\";").expect("a row ends in `\";`").to_string()));
        }
    }
    for immediate in PAIRED_IMMEDIATES {
        assert!(out.iter().any(|(i, _)| *i == immediate), "{immediate}: no row of the table carries it");
    }
    out
}

/// The pairs of one instruction whose immediate is paired, rendered, in
/// binary order; `None` for an instruction of no such immediate.
fn paired_values(instr: &Instr) -> Option<Vec<(String, String)>> {
    use n0xis_wasm::Catch;
    let pair = |a: &dyn std::fmt::Display, b: &dyn std::fmt::Display| vec![(a.to_string(), b.to_string())];
    Some(match instr {
        Instr::TableCopy(p) => pair(&p.dst, &p.src),
        Instr::MemoryCopy(p) => pair(&p.dst, &p.src),
        Instr::ArrayCopy(p) => pair(&p.dst, &p.src),
        Instr::CallIndirect(c) | Instr::ReturnCallIndirect(c) => pair(&c.ty, &c.table),
        Instr::TableInit(e) => pair(&e.elem, &e.table),
        Instr::MemoryInit(d) => pair(&d.data, &d.memory),
        Instr::ArrayNewData(a) | Instr::ArrayInitData(a) => pair(&a.ty, &a.data),
        Instr::ArrayNewElem(a) | Instr::ArrayInitElem(a) => pair(&a.ty, &a.elem),
        Instr::StructGet(f) | Instr::StructGetS(f) | Instr::StructGetU(f) | Instr::StructSet(f) => pair(&f.ty, &f.field),
        Instr::ArrayNewFixed(f) => pair(&f.ty, &f.len),
        Instr::TryTable(t) => t
            .catches
            .iter()
            .filter_map(|c| match c {
                Catch::Catch { tag, label } | Catch::CatchRef { tag, label } => Some((tag.to_string(), label.to_string())),
                Catch::CatchAll { .. } | Catch::CatchAllRef { .. } => None,
            })
            .collect(),
        Instr::BrOnCast(c) | Instr::BrOnCastFail(c) => pair(&c.from, &c.to),
        _ => return None,
    })
}

/// **A reader that exchanges the two values of an immediate is caught.** The
/// first test compares every decoded line with the text, but an exchange of
/// two equal values changes no line: a reader that read `table.copy`'s source
/// as its destination passed every test while the fixtures held only
/// `table.copy 0 0` and `table.copy 1 1`. So for every opcode of a paired
/// immediate, some text fixture must state an instance whose two values
/// differ; this fails naming each opcode that has none.
///
/// Known and not fixed: for `TryTable` one differing clause of one kind
/// (`catch` or `catch_ref`) stands for both kinds; `CastBranch`'s label is not
/// paired with anything; and the immediates of three or more values
/// (`br_table`'s targets, a memory argument's memory, offset and alignment, a
/// lane access's memory argument and lane) are outside this check.
#[test]
fn every_paired_immediate_is_stated_with_two_different_values() {
    let opcodes = paired_opcodes();
    // 19 rows: grep -cE '\((TablePair|MemoryPair|ArrayPair|IndirectCall|
    // ElemToTable|DataToMemory|ArrayData|ArrayElem|FieldRef|FixedArray|
    // TryTable|CastBranch)\) = ' src/instr.rs, 2026-10-20.
    assert_eq!(opcodes.len(), 19, "opcodes of a paired immediate: {opcodes:?}");
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut differing: BTreeSet<&str> = BTreeSet::new();
    for stem in common::TEXT_FIXTURES {
        for (_, body) in common::bodies(&common::module(stem)) {
            for l in &body.instructions {
                let name = l.instr.name();
                if !opcodes.iter().any(|(_, n)| n == name) {
                    continue;
                }
                let pairs = paired_values(&l.instr).unwrap_or_else(|| panic!("{name}: this test does not read its pair"));
                seen.insert(name);
                if pairs.iter().any(|(a, b)| a != b) {
                    differing.insert(name);
                }
            }
        }
    }
    let missing: Vec<String> = opcodes
        .iter()
        .filter(|(_, name)| !differing.contains(name.as_str()))
        .map(|(immediate, name)| {
            let why = if seen.contains(name.as_str()) { "only with two equal values" } else { "in no text fixture" };
            format!("{name} ({immediate}): {why}")
        })
        .collect();
    assert!(missing.is_empty(), "opcodes whose two values no text fixture tells apart:\n{}", missing.join("\n"));
    eprintln!("{} opcodes of a paired immediate, each stated with two different values", opcodes.len());
}

/// What the C source states, read back: its two imports with their types, its
/// functions by name, and its globals among the exports.
#[test]
fn the_c_fixture_holds_what_its_source_declares() {
    use n0xis_wasm::{FuncOrigin, ImportItem, ValType};
    let source = common::text("ctarget.c");
    for stem in ["ctarget-O0", "ctarget-O2"] {
        let m = common::module(stem);
        assert!(m.findings().is_empty(), "{stem}: {:?}", m.findings());
        let imports: Vec<(&str, &str)> = m.imports().iter().map(|i| (i.module.as_str(), i.name.as_str())).collect();
        assert_eq!(imports, [("host", "report"), ("host", "scale")], "{stem}");
        let ty = |i: usize| match m.imports()[i].item {
            ImportItem::Func(t) => m.func_type(t).unwrap_or_else(|| panic!("{stem}: type {t} is not a function type")),
            other => panic!("{stem}: import {i} is {other:?}"),
        };
        assert_eq!((ty(0).params.as_slice(), ty(0).results.as_slice()), (&[ValType::I32, ValType::I64][..], &[][..]));
        assert_eq!((ty(1).params.as_slice(), ty(1).results.as_slice()), (&[ValType::F64][..], &[ValType::F64][..]));
        // Imports come first in the function index space.
        assert_eq!(m.imported_functions(), 2, "{stem}");
        assert!(matches!(m.functions()[0].origin, FuncOrigin::Imported { import: 0 }));
        assert!(matches!(m.functions()[2].origin, FuncOrigin::Defined { body: 0 }));
        // Every function the source defines, by the shape of its definition
        // line: defined, named by the name section and exported under that
        // name. (Being among the name section's names alone let a name given
        // to the wrong function pass.)
        let stated = source_definitions(&source, &[], &["i32", "i64", "void", "double"]);
        assert_eq!(stated.len(), 23, "{stem}: definitions found in the source");
        defined_named_and_exported(&m, stem, &stated);
        let exported: BTreeSet<&str> = m.exports().iter().map(|e| e.name.as_str()).collect();
        for global in ["counter", "big_total", "accumulated", "pool", "operations"] {
            assert!(exported.contains(global), "{stem}: {global} is not exported");
        }
    }
}

/// The functions a C or C++ fixture defines, found by the shape of definition
/// line its header comment states: at the top level (outside every brace and
/// every parenthesis), the words of `prefix`, one of `types`, then the name,
/// before the first `(`.
///
/// The shape is a promise the source makes, so it is checked, not trusted.
/// Every top-level line that could begin a definition is a candidate: one
/// that contains a name followed by `(` and does not end in `;` (a
/// declaration ends in `;` and is not one), and, as before, one that contains
/// `(` and ends in `{` or `}`. A candidate the promised shape does not match
/// fails, naming the line, so a definition of another shape is never skipped
/// silently: neither one whose `{` is on the next line nor one whose
/// parameters span lines (the lines after the first are inside its
/// parenthesis, so not top-level). `//` comments are not code (the header
/// comment itself writes the shape); a `/*` comment, which this scan does not
/// read, fails too.
///
/// Known and not fixed: a declaration whose parameters span lines has a first
/// line that does not end in `;`, so it is a candidate; of the promised shape
/// it is counted as a definition (and then fails the export check, which
/// finds no such function), of another it fails here. Neither is silent; no
/// fixture's source has one. A string or character literal that holds a brace
/// or a parenthesis would unbalance the count; none does. Two layouts are
/// skipped silently, both outside the one definition per line that the
/// headers of `cthreads.c` and `ceh.cpp` promise (`ctarget.c`'s header states
/// no shape; it is scanned by the same rule): two definitions on one line,
/// of which only the first is found, since the line is read once, from its
/// start; and a definition whose first line opens the body and ends in `;`
/// (`u32 one(void) { return 1;`, the `}` on a later line), which ends in
/// neither `{` nor `}` and is taken for a declaration.
fn source_definitions<'a>(source: &'a str, prefix: &[&str], types: &[&str]) -> Vec<&'a str> {
    let (mut braces, mut parens) = (0usize, 0usize);
    let mut found = Vec::new();
    for (number, line) in source.lines().enumerate() {
        assert!(!line.contains("/*"), "line {}: a block comment, which this scan does not read: {line}", number + 1);
        let code = line.split_once("//").map_or(line, |(code, _)| code).trim_end();
        let top_level = braces == 0 && parens == 0;
        for c in code.chars() {
            let unopened = || panic!("line {}: an unopened `{c}`", number + 1);
            match c {
                '{' => braces += 1,
                '}' => braces = braces.checked_sub(1).unwrap_or_else(unopened),
                '(' => parens += 1,
                ')' => parens = parens.checked_sub(1).unwrap_or_else(unopened),
                _ => {}
            }
        }
        let Some((head, _)) = code.split_once('(') else { continue };
        // A name, then `(` (spaces between allowed): `guarded(`, `one (`.
        let names_a_call = code.match_indices('(').any(|(at, _)| {
            code[..at].trim_end().chars().next_back().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        });
        let candidate = (names_a_call && !code.ends_with(';')) || code.ends_with('{') || code.ends_with('}');
        if !top_level || !candidate {
            continue;
        }
        let words: Vec<&str> = head.split_whitespace().collect();
        let identifier = |w: &str| {
            w.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && w.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        };
        let shaped = words.len() == prefix.len() + 2
            && words[..prefix.len()] == *prefix
            && types.contains(&words[prefix.len()])
            && identifier(words[prefix.len() + 1]);
        assert!(
            shaped,
            "line {}: a top-level line that may begin a definition but is not of the shape the source states \
             (`{}<type> <name>(<parameters>)`, <type> one of {types:?}): {line}",
            number + 1,
            prefix.iter().map(|w| format!("{w} ")).collect::<String>()
        );
        found.push(words[prefix.len() + 1]);
    }
    assert_eq!((braces, parens), (0, 0), "an unclosed brace or parenthesis at the end of the source");
    found
}

/// The scan finds the promised shape however the definition is laid out,
/// refuses a definition of a shape the source did not promise however it is
/// laid out, and reads no line inside a body or a parameter list as one; the
/// three fixtures' sources are the tests above.
#[test]
fn source_definitions_checks_the_promised_shape() {
    let source = [
        "// u32 <name>(<parameters>) { <body> }",
        "u32 one(void) { return 1; }",
        "u32 two(void) {",
        "    if (one()) {",
        "    }",
        "    return 2;",
        "}",
        "u32 three(void)",
        "{",
        "    return 3;",
        "}",
        "u32 four(u32 a,",
        "         u32 b) { return a + b; }",
        "u32 five(u32 a);",
        // A parameter list that goes on with a `(` of its own: the second line
        // is inside the parenthesis, not a definition of another shape.
        "u32 six(u32 a,",
        "        u32 (*f)(u32)) { return f(a); }",
        "",
    ]
    .join("\n");
    assert_eq!(source_definitions(&source, &[], &["u32"]), ["one", "two", "three", "four", "six"]);
    // Each planted definition of another shape, on line 17, and the text the
    // failure must name.
    for (planted, named) in [
        ("static u32 seven(void) { return 7; }\n", "static u32 seven(void)"),
        // The `{` on the next line: the line ends in neither `{` nor `}`.
        ("static u32 eight(void)\n{\n    return 8;\n}\n", "static u32 eight(void)"),
        // The parameters across lines: the first line ends in `,`, the second
        // holds no `(`.
        ("static u32 nine(u32 a,\n                 u32 b) { return a; }\n", "static u32 nine(u32 a,"),
        // A name that is not one: a pointer the promised type does not carry.
        ("u32 *ten(void) { return 0; }\n", "u32 *ten(void)"),
    ] {
        let planted = format!("{source}{planted}");
        let refused = std::panic::catch_unwind(|| source_definitions(&planted, &[], &["u32"]));
        let message = refused.expect_err("a definition of another shape must fail");
        let message = message.downcast_ref::<String>().expect("a formatted message");
        assert!(message.contains("line 17:") && message.contains(named), "{message}");
    }
}

/// What `-Wl,--export-all` and the linker's name section make of a function
/// the source defines: the module defines it, its name section names it, and
/// it is exported under that name. The functions the linker adds are printed,
/// not compared: the source does not state them.
fn defined_named_and_exported(m: &n0xis_wasm::Module, stem: &str, stated: &[&str]) {
    use n0xis_wasm::{ExportItem, FuncOrigin};
    let names = m.names().expect("the linker keeps a name section");
    for name in stated {
        let export = m.exports().iter().find(|e| e.name == *name);
        let export = export.unwrap_or_else(|| panic!("{stem}: {name} is not exported"));
        let ExportItem::Func(f) = export.item else { panic!("{stem}: the export {name} is {:?}", export.item) };
        assert_eq!(names.functions.get(&f).map(String::as_str), Some(*name), "{stem}: the name of function {}", f.0);
        let origin = m.function(f).map(|func| func.origin);
        assert!(matches!(origin, Some(FuncOrigin::Defined { .. })), "{stem}: {name} is {origin:?}");
    }
    let added: Vec<&str> = (m.imported_functions()..m.functions().len() as u32)
        .filter_map(|f| names.functions.get(&n0xis_wasm::FuncIdx(f)).map(String::as_str))
        .filter(|name| !stated.contains(name))
        .collect();
    eprintln!("{stem}: defined but not by the source (not compared): {}", added.join(", "));
}

/// The instructions of the function the name section gives `name`, rendered.
fn rendered_body(m: &n0xis_wasm::Module, stem: &str, name: &str) -> Vec<String> {
    let names = m.names().expect("the linker keeps a name section");
    let (&f, _) = names.functions.iter().find(|(_, n)| *n == name).unwrap_or_else(|| panic!("{stem}: no {name}"));
    let body = m.body(f).unwrap_or_else(|| panic!("{stem}: {name} has no body")).expect("a body that decodes");
    body.instructions.iter().map(|l| l.instr.to_string()).collect()
}

/// The size of a WebAssembly page, in bytes. `--max-memory` is given in
/// bytes: wasm-ld refuses a value that is not a multiple of it ("maximum
/// memory must be aligned to the page size (65536 bytes)", measured
/// 2026-10-19 with `--max-memory=1000`).
const PAGE: u64 = 65536;

/// What `cthreads.c` and its build flags state, read back from
/// `cthreads-O2.wasm`: the shared memory it imports, its functions, the
/// instructions its builtins name, and its variables among the exports.
///
/// Not compared, because neither the source nor the flags state it: the
/// memory's minimum (the linker sizes it to the data), the functions the
/// linker adds, and which atomic instruction the compiler picks for each C11
/// operation (the operations are not instructions; the three builtins are).
#[test]
fn the_threads_fixture_holds_what_its_source_and_flags_declare() {
    use n0xis_wasm::{AddressType, ExportItem, ImportItem, Origin};
    let stem = "cthreads-O2";
    let source = common::text("cthreads.c");
    let m = common::module(stem);
    assert!(m.findings().is_empty(), "{stem}: {:?}", m.findings());
    // `-Wl,--import-memory`: "Import the module's memory from the default
    // module of "env" with the name "memory"" (wasm-ld --help);
    // `-Wl,--shared-memory`: shared; `-Wl,--max-memory=262144`: 262144 bytes;
    // `--target=wasm32`: 32-bit addresses. The source declares no function it
    // does not define, so the memory is the one import.
    let [import] = m.imports() else { panic!("{stem}: imports {:?}", m.imports()) };
    assert_eq!((import.module.as_str(), import.name.as_str()), ("env", "memory"), "{stem}");
    let ImportItem::Memory(ty) = import.item else { panic!("{stem}: the import is {:?}", import.item) };
    assert!(ty.shared, "{stem}: the imported memory is not shared");
    assert_eq!((ty.limits.address, ty.limits.max), (AddressType::I32, Some(262144 / PAGE)), "{stem}");
    // The flag is twice what the linker sizes the memory to (2 pages, the
    // recordings say), so a reader that gave the minimum for the maximum
    // fails above; with the two equal (the earlier 131072) it passed.
    assert_ne!(Some(ty.limits.min), ty.limits.max, "{stem}: the build must keep the minimum and the maximum apart");
    eprintln!("{stem}: memory minimum {} pages, the linker's choice (not compared)", ty.limits.min);
    // The module defines no memory of its own beside the imported one.
    let origins: Vec<Origin> = m.memories().iter().map(|mm| mm.origin).collect();
    assert_eq!(origins, [Origin::Imported { import: 0 }], "{stem}: the memory index space");

    // Every function the source defines, by the shape its comment states.
    let stated = source_definitions(&source, &[], &["u8", "u16", "u32", "u64", "i32", "void"]);
    assert_eq!(stated.len(), 24, "{stem}: definitions found in the source");
    defined_named_and_exported(&m, stem, &stated);
    // Each of the three builtins is named for the instruction it is.
    for (func, instr) in
        [("wait32", "memory.atomic.wait32"), ("wait64", "memory.atomic.wait64"), ("notify", "memory.atomic.notify")]
    {
        let body = rendered_body(&m, stem, func);
        assert!(body.iter().any(|l| l.split(' ').next() == Some(instr)), "{stem}: {func} has no {instr}: {body:?}");
    }
    // Every variable of external linkage is a symbol `--export-all` exports;
    // `weights` is `static`, of internal linkage, and is not.
    let exported: Vec<(&str, ExportItem)> = m.exports().iter().map(|e| (e.name.as_str(), e.item)).collect();
    for global in ["flag8", "count16", "count32", "count64", "per_thread", "per_thread_total", "shared_table"] {
        let item = exported.iter().find(|(name, _)| *name == global).map(|(_, item)| item);
        assert!(matches!(item, Some(ExportItem::Global(_))), "{stem}: {global} is exported as {item:?}");
    }
    assert!(exported.iter().all(|(name, _)| *name != "weights"), "{stem}: a static variable is exported");
}

/// What `ceh.cpp` and its two builds state, read back from `ceh-legacy-O2`
/// and `ceh-exnref-O2`: the host functions and runtime functions it leaves
/// undefined, imported; the C++ tag, imported, with the payload
/// `__builtin_wasm_throw` gives it; its functions; and which of the two
/// instruction sets the flags select.
///
/// Not compared, because neither the source nor the flags state it: the
/// module the imports come from (`--import-undefined` does not name one), the
/// imports the compiler adds (printed), the types of the runtime functions,
/// the tag's import name, the functions the linker adds, and which handler
/// instructions each `catch (...)` becomes. The source's comment says the
/// compiled handlers import `std::terminate` and counts the legacy build's
/// handler instructions; both were read from wabt's recordings of the modules
/// (`-x`, `-d`), not from the source, so neither is asserted here: the
/// recordings themselves are compared in `tests/references.rs`.
#[test]
fn the_exception_fixtures_hold_what_their_source_and_flags_declare() {
    use n0xis_wasm::{AddressType, ImportItem, Origin, Tag, ValType};
    let source = common::text("ceh.cpp");
    let stated = source_definitions(&source, &["extern", "\"C\""], &["int", "void"]);
    assert_eq!(stated.len(), 5, "definitions found in the source");
    // The flags' only difference: `-mllvm -wasm-use-legacy-eh=false` selects
    // the `exnref` instructions; without it LLVM emits the legacy ones.
    let legacy = ["try", "catch", "catch_all", "delegate", "rethrow"];
    let exnref = ["try_table", "throw_ref"];
    for (stem, is_legacy) in [("ceh-legacy-O2", true), ("ceh-exnref-O2", false)] {
        let m = common::module(stem);
        assert!(m.findings().is_empty(), "{stem}: {:?}", m.findings());
        let import = |name: &str| {
            let i = m.imports().iter().position(|i| i.name == name);
            i.unwrap_or_else(|| panic!("{stem}: {name} is not imported"))
        };
        let func_type = |i: usize| match m.imports()[i].item {
            ImportItem::Func(t) => m.func_type(t).unwrap_or_else(|| panic!("{stem}: type {t} is not a function type")),
            other => panic!("{stem}: import {i} is {other:?}"),
        };
        // Declared and not defined, so imported (`-Wl,--allow-undefined`),
        // with the types of their declarations: `int` is i32 on wasm32.
        let may_throw = func_type(import("may_throw"));
        assert_eq!((may_throw.params.as_slice(), may_throw.results.as_slice()), (&[ValType::I32][..], &[][..]));
        let report = func_type(import("report"));
        assert_eq!((report.params.as_slice(), report.results.as_slice()), (&[ValType::I32][..], &[ValType::I32][..]));
        // What the source's comment says the runtime would supply.
        for runtime in ["__cxa_begin_catch", "__cxa_end_catch", "__cxa_rethrow"] {
            func_type(import(runtime));
        }
        let stated_imports = ["may_throw", "report", "__cxa_begin_catch", "__cxa_end_catch", "__cxa_rethrow"];
        let others: Vec<String> = m
            .imports()
            .iter()
            .filter(|i| !stated_imports.contains(&i.name.as_str()))
            .map(|i| format!("{}.{} ({:?})", i.module, i.name, i.item))
            .collect();
        eprintln!("{stem}: imports the source does not name (not compared): {}", others.join(", "));
        // The C++ tag, the only one: `__builtin_wasm_throw(0, payload)` throws
        // a `void *`, an i32 on wasm32, and the source throws nothing else.
        let tags: Vec<usize> =
            (0..m.imports().len()).filter(|&i| matches!(m.imports()[i].item, ImportItem::Tag(_))).collect();
        let [tag] = tags[..] else { panic!("{stem}: tag imports at {tags:?}") };
        let ImportItem::Tag(ty) = m.imports()[tag].item else { unreachable!() };
        let payload = m.func_type(ty).unwrap_or_else(|| panic!("{stem}: the tag's type {ty} is not a function type"));
        assert_eq!((payload.params.as_slice(), payload.results.as_slice()), (&[ValType::I32][..], &[][..]));
        assert_eq!(m.tags(), [Tag { ty, origin: Origin::Imported { import: tag } }], "{stem}: the tag index space");
        // No `--import-memory`, no `--shared-memory`: the module's own
        // memory, not shared, of 32-bit addresses.
        let [memory] = m.memories() else { panic!("{stem}: memories {:?}", m.memories()) };
        let memory = (memory.origin, memory.ty.shared, memory.ty.limits.address);
        assert_eq!(memory, (Origin::Defined, false, AddressType::I32), "{stem}: the memory");

        defined_named_and_exported(&m, stem, &stated);
        let raise = rendered_body(&m, stem, "raise");
        assert!(raise.iter().any(|l| l == "throw 0"), "{stem}: raise does not throw tag 0: {raise:?}");
        let used: BTreeSet<&str> =
            common::bodies(&m).iter().flat_map(|(_, b)| b.instructions.iter().map(|l| l.instr.opcode().name)).collect();
        let (selected, other) = if is_legacy { (&legacy[..], &exnref[..]) } else { (&exnref[..], &legacy[..]) };
        assert!(used.contains(selected[0]), "{stem}: no {}", selected[0]);
        let mixed: Vec<&&str> = other.iter().filter(|name| used.contains(*name)).collect();
        assert!(mixed.is_empty(), "{stem}: instructions of the other set: {mixed:?}");
    }
}

/// The label names: the one subsection of the name section neither recorded
/// tool shows. `shapes.wat` names one label, `$outer`, the first block of
/// `$multi` (function 3).
#[test]
fn label_names_are_the_ones_the_text_gives() {
    use n0xis_wasm::FuncIdx;
    let m = common::module("shapes");
    let names = m.names().expect("a name section");
    let labels: Vec<(u32, u32, &str)> =
        names.labels.iter().flat_map(|(f, ls)| ls.iter().map(move |(l, n)| (f.0, *l, n.as_str()))).collect();
    assert_eq!(labels, [(3, 0, "outer")]);
    assert_eq!(names.functions.get(&FuncIdx(3)).map(String::as_str), Some("multi"));
}
