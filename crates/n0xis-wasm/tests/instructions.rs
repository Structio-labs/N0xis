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
//! [`OPCODES`] must be decoded from some fixture, so the coverage the first
//! test speaks for cannot shrink unnoticed.

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
    }
    eprintln!("{compared} instructions decoded as the text states them");
    // The three fixtures hold 766 + 854 + 66 instruction lines (counted with
    // awk over the body lines): a parse of the text that found none, or
    // stopped early, would otherwise pass.
    assert_eq!(compared, 1686);
}

#[test]
fn every_opcode_of_the_table_is_in_a_fixture() {
    let table: BTreeSet<(Option<u8>, u32)> = OPCODES.iter().map(|o| (o.prefix, o.code)).collect();
    assert_eq!(table.len(), OPCODES.len(), "an opcode listed twice");
    let mut seen: BTreeSet<(Option<u8>, u32)> = BTreeSet::new();
    for stem in common::FIXTURES {
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
    assert!(missing.is_empty(), "{} opcodes in no fixture: {}", missing.len(), missing.join(", "));
    // 183 one-byte opcodes, 18 under 0xFC, 236 under 0xFD: the counts the
    // WebAssembly 2.0 opcode tables give.
    let count = |p: Option<u8>| OPCODES.iter().filter(|o| o.prefix == p).count();
    assert_eq!((count(None), count(Some(0xfc)), count(Some(0xfd))), (183, 18, 236));
    eprintln!("{} of {} opcodes exercised", seen.len(), OPCODES.len());
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
            ImportItem::Func(t) => &m.types()[t.0 as usize],
            other => panic!("{stem}: import {i} is {other:?}"),
        };
        assert_eq!((ty(0).params.as_slice(), ty(0).results.as_slice()), (&[ValType::I32, ValType::I64][..], &[][..]));
        assert_eq!((ty(1).params.as_slice(), ty(1).results.as_slice()), (&[ValType::F64][..], &[ValType::F64][..]));
        // Imports come first in the function index space.
        assert_eq!(m.imported_functions(), 2, "{stem}");
        assert!(matches!(m.functions()[0].origin, FuncOrigin::Imported { import: 0 }));
        assert!(matches!(m.functions()[2].origin, FuncOrigin::Defined { body: 0 }));
        let names = m.names().expect("the linker keeps a name section");
        let defined: BTreeSet<&str> = names.functions.values().map(String::as_str).collect();
        // Every function the source defines, by the shape of its definition line.
        let mut stated = 0;
        for line in source.lines() {
            let Some((head, _)) = line.split_once('(') else { continue };
            let words: Vec<&str> = head.split_whitespace().collect();
            let is_definition = words.len() == 2
                && ["i32", "i64", "void", "double"].contains(&words[0])
                && (line.trim_end().ends_with('{') || line.trim_end().ends_with('}'));
            if is_definition {
                assert!(defined.contains(words[1]), "{stem}: {} is not among the function names", words[1]);
                stated += 1;
            }
        }
        assert_eq!(stated, 23, "{stem}: definitions found in the source");
        let exported: BTreeSet<&str> = m.exports().iter().map(|e| e.name.as_str()).collect();
        for global in ["counter", "big_total", "accumulated", "pool", "operations"] {
            assert!(exported.contains(global), "{stem}: {global} is not exported");
        }
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
