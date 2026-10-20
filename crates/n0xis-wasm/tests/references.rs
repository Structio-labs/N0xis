// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **What the reader says about every fixture is what two independent tools
//! say**, from the recordings `fixtures/build.sh` made with them:
//!
//! - wabt's `wasm-objdump -h` (sections: kind, contents range, count),
//!   `-x` (every entry of every section, the name section) and `-d` (every
//!   body: locals and every instruction with its offset), for every fixture
//!   wabt reads. For one it refuses (`common::WABT_REFUSES`), the test checks
//!   that the refusal is what is recorded, an error and a failing exit status,
//!   in place of the three recordings, and prints `not compared with wabt:
//!   <stem> (<message>)` with what that leaves compared by no tool here;
//! - `wasm-tools print -p` of a copy without custom sections, for every
//!   fixture: the type section (each type as `SubType` writes it, each
//!   recursion group as the tool groups it), every function's type index
//!   (`(type N)` of its header, imported or defined), every body again
//!   (offsets, locals, instructions), every global's initial value, and the
//!   defined tables (with their initial values), the exports and the element
//!   segments.
//!
//! Section details are compared by rendering this crate's facts in each tool's
//! own spelling and comparing line by line. Instructions are compared the
//! other way: each tool's spelling is normalised into this crate's canonical
//! one (`src/instr.rs`) and compared with the decoder's rendering, offset by
//! offset.
//!
//! The comparison must find exactly the disagreements in [`EXPLAINED`], each
//! with its reason and a third source that settles it: a new disagreement
//! fails, and so does an explained one that has gone away. The fixtures
//! compared must be every `.wasm` file of `tests/fixtures/`, and the number of
//! comparisons per fixture and reference is asserted, so that a comparison
//! that silently stops comparing, or compares in one fixture what it no
//! longer compares in another, fails too.
//!
//! Not compared here, and why (those marked "counted" are counted in the
//! test's output and the counts asserted):
//! - with wabt, a fixture it refuses (`gc`): wabt 1.0.42 reads no recursion
//!   group, so its section ranges and counts, its data bytes and its name
//!   section are compared by no tool in this file (the test prints them);
//! - the offset of each type-section entry `wasm-tools print` shows: the reader
//!   records no offset for a recursion group or a type;
//! - a table's initial value with wabt: `wasm-objdump -x` does not show it, so
//!   it is compared with `wasm-tools print` only;
//! - field names (name subsection 10): wabt lists none, and the only fixture
//!   that has them is the one it refuses;
//! - with `wasm-tools print`, the imports, memories, tags and data segments:
//!   wabt compares them for every fixture it reads;
//! - the element type of a segment whose items are function indices (forms 0
//!   to 3, counted): wabt -x prints none and wasm-tools print writes the items
//!   as `func N ...` whatever the type; `tests/v8.rs` compares it with V8;
//! - the contents of the `producers` and `target_features` custom sections
//!   (counted: the sections, and the `  - [` lines of `target_features` that
//!   wasm-objdump -x lists and this file drops): the reader does not read
//!   them, and print is of a copy without custom sections;
//! - a constant expression of more than one instruction with wabt: `-x`
//!   writes one whole (`init (i32.const 40, i32.const 2, i32.add)`, an
//!   unrecorded probe, 2026-10-20), and [`init_text`] renders its first
//!   instruction only, so one in a fixture wabt reads would be a disagreement,
//!   not a pass; none has one (counted, 0). Those of `gc` (12 global initial
//!   values, counted) are compared with print; a data offset of more than one
//!   instruction where wabt does not read would be compared with V8 only
//!   (counted, 0); a table's initial value of more than one is compared with
//!   print, in every fixture, since wabt shows none (counted, 0: the only two,
//!   in refs, are of one instruction);
//! - V8's disassembly: `tests/v8.rs`.

mod common;

use std::collections::BTreeMap;
use std::fmt::Write as _;

use common::memarg::{is_memory_access, natural_align};

use n0xis_wasm::{
    CompositeType, DataMode, ElementItems, ElementMode, ExportItem, FuncOrigin, GlobalOrigin, ImportItem, Instr, Limits,
    Located, MemoryType, Module, Origin, RecGroup, RefType, SectionKind, TableOrigin, ValType,
};

/// One line on which the reader and a tool differ.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Disagreement {
    fixture: String,
    reference: &'static str,
    at: String,
    ours: String,
    theirs: String,
}

/// The reason for an atomic access whose offset wasm-objdump cuts to 32 bits,
/// the fault of the first entry of [`EXPLAINED`] on another instruction: the
/// line of the text that states it, that statement, the bytes, and what
/// wasm-tools print reads.
macro_rules! offset_cut {
    ($wat:literal, $text:literal, $bytes:literal, $print:literal) => {
        concat!(
            "wasm-objdump prints a 64-bit memory's offset cut to its low 32 bits, on an atomic access \
             as on a load (the first entry). The text states `",
            $text,
            "` (",
            $wat,
            "), the bytes encode it (",
            $bytes,
            ") and wasm-tools print reads `",
            $print,
            "`."
        )
    };
}

/// Every disagreement the comparison finds, with the source that settles it.
/// Fields: fixture, reference, where, ours, theirs, why.
const EXPLAINED: &[(&str, &str, &str, &str, &str, &str)] = &[
    (
        "shapes",
        "wasm-objdump -d",
        "func 4 at 0x15b",
        "i32.load 1 offset=4294967300 align=4",
        "i32.load 1 offset=4 align=4",
        "wasm-objdump prints a memory64 offset cut to its low 32 bits (0x1_0000_0004 -> 4). The \
         text states offset=4294967300 (shapes.wat), the bytes encode it (84 80 80 80 10) and \
         wasm-tools print reads it the same.",
    ),
    (
        "shapes",
        "wasm-objdump -x",
        "Global line 1",
        " - global[3] v128 mutable=0 <vector> - init v128=0x00000001 0x00000002 0x00000003 0x00000004",
        " - global[3] v128 mutable=0 <vector> - init i32=0",
        "wasm-objdump prints a v128.const initial value as `i32=0`. The text states \
         v128.const i32x4 1 2 3 4 (shapes.wat) and wasm-tools print reads the same.",
    ),
    (
        "threads",
        "wasm-objdump -d",
        "func 0 at 0x8a",
        "memory.atomic.notify 1 offset=4294967296 align=4",
        "memory.atomic.notify 1 offset=0 align=4",
        offset_cut!("threads.wat:47", "memory.atomic.notify 1 offset=4294967296 align=4", "fe 00 42 01 80 80 80 80 10", "memory.atomic.notify 1 offset=4294967296"),
    ),
    (
        "threads",
        "wasm-objdump -d",
        "func 0 at 0x9a",
        "memory.atomic.wait32 1 offset=4294967300 align=4",
        "memory.atomic.wait32 1 offset=4 align=4",
        offset_cut!("threads.wat:52", "memory.atomic.wait32 1 offset=4294967300 align=4", "fe 01 42 01 84 80 80 80 10", "memory.atomic.wait32 1 offset=4294967300"),
    ),
    (
        "threads",
        "wasm-objdump -d",
        "func 0 at 0xaa",
        "memory.atomic.wait64 1 offset=4294967304 align=8",
        "memory.atomic.wait64 1 offset=8 align=8",
        offset_cut!("threads.wat:57", "memory.atomic.wait64 1 offset=4294967304 align=8", "fe 02 43 01 88 80 80 80 10", "memory.atomic.wait64 1 offset=4294967304"),
    ),
    (
        "threads",
        "wasm-objdump -d",
        "func 3 at 0x376",
        "i32.atomic.load 1 offset=4294967296 align=4",
        "i32.atomic.load 1 offset=0 align=4",
        offset_cut!("threads.wat:342", "i32.atomic.load 1 offset=4294967296 align=4", "fe 10 42 01 80 80 80 80 10", "i32.atomic.load 1 offset=4294967296"),
    ),
    (
        "threads",
        "wasm-objdump -d",
        "func 3 at 0x382",
        "i64.atomic.load 1 offset=4294967304 align=8",
        "i64.atomic.load 1 offset=8 align=8",
        offset_cut!("threads.wat:345", "i64.atomic.load 1 offset=4294967304 align=8", "fe 11 43 01 88 80 80 80 10", "i64.atomic.load 1 offset=4294967304"),
    ),
    (
        "threads",
        "wasm-objdump -d",
        "func 3 at 0x38e",
        "i64.atomic.load32_u 1 offset=18446744073709551612 align=4",
        "i64.atomic.load32_u 1 offset=4294967292 align=4",
        offset_cut!("threads.wat:348", "i64.atomic.load32_u 1 offset=18446744073709551612 align=4", "fe 16 42 01 fc ff ff ff ff ff ff ff ff 01", "i64.atomic.load32_u 1 offset=18446744073709551612"),
    ),
    (
        "threads",
        "wasm-objdump -d",
        "func 3 at 0x3a1",
        "i64.atomic.store 1 offset=8589934592 align=8",
        "i64.atomic.store 1 offset=0 align=8",
        offset_cut!("threads.wat:352", "i64.atomic.store 1 offset=8589934592 align=8", "fe 18 43 01 80 80 80 80 20", "i64.atomic.store 1 offset=8589934592"),
    ),
    (
        "threads",
        "wasm-objdump -d",
        "func 3 at 0x3ae",
        "i32.atomic.store16 1 offset=4294967298 align=2",
        "i32.atomic.store16 1 offset=2 align=2",
        offset_cut!("threads.wat:355", "i32.atomic.store16 1 offset=4294967298 align=2", "fe 1a 41 01 82 80 80 80 10", "i32.atomic.store16 1 offset=4294967298"),
    ),
    (
        "threads",
        "wasm-objdump -d",
        "func 3 at 0x3bb",
        "i32.atomic.rmw.add 1 offset=4294967296 align=4",
        "i32.atomic.rmw.add 1 offset=0 align=4",
        offset_cut!("threads.wat:358", "i32.atomic.rmw.add 1 offset=4294967296 align=4", "fe 1e 42 01 80 80 80 80 10", "i32.atomic.rmw.add 1 offset=4294967296"),
    ),
    (
        "threads",
        "wasm-objdump -d",
        "func 3 at 0x3c9",
        "i64.atomic.rmw8.xchg_u 1 offset=4294967297 align=1",
        "i64.atomic.rmw8.xchg_u 1 offset=1 align=1",
        offset_cut!("threads.wat:362", "i64.atomic.rmw8.xchg_u 1 offset=4294967297 align=1", "fe 45 40 01 81 80 80 80 10", "i64.atomic.rmw8.xchg_u 1 offset=4294967297"),
    ),
    (
        "threads",
        "wasm-objdump -d",
        "func 3 at 0x3d9",
        "i64.atomic.rmw.cmpxchg 1 offset=1099511627776 align=8",
        "i64.atomic.rmw.cmpxchg 1 offset=0 align=8",
        offset_cut!("threads.wat:367", "i64.atomic.rmw.cmpxchg 1 offset=1099511627776 align=8", "fe 49 43 01 80 80 80 80 80 20", "i64.atomic.rmw.cmpxchg 1 offset=1099511627776"),
    ),
    (
        "refs",
        "wasm-objdump -d",
        "func 7 at 0xfd",
        "return_call_ref 1",
        "return_call_ref <invalid>",
        "wasm-objdump prints no type index for return_call_ref, only `<invalid>`. The bytes are \
         15 01, type 1; the text states `return_call_ref 1` (refs.wat:89) and wasm-tools print \
         reads `return_call_ref 1`.",
    ),
    (
        "refs",
        "wasm-objdump -d",
        "func 8 at 0x12a",
        "ref.null 1",
        "ref.null <invalid>",
        "wasm-objdump prints a ref.null of a type index as `<invalid>`; it spells only the \
         abstract heap types (`ref.null func` at 0x142 of the same function). The bytes are d0 01, \
         heap type 1; the text states `ref.null 1` (refs.wat:108) and wasm-tools print reads \
         `ref.null 1`.",
    ),
];

// ---------------------------------------------------------------------------
// Spellings shared by both tools.

fn types(ts: &[ValType]) -> String {
    ts.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(", ")
}

/// A tool's float literal, in the canonical spelling: `nan` is the canonical
/// NaN with its payload stated, and `0x1.p-149` loses its empty fraction.
fn float_literal(text: &str, is_f32: bool) -> String {
    let (sign, body) = match text.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", text),
    };
    if body == "nan" {
        return format!("{sign}nan:{}", if is_f32 { "0x400000" } else { "0x8000000000000" });
    }
    format!("{sign}{}", body.replace(".p", "p"))
}

/// A tool's operands split at the top level: a bare word, or a parenthesised
/// group kept whole (`(ref null 1)`, `(catch 0 1)`), so that a reference type
/// is one operand however many words it has.
fn operands(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut depth = 0usize;
    for word in text.split_whitespace() {
        if depth > 0 {
            let last = out.last_mut().expect("an open group");
            last.push(' ');
            last.push_str(word);
        } else {
            out.push(word.to_string());
        }
        depth += word.matches('(').count();
        depth = depth.saturating_sub(word.matches(')').count());
    }
    out
}

// ---------------------------------------------------------------------------
// wasm-objdump -d

/// What `wasm-objdump -d` prints in place of an immediate it cannot spell.
const INVALID: &str = "<invalid>";

/// `wasm-objdump -d`'s instruction text, in the canonical spelling.
fn from_objdump(text: &str) -> String {
    // Names are annotations: `call 3 <add>`, `local.get 0 <p>`. But
    // `<invalid>` is what the tool says in place of an immediate it could not
    // print (`ref.null <invalid>`), so it is kept: it is the tool's answer.
    let mut plain = String::new();
    let mut depth = 0;
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        if depth == 0 && rest.starts_with(INVALID) {
            plain.push_str(INVALID);
            rest = &rest[INVALID.len()..];
            continue;
        }
        match c {
            '<' => depth += 1,
            '>' if depth > 0 => depth -= 1,
            _ if depth == 0 => plain.push(c),
            _ => {}
        }
        rest = &rest[c.len_utf8()..];
    }
    // `(type 0 <t>)` leaves `(type 0 )` behind.
    let plain = plain.replace(" )", ")");
    let words: Vec<&str> = plain.split_whitespace().collect();
    let (name, args) = (words[0], &words[1..]);
    let grouped = operands(&plain);
    let block_type = |t: &str| match t.strip_prefix("type[").and_then(|t| t.strip_suffix(']')) {
        Some(index) => format!(" (type {index})"),
        None => format!(" (result {t})"),
    };
    match (name, args) {
        ("block" | "loop" | "if" | "try", _) if grouped.len() == 2 => format!("{name}{}", block_type(&grouped[1])),
        // `try_table i32 catch 2 0 catch_ref 3 1 catch_all  2`: the block
        // type, if any, then each clause unparenthesised (an empty tag field
        // leaves two spaces before `catch_all`'s label).
        ("try_table", _) => {
            let mut out = name.to_string();
            let mut rest = &grouped[1..];
            if let Some(t) = rest.first().filter(|t| !t.starts_with("catch")) {
                out.push_str(&block_type(t));
                rest = &rest[1..];
            }
            while let Some((kind, tail)) = rest.split_first() {
                let n = if kind.starts_with("catch_all") { 1 } else { 2 };
                let clause: Vec<&str> = tail.iter().take(n).map(String::as_str).collect();
                assert_eq!(clause.len(), n, "a {kind} clause of {n} fields: {text}");
                write!(out, " ({kind} {})", clause.join(" ")).unwrap();
                rest = &tail[n..];
            }
            out
        }
        ("select", _) if grouped.len() == 2 => format!("select (result {})", grouped[1]),
        // The type index printed as the reference to it (`call_ref (ref null
        // 1)` for bytes `14 01`): the index is all the instruction carries.
        ("call_ref", _) if grouped.len() == 2 => match grouped[1].strip_prefix("(ref null ").and_then(|t| t.strip_suffix(')')) {
            Some(index) => format!("call_ref {index}"),
            None => plain.clone(),
        },
        // Binary order, type then table: `return_call_indirect 1 0` for bytes
        // `13 01 00`.
        ("return_call_indirect", [ty, table]) => format!("return_call_indirect {table} (type {ty})"),
        // The reserved byte the instruction carries, which the canonical text
        // checks and does not print.
        ("atomic.fence", ["0"]) => name.to_string(),
        ("i32.const", [n]) => format!("i32.const {}", n.parse::<u32>().expect("unsigned") as i32),
        ("i64.const", [n]) => format!("i64.const {}", n.parse::<u64>().expect("unsigned") as i64),
        ("f32.const", [x]) => format!("f32.const {}", float_literal(x, true)),
        ("f64.const", [x]) => format!("f64.const {}", float_literal(x, false)),
        ("v128.const", words) => format!("v128.const i32x4 {}", words.join(" ")),
        ("i8x16.shuffle", words) => {
            let lanes: Vec<String> = words
                .iter()
                .flat_map(|w| u32::from_str_radix(w.trim_start_matches("0x"), 16).expect("hex").to_le_bytes())
                .map(|b| b.to_string())
                .collect();
            format!("i8x16.shuffle {}", lanes.join(" "))
        }
        ("memory.size" | "memory.grow" | "memory.fill", ["0"]) => name.to_string(),
        ("memory.copy", ["0", "0"]) => name.to_string(),
        ("memory.init", [data, "0"]) => format!("memory.init {data}"),
        ("memory.init", [data, memory]) => format!("memory.init {memory} {data}"),
        ("table.init", [elem, table]) => format!("table.init {table} {elem}"),
        _ if is_memory_access(name) => {
            let (memarg, lane) = if name.ends_with("_lane") { (&args[..args.len() - 1], args.last()) } else { (args, None) };
            let (align, memory, offset) = match memarg {
                [a, o] => (a, &"0", o),
                [a, m, o] => (a, m, o),
                other => panic!("a memory argument of {} fields: {text}", other.len()),
            };
            let align = 1u64 << align.parse::<u32>().expect("an alignment");
            let memory = if *memory == "0" { String::new() } else { format!(" {memory}") };
            let lane = lane.map(|l| format!(" {l}")).unwrap_or_default();
            format!("{name}{memory} offset={offset} align={align}{lane}")
        }
        _ => words.join(" "),
    }
}

struct ObjdumpFunction {
    func: u32,
    start: usize,
    name: Option<String>,
    locals: Vec<String>,
    instructions: Vec<(usize, String)>,
}

fn parse_objdump_disassembly(text: &str) -> Vec<ObjdumpFunction> {
    let mut out: Vec<ObjdumpFunction> = Vec::new();
    for line in text.lines() {
        if let Some((start, rest)) = line.split_once(" func[") {
            if start.starts_with(' ') {
                continue;
            }
            let (index, rest) = rest.split_once(']').expect("func[N]");
            let name = rest.trim().trim_end_matches(':').trim();
            let name = name.strip_prefix('<').and_then(|n| n.strip_suffix('>')).map(str::to_string);
            out.push(ObjdumpFunction {
                func: index.parse().unwrap(),
                start: usize::from_str_radix(start, 16).unwrap(),
                name,
                locals: Vec::new(),
                instructions: Vec::new(),
            });
            continue;
        }
        let Some((head, instr)) = line.split_once('|') else { continue };
        let instr = instr.trim();
        // A long instruction's bytes continue on a line with no text.
        if instr.is_empty() {
            continue;
        }
        let offset = usize::from_str_radix(head.trim().split(':').next().unwrap(), 16).expect("an offset");
        let f = out.last_mut().expect("an instruction before any function");
        if instr.starts_with("local[") {
            f.locals.push(instr.to_string());
        } else {
            f.instructions.push((offset, from_objdump(instr)));
        }
    }
    out
}

/// The locals a body declares, as `wasm-objdump -d` lists them.
fn objdump_locals(params: usize, body: &n0xis_wasm::Body) -> Vec<String> {
    let mut next = params as u64;
    let mut out = Vec::new();
    for run in &body.locals {
        let last = next + u64::from(run.count) - 1;
        if run.count == 1 {
            out.push(format!("local[{next}] type={}", run.ty));
        } else {
            out.push(format!("local[{next}..{last}] type={}", run.ty));
        }
        next = last + 1;
    }
    out
}

/// Compare `ours` with `theirs` instruction by instruction, keyed by offset.
///
/// Two instructions cannot start at one offset, so a second one at an offset
/// already seen, on either side, is a disagreement of its own: keyed by
/// offset, it would otherwise replace the first in the map and vanish (a
/// decoder that emitted an instruction twice passed that way). The number of
/// instructions of the function is compared as well.
fn compare_instructions(
    report: &mut Report,
    reference: &'static str,
    func: u32,
    ours: &[Located],
    theirs: &[(usize, String)],
) {
    let at = |offset: usize| format!("func {func} at {offset:#x}");
    report.lines(reference, &format!("func {func} instruction count"), &[ours.len().to_string()], &[theirs.len().to_string()]);
    let mut mine: BTreeMap<usize, String> = BTreeMap::new();
    for l in ours {
        let text = l.instr.to_string();
        if let Some(first) = mine.get(&l.offset) {
            report.differ(reference, at(l.offset), &format!("a second instruction at this offset: {first}, then {text}"), "(one instruction here)");
        } else {
            mine.insert(l.offset, text);
        }
    }
    let mut tool: BTreeMap<usize, &String> = BTreeMap::new();
    for (offset, text) in theirs {
        if let Some(first) = tool.get(offset) {
            report.differ(reference, at(*offset), "(one instruction here)", &format!("a second instruction at this offset: {first}, then {text}"));
        } else {
            tool.insert(*offset, text);
        }
    }
    for (offset, text) in &mine {
        *report.compared.entry(if reference == "wasm-objdump -d" { "wasm-objdump -d, instructions" } else { "wasm-tools print, instructions" }).or_default() += 1;
        match tool.get(offset) {
            Some(t) if *t == text => {}
            Some(t) => report.differ(reference, at(*offset), text, t),
            None => report.differ(reference, at(*offset), text, "(no instruction here)"),
        }
    }
    for (offset, text) in tool {
        if !mine.contains_key(&offset) {
            report.differ(reference, at(offset), "(no instruction here)", text);
        }
    }
}

// ---------------------------------------------------------------------------
// wasm-tools print -p

/// `wasm-tools print`'s instruction text, in the canonical spelling.
fn from_print(text: &str) -> String {
    // Comments: `;; label = @1`, `(;@3;)` after a label, `(;=1.5;)` after a float.
    let text = text.split(";;").next().unwrap();
    let mut plain = String::new();
    let mut rest = text;
    while let Some(open) = rest.find("(;") {
        plain.push_str(&rest[..open]);
        let close = rest[open..].find(";)").expect("a closed comment");
        rest = &rest[open + close + 2..];
    }
    plain.push_str(rest);
    // `(catch_all 0 (;@1;))` leaves `(catch_all 0 )` behind.
    let plain = plain.replace(" )", ")");
    let words: Vec<&str> = plain.split_whitespace().collect();
    let (name, args) = (words[0], &words[1..]);
    match (name, args) {
        // `block (type 1) (param i32) (result i32 i32)`: the index is the
        // immediate; `try_table`'s clauses follow the signature and are kept.
        ("block" | "loop" | "if" | "try" | "try_table", ["(type", ..]) => {
            let groups = operands(&args.join(" "));
            let clauses: Vec<&str> = groups.iter().filter(|g| g.starts_with("(catch")).map(String::as_str).collect();
            let clauses: String = clauses.iter().map(|c| format!(" {c}")).collect();
            format!("{name} {}{clauses}", groups[0])
        }
        ("call_indirect" | "return_call_indirect", ["(type", ..]) => format!("{name} 0 {}", args.join(" ")),
        ("table.copy", []) => "table.copy 0 0".to_string(),
        ("table.init", [elem]) => format!("table.init 0 {elem}"),
        ("f32.const", [x]) => format!("f32.const {}", float_literal(x, true)),
        ("f64.const", [x]) => format!("f64.const {}", float_literal(x, false)),
        _ if is_memory_access(name) => {
            let mut memory = String::new();
            let mut offset = "0".to_string();
            let mut align = natural_align(name).to_string();
            let mut lane = String::new();
            for (i, a) in args.iter().enumerate() {
                if let Some(o) = a.strip_prefix("offset=") {
                    offset = o.to_string();
                } else if let Some(x) = a.strip_prefix("align=") {
                    align = x.to_string();
                } else if i == 0 && (args.len() > 1 || !name.ends_with("_lane")) {
                    memory = format!(" {a}");
                } else {
                    lane = format!(" {a}");
                }
            }
            format!("{name}{memory} offset={offset} align={align}{lane}")
        }
        _ => words.join(" "),
    }
}

struct PrintFunction {
    func: u32,
    start: usize,
    locals: Vec<String>,
    instructions: Vec<(usize, String)>,
}

/// The offset and the text of a `(;@1a ;) text` line.
fn print_line(line: &str) -> Option<(usize, &str)> {
    let rest = line.strip_prefix("(;@")?;
    let (offset, text) = rest.split_once(";)")?;
    Some((usize::from_str_radix(offset.trim(), 16).ok()?, text.trim()))
}

fn parse_print_functions(text: &str) -> Vec<PrintFunction> {
    let mut out: Vec<PrintFunction> = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let Some((offset, text)) = print_line(line) else { continue };
        if let Some(rest) = text.strip_prefix("(func (;") {
            let index = rest.split(';').next().unwrap();
            out.push(PrintFunction { func: index.parse().unwrap(), start: offset, locals: Vec::new(), instructions: Vec::new() });
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        let f = out.last_mut().unwrap();
        if let Some(locals) = text.strip_prefix("(local ") {
            // `(local (ref null 1) (ref 1) i32)`: a reference type is one local.
            f.locals.extend(operands(locals.strip_suffix(')').expect("a closed (local")));
        } else if text == ")" {
            // The function's closing line stands at its final `end`.
            f.instructions.push((offset, "end".to_string()));
            inside = false;
        } else {
            f.instructions.push((offset, from_print(text)));
        }
    }
    out
}

/// Every function's type index as `wasm-tools print` writes it, imported
/// (`(import "m" "n" (func (;0;) (type 1)))`) and defined (`(func (;3;) (type
/// 2) (param i32) ...`), in the tool's order, which is the index space's:
/// `func N (type T)`, or `func N (no type)` for a header that names none.
fn parse_print_function_types(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(print_line)
        .filter_map(|(_, t)| {
            let rest = &t[t.find("(func (;")? + "(func (;".len()..];
            let (index, rest) = rest.split_once(";)").expect("(func (;N;)");
            let ty = rest.trim_start().strip_prefix("(type ").and_then(|r| r.split_once(')')).map(|(ty, _)| ty);
            Some(match ty {
                Some(ty) => format!("func {index} (type {ty})"),
                None => format!("func {index} (no type)"),
            })
        })
        .collect()
}

/// Every function's type index, from this crate's facts, as
/// [`parse_print_function_types`] reads the tool's.
fn print_function_types(m: &Module) -> Vec<String> {
    m.functions().iter().enumerate().map(|(i, f)| format!("func {i} (type {})", f.ty)).collect()
}

/// The type section as `wasm-tools print` writes it, one entry per line, from
/// this crate's facts: each type as [`SubType`](n0xis_wasm::SubType)'s
/// `Display` writes it, inside `(rec` ... `)` when the file wrote an explicit
/// recursion group and as `(rec)` for an empty one; a bare type is a group of
/// one the file did not write as a group, and stands alone.
fn print_types(m: &Module) -> Vec<String> {
    let mut out = Vec::new();
    for g in m.rec_groups() {
        let types = g.types().map(|i| format!("(type (;{i};) {})", m.types()[i as usize]));
        match g {
            RecGroup::Rec(r) if r.is_empty() => out.push("(rec)".to_string()),
            RecGroup::Rec(_) => {
                out.push("(rec".to_string());
                out.extend(types);
                out.push(")".to_string());
            }
            RecGroup::Single(_) => out.extend(types),
        }
    }
    out
}

/// The type section's lines of a `wasm-tools print` recording, trimmed and
/// without their offsets: the `(type (;N;) ...)` lines and the `(rec`, `(rec)`
/// and `)` lines that group them. They come first in the module; the first
/// other line ends them.
fn parse_print_types(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_group = false;
    for line in text.lines().skip_while(|l| *l != "(module") {
        let line = print_line(line).map(|(_, t)| t).unwrap_or(line.trim());
        match line {
            "(module" => continue,
            "(rec" => in_group = true,
            ")" if in_group => in_group = false,
            "(rec)" => {}
            _ if line.starts_with("(type (;") => {}
            _ => break,
        }
        out.push(line.to_string());
    }
    out
}

/// A constant expression as `wasm-tools print` writes it on a module-level
/// line: its instructions without the final `end`, separated by spaces.
fn print_expr(expr: &[Located]) -> String {
    expr[..expr.len() - 1].iter().map(|l| l.instr.to_string()).collect::<Vec<_>>().join(" ")
}

/// The defined tables, element segments and exports as `wasm-tools print`
/// writes them, from this crate's facts. A table's initial value (the `0x40
/// 0x00` form) is compared only here: `wasm-objdump -x` does not show it.
fn print_module_lines(m: &Module) -> Vec<String> {
    let mut out = Vec::new();
    for (i, t) in m.tables().iter().enumerate() {
        let TableOrigin::Defined { init } = &t.origin else { continue };
        let wide = if t.ty.limits.address == n0xis_wasm::AddressType::I64 { "i64 " } else { "" };
        let max = t.ty.limits.max.map(|x| format!(" {x}")).unwrap_or_default();
        let init = init.as_deref().map(|e| format!(" {}", print_expr(e))).unwrap_or_default();
        out.push(format!("(table (;{i};) {wide}{}{max} {}{init})", t.ty.limits.min, t.ty.element));
    }
    for e in m.exports() {
        let item = match e.item {
            ExportItem::Func(x) => format!("func {x}"),
            ExportItem::Table(x) => format!("table {x}"),
            ExportItem::Memory(x) => format!("memory {x}"),
            ExportItem::Global(x) => format!("global {x}"),
            ExportItem::Tag(x) => format!("tag {x}"),
        };
        out.push(format!("(export \"{}\" ({item}))", e.name));
    }
    for (i, e) in m.elements().iter().enumerate() {
        let mut line = format!("(elem (;{i};)");
        match &e.mode {
            // The tool names a table other than 0 (every fixture's form 2 and
            // 6 segment names one).
            ElementMode::Active { table, offset } => {
                if table.0 != 0 {
                    write!(line, " (table {table})").unwrap();
                }
                write!(line, " ({})", print_expr(offset)).unwrap();
            }
            ElementMode::Passive => {}
            ElementMode::Declarative => line.push_str(" declare"),
        }
        match &e.items {
            // A list of function indices is `func N ...`, whatever its type.
            ElementItems::Functions(f) => {
                line.push_str(" func");
                for f in f {
                    write!(line, " {f}").unwrap();
                }
            }
            ElementItems::Expressions(x) => {
                write!(line, " {}", e.ty).unwrap();
                for x in x {
                    write!(line, " ({})", print_expr(x)).unwrap();
                }
            }
        }
        line.push(')');
        out.push(line);
    }
    out
}

/// The `(table`, `(export` and `(elem` lines of a `wasm-tools print`
/// recording, trimmed and without their offsets, in the order
/// [`print_module_lines`] gives them: tables, exports, element segments (the
/// tool's order, which is the sections').
fn parse_print_module_lines(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().filter_map(print_line).map(|(_, t)| t).collect();
    let mut out = Vec::new();
    for prefix in ["(table (;", "(export \"", "(elem (;"] {
        out.extend(lines.iter().filter(|t| t.starts_with(prefix)).map(|t| t.to_string()));
    }
    out
}

/// A `(global (;N;) TYPE VALUE)` line, from after `(global (;`, to its initial
/// value: the type is a word (`i32`) or a parenthesised form (`(mut i32)`,
/// `(ref null 1)`, `(mut (ref null 0))`).
fn global_value(line: &str) -> &str {
    let t = line.split_once(";)").expect("(global (;N;)").1.trim();
    let t = t.strip_suffix(')').expect("a closed global");
    let end = if t.starts_with('(') {
        let mut depth = 0;
        t.char_indices()
            .find_map(|(i, c)| {
                match c {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                (depth == 0).then_some(i + 1)
            })
            .expect("a balanced type")
    } else {
        t.find(' ').expect("a type, then a value")
    };
    t[end..].trim()
}

// ---------------------------------------------------------------------------
// wasm-objdump -h and -x, from this crate's facts

fn section_title(kind: &SectionKind) -> &'static str {
    match kind {
        SectionKind::Custom { .. } => "Custom",
        SectionKind::Type => "Type",
        SectionKind::Import => "Import",
        SectionKind::Function => "Function",
        SectionKind::Table => "Table",
        SectionKind::Memory => "Memory",
        SectionKind::Global => "Global",
        SectionKind::Export => "Export",
        SectionKind::Start => "Start",
        SectionKind::Element => "Elem",
        SectionKind::Code => "Code",
        SectionKind::Data => "Data",
        SectionKind::DataCount => "DataCount",
        SectionKind::Tag => "Tag",
    }
}

fn section_count(m: &Module, kind: &SectionKind) -> Option<usize> {
    let defined = |origins: &mut dyn Iterator<Item = bool>| origins.filter(|d| *d).count();
    Some(match kind {
        // The section's entries, which are recursion groups: 3.0's binary
        // grammar makes the type section a vector of `rectype`s. What the
        // recordings can show: nothing that tells groups from types, because
        // every module wabt reads has only one-type groups (it refuses an
        // explicit `rec`, byte 0x4e, as gc.wabt-refuses.txt records), so there
        // the two counts coincide; a reader counting types would pass. An
        // unrecorded probe (2026-10-20: `(rec` of two types, then three bare
        // ones) had `wasm-objdump -h` print `count: 4` before it refused the
        // contents; no test checks that.
        SectionKind::Type => m.rec_groups().len(),
        SectionKind::Import => m.imports().len(),
        SectionKind::Function => m.bodies().len(),
        SectionKind::Table => defined(&mut m.tables().iter().map(|t| matches!(t.origin, TableOrigin::Defined { .. }))),
        SectionKind::Memory => defined(&mut m.memories().iter().map(|t| t.origin == Origin::Defined)),
        SectionKind::Tag => defined(&mut m.tags().iter().map(|t| t.origin == Origin::Defined)),
        SectionKind::Global => {
            defined(&mut m.globals().iter().map(|g| matches!(g.origin, GlobalOrigin::Defined { .. })))
        }
        SectionKind::Export => m.exports().len(),
        SectionKind::Element => m.elements().len(),
        SectionKind::Code => m.bodies().len(),
        SectionKind::Data => m.data().len(),
        SectionKind::DataCount => m.data_count()? as usize,
        SectionKind::Custom { .. } | SectionKind::Start => return None,
    })
}

/// `wasm-objdump -h`'s section lines, from this crate's facts.
fn headers(m: &Module) -> Vec<String> {
    m.sections()
        .iter()
        .map(|s| {
            let mut line = format!(
                "{:>9} start={:#010x} end={:#010x} (size={:#010x})",
                section_title(&s.kind),
                s.contents.start,
                s.contents.end,
                s.contents.len()
            );
            match &s.kind {
                SectionKind::Custom { name } => write!(line, " \"{name}\"").unwrap(),
                SectionKind::Start => write!(line, " start: {}", m.start().unwrap().0).unwrap(),
                kind => write!(line, " count: {}", section_count(m, kind).unwrap()).unwrap(),
            }
            line
        })
        .collect()
}

fn limits_text(l: &Limits) -> String {
    let mut s = format!("initial={}", l.min);
    if let Some(max) = l.max {
        write!(s, " max={max}").unwrap();
    }
    s
}

/// A memory's limits, then ` shared` for a shared one, before ` i64` (wabt
/// 1.0.42: `memory[1] pages: initial=1 max=65536 shared i64` in
/// threads.details.txt).
fn memory_text(t: &MemoryType) -> String {
    let shared = if t.shared { " shared" } else { "" };
    format!("{}{shared}", limits_text(&t.limits))
}

/// A constant expression as `wasm-objdump -x` writes an initial value, for an
/// expression of one instruction: the tool writes a longer one whole, as `init
/// (i32.const 40, i32.const 2, i32.add)`, which this does not render, so such an
/// expression shows as a disagreement (no fixture wabt reads has one).
fn init_text(m: &Module, expr: &[Located]) -> String {
    match expr.first().map(|l| &l.instr) {
        Some(Instr::I32Const(v)) => format!("i32={v}"),
        Some(Instr::I64Const(v)) => format!("i64={v}"),
        Some(Instr::RefFunc(f)) => format!("ref.func:{f}{}", func_name(m, f.0)),
        // The tool writes the reference type (`ref.null funcref`), not the
        // heap type the instruction carries.
        Some(Instr::RefNull(t)) => format!("ref.null {}", RefType { nullable: true, heap: *t }),
        Some(Instr::GlobalGet(g)) => format!("global={g}"),
        Some(Instr::V128Const(v)) => {
            let words: Vec<String> = v.0.as_chunks::<4>().0.iter().map(|w| format!("{:#010x}", u32::from_le_bytes(*w))).collect();
            format!("v128={}", words.join(" "))
        }
        other => format!("{other:?}"),
    }
}

fn func_name(m: &Module, index: u32) -> String {
    m.names()
        .and_then(|n| n.functions.get(&n0xis_wasm::FuncIdx(index)))
        .map(|n| format!(" <{n}>"))
        .unwrap_or_default()
}

/// `wasm-objdump -x`'s section details, from this crate's facts, by section:
/// (title, lines). Data segment bytes are compared on their own (see
/// [`data_dumps`]); custom sections other than `name` give their title only.
fn details(m: &Module) -> Vec<(String, Vec<String>)> {
    let names = m.names().cloned().unwrap_or_default();
    let named = |map: Option<&String>| map.map(|n| format!(" <{n}>")).unwrap_or_default();
    let mut out = Vec::new();
    for s in m.sections() {
        let mut lines = Vec::new();
        match &s.kind {
            SectionKind::Type => {
                for (i, t) in m.types().iter().enumerate() {
                    lines.push(match &t.composite {
                        CompositeType::Func(t) => {
                            let results = match t.results.len() {
                                0 => "nil".to_string(),
                                1 => t.results[0].to_string(),
                                _ => format!("({})", types(&t.results)),
                            };
                            format!(" - type[{i}] ({}) -> {results}", types(&t.params))
                        }
                        // wabt 1.0.42's spelling, from an unrecorded probe
                        // module (2026-10-20: `(struct i32 (mut i64))`,
                        // `(array (mut i32))`). No fixture wabt reads holds a
                        // structure or an array (the one that does, gc.wasm,
                        // it refuses), so no recording checks these two lines
                        // and nothing here says they are right.
                        CompositeType::Struct(s) => {
                            let fields: Vec<String> = s.fields.iter().map(|f| format!(" {f}")).collect();
                            format!(" - type[{i}] (struct{})", fields.concat())
                        }
                        CompositeType::Array(a) => format!(" - type[{i}] (array {})", a.field),
                    });
                }
            }
            SectionKind::Import => {
                let (mut f, mut t, mut mem, mut g, mut tag) = (0, 0, 0, 0, 0);
                for i in m.imports() {
                    let from = format!("<- {}.{}", i.module, i.name);
                    lines.push(match i.item {
                        ImportItem::Func(ty) => {
                            f += 1;
                            format!(" - func[{}] sig={ty}{} {from}", f - 1, func_name(m, f - 1))
                        }
                        ImportItem::Table(tt) => {
                            t += 1;
                            format!(" - table[{}] type={} {} {from}", t - 1, tt.element, limits_text(&tt.limits))
                        }
                        ImportItem::Memory(mt) => {
                            mem += 1;
                            format!(" - memory[{}] pages: {} {from}", mem - 1, memory_text(&mt))
                        }
                        ImportItem::Global(gt) => {
                            g += 1;
                            format!(" - global[{}] {} mutable={} {from}", g - 1, gt.ty, u8::from(gt.mutable))
                        }
                        // An imported tag carries its name, or else the import's
                        // (wabt 1.0.42: `tag[0] sig=1 <failure> <- env.failure` in
                        // eh.details.txt, `tag[0] sig=0 <env.__cpp_exception> <-
                        // env.__cpp_exception` in ceh-legacy-O2.details.txt).
                        ImportItem::Tag(ty) => {
                            tag += 1;
                            let name = names.tags.get(&n0xis_wasm::TagIdx(tag - 1)).cloned().unwrap_or_else(|| format!("{}.{}", i.module, i.name));
                            format!(" - tag[{}] sig={ty} <{name}> {from}", tag - 1)
                        }
                    });
                }
            }
            SectionKind::Function => {
                for (i, f) in m.functions().iter().enumerate() {
                    if matches!(f.origin, FuncOrigin::Defined { .. }) {
                        lines.push(format!(" - func[{i}] sig={}{}", f.ty, func_name(m, i as u32)));
                    }
                }
            }
            SectionKind::Table => {
                for (i, t) in m.tables().iter().enumerate().filter(|(_, t)| matches!(t.origin, TableOrigin::Defined { .. })) {
                    let wide = if t.ty.limits.address == n0xis_wasm::AddressType::I64 { " i64" } else { "" };
                    let name = named(names.tables.get(&n0xis_wasm::TableIdx(i as u32)));
                    lines.push(format!(" - table[{i}] type={} {}{name}{wide}", t.ty.element, limits_text(&t.ty.limits)));
                }
            }
            SectionKind::Memory => {
                for (i, mm) in m.memories().iter().enumerate().filter(|(_, mm)| mm.origin == Origin::Defined) {
                    let wide = if mm.ty.limits.address == n0xis_wasm::AddressType::I64 { " i64" } else { "" };
                    lines.push(format!(" - memory[{i}] pages: {}{wide}", memory_text(&mm.ty)));
                }
            }
            // A defined tag is listed with no name, even a named one (wabt
            // 1.0.42: `tag[1] sig=0` in eh.details.txt, whose tag 1 the name
            // section calls `empty`).
            SectionKind::Tag => {
                for (i, t) in m.tags().iter().enumerate().filter(|(_, t)| t.origin == Origin::Defined) {
                    lines.push(format!(" - tag[{i}] sig={}", t.ty));
                }
            }
            SectionKind::Global => {
                for (i, g) in m.globals().iter().enumerate() {
                    if let GlobalOrigin::Defined { init } = &g.origin {
                        // The tool's convention: a global the name section does
                        // not name is shown with the name it is exported under.
                        let index = n0xis_wasm::GlobalIdx(i as u32);
                        let exported = m.exports().iter().find(|e| e.item == ExportItem::Global(index)).map(|e| &e.name);
                        let name = named(names.globals.get(&index).or(exported));
                        lines.push(format!(
                            " - global[{i}] {} mutable={}{name} - init {}",
                            g.ty.ty,
                            u8::from(g.ty.mutable),
                            init_text(m, init)
                        ));
                    }
                }
            }
            SectionKind::Export => {
                for e in m.exports() {
                    lines.push(match e.item {
                        ExportItem::Func(f) => format!(" - func[{f}]{} -> \"{}\"", func_name(m, f.0), e.name),
                        ExportItem::Table(t) => format!(" - table[{t}] -> \"{}\"", e.name),
                        ExportItem::Memory(x) => format!(" - memory[{x}] -> \"{}\"", e.name),
                        ExportItem::Global(g) => format!(" - global[{g}] -> \"{}\"", e.name),
                        ExportItem::Tag(x) => format!(" - tag[{x}] -> \"{}\"", e.name),
                    });
                }
            }
            SectionKind::Start => {
                let f = m.start().unwrap();
                lines.push(format!(" - start function: {f}{}", func_name(m, f.0)));
            }
            SectionKind::Element => {
                for (i, e) in m.elements().iter().enumerate() {
                    let n = match &e.items {
                        ElementItems::Functions(f) => f.len(),
                        ElementItems::Expressions(x) => x.len(),
                    };
                    let (table, init, first) = match &e.mode {
                        ElementMode::Active { table, offset } => {
                            let first = match offset.first().map(|l| &l.instr) {
                                Some(Instr::I32Const(v)) => Some(*v as i64),
                                Some(Instr::I64Const(v)) => Some(*v),
                                _ => None,
                            };
                            (table.0, format!(" - init {}", init_text(m, offset)), first)
                        }
                        _ => (0, String::new(), None),
                    };
                    lines.push(format!(" - segment[{i}] flags={} table={table} count={n}{init}", e.form));
                    let values: Vec<String> = match &e.items {
                        ElementItems::Functions(f) => {
                            f.iter().map(|f| format!("ref.func:{f}{}", func_name(m, f.0))).collect()
                        }
                        ElementItems::Expressions(x) => x.iter().map(|x| init_text(m, x)).collect(),
                    };
                    for (k, v) in values.iter().enumerate() {
                        // Only an active segment's element index is a fact: the
                        // tool numbers the others from the previous segment.
                        let k = first.map(|f| (f + k as i64).to_string()).unwrap_or_else(|| "?".to_string());
                        lines.push(format!("  - elem[{k}] = {v}"));
                    }
                }
            }
            SectionKind::DataCount => lines.push(format!(" - data count: {}", m.data_count().unwrap())),
            SectionKind::Code => {
                let first = m.imported_functions();
                for (i, r) in m.bodies().iter().enumerate() {
                    let f = first + i as u32;
                    lines.push(format!(" - func[{f}] size={}{}", r.len(), func_name(m, f)));
                }
            }
            SectionKind::Data => {
                for (i, d) in m.data().iter().enumerate() {
                    let name = named(names.data.get(&n0xis_wasm::DataIdx(i as u32)));
                    lines.push(match &d.mode {
                        DataMode::Passive => format!(" - segment[{i}]{name} passive size={}", d.init.len()),
                        DataMode::Active { memory, offset } => format!(
                            " - segment[{i}]{name} memory={memory} size={} - init {}",
                            d.init.len(),
                            init_text(m, offset)
                        ),
                    });
                }
            }
            SectionKind::Custom { name } => {
                lines.push(format!(" - name: \"{name}\""));
                if name == "name" {
                    if let Some(module) = &names.module {
                        lines.push(format!(" - module <{module}>"));
                    }
                    for (f, n) in &names.functions {
                        lines.push(format!(" - func[{f}] <{n}>"));
                    }
                    for (f, locals) in &names.locals {
                        for (l, n) in locals {
                            lines.push(format!(" - func[{f}] local[{l}] <{n}>"));
                        }
                    }
                    for (t, n) in &names.types {
                        lines.push(format!(" - type[{t}] <{n}>"));
                    }
                    for (t, n) in &names.tables {
                        lines.push(format!(" - table[{t}] <{n}>"));
                    }
                    for (x, n) in &names.memories {
                        lines.push(format!(" - memory[{x}] <{n}>"));
                    }
                    for (g, n) in &names.globals {
                        lines.push(format!(" - global[{g}] <{n}>"));
                    }
                    for (e, n) in &names.elements {
                        lines.push(format!(" - elemseg[{e}] <{n}>"));
                    }
                    for (d, n) in &names.data {
                        lines.push(format!(" - dataseg[{d}] <{n}>"));
                    }
                    // After the data segments, and no field names: wabt
                    // 1.0.42's order and omission as an unrecorded probe
                    // module showed them (2026-10-19; re-run 2026-10-20 on a
                    // module naming one data segment and one tag: `dataseg[0]`
                    // then `tag[0]`). What the recordings can show: tag names
                    // of the name section (subsection 11) in eh (5) and
                    // eh-legacy (3) alone, and data segment names alone in
                    // ctarget-O0, ctarget-O2, cthreads-O2 and shapes, never
                    // both in one module, so the order of the two is checked
                    // by none; and the only fixture with field names is
                    // gc.wasm, which wabt refuses. ceh-legacy-O2 and
                    // ceh-exnref-O2 show one tag name each, `<env.__cpp_
                    // exception>` on the tag's import line, but it is the
                    // import's name, not one the name section gives (their
                    // name sections hold module, function and global names
                    // only: `wasm-tools dump`, 2026-10-20), so it checks the
                    // import line's fallback above, not this order.
                    for (x, n) in &names.tags {
                        lines.push(format!(" - tag[{x}] <{n}>"));
                    }
                }
            }
        }
        let title = match &s.kind {
            SectionKind::Custom { .. } | SectionKind::Start | SectionKind::DataCount => {
                format!("{}:", section_title(&s.kind))
            }
            kind => format!("{}[{}]:", section_title(kind), section_count(m, kind).unwrap()),
        };
        out.push((title, lines));
    }
    out
}

/// `wasm-objdump -x` by section, without the data dumps and the entries of
/// custom sections this crate does not read (`target_features`), and the
/// number of those entries it dropped.
///
/// The tool numbers the elements of a passive or declarative segment from
/// where the previous segment's left off, which is no fact about the segment;
/// that number is read as `?`, as [`details`] writes it.
fn parse_details(text: &str) -> (Vec<(String, Vec<String>)>, usize) {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    let mut dropped = 0;
    let mut started = false;
    let mut active_segment = false;
    for line in text.lines() {
        if line.starts_with(" - segment[") {
            active_segment = line.contains(" - init ");
        }
        let masked;
        let line = match line.strip_prefix("  - elem[").and_then(|r| r.split_once(']')) {
            Some((_, rest)) if !active_segment => {
                masked = format!("  - elem[?]{rest}");
                masked.as_str()
            }
            _ => line,
        };
        if line == "Section Details:" {
            started = true;
            continue;
        }
        if !started || line.is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            out.push((line.to_string(), Vec::new()));
        } else if line.starts_with("  - ") && out.last().is_some_and(|(t, _)| t.starts_with("Data")) {
            // A data dump line: compared by `data_dumps`.
        } else if line.starts_with("  - [") {
            // A `target_features` entry: not compared, counted.
            dropped += 1;
        } else {
            out.last_mut().expect("a line before any section").1.push(line.to_string());
        }
    }
    (out, dropped)
}

/// Each data segment's dump in `wasm-objdump -x`: its address and its bytes.
fn data_dumps(text: &str) -> Vec<(u64, Vec<u8>)> {
    let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut in_data = false;
    for line in text.lines() {
        if !line.starts_with(' ') {
            in_data = line.starts_with("Data[");
            continue;
        }
        if !in_data {
            continue;
        }
        if line.starts_with(" - segment[") {
            out.push((u64::MAX, Vec::new()));
        } else if let Some(rest) = line.strip_prefix("  - ") {
            let (address, rest) = rest.split_once(": ").expect("address: bytes");
            let hex = rest.split("  ").next().unwrap().replace(' ', "");
            let segment = out.last_mut().unwrap();
            if segment.0 == u64::MAX {
                segment.0 = u64::from_str_radix(address, 16).unwrap();
            }
            for pair in hex.as_bytes().chunks(2) {
                segment.1.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------

// What is not compared, each counted in the test's output under one of these
// names (the module's doc says why).
const NOT_TARGET_FEATURES: &str = "target_features entries wasm-objdump -x lists (dropped)";
const NOT_PRODUCERS: &str = "producers sections (wasm-objdump -x lists the name only)";
const NOT_FUNCTION_SEGMENT_TYPES: &str = "element types of segments of function indices (compared with V8 only)";
const NOT_LONG_DATA_OFFSETS: &str = "data offsets of more than one instruction where wabt does not read (compared with V8 only)";
/// Where [`long_constants`] counts a table's initial value: one place `wasm-objdump
/// -x` does not show at all, so print compares it whichever tool read the
/// fixture.
const TABLE_INITS: &str = "table initial values";

/// The constant expressions of more than one instruction (and the final
/// `end`) in a module, by where they stand: every place the binary format
/// puts one, a defined table's initial value (the `0x40 0x00` form) included.
fn long_constants(m: &Module) -> [(&'static str, usize); 5] {
    let longer = |e: &&Vec<Located>| e.len() > 2;
    let globals = m.globals().iter().filter_map(|g| match &g.origin {
        GlobalOrigin::Defined { init } => Some(init),
        GlobalOrigin::Imported { .. } => None,
    });
    let table_inits = m.tables().iter().filter_map(|t| match &t.origin {
        TableOrigin::Defined { init } => init.as_ref(),
        TableOrigin::Imported { .. } => None,
    });
    let element_offsets = m.elements().iter().filter_map(|e| match &e.mode {
        ElementMode::Active { offset, .. } => Some(offset),
        _ => None,
    });
    let element_items = m.elements().iter().flat_map(|e| match &e.items {
        ElementItems::Expressions(x) => x.as_slice(),
        ElementItems::Functions(_) => &[],
    });
    let data_offsets = m.data().iter().filter_map(|d| match &d.mode {
        DataMode::Active { offset, .. } => Some(offset),
        DataMode::Passive => None,
    });
    [
        ("global initial values", globals.filter(longer).count()),
        (TABLE_INITS, table_inits.filter(longer).count()),
        ("element offsets", element_offsets.filter(longer).count()),
        ("element items", element_items.filter(longer).count()),
        ("data offsets", data_offsets.filter(longer).count()),
    ]
}

#[derive(Default)]
struct Report {
    fixture: String,
    compared: BTreeMap<&'static str, usize>,
    /// What is not compared, by what it is: see the module's doc.
    not_compared: BTreeMap<&'static str, usize>,
    found: Vec<Disagreement>,
}

impl Report {
    fn differ(&mut self, reference: &'static str, at: String, ours: &str, theirs: &str) {
        self.found.push(Disagreement {
            fixture: self.fixture.clone(),
            reference,
            at,
            ours: ours.to_string(),
            theirs: theirs.to_string(),
        });
    }

    fn lines(&mut self, reference: &'static str, at: &str, ours: &[String], theirs: &[String]) {
        for i in 0..ours.len().max(theirs.len()) {
            *self.compared.entry(reference).or_default() += 1;
            let (o, t) = (ours.get(i).map(String::as_str), theirs.get(i).map(String::as_str));
            if o != t {
                self.differ(reference, format!("{at} line {i}"), o.unwrap_or("(none)"), t.unwrap_or("(none)"));
            }
        }
    }
}

/// Everything wabt's three recordings say about one fixture, against the
/// reader: sections (`-h`), every entry of every section and the data bytes
/// (`-x`), every body's name, locals and instructions (`-d`).
fn compare_with_wabt(report: &mut Report, m: &Module, bodies: &[(n0xis_wasm::FuncIdx, n0xis_wasm::Body)], recorded: &dyn Fn(&str) -> String) {
    let stem = report.fixture.clone();

    // Sections.
    let theirs: Vec<String> = recorded("headers").lines().filter(|l| l.contains(" start=0x")).map(str::to_string).collect();
    assert!(!theirs.is_empty(), "{stem}: no section in the recording");
    report.lines("wasm-objdump -h", "sections", &headers(m), &theirs);

    // Every entry of every section.
    let (theirs, dropped) = parse_details(&recorded("details"));
    *report.not_compared.entry(NOT_TARGET_FEATURES).or_default() += dropped;
    let ours = details(m);
    let titles = |d: &[(String, Vec<String>)]| d.iter().map(|(t, _)| t.clone()).collect::<Vec<_>>();
    report.lines("wasm-objdump -x", "section titles", &titles(&ours), &titles(&theirs));
    for ((title, ours), (_, theirs)) in ours.iter().zip(&theirs) {
        report.lines("wasm-objdump -x", title.split('[').next().unwrap().trim_end_matches(':'), ours, theirs);
    }
    // The bytes of every data segment, at the address its offset gives.
    let dumps = data_dumps(&recorded("details"));
    *report.compared.entry("wasm-objdump -x").or_default() += 1;
    if dumps.len() != m.data().len() {
        report.differ("wasm-objdump -x", "data segments".into(), &m.data().len().to_string(), &dumps.len().to_string());
    }
    for (i, (d, (address, bytes))) in m.data().iter().zip(&dumps).enumerate() {
        *report.compared.entry("wasm-objdump -x").or_default() += 1;
        let ours = m.bytes(d.init.clone()).expect("in the file");
        // A passive segment has no address; the tool shows the previous
        // segment's, so only an active segment's is compared.
        let (at, address) = match &d.mode {
            DataMode::Active { offset, .. } => match offset.first().map(|l| &l.instr) {
                Some(Instr::I32Const(v)) => (Some(*v as u32 as u64), Some(*address)),
                Some(Instr::I64Const(v)) => (Some(*v as u64), Some(*address)),
                other => panic!("{stem}: data segment {i} at {other:?}"),
            },
            DataMode::Passive => (None, None),
        };
        if (at, ours) != (address, bytes.as_slice()) {
            report.differ("wasm-objdump -x", format!("data segment {i}"), &format!("{at:x?} {ours:02x?}"), &format!("{address:x?} {bytes:02x?}"));
        }
    }

    // Every body.
    let objdump = parse_objdump_disassembly(&recorded("disassembly"));
    *report.compared.entry("wasm-objdump -d").or_default() += 1;
    if objdump.len() != bodies.len() {
        report.differ("wasm-objdump -d", "functions".into(), &bodies.len().to_string(), &objdump.len().to_string());
    }
    for ((func, body), od) in bodies.iter().zip(&objdump) {
        let params = m.func_type(m.function(*func).unwrap().ty).expect("a function's type").params.len();
        let at = format!("func {}", func.0);
        let header = |start: usize, f: u32| format!("func {f} at {start:#x}");
        report.lines("wasm-objdump -d", &at, &[header(body.range.start, func.0)], &[header(od.start, od.func)]);
        let name = m.names().and_then(|n| n.functions.get(func)).cloned();
        report.lines("wasm-objdump -d", &format!("{at} name"), &[format!("{name:?}")], &[format!("{:?}", od.name)]);
        report.lines("wasm-objdump -d", &format!("{at} locals"), &objdump_locals(params, body), &od.locals);
        compare_instructions(report, "wasm-objdump -d", func.0, &body.instructions, &od.instructions);
    }
}

/// What only wabt's recordings compare in this file, counted in one module:
/// for a fixture wabt refuses, these facts are compared by no tool here
/// (`wasm-tools print` is of a copy without the name section, and its
/// imports, memories, tags and data lines are not compared).
fn compared_only_by_wabt(m: &Module) -> String {
    let defined = |origins: &mut dyn Iterator<Item = bool>| origins.filter(|d| *d).count();
    let names = m.names().map_or(0, |n| {
        n.functions.len()
            + n.locals.values().map(BTreeMap::len).sum::<usize>()
            + n.labels.values().map(BTreeMap::len).sum::<usize>()
            + n.types.len()
            + n.tables.len()
            + n.memories.len()
            + n.globals.len()
            + n.elements.len()
            + n.data.len()
            + n.fields.values().map(BTreeMap::len).sum::<usize>()
            + n.tags.len()
            + usize::from(n.module.is_some())
    });
    format!(
        "the ranges and counts of {} sections, {} imports, {} defined memories, {} defined tags, {} data \
         segments and their bytes, {names} names",
        m.sections().len(),
        m.imports().len(),
        defined(&mut m.memories().iter().map(|x| x.origin == Origin::Defined)),
        defined(&mut m.tags().iter().map(|x| x.origin == Origin::Defined)),
        m.data().len(),
    )
}

/// What `wasm-objdump -h` said when it refused a fixture, as the refusal file
/// records it: its first error's message. The file must hold an error and a
/// failing exit status, or it records no refusal.
fn wabt_refusal(text: &str) -> String {
    let status = text.lines().find_map(|l| l.strip_prefix("exit status ")).expect("the refusal records wabt's exit status");
    assert_ne!(status.trim(), "0", "the refusal records a successful exit:\n{text}");
    let first = text.lines().find_map(|l| l.split_once(": error: ")).expect("the refusal records an error");
    first.1.to_string()
}

/// Everything `wasm-tools print` says about one fixture, against the reader:
/// the type section, every body's locals and instructions, every global's
/// initial value.
fn compare_with_print(report: &mut Report, m: &Module, bodies: &[(n0xis_wasm::FuncIdx, n0xis_wasm::Body)], print_text: &str) {
    report.lines("wasm-tools print, types", "types", &print_types(m), &parse_print_types(print_text));

    // Every function's type index. For `gc` nothing else compares it: wabt
    // refuses the module and V8 shows only the signature, so two types of one
    // signature (its types 12 and 13) would be interchangeable to both.
    report.lines("wasm-tools print, function types", "function types", &print_function_types(m), &parse_print_function_types(print_text));

    let print = parse_print_functions(print_text);
    *report.compared.entry("wasm-tools print").or_default() += 1;
    if print.len() != bodies.len() {
        report.differ("wasm-tools print", "functions".into(), &bodies.len().to_string(), &print.len().to_string());
    }
    for ((func, body), pr) in bodies.iter().zip(&print) {
        let at = format!("func {}", func.0);
        let header = |start: usize, f: u32| format!("func {f} at {start:#x}");
        report.lines("wasm-tools print", &at, &[header(body.range.start, func.0)], &[header(pr.start, pr.func)]);
        let expanded: Vec<String> =
            body.locals.iter().flat_map(|run| std::iter::repeat_n(run.ty.to_string(), run.count as usize)).collect();
        report.lines("wasm-tools print", &format!("{at} locals"), &expanded, &pr.locals);
        compare_instructions(report, "wasm-tools print", func.0, &body.instructions, &pr.instructions);
    }

    // Every global's initial value, as wasm-tools prints it.
    let printed: Vec<String> = print_text
        .lines()
        .filter_map(print_line)
        .filter_map(|(_, t)| t.strip_prefix("(global (;"))
        .filter(|t| !t.contains("(import"))
        .map(|t| from_print(global_value(t)))
        .collect();
    let ours: Vec<String> = m
        .globals()
        .iter()
        .filter_map(|g| match &g.origin {
            GlobalOrigin::Defined { init } => {
                Some(init[..init.len() - 1].iter().map(|l| l.instr.to_string()).collect::<Vec<_>>().join(" "))
            }
            GlobalOrigin::Imported { .. } => None,
        })
        .collect();
    report.lines("wasm-tools print", "globals", &ours, &printed);

    report.lines("wasm-tools print, module", "tables, exports, elements", &print_module_lines(m), &parse_print_module_lines(print_text));
}

/// The comparison of every fixture with wabt's and wasm-tools' recordings
/// (the module's doc says what is compared and what is not).
///
/// Known and not fixed:
/// - the counts asserted per fixture are counts of lines, not of facts: a
///   line that holds several facts (a section header's range and count) is
///   one comparison, and a fact dropped from inside a line both sides render
///   alike is not seen by the count;
/// - the counter that re-derived the 120 numbers of `COMPARED` from the
///   recordings alone is not checked in, so re-deriving them again means
///   rebuilding it from the rules written at the assertion;
/// - every fixture's count of table initial values of more than one
///   instruction is 0, so the print comparison of such a value has never
///   run on a fixture; only the planted module of
///   `the_long_constant_count_reads_table_initial_values` shows the count to
///   be anything but 0;
/// - the order of tag and data segment names in wabt's listing is checked by
///   no recording (no module has both), and field names by no tool here.
#[test]
fn every_fixture_reads_as_the_independent_tools_read_it() {
    let mut found = Vec::new();
    let mut totals: Vec<(String, BTreeMap<&'static str, usize>)> = Vec::new();
    let mut not_compared: Vec<(&str, String, String)> = Vec::new();
    let mut not_compared_counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut long_constants_seen: BTreeMap<(bool, &'static str), usize> = BTreeMap::new();

    // The fixtures compared are the fixtures there are: a module in the
    // directory that `common::FIXTURES` does not list would be compared with
    // nothing, silently.
    let mut on_disk: Vec<String> = std::fs::read_dir(common::dir())
        .expect("the fixtures directory")
        .map(|e| e.expect("a directory entry").file_name().into_string().expect("a UTF-8 file name"))
        .filter_map(|name| name.strip_suffix(".wasm").map(str::to_string))
        .collect();
    on_disk.sort();
    let mut listed: Vec<String> = common::FIXTURES.iter().map(|s| s.to_string()).collect();
    listed.sort();
    assert_eq!(on_disk, listed, "the .wasm files of tests/fixtures/ against common::FIXTURES");

    for stem in common::FIXTURES {
        let m = common::module(stem);
        assert!(m.findings().is_empty(), "{stem}: {:?}", m.findings());
        let recorded = |what: &str| common::text(&format!("{stem}.{what}.txt"));
        let mut report = Report { fixture: stem.to_string(), ..Default::default() };
        let bodies = common::bodies(&m);

        // The files on disk are the ones the table says: wabt's three
        // recordings, or its refusal, never both and never neither.
        let wabt_files = ["headers", "details", "disassembly"].map(|what| common::dir().join(format!("{stem}.{what}.txt")));
        let refusal = common::dir().join(format!("{stem}.wabt-refuses.txt"));
        if common::wabt_reads(stem) {
            for f in &wabt_files {
                assert!(f.is_file(), "{stem}: wabt reads it, so {} must exist", f.display());
            }
            assert!(!refusal.exists(), "{stem}: wabt reads it, yet {} exists", refusal.display());
            compare_with_wabt(&mut report, &m, &bodies, &recorded);
        } else {
            for f in &wabt_files {
                assert!(!f.exists(), "{stem}: wabt refuses it, yet {} exists", f.display());
            }
            not_compared.push((stem, wabt_refusal(&recorded("wabt-refuses")), compared_only_by_wabt(&m)));
        }

        compare_with_print(&mut report, &m, &bodies, &recorded("print"));

        // Compared by no tool in this file, whichever tool read the fixture.
        let custom = |wanted: &str| m.sections().iter().filter(|s| matches!(&s.kind, SectionKind::Custom { name } if name == wanted)).count();
        *report.not_compared.entry(NOT_PRODUCERS).or_default() += custom("producers");
        let function_segments = m.elements().iter().filter(|e| matches!(e.items, ElementItems::Functions(_))).count();
        *report.not_compared.entry(NOT_FUNCTION_SEGMENT_TYPES).or_default() += function_segments;
        // A constant expression of more than one instruction: wabt -x writes
        // it whole, which `init_text` does not, so in a fixture wabt reads one
        // would be a disagreement (none has one); elsewhere print compares the
        // globals', the tables' and the element segments' in full, and of a
        // data offset, which print is not compared on, V8 only (tests/v8.rs).
        // A table's initial value wabt -x does not show at all, so print
        // compares it in every fixture, of any length.
        for (what, n) in long_constants(&m) {
            *long_constants_seen.entry((common::wabt_reads(stem), what)).or_default() += n;
            if what == "data offsets" && !common::wabt_reads(stem) {
                *report.not_compared.entry(NOT_LONG_DATA_OFFSETS).or_default() += n;
            }
        }
        for (what, n) in &report.not_compared {
            *not_compared_counts.entry(what).or_default() += n;
        }

        totals.push((stem.to_string(), report.compared));
        found.extend(report.found);
    }

    let explained: Vec<Disagreement> = EXPLAINED
        .iter()
        .map(|(fixture, reference, at, ours, theirs, _)| Disagreement {
            fixture: fixture.to_string(),
            reference,
            at: at.to_string(),
            ours: ours.to_string(),
            theirs: theirs.to_string(),
        })
        .collect();
    let unexplained: Vec<&Disagreement> = found.iter().filter(|d| !explained.contains(d)).collect();
    let gone: Vec<&Disagreement> = explained.iter().filter(|d| !found.contains(d)).collect();
    let mut all: BTreeMap<&str, usize> = BTreeMap::new();
    for (stem, counts) in &totals {
        eprintln!("{stem}: {counts:?}");
        for (reference, n) in counts {
            *all.entry(reference).or_default() += n;
        }
    }
    for (stem, why, what) in &not_compared {
        eprintln!("not compared with wabt: {stem} ({why}); so compared by no tool here: {what}");
    }
    eprintln!("all fixtures: {all:?}");
    for (what, n) in &not_compared_counts {
        eprintln!("not compared: {what}: {n}");
    }
    for ((wabt, what), n) in &long_constants_seen {
        let compared_by = match (*wabt, *what) {
            (true, TABLE_INITS) => "wabt (whose -x shows none) and print",
            (true, _) => "wabt -x and print",
            (false, _) => "print",
        };
        eprintln!("{what} of more than one instruction, in fixtures compared with {compared_by}: {n}");
    }
    eprintln!(
        "{} comparisons, {} disagreements, {} explained, {} of {} fixtures not compared with wabt",
        all.values().sum::<usize>(),
        found.len(),
        found.len() - unexplained.len(),
        not_compared.len(),
        common::FIXTURES.len()
    );
    assert!(unexplained.is_empty(), "{} unexplained disagreements:\n{unexplained:#?}", unexplained.len());
    assert!(gone.is_empty(), "explained disagreements no longer found (remove them from EXPLAINED):\n{gone:#?}");

    // The counts are fixed by the fixtures, so a change in any of them is a
    // change in what is compared and must be looked at: a parse that silently
    // reads less (a fixture skipped, a recording's lines dropped on both
    // sides) finds no disagreement, only fewer comparisons. They are asserted
    // per fixture, not summed: a sum lets a change that moves comparisons
    // from one fixture to another pass.
    //
    // Each is a count of the recordings' lines, which is what the test counts
    // when the two sides agree in length: re-derived 2026-10-20, all 120 (14
    // fixtures by 9 references, less gc's four wabt ones and simd's and
    // relaxed's module lines), by a counter that reads the recordings alone
    // and never the reader (a Python script, not checked in), which gave
    // every number below:
    // - `-h`: the lines with ` start=0x`;
    // - `-x`: after `Section Details:`, the section titles and the entry
    //   lines (not a data dump's `  - ` lines, not `target_features`'
    //   `  - [`), plus 1, plus the data sections' ` - segment[` lines;
    // - `-d`: 1, plus 3 per ` func[` header, plus the `local[` lines; its
    //   instructions, the other lines with text after `|`;
    // - print: 1, plus 2 per `(func (;` definition, plus the locals of its
    //   `(local` lines (a reference type one local), plus the defined
    //   `(global` lines; its instructions, each definition's lines up to and
    //   with its closing `)`; its function types, every line with `(func (;`
    //   (imports too); its types, the type section's lines; its module lines,
    //   the `(table (;`, `(export "` and `(elem (;` lines.
    // refs and gc moved on 2026-10-20 with their new lines (refs 78 -> 82
    // instructions for both tools, gc 472 -> 480 for print), nothing else.
    const OD: &str = "wasm-objdump -d";
    const ODI: &str = "wasm-objdump -d, instructions";
    const OH: &str = "wasm-objdump -h";
    const OX: &str = "wasm-objdump -x";
    const P: &str = "wasm-tools print";
    const PF: &str = "wasm-tools print, function types";
    const PI: &str = "wasm-tools print, instructions";
    const PM: &str = "wasm-tools print, module";
    const PT: &str = "wasm-tools print, types";
    const COMPARED: [(&str, &[(&str, usize)]); 14] = [
        ("ctarget-O0", &[(OD, 104), (ODI, 942), (OH, 13), (OX, 184), (P, 130), (PF, 26), (PI, 942), (PM, 47), (PT, 13)]),
        ("ctarget-O2", &[(OD, 84), (ODI, 453), (OH, 13), (OX, 184), (P, 83), (PF, 26), (PI, 453), (PM, 47), (PT, 13)]),
        ("core", &[(OD, 16), (ODI, 771), (OH, 9), (OX, 39), (P, 13), (PF, 5), (PI, 771), (PM, 4), (PT, 4)]),
        ("simd", &[(OD, 4), (ODI, 855), (OH, 4), (OX, 9), (P, 3), (PF, 1), (PI, 855), (PT, 1)]),
        ("shapes", &[(OD, 14), (ODI, 69), (OH, 13), (OX, 113), (P, 15), (PF, 5), (PI, 69), (PM, 15), (PT, 4)]),
        ("threads", &[(OD, 19), (ODI, 367), (OH, 7), (OX, 56), (P, 13), (PF, 6), (PI, 367), (PM, 2), (PT, 4)]),
        ("refs", &[(OD, 29), (ODI, 82), (OH, 9), (OX, 90), (P, 24), (PF, 9), (PI, 82), (PM, 8), (PT, 4)]),
        ("gc", &[(P, 64), (PF, 9), (PI, 480), (PM, 3), (PT, 26)]),
        ("eh", &[(OD, 21), (ODI, 115), (OH, 7), (OX, 64), (P, 15), (PF, 6), (PI, 115), (PM, 2), (PT, 8)]),
        ("eh-legacy", &[(OD, 16), (ODI, 154), (OH, 6), (OX, 46), (P, 11), (PF, 5), (PI, 154), (PM, 1), (PT, 5)]),
        ("relaxed", &[(OD, 7), (ODI, 99), (OH, 4), (OX, 21), (P, 5), (PF, 2), (PI, 99), (PT, 1)]),
        ("cthreads-O2", &[(OD, 83), (ODI, 178), (OH, 12), (OX, 202), (P, 81), (PF, 27), (PI, 178), (PM, 51), (PT, 11)]),
        ("ceh-legacy-O2", &[(OD, 23), (ODI, 178), (OH, 11), (OX, 92), (P, 32), (PF, 12), (PI, 178), (PM, 23), (PT, 3)]),
        ("ceh-exnref-O2", &[(OD, 27), (ODI, 263), (OH, 11), (OX, 92), (P, 36), (PF, 12), (PI, 263), (PM, 23), (PT, 3)]),
    ];
    let stems: Vec<&str> = COMPARED.iter().map(|(stem, _)| *stem).collect();
    assert_eq!(stems, common::FIXTURES, "the fixtures of the table of comparisons");
    let wrong: Vec<String> = totals
        .iter()
        .zip(COMPARED)
        .filter_map(|((stem, counts), (_, expected))| {
            let counts: Vec<(&str, usize)> = counts.iter().map(|(r, n)| (*r, *n)).collect();
            (counts != expected).then(|| format!("{stem}:\n  counted  {counts:?}\n  expected {expected:?}"))
        })
        .collect();
    assert!(wrong.is_empty(), "comparisons per reference, per fixture:\n{}", wrong.join("\n"));
    // And what is not compared, so an absence cannot grow or vanish unseen
    // (12 global initial values of more than one instruction in gc: its
    // `(global` lines in gc.print.txt with two or more instructions; the
    // only tables with an initial value, `grep '(table' *.print.txt` shows,
    // are refs' two, `ref.null 1` and `ref.func 2`, of one instruction each).
    let not_compared_counts: Vec<(&str, usize)> = not_compared_counts.into_iter().collect();
    assert_eq!(
        not_compared_counts,
        [(NOT_LONG_DATA_OFFSETS, 0), (NOT_FUNCTION_SEGMENT_TYPES, 8), (NOT_PRODUCERS, 5), (NOT_TARGET_FEATURES, 43)],
        "not compared, all fixtures"
    );
    // Every place, the zeros too: a count that stays at zero is asserted to
    // be zero, so a fixture line that makes it grow must be looked at.
    let long_constants_seen: Vec<((bool, &str), usize)> = long_constants_seen.into_iter().collect();
    assert_eq!(
        long_constants_seen,
        [
            ((false, "data offsets"), 0),
            ((false, "element items"), 0),
            ((false, "element offsets"), 0),
            ((false, "global initial values"), 12),
            ((false, TABLE_INITS), 0),
            ((true, "data offsets"), 0),
            ((true, "element items"), 0),
            ((true, "element offsets"), 0),
            ((true, "global initial values"), 0),
            ((true, TABLE_INITS), 0),
        ],
        "constant expressions of more than one instruction, by whether wabt read the fixture"
    );
}

/// The long-constant count reads every place a constant expression stands:
/// planted, a table whose initial value is two instructions and one whose is
/// one. Every fixture's count of the tables' is 0, so without this the count
/// would never have been seen to be anything else. The bytes, `(table 1
/// i31ref (ref.i31 (i32.const 7)))` and `(table 1 i31ref (ref.null i31))`,
/// are valid: `wasm-tools validate --features all` accepts them (wasm-tools
/// 1.262.0, 2026-10-20).
#[test]
fn the_long_constant_count_reads_table_initial_values() {
    use common::planted::{module, section, vector};
    let long = vec![0x40, 0x00, 0x6c, 0x00, 0x01, 0x41, 0x07, 0xfb, 0x1c, 0x0b];
    let short = vec![0x40, 0x00, 0x6c, 0x00, 0x01, 0xd0, 0x6c, 0x0b];
    let m = n0xis_wasm::read(&module(&[section(4, &vector(&[long, short]))])).expect("reads");
    assert!(m.findings().is_empty(), "{:?}", m.findings());
    let counts = long_constants(&m);
    assert_eq!(counts.iter().find(|(what, _)| *what == TABLE_INITS), Some(&(TABLE_INITS, 1)), "{counts:?}");
    assert_eq!(counts.iter().map(|(_, n)| n).sum::<usize>(), 1, "{counts:?}");
}

/// The normalisers are part of the measurement: each must turn the tool's
/// spelling into the canonical one, checked on lines copied from the
/// recordings.
#[test]
fn the_normalisers_map_each_spelling_to_the_canonical_one() {
    assert_eq!(from_objdump("i32.const 4294967295"), "i32.const -1");
    assert_eq!(from_objdump("block type[1]"), "block (type 1)");
    assert_eq!(from_objdump("if i32"), "if (result i32)");
    assert_eq!(from_objdump("select externref"), "select (result externref)");
    assert_eq!(from_objdump("call_indirect 0 <tab> (type 0 <t>)"), "call_indirect 0 (type 0)");
    assert_eq!(from_objdump("i32.load 2 65560"), "i32.load offset=65560 align=4");
    assert_eq!(from_objdump("v128.load32_lane 2 2 4 3"), "v128.load32_lane 2 offset=4 align=4 3");
    assert_eq!(from_objdump("v128.load8_lane 0 1360 15"), "v128.load8_lane offset=1360 align=1 15");
    assert_eq!(from_objdump("memory.init 2 2 <second_data>"), "memory.init 2 2");
    assert_eq!(from_objdump("memory.init 1 0"), "memory.init 1");
    assert_eq!(from_objdump("table.init 1 0"), "table.init 0 1");
    assert_eq!(from_objdump("f32.const nan"), "f32.const nan:0x400000");
    assert_eq!(from_objdump("f64.const 0x1.p-1074"), "f64.const 0x1p-1074");
    assert_eq!(
        from_objdump("i8x16.shuffle 0x13021100 0x17061504 0x1b0a1908 0x1f0e1d0c"),
        "i8x16.shuffle 0 17 2 19 4 21 6 23 8 25 10 27 12 29 14 31"
    );
    assert_eq!(from_print("br_table 0 (;@3;) 1 (;@2;) 2 (;@1;) 1 (;@2;)"), "br_table 0 1 2 1");
    assert_eq!(from_print("if (type 1) (param i32) (result i32 i32) ;; label = @1"), "if (type 1)");
    assert_eq!(from_print("call_indirect (type 2)"), "call_indirect 0 (type 2)");
    assert_eq!(from_print("table.copy"), "table.copy 0 0");
    assert_eq!(from_print("table.init 1"), "table.init 0 1");
    assert_eq!(from_print("f32.const 0x1.8p+0 (;=1.5;)"), "f32.const 0x1.8p+0");
    assert_eq!(from_print("i64.load8_u 1"), "i64.load8_u 1 offset=0 align=1");
    assert_eq!(from_print("v128.load8x8_s offset=32"), "v128.load8x8_s offset=32 align=8");
    assert_eq!(from_print("v128.load64_lane offset=1408 0"), "v128.load64_lane offset=1408 align=8 0");
    assert_eq!(from_print("v128.load32_lane 2 offset=4 3"), "v128.load32_lane 2 offset=4 align=4 3");
    assert_eq!(from_print("i32.load16_s 2 offset=4"), "i32.load16_s 2 offset=4 align=2");

    // WebAssembly 3.0, threads and legacy exception handling, from the
    // recordings of the fixtures that hold them.
    assert_eq!(from_objdump("try i32"), "try (result i32)");
    assert_eq!(from_objdump("try type[4]"), "try (type 4)");
    assert_eq!(from_objdump("block (ref 1)"), "block (result (ref 1))");
    assert_eq!(from_objdump("select (ref null 1)"), "select (result (ref null 1))");
    assert_eq!(from_objdump("select (ref func)"), "select (result (ref func))");
    assert_eq!(from_objdump("try_table "), "try_table");
    assert_eq!(from_objdump("try_table catch_all  0"), "try_table (catch_all 0)");
    assert_eq!(from_objdump("try_table type[4] catch_all  0"), "try_table (type 4) (catch_all 0)");
    assert_eq!(
        from_objdump("try_table i32 catch 2 0 catch_ref 3 1 catch_all  2 catch_all_ref  3"),
        "try_table (result i32) (catch 2 0) (catch_ref 3 1) (catch_all 2) (catch_all_ref 3)"
    );
    assert_eq!(from_objdump("call_ref (ref null 1)"), "call_ref 1");
    assert_eq!(from_objdump("return_call_indirect 1 0"), "return_call_indirect 0 (type 1)");
    assert_eq!(from_objdump("atomic.fence 0"), "atomic.fence");
    assert_eq!(from_objdump("throw 0 <env.__cpp_exception>"), "throw 0");
    assert_eq!(from_objdump("memory.atomic.notify 2 0"), "memory.atomic.notify offset=0 align=4");
    assert_eq!(from_objdump("memory.atomic.notify 2 1 0"), "memory.atomic.notify 1 offset=0 align=4");
    assert_eq!(from_objdump("i64.atomic.rmw32.cmpxchg_u 2 384"), "i64.atomic.rmw32.cmpxchg_u offset=384 align=4");
    assert_eq!(from_objdump("i64.atomic.rmw32.cmpxchg_u 2 2 8"), "i64.atomic.rmw32.cmpxchg_u 2 offset=8 align=4");
    // What the tool says in place of an immediate stays visible.
    assert_eq!(from_objdump("ref.null <invalid>"), "ref.null <invalid>");
    assert_eq!(from_objdump("return_call_ref <invalid>"), "return_call_ref <invalid>");
    assert_eq!(from_print("try (type 4) (result i32 i64) ;; label = @1"), "try (type 4)");
    assert_eq!(from_print("try_table ;; label = @1"), "try_table");
    assert_eq!(from_print("try_table (catch_all_ref 0 (;@1;)) ;; label = @2"), "try_table (catch_all_ref 0)");
    assert_eq!(
        from_print("try_table (type 4) (param i32) (result i32) (catch_all 0 (;@1;)) ;; label = @2"),
        "try_table (type 4) (catch_all 0)"
    );
    assert_eq!(
        from_print("try_table (result i32) (catch 2 0 (;@4;)) (catch_ref 3 1 (;@3;)) (catch_all 2 (;@2;)) (catch_all_ref 3 (;@1;)) ;; label = @5"),
        "try_table (result i32) (catch 2 0) (catch_ref 3 1) (catch_all 2) (catch_all_ref 3)"
    );
    assert_eq!(from_print("delegate 0 (;@1;)"), "delegate 0");
    assert_eq!(from_print("br_on_cast 1 (;@1;) anyref (ref null 0)"), "br_on_cast 1 anyref (ref null 0)");
    assert_eq!(from_print("return_call_indirect (type 1)"), "return_call_indirect 0 (type 1)");
    assert_eq!(from_print("return_call_indirect 1 (type 1)"), "return_call_indirect 1 (type 1)");
    assert_eq!(from_print("memory.atomic.notify"), "memory.atomic.notify offset=0 align=4");
    assert_eq!(from_print("memory.atomic.wait64 1 offset=4294967304"), "memory.atomic.wait64 1 offset=4294967304 align=8");
    assert_eq!(from_print("i64.atomic.rmw.cmpxchg offset=344"), "i64.atomic.rmw.cmpxchg offset=344 align=8");
    assert_eq!(from_print("atomic.fence"), "atomic.fence");

    // The module-level lines of `wasm-tools print`.
    assert_eq!(operands("(ref null 1) (ref 1) (ref func) (ref extern)"), ["(ref null 1)", "(ref 1)", "(ref func)", "(ref extern)"]);
    assert_eq!(operands("i32 (mut (ref null 0)) f32"), ["i32", "(mut (ref null 0))", "f32"]);
    assert_eq!(global_value("0;) (mut (ref null 1)) ref.null 1)"), "ref.null 1");
    assert_eq!(global_value("14;) (ref 2) i32.const 5 ref.null 0 ref.null 1 ref.null 1 i64.const 9 struct.new 2)"), "i32.const 5 ref.null 0 ref.null 1 ref.null 1 i64.const 9 struct.new 2");
    assert_eq!(global_value("0;) (mut i32) i32.const 65536)"), "i32.const 65536");
    assert_eq!(global_value("1;) i64 i64.const 6 i64.const 7 i64.mul)"), "i64.const 6 i64.const 7 i64.mul");
    let gc_types = "(module\n\
                    (;@c     ;)  (rec)\n\
                    (;@e     ;)  (rec\n\
                    (;@10    ;)    (type (;0;) (sub (struct (field i32) (field (mut (ref null 0))))))\n             )\n\
                    (;@3f    ;)  (type (;4;) (array (mut i8)))\n\
                    (;@189   ;)  (elem (;0;) funcref (ref.func 7) (ref.null func))\n";
    assert_eq!(
        parse_print_types(gc_types),
        ["(rec)", "(rec", "(type (;0;) (sub (struct (field i32) (field (mut (ref null 0))))))", ")", "(type (;4;) (array (mut i8)))"]
    );
    assert_eq!(parse_print_module_lines(gc_types), ["(elem (;0;) funcref (ref.func 7) (ref.null func))"]);
    assert_eq!(
        wabt_refusal("000000d: error: unexpected type form (got -0x32)\n0000114: error: invalid global type: 0xffffffec\nexit status 1\n"),
        "unexpected type form (got -0x32)"
    );
}
