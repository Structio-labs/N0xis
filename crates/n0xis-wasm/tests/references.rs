// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **What the reader says about every fixture is what two independent tools
//! say**, from the recordings `fixtures/build.sh` made with them:
//!
//! - wabt's `wasm-objdump -h` (sections: kind, contents range, count),
//!   `-x` (every entry of every section, the name section) and `-d` (every
//!   body: locals and every instruction with its offset);
//! - `wasm-tools print -p` of a copy without custom sections (every body
//!   again, offsets and instructions, and every global's initial value).
//!
//! Section details are compared by rendering this crate's facts in
//! `wasm-objdump`'s own spelling and comparing line by line. Instructions are
//! compared the other way: each tool's spelling is normalised into this
//! crate's canonical one (`src/instr.rs`) and compared with the decoder's
//! rendering, offset by offset.
//!
//! The comparison must find exactly the disagreements in [`EXPLAINED`], each
//! with its reason and a third source that settles it: a new disagreement
//! fails, and so does an explained one that has gone away.

mod common;

use std::collections::BTreeMap;
use std::fmt::Write as _;

use n0xis_wasm::{
    DataMode, ElementItems, ElementMode, ExportItem, FuncOrigin, GlobalOrigin, ImportItem, Instr, Limits, Located,
    Module, Origin, SectionKind, ValType,
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

/// The natural alignment of a memory access, in bytes, from its name: the
/// width the name states (`i64.load16_u`: 2, `v128.load8x8_s`: 8).
fn natural_align(name: &str) -> u64 {
    let (ty, op) = name.split_once('.').expect("a typed memory instruction");
    let digits: String = op.chars().skip_while(|c| !c.is_ascii_digit()).take_while(|c| c.is_ascii_digit()).collect();
    if op.contains('x') && ty == "v128" {
        return 8; // v128.loadNxM_s/u reads 64 bits
    }
    let bits: u64 = if digits.is_empty() { ty[1..].parse().expect("a width") } else { digits.parse().unwrap() };
    bits / 8
}

fn is_memory_access(name: &str) -> bool {
    name.contains(".load") || name.contains(".store")
}

// ---------------------------------------------------------------------------
// wasm-objdump -d

/// `wasm-objdump -d`'s instruction text, in the canonical spelling.
fn from_objdump(text: &str) -> String {
    // Names are annotations: `call 3 <add>`, `local.get 0 <p>`.
    let mut plain = String::new();
    let mut depth = 0;
    for c in text.chars() {
        match c {
            '<' => depth += 1,
            '>' if depth > 0 => depth -= 1,
            _ if depth == 0 => plain.push(c),
            _ => {}
        }
    }
    // `(type 0 <t>)` leaves `(type 0 )` behind.
    let plain = plain.replace(" )", ")");
    let words: Vec<&str> = plain.split_whitespace().collect();
    let (name, args) = (words[0], &words[1..]);
    match (name, args) {
        ("block" | "loop" | "if", [t]) => match t.strip_prefix("type[").and_then(|t| t.strip_suffix(']')) {
            Some(index) => format!("{name} (type {index})"),
            None => format!("{name} (result {t})"),
        },
        ("select", [t]) => format!("select (result {t})"),
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
fn compare_instructions(
    report: &mut Report,
    reference: &'static str,
    func: u32,
    ours: &[Located],
    theirs: &[(usize, String)],
) {
    let theirs: BTreeMap<usize, &String> = theirs.iter().map(|(o, t)| (*o, t)).collect();
    let mine: BTreeMap<usize, String> = ours.iter().map(|l| (l.offset, l.instr.to_string())).collect();
    for (offset, text) in &mine {
        *report.compared.entry(if reference == "wasm-objdump -d" { "wasm-objdump -d, instructions" } else { "wasm-tools print, instructions" }).or_default() += 1;
        match theirs.get(offset) {
            Some(t) if *t == text => {}
            Some(t) => report.differ(reference, format!("func {func} at {offset:#x}"), text, t),
            None => report.differ(reference, format!("func {func} at {offset:#x}"), text, "(no instruction here)"),
        }
    }
    for (offset, text) in theirs {
        if !mine.contains_key(&offset) {
            report.differ(reference, format!("func {func} at {offset:#x}"), "(no instruction here)", text);
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
    let words: Vec<&str> = plain.split_whitespace().collect();
    let (name, args) = (words[0], &words[1..]);
    match (name, args) {
        // `block (type 1) (param i32) (result i32 i32)`: the index is the immediate.
        ("block" | "loop" | "if", ["(type", index, ..]) => format!("{name} (type {index}"),
        ("call_indirect", ["(type", ..]) => format!("call_indirect 0 {}", args.join(" ")),
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
            f.locals.extend(locals.trim_end_matches(')').split_whitespace().map(str::to_string));
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
    }
}

fn section_count(m: &Module, kind: &SectionKind) -> Option<usize> {
    let defined = |origins: &mut dyn Iterator<Item = bool>| origins.filter(|d| *d).count();
    Some(match kind {
        SectionKind::Type => m.types().len(),
        SectionKind::Import => m.imports().len(),
        SectionKind::Function => m.bodies().len(),
        SectionKind::Table => defined(&mut m.tables().iter().map(|t| t.origin == Origin::Defined)),
        SectionKind::Memory => defined(&mut m.memories().iter().map(|t| t.origin == Origin::Defined)),
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

/// A constant expression as `wasm-objdump -x` writes an initial value.
fn init_text(m: &Module, expr: &[Located]) -> String {
    match expr.first().map(|l| &l.instr) {
        Some(Instr::I32Const(v)) => format!("i32={v}"),
        Some(Instr::I64Const(v)) => format!("i64={v}"),
        Some(Instr::RefFunc(f)) => format!("ref.func:{f}{}", func_name(m, f.0)),
        Some(Instr::RefNull(t)) => format!("ref.null {t}"),
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
                    let results = match t.results.len() {
                        0 => "nil".to_string(),
                        1 => t.results[0].to_string(),
                        _ => format!("({})", types(&t.results)),
                    };
                    lines.push(format!(" - type[{i}] ({}) -> {results}", types(&t.params)));
                }
            }
            SectionKind::Import => {
                let (mut f, mut t, mut mem, mut g) = (0, 0, 0, 0);
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
                        ImportItem::Memory(l) => {
                            mem += 1;
                            format!(" - memory[{}] pages: {} {from}", mem - 1, limits_text(&l))
                        }
                        ImportItem::Global(gt) => {
                            g += 1;
                            format!(" - global[{}] {} mutable={} {from}", g - 1, gt.ty, u8::from(gt.mutable))
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
                for (i, t) in m.tables().iter().enumerate().filter(|(_, t)| t.origin == Origin::Defined) {
                    let wide = if t.ty.limits.address == n0xis_wasm::AddressType::I64 { " i64" } else { "" };
                    let name = named(names.tables.get(&n0xis_wasm::TableIdx(i as u32)));
                    lines.push(format!(" - table[{i}] type={} {}{name}{wide}", t.ty.element, limits_text(&t.ty.limits)));
                }
            }
            SectionKind::Memory => {
                for (i, mm) in m.memories().iter().enumerate().filter(|(_, mm)| mm.origin == Origin::Defined) {
                    let wide = if mm.limits.address == n0xis_wasm::AddressType::I64 { " i64" } else { "" };
                    lines.push(format!(" - memory[{i}] pages: {}{wide}", limits_text(&mm.limits)));
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
/// custom sections this crate does not read (`target_features`).
///
/// The tool numbers the elements of a passive or declarative segment from
/// where the previous segment's left off, which is no fact about the segment;
/// that number is read as `?`, as [`details`] writes it.
fn parse_details(text: &str) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
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
            // A `target_features` entry.
        } else {
            out.last_mut().expect("a line before any section").1.push(line.to_string());
        }
    }
    out
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

#[derive(Default)]
struct Report {
    fixture: String,
    compared: BTreeMap<&'static str, usize>,
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

#[test]
fn every_fixture_reads_as_the_independent_tools_read_it() {
    let mut found = Vec::new();
    let mut totals: Vec<(String, BTreeMap<&'static str, usize>)> = Vec::new();
    for stem in common::FIXTURES {
        let m = common::module(stem);
        assert!(m.findings().is_empty(), "{stem}: {:?}", m.findings());
        let recorded = |what: &str| common::text(&format!("{stem}.{what}.txt"));
        let mut report = Report { fixture: stem.to_string(), ..Default::default() };

        // Sections.
        let theirs: Vec<String> = recorded("headers")
            .lines()
            .filter(|l| l.contains(" start=0x"))
            .map(str::to_string)
            .collect();
        assert!(!theirs.is_empty(), "{stem}: no section in the recording");
        report.lines("wasm-objdump -h", "sections", &headers(&m), &theirs);

        // Every entry of every section.
        let theirs = parse_details(&recorded("details"));
        let ours = details(&m);
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

        // Every body, both tools.
        let bodies = common::bodies(&m);
        let objdump = parse_objdump_disassembly(&recorded("disassembly"));
        let print = parse_print_functions(&recorded("print"));
        *report.compared.entry("wasm-objdump -d").or_default() += 1;
        *report.compared.entry("wasm-tools print").or_default() += 1;
        if objdump.len() != bodies.len() {
            report.differ("wasm-objdump -d", "functions".into(), &bodies.len().to_string(), &objdump.len().to_string());
        }
        if print.len() != bodies.len() {
            report.differ("wasm-tools print", "functions".into(), &bodies.len().to_string(), &print.len().to_string());
        }
        for ((func, body), (od, pr)) in bodies.iter().zip(objdump.iter().zip(&print)) {
            let params = m.types()[m.function(*func).unwrap().ty.0 as usize].params.len();
            let at = format!("func {}", func.0);
            let header = |start: usize, f: u32| format!("func {f} at {start:#x}");
            report.lines("wasm-objdump -d", &at, &[header(body.range.start, func.0)], &[header(od.start, od.func)]);
            report.lines("wasm-tools print", &at, &[header(body.range.start, func.0)], &[header(pr.start, pr.func)]);
            let name = m.names().and_then(|n| n.functions.get(func)).cloned();
            report.lines("wasm-objdump -d", &format!("{at} name"), &[format!("{name:?}")], &[format!("{:?}", od.name)]);
            report.lines("wasm-objdump -d", &format!("{at} locals"), &objdump_locals(params, body), &od.locals);
            let expanded: Vec<String> = body
                .locals
                .iter()
                .flat_map(|run| std::iter::repeat_n(run.ty.to_string(), run.count as usize))
                .collect();
            report.lines("wasm-tools print", &format!("{at} locals"), &expanded, &pr.locals);
            compare_instructions(&mut report, "wasm-objdump -d", func.0, &body.instructions, &od.instructions);
            compare_instructions(&mut report, "wasm-tools print", func.0, &body.instructions, &pr.instructions);
        }

        // Every global's initial value, as wasm-tools prints it.
        let print_text = recorded("print");
        let printed: Vec<String> = print_text
            .lines()
            .filter_map(print_line)
            .filter_map(|(_, t)| t.strip_prefix("(global (;"))
            .filter(|t| !t.contains("(import"))
            .map(|t| {
                let t = t.split_once(";)").unwrap().1.trim().trim_end_matches(')');
                // `(mut i32) i32.const 0` or `i32 i32.const 0`: the type, then the value.
                let value = if let Some(rest) = t.strip_prefix("(mut ") { rest.split_once(") ").unwrap().1 } else { t.split_once(' ').unwrap().1 };
                from_print(value)
            })
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
    eprintln!("all fixtures: {all:?}");
    eprintln!(
        "{} comparisons, {} disagreements, {} explained",
        all.values().sum::<usize>(),
        found.len(),
        found.len() - unexplained.len()
    );
    assert!(unexplained.is_empty(), "{} unexplained disagreements:\n{unexplained:#?}", unexplained.len());
    assert!(gone.is_empty(), "explained disagreements no longer found (remove them from EXPLAINED):\n{gone:#?}");
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
}
