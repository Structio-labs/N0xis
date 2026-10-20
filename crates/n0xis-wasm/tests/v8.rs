// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **What the reader says about every fixture is what V8 says**, from the
//! recordings `fixtures/build.sh` made with `v8dis.mjs`: V8's own disassembly
//! of the stripped copy of each module (`<stem>.v8.txt`), every line prefixed
//! with the byte offset V8 gives it. V8 is a third reader of the format,
//! independent of wabt and wasm-tools (`tests/references.rs`), and the one a
//! browser runs.
//!
//! Every instruction of every body is compared at its offset with the
//! decoder's instruction at that offset. V8 writes indices as names it makes
//! up (`$func3`, `$var0`, `$label1`) or takes from an export or an import
//! (`$multi`, `$env.failure`); each is turned back into an index from V8's own
//! text, never from this crate's facts:
//!
//! - functions, tables, memories, globals, tags and element segments: by the
//!   order of V8's declaration lines of that kind (imports first, as the index
//!   space has them); where a line also states the index (`(;3;)`) or the
//!   name is V8's numbered one (`$func3`), the two must agree, or the test
//!   fails before it compares anything;
//! - locals: by the order of the function's `(param $varN ..)` and
//!   `(local $varN ..)` lines; structure fields: by the order of the
//!   `(field $fieldN ..)` entries of the type's declaration;
//! - types: by V8's name `$typeN` itself, because V8 declares no function
//!   type, so a declaration order would skip them;
//! - labels: by tracking the blocks open at each line (`block`, `loop`, `if`,
//!   `try`, `try_table` open one, labelled or not; `end` and `delegate` close
//!   one), so a label is the depth of the block V8 named.
//!
//! A memory or table operand V8 leaves out is compared as index 0, in a module
//! of several memories or tables as in one: V8 leaves out exactly an index
//! that is 0, measured on a probe of three of each ([`instruction`]).
//!
//! Then V8's spelling is normalised into this crate's canonical one
//! (`src/instr.rs`) where the line alone suffices; where V8 prints something
//! only the module knows, this crate's instruction is written in V8's terms
//! instead: a block type, or the type of `call_indirect` and
//! `return_call_indirect`, as the signature it names (`(param i32) (result
//! i32)`), and float constants, which V8 writes in decimal, as their bits.
//!
//! Module-level facts compared with V8, each from V8's declaration lines:
//! every function's import, exports, signature and body offset, and every
//! defined function's locals; every table's import, exports, limits and
//! element type; every memory's import, exports, limits and `shared`; every
//! global's import, exports, type, mutability and initial value; every tag's
//! import, exports and signature; every element segment's mode, table,
//! offset, element type and items; every data segment's mode, offset and
//! bytes; the start function; every structure and array type, with its
//! finality and supertypes; and the recursion groups.
//!
//! **Not compared with V8, and why** (each is counted, per fixture and per
//! kind, and the counts must be exactly those of [`NOT_COMPARED`], so an
//! absence is reported and a change in it fails):
//!
//! - the memory index of a load, a store or an atomic instruction: V8 prints
//!   none (`i32.load offset=4294967300` for the fixture text's
//!   `i32.load 1 offset=4294967300 align=4`, `shapes.wat`); the other fields
//!   of the memory argument are compared;
//! - function types: V8 declares none, so a function type is compared only
//!   through the signatures that name it, and its finality, supertypes and
//!   type index not at all;
//! - the type index of a function, a tag, a block or an indirect call: V8
//!   writes the signature it names, so two types of one signature (`gc.wat`'s
//!   12 and 13) are interchangeable here (`tests/references.rs` compares the
//!   index with wasm-tools print);
//! - a table's initial value (the `0x40 0x00` table form): V8 prints none;
//! - the address type of a 64-bit memory or table: V8 prints no `i64`;
//! - the memory of a data segment: V8 prints none;
//! - where an element segment's items begin and end: V8 writes each item as
//!   one parenthesised instruction, so the items are compared as the sequence
//!   of their instructions;
//! - names and every custom section: V8 reads a stripped copy.
//!
//! The comparison must find exactly the disagreements in [`EXPLAINED`], each
//! with the third source that settles it: a new disagreement fails, and so
//! does an explained one that has gone away.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use common::memarg::{is_memory_access, natural_align};

use n0xis_wasm::{
    AddressType, BlockType, Catch, CompositeType, DataMode, ElementItems, ElementMode, ExportItem, FuncOrigin, FuncType,
    GlobalOrigin, Ieee32, Ieee64, Instr, Located, Module, Origin, TableOrigin,
};

/// One line on which the reader and V8 differ.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Disagreement {
    fixture: String,
    at: String,
    ours: String,
    theirs: String,
}

/// Every disagreement the comparison finds, with the source that settles it.
/// Fields: fixture, where, ours, theirs, why.
const EXPLAINED: &[(&str, &str, &str, &str, &str)] = &[
    (
        "gc",
        "type 0",
        "(sub (struct (field i32) (field (mut (ref null 0)))))",
        "(struct (field i32) (field (mut (ref null 0))))",
        "V8 prints a non-final type with no supertype as a final one (no `sub`). The text states \
         `(type $node (sub (struct ...)))` (gc.wat), the bytes encode it with 0x50 0x00, and \
         wasm-tools print reads `(sub (struct ...))`; type 1 declares it as its supertype, which \
         only a non-final type may be.",
    ),
    (
        "eh-legacy",
        "func 2 at 0xe2",
        "delegate 2",
        "delegate $label1?",
        "V8 names a label that is not open here: `$label1` is the block that ended at 0xd6. The \
         text states `delegate 2` (eh-legacy.wat, function $delegates: the function's own label, \
         seen from outside the `try` inside a `try` inside a `block`), and wasm-tools print and \
         wasm-objdump both read `delegate 2`.",
    ),
    (
        "eh-legacy",
        "func 2 at 0xee",
        "delegate 0",
        "delegate $label2?",
        "V8 names a label that is not open here: `$label2` is the block that ended at 0xe6. The \
         text states `delegate 0` (eh-legacy.wat, function $delegates: a `try` at the top level \
         delegating to the function's own label), and wasm-tools print and wasm-objdump both \
         read `delegate 0`.",
    ),
];

// The kinds of fact a module has that V8 does not print, each the key it is
// counted under in a report and in [`NOT_COMPARED`].
const FUNCTION_TYPES: &str = "function types (V8 declares none)";
const TYPE_INDICES: &str = "type indices of functions, tags, blocks and indirect calls (V8 writes the signature)";
const ACCESS_MEMORIES: &str = "memory indices of memory accesses (V8 prints none)";
const ADDRESS_TYPES: &str = "64-bit address types (V8 prints no i64)";
const TABLE_INITS: &str = "table initial values (V8 prints none)";
const DATA_MEMORIES: &str = "data segment memory indices (V8 prints none)";

/// How many facts of each kind every fixture V8 disassembles has that V8
/// does not print: a ratchet, measured with the recordings of `build.sh`. A
/// count that falls is as much a failure as one that rises: a reader that
/// lost every multi-memory index of a memory access, or read every 64-bit
/// memory as a 32-bit one, would agree with V8 on every line it prints and
/// show only here (33 to 0 and 3 to 0).
///
/// The counts of what is compared are printed and not asserted: every
/// compared fact is compared one by one, a missing one as a disagreement
/// (`(no instruction here)`, `(none)`), so a count adds nothing a reader
/// could lose silently, except that a fixture could gain or lose facts V8
/// prints with the reader agreeing on all of them.
///
/// Checked against wasm-tools print (`<stem>.print.txt`), not this file's
/// own counting: the type indices are the functions and tags it declares plus
/// its `(type N)` on a `block`, `loop`, `if`, `try`, `try_table`,
/// `call_indirect` or `return_call_indirect` line; the memory indices of
/// accesses its loads, stores and atomics with a memory index; the function
/// types its `(func` types; the address types its memories and tables
/// declared `i64`; the table initial values its defined tables with an
/// expression after the element type; the data segment memories its active
/// segments on a memory other than 0.
const NOT_COMPARED: &[(&str, &[(&str, usize)])] = &[
    ("ctarget-O0", &[(FUNCTION_TYPES, 13), (TYPE_INDICES, 27)]),
    ("ctarget-O2", &[(FUNCTION_TYPES, 13), (TYPE_INDICES, 28)]),
    ("core", &[(FUNCTION_TYPES, 4), (TYPE_INDICES, 8)]),
    ("simd", &[(FUNCTION_TYPES, 1), (TYPE_INDICES, 1)]),
    (
        "shapes",
        &[
            (FUNCTION_TYPES, 4),
            (TYPE_INDICES, 6),
            (ACCESS_MEMORIES, 7),
            (ADDRESS_TYPES, 2),
            (DATA_MEMORIES, 2),
        ],
    ),
    ("threads", &[(FUNCTION_TYPES, 4), (TYPE_INDICES, 6), (ACCESS_MEMORIES, 26), (ADDRESS_TYPES, 1)]),
    ("refs", &[(FUNCTION_TYPES, 4), (TYPE_INDICES, 11), (TABLE_INITS, 2)]),
    ("gc", &[(FUNCTION_TYPES, 9), (TYPE_INDICES, 9)]),
    ("eh", &[(FUNCTION_TYPES, 8), (TYPE_INDICES, 14)]),
    ("eh-legacy", &[(FUNCTION_TYPES, 5), (TYPE_INDICES, 10)]),
    ("relaxed", &[(FUNCTION_TYPES, 1), (TYPE_INDICES, 2)]),
    ("cthreads-O2", &[(FUNCTION_TYPES, 11), (TYPE_INDICES, 27)]),
    ("ceh-legacy-O2", &[(FUNCTION_TYPES, 3), (TYPE_INDICES, 13)]),
    ("ceh-exnref-O2", &[(FUNCTION_TYPES, 3), (TYPE_INDICES, 13)]),
];

/// V8 14.6 prints six relaxed SIMD opcodes under the names they had in the
/// proposal's drafts; the proposal's own opcode table (the relaxed SIMD
/// Overview, 0xFD 0x105 to 0x108, 0x112, 0x113) and the 3.0 text format use
/// the second name, and wasm-tools and wabt print it at the same offsets.
const DRAFT_NAMES: [(&str, &str); 6] = [
    ("f32x4.qfma", "f32x4.relaxed_madd"),
    ("f32x4.qfms", "f32x4.relaxed_nmadd"),
    ("f64x2.qfma", "f64x2.relaxed_madd"),
    ("f64x2.qfms", "f64x2.relaxed_nmadd"),
    ("i16x8.dot_i8x16_i7x16_s", "i16x8.relaxed_dot_i8x16_i7x16_s"),
    ("i32x4.dot_i8x16_i7x16_add_s", "i32x4.relaxed_dot_i8x16_i7x16_add_s"),
];

/// The 3.0 text format's abbreviations of a nullable reference to an abstract
/// heap type ("Reference Types", text format), for V8 writing the long form.
const ABBREVIATIONS: [(&str, &str); 12] = [
    ("func", "funcref"),
    ("nofunc", "nullfuncref"),
    ("extern", "externref"),
    ("noextern", "nullexternref"),
    ("any", "anyref"),
    ("eq", "eqref"),
    ("i31", "i31ref"),
    ("struct", "structref"),
    ("array", "arrayref"),
    ("none", "nullref"),
    ("exn", "exnref"),
    ("noexn", "nullexnref"),
];

// ---------------------------------------------------------------------------
// V8's text as S-expressions.

/// One item of V8's text.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Sx {
    Atom(String),
    Str(Vec<u8>),
    /// `(;3;)`: the index V8 writes after a name that does not state it.
    Index(u32),
    List(Vec<Sx>),
}

impl Sx {
    fn atom(&self) -> Option<&str> {
        match self {
            Sx::Atom(a) => Some(a),
            _ => None,
        }
    }

    fn list(&self) -> Option<&[Sx]> {
        match self {
            Sx::List(l) => Some(l),
            _ => None,
        }
    }

    /// The first word of a list: `param` for `(param i32)`.
    fn head(&self) -> Option<&str> {
        self.list()?.first()?.atom()
    }

    /// A list whose first word names an instruction (`(i32.const 0)`,
    /// `(ref.func $f)`), not a type (`(ref null $type0)`) or a clause.
    fn is_instruction(&self) -> bool {
        self.head().is_some_and(|h| h.contains('.'))
    }
}

enum Token {
    Open,
    Close,
    Item(Sx),
}

/// One escape of a string, after its backslash: the byte and how many bytes
/// the escape took. The text format's escapes; V8 writes `\hh` for anything
/// it does not print as itself.
fn escape(rest: &[u8], text: &str) -> (u8, usize) {
    match rest {
        [b'n', ..] => (b'\n', 1),
        [b't', ..] => (b'\t', 1),
        [b'r', ..] => (b'\r', 1),
        [b'"', ..] => (b'"', 1),
        [b'\'', ..] => (b'\'', 1),
        [b'\\', ..] => (b'\\', 1),
        [h, l, ..] if h.is_ascii_hexdigit() && l.is_ascii_hexdigit() => {
            (u8::from_str_radix(std::str::from_utf8(&[*h, *l]).unwrap(), 16).unwrap(), 2)
        }
        _ => panic!("an escape no recording has shown: {text}"),
    }
}

fn tokens(text: &str) -> Vec<Token> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b' ' => i += 1,
            b'(' if bytes.get(i + 1) == Some(&b';') => {
                let close = i + text[i..].find(";)").unwrap_or_else(|| panic!("an unclosed comment: {text}"));
                let n = text[i + 2..close].parse().unwrap_or_else(|_| panic!("a comment that is no index: {text}"));
                out.push(Token::Item(Sx::Index(n)));
                i = close + 2;
            }
            b'(' => {
                out.push(Token::Open);
                i += 1;
            }
            b')' => {
                out.push(Token::Close);
                i += 1;
            }
            b'"' => {
                let mut s = Vec::new();
                i += 1;
                loop {
                    match bytes.get(i) {
                        None => panic!("an unclosed string: {text}"),
                        Some(b'"') => break,
                        Some(b'\\') => {
                            let (b, n) = escape(&bytes[i + 1..], text);
                            s.push(b);
                            i += 1 + n;
                        }
                        Some(&b) => {
                            s.push(b);
                            i += 1;
                        }
                    }
                }
                i += 1;
                out.push(Token::Item(Sx::Str(s)));
            }
            _ => {
                let start = i;
                while i < bytes.len() && !matches!(bytes[i], b' ' | b'(' | b')' | b'"') {
                    i += 1;
                }
                out.push(Token::Item(Sx::Atom(text[start..i].to_string())));
            }
        }
    }
    out
}

/// How many more parentheses the text opens than it closes (strings and
/// index comments excepted).
fn depth(text: &str) -> i64 {
    tokens(text)
        .iter()
        .map(|t| match t {
            Token::Open => 1,
            Token::Close => -1,
            Token::Item(_) => 0,
        })
        .sum()
}

/// The items of a balanced text, in order.
fn sexprs(text: &str) -> Vec<Sx> {
    let mut stack: Vec<Vec<Sx>> = vec![Vec::new()];
    for t in tokens(text) {
        match t {
            Token::Open => stack.push(Vec::new()),
            Token::Close => {
                let list = stack.pop().unwrap();
                stack.last_mut().unwrap_or_else(|| panic!("unbalanced: {text}")).push(Sx::List(list));
            }
            Token::Item(s) => stack.last_mut().unwrap().push(s),
        }
    }
    assert_eq!(stack.len(), 1, "unbalanced: {text}");
    stack.pop().unwrap()
}

/// A line of a recording: `OFFSET: text`, the text indented two spaces a level.
struct Line<'a> {
    offset: usize,
    indent: usize,
    text: &'a str,
}

fn v8_lines(recording: &str) -> Vec<Line<'_>> {
    recording
        .lines()
        .map(|l| {
            let (offset, rest) = l.split_once(": ").unwrap_or_else(|| panic!("not `OFFSET: text`: {l:?}"));
            let text = rest.trim_start_matches(' ');
            Line {
                offset: usize::from_str_radix(offset, 16).unwrap_or_else(|_| panic!("not a hex offset: {l:?}")),
                indent: rest.len() - text.len(),
                text,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// V8's names, from V8's declaration lines.

/// What each name V8 writes stands for.
#[derive(Default)]
struct Names {
    /// Kind (`func`, `table`, `memory`, `global`, `tag`, `elem`) to name to index.
    spaces: HashMap<&'static str, HashMap<String, u32>>,
    /// Type index to field name to field index, from the type's declaration.
    fields: HashMap<u32, HashMap<String, u32>>,
}

impl Names {
    /// Record that V8's declaration line number `index` of `kind` is `name`;
    /// `comment` is the `(;N;)` it writes, if any. V8's own statements of the
    /// index must agree with the order: this is the join's self-check.
    fn declare(&mut self, kind: &'static str, name: Option<&str>, comment: Option<u32>, index: u32) {
        if let Some(n) = comment {
            assert_eq!(n, index, "V8 writes (;{n};) on its declaration {index} of a {kind}");
        }
        let Some(name) = name else { return };
        if let Some(n) = name.strip_prefix('$').and_then(|n| n.strip_prefix(kind)).and_then(|n| n.parse::<u32>().ok()) {
            assert_eq!(n, index, "V8 names its declaration {index} of a {kind} {name}");
        }
        let previous = self.spaces.entry(kind).or_default().insert(name.to_string(), index);
        assert!(previous.is_none(), "V8 declares two of a {kind} named {name}");
    }

    fn index(&self, kind: &str, name: &str) -> Option<u32> {
        self.spaces.get(kind)?.get(name).copied()
    }
}

/// A type index from V8's name for it. V8 declares no function type, so its
/// names `$typeN` are the only statement of a function type's index.
fn type_index(name: &str) -> Option<u32> {
    name.strip_prefix("$type")?.parse().ok()
}

/// The index a name stands for, or the name marked unresolved: a name that
/// resolves to nothing must show up as a disagreement, not vanish.
fn named(names: &Names, kind: &str, item: &Sx) -> String {
    let name = item.atom().unwrap_or_else(|| panic!("a {kind} name, not {item:?}"));
    match names.index(kind, name) {
        Some(i) => i.to_string(),
        None => format!("{name}?"),
    }
}

fn type_named(item: &Sx) -> String {
    let name = item.atom().unwrap_or_else(|| panic!("a type name, not {item:?}"));
    type_index(name).map_or_else(|| format!("{name}?"), |i| i.to_string())
}

// ---------------------------------------------------------------------------
// Types.

/// A heap type: an abstract name as is, `$type3` as `3`.
fn heap_type(item: &Sx) -> String {
    match item.atom() {
        Some(a) if a.starts_with('$') => type_named(item),
        Some(a) => a.to_string(),
        None => panic!("a heap type, not {item:?}"),
    }
}

/// A reference type in the canonical spelling, from its nullability and V8's
/// heap type.
fn ref_type(nullable: bool, heap: &Sx) -> String {
    let heap = heap_type(heap);
    match (nullable, ABBREVIATIONS.iter().find(|(h, _)| *h == heap)) {
        (true, Some((_, abbreviation))) => abbreviation.to_string(),
        (true, None) => format!("(ref null {heap})"),
        (false, _) => format!("(ref {heap})"),
    }
}

/// A value type: `i32`, `anyref`, `(ref null $type1)`.
fn val_type(item: &Sx) -> String {
    match item {
        Sx::Atom(a) if !a.starts_with('$') => a.clone(),
        Sx::List(l) if item.head() == Some("ref") => match &l[1..] {
            [Sx::Atom(null), heap] if null == "null" => ref_type(true, heap),
            [heap] => ref_type(false, heap),
            _ => panic!("a reference type no recording has shown: {item:?}"),
        },
        _ => panic!("a value type, not {item:?}"),
    }
}

/// A field's storage type, mutable or not: `i8`, `(mut (ref null 0))`.
fn storage_type(item: &Sx) -> String {
    match (item.head(), item.list()) {
        (Some("mut"), Some([_, ty])) if ty.head() != Some("mut") => format!("(mut {})", storage_type(ty)),
        (Some("mut"), _) => panic!("a mutable storage type no recording has shown: {item:?}"),
        _ => val_type(item),
    }
}

/// `(param ..)` and `(result ..)` as one parenthesised group each, as this
/// crate writes a signature; nothing for an empty one.
fn signature(params: &[String], results: &[String]) -> String {
    let mut s = String::new();
    if !params.is_empty() {
        write!(s, " (param {})", params.join(" ")).unwrap();
    }
    if !results.is_empty() {
        write!(s, " (result {})", results.join(" ")).unwrap();
    }
    s
}

/// The `(param ..)` and `(result ..)` groups at the start of `items`, however
/// V8 groups them (`(param $var0 i32) (param $var1 i64)`, `(param i32 i64)`),
/// as [`signature`] writes them; and the items after them, which every
/// caller must read or refuse. A named parameter has one type, and no
/// parameter follows a result: any other group is no signature V8 has
/// written, and fails.
fn v8_signature(items: &[Sx]) -> (String, &[Sx]) {
    let (mut params, mut results) = (Vec::new(), Vec::new());
    let mut used = 0;
    for item in items {
        let (Some(kind), Some([_, group @ ..])) = (item.head(), item.list()) else { break };
        match (kind, group) {
            ("param", _) if !results.is_empty() => panic!("a parameter after a result: {items:?}"),
            // A parameter's name (`$var0`) is no type.
            ("param", [Sx::Atom(name), ty]) if name.starts_with('$') => params.push(val_type(ty)),
            ("param", types) => params.extend(types.iter().map(val_type)),
            ("result", types) => results.extend(types.iter().map(val_type)),
            _ => break,
        }
        used += 1;
    }
    (signature(&params, &results), &items[used..])
}

fn func_signature(t: &FuncType) -> String {
    let strings = |ts: &[n0xis_wasm::ValType]| ts.iter().map(|t| t.to_string()).collect::<Vec<_>>();
    signature(&strings(&t.params), &strings(&t.results))
}

/// A subtype as this crate's `Display` writes it, from V8's declaration.
fn v8_subtype(item: &Sx) -> String {
    let Some("sub") = item.head() else { return v8_composite(item) };
    let rest = &item.list().unwrap()[1..];
    let (composite, heads) = rest.split_last().expect("a composite type");
    let mut s = "(sub".to_string();
    for h in heads {
        match h.atom() {
            Some("final") => s.push_str(" final"),
            Some(_) => write!(s, " {}", type_named(h)).unwrap(),
            None => panic!("a subtype no recording has shown: {item:?}"),
        }
    }
    write!(s, " {})", v8_composite(composite)).unwrap();
    s
}

/// The fields of a structure or an array V8 declares, each with V8's name
/// for it and its storage type: `(field $field3 T)` in a structure, `(field
/// T)` in an array, one field each. Any other shape fails, so that no part
/// of a field is passed over (a `(field i32 i64)` read as its last type
/// would be one field where the text has two).
fn v8_fields(composite: &Sx) -> Vec<(Option<&str>, &Sx)> {
    let parts = composite.list().unwrap_or_else(|| panic!("a composite type, not {composite:?}"));
    let in_struct = match composite.head() {
        Some("struct") => true,
        Some("array") if parts.len() == 2 => false,
        _ => panic!("a composite type no recording has shown: {composite:?}"),
    };
    parts[1..]
        .iter()
        .map(|f| match (in_struct, f.head(), f.list()) {
            (true, Some("field"), Some([_, Sx::Atom(name), ty])) if name.starts_with('$') => (Some(name.as_str()), ty),
            (false, Some("field"), Some([_, ty])) => (None, ty),
            _ => panic!("a field no recording has shown: {f:?} in a {}", composite.head().unwrap_or_default()),
        })
        .collect()
}

fn v8_composite(item: &Sx) -> String {
    let fields: Vec<String> = v8_fields(item).into_iter().map(|(_, ty)| storage_type(ty)).collect();
    match (item.head(), fields.as_slice()) {
        (Some("struct"), []) => "(struct)".to_string(),
        (Some("struct"), fields) => {
            let fields: Vec<String> = fields.iter().map(|f| format!("(field {f})")).collect();
            format!("(struct {})", fields.join(" "))
        }
        (_, [f]) => format!("(array {f})"),
        _ => unreachable!("v8_fields reads a structure or an array of one field"),
    }
}

// ---------------------------------------------------------------------------
// Instructions, V8's spelling to the canonical one.

/// The blocks open at a line of V8's text, innermost last, each with the
/// label V8 gave it (`block $label0`) or none; the function's own block is at
/// the bottom.
#[derive(Default)]
struct Frames(Vec<Option<String>>);

impl Frames {
    /// The depth of the open block V8 named `label`, or the name marked
    /// unresolved.
    fn depth(&self, label: &Sx) -> String {
        let name = label.atom().unwrap_or_else(|| panic!("a label, not {label:?}"));
        match self.0.iter().rev().position(|l| l.as_deref() == Some(name)) {
            Some(d) => d.to_string(),
            None => format!("{name}?"),
        }
    }
}

/// What the names in an instruction line stand for.
struct Scope<'a> {
    names: &'a Names,
    /// The function's parameters and locals by V8's names; empty for a
    /// constant expression.
    locals: &'a HashMap<String, u32>,
    frames: Frames,
}

impl Scope<'_> {
    fn new<'a>(names: &'a Names, locals: &'a HashMap<String, u32>, frames: Frames) -> Scope<'a> {
        Scope { names, locals, frames }
    }
}

/// The bits of V8's float literal: decimal (`1.5`, `-0.0`, `5e-324`), `inf`,
/// `nan` (the canonical NaN) or `nan:0x1` (a payload).
fn float_bits(text: &str, is_f32: bool) -> u64 {
    let (negative, body) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (exponent_bits, mantissa_bits) = if is_f32 { (8, 23) } else { (11, 52) };
    let sign = u64::from(negative) << (exponent_bits + mantissa_bits);
    let infinite = ((1u64 << exponent_bits) - 1) << mantissa_bits;
    let bits = match body {
        "inf" => infinite,
        "nan" => infinite | 1 << (mantissa_bits - 1),
        _ if body.starts_with("nan:0x") => infinite | u64::from_str_radix(&body[6..], 16).expect("a payload"),
        _ if is_f32 => return u64::from(text.parse::<f32>().unwrap_or_else(|_| panic!("a float: {text}")).to_bits()),
        _ => return text.parse::<f64>().unwrap_or_else(|_| panic!("a float: {text}")).to_bits(),
    };
    sign | bits
}

fn float_text(name: &str, bits: u64) -> String {
    if name == "f32.const" { format!("f32.const bits={bits:#010x}") } else { format!("f64.const bits={bits:#018x}") }
}

fn unmeasured(items: &[Sx]) -> ! {
    panic!("a spelling no recording has shown, so no rule reads it: {items:?}")
}

/// A label V8 writes on a block, if it writes one.
fn split_label(args: &[Sx]) -> (Option<String>, &[Sx]) {
    match args.first().and_then(Sx::atom) {
        Some(a) if a.starts_with('$') => (Some(a.to_string()), &args[1..]),
        _ => (None, args),
    }
}

/// One line of V8's disassembly, in the canonical spelling, updating the
/// open blocks.
fn from_v8(text: &str, s: &mut Scope) -> String {
    instruction(&sexprs(text), s)
}

/// One instruction of V8's, in the canonical spelling.
///
/// A memory or a table operand V8 leaves out is index 0, whatever the module
/// has: V8 leaves out exactly an index that is 0 (the two of a copy only when
/// both are) and writes every other, with three memories and three tables as
/// with one. Measured by [`v8_leaves_out_exactly_index_0`] (`--features
/// oracle`), which runs V8 14.6 (v8dis.mjs) on a probe of three memories and
/// three tables holding each instruction that has such an operand, on index 0
/// and on another, and requires V8's lines and this comparison's agreement
/// with the reader on every one: `memory.size`, `memory.size 1`,
/// `memory.size 2`; `memory.grow`, `memory.grow 2`; `memory.fill`,
/// `memory.fill 1`; `memory.copy`, `memory.copy 0 1`, `memory.copy 1 0`;
/// `memory.init 1` (data 1 into memory 0), `memory.init 2 2`; `table.copy`,
/// `table.copy $table0 $table2`, `table.copy $table2 $table0`;
/// `table.init $elem1` (into table 0); `call_indirect`, `call_indirect
/// $table2`, `return_call_indirect`, `return_call_indirect $table2`. So the
/// omitted operand is compared as 0, here as in a module of one memory or
/// table.
fn instruction(items: &[Sx], s: &mut Scope) -> String {
    let name = items[0].atom().unwrap_or_else(|| unmeasured(items));
    let name = DRAFT_NAMES.iter().find(|(draft, _)| *draft == name).map_or(name, |(_, spec)| *spec);
    let args = &items[1..];
    let names = s.names;
    let all_plain = || args.iter().all(|a| a.atom().is_some_and(|a| !a.starts_with('$')));
    match (name, args) {
        ("block" | "loop" | "if" | "try", _) => {
            let (label, rest) = split_label(args);
            let (sig, rest) = v8_signature(rest);
            if !rest.is_empty() {
                unmeasured(items);
            }
            s.frames.0.push(label);
            format!("{name}{sig}")
        }
        ("try_table", _) => {
            let (label, rest) = split_label(args);
            let (sig, mut rest) = v8_signature(rest);
            // The clauses branch from outside the `try_table`: resolved before
            // its block opens.
            let mut out = format!("try_table{sig}");
            while let Some(kind) = rest.first().and_then(Sx::atom) {
                match (kind, rest) {
                    ("catch" | "catch_ref", [_, tag, l, ..]) => {
                        write!(out, " ({kind} {} {})", named(names, "tag", tag), s.frames.depth(l)).unwrap();
                        rest = &rest[3..];
                    }
                    ("catch_all" | "catch_all_ref", [_, l, ..]) => {
                        write!(out, " ({kind} {})", s.frames.depth(l)).unwrap();
                        rest = &rest[2..];
                    }
                    _ => unmeasured(items),
                }
            }
            if !rest.is_empty() {
                unmeasured(items);
            }
            s.frames.0.push(label);
            out
        }
        ("end", _) => {
            let open = s.frames.0.pop().unwrap_or_else(|| panic!("V8 ends a block that is not open: {items:?}"));
            if let [label] = args {
                assert_eq!(open.as_deref(), label.atom(), "V8's `end` names another block than the one it ends");
            }
            "end".to_string()
        }
        // `delegate` closes its `try`, and its label is counted from outside it.
        ("delegate", [label]) => {
            s.frames.0.pop().expect("a `try` for `delegate` to close");
            format!("delegate {}", s.frames.depth(label))
        }
        ("catch" | "throw", [tag]) => format!("{name} {}", named(names, "tag", tag)),
        ("br" | "br_if" | "br_on_null" | "br_on_non_null" | "rethrow", [label]) => format!("{name} {}", s.frames.depth(label)),
        ("br_table", labels) if !labels.is_empty() => {
            let depths: Vec<String> = labels.iter().map(|l| s.frames.depth(l)).collect();
            format!("br_table {}", depths.join(" "))
        }
        ("br_on_cast" | "br_on_cast_fail", [label, from, to]) => {
            format!("{name} {} {} {}", s.frames.depth(label), val_type(from), val_type(to))
        }
        ("call" | "return_call" | "ref.func", [f]) => format!("{name} {}", named(names, "func", f)),
        ("call_indirect" | "return_call_indirect", _) => {
            let (sig, rest) = v8_signature(args);
            // V8 names the table only when it is not table 0.
            let table = match rest {
                [] => "0".to_string(),
                [t] => named(names, "table", t),
                _ => unmeasured(items),
            };
            format!("{name} {table}{sig}")
        }
        ("call_ref" | "return_call_ref", [t]) => format!("{name} {}", type_named(t)),
        ("local.get" | "local.set" | "local.tee", [Sx::Atom(l)]) => match s.locals.get(l) {
            Some(i) => format!("{name} {i}"),
            None => format!("{name} {l}?"),
        },
        ("global.get" | "global.set", [g]) => format!("{name} {}", named(names, "global", g)),
        ("table.get" | "table.set" | "table.size" | "table.grow" | "table.fill", [t]) => {
            format!("{name} {}", named(names, "table", t))
        }
        // The order of the operands V8 writes, measured on a probe, since
        // the recordings show one asymmetric `table.copy` (`refs`, 0x154), no
        // asymmetric `table.init`, a single asymmetric `memory.copy`
        // (`shapes`, 0x1aa) and only equal pairs of `memory.init`. The probe, a module of three memories, three
        // tables, element segments $e0..$e2 and data segments $d0..$d2:
        //
        //   (memory.copy 1 2 ..) (memory.copy 2 1 ..) (memory.copy 0 2 ..)
        //   (memory.copy 2 0 ..) (memory.init 1 2 ..) (memory.init 2 1 ..)
        //   (memory.init 0 2 ..) (memory.init 2 0 ..) (table.copy 1 2 ..)
        //   (table.copy 2 1 ..) (table.copy 0 2 ..) (table.init 1 2 ..)
        //   (table.init 2 0 ..) (table.init 0 2 ..)
        //
        // and, after `wasm-tools parse`, V8 14.6 (v8dis.mjs) on its bytes:
        //
        //   fc 0a 01 02  memory.copy 1 2         fc 08 02 01  memory.init 2 1
        //   fc 0a 02 01  memory.copy 2 1         fc 08 01 02  memory.init 1 2
        //   fc 0a 00 02  memory.copy 0 2         fc 08 02 00  memory.init 2
        //   fc 0a 02 00  memory.copy 2 0         fc 08 00 02  memory.init 0 2
        //   fc 0e 01 02  table.copy $table1 $table2
        //   fc 0e 02 01  table.copy $table2 $table1
        //   fc 0e 00 02  table.copy $table0 $table2
        //   fc 0c 02 01  table.init $table1 $e2
        //   fc 0c 00 02  table.init $table2 $e0
        //   fc 0c 02 00  table.init $e2
        //
        // The bytes are the specification's order (`memory.copy` and
        // `table.copy`: destination, source; `memory.init`: data segment,
        // memory; `table.init`: element segment, table). So V8 writes both
        // copies destination first, as the text format does; `table.init`
        // as the text does, table first, the table left out when it is 0;
        // and `memory.init` in the binary order, data segment first, which is
        // the reverse of the text's, with the memory left out when it is 0.
        ("table.copy", []) => "table.copy 0 0".to_string(),
        ("table.copy", [d, src]) => format!("table.copy {} {}", named(names, "table", d), named(names, "table", src)),
        // Into table 0: V8 names the segment only. (No recording shows the
        // table named; the probe above does, but no rule reads a spelling no
        // recording has.)
        ("table.init", [e]) => format!("table.init 0 {}", named(names, "elem", e)),
        ("elem.drop", [e]) => format!("elem.drop {}", named(names, "elem", e)),
        // Memory 0: V8 writes the data segment only, as the canonical text
        // does. Of two numbers the recordings show only equal ones; the probe
        // says V8 writes them data segment first, but no rule reads a
        // spelling no recording has.
        ("memory.init", [Sx::Atom(d)]) => format!("memory.init {d}"),
        ("memory.init", [Sx::Atom(a), Sx::Atom(b)]) if a == b => format!("memory.init {a} {b}"),
        ("memory.size" | "memory.grow" | "memory.fill", []) => name.to_string(),
        ("memory.size" | "memory.grow" | "memory.fill", [Sx::Atom(m)]) if m != "0" => format!("{name} {m}"),
        ("memory.copy", []) => name.to_string(),
        ("memory.copy", [Sx::Atom(d), Sx::Atom(src)]) => format!("memory.copy {d} {src}"),
        ("select", []) => "select".to_string(),
        ("select", types) => {
            let types: Vec<String> = types.iter().map(val_type).collect();
            format!("select (result {})", types.join(" "))
        }
        ("ref.null", [h]) => format!("ref.null {}", heap_type(h)),
        ("ref.test" | "ref.cast", [h]) => format!("{name} {}", ref_type(false, h)),
        ("ref.test" | "ref.cast", [Sx::Atom(null), h]) if null == "null" => format!("{name} {}", ref_type(true, h)),
        (
            "struct.new" | "struct.new_default" | "array.new" | "array.new_default" | "array.get" | "array.get_s"
            | "array.get_u" | "array.set" | "array.fill",
            [t],
        ) => format!("{name} {}", type_named(t)),
        ("struct.get" | "struct.get_s" | "struct.get_u" | "struct.set", [t, Sx::Atom(f)]) => {
            let ty = type_named(t);
            let field = ty.parse::<u32>().ok().and_then(|ty| names.fields.get(&ty)?.get(f).copied());
            format!("{name} {ty} {}", field.map_or_else(|| format!("{f}?"), |f| f.to_string()))
        }
        ("array.new_fixed" | "array.new_data" | "array.init_data", [t, Sx::Atom(n)]) => format!("{name} {} {n}", type_named(t)),
        ("array.new_elem" | "array.init_elem", [t, e]) => format!("{name} {} {}", type_named(t), named(names, "elem", e)),
        ("array.copy", [d, src]) => format!("array.copy {} {}", type_named(d), type_named(src)),
        ("f32.const" | "f64.const", [Sx::Atom(x)]) => float_text(name, float_bits(x, name == "f32.const")),
        ("v128.const", _) if all_plain() => {
            let words: Vec<String> = args.iter().map(|a| a.atom().unwrap().to_ascii_lowercase()).collect();
            format!("v128.const {}", words.join(" "))
        }
        _ if is_memory_access(name) && all_plain() => {
            let mut offset = "0".to_string();
            let mut align = natural_align(name).to_string();
            let mut bare = Vec::new();
            for a in args.iter().map(|a| a.atom().unwrap()) {
                if let Some(o) = a.strip_prefix("offset=") {
                    offset = o.to_string();
                } else if let Some(x) = a.strip_prefix("align=") {
                    align = x.to_string();
                } else {
                    bare.push(a);
                }
            }
            // V8 prints no memory index in any recording; one it printed
            // would be compared.
            let (memory, lane) = match (name.ends_with("_lane"), bare.as_slice()) {
                (false, []) => (None, None),
                (false, [m]) => (Some(*m), None),
                (true, [l]) => (None, Some(*l)),
                (true, [m, l]) => (Some(*m), Some(*l)),
                _ => unmeasured(items),
            };
            let memory = memory.filter(|m| *m != "0").map(|m| format!(" {m}")).unwrap_or_default();
            let lane = lane.map(|l| format!(" {l}")).unwrap_or_default();
            format!("{name}{memory} offset={offset} align={align}{lane}")
        }
        _ if all_plain() => {
            let words: Vec<&str> = items.iter().map(|a| a.atom().unwrap()).collect();
            let words = [&[name][..], &words[1..]].concat();
            words.join(" ")
        }
        _ => unmeasured(items),
    }
}

/// A constant expression as V8 writes it, one parenthesised instruction
/// each: `(i32.const 40) (i32.const 2) (i32.add)`.
fn v8_constant(items: &[Sx], names: &Names) -> String {
    let locals = HashMap::new();
    let mut scope = Scope::new(names, &locals, Frames::default());
    let out: Vec<String> =
        items.iter().map(|i| format!("({})", instruction(i.list().unwrap_or_else(|| unmeasured(items)), &mut scope))).collect();
    out.join(" ")
}

// ---------------------------------------------------------------------------
// This crate's facts, in the terms V8 prints.

/// A block type as the signature it stands for.
fn block_signature(m: &Module, bt: &BlockType) -> String {
    match bt {
        BlockType::Empty => String::new(),
        BlockType::Value(t) => signature(&[], &[t.to_string()]),
        BlockType::Type(x) => m.func_type(*x).map_or_else(|| format!(" (type {x}: no function type)"), func_signature),
    }
}

/// Count one fact of the kind `what` that V8 does not print.
fn unprinted(counts: &mut BTreeMap<&'static str, usize>, what: &'static str) {
    *counts.entry(what).or_default() += 1;
}

/// A block type's index, if it has one, is compared only through the
/// signature V8 writes for it.
fn count_block_type(bt: &BlockType, counts: &mut BTreeMap<&'static str, usize>) {
    if matches!(bt, BlockType::Type(_)) {
        unprinted(counts, TYPE_INDICES);
    }
}

/// This crate's instruction in the terms the comparison uses: the canonical
/// text, except what V8 writes from the module (signatures) or in another
/// base (floats, as bits), and without the memory index of a memory access,
/// which V8 never prints. Counts in `counts` each memory index it drops and
/// each type index it writes as a signature.
fn ours(m: &Module, instr: &Instr, counts: &mut BTreeMap<&'static str, usize>) -> String {
    match instr {
        Instr::Block(bt) | Instr::Loop(bt) | Instr::If(bt) | Instr::Try(bt) => {
            count_block_type(bt, counts);
            format!("{}{}", instr.name(), block_signature(m, bt))
        }
        Instr::TryTable(t) => {
            count_block_type(&t.ty, counts);
            let mut s = format!("try_table{}", block_signature(m, &t.ty));
            for c in &t.catches {
                match c {
                    Catch::Catch { tag, label } => write!(s, " (catch {tag} {label})"),
                    Catch::CatchRef { tag, label } => write!(s, " (catch_ref {tag} {label})"),
                    Catch::CatchAll { label } => write!(s, " (catch_all {label})"),
                    Catch::CatchAllRef { label } => write!(s, " (catch_all_ref {label})"),
                }
                .unwrap();
            }
            s
        }
        Instr::CallIndirect(c) | Instr::ReturnCallIndirect(c) => {
            unprinted(counts, TYPE_INDICES);
            let sig = m.func_type(c.ty).map_or_else(|| format!(" (type {}: no function type)", c.ty), func_signature);
            format!("{} {}{sig}", instr.name(), c.table)
        }
        Instr::F32Const(Ieee32(b)) => float_text("f32.const", u64::from(*b)),
        Instr::F64Const(Ieee64(b)) => float_text("f64.const", *b),
        _ => {
            let text = instr.to_string();
            let mut words: Vec<&str> = text.split(' ').collect();
            // The canonical text writes the memory index, when not 0, right
            // after the name.
            if is_memory_access(instr.name()) && words.get(1).is_some_and(|w| w.bytes().all(|b| b.is_ascii_digit())) {
                words.remove(1);
                unprinted(counts, ACCESS_MEMORIES);
            }
            words.join(" ")
        }
    }
}

/// A constant expression without its final `end`, one parenthesised
/// instruction each, as V8 writes it.
fn ours_constant(m: &Module, expr: &[Located], counts: &mut BTreeMap<&'static str, usize>) -> String {
    let body = match expr.split_last() {
        Some((last, body)) if last.instr == Instr::End => body,
        _ => expr,
    };
    body.iter().map(|l| format!("({})", ours(m, &l.instr, counts))).collect::<Vec<_>>().join(" ")
}

/// `(export "a") (export "b")` for every export of `item`, in export order.
fn ours_exports(m: &Module, item: ExportItem) -> String {
    m.exports().iter().filter(|e| e.item == item).map(|e| format!(" (export {:?})", e.name)).collect()
}

fn ours_import(m: &Module, import: usize) -> String {
    let i = &m.imports()[import];
    format!(" (import {:?} {:?})", i.module, i.name)
}

fn limits_text(min: u64, max: Option<u64>) -> String {
    match max {
        Some(max) => format!(" {min} {max}"),
        None => format!(" {min}"),
    }
}

// ---------------------------------------------------------------------------
// V8's module.

/// A declaration line of V8's: its name, the index it states, its import and
/// its exports, and the rest of it in order, which its kind's reader must
/// consume whole.
struct Decl {
    offset: usize,
    name: Option<String>,
    comment: Option<u32>,
    import: Option<(String, String)>,
    exports: Vec<String>,
    rest: Vec<Sx>,
}

/// Which of the parts [`decl`] takes out of a declaration a kind may carry.
/// A part its kind's reader would never look at (an export on a type, a name
/// on a data segment) is one no rule reads, and fails rather than vanishing.
#[derive(Clone, Copy)]
struct Parts {
    /// `$name`, as the first item.
    name: bool,
    /// `(;N;)`, at most one.
    comment: bool,
    /// `(import "m" "n")`, at most one, and `(export "e")`, any number.
    origin: bool,
}

/// The parts each kind of declaration V8 writes may carry, `None` for a kind
/// no recording has. Every index space's may have all three; an element
/// segment is named and numbered as one is, but neither imported nor
/// exported; a type is numbered by its name alone (`$type3`), and `start`
/// names its function; a data segment, as V8 writes it in every recording, has
/// none.
fn parts(kind: &str) -> Option<Parts> {
    let all = Parts { name: true, comment: true, origin: true };
    match kind {
        "func" | "table" | "memory" | "global" | "tag" => Some(all),
        "elem" => Some(Parts { origin: false, ..all }),
        "type" | "start" => Some(Parts { name: true, comment: false, origin: false }),
        "data" => Some(Parts { name: false, comment: false, origin: false }),
        _ => None,
    }
}

/// The declaration `(kind items..)` V8 writes at `offset`. Every item is
/// taken as one of the parts [`Parts`] lets the kind carry, each in the only
/// shape V8 writes it, or left in `rest` for the kind's reader; a second
/// index comment or import, an export or import with more or other than its
/// strings, and a part the kind may not carry all fail here, naming the
/// item, so that no item is passed over.
fn decl(offset: usize, kind: &str, items: &[Sx]) -> Decl {
    let parts = parts(kind).unwrap_or_else(|| panic!("a declaration no recording has shown: ({kind} ..) at {offset:#x}"));
    let refuse = |what: &str, item: &Sx| -> ! { panic!("({kind} ..) at {offset:#x} with {what}, which no rule reads: {item:?}") };
    let string = |s: &Sx| match s {
        Sx::Str(b) => String::from_utf8(b.clone()).expect("a UTF-8 name"),
        _ => unreachable!("matched as a string"),
    };
    let mut d = Decl { offset, name: None, comment: None, import: None, exports: Vec::new(), rest: Vec::new() };
    for (i, item) in items.iter().enumerate() {
        match (item, item.list()) {
            (Sx::Atom(a), _) if i == 0 && a.starts_with('$') => match parts.name {
                true => d.name = Some(a.clone()),
                false => refuse("a name", item),
            },
            (Sx::Index(n), _) => match (parts.comment, d.comment) {
                (true, None) => d.comment = Some(*n),
                (true, Some(_)) => refuse("a second index comment", item),
                (false, _) => refuse("an index comment", item),
            },
            (_, Some([Sx::Atom(head), shape @ ..])) if head == "export" || head == "import" => {
                if !parts.origin {
                    refuse(&format!("an {head}"), item);
                }
                match (head.as_str(), shape) {
                    ("export", [e @ Sx::Str(_)]) => d.exports.push(string(e)),
                    ("import", [m @ Sx::Str(_), n @ Sx::Str(_)]) if d.import.is_none() => {
                        d.import = Some((string(m), string(n)))
                    }
                    ("import", [Sx::Str(_), Sx::Str(_)]) => refuse("a second import", item),
                    _ => refuse(&format!("an {head} of another shape than V8's"), item),
                }
            }
            _ => d.rest.push(item.clone()),
        }
    }
    d
}

impl Decl {
    /// Its import and exports, as [`ours_import`] and [`ours_exports`] write them.
    fn origin(&self) -> String {
        let mut s = String::new();
        if let Some((module, name)) = &self.import {
            write!(s, " (import {module:?} {name:?})").unwrap();
        }
        for e in &self.exports {
            write!(s, " (export {e:?})").unwrap();
        }
        s
    }
}

struct V8Func {
    decl: Decl,
    /// `(local $var5 T)` lines.
    locals: Vec<Sx>,
    /// Parameter and local names to their index.
    local_names: HashMap<String, u32>,
    /// Every line of the body with its offset, the function's closing line
    /// as its final `end`.
    body: Vec<(usize, String)>,
}

enum Group {
    /// `(rec ...)`, with the indices of the types V8 printed in it.
    Explicit(Vec<u32>),
    /// A type outside any `rec`.
    Bare(u32),
}

#[derive(Default)]
struct V8Module {
    names: Names,
    /// Each type V8 declares, by its index, with the declaration's subtype.
    types: Vec<(u32, Sx)>,
    groups: Vec<Group>,
    funcs: Vec<V8Func>,
    tables: Vec<Decl>,
    memories: Vec<Decl>,
    globals: Vec<Decl>,
    tags: Vec<Decl>,
    elems: Vec<Decl>,
    data: Vec<Decl>,
    start: Vec<Decl>,
}

fn parse_module(recording: &str) -> V8Module {
    let lines = v8_lines(recording);
    assert_eq!(lines.first().map(|l| l.text), Some("(module"), "a recording that is no module");
    assert_eq!(lines.last().map(|l| (l.indent, l.text)), Some((0, ")")), "a module that does not end");
    let mut v = V8Module::default();
    let mut group: Option<Vec<u32>> = None;
    let mut counts: HashMap<&'static str, u32> = HashMap::new();
    let mut i = 1;
    let end = lines.len() - 1;
    while i < end {
        let line = &lines[i];
        i += 1;
        match (line.indent, line.text) {
            (2, "(rec)") => {
                v.groups.push(Group::Explicit(Vec::new()));
                continue;
            }
            (2, "(rec") => {
                group = Some(Vec::new());
                continue;
            }
            (2, ")") => {
                v.groups.push(Group::Explicit(group.take().expect("a `)` that closes a `(rec`")));
                continue;
            }
            _ => {}
        }
        // A declaration, perhaps continued on lines indented further.
        let mut text = line.text.to_string();
        let function = text.starts_with("(func ") || text == "(func";
        let defined = function && depth(&text) == 1;
        if defined {
            text.push(')');
        }
        while depth(&text) > 0 {
            let next = &lines[i];
            assert!(next.indent > line.indent, "an unclosed declaration at {:#x}", line.offset);
            text.push(' ');
            text.push_str(next.text);
            i += 1;
        }
        let items = sexprs(&text);
        let [Sx::List(items)] = items.as_slice() else { panic!("one declaration per line: {text}") };
        let kind = items[0].atom().unwrap_or_else(|| panic!("a declaration: {text}"));
        let d = decl(line.offset, kind, &items[1..]);
        let space: Option<&'static str> = match kind {
            "func" => Some("func"),
            "table" => Some("table"),
            "memory" => Some("memory"),
            "global" => Some("global"),
            "tag" => Some("tag"),
            "elem" => Some("elem"),
            _ => None,
        };
        if let Some(space) = space {
            let n = counts.entry(space).or_default();
            v.names.declare(space, d.name.as_deref(), d.comment, *n);
            *n += 1;
        }
        match kind {
            "type" => {
                let index = d.name.as_deref().and_then(type_index).unwrap_or_else(|| panic!("a type V8 does not number: {text}"));
                let [subtype] = d.rest.as_slice() else { panic!("one subtype per type: {text}") };
                // The fields of a structure, by V8's names for them.
                let composite = if subtype.head() == Some("sub") { subtype.list().unwrap().last().unwrap() } else { subtype };
                let fields = v.names.fields.entry(index).or_default();
                for (k, (name, _)) in v8_fields(composite).into_iter().enumerate() {
                    if let Some(name) = name {
                        let previous = fields.insert(name.to_string(), k as u32);
                        assert!(previous.is_none(), "V8 names two fields of type {index} {name}");
                    }
                }
                v.types.push((index, subtype.clone()));
                match &mut group {
                    Some(g) => g.push(index),
                    None => v.groups.push(Group::Bare(index)),
                }
            }
            "func" => {
                // The header is its name, index, import, exports and
                // signature, and nothing else: an item after the signature
                // (a `(type $type12)`, a stray word) is one no rule reads.
                let (_, after) = v8_signature(&d.rest);
                assert!(after.is_empty(), "a function header item no rule reads at {:#x}: {after:?}", d.offset);
                let mut f = V8Func { decl: d, locals: Vec::new(), local_names: HashMap::new(), body: Vec::new() };
                let mut next_local = 0;
                // A group `(param $var0 T)` or `(local $var5 T)` is one local
                // and names it; an unnamed `(param T T)` is as many as its
                // types.
                let mut name_local = |f: &mut V8Func, item: &Sx| match item.list() {
                    Some([_, Sx::Atom(name), _]) if name.starts_with('$') => {
                        if let Some(n) = name.strip_prefix("$var").and_then(|n| n.parse::<u32>().ok()) {
                            assert_eq!(n, next_local, "V8 names local {next_local} {name}");
                        }
                        let previous = f.local_names.insert(name.to_string(), next_local);
                        assert!(previous.is_none(), "V8 names two locals {name}");
                        next_local += 1;
                    }
                    Some([_, types @ ..]) => next_local += types.len() as u32,
                    _ => panic!("a local no recording has shown: {item:?}"),
                };
                for p in f.decl.rest.clone().iter().filter(|p| p.head() == Some("param")) {
                    name_local(&mut f, p);
                }
                if defined {
                    loop {
                        let l = &lines[i];
                        i += 1;
                        if (l.indent, l.text) == (2, ")") {
                            f.body.push((l.offset, "end".to_string()));
                            break;
                        }
                        if l.text.starts_with("(local ") && f.body.is_empty() {
                            let [local] = sexprs(l.text).try_into().unwrap_or_else(|_| panic!("one local per line: {}", l.text));
                            // `(local $var5 T)`: one named local of one type.
                            let Some([_, Sx::Atom(name), ty]) = local.list() else {
                                panic!("a local no recording has shown: {}", l.text)
                            };
                            assert!(name.starts_with('$'), "a local no recording has shown: {}", l.text);
                            f.locals.push(ty.clone());
                            name_local(&mut f, &local);
                        } else {
                            f.body.push((l.offset, l.text.to_string()));
                        }
                    }
                }
                v.funcs.push(f);
            }
            "table" => v.tables.push(d),
            "memory" => v.memories.push(d),
            "global" => v.globals.push(d),
            "tag" => v.tags.push(d),
            "elem" => v.elems.push(d),
            "data" => v.data.push(d),
            // `(start $func2)`: the function's name and nothing else (a
            // number after it; an index comment or an export [`decl`]
            // refuses), or no rule reads what the rest says.
            "start" => {
                assert!(d.name.is_some() && d.rest.is_empty(), "a start declaration no recording has shown: {text}");
                v.start.push(d)
            }
            _ => unreachable!("decl refuses a kind it has no parts for: {text}"),
        }
    }
    assert!(group.is_none(), "a `(rec` that is not closed");
    v
}

// ---------------------------------------------------------------------------
// The comparison.

#[derive(Default)]
struct Report {
    fixture: String,
    compared: BTreeMap<&'static str, usize>,
    /// Facts the module has that V8 does not print, by kind.
    not_compared: BTreeMap<&'static str, usize>,
    found: Vec<Disagreement>,
}

impl Report {
    fn check(&mut self, what: &'static str, at: String, ours: &str, theirs: &str) {
        *self.compared.entry(what).or_default() += 1;
        if ours != theirs {
            let (fixture, ours, theirs) = (self.fixture.clone(), ours.to_string(), theirs.to_string());
            self.found.push(Disagreement { fixture, at, ours, theirs });
        }
    }

    /// Two lists entry by entry, a missing entry as `(none)`.
    fn lists(&mut self, what: &'static str, at: &str, ours: &[String], theirs: &[String]) {
        for i in 0..ours.len().max(theirs.len()) {
            let (o, t) = (ours.get(i).map_or("(none)", String::as_str), theirs.get(i).map_or("(none)", String::as_str));
            self.check(what, format!("{at} {i}"), o, t);
        }
    }
}

fn compare_fixture(stem: &str, m: &Module, recording: &str) -> Report {
    let v = parse_module(recording);
    let names = &v.names;
    let mut r = Report { fixture: stem.to_string(), ..Default::default() };
    // What V8 does not print, counted as it is met; the report's.
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();

    // Types: V8 declares the structures and arrays, and no function type.
    let printed: HashMap<u32, &Sx> = v.types.iter().map(|(i, s)| (*i, s)).collect();
    for (i, t) in m.types().iter().enumerate() {
        let i = i as u32;
        let theirs = printed.get(&i).map_or_else(|| "(not printed)".to_string(), |s| v8_subtype(s));
        if matches!(t.composite, CompositeType::Func(_)) && !printed.contains_key(&i) {
            unprinted(&mut counts, FUNCTION_TYPES);
            continue;
        }
        r.check("types", format!("type {i}"), &t.to_string(), &theirs);
    }
    for (i, _) in v.types.iter().filter(|(i, _)| *i as usize >= m.types().len()) {
        r.check("types", format!("type {i}"), "(none)", "(printed)");
    }
    let ours_groups: Vec<String> = m
        .rec_groups()
        .iter()
        .filter_map(|g| {
            let indices: Vec<String> = g.types().map(|t| t.to_string()).collect();
            if g.is_explicit() {
                return Some(format!("(rec {})", indices.join(" ")));
            }
            let t = g.types().start;
            if matches!(m.types()[t as usize].composite, CompositeType::Func(_)) && !printed.contains_key(&t) {
                return None;
            }
            Some(format!("type {t}"))
        })
        .collect();
    let theirs_groups: Vec<String> = v
        .groups
        .iter()
        .map(|g| match g {
            Group::Explicit(t) => format!("(rec {})", t.iter().map(u32::to_string).collect::<Vec<_>>().join(" ")),
            Group::Bare(t) => format!("type {t}"),
        })
        .collect();
    r.lists("recursion groups", "group", &ours_groups, &theirs_groups);

    // Functions: the header, the locals, every instruction.
    let funcs = m.functions();
    for i in 0..funcs.len().max(v.funcs.len()) {
        let at = format!("func {i}");
        let (Some(f), Some(vf)) = (funcs.get(i), v.funcs.get(i)) else {
            let there = |n: usize| if i < n { "(a function)" } else { "(none)" };
            r.check("functions", at, there(funcs.len()), there(v.funcs.len()));
            continue;
        };
        let sig = m.func_type(f.ty).map_or_else(|| format!(" (type {}: no function type)", f.ty), func_signature);
        let (import, start) = match f.origin {
            FuncOrigin::Imported { import } => (ours_import(m, import), String::new()),
            FuncOrigin::Defined { body } => (String::new(), format!(" at {:#x}", m.bodies()[body].start)),
        };
        unprinted(&mut counts, TYPE_INDICES);
        let ours_header = format!("{import}{}{sig}{start}", ours_exports(m, ExportItem::Func(n0xis_wasm::FuncIdx(i as u32))));
        let theirs_start = if vf.body.is_empty() { String::new() } else { format!(" at {:#x}", vf.decl.offset) };
        let theirs_header = format!("{}{}{theirs_start}", vf.decl.origin(), v8_signature(&vf.decl.rest).0);
        r.check("functions", at.clone(), &ours_header, &theirs_header);
        if !matches!(f.origin, FuncOrigin::Defined { .. }) {
            continue;
        }
        let body = m.body(n0xis_wasm::FuncIdx(i as u32)).expect("a defined function").expect("a body that decodes");
        let ours_locals: Vec<String> =
            body.locals.iter().flat_map(|run| std::iter::repeat_n(run.ty.to_string(), run.count as usize)).collect();
        let theirs_locals: Vec<String> = vf.locals.iter().map(val_type).collect();
        r.lists("locals", &format!("{at} local"), &ours_locals, &theirs_locals);

        let mut scope = Scope::new(names, &vf.local_names, Frames(vec![None]));
        // Each line in the canonical spelling.
        let mut theirs: BTreeMap<usize, String> = BTreeMap::new();
        for (k, (offset, text)) in vf.body.iter().enumerate() {
            // The closing line stands at the function's final `end`.
            let canonical = if k + 1 == vf.body.len() {
                scope.frames.0.pop().expect("the function's own block");
                "end".to_string()
            } else {
                from_v8(text, &mut scope)
            };
            let previous = theirs.insert(*offset, canonical);
            assert!(previous.is_none(), "{stem}: two V8 lines at {offset:#x} in func {i}");
        }
        assert!(scope.frames.0.is_empty(), "{stem}: func {i} ends with blocks open: {:?}", scope.frames.0);
        let mut mine: BTreeMap<usize, &Instr> = BTreeMap::new();
        for l in &body.instructions {
            let previous = mine.insert(l.offset, &l.instr);
            assert!(previous.is_none(), "{stem}: two instructions at {:#x} in func {i}", l.offset);
        }
        for (offset, instr) in &mine {
            let text = ours(m, instr, &mut counts);
            let t = theirs.get(offset).map_or("(no instruction here)", String::as_str);
            r.check("instructions", format!("func {i} at {offset:#x}"), &text, t);
        }
        for (offset, text) in &theirs {
            if !mine.contains_key(offset) {
                r.check("instructions", format!("func {i} at {offset:#x}"), "(no instruction here)", text);
            }
        }
    }

    // Tables: limits and element type; neither the address type nor an
    // initial value is printed.
    let tables = m.tables();
    let ours_tables: Vec<String> = tables
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let import = match t.origin {
                TableOrigin::Imported { import } => ours_import(m, import),
                TableOrigin::Defined { .. } => String::new(),
            };
            let exports = ours_exports(m, ExportItem::Table(n0xis_wasm::TableIdx(i as u32)));
            format!("{import}{exports}{} {}", limits_text(t.ty.limits.min, t.ty.limits.max), t.ty.element)
        })
        .collect();
    for t in tables {
        if t.ty.limits.address == AddressType::I64 {
            unprinted(&mut counts, ADDRESS_TYPES);
        }
        if matches!(t.origin, TableOrigin::Defined { init: Some(_) }) {
            unprinted(&mut counts, TABLE_INITS);
        }
    }
    let theirs_tables: Vec<String> = v
        .tables
        .iter()
        .map(|d| {
            let mut s = d.origin();
            for item in &d.rest {
                match item.atom() {
                    Some(n) if n.bytes().all(|b| b.is_ascii_digit()) => write!(s, " {n}").unwrap(),
                    _ => write!(s, " {}", val_type(item)).unwrap(),
                }
            }
            s
        })
        .collect();
    r.lists("tables", "table", &ours_tables, &theirs_tables);

    // Memories: limits and `shared`; the address type is not printed.
    let ours_memories: Vec<String> = m
        .memories()
        .iter()
        .enumerate()
        .map(|(i, mem)| {
            let import = match mem.origin {
                Origin::Imported { import } => ours_import(m, import),
                Origin::Defined => String::new(),
            };
            let exports = ours_exports(m, ExportItem::Memory(n0xis_wasm::MemIdx(i as u32)));
            let shared = if mem.ty.shared { " shared" } else { "" };
            format!("{import}{exports}{}{shared}", limits_text(mem.ty.limits.min, mem.ty.limits.max))
        })
        .collect();
    for mem in m.memories() {
        if mem.ty.limits.address == AddressType::I64 {
            unprinted(&mut counts, ADDRESS_TYPES);
        }
    }
    let theirs_memories: Vec<String> = v
        .memories
        .iter()
        .map(|d| {
            let mut s = d.origin();
            for item in &d.rest {
                let word = item.atom().unwrap_or_else(|| panic!("a memory no recording has shown: {item:?}"));
                write!(s, " {word}").unwrap();
            }
            s
        })
        .collect();
    r.lists("memories", "memory", &ours_memories, &theirs_memories);

    // Globals: type, mutability, initial value.
    let ours_globals: Vec<String> = m
        .globals()
        .iter()
        .enumerate()
        .map(|(i, g)| {
            let ty = if g.ty.mutable { format!("(mut {})", g.ty.ty) } else { g.ty.ty.to_string() };
            let exports = ours_exports(m, ExportItem::Global(n0xis_wasm::GlobalIdx(i as u32)));
            match &g.origin {
                GlobalOrigin::Imported { import } => format!("{}{exports} {ty}", ours_import(m, *import)),
                GlobalOrigin::Defined { init } => format!("{exports} {ty} {}", ours_constant(m, init, &mut counts)),
            }
        })
        .collect();
    let theirs_globals: Vec<String> = v
        .globals
        .iter()
        .map(|d| {
            let (ty, init) = d.rest.split_first().unwrap_or_else(|| panic!("a global with no type at {:#x}", d.offset));
            // `(mut T)` holds exactly one type: a second would be passed over.
            let ty = match (ty.head(), ty.list()) {
                (Some("mut"), Some([_, inner])) => format!("(mut {})", val_type(inner)),
                (Some("mut"), _) => panic!("a global type no recording has shown at {:#x}: {ty:?}", d.offset),
                _ => val_type(ty),
            };
            match init {
                [] => format!("{} {ty}", d.origin()),
                init => format!("{} {ty} {}", d.origin(), v8_constant(init, names)),
            }
        })
        .collect();
    r.lists("globals", "global", &ours_globals, &theirs_globals);

    // Tags: the signature of their type.
    let ours_tags: Vec<String> = m
        .tags()
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let import = match t.origin {
                Origin::Imported { import } => ours_import(m, import),
                Origin::Defined => String::new(),
            };
            unprinted(&mut counts, TYPE_INDICES);
            let sig = m.func_type(t.ty).map_or_else(|| format!(" (type {}: no function type)", t.ty), func_signature);
            format!("{import}{}{sig}", ours_exports(m, ExportItem::Tag(n0xis_wasm::TagIdx(i as u32))))
        })
        .collect();
    let theirs_tags: Vec<String> = v
        .tags
        .iter()
        .map(|d| {
            let (sig, rest) = v8_signature(&d.rest);
            assert!(rest.is_empty(), "a tag no recording has shown at {:#x}", d.offset);
            format!("{}{sig}", d.origin())
        })
        .collect();
    r.lists("tags", "tag", &ours_tags, &theirs_tags);

    // Element segments: mode, table, offset, type, items.
    let ours_elems: Vec<String> = m
        .elements()
        .iter()
        .map(|e| {
            let mode = match &e.mode {
                ElementMode::Passive => "passive".to_string(),
                ElementMode::Declarative => "declare".to_string(),
                ElementMode::Active { table, offset } => format!("(table {table}) {}", ours_constant(m, offset, &mut counts)),
            };
            let items: Vec<String> = match &e.items {
                ElementItems::Functions(f) => f.iter().map(|f| format!("(ref.func {f})")).collect(),
                ElementItems::Expressions(x) => x.iter().map(|x| ours_constant(m, x, &mut counts)).collect(),
            };
            format!("{mode} {} {}", e.ty, items.join(" "))
        })
        .collect();
    let theirs_elems: Vec<String> = v
        .elems
        .iter()
        .map(|d| {
            let mut rest = d.rest.as_slice();
            let declare = rest.first().and_then(Sx::atom) == Some("declare");
            if declare {
                rest = &rest[1..];
            }
            let mut table = "0".to_string();
            // `(table $t)` names one table and holds nothing else.
            if rest.first().and_then(Sx::head) == Some("table") {
                let [_, t] = rest[0].list().unwrap() else {
                    panic!("a segment's table no recording has shown at {:#x}: {:?}", d.offset, rest[0])
                };
                table = named(names, "table", t);
                rest = &rest[1..];
            }
            let offset_len = rest.iter().take_while(|i| i.is_instruction()).count();
            let (offset, rest) = rest.split_at(offset_len);
            let (ty, items) = rest.split_first().unwrap_or_else(|| panic!("an element segment with no type at {:#x}", d.offset));
            let mode = match (declare, offset.is_empty()) {
                (true, true) => "declare".to_string(),
                (false, true) => "passive".to_string(),
                (false, false) => format!("(table {table}) {}", v8_constant(offset, names)),
                (true, false) => panic!("a declarative segment with an offset at {:#x}", d.offset),
            };
            format!("{mode} {} {}", val_type(ty), v8_constant(items, names))
        })
        .collect();
    r.lists("elements", "elem", &ours_elems, &theirs_elems);

    // Data segments: mode, offset, bytes; V8 prints no memory index.
    let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let ours_data: Vec<String> = m
        .data()
        .iter()
        .map(|d| {
            let bytes = hex(m.bytes(d.init.clone()).expect("in the file"));
            match &d.mode {
                DataMode::Passive => format!("passive {bytes}"),
                DataMode::Active { memory, offset } => {
                    if memory.0 != 0 {
                        unprinted(&mut counts, DATA_MEMORIES);
                    }
                    format!("{} {bytes}", ours_constant(m, offset, &mut counts))
                }
            }
        })
        .collect();
    let theirs_data: Vec<String> = v
        .data
        .iter()
        .map(|d| {
            let offset_len = d.rest.iter().take_while(|i| i.is_instruction()).count();
            let (offset, strings) = d.rest.split_at(offset_len);
            let bytes: Vec<u8> = strings
                .iter()
                .flat_map(|s| match s {
                    Sx::Str(b) => b.clone(),
                    other => panic!("a data segment no recording has shown: {other:?}"),
                })
                .collect();
            match offset {
                [] => format!("passive {}", hex(&bytes)),
                offset => format!("{} {}", v8_constant(offset, names), hex(&bytes)),
            }
        })
        .collect();
    r.lists("data", "data", &ours_data, &theirs_data);

    // The start function.
    let ours_start: Vec<String> = m.start().map(|f| format!("start {f}")).into_iter().collect();
    let theirs_start: Vec<String> = v
        .start
        .iter()
        .map(|d| {
            let f = d.name.as_deref().and_then(|n| names.index("func", n));
            format!("start {}", f.map_or("?".to_string(), |i| i.to_string()))
        })
        .collect();
    r.lists("start", "start", &ours_start, &theirs_start);

    r.not_compared = counts;
    r
}

/// What V8 said about a fixture: its disassembly, or the reason it refused
/// the module.
#[derive(Debug, PartialEq, Eq)]
enum V8Answer {
    Disassembly(String),
    Refusal(String),
}

/// The recording of V8's answer for `stem` in `dir`: exactly one of
/// `<stem>.v8.txt` and `<stem>.v8-refuses.txt` must be there, and a refusal
/// must read as one ([`v8_refusal`]).
fn v8_answer(dir: &std::path::Path, stem: &str) -> V8Answer {
    let read = |file: String| {
        let path = dir.join(file);
        path.exists().then(|| std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
    };
    match (read(format!("{stem}.v8.txt")), read(format!("{stem}.v8-refuses.txt"))) {
        (Some(disassembly), None) => V8Answer::Disassembly(disassembly),
        (None, Some(refusal)) => {
            V8Answer::Refusal(v8_refusal(&refusal).unwrap_or_else(|e| panic!("{stem}.v8-refuses.txt: {e}")).to_string())
        }
        (Some(_), Some(_)) => panic!("{stem}: both V8's disassembly and a refusal are recorded"),
        (None, None) => panic!("{stem}: neither V8's disassembly nor its refusal is recorded"),
    }
}

/// The reason in a record of V8 refusing a module, written as `build.sh`
/// writes wabt's (`<stem>.wabt-refuses.txt`): what the tool printed on
/// stderr, then a last line `exit status N`. Only status 1 is V8's refusal:
/// `v8dis.mjs` exits 1 when `new WebAssembly.Module` throws, with the line
/// `v8dis.mjs: V8 refuses the module: <V8's message>` on stderr, and 2 when
/// anything else goes wrong, which is the tool failing, not a verdict. No
/// fixture has one today (`build.sh`'s `v8_refuses` is empty); the shape is
/// the one `build.sh`'s `record_refusal` writes for wabt and V8 alike, and
/// [`build_sh_writes_a_v8_refusal_as_this_file_reads_it`] (`--features
/// oracle`) runs that function on a module V8 refuses and reads its record
/// here.
fn v8_refusal(record: &str) -> Result<&str, String> {
    const PREFIX: &str = "v8dis.mjs: V8 refuses the module: ";
    let lines: Vec<&str> = record.lines().collect();
    let Some((status, stderr)) = lines.split_last() else { return Err("an empty record".to_string()) };
    match status.strip_prefix("exit status ") {
        Some("1") => {}
        Some(other) => return Err(format!("exit status {other}, not V8's refusal (1)")),
        None => return Err(format!("no exit status on the last line: {status:?}")),
    }
    match stderr {
        [reason] => match reason.strip_prefix(PREFIX) {
            Some(message) if !message.trim().is_empty() => Ok(reason),
            _ => Err(format!("not V8's refusal: {reason:?}")),
        },
        _ => Err(format!("{} lines on stderr, not v8dis.mjs's one: {stderr:?}", stderr.len())),
    }
}

fn explained() -> Vec<Disagreement> {
    EXPLAINED
        .iter()
        .map(|(fixture, at, ours, theirs, _)| Disagreement {
            fixture: fixture.to_string(),
            at: at.to_string(),
            ours: ours.to_string(),
            theirs: theirs.to_string(),
        })
        .collect()
}

#[test]
fn every_fixture_reads_as_v8_reads_it() {
    let mut found = Vec::new();
    let mut all: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut all_skipped: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut not_compared = Vec::new();
    let expected: BTreeMap<&str, BTreeMap<&str, usize>> =
        NOT_COMPARED.iter().map(|(stem, counts)| (*stem, counts.iter().copied().collect())).collect();
    assert_eq!(expected.len(), NOT_COMPARED.len(), "a fixture listed twice in NOT_COMPARED");
    let mut counted: BTreeMap<&str, BTreeMap<&str, usize>> = BTreeMap::new();
    for stem in common::FIXTURES {
        let recording = match v8_answer(&common::dir(), stem) {
            V8Answer::Disassembly(recording) => recording,
            V8Answer::Refusal(reason) => {
                not_compared.push(format!("{stem} ({reason})"));
                continue;
            }
        };
        let m = common::module(stem);
        assert!(m.findings().is_empty(), "{stem}: {:?}", m.findings());
        let report = compare_fixture(stem, &m, &recording);
        assert!(report.compared.get("instructions").copied().unwrap_or(0) > 0, "{stem}: no instruction compared");
        eprintln!("{stem}: compared {:?}", report.compared);
        if !report.not_compared.is_empty() {
            eprintln!("{stem}: not compared {:?}", report.not_compared);
        }
        counted.insert(stem, report.not_compared.clone());
        for (k, n) in &report.compared {
            *all.entry(k).or_default() += n;
        }
        for (k, n) in &report.not_compared {
            *all_skipped.entry(k).or_default() += n;
        }
        found.extend(report.found);
    }
    let explained = explained();
    let unexplained: Vec<&Disagreement> = found.iter().filter(|d| !explained.contains(d)).collect();
    let gone: Vec<&Disagreement> = explained.iter().filter(|d| !found.contains(d)).collect();
    eprintln!("all fixtures: compared {all:?}");
    eprintln!("all fixtures: not compared {all_skipped:?}");
    for n in &not_compared {
        eprintln!("not compared with V8: {n}");
    }
    eprintln!(
        "{} comparisons with V8, {} disagreements, {} explained",
        all.values().sum::<usize>(),
        found.len(),
        found.len() - unexplained.len()
    );
    assert!(unexplained.is_empty(), "{} unexplained disagreements:\n{unexplained:#?}", unexplained.len());
    assert!(gone.is_empty(), "explained disagreements no longer found (remove them from EXPLAINED):\n{gone:#?}");
    // Every fixture compared, and no other, with exactly the counts of what
    // V8 does not print: a fact lost or gained shows here even where V8's
    // lines cannot show it.
    let changed: Vec<String> = counted
        .keys()
        .chain(expected.keys())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter(|stem| counted.get(*stem) != expected.get(*stem))
        .map(|stem| format!("{stem}: counted {:?}, NOT_COMPARED says {:?}", counted.get(stem), expected.get(stem)))
        .collect();
    assert!(changed.is_empty(), "the counts of what V8 does not print changed:\n{}", changed.join("\n"));
}

/// The comparison is calibrated: a recording changed in one place gives
/// exactly one disagreement more, at that place. One change for each kind of
/// rule: a number, a label's depth, a try_table clause, a declaration's
/// initial value, limits, `shared` and a structure's field.
#[test]
fn a_changed_recording_gives_a_disagreement_where_it_changed() {
    for (stem, anchor, changed, at) in [
        ("core", "000156:     f32.const 1.5\n", "000156:     f32.const 1.25\n", "func 2 at 0x156"),
        ("core", "0000b4:         br $label3\n", "0000b4:         br $label2\n", "func 0 at 0xb4"),
        ("eh", "catch $code $label0\n0000a7", "catch $tag1 $label0\n0000a7", "func 1 at 0xa1"),
        (
            "core",
            "00003c:   (global $global0 (mut i32) (i32.const 0))\n",
            "00003c:   (global $global0 (mut i32) (i32.const 1))\n",
            "global 0",
        ),
        ("core", "00002c:   (table $table0 4 8 funcref)\n", "00002c:   (table $table0 4 9 funcref)\n", "table 0"),
        ("threads", "000047:   (memory $memory3 1 1 shared)\n", "000047:   (memory $memory3 1 1)\n", "memory 3"),
        ("gc", "00006a:   (type $type6 (array (field i16)))\n", "00006a:   (type $type6 (array (field i8)))\n", "type 6"),
    ] {
        let m = common::module(stem);
        let recording = common::text(&format!("{stem}.v8.txt"));
        let baseline = compare_fixture(stem, &m, &recording).found;
        assert_eq!(recording.matches(anchor).count(), 1, "the anchor {anchor:?} is in {stem}.v8.txt once");
        let found = compare_fixture(stem, &m, &recording.replacen(anchor, changed, 1)).found;
        let new: Vec<&Disagreement> = found.iter().filter(|d| !baseline.contains(d)).collect();
        assert_eq!(new.len(), 1, "{stem}, {anchor:?}: {new:#?}");
        assert_eq!(new[0].at, at, "{stem}, {anchor:?}");
    }
}

/// The normalisers are part of the measurement: each rule must turn V8's
/// spelling into the canonical one, checked on lines copied from the
/// recordings.
#[test]
fn the_normalisers_map_each_spelling_to_the_canonical_one() {
    let mut names = Names::default();
    names.declare("func", Some("$env.unary"), Some(0), 0);
    names.declare("func", Some("$multi"), Some(3), 3);
    names.declare("table", Some("$table1"), None, 1);
    names.declare("table", Some("$table2"), None, 2);
    names.declare("global", Some("$__stack_pointer"), Some(0), 0);
    names.declare("tag", Some("$env.failure"), Some(0), 0);
    names.declare("tag", Some("$code"), Some(2), 2);
    names.declare("tag", Some("$tag3"), None, 3);
    names.declare("elem", Some("$elem0"), None, 0);
    names.declare("elem", Some("$elem1"), None, 1);
    names.fields.insert(4, [("$field17".to_string(), 17)].into_iter().collect());
    let locals: HashMap<String, u32> = [("$var0".to_string(), 0), ("$var6".to_string(), 6)].into_iter().collect();
    let scope = || Scope::new(&names, &locals, Frames(vec![None]));
    let line = |text: &str| from_v8(text, &mut scope());

    // Names, from the declarations and V8's numbering.
    assert_eq!(line("local.get $var0"), "local.get 0");
    assert_eq!(line("call $multi"), "call 3");
    assert_eq!(line("return_call $env.unary"), "return_call 0");
    assert_eq!(line("global.set $__stack_pointer"), "global.set 0");
    assert_eq!(line("throw $env.failure"), "throw 0");
    assert_eq!(line("call_ref $type1"), "call_ref 1");
    assert_eq!(line("table.get $table2"), "table.get 2");
    assert_eq!(line("table.copy"), "table.copy 0 0");
    assert_eq!(line("table.copy $table1 $table1"), "table.copy 1 1");
    assert_eq!(line("table.init $elem1"), "table.init 0 1");
    assert_eq!(line("elem.drop $elem0"), "elem.drop 0");
    assert_eq!(line("call $nowhere"), "call $nowhere?");
    // Memory indices of the bulk instructions, which V8 prints.
    assert_eq!(line("memory.init 1"), "memory.init 1");
    assert_eq!(line("memory.init 2 2"), "memory.init 2 2");
    assert_eq!(line("memory.size 1"), "memory.size 1");
    assert_eq!(line("memory.copy 1 2"), "memory.copy 1 2");
    assert_eq!(line("memory.fill"), "memory.fill");
    // Memory arguments: a natural alignment and a zero offset omitted.
    assert_eq!(line("i32.load offset=4294967300"), "i32.load offset=4294967300 align=4");
    assert_eq!(line("i64.load8_u"), "i64.load8_u offset=0 align=1");
    assert_eq!(line("f32.load offset=16 align=1"), "f32.load offset=16 align=1");
    assert_eq!(line("v128.load32_lane offset=1392 align=1 1"), "v128.load32_lane offset=1392 align=1 1");
    assert_eq!(line("v128.load8x8_u offset=48 align=1"), "v128.load8x8_u offset=48 align=1");
    assert_eq!(line("v128.load offset=16 align=1"), "v128.load offset=16 align=1");
    assert_eq!(line("memory.atomic.notify offset=4294967296"), "memory.atomic.notify offset=4294967296 align=4");
    assert_eq!(line("memory.atomic.wait32 offset=4"), "memory.atomic.wait32 offset=4 align=4");
    assert_eq!(line("memory.atomic.wait64 offset=8"), "memory.atomic.wait64 offset=8 align=8");
    assert_eq!(line("i64.atomic.rmw32.cmpxchg_u offset=8"), "i64.atomic.rmw32.cmpxchg_u offset=8 align=4");
    assert_eq!(line("i32.atomic.rmw8.add_u offset=0"), "i32.atomic.rmw8.add_u offset=0 align=1");
    assert_eq!(line("atomic.fence"), "atomic.fence");
    // Every class of natural alignment, each with the alignment omitted as
    // V8 omits a natural one: the width the name states (8, 16, 32, 64
    // bits), the width of the type (i32, i64, f32, f64, v128), the 64 bits a
    // `v128.loadNxM` reads, and the three atomics whose name states none.
    // The widths are the specification's (`memarg` natural alignment; the
    // threads overview requires an atomic access to state exactly it).
    assert_eq!(line("i32.store8"), "i32.store8 offset=0 align=1");
    assert_eq!(line("i64.load16_s"), "i64.load16_s offset=0 align=2");
    assert_eq!(line("i64.store32"), "i64.store32 offset=0 align=4");
    assert_eq!(line("v128.load64_splat"), "v128.load64_splat offset=0 align=8");
    assert_eq!(line("i32.store"), "i32.store offset=0 align=4");
    assert_eq!(line("i64.load"), "i64.load offset=0 align=8");
    assert_eq!(line("f32.load"), "f32.load offset=0 align=4");
    assert_eq!(line("f64.store"), "f64.store offset=0 align=8");
    assert_eq!(line("v128.load"), "v128.load offset=0 align=16");
    assert_eq!(line("v128.load16x4_s"), "v128.load16x4_s offset=0 align=8");
    assert_eq!(line("v128.load64_lane 1"), "v128.load64_lane offset=0 align=8 1");
    assert_eq!(line("i64.atomic.load"), "i64.atomic.load offset=0 align=8");
    assert_eq!(line("i32.atomic.rmw16.xchg_u"), "i32.atomic.rmw16.xchg_u offset=0 align=2");
    assert_eq!(line("memory.atomic.notify"), "memory.atomic.notify offset=0 align=4");
    assert_eq!(line("memory.atomic.wait32"), "memory.atomic.wait32 offset=0 align=4");
    assert_eq!(line("memory.atomic.wait64"), "memory.atomic.wait64 offset=0 align=8");
    // Numbers: floats as bits, vector words in lower case.
    assert_eq!(line("f32.const 1.5"), "f32.const bits=0x3fc00000");
    assert_eq!(line("f32.const -0.0"), "f32.const bits=0x80000000");
    assert_eq!(line("f32.const 1.40129846e-45"), "f32.const bits=0x00000001");
    assert_eq!(line("f32.const 3.40282347e+38"), "f32.const bits=0x7f7fffff");
    assert_eq!(line("f32.const nan"), "f32.const bits=0x7fc00000");
    assert_eq!(line("f32.const -nan:0x1"), "f32.const bits=0xff800001");
    assert_eq!(line("f32.const -inf"), "f32.const bits=0xff800000");
    assert_eq!(line("f64.const 5e-324"), "f64.const bits=0x0000000000000001");
    assert_eq!(line("f64.const -nan:0xfffffffffffff"), "f64.const bits=0xffffffffffffffff");
    assert_eq!(line("f64.const 3"), "f64.const bits=0x4008000000000000");
    assert_eq!(
        line("v128.const i32x4 0x03020100 0x07060504 0x0B0A0908 0x0F0E0D0C"),
        "v128.const i32x4 0x03020100 0x07060504 0x0b0a0908 0x0f0e0d0c"
    );
    assert_eq!(line("i32.const -1"), "i32.const -1");
    // Types: signatures, `select`, references.
    assert_eq!(line("select i32"), "select (result i32)");
    assert_eq!(line("select (ref null $type1)"), "select (result (ref null 1))");
    assert_eq!(line("select funcref"), "select (result funcref)");
    assert_eq!(line("call_indirect (param i32 i32) (result i32)"), "call_indirect 0 (param i32 i32) (result i32)");
    assert_eq!(
        line("return_call_indirect (param i32) (result i32) $table1"),
        "return_call_indirect 1 (param i32) (result i32)"
    );
    assert_eq!(line("block (param i32) (result i32) (result i64)"), "block (param i32) (result i32 i64)");
    // A label no open block has is marked, so that it shows as a disagreement.
    assert_eq!(
        line("try_table (param i32) (result i32) catch_all $label2"),
        "try_table (param i32) (result i32) (catch_all $label2?)"
    );
    assert_eq!(line("ref.null $type1"), "ref.null 1");
    assert_eq!(line("ref.null noexn"), "ref.null noexn");
    assert_eq!(line("ref.test $type0"), "ref.test (ref 0)");
    assert_eq!(line("ref.test null $type1"), "ref.test (ref null 1)");
    assert_eq!(line("ref.test eq"), "ref.test (ref eq)");
    assert_eq!(line("ref.test null i31"), "ref.test i31ref");
    assert_eq!(line("ref.cast null func"), "ref.cast funcref");
    assert_eq!(line("struct.get $type4 $field17"), "struct.get 4 17");
    assert_eq!(line("struct.new_default $type3"), "struct.new_default 3");
    assert_eq!(line("array.new_fixed $type6 3"), "array.new_fixed 6 3");
    assert_eq!(line("array.new_data $type5 0"), "array.new_data 5 0");
    assert_eq!(line("array.new_elem $type11 $elem0"), "array.new_elem 11 0");
    assert_eq!(line("array.copy $type5 $type5"), "array.copy 5 5");
    // Relaxed SIMD under the drafts' names.
    assert_eq!(line("f32x4.qfma"), "f32x4.relaxed_madd");
    assert_eq!(line("f32x4.qfms"), "f32x4.relaxed_nmadd");
    assert_eq!(line("f64x2.qfma"), "f64x2.relaxed_madd");
    assert_eq!(line("f64x2.qfms"), "f64x2.relaxed_nmadd");
    assert_eq!(line("i16x8.dot_i8x16_i7x16_s"), "i16x8.relaxed_dot_i8x16_i7x16_s");
    assert_eq!(line("i32x4.dot_i8x16_i7x16_add_s"), "i32x4.relaxed_dot_i8x16_i7x16_add_s");
    assert_eq!(line("i8x16.relaxed_swizzle"), "i8x16.relaxed_swizzle");

    // Labels: the depth of the block V8 named, a block with no label counted
    // too (eh.wat's function 2, lines 0xeb to 0x105, and gc.wat's 0x4ad).
    let mut s = scope();
    let lines = [
        ("block $label3 (result exnref)", "block (result exnref)"),
        ("block $label2", "block"),
        ("block $label1 (result i32) (result i64) (result exnref)", "block (result i32 i64 exnref)"),
        ("block $label0 (result i32)", "block (result i32)"),
        (
            "try_table (result i32) catch $code $label0 catch_ref $tag3 $label1 catch_all $label2 catch_all_ref $label3",
            "try_table (result i32) (catch 2 0) (catch_ref 3 1) (catch_all 2) (catch_all_ref 3)",
        ),
        ("local.get $var0", "local.get 0"),
        ("br $label2", "br 3"),
        ("end", "end"),
        ("br_table $label0 $label3 $label1", "br_table 0 3 1"),
        ("end $label0", "end"),
        ("br_on_cast $label1 (ref any) (ref $type0)", "br_on_cast 0 (ref any) (ref 0)"),
        ("br_on_cast_fail $label2 eqref arrayref", "br_on_cast_fail 1 eqref arrayref"),
        ("end $label1", "end"),
    ];
    for (v8, canonical) in lines {
        assert_eq!(from_v8(v8, &mut s), canonical, "{v8}");
    }
    // Legacy exception handling (eh-legacy.wat, function $delegates and
    // $rethrows): `delegate` counts from outside the `try` it closes.
    let mut s = scope();
    for (v8, canonical) in [
        ("try $label0 (result i32)", "try (result i32)"),
        ("try", "try"),
        ("delegate $label0", "delegate 0"),
        ("catch $tag3", "catch 3"),
        ("block", "block"),
        ("rethrow $label0", "rethrow 1"),
        ("end", "end"),
        ("catch_all", "catch_all"),
        ("end", "end"),
        ("try", "try"),
        ("delegate $label0", "delegate $label0?"),
    ] {
        assert_eq!(from_v8(v8, &mut s), canonical, "{v8}");
    }

    // Constant expressions and declarations.
    assert_eq!(
        v8_constant(&sexprs("(i64.const 1) (i64.const 2) (i64.add) (i64.const 3) (i64.const 4) (i64.mul) (i64.sub)"), &names),
        "(i64.const 1) (i64.const 2) (i64.add) (i64.const 3) (i64.const 4) (i64.mul) (i64.sub)"
    );
    assert_eq!(
        v8_constant(&sexprs("(i32.const 1) (ref.null $type0) (struct.new $type0)"), &names),
        "(i32.const 1) (ref.null 0) (struct.new 0)"
    );
    assert_eq!(v8_constant(&sexprs("(ref.func $multi) (ref.null func)"), &names), "(ref.func 3) (ref.null func)");
    assert_eq!(val_type(&sexprs("(ref null $type1)")[0]), "(ref null 1)");
    // Every abbreviation of the 3.0 text format ("Reference Types", text
    // format: `funcref` is `(ref null func)` and so on), one line each; a
    // non-nullable reference has none.
    assert_eq!(val_type(&sexprs("(ref null func)")[0]), "funcref");
    assert_eq!(val_type(&sexprs("(ref null nofunc)")[0]), "nullfuncref");
    assert_eq!(val_type(&sexprs("(ref null extern)")[0]), "externref");
    assert_eq!(val_type(&sexprs("(ref null noextern)")[0]), "nullexternref");
    assert_eq!(val_type(&sexprs("(ref null any)")[0]), "anyref");
    assert_eq!(val_type(&sexprs("(ref null eq)")[0]), "eqref");
    assert_eq!(val_type(&sexprs("(ref null i31)")[0]), "i31ref");
    assert_eq!(val_type(&sexprs("(ref null struct)")[0]), "structref");
    assert_eq!(val_type(&sexprs("(ref null array)")[0]), "arrayref");
    assert_eq!(val_type(&sexprs("(ref null none)")[0]), "nullref");
    assert_eq!(val_type(&sexprs("(ref null exn)")[0]), "exnref");
    assert_eq!(val_type(&sexprs("(ref null noexn)")[0]), "nullexnref");
    assert_eq!(val_type(&sexprs("(ref nofunc)")[0]), "(ref nofunc)");
    assert_eq!(val_type(&sexprs("(ref noexn)")[0]), "(ref noexn)");
    assert_eq!(val_type(&sexprs("(ref func)")[0]), "(ref func)");
    assert_eq!(val_type(&sexprs("nullexnref")[0]), "nullexnref");
    assert_eq!(v8_signature(&sexprs("(param $var0 i32) (param $var1 i64) (result i32)")).0, " (param i32 i64) (result i32)");
    assert_eq!(v8_signature(&sexprs("(param i32 i64)")).0, " (param i32 i64)");
    assert_eq!(
        v8_subtype(
            &sexprs("(sub final $type1 (struct (field $field0 i32) (field $field1 (mut (ref null $type0))) (field $field4 (mut i64))))")[0]
        ),
        "(sub final 1 (struct (field i32) (field (mut (ref null 0))) (field (mut i64))))"
    );
    assert_eq!(v8_subtype(&sexprs("(struct)")[0]), "(struct)");
    assert_eq!(v8_subtype(&sexprs("(array (field (mut (ref null $type0))))")[0]), "(array (mut (ref null 0)))");
    assert_eq!(v8_subtype(&sexprs("(array (field i16))")[0]), "(array i16)");
    let data = sexprs(r#"(data (i32.const 65536) "\07\00\ef\cd\ab\89gE#\01\f8?(\00\0a")"#);
    let bytes = vec![7, 0, 0xef, 0xcd, 0xab, 0x89, b'g', b'E', b'#', 1, 0xf8, b'?', b'(', 0, 10];
    assert_eq!(data[0].list().unwrap()[2], Sx::Str(bytes));
    // Every escape of the text format's strings, one each.
    assert_eq!(sexprs(r#""\n""#)[0], Sx::Str(vec![b'\n']));
    assert_eq!(sexprs(r#""\t""#)[0], Sx::Str(vec![b'\t']));
    assert_eq!(sexprs(r#""\r""#)[0], Sx::Str(vec![b'\r']));
    assert_eq!(sexprs(r#""\"""#)[0], Sx::Str(vec![b'"']));
    assert_eq!(sexprs(r#""\'""#)[0], Sx::Str(vec![b'\'']));
    assert_eq!(sexprs(r#""\\""#)[0], Sx::Str(vec![b'\\']));
    assert_eq!(sexprs(r#""\Ff""#)[0], Sx::Str(vec![0xff]));
    let header = r#"(func $env.pair (;0;) (export "imported_again") (import "env" "pair") (param i32) (result i32) (result i64))"#;
    let d = decl(0, "func", &sexprs(header)[0].list().unwrap()[1..]);
    assert_eq!(d.origin(), r#" (import "env" "pair") (export "imported_again")"#);
    assert_eq!(v8_signature(&d.rest).0, " (param i32) (result i32 i64)");
}

/// Every recording of V8's answer in `tests/fixtures/` is one of a fixture
/// the comparison reads, and every fixture has exactly one, so that no
/// recording sits unread and no fixture goes uncompared.
#[test]
fn every_v8_recording_belongs_to_a_fixture() {
    let mut stray = Vec::new();
    for entry in std::fs::read_dir(common::dir()).expect("the fixtures directory") {
        let name = entry.expect("a directory entry").file_name().into_string().expect("a UTF-8 file name");
        let stem = name.strip_suffix(".v8.txt").or_else(|| name.strip_suffix(".v8-refuses.txt"));
        if let Some(stem) = stem.filter(|stem| !common::FIXTURES.contains(stem)) {
            stray.push(format!("{name} ({stem} is no fixture)"));
        }
    }
    assert!(stray.is_empty(), "recordings of V8 for no fixture: {stray:?}");
    for stem in common::FIXTURES {
        // Panics unless exactly one of the two is there and reads as what it is.
        v8_answer(&common::dir(), stem);
    }
}

/// The record of a refusal, on synthetic records in a directory of their
/// own: what V8 refused is read as a refusal, and a tool that failed, a
/// record without its status or one of another tool is not. The records are
/// written here in the shape `build.sh` writes; that it does is
/// [`build_sh_writes_a_v8_refusal_as_this_file_reads_it`]'s to check.
#[test]
fn a_refusal_is_read_only_as_v8_refusing() {
    let refused = "v8dis.mjs: V8 refuses the module: WebAssembly.Module(): expected magic word 00 61 73 6d, found 00 00 00 00 @+0";
    assert_eq!(v8_refusal(&format!("{refused}\nexit status 1\n")), Ok(refused));
    // v8dis.mjs's status 2: the tool failed, V8 said nothing.
    let failed = "v8dis.mjs: 0 WebAssembly scripts reported within 5000 ms of compiling the module, not 1";
    assert_eq!(v8_refusal(&format!("{failed}\nexit status 2\n")), Err("exit status 2, not V8's refusal (1)".to_string()));
    assert_eq!(v8_refusal(&format!("{refused}\nexit status 0\n")), Err("exit status 0, not V8's refusal (1)".to_string()));
    assert!(v8_refusal(&format!("{refused}\n")).unwrap_err().starts_with("no exit status on the last line"));
    assert!(v8_refusal("").is_err());
    assert!(v8_refusal("exit status 1\n").unwrap_err().starts_with("0 lines on stderr"));
    assert!(v8_refusal("v8dis.mjs: V8 refuses the module: \nexit status 1\n").unwrap_err().starts_with("not V8's refusal"));
    assert!(v8_refusal("wasm-objdump: error\nexit status 1\n").unwrap_err().starts_with("not V8's refusal"));

    // The branch the comparison takes, on files: a refusal in place of a
    // disassembly, both, neither.
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("v8-refusal");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("refused.v8-refuses.txt"), format!("{refused}\nexit status 1\n")).unwrap();
    assert_eq!(v8_answer(&dir, "refused"), V8Answer::Refusal(refused.to_string()));
    std::fs::write(dir.join("failed.v8-refuses.txt"), format!("{failed}\nexit status 2\n")).unwrap();
    assert_eq!(
        panic_message(|| v8_answer(&dir, "failed")).as_deref(),
        Some("failed.v8-refuses.txt: exit status 2, not V8's refusal (1)")
    );
    std::fs::write(dir.join("refused.v8.txt"), "000000: (module\n000008: )\n").unwrap();
    assert_eq!(
        panic_message(|| v8_answer(&dir, "refused")).as_deref(),
        Some("refused: both V8's disassembly and a refusal are recorded")
    );
    assert_eq!(
        panic_message(|| v8_answer(&dir, "absent")).as_deref(),
        Some("absent: neither V8's disassembly nor its refusal is recorded")
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The message `f` panics with, or `None` if it returns.
fn panic_message<T>(f: impl FnOnce() -> T) -> Option<String> {
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).err()?;
    Some(match payload.downcast::<String>() {
        Ok(s) => *s,
        Err(payload) => payload.downcast::<&str>().map(|s| s.to_string()).expect("a panic with a message"),
    })
}

/// Every item of a declaration is read or refused: an item a parser does not
/// recognise fails the comparison, so that nothing after what a rule reads is
/// passed over. Each plant is one V8 has never written, into a real
/// recording, and each must fail with its own message; every plant that does
/// not is listed at once.
///
/// Known and not fixed: [`val_type`] takes any word that is not a name as a
/// value type, so a stray word where a type stands (`(table $t 4 bogus)`)
/// is compared, and disagrees, rather than refused here; the order of a
/// declaration's parts is not checked (an `(export ..)` after a signature is
/// read as one before it); and which parts each kind may carry ([`parts`]) is
/// what the recordings show, so a V8 that named a data segment would fail
/// here, loudly, before anyone decided whether that name should be compared.
#[test]
fn an_item_no_rule_reads_fails_the_comparison() {
    let mut missed = Vec::new();
    for (stem, anchor, planted, message) in [
        // A function header: a type use and a stray word after the signature.
        (
            "gc",
            "00061d:   (func $func8 (param $var0 i32) (result i32)\n",
            "00061d:   (func $func8 (param $var0 i32) (result i32) (type $type12) bogus\n",
            "a function header item no rule reads at 0x61d",
        ),
        (
            "eh",
            "00006a:   (func $func0 (param $var0 i32) (result i32)\n",
            "00006a:   (func $func0 (result i32) (param $var0 i32)\n",
            "a parameter after a result",
        ),
        ("eh", "00006a:   (func $func0 (param $var0 i32)", "00006a:   (func $func0 (param $var0 i32 i64)", "a value type, not"),
        // The start function: a number after its name.
        ("shapes", "0000e6:   (start $func2)\n", "0000e6:   (start $func2 999)\n", "a start declaration no recording has shown"),
        // A structure's field and an array's of two types, a field with no
        // name in a structure, a mutable type with a second one.
        (
            "gc",
            "00006a:   (type $type6 (array (field i16)))\n",
            "00006a:   (type $type6 (array (field i16 i8)))\n",
            "a field no recording has shown",
        ),
        ("gc", "    (field $field0 i8)\n", "    (field $field0 i8 i16)\n", "a field no recording has shown"),
        ("gc", "    (field $field0 i8)\n", "    (field i8)\n", "a field no recording has shown"),
        ("gc", "    (field $field1 (mut i8))\n", "    (field $field1 (mut i8 i16))\n", "a mutable storage type no recording"),
        // A local of two types.
        ("gc", "(local $var5 (ref null $type0))", "(local $var5 (ref null $type0) i32)", "a local no recording has shown"),
        // The parts `decl` takes out of every declaration: each a second
        // time, or with an item more, or on a kind that cannot carry it. Each
        // plant repeats what the line already says, so that a parser keeping
        // only the last or the first would agree with the reader.
        (
            "ctarget-O2",
            "(func $host.report (;0;) (import",
            "(func $host.report (;0;) (;0;) (import",
            "(func ..) at 0x5b with a second index comment, which no rule reads",
        ),
        (
            "ctarget-O2",
            r#"(import "host" "report") (param i32 i64))"#,
            r#"(import "host" "report") (import "host" "report") (param i32 i64))"#,
            "(func ..) at 0x5b with a second import, which no rule reads",
        ),
        (
            "threads",
            r#"(memory $env.memory (;0;) (import "env" "memory")"#,
            r#"(memory $env.memory (;0;) (import "env" "memory" "memory")"#,
            "(memory ..) at 0x24 with an import of another shape than V8's, which no rule reads",
        ),
        (
            "threads",
            r#"(memory $wide (;1;) (export "wide")"#,
            r#"(memory $wide (;1;) (export "wide" "wide")"#,
            "(memory ..) at 0x47 with an export of another shape than V8's, which no rule reads",
        ),
        (
            "core",
            "000049:   (elem $elem0 (i32.const 0)",
            r#"000049:   (elem $elem0 (export "elem0") (i32.const 0)"#,
            "(elem ..) at 0x49 with an export, which no rule reads",
        ),
        (
            "gc",
            "00006a:   (type $type6 (array",
            r#"00006a:   (type $type6 (export "type6") (array"#,
            "(type ..) at 0x6a with an export, which no rule reads",
        ),
        ("gc", "00006a:   (type $type6 (array", "00006a:   (type $type6 (;6;) (array", "(type ..) at 0x6a with an index comment, which no rule reads"),
        (
            "shapes",
            "0001db:   (data (i32.const 8)",
            "0001db:   (data $data0 (i32.const 8)",
            "(data ..) at 0x1db with a name, which no rule reads",
        ),
        ("shapes", "0001db:   (data (i32.const 8)", "0001db:   (data (;0;) (i32.const 8)", "(data ..) at 0x1db with an index comment, which no rule reads"),
        // A global's mutable type and a segment's table, each with an item
        // after the one its reader takes.
        (
            "core",
            "000041:   (global $global1 (mut i64) (i64.const 0))",
            "000041:   (global $global1 (mut i64 i32) (i64.const 0))",
            "a global type no recording has shown at 0x41",
        ),
        (
            "refs",
            "(elem $elem1 (table $table1) (i32.const 0)",
            "(elem $elem1 (table $table1 bogus) (i32.const 0)",
            "a segment's table no recording has shown at 0x91",
        ),
    ] {
        let m = common::module(stem);
        let recording = common::text(&format!("{stem}.v8.txt"));
        assert_eq!(recording.matches(anchor).count(), 1, "the anchor {anchor:?} is in {stem}.v8.txt once");
        let changed = recording.replacen(anchor, planted, 1);
        let got = panic_message(|| compare_fixture(stem, &m, &changed));
        if !got.as_deref().is_some_and(|g| g.contains(message)) {
            missed.push(format!("{stem}, {planted:?}: {got:?}, not a panic with {message:?}"));
        }
    }
    assert!(missed.is_empty(), "{} plants passed over or refused for another reason:\n{}", missed.len(), missed.join("\n"));
}

/// An operand V8 leaves out is read as index 0 and compared, in a module of
/// several memories or tables as in one (the probe at [`instruction`]): a
/// reader that put such an instruction on another memory or table disagrees.
///
/// On the fixtures, every line V8 writes without its operand in a module of
/// several memories or tables (`core`: two tables; `refs`: three; `shapes`:
/// three memories) is planted in the module's bytes with that operand 1 in
/// place of 0, the byte's place read from wabt's disassembly
/// (`<stem>.disassembly.txt`), and must give exactly one disagreement more,
/// at that line. Before this rule these five lines were set aside, counted
/// and not compared, so a reader that misread any of them passed.
///
/// Known and not fixed: the rule rests on [`v8_leaves_out_exactly_index_0`],
/// one V8 (14.6) on one probe, run only with `--features oracle`, never in
/// CI; the plants change one operand from 0 to 1 and no other value; and no
/// rule reads a `table.init` that names its table or a `memory.init` of two
/// different numbers (the probes show V8 writing both, no recording has
/// one), so such a line fails as a spelling no rule reads.
#[test]
fn an_omitted_operand_is_read_as_index_0_and_compared() {
    let locals = HashMap::new();
    let mut several = Names::default();
    for i in 0..3 {
        several.declare("memory", Some(&format!("$memory{i}")), None, i);
        several.declare("table", Some(&format!("$table{i}")), None, i);
    }
    several.declare("elem", Some("$elem0"), None, 0);
    for (v8, canonical) in [
        ("memory.init 1", "memory.init 1"),
        ("memory.size", "memory.size"),
        ("memory.grow", "memory.grow"),
        ("memory.fill", "memory.fill"),
        ("memory.copy", "memory.copy"),
        ("table.copy", "table.copy 0 0"),
        ("table.init $elem0", "table.init 0 0"),
        ("call_indirect (param i32)", "call_indirect 0 (param i32)"),
        ("return_call_indirect (result i32)", "return_call_indirect 0 (result i32)"),
    ] {
        assert_eq!(from_v8(v8, &mut Scope::new(&several, &locals, Frames(vec![None]))), canonical, "{v8}");
    }

    // (fixture, the instruction's offset, wabt's line for it, the offset of
    // the operand's byte, the place the disagreement is reported).
    for (stem, at, wabt, operand, place) in [
        ("core", 0xcf, "0000cf: 11 02 00                   | call_indirect 0 (type 2)", 0xd1, "func 0 at 0xcf"),
        ("core", 0x589, "000589: fc 0e 00 00                | table.copy 0 0", 0x58b, "func 4 at 0x589"),
        ("core", 0x59d, "00059d: fc 0c 01 00                | table.init 1 0", 0x5a0, "func 4 at 0x59d"),
        ("refs", 0xe7, "0000e7: 13 01 00                   |   return_call_indirect 1 0", 0xe9, "func 6 at 0xe7"),
        ("shapes", 0x1c8, "0001c8: fc 08 00 00                | memory.init 0 0 <form0_data>", 0x1cb, "func 4 at 0x1c8"),
    ] {
        assert_eq!(common::text(&format!("{stem}.disassembly.txt")).matches(wabt).count(), 1, "{stem}: wabt's line {wabt:?}");
        let recording = common::text(&format!("{stem}.v8.txt"));
        let baseline = compare_fixture(stem, &common::module(stem), &recording).found;
        let mut bytes = common::bytes(stem);
        assert_eq!(bytes[operand], 0, "{stem}: the operand at {operand:#x} of the instruction at {at:#x} is index 0");
        bytes[operand] = 1;
        let planted = n0xis_wasm::read(&bytes).unwrap_or_else(|e| panic!("{stem}, planted: {e}"));
        let found = compare_fixture(stem, &planted, &recording).found;
        let new: Vec<&Disagreement> = found.iter().filter(|d| !baseline.contains(d)).collect();
        assert_eq!(new.iter().map(|d| d.at.as_str()).collect::<Vec<_>>(), [place], "{stem}, operand at {operand:#x}: {new:#?}");
    }
}

/// Run `program` with `args`, which must succeed; its stdout.
#[cfg(feature = "oracle")]
fn run(program: &str, args: &[&std::ffi::OsStr]) -> Vec<u8> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("{program} does not run (a missing tool is a failure): {e}"));
    assert!(out.status.success(), "{program} {args:?}: {}\n{}", out.status, String::from_utf8_lossy(&out.stderr));
    out.stdout
}

/// `build.sh` writes a V8 refusal in exactly the shape [`v8_refusal`] reads.
/// Its `--v8-refusal` mode runs the function its fixture loop runs for a
/// module V8 refuses; on a module without the magic word the record it
/// writes reads here as V8's refusal, with V8's message, and on a module V8
/// compiles (status 0) or one `v8dis.mjs` cannot read (status 2, the tool
/// failing: a file that is not there) it fails rather than recording one,
/// and leaves no record behind. (Without the status-2 case a `build.sh` that
/// took `1|2` for a refusal passed every test, calibrated 2026-10-20.)
///
/// Known and not fixed: no fixture is refused by V8, so the loop branch of
/// `build.sh` that calls the same function for a listed fixture has never
/// run; `tests/oracle.rs` derives a `<stem>.v8.txt` for every fixture and
/// knows no list of V8's refusals, so listing one in `build.sh`'s
/// `v8_refuses` fails its rebuild test (a file made that it does not list)
/// until `tests/common/` gains that list beside `WABT_REFUSES`, and the two
/// lists of refusals (`build.sh`'s and `tests/common/`'s) are one fact in two
/// places that only that rebuild test compares; V8's message is pinned to
/// V8 14.6.
#[cfg(feature = "oracle")]
#[test]
fn build_sh_writes_a_v8_refusal_as_this_file_reads_it() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("v8-refusal-recorded");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let build = common::dir().join("build.sh");
    let record_of = |stem: &str| dir.join(format!("{stem}.v8-refuses.txt"));
    let run = |module: &std::path::Path, stem: &str| {
        std::process::Command::new("sh").arg(&build).arg("--v8-refusal").arg(module).arg(record_of(stem)).output().expect("sh runs")
    };
    let record = |stem: &str, bytes: &[u8]| {
        let module = dir.join(format!("{stem}.wasm"));
        std::fs::write(&module, bytes).unwrap();
        run(&module, stem)
    };

    let refused = record("refused", &[0, 0, 0, 0, 1, 0, 0, 0]);
    assert!(refused.status.success(), "build.sh --v8-refusal: {}\n{}", refused.status, String::from_utf8_lossy(&refused.stderr));
    assert_eq!(
        v8_answer(&dir, "refused"),
        V8Answer::Refusal(
            "v8dis.mjs: V8 refuses the module: WebAssembly.Module(): expected magic word 00 61 73 6d, found 00 00 00 00 @+0"
                .to_string()
        )
    );

    let compiled = record("compiled", b"\0asm\x01\0\0\0");
    assert!(!compiled.status.success(), "build.sh recorded a refusal of a module V8 compiles");
    let stderr = String::from_utf8_lossy(&compiled.stderr);
    assert!(stderr.contains("V8 compiles"), "build.sh --v8-refusal on a module V8 compiles: {stderr}");
    assert!(!record_of("compiled").exists(), "build.sh left a record of a module V8 compiles");

    // v8dis.mjs exits 2 on a module it cannot read: the tool failed, V8 said
    // nothing, and that is no refusal.
    let absent = dir.join("absent.wasm");
    assert!(!absent.exists());
    let failed = run(&absent, "absent");
    assert!(!failed.status.success(), "build.sh recorded v8dis.mjs failing (status 2) as V8's refusal");
    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(stderr.contains("(exit status 2), which is no verdict"), "build.sh --v8-refusal on a module that is not there: {stderr}");
    assert!(!record_of("absent").exists(), "build.sh left a record of v8dis.mjs failing");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// What [`instruction`] rests on: V8 leaves out a memory or a table operand
/// exactly when it is index 0, with several memories and tables as with one.
/// The probe holds every instruction with such an operand on index 0 and on
/// another, in a module of three memories and three tables; V8 14.6
/// (v8dis.mjs) must write exactly the lines below for it, stripped as the
/// fixtures are, and the comparison must agree with the reader on every
/// line. A V8 that began to write an index 0, or to leave out another, fails
/// here before it can make a recording read wrongly.
///
/// Known and not fixed: the probe has one function and indices 0 to 2 only;
/// its V8 lines are pinned to V8 14.6, so a V8 upgrade that changes any of
/// them fails here and must be read, as `build.sh`'s recordings must.
#[cfg(feature = "oracle")]
#[test]
fn v8_leaves_out_exactly_index_0() {
    const PROBE: &str = r#"(module
  (type $t (func (param i32) (result i32)))
  (memory 1) (memory 1) (memory 1)
  (table 1 funcref) (table 1 funcref) (table 1 funcref)
  (elem $e0 func) (elem $e1 func) (elem $e2 func)
  (data $d0 "") (data $d1 "") (data $d2 "")
  (func (param i32) (result i32)
    (drop (memory.size 0)) (drop (memory.size 1)) (drop (memory.size 2))
    (drop (memory.grow 0 (i32.const 0))) (drop (memory.grow 2 (i32.const 0)))
    (memory.fill 0 (i32.const 0) (i32.const 0) (i32.const 0))
    (memory.fill 1 (i32.const 0) (i32.const 0) (i32.const 0))
    (memory.copy 0 0 (i32.const 0) (i32.const 0) (i32.const 0))
    (memory.copy 0 1 (i32.const 0) (i32.const 0) (i32.const 0))
    (memory.copy 1 0 (i32.const 0) (i32.const 0) (i32.const 0))
    (memory.init 0 $d1 (i32.const 0) (i32.const 0) (i32.const 0))
    (memory.init 2 $d2 (i32.const 0) (i32.const 0) (i32.const 0))
    (table.copy 0 0 (i32.const 0) (i32.const 0) (i32.const 0))
    (table.copy 0 2 (i32.const 0) (i32.const 0) (i32.const 0))
    (table.copy 2 0 (i32.const 0) (i32.const 0) (i32.const 0))
    (table.init 0 $e1 (i32.const 0) (i32.const 0) (i32.const 0))
    (drop (call_indirect 0 (type $t) (i32.const 0) (i32.const 0)))
    (drop (call_indirect 2 (type $t) (i32.const 0) (i32.const 0)))
    (if (local.get 0) (then (return_call_indirect 2 (type $t) (i32.const 0) (i32.const 0))))
    (return_call_indirect 0 (type $t) (i32.const 0) (i32.const 0))))
"#;
    const V8_WRITES: [&str; 20] = [
        "memory.size",
        "memory.size 1",
        "memory.size 2",
        "memory.grow",
        "memory.grow 2",
        "memory.fill",
        "memory.fill 1",
        "memory.copy",
        "memory.copy 0 1",
        "memory.copy 1 0",
        "memory.init 1",
        "memory.init 2 2",
        "table.copy",
        "table.copy $table0 $table2",
        "table.copy $table2 $table0",
        "table.init $elem1",
        "call_indirect (param i32) (result i32)",
        "call_indirect (param i32) (result i32) $table2",
        "return_call_indirect (param i32) (result i32) $table2",
        "return_call_indirect (param i32) (result i32)",
    ];
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("v8-omitted-probe");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (wat, wasm, stripped) = (dir.join("probe.wat"), dir.join("probe.wasm"), dir.join("probe.stripped.wasm"));
    std::fs::write(&wat, PROBE).unwrap();
    run("wasm-tools", &["parse".as_ref(), wat.as_os_str(), "-o".as_ref(), wasm.as_os_str()]);
    run("wasm-tools", &["strip".as_ref(), "--all".as_ref(), wasm.as_os_str(), "-o".as_ref(), stripped.as_os_str()]);
    let recording = String::from_utf8(run("node", &[common::dir().join("v8dis.mjs").as_os_str(), stripped.as_os_str()])).unwrap();
    let operand_lines: Vec<&str> = v8_lines(&recording)
        .into_iter()
        .map(|l| l.text)
        .filter(|t| ["memory.", "table.", "call_indirect", "return_call_indirect"].iter().any(|p| t.starts_with(p)))
        .collect();
    assert_eq!(operand_lines, V8_WRITES, "V8's lines for the probe:\n{recording}");

    let m = n0xis_wasm::read(&std::fs::read(&stripped).unwrap()).expect("the probe reads");
    let report = compare_fixture("probe", &m, &recording);
    assert!(report.found.is_empty(), "the probe: {:#?}", report.found);
    assert!(report.compared.get("instructions").copied().unwrap_or(0) > V8_WRITES.len(), "the probe: {:?}", report.compared);
    std::fs::remove_dir_all(&dir).unwrap();
}
