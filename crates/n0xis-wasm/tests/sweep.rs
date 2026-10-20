// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Every byte at every module-level decision point is read as an independent
//! decoder reads it.** A local instrument, not a CI gate (`--features
//! oracle`): it runs wasm-tools and node from this machine.
//!
//! At each decision point ([`points`]) the module is built 256 times, once
//! per byte, and for each byte once per continuation the point lists: bytes
//! after the swept one that complete it where the byte begins something the
//! format gives (`0x63` needs a heap type, `0x4e` a count and a subtype).
//! Three judges look at each module: the reader (`read`, and every body),
//! `wasm-tools print` (which decodes without validating) and V8
//! (`new WebAssembly.Module`, which validates too, through
//! `tools/v8-validate-dir.mjs`, one process for every module).
//!
//! The test fails when
//! - the reader reads a module wasm-tools cannot decode: the reader accepts
//!   bytes the format does not give;
//! - the reader refuses a module wasm-tools decodes and V8 accepts, whatever
//!   [`OUTSIDE_SCOPE`] says: two independent decoders read it, and one
//!   compiles it with its defaults;
//! - the reader refuses a module wasm-tools decodes and V8 refuses, and the
//!   byte is not in [`OUTSIDE_SCOPE`]. V8's refusal alone settles nothing: it
//!   validates, and it lacks proposals, and neither says the bytes are
//!   malformed. So each such byte is named with the proposal it belongs to;
//! - an [`OUTSIDE_SCOPE`] entry, keyed by the point and the byte, does not
//!   account for exactly the modules it states, so a byte that no longer
//!   occurs, or occurs at a new point, is looked at; or the evidence of its
//!   proposal is not in what the tools said of each of them (wasm-tools' text
//!   holds the proposal's construct, V8's refusal names the proposal);
//! - what a judge read and refused at a point is not the point's stated
//!   [`Tally`]: a ratchet, so that a reader change or a tool upgrade that
//!   moves any of them is looked at, even where no judge disagrees;
//! - the reader stops (`Error::Internal`), or a judge gives no verdict: a tool
//!   that cannot run, a file that is not there, an exit status that is neither
//!   0 nor 1, a refusal with nothing on stderr, a line of V8's of no known
//!   shape. Each judge is first shown two controls, a minimal module it must
//!   accept and one with no magic it must refuse.
//!
//! A module that V8 accepts and both decoders refuse is printed, not judged:
//! it says nothing against the reader. Measured 2026-10-20 there are five,
//! form 5 of an element segment whose type is `7b` to `7f`, a number or
//! vector type, with no items. wasm-tools ("malformed reference type") and
//! wabt (`wasm-validate --enable-all` and `wasm-objdump -x`: "table elem type
//! must be a reference type") refuse them, as the reader does.
//!
//! Not swept: function bodies (their opcodes are `tests/instructions.rs`'s),
//! LEB128 encodings other than the one-byte ones and `80 00` the
//! continuations use, and anything after the byte but the continuations
//! listed. A byte that begins a construct none of a point's continuations
//! completes is judged only on incomplete modules, which every judge may
//! refuse for the missing bytes alone: such a byte is not tested at that point.
//!
//! Known and not fixed:
//! - The continuations are chosen by hand to complete the shapes the format
//!   gives at each point (and, at the import kind, each kind's shape after
//!   every byte). Nothing checks that every shape is completed: a byte whose
//!   construct needs bytes no continuation gives is judged only incomplete,
//!   as `0x63` at form 5 was before `70 00` was added.
//! - Of shared-everything threads, V8 names the proposal for the type entry
//!   and after `0x63` and `0x64`. At the four positions where `0x65` begins a
//!   reference type (a value type, a field's storage type, a table's element
//!   type, form 5's reference type) it names only the byte, "invalid value
//!   type 0x65", and refuses those modules with the same words even with
//!   `--experimental-wasm-shared` (V8 14.6.202.34, measured by hand
//!   2026-10-20, not by this test). So there the proposal rests on
//!   wasm-tools' printed `(shared ...)` construct plus V8's refusal of the
//!   byte ([`V8Names::ByteOnly`]).
//! - The [`Tally`] values are the judges' own counts, measured once: the
//!   import and export kinds', form 1's and form 5's were worked out by hand
//!   from the bytes before the run and agreed, the other nine were carried
//!   from the first version's printout. A ratchet says that something moved, not that the stated
//!   number was right.
//! - V8 refuses every module of [`OUTSIDE_SCOPE`]; whether V8 with the named
//!   flag would accept it is not asked here, so V8's message is the only V8
//!   evidence of the proposal (asked by hand only of the shared-everything
//!   entries, above).
#![cfg(feature = "oracle")]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use common::planted::{module, name, section, types, vector};

/// A module-level decision point: the byte under test goes where `build`
/// puts it, followed by each continuation in turn. `tally` is what each judge
/// said over the point's modules, stated, so that a change in any of them (a
/// reader change, a tool upgrade) fails here and is looked at.
struct Point {
    name: &'static str,
    continuations: &'static [&'static [u8]],
    build: fn(u8, &[u8]) -> Vec<u8>,
    tally: Tally,
}

/// Over one point's modules, how many each judge read and how many it
/// refused: the reader reads or refuses, `wasm-tools print` decodes or
/// refuses, V8 accepts or refuses. Measured 2026-10-20 with wasm-tools 1.262.0 and V8
/// 14.6.202.34 (node 26.10.0, no flags).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Tally {
    reader: [usize; 2],
    wasm_tools: [usize; 2],
    v8: [usize; 2],
}

/// One section of one entry.
fn one_entry(id: u8, entry: &[u8]) -> Vec<u8> {
    section(id, &vector(&[entry.to_vec()]))
}

/// What follows an import's kind byte, once in the shape of each kind the
/// format gives: a function's type index `00`, a table type `70 00 01`, a
/// memory type `00 01`, a global type `7f 00`, a tag type `00 00`. Every
/// byte, defined or not, is followed by each of the five, so that a reader
/// that read a byte the format does not define as one of the five kinds would
/// read the entry it completes, where wasm-tools refuses it. Followed by a
/// function's `00` alone, as the sweep's first version did, a byte read as a
/// table, memory, global or tag left the entry incomplete, the reader refused
/// it for that, and the test agreed with it (calibrated 2026-10-20: a reader
/// that read import kind `0x05` as a table passed).
///
/// An export's kinds all take one index, which `00` completes for each; the
/// same five follow its kind byte too, so that what comes after the index is
/// swept as at the import, the four longer ones leaving bytes the entry does
/// not hold.
const KIND_PAYLOADS: &[&[u8]] = &[&[0x00], &[0x70, 0x00, 0x01], &[0x00, 0x01], &[0x7f, 0x00], &[0x00, 0x00]];

/// Every decision point and its continuations: 13 points, 41 continuations,
/// 10 496 modules. Each point's comment says what its continuations complete;
/// a point with one continuation is one where every byte the format gives
/// takes the same shape after it.
fn points() -> Vec<Point> {
    vec![
        // The first byte of a recursion group: a composite type's form,
        // `0x4e` a group, `0x50`/`0x4f` a subtype. `00` is an empty structure
        // or group, `01 5f 00` a group of one, `00 5f 00` a subtype with no
        // supertype, `5f 00` a structure, `7f 00` an array of i32, `00 00` a
        // function type.
        Point {
            name: "a type-section entry",
            continuations: &[&[], &[0x00], &[0x01, 0x5f, 0x00], &[0x00, 0x5f, 0x00], &[0x5f, 0x00], &[0x7f, 0x00], &[0x00, 0x00]],
            build: |b, c| module(&[one_entry(1, &[&[b], c].concat())]),
            tally: Tally { reader: [7, 1785], wasm_tools: [13, 1779], v8: [7, 1785] },
        },
        // `60 01 <b> <cont> 00`: a function type's only parameter.
        Point {
            name: "a value type",
            continuations: &[&[], &[0x70], &[0x00]],
            build: |b, c| module(&[one_entry(1, &[&[0x60, 0x01, b], c, &[0x00]].concat())]),
            tally: Tally { reader: [21, 747], wasm_tools: [24, 744], v8: [21, 747] },
        },
        // After a first type `60 00 00`, a second function type whose only
        // parameter is the reference, so that type index 0 exists. Nothing
        // completes a one-byte heap type, `00` and `80 00` the byte read as
        // the first byte of a type index, and `70` an abstract heap type
        // after a prefix that takes one, `0x65` shared: without `70`,
        // `63 65` was never completed, and a reader that read `63 65 70` as
        // `funcref`, dropping `shared`, passed (calibrated 2026-10-20).
        Point {
            name: "a heap type after 0x63",
            continuations: &[&[], &[0x00], &[0x80, 0x00], &[0x70]],
            build: |b, c| module(&[section(1, &vector(&[vec![0x60, 0x00, 0x00], [&[0x60, 0x01, 0x63, b], c, &[0x00]].concat()]))]),
            tally: Tally { reader: [332, 692], wasm_tools: [338, 686], v8: [18, 1006] },
        },
        // The same four, after `0x64`.
        Point {
            name: "a heap type after 0x64",
            continuations: &[&[], &[0x00], &[0x80, 0x00], &[0x70]],
            build: |b, c| module(&[section(1, &vector(&[vec![0x60, 0x00, 0x00], [&[0x60, 0x01, 0x64, b], c, &[0x00]].concat()]))]),
            tally: Tally { reader: [332, 692], wasm_tools: [338, 686], v8: [18, 1006] },
        },
        // `5f 01 <b> <cont> 00`: a structure's only field, constant; the
        // continuations are the value type's.
        Point {
            name: "a structure field's storage type",
            continuations: &[&[], &[0x70], &[0x00]],
            build: |b, c| module(&[one_entry(1, &[&[0x5f, 0x01, b], c, &[0x00]].concat())]),
            tally: Tally { reader: [23, 745], wasm_tools: [26, 742], v8: [23, 745] },
        },
        // A table section's only entry: `00 01` completes a one-byte
        // reference type (limits: no maximum, one element), `70 00 01` a
        // `0x63`/`0x64` one, and `00 70 00 01 d0 70 0b` the `0x40` entry with
        // an initial value (`ref.null func`).
        Point {
            name: "a table entry's first byte",
            continuations: &[&[0x00, 0x01], &[0x70, 0x00, 0x01], &[0x00, 0x70, 0x00, 0x01, 0xd0, 0x70, 0x0b]],
            build: |b, c| module(&[one_entry(4, &[&[b], c].concat())]),
            tally: Tally { reader: [15, 753], wasm_tools: [18, 750], v8: [14, 754] },
        },
        // `"m" "n" <b>` then each kind's payload ([`KIND_PAYLOADS`]), over
        // type 0 `() -> ()`.
        Point {
            name: "an import kind",
            continuations: KIND_PAYLOADS,
            build: |b, c| module(&[types(), one_entry(2, &[name(b"m"), name(b"n"), vec![b], c.to_vec()].concat())]),
            tally: Tally { reader: [7, 1273], wasm_tools: [8, 1272], v8: [6, 1274] },
        },
        // `"e" <b>` then the same five, in a module that defines one function,
        // table, memory, tag and global, so that whichever of the five kinds
        // the byte is, index 0 of it exists.
        Point {
            name: "an export kind",
            continuations: KIND_PAYLOADS,
            build: |b, c| {
                module(&[
                    types(),
                    one_entry(3, &[0x00]),
                    one_entry(4, &[0x70, 0x00, 0x01]),
                    one_entry(5, &[0x00, 0x01]),
                    one_entry(13, &[0x00, 0x00]),
                    one_entry(6, &[0x7f, 0x00, 0x41, 0x00, 0x0b]),
                    one_entry(7, &[name(b"e"), vec![b], c.to_vec()].concat()),
                    section(10, &vector(&[vec![0x02, 0x00, 0x0b]])),
                ])
            },
            tally: Tally { reader: [5, 1275], wasm_tools: [5, 1275], v8: [5, 1275] },
        },
        // `<b> 00`: the attribute, then type 0. The format gives one
        // attribute, `0x00`, and one shape after it.
        Point {
            name: "a tag attribute in the tag section",
            continuations: &[&[0x00]],
            build: |b, c| module(&[types(), one_entry(13, &[&[b], c].concat())]),
            tally: Tally { reader: [1, 255], wasm_tools: [1, 255], v8: [1, 255] },
        },
        Point {
            name: "a tag attribute in a tag import",
            continuations: &[&[0x00]],
            build: |b, c| module(&[types(), one_entry(2, &[name(b"m"), name(b"t"), vec![0x04, b], c.to_vec()].concat())]),
            tally: Tally { reader: [1, 255], wasm_tools: [1, 255], v8: [1, 255] },
        },
        // A passive segment of function indices: form 1, the element kind,
        // then no items. The format gives one element kind, `0x00`, which
        // `00` completes; `70 00` completes the byte read as a reference type
        // that takes a heap type (`0x63`/`0x64`, then `func`), which a reader
        // reading the element kind as form 5's reference type would read.
        Point {
            name: "the element kind of form 1",
            continuations: &[&[0x00], &[0x70, 0x00]],
            build: |b, c| module(&[one_entry(9, &[&[0x01, b], c].concat())]),
            tally: Tally { reader: [1, 511], wasm_tools: [1, 511], v8: [1, 511] },
        },
        // A passive segment of expressions: form 5, the reference type, then
        // no items. `00` completes a one-byte reference type, `70 00` one
        // that takes a heap type (`0x63`/`0x64`, then `func`), which `00`
        // alone left without its count.
        Point {
            name: "the reference type of form 5",
            continuations: &[&[0x00], &[0x70, 0x00]],
            build: |b, c| module(&[one_entry(9, &[&[0x05, b], c].concat())]),
            tally: Tally { reader: [14, 498], wasm_tools: [17, 495], v8: [19, 493] },
        },
        // A section of one byte, `00`: an empty name for a custom section, a
        // count of zero for a vector section, function 0 for the start
        // section, zero for the data count. Every id the format gives is
        // complete, and takes no other shape.
        Point {
            name: "a section id",
            continuations: &[&[0x01, 0x00]],
            build: |b, c| module(&[[&[b], c].concat()]),
            tally: Tally { reader: [14, 242], wasm_tools: [14, 242], v8: [13, 243] },
        },
    ]
}

/// A proposal this crate does not read, whose bytes the sweep meets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Proposal {
    CustomDescriptors,
    StackSwitching,
    SharedEverythingThreads,
}

impl Proposal {
    /// What V8's refusal of the proposal's bytes says that names it: for the
    /// first two the flag that would enable it, `--experimental-wasm-<flag>`;
    /// for shared-everything threads the word `shared`, not the flag. The
    /// refusals of the type entry and of the heap types after `0x63` and
    /// `0x64` hold it in the flag, `--experimental-wasm-shared`; V8 with that
    /// flag says it otherwise ("shared function references are not
    /// supported"). Where `0x65` begins a reference type V8 says neither, only
    /// the byte: see [`V8Names`].
    fn v8_names(self) -> &'static str {
        match self {
            Proposal::CustomDescriptors => "--experimental-wasm-custom-descriptors",
            Proposal::StackSwitching => "--experimental-wasm-wasmfx",
            Proposal::SharedEverythingThreads => "shared",
        }
    }
}

/// How V8's refusal of an [`OUTSIDE_SCOPE`] entry's modules is checked.
#[derive(Clone, Copy, Debug)]
enum V8Names {
    /// Every refusal contains the proposal's [`Proposal::v8_names`].
    Proposal,
    /// V8's refusal names no proposal, only the byte: every refusal contains
    /// this text instead, and the evidence of the proposal is wasm-tools'
    /// alone.
    ByteOnly(&'static str),
}

/// One point and byte at which the reader refuses and wasm-tools decodes
/// because the byte belongs to a proposal this crate does not read.
struct Outside {
    point: &'static str,
    byte: u8,
    proposal: Proposal,
    /// What `wasm-tools print`'s text of every one of the modules contains,
    /// as [`prints`] finds it: the proposal's construct, as wasm-tools decoded
    /// it.
    construct: &'static str,
    v8: V8Names,
    /// How many of the point's modules it accounts for.
    modules: usize,
}

/// Every point and byte the reader refuses and wasm-tools decodes because it
/// belongs to a proposal this crate does not read, keyed by both, so that the
/// byte refused at a point not listed fails. Measured 2026-10-20 with
/// wasm-tools 1.262.0 and V8 14.6.202.34 (node 26.10.0, no flags), which
/// refuses every one of them; what V8 says is checked against the proposal
/// named ([`V8Names`]).
///
/// The custom descriptors refusals of `0x4c` and `0x4d` say "descriptor
/// types need --experimental-wasm-custom-descriptors", the others "..., enable
/// with --experimental-wasm-<flag>": for custom descriptors and stack
/// switching the flag is what is required, not the words before it. For
/// shared-everything threads what is required is the word `shared`
/// ([`Proposal::v8_names`]), or the byte: V8 names the proposal for the type
/// entry ("unknown type form: 101, enable with --experimental-wasm-shared")
/// and after `0x63` and `0x64` ("invalid heap type 0x65, enable with
/// --experimental-wasm-shared"); at the four positions where `0x65` begins a
/// reference type it says "invalid value type 0x65" and nothing more, with
/// `--experimental-wasm-shared` too, so there the proposal rests on
/// wasm-tools' printed `(shared func)` plus V8's refusal of the byte.
///
/// A construct is found in wasm-tools' text as a whole token ([`prints`]),
/// so `cont` is not found in `(ref null nocont)`.
///
/// A first sweep, run by hand before this test existed, found 25 and not
/// `0x20`. Here an import kind is followed by what kind 0 takes, a type index,
/// among the others, and `20 00` is complete: the exact function import.
const OUTSIDE_SCOPE: &[Outside] = {
    use Proposal::*;
    use V8Names::{ByteOnly, Proposal as Named};
    const fn at(point: &'static str, byte: u8, proposal: Proposal, construct: &'static str, v8: V8Names, modules: usize) -> Outside {
        Outside { point, byte, proposal, construct, v8, modules }
    }
    &[
        // `(import "m" "n" (func (exact (type 0))))`: a function import of
        // exactly type 0, after `00` only.
        at("an import kind", 0x20, CustomDescriptors, "(exact", Named, 1),
        // `(describes 1) (struct)`, with continuations `01 5f 00` and `00 5f 00`.
        at("a type-section entry", 0x4c, CustomDescriptors, "(describes", Named, 2),
        // `(descriptor 1) (struct)`, the same two.
        at("a type-section entry", 0x4d, CustomDescriptors, "(descriptor", Named, 2),
        // `(ref null (exact 0))` and `(ref (exact 0))`, the index plain and
        // padded, and `(exact 112)` with continuation `70`, which wasm-tools
        // prints without validating.
        at("a heap type after 0x63", 0x62, CustomDescriptors, "(exact", Named, 3),
        at("a heap type after 0x64", 0x62, CustomDescriptors, "(exact", Named, 3),
        // `(cont 0)`, a type entry.
        at("a type-section entry", 0x5d, StackSwitching, "(cont", Named, 1),
        // `(ref null cont)` and `(ref cont)` as a value type, a field, a
        // table's element type, form 5's reference type, and after 0x63 and
        // 0x64; `nocont` at the same six.
        at("a value type", 0x68, StackSwitching, "cont", Named, 1),
        at("a heap type after 0x63", 0x68, StackSwitching, "cont", Named, 1),
        at("a heap type after 0x64", 0x68, StackSwitching, "cont", Named, 1),
        at("a structure field's storage type", 0x68, StackSwitching, "cont", Named, 1),
        at("a table entry's first byte", 0x68, StackSwitching, "cont", Named, 1),
        at("the reference type of form 5", 0x68, StackSwitching, "cont", Named, 1),
        at("a value type", 0x75, StackSwitching, "nocont", Named, 1),
        at("a heap type after 0x63", 0x75, StackSwitching, "nocont", Named, 1),
        at("a heap type after 0x64", 0x75, StackSwitching, "nocont", Named, 1),
        at("a structure field's storage type", 0x75, StackSwitching, "nocont", Named, 1),
        at("a table entry's first byte", 0x75, StackSwitching, "nocont", Named, 1),
        at("the reference type of form 5", 0x75, StackSwitching, "nocont", Named, 1),
        // `(shared (struct))` as a type entry; `(ref null (shared func))` and
        // `(ref (shared func))` after 0x63 and 0x64, with continuation `70`;
        // `(ref null (shared func))` as a value type, a field, a table's
        // element type and form 5's reference type.
        at("a type-section entry", 0x65, SharedEverythingThreads, "(shared", Named, 1),
        at("a heap type after 0x63", 0x65, SharedEverythingThreads, "(shared func)", Named, 1),
        at("a heap type after 0x64", 0x65, SharedEverythingThreads, "(shared func)", Named, 1),
        at("a value type", 0x65, SharedEverythingThreads, "(shared func)", ByteOnly("invalid value type 0x65"), 1),
        at("a structure field's storage type", 0x65, SharedEverythingThreads, "(shared func)", ByteOnly("invalid value type 0x65"), 1),
        at("a table entry's first byte", 0x65, SharedEverythingThreads, "(shared func)", ByteOnly("invalid value type 0x65"), 1),
        at("the reference type of form 5", 0x65, SharedEverythingThreads, "(shared func)", ByteOnly("invalid value type 0x65"), 1),
    ]
};

/// Whether `text`, as `wasm-tools print` writes it, holds `construct` as
/// whole tokens: at an occurrence, a construct that begins with a character
/// of a keyword or an identifier (the text format's `idchar`: a letter, a
/// digit, or one of ``!#$%&'*+-./:<=>?@\^_`|~``) must not follow one, and one
/// that ends with such a character must not be followed by one. A
/// parenthesis, a space or the end of the text bounds a token. So `cont` is
/// found in `(ref null cont)` and not in `(ref null nocont)` or `contref`,
/// and `(exact` in `(exact 0)` and not in `(exacting`. Strings are not
/// told apart from code: a construct inside a quoted name would be found.
fn prints(text: &str, construct: &str) -> bool {
    let idchar = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-./:<=>?@\\^_`|~".contains(c);
    let starts_token = construct.chars().next().is_some_and(idchar);
    let ends_token = construct.chars().next_back().is_some_and(idchar);
    text.match_indices(construct).any(|(at, _)| {
        let before = text[..at].chars().next_back().is_some_and(idchar);
        let after = text[at + construct.len()..].chars().next().is_some_and(idchar);
        !(starts_token && before) && !(ends_token && after)
    })
}

#[test]
fn prints_finds_a_construct_only_as_whole_tokens() {
    let text = "(type (;1;) (func (param (ref null nocont) (ref null (exact 0)))))";
    assert!(prints(text, "nocont"));
    assert!(!prints(text, "cont"), "`cont` found inside `nocont`");
    assert!(prints(text, "(exact"));
    assert!(!prints(text, "exac"), "`exac` found inside `exact`");
    assert!(!prints("(ref null contref)", "cont"), "`cont` found inside `contref`");
    assert!(prints("(ref null cont)", "cont"));
    assert!(prints("(ref null (shared func))", "(shared func)"));
    assert!(!prints("(ref null (shared funcs))", "(shared func"), "`(shared func` found inside `(shared funcs`");
}

/// Where the modules go, under the system's temporary directory.
fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis-wasm-sweep-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

/// What the reader says: it reads the module and decodes every body, or it
/// refuses. A stop inside it is not an answer.
fn reader_reads(bytes: &[u8]) -> Result<bool, String> {
    match n0xis_wasm::read(bytes) {
        Ok(m) => {
            for f in m.findings() {
                match f {
                    n0xis_wasm::Finding::Body { error: n0xis_wasm::Error::Internal(why), .. } => return Err(why.clone()),
                    n0xis_wasm::Finding::Body { .. } => return Ok(false),
                    n0xis_wasm::Finding::Name(_) => {}
                }
            }
            Ok(true)
        }
        Err(n0xis_wasm::Error::Internal(why)) => Err(why),
        Err(n0xis_wasm::Error::Unreadable { .. }) => Ok(false),
    }
}

/// Whether `wasm-tools print` decodes the module at `path`: exit status 0
/// decodes, 1 with a message refuses. The file is checked first, since
/// wasm-tools answers a file it cannot open with status 1 too.
fn wasm_tools_decodes(path: &Path) -> bool {
    assert!(path.is_file(), "{}: not there to be judged", path.display());
    let out = Command::new("wasm-tools")
        .arg("print")
        .arg(path)
        .env("LC_ALL", "C")
        .output()
        .unwrap_or_else(|e| panic!("wasm-tools could not run (a missing tool is a failure here): {e}"));
    match out.status.code() {
        Some(0) => true,
        Some(1) if !out.stderr.is_empty() => false,
        _ => panic!("wasm-tools print gave no verdict on {} ({}):\n{}", path.display(), out.status, String::from_utf8_lossy(&out.stderr)),
    }
}

/// `wasm-tools print` over every module, on a few threads.
fn wasm_tools_over(paths: &[PathBuf]) -> Vec<bool> {
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get()).min(4);
    let chunk = paths.len().div_ceil(workers);
    std::thread::scope(|s| {
        let handles: Vec<_> = paths.chunks(chunk).map(|part| s.spawn(move || part.iter().map(|p| wasm_tools_decodes(p)).collect::<Vec<_>>())).collect();
        handles.into_iter().flat_map(|h| h.join().expect("a wasm-tools worker")).collect()
    })
}

/// What `wasm-tools print` prints for a module it decodes.
fn wasm_tools_text(path: &Path) -> String {
    let out = Command::new("wasm-tools")
        .arg("print")
        .arg(path)
        .env("LC_ALL", "C")
        .output()
        .unwrap_or_else(|e| panic!("wasm-tools could not run (a missing tool is a failure here): {e}"));
    assert!(out.status.success(), "wasm-tools print no longer decodes {} ({}):\n{}", path.display(), out.status, String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).expect("UTF-8 from wasm-tools")
}

/// V8's verdict on every `.wasm` file of `dir`, by file name: accepts, or
/// refuses with this message.
fn v8_over(dir: &Path) -> BTreeMap<String, Result<(), String>> {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/tools/v8-validate-dir.mjs");
    assert!(script.is_file(), "{}: not there", script.display());
    let out = Command::new("node")
        .arg(&script)
        .arg(dir)
        .env("LC_ALL", "C")
        .output()
        .unwrap_or_else(|e| panic!("node could not run (a missing tool is a failure here): {e}"));
    assert!(out.status.success(), "v8-validate-dir.mjs gave no verdicts ({}):\n{}", out.status, String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).expect("UTF-8 from the script");
    let mut verdicts = BTreeMap::new();
    for line in text.lines() {
        let verdict = match line.split('\t').collect::<Vec<_>>()[..] {
            [file, "accepts"] => (file, Ok(())),
            [file, "refuses", why] if !why.is_empty() => (file, Err(why.to_string())),
            _ => panic!("v8-validate-dir.mjs wrote a line of no known shape: {line:?}"),
        };
        assert!(verdicts.insert(verdict.0.to_string(), verdict.1).is_none(), "{line:?}: a second verdict on one file");
    }
    verdicts
}

/// One module of the sweep and what each judge said.
struct Judged {
    point: &'static str,
    byte: u8,
    continuation: &'static [u8],
    file: String,
    reader: bool,
    wasm_tools: bool,
    v8: Result<(), String>,
}

#[test]
fn every_byte_at_every_module_level_decision_point_is_read_as_wasm_tools_reads_it() {
    let dir = scratch();

    // The controls: each judge must give the answer known before it is asked.
    let minimal = module(&[]);
    let no_magic = [b"\0asn".to_vec(), vec![1, 0, 0, 0]].concat();
    let controls = dir.join("controls");
    std::fs::create_dir_all(&controls).expect("a directory for the controls");
    std::fs::write(controls.join("minimal.wasm"), &minimal).expect("written");
    std::fs::write(controls.join("no-magic.wasm"), &no_magic).expect("written");
    assert_eq!(reader_reads(&minimal), Ok(true), "the reader on the minimal module");
    assert_eq!(reader_reads(&no_magic), Ok(false), "the reader on a module with no magic");
    assert!(wasm_tools_decodes(&controls.join("minimal.wasm")), "wasm-tools print refuses the minimal module");
    assert!(!wasm_tools_decodes(&controls.join("no-magic.wasm")), "wasm-tools print decodes a module with no magic");
    let v8 = v8_over(&controls);
    assert_eq!(v8.len(), 2, "V8's verdicts on the controls: {v8:?}");
    assert_eq!(v8.get("minimal.wasm"), Some(&Ok(())), "V8 on the minimal module");
    assert!(matches!(v8.get("no-magic.wasm"), Some(Err(_))), "V8 on a module with no magic: {v8:?}");

    // The sweep: file names in generation order, so that the sorted order V8
    // answers in is the same.
    let points = points();
    let names: BTreeSet<&str> = points.iter().map(|p| p.name).collect();
    assert_eq!(names.len(), points.len(), "two decision points of one name");
    let modules_dir = dir.join("modules");
    std::fs::create_dir_all(&modules_dir).expect("a directory for the modules");
    let mut sweep = Vec::new();
    let mut stopped = Vec::new();
    for point in &points {
        for continuation in point.continuations {
            for byte in 0..=255u8 {
                let bytes = (point.build)(byte, continuation);
                let file = format!("{:05}.wasm", sweep.len());
                std::fs::write(modules_dir.join(&file), &bytes).expect("written");
                let reader = reader_reads(&bytes).unwrap_or_else(|why| {
                    stopped.push(format!("{} {byte:#04x} {continuation:02x?}: {why}", point.name));
                    false
                });
                sweep.push((point.name, byte, *continuation, file, reader));
            }
        }
    }
    // 13 points: 256 bytes each, for the type entry's 7 continuations, both
    // heap types' 4, the value type's, the field's and the table entry's 3,
    // the import and export kinds' 5, the two element forms' 2, and one for
    // each of the other three.
    assert_eq!(sweep.len(), 256 * (7 + 3 + 4 + 4 + 3 + 3 + 5 + 5 + 1 + 1 + 2 + 2 + 1), "modules in the sweep");
    assert_eq!(sweep.len(), 10496, "modules in the sweep");
    assert!(stopped.is_empty(), "the reader stopped:\n{}", stopped.join("\n"));

    let paths: Vec<PathBuf> = sweep.iter().map(|(_, _, _, file, _)| modules_dir.join(file)).collect();
    let wasm_tools = wasm_tools_over(&paths);
    let mut v8 = v8_over(&modules_dir);
    assert_eq!(wasm_tools.len(), sweep.len(), "wasm-tools verdicts");
    assert_eq!(v8.len(), sweep.len(), "V8 verdicts");
    let judged: Vec<Judged> = sweep
        .into_iter()
        .zip(wasm_tools)
        .map(|((point, byte, continuation, file, reader), wasm_tools)| {
            let v8 = v8.remove(&file).unwrap_or_else(|| panic!("{file}: no verdict from V8"));
            Judged { point, byte, continuation, file, reader, wasm_tools, v8 }
        })
        .collect();

    // Per decision point, what each judge read and refused, against what is
    // stated.
    let mut tallies: BTreeMap<&str, Tally> = BTreeMap::new();
    for j in &judged {
        let tally = tallies.entry(j.point).or_default();
        tally.reader[usize::from(!j.reader)] += 1;
        tally.wasm_tools[usize::from(!j.wasm_tools)] += 1;
        tally.v8[usize::from(j.v8.is_err())] += 1;
    }
    eprintln!("{} modules: reader reads / refuses, wasm-tools print decodes / refuses, V8 accepts / refuses", judged.len());
    let mut tally_wrong = Vec::new();
    for point in &points {
        let c = tallies.get(point.name).copied().unwrap_or_default();
        eprintln!(
            "  {:<36} {:>4} / {:<4} {:>4} / {:<4} {:>4} / {:<4}",
            point.name, c.reader[0], c.reader[1], c.wasm_tools[0], c.wasm_tools[1], c.v8[0], c.v8[1]
        );
        if c != point.tally {
            tally_wrong.push(format!("{}: {c:?}, stated {:?}", point.name, point.tally));
        }
    }

    let describe = |j: &Judged| {
        format!(
            "{} {:#04x} then {:02x?} ({}): V8 {}",
            j.point,
            j.byte,
            j.continuation,
            j.file,
            match &j.v8 {
                Ok(()) => "accepts".to_string(),
                Err(why) => format!("refuses: {why}"),
            }
        )
    };
    let lenient: Vec<String> = judged.iter().filter(|j| j.reader && !j.wasm_tools).map(describe).collect();
    let mut explained: BTreeMap<(&str, u8), Vec<&Judged>> = BTreeMap::new();
    let mut accepted = Vec::new();
    let mut unexplained = Vec::new();
    for j in judged.iter().filter(|j| !j.reader && j.wasm_tools) {
        let in_scope = !OUTSIDE_SCOPE.iter().any(|o| o.point == j.point && o.byte == j.byte);
        if j.v8.is_ok() {
            accepted.push(describe(j));
        } else if in_scope {
            unexplained.push(describe(j));
        }
        if !in_scope {
            explained.entry((j.point, j.byte)).or_default().push(j);
        }
    }
    // Each entry must account for exactly the modules it states, and the
    // evidence of its proposal must be in what each of them was answered:
    // wasm-tools' text holds the proposal's construct, and V8's refusal names
    // the proposal, or where V8 names only the byte, says what is stated.
    let mut scope_wrong = Vec::new();
    for o in OUTSIDE_SCOPE {
        if !names.contains(o.point) {
            scope_wrong.push(format!("{} {:#04x}: no decision point of that name", o.point, o.byte));
        }
        let found = explained.get(&(o.point, o.byte)).map_or(&[][..], |v| &v[..]);
        eprintln!("  outside scope: {} {:#04x} ({:?}, {}): {} modules", o.point, o.byte, o.proposal, o.construct, found.len());
        if found.len() != o.modules {
            scope_wrong.push(format!("{} {:#04x} ({:?}): {} modules stated, {} found", o.point, o.byte, o.proposal, o.modules, found.len()));
        }
        for j in found {
            eprintln!("    {}", describe(j));
            let text = wasm_tools_text(&modules_dir.join(&j.file));
            if !prints(&text, o.construct) {
                scope_wrong.push(format!("{}: wasm-tools prints no {:?} ({:?}):\n{text}", describe(j), o.construct, o.proposal));
            }
            let says = match o.v8 {
                V8Names::Proposal => o.proposal.v8_names(),
                V8Names::ByteOnly(says) => says,
            };
            if !j.v8.as_ref().err().is_some_and(|why| why.contains(says)) {
                scope_wrong.push(format!("{}: V8's refusal does not say {says:?} ({:?})", describe(j), o.proposal));
            }
        }
    }
    let total_explained: usize = explained.values().map(Vec::len).sum();
    // Shown, not judged: the reader agrees with wasm-tools on these, so they
    // say nothing against it.
    let v8_alone: Vec<String> = judged.iter().filter(|j| !j.reader && !j.wasm_tools && j.v8.is_ok()).map(describe).collect();
    eprintln!("  {} that V8 alone accepts", v8_alone.len());
    for line in &v8_alone {
        eprintln!("    {line}");
    }
    eprintln!(
        "  {} read that wasm-tools cannot decode; refused that wasm-tools decodes: {} V8 accepts, {} unexplained, {total_explained} outside scope",
        lenient.len(),
        accepted.len(),
        unexplained.len()
    );

    // Kept when something fails, so the bytes can be looked at.
    if lenient.is_empty() && accepted.is_empty() && unexplained.is_empty() && scope_wrong.is_empty() && tally_wrong.is_empty() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    let files = modules_dir.display();
    assert!(lenient.is_empty(), "the reader reads what wasm-tools print cannot decode (files in {files}):\n{}", lenient.join("\n"));
    assert!(accepted.is_empty(), "the reader refuses what wasm-tools print decodes and V8 accepts (files in {files}):\n{}", accepted.join("\n"));
    assert!(unexplained.is_empty(), "the reader refuses what wasm-tools print decodes, for no proposal named (files in {files}):\n{}", unexplained.join("\n"));
    assert!(scope_wrong.is_empty(), "the points and bytes outside this crate's scope are not as stated (files in {files}):\n{}", scope_wrong.join("\n"));
    assert!(
        tally_wrong.is_empty(),
        "what a judge read and refused at a decision point is not what is stated (a reader change or a tool upgrade moved it: \
         look at which modules, then restate it; files in {files}):\n{}",
        tally_wrong.join("\n")
    );
}
