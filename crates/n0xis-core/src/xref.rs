// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`XrefPass`] — cross-references to or from an address.
//!
//! Decodes a code range and finds references via the arch-provided fields on
//! [`DecodedInsn`](n0xis_arch::DecodedInsn): `target` (direct branch/call) and
//! `rip_target` (RIP-relative data access, e.g. `lea`). Because both come from
//! the arch, this pass carries **no** ISA byte patterns — unlike v0, which
//! hand-scanned `48 8D … mod/rm` for `lea`. Works over any source.

use std::collections::BTreeMap;
use std::ops::ControlFlow;

use n0xis_arch::InsnKind;
use n0xis_contracts::Va;
use n0xis_sources::{HeldBy, HeldWords, WordRule};
use serde::{Deserialize, Serialize};

use crate::sweep::{SWEEP_CHUNK, sweep_code};
use crate::{Ctx, CoreError, Pass};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XrefDir {
    /// Who references `addr`.
    To,
    /// What `addr` references.
    From,
}

/// What to cross-reference.
#[derive(Clone, Copy, Debug)]
pub struct XrefInput {
    /// Start of the code window to scan.
    pub scan_start: Va,
    /// Size of the window.
    pub size: usize,
    /// The address of interest.
    pub addr: Va,
    pub dir: XrefDir,
}

#[derive(Clone, Debug, Serialize)]
pub struct XrefEntry {
    pub from: Va,
    /// The index of the function `from` is in, beside the position, on an
    /// image whose functions are identified by index (a WebAssembly module:
    /// docs/design/WASM.md §5 decision 1). Absent on a native image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_function: Option<u32>,
    /// What is referenced. Absent only for a reference to an imported
    /// WebAssembly function, which has an index (`to_function`) and no
    /// position: a `call 0` to an import is a call, and is listed as one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Va>,
    /// The index of the function referenced, on an image whose functions are
    /// identified by index; absent on a native image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_function: Option<u32>,
    /// `call` / `jmp` / `cond_jmp` / `data` (a `ref.func`, which takes a
    /// function as a value, is `data`, as taking an address is natively).
    pub kind: String,
    pub text: String,
    /// The `to` target's symbol name, when the symbol layer has one at exactly
    /// that address (a recovered RTTI method, a user rename, an export). Lets the
    /// caller render `→ verify_signature` beside a row instead of a bare address —
    /// the instruction `text` itself stays the raw decoded form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sym: Option<String>,
    /// The word of data this reference is, for a reference that is one.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub held: Option<HeldIn>,
    /// `xref string`: where the reference lands against the text asked for, where it
    /// is not on its first byte. Negative for one that starts before it, so the
    /// text is the end or the middle of what is referenced; positive for one inside
    /// it, so what is referenced is its end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub string_offset: Option<i64>,
}

/// A word of an image's data that holds an address ([`XrefEntry::held`]). Its
/// three facts travel together, so no reference can state one without the others.
#[derive(Clone, Debug, Serialize)]
pub struct HeldIn {
    /// Where the word is.
    pub slot: Va,
    /// The section it is in. Absent only on a source with no sections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// What says the word is an address. [`HeldBy::MatchingValue`] is the mark on
    /// what is only a number equal to one.
    pub evidence: HeldBy,
    /// For an entry relative to a table: the table's base, which the entry is
    /// added to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relative_to: Option<Va>,
}

/// A range of code decoded for the answer.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct SearchedCode {
    pub start: Va,
    pub size: u64,
}

/// Whether, and how, data was searched for words holding the address.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SearchedData {
    Searched {
        /// The sections read for stored values. The relocation tables are read
        /// whole, and name words in any section.
        sections: Vec<String>,
        /// How a word was told from a number: `relocations`, where the image may
        /// load anywhere, so only a word a relocation writes is an address;
        /// `relocations_and_stored_values`, where the image runs where it says, so a
        /// pointer can be a bare value, and those are marked `matching_value`;
        /// `stored_values_only`, where the relocations were not read.
        rule: &'static str,
        /// Words equal to the address that no relocation writes on an image that
        /// may load anywhere: numbers, so not in `refs`.
        unrelocated_matches: usize,
    },
    NotSearched {
        why: String,
    },
}

/// Whether the indirect jumps of the code were read for their tables.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SearchedJumps {
    Read {
        /// Jumps whose table was read: their entries are references.
        resolved: usize,
        /// Jumps with the shape of a table's dispatch whose table could not be
        /// read: a target of one of these is not in `refs`.
        not_resolved: usize,
        /// The first of them.
        not_resolved_at: Vec<Va>,
        /// Other indirect jumps, with no table to read: a tail call through a
        /// pointer, or a table this does not recognize.
        no_table: usize,
    },
    NotRead {
        why: String,
    },
}

/// What a `count` is out of: a zero means no such reference **in this**.
#[derive(Clone, Debug, Serialize)]
pub struct XrefSearched {
    pub code: Vec<SearchedCode>,
    pub data: SearchedData,
    pub jump_tables: SearchedJumps,
    /// Forms of reference this answer does not look for, whatever it found.
    pub not_searched: Vec<&'static str>,
    /// The address is in no section of the image: what a zero says there is that
    /// nothing in the image points outside it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub address_outside_image: bool,
}

/// Whether a value an instruction states (`mov edi, 0x402010`, `mov eax, ds:0x403020`)
/// is an address on this image.
#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub enum StatedValues {
    /// Not read for addresses: the image's relocations were not read, or it has no
    /// image at all.
    #[default]
    NotRead,
    /// The image runs where it says, so a value inside one of these `(start, size)`
    /// ranges is the address it equals, and only that: it may be a number.
    InImage(Vec<(u64, u64)>),
    /// The image may load anywhere, so a value is an address where a relocation
    /// writes a word of the instruction, and a number elsewhere. These are the words
    /// of code a relocation writes, sorted (a PE32's `push offset`, a `movabs`).
    WhereRelocated(Vec<u64>),
}

/// What in code names an address besides a branch and a RIP-relative operand.
#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct CodeReferences {
    pub stated: StatedValues,
    /// An i386 ELF: position-independent code reads data through a register a PC
    /// thunk sets ([`n0xis_arch::Arch::pic_relative`]).
    pub pic_register: bool,
}

/// What no answer of `xref to` or `xref string` looks for, given what it read. Each
/// is a real way for code to reach an address, so a zero must not read as if it had
/// been ruled out.
pub fn not_searched(refs: &CodeReferences) -> Vec<&'static str> {
    let mut out = vec![
        "an address built by more than one instruction, other than an i386 PC thunk's register",
        "an image-relative (RVA) word",
        "a word not aligned to a pointer, unless a relocation names it",
    ];
    match refs.stated {
        StatedValues::NotRead => out.insert(0, "an address as an immediate operand of an instruction"),
        StatedValues::WhereRelocated(_) => out.insert(0, "an immediate operand no relocation names, which on this image is a number"),
        StatedValues::InImage(_) => {}
    }
    out
}

/// Walks code in address order, and says what each instruction names beyond its
/// branch target and RIP-relative operand ([`CodeReferences`]).
pub(crate) struct CodeScan<'a> {
    refs: &'a CodeReferences,
    pic: n0xis_arch::PicState,
    function: Option<u64>,
}

impl<'a> CodeScan<'a> {
    pub(crate) fn new(refs: &'a CodeReferences) -> Self {
        Self { refs, pic: n0xis_arch::PicState::default(), function: None }
    }

    /// `(address, kind)`: `immediate` for a value the instruction states, and
    /// `pic_relative` for a read through a register a PC thunk set.
    pub(crate) fn of(&mut self, ctx: &Ctx, ins: &n0xis_arch::DecodedInsn) -> Vec<(Va, &'static str)> {
        let mut out = Vec::new();
        let stated = match &self.refs.stated {
            StatedValues::NotRead => false,
            StatedValues::InImage(_) => true,
            StatedValues::WhereRelocated(words) => {
                let first = words.partition_point(|&w| w < ins.va.0);
                words.get(first).is_some_and(|&w| w < ins.va.0 + u64::from(ins.len))
            }
        };
        if stated {
            for t in ctx.arch.stated_addresses(ins) {
                let inside = match &self.refs.stated {
                    StatedValues::InImage(ranges) => ranges.iter().any(|&(s, n)| t.0 >= s && t.0 - s < n),
                    _ => true,
                };
                if inside && Some(t) != ins.rip_target && Some(t) != ins.target {
                    out.push((t, "immediate"));
                }
            }
        }
        if self.refs.pic_register {
            // What a function set is that function's: where one starts, nothing is known.
            let function = stated_function(ctx, ins.va).map(|(s, _)| s.0);
            if function != self.function {
                self.pic.clear();
                self.function = function;
            }
            if let Some(t) = ctx.arch.pic_relative(&mut self.pic, ins, &|va, n| ctx.source.read(va, n).ok())
                && !out.iter().any(|(o, _)| *o == t)
            {
                out.push((t, "pic_relative"));
            }
        }
        out
    }
}

/// The kind of a reference the index holds from `ins` to `addr`, which it does not
/// keep: the one rule the index and a scan state it by.
pub fn indexed_kind(ins: &n0xis_arch::DecodedInsn, addr: Va, arch: &dyn n0xis_arch::Arch) -> &'static str {
    if ins.target == Some(addr) {
        branch_kind(ins.kind).unwrap_or("branch")
    } else if ins.rip_target == Some(addr) || ins.target_function.is_some_and(|f| f.body == Some(addr)) {
        "data"
    } else if arch.stated_addresses(ins).contains(&addr) {
        "immediate"
    } else {
        // What else the index keeps of an instruction is a read through a PC thunk's
        // register.
        "pic_relative"
    }
}

impl XrefSearched {
    /// Code windows only, and why data was not looked at.
    pub fn code_only(code: Vec<SearchedCode>, why: impl Into<String>) -> Self {
        let why = why.into();
        Self {
            code,
            jump_tables: SearchedJumps::NotRead { why: why.clone() },
            data: SearchedData::NotSearched { why },
            not_searched: not_searched(&CodeReferences::default()),
            address_outside_image: false,
        }
    }

    /// Code windows, and what [`held_references`] searched.
    pub fn with_held(code: Vec<SearchedCode>, held: &HeldWords, jump_tables: SearchedJumps, refs: &CodeReferences) -> Self {
        let rule = match held.rule {
            WordRule::Relocated => "relocations",
            WordRule::StoredValues => "relocations_and_stored_values",
            WordRule::NotRead(_) => "stored_values_only",
        };
        Self {
            code,
            data: SearchedData::Searched { sections: held.sections.clone(), rule, unrelocated_matches: held.unrelocated_matches },
            jump_tables,
            not_searched: not_searched(refs),
            address_outside_image: false,
        }
    }
}

/// The xref artifact (`n0xis.xref.v1`).
#[derive(Clone, Debug, Serialize)]
pub struct XrefArtifact {
    pub addr: Va,
    pub dir: XrefDir,
    pub count: usize,
    pub refs: Vec<XrefEntry>,
    /// What was searched: `count` is out of this, and only this.
    pub searched: XrefSearched,
    /// For `xref from` at an indirect jump: whether its table was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_table: Option<JumpTableAnswer>,
}

/// What `xref from` says of an indirect jump.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum JumpTableAnswer {
    /// Every entry is in `refs`.
    Resolved { table: Va, entries: usize, guarded: bool },
    /// Its targets are not known, and not in `refs`.
    NotResolved { why: &'static str },
}

/// Enough bytes to hold any single instruction on the supported ISAs — x86-64
/// tops out at 15, AArch64 is a fixed 4. Used to bound the `From` read to the one
/// instruction that direction can ever report.
const MAX_INSN_BYTES: usize = 16;

/// Cross-reference pass.
#[derive(Clone, Copy, Debug, Default)]
pub struct XrefPass;

/// One reference, with what every reference states beside its positions: the
/// function indices where the image identifies functions by index, and the
/// referenced function's symbol name. The one constructor, so the pass and
/// the index lookup in the frontend cannot state an entry two ways.
///
/// `to` is `None` only with `to_function` naming an imported function.
pub fn xref_entry(ctx: &Ctx, from: Va, to: Option<Va>, to_function: Option<u32>, kind: &str, text: String) -> XrefEntry {
    let to_function = to_function.or_else(|| to.and_then(|t| ctx.arch.indexed_function(t)).filter(|f| Some(f.body) == to).map(|f| f.index));
    XrefEntry {
        from,
        from_function: ctx.arch.indexed_function(from).map(|f| f.index),
        to,
        to_function,
        kind: kind.to_string(),
        text,
        sym: to.and_then(|t| crate::ir::symbol_on_entry(ctx, t)).map(|sy| sy.name),
        held: None,
        string_offset: None,
    }
}

/// How far back of an indirect jump to read for the instructions that lead to it,
/// when no function is stated to start from.
const JUMP_LOOKBACK: u64 = 4096;
/// The most of one function decoded for a jump in it.
const FUNCTION_LOOKBACK: u64 = 1 << 20;

/// The start and exclusive end the image states for the function `at` is in.
fn stated_function(ctx: &Ctx, at: Va) -> Option<(Va, Va)> {
    let f = ctx.functions?.extents;
    let i = f.partition_point(|s| s.start.0 <= at.0);
    f[..i].iter().rev().take(8).find(|s| s.end.0 > at.0).map(|s| (s.start, s.end))
}

/// The instructions from where `at`'s function starts up to and including `at`,
/// and the index where its block starts. `None` when no decode lands on `at`.
fn instructions_up_to(ctx: &Ctx, at: Va) -> Option<(Vec<n0xis_arch::DecodedInsn>, usize)> {
    let start = match stated_function(ctx, at) {
        Some((start, _)) => start.0.max(at.0.saturating_sub(FUNCTION_LOOKBACK)),
        None => at.0.saturating_sub(JUMP_LOOKBACK),
    };
    let bytes = ctx.source.read(Va(start), (at.0 - start + MAX_INSN_BYTES as u64) as usize).ok()?;
    let mut insns = ctx.arch.decode_range(&bytes, Va(start), bytes.len());
    let last = insns.iter().position(|i| i.va == at)?;
    insns.truncate(last + 1);
    // The same rule the CFG cuts a block by.
    let block_start = insns[..last].iter().rposition(|i| crate::ir::ends_block(i.kind)).map_or(0, |p| p + 1);
    Some((insns, block_start))
}

/// What the index keeps of one indirect jump. Stated from code alone, as the
/// index's key is the code's bytes; the table is read when it is asked for.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexedJump {
    pub at: u64,
    /// `None`: no table's dispatch. A tail call through a pointer, or a table this
    /// does not recognize.
    pub dispatch: Option<IndexedDispatch>,
}

/// The facts of a dispatch that the code states.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct IndexedDispatch {
    /// `None`: the table's base is in a register no instruction before it sets.
    pub table: Option<u64>,
    /// Entries are 32-bit offsets from the table's base.
    pub relative: bool,
    /// The largest index the guard of the index lets through, where one was read.
    pub guard: Option<u64>,
}

/// The dispatch of the indirect jump at `at`, from the instructions before it.
/// `Err` is why there is none.
fn dispatch_of(ctx: &Ctx, at: Va) -> Result<IndexedDispatch, &'static str> {
    let (insns, block_start) = instructions_up_to(ctx, at).ok_or("no decode from the start of its function lands on it")?;
    let disp = ctx.arch.detect_switch_with_context(&insns, block_start).ok_or("no table's dispatch: a tail call through a pointer, or a table this does not recognize")?;
    Ok(IndexedDispatch { table: disp.table.map(|t| t.0), relative: matches!(disp.kind, n0xis_arch::SwitchKind::RegRel32), guard: ctx.arch.index_guard(&insns, &disp) })
}

/// Every address code takes that a table may start at: what the index recorded, and
/// each jump's own table, which a fixed image's `jmp [table+rax*8]` names in no
/// edge. Where a table ends is where the next begins.
struct TableBases {
    sorted: Vec<u64>,
}

impl TableBases {
    fn of(idx: &XrefIndex) -> Self {
        let tables = idx.jumps.iter().filter_map(|j| j.dispatch.as_ref()?.table);
        let mut sorted: Vec<u64> = idx.edges.keys().copied().chain(tables).collect();
        sorted.sort_unstable();
        sorted.dedup();
        Self { sorted }
    }

    fn after(&self, table: u64) -> Option<u64> {
        self.sorted.get(self.sorted.partition_point(|&b| b <= table)).copied()
    }
}

/// The largest index the guard of the index at the indirect jump at `at` lets
/// through ([`n0xis_arch::Arch::index_guard`]), where one could be read.
pub(crate) fn index_guard_at(ctx: &Ctx, at: Va) -> Option<u64> {
    dispatch_of(ctx, at).ok()?.guard
}

/// A dispatch's table, read from the image.
fn read_dispatch(ctx: &Ctx, at: Va, d: &IndexedDispatch, bases: &TableBases) -> Result<crate::switch::TableRead, &'static str> {
    let table = d.table.ok_or("the dispatch reads its table through a register no instruction before it sets to an address")?;
    let kind = if d.relative { n0xis_arch::SwitchKind::RegRel32 } else { n0xis_arch::SwitchKind::MemIndexed };
    crate::switch::read_table(ctx, kind, Va(table), d.guard, stated_function(ctx, at), bases.after(table)).ok_or("the table's first entry is not code, or cannot be read")
}

/// One reference per entry of a jump's table.
fn table_rows(ctx: &Ctx, at: Va, read: &crate::switch::TableRead, only: Option<Va>, section_at: &dyn Fn(u64) -> Option<String>) -> Vec<XrefEntry> {
    let text = ctx
        .source
        .read(at, MAX_INSN_BYTES)
        .ok()
        .and_then(|b| ctx.arch.decode_range(&b, at, b.len()).into_iter().next())
        .map(|i| i.text)
        .unwrap_or_default();
    let evidence = if read.guarded { HeldBy::JumpTableGuarded } else { HeldBy::JumpTableWalked };
    read.entries
        .iter()
        .filter(|(_, target)| only.is_none_or(|o| o == *target))
        .map(|&(slot, target)| {
            let mut entry = xref_entry(ctx, at, Some(target), None, "jump_table", text.clone());
            entry.held = Some(HeldIn { slot, section: section_at(slot.0), evidence, relative_to: read.relative_to });
            entry
        })
        .collect()
}

/// What `xref from` adds at `addr`, when it is an indirect jump: every entry of
/// its table, or why it has none. `None` for any other instruction.
pub fn jump_table_from(ctx: &Ctx, addr: Va, idx: &XrefIndex, section_at: &dyn Fn(u64) -> Option<String>) -> Option<(Vec<XrefEntry>, JumpTableAnswer)> {
    let bytes = ctx.source.read(addr, MAX_INSN_BYTES).ok()?;
    let ins = ctx.arch.decode_range(&bytes, addr, bytes.len()).into_iter().next().filter(|i| i.va == addr)?;
    if !is_indirect_jump(&ins) {
        return None;
    }
    if !ctx.arch.recognizes_jump_tables() {
        return Some((Vec::new(), JumpTableAnswer::NotResolved { why: "no table's dispatch is recognized on this instruction set" }));
    }
    let bases = TableBases::of(idx);
    Some(match dispatch_of(ctx, addr).and_then(|d| read_dispatch(ctx, addr, &d, &bases)) {
        Ok(read) => {
            let table = read.relative_to.or_else(|| read.entries.first().map(|e| e.0)).unwrap_or(addr);
            let refs = table_rows(ctx, addr, &read, None, section_at);
            let answer = JumpTableAnswer::Resolved { table, entries: refs.len(), guarded: read.guarded };
            (refs, answer)
        }
        Err(why) => (Vec::new(), JumpTableAnswer::NotResolved { why }),
    })
}

/// What [`jump_table_references`] read.
pub struct JumpTableReferences {
    /// One per entry that lands on the address.
    pub refs: Vec<XrefEntry>,
    pub searched: SearchedJumps,
    /// `[start, end)` of every table read, sorted.
    pub tables: Vec<(u64, u64)>,
}

/// The references to `addr` from the index's jumps through their tables, and what
/// was read to say so. Reads every table, which the index does not keep: a table's
/// bytes are not what the index is keyed on.
pub fn jump_table_references(ctx: &Ctx, addr: Va, idx: &XrefIndex, section_at: &dyn Fn(u64) -> Option<String>) -> JumpTableReferences {
    /// So that a wide image's answer stays a screen long; the counts are whole.
    const LISTED: usize = 32;
    if !ctx.arch.recognizes_jump_tables() {
        let searched = SearchedJumps::NotRead { why: "no table's dispatch is recognized on this instruction set".to_string() };
        return JumpTableReferences { refs: Vec::new(), searched, tables: Vec::new() };
    }
    let bases = TableBases::of(idx);
    let mut refs = Vec::new();
    let mut tables = Vec::new();
    let (mut resolved, mut not_resolved, mut no_table) = (0usize, 0usize, 0usize);
    let mut not_resolved_at = Vec::new();
    for jump in &idx.jumps {
        let Some(dispatch) = &jump.dispatch else {
            no_table += 1;
            continue;
        };
        match read_dispatch(ctx, Va(jump.at), dispatch, &bases) {
            Ok(read) => {
                resolved += 1;
                if let (Some(first), Some(last)) = (read.entries.first(), read.entries.last()) {
                    tables.push((first.0.0, last.0.0 + read.entry_size));
                }
                if read.entries.iter().any(|(_, t)| *t == addr) {
                    refs.extend(table_rows(ctx, Va(jump.at), &read, Some(addr), section_at));
                }
            }
            Err(_) => {
                not_resolved += 1;
                if not_resolved_at.len() < LISTED {
                    not_resolved_at.push(Va(jump.at));
                }
            }
        }
    }
    tables.sort_unstable();
    tables.dedup();
    JumpTableReferences { refs, searched: SearchedJumps::Read { resolved, not_resolved, not_resolved_at, no_table }, tables }
}

fn is_indirect_jump(ins: &n0xis_arch::DecodedInsn) -> bool {
    ins.kind == InsnKind::Jump && ins.target.is_none() && ins.rip_target.is_none()
}

/// The longest table [`relative_entries`] walks from one base, as many as the
/// longest jump table the switch resolver reads.
const MAX_RELATIVE_ENTRIES: usize = 4096;

/// The references a word of data makes to `addr`: every word `held` found, and
/// every entry of a table relative to its base.
///
/// A relative entry states an offset, so no word of it equals an address and no
/// relocation names it. What makes it a reference is a base: `bases` are the data
/// addresses code takes (every `lea` into data, from the index), and a run of
/// 32-bit entries from one, each landing in code, is a table. Such a run is
/// recognized by its shape alone, so every one is marked
/// [`HeldBy::MatchingValue`]. A run stops at the next base, since the entries past
/// it are relative to that one; a run of one is not called a table.
pub fn held_references(ctx: &Ctx, addr: Va, held: &HeldWords, code: &[(Va, u64)], bases: &[u64], section_at: &dyn Fn(u64) -> Option<String>) -> Vec<XrefEntry> {
    let mut refs: Vec<XrefEntry> = Vec::new();
    for w in &held.words {
        let text = format!("word in {} holds {addr}", w.section);
        let mut entry = xref_entry(ctx, Va(w.at), Some(addr), None, "data_word", text);
        entry.held = Some(HeldIn { slot: Va(w.at), section: Some(w.section.clone()), evidence: w.by, relative_to: None });
        refs.push(entry);
    }
    for (slot, base) in relative_entries(ctx, addr, code, bases) {
        let section = section_at(slot);
        let text = format!("entry of a table at {}", Va(base));
        let mut entry = xref_entry(ctx, Va(slot), Some(addr), None, "relative_entry", text);
        entry.held = Some(HeldIn { slot: Va(slot), section, evidence: HeldBy::MatchingValue, relative_to: Some(Va(base)) });
        refs.push(entry);
    }
    refs
}

/// `(slot, base)` of each relative entry that lands on `addr`; `bases` sorted.
fn relative_entries(ctx: &Ctx, addr: Va, code: &[(Va, u64)], bases: &[u64]) -> Vec<(u64, u64)> {
    let in_code = |a: u64| code.iter().any(|&(s, n)| a >= s.0 && a - s.0 < n);
    let mut found = Vec::new();
    for (i, &base) in bases.iter().enumerate() {
        let next = bases.get(i + 1).copied().unwrap_or(u64::MAX);
        let mut hits = Vec::new();
        let mut entries = 0usize;
        while entries < MAX_RELATIVE_ENTRIES {
            let slot = base + (entries as u64) * 4;
            if slot >= next {
                break;
            }
            let Ok(b) = ctx.source.read(Va(slot), 4) else { break };
            let Ok(word) = <[u8; 4]>::try_from(b.as_slice()) else { break };
            let target = base.wrapping_add(i64::from(i32::from_le_bytes(word)) as u64);
            if !in_code(target) {
                break;
            }
            if target == addr.0 {
                hits.push((slot, base));
            }
            entries += 1;
        }
        if entries >= 2 {
            found.extend(hits);
        }
    }
    found.sort_unstable();
    found
}

/// Whether `ins` references the function `index` by index without a branch
/// target to it: a `ref.func`, or a call to an import (which has no body to
/// be a target).
fn names_function(ins: &n0xis_arch::DecodedInsn, index: Option<u32>) -> bool {
    index.is_some() && ins.target_function.map(|f| f.index) == index
}

fn branch_kind(k: InsnKind) -> Option<&'static str> {
    match k {
        InsnKind::Call => Some("call"),
        InsnKind::Jump => Some("jmp"),
        InsnKind::CondJump => Some("cond_jmp"),
        _ => None,
    }
}

impl Pass for XrefPass {
    type In = XrefInput;
    type Out = XrefArtifact;

    fn name(&self) -> &'static str {
        "xref"
    }

    fn run(&self, ctx: &Ctx, input: XrefInput) -> Result<XrefArtifact, CoreError> {
        self.run_in(ctx, input, SWEEP_CHUNK)
    }
}

impl XrefPass {
    /// [`Pass::run`] with the sweep's window size given, so a test can show the
    /// answer does not depend on it.
    pub(crate) fn run_in(&self, ctx: &Ctx, input: XrefInput, chunk: u64) -> Result<XrefArtifact, CoreError> {
        let target = Some(input.addr);
        let mut refs = Vec::new();
        // A window of code is all this pass is handed; the frontend, which holds
        // the image, says what else it looked at.
        let mut searched = XrefSearched::code_only(
            vec![SearchedCode { start: input.scan_start, size: input.size as u64 }],
            match input.dir {
                XrefDir::To => "a window of code was asked for",
                XrefDir::From => "`xref from` reads the instruction at the address",
            },
        );
        match input.dir {
            XrefDir::To => {
                // The function that starts at `addr`, where functions are
                // identified by index: a `ref.func` names it by that index alone.
                let addr_index = ctx.arch.indexed_function(input.addr).filter(|f| f.body == input.addr).map(|f| f.index);
                // Swept, not decoded whole: only the hits are kept, and their
                // text is the only text cloned (`crate::sweep`).
                sweep_code(ctx, input.scan_start, input.size as u64, chunk, |ins| {
                    let named = ins.target_function.map(|f| f.index);
                    if ins.target == target {
                        let kind = branch_kind(ins.kind).unwrap_or("branch");
                        refs.push(xref_entry(ctx, ins.va, target, named, kind, ins.text.clone()));
                    } else if ins.rip_target == target || names_function(ins, addr_index) {
                        refs.push(xref_entry(ctx, ins.va, target, named, "data", ins.text.clone()));
                    }
                    ControlFlow::Continue(())
                })?;
            }
            XrefDir::From => {
                // `From` reports ONLY the single instruction at `addr`. Decoding
                // the caller's whole window to then discard all of it is pure
                // waste, and for a whole-program query (the shape `xref from`
                // gets from the frontend, which has no reverse-index fast path
                // for this direction) that window is the entire `.text`:
                // measured at **16 s and +2.8 GB per call** on the Qt desktop
                // PE, for a 0.2 KB answer. Reading one instruction's worth
                // instead is identical by construction — `XrefArtifact` exposes
                // no scan range, so the narrowing is invisible. Bounded, so not
                // a sweep.
                //
                // The window bound is still honoured: a caller that sweeps
                // several code ranges must not get the same refs back once per
                // range.
                let end = input.scan_start.get().saturating_add(input.size as u64);
                if input.addr.get() < input.scan_start.get() || input.addr.get() >= end {
                    return Ok(XrefArtifact { addr: input.addr, dir: input.dir, count: 0, refs: Vec::new(), searched, jump_table: None });
                }
                let bytes = ctx.source.read(input.addr, MAX_INSN_BYTES)?;
                for ins in ctx.arch.decode_range(&bytes, input.addr, bytes.len()) {
                    if ins.va != input.addr {
                        continue;
                    }
                    searched.code = vec![SearchedCode { start: input.addr, size: u64::from(ins.len) }];
                    let named = ins.target_function.map(|f| f.index);
                    match (ins.target, ins.target_function) {
                        (Some(t), _) => {
                            let kind = branch_kind(ins.kind).unwrap_or("branch");
                            refs.push(xref_entry(ctx, input.addr, Some(t), named, kind, ins.text.clone()));
                        }
                        // Named by index with no branch target: a call to an
                        // import, which has no position, or a `ref.func`.
                        (None, Some(f)) => {
                            let kind = branch_kind(ins.kind).unwrap_or("data");
                            refs.push(xref_entry(ctx, input.addr, f.body, Some(f.index), kind, ins.text.clone()));
                        }
                        (None, None) => {}
                    }
                    if let Some(t) = ins.rip_target {
                        refs.push(xref_entry(ctx, input.addr, Some(t), None, "data", ins.text.clone()));
                    }
                }
            }
        }

        Ok(XrefArtifact {
            addr: input.addr,
            dir: input.dir,
            count: refs.len(),
            refs,
            searched,
            jump_table: None,
        })
    }
}

/// A reverse-edge map (`referenced VA → the VAs that reference it`), built with
/// ONE sweep ([`crate::sweep`]) over all code ranges. Turns `xref to` from a full
/// re-scan of the code section (seconds on a large image) into a map lookup.
///
/// Only the *source addresses* are stored — not the reference kind or the
/// instruction text. On a large image storing those per edge multiplies the
/// on-disk size for nothing, since a query needs them only for the handful of
/// hits it returns: both are re-derived by decoding the single `from`
/// instruction at query time (see [`xref_kind`]). It is a *cache of a
/// deterministic pass*, keyed on the actual bytes by the caller
/// (`n0xis-pipeline`), never a mutable source of truth (CONCEPT §3 rule 6).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct XrefIndex {
    /// Referenced address (raw VA) → the VAs of instructions that reference it.
    pub edges: BTreeMap<u64, Vec<u64>>,
    /// How many instructions were decoded to build this index (for `meta`).
    pub insns: usize,
    /// Every indirect jump of the code, in address order.
    #[serde(default)]
    pub jumps: Vec<IndexedJump>,
}

impl XrefIndex {
    /// The addresses of every instruction that references `addr`.
    pub fn to(&self, addr: Va) -> Vec<Va> {
        self.edges.get(&addr.0).map(|v| v.iter().map(|&f| Va(f)).collect()).unwrap_or_default()
    }
}

/// The reference-kind string for a branch instruction, or `"branch"` for an
/// indirect/other control-flow instruction. Public so a caller re-deriving a hit
/// from the index (which stores no kind) classifies it exactly as the pass would.
pub fn xref_kind(kind: InsnKind) -> &'static str {
    branch_kind(kind).unwrap_or("branch")
}

/// Build the reverse-xref index over `ranges` (`[(start, size)]`) — a linear
/// decode per range recording every `target` (branch/call) and `rip_target`
/// (data) edge, done once for the whole program so queries need no scan at all.
/// Swept ([`crate::sweep`]), so peak memory is one window of instructions
/// whatever the image's size (CLAUDE.md: a parser must be OOM-proof by design).
///
/// It was the first chunked sweep, in 8 MiB windows that cost 650-750 MB each
/// on a real library, resuming *after* the last kept instruction, which is not
/// where the whole-range decode resumes when an undecodable byte follows it
/// (`crate::sweep` says why).
pub fn build_xref_index(ctx: &Ctx, ranges: &[(Va, u64)]) -> XrefIndex {
    build_xref_index_in(ctx, ranges, SWEEP_CHUNK, &CodeReferences::default())
}

/// [`build_xref_index`], keeping also what [`CodeReferences`] says code names.
pub fn build_xref_index_with(ctx: &Ctx, ranges: &[(Va, u64)], refs: &CodeReferences) -> XrefIndex {
    build_xref_index_in(ctx, ranges, SWEEP_CHUNK, refs)
}

/// [`build_xref_index`] with the sweep's window size given.
pub(crate) fn build_xref_index_in(ctx: &Ctx, ranges: &[(Va, u64)], chunk: u64, refs: &CodeReferences) -> XrefIndex {
    let mut idx = XrefIndex::default();
    let mut scan = CodeScan::new(refs);
    let recognizes = ctx.arch.recognizes_jump_tables();
    let mut sites = Vec::new();
    for &(start, size) in ranges {
        if size == 0 {
            continue;
        }
        // A range whose start cannot be read adds nothing, as it did when the
        // index broke out of its chunk loop on a failed read.
        let _ = sweep_code(ctx, start, size, chunk, |ins| {
            idx.insns += 1;
            if recognizes && is_indirect_jump(ins) {
                sites.push(ins.va);
            }
            if let Some(t) = ins.target {
                idx.edges.entry(t.0).or_default().push(ins.va.0);
            }
            if let Some(t) = ins.rip_target {
                idx.edges.entry(t.0).or_default().push(ins.va.0);
            }
            for (t, _) in scan.of(ctx, ins) {
                idx.edges.entry(t.0).or_default().push(ins.va.0);
            }
            // A function named by index with no branch to it (`ref.func`)
            // references its body all the same.
            if ins.target.is_none()
                && let Some(body) = ins.target_function.and_then(|f| f.body)
            {
                idx.edges.entry(body.0).or_default().push(ins.va.0);
            }
            ControlFlow::Continue(())
        });
    }
    // After the sweep, each from its function's start: a table's base may be set
    // far before the jump, and the sweep holds one window of instructions.
    idx.jumps = sites
        .into_iter()
        .map(|at| {
            IndexedJump { at: at.0, dispatch: dispatch_of(ctx, at).ok() }
        })
        .collect();
    idx
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    #[test]
    fn from_is_window_bounded_and_window_size_independent() {
        // `From` reports only the instruction AT `addr`, so its result must not
        // depend on how large a window the caller sweeps — the frontend passes the
        // WHOLE program for this direction, which used to decode all of `.text`
        // (16 s, +2.8 GB on a real target) to keep one instruction.
        let code = vec![
            0xE8, 0x03, 0x00, 0x00, 0x00, // 0x1000: call 0x1008
            0x90, 0x90, 0x90, // padding
            0xC3, // 0x1008: ret
        ];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let run = |scan_start, size| {
            XrefPass.run(&ctx, XrefInput { scan_start, size, addr: Va(0x1000), dir: XrefDir::From }).unwrap()
        };
        let tight = run(Va(0x1000), 16);
        let wide = run(Va(0x1000), 4096);
        assert_eq!(tight.count, 1, "the call at 0x1000 references 0x1008");
        assert_eq!(tight.refs[0].to, Some(Va(0x1008)));
        // Same answer no matter how much the caller asked us to sweep.
        assert_eq!(format!("{:?}", tight.refs), format!("{:?}", wide.refs));

        // Still window-bounded: a caller sweeping several ranges must not get the
        // same refs back once per range.
        let outside = XrefPass
            .run(&ctx, XrefInput { scan_start: Va(0x1008), size: 8, addr: Va(0x1000), dir: XrefDir::From })
            .unwrap();
        assert_eq!(outside.count, 0, "addr outside the window yields nothing");
    }

    #[test]
    fn finds_call_xref_to_target() {
        // 0x1000: e8 03 00 00 00  call 0x1008
        // 0x1005: 90 90 90        nops
        // 0x1008: c3              ret  (the target)
        let code = vec![
            0xE8, 0x03, 0x00, 0x00, 0x00, // call 0x1008
            0x90, 0x90, 0x90, // padding
            0xC3, // 0x1008 ret
        ];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = XrefPass
            .run(
                &ctx,
                XrefInput {
                    scan_start: Va(0x1000),
                    size: 64,
                    addr: Va(0x1008),
                    dir: XrefDir::To,
                },
            )
            .unwrap();
        assert_eq!(art.count, 1);
        assert_eq!(art.refs[0].from, Va(0x1000));
        assert_eq!(art.refs[0].kind, "call");
    }

    #[test]
    fn reverse_index_matches_a_direct_to_scan() {
        // 0x1000: e8 03 00 00 00  call 0x1008
        // 0x1005: 90 90 90
        // 0x1008: c3              ret (the target)
        let code = vec![0xE8, 0x03, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0xC3];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let idx = build_xref_index(&ctx, &[(Va(0x1000), 64)]);
        let hits = idx.to(Va(0x1008));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0], Va(0x1000));
        // an address nothing references yields nothing
        assert!(idx.to(Va(0x1005)).is_empty());
    }

    #[test]
    fn reverse_index_round_trips_through_json() {
        let code = vec![0xE8, 0x03, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0xC3];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let idx = build_xref_index(&ctx, &[(Va(0x1000), 64)]);
        let json = serde_json::to_string(&idx).unwrap();
        let back: XrefIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(back.to(Va(0x1008)).len(), 1);
        assert_eq!(back.insns, idx.insns);
    }
}
