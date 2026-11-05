// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Where a run of text is several strings: a reference with its length.
//!
//! A `&str` has no terminator, so a compiler lays literals side by side and a
//! scan for printable bytes reads `PLANTED_ALPHAPLANTED_BETA` as one string, with
//! nothing in the bytes to say otherwise. What says otherwise is elsewhere in
//! the image: a pointer with a length beside it, in data ([`CutKind::DataPair`])
//! or built by instructions ([`CutKind::CodePair`]).
//!
//! **The rule that keeps C answers as they are.** A cut at `c` inside a run needs
//! one of:
//!
//! - (a) `c` is the start of a reference with its length;
//! - (b) `c` is the end of one, and the run is not ended by a NUL.
//!
//! So `strncmp(x, "abcdef", 3)`, on a string a NUL ends, cuts nothing: stating
//! how much of a string to read is not stating where it stops. Where nothing
//! states a length, a run stays whole.
//!
//! A reference is never believed past its run, nor when it starts or ends inside
//! a character: a `&str` is valid UTF-8 by its type, so such a word is not one.
//! Wide text has no such references and is not cut.

use std::collections::BTreeMap;
use std::ops::ControlFlow;

use n0xis_arch::{DecodedInsn, InsnKind};
use n0xis_contracts::Va;
use n0xis_sources::{AddressWords, ByteOrder, MemorySource, PointerWidth, RelocatedWords};
use serde::Serialize;

use crate::sweep::{SWEEP_CHUNK, sweep_code};
use crate::{CoreError, Ctx, FoundString, StringEncoding};

/// Instructions a length may be from the instruction that loads the address,
/// either side of it, with no control transfer between. Rust's `lea; mov; call`
/// is adjacent; the others are register moves and the next argument's setup.
pub const CODE_PAIR_WINDOW: u32 = 6;

/// The longest length an immediate is taken for, in bytes. A longer immediate is
/// not a length here, not the end of the search for one.
pub const CODE_PAIR_MAX_LEN: u64 = 0x1_0000;

/// What a reference's length was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CutKind {
    /// A pointer-sized word in data holding the address, and the next word the
    /// length.
    DataPair,
    /// An instruction loading the address, and an immediate near it.
    CodePair,
}

/// The evidence a row of text was cut on: what kind, and where it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CutBy {
    pub kind: CutKind,
    pub at: Va,
}

/// What is known so far about references into a set of runs, each already
/// checked against the run it falls in.
pub struct LiteralEvidence<'a> {
    /// The UTF-8 runs that may be cut, by address.
    runs: Vec<(u64, &'a str)>,
    refs: LiteralRefs,
}

impl<'a> LiteralEvidence<'a> {
    /// Over the runs given, of which only UTF-8 ones can be referred to.
    pub fn new(found: impl Iterator<Item = &'a FoundString>) -> Self {
        let mut runs: Vec<(u64, &str)> = found.filter(|s| s.encoding == StringEncoding::Utf8).map(|s| (s.address.0, s.text.as_str())).collect();
        runs.sort_by_key(|&(start, _)| start);
        Self { runs, refs: LiteralRefs::default() }
    }

    /// Whether no run can be referred to, so nothing need be looked for.
    pub fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }

    /// The run holding the byte at `va`.
    fn run_at(&self, va: u64) -> Option<(u64, &'a str)> {
        let after = self.runs.partition_point(|&(start, _)| start <= va);
        let (start, text) = *self.runs.get(after.checked_sub(1)?)?;
        (va - start < text.len() as u64).then_some((start, text))
    }

    /// Take `(start, len)` as a reference if it holds: at least a byte, inside
    /// one run, on character boundaries. Evidence for one reference found twice
    /// keeps the lowest address, so the answer does not depend on the order of
    /// a table.
    fn add(&mut self, start: u64, len: u64, kind: CutKind, at: Va) -> bool {
        let Some((run, text)) = self.run_at(start) else { return false };
        let from = (start - run) as usize;
        let Some(to) = usize::try_from(len).ok().and_then(|l| from.checked_add(l)) else { return false };
        if len == 0 || to > text.len() || !text.is_char_boundary(from) || !text.is_char_boundary(to) {
            return false;
        }
        let cut = CutBy { kind, at };
        self.refs.0.entry((start, len)).and_modify(|had| *had = if at.0 < had.at.0 { cut } else { *had }).or_insert(cut);
        true
    }

    /// A word a relative relocation writes `value` at: a data pair when `value`
    /// falls in a run and the next word, one no relocation writes, is its length.
    pub fn relocated_word(&mut self, source: &dyn MemorySource, relocated: &RelocatedWords, at: u64, value: u64, width: PointerWidth, order: ByteOrder) {
        if self.run_at(value).is_none() {
            return;
        }
        let next = at.saturating_add(u64::from(width.bytes()));
        if matches!(relocated, RelocatedWords::Read { words, .. } if words.binary_search(&next).is_ok()) {
            return;
        }
        let Ok(bytes) = source.read(Va(next), usize::from(width.bytes())) else { return };
        if let Some(len) = width.read_word(&bytes, order) {
            self.add(value, len, CutKind::DataPair, Va(at));
        }
    }

    /// Every aligned word of `bytes`, which start at `va`, read as it is stored:
    /// for an image that runs at the addresses it states.
    pub fn stored_words(&mut self, bytes: &[u8], va: Va, width: PointerWidth, order: ByteOrder) {
        let w = usize::from(width.bytes());
        let first = (w - (va.0 % w as u64) as usize) % w;
        for off in (first..bytes.len()).step_by(w) {
            let Some(value) = width.read_word(&bytes[off..], order) else { break };
            if self.run_at(value).is_none() {
                continue;
            }
            let Some(len) = bytes.get(off + w..).and_then(|b| width.read_word(b, order)) else { break };
            self.add(value, len, CutKind::DataPair, Va(va.0.wrapping_add(off as u64)));
        }
    }

    /// Code pairs in x86-64 code, through the one bounded sweep: what is kept
    /// per instruction is at most one entry of [`LiteralRefs`], which holds only
    /// references that fit a run. `words` is how the image states an address: an
    /// immediate is one only in an image that runs where it says.
    ///
    /// `Err` when a read fails.
    pub fn x64_code_pairs(&mut self, ctx: &Ctx, start: Va, size: u64, words: AddressWords) -> Result<(), CoreError> {
        let mut reader = X64Pairs { immediate_addresses: words == AddressWords::Stored, ..X64Pairs::default() };
        sweep_code(ctx, start, size, SWEEP_CHUNK, |ins| {
            reader.step(ins, self);
            ControlFlow::Continue(())
        })?;
        reader.retire_all(self);
        Ok(())
    }

    /// The references found. They no longer borrow the runs, which [`cut_run`]
    /// consumes.
    pub fn into_refs(self) -> LiteralRefs {
        self.refs
    }
}

/// References with their lengths: the first evidence of each `(start, len)`.
#[derive(Debug, Default)]
pub struct LiteralRefs(BTreeMap<(u64, u64), CutBy>);

/// The pieces of the run `run`, cut where a reference says ([the rule](self));
/// the run as it is when none does. A piece carries `cut_by` when a reference
/// states it: it starts at a cut one makes, or both its ends are one's. Text left
/// between pieces carries none. Pieces under `min` characters go the way any
/// string that short goes.
pub fn cut_run(run: FoundString, ended_by_nul: bool, refs: &LiteralRefs, min: usize) -> Vec<FoundString> {
    let start = run.address.0;
    let end = start.saturating_add(run.size as u64);
    if run.encoding != StringEncoding::Utf8 {
        return vec![run];
    }
    let inside: Vec<(u64, u64, CutBy)> = refs.0.range((start, 0)..(end, 0)).map(|(&(s, l), &by)| (s, s + l, by)).collect();
    let mut cuts: Vec<u64> = Vec::new();
    for &(s, e, _) in &inside {
        if s > start {
            cuts.push(s); // (a)
        }
        if !ended_by_nul && e < end {
            cuts.push(e); // (b)
        }
    }
    if cuts.is_empty() {
        return vec![run];
    }
    cuts.sort_unstable();
    cuts.dedup();
    cuts.push(end);

    let mut out = Vec::with_capacity(cuts.len());
    let mut from = start;
    for to in cuts {
        let text = &run.text[(from - start) as usize..(to - start) as usize];
        let length = text.chars().count();
        if length >= min.max(1) {
            let stated = |&&(s, e, _): &&(u64, u64, CutBy)| s == from && (from > start || e == to);
            // The reference this piece is exactly, before any other that starts
            // here: a longer one was cut by something inside it.
            let exact = inside.iter().filter(|r| stated(r) && r.1 == to).map(|r| r.2).min_by_key(|by| by.at.0);
            let cut_by = exact.or_else(|| inside.iter().filter(stated).map(|r| r.2).min_by_key(|by| by.at.0));
            out.push(FoundString { address: Va(from), encoding: run.encoding, length, size: (to - from) as usize, text: text.to_string(), cut_by });
        }
        from = to;
    }
    out
}

/// A general register of x86-64 and its width, from its name in instruction
/// text. Only the widths a pointer or a length is moved in.
fn gpr(name: &str) -> Option<(u8, u8)> {
    const NAMES: [(&str, &str); 16] = [
        ("rax", "eax"),
        ("rcx", "ecx"),
        ("rdx", "edx"),
        ("rbx", "ebx"),
        ("rsp", "esp"),
        ("rbp", "ebp"),
        ("rsi", "esi"),
        ("rdi", "edi"),
        ("r8", "r8d"),
        ("r9", "r9d"),
        ("r10", "r10d"),
        ("r11", "r11d"),
        ("r12", "r12d"),
        ("r13", "r13d"),
        ("r14", "r14d"),
        ("r15", "r15d"),
    ];
    NAMES.iter().position(|(q, _)| *q == name).map(|i| (i as u8, 8)).or_else(|| NAMES.iter().position(|(_, d)| *d == name).map(|i| (i as u8, 4)))
}

/// A number in the decoder's text: `0Dh`, `5`.
fn number(text: &str) -> Option<u64> {
    match text.strip_suffix('h') {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// A memory operand of the shape `[base+disp]`, or `None` for any other: a slot
/// another slot can be known to sit next to.
fn slot(operand: &str) -> Option<(u8, i64)> {
    let inner = operand.strip_prefix("qword ptr ").unwrap_or(operand).strip_prefix('[')?.strip_suffix(']')?;
    let at = inner.find(['+', '-']).unwrap_or(inner.len());
    let (base, width) = gpr(&inner[..at])?;
    if width != 8 {
        return None;
    }
    let disp = match inner.as_bytes().get(at) {
        None => 0,
        Some(b'+') => i64::try_from(number(&inner[at + 1..])?).ok()?,
        _ => -i64::try_from(number(&inner[at + 1..])?).ok()?,
    };
    Some((base, disp))
}

/// An instruction that loaded a run's address, not yet decided: `lea reg,[rip+x]`,
/// or, in an image that runs where it says, the address as an immediate.
struct Loaded {
    va: Va,
    /// The register holding it; none when the immediate went straight to memory.
    reg: Option<u8>,
    start: u64,
    age: u32,
    /// The slot the address was stored in.
    stored: Option<(u8, i64)>,
    /// The length stored in the slot after it: the pair as memory holds it.
    in_memory: Option<u64>,
    /// The immediate moved into another register after it.
    after: Option<u64>,
    /// The one immediate moved into another register just before it.
    before: Option<u64>,
    /// Two addresses waited for this register's immediate: which one it belongs
    /// to cannot be said, so neither takes it.
    shared: bool,
}

impl Loaded {
    /// What this load's length is, strongest evidence first.
    fn decided(&self) -> Option<u64> {
        self.in_memory.or(if self.shared { None } else { self.after.or(self.before) })
    }
}

/// An immediate moved recently, and where to.
struct Moved<T> {
    to: T,
    value: u64,
    age: u32,
}

/// The state of the search for code pairs, one instruction at a time.
#[derive(Default)]
struct X64Pairs {
    /// Whether an immediate can be a run's address ([`AddressWords::Stored`]).
    /// Where the image may load anywhere it is a number, whatever it equals.
    immediate_addresses: bool,
    open: Vec<Loaded>,
    regs: Vec<Moved<u8>>,
    slots: Vec<Moved<(u8, i64)>>,
}

impl X64Pairs {
    fn step(&mut self, ins: &DecodedInsn, evidence: &mut LiteralEvidence) {
        if ins.kind != InsnKind::Seq {
            self.retire_all(evidence);
            return;
        }
        for o in &mut self.open {
            o.age += 1;
        }
        self.retire(|o| o.age > CODE_PAIR_WINDOW, evidence);
        self.regs.iter_mut().for_each(|m| m.age += 1);
        self.slots.iter_mut().for_each(|m| m.age += 1);
        self.regs.retain(|m| m.age <= CODE_PAIR_WINDOW);
        self.slots.retain(|m| m.age <= CODE_PAIR_WINDOW);

        let Some((dst, src)) = ins.text.split_once(' ').and_then(|(_, ops)| ops.split_once(',')) else { return };
        let dst_reg = gpr(dst);
        // Whatever is written to a register ends what it was holding.
        if let Some((reg, _)) = dst_reg {
            self.retire(|o| o.reg == Some(reg), evidence);
            self.regs.retain(|m| m.to != reg);
        }
        match ins.mnemonic.as_str() {
            "lea" => {
                if let (Some((reg, 8)), Some(target)) = (dst_reg, ins.rip_target)
                    && evidence.run_at(target.0).is_some()
                {
                    let mut near = self.regs.iter().filter(|m| m.to != reg);
                    let before = match (near.next(), near.next()) {
                        (Some(one), None) => Some(one.value),
                        _ => None,
                    };
                    self.open.push(Loaded { va: ins.va, reg: Some(reg), start: target.0, age: 0, stored: None, in_memory: None, after: None, before, shared: false });
                }
            }
            "mov" => {
                let raw = number(src);
                if self.immediate_addresses
                    && let Some(address) = raw.filter(|&v| evidence.run_at(v).is_some())
                {
                    self.load_immediate(ins.va, address, dst_reg, dst);
                    return;
                }
                let imm = raw.filter(|&v| v <= CODE_PAIR_MAX_LEN);
                match (dst_reg, slot(dst), imm) {
                    (Some((reg, _)), _, Some(value)) => {
                        let mut waiting: Vec<&mut Loaded> = self.open.iter_mut().filter(|o| o.reg.is_some() && o.after.is_none() && !o.shared).collect();
                        match waiting.as_mut_slice() {
                            [] => self.regs.push(Moved { to: reg, value, age: 0 }),
                            [one] => one.after = Some(value),
                            many => many.iter_mut().for_each(|o| o.shared = true),
                        }
                    }
                    (None, Some(at), Some(value)) if dst.starts_with("qword ptr ") => {
                        if let Some(o) = self.open.iter_mut().find(|o| o.stored == Some((at.0, at.1 - 8))) {
                            o.in_memory = Some(value);
                        } else {
                            self.slots.push(Moved { to: at, value, age: 0 });
                        }
                    }
                    (None, Some(at), None) => {
                        if let Some((reg, 8)) = gpr(src)
                            && let Some(o) = self.open.iter_mut().find(|o| o.reg == Some(reg) && o.stored.is_none())
                        {
                            o.stored = Some(at);
                            if let Some(i) = self.slots.iter().position(|m| m.to == (at.0, at.1 + 8)) {
                                o.in_memory = Some(self.slots.swap_remove(i).value);
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// A run's address as an immediate, into a register or straight into a slot.
    fn load_immediate(&mut self, va: Va, start: u64, dst_reg: Option<(u8, u8)>, dst: &str) {
        let (reg, stored) = match (dst_reg, slot(dst)) {
            (Some((reg, _)), _) => (Some(reg), None),
            (None, Some(at)) if dst.starts_with("qword ptr ") => (None, Some(at)),
            _ => return,
        };
        let beside = stored.and_then(|at| self.slots.iter().position(|m| m.to == (at.0, at.1 + 8)));
        let in_memory = beside.map(|i| self.slots.swap_remove(i).value);
        self.open.push(Loaded { va, reg, start, age: 0, stored, in_memory, after: None, before: None, shared: false });
    }

    /// Decide and forget the loads `done` says are over.
    fn retire(&mut self, done: impl Fn(&Loaded) -> bool, evidence: &mut LiteralEvidence) {
        self.open.retain(|o| {
            if !done(o) {
                return true;
            }
            if let Some(len) = o.decided() {
                evidence.add(o.start, len, CutKind::CodePair, o.va);
            }
            false
        });
    }

    /// A control transfer: nothing before it is known to reach what follows.
    fn retire_all(&mut self, evidence: &mut LiteralEvidence) {
        self.retire(|_| true, evidence);
        self.regs.clear();
        self.slots.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(address: u64, text: &str) -> FoundString {
        FoundString { address: Va(address), encoding: StringEncoding::Utf8, length: text.chars().count(), size: text.len(), text: text.to_string(), cut_by: None }
    }

    /// `refs` as `(start, len)`, with evidence at `0x9000` plus their index.
    fn cut(text: &str, ended_by_nul: bool, refs: &[(u64, u64)], min: usize) -> Vec<(u64, String, Option<u64>)> {
        let found = run(0x100, text);
        let mut evidence = LiteralEvidence::new(std::iter::once(&found));
        for (i, &(s, l)) in refs.iter().enumerate() {
            evidence.add(s, l, CutKind::DataPair, Va(0x9000 + i as u64));
        }
        let refs = evidence.into_refs();
        cut_run(found.clone(), ended_by_nul, &refs, min).into_iter().map(|s| (s.address.0, s.text, s.cut_by.map(|c| c.at.0))).collect()
    }

    fn row(address: u64, text: &str, by: Option<u64>) -> (u64, String, Option<u64>) {
        (address, text.to_string(), by)
    }

    #[test]
    fn two_references_part_two_literals() {
        assert_eq!(cut("AAAABBBB", true, &[(0x100, 4), (0x104, 4)], 1), [row(0x100, "AAAA", Some(0x9000)), row(0x104, "BBBB", Some(0x9001))]);
    }

    #[test]
    fn a_start_inside_a_run_cuts_it_with_or_without_a_nul() {
        for ended_by_nul in [true, false] {
            assert_eq!(cut("AAAABBBB", ended_by_nul, &[(0x104, 4)], 1), [row(0x100, "AAAA", None), row(0x104, "BBBB", Some(0x9000))]);
        }
    }

    #[test]
    fn an_end_cuts_only_a_run_no_nul_ends() {
        assert_eq!(cut("abcdef", true, &[(0x100, 3)], 1), [row(0x100, "abcdef", None)]);
        assert_eq!(cut("abcdef", false, &[(0x100, 3)], 1), [row(0x100, "abc", Some(0x9000)), row(0x103, "def", None)]);
    }

    #[test]
    fn text_between_two_literals_stays_a_row_with_no_evidence() {
        assert_eq!(
            cut("AAAAxxxxBBBB", false, &[(0x100, 4), (0x108, 4)], 1),
            [row(0x100, "AAAA", Some(0x9000)), row(0x104, "xxxx", None), row(0x108, "BBBB", Some(0x9001))]
        );
    }

    #[test]
    fn a_reference_to_a_whole_run_is_no_cut() {
        assert_eq!(cut("abcdef", false, &[(0x100, 6)], 1), [row(0x100, "abcdef", None)]);
    }

    #[test]
    fn a_length_past_the_run_is_not_a_reference() {
        assert_eq!(cut("abcdef", false, &[(0x103, 4), (0x100, 7), (0x102, 0)], 1), [row(0x100, "abcdef", None)]);
    }

    #[test]
    fn a_reference_inside_a_character_is_not_a_reference() {
        // `і` is two bytes, at offset 1.
        assert_eq!(cut("aіbcd", false, &[(0x102, 2), (0x100, 2)], 1), [row(0x100, "aіbcd", None)]);
    }

    #[test]
    fn a_piece_under_the_minimum_goes_as_any_short_string_does() {
        assert_eq!(cut("okPLANTED", true, &[(0x102, 7)], 4), [row(0x102, "PLANTED", Some(0x9000))]);
    }

    #[test]
    fn a_row_shows_the_reference_it_is_not_the_longer_one_cut_inside() {
        assert_eq!(cut("abcdef", false, &[(0x100, 6), (0x100, 3)], 1), [row(0x100, "abc", Some(0x9001)), row(0x103, "def", None)]);
    }

    #[test]
    fn wide_text_is_left_alone() {
        let wide = FoundString { encoding: StringEncoding::Utf16le, size: 12, ..run(0x100, "abcdef") };
        let refs = LiteralRefs::default();
        assert_eq!(cut_run(wide.clone(), true, &refs, 1), [wide]);
    }

    #[test]
    fn stored_words_read_the_width_and_order_they_are_given() {
        let found = run(0x1000, "AAAABBBB");
        for (width, order, bytes) in [
            (PointerWidth::Eight, ByteOrder::Little, [0x1004u64.to_le_bytes(), 4u64.to_le_bytes()].concat()),
            (PointerWidth::Eight, ByteOrder::Big, [0x1004u64.to_be_bytes(), 4u64.to_be_bytes()].concat()),
            (PointerWidth::Four, ByteOrder::Little, [0x1004u32.to_le_bytes(), 4u32.to_le_bytes()].concat()),
            (PointerWidth::Four, ByteOrder::Big, [0x1004u32.to_be_bytes(), 4u32.to_be_bytes()].concat()),
        ] {
            let mut evidence = LiteralEvidence::new(std::iter::once(&found));
            evidence.stored_words(&bytes, Va(0x2000), width, order);
            let refs = evidence.into_refs();
            assert_eq!(refs.0.len(), 1, "{width:?} {order:?}");
            assert_eq!(refs.0[&(0x1004, 4)], CutBy { kind: CutKind::DataPair, at: Va(0x2000) });
        }
    }

    /// What the search says of a listing, in the decoder's own text.
    fn pairs(run_start: u64, listing: &[(&str, Option<u64>)]) -> Vec<(u64, u64, u64)> {
        let found = run(run_start, &"x".repeat(64));
        let mut evidence = LiteralEvidence::new(std::iter::once(&found));
        let mut reader = X64Pairs::default();
        for (i, (text, rip)) in listing.iter().enumerate() {
            let ins = DecodedInsn {
                va: Va(0x5000 + i as u64),
                len: 1,
                bytes: vec![0],
                mnemonic: text.split(' ').next().unwrap().to_string(),
                text: (*text).to_string(),
                kind: if text.starts_with("call") || text.starts_with("ret") { InsnKind::Call } else { InsnKind::Seq },
                target: None,
                rip_target: rip.map(Va),
                cond: None,
                stack_adjust: None,
                target_function: None,
            };
            reader.step(&ins, &mut evidence);
        }
        reader.retire_all(&mut evidence);
        evidence.into_refs().0.iter().map(|(&(s, l), by)| (s, l, by.at.0)).collect()
    }

    #[test]
    fn a_load_with_a_register_immediate_is_a_pair() {
        assert_eq!(pairs(0x100, &[("lea rdi,[110h]", Some(0x110)), ("mov esi,0Dh", None), ("call rax", None)]), [(0x110, 13, 0x5000)]);
        assert_eq!(pairs(0x100, &[("mov esi,0Dh", None), ("lea rdi,[110h]", Some(0x110)), ("call rax", None)]), [(0x110, 13, 0x5001)]);
    }

    #[test]
    fn a_load_stored_beside_its_length_is_a_pair() {
        let listing = [("lea rax,[110h]", Some(0x110)), ("mov [rsp+50h],rax", None), ("mov edx,3", None), ("mov qword ptr [rsp+58h],0Dh", None)];
        assert_eq!(pairs(0x100, &listing), [(0x110, 13, 0x5000)]);
        let before = [("mov qword ptr [rsp+8],0Dh", None), ("lea rax,[110h]", Some(0x110)), ("mov [rsp],rax", None)];
        assert_eq!(pairs(0x100, &before), [(0x110, 13, 0x5001)]);
    }

    #[test]
    fn a_length_in_a_slot_not_beside_the_pointer_is_no_pair() {
        let listing = [("lea rax,[110h]", Some(0x110)), ("mov [rsp+50h],rax", None), ("mov qword ptr [rsp+60h],0Dh", None)];
        assert_eq!(pairs(0x100, &listing), []);
    }

    #[test]
    fn nothing_crosses_a_control_transfer_or_the_window() {
        assert_eq!(pairs(0x100, &[("lea rdi,[110h]", Some(0x110)), ("call rax", None), ("mov esi,0Dh", None)]), []);
        let mut far = vec![("lea rdi,[110h]", Some(0x110))];
        far.extend(std::iter::repeat_n(("add rax,rbx", None), CODE_PAIR_WINDOW as usize));
        far.push(("mov esi,0Dh", None));
        assert_eq!(pairs(0x100, &far), []);
    }

    #[test]
    fn two_addresses_and_one_immediate_is_no_pair() {
        let listing = [("lea rdi,[110h]", Some(0x110)), ("lea rdx,[118h]", Some(0x118)), ("mov esi,0Dh", None), ("call rax", None)];
        assert_eq!(pairs(0x100, &listing), []);
    }

    #[test]
    fn an_immediate_into_the_same_register_ends_the_load() {
        assert_eq!(pairs(0x100, &[("lea rdi,[110h]", Some(0x110)), ("mov edi,0Dh", None), ("call rax", None)]), []);
    }

    #[test]
    fn the_decoder_text_is_read_as_the_decoder_writes_it() {
        assert_eq!(number("0Dh"), Some(13));
        assert_eq!(number("5"), Some(5));
        assert_eq!(number("rax"), None);
        assert_eq!(slot("qword ptr [rsp+58h]"), Some((4, 0x58)));
        assert_eq!(slot("[rbp-8]"), Some((5, -8)));
        assert_eq!(slot("[rsp]"), Some((4, 0)));
        assert_eq!(slot("[rsp+rcx*8+10h]"), None);
        assert_eq!(slot("rax"), None);
    }
}
