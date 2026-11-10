// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`StringXrefPass`] — find a string literal and who references it (`xref
//! string`).
//!
//! Two independent windows, because they're usually different sections: a
//! **data** window is searched for the byte needle, a **code** window is
//! swept once ([`crate::sweep`]) for `lea`-style RIP-relative references (via
//! the same [`DecodedInsn::rip_target`](n0xis_arch::DecodedInsn) field
//! [`XrefPass`](crate::XrefPass) already uses) that land on a match. Only
//! matches with at least one referencing instruction are reported — an
//! unreferenced byte sequence that happens to match is noise, not a "string".
//! They are **counted** in `found_unreferenced` all the same, because "absent"
//! and "present but unreferenced" are opposite facts that must not share one
//! zero.
//!
//! A reference need not land on the text's first byte. A linker merges tails, so
//! `"not found\n"` and `"found\n"` are one string and the second is its end; a
//! format's middle is what is searched for as often as its start. So what reaches
//! an occurrence is any reference from the start of its string to its own last
//! byte, marked with where it lands ([`XrefEntry::string_offset`]). What is called
//! unreferenced is what nothing in the [`StringSearched`] reaches.

use std::ops::ControlFlow;

use n0xis_contracts::Va;
use serde::Serialize;

use crate::sweep::{SWEEP_CHUNK, sweep_code};
use crate::xref::{HeldIn, SearchedCode, SearchedData, XrefEntry};
use crate::{Ctx, CoreError, Pass};

/// What to search for and where.
#[derive(Clone, Debug)]
pub struct StringXrefInput {
    /// Window searched for `query` (typically `.rdata`).
    pub data_start: Va,
    pub data_size: usize,
    /// Ranges decoded and scanned for referencing instructions (typically `.text`).
    pub code: Vec<(Va, usize)>,
    pub query: String,
    /// Cap on reported hits (each hit may carry several xrefs).
    pub limit: usize,
    /// Words of data that reach an occurrence ([`StringOccurrences::reaches`]).
    pub held: Vec<n0xis_sources::HeldWord>,
    /// Whether a word-sized value in an instruction is an address here: only on an
    /// image that runs where it says, whose code names data that way.
    pub references: crate::xref::CodeReferences,
    /// What the words of data were read from, for the answer.
    pub words: SearchedData,
    /// Whether a string here ends at a NUL. Where it does not, a reference before the
    /// text says nothing of the text ([`StringOccurrences::find`]).
    pub strings_are_terminated: bool,
}

impl StringXrefInput {
    /// Code ranges alone, with no words of data and no value in an instruction
    /// taken for an address.
    pub fn of_code(data_start: Va, data_size: usize, code: Vec<(Va, usize)>, query: String, limit: usize) -> Self {
        let words = SearchedData::NotSearched { why: "no words of data were read for this answer".to_string() };
        Self { data_start, data_size, code, query, limit, held: Vec::new(), references: Default::default(), words, strings_are_terminated: true }
    }
}

/// What `found_unreferenced` is out of.
#[derive(Clone, Debug, Serialize)]
pub struct StringSearched {
    pub code: Vec<SearchedCode>,
    pub data: SearchedData,
    /// Forms of reference this answer does not look for.
    pub not_searched: Vec<&'static str>,
}

/// Each place a query's text is in a window of data, with the start of the string
/// around it: the run of bytes since the last NUL.
#[derive(Clone, Debug)]
pub struct StringOccurrences {
    /// `(the occurrence, the start of its string)`, in address order.
    at: Vec<(u64, u64)>,
    len: u64,
}

/// The furthest before a text a reference still reaches it from. A C literal longer
/// than this is rare, and a run of text this long with no NUL in it is rarely one
/// literal: on one image built by rustc, 118 160 bytes of `.rodata` have none.
const MAX_BEFORE: usize = 4096;

impl StringOccurrences {
    /// `terminated` says whether a string here ends at a NUL. An image rustc built
    /// cuts its literals by a length, so the bytes before a text are other literals,
    /// and a reference to them does not reach it: only one on the text's own bytes
    /// does. It was measured: taken as NUL-terminated, every `lea` of a neighbouring
    /// literal called the text referenced.
    pub fn find(data: &[u8], data_start: Va, needle: &[u8], terminated: bool) -> Self {
        let mut at = Vec::new();
        let mut pos = 0usize;
        let mut run = 0usize;
        if !needle.is_empty() {
            while let Some(rel) = data[pos..].windows(needle.len()).position(|w| w == needle) {
                let idx = pos + rel;
                if let Some(nul) = data[pos..idx].iter().rposition(|&b| b == 0) {
                    run = pos + nul + 1;
                }
                let start = if terminated { run.max(idx.saturating_sub(MAX_BEFORE)) } else { idx };
                at.push((data_start.0 + idx as u64, data_start.0 + start as u64));
                pos = idx + 1;
            }
        }
        Self { at, len: needle.len() as u64 }
    }

    /// The occurrences a reference to `target` reaches: those whose string starts
    /// at or before it, and which do not end before it.
    fn reached_by(&self, target: u64) -> impl Iterator<Item = usize> + '_ {
        let first = self.at.partition_point(|&(occ, _)| occ + self.len <= target);
        (first..self.at.len()).take_while(move |&i| self.at[i].1 <= target)
    }

    /// Whether a reference to `target` reaches any occurrence.
    pub fn reaches(&self, target: u64) -> bool {
        self.reached_by(target).next().is_some()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct StringHit {
    pub address: Va,
    /// Up to 64 bytes at the match, non-printable bytes shown as `.`.
    pub preview: String,
    pub xrefs: Vec<XrefEntry>,
}

/// The string-xref artifact (`n0xis.xref.string.v1`).
#[derive(Clone, Debug, Serialize)]
pub struct StringXrefArtifact {
    pub query: String,
    pub count: usize,
    /// Occurrences of `query` that were found in the data window but had **no**
    /// referencing instruction, and so are not in `hits`.
    ///
    /// Without this, `count: 0` means two opposite things — "that text is not in
    /// this binary" and "it is there, nothing in the scanned code points at it"
    /// — and both read as a confident negative. Measured cost of the confusion:
    /// a session concluded an IL2CPP build resolved its engine calls by some other
    /// mechanism, when the truth was that the sweep never reached the code doing
    /// it.
    pub found_unreferenced: usize,
    pub hits: Vec<StringHit>,
    /// What was read for references: `found_unreferenced` is out of this.
    pub searched: StringSearched,
}

/// String cross-reference pass.
#[derive(Clone, Copy, Debug, Default)]
pub struct StringXrefPass;

impl Pass for StringXrefPass {
    type In = StringXrefInput;
    type Out = StringXrefArtifact;

    fn name(&self) -> &'static str {
        "xref.string"
    }

    fn run(&self, ctx: &Ctx, input: StringXrefInput) -> Result<StringXrefArtifact, CoreError> {
        self.run_in(ctx, input, SWEEP_CHUNK)
    }
}

impl StringXrefPass {
    /// [`Pass::run`] with the sweep's window size given, so a test can show the
    /// answer does not depend on it.
    pub(crate) fn run_in(&self, ctx: &Ctx, input: StringXrefInput, chunk: u64) -> Result<StringXrefArtifact, CoreError> {
        let needle = input.query.as_bytes();
        let mut not_searched = crate::xref::not_searched(&input.references);
        if !input.strings_are_terminated {
            not_searched.push("a reference to bytes before the text: this image cuts its strings by a length, so those are other strings");
        }
        let searched = StringSearched {
            code: input.code.iter().map(|&(start, size)| SearchedCode { start, size: size as u64 }).collect(),
            data: input.words.clone(),
            not_searched,
        };
        if needle.is_empty() {
            return Ok(StringXrefArtifact { query: input.query, count: 0, found_unreferenced: 0, hits: Vec::new(), searched });
        }

        let data = ctx.source.read(input.data_start, input.data_size)?;
        let occurrences = StringOccurrences::find(&data, input.data_start, needle, input.strings_are_terminated);
        // Every reference that reaches an occurrence, as (occurrence, row). One
        // sweep answers every occurrence at once. Each occurrence used to filter the
        // whole decoded window, which had to be held to be filtered again, and took
        // the code's length times the occurrences.
        let row = |occ: usize, from: Va, target: Va, kind: &str, text: String| -> (usize, XrefEntry) {
            let offset = target.0 as i64 - occurrences.at[occ].0 as i64;
            let mut entry = crate::xref_entry(ctx, from, Some(target), None, kind, text);
            entry.sym = None; // the target is a string literal, not a named symbol
            entry.string_offset = (offset != 0).then_some(offset);
            (occ, entry)
        };
        let mut referencing: Vec<(usize, XrefEntry)> = Vec::new();
        // Each instruction that reaches an occurrence, so a word a relocation writes
        // inside one is not listed again as a word of data.
        let mut instructions: Vec<(u64, u64)> = Vec::new();
        let mut scan = crate::xref::CodeScan::new(&input.references);
        for &(code_start, code_size) in &input.code {
            sweep_code(ctx, code_start, code_size as u64, chunk, |ins| {
                let named = ins.rip_target.map(|t| (t, "data")).into_iter().chain(scan.of(ctx, ins));
                for (t, kind) in named {
                    for occ in occurrences.reached_by(t.0) {
                        referencing.push(row(occ, ins.va, t, kind, ins.text.clone()));
                        instructions.push((ins.va.0, ins.va.0 + u64::from(ins.len)));
                    }
                }
                ControlFlow::Continue(())
            })?;
        }
        for w in input.held.iter().filter(|w| !instructions.iter().any(|&(s, e)| w.at >= s && w.at < e)) {
            for occ in occurrences.reached_by(w.holds) {
                let (occ, mut entry) = row(occ, Va(w.at), Va(w.holds), "data_word", format!("word in {} holds {}", w.section, Va(w.holds)));
                entry.held = Some(HeldIn { slot: Va(w.at), section: Some(w.section.clone()), evidence: w.by, relative_to: None });
                referencing.push((occ, entry));
            }
        }
        // By occurrence, each one's references kept in the order they were found.
        referencing.sort_by_key(|&(occ, _)| occ);

        let mut hits = Vec::new();
        let mut found_unreferenced = 0usize;
        let mut rows = referencing.into_iter().peekable();
        // Every occurrence, past `limit` too: the limit is on what is listed, and
        // `found_unreferenced` is a statement about the whole of the window.
        for (occ, &(address, _)) in occurrences.at.iter().enumerate() {
            let mut xrefs = Vec::new();
            while let Some((_, entry)) = rows.next_if(|(o, _)| *o == occ) {
                xrefs.push(entry);
            }
            if xrefs.is_empty() {
                found_unreferenced += 1;
            } else if hits.len() < input.limit {
                let idx = (address - input.data_start.0) as usize;
                let end = (idx + 64).min(data.len());
                hits.push(StringHit { address: Va(address), preview: preview_ascii(&data[idx..end]), xrefs });
            }
        }

        Ok(StringXrefArtifact { query: input.query, count: hits.len(), found_unreferenced, hits, searched })
    }
}

/// Printable-ASCII preview; non-printable bytes render as `.`.
fn preview_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| if (32..=126).contains(&b) { b as char } else { '.' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_contracts::Va;
    use n0xis_sources::Snapshot;

    #[test]
    fn finds_a_string_referenced_by_lea() {
        // Data: "Hello, world!\0" at 0x2000.
        // Code at 0x1000: lea rcx, [rip+disp] -> 0x2000 ; call somewhere ; ret
        let mut data = b"Hello, world!".to_vec();
        data.push(0);
        // lea rcx, [rip+0x0ff6]  (48 8D 0D d0 0f 00 00) chosen so rip(after insn)+disp = 0x2000
        // next_ip = 0x1007; disp = 0x2000 - 0x1007 = 0xFF9
        let disp: i32 = 0x2000 - 0x1007;
        let mut code = vec![0x48, 0x8D, 0x0D];
        code.extend_from_slice(&disp.to_le_bytes());
        code.push(0xC3); // ret

        let snap = Snapshot::builder()
            .region(Va(0x1000), code)
            .region(Va(0x2000), data)
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let art = StringXrefPass
            .run(
                &ctx,
                StringXrefInput::of_code(Va(0x2000), 64, vec![(Va(0x1000), 64)], "Hello, world!".into(), 10),
            )
            .expect("string xref runs");

        assert_eq!(art.count, 1);
        let hit = &art.hits[0];
        assert_eq!(hit.address, Va(0x2000));
        assert!(hit.preview.starts_with("Hello, world!"));
        assert_eq!(hit.xrefs.len(), 1);
        assert_eq!(hit.xrefs[0].from, Va(0x1000));
        assert_eq!(hit.xrefs[0].kind, "data");
    }

    #[test]
    fn an_unreferenced_match_is_counted_so_the_zero_can_be_read() {
        // "not in this binary" and "here, but nothing scanned points at it" are
        // opposite facts. Sharing one zero between them is what turned a swept
        // -too-little scan into a confident claim about a target's codegen.
        let snap = Snapshot::builder().region(Va(0x1000), vec![0x90, 0xC3]).region(Va(0x2000), b"orphan-string ".to_vec()).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = StringXrefPass
            .run(&ctx, StringXrefInput::of_code(Va(0x2000), 32, vec![(Va(0x1000), 2)], "orphan".into(), 10))
            .unwrap();
        assert_eq!(art.count, 0);
        assert_eq!(art.found_unreferenced, 1, "the string is there; say so");
    }

    #[test]
    fn unreferenced_match_is_not_reported() {
        // The string exists in data but nothing in the code window points to it.
        let data = b"orphan-string\0".to_vec();
        let code = vec![0x90, 0xC3]; // nop; ret — no lea
        let snap = Snapshot::builder()
            .region(Va(0x1000), code)
            .region(Va(0x2000), data)
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let art = StringXrefPass
            .run(
                &ctx,
                StringXrefInput::of_code(Va(0x2000), 64, vec![(Va(0x1000), 64)], "orphan-string".into(), 10),
            )
            .expect("string xref runs");
        assert_eq!(art.count, 0);
    }
}
