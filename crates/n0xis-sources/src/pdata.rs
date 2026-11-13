// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The x64 exception table (`.pdata`) read as **functions**, not as entries.
//!
//! Each `RUNTIME_FUNCTION` is three RVAs: begin, end, and the `UNWIND_INFO`
//! that describes the range. A compiler may split one function over several
//! entries: the first (the root) carries the prologue's unwind codes, and every
//! further one carries `UNW_FLAG_CHAININFO`, its "handler" slot holding a copy
//! of the `RUNTIME_FUNCTION` it continues. A chain may pass through another
//! continuation before it reaches the root (nested once is common enough to
//! occur in a system DLL's table).
//!
//! Reading the table as one function per entry lists every continuation as a
//! function of its own, and ends the real one where its first entry ends: on a
//! field report about an optimized x64 PE, `function discover --pdata` counted
//! the continuations, and `decomp` dropped about three quarters of one body
//! while saying its end was stated. So the only thing this hands out is an
//! [`UnwindFunction`], which can only be built here, from a root entry, with
//! every continuation whose chain ends at it as one of its [`parts`]
//! (`UnwindFunction::parts`). A continuation is never a function start.
//!
//! **The one reader of the table as functions**: discovery from the table, the
//! image's declared starts and the unwind extents the core attaches all ask it.
//! The live unwinder (`unwind.rs`) reads entries, not functions, and follows
//! chains for their unwind codes; it does not ask what a function is.

use crate::{Isa, MemorySource, SourceError};
use n0xis_contracts::Va;
use serde::{Deserialize, Serialize};

/// `UNW_FLAG_CHAININFO`, in the flags of `UNWIND_INFO`'s first byte (after the
/// three version bits).
const UNW_FLAG_CHAININFO: u8 = 0x4;
/// How deep a chain is followed. Real ones are one or two links; a longer one
/// (or a cycle) is a table this reader does not believe.
const MAX_CHAIN: usize = 32;
/// Upper bound on the table read in one go. A browser engine's table is under
/// a megabyte; a header that states more than this is not believed.
pub const MAX_EXCEPTION_TABLE: usize = 64 * 1024 * 1024;

/// The instruction set a COFF `Machine` value names — the one mapping, for
/// the file reader and for a header read through the seam alike.
pub(crate) fn isa_of_coff_machine(raw: u16) -> Isa {
    match raw {
        0x8664 => Isa::X64,
        0x014c => Isa::X86,
        0xAA64 => Isa::Arm64,
        0x01c0 | 0x01c4 => Isa::Arm,
        raw => Isa::Unrecognized { raw },
    }
}

/// The instruction set the PE headers at `image_base` state, read through the
/// seam (a live module, a snapshot, a loaded image): what
/// [`read_unwind_table`] needs to know whether the records are x64 ones.
pub fn pe_isa(src: &dyn MemorySource, image_base: Va) -> Isa {
    let Some(e_lfanew) = src.read(Va(image_base.0.saturating_add(0x3c)), 4).ok().and_then(|b| b.get(..4).map(|b| u32::from_le_bytes(b.try_into().expect("four bytes")))) else {
        return Isa::Unreadable;
    };
    match src.read(Va(image_base.0.saturating_add(u64::from(e_lfanew))), 6).ok() {
        Some(h) if h.len() == 6 && h[..4] == *b"PE\0\0" => isa_of_coff_machine(u16::from_le_bytes([h[4], h[5]])),
        _ => Isa::Unreadable,
    }
}

/// One range of code a continuation entry covers, `[start, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FunctionPart {
    pub start: Va,
    /// Exclusive.
    pub end: Va,
}

impl FunctionPart {
    pub fn holds(&self, va: Va) -> bool {
        va >= self.start && va < self.end
    }
}

/// A function the exception table states: its root entry, and every
/// continuation whose chain ends at that root. No constructor outside this
/// module, so a continuation cannot be handed out as a function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwindFunction {
    start: Va,
    /// The root entry's own end.
    root_end: Va,
    /// The root entry's `UNWIND_INFO`, as an RVA: where its handler data is.
    unwind_rva: u32,
    /// Every continuation, in address order.
    parts: Vec<FunctionPart>,
}

impl UnwindFunction {
    pub fn start(&self) -> Va {
        self.start
    }

    /// The root entry's `UNWIND_INFO` RVA.
    pub fn unwind_rva(&self) -> u32 {
        self.unwind_rva
    }

    /// The root entry's own end — where a reader that takes one entry for the
    /// function ends it. Only the exception scan asks it, to place a protected
    /// range the root's handler data states.
    pub fn root_end(&self) -> Va {
        self.root_end
    }

    /// Every continuation, in address order, contiguous with the root or not.
    pub fn parts(&self) -> &[FunctionPart] {
        &self.parts
    }

    /// The exclusive end of the code that runs on from the start without a
    /// gap: the root entry, then every part that begins where the run so far
    /// ends (or inside it). This is the function's stated end in every
    /// consumer that takes one `[start, end)`.
    pub fn contiguous_end(&self) -> Va {
        let mut end = self.root_end;
        for p in &self.parts {
            if p.start >= self.start && p.start <= end {
                end = end.max(p.end);
            }
        }
        end
    }

    /// The parts that do not continue the run from the start
    /// ([`Self::contiguous_end`]): code of this function elsewhere, which a
    /// consumer must fold in rather than take for another function.
    pub fn detached(&self) -> Vec<FunctionPart> {
        let end = self.contiguous_end();
        self.parts.iter().copied().filter(|p| !(p.start >= self.start && p.start < end)).collect()
    }
}

/// The table read as functions, and how many continuations belong to no root
/// entry of it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnwindTable {
    /// In the table's order, which the format requires to be by address.
    pub functions: Vec<UnwindFunction>,
    /// Continuations whose chain did not end at a root entry of this table: a
    /// chain past [`MAX_CHAIN`] links, a cycle, an `UNWIND_INFO` that cannot be
    /// read partway, or a root the table does not list. Listed as no function
    /// and folded into none, because nothing says which function holds them.
    pub orphans: usize,
}

/// One `RUNTIME_FUNCTION` as the table holds it.
#[derive(Clone, Copy)]
struct Entry {
    begin: u32,
    end: u32,
    unwind: u32,
}

/// Read the exception table at `table` (`size` bytes as the directory states
/// them) of the image loaded at `image_base`, as functions.
///
/// `isa` is the image's: the 12-byte record and the `UNWIND_INFO` chain are the
/// x64 format. **A known wrong answer, unchanged here:** an ARM64 PE32+ holds
/// 8-byte records in the same directory; they are read as 12-byte ones, every
/// one a function of its own (no chain is read for an ISA whose records are
/// not this shape), exactly as the readers this replaced did. On an ARM64 DLL
/// linked here (clang and lld-link 23.1.1), `llvm-readobj --unwind` lists four
/// functions of 60, 44, 40 and 40 bytes; this answers one, the first, ending
/// `0x121efd9` bytes past its start.
///
/// Every bound comes from the bytes actually read, never from a count in the
/// file, so a truncated or hostile table yields a short answer rather than a
/// large allocation. An error only where the table's first bytes cannot be
/// read at all.
pub fn read_unwind_table(src: &dyn MemorySource, image_base: Va, table: Va, size: usize, isa: Isa) -> Result<UnwindTable, SourceError> {
    let bytes = src.read(table, size.min(MAX_EXCEPTION_TABLE))?;
    let mut entries: Vec<Entry> = Vec::new();
    for rec in bytes.as_chunks::<12>().0 {
        let word = |i: usize| u32::from_le_bytes(rec[i * 4..i * 4 + 4].try_into().expect("four bytes"));
        let e = Entry { begin: word(0), end: word(1), unwind: word(2) };
        if e.begin == 0 && e.end == 0 {
            break; // the table's terminator
        }
        // An entry whose end does not follow its begin describes no code:
        // dropped, as the readers before this one dropped it.
        if e.end <= e.begin {
            continue;
        }
        entries.push(e);
    }
    let follow = isa == Isa::X64;
    let va = |rva: u32| Va(image_base.0.saturating_add(u64::from(rva)));

    // Which entry each one continues, resolved to its root's begin RVA; `None`
    // for a root.
    let root_of: Vec<Option<Result<u32, ()>>> =
        entries.iter().map(|e| if follow { chain_root(src, image_base, e.unwind) } else { None }).collect();

    let mut functions: Vec<UnwindFunction> = Vec::new();
    let mut index: std::collections::BTreeMap<u32, usize> = std::collections::BTreeMap::new();
    for (e, root) in entries.iter().zip(&root_of) {
        if root.is_none() {
            // Two entries with one begin would be two functions at one
            // address; the first is kept, as a lookup by start would find it.
            index.entry(e.begin).or_insert_with(|| {
                functions.push(UnwindFunction { start: va(e.begin), root_end: va(e.end), unwind_rva: e.unwind, parts: Vec::new() });
                functions.len() - 1
            });
        }
    }
    let mut orphans = 0usize;
    for (e, root) in entries.iter().zip(&root_of) {
        match root {
            None => {}
            Some(Ok(begin)) => match index.get(begin) {
                Some(&i) => functions[i].parts.push(FunctionPart { start: va(e.begin), end: va(e.end) }),
                None => orphans += 1,
            },
            Some(Err(())) => orphans += 1,
        }
    }
    for f in &mut functions {
        f.parts.sort_unstable();
        f.parts.dedup();
    }
    Ok(UnwindTable { functions, orphans })
}

/// Where the chain from the `UNWIND_INFO` at `unwind_rva` ends: `None` when
/// that info is not chained (the entry is a root, or its info cannot be read,
/// which is what every entry was before chains were read); `Some(Ok(begin))`
/// with the root's begin RVA; `Some(Err(()))` when the chain starts but does
/// not reach a root.
fn chain_root(src: &dyn MemorySource, image_base: Va, unwind_rva: u32) -> Option<Result<u32, ()>> {
    // An odd RVA is not an `UNWIND_INFO` (which is 4-byte aligned) but the
    // indirect form, whose meaning this reader does not take on.
    if unwind_rva & 1 != 0 {
        return None;
    }
    let first = chained_parent(src, image_base, unwind_rva)?;
    let Ok(mut parent) = first else { return Some(Err(())) };
    for _ in 0..MAX_CHAIN {
        match chained_parent(src, image_base, parent.unwind) {
            None => return Some(Ok(parent.begin)),
            Some(Ok(next)) => parent = next,
            Some(Err(())) => return Some(Err(())),
        }
    }
    Some(Err(()))
}

/// The `RUNTIME_FUNCTION` the `UNWIND_INFO` at `unwind_rva` chains to: `None`
/// when it carries no `UNW_FLAG_CHAININFO` or cannot be read at all;
/// `Some(Err(()))` when it is chained and the record cannot be read.
fn chained_parent(src: &dyn MemorySource, image_base: Va, unwind_rva: u32) -> Option<Result<Entry, ()>> {
    let at = Va(image_base.0.saturating_add(u64::from(unwind_rva)));
    let head = src.read(at, 4).ok().filter(|h| h.len() == 4)?;
    // Version 1 and 2 share this layout; another version is not a shape known.
    if !matches!(head[0] & 7, 1 | 2) || (head[0] >> 3) & UNW_FLAG_CHAININFO == 0 {
        return None;
    }
    // The unwind codes, two bytes each and padded to an even count, then the
    // parent's RUNTIME_FUNCTION.
    let codes = 2 * ((u64::from(head[2]) + 1) & !1);
    let rec = match src.read(Va(at.0.saturating_add(4 + codes)), 12) {
        Ok(r) if r.len() == 12 => r,
        _ => return Some(Err(())),
    };
    let word = |i: usize| u32::from_le_bytes(rec[i * 4..i * 4 + 4].try_into().expect("four bytes"));
    let parent = Entry { begin: word(0), end: word(1), unwind: word(2) };
    if parent.end <= parent.begin || parent.unwind & 1 != 0 {
        return Some(Err(()));
    }
    Some(Ok(parent))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A flat image at `0x1000`: what a `MemorySource` over a loaded PE serves.
    struct Flat(Vec<u8>);
    impl MemorySource for Flat {
        fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, SourceError> {
            let off = va.0.checked_sub(0x1000).ok_or(SourceError::Unmapped(va))? as usize;
            let b = self.0.get(off..).ok_or(SourceError::Unmapped(va))?;
            Ok(b[..len.min(b.len())].to_vec())
        }
        fn contains(&self, va: Va) -> bool {
            va.0 >= 0x1000 && va.0 < 0x1000 + self.0.len() as u64
        }
        fn label(&self) -> String {
            "flat".into()
        }
    }

    fn put(b: &mut [u8], off: usize, words: &[u32]) {
        for (i, w) in words.iter().enumerate() {
            b[off + i * 4..off + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
    }

    /// The fixture's shape, planted: a root `0x100..0x107`, a continuation
    /// `0x107..0x114` chained to it, a function of its own `0x120..0x126`, and
    /// a continuation `0x130..0x13c` chained through the first continuation.
    /// The table is at RVA `0x0`, the unwind infos at `0x80`, `0x88`, `0x98`,
    /// `0xa8`; the image base is `0x1000`.
    fn chained_image() -> Flat {
        let mut b = vec![0u8; 0x200];
        put(&mut b, 0x00, &[0x100, 0x107, 0x80, 0x107, 0x114, 0x88, 0x120, 0x126, 0x98, 0x130, 0x13c, 0xa8]);
        b[0x80..0x84].copy_from_slice(&[0x01, 0, 0, 0]);
        b[0x88..0x8c].copy_from_slice(&[0x21, 0, 0, 0]);
        put(&mut b, 0x8c, &[0x100, 0x107, 0x80]);
        b[0x98..0x9c].copy_from_slice(&[0x01, 0, 0, 0]);
        b[0xa8..0xac].copy_from_slice(&[0x21, 0, 0, 0]);
        put(&mut b, 0xac, &[0x107, 0x114, 0x88]);
        Flat(b)
    }

    #[test]
    fn a_continuation_is_a_part_of_the_function_its_chain_ends_at() {
        let t = read_unwind_table(&chained_image(), Va(0x1000), Va(0x1000), 48, Isa::X64).expect("readable");
        let starts: Vec<u64> = t.functions.iter().map(|f| f.start().0).collect();
        assert_eq!(starts, vec![0x1100, 0x1120], "two functions: no continuation is a start");
        let g = &t.functions[0];
        assert_eq!(g.parts(), &[FunctionPart { start: Va(0x1107), end: Va(0x1114) }, FunctionPart { start: Va(0x1130), end: Va(0x113c) }]);
        assert_eq!(g.contiguous_end(), Va(0x1114), "the contiguous continuation extends the stated end");
        assert_eq!(g.detached(), vec![FunctionPart { start: Va(0x1130), end: Va(0x113c) }], "the far one is a part apart");
        assert!(t.functions[1].parts().is_empty());
        assert_eq!(t.orphans, 0);
    }

    #[test]
    fn a_chain_whose_root_the_table_does_not_list_is_no_function() {
        let mut img = chained_image();
        // The nested continuation now chains to a record no entry begins at.
        put(&mut img.0, 0xac, &[0x150, 0x160, 0x80]);
        let t = read_unwind_table(&img, Va(0x1000), Va(0x1000), 48, Isa::X64).expect("readable");
        assert_eq!(t.functions.iter().map(|f| f.start().0).collect::<Vec<_>>(), vec![0x1100, 0x1120]);
        assert_eq!(t.orphans, 1);
    }

    #[test]
    fn a_chain_that_loops_is_no_function() {
        let mut img = chained_image();
        // The first continuation's parent is the nested one, whose parent is
        // the first: a cycle.
        put(&mut img.0, 0x8c, &[0x130, 0x13c, 0xa8]);
        let t = read_unwind_table(&img, Va(0x1000), Va(0x1000), 48, Isa::X64).expect("readable");
        assert_eq!(t.functions.iter().map(|f| f.start().0).collect::<Vec<_>>(), vec![0x1100, 0x1120]);
        assert_eq!(t.orphans, 2);
    }

    #[test]
    fn an_isa_whose_records_are_not_this_shape_reads_no_chain() {
        let t = read_unwind_table(&chained_image(), Va(0x1000), Va(0x1000), 48, Isa::Arm64).expect("readable");
        assert_eq!(t.functions.len(), 4, "the old flat reading, unchanged");
    }
}
