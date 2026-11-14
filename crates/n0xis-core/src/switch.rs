// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Memory-side jump-table resolution — the edge static tools lack.
//!
//! The arch recognizes the *shape* of a switch dispatch ([`SwitchDispatch`])
//! but never reads memory. Here the core reads the jump table through the
//! [`MemorySource`](n0xis_sources::MemorySource) seam and turns it into
//! concrete case targets. Because the seam is source-agnostic, this resolves
//! tables from a **running process** exactly as from a file on disk — so an
//! indirect `switch` in a live process gets its edges filled in, which a
//! file-only disassembler cannot do (CONCEPT §5.1).

use n0xis_arch::{DecodedInsn, IndexBound, SwitchDispatch, SwitchKind};
use n0xis_contracts::Va;
use serde::{Deserialize, Serialize};

use crate::Ctx;

/// Hard cap on resolved cases, even when a larger bound is recovered — a guard
/// against a misread bound blowing up into a huge table read.
const MAX_SWITCH_CASES: usize = 4096;
/// How many entries to probe when no upper bound was recovered; the walk also
/// stops early at the first entry that doesn't land in the address space.
const UNBOUNDED_PROBE_LIMIT: usize = 256;
/// Confidence attached to a memory-resolved switch-case edge — high, but below
/// the `1.0` of a directly-encoded branch, since a table read is best-effort.
pub const SWITCH_CASE_CONFIDENCE: f32 = 0.9;

/// A switch dispatch with its cases resolved from memory (`cases` empty when
/// the table base was unknown or unreadable). Embedded in the CFG artifact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedSwitch {
    pub at: Va,
    /// `"mem-indexed"` or `"reg-rel32"`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<Va>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_reg: Option<String>,
    pub scale: u32,
    /// What held the read: the guard of the index, else the index's width, as
    /// [`n0xis_arch::Arch::index_guard`] read them; `None` where neither was read.
    /// One value, so a switch cannot carry a guard and a width at once. The JSON keeps
    /// the two keys it has always had a reader for: `bound`, the guard's, and `width`
    /// ([`index_keys`]).
    #[serde(flatten, with = "index_keys")]
    pub index: Option<IndexBound>,
    /// Bytes per table entry (pointer width for mem-indexed, 4 for rel32).
    pub entry_size: u32,
    /// Whether `cases` were actually read from memory.
    pub resolved: bool,
    /// Resolved case targets, in table order.
    pub cases: Vec<Va>,
    /// Why the read of the table stopped where it did. `None` where nothing was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<TableEnd>,
}

/// [`ResolvedSwitch::index`] as the JSON keys `bound` (a guard's) and `width`.
mod index_keys {
    use n0xis_arch::IndexBound;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Keys {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bound: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        width: Option<u64>,
    }

    pub fn serialize<S: Serializer>(index: &Option<IndexBound>, s: S) -> Result<S::Ok, S::Error> {
        let keys = match *index {
            Some(IndexBound::Guard(n)) => Keys { bound: Some(n), width: None },
            Some(IndexBound::Width(n)) => Keys { bound: None, width: Some(n) },
            None => Keys { bound: None, width: None },
        };
        keys.serialize(s)
    }

    /// Both keys at once is no switch this writes, and is refused rather than one of
    /// them picked.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<IndexBound>, D::Error> {
        match Keys::deserialize(d)? {
            Keys { bound: Some(_), width: Some(_) } => Err(serde::de::Error::custom("a switch with both a guard's bound and a width")),
            Keys { bound: Some(n), width: None } => Ok(Some(IndexBound::Guard(n))),
            Keys { bound: None, width: Some(n) } => Ok(Some(IndexBound::Width(n))),
            Keys { bound: None, width: None } => Ok(None),
        }
    }
}

impl ResolvedSwitch {
    /// The largest index the guard of the index lets through, where one was read.
    pub fn bound(&self) -> Option<u64> {
        self.index.and_then(IndexBound::guard)
    }

    /// Where a guard was read and the read stopped before as many entries as it lets
    /// through: the guard's count and why the read stopped. The guard and the table
    /// disagree (an index masked to 8 values over a table of 7), and the read keeps
    /// the earlier stop. In the JSON: a `bound` with an `end` other than `guard`.
    pub fn short_of_its_guard(&self) -> Option<(u64, TableEnd)> {
        let guard = self.bound()?;
        let end = self.end?;
        (end != TableEnd::Guard && end != TableEnd::Limit && (self.cases.len() as u64) <= guard).then_some((guard.saturating_add(1), end))
    }

    /// What a body says above a switch whose cases no guard of the index bounds:
    /// the bound the read was held to and why it stopped. `None` for a guarded
    /// table, and for one not read, which says so in its own words.
    pub fn unguarded_note(&self) -> Option<String> {
        let end = self.end?;
        let held = match self.index {
            Some(IndexBound::Guard(_)) => return None,
            Some(IndexBound::Width(w)) => format!("the index's width ({} entries)", u128::from(w) + 1),
            None => format!("no bound but the read's own ({UNBOUNDED_PROBE_LIMIT} entries)"),
        };
        Some(format!("{UNGUARDED_TABLE}: held to {held}, {} read, {}", self.cases.len(), end.words()))
    }
}

/// How a body's note on a table with no guard of its index begins
/// ([`ResolvedSwitch::unguarded_note`]); the count of marks in `quality` looks for it.
pub const UNGUARDED_TABLE: &str = "// no guard of the switch's index was read";

/// Why the read of a jump table stopped. The read stops at whichever comes first,
/// in this order: the guard's bound, else the index's width; the function's stated
/// end; the next table's base; the first entry that is not code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TableEnd {
    /// As many entries as the guard of the index lets through.
    Guard,
    /// As many as the index's width allows.
    Width,
    /// The read's own limit, with neither a guard nor a width to hold it
    /// ([`UNBOUNDED_PROBE_LIMIT`], or [`MAX_SWITCH_CASES`] above a larger bound).
    Limit,
    /// The next entry leads out of the function the image states the jump is in,
    /// its parts apart included.
    FunctionEnd,
    /// The next entry is where code takes another address, where another table
    /// may begin.
    NextTable,
    /// The next entry is not code.
    NotCode,
    /// The words end before the next entry: the image holds no more of them.
    Unreadable,
}

impl TableEnd {
    /// The reason, in the words a body's note says it.
    pub fn words(self) -> &'static str {
        match self {
            TableEnd::Guard => "as many as the guard lets through",
            TableEnd::Width => "as many as the width allows",
            TableEnd::Limit => "stopped at the read's own limit",
            TableEnd::FunctionEnd => "stopped where an entry leaves the function",
            TableEnd::NextTable => "stopped where the next table begins",
            TableEnd::NotCode => "stopped where an entry is not code",
            TableEnd::Unreadable => "stopped where the words end",
        }
    }
}

/// Every address code takes that a table may start at: where a table ends is
/// where the next begins. **One list per image**, the one `xref` builds from its
/// index of the whole image's code ([`TableBases::of_index`]); a graph takes it
/// through [`Ctx::table_bases`](crate::Ctx::table_bases). Taken from the function's
/// own code instead, a graph missed a table the next function names, and read on
/// into it: 15 tables on the five images read one or two entries past where `xref`
/// stopped, fd's ELF 19 for 18, rg's PE 11 for 9 with two into the middle of a `ud2`.
#[derive(Debug, Default)]
pub struct TableBases {
    sorted: Vec<u64>,
}

impl TableBases {
    /// From the addresses code names ([`crate::xref::addresses_named`]) and the
    /// tables of its dispatches, which a fixed image's `jmp [table+rax*8]` names in
    /// no other way.
    pub fn new(named: impl IntoIterator<Item = u64>, tables: impl IntoIterator<Item = u64>) -> Self {
        let mut sorted: Vec<u64> = named.into_iter().chain(tables).collect();
        sorted.sort_unstable();
        sorted.dedup();
        Self { sorted }
    }

    /// The image's: every address its index recorded code taking, and each jump's
    /// own table.
    pub fn of_index(idx: &crate::xref::XrefIndex) -> Self {
        Self::new(idx.edges.keys().copied(), idx.jumps.iter().filter_map(|j| j.dispatch.as_ref()?.table))
    }

    /// The table bases one stretch of code states: what its instructions name, by
    /// the rule the xref index records them by, and the tables of `dispatches`. What
    /// a graph falls back to where no image's list is attached (a live process, a
    /// context built bare); it misses a table only other code names.
    pub fn of_code<'a>(ctx: &Ctx, insns: &[DecodedInsn], dispatches: impl IntoIterator<Item = &'a SwitchDispatch>) -> Self {
        let refs = crate::xref::CodeReferences::default();
        let mut scan = crate::xref::CodeScan::new(&refs);
        let named: Vec<u64> = insns.iter().flat_map(|ins| crate::xref::addresses_named(ctx, &mut scan, ins)).map(|v| v.0).collect();
        Self::new(named, dispatches.into_iter().filter_map(|d| d.table).map(|t| t.0))
    }

    /// The bases a graph reads its tables against: the image's where `ctx` has them,
    /// else those of its own code.
    pub fn for_graph<'a>(ctx: &Ctx, insns: &[DecodedInsn], dispatches: impl IntoIterator<Item = &'a SwitchDispatch>) -> std::sync::Arc<Self> {
        ctx.table_bases.and_then(|t| t.bases()).unwrap_or_else(|| std::sync::Arc::new(Self::of_code(ctx, insns, dispatches)))
    }

    pub fn after(&self, table: u64) -> Option<u64> {
        self.sorted.get(self.sorted.partition_point(|&b| b <= table)).copied()
    }
}

/// Where a context gets the image's [`TableBases`], built when a graph first meets
/// a table: the frontend's, from the `xref` index it keeps for the image.
pub trait TableBasesSource {
    /// `None` where the image's list cannot be had; a graph then takes its own code's.
    fn bases(&self) -> Option<std::sync::Arc<TableBases>>;
}

/// Read the jump table for `disp` through the source seam and resolve cases.
///
/// `insns` end at the dispatching jump. The bound is the guard of the index that
/// reaches the table, read from them ([`n0xis_arch::Arch::index_guard`]), and it is
/// the one bound: `ir build`'s, the `switch` a body prints and `ir explain`'s. It was
/// [`SwitchDispatch::bound`], the nearest comparison against any constant: on a
/// loop's dispatch that is a step limit of 99999 above a guard that compares memory,
/// and the graph read on past the table by it, two case edges to code no index
/// reaches. Where no guard is read the read stops as [`read_table`] says, and the
/// switch keeps why ([`ResolvedSwitch::end`]).
pub fn resolve_switch(ctx: &Ctx, insns: &[DecodedInsn], disp: &SwitchDispatch, bases: &TableBases) -> ResolvedSwitch {
    let index = ctx.arch.index_guard(insns, disp);
    let mut out = ResolvedSwitch {
        at: disp.at,
        kind: disp.kind.as_str().to_string(),
        table: disp.table,
        index_reg: disp.index_reg.clone(),
        scale: disp.scale,
        index,
        // An architecture with no native pointer width (a WebAssembly module's)
        // recognizes no jump table — `detect_switch` is how it would, and it
        // lifts nothing — so it does not get here. Were it to, a table of
        // pointers has no width to be read with, and nothing is read: the switch
        // stays unresolved, with no entry size.
        entry_size: ctx.arch.pointer_size().map_or(0, |p| disp.kind.entry_size(p)),
        resolved: false,
        cases: Vec::new(),
        end: None,
    };
    // A base in a register is a runtime value: nothing to read statically.
    let Some(read) = disp.table.and_then(|table| read_table(ctx, disp.kind, table, disp.at, index, bases)) else {
        return out;
    };
    out.cases = read.entries.into_iter().map(|(_, t)| t).collect();
    out.resolved = true;
    out.end = Some(read.end);
    out
}

/// A jump's table as read: its entries, each with the word it is in.
#[derive(Clone, Debug)]
pub struct TableRead {
    /// `(slot, target)` in table order.
    pub entries: Vec<(Va, Va)>,
    /// What held the read, where anything did ([`Arch::index_guard`](n0xis_arch::Arch::index_guard)).
    pub bound: Option<IndexBound>,
    /// Why the read stopped.
    pub end: TableEnd,
    /// The address an entry is relative to.
    pub relative_to: Option<Va>,
    /// Bytes per entry.
    pub entry_size: u64,
}

impl TableRead {
    /// Whether a guard of the index says how many entries there are.
    pub fn guarded(&self) -> bool {
        self.bound.and_then(IndexBound::guard).is_some()
    }
}

/// Read the table at `table` of the jump at `at`. **The one reader**: the graph's
/// cases and `xref`'s are read by it. The read stops at whichever comes first:
///
/// 1. the guard's bound, when one is read;
/// 2. else the index's width (a byte widened with zeros: 256 entries);
/// 3. the end of the function the image states the jump is in, its parts apart
///    included: an entry that leads out of it ends the table;
/// 4. the next table's base (`bases`): the words after a table are often the next
///    table, whose entries are code too, and an index may be masked to more values
///    than its table has;
/// 5. the first entry that is not code;
///
/// and where none of them does, where the words the image holds end.
///
/// With neither 1 nor 2 the count is not known, and the walk is held to
/// [`UNBOUNDED_PROBE_LIMIT`] besides. `None` where the first entry already stops it,
/// or the words cannot be read.
pub fn read_table(ctx: &Ctx, kind: SwitchKind, table: Va, at: Va, bound: Option<IndexBound>, bases: &TableBases) -> Option<TableRead> {
    let pointer_size = ctx.arch.pointer_size()?;
    let step = u64::from(kind.entry_size(pointer_size));
    let (held, by) = match bound {
        Some(b) if b.largest() < MAX_SWITCH_CASES as u64 => (b.largest() as usize + 1, if b.guard().is_some() { TableEnd::Guard } else { TableEnd::Width }),
        Some(_) => (MAX_SWITCH_CASES, TableEnd::Limit),
        None => (UNBOUNDED_PROBE_LIMIT, TableEnd::Limit),
    };
    let (count, mut end) = match bases.after(table.0).map(|next| (next.saturating_sub(table.0) / step) as usize) {
        Some(before_next) if before_next < held => (before_next, TableEnd::NextTable),
        _ => (held, by),
    };
    // A guard read from the bytes says more than a stated end: gcc moves a default
    // case into a `.cold` part, which a stripped ELF's unwind data states as a
    // function of its own, and Lua's guarded tables of 34 were cut to 4 there, a case
    // of the function itself among those lost. The next table and what is not code
    // stop a guarded read too; where one stops it short of its guard, the switch
    // says so ([`ResolvedSwitch::short_of_its_guard`]).
    let function = crate::xref::stated_function(ctx, at).filter(|_| !matches!(bound, Some(IndexBound::Guard(_))));
    let mut targets = Vec::new();
    let read = read_entries(ctx, kind, table, count)?;
    if read.len() < count && read.last().is_none_or(Option::is_some) {
        end = TableEnd::Unreadable;
    }
    for target in read {
        let Some(target) = target else {
            end = TableEnd::NotCode;
            break;
        };
        if function.is_some_and(|f| !f.holds(target)) {
            end = TableEnd::FunctionEnd;
            break;
        }
        targets.push(target);
    }
    if targets.is_empty() {
        return None;
    }
    let entries = targets.into_iter().enumerate().map(|(i, t)| (Va(table.0 + i as u64 * step), t)).collect();
    Some(TableRead { entries, bound, end, relative_to: matches!(kind, SwitchKind::RegRel32).then_some(table), entry_size: step })
}

/// The entries of a table, in order, up to `count`: each its target where that is
/// code, `None` from the first that is not, after which nothing is read. Fewer
/// than `count`, all code, where the words end first. `None` where none can be read.
fn read_entries(ctx: &Ctx, kind: SwitchKind, table: Va, count: usize) -> Option<Vec<Option<Va>>> {
    let step = kind.entry_size(ctx.arch.pointer_size()?) as usize;
    let raw = ctx.source.read(table, count.saturating_mul(step)).ok()?;
    // Prefer the executable ranges as the "is this code?" gate; fall back to
    // mere mapped-ness when the source can't report a code extent.
    //
    // **All** of them, not just `.text`: an IL2CPP image keeps its
    // transpiled C# in a second executable section, so gating on `.text` alone
    // rejected every jump table in 89% of the binary — switch recovery quietly
    // giving up on the bulk of the code, reported as "unresolved".
    let code = ctx.source.code_ranges();
    let mut entries = Vec::new();
    for chunk in raw.chunks_exact(step) {
        let target = decode_entry(kind, table, chunk).filter(|&t| is_code(ctx, &code, t));
        entries.push(target);
        if target.is_none() {
            break;
        }
    }
    Some(entries)
}

/// Does `target` land in executable code? Uses the source's code extent when
/// known (rejects data addresses like the table itself), else falls back to
/// plain mapped-ness.
fn is_code(ctx: &Ctx, code: &[(Va, u64)], target: Va) -> bool {
    if code.is_empty() {
        return ctx.source.contains(target);
    }
    code.iter().any(|(base, size)| target.0 >= base.0 && target.0 < base.0.saturating_add(*size))
}

/// Turn one table entry into a case target VA.
fn decode_entry(kind: SwitchKind, table: Va, bytes: &[u8]) -> Option<Va> {
    match kind {
        SwitchKind::MemIndexed => {
            // Little-endian native pointer (entry_size == pointer width).
            let mut v: u64 = 0;
            for (i, b) in bytes.iter().enumerate() {
                v |= (*b as u64) << (8 * i);
            }
            (v != 0).then_some(Va(v))
        }
        SwitchKind::RegRel32 => {
            // Signed 32-bit offset from the table base.
            let arr: [u8; 4] = bytes.try_into().ok()?;
            let rel = i32::from_le_bytes(arr) as i64;
            Some(Va(table.0.wrapping_add(rel as u64)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::{Arch, X64};
    use n0xis_sources::{MemorySource, Snapshot};

    /// The gate must accept a target in **any** executable range, not only the
    /// first. On an IL2CPP image the second one holds 89% of the code, so
    /// a first-range-only check rejected every jump table there and reported
    /// the switch as unresolved.
    #[test]
    fn a_target_in_a_second_code_range_is_still_code() {
        let snap = Snapshot::builder().region(Va(0x1000), vec![0u8; 16]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let ranges = [(Va(0x1000), 0x200u64), (Va(0x8000), 0x4000)];

        assert!(is_code(&ctx, &ranges, Va(0x1100)), "first range");
        assert!(is_code(&ctx, &ranges, Va(0x9000)), "second range — the case that used to fail");
        assert!(!is_code(&ctx, &ranges, Va(0x5000)), "between the ranges is not code");
        assert!(!is_code(&ctx, &ranges, Va(0xC000)), "past the last range is not code");
    }

    /// The dispatch the tests below read, at 0x1017, through a table of 32-bit offsets
    /// at 0x2000. As `objdump -D -b binary -m i386:x86-64 -M intel --adjust-vma=0x1000`
    /// reads the bytes (each optional part replaced by as many `nop`s when absent):
    ///
    /// ```text
    /// 1000: 83 ff 02              cmp    edi,0x2          (guard; or 83 fe 02: cmp esi,0x2,
    /// 1003: 77 2b                 ja     0x1030            which guards another register)
    /// 1005: 40 0f b6 c7           movzx  eax,dil          (widen; else 89 f8 90 90: mov eax,edi)
    /// 1009: 48 8d 15 f0 0f 00 00  lea    rdx,[rip+0xff0]  # 0x2000
    /// 1010: 48 63 04 82           movsxd rax,DWORD PTR [rdx+rax*4]
    /// 1014: 48 01 d0              add    rax,rdx
    /// 1017: ff e0                 jmp    rax
    /// 1019: 48 8d 0d f0 0f 00 00  lea    rcx,[rip+0xff0]  # 0x2010 (second table)
    /// 1020: c3                    ret, and a `ret` at every byte to 0x1200
    /// ```
    ///
    /// The table's entries are planted: `targets`, each as its offset from 0x2000.
    struct Planted {
        guard: bool,
        /// `cmp esi,2; ja` in the guard's place: the same instructions, no guard of the index.
        compares_another: bool,
        widen: bool,
        second_table: bool,
        targets: Vec<u64>,
    }

    impl Planted {
        fn new(targets: impl IntoIterator<Item = u64>) -> Self {
            Planted { guard: false, compares_another: false, widen: false, second_table: false, targets: targets.into_iter().collect() }
        }

        fn image(&self) -> Snapshot {
            let mut code = Vec::new();
            code.extend_from_slice(match (self.guard, self.compares_another) {
                (true, _) => &[0x83, 0xff, 0x02, 0x77, 0x2b],
                (false, true) => &[0x83, 0xfe, 0x02, 0x77, 0x2b],
                (false, false) => &[0x90; 5],
            });
            code.extend_from_slice(if self.widen { &[0x40, 0x0f, 0xb6, 0xc7] } else { &[0x89, 0xf8, 0x90, 0x90] });
            code.extend_from_slice(&[0x48, 0x8d, 0x15, 0xf0, 0x0f, 0x00, 0x00, 0x48, 0x63, 0x04, 0x82, 0x48, 0x01, 0xd0, 0xff, 0xe0]);
            code.extend_from_slice(if self.second_table { &[0x48, 0x8d, 0x0d, 0xf0, 0x0f, 0x00, 0x00] } else { &[0x90; 7] });
            code.resize(0x200, 0xc3);
            let table: Vec<u8> = self.targets.iter().flat_map(|t| ((*t as i64 - 0x2000) as i32).to_le_bytes()).collect();
            Snapshot::builder().region(Va(0x1000), code).region(Va(0x2000), table).build()
        }

        /// The switch as the graph resolves it: the bases from the whole function's
        /// code, as `ir build` takes them.
        fn resolve(&self, functions: Option<&[crate::StatedFunction]>) -> ResolvedSwitch {
            let snap = self.image();
            let arch = X64::new();
            let mut ctx = Ctx::new(&snap, &arch);
            if let Some(f) = functions {
                ctx = ctx.with_stated_functions(f, n0xis_sources::StartCoverage::Some);
            }
            let code = snap.read(Va(0x1000), 0x30).expect("code");
            let insns = arch.decode_range(&code, Va(0x1000), code.len());
            let jump = insns.iter().position(|i| i.va == Va(0x1017)).expect("the jump decodes");
            let disp = arch.detect_switch_with_context(&insns[..=jump], 0).expect("a dispatch");
            let bases = TableBases::of_code(&ctx, &insns, [&disp]);
            resolve_switch(&ctx, &insns[..=jump], &disp, &bases)
        }
    }

    fn cases(from: u64, n: u64) -> impl Iterator<Item = u64> {
        (0..n).map(move |i| from + i)
    }

    /// A guard of the index: `cmp edi,2; ja` lets three through, and three are read
    /// of eight that are code.
    #[test]
    fn a_guarded_table_is_read_to_its_guard() {
        let sw = Planted { guard: true, widen: true, ..Planted::new(cases(0x1020, 8)) }.resolve(None);
        assert_eq!((sw.index, sw.end), (Some(IndexBound::Guard(2)), Some(TableEnd::Guard)));
        assert_eq!(sw.cases, vec![Va(0x1020), Va(0x1021), Va(0x1022)]);
        assert_eq!(sw.unguarded_note(), None, "a guarded table needs no word");
    }

    /// No guard, but the index is a byte widened with zeros: no index past 255
    /// reaches the table, so 256 of 300 entries that are code are read, and the
    /// body says the width held them.
    #[test]
    fn an_index_widened_from_a_byte_holds_the_read_to_256() {
        let sw = Planted { widen: true, ..Planted::new((0..300).map(|i| 0x1020 + i % 0x1e0)) }.resolve(None);
        assert_eq!((sw.index, sw.end), (Some(IndexBound::Width(0xff)), Some(TableEnd::Width)));
        assert_eq!(sw.cases.len(), 256);
        let note = sw.unguarded_note().expect("an unguarded table is said");
        assert!(note.starts_with(UNGUARDED_TABLE) && note.contains("width (256 entries)"), "{note}");
    }

    /// No guard and no width: the read stops at the first entry that leads out of
    /// the function the image states, `[0x1000, 0x1030)`: 16 of them are its.
    #[test]
    fn an_unguarded_read_stops_at_the_functions_stated_end() {
        let functions = crate::origin::fdes(&[(Va(0x1000), Va(0x1030))]);
        let sw = Planted::new(cases(0x1020, 40)).resolve(Some(&functions));
        assert_eq!((sw.index, sw.end), (None, Some(TableEnd::FunctionEnd)));
        assert_eq!(sw.cases.len(), 16);
        assert!(sw.unguarded_note().expect("said").contains("leaves the function"));
    }

    /// The function's parts apart are the function: entries into its detached part
    /// at 0x1100 are read, and the read stops at the first one past both.
    #[test]
    fn a_part_of_the_function_apart_is_inside_it() {
        let f = crate::EhFunction {
            start: Va(0x1000),
            end: Va(0x1030),
            detached: vec![n0xis_sources::FunctionPart { start: Va(0x1100), end: Va(0x1110) }],
            regions: Vec::new(),
        };
        let functions = vec![crate::StatedFunction::of_unwind(&f, crate::origin::StatedBy::EhFrame)];
        let sw = Planted::new(cases(0x1020, 16).chain(cases(0x1100, 8)).chain([0x1180])).resolve(Some(&functions));
        assert_eq!(sw.end, Some(TableEnd::FunctionEnd));
        assert_eq!(sw.cases.len(), 24, "16 in [start, end) and 8 in the part apart");
    }

    /// The function takes 0x2010 too, four entries on: the table ends where it
    /// begins, though the words after are code of the function.
    #[test]
    fn an_unguarded_read_stops_at_the_next_table() {
        let functions = crate::origin::fdes(&[(Va(0x1000), Va(0x1200))]);
        let sw = Planted { second_table: true, ..Planted::new(cases(0x1020, 40)) }.resolve(Some(&functions));
        assert_eq!((sw.index, sw.end), (None, Some(TableEnd::NextTable)));
        assert_eq!(sw.cases.len(), 4);
    }

    /// With nothing else to hold it, the read stops at the first entry that is not
    /// code: the sixth leads to 0x9000, which nothing maps.
    #[test]
    fn an_unguarded_read_stops_at_an_entry_that_is_not_code() {
        let sw = Planted::new(cases(0x1020, 5).chain([0x9000]).chain(cases(0x1030, 5))).resolve(None);
        assert_eq!((sw.index, sw.end), (None, Some(TableEnd::NotCode)));
        assert_eq!(sw.cases.len(), 5);
    }

    /// With nothing to hold it, not even the image's code, the read stops at its own
    /// limit: 256 of 300 entries that are all code.
    #[test]
    fn an_unheld_read_stops_at_its_own_limit() {
        let sw = Planted::new((0..300).map(|i| 0x1020 + i % 0x1e0)).resolve(None);
        assert_eq!((sw.index, sw.end), (None, Some(TableEnd::Limit)));
        assert_eq!(sw.cases.len(), UNBOUNDED_PROBE_LIMIT);
    }

    /// The image holds six words of the table and no more: six are read, and the
    /// read says it was the words that ended, not a bound.
    #[test]
    fn a_read_past_the_words_the_image_holds_says_so() {
        let sw = Planted::new(cases(0x1020, 6)).resolve(None);
        assert_eq!((sw.cases.len(), sw.end), (6, Some(TableEnd::Unreadable)));
    }

    /// The graph takes the next table's base from its function's own code, as
    /// `xref` takes it from its index: `ir build`'s switch has four cases, and says
    /// why.
    #[test]
    fn the_graph_stops_a_table_where_its_function_takes_the_next() {
        let planted = Planted { second_table: true, ..Planted::new(cases(0x1020, 40)) };
        let snap = planted.image();
        let arch = X64::new();
        let functions = crate::origin::fdes(&[(Va(0x1000), Va(0x1200))]);
        let ctx = Ctx::new(&snap, &arch).with_stated_functions(&functions, n0xis_sources::StartCoverage::Some);
        let art = crate::Pass::run(&crate::ir::CfgPass, &ctx, crate::ir::CfgInput::new(Va(0x1000), 0x200)).expect("cfg builds");
        let sw = art.switches.first().expect("one switch");
        assert_eq!((sw.cases.len(), sw.end), (4, Some(TableEnd::NextTable)), "{sw:?}");
    }

    /// A body says a switch's cases are only what the read found, in every style,
    /// and that is a mark in `quality`: the same instructions with a guard of the
    /// index (`cmp edi,2` for `cmp esi,2`) say nothing of it, and score higher.
    #[test]
    fn a_body_says_no_guard_held_its_switch() {
        let decompile = |planted: Planted, style| {
            let snap = planted.image();
            let arch = X64::new();
            let functions = crate::origin::fdes(&[(Va(0x1000), Va(0x1200))]);
            let ctx = Ctx::new(&snap, &arch).with_stated_functions(&functions, n0xis_sources::StartCoverage::Some);
            let cfg = crate::Pass::run(&crate::ir::CfgPass, &ctx, crate::ir::CfgInput::new(Va(0x1000), 0x200)).expect("cfg builds");
            let input = crate::DecompInput { cfg, style, explain: false, strip_block_labels: false, var_names: Default::default(), var_types: Default::default(), struct_defs: Default::default() };
            crate::Pass::run(&crate::DecompPass, &ctx, input).expect("decomp")
        };
        for style in [crate::DecompStyle::Ssa, crate::DecompStyle::Goto] {
            let open = decompile(Planted { compares_another: true, widen: true, second_table: true, ..Planted::new(cases(0x1020, 40)) }, style);
            let guarded = decompile(Planted { guard: true, widen: true, second_table: true, ..Planted::new(cases(0x1020, 40)) }, style);
            let body = open.pseudo.join("\n");
            let note = body.lines().find(|l| l.trim_start().starts_with(UNGUARDED_TABLE)).unwrap_or_else(|| panic!("{style:?}: {body}"));
            assert!(note.contains("width (256 entries)") && note.contains("4 read") && note.contains("next table"), "{note}");
            assert!(!guarded.pseudo.iter().any(|l| l.contains(UNGUARDED_TABLE)), "{style:?}: {:?}", guarded.pseudo);
            assert!(open.quality < guarded.quality, "{style:?}: {} against {}", open.quality, guarded.quality);
        }
    }

    /// The switch at `jump` in `code` at 0x1000 (padded with `ret` to 0x1100), over
    /// a table of 32-bit offsets from 0x2000 to `targets`.
    fn resolve_code(code: &[u8], jump: u64, targets: &[u64], bases: Option<&dyn TableBasesSource>) -> ResolvedSwitch {
        let mut bytes = code.to_vec();
        bytes.resize(0x100, 0xc3);
        let table: Vec<u8> = targets.iter().flat_map(|t| ((*t as i64 - 0x2000) as i32).to_le_bytes()).collect();
        let snap = Snapshot::builder().region(Va(0x1000), bytes).region(Va(0x2000), table).build();
        let arch = X64::new();
        let mut ctx = Ctx::new(&snap, &arch);
        if let Some(b) = bases {
            ctx = ctx.with_table_bases(b);
        }
        let insns = arch.decode_range(code, Va(0x1000), code.len());
        let at = insns.iter().position(|i| i.va == Va(jump)).expect("the jump decodes");
        let disp = arch.detect_switch_with_context(&insns[..=at], 0).expect("a dispatch");
        let bases = TableBases::for_graph(&ctx, &insns, [&disp]);
        resolve_switch(&ctx, &insns[..=at], &disp, &bases)
    }

    /// A guard read from the bytes says more than the function's stated end: an entry
    /// to code outside `[0x1000, 0x1030)`, as gcc's `.cold` part of the function is
    /// to a stripped ELF's unwind data, does not end a guarded read. Lua's tables of
    /// 34 were cut to 4 there, a case of the function itself among those lost.
    #[test]
    fn a_guarded_read_goes_past_the_functions_stated_end() {
        let functions = crate::origin::fdes(&[(Va(0x1000), Va(0x1030))]);
        let sw = Planted { guard: true, ..Planted::new([0x1020, 0x1100, 0x1021]) }.resolve(Some(&functions));
        assert_eq!((sw.cases.len(), sw.end), (3, Some(TableEnd::Guard)));
        assert_eq!(sw.short_of_its_guard(), None);
    }

    /// The next table and what is not code stop a guarded read too, and the switch
    /// says it stopped short of its guard, which `ir explain` shows.
    #[test]
    fn a_guarded_read_stopped_early_says_it_is_short_of_its_guard() {
        let sw = Planted { guard: true, ..Planted::new([0x1020, 0x9000, 0x1021]) }.resolve(None);
        assert_eq!((sw.cases.len(), sw.end), (1, Some(TableEnd::NotCode)));
        assert_eq!(sw.short_of_its_guard(), Some((3, TableEnd::NotCode)));
    }

    struct Bases(Vec<u64>);
    impl TableBasesSource for Bases {
        fn bases(&self) -> Option<std::sync::Arc<TableBases>> {
            Some(std::sync::Arc::new(TableBases::new(self.0.iter().copied(), [])))
        }
    }

    /// Where the image's table bases are attached, the graph reads against them: a
    /// table 0x2014 starts, named only by code elsewhere, ends this one at 5 entries,
    /// which the function's own code would have read on past.
    #[test]
    fn the_images_table_bases_end_a_table_its_own_code_does_not_name() {
        let code = Planted::new([]).image().read(Va(0x1000), 0x30).expect("code");
        let targets: Vec<u64> = cases(0x1020, 12).collect();
        let own = resolve_code(&code[..0x19], 0x1017, &targets, None);
        assert_eq!(own.cases.len(), 12, "the function's own code names no second table");
        let image = Bases(vec![0x2014]);
        let sw = resolve_code(&code[..0x19], 0x1017, &targets, Some(&image));
        assert_eq!((sw.cases.len(), sw.end), (5, Some(TableEnd::NextTable)));
    }

    /// The JSON a switch has always had: `bound` is the guard's, and only the
    /// guard's; a width is its own key; and a switch with both is refused, not read
    /// as one of them.
    #[test]
    fn a_switch_says_its_guard_and_its_width_under_their_own_keys() {
        let widened = Planted { widen: true, ..Planted::new((0..300).map(|i| 0x1020 + i % 0x1e0)) }.resolve(None);
        let json = serde_json::to_value(&widened).expect("serializes");
        assert_eq!((json.get("bound"), json.get("width")), (None, Some(&serde_json::json!(255))), "{json}");
        let guarded = Planted { guard: true, ..Planted::new(cases(0x1020, 8)) }.resolve(None);
        let json = serde_json::to_value(&guarded).expect("serializes");
        assert_eq!((json.get("bound"), json.get("width")), (Some(&serde_json::json!(2)), None), "{json}");
        let back: ResolvedSwitch = serde_json::from_value(json.clone()).expect("reads back");
        assert_eq!((back.index, back.cases.len(), back.end), (Some(IndexBound::Guard(2)), 3, Some(TableEnd::Guard)));
        let mut both = json;
        both["width"] = serde_json::json!(255);
        assert!(serde_json::from_value::<ResolvedSwitch>(both).is_err(), "a guard and a width at once");
    }

    /// With no ranges at all the gate falls back to plain mapped-ness, exactly
    /// as it did when the source could not report a code extent.
    #[test]
    fn no_known_ranges_falls_back_to_mapped_ness() {
        let snap = Snapshot::builder().region(Va(0x1000), vec![0u8; 16]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        assert!(is_code(&ctx, &[], Va(0x1000)));
        assert!(!is_code(&ctx, &[], Va(0x9999)));
    }
}
