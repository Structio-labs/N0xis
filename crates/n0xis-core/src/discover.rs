// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`DiscoverPass`] — heuristic function discovery by prologue scanning.
//!
//! Scans a code range for the ISA's function-entry byte patterns (supplied by
//! [`Arch::prologues`](n0xis_arch::Arch::prologues), never hardcoded here) and
//! emits `sub_<addr>` candidates. Ported from v0's `.text` prolog scan, refit
//! to read through the [`MemorySource`](n0xis_sources::MemorySource) seam so it
//! works the same on a live module and a static image.

use n0xis_sources::MemorySource;
use n0xis_arch::{DecodedInsn, InsnKind};
use n0xis_contracts::Va;
use serde::Serialize;

use crate::{Ctx, CoreError, Pass};
use std::collections::{BTreeMap, BTreeSet};

/// Where and how much to scan.
#[derive(Clone, Copy, Debug)]
pub struct DiscoverInput {
    /// Start of the code range (usually `.text`).
    pub start: Va,
    /// Bytes to scan from `start`.
    pub size: usize,
    /// Cap on the number of candidates; `0` = unlimited (the prologue scan is
    /// bounded by the range anyway, so "no cap" is a sane default).
    pub limit: usize,
    /// How many matches to skip before collecting — pagination over a range
    /// too big to return at once. Skipped matches are still *found* (the scan
    /// is sequential), just not carried, so the cost is the scan, not the
    /// payload.
    pub offset: usize,
}

/// A discovered function candidate.
#[derive(Clone, Debug, Serialize)]
pub struct FunctionCandidate {
    pub name: String,
    pub va: Va,
    /// Exclusive end address, when known (only the `.pdata` discovery has it;
    /// the prologue scan can't know a function's extent). Lets a caller pass
    /// an exact `--size` to `decomp`/`ir` instead of guessing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<Va>,
}

/// Authoritative function discovery from the PE exception directory (the
/// `.pdata` `RUNTIME_FUNCTION` table): **every** function that has unwind info,
/// with an exact start *and* end, no prologue heuristic and no cap. x64-only —
/// the table only exists on exception-handling architectures. Reads the PE
/// headers through the [`MemorySource`] seam, so it behaves identically on a
/// [`StaticPe`](n0xis_sources::StaticPe) and a live module. Returns an empty
/// list (not an error) when the image has no exception directory.
///
/// ⚠️ Takes a bare [`MemorySource`], not a [`Ctx`], so it has no symbol seam to
/// consult: its candidates are always `sub_<addr>`. The prologue scan below
/// names its own through [`name_at`]. Closing this asymmetry means giving the
/// CLI's hand-written `--pdata` handler a symbol-carrying context, which it
/// does not build today — a known gap, stated here rather than left to be
/// discovered as "why does `--pdata` lose the names".
/// Upper bound on the exception directory this will read in one go. Generous
/// against real images (a browser engine's table is under a megabyte) and
/// bounded against a header that states a size the file cannot hold.
const MAX_EXCEPTION_TABLE: usize = 64 * 1024 * 1024;

pub fn discover_pdata(source: &dyn MemorySource, module_base: Va) -> Result<Vec<FunctionCandidate>, CoreError> {
    let hdr = source.read(module_base, 0x400)?;
    let rd_u32 = |off: usize| -> Option<u32> { hdr.get(off..off + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())) };
    let rd_u16 = |off: usize| -> Option<u16> { hdr.get(off..off + 2).map(|b| u16::from_le_bytes(b.try_into().unwrap())) };
    let e_lfanew = rd_u32(0x3c).ok_or_else(|| CoreError::Other("truncated PE header at module base".into()))? as usize;
    if hdr.get(e_lfanew..e_lfanew + 4) != Some(&b"PE\0\0"[..]) {
        return Err(CoreError::Other("no PE signature at module base (not a mapped PE image?)".into()));
    }
    // IMAGE_NT_HEADERS: sig(4) + IMAGE_FILE_HEADER(20) → optional header at
    // e_lfanew+24; entry [3] of the DataDirectory is
    // IMAGE_DIRECTORY_ENTRY_EXCEPTION.
    //
    // **The directory does not sit at the same offset in both PE flavours**:
    // 96 in a PE32 optional header, 112 in a PE32+. Reading a PE32 at 112
    // lands 16 bytes past the directory, inside the section table, and the
    // bytes there parse as a perfectly plausible RVA and size — which is how a
    // 32-bit image with no exception directory at all answered with 50
    // "functions", the first of them ending before it began.
    let magic = rd_u16(e_lfanew + 24).unwrap_or(0x20b);
    let exc_off = e_lfanew + 24 + if magic == 0x10b { 96 } else { 112 } + 3 * 8;
    let exc_rva = rd_u32(exc_off).ok_or_else(|| CoreError::Other("PE optional header too short for the exception directory".into()))?;
    let exc_size = rd_u32(exc_off + 4).unwrap_or(0);
    if exc_rva == 0 || exc_size == 0 {
        // Not an empty answer — no answer, and the caller asked this table a
        // question. A 32-bit image has no x64 unwind table to hold one, and
        // reporting that as "0 functions" reads like a finding rather than
        // like the wrong question.
        return Err(CoreError::Other(format!(
            "this image declares no exception directory, so there is no `.pdata` table to discover from ({})",
            if magic == 0x10b { "PE32 — x64 unwind tables are a PE32+ structure" } else { "PE32+ with the directory empty or stripped" }
        )));
    }
    // `exc_size` is a length read out of the image's own header, so it is
    // untrusted: it bounds the read, it never sizes an allocation on its own.
    let table = source.read(module_base.offset(exc_rva as u64), (exc_size as usize).min(MAX_EXCEPTION_TABLE))?;
    let mut out = Vec::new();
    let mut off = 0usize;
    // Each RUNTIME_FUNCTION is 12 bytes: BeginAddress, EndAddress, UnwindInfo
    // (all RVAs). We only need begin+end.
    while off + 12 <= table.len() {
        let begin = u32::from_le_bytes(table[off..off + 4].try_into().unwrap());
        let end = u32::from_le_bytes(table[off + 4..off + 8].try_into().unwrap());
        off += 12;
        if begin == 0 && end == 0 {
            break;
        }
        // A RUNTIME_FUNCTION whose end does not follow its start describes no
        // function. Dropping it is not tidiness: it is the difference between
        // reporting a misparse and reporting a function at an address that
        // holds none.
        if end <= begin {
            continue;
        }
        let va = module_base.offset(begin as u64);
        out.push(FunctionCandidate {
            name: format!("sub_{:X}", va.0),
            va,
            end: Some(module_base.offset(end as u64)),
        });
    }
    Ok(out)
}

/// The name to report for a function starting at `va`.
///
/// **Only an exact hit counts.** A provider that attributes a whole function
/// span answers for any address inside it, so accepting a near miss would name
/// a discovered function after whichever one precedes it — the same
/// sound-over-complete rule `decomp`'s own-name resolution follows. With no
/// symbol source, or no exact hit, the address stands in exactly as it always
/// did.
///
/// This is what makes the managed layer visible in triage: on an IL2CPP target
/// with an imported index, `ir manifest` ranks *named C# methods* instead of a
/// wall of `sub_`, which is the difference between a browsable index and a list
/// of numbers.
/// A run of zero bytes is a section's fill, not code — on any ISA whose zero
/// encoding is degenerate, which is every one this targets (`add [rax], al` on
/// x86, `udf #0` on AArch64). A function does not begin by dereferencing a
/// register the ABI never set.
///
/// Byte-level rather than decoder-level on purpose: the decoder happily turns
/// `00 00` into an instruction, which is exactly the trap — a synthetic image
/// whose `.text` is zero-filled had two functions invented in it.
fn zero_fill(bytes: &[u8], off: usize) -> bool {
    bytes.get(off).is_some_and(|&b| b == 0)
}

/// Alignment filler rather than a function's first instruction.
///
/// Asked of the decoder rather than matched as bytes: `90`, `cc`, and the whole
/// family of multi-byte `nop`s (`66 66 0f 1f 84 00 …`) are one question to an
/// instruction decoder and a list of magic strings to anything else. A byte
/// pattern list also silently stops being right on the next architecture.
fn is_filler(ins: &DecodedInsn) -> bool {
    matches!(ins.mnemonic.as_str(), "nop" | "int3")
}

/// The first real instruction after each declared function's end — the next
/// function, when the compiler laid them out back to back.
///
/// Stops at the first thing that is neither filler nor decodable: a gap that
/// holds data rather than code produces nothing rather than a guess.
fn after_declared_ends(ctx: &Ctx, bytes: &[u8], start: Va, declared: &[(u64, u64)]) -> BTreeSet<u64> {
    let lo = start.0;
    let hi = lo.saturating_add(bytes.len() as u64);
    let mut out = BTreeSet::new();
    for &(_, end) in declared {
        let mut va = end;
        while va >= lo && va < hi {
            if zero_fill(bytes, (va - lo) as usize) {
                va += 1;
                continue;
            }
            let Ok(ins) = ctx.arch.decode(&bytes[(va - lo) as usize..], Va(va)) else { break };
            if !is_filler(&ins) {
                out.insert(va);
                break;
            }
            va = va.saturating_add(u64::from(ins.len));
        }
    }
    out
}

/// Linear sweep of the code **between** declared functions, emitting a start
/// wherever one function has ended and the next has not been declared.
///
/// Bounded to the gaps on purpose: inside a declared extent the table already
/// answers the question, and past the last declared function there is no
/// bracket to stop at. That also bounds the cost to the part of the image the
/// image itself does not describe.
fn sweep_declared_gaps(ctx: &Ctx, bytes: &[u8], start: Va, declared: &[(u64, u64)]) -> BTreeSet<u64> {
    let lo = start.0;
    let hi = lo.saturating_add(bytes.len() as u64);
    let mut out = BTreeSet::new();
    let at = |va: u64| -> Option<DecodedInsn> {
        (va >= lo && va < hi).then(|| ctx.arch.decode(&bytes[(va - lo) as usize..], Va(va)).ok())?
    };
    for pair in declared.windows(2) {
        // **Clip the gap to what was actually read.** The declared table
        // describes the whole image; `bytes` is one section of it, so a
        // declared function can end before the window starts and the next one
        // begin after it ends. Walking from an address below `lo` computes
        // `va - lo` on unsigned addresses: a release build wraps it, and the
        // walk then crawls one byte at a time from a nonsense offset up to the
        // window (the right answer, arrived at slowly); a debug build panics
        // outright, which is how this was found — on a real C library, through
        // the test that compares the function list with the linker's exports.
        let (gap_lo, gap_hi) = (pair[0].1.max(lo), pair[1].0.min(hi));
        if gap_hi <= gap_lo {
            continue;
        }
        let mut va = gap_lo;
        let mut armed = true;
        let mut reach = gap_lo;
        let mut targets: BTreeSet<u64> = BTreeSet::new();
        while va < gap_hi {
            if zero_fill(bytes, (va - lo) as usize) {
                va += 1;
                continue;
            }
            let Some(ins) = at(va) else {
                va += 1;
                continue;
            };
            if is_filler(&ins) {
                va = va.saturating_add(u64::from(ins.len));
                continue;
            }
            if armed && va >= reach && !targets.contains(&va) {
                out.insert(va);
            }
            if matches!(ins.kind, InsnKind::Jump | InsnKind::CondJump)
                && let Some(t) = ins.target
                && t.0 > va
            {
                reach = reach.max(t.0);
                targets.insert(t.0);
            }
            let next = va.saturating_add(u64::from(ins.len));
            armed = match ins.kind {
                // A function ends at a `ret` only when filler follows it —
                // otherwise it is an early return and the function goes on.
                InsnKind::Ret => at(next).is_some_and(|n| is_filler(&n)),
                InsnKind::Jump => true,
                _ => false,
            };
            va = next;
        }
    }
    out
}

/// Every address a direct `call` in `bytes` names, as a sorted set.
///
/// The sweep is linear and resynchronizing ([`Arch::decode_range`]) — data in a
/// code section decodes as nonsense, and nonsense that happens to look like
/// `call rel32` names an address. That risk is why the caller still refuses a
/// target a declared extent already claims, and it is bounded in practice: on
/// the image this was measured against, the sweep produced no target that was
/// not a function entry.
///
/// Decoded in windows rather than all at once: a 10 MB code section is millions
/// of instructions, and only the handful of call targets is kept.
fn direct_call_targets(ctx: &Ctx, bytes: &[u8], start: Va) -> BTreeSet<u64> {
    const WINDOW_INSNS: usize = 8192;
    let mut out = BTreeSet::new();
    let mut at = 0usize;
    while at < bytes.len() {
        let base = start.0.saturating_add(at as u64);
        let insns = ctx.arch.decode_range(&bytes[at..], Va(base), WINDOW_INSNS);
        let Some(last) = insns.last() else { break };
        let consumed = (last.va.0 + u64::from(last.len)).saturating_sub(base) as usize;
        for ins in &insns {
            if ins.kind == n0xis_arch::InsnKind::Call
                && let Some(t) = ins.target
            {
                out.insert(t.0);
            }
        }
        if consumed == 0 {
            break;
        }
        at += consumed;
    }
    out
}

fn name_at(ctx: &Ctx, va: Va) -> String {
    crate::ir::symbol_on_entry(ctx, va)
        .map(|sym| crate::render::render_callee_name(&sym.name))
        .unwrap_or_else(|| format!("sub_{:X}", va.0))
}

/// The discovery artifact (`n0xis.function.discover.v1`).
#[derive(Clone, Debug, Serialize)]
pub struct DiscoverArtifact {
    pub start: Va,
    pub scanned_bytes: usize,
    /// How many candidates `functions` carries (**not** how many exist — see
    /// `meta.total`/`meta.truncated` on the envelope).
    pub count: usize,
    pub functions: Vec<FunctionCandidate>,
    /// `true` when the scan stopped at `limit` with bytes left unscanned, so
    /// more candidates exist beyond what is returned. The exact remaining count
    /// is deliberately not computed — finishing the scan is the work the cap
    /// exists to avoid.
    pub truncated: bool,
}

/// Function discovery pass.
#[derive(Clone, Copy, Debug, Default)]
pub struct DiscoverPass;

impl Pass for DiscoverPass {
    type In = DiscoverInput;
    type Out = DiscoverArtifact;

    fn name(&self) -> &'static str {
        "function.discover"
    }

    fn run(&self, ctx: &Ctx, input: DiscoverInput) -> Result<DiscoverArtifact, CoreError> {
        let bytes = ctx.source.read(input.start, input.size)?;
        let prologues = ctx.arch.prologues(n0xis_sources::MemorySource::abi_name(ctx.source));
        let range = input.start.0..input.start.0.saturating_add(bytes.len() as u64);

        // Facts first. A start the image declares is not a guess, and it comes
        // with an authoritative extent (see `Ctx::functions`).
        let mut found: BTreeMap<u64, Option<Va>> = BTreeMap::new();
        let mut declared: Vec<(u64, u64)> = Vec::new();
        for (s, e) in ctx.functions.unwrap_or(&[]) {
            // `end <= start` is a declared *start* with no stated length — a PE
            // export, say, on an image with no `.pdata` to give extents. It
            // seeds the start and leaves the extent to be inferred; it must not
            // overwrite a real extent already recorded for the same address.
            let extent = (e.0 > s.0).then_some(*e);
            if range.contains(&s.0) {
                found.entry(s.0).and_modify(|slot| { if slot.is_none() { *slot = extent } }).or_insert(extent);
            }
            if e.0 > s.0 {
                declared.push((s.0, e.0));
            }
        }
        declared.sort_unstable();
        // A declared extent settles every address inside it: whatever the scan
        // matches there is part of *that* function, not the start of another
        // one. This is the same rule as trusting a declared start, applied to
        // the rest of the range it claims.
        let inside_a_declared_function = |va: u64| -> bool {
            match declared.binary_search_by(|(s, _)| s.cmp(&va)) {
                Ok(_) => false, // the start itself, already carried above
                Err(0) => false,
                Err(i) => {
                    let (s, e) = declared[i - 1];
                    va > s && va < e
                }
            }
        };

        // The code that begins where a known function ends.
        //
        // A compiler emits functions back to back with alignment padding
        // between them, so the first instruction after a function's declared
        // end is, overwhelmingly, the next function — and the small leaf
        // helpers this misses have no prologue and no unwind record, so nothing
        // else can see them. Measured against an independent function table on
        // a real C++ DLL: 353 addresses this produces that the exception table
        // does not already state, of which **343 are function entries there and
        // none is interior to a known function**.
        //
        // It needs an extent to start from, which is why it is a rule about
        // *declared* functions: a start with no stated length says nothing
        // about where the next one begins.
        for va in after_declared_ends(ctx, &bytes, input.start, &declared) {
            if range.contains(&va) && !inside_a_declared_function(va) {
                found.entry(va).or_insert(None);
            }
        }

        // …and then the rest of that gap. A run of small helpers is emitted back
        // to back with no filler between them, so "the instruction after a
        // declared end" finds only the first of each run. Sweeping the whole
        // gap linearly finds the rest.
        //
        // Two tests keep it from cutting a real function in half, and both were
        // added because measuring showed the damage they prevent:
        //
        // - a `ret` only ends a function when **filler follows it**; a bare
        //   `ret` in the middle of a run of code is an early return. Without
        //   this, 43 of 274 candidates landed inside a known function.
        // - a candidate may not be a place anything **already branches to**,
        //   nor lie before the furthest forward branch target seen. A function
        //   with a forward jump over its own tail otherwise reads as two.
        //
        // Measured on a real C++ DLL: 233 addresses the other sources do not
        // have, 226 of them function entries per an independent function table
        // and 5 interior to one. That takes the functions that table has and
        // n0xis did not from 478 to 5.
        for va in sweep_declared_gaps(ctx, &bytes, input.start, &declared) {
            if range.contains(&va) && !inside_a_declared_function(va) {
                found.entry(va).or_insert(None);
            }
        }

        // A direct `call` names its callee. Unlike a prologue pattern this is
        // not a guess about what the bytes look like — it is how control
        // reaches the function at all, and a compiler cannot withhold it.
        //
        // It matters because the two existing sources both miss the same kind
        // of function: a small leaf helper sets up no frame (no prologue to
        // match) and needs no unwind data (no entry in the exception table).
        // Measured against an independent function table on a real C++ DLL: of
        // 494 distinct direct-call targets in the image, every single one was a
        // function entry there and none pointed into the middle of one — and 47
        // of them were functions neither of the other two sources had.
        //
        // A declared extent still wins: an address a function table places
        // *inside* a function is not a second function, whatever branches at it.
        for va in direct_call_targets(ctx, &bytes, input.start) {
            if range.contains(&va) && !inside_a_declared_function(va) {
                found.entry(va).or_insert(None);
            }
        }

        // Then the scan, for the gaps the declarations leave. A pattern match
        // that no declaration confirms must be **entry-aligned**: the scan
        // walks every byte offset, so a short pattern also matches inside a
        // longer instruction, and a compiler aligns what it enters. On one Qt
        // build that rule dropped 3 978 of 4 483 unconfirmed candidates — an
        // independent function table calls 4 461 of them the middle of another
        // function — while costing 13 of 13 934 real starts.
        let align = ctx.arch.entry_alignment().max(1);
        let markers = ctx.arch.entry_markers();
        let max_pat = prologues.iter().map(|p| p.len()).max().unwrap_or(0);
        let mut i = 0usize;
        while i + max_pat <= bytes.len() {
            if prologues.iter().any(|p| bytes[i..].starts_with(p)) {
                let va = input.start.0 + i as u64;
                let marker = markers.iter().any(|p| bytes[i..].starts_with(p));
                if va.is_multiple_of(align) && (marker || !inside_a_declared_function(va)) {
                    found.entry(va).or_insert(None);
                }
                // Skip ahead so overlapping patterns in one prologue count once.
                i += 8;
                continue;
            }
            i += 1;
        }

        // `limit`/`offset` page over the address-ordered result: page N is the
        // same set of addresses however it was reached.
        let unlimited = input.limit == 0;
        let mut functions = Vec::new();
        let mut hit_limit = false;
        for (n, (va, stated_end)) in found.into_iter().enumerate() {
            if n < input.offset {
                continue;
            }
            if !unlimited && functions.len() >= input.limit {
                hit_limit = true;
                break;
            }
            let va = Va(va);
            // A stated size (ELF `st_size`, a PE `.pdata` entry) makes `end` a
            // fact here — so a scanned image gets exact extents instead of
            // leaving every consumer to infer one.
            let end = ctx
                .symbols
                .and_then(|s| s.symbol_size(va))
                .and_then(|n| va.0.checked_add(n))
                .map(Va)
                .or(stated_end);
            functions.push(FunctionCandidate { name: name_at(ctx, va), va, end });
        }

        Ok(DiscoverArtifact {
            start: input.start,
            scanned_bytes: bytes.len(),
            count: functions.len(),
            functions,
            truncated: hit_limit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    /// A blob whose prologues sit on 16-byte boundaries, the way a compiler
    /// emits them — an unaligned match is no longer a candidate on its own, see
    /// `an_unaligned_prologue_match_is_not_a_candidate`.
    fn two_prologues() -> Vec<u8> {
        let mut code = vec![0x55, 0x48, 0x8B, 0xEC]; // 0x1000 push rbp; mov rbp,rsp
        code.resize(0x10, 0x90); // padding to the next entry
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20, 0xC3]); // 0x1010 sub rsp,0x20
        code
    }

    /// A minimal PE image: header at `base`, one exception-directory entry
    /// written at the offset `magic` puts it, and a RUNTIME_FUNCTION table at
    /// RVA 0x200. `stray` is written at the *other* flavour's directory offset,
    /// standing in for the section-table bytes a wrong-flavour read lands on.
    fn synthetic_pe(magic: u16, dir: Option<(u32, u32)>, stray: Option<(u32, u32)>, table: &[(u32, u32, u32)]) -> Vec<u8> {
        const E_LFANEW: usize = 0x80;
        let mut img = vec![0u8; 0x400];
        img[..2].copy_from_slice(b"MZ");
        img[0x3c..0x40].copy_from_slice(&(E_LFANEW as u32).to_le_bytes());
        img[E_LFANEW..E_LFANEW + 4].copy_from_slice(b"PE\0\0");
        let opt = E_LFANEW + 24;
        img[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
        let (mine, theirs) = if magic == 0x10b { (96, 112) } else { (112, 96) };
        for (off, val) in [(opt + mine + 3 * 8, dir), (opt + theirs + 3 * 8, stray)] {
            if let Some((rva, size)) = val {
                img[off..off + 4].copy_from_slice(&rva.to_le_bytes());
                img[off + 4..off + 8].copy_from_slice(&size.to_le_bytes());
            }
        }
        for (i, (begin, end, unwind)) in table.iter().enumerate() {
            let at = 0x200 + i * 12;
            img[at..at + 4].copy_from_slice(&begin.to_le_bytes());
            img[at + 4..at + 8].copy_from_slice(&end.to_le_bytes());
            img[at + 8..at + 12].copy_from_slice(&unwind.to_le_bytes());
        }
        img
    }

    /// PE32 puts the data directory 16 bytes earlier than PE32+ does, and the
    /// bytes at the PE32+ offset in a PE32 belong to the section table. They
    /// parse as an RVA and a size like any other four bytes, so reading them
    /// does not fail — it answers. Measured on a 32-bit build with no
    /// exception directory at all: 50 "functions", the first ending before it
    /// began.
    #[test]
    fn a_32_bit_image_is_not_read_at_the_64_bit_directory_offset() {
        let img = synthetic_pe(
            0x10b,
            None,                             // PE32: no exception directory, which is the norm
            Some((0x200, 24)),                // section-table bytes that read as one
            &[(0x1000, 0x1010, 0x3000), (0x1020, 0x1030, 0x3000)],
        );
        let snap = Snapshot::builder().region(Va(0x400000), img).build();
        let err = discover_pdata(&snap, Va(0x400000)).expect_err("a PE32 has no x64 unwind table to discover from");
        assert!(
            format!("{err}").contains("PE32"),
            "the refusal must say which flavour it is, so the caller knows it asked the wrong question: {err}"
        );
    }

    /// The same header written as a PE32+ still answers, so the test above is
    /// measuring the offset and not merely a refusal to read anything.
    #[test]
    fn a_64_bit_image_is_still_read_at_its_own_directory_offset() {
        let img = synthetic_pe(0x20b, Some((0x200, 24)), None, &[(0x1000, 0x1010, 0x3000), (0x1020, 0x1030, 0x3000)]);
        let snap = Snapshot::builder().region(Va(0x140000000), img).build();
        let out = discover_pdata(&snap, Va(0x140000000)).expect("a PE32+ exception directory is readable");
        assert_eq!(out.iter().map(|f| f.va).collect::<Vec<_>>(), vec![Va(0x140001000), Va(0x140001020)]);
        assert_eq!(out[0].end, Some(Va(0x140001010)), "the table's extent is a fact, not a heuristic");
    }

    /// A record whose end does not follow its start describes no function.
    /// Reporting it puts a function at an address that holds none, which is a
    /// misparse presented as a finding.
    #[test]
    fn a_runtime_function_that_ends_before_it_begins_is_not_a_function() {
        let img = synthetic_pe(0x20b, Some((0x200, 36)), None, &[(0x1000, 0x1010, 0x3000), (0x2000, 0x1000, 0x3000), (0x1020, 0x1030, 0x3000)]);
        let snap = Snapshot::builder().region(Va(0x140000000), img).build();
        let out = discover_pdata(&snap, Va(0x140000000)).expect("readable");
        assert_eq!(out.iter().map(|f| f.va).collect::<Vec<_>>(), vec![Va(0x140001000), Va(0x140001020)]);
    }

    #[test]
    fn finds_prologues_in_a_code_blob() {
        let code = two_prologues();
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = DiscoverPass
            .run(&ctx, DiscoverInput { start: Va(0x1000), size: 64, limit: 100, offset: 0 })
            .unwrap();
        assert_eq!(art.count, 2);
        assert!(!art.truncated);
        assert_eq!(art.functions[0].va, Va(0x1000));
        assert_eq!(art.functions[0].name, "sub_1000");
        assert_eq!(art.functions[1].va, Va(0x1010));
    }

    /// The function that begins where the last one ended.
    ///
    /// A compiler lays functions out back to back with alignment filler
    /// between them, so the first real instruction after a declared extent is
    /// the next function. Measured against an independent function table on a
    /// real C++ DLL: 353 addresses this produces that the exception table does
    /// not already state, 343 of them function entries there and none interior
    /// to a known function.
    #[test]
    fn the_first_instruction_after_a_declared_end_is_the_next_function() {
        // 0x1000: mov rax,[rdi] ; ret     — declared, extent stated
        // 0x1004: twelve int3 of alignment filler
        // 0x1010: mov rax,[rdi+8] ; ret   — no prologue, no unwind record
        let mut code = vec![0x48, 0x8B, 0x07, 0xC3];
        code.resize(0x10, 0xCC);
        code.extend_from_slice(&[0x48, 0x8B, 0x47, 0x08, 0xC3]);
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let stated = [(Va(0x1000), Va(0x1004))];
        let ctx = Ctx::new(&snap, &arch).with_stated_functions(&stated);
        let art = DiscoverPass
            .run(&ctx, DiscoverInput { start: Va(0x1000), size: 0x15, limit: 100, offset: 0 })
            .unwrap();
        assert_eq!(art.functions.iter().map(|f| f.va).collect::<Vec<_>>(), vec![Va(0x1000), Va(0x1010)]);
    }

    /// A zero-filled code section holds no functions.
    ///
    /// The decoder turns `00 00` into `add byte ptr [rax], al` quite happily,
    /// so a gap of section fill read as code and a function was invented in it —
    /// caught by a synthetic image whose `.text` is all zeros, which is what
    /// the tail of a real section often is too.
    #[test]
    fn a_gap_of_zero_fill_holds_no_functions() {
        let mut code = vec![0x48, 0x8B, 0x07, 0xC3];
        code.resize(0x40, 0x00);
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let stated = [(Va(0x1000), Va(0x1004)), (Va(0x1030), Va(0x1034))];
        let ctx = Ctx::new(&snap, &arch).with_stated_functions(&stated);
        let art = DiscoverPass
            .run(&ctx, DiscoverInput { start: Va(0x1000), size: 0x40, limit: 100, offset: 0 })
            .unwrap();
        assert_eq!(
            art.functions.iter().map(|f| f.va).collect::<Vec<_>>(),
            vec![Va(0x1000), Va(0x1030)],
            "only the two the table declares"
        );
    }

    /// Filler all the way to the end of the range is not a function.
    #[test]
    fn a_gap_that_is_only_padding_produces_no_candidate() {
        let mut code = vec![0x48, 0x8B, 0x07, 0xC3];
        code.resize(0x20, 0xCC);
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let stated = [(Va(0x1000), Va(0x1004))];
        let ctx = Ctx::new(&snap, &arch).with_stated_functions(&stated);
        let art = DiscoverPass
            .run(&ctx, DiscoverInput { start: Va(0x1000), size: 0x20, limit: 100, offset: 0 })
            .unwrap();
        assert_eq!(art.functions.iter().map(|f| f.va).collect::<Vec<_>>(), vec![Va(0x1000)]);
    }

    /// The function a compiler gives no prologue and no unwind data.
    ///
    /// A small leaf helper sets up no frame and needs nothing unwound, so
    /// neither of the other two sources can see it; the only trace it leaves is
    /// the `call` that reaches it. Measured against an independent function
    /// table on a real C++ DLL, that trace was worth 47 functions the other two
    /// sources between them had missed, with nothing wrong added.
    #[test]
    fn a_function_with_no_prologue_is_still_found_by_the_call_that_reaches_it() {
        // 0x1000: push rbp ; mov rbp,rsp ; call 0x1020 ; ret
        // 0x1020: mov rax,[rdi] ; ret   — no prologue, nothing to unwind
        let mut code = vec![0x55, 0x48, 0x8B, 0xEC, 0xE8, 0x17, 0x00, 0x00, 0x00, 0xC3];
        code.resize(0x20, 0x90);
        code.extend_from_slice(&[0x48, 0x8B, 0x07, 0xC3]);
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = DiscoverPass
            .run(&ctx, DiscoverInput { start: Va(0x1000), size: 0x24, limit: 100, offset: 0 })
            .unwrap();
        assert_eq!(art.functions.iter().map(|f| f.va).collect::<Vec<_>>(), vec![Va(0x1000), Va(0x1020)]);
    }

    /// …but a declared extent still settles it. A `call` that lands inside a
    /// function a table already delimits is a second entry point into that
    /// function, not a second function.
    #[test]
    fn a_call_into_a_declared_function_does_not_split_it_in_two() {
        let mut code = vec![0x55, 0x48, 0x8B, 0xEC, 0xE8, 0x17, 0x00, 0x00, 0x00, 0xC3];
        code.resize(0x20, 0x90);
        code.extend_from_slice(&[0x48, 0x8B, 0x07, 0xC3]);
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let stated = [(Va(0x1000), Va(0x1024))];
        let ctx = Ctx::new(&snap, &arch).with_stated_functions(&stated);
        let art = DiscoverPass
            .run(&ctx, DiscoverInput { start: Va(0x1000), size: 0x24, limit: 100, offset: 0 })
            .unwrap();
        assert_eq!(art.functions.iter().map(|f| f.va).collect::<Vec<_>>(), vec![Va(0x1000)]);
    }

    #[test]
    fn an_unaligned_prologue_match_is_not_a_candidate() {
        // The same two prologues, the second moved off a 16-byte boundary. The
        // scan walks every byte offset, so a short pattern matches inside a
        // longer instruction as readily as at an entry; on one Qt build,
        // requiring alignment dropped 3 978 of 4 483 unconfirmed candidates
        // that an independent function table calls the middle of a function.
        let mut code = vec![0x55, 0x48, 0x8B, 0xEC];
        code.resize(0x18, 0x90);
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20, 0xC3]); // 0x1018 — unaligned
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = DiscoverPass
            .run(&ctx, DiscoverInput { start: Va(0x1000), size: 64, limit: 100, offset: 0 })
            .unwrap();
        assert_eq!(art.functions.iter().map(|f| f.va).collect::<Vec<_>>(), vec![Va(0x1000)]);
    }

    #[test]
    fn a_prologue_inside_a_declared_function_is_not_a_second_function() {
        // The canary store, the epilogue's stack adjustment, a byte pattern
        // that happens to fall inside a longer instruction — all of them match
        // a prologue mid-function. A declared extent settles them: 499 of the
        // 502 candidates left on a Qt build after the alignment rule were
        // inside a function `.eh_frame` already delimits.
        let mut code = vec![0x55, 0x48, 0x8B, 0xEC]; // 0x1000, a real entry
        code.resize(0x20, 0x90);
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // 0x1020, aligned but inside
        code.resize(0x40, 0x90);
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let stated = [(Va(0x1000), Va(0x1030))];
        let ctx = Ctx::new(&snap, &arch).with_stated_functions(&stated);
        let art = DiscoverPass
            .run(&ctx, DiscoverInput { start: Va(0x1000), size: 64, limit: 100, offset: 0 })
            .unwrap();
        assert_eq!(art.functions.iter().map(|f| f.va).collect::<Vec<_>>(), vec![Va(0x1000)]);

        // …and with nothing declared, the same match is still a candidate: the
        // rule only ever spends a fact it has.
        let ctx = Ctx::new(&snap, &arch);
        let art = DiscoverPass
            .run(&ctx, DiscoverInput { start: Va(0x1000), size: 64, limit: 100, offset: 0 })
            .unwrap();
        assert_eq!(art.functions.iter().map(|f| f.va).collect::<Vec<_>>(), vec![Va(0x1000), Va(0x1020)]);
    }

    #[test]
    fn an_entry_marker_survives_inside_a_declared_extent() {
        // Several entry points can share one unwind range — glibc's `tlsdesc`
        // helpers do, and `_dl_tlsdesc_undefweak` sits inside the FDE of the
        // one before it. `endbr64` is required by the architecture at any
        // indirectly-reachable entry, so it is evidence the weak patterns are
        // not, and it is trusted there.
        let mut code = vec![0xF3, 0x0F, 0x1E, 0xFA]; // 0x1000 endbr64
        code.resize(0x20, 0x90);
        code.extend_from_slice(&[0xF3, 0x0F, 0x1E, 0xFA]); // 0x1020 endbr64, inside
        code.resize(0x30, 0x90);
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // 0x1030 weak, inside
        code.resize(0x40, 0x90);
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let stated = [(Va(0x1000), Va(0x1040))];
        let ctx = Ctx::new(&snap, &arch).with_stated_functions(&stated);
        let art = DiscoverPass
            .run(&ctx, DiscoverInput { start: Va(0x1000), size: 64, limit: 100, offset: 0 })
            .unwrap();
        assert_eq!(
            art.functions.iter().map(|f| f.va).collect::<Vec<_>>(),
            vec![Va(0x1000), Va(0x1020)],
            "the marker is kept, the stack-adjust idiom is not",
        );
    }

    #[test]
    fn a_stated_start_is_a_fact_and_needs_no_prologue() {
        // What the image declares wins over what the scan can pattern-match:
        // an unaligned start with no recognised prologue is still a function
        // when `.eh_frame` or `.pdata` says so, and it arrives with its extent.
        let code = vec![0x90; 0x40];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let stated = [(Va(0x1023), Va(0x1030))];
        let ctx = Ctx::new(&snap, &arch).with_stated_functions(&stated);
        let art = DiscoverPass
            .run(&ctx, DiscoverInput { start: Va(0x1000), size: 64, limit: 100, offset: 0 })
            .unwrap();
        assert_eq!(art.functions.len(), 1);
        assert_eq!(art.functions[0].va, Va(0x1023));
        assert_eq!(art.functions[0].end, Some(Va(0x1030)), "a declared extent is carried through");
    }

    #[test]
    fn a_symbol_on_a_function_start_names_the_candidate() {
        use n0xis_contracts::{SymKind, Symbol};
        let snap = Snapshot::builder()
            .region(Va(0x1000), two_prologues())
            .symbol(Symbol { va: Va(0x1000), name: "PlayerHealth$$ApplyDamage".into(), kind: SymKind::Function, module: String::new() })
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch).with_symbols(&snap);
        let art = DiscoverPass.run(&ctx, DiscoverInput { start: Va(0x1000), size: 64, limit: 100, offset: 0 }).unwrap();
        assert!(art.functions[0].name.contains("PlayerHealth"), "a named function start must carry its name, got {}", art.functions[0].name);
        assert_eq!(art.functions[1].name, "sub_1010", "a function with no symbol keeps the address placeholder");
        // The *near-miss* half of the rule cannot be proved here: `Snapshot`
        // resolves symbols by exact address, so it can never return a covering
        // one. It is asserted where a span-attributing provider actually exists
        // — `phase12_il2cpp.rs`, against a real imported index.
    }

    /// The blob from the test above, three prologues instead of two, so a
    /// limit/offset pair has something to slice.
    fn three_prologue_ctx() -> Snapshot {
        let mut code = two_prologues();
        code.resize(0x20, 0x90);
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20, 0xC3]); // 0x1020
        Snapshot::builder().region(Va(0x1000), code).build()
    }

    #[test]
    fn limit_caps_the_result_and_says_so() {
        let snap = three_prologue_ctx();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = DiscoverPass
            .run(&ctx, DiscoverInput { start: Va(0x1000), size: 64, limit: 2, offset: 0 })
            .unwrap();
        assert_eq!(art.count, 2, "capped");
        assert!(art.truncated, "a capped scan must admit that more exist");
        assert_eq!(art.functions[0].va, Va(0x1000));
        assert_eq!(art.functions[1].va, Va(0x1010));
    }

    #[test]
    fn offset_pages_from_the_start_of_the_range() {
        let snap = three_prologue_ctx();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let page2 = DiscoverPass
            .run(&ctx, DiscoverInput { start: Va(0x1000), size: 64, limit: 2, offset: 2 })
            .unwrap();
        // Page 1 was [0x1000, 0x1010]; page 2 continues at the third match and
        // runs out of range rather than being cut off.
        assert_eq!(page2.count, 1);
        assert_eq!(page2.functions[0].va, Va(0x1020));
        assert!(!page2.truncated, "the range ended; nothing was withheld");
    }
}
