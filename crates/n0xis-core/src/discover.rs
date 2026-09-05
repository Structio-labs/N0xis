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
use n0xis_contracts::Va;
use serde::Serialize;

use crate::{Ctx, CoreError, Pass};

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
pub fn discover_pdata(source: &dyn MemorySource, module_base: Va) -> Result<Vec<FunctionCandidate>, CoreError> {
    let hdr = source.read(module_base, 0x400)?;
    let rd_u32 = |off: usize| -> Option<u32> { hdr.get(off..off + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())) };
    let e_lfanew = rd_u32(0x3c).ok_or_else(|| CoreError::Other("truncated PE header at module base".into()))? as usize;
    if hdr.get(e_lfanew..e_lfanew + 4) != Some(&b"PE\0\0"[..]) {
        return Err(CoreError::Other("no PE signature at module base (not a mapped PE image?)".into()));
    }
    // IMAGE_NT_HEADERS64: sig(4) + IMAGE_FILE_HEADER(20) → optional header at
    // e_lfanew+24; PE32+ DataDirectory array is at optional-header offset 112;
    // entry [3] is IMAGE_DIRECTORY_ENTRY_EXCEPTION.
    let exc_off = e_lfanew + 24 + 112 + 3 * 8;
    let exc_rva = rd_u32(exc_off).ok_or_else(|| CoreError::Other("PE optional header too short for the exception directory".into()))?;
    let exc_size = rd_u32(exc_off + 4).unwrap_or(0);
    if exc_rva == 0 || exc_size == 0 {
        return Ok(Vec::new()); // no .pdata — non-x64 or stripped of unwind info
    }
    let table = source.read(module_base.offset(exc_rva as u64), exc_size as usize)?;
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
fn name_at(ctx: &Ctx, va: Va) -> String {
    ctx.symbols
        .and_then(|s| s.symbol_at(va))
        .filter(|sym| sym.va == va)
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
        let prologues = ctx.arch.prologues();
        let mut functions = Vec::new();

        let mut i = 0usize;
        // Need room to match the longest pattern.
        let max_pat = prologues.iter().map(|p| p.len()).max().unwrap_or(0);
        // `limit == 0` means unlimited — the range itself bounds the scan.
        let unlimited = input.limit == 0;
        // Matches seen so far, including the ones `offset` skips: pagination
        // counts from the start of the range, so page N is the same set of
        // addresses no matter how it was reached.
        let mut seen = 0usize;
        let mut hit_limit = false;
        while i + max_pat <= bytes.len() {
            let window = &bytes[i..];
            if prologues.iter().any(|p| window.starts_with(p)) {
                if seen >= input.offset {
                    if !unlimited && functions.len() >= input.limit {
                        // One match past the cap — enough to know more exist
                        // without scanning the rest.
                        hit_limit = true;
                        break;
                    }
                    let va = Va(input.start.0 + i as u64);
                    // A stated size (ELF `st_size`) makes `end` a fact here, the
                    // way `.pdata` does on PE — so a prologue-scanned ELF gets
                    // exact extents instead of leaving every consumer to infer
                    // one. `None` everywhere else, exactly as before.
                    let end = ctx
                        .symbols
                        .and_then(|s| s.symbol_size(va))
                        .and_then(|n| va.0.checked_add(n))
                        .map(Va);
                    functions.push(FunctionCandidate { name: name_at(ctx, va), va, end });
                }
                seen += 1;
                // Skip ahead so overlapping patterns in one prologue count once.
                i += 8;
                continue;
            }
            i += 1;
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

    #[test]
    fn finds_prologues_in_a_code_blob() {
        // push rbp; mov rbp,rsp (0x1000) … filler … sub rsp,0x20 (0x1008)
        let code = vec![
            0x55, 0x48, 0x8B, 0xEC, // 0x1000 push rbp; mov rbp,rsp
            0x90, 0x90, 0x90, 0x90, // filler
            0x48, 0x83, 0xEC, 0x20, // 0x1008 sub rsp, 0x20
            0xC3,
        ];
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
        assert_eq!(art.functions[1].va, Va(0x1008));
    }

    #[test]
    fn a_symbol_on_a_function_start_names_the_candidate() {
        use n0xis_contracts::{SymKind, Symbol};
        let code = vec![0x55, 0x48, 0x8B, 0xEC, 0x90, 0x90, 0x90, 0x90, 0x48, 0x83, 0xEC, 0x20, 0xC3];
        let snap = Snapshot::builder()
            .region(Va(0x1000), code)
            .symbol(Symbol { va: Va(0x1000), name: "PlayerHealth$$ApplyDamage".into(), kind: SymKind::Function, module: String::new() })
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch).with_symbols(&snap);
        let art = DiscoverPass.run(&ctx, DiscoverInput { start: Va(0x1000), size: 64, limit: 100, offset: 0 }).unwrap();
        assert!(art.functions[0].name.contains("PlayerHealth"), "a named function start must carry its name, got {}", art.functions[0].name);
        assert_eq!(art.functions[1].name, "sub_1008", "a function with no symbol keeps the address placeholder");
        // The *near-miss* half of the rule cannot be proved here: `Snapshot`
        // resolves symbols by exact address, so it can never return a covering
        // one. It is asserted where a span-attributing provider actually exists
        // — `phase12_il2cpp.rs`, against a real imported index.
    }

    /// The blob from the test above, three prologues instead of two, so a
    /// limit/offset pair has something to slice.
    fn three_prologue_ctx() -> Snapshot {
        let code = vec![
            0x55, 0x48, 0x8B, 0xEC, // 0x1000 push rbp; mov rbp,rsp
            0x90, 0x90, 0x90, 0x90, //
            0x48, 0x83, 0xEC, 0x20, // 0x1008 sub rsp, 0x20
            0x90, 0x90, 0x90, 0x90, //
            0x48, 0x83, 0xEC, 0x20, // 0x1010 sub rsp, 0x20
            0xC3,
        ];
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
        assert_eq!(art.functions[1].va, Va(0x1008));
    }

    #[test]
    fn offset_pages_from_the_start_of_the_range() {
        let snap = three_prologue_ctx();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let page2 = DiscoverPass
            .run(&ctx, DiscoverInput { start: Va(0x1000), size: 64, limit: 2, offset: 2 })
            .unwrap();
        // Page 1 was [0x1000, 0x1008]; page 2 continues at the third match and
        // runs out of range rather than being cut off.
        assert_eq!(page2.count, 1);
        assert_eq!(page2.functions[0].va, Va(0x1010));
        assert!(!page2.truncated, "the range ended; nothing was withheld");
    }
}
