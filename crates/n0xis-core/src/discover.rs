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

/// The discovery artifact (`n0xis.function.discover.v1`).
#[derive(Clone, Debug, Serialize)]
pub struct DiscoverArtifact {
    pub start: Va,
    pub scanned_bytes: usize,
    pub count: usize,
    pub functions: Vec<FunctionCandidate>,
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
        while i + max_pat <= bytes.len() && (unlimited || functions.len() < input.limit) {
            let window = &bytes[i..];
            if prologues.iter().any(|p| window.starts_with(p)) {
                let va = Va(input.start.0 + i as u64);
                functions.push(FunctionCandidate {
                    name: format!("sub_{:X}", va.0),
                    va,
                    end: None,
                });
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
            .run(&ctx, DiscoverInput { start: Va(0x1000), size: 64, limit: 100 })
            .unwrap();
        assert_eq!(art.count, 2);
        assert_eq!(art.functions[0].va, Va(0x1000));
        assert_eq!(art.functions[0].name, "sub_1000");
        assert_eq!(art.functions[1].va, Va(0x1008));
    }
}
