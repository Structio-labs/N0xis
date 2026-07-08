//! [`DiscoverPass`] — heuristic function discovery by prologue scanning.
//!
//! Scans a code range for the ISA's function-entry byte patterns (supplied by
//! [`Arch::prologues`](n0xis_arch::Arch::prologues), never hardcoded here) and
//! emits `sub_<addr>` candidates. Ported from v0's `.text` prolog scan, refit
//! to read through the [`MemorySource`](n0xis_sources::MemorySource) seam so it
//! works the same on a live module and a static image.

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
    /// Cap on the number of candidates.
    pub limit: usize,
}

/// A discovered function candidate.
#[derive(Clone, Debug, Serialize)]
pub struct FunctionCandidate {
    pub name: String,
    pub va: Va,
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
        while i + max_pat <= bytes.len() && functions.len() < input.limit {
            let window = &bytes[i..];
            if prologues.iter().any(|p| window.starts_with(p)) {
                let va = Va(input.start.0 + i as u64);
                functions.push(FunctionCandidate {
                    name: format!("sub_{:X}", va.0),
                    va,
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
