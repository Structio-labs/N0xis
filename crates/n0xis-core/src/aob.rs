// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! AOB (array-of-bytes) signature scanning with wildcards (ROADMAP Phase 4b)
//! — used for code-cave/anchor discovery and version-resilient hooking (an
//! AOB signature survives a patch/recompile that a raw address wouldn't).

use n0xis_contracts::Va;
use n0xis_sources::{RegionCoverage, Swept};
use serde::Serialize;

use crate::{Ctx, CoreError, Pass};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AobByte {
    Exact(u8),
    Wildcard,
}

/// Parse a wildcard byte pattern (`"48 8B ?? 68"`, `?` or `??` as a wildcard
/// token) into a byte-matchable pattern.
pub fn parse_aob(pattern: &str) -> Result<Vec<AobByte>, String> {
    pattern
        .split_whitespace()
        .map(|tok| match tok {
            "?" | "??" => Ok(AobByte::Wildcard),
            _ => u8::from_str_radix(tok, 16).map(AobByte::Exact).map_err(|_| format!("invalid AOB byte token: {tok:?}")),
        })
        .collect()
}

pub struct AobInput {
    pub start: Va,
    pub size: usize,
    pub pattern: Vec<AobByte>,
    /// Whether a match that starts in the window may end past it.
    pub past_end: PastEnd,
}

/// What a match that starts in a window and would end past it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PastEnd {
    /// Not a match: the window is the answer's subject, and nothing past it.
    Stop,
    /// A match, where the source holds bytes right after the window. What
    /// `find` over a whole image asks: the image's sections are its windows,
    /// and two that touch hold one run of bytes. Searched one at a time, the
    /// eight bytes over the seam between `.note.gnu.build-id` and `.interp`
    /// answered `count: 0` (audit 2026-11-06).
    ReadOn,
}

#[derive(Clone, Debug, Serialize)]
pub struct AobArtifact {
    pub matches: Vec<Va>,
    pub bytes_scanned: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AobScanPass;

impl Pass for AobScanPass {
    type In = AobInput;
    type Out = AobArtifact;

    fn name(&self) -> &'static str {
        "scan.aob"
    }

    fn run(&self, ctx: &Ctx, input: AobInput) -> Result<AobArtifact, CoreError> {
        let bytes = match input.past_end {
            PastEnd::Stop => ctx.source.read(input.start, input.size)?,
            PastEnd::ReadOn => {
                let reach = input.size.saturating_add(input.pattern.len().saturating_sub(1));
                n0xis_sources::read_across(ctx.source, input.start, reach)?
            }
        };
        let mut matches = Vec::new();
        matches_in(&bytes, input.start, &input.pattern, &mut matches);
        // A match past the end is the next window's; the bytes read on to are
        // not this window's bytes scanned.
        let end = input.start.0.saturating_add(input.size as u64);
        matches.retain(|m| m.0 < end);
        Ok(AobArtifact { matches, bytes_scanned: bytes.len().min(input.size) })
    }
}

/// Every place `pattern` matches in `bytes`, which were read at `start`.
fn matches_in(bytes: &[u8], start: Va, pattern: &[AobByte], matches: &mut Vec<Va>) {
    let plen = pattern.len();
    if plen == 0 || bytes.len() < plen {
        return;
    }
    for i in 0..=(bytes.len() - plen) {
        let hit = pattern.iter().enumerate().all(|(k, p)| match p {
            AobByte::Wildcard => true,
            AobByte::Exact(b) => bytes[i + k] == *b,
        });
        if hit {
            matches.push(start.offset(i as u64));
        }
    }
}

pub struct AobSweepInput {
    pub regions: Vec<(Va, usize)>,
    pub pattern: Vec<AobByte>,
}

/// The pattern over many regions, as `scan aob` asks on a live process. What
/// happens to a region that will not read is [`RegionCoverage`]'s rule: noted,
/// with what the read said, and the sweep goes on; a failure about no region
/// (the process exited, reading it is denied) is the sweep's error.
#[derive(Clone, Copy, Debug, Default)]
pub struct AobSweepPass;

impl Pass for AobSweepPass {
    type In = AobSweepInput;
    type Out = Swept<AobArtifact>;

    fn name(&self) -> &'static str {
        "scan.aob.sweep"
    }

    fn run(&self, ctx: &Ctx, input: AobSweepInput) -> Result<Swept<AobArtifact>, CoreError> {
        let mut read = RegionCoverage::default();
        let mut matches = Vec::new();
        let mut bytes_scanned = 0usize;
        for (start, bytes) in read.read_runs(ctx.source, &input.regions)? {
            bytes_scanned += bytes.len();
            matches_in(&bytes, start, &input.pattern, &mut matches);
        }
        Ok(Swept { answer: AobArtifact { matches, bytes_scanned }, read })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    #[test]
    fn parses_wildcards_and_hex_bytes() {
        let pattern = parse_aob("48 8B ?? 68").unwrap();
        assert_eq!(pattern, vec![AobByte::Exact(0x48), AobByte::Exact(0x8B), AobByte::Wildcard, AobByte::Exact(0x68)]);
    }

    #[test]
    fn rejects_a_malformed_token() {
        assert!(parse_aob("zz").is_err());
    }

    #[test]
    fn finds_two_matches_with_a_wildcard_byte() {
        let code = vec![0x48, 0x8B, 0x50, 0x68, 0x90, 0x48, 0x8B, 0x60, 0x68, 0xC3];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let pattern = parse_aob("48 8B ?? 68").unwrap();
        let art = AobScanPass.run(&ctx, AobInput { start: Va(0x1000), size: 10, pattern, past_end: PastEnd::Stop }).unwrap();
        assert_eq!(art.matches, vec![Va(0x1000), Va(0x1005)]);
    }

    /// Over two regions that touch, a match that starts in the first and ends
    /// in the second is the first's, with `ReadOn`; with `Stop` it is not
    /// there; and the second does not list it again.
    #[test]
    fn a_match_over_the_seam_of_two_windows_that_touch_is_the_first_ones() {
        let snap = Snapshot::builder().region(Va(0x1000), vec![0x90, 0x90, 0x48]).region(Va(0x1003), vec![0x8B, 0x90]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let pattern = parse_aob("48 8B").unwrap();
        let run = |start, size, past_end| AobScanPass.run(&ctx, AobInput { start: Va(start), size, pattern: pattern.clone(), past_end }).unwrap();
        let first = run(0x1000, 3, PastEnd::ReadOn);
        assert_eq!((first.matches.as_slice(), first.bytes_scanned), (&[Va(0x1002)][..], 3));
        assert!(run(0x1000, 3, PastEnd::Stop).matches.is_empty());
        assert!(run(0x1003, 2, PastEnd::ReadOn).matches.is_empty());
    }

    #[test]
    fn a_sweep_goes_on_past_a_region_with_no_mapping_and_says_so() {
        let snap = Snapshot::builder().region(Va(0x1000), vec![0x48, 0x8B]).region(Va(0x9000), vec![0x90, 0x48, 0x8B]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let pattern = parse_aob("48 8B").unwrap();
        let swept = AobSweepPass.run(&ctx, AobSweepInput { regions: vec![(Va(0x5000), 4), (Va(0x1000), 2), (Va(0x9000), 3)], pattern }).unwrap();
        assert_eq!(swept.answer.matches, vec![Va(0x1000), Va(0x9001)]);
        assert_eq!(swept.answer.bytes_scanned, 5);
        assert_eq!(swept.read.regions_scanned(), 2);
        assert_eq!(swept.read.not_read()[0].start, Va(0x5000));
    }
}
