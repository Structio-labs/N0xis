// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Linear-congruential RNG model + a seed brute-forcer.
//!
//! Some engines (the Bitsquid-bundle engine family's `Math.next_random` among
//! them) derive a deterministic sequence from a small integer seed with a textbook LCG:
//! `s' = s*a + c (mod 2^32)`, then a normalized draw `u = s'/2^32` scaled into a
//! range. When such a sequence is *observed* (e.g. an on-screen combo) but the
//! seed lives at an unknown address, we can recover the seed by scanning memory:
//! every 4-byte-aligned word is a candidate seed, and the one whose generated
//! sequence matches the observation is (very likely) the real one — which
//! simultaneously locates the seed field and validates the model.
//!
//! The LCG constants are **parameters**, never baked in: different builds use
//! different `a`/`c`, so [`Lcg`] carries them and the CLI surfaces them as
//! flags (defaults documented at the call site, not hidden here).

use n0xis_contracts::Va;
use n0xis_sources::{MemorySource, RegionCoverage, SourceError, Swept};
use serde::Serialize;

/// A 32-bit linear-congruential generator with a normalized ranged draw.
#[derive(Debug, Clone, Copy)]
pub struct Lcg {
    /// Multiplier `a`.
    pub a: u32,
    /// Increment `c`.
    pub c: u32,
}

impl Lcg {
    /// Advance the state once: `s' = s*a + c (mod 2^32)`.
    #[inline]
    pub fn next(&self, s: u32) -> u32 {
        s.wrapping_mul(self.a).wrapping_add(self.c)
    }

    /// The sequence of `n` ranged draws `random(0, k-1) = floor((s'/2^32) * k)`
    /// starting from `seed` (each draw advances the state first, matching the
    /// observed `new_seed, value = next_random(seed)` order).
    pub fn range_seq(&self, seed: u32, k: u32, n: usize) -> Vec<u32> {
        let mut s = seed;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            s = self.next(s);
            let u = (s as f64) / 4_294_967_296.0; // /2^32 → [0,1)
            out.push((u * k as f64) as u32);
        }
        out
    }
}

/// One memory location whose 4-byte value, used as an LCG seed, reproduces the
/// target sequence.
#[derive(Debug, Clone, Serialize)]
pub struct SeedHit {
    pub addr: Va,
    pub seed: u32,
}

/// What a seed scan found, and how many words it tried: the number a count of
/// hits is out of.
#[derive(Debug, Clone, Serialize)]
pub struct SeedScan {
    pub hits: Vec<SeedHit>,
    /// Words taken as a seed: every aligned word read, less those outside the
    /// seed bounds.
    pub words_tried: u64,
}

/// Fewer matches than this expected by chance over the words tried, and a hit
/// stands out from chance. At or above it, the hits are what any memory of
/// that size gives, and say nothing of where the seed is.
pub const CHANCE_BOUND: f64 = 0.01;

/// How many of a scan's hits chance alone would give.
///
/// A sequence of `n` draws of `random(0, k-1)` from an LCG matches a word that
/// is not the seed about once in `k^n` (the draws are uniform over the state;
/// exactly so where `k` divides `2^32`). A process that uses no random number
/// at all gave 24 hits for a four-step sequence, stated as found seeds (audit
/// 2026-11-06): `4^4` is 256, and 24 is what 6 000 words give.
#[derive(Debug, Clone, Serialize)]
pub struct ChanceMatches {
    /// `k^-n`: the chance one word that is not the seed gives the sequence.
    pub per_word: f64,
    pub words_tried: u64,
    /// `words_tried * per_word`.
    pub expected_by_chance: f64,
    /// [`CHANCE_BOUND`].
    pub bound: f64,
    /// Whether `expected_by_chance` is below the bound: only then is a hit a
    /// finding rather than what chance gives.
    pub above_chance: bool,
    pub note: String,
}

impl SeedScan {
    /// The chance matches for a sequence of `n` draws in `0..k`.
    pub fn chance(&self, k: u32, n: usize) -> ChanceMatches {
        let per_word = f64::from(k.max(1)).powi(-(n.min(i32::MAX as usize) as i32));
        let expected_by_chance = self.words_tried as f64 * per_word;
        let above_chance = expected_by_chance < CHANCE_BOUND;
        let note = if above_chance {
            format!(
                "{expected_by_chance:.2e} matches expected by chance over {} words, below {CHANCE_BOUND}: a hit stands out from chance",
                self.words_tried
            )
        } else {
            format!(
                "{expected_by_chance:.1} matches expected by chance over {} words (one in {k}^{n}), not below {CHANCE_BOUND}: {} hit(s) are what \
                 chance gives, and do not locate a seed; observe a longer sequence or narrow the region",
                self.words_tried,
                self.hits.len()
            )
        };
        ChanceMatches { per_word, words_tried: self.words_tried, expected_by_chance, bound: CHANCE_BOUND, above_chance, note }
    }
}

/// Scan `regions` for 4-byte-aligned words that, as an [`Lcg`] seed, generate
/// `target` (a sequence of `random(0, k-1)` draws, so every element must be
/// `< k`). Optionally require the seed itself to fall in `[seed_min, seed_max]`
/// (the target draws its seed from `math.random(1, 2^31-2)`, so a uint31 bound
/// cuts the coincidental-match rate hard). Returns every hit; a short `target`
/// yields many, a long one pins it down.
pub fn find_seeds(
    source: &dyn MemorySource,
    regions: &[(Va, usize)],
    lcg: &Lcg,
    k: u32,
    target: &[u32],
    seed_bounds: Option<(u32, u32)>,
) -> Result<Swept<SeedScan>, SourceError> {
    let mut out = Vec::new();
    let mut tried = 0u64;
    let mut read = RegionCoverage::default();
    if target.is_empty() || k == 0 {
        return Ok(Swept { answer: SeedScan { hits: out, words_tried: tried }, read });
    }
    for &(base, size) in regions {
        let bytes = read.read_region(source, base, size)?;
        let words = bytes.len() / 4;
        for w in 0..words {
            let seed = u32::from_le_bytes(bytes[w * 4..w * 4 + 4].try_into().unwrap());
            if let Some((lo, hi)) = seed_bounds
                && (seed < lo || seed > hi)
            {
                continue;
            }
            tried += 1;
            // Cheap reject on the first draw before generating the whole seq.
            let first = {
                let s = lcg.next(seed);
                ((s as f64 / 4_294_967_296.0) * k as f64) as u32
            };
            if first != target[0] {
                continue;
            }
            if lcg.range_seq(seed, k, target.len()) == target {
                out.push(SeedHit { addr: base.offset(w as u64 * 4), seed });
            }
        }
    }
    Ok(Swept { answer: SeedScan { hits: out, words_tried: tried }, read })
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_sources::Snapshot;

    // Observed live in a Bitsquid-bundle application (Numerical Recipes).
    const A: u32 = 1664525;
    const C: u32 = 1013904223;

    #[test]
    fn lcg_sequence_is_deterministic_and_ranged() {
        let lcg = Lcg { a: A, c: C };
        let seq = lcg.range_seq(0xABCDEF, 4, 6);
        assert_eq!(seq.len(), 6);
        assert!(seq.iter().all(|&x| x < 4));
        // Deterministic: same seed → same sequence.
        assert_eq!(seq, lcg.range_seq(0xABCDEF, 4, 6));
    }

    #[test]
    fn finds_a_planted_seed_by_its_generated_sequence() {
        let lcg = Lcg { a: A, c: C };
        let seed: u32 = 0x1234_5678 & 0x7FFF_FFFF;
        let target = lcg.range_seq(seed, 4, 6); // a 6-long combo pins it down
        // Plant the seed word amid noise.
        let base = Va(0x8000);
        let mut buf = vec![0u8; 64];
        buf[24..28].copy_from_slice(&seed.to_le_bytes());
        let snap = Snapshot::builder().region(base, buf).build();

        let hits = find_seeds(&snap, &[(base, 64)], &lcg, 4, &target, Some((1, 0x7FFF_FFFE))).unwrap().answer.hits;
        assert!(hits.iter().any(|h| h.addr == base.offset(24) && h.seed == seed), "planted seed must be found");
    }

    #[test]
    fn respects_seed_bounds() {
        let lcg = Lcg { a: A, c: C };
        // seed 0 is outside a [1, N] bound and must be skipped even if its
        // sequence happened to match.
        let target = lcg.range_seq(0, 4, 3);
        let base = Va(0x9000);
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&0u32.to_le_bytes());
        let snap = Snapshot::builder().region(base, buf).build();
        let hits = find_seeds(&snap, &[(base, 16)], &lcg, 4, &target, Some((1, 0x7FFF_FFFE))).unwrap().answer.hits;
        assert!(hits.iter().all(|h| h.seed != 0));
    }

    /// Over memory with no seed in it, a short sequence matches as often as
    /// `k^-n` says, and the answer says the hits are what chance gives; a long
    /// one over the same memory stands out. The memory is a counter's words,
    /// none of them a seed planted for the sequence.
    #[test]
    fn hits_are_weighed_against_what_chance_gives() {
        let lcg = Lcg { a: A, c: C };
        let words: Vec<u8> = (1u32..=40_000).flat_map(|w| w.wrapping_mul(2_654_435_761).to_le_bytes()).collect();
        let base = Va(0x10_0000);
        let snap = Snapshot::builder().region(base, words.clone()).build();
        let short = [1, 3, 3, 1];
        let scan = find_seeds(&snap, &[(base, words.len())], &lcg, 4, &short, None).unwrap().answer;
        assert_eq!(scan.words_tried, 40_000);
        let chance = scan.chance(4, short.len());
        assert!((chance.expected_by_chance - 40_000.0 / 256.0).abs() < 1e-9);
        // The count is what chance gives, give or take: 156 expected.
        assert!(scan.hits.len() > 100 && scan.hits.len() < 220, "{} hits", scan.hits.len());
        assert!(!chance.above_chance && chance.note.contains("what chance gives"), "{}", chance.note);
        // Twenty draws: 4^-20 a word, so a hit would stand out.
        let long = lcg.range_seq(0x1234_5678, 4, 20);
        let scan = find_seeds(&snap, &[(base, words.len())], &lcg, 4, &long, None).unwrap().answer;
        assert!(scan.chance(4, long.len()).above_chance);
    }
}
