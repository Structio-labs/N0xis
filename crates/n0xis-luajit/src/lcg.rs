//! Linear-congruential RNG model + a seed brute-forcer.
//!
//! Some engines (Bitsquid/Stingray's `Math.next_random` among them) derive a
//! deterministic sequence from a small integer seed with a textbook LCG:
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
use n0xis_sources::MemorySource;
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

/// Scan `regions` for 4-byte-aligned words that, as an [`Lcg`] seed, generate
/// `target` (a sequence of `random(0, k-1)` draws, so every element must be
/// `< k`). Optionally require the seed itself to fall in `[seed_min, seed_max]`
/// (the game draws its seed from `math.random(1, 2^31-2)`, so a uint31 bound
/// cuts the coincidental-match rate hard). Returns every hit; a short `target`
/// yields many, a long one pins it down.
pub fn find_seeds(
    source: &dyn MemorySource,
    regions: &[(Va, usize)],
    lcg: &Lcg,
    k: u32,
    target: &[u32],
    seed_bounds: Option<(u32, u32)>,
) -> Vec<SeedHit> {
    let mut out = Vec::new();
    if target.is_empty() || k == 0 {
        return out;
    }
    for &(base, size) in regions {
        let Ok(bytes) = source.read(base, size) else { continue };
        let words = bytes.len() / 4;
        for w in 0..words {
            let seed = u32::from_le_bytes(bytes[w * 4..w * 4 + 4].try_into().unwrap());
            if let Some((lo, hi)) = seed_bounds
                && (seed < lo || seed > hi)
            {
                continue;
            }
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
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_sources::Snapshot;

    // Observed live in a Bitsquid/Stingray-engine game (Numerical Recipes).
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

        let hits = find_seeds(&snap, &[(base, 64)], &lcg, 4, &target, Some((1, 0x7FFF_FFFE)));
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
        let hits = find_seeds(&snap, &[(base, 16)], &lcg, 4, &target, Some((1, 0x7FFF_FFFE)));
        assert!(hits.iter().all(|h| h.seed != 0));
    }
}
