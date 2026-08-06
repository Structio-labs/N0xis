//! `const identify` — recognize canonical magic constants (ROADMAP Phase 8,
//! automates RE_METHOD W3).
//!
//! A single flat fingerprint table maps a well-known numeric constant to the
//! algorithm it identifies, the role it plays, and (where it exists) the
//! closed-form the algorithm computes. Recognizing one constant identifies a
//! whole algorithm *instantly, with zero reversing* — the campaign's
//! `0x5bd1e995 → MurmurHash2` and `1664525 → Numerical-Recipes LCG` moments,
//! turned from a memory-of-a-table into a lookup.
//!
//! Purely a table + two match functions ([`identify_u64`] / [`identify_f64`]) —
//! no `Ctx`, no memory source. The CLI feeds it constants it scraped from
//! decompiled output, a Lua chunk's number pool, or a bare `--value`; this
//! module only answers "what is this number". These constants are genuinely
//! immutable (the one hardcode the project's anti-hardcode rule explicitly
//! exempts): they are the fingerprints, not tunable values.

use serde::Serialize;

/// One recognized constant, ready to serialize into `n0xis.const.identify.v1`.
#[derive(Clone, Debug, Serialize)]
pub struct ConstMatch {
    /// The queried value, in the width the fingerprint matched at (`0x5bd1e995`,
    /// `1664525`).
    pub value: String,
    /// Decimal form, for the many constants humans recognize decimal-first
    /// (LCG multipliers) rather than hex-first (hash seeds).
    pub decimal: String,
    /// Family this fingerprint belongs to (`MurmurHash2`, `LCG`, `FNV`, `CRC-32`,
    /// `xxHash`, `float-normalizer`).
    pub algorithm: String,
    /// What this specific number *is* within the algorithm (`mixing constant m`,
    /// `multiplier a`, `increment c`, `reversed polynomial`).
    pub role: String,
    /// The formula the algorithm computes, when short enough to be useful inline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formula: Option<String>,
    /// Any extra disambiguation (which library/reference uses it, common
    /// look-alikes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Bit width the constant is canonically defined at (`32`/`64`). A `32`-bit
    /// fingerprint is matched against the query's low 32 bits too, since
    /// immediates get sign/zero-extended in a 64-bit decompilation.
    pub width: u8,
}

struct Fingerprint {
    value: u64,
    width: u8,
    algorithm: &'static str,
    role: &'static str,
    formula: Option<&'static str>,
    note: Option<&'static str>,
}

/// The canonical-constant table. Every entry is a fingerprint recognized in the
/// wild across common PRNGs, non-cryptographic hashes, and CRCs. Collisions are
/// fine (the golden-ratio family shares a 32-bit prefix): [`identify_u64`]
/// returns *every* match, and the caller sees all plausible readings.
static FINGERPRINTS: &[Fingerprint] = &[
    // ---- Linear congruential generators (multiplier a, increment c) ----
    Fingerprint { value: 1664525, width: 32, algorithm: "LCG", role: "multiplier a", formula: Some("s' = s*1664525 + 1013904223 (mod 2^32)"), note: Some("Numerical Recipes — observed live in a Bitsquid/Stingray-engine game's combo RNG — pairs with c=1013904223") },
    Fingerprint { value: 1013904223, width: 32, algorithm: "LCG", role: "increment c", formula: Some("s' = s*1664525 + 1013904223 (mod 2^32)"), note: Some("Numerical Recipes — pairs with a=1664525") },
    Fingerprint { value: 214013, width: 32, algorithm: "LCG", role: "multiplier a", formula: Some("s' = s*214013 + 2531011 (mod 2^31)"), note: Some("MSVC rand() — pairs with c=2531011") },
    Fingerprint { value: 2531011, width: 32, algorithm: "LCG", role: "increment c", formula: Some("s' = s*214013 + 2531011"), note: Some("MSVC rand()") },
    Fingerprint { value: 1103515245, width: 32, algorithm: "LCG", role: "multiplier a", formula: Some("s' = s*1103515245 + 12345"), note: Some("glibc / ANSI C rand() — pairs with c=12345") },
    Fingerprint { value: 12345, width: 32, algorithm: "LCG", role: "increment c", formula: Some("s' = s*1103515245 + 12345"), note: Some("glibc / ANSI C rand()") },
    Fingerprint { value: 22695477, width: 32, algorithm: "LCG", role: "multiplier a", formula: Some("s' = s*22695477 + 1"), note: Some("Borland C/C++ rand()") },
    Fingerprint { value: 69069, width: 32, algorithm: "LCG", role: "multiplier a", formula: Some("s' = s*69069 + c"), note: Some("Marsaglia 'super-duper' / VAX MTH$RANDOM") },
    Fingerprint { value: 6364136223846793005, width: 64, algorithm: "LCG", role: "multiplier a", formula: Some("s' = s*6364136223846793005 + inc"), note: Some("PCG / Knuth MMIX 64-bit LCG multiplier") },
    Fingerprint { value: 1442695040888963407, width: 64, algorithm: "LCG", role: "increment c", formula: Some("s' = s*a + 1442695040888963407"), note: Some("PCG default stream / Knuth MMIX increment") },
    Fingerprint { value: 2862933555777941757, width: 64, algorithm: "LCG", role: "multiplier a", formula: Some("s' = s*2862933555777941757 + c"), note: Some("Knuth/Lavaux–Janssens 64-bit LCG") },
    Fingerprint { value: 0x2545F4914F6CDD1D, width: 64, algorithm: "xorshift*", role: "multiplier", formula: Some("x ^= x>>12; x ^= x<<25; x ^= x>>27; return x*0x2545F4914F6CDD1D"), note: Some("Marsaglia xorshift64*") },
    Fingerprint { value: 0x9E3779B97F4A7C15, width: 64, algorithm: "SplitMix64", role: "golden-ratio increment", formula: Some("z = (s += 0x9E3779B97F4A7C15); mix..."), note: Some("SplitMix64 / fibonacci-hash 64-bit golden ratio (2^64/φ)") },

    // ---- MurmurHash family ----
    Fingerprint { value: 0x5bd1e995, width: 32, algorithm: "MurmurHash2", role: "mixing constant m", formula: Some("h ^= h>>r; h *= 0x5bd1e995 (r=24)"), note: Some("MurmurHash2 32-bit — the classic 'this is a hashmap lookup' tell") },
    Fingerprint { value: 0xcc9e2d51, width: 32, algorithm: "MurmurHash3", role: "constant c1", formula: Some("k *= c1; k = rotl(k,15); k *= c2"), note: Some("MurmurHash3 x86_32 c1") },
    Fingerprint { value: 0x1b873593, width: 32, algorithm: "MurmurHash3", role: "constant c2", formula: Some("k *= c1; k = rotl(k,15); k *= c2"), note: Some("MurmurHash3 x86_32 c2") },
    Fingerprint { value: 0xe6546b64, width: 32, algorithm: "MurmurHash3", role: "round add constant", formula: Some("h = rotl(h,13); h = h*5 + 0xe6546b64"), note: Some("MurmurHash3 round mix") },
    Fingerprint { value: 0x85ebca6b, width: 32, algorithm: "MurmurHash3", role: "fmix constant", formula: Some("h ^= h>>16; h *= 0x85ebca6b; ..."), note: Some("MurmurHash3 x86_32 finalizer") },
    Fingerprint { value: 0xc2b2ae35, width: 32, algorithm: "MurmurHash3", role: "fmix constant", formula: Some("...; h *= 0xc2b2ae35; h ^= h>>16"), note: Some("MurmurHash3 x86_32 finalizer") },
    Fingerprint { value: 0xff51afd7ed558ccd, width: 64, algorithm: "MurmurHash3", role: "fmix64 constant", formula: Some("k ^= k>>33; k *= 0xff51afd7ed558ccd; ..."), note: Some("MurmurHash3 x64_128 finalizer") },
    Fingerprint { value: 0xc4ceb9fe1a85ec53, width: 64, algorithm: "MurmurHash3", role: "fmix64 constant", formula: Some("...; k *= 0xc4ceb9fe1a85ec53; k ^= k>>33"), note: Some("MurmurHash3 x64_128 finalizer") },

    // ---- FNV ----
    Fingerprint { value: 2166136261, width: 32, algorithm: "FNV", role: "offset basis (32-bit)", formula: Some("h = 2166136261; for b: h ^= b; h *= 16777619 (FNV-1a)"), note: Some("FNV-1/1a 32-bit offset basis = 0x811c9dc5") },
    Fingerprint { value: 16777619, width: 32, algorithm: "FNV", role: "prime (32-bit)", formula: Some("h *= 16777619"), note: Some("FNV 32-bit prime = 0x01000193") },
    Fingerprint { value: 0xcbf29ce484222325, width: 64, algorithm: "FNV", role: "offset basis (64-bit)", formula: Some("h = 0xcbf29ce484222325; ... h *= 0x100000001b3"), note: Some("FNV-1/1a 64-bit offset basis") },
    Fingerprint { value: 1099511628211, width: 64, algorithm: "FNV", role: "prime (64-bit)", formula: Some("h *= 1099511628211"), note: Some("FNV 64-bit prime = 0x100000001b3") },

    // ---- CRC-32 polynomials ----
    Fingerprint { value: 0xEDB88320, width: 32, algorithm: "CRC-32", role: "reversed polynomial", formula: Some("crc = (crc>>1) ^ (0xEDB88320 & -(crc&1))"), note: Some("zlib/PNG/Ethernet CRC-32, reflected form") },
    Fingerprint { value: 0x04C11DB7, width: 32, algorithm: "CRC-32", role: "normal polynomial", formula: Some("crc = (crc<<1) ^ (0x04C11DB7 & ...)"), note: Some("IEEE 802.3 CRC-32, MSB-first form") },
    Fingerprint { value: 0x82F63B78, width: 32, algorithm: "CRC-32C", role: "reversed polynomial", formula: Some("Castagnoli CRC-32C, reflected"), note: Some("SSE4.2 crc32 instruction / iSCSI / ext4") },
    Fingerprint { value: 0x1EDC6F41, width: 32, algorithm: "CRC-32C", role: "normal polynomial", formula: Some("Castagnoli CRC-32C, MSB-first"), note: None },

    // ---- xxHash primes ----
    Fingerprint { value: 0x9E3779B1, width: 32, algorithm: "xxHash", role: "PRIME32_1", formula: Some("acc = rotl(acc + lane*PRIME32_2, 13) * PRIME32_1"), note: Some("xxHash32 — near golden ratio 0x9E3779B9") },
    Fingerprint { value: 0x85EBCA77, width: 32, algorithm: "xxHash", role: "PRIME32_2", formula: None, note: None },
    Fingerprint { value: 0xC2B2AE3D, width: 32, algorithm: "xxHash", role: "PRIME32_3", formula: None, note: None },
    Fingerprint { value: 0x27D4EB2F, width: 32, algorithm: "xxHash", role: "PRIME32_4", formula: None, note: None },
    Fingerprint { value: 0x165667B1, width: 32, algorithm: "xxHash", role: "PRIME32_5", formula: None, note: None },
    Fingerprint { value: 0x9E3779B185EBCA87, width: 64, algorithm: "xxHash", role: "PRIME64_1", formula: None, note: Some("xxHash64") },
    Fingerprint { value: 0xC2B2AE3D27D4EB4F, width: 64, algorithm: "xxHash", role: "PRIME64_2", formula: None, note: Some("xxHash64") },
    Fingerprint { value: 0x165667B19E3779F9, width: 64, algorithm: "xxHash", role: "PRIME64_3", formula: None, note: Some("xxHash64") },
    Fingerprint { value: 0x27D4EB2F165667C5, width: 64, algorithm: "xxHash", role: "PRIME64_4", formula: None, note: Some("xxHash64") },
    Fingerprint { value: 0x60EA27EEADC0B5D6, width: 64, algorithm: "xxHash", role: "PRIME64_5", formula: None, note: Some("xxHash64") },

    // ---- golden-ratio / fibonacci-hashing / TEA ----
    Fingerprint { value: 0x9E3779B9, width: 32, algorithm: "golden-ratio", role: "2^32 / φ", formula: Some("hash = (key * 0x9E3779B9) >> (32 - bits)"), note: Some("Fibonacci hashing / TEA 'delta' / Boost hash_combine 32-bit") },
];

/// Every fingerprint the value matches. A 32-bit fingerprint is compared both
/// against the whole value and against the value's low 32 bits (immediates in a
/// 64-bit decompilation arrive sign- or zero-extended), so `0xffffffff85ebca6b`
/// still identifies the MurmurHash3 finalizer.
pub fn identify_u64(value: u64) -> Vec<ConstMatch> {
    let low32 = value & 0xFFFF_FFFF;
    FINGERPRINTS
        .iter()
        .filter(|fp| value == fp.value || (fp.width == 32 && low32 == fp.value))
        .map(|fp| {
            let matched = if value == fp.value { value } else { fp.value };
            ConstMatch {
                value: if fp.width == 32 { format!("0x{matched:08x}") } else { format!("0x{matched:016x}") },
                decimal: matched.to_string(),
                algorithm: fp.algorithm.to_string(),
                role: fp.role.to_string(),
                formula: fp.formula.map(str::to_string),
                note: fp.note.map(str::to_string),
                width: fp.width,
            }
        })
        .collect()
}

/// Recognize float normalizers of the form `1 / 2^n` — the `* (1.0/2^32)` step
/// that turns an LCG's raw `u32` state into a `[0,1)` float (RE_METHOD W3's
/// `1/2^32`). Matched with a relative tolerance so a single-precision-rounded
/// literal still hits.
pub fn identify_f64(value: f64) -> Vec<ConstMatch> {
    let mut out = Vec::new();
    if value <= 0.0 || !value.is_finite() {
        return out;
    }
    for n in 1u32..=64 {
        let expect = 2.0f64.powi(-(n as i32));
        // Relative tolerance: a value stored as f32 then widened differs from
        // the exact f64 by ~2^-24; 1e-6 relative comfortably covers that.
        if (value - expect).abs() <= expect * 1e-6 {
            out.push(ConstMatch {
                value: format!("{value:e}"),
                decimal: format!("1/2^{n}"),
                algorithm: "float-normalizer".to_string(),
                role: format!("1 / 2^{n}"),
                formula: Some(format!("x_float = x_int * (1.0 / 2^{n})")),
                note: Some(match n {
                    32 => "canonical u32 → [0,1) normalization (RE_METHOD W3)",
                    31 => "i32 → [0,1) normalization",
                    24 => "f32 mantissa-width normalization",
                    23 => "f32 mantissa normalization",
                    _ => "power-of-two reciprocal",
                }.to_string()),
                width: 64,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn murmur2_seed_is_recognized() {
        let m = identify_u64(0x5bd1e995);
        assert!(m.iter().any(|c| c.algorithm == "MurmurHash2" && c.role.contains('m')));
    }

    #[test]
    fn nr_lcg_pair_is_recognized_by_decimal() {
        assert!(identify_u64(1664525).iter().any(|c| c.algorithm == "LCG" && c.role.contains('a')));
        assert!(identify_u64(1013904223).iter().any(|c| c.algorithm == "LCG" && c.role.contains('c')));
    }

    #[test]
    fn sign_extended_32bit_constant_still_matches() {
        // A 32-bit fingerprint arriving zero/sign-extended in a 64-bit value.
        let m = identify_u64(0xffff_ffff_5bd1_e995);
        assert!(m.iter().any(|c| c.algorithm == "MurmurHash2"), "low-32 match must fire: {m:?}");
    }

    #[test]
    fn crc32_and_fnv_prime_are_distinct_families() {
        assert!(identify_u64(0xEDB88320).iter().all(|c| c.algorithm == "CRC-32"));
        assert!(identify_u64(16777619).iter().any(|c| c.algorithm == "FNV"));
    }

    #[test]
    fn one_over_2_pow_32_is_a_float_normalizer() {
        let m = identify_f64(1.0 / 4294967296.0);
        assert!(m.iter().any(|c| c.decimal == "1/2^32"), "got {m:?}");
    }

    // `3.14` is deliberately a *rough* approximation of PI: the point of the
    // assertion is that a sloppy literal must NOT be identified as the real
    // constant, so clippy's "use std::f64::consts::PI instead" is exactly
    // backwards here.
    #[allow(clippy::approx_constant)]
    #[test]
    fn an_ordinary_number_matches_nothing() {
        assert!(identify_u64(42).is_empty());
        assert!(identify_u64(0xdead_beef).is_empty());
        assert!(identify_f64(3.14).is_empty());
    }
}
