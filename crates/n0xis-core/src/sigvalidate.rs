// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `sig validate` — refuse to bless a signature from fewer than 3 independent
//! samples (ROADMAP Phase 8, fixes RE_METHOD F3).
//!
//! The campaign shipped a broken marker (`0xCF` at `+0x18`) that "matched two
//! instances" — two repeated test missions sharing a generated-level seed, i.e.
//! a coincidence promoted to an invariant. A third instance on a new map broke
//! it. This pass is the guardrail: given ≥2 concrete byte samples of the same
//! structure, it reports **which bytes are actually invariant** across all of
//! them, derives the honest signature (invariant bytes fixed, everything else
//! wildcarded), and **refuses to bless** a signature unless there are ≥3 samples
//! *and* the operator has named which axis was deliberately varied.
//!
//! Pure byte analysis — no `Ctx`. The CLI supplies the samples (from repeated
//! `--sample` hex, files, or reads at several live addresses) and the varied
//! axis; this module has no opinion on where the bytes came from, only on
//! whether the evidence is strong enough to trust.

use serde::Serialize;

/// The minimum number of independent, deliberately-varied samples before a
/// signature may be blessed. Three is the smallest count that can distinguish a
/// real invariant from an N=2 coincidence (RE_METHOD F3's lesson, stated as a
/// number).
pub const MIN_INDEPENDENT_SAMPLES: usize = 3;

/// A proposed signature byte: a fixed value, or a wildcard (`??`).
pub type MaskByte = Option<u8>;

#[derive(Clone, Debug)]
pub struct SigValidateInput {
    /// The concrete samples, most naturally the same length. Shorter samples
    /// are analyzed up to the shortest length and a warning is raised.
    pub samples: Vec<Vec<u8>>,
    /// An optional proposed signature to audit (fixed bytes + `??` wildcards).
    pub proposed: Option<Vec<MaskByte>>,
    /// Which axes the operator says they deliberately varied across the samples
    /// (`["map","mission","seed"]`). Blessing requires at least one — an
    /// invariant is only meaningful *relative to what changed*.
    pub varied_axes: Vec<String>,
    /// Override the default independence bar (kept configurable, but defaults to
    /// [`MIN_INDEPENDENT_SAMPLES`]).
    pub min_independent: usize,
}

/// Per-offset verdict across the samples.
#[derive(Clone, Debug, Serialize)]
pub struct BytePosition {
    pub offset: usize,
    /// `true` when every sample agrees on this byte.
    pub invariant: bool,
    /// The agreed byte, hex, when invariant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Distinct observed values (hex), when it varies.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub observed: Vec<String>,
}

/// One problem found while auditing a proposed signature against the samples.
#[derive(Clone, Debug, Serialize)]
pub struct MaskFinding {
    pub offset: usize,
    /// `false-invariant` (mask fixes a byte the samples show varying — the F3
    /// bug), `contradiction` (mask's fixed byte disagrees with the samples'
    /// agreed byte), or `loose` (mask wildcards a byte that is actually
    /// invariant — a correct-but-weaker signature).
    pub kind: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SigValidateArtifact {
    pub sample_count: usize,
    /// Length actually analyzed (the shortest sample).
    pub analyzed_len: usize,
    pub invariant_bytes: usize,
    pub varying_bytes: usize,
    /// The honest signature derived purely from the samples: agreed bytes fixed,
    /// everything else `??`. This is the *useful* output — a broken signature
    /// turned into a corrected one (RE_METHOD F3 scope note).
    pub derived_signature: String,
    /// `true` only when there are ≥ `min_independent` samples **and** a varied
    /// axis was named. This is the refusal the pass exists to make.
    pub blessed: bool,
    /// Why `blessed` is false (empty when blessed).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub refusals: Vec<String>,
    /// Non-fatal advisories (length mismatch, single distinct sample, …).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Problems auditing the proposed signature (empty when none was given or
    /// none were found).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mask_findings: Vec<MaskFinding>,
    pub positions: Vec<BytePosition>,
}

fn hex_byte(b: u8) -> String {
    format!("{b:02x}")
}

/// Analyze the samples and (optionally) audit a proposed signature. Never
/// errors: too-few-samples and length mismatches are *reported* (as refusals /
/// warnings), because the point of this pass is to make weak evidence visible,
/// not to reject the call.
pub fn validate(input: &SigValidateInput) -> SigValidateArtifact {
    let min_independent = if input.min_independent == 0 { MIN_INDEPENDENT_SAMPLES } else { input.min_independent };
    let sample_count = input.samples.len();
    let analyzed_len = input.samples.iter().map(|s| s.len()).min().unwrap_or(0);

    let mut warnings = Vec::new();
    let lengths: Vec<usize> = input.samples.iter().map(|s| s.len()).collect();
    if lengths.iter().collect::<std::collections::BTreeSet<_>>().len() > 1 {
        warnings.push(format!(
            "samples differ in length ({lengths:?}); only the first {analyzed_len} bytes were compared"
        ));
    }

    let mut positions = Vec::with_capacity(analyzed_len);
    let mut derived = String::new();
    let mut invariant_bytes = 0usize;
    for off in 0..analyzed_len {
        let first = input.samples[0][off];
        let mut distinct: std::collections::BTreeSet<u8> = std::collections::BTreeSet::new();
        for s in &input.samples {
            distinct.insert(s[off]);
        }
        let invariant = distinct.len() == 1;
        if off > 0 {
            derived.push(' ');
        }
        if invariant {
            invariant_bytes += 1;
            derived.push_str(&hex_byte(first).to_uppercase());
            positions.push(BytePosition { offset: off, invariant: true, value: Some(hex_byte(first)), observed: Vec::new() });
        } else {
            derived.push_str("??");
            positions.push(BytePosition {
                offset: off,
                invariant: false,
                value: None,
                observed: distinct.iter().map(|&b| hex_byte(b)).collect(),
            });
        }
    }
    let varying_bytes = analyzed_len - invariant_bytes;

    // Audit a proposed signature, if one was given.
    let mut mask_findings = Vec::new();
    if let Some(proposed) = &input.proposed {
        if proposed.len() != analyzed_len && analyzed_len > 0 {
            warnings.push(format!(
                "proposed signature has {} bytes but samples are {} bytes; auditing the overlap",
                proposed.len(), analyzed_len
            ));
        }
        for (off, mb) in proposed.iter().enumerate() {
            if off >= analyzed_len {
                break;
            }
            let pos = &positions[off];
            match (mb, pos.invariant) {
                // Mask fixes a byte, samples say it varies → the shipped-bug class.
                (Some(fixed), false) => mask_findings.push(MaskFinding {
                    offset: off,
                    kind: "false-invariant".into(),
                    detail: format!(
                        "signature fixes {:02X} here, but the samples show {} distinct values {:?} — not invariant",
                        fixed, pos.observed.len(), pos.observed
                    ),
                }),
                // Mask fixes a byte the samples agree on, but disagrees on the value.
                (Some(fixed), true) => {
                    let agreed = input.samples[0][off];
                    if *fixed != agreed {
                        mask_findings.push(MaskFinding {
                            offset: off,
                            kind: "contradiction".into(),
                            detail: format!("signature fixes {fixed:02X} but every sample has {agreed:02X}"),
                        });
                    }
                }
                // Mask wildcards a byte that is actually invariant → correct but weaker.
                (None, true) => mask_findings.push(MaskFinding {
                    offset: off,
                    kind: "loose".into(),
                    detail: format!("byte is invariant ({:02X}) but signature wildcards it — could tighten", input.samples[0][off]),
                }),
                (None, false) => {}
            }
        }
    }

    // The refusal logic — the reason this pass exists.
    let mut refusals = Vec::new();
    if sample_count < min_independent {
        refusals.push(format!(
            "only {sample_count} sample(s); need ≥{min_independent} deliberately-varied ones to bless a signature (RE_METHOD F3: an N<3 pattern is a guess, not an invariant)"
        ));
    }
    if input.varied_axes.is_empty() {
        refusals.push(
            "no varied axis named — say which axis you varied (--varied map,mission,seed); an invariant is only meaningful relative to what changed".into(),
        );
    }
    if analyzed_len == 0 {
        refusals.push("no sample bytes to analyze".into());
    }
    if mask_findings.iter().any(|f| f.kind == "false-invariant" || f.kind == "contradiction") {
        refusals.push("proposed signature fixes bytes the samples prove variable — use the derived_signature instead".into());
    }
    if sample_count >= 2 && invariant_bytes == analyzed_len && analyzed_len > 0 {
        warnings.push("every byte is invariant across the samples — either the samples are not actually varied, or this really is a rigid structure; confirm the varied axis truly differs".into());
    }

    SigValidateArtifact {
        sample_count,
        analyzed_len,
        invariant_bytes,
        varying_bytes,
        derived_signature: derived,
        blessed: refusals.is_empty(),
        refusals,
        warnings,
        mask_findings,
        positions,
    }
}

/// Parse a signature/AOB mask string like `"48 8B ?? 68"` into fixed bytes and
/// wildcards. Accepts `??`, `?`, `*`, and `xx`/`XX` as wildcards; hex pairs
/// otherwise. Shared shape with `n0xis_core::parse_aob`, but yields `Option<u8>`
/// so a caller can audit *which* positions are wildcards.
pub fn parse_mask(text: &str) -> Result<Vec<MaskByte>, String> {
    let mut out = Vec::new();
    for tok in text.split_whitespace() {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        if t == "??" || t == "?" || t == "*" || t.eq_ignore_ascii_case("xx") {
            out.push(None);
        } else {
            let byte = u8::from_str_radix(t, 16).map_err(|_| format!("bad signature byte '{t}' (want a hex pair or a ?? wildcard)"))?;
            out.push(Some(byte));
        }
    }
    if out.is_empty() {
        return Err("empty signature".into());
    }
    Ok(out)
}

/// Parse a concrete byte sample like `"CF 01 A0 00"` (no wildcards — a sample is
/// observed reality, not a pattern).
pub fn parse_sample(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for tok in text.split_whitespace() {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        let byte = u8::from_str_radix(t, 16).map_err(|_| format!("bad sample byte '{t}' (want a hex pair)"))?;
        out.push(byte);
    }
    if out.is_empty() {
        return Err("empty sample".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(samples: Vec<Vec<u8>>, varied: &[&str]) -> SigValidateInput {
        SigValidateInput {
            samples,
            proposed: None,
            varied_axes: varied.iter().map(|s| s.to_string()).collect(),
            min_independent: MIN_INDEPENDENT_SAMPLES,
        }
    }

    #[test]
    fn refuses_two_samples_even_when_they_agree() {
        // The exact F3 scenario: two instances that happen to share a byte.
        let art = validate(&input(vec![vec![0xCF, 0x01], vec![0xCF, 0x99]], &["seed"]));
        assert!(!art.blessed);
        assert!(art.refusals.iter().any(|r| r.contains("≥3")));
    }

    #[test]
    fn blesses_three_varied_samples_and_reports_invariants() {
        let art = validate(&input(
            vec![vec![0xCF, 0x01, 0xAA], vec![0xCF, 0x99, 0xBB], vec![0xCF, 0x40, 0xCC]],
            &["map", "mission"],
        ));
        assert!(art.blessed, "3 varied samples should bless: {:?}", art.refusals);
        assert_eq!(art.invariant_bytes, 1); // only offset 0 (0xCF) is invariant
        assert_eq!(art.derived_signature, "CF ?? ??");
    }

    #[test]
    fn refuses_when_no_varied_axis_named() {
        let art = validate(&input(
            vec![vec![0x10], vec![0x10], vec![0x10]],
            &[],
        ));
        assert!(!art.blessed);
        assert!(art.refusals.iter().any(|r| r.contains("varied axis")));
    }

    #[test]
    fn audits_a_proposed_false_invariant() {
        // Signature fixes 0xCF at offset 1, but offset 1 actually varies.
        let mut inp = input(
            vec![vec![0x48, 0x01], vec![0x48, 0x99], vec![0x48, 0x40]],
            &["map"],
        );
        inp.proposed = Some(vec![Some(0x48), Some(0x01)]);
        let art = validate(&inp);
        assert!(art.mask_findings.iter().any(|f| f.kind == "false-invariant" && f.offset == 1));
        assert!(!art.blessed, "a proven false-invariant must block blessing");
    }

    #[test]
    fn flags_a_loose_wildcard_without_blocking() {
        let mut inp = input(
            vec![vec![0x48, 0x01], vec![0x48, 0x99], vec![0x48, 0x40]],
            &["map"],
        );
        inp.proposed = Some(vec![None, None]); // wildcards offset 0 which is invariant
        let art = validate(&inp);
        assert!(art.mask_findings.iter().any(|f| f.kind == "loose" && f.offset == 0));
        assert!(art.blessed, "a loose-but-correct signature still blesses");
    }

    #[test]
    fn parse_mask_handles_wildcards() {
        assert_eq!(parse_mask("48 8B ?? 68").unwrap(), vec![Some(0x48), Some(0x8B), None, Some(0x68)]);
    }
}
