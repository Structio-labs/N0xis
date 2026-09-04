// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `game grep <concept>` — rank a target's scripts/data/strings by how densely
//! they cluster a concept's vocabulary (ROADMAP Phase 8, fixes RE_METHOD F2 —
//! the campaign's root cause).
//!
//! One grep for `combo|interact|stratagem` found the component, the algorithm
//! module, the RNG class, and every data template in ~30 minutes — after weeks
//! of native RE had found none of it. That grep was hand-rolled in throwaway
//! Python; this is the first-class version.
//!
//! The interesting part is the **ranking**, per the ROADMAP scope note: a file
//! mentioning 5 of the concept's words matters far more than one mentioning a
//! single word 50 times. So the score is dominated by *vocabulary-cluster
//! breadth* (how many distinct concept terms appear), with raw frequency only a
//! log-damped tiebreak. Pure text analysis — no `Ctx`, no memory source. The
//! CLI walks the corpus (decoding Lua chunks, reading strings) and hands each
//! file's text in as a [`Document`]; this module has no opinion on where the
//! text came from.

use serde::Serialize;

/// One searchable unit of the corpus: a decoded Lua chunk, a data file, a run of
/// binary strings — whatever the CLI extracted, flattened to text.
#[derive(Clone, Debug)]
pub struct Document {
    /// Stable identifier shown in the report (a path, a module+range).
    pub id: String,
    /// What kind of thing this is (`lua`, `text`, `strings`), for grouping.
    pub kind: String,
    pub text: String,
}

/// How strongly one document clusters the concept's vocabulary.
#[derive(Clone, Debug, Serialize)]
pub struct RankedHit {
    pub id: String,
    pub kind: String,
    /// Cluster-dominated score (breadth ≫ frequency). Not normalized — only the
    /// ordering is meaningful.
    pub score: f64,
    /// How many *distinct* concept terms appear here (the breadth signal).
    pub distinct_terms: usize,
    /// Total occurrences across all terms (the frequency signal).
    pub total_hits: usize,
    /// Per-term occurrence counts, only for terms that appeared.
    pub term_hits: Vec<TermHit>,
    /// A few context snippets (one line / window around a match), deduplicated.
    pub snippets: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TermHit {
    pub term: String,
    pub count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct GameGrepArtifact {
    /// The vocabulary that was searched (normalized, lowercased).
    pub concept: Vec<String>,
    pub documents_scanned: usize,
    pub documents_matched: usize,
    pub hits: Vec<RankedHit>,
}

/// Options controlling the report shape (not the scoring).
#[derive(Clone, Debug)]
pub struct RankOptions {
    /// Cap on ranked documents returned.
    pub limit: usize,
    /// Max context snippets per document.
    pub max_snippets: usize,
    /// Require at least this many distinct terms for a document to count as a
    /// hit — the cluster threshold (default 1: any single-term match still
    /// reports, but raising it to 2+ is how you cut single-word noise).
    pub min_distinct: usize,
}

impl Default for RankOptions {
    fn default() -> Self {
        RankOptions { limit: 40, max_snippets: 3, min_distinct: 1 }
    }
}

const SNIPPET_MAX_LEN: usize = 160;

/// Count non-overlapping occurrences of `needle` in `haystack` (both already
/// lowercased). Simple substring scan — robust for identifier vocabularies
/// (`interact_progress` contains `interact`) where a word-boundary regex would
/// miss the very hits that matter.
fn count_occurrences(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(needle) {
        count += 1;
        start += pos + needle.len();
    }
    count
}

/// Extract a readable snippet around the first occurrence of `term` in the
/// original-cased text (searching a lowercased copy for the position).
fn snippet_around(text: &str, lower: &str, term: &str) -> Option<String> {
    let pos = lower.find(term)?;
    // Prefer the enclosing line; fall back to a byte window.
    let line_start = text[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line_end = text[pos..].find('\n').map(|i| pos + i).unwrap_or(text.len());
    let mut line = text[line_start..line_end].trim().to_string();
    if line.len() > SNIPPET_MAX_LEN {
        // Center the window on the match.
        let rel = pos.saturating_sub(line_start);
        let half = SNIPPET_MAX_LEN / 2;
        let from = rel.saturating_sub(half);
        let to = (from + SNIPPET_MAX_LEN).min(line.len());
        // Respect char boundaries.
        let from = floor_char_boundary(&line, from);
        let to = floor_char_boundary(&line, to);
        line = format!("…{}…", &line[from..to]);
    }
    if line.is_empty() { None } else { Some(line) }
}

/// `str::floor_char_boundary` is unstable; this is the same idea.
fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

/// Rank `docs` by vocabulary-cluster density for `concept`. `concept` terms are
/// lowercased and de-duplicated; empty terms are dropped.
pub fn rank(concept: &[String], docs: &[Document], opts: &RankOptions) -> GameGrepArtifact {
    let mut terms: Vec<String> = concept.iter().map(|t| t.trim().to_lowercase()).filter(|t| !t.is_empty()).collect();
    terms.sort();
    terms.dedup();

    let mut hits = Vec::new();
    for doc in docs {
        let lower = doc.text.to_lowercase();
        let mut term_hits = Vec::new();
        let mut total_hits = 0usize;
        for term in &terms {
            let c = count_occurrences(&lower, term);
            if c > 0 {
                total_hits += c;
                term_hits.push(TermHit { term: term.clone(), count: c });
            }
        }
        let distinct_terms = term_hits.len();
        if distinct_terms < opts.min_distinct {
            continue;
        }

        // Cluster-dominated score: breadth (distinct terms) is squared and
        // weighted so it always outranks raw frequency; frequency contributes a
        // log-damped tail so a genuinely dense file edges out a sparse one of
        // equal breadth, without a single spammed word ever winning.
        let breadth = distinct_terms as f64;
        let freq_tail: f64 = term_hits.iter().map(|t| (t.count as f64).ln_1p()).sum();
        let score = breadth * breadth * 100.0 + freq_tail;

        // Snippets: one per matched term (in the concept's order), deduped.
        let mut snippets = Vec::new();
        for t in &term_hits {
            if snippets.len() >= opts.max_snippets {
                break;
            }
            if let Some(s) = snippet_around(&doc.text, &lower, &t.term)
                && !snippets.contains(&s)
            {
                snippets.push(s);
            }
        }

        // Report term hits in descending count for readability.
        term_hits.sort_by(|a, b| b.count.cmp(&a.count).then(a.term.cmp(&b.term)));

        hits.push(RankedHit {
            id: doc.id.clone(),
            kind: doc.kind.clone(),
            score,
            distinct_terms,
            total_hits,
            term_hits,
            snippets,
        });
    }

    let documents_matched = hits.len();
    // Highest score first; ties broken by breadth then id for determinism.
    hits.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.distinct_terms.cmp(&a.distinct_terms))
            .then(a.id.cmp(&b.id))
    });
    hits.truncate(opts.limit);

    GameGrepArtifact {
        concept: terms,
        documents_scanned: docs.len(),
        documents_matched,
        hits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(id: &str, kind: &str, text: &str) -> Document {
        Document { id: id.into(), kind: kind.into(), text: text.into() }
    }

    #[test]
    fn breadth_outranks_frequency() {
        // Doc A mentions one term 50 times; doc B mentions three terms once each.
        let a = doc("a", "lua", &"combo ".repeat(50));
        let b = doc("b", "lua", "combo interact stratagem");
        let art = rank(
            &["combo".into(), "interact".into(), "stratagem".into()],
            &[a, b],
            &RankOptions::default(),
        );
        assert_eq!(art.hits[0].id, "b", "breadth (3 distinct terms) must beat frequency (50 of one)");
        assert_eq!(art.hits[0].distinct_terms, 3);
    }

    #[test]
    fn min_distinct_filters_single_word_noise() {
        let a = doc("noise", "text", "combo combo combo");
        let b = doc("signal", "lua", "combo interact");
        let opts = RankOptions { min_distinct: 2, ..RankOptions::default() };
        let art = rank(&["combo".into(), "interact".into()], &[a, b], &opts);
        assert_eq!(art.documents_matched, 1);
        assert_eq!(art.hits[0].id, "signal");
    }

    #[test]
    fn substring_matches_identifiers() {
        let d = doc("m", "lua", "function interact_progress() end");
        let art = rank(&["interact".into()], &[d], &RankOptions::default());
        assert_eq!(art.hits[0].total_hits, 1);
        assert!(art.hits[0].snippets[0].contains("interact_progress"));
    }

    #[test]
    fn no_match_reports_nothing() {
        let d = doc("x", "lua", "totally unrelated content");
        let art = rank(&["combo".into()], &[d], &RankOptions::default());
        assert_eq!(art.documents_matched, 0);
        assert!(art.hits.is_empty());
    }

    #[test]
    fn concept_is_normalized() {
        let d = doc("x", "lua", "Combo INTERACT");
        let art = rank(&["COMBO".into(), " interact ".into(), "combo".into()], &[d], &RankOptions::default());
        // dedup + lowercase → two distinct terms.
        assert_eq!(art.concept.len(), 2);
        assert_eq!(art.hits[0].distinct_terms, 2);
    }
}
