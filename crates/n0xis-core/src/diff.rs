// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`DiffPass`] — line-level structural diffing (ROADMAP Phase 7: "Diffing
//! two binaries/versions at the IR/pseudo level, agent-friendly change
//! reports").
//!
//! Works over any two line sequences — in practice, two `PseudoFunction`s'
//! `pseudo` output (same decompile style on both sides, so the diff reflects
//! real logic changes, not a style difference) — via a classic LCS-based
//! diff: `Ok`/`Removed`/`Added` hunks plus a similarity score, the shape an
//! agent can act on directly ("what changed between these two builds of
//! this function") without re-deriving it from two raw pseudo-C blobs.
//!
//! **Scope**: this pass diffs *one already-identified pair* of functions.
//! Automatically matching every function across two whole binaries (name
//! matching where symbols exist, structural-similarity matching where they
//! don't) is a substantially larger problem of its own — the same "not
//! attempted, documented" split `Arch::detect_switch` draws for ARM64's
//! different jump-table idioms — left to the caller (or a follow-on pass) to
//! pick which pairs of addresses to compare.

use serde::Serialize;

use crate::{CoreError, Ctx, Pass};

/// Bound on `a.len() * b.len()` before the LCS table would get expensive —
/// past this, [`DiffPass`] falls back to a whole-block replace rather than
/// building an O(n*m) table (the "light" in this pass's scope).
const MAX_LCS_CELLS: usize = 2_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffOp {
    Equal,
    Insert,
    Delete,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiffHunk {
    pub op: DiffOp,
    /// 1-based line number on the `a` side, when this hunk has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a_line: Option<usize>,
    /// 1-based line number on the `b` side, when this hunk has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub b_line: Option<usize>,
    pub text: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiffArtifact {
    pub hunks: Vec<DiffHunk>,
    pub equal: usize,
    pub inserted: usize,
    pub deleted: usize,
    /// `equal / max(a.len(), b.len())`, `1.0` for two identical (non-empty)
    /// sides — a quick "how similar" signal before reading the hunks.
    pub similarity: f32,
}

#[derive(Clone, Debug, Default)]
pub struct DiffInput {
    pub a: Vec<String>,
    pub b: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DiffPass;

impl Pass for DiffPass {
    type In = DiffInput;
    type Out = DiffArtifact;

    fn name(&self) -> &'static str {
        "diff"
    }

    fn run(&self, _ctx: &Ctx, input: Self::In) -> Result<Self::Out, CoreError> {
        let DiffInput { a, b } = input;
        let hunks = if a.len().saturating_mul(b.len()) > MAX_LCS_CELLS {
            whole_block_replace(&a, &b)
        } else {
            lcs_diff(&a, &b)
        };

        let equal = hunks.iter().filter(|h| h.op == DiffOp::Equal).count();
        let inserted = hunks.iter().filter(|h| h.op == DiffOp::Insert).count();
        let deleted = hunks.iter().filter(|h| h.op == DiffOp::Delete).count();
        let denom = a.len().max(b.len()).max(1);
        let similarity = equal as f32 / denom as f32;

        Ok(DiffArtifact { hunks, equal, inserted, deleted, similarity })
    }
}

fn whole_block_replace(a: &[String], b: &[String]) -> Vec<DiffHunk> {
    let mut hunks = Vec::with_capacity(a.len() + b.len());
    for (i, line) in a.iter().enumerate() {
        hunks.push(DiffHunk { op: DiffOp::Delete, a_line: Some(i + 1), b_line: None, text: line.clone() });
    }
    for (j, line) in b.iter().enumerate() {
        hunks.push(DiffHunk { op: DiffOp::Insert, a_line: None, b_line: Some(j + 1), text: line.clone() });
    }
    hunks
}

/// Standard LCS dynamic-programming diff: `table[i][j]` is the LCS length of
/// `a[i..]` and `b[j..]`, then a forward walk reconstructs the hunks from the
/// table. O(n*m) time and space — bounded by [`MAX_LCS_CELLS`] at the
/// caller.
fn lcs_diff(a: &[String], b: &[String]) -> Vec<DiffHunk> {
    let (n, m) = (a.len(), b.len());
    let mut table = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            table[i][j] = if a[i] == b[j] {
                table[i + 1][j + 1] + 1
            } else {
                table[i + 1][j].max(table[i][j + 1])
            };
        }
    }

    let mut hunks = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if a[i] == b[j] {
            hunks.push(DiffHunk { op: DiffOp::Equal, a_line: Some(i + 1), b_line: Some(j + 1), text: a[i].clone() });
            i += 1;
            j += 1;
        } else if table[i + 1][j] >= table[i][j + 1] {
            hunks.push(DiffHunk { op: DiffOp::Delete, a_line: Some(i + 1), b_line: None, text: a[i].clone() });
            i += 1;
        } else {
            hunks.push(DiffHunk { op: DiffOp::Insert, a_line: None, b_line: Some(j + 1), text: b[j].clone() });
            j += 1;
        }
    }
    while i < n {
        hunks.push(DiffHunk { op: DiffOp::Delete, a_line: Some(i + 1), b_line: None, text: a[i].clone() });
        i += 1;
    }
    while j < m {
        hunks.push(DiffHunk { op: DiffOp::Insert, a_line: None, b_line: Some(j + 1), text: b[j].clone() });
        j += 1;
    }
    hunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_contracts::Va;
    use n0xis_sources::Snapshot;

    fn diff(a: Vec<&str>, b: Vec<&str>) -> DiffArtifact {
        let snap = Snapshot::builder().region(Va(0x1000), vec![]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        DiffPass
            .run(&ctx, DiffInput { a: a.into_iter().map(String::from).collect(), b: b.into_iter().map(String::from).collect() })
            .unwrap()
    }

    #[test]
    fn identical_input_is_fully_equal() {
        let art = diff(vec!["a", "b", "c"], vec!["a", "b", "c"]);
        assert_eq!(art.equal, 3);
        assert_eq!(art.inserted, 0);
        assert_eq!(art.deleted, 0);
        assert_eq!(art.similarity, 1.0);
    }

    #[test]
    fn a_single_changed_line_is_reported_precisely() {
        // "b" became "B" — the surrounding "a"/"c" lines must stay Equal, not
        // get swept into a whole-block replace.
        let art = diff(vec!["a", "b", "c"], vec!["a", "B", "c"]);
        assert_eq!(art.equal, 2, "a and c are still equal: {:#?}", art.hunks);
        assert_eq!(art.deleted, 1);
        assert_eq!(art.inserted, 1);
        let deleted: Vec<_> = art.hunks.iter().filter(|h| h.op == DiffOp::Delete).map(|h| h.text.as_str()).collect();
        let inserted: Vec<_> = art.hunks.iter().filter(|h| h.op == DiffOp::Insert).map(|h| h.text.as_str()).collect();
        assert_eq!(deleted, vec!["b"]);
        assert_eq!(inserted, vec!["B"]);
    }

    #[test]
    fn an_appended_line_is_a_pure_insert() {
        let art = diff(vec!["a", "b"], vec!["a", "b", "c"]);
        assert_eq!(art.equal, 2);
        assert_eq!(art.inserted, 1);
        assert_eq!(art.deleted, 0);
    }

    #[test]
    fn completely_different_functions_have_low_similarity() {
        let art = diff(vec!["x", "y", "z"], vec!["p", "q", "r"]);
        assert_eq!(art.equal, 0);
        assert_eq!(art.similarity, 0.0);
    }

    #[test]
    fn empty_inputs_do_not_panic() {
        let art = diff(vec![], vec![]);
        assert_eq!(art.hunks.len(), 0);
        assert_eq!(art.similarity, 0.0, "denom clamps to 1 so this never divides by zero");
    }
}
