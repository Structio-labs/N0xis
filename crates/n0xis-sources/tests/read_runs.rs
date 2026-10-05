// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`read_runs`] on a source whose map is planted: which stretches it gives,
//! that it crosses a gap with the default [`MemorySource::next_readable`], and
//! that a failure is returned rather than shown as a gap.

use n0xis_contracts::Va;
use n0xis_sources::{MemorySource, SourceError, page_bounds, read_runs};

/// Bytes at `[0x100, 0x110)` and `[0x120, 0x130)`; reading at `fails_at`
/// is an OS error, as a process that exits mid-read gives.
struct Planted {
    fails_at: Option<u64>,
}

impl Planted {
    const STRETCHES: [(u64, u64); 2] = [(0x100, 0x110), (0x120, 0x130)];
}

impl MemorySource for Planted {
    fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, SourceError> {
        if self.fails_at == Some(va.0) {
            return Err(SourceError::Os("the process exited".into()));
        }
        let (_, end) = Self::STRETCHES.iter().find(|(s, e)| va.0 >= *s && va.0 < *e).ok_or(SourceError::Unmapped(va))?;
        let take = len.min((end - va.0) as usize);
        Ok((0..take as u64).map(|i| (va.0 + i) as u8).collect())
    }
    fn contains(&self, va: Va) -> bool {
        Self::STRETCHES.iter().any(|(s, e)| va.0 >= *s && va.0 < *e)
    }
    fn label(&self) -> String {
        "planted".into()
    }
}

#[test]
fn each_stretch_is_a_run_and_the_gaps_are_crossed() {
    let runs = read_runs(&Planted { fails_at: None }, Va(0xf0), 0x48).expect("no failure");
    let got: Vec<(u64, usize)> = runs.iter().map(|(va, b)| (va.0, b.len())).collect();
    assert_eq!(got, [(0x100, 0x10), (0x120, 0x10)]);
    assert_eq!(runs[1].1.first(), Some(&0x20), "the bytes are the source's own");
    // A window that ends inside a stretch takes only its share.
    let cut = read_runs(&Planted { fails_at: None }, Va(0x108), 0x1c).expect("no failure");
    assert_eq!(cut.iter().map(|(va, b)| (va.0, b.len())).collect::<Vec<_>>(), [(0x108, 8), (0x120, 4)]);
}

#[test]
fn a_failure_is_returned_not_shown_as_a_gap() {
    let failed = read_runs(&Planted { fails_at: Some(0x120) }, Va(0xf0), 0x48);
    assert!(matches!(failed, Err(SourceError::Os(_))), "{failed:?}");
}

#[test]
fn page_bounds_are_the_pages_strictly_inside() {
    assert_eq!(page_bounds(Va(0x0fff), Va(0x3001)).collect::<Vec<_>>(), [0x1000, 0x2000, 0x3000]);
    assert_eq!(page_bounds(Va(0x1000), Va(0x2000)).collect::<Vec<_>>(), Vec::<u64>::new());
    assert_eq!(page_bounds(Va(u64::MAX - 1), Va(u64::MAX)).count(), 0, "no wrap at the top");
}
