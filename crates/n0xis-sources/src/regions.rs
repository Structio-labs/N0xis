// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What a sweep over many regions of an address space read, and what it did not.
//!
//! A scan of a live process reads regions one by one, from a list taken a moment
//! earlier. Some will not read: a region freed since the list was taken, a device
//! mapping that `process_vm_readv` cannot follow. Every loop that swept regions
//! once decided that for itself, and they decided four ways: one aborted on any
//! error but "unmapped" (one faulting region ended the scan, with the pattern
//! still ahead of it), several skipped on *every* error (a process that had exited
//! read as a scan that found nothing), and none said what it had left out, so a
//! scan that skipped half the process could not be told from a clean one.
//!
//! The rule is here, once, in [`RegionCoverage::record`]:
//!
//! * a failure about one region ([`SourceError::is_about_a_region`]) is noted and
//!   the sweep goes on;
//! * any other failure is returned, because it says nothing about that region and
//!   everything about the sweep: the target exited, or reading it is refused;
//! * fewer bytes than asked for are noted too.
//!
//! A region is judged by what the read returned, never by its path or its kind.
//! Two device mappings of one process, side by side, are not alike: measured on a
//! real process, one reads and the next faults on its first byte, so a list of
//! names to leave out would hide memory that reads.
//!
//! [`Swept`] is what a sweep hands back. It does not serialize: an answer goes
//! through [`Swept::live`] or [`Swept::window`], which is where a sweep that read
//! nothing becomes [`NothingReadable`] instead of an empty result.

use n0xis_contracts::{Searched, Va};
use serde::Serialize;

use crate::{MemorySource, SourceError};

/// How many entries each of `not_read` and `read_short` carries in an answer. The
/// counts beside them stay true past it. A process can have thousands of
/// mappings; the first few say what kind of thing was missed, and a reply the
/// size of the memory map says nothing more.
pub const NOT_READ_SHOWN: usize = 64;

/// The longest stretch [`RegionCoverage::read_runs`] joins regions into: a
/// scan's saved working set keeps a match's offset in its stretch as a `u32`.
pub const MAX_RUN: usize = u32::MAX as usize;

/// The error code of [`NothingReadable`], for every front door.
pub const NOTHING_READABLE: &str = "nothing-readable";

/// A region that gave no bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RegionNotRead {
    pub start: Va,
    pub size: usize,
    /// The read's own failure, as the source stated it.
    pub why: String,
}

/// A region that gave fewer bytes than asked for: `read` of its `size`, the rest
/// not looked at. A read that stops part-way gives no reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RegionReadShort {
    pub start: Va,
    pub size: usize,
    pub read: usize,
}

/// The tally of one sweep. Holds every entry; the cap applies where it is
/// serialized, so that two sweeps of one region set can still be merged exactly.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegionCoverage {
    asked: usize,
    not_read: Vec<RegionNotRead>,
    read_short: Vec<RegionReadShort>,
}

impl RegionCoverage {
    /// Note what reading `[start, start + size)` came to: the number of bytes it
    /// gave, or its failure. A failure about the region is noted; any other is
    /// handed back, and the sweep ends there.
    pub fn record(&mut self, start: Va, size: usize, outcome: Result<usize, SourceError>) -> Result<(), SourceError> {
        self.asked += 1;
        match outcome {
            Ok(read) if read >= size => {}
            Ok(0) => self.not_read.push(RegionNotRead { start, size, why: "the read gave no bytes".to_string() }),
            Ok(read) => self.read_short.push(RegionReadShort { start, size, read }),
            Err(e) if e.is_about_a_region() => self.not_read.push(RegionNotRead { start, size, why: e.to_string() }),
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Read one region and [`record`](Self::record) it. A region that did not
    /// read gives no bytes here, so a loop's body needs no case for it.
    ///
    /// A source's read stops where its mapping or section ends. A region that
    /// goes on into the next one, which [`read_runs`](Self::read_runs) makes by
    /// joining two that touch, is read on across the seam for as long as the
    /// source gives bytes, so it reads whole or is noted short where it stopped.
    pub fn read_region<S: MemorySource + ?Sized>(&mut self, src: &S, start: Va, size: usize) -> Result<Vec<u8>, SourceError> {
        let mut bytes = match src.read(start, size) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.record(start, size, Err(e))?;
                return Ok(Vec::new());
            }
        };
        while !bytes.is_empty() && bytes.len() < size {
            match src.read(start.offset(bytes.len() as u64), size - bytes.len()) {
                Ok(more) if !more.is_empty() => bytes.extend_from_slice(&more[..more.len().min(size - bytes.len())]),
                Ok(_) => break,
                Err(e) if e.is_about_a_region() => break,
                Err(e) => return Err(e),
            }
        }
        self.record(start, size, Ok(bytes.len()))?;
        Ok(bytes)
    }

    /// Read each of `regions`, in the order given, and join each to the one
    /// before it when they touch and the one before read whole: the stretches a
    /// sweep looks for a match in, as `(start, bytes)`.
    ///
    /// A process's map lists two writable mappings side by side as two regions,
    /// and an image's window crosses from one section into the next. Each was
    /// read alone and searched alone, so a value or a pattern lying across the
    /// seam was in neither: measured on a live process, a `u32` across an
    /// `rw-p` mapping and the `rwxp` one after it was not found at any stride,
    /// by `scan value`, `scan aob` or `scan group`, and each said it had read
    /// everything. What is noted per region is as before: one entry each.
    ///
    /// A stretch stops growing short of [`MAX_RUN`] bytes, where a match's offset
    /// would no longer fit a scan's saved working set.
    pub fn read_runs<S: MemorySource + ?Sized>(&mut self, src: &S, regions: &[(Va, usize)]) -> Result<Vec<(Va, Vec<u8>)>, SourceError> {
        let mut runs: Vec<(Va, Vec<u8>)> = Vec::new();
        for &(start, size) in regions {
            let bytes = self.read_region(src, start, size)?;
            if bytes.is_empty() {
                continue;
            }
            match runs.last_mut() {
                Some((at, run)) if at.0.checked_add(run.len() as u64) == Some(start.0) && run.len() + bytes.len() <= MAX_RUN => {
                    run.extend_from_slice(&bytes)
                }
                _ => runs.push((start, bytes)),
            }
        }
        Ok(runs)
    }

    /// Fold in a later sweep of the same regions, as `pointer path` and
    /// `lua combo` make one per step. A region is not read if any sweep did not
    /// read it: its bytes are missing from that step's result.
    pub fn merge(&mut self, later: RegionCoverage) {
        self.asked = self.asked.max(later.asked);
        for n in later.not_read {
            self.read_short.retain(|s| s.start != n.start);
            if !self.not_read.iter().any(|m| m.start == n.start) {
                self.not_read.push(n);
            }
        }
        for s in later.read_short {
            let listed = self.not_read.iter().any(|n| n.start == s.start);
            match self.read_short.iter_mut().find(|m| m.start == s.start) {
                // The sweep that read least decides what is known to be missing.
                Some(m) => m.read = m.read.min(s.read),
                None if !listed => self.read_short.push(s),
                None => {}
            }
        }
        self.not_read.sort_by_key(|n| n.start.0);
        self.read_short.sort_by_key(|s| s.start.0);
    }

    /// Regions a read gave at least one byte of, whole or short.
    pub fn regions_scanned(&self) -> usize {
        self.asked.saturating_sub(self.not_read.len())
    }

    pub fn not_read(&self) -> &[RegionNotRead] {
        &self.not_read
    }

    pub fn read_short(&self) -> &[RegionReadShort] {
        &self.read_short
    }

    /// Every region asked for gave every byte asked for. What `exhaustive` in a
    /// scan's report rests on.
    pub fn read_whole(&self) -> bool {
        self.not_read.is_empty() && self.read_short.is_empty()
    }

    /// Regions were asked for and none gave a byte. An empty list of regions is
    /// not this: nothing failed.
    pub fn nothing_read(&self) -> bool {
        self.asked > 0 && self.not_read.len() == self.asked
    }
}

/// The form an answer carries: the true counts, and the entries up to
/// [`NOT_READ_SHOWN`].
impl Serialize for RegionCoverage {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Stated<'a> {
            regions_scanned: usize,
            regions_not_read: usize,
            not_read: &'a [RegionNotRead],
            regions_read_short: usize,
            read_short: &'a [RegionReadShort],
        }
        Stated {
            regions_scanned: self.regions_scanned(),
            regions_not_read: self.not_read.len(),
            not_read: &self.not_read[..self.not_read.len().min(NOT_READ_SHOWN)],
            regions_read_short: self.read_short.len(),
            read_short: &self.read_short[..self.read_short.len().min(NOT_READ_SHOWN)],
        }
        .serialize(serializer)
    }
}

/// A sweep's result beside what the sweep read.
///
/// Not serializable, so that an answer has to say which it is: [`live`](Self::live)
/// about a running process, [`window`](Self::window) about a window of an image.
/// Either way, reading nothing is a refusal and cannot come about by forgetting.
#[derive(Clone, Debug)]
pub struct Swept<T> {
    pub answer: T,
    pub read: RegionCoverage,
}

impl<T> Swept<T> {
    /// The answer about a live target: the result with the coverage beside it,
    /// or, when no region gave a byte, the refusal to call that a result.
    pub fn live(self) -> Result<LiveAnswer<T>, NothingReadable> {
        if self.read.nothing_read() {
            return Err(NothingReadable(self.read));
        }
        Ok(LiveAnswer { answer: self.answer, read: self.read })
    }

    /// The answer about a window of an image or a snapshot: the result alone, since
    /// what a file holds does not come and go, or the same refusal. A window that
    /// misses the image has read nothing, and `ok: true` with nothing in it is the
    /// worst shape an answer can take.
    pub fn window(self) -> Result<T, NothingReadable> {
        if self.read.nothing_read() {
            return Err(NothingReadable(self.read));
        }
        Ok(self.answer)
    }

    /// The answer of a scan, about a process or a window of an image: the result,
    /// what the sweep did not read and what it `searched`, or the refusal when
    /// no region gave a byte.
    pub fn stated(self, searched: Searched) -> Result<StatedAnswer<T>, NothingReadable> {
        if self.read.nothing_read() {
            return Err(NothingReadable(self.read));
        }
        Ok(StatedAnswer { answer: self.answer, read: self.read, searched })
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Swept<U> {
        Swept { answer: f(self.answer), read: self.read }
    }
}

/// A window of a source cut where what it holds starts and stops: each stretch
/// [`crate::read_runs`] finds, and each gap before, between and after them, in
/// address order and adding up to the window.
///
/// A window of an image was one region, read from its start: the read stopped
/// at the end of the first section, so the rest of the window was never
/// searched and the answer said nothing of it, and a window starting in a gap
/// between sections read nothing at all and was refused as `nothing-readable`
/// while holding data. Cut here, each stretch is read whole and each gap is
/// noted as not read, with the source's own reason.
pub fn window_regions<S: MemorySource + ?Sized>(src: &S, start: Va, size: usize) -> Result<Vec<(Va, usize)>, SourceError> {
    let end = start.0.saturating_add(size as u64);
    let mut parts = Vec::new();
    let mut at = start.0;
    for (va, bytes) in crate::read_runs(src, start, size)? {
        if va.0 > at {
            parts.push((Va(at), (va.0 - at) as usize));
        }
        parts.push((va, bytes.len()));
        at = va.0 + bytes.len() as u64;
    }
    if at < end || parts.is_empty() {
        parts.push((Va(at), (end - at) as usize));
    }
    Ok(parts)
}

/// A result, what the sweep behind it did not read, and what it searched.
///
/// The form every scan's answer takes: the third part is what lets a reader
/// tell "not in the process" from "not where this looked", and [`Swept::stated`]
/// will not make one without it.
#[derive(Clone, Debug, Serialize)]
pub struct StatedAnswer<T> {
    #[serde(flatten)]
    pub answer: T,
    #[serde(flatten)]
    pub read: RegionCoverage,
    pub searched: Searched,
}

/// A result and, in the same object, what the sweep behind it did not read.
#[derive(Clone, Debug, Serialize)]
pub struct LiveAnswer<T> {
    #[serde(flatten)]
    pub answer: T,
    #[serde(flatten)]
    pub read: RegionCoverage,
}

/// Every region asked for failed, each for a reason about that region. That is
/// not "no matches": nothing was looked at. Its code is [`NOTHING_READABLE`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NothingReadable(pub RegionCoverage);

impl std::fmt::Display for NothingReadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let regions = self.0.not_read.len();
        write!(f, "nothing was readable: regions asked for {regions}, regions that gave a byte 0")?;
        if let Some(first) = self.0.not_read.first() {
            write!(f, "; the first, {} bytes at {}: {}", first.size, first.start, first.why)?;
        }
        Ok(())
    }
}

impl std::error::Error for NothingReadable {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regions at 0x1000 (reads), 0x2000 (a fault), 0x3000 (stops short), and an
    /// optional address whose read fails with a failure about no region.
    struct Planted {
        ends_at: Option<u64>,
    }

    impl MemorySource for Planted {
        fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, SourceError> {
            if self.ends_at == Some(va.0) {
                return Err(SourceError::Os("the process exited".into()));
            }
            match va.0 {
                0x1000 => Ok(vec![1; len]),
                0x2000 => Err(SourceError::Unreadable { va, reason: "Bad address".into() }),
                0x3000 => Ok(vec![3; len / 2]),
                0x4000 => Ok(Vec::new()),
                _ => Err(SourceError::Unmapped(va)),
            }
        }
        fn contains(&self, _: Va) -> bool {
            true
        }
        fn label(&self) -> String {
            "planted".into()
        }
    }

    fn swept(src: &Planted, regions: &[u64]) -> Result<RegionCoverage, SourceError> {
        let mut read = RegionCoverage::default();
        for &r in regions {
            read.read_region(src, Va(r), 0x100)?;
        }
        Ok(read)
    }

    #[test]
    fn a_failure_about_a_region_is_noted_and_the_sweep_goes_on() {
        let read = swept(&Planted { ends_at: None }, &[0x1000, 0x2000, 0x3000, 0x4000, 0x5000]).expect("no failure ends it");
        assert_eq!(read.regions_scanned(), 2);
        let not_read: Vec<u64> = read.not_read().iter().map(|n| n.start.0).collect();
        assert_eq!(not_read, [0x2000, 0x4000, 0x5000]);
        assert!(read.not_read()[0].why.contains("Bad address"), "{:?}", read.not_read()[0]);
        assert_eq!(read.read_short(), [RegionReadShort { start: Va(0x3000), size: 0x100, read: 0x80 }]);
    }

    /// Whatever precedes it, a failure about no region ends the sweep: what is
    /// left after it would read as regions that merely held nothing.
    #[test]
    fn a_failure_about_no_region_is_returned() {
        let got = swept(&Planted { ends_at: Some(0x3000) }, &[0x1000, 0x2000, 0x3000, 0x1000]);
        assert!(matches!(got, Err(SourceError::Os(ref m)) if m.contains("exited")), "{got:?}");
    }

    #[test]
    fn nothing_read_is_a_refusal_and_an_empty_list_is_not() {
        let none = swept(&Planted { ends_at: None }, &[0x2000, 0x5000]).unwrap();
        let refused = Swept { answer: (), read: none }.live().expect_err("no region gave a byte");
        let message = refused.to_string();
        assert!(message.starts_with("nothing was readable"), "{message}");
        assert!(message.contains("Bad address"), "it says why: {message}");

        let no_regions = swept(&Planted { ends_at: None }, &[]).unwrap();
        assert!(!no_regions.nothing_read(), "nothing was asked, so nothing failed");
        // One short region is a result, however little of it came back.
        let short = swept(&Planted { ends_at: None }, &[0x2000, 0x3000]).unwrap();
        assert!(Swept { answer: (), read: short }.live().is_ok());
    }

    #[test]
    fn the_answer_is_capped_and_its_counts_are_not() {
        let mut read = RegionCoverage::default();
        let over = NOT_READ_SHOWN + 5;
        for i in 0..over as u64 {
            read.record(Va(0x1000 * (i + 1)), 8, Err(SourceError::Unmapped(Va(0)))).unwrap();
            read.record(Va(0x1000_0000 + 0x1000 * i), 8, Ok(4)).unwrap();
        }
        read.record(Va(0x9000_0000), 8, Ok(8)).unwrap();
        let v = serde_json::to_value(&read).unwrap();
        assert_eq!(v["regions_not_read"], over);
        assert_eq!(v["not_read"].as_array().unwrap().len(), NOT_READ_SHOWN);
        assert_eq!(v["regions_read_short"], over);
        assert_eq!(v["read_short"].as_array().unwrap().len(), NOT_READ_SHOWN);
        assert_eq!(v["regions_scanned"], over + 1, "short regions were scanned, in part");
    }

    #[test]
    fn a_region_missed_by_any_sweep_is_not_read() {
        let first = swept(&Planted { ends_at: None }, &[0x1000, 0x2000, 0x3000]).unwrap();
        // The same three regions, a moment later: 0x1000 has gone, 0x3000 stopped sooner.
        let mut later = RegionCoverage::default();
        later.record(Va(0x1000), 0x100, Err(SourceError::Unmapped(Va(0x1000)))).unwrap();
        later.record(Va(0x2000), 0x100, Err(SourceError::Unreadable { va: Va(0x2000), reason: "Bad address".into() })).unwrap();
        later.record(Va(0x3000), 0x100, Ok(0x10)).unwrap();

        let mut merged = first.clone();
        merged.merge(later);
        assert_eq!(merged.regions_scanned(), 1, "three regions, two of them missed by one sweep or the other");
        assert_eq!(merged.not_read().iter().map(|n| n.start.0).collect::<Vec<_>>(), [0x1000, 0x2000]);
        assert_eq!(merged.read_short()[0].read, 0x10, "what is known to be missing is the larger part");

        // A short region a later sweep could not read at all is not read, not short.
        let mut later = RegionCoverage::default();
        later.record(Va(0x3000), 0x100, Err(SourceError::Unmapped(Va(0x3000)))).unwrap();
        let mut merged = first;
        merged.merge(later);
        assert!(merged.read_short().is_empty(), "{merged:?}");
        assert!(merged.not_read().iter().any(|n| n.start.0 == 0x3000));
    }
}
