// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What a search looked through, stated beside what it found.
//!
//! An audit of the tool's statements of absence and completeness (2026-11-06)
//! found 74 of 220 false, and the false ones had one shape: the answer reported
//! what the tool's own procedure had visited, in words about the program. A value
//! scan said `exhaustive: true, total_matches: 0` about a process holding the
//! value, because its default set was the writable mappings, its stride was four
//! bytes and its regions were read one mapping at a time, and nothing in the
//! answer said any of the three. Lists cut at 200 or 256 or 400 said `count` and
//! nothing else. Each of those answers was computed correctly; it was the claim
//! that was larger than the search.
//!
//! The two types here are the half of such an answer that says where it looked,
//! and they are built so that it cannot be left out:
//!
//! * [`Searched`] names what a search went through ([`Over`]), the stride it
//!   tried a match at, and each thing a reader would count as inside that it did
//!   not look at. Whether the search was whole is a method, [`Searched::whole`],
//!   never a field a caller sets: an answer that says `exhaustive` derives it
//!   from what it states, and a set the tool chose for the caller cannot be built
//!   without naming what is outside it.
//! * [`Shown`] is a list's cut: built from the list itself and the limit, so the
//!   total and the fact of the cut come with the list or not at all.

use serde::{Deserialize, Serialize};

use crate::Va;

/// What a search went through.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Over {
    /// A window the caller named: the answer is about it, and about nothing past it.
    Window { start: Va, size: u64 },
    /// A set the tool picked because the caller named none. What it leaves out is
    /// part of the program, so a [`Searched`] over it always carries a
    /// [`NotSearched`] for the rest: [`Searched::chosen`] takes one.
    Chosen { set: String },
    /// The addresses a saved working set holds: a rescan is about those, and only those.
    Saved,
}

/// One thing a reader would take to be inside the search and was not looked at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotSearched {
    /// What it is, in the program's words: "mappings without write permission".
    pub what: String,
    /// How many of them, when they are things that can be counted.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub count: Option<u64>,
    /// How many bytes they hold, when that is known.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bytes: Option<u64>,
}

impl NotSearched {
    pub fn new(what: impl Into<String>) -> Self {
        NotSearched { what: what.into(), count: None, bytes: None }
    }

    pub fn count(mut self, n: u64) -> Self {
        self.count = Some(n);
        self
    }

    pub fn bytes(mut self, n: u64) -> Self {
        self.bytes = Some(n);
        self
    }
}

/// What a search looked through. The field `searched` of an answer that says a
/// thing is absent, or that what it lists is all there is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Searched {
    pub over: Over,
    /// A match was tried at every `stride`-th byte from the start of each stretch
    /// read; `1` is every byte. Stated whatever it is, since a value at an offset
    /// the stride steps over is a value the search never saw.
    pub stride: u64,
    /// Inside `over`, or outside a set the tool chose, and not looked at. Empty
    /// when there was nothing such.
    pub not_searched: Vec<NotSearched>,
}

impl Searched {
    /// A search over a window the caller named.
    pub fn window(start: Va, size: u64, stride: u64) -> Self {
        Searched { over: Over::Window { start, size }, stride, not_searched: Vec::new() }
    }

    /// A search over a set the tool picked: `rest` is what the set leaves out, and
    /// there is no way to build one without saying it.
    pub fn chosen(set: impl Into<String>, stride: u64, rest: NotSearched) -> Self {
        Searched { over: Over::Chosen { set: set.into() }, stride, not_searched: vec![rest] }
    }

    /// A rescan of a saved working set: each address it holds is read again,
    /// so the stride is one, over those addresses. What the first scan left out
    /// is that scan's statement, not this one's.
    pub fn saved() -> Self {
        Searched { over: Over::Saved, stride: 1, not_searched: Vec::new() }
    }

    /// Add one more thing that was not looked at.
    pub fn left_out(mut self, what: NotSearched) -> Self {
        self.not_searched.push(what);
        self
    }

    /// Every byte of what [`over`](Self::over) names was a place a match was
    /// tried, and nothing in it was left out. What `exhaustive` rests on; a set
    /// the tool chose is never whole, since it was built with its rest left out.
    pub fn whole(&self) -> bool {
        self.stride == 1 && self.not_searched.is_empty() && !matches!(self.over, Over::Chosen { .. })
    }
}

/// How much of a list an answer shows: the total there was, and whether the
/// list was cut. Made by [`Shown::cap`] from the list itself, so a cut list
/// cannot come back without its total.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shown {
    pub total: usize,
    pub truncated: bool,
}

impl Shown {
    /// Cut `all` to `limit` entries (`0` is no limit) and say what was cut.
    pub fn cap<T>(all: &mut Vec<T>, limit: usize) -> Shown {
        let total = all.len();
        if limit != 0 && total > limit {
            all.truncate(limit);
        }
        Shown { total, truncated: all.len() < total }
    }
}

/// A list and its cut, in one object: the list's own fields, then `total` and
/// `truncated` beside them.
#[derive(Clone, Debug, Serialize)]
pub struct Listed<T> {
    #[serde(flatten)]
    pub list: T,
    #[serde(flatten)]
    pub shown: Shown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chosen_set_is_never_whole() {
        let s = Searched::chosen("writable mappings", 1, NotSearched::new("mappings without write permission").count(3));
        assert!(!s.whole());
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["over"]["kind"], "chosen");
        assert_eq!(v["not_searched"][0]["count"], 3);
    }

    #[test]
    fn a_stride_past_one_byte_is_not_whole() {
        assert!(Searched::window(Va(0x1000), 0x100, 1).whole());
        assert!(!Searched::window(Va(0x1000), 0x100, 4).whole(), "three offsets in four were never tried");
        assert!(!Searched::window(Va(0x1000), 0x100, 1).left_out(NotSearched::new("a gap")).whole());
    }

    #[test]
    fn a_cut_list_says_its_total() {
        let mut v: Vec<u32> = (0..10).collect();
        assert_eq!(Shown::cap(&mut v, 4), Shown { total: 10, truncated: true });
        assert_eq!(v.len(), 4);
        let mut w: Vec<u32> = (0..3).collect();
        assert_eq!(Shown::cap(&mut w, 4), Shown { total: 3, truncated: false });
        assert_eq!(Shown::cap(&mut w, 0), Shown { total: 3, truncated: false }, "0 is no limit");
    }
}
