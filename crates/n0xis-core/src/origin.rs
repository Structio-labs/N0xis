// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Where a fact about a function came from (docs/design/WHY.md): the input or
//! the rule that produced it, as a category from a closed list.
//!
//! **Recorded where the rule fires, never recomputed.** Discovery decides a
//! start in one place ([`crate::discover_entries`]); re-running its rules for
//! one address to say which of them would fire is a second copy of discovery,
//! and copies drift. So each rule names its category as it adds a start, the
//! function list carries the categories, and `n0x why` only reads them.
//!
//! **Enums, not strings,** so a rule cannot reach an answer without naming its
//! category: a new rule is a new variant, and every `match` that turns one into
//! an answer stops compiling until it says what the new one is.

use n0xis_contracts::Va;
use n0xis_sources::StartReason;
use serde::{Deserialize, Serialize};

/// What states a function the image (or a file built with it) declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum StatedBy {
    /// The image's own declaration, with its reason: a PE export, a PE32+
    /// `.pdata` entry, a WebAssembly body.
    Image(StartReason),
    /// An `.eh_frame` FDE: unwind information the image carries, read by
    /// [`crate::scan_eh_frame`] — not one of the image reader's own starts.
    EhFrame,
    /// A procedure in the PDB built with the image.
    Pdb,
}

/// One function the image states, and everything that states it.
///
/// One entry per distinct `(start, end)`: two declarations of the same extent
/// (a `.pdata` entry and an export with no length are *not* the same extent)
/// are one function with two sources. The list stays the shape it had when it
/// was bare pairs, which every lookup by start relies on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatedFunction {
    pub start: Va,
    /// Exclusive; `end <= start` is a start with no stated extent.
    pub end: Va,
    pub stated_by: Sources<StatedBy>,
}

impl StatedFunction {
    pub fn new(start: Va, end: Va, by: StatedBy) -> Self {
        StatedFunction { start, end, stated_by: Sources::one(by) }
    }

    /// Sort by `(start, end)` and fold every declaration of one extent into
    /// one entry — the order and the uniqueness `Ctx::functions` promises.
    pub fn merged(mut all: Vec<StatedFunction>) -> Vec<StatedFunction> {
        all.sort_by_key(|f| (f.start, f.end));
        let mut out: Vec<StatedFunction> = Vec::with_capacity(all.len());
        for f in all {
            match out.last_mut() {
                Some(last) if last.start == f.start && last.end == f.end => {
                    for by in f.stated_by.iter() {
                        last.stated_by.add(*by);
                    }
                }
                _ => out.push(f),
            }
        }
        out
    }
}

/// Why discovery lists a function start: a declaration, or the rule that
/// found it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StartSource {
    /// A declaration ([`StatedBy`]).
    Stated(StatedBy),
    /// The first instruction after a declared function's end.
    AfterDeclaredEnd,
    /// A linear sweep of the gap between two declared functions.
    GapSweep,
    /// A direct `call` names it; `from` is the first such call in the code
    /// scanned, in address order.
    CallTarget { from: Va },
    /// An entry pattern of the architecture matched.
    Prologue,
}

/// Where a listed function's end came from, as [`crate::Discovered::end_of`]
/// decides it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndFrom {
    /// The symbol seam's stated length (`SymbolProvider::symbol_size`): which
    /// of the composed layers answered is the composition's to say.
    SymbolSize,
    /// The extent a declaration handed to discovery states.
    Stated(Sources<StatedBy>),
}

/// How the name a function list gives a start was found
/// ([`crate::function_name_and_source`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameFrom {
    /// The symbol seam names the start exactly: which of the composed layers
    /// answered is the composition's to say.
    Symbol,
    /// The start is a stub that only jumps through `slot`, and the slot is
    /// bound to an import: named after the import.
    Import { slot: Va },
    /// Nothing names it: `sub_<address>`, or `func_<index>` on a module whose
    /// functions are identified by index.
    Fallback,
}

/// One or more sources, in the order they were recorded, each once. Never
/// empty: a start nothing found is not a start, and a list that could hold an
/// empty set of sources could answer "found by nothing".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<T>", into = "Vec<T>", bound(serialize = "T: Clone + Serialize", deserialize = "T: Deserialize<'de>"))]
pub struct Sources<T> {
    first: T,
    rest: Vec<T>,
}

impl<T: PartialEq + Copy> Sources<T> {
    pub fn one(first: T) -> Self {
        Sources { first, rest: Vec::new() }
    }

    /// Record `by`, unless it is already recorded.
    pub fn add(&mut self, by: T) {
        if self.first != by && !self.rest.contains(&by) {
            self.rest.push(by);
        }
    }

    pub fn first(&self) -> T {
        self.first
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        std::iter::once(&self.first).chain(self.rest.iter())
    }
}

impl<T> From<Sources<T>> for Vec<T> {
    fn from(s: Sources<T>) -> Vec<T> {
        let mut out = Vec::with_capacity(1 + s.rest.len());
        out.push(s.first);
        out.extend(s.rest);
        out
    }
}

impl<T> TryFrom<Vec<T>> for Sources<T> {
    type Error = &'static str;

    /// An empty list is refused, so a kept function list that lost its sources
    /// fails to load (a cache miss) rather than reading as "found by nothing".
    fn try_from(v: Vec<T>) -> Result<Self, Self::Error> {
        let mut it = v.into_iter();
        let first = it.next().ok_or("a start with no source")?;
        Ok(Sources { first, rest: it.collect() })
    }
}

/// Unit tests' stated functions: each pair an `.eh_frame` FDE.
#[cfg(test)]
pub(crate) fn fdes(pairs: &[(Va, Va)]) -> Vec<StatedFunction> {
    StatedFunction::merged(pairs.iter().map(|&(s, e)| StatedFunction::new(s, e, StatedBy::EhFrame)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_is_recorded_once_and_an_empty_list_does_not_load() {
        let mut s = Sources::one(StartSource::Prologue);
        s.add(StartSource::GapSweep);
        s.add(StartSource::Prologue);
        assert_eq!(s.iter().copied().collect::<Vec<_>>(), vec![StartSource::Prologue, StartSource::GapSweep]);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<Sources<StartSource>>(&json).unwrap(), s);
        assert!(serde_json::from_str::<Sources<StartSource>>("[]").is_err(), "an empty set of sources must not load");
    }

    #[test]
    fn one_extent_stated_twice_is_one_function_with_two_sources() {
        let all = vec![
            StatedFunction::new(Va(0x20), Va(0x30), StatedBy::Pdb),
            StatedFunction::new(Va(0x10), Va(0x10), StatedBy::Image(StartReason::Export)),
            StatedFunction::new(Va(0x10), Va(0x18), StatedBy::EhFrame),
            StatedFunction::new(Va(0x10), Va(0x10), StatedBy::Pdb),
        ];
        let merged = StatedFunction::merged(all);
        let pairs: Vec<(u64, u64)> = merged.iter().map(|f| (f.start.0, f.end.0)).collect();
        assert_eq!(pairs, vec![(0x10, 0x10), (0x10, 0x18), (0x20, 0x30)]);
        assert_eq!(merged[0].stated_by.iter().copied().collect::<Vec<_>>(), vec![StatedBy::Image(StartReason::Export), StatedBy::Pdb]);
    }
}
