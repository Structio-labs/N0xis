// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `contradictions`: every place in an image where two sources the engine
//! reads disagree — the map of where to doubt (docs/design/WHY.md §6 item 1).
//!
//! **A reader of what is already kept, never a second parse.** Each value
//! compared is the one a source handed the engine where it was read: the
//! extents the stated functions carry (`Ctx::functions`, each with what states
//! it), every length and every name the composed name layers give an address
//! ([`StaticNames::every_size_at`], [`StaticNames::every_name_at`], which ask
//! the same layers `function discover` and `why` ask), and the image reader's
//! own [`Finding::Contradiction`]s. The vocabulary of sources is `why`'s
//! ([`EndBy`], [`NameSource`]), so a source named here is the source `why`
//! names for the same fact.
//!
//! **No grade.** A contradiction says two sources disagree, and what each
//! says; it does not say which is right.
//!
//! **A user's name is not a contradiction.** It is the user's decision to
//! override what a layer says, so it is counted apart, as an override, with
//! the layer it overrode.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use n0xis_contracts::Va;
use n0xis_core::{Ctx, DiscoveredStart};
use n0xis_sources::{Finding, ImageName, ImageSource, SymbolTable};
use serde::Serialize;

use crate::annotation_syms::LocalLayer;
use crate::static_names::{LayerName, NameLayer, StaticNames};
use crate::why::{AlsoNamed, Declared, EndBy, Given, Length, NameSource, SizeOf, UnwindTable};

/// `n0xis.contradictions.v1`.
#[derive(Clone, Debug, Serialize)]
pub struct ContradictionsArtifact {
    /// Every kind, whether it was checked here and against which sources.
    pub kinds: Kinds,
    /// Where the user's own name overrides a layer's.
    pub overrides: Overrides,
    /// How many contradictions this page carries (`meta.total` is all of
    /// them).
    pub count: usize,
    /// Grouped by kind in the order of [`Kinds`], each kind in address order.
    pub contradictions: Vec<Contradiction>,
}

/// What can disagree. Each kind is a field of [`Kinds`] and a variant of
/// [`Contradiction`], so a kind added later has to say, on every image,
/// whether it was checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// One start with stated ends that differ.
    End,
    /// Two stated extents with different starts, one reaching past the
    /// other's start.
    Overlap,
    /// Two sources naming one address differently.
    Name,
    /// The image reader's own report that two of the image's statements
    /// disagree.
    Image,
}

/// Each kind's verdict on this image.
#[derive(Clone, Debug, Serialize)]
pub struct Kinds {
    pub end: KindReport<EndSort>,
    pub overlap: KindReport<EndSort>,
    pub name: KindReport<NameSort>,
    pub image: KindReport<FindingsOf>,
}

/// Which sort of source states an end: an [`EndBy`] without what tells one
/// instance from another (which body, which stub), so a module's thousand
/// bodies are one sort of source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum EndSort {
    Export,
    Symbol,
    Unwind { table: UnwindTable },
    Pdb,
    Body,
    Stub,
    SymbolSize { of: SizeOf },
}

impl From<EndBy> for EndSort {
    fn from(by: EndBy) -> Self {
        match by {
            EndBy::Declared(d) => match d {
                Declared::Export => EndSort::Export,
                Declared::Symbol => EndSort::Symbol,
                Declared::Unwind { table } => EndSort::Unwind { table },
                Declared::Pdb => EndSort::Pdb,
                Declared::Body { .. } => EndSort::Body,
                Declared::Stub { .. } => EndSort::Stub,
            },
            EndBy::Length(Length::SymbolSize { of }) => EndSort::SymbolSize { of },
        }
    }
}

/// Which sort of source gives a name: a [`NameSource`] without the slot a
/// stub jumps through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum NameSort {
    User,
    Rtti,
    Flirt { given_by: Given },
    Pdb,
    Managed,
    Image { table: SymbolTable },
    Stub,
    Fallback,
}

impl From<NameSource> for NameSort {
    fn from(s: NameSource) -> Self {
        match s {
            NameSource::User => NameSort::User,
            NameSource::Rtti => NameSort::Rtti,
            NameSource::Flirt { given_by } => NameSort::Flirt { given_by },
            NameSource::Pdb => NameSort::Pdb,
            NameSource::Managed => NameSort::Managed,
            NameSource::Image { table } => NameSort::Image { table },
            NameSource::Stub { .. } => NameSort::Stub,
            NameSource::Fallback => NameSort::Fallback,
        }
    }
}

/// Whether a kind was checked, and the sources it read.
#[derive(Clone, Debug, Serialize)]
pub struct KindReport<S> {
    #[serde(flatten)]
    pub state: Checked,
    /// Every source of this kind of fact that stated one here, in the order
    /// first met (address order): what was compared, or, where the kind was
    /// not checked, all there was.
    pub sources: Vec<S>,
    /// Sources that stated something here and were not compared, each with
    /// why.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_compared: Vec<NotCompared>,
}

/// Checked, with how many contradictions were found; or not checked, and why
/// — never "none found" for a kind that could not be found here.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Checked {
    Checked { count: usize },
    NotChecked { why: &'static str },
}

/// The image reader, whose findings the `image` kind passes on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingsOf {
    ImageReader,
}

/// A sort of source whose names were not compared, and why.
#[derive(Clone, Debug, Serialize)]
pub struct NotCompared {
    #[serde(flatten)]
    pub source: NameSort,
    pub why: &'static str,
}

/// One place two sources disagree.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Contradiction {
    /// The ends stated for `start`, each with everything that states it: two
    /// or more, all different.
    End { start: Va, ends: Vec<StatedEnd> },
    /// `first` starts before `second` and ends past `second`'s start.
    Overlap { first: Extent, second: Extent },
    /// Every name the sources compared give `addr`, at least two of the
    /// sources with no name in common.
    Name { addr: Va, names: Vec<ComparedName> },
    /// The image reader's own words.
    Image { what: String },
}

impl Contradiction {
    pub fn kind(&self) -> Kind {
        match self {
            Contradiction::End { .. } => Kind::End,
            Contradiction::Overlap { .. } => Kind::Overlap,
            Contradiction::Name { .. } => Kind::Name,
            Contradiction::Image { .. } => Kind::Image,
        }
    }
}

/// An exclusive end, and everything that states it.
#[derive(Clone, Debug, Serialize)]
pub struct StatedEnd {
    pub end: Va,
    pub by: Vec<EndBy>,
}

/// A stated extent, and everything that states exactly it.
#[derive(Clone, Debug, Serialize)]
pub struct Extent {
    pub start: Va,
    /// Exclusive.
    pub end: Va,
    pub by: Vec<EndBy>,
}

/// One name a source gives, and the form it was compared in.
#[derive(Clone, Debug, Serialize)]
pub struct ComparedName {
    #[serde(flatten)]
    pub source: NameSource,
    /// As the source states it.
    pub name: String,
    /// What was compared: a WebAssembly function's name as the module states
    /// it; a native name with an ELF version suffix cut off (`.symtab` and
    /// `.dynsym` only), and a mangled one as the qualified name it stands for,
    /// with no return type and no parameter list.
    pub compared_as: String,
}

/// The user's names that override a layer's.
#[derive(Clone, Debug, Serialize)]
pub struct Overrides {
    pub count: usize,
    pub at: Vec<Override>,
}

/// An address the user named, and the layer whose name the user's replaces.
#[derive(Clone, Debug, Serialize)]
pub struct Override {
    pub addr: Va,
    /// The user's name.
    pub name: String,
    /// The most trusted other layer naming the address: the name the list
    /// would show without the user's.
    pub overrode: AlsoNamed,
}

/// How many contradictions a page carries when the caller does not say: one
/// default for every front door.
pub const DEFAULT_LIMIT: usize = 1000;

/// Why a kind was not checked.
const NO_END_STATED: &str =
    "nothing the engine reads states a function's length here (no unwind table, no symbol size, no PDB length, no WebAssembly body)";
const NAMED_BY_FEWER_THAN_TWO: &str =
    "fewer than two sources name functions here, and the names one source gives an address are its aliases, not a disagreement";
const NOT_AN_IMAGE: &str = "the target is not an image file, so there is no image reader to report its findings";

/// Why some names were not compared.
const RTTI_NAMES_A_SLOT: &str =
    "a name recovered from RTTI is `Class::vfN`, the slot of the first vtable that reaches the method: it states a slot, not the method's name";
const ORDINAL_ONLY: &str =
    "an export by ordinal only: the image layer's `Ordinal<n>` says the export has an ordinal and no name, so there is no name to compare";

/// What the sources the engine reads hand it, for one target.
pub struct Inputs<'a> {
    pub ctx: &'a Ctx<'a>,
    pub names: &'a StaticNames<'a>,
    /// The image file the target is, if it is one.
    pub image: Option<&'a ImageSource>,
    /// The function list `function discover` gives (its starts), so a name a
    /// layer that cannot list its names gives a listed start is compared too.
    pub listed: &'a [DiscoveredStart],
}

/// Every contradiction among `inputs`, the page `offset..offset + limit`
/// (`limit` 0: all from `offset`) of them, and how many there are in all.
pub fn answer(inputs: &Inputs, offset: usize, limit: usize) -> (ContradictionsArtifact, usize) {
    let addresses = addresses(inputs);

    let mut extents: Vec<Extent> = Vec::new();
    let mut end_sources: Vec<EndSort> = Vec::new();
    let mut ends_found: Vec<Contradiction> = Vec::new();
    let mut names_found: Vec<Contradiction> = Vec::new();
    let mut name_sources: Vec<NameSort> = Vec::new();
    let mut not_compared: Vec<NotCompared> = Vec::new();
    let mut overrides: Vec<Override> = Vec::new();
    let stated_exports = stated_export_names(inputs.image);

    for &va in &addresses {
        let va = Va(va);
        // Ends: every extent stated for this start, by every source.
        let stated = stated_ends(inputs, va);
        for s in &stated {
            for by in &s.by {
                push_once(&mut end_sources, EndSort::from(*by));
            }
            extents.push(Extent { start: va, end: s.end, by: s.by.clone() });
        }
        if stated.len() > 1 {
            ends_found.push(Contradiction::End { start: va, ends: stated });
        }

        // Names: every layer's, the user's apart.
        let all = inputs.names.every_name_at(va);
        let verbatim = inputs.ctx.arch.indexed_function(va).is_some();
        let mut compared: Vec<ComparedName> = Vec::new();
        for n in &all {
            let source = crate::why::name_source(n.layer);
            match n.layer {
                NameLayer::Local(LocalLayer::User) => continue,
                NameLayer::Local(LocalLayer::Rtti) => push_not_compared(&mut not_compared, source, RTTI_NAMES_A_SLOT),
                NameLayer::Image(ImageName::Table(SymbolTable::Exports)) if stated_exports.as_ref().is_some_and(|s| !s.contains(&n.name)) => {
                    push_not_compared(&mut not_compared, source, ORDINAL_ONLY)
                }
                _ => {
                    push_once(&mut name_sources, NameSort::from(source));
                    compared.push(ComparedName { source, name: n.name.clone(), compared_as: compared_as(n, verbatim) });
                }
            }
        }
        if disagree(&compared) {
            names_found.push(Contradiction::Name { addr: va, names: compared });
        }
        if let Some(user) = all.iter().find(|n| n.layer == NameLayer::Local(LocalLayer::User))
            && let Some(other) = all.iter().find(|n| n.layer != NameLayer::Local(LocalLayer::User))
        {
            overrides.push(Override {
                addr: va,
                name: user.name.clone(),
                overrode: AlsoNamed { source: crate::why::name_source(other.layer), name: other.name.clone() },
            });
        }
    }

    let overlaps = overlaps(&mut extents);
    let findings: Option<Vec<Contradiction>> = inputs.image.map(|img| {
        img.image()
            .findings()
            .iter()
            .filter_map(|f| match f {
                Finding::Contradiction { what } => Some(Contradiction::Image { what: what.clone() }),
                Finding::StrictParseRefused { .. } | Finding::PartNotRead { .. } => None,
            })
            .collect()
    });

    let any_extent = !end_sources.is_empty();
    let kinds = Kinds {
        end: report(any_extent.then_some(ends_found.len()), NO_END_STATED, end_sources.clone(), Vec::new()),
        overlap: report(any_extent.then_some(overlaps.len()), NO_END_STATED, end_sources, Vec::new()),
        name: report((name_sources.len() > 1).then_some(names_found.len()), NAMED_BY_FEWER_THAN_TWO, name_sources, not_compared),
        image: report(findings.as_ref().map(Vec::len), NOT_AN_IMAGE, findings.as_ref().map(|_| vec![FindingsOf::ImageReader]).unwrap_or_default(), Vec::new()),
    };

    // Grouped by kind, in the order `Kinds` lists them.
    let all: Vec<Contradiction> = ends_found.into_iter().chain(overlaps).chain(names_found).chain(findings.unwrap_or_default()).collect();
    let total = all.len();
    let take = if limit == 0 { usize::MAX } else { limit };
    let page: Vec<Contradiction> = all.into_iter().skip(offset).take(take).collect();
    let artifact = ContradictionsArtifact {
        kinds,
        overrides: Overrides { count: overrides.len(), at: overrides },
        count: page.len(),
        contradictions: page,
    };
    (artifact, total)
}

fn report<S>(count: Option<usize>, why_not: &'static str, sources: Vec<S>, not_compared: Vec<NotCompared>) -> KindReport<S> {
    let state = match count {
        Some(count) => Checked::Checked { count },
        None => Checked::NotChecked { why: why_not },
    };
    KindReport { state, sources, not_compared }
}

/// The addresses asked about, in address order: every start the function list
/// holds, every start the stated functions hold, and every address a layer
/// that can list what it names names a function at or states a length for.
fn addresses(inputs: &Inputs) -> BTreeSet<u64> {
    let mut out = inputs.names.listed_starts();
    out.extend(inputs.listed.iter().map(|e| e.va.0));
    out.extend(inputs.ctx.functions.map_or(&[][..], |f| f.extents).iter().map(|f| f.start.0));
    out
}

/// Every end stated for a function at `va`, each with everything that states
/// it, in address order of the end: the extents the stated functions carry,
/// then every length every name layer states.
fn stated_ends(inputs: &Inputs, va: Va) -> Vec<StatedEnd> {
    let mut by_end: BTreeMap<u64, Vec<EndBy>> = BTreeMap::new();
    let extents = inputs.ctx.functions.map_or(&[][..], |f| f.extents);
    let from = extents.partition_point(|f| f.start < va);
    for f in extents[from..].iter().take_while(|f| f.start == va).filter(|f| f.end > f.start) {
        let by = by_end.entry(f.end.0).or_default();
        for s in f.stated_by.iter() {
            push_once(by, EndBy::Declared(crate::why::declared(*s)));
        }
    }
    for (len, layer) in inputs.names.every_size_at(va) {
        if len == 0 {
            continue;
        }
        let Some(end) = va.0.checked_add(len) else { continue };
        push_once(by_end.entry(end).or_default(), crate::why::size_by(layer));
    }
    by_end.into_iter().map(|(end, by)| StatedEnd { end: Va(end), by }).collect()
}

/// Every pair of extents with different starts where the first reaches past
/// the second's start. `extents` is sorted here.
fn overlaps(extents: &mut [Extent]) -> Vec<Contradiction> {
    extents.sort_by_key(|e| (e.start, e.end));
    let mut out = Vec::new();
    let mut open: Vec<usize> = Vec::new();
    for (j, second) in extents.iter().enumerate() {
        open.retain(|&i| extents[i].end > second.start);
        for &i in &open {
            if extents[i].start < second.start {
                out.push(Contradiction::Overlap { first: extents[i].clone(), second: second.clone() });
            }
        }
        open.push(j);
    }
    out
}

/// The form a name is compared in (see [`ComparedName::compared_as`]).
fn compared_as(n: &LayerName, verbatim: bool) -> String {
    if verbatim {
        return n.name.clone();
    }
    let bare = match n.layer {
        NameLayer::Image(ImageName::Table(SymbolTable::Static | SymbolTable::Dynamic)) => n0xis_core::elf_unversioned(&n.name),
        _ => n.name.as_str(),
    };
    n0xis_core::qualified_name_only(bare).unwrap_or_else(|| bare.to_string())
}

/// Whether two of the sources give the address names with nothing in common.
/// Names one source gives an address are its aliases: two sources agree when
/// any name of one is a name of the other.
fn disagree(names: &[ComparedName]) -> bool {
    let mut by_source: Vec<(NameSource, HashSet<&str>)> = Vec::new();
    for n in names {
        match by_source.iter_mut().find(|(s, _)| *s == n.source) {
            Some((_, set)) => {
                set.insert(&n.compared_as);
            }
            None => by_source.push((n.source, HashSet::from([n.compared_as.as_str()]))),
        }
    }
    by_source.iter().enumerate().any(|(i, (_, a))| by_source[i + 1..].iter().any(|(_, b)| a.is_disjoint(b)))
}

/// The names the image's export table states, where it was read: an
/// export-table name not among them is a stand-in for an export with no name.
fn stated_export_names(image: Option<&ImageSource>) -> Option<HashSet<String>> {
    let exports = image?.image().exports().read()?;
    Some(exports.iter().filter_map(|e| e.name.clone()).collect())
}

fn push_once<T: PartialEq>(into: &mut Vec<T>, item: T) {
    if !into.contains(&item) {
        into.push(item);
    }
}

fn push_not_compared(into: &mut Vec<NotCompared>, source: NameSource, why: &'static str) {
    let source = NameSort::from(source);
    if !into.iter().any(|n| n.source == source && n.why == why) {
        into.push(NotCompared { source, why });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(start: u64, end: u64) -> Extent {
        Extent { start: Va(start), end: Va(end), by: Vec::new() }
    }

    fn pairs(found: &[Contradiction]) -> Vec<(u64, u64)> {
        found
            .iter()
            .map(|c| match c {
                Contradiction::Overlap { first, second } => (first.start.0, second.start.0),
                other => panic!("not an overlap: {other:?}"),
            })
            .collect()
    }

    /// Back to back is not an overlap, one start with two ends is not one
    /// either (that is `end`), and a long extent overlaps every start it
    /// covers.
    #[test]
    fn an_overlap_is_a_start_inside_another_extent() {
        let mut all = vec![ext(0x10, 0x20), ext(0x20, 0x30), ext(0x20, 0x28), ext(0x40, 0x80), ext(0x50, 0x60), ext(0x70, 0x90)];
        assert_eq!(pairs(&overlaps(&mut all)), vec![(0x40, 0x50), (0x40, 0x70)]);
    }

    fn named(table: SymbolTable, name: &str) -> ComparedName {
        let n = LayerName { layer: NameLayer::Image(ImageName::Table(table)), name: name.into() };
        ComparedName { source: crate::why::name_source(n.layer), name: n.name.clone(), compared_as: compared_as(&n, false) }
    }

    /// An alias is not a disagreement, a version suffix is not one, a mangled
    /// name agrees with the name it stands for, and two names with nothing in
    /// common are one.
    #[test]
    fn sources_disagree_only_when_they_share_no_name() {
        let alias = [named(SymbolTable::Static, "__libc_malloc"), named(SymbolTable::Static, "malloc"), named(SymbolTable::Dynamic, "malloc")];
        assert!(!disagree(&alias));
        let versioned = [named(SymbolTable::Static, "memcpy@@GLIBC_2.14"), named(SymbolTable::Dynamic, "memcpy")];
        assert!(!disagree(&versioned));
        let mangled = [named(SymbolTable::Exports, "?isNull@QPixmap@@QEBA_NXZ"), named(SymbolTable::Static, "_ZNK7QPixmap6isNullEv")];
        assert_eq!(mangled[0].compared_as, "QPixmap::isNull");
        assert!(!disagree(&mangled));
        let different = [named(SymbolTable::Static, "foo"), named(SymbolTable::Dynamic, "bar")];
        assert!(disagree(&different));
        let one_source = [named(SymbolTable::Static, "foo"), named(SymbolTable::Static, "bar")];
        assert!(!disagree(&one_source), "two names in one table are aliases");
    }
}
