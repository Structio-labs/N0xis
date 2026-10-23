// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `why --addr <va>`: for one address, what the engine states about the
//! function it is in, and **where each statement came from**, as a category
//! from a closed list (docs/design/WHY.md).
//!
//! **A reader, never a second discovery.** Every source here was recorded
//! where its rule fired — a start's sources by [`n0xis_core::discover_entries`],
//! an end's by [`n0xis_core::Discovered::end_of`], a name's layer by the name
//! composition ([`StaticNames`]) through the lookup that gave the name — and is
//! only translated into the answer's vocabulary here. Re-running the rules for
//! one address would be a copy of discovery, and a copy drifts.
//!
//! **No grade.** A category says what produced a fact, checkable by someone
//! else; it does not say how likely the fact is. A confidence number would be
//! a claim needing a measurement per rule.

use n0xis_contracts::Va;
use n0xis_core::{Ctx, Discovered, DiscoveredStart, EndFrom, NameFrom, StartSource, StatedBy};
use n0xis_sources::{ImageName, StartReason, SymbolTable};
use serde::Serialize;

use crate::annotation_syms::LocalLayer;
use crate::static_names::{NameLayer, SizeLayer, StaticNames};

/// `n0xis.why.v1`.
#[derive(Clone, Debug, Serialize)]
pub struct WhyArtifact {
    /// The address asked about.
    pub addr: Va,
    /// The function the address is in, or why there is none.
    pub function: Containing,
}

/// The function an address is in, or the statement that the function list has
/// none that contains it.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Containing {
    Found(Box<FunctionWhy>),
    None { why: String },
}

/// One function, each fact with its source.
#[derive(Clone, Debug, Serialize)]
pub struct FunctionWhy {
    /// Where the function starts, as `function discover` lists it.
    pub start: Va,
    /// The function's index, on an image whose functions are identified by
    /// index (a WebAssembly module), as `function discover` gives it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    /// Whether the address asked about is this start.
    pub addr_is_start: bool,
    /// Everything that found the start, in the order discovery ran: every
    /// declaration first, then every rule. Never empty.
    pub start_sources: Vec<StartCategory>,
    /// The end, with the one source the function list took it from.
    pub end: EndWhy,
    /// The name the function list gives it, the layer that gave it, and every
    /// other layer that names the start.
    pub name: NameWhy,
}

/// A table that states function extents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnwindTable {
    /// A PE32+ exception directory's `RUNTIME_FUNCTION` entries.
    Pdata,
    /// DWARF call-frame information: an FDE.
    EhFrame,
}

/// A declaration: the image, or a file built with it, says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum Declared {
    /// A PE export in an executable section.
    Export,
    /// An ELF `STT_FUNC` symbol.
    Symbol,
    /// An unwind table entry.
    Unwind { table: UnwindTable },
    /// A procedure in the PDB built with the image.
    Pdb,
    /// A WebAssembly function body, of function `function`.
    Body { function: u32 },
    /// A stub that only jumps through `slot` (an x86-64 PLT entry).
    Stub { slot: Va },
}

/// A rule of discovery found it: no declaration says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum Rule {
    /// The first instruction after a declared function's end.
    AfterDeclaredEnd,
    /// A linear sweep of the gap between two declared functions.
    GapSweep,
    /// A direct call names it; `from` is the first such call in the code
    /// scanned.
    CallTarget { from: Va },
    /// An entry pattern of the architecture matched.
    Prologue,
}

/// What found a start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum StartCategory {
    Declared(Declared),
    Rule(Rule),
}

/// Whose stated length an end is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SizeOf {
    /// An ELF symbol's `st_size`.
    StSize,
    /// The PDB's procedure length.
    Pdb,
    /// A managed index's.
    Managed,
    /// A signature database's.
    Flirt,
    /// The project's own names'.
    Project,
}

/// A stated length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum Length {
    SymbolSize { of: SizeOf },
}

/// What stated an end.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum EndBy {
    Declared(Declared),
    Length(Length),
}

/// The function's end and its source.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum EndWhy {
    /// An exclusive end something states.
    Stated {
        va: Va,
        #[serde(flatten)]
        by: EndBy,
        /// Other declarations of the same extent, when there are any.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        also: Vec<Declared>,
    },
    /// Nothing states one.
    NotStated(NotStated),
}

/// Nothing states the end: the control-flow graph decides it, by the
/// heuristic `ir cfg` applies.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum NotStated {
    NotStated { cfg: CfgEnd },
}

/// The end of the control-flow graph built from the start.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CfgEnd {
    End(Va),
    NotBuilt { why: String },
}

/// Which signature database a signature name came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Given {
    /// Kept in the project by `analyze --flirt`.
    Project,
    /// Named on the command (`--flirt`).
    Argument,
}

/// The layer a name came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum NameSource {
    /// The user's rename.
    User,
    /// Recovered from RTTI by `analyze`.
    Rtti,
    /// A signature match.
    Flirt { given_by: Given },
    /// The PDB built with the image.
    Pdb,
    /// A managed index.
    Managed,
    /// One of the image's symbol tables.
    Image { table: SymbolTable },
    /// A stub that only jumps through `slot`, named after the import the slot
    /// is bound to.
    Stub { slot: Va },
    /// Nothing names it: `sub_<address>`, or `func_<index>`.
    Fallback,
}

/// A function's name and where it came from.
#[derive(Clone, Debug, Serialize)]
pub struct NameWhy {
    /// As `function discover` lists it.
    pub name: String,
    #[serde(flatten)]
    pub source: NameSource,
    /// Every other layer that names the start, most trusted first, each with
    /// the name it gives, spelled as the list would. Empty when none does.
    pub also: Vec<AlsoNamed>,
}

/// Another layer's name for the same start.
#[derive(Clone, Debug, Serialize)]
pub struct AlsoNamed {
    #[serde(flatten)]
    pub source: NameSource,
    pub name: String,
}

/// An answer that cannot be given because two readings of one fact disagree.
/// Never expected: it would mean the composition handed to the function list
/// is not the one asked which layer named it.
#[derive(Debug)]
pub struct Inconsistent(pub String);

/// The answer for `addr`, from the function list `found` (as `function
/// discover` builds it over the same windows), the `Ctx` it was built with and
/// the name composition that `Ctx`'s symbols are. `cfg_end` builds the
/// control-flow graph of a start whose end nothing states, the way `ir cfg`
/// does.
pub fn answer(
    ctx: &Ctx,
    names: &StaticNames,
    found: &Discovered,
    addr: Va,
    cfg_end: &dyn Fn(Va) -> CfgEnd,
) -> Result<WhyArtifact, Inconsistent> {
    let function = match containing(ctx, names, found, addr, cfg_end)? {
        Located::In(entry, end) => Containing::Found(Box::new(FunctionWhy {
            start: entry.va,
            index: n0xis_core::function_index(ctx, entry.va),
            addr_is_start: addr == entry.va,
            start_sources: entry.sources.iter().map(|s| start_category(*s)).collect(),
            end,
            name: name_why(ctx, names, entry.va)?,
        })),
        Located::Outside(why) => Containing::None { why },
    };
    Ok(WhyArtifact { addr, function })
}

/// Where `addr` is in the function list.
enum Located<'a> {
    In(&'a DiscoveredStart, EndWhy),
    Outside(String),
}

/// The listed function `addr` lies in, and its end: the nearest start at or
/// below `addr` when its end (stated, or the graph's where none is) is past
/// `addr`; else the nearest earlier start whose **stated** end is past it (a
/// function another start lies inside). A start with no stated end before the
/// nearest one is not asked: that would build a graph for each.
fn containing<'a>(
    ctx: &Ctx,
    names: &StaticNames,
    found: &'a Discovered,
    addr: Va,
    cfg_end: &dyn Fn(Va) -> CfgEnd,
) -> Result<Located<'a>, Inconsistent> {
    let below = found.entries.partition_point(|e| e.va <= addr);
    let Some(nearest) = below.checked_sub(1).map(|i| &found.entries[i]) else {
        return Ok(Located::Outside(match found.entries.first() {
            Some(first) => format!("no listed function starts at or below {addr}; the first starts at {}", first.va),
            None => "the function list is empty".to_string(),
        }));
    };
    let end = end_why(ctx, names, nearest, cfg_end)?;
    if end_va(&end).is_some_and(|end| addr < end) {
        return Ok(Located::In(nearest, end));
    }
    for entry in found.entries[..below - 1].iter().rev() {
        if let Some((end, _)) = Discovered::end_of(ctx, entry)
            && addr < end
        {
            return Ok(Located::In(entry, end_why(ctx, names, entry, cfg_end)?));
        }
    }
    Ok(Located::Outside(match end_va(&end) {
        Some(end) => format!(
            "no listed function contains {addr}: the nearest start at or below it, {}, ends at {end}, and no earlier function's stated end is past it",
            nearest.va
        ),
        None => format!(
            "no listed function contains {addr}: nothing states an end for the nearest start at or below it, {}, and its control-flow graph was not built",
            nearest.va
        ),
    }))
}

fn end_va(end: &EndWhy) -> Option<Va> {
    match end {
        EndWhy::Stated { va, .. } => Some(*va),
        EndWhy::NotStated(NotStated::NotStated { cfg: CfgEnd::End(va) }) => Some(*va),
        EndWhy::NotStated(NotStated::NotStated { cfg: CfgEnd::NotBuilt { .. } }) => None,
    }
}

/// The end the function list gives `entry` ([`Discovered::end_of`], the rule
/// `function discover` uses), with its source; the graph's end where nothing
/// states one.
fn end_why(ctx: &Ctx, names: &StaticNames, entry: &DiscoveredStart, cfg_end: &dyn Fn(Va) -> CfgEnd) -> Result<EndWhy, Inconsistent> {
    Ok(match Discovered::end_of(ctx, entry) {
        // The symbol seam's length: the composition says which layer gave it.
        Some((va, EndFrom::SymbolSize)) => match names.size_layer(entry.va) {
            Some(layer) => EndWhy::Stated { va, by: size_by(layer), also: Vec::new() },
            None => {
                return Err(Inconsistent(format!(
                    "the function list's end of {} is a stated length that no layer of its names states",
                    entry.va
                )));
            }
        },
        Some((va, EndFrom::Stated(by))) => {
            EndWhy::Stated { va, by: EndBy::Declared(declared(by.first())), also: by.iter().skip(1).map(|b| declared(*b)).collect() }
        }
        None => EndWhy::NotStated(NotStated::NotStated { cfg: cfg_end(entry.va) }),
    })
}

/// The name the function list gives `start`, and the layer it came from.
fn name_why(ctx: &Ctx, names: &StaticNames, start: Va) -> Result<NameWhy, Inconsistent> {
    let (name, from) = n0xis_core::function_name_and_source(ctx, start);
    let layered = names.names_at(start);
    let also_of = |rest: &[crate::static_names::LayerName]| -> Vec<AlsoNamed> {
        rest.iter().map(|n| AlsoNamed { source: name_source(n.layer), name: n0xis_core::listed_name(ctx, start, &n.name) }).collect()
    };
    let source = match from {
        NameFrom::Symbol => {
            let Some(winner) = layered.first() else {
                return Err(Inconsistent(format!("{start} is named `{name}` by the symbol seam and by no layer of its names")));
            };
            if n0xis_core::listed_name(ctx, start, &winner.name) != name {
                return Err(Inconsistent(format!("{start} is listed as `{name}` and its names' first layer says `{}`", winner.name)));
            }
            return Ok(NameWhy { name, source: name_source(winner.layer), also: also_of(&layered[1..]) });
        }
        NameFrom::Import { slot } => NameSource::Stub { slot },
        NameFrom::Fallback => NameSource::Fallback,
    };
    Ok(NameWhy { name, source, also: also_of(&layered) })
}

fn start_category(s: StartSource) -> StartCategory {
    match s {
        StartSource::Stated(by) => StartCategory::Declared(declared(by)),
        StartSource::AfterDeclaredEnd => StartCategory::Rule(Rule::AfterDeclaredEnd),
        StartSource::GapSweep => StartCategory::Rule(Rule::GapSweep),
        StartSource::CallTarget { from } => StartCategory::Rule(Rule::CallTarget { from }),
        StartSource::Prologue => StartCategory::Rule(Rule::Prologue),
    }
}

fn declared(by: StatedBy) -> Declared {
    match by {
        StatedBy::Image(reason) => image_reason(reason),
        StatedBy::EhFrame => Declared::Unwind { table: UnwindTable::EhFrame },
        StatedBy::Pdb => Declared::Pdb,
    }
}

fn image_reason(reason: StartReason) -> Declared {
    match reason {
        StartReason::Export => Declared::Export,
        StartReason::Symbol => Declared::Symbol,
        StartReason::UnwindEntry => Declared::Unwind { table: UnwindTable::Pdata },
        StartReason::Stub { slot } => Declared::Stub { slot },
        StartReason::Body { function } => Declared::Body { function },
    }
}

fn size_by(layer: SizeLayer) -> EndBy {
    match layer {
        SizeLayer::Image(StartReason::Symbol) => EndBy::Length(Length::SymbolSize { of: SizeOf::StSize }),
        SizeLayer::Image(reason) => EndBy::Declared(image_reason(reason)),
        SizeLayer::Pdb => EndBy::Length(Length::SymbolSize { of: SizeOf::Pdb }),
        SizeLayer::Managed => EndBy::Length(Length::SymbolSize { of: SizeOf::Managed }),
        SizeLayer::Signatures => EndBy::Length(Length::SymbolSize { of: SizeOf::Flirt }),
        SizeLayer::Local => EndBy::Length(Length::SymbolSize { of: SizeOf::Project }),
    }
}

fn name_source(layer: NameLayer) -> NameSource {
    match layer {
        NameLayer::Local(LocalLayer::User) => NameSource::User,
        NameLayer::Local(LocalLayer::Rtti) => NameSource::Rtti,
        NameLayer::Local(LocalLayer::Flirt) => NameSource::Flirt { given_by: Given::Project },
        NameLayer::Pdb => NameSource::Pdb,
        NameLayer::Managed => NameSource::Managed,
        NameLayer::Image(ImageName::Table(table)) => NameSource::Image { table },
        NameLayer::Image(ImageName::Stub { slot }) => NameSource::Stub { slot },
        NameLayer::Signatures => NameSource::Flirt { given_by: Given::Argument },
    }
}
