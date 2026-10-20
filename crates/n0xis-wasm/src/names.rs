// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The `name` custom section: the names a producer kept for the module, its
//! functions and their locals, its types and the fields of its structure
//! types, and its tags, which are the subsections the WebAssembly 3.0
//! custom-sections appendix defines (0 module, 1 functions, 2 locals, 4
//! types, 10 fields, 11 tags); and the labels of its functions, its tables,
//! memories, globals, and element and data segments, which are the extended
//! name section's (3 labels, 5 tables, 6 memories, 7 globals, 8 element
//! segments, 9 data segments) and which wasm-tools writes.
//!
//! A custom section does not make a module malformed, and the format says a
//! broken name section may be ignored. So nothing here is an [`Error`] of the
//! module: a subsection that cannot be read is left out whole and recorded as
//! a [`NameProblem`], and the subsections around it are still read, because
//! each one states its own size.

use std::collections::BTreeMap;

use crate::error::{Error, Problem};
use crate::reader::Reader;
use crate::types::{DataIdx, ElemIdx, FieldIdx, FuncIdx, GlobalIdx, LocalIdx, MemIdx, TableIdx, TagIdx, TypeIdx};

/// What an inner map of an indirect name map belongs to. Locals and labels
/// are listed by function, field names by type: two index spaces, so the
/// index is typed by the one it is in and cannot be read as the other's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Within {
    /// The map of a function's locals (subsection 2) or labels (3).
    Function(FuncIdx),
    /// The map of a structure type's field names (subsection 10).
    Type(TypeIdx),
}

impl From<FuncIdx> for Within {
    fn from(f: FuncIdx) -> Self {
        Within::Function(f)
    }
}

impl From<TypeIdx> for Within {
    fn from(t: TypeIdx) -> Self {
        Within::Type(t)
    }
}

/// The names a module's `name` section gives, by index.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Names {
    pub module: Option<String>,
    pub functions: BTreeMap<FuncIdx, String>,
    pub locals: BTreeMap<FuncIdx, BTreeMap<LocalIdx, String>>,
    /// Labels by function, numbered as the function's blocks open (not by
    /// branch depth).
    pub labels: BTreeMap<FuncIdx, BTreeMap<u32, String>>,
    pub types: BTreeMap<TypeIdx, String>,
    pub tables: BTreeMap<TableIdx, String>,
    pub memories: BTreeMap<MemIdx, String>,
    pub globals: BTreeMap<GlobalIdx, String>,
    pub elements: BTreeMap<ElemIdx, String>,
    pub data: BTreeMap<DataIdx, String>,
    /// Field names by structure type.
    pub fields: BTreeMap<TypeIdx, BTreeMap<FieldIdx, String>>,
    pub tags: BTreeMap<TagIdx, String>,
}

/// What was wrong in a `name` section, and what was left out because of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameProblem {
    /// A second `name` section; only the first is read.
    Repeated,
    /// A `name` section before a standard section; the format places it after
    /// the data section. It is read all the same.
    BeforeStandardSection { id: u8 },
    /// A subsection whose id is not above the previous one: each appears at
    /// most once, in increasing order. Left out.
    SubsectionOrder { id: u8, after: u8 },
    /// A subsection id not read here: one above 11 (tag names), the last the
    /// format defines. Left out.
    SubsectionNotRead { id: u8 },
    /// A subsection that could not be read, or whose contents do not fill its
    /// stated size. Left out whole.
    Subsection { id: u8, error: Error },
    /// The subsections' own framing broke (a size past the section's end);
    /// nothing after this point was read.
    Framing { error: Error },
    /// An index not above the one listed before it in its map: the format
    /// lists each index once, in increasing order. `within` is `None` for a
    /// top-level map (the functions, or the outer list of an indirect map), and
    /// names the function or the type whose inner map it is otherwise. A name
    /// for an index already named is left out, so the first stays; any other
    /// is kept.
    IndexOrder { subsection: u8, within: Option<Within>, index: u32 },
}

/// A name and where it was found, before being placed in a map.
type Assoc = (u32, String);

/// `vec(idx name)`. Each entry is at least two bytes.
fn name_map(r: &mut Reader) -> Result<Vec<Assoc>, Error> {
    let n = r.count(2)?;
    let mut out = Vec::new();
    for _ in 0..n {
        let index = r.u32()?;
        out.push((index, r.name()?));
    }
    Ok(out)
}

/// `vec(idx namemap)`. Each entry is at least two bytes.
fn indirect_name_map(r: &mut Reader) -> Result<Vec<(u32, Vec<Assoc>)>, Error> {
    let n = r.count(2)?;
    let mut out = Vec::new();
    for _ in 0..n {
        let index = r.u32()?;
        out.push((index, name_map(r)?));
    }
    Ok(out)
}

/// Whether `index` breaks the increasing order after `previous`; recorded if so.
fn out_of_order(
    previous: &mut Option<u32>,
    index: u32,
    subsection: u8,
    within: Option<Within>,
    problems: &mut Vec<NameProblem>,
) {
    if previous.is_some_and(|p| index <= p) {
        problems.push(NameProblem::IndexOrder { subsection, within, index });
    }
    *previous = Some(index);
}

fn place<K: Ord>(
    map: &mut BTreeMap<K, String>,
    entries: Vec<Assoc>,
    key: impl Fn(u32) -> K,
    subsection: u8,
    within: Option<Within>,
    problems: &mut Vec<NameProblem>,
) {
    let mut previous = None;
    for (index, name) in entries {
        out_of_order(&mut previous, index, subsection, within, problems);
        map.entry(key(index)).or_insert(name);
    }
}

/// An indirect map, placed by `outer`'s key, whose index space also names
/// each inner map in a [`NameProblem::IndexOrder`]: one key, so a map of
/// locals cannot be reported as within a type.
fn place_indirect<K: Ord + Copy + Into<Within>, L: Ord>(
    map: &mut BTreeMap<K, BTreeMap<L, String>>,
    entries: Vec<(u32, Vec<Assoc>)>,
    outer: impl Fn(u32) -> K,
    inner: impl Fn(u32) -> L + Copy,
    subsection: u8,
    problems: &mut Vec<NameProblem>,
) {
    let mut previous = None;
    for (index, names) in entries {
        out_of_order(&mut previous, index, subsection, None, problems);
        let key = outer(index);
        if map.contains_key(&key) {
            continue;
        }
        let mut inner_map = BTreeMap::new();
        place(&mut inner_map, names, inner, subsection, Some(key.into()), problems);
        map.insert(key, inner_map);
    }
}

/// The highest subsection id read here. The WebAssembly 3.0 custom-sections
/// appendix defines 0 (module), 1 (functions), 2 (locals), 4 (types), 10
/// (fields) and 11 (tags); 3 (labels) and 5 to 9 (tables, memories, globals,
/// element and data segments) are the extended name section's, which
/// wasm-tools writes.
const LAST_KNOWN_SUBSECTION: u8 = 11;

/// Read a `name` section's contents into `names`.
pub(crate) fn read(mut r: Reader, names: &mut Names, problems: &mut Vec<NameProblem>) {
    let mut last: Option<u8> = None;
    while !r.at_end() {
        let framed = (|| {
            let id = r.byte()?;
            let size = r.u32()?;
            Ok::<_, Error>((id, size, r.sub(size as usize)?))
        })();
        let (id, size, mut sub) = match framed {
            Ok(framed) => framed,
            Err(error) => {
                problems.push(NameProblem::Framing { error });
                return;
            }
        };
        if let Some(after) = last
            && id <= after
        {
            problems.push(NameProblem::SubsectionOrder { id, after });
            continue;
        }
        last = Some(id);
        if id > LAST_KNOWN_SUBSECTION {
            problems.push(NameProblem::SubsectionNotRead { id });
            continue;
        }
        if let Err(error) = subsection(id, size, &mut sub, names, problems) {
            problems.push(NameProblem::Subsection { id, error });
        }
    }
}

/// One subsection, read whole before any of it is kept.
fn subsection(id: u8, size: u32, r: &mut Reader, names: &mut Names, problems: &mut Vec<NameProblem>) -> Result<(), Error> {
    let filled = |r: &Reader| {
        if r.at_end() {
            Ok(())
        } else {
            let used = size as usize - r.remaining();
            Err(r.error(r.offset(), Problem::SubsectionSize { id, declared: size, used }))
        }
    };
    match id {
        0 => {
            let name = r.name()?;
            filled(r)?;
            names.module = Some(name);
        }
        2 | 3 | 10 => {
            let m = indirect_name_map(r)?;
            filled(r)?;
            match id {
                2 => place_indirect(&mut names.locals, m, FuncIdx, LocalIdx, id, problems),
                3 => place_indirect(&mut names.labels, m, FuncIdx, |i| i, id, problems),
                _ => place_indirect(&mut names.fields, m, TypeIdx, FieldIdx, id, problems),
            }
        }
        _ => {
            let m = name_map(r)?;
            filled(r)?;
            match id {
                1 => place(&mut names.functions, m, FuncIdx, id, None, problems),
                4 => place(&mut names.types, m, TypeIdx, id, None, problems),
                5 => place(&mut names.tables, m, TableIdx, id, None, problems),
                6 => place(&mut names.memories, m, MemIdx, id, None, problems),
                7 => place(&mut names.globals, m, GlobalIdx, id, None, problems),
                8 => place(&mut names.elements, m, ElemIdx, id, None, problems),
                9 => place(&mut names.data, m, DataIdx, id, None, problems),
                // 11, the last id read here: the caller left out the rest.
                _ => place(&mut names.tags, m, TagIdx, id, None, problems),
            }
        }
    }
    Ok(())
}
