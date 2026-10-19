// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The `name` custom section: the names a producer kept for the module, its
//! functions, their locals and labels, and (the extended name section) its
//! types, tables, memories, globals and segments.
//!
//! A custom section does not make a module malformed, and the format says a
//! broken name section may be ignored. So nothing here is an [`Error`] of the
//! module: a subsection that cannot be read is left out whole and recorded as
//! a [`NameProblem`], and the subsections around it are still read, because
//! each one states its own size.

use std::collections::BTreeMap;

use crate::error::{Error, Problem};
use crate::reader::Reader;
use crate::types::{DataIdx, ElemIdx, FuncIdx, GlobalIdx, LocalIdx, MemIdx, TableIdx, TypeIdx};

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
    /// A subsection id this reader does not know. Left out.
    UnknownSubsection { id: u8 },
    /// A subsection that could not be read, or whose contents do not fill its
    /// stated size. Left out whole.
    Subsection { id: u8, error: Error },
    /// The subsections' own framing broke (a size past the section's end);
    /// nothing after this point was read.
    Framing { error: Error },
    /// Two names for one index in one map; the first is kept.
    Duplicate { subsection: u8, index: u32 },
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

fn place<K: Ord>(
    map: &mut BTreeMap<K, String>,
    entries: Vec<Assoc>,
    key: impl Fn(u32) -> K,
    subsection: u8,
    problems: &mut Vec<NameProblem>,
) {
    for (index, name) in entries {
        if let std::collections::btree_map::Entry::Vacant(slot) = map.entry(key(index)) {
            slot.insert(name);
        } else {
            problems.push(NameProblem::Duplicate { subsection, index });
        }
    }
}

fn place_indirect<K: Ord, L: Ord>(
    map: &mut BTreeMap<K, BTreeMap<L, String>>,
    entries: Vec<(u32, Vec<Assoc>)>,
    outer: impl Fn(u32) -> K,
    inner: impl Fn(u32) -> L + Copy,
    subsection: u8,
    problems: &mut Vec<NameProblem>,
) {
    for (index, names) in entries {
        if map.contains_key(&outer(index)) {
            problems.push(NameProblem::Duplicate { subsection, index });
            continue;
        }
        let mut inner_map = BTreeMap::new();
        place(&mut inner_map, names, inner, subsection, problems);
        map.insert(outer(index), inner_map);
    }
}

/// The highest subsection id read here: 0 module, 1 functions, 2 locals,
/// 3 labels, 4 types, 5 tables, 6 memories, 7 globals, 8 element segments,
/// 9 data segments.
const LAST_KNOWN_SUBSECTION: u8 = 9;

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
            problems.push(NameProblem::UnknownSubsection { id });
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
            Err(r.error(r.offset(), Problem::SectionSize { id, declared: size, used }))
        }
    };
    match id {
        0 => {
            let name = r.name()?;
            filled(r)?;
            names.module = Some(name);
        }
        2 | 3 => {
            let m = indirect_name_map(r)?;
            filled(r)?;
            if id == 2 {
                place_indirect(&mut names.locals, m, FuncIdx, LocalIdx, id, problems);
            } else {
                place_indirect(&mut names.labels, m, FuncIdx, |i| i, id, problems);
            }
        }
        _ => {
            let m = name_map(r)?;
            filled(r)?;
            match id {
                1 => place(&mut names.functions, m, FuncIdx, id, problems),
                4 => place(&mut names.types, m, TypeIdx, id, problems),
                5 => place(&mut names.tables, m, TableIdx, id, problems),
                6 => place(&mut names.memories, m, MemIdx, id, problems),
                7 => place(&mut names.globals, m, GlobalIdx, id, problems),
                8 => place(&mut names.elements, m, ElemIdx, id, problems),
                // 9, the last id read here: the caller left out the rest.
                _ => place(&mut names.data, m, DataIdx, id, problems),
            }
        }
    }
    Ok(())
}
