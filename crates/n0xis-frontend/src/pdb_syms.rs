// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Names and function extents from a program database (PDB), for a PE image
//! whose CodeView record names one (ROADMAP gap-closing item 1, M1).
//!
//! **Which file.** These places are tried in order, and the first PDB whose
//! identity equals the image's own record is used (`n0xis_pdb` says which GUID
//! and which age are compared). A file that is there and does not match is
//! reported, never used:
//!
//! 1. beside the image, under the file name the linker wrote;
//! 2. the path the linker wrote, as written: it exists when the image was
//!    built on this machine;
//! 3. the project's symbol store, `.n0x/symbols/<name>/<GUID><age>/<name>`,
//!    the layout a symbol server uses ([`store_path`]).
//!
//! **Checked against the image.** A function the PDB places outside every
//! range the image marks executable, or whose stated length runs past the end
//! of its range, is left out and counted: a PDB is not trusted on its own.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use n0xis_contracts::{SymKind, Symbol, Va};
use n0xis_pdb::{Guid, Identity, Skipped};
use n0xis_sources::{MemorySource, SourceId, StaticImage, SymbolProvider};

/// The names a matched PDB gives, by function start.
#[derive(Debug)]
pub struct PdbSymbols {
    module: String,
    /// Start VA → (stated length, name).
    by_start: BTreeMap<u64, (Option<u64>, String)>,
    /// Which PDB: a cache keyed on names must be rebuilt when one appears.
    fingerprint: String,
}

impl PdbSymbols {
    /// Every function the PDB places, as `(start, end)`; `end == start` when no
    /// length is stated (a public name gives none).
    pub fn functions(&self) -> Vec<(Va, Va)> {
        self.by_start.iter().map(|(&start, (len, _))| (Va(start), Va(start + len.unwrap_or(0)))).collect()
    }

    pub fn len(&self) -> usize {
        self.by_start.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_start.is_empty()
    }
}

impl SymbolProvider for PdbSymbols {
    /// A name at a function's start, as the image's own exports are given.
    fn symbol_at(&self, va: Va) -> Option<Symbol> {
        self.by_start.get(&va.0).map(|(_, name)| Symbol { va, module: self.module.clone(), name: name.clone(), kind: SymKind::Function })
    }

    /// The length a procedure record states.
    fn symbol_size(&self, va: Va) -> Option<u64> {
        self.by_start.get(&va.0).and_then(|(len, _)| *len)
    }

    fn symbol_fingerprint(&self) -> String {
        self.fingerprint.clone()
    }
}

/// One place a PDB was looked for, and what was there.
#[derive(Debug, Clone)]
pub enum Looked {
    Absent(PathBuf),
    /// The PDB of another build: its identity does not match.
    Other { path: PathBuf, found: Identity },
    Unreadable { path: PathBuf, why: String },
}

/// What a matching PDB brought, after the check against the image.
#[derive(Debug)]
pub struct Matched {
    pub path: PathBuf,
    pub symbols: PdbSymbols,
    /// Functions placed with a stated length.
    pub with_length: usize,
    /// What the reader left out (see `n0xis_pdb::Skipped`).
    pub skipped: Skipped,
    /// Functions the PDB places outside the image's code, or running past the
    /// end of it: left out.
    pub outside_code: usize,
}

#[derive(Debug)]
pub enum PdbLookup {
    /// Not a PE, or a PE with no CodeView record: no PDB is named.
    NotNamed,
    Matched { wanted: Identity, matched: Matched, looked: Vec<Looked> },
    NotFound { wanted: Identity, pdb_name: String, looked: Vec<Looked> },
}

impl PdbLookup {
    pub fn symbols(&self) -> Option<&PdbSymbols> {
        match self {
            PdbLookup::Matched { matched, .. } => Some(&matched.symbols),
            _ => None,
        }
    }
}

type Memo = Option<(SourceId, Arc<PdbLookup>)>;
static MEMO: Mutex<Memo> = Mutex::new(None);

/// The PDB for `image`, looked for once per image in a process.
pub fn lookup(image: &StaticImage) -> Arc<PdbLookup> {
    let id = image.identity();
    if let Some(id) = id
        && let Ok(memo) = MEMO.lock()
        && let Some((kept, found)) = memo.as_ref()
        && *kept == id
    {
        return found.clone();
    }
    let found = Arc::new(look(image));
    if let Some(id) = id
        && let Ok(mut memo) = MEMO.lock()
    {
        *memo = Some((id, found.clone()));
    }
    found
}

/// Forget what was found, so the next lookup reads the places again: a PDB
/// was just added to the store.
pub fn forget() {
    if let Ok(mut memo) = MEMO.lock() {
        *memo = None;
    }
}

/// The identity an image's CodeView record names, and the PDB's file name.
pub fn wanted(image: &StaticImage) -> Option<(Identity, String)> {
    let cv = image.codeview()?;
    // The file name, whichever separator the building machine used.
    let name = cv.pdb_path.rsplit(['/', '\\']).next().unwrap_or_default().to_string();
    Some((Identity { guid: Guid::from_codeview(cv.guid), age: cv.age }, name))
}

/// Where a symbol store keeps the PDB with `identity`.
pub fn store_path(store: &Path, pdb_name: &str, identity: &Identity) -> PathBuf {
    store.join(pdb_name).join(identity.store_key()).join(pdb_name)
}

/// The places [`lookup`] tries, in order (see the module notes).
pub fn places(image: &StaticImage) -> Vec<PathBuf> {
    let Some((identity, name)) = wanted(image) else { return Vec::new() };
    let mut places = Vec::new();
    if !name.is_empty()
        && let Some(dir) = image.module().path.as_deref().map(Path::new).and_then(Path::parent)
    {
        places.push(dir.join(&name));
    }
    if let Some(cv) = image.codeview() {
        let written = PathBuf::from(&cv.pdb_path);
        if written.is_absolute() {
            places.push(written);
        }
    }
    if !name.is_empty()
        && let Ok(root) = n0xis_project::resolve()
    {
        places.push(store_path(&root.symbols_dir(), &name, &identity));
    }
    let mut seen = Vec::new();
    places.retain(|p| {
        let fresh = !seen.contains(p);
        seen.push(p.clone());
        fresh
    });
    places
}

fn look(image: &StaticImage) -> PdbLookup {
    let Some((wanted, pdb_name)) = wanted(image) else { return PdbLookup::NotNamed };
    let mut looked = Vec::new();
    for path in places(image) {
        if !path.is_file() {
            looked.push(Looked::Absent(path));
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) => {
                looked.push(Looked::Unreadable { path, why: e.to_string() });
                continue;
            }
        };
        // The identity first: a PDB of another build is never read further.
        match n0xis_pdb::identity(&bytes) {
            Ok(found) if found == wanted => {}
            Ok(found) => {
                looked.push(Looked::Other { path, found });
                continue;
            }
            Err(e) => {
                looked.push(Looked::Unreadable { path, why: e.to_string() });
                continue;
            }
        }
        match n0xis_pdb::read(&bytes) {
            Ok(contents) => return PdbLookup::Matched { wanted, matched: placed(image, path, contents), looked },
            Err(e) => looked.push(Looked::Unreadable { path, why: e.to_string() }),
        }
    }
    PdbLookup::NotFound { wanted, pdb_name, looked }
}

/// The PDB's functions that the image's own layout bears out.
fn placed(image: &StaticImage, path: PathBuf, contents: n0xis_pdb::Contents) -> Matched {
    let base = image.image_base().0;
    let code = image.code_ranges();
    let mut by_start = BTreeMap::new();
    let (mut with_length, mut outside_code) = (0, 0);
    for function in contents.functions {
        let start = base.saturating_add(u64::from(function.rva));
        let len = function.len.map(u64::from);
        let inside = code.iter().any(|&(va, size)| {
            let end = va.0.saturating_add(size);
            start >= va.0 && start < end && len.is_none_or(|len| start.saturating_add(len) <= end)
        });
        if !inside {
            outside_code += 1;
            continue;
        }
        with_length += usize::from(len.is_some());
        by_start.insert(start, (len, function.name));
    }
    let symbols = PdbSymbols { module: image.module().name.clone(), by_start, fingerprint: format!("pdb:{}", contents.identity.store_key()) };
    Matched { path, symbols, with_length, skipped: contents.skipped, outside_code }
}

/// What `profile` says about the image's PDB: which one it names, where it was
/// looked for and what was there, and what a match brought. `null` when the
/// image names none.
pub fn report(image: &StaticImage) -> serde_json::Value {
    use serde_json::{Value, json};
    let Some((wanted, name)) = wanted(image) else { return Value::Null };
    let written = image.codeview().map(|cv| cv.pdb_path.clone()).unwrap_or_default();
    let places = |looked: &[Looked]| -> Vec<Value> {
        looked
            .iter()
            .map(|place| match place {
                Looked::Absent(path) => json!({ "path": path.display().to_string(), "found": "nothing" }),
                Looked::Other { path, found } => json!({
                    "path": path.display().to_string(),
                    "found": "the PDB of another build",
                    "guid": found.guid.to_string(),
                    "age": found.age,
                }),
                Looked::Unreadable { path, why } => json!({ "path": path.display().to_string(), "found": "an unreadable file", "why": why }),
            })
            .collect()
    };
    let found = lookup(image);
    let (matched, looked) = match found.as_ref() {
        PdbLookup::Matched { matched, looked, .. } => (
            json!({
                "path": matched.path.display().to_string(),
                "functions": matched.symbols.len(),
                "with_length": matched.with_length,
                "outside_code": matched.outside_code,
                "skipped": {
                    "streams": matched.skipped.streams,
                    "unplaced": matched.skipped.unplaced,
                    "names": matched.skipped.names,
                },
            }),
            places(looked),
        ),
        PdbLookup::NotFound { looked, .. } => (Value::Null, places(looked)),
        PdbLookup::NotNamed => (Value::Null, Vec::new()),
    };
    json!({
        "pdb": name,
        "written_path": written,
        "guid": wanted.guid.to_string(),
        "age": wanted.age,
        "store_key": wanted.store_key(),
        "matched": matched,
        "looked": looked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> StaticImage {
        StaticImage::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../n0xis-pdb/tests/fixtures/pdbtarget.exe")).expect("the fixture")
    }

    /// The PDB is checked against the image: a function it places in a
    /// section the image does not mark executable, or whose stated length runs
    /// past the end of the code, is left out and counted.
    #[test]
    fn a_function_the_image_does_not_bear_out_is_left_out() {
        let image = fixture();
        let identity = Identity { guid: Guid::from_codeview([0; 16]), age: 1 };
        let function = |rva, len: Option<u32>, name: &str| n0xis_pdb::Function { rva, len, name: name.into(), aliases: 0 };
        let (text, text_len) = image.code_ranges().into_iter().next().map(|(va, len)| (va.0 - image.image_base().0, len)).expect("a code range");
        let contents = n0xis_pdb::Contents {
            identity,
            functions: vec![
                function(0x1580, Some(7), "record_failure"),
                // In `.rdata`, which the image does not mark executable.
                function(0x3000, None, "in_data"),
                // Starts in the code and runs past its end.
                function((text + text_len - 4) as u32, Some(16), "past_the_end"),
            ],
            skipped: Skipped::default(),
        };
        let matched = placed(&image, PathBuf::from("pdbtarget.pdb"), contents);
        assert_eq!((matched.symbols.len(), matched.outside_code, matched.with_length), (1, 2, 1));
        let start = Va(image.image_base().0 + 0x1580);
        assert_eq!(matched.symbols.symbol_at(start).map(|s| s.name), Some("record_failure".into()));
        assert_eq!(matched.symbols.symbol_size(start), Some(7));
    }
}
