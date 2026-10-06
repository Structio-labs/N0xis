// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! # n0xis-pdb — program databases
//!
//! What a Windows image's PDB says about the image's functions: where each one
//! starts, how long it is when the compiler recorded that, and what it is
//! called. The reader underneath (`pdb2`) stays behind this crate's own types,
//! so replacing it touches this file and nothing else.
//!
//! ## Which PDB belongs to which image
//!
//! An image's CodeView record names a GUID and an age. The PDB built with it
//! carries the same GUID in its information stream and the same age in its
//! debug-information (DBI) stream. The information stream has an age of its
//! own, and it is **not** the one to compare: rewriting a PDB after the build
//! (stripping it to its public part for a symbol server, say) raises it.
//! Measured on five system DLLs and the public PDBs their vendor serves: every
//! image records age 1, every DBI stream says 1, and the information streams
//! say 2, 4, 3, 3 and 2, so matching on that age would refuse all five.
//! [`Identity`] is the pair to compare, and [`Identity::store_key`] is where a
//! symbol store keeps the file.
//!
//! ## Untrusted input
//!
//! A PDB comes from beside the image, from a download, from anywhere, so it is
//! read as hostile. A file whose identity cannot be read is an [`Error`]. A
//! stream that breaks partway, a record the PDB's own address map cannot place
//! and a name too long to be real are left out and counted in [`Skipped`],
//! never guessed around, so a caller can say what was not read. Nothing here is
//! sized from a count the file states. `tests/mutated.rs` reads thousands of
//! corrupted copies of a real PDB under an allocation cap and a deadline.
//!
//! The reader underneath trusts sizes it reads: it adds the DBI header's
//! substream sizes without checking, which a cleared page of the file
//! overflows. The workspace builds it with overflow checks on in release too,
//! so it stops instead of reading on from a wrapped offset, and every call
//! into it here is guarded: a stop is an [`Error::Unreadable`], not a crash of
//! the program that asked.

use std::collections::BTreeMap;
use std::io::Cursor;

use pdb2::FallibleIterator;

/// The longest name kept. A longer one is left out rather than cut, because a
/// cut name is a wrong name. MSVC shortens decorated names well before this.
pub const MAX_NAME_BYTES: usize = 16 * 1024;

/// A GUID as its four fields, the way it is printed and keyed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// From the 16 bytes an image's CodeView record holds: the first three
    /// fields little-endian, the last eight bytes as they are.
    pub fn from_codeview(bytes: [u8; 16]) -> Self {
        let mut data4 = [0u8; 8];
        data4.copy_from_slice(&bytes[8..]);
        Guid {
            data1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            data2: u16::from_le_bytes([bytes[4], bytes[5]]),
            data3: u16::from_le_bytes([bytes[6], bytes[7]]),
            data4,
        }
    }
}

impl std::fmt::Display for Guid {
    /// `8D8D6800-F0CC-C475-4C4C-44205044422E`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let d = &self.data4;
        write!(
            f,
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data1, self.data2, self.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        )
    }
}

/// What ties a PDB to the image built with it (see the crate notes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Identity {
    pub guid: Guid,
    pub age: u32,
}

impl Identity {
    /// The directory a symbol store keeps the PDB under, beneath its file name:
    /// the GUID's 32 hex digits, then the age in hex, upper case.
    pub fn store_key(&self) -> String {
        let g = &self.guid;
        let mut key = format!("{:08X}{:04X}{:04X}", g.data1, g.data2, g.data3);
        for b in g.data4 {
            key.push_str(&format!("{b:02X}"));
        }
        key.push_str(&format!("{:X}", self.age));
        key
    }
}

/// A function the PDB places in the image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    /// Where it starts, relative to the image base.
    pub rva: u32,
    /// Its length in bytes, when a procedure record states it. The public
    /// table gives an address and a name only, and so does a public PDB.
    pub len: Option<u32>,
    /// The name as the PDB writes it: the public (decorated) name when there is
    /// one, the procedure's name otherwise.
    pub name: String,
    /// How many other names the PDB places at the same address: identical code
    /// folded into one body. None is preferred; `name` is the first by byte order.
    pub aliases: usize,
}

/// What was left out, and why. Each count is a fact about the file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Skipped {
    /// Streams that broke partway (the public table, or a module's symbols);
    /// what came before the break was kept.
    pub streams: usize,
    /// Records whose section and offset the PDB's own address map does not place.
    pub unplaced: usize,
    /// Records with no name, or one longer than [`MAX_NAME_BYTES`].
    pub names: usize,
}

/// What a PDB says about an image's functions.
#[derive(Clone, Debug)]
pub struct Contents {
    pub identity: Identity,
    /// One entry per address, by address.
    pub functions: Vec<Function>,
    pub skipped: Skipped,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Not a PDB this reader can open, or one whose structure is broken where
    /// the identity or the address map lives.
    #[error("not a readable PDB: {0}")]
    Unreadable(String),
    /// The debug-information stream states no age, so no image can match it.
    #[error("the PDB states no age in its debug-information stream, so no image can be matched to it")]
    NoAge,
}

impl From<pdb2::Error> for Error {
    fn from(e: pdb2::Error) -> Self {
        Error::Unreadable(e.to_string())
    }
}

/// The identity alone: what to compare before reading anything else.
pub fn identity(bytes: &[u8]) -> Result<Identity, Error> {
    guarded(|| {
        let mut pdb = pdb2::PDB::open(Cursor::new(bytes))?;
        identity_of(&mut pdb)
    })
}

/// Run the reader. A stop inside it is an error about the file.
fn guarded<T>(work: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).unwrap_or_else(|stop| {
        let why = stop
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| stop.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "no reason given".to_string());
        Err(Error::Unreadable(format!("the reader stopped on a malformed file: {why}")))
    })
}

fn identity_of<'s, S: pdb2::Source<'s> + 's>(pdb: &mut pdb2::PDB<'s, S>) -> Result<Identity, Error> {
    let info = pdb.pdb_information()?;
    let (data1, data2, data3, data4) = info.guid.as_fields();
    let age = pdb.debug_information()?.age().ok_or(Error::NoAge)?;
    Ok(Identity { guid: Guid { data1, data2, data3, data4: *data4 }, age })
}

/// What the records at one address said.
#[derive(Default)]
struct AtAddress {
    len: Option<u32>,
    public: Vec<String>,
    procedure: Vec<String>,
}

/// Everything the PDB says about the image's functions.
pub fn read(bytes: &[u8]) -> Result<Contents, Error> {
    guarded(|| read_unguarded(bytes))
}

fn read_unguarded(bytes: &[u8]) -> Result<Contents, Error> {
    let mut pdb = pdb2::PDB::open(Cursor::new(bytes))?;
    let identity = identity_of(&mut pdb)?;
    let map = pdb.address_map()?;
    let mut skipped = Skipped::default();
    let mut at: BTreeMap<u32, AtAddress> = BTreeMap::new();

    // The public table: every function the linker exported a name for, in a
    // public PDB the only one there is.
    let publics = pdb.global_symbols()?;
    let mut records = publics.iter();
    loop {
        let symbol = match records.next() {
            Ok(Some(symbol)) => symbol,
            Ok(None) => break,
            Err(_) => {
                skipped.streams += 1;
                break;
            }
        };
        let Ok(pdb2::SymbolData::Public(public)) = symbol.parse() else { continue };
        if !public.function {
            continue;
        }
        let Some(rva) = public.offset.to_rva(&map) else {
            skipped.unplaced += 1;
            continue;
        };
        let Some(name) = kept(&public.name.to_string(), &mut skipped) else { continue };
        at.entry(rva.0).or_default().public.push(name);
    }

    // Each module's procedures, with the lengths the compiler stated. A static
    // function exists only here.
    let dbi = pdb.debug_information()?;
    let mut modules = dbi.modules()?;
    loop {
        let module = match modules.next() {
            Ok(Some(module)) => module,
            Ok(None) => break,
            Err(_) => {
                skipped.streams += 1;
                break;
            }
        };
        let info = match pdb.module_info(&module) {
            Ok(Some(info)) => info,
            Ok(None) => continue,
            Err(_) => {
                skipped.streams += 1;
                continue;
            }
        };
        let mut records = match info.symbols() {
            Ok(records) => records,
            Err(_) => {
                skipped.streams += 1;
                continue;
            }
        };
        loop {
            let symbol = match records.next() {
                Ok(Some(symbol)) => symbol,
                Ok(None) => break,
                Err(_) => {
                    skipped.streams += 1;
                    break;
                }
            };
            let Ok(pdb2::SymbolData::Procedure(procedure)) = symbol.parse() else { continue };
            let Some(rva) = procedure.offset.to_rva(&map) else {
                skipped.unplaced += 1;
                continue;
            };
            let Some(name) = kept(&procedure.name.to_string(), &mut skipped) else { continue };
            let entry = at.entry(rva.0).or_default();
            // A length of zero states nothing.
            if procedure.len > 0 {
                entry.len = Some(entry.len.map_or(procedure.len, |len| len.max(procedure.len)));
            }
            entry.procedure.push(name);
        }
    }

    let functions = at
        .into_iter()
        .map(|(rva, mut entry)| {
            let names = if entry.public.is_empty() { &mut entry.procedure } else { &mut entry.public };
            names.sort_unstable();
            names.dedup();
            let aliases = names.len() - 1;
            Function { rva, len: entry.len, name: names.swap_remove(0), aliases }
        })
        .collect();
    Ok(Contents { identity, functions, skipped })
}

/// `name`, unless it is empty or too long to be real.
fn kept(name: &str, skipped: &mut Skipped) -> Option<String> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        skipped.names += 1;
        return None;
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::{Guid, Identity};

    /// The bytes and the printed form of one image's CodeView record, as
    /// `llvm-readobj --coff-debug-directory` prints them, and the key its
    /// vendor's symbol server answered to (the spike downloaded by it).
    #[test]
    fn a_codeview_guid_prints_and_keys_as_the_toolchain_does() {
        let bytes: [u8; 16] = [0x1e, 0xae, 0x96, 0xeb, 0x7e, 0x1a, 0x44, 0xfe, 0x17, 0x67, 0x74, 0xc1, 0x5e, 0xd1, 0xfe, 0xb0];
        let guid = Guid::from_codeview(bytes);
        assert_eq!(guid.to_string(), "EB96AE1E-1A7E-FE44-1767-74C15ED1FEB0");
        assert_eq!(Identity { guid, age: 1 }.store_key(), "EB96AE1E1A7EFE44176774C15ED1FEB01");
        assert_eq!(Identity { guid, age: 0x1f }.store_key(), "EB96AE1E1A7EFE44176774C15ED1FEB01F");
    }
}
