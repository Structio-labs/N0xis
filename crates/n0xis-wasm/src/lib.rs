// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! # n0xis-wasm — WebAssembly modules
//!
//! What a WebAssembly module states: its sections and their entries, the
//! index spaces they make, its names, and every function body as a sequence of
//! instructions with their immediates. Bytes in, owned facts out; no I/O.
//!
//! ## What is read
//!
//! The core binary format of WebAssembly 2.0 (multiple results, reference
//! types, bulk memory, mutable globals, sign extension, saturating truncation,
//! 128-bit SIMD), and from later work the 64-bit limits of memory64 and
//! table64, the 64-bit offsets of memory arguments, and the memory index of
//! multiple memories. Every standard section, custom sections by name and
//! range, and the `name` section with the extended name section's
//! subsections (types, tables, memories, globals, element and data segments).
//!
//! Not read, and refused by name when met: shared memories and the atomic
//! instructions (threads), tail calls, exception handling, typed function
//! references, garbage-collected types, relaxed SIMD, the wide-arithmetic
//! instructions, and the component format (binary version 0x0d). The error
//! says which byte; it cannot say which proposal, since a byte outside the
//! set read here may belong to one or to none.
//!
//! ## What is checked
//!
//! Structure, as the binary format states it, not validation: standard
//! sections at most once and in order, every section's contents exactly
//! filling its stated size, LEB128 within its bound, the code section's count
//! matching the function section's and the data count matching the data
//! section, UTF-8 names, balanced `block`/`loop`/`if`/`else`/`end`, nothing
//! after a body's final `end`, a data count section wherever code names a data
//! segment. Whether an index is in range, a type matches or an expression is
//! constant is validation, and is not checked.
//!
//! A break in a standard section is an [`Error`]: nothing past it can be
//! placed. A break that leaves the rest readable is a [`Finding`]: a function
//! body that cannot be decoded (the other bodies can), and anything in the
//! `name` section, which the format says may be ignored when malformed.
//!
//! ## Untrusted input
//!
//! A module comes from anywhere, so it is read as hostile. No vector is
//! sized from a count the file states: a count is refused at once when the
//! bytes left cannot hold that many entries, and entries are then pushed one
//! by one as they are read. Every loop consumes at least one byte per turn.
//! The two entry points, [`read`] and [`Module::body`], run under
//! `catch_unwind`, and a stop inside is an [`Error::Internal`]: a defect of
//! this crate, which `tests/mutated.rs` counts as a failure over thousands of
//! corrupted copies of every fixture.

mod body;
mod error;
mod instr;
mod module;
mod names;
mod reader;
mod types;

pub use body::{Body, LocalRun};
pub use error::{Error, Problem};
pub use instr::{
    BrTargets, DataToMemory, ElemToTable, Ieee32, Ieee64, IndirectCall, Instr, LaneIdx, Located, MemArg, MemArgLane,
    MemoryPair, OPCODES, Opcode, SelectTypes, ShuffleLanes, TablePair, V128Bytes,
};
pub use module::{
    DataMode, DataSegment, ElementItems, ElementMode, ElementSegment, Export, ExportItem, Finding, Func, FuncOrigin,
    Global, GlobalOrigin, Import, ImportItem, Memory, Module, Origin, Section, SectionKind, Table,
};
pub use names::{NameProblem, Names};
pub use types::{
    AddressType, BlockType, DataIdx, ElemIdx, FuncIdx, FuncType, GlobalIdx, GlobalType, LabelIdx, Limits, LocalIdx, MemIdx, RefType,
    TableIdx, TableType, TypeIdx, ValType,
};

/// Read a module.
pub fn read(bytes: &[u8]) -> Result<Module, Error> {
    guarded(|| module::read_unguarded(bytes))
}

impl Module {
    /// The body of a function this module defines, decoded: its locals, then
    /// every instruction to the final `end`, each with its offset in the file.
    /// `None` for an imported function or an index past the index space.
    pub fn body(&self, func: FuncIdx) -> Option<Result<Body, Error>> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.body_unguarded(func))) {
            Ok(answer) => answer,
            Err(stop) => Some(Err(internal(stop))),
        }
    }
}

/// Run a read. A stop inside it is a defect of the reader, reported as one.
fn guarded<T>(work: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).unwrap_or_else(|stop| Err(internal(stop)))
}

fn internal(stop: Box<dyn std::any::Any + Send>) -> Error {
    let why = stop
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| stop.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "no reason given".to_string());
    Error::Internal(why)
}
