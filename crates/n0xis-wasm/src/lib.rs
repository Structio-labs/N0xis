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
//! The whole core binary format of WebAssembly 3.0: everything of 2.0
//! (multiple results, bulk memory, mutable globals, sign extension,
//! saturating truncation, 128-bit SIMD), typed references (heap types,
//! `(ref null? ht)`), garbage-collected types (recursion groups, subtypes,
//! structures, arrays, packed fields) and the `0xFB` instructions, tail
//! calls, exception handling with `exnref` (the tag section, `throw`,
//! `throw_ref`, `try_table`), relaxed SIMD, extended constant expressions,
//! the 64-bit limits of memory64 and table64, and multiple memories. Beside
//! 3.0: threads (shared memories and the `0xFE` atomic instructions), and the
//! legacy exception handling instructions (`try`, `catch`, `catch_all`,
//! `delegate`, `rethrow`), which are not in 3.0 but are what LLVM still emits
//! for `-fwasm-exceptions`. Every standard section, custom sections by name
//! and range, and the `name` section with every subsection the specification
//! and the extended name section define (module, functions, locals, labels,
//! types, tables, memories, globals, element and data segments, fields,
//! tags). Fields that 3.0 reads more widely than 2.0 did (memory arguments'
//! offsets and every limit as `u64`) are read as 3.0 does.
//!
//! An element segment is typed as 3.0 types it: a segment of function indices
//! (forms 0 to 3) holds the non-null `(ref func)`, form 4 `funcref`, and forms
//! 5 to 7 state their type ([`ElementSegment::ty`]).
//!
//! Not read, and refused where met: shared-everything threads (shared heap
//! types, `0x65`; shared tables; the `0xFE` codes from `0x4F`), stack
//! switching (`0xE0` and up), the wide-arithmetic instructions (`0xFC` from
//! `0x13`), custom page sizes (bit 3 of a memory's limits), and the component
//! format (binary version 0x0d). The error says which byte; it cannot say
//! which proposal, since a byte outside the set read here may belong to one
//! or to none.
//!
//! ## What is checked
//!
//! Structure, as the binary format states it, not validation: standard
//! sections at most once and in order (the tag section between the memory and
//! global sections, the data count section between the element and code
//! sections), every section's contents exactly filling its stated size,
//! LEB128 within its bound, the code section's count matching the function
//! section's and the data count matching the data section, UTF-8 names,
//! balanced `block`/`loop`/`if`/`else`/`try_table`/`end`, a legacy `try`
//! whose `catch` clauses come before its `catch_all` (at most one) and whose
//! `delegate` stands only directly after its body, nothing after a body's
//! final `end`, a data count section wherever code names a data segment,
//! reserved bytes zero. Whether an index is in range, a type matches or an
//! expression is constant is validation, and is not checked.
//!
//! The legacy exception handling document gives no binary grammar for `try`,
//! only an opcode table. The order of its clauses is taken from the legacy
//! document's text-format rules and applied as structure, as WebAssembly 3.0's
//! binary grammar applies the order of `if` and `else`.
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
    ArrayData, ArrayElem, ArrayPair, BrTargets, CastBranch, Catch, DataToMemory, ElemToTable, FenceZero, FieldRef,
    FixedArray, Ieee32, Ieee64, IndirectCall, Instr, LaneIdx, Located, MemArg, MemArgLane, MemoryPair, NonNull, Nullable,
    OPCODES, Opcode, SelectTypes, ShuffleLanes, TablePair, TryTable, V128Bytes,
};
pub use module::{
    DataMode, DataSegment, ElementItems, ElementMode, ElementSegment, Export, ExportItem, Finding, Func, FuncOrigin,
    Global, GlobalOrigin, Import, ImportItem, Memory, Module, Origin, Section, SectionKind, Table, TableOrigin, Tag,
};
pub use names::{NameProblem, Names, Within};
pub use types::{
    AbsHeapType, AddressType, ArrayType, BlockType, CompositeType, DataIdx, ElemIdx, FieldIdx, FieldType, FuncIdx,
    FuncType, GlobalIdx, GlobalType, HeapType, LabelIdx, Limits, LocalIdx, MemIdx, MemoryType, RecGroup, RefType,
    StorageType, StructType, SubType, TableIdx, TableType, TagIdx, TypeIdx, ValType,
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

pub(crate) fn internal(stop: Box<dyn std::any::Any + Send>) -> Error {
    let why = stop
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| stop.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "no reason given".to_string());
    Error::Internal(why)
}
