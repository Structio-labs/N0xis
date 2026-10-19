// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Types and indices. Each index space has its own type, so a function index
//! cannot be handed where a global index belongs.

use std::fmt;

use crate::error::{Error, Problem};
use crate::reader::Reader;

macro_rules! index {
    ($( $(#[$doc:meta])* $name:ident ),* $(,)?) => {$(
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub u32);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl $name {
            pub(crate) fn read(r: &mut Reader) -> Result<Self, Error> {
                Ok($name(r.u32()?))
            }
        }
    )*};
}

index! {
    /// An index into the type section.
    TypeIdx,
    /// An index into the function index space: imported functions first, in
    /// import order, then the functions this module defines.
    FuncIdx,
    /// An index into the table index space (imports first).
    TableIdx,
    /// An index into the memory index space (imports first).
    MemIdx,
    /// An index into the global index space (imports first).
    GlobalIdx,
    /// An index into a function's locals: its parameters first, then the
    /// locals its body declares.
    LocalIdx,
    /// A branch target, counted outwards from the innermost enclosing block.
    LabelIdx,
    /// An index into the element segments.
    ElemIdx,
    /// An index into the data segments.
    DataIdx,
}

/// A reference type of the core format: the two of WebAssembly 2.0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefType {
    FuncRef,
    ExternRef,
}

impl RefType {
    pub(crate) fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x70 => Some(RefType::FuncRef),
            0x6f => Some(RefType::ExternRef),
            _ => None,
        }
    }

    pub(crate) fn read(r: &mut Reader) -> Result<Self, Error> {
        let at = r.offset();
        let b = r.byte()?;
        RefType::from_byte(b).ok_or_else(|| r.error(at, Problem::UnknownRefType(b)))
    }

    /// The heap type's name, as `ref.null` spells it.
    pub fn heap_name(self) -> &'static str {
        match self {
            RefType::FuncRef => "func",
            RefType::ExternRef => "extern",
        }
    }
}

impl fmt::Display for RefType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RefType::FuncRef => "funcref",
            RefType::ExternRef => "externref",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValType {
    I32,
    I64,
    F32,
    F64,
    V128,
    Ref(RefType),
}

impl ValType {
    pub(crate) fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x7f => Some(ValType::I32),
            0x7e => Some(ValType::I64),
            0x7d => Some(ValType::F32),
            0x7c => Some(ValType::F64),
            0x7b => Some(ValType::V128),
            _ => RefType::from_byte(b).map(ValType::Ref),
        }
    }

    pub(crate) fn read(r: &mut Reader) -> Result<Self, Error> {
        let at = r.offset();
        let b = r.byte()?;
        ValType::from_byte(b).ok_or_else(|| r.error(at, Problem::UnknownValueType(b)))
    }

    /// `vec(valtype)`: every entry is one byte, so the count is bounded by
    /// the bytes before anything is pushed.
    pub(crate) fn read_vec(r: &mut Reader) -> Result<Vec<Self>, Error> {
        let n = r.count(1)?;
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(ValType::read(r)?);
        }
        Ok(out)
    }
}

impl fmt::Display for ValType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValType::I32 => f.write_str("i32"),
            ValType::I64 => f.write_str("i64"),
            ValType::F32 => f.write_str("f32"),
            ValType::F64 => f.write_str("f64"),
            ValType::V128 => f.write_str("v128"),
            ValType::Ref(r) => r.fmt(f),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FuncType {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
}

impl FuncType {
    pub(crate) fn read(r: &mut Reader) -> Result<Self, Error> {
        let at = r.offset();
        let form = r.byte()?;
        if form != 0x60 {
            return Err(r.error(at, Problem::UnknownTypeForm(form)));
        }
        let params = ValType::read_vec(r)?;
        let results = ValType::read_vec(r)?;
        Ok(FuncType { params, results })
    }
}

/// The size bounds of a table or a memory, in elements or pages. The width
/// of the bounds is the width of the addresses (memory64 and table64 use 64).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Limits {
    I32 { min: u32, max: Option<u32> },
    I64 { min: u64, max: Option<u64> },
}

impl Limits {
    pub(crate) fn read(r: &mut Reader) -> Result<Self, Error> {
        let at = r.offset();
        let flags = r.byte()?;
        // Bit 0: a maximum follows. Bit 2: 64-bit bounds. Bit 1 (shared, the
        // threads proposal) is not read here, and no other bit is defined.
        match flags {
            0x00 => Ok(Limits::I32 { min: r.u32()?, max: None }),
            0x01 => Ok(Limits::I32 { min: r.u32()?, max: Some(r.u32()?) }),
            0x04 => Ok(Limits::I64 { min: r.u64()?, max: None }),
            0x05 => Ok(Limits::I64 { min: r.u64()?, max: Some(r.u64()?) }),
            _ => Err(r.error(at, Problem::UnknownLimitsFlags(flags))),
        }
    }

    pub fn min(&self) -> u64 {
        match *self {
            Limits::I32 { min, .. } => u64::from(min),
            Limits::I64 { min, .. } => min,
        }
    }

    pub fn max(&self) -> Option<u64> {
        match *self {
            Limits::I32 { max, .. } => max.map(u64::from),
            Limits::I64 { max, .. } => max,
        }
    }

    pub fn is_64(&self) -> bool {
        matches!(self, Limits::I64 { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TableType {
    pub element: RefType,
    pub limits: Limits,
}

impl TableType {
    pub(crate) fn read(r: &mut Reader) -> Result<Self, Error> {
        let element = RefType::read(r)?;
        let limits = Limits::read(r)?;
        Ok(TableType { element, limits })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GlobalType {
    pub ty: ValType,
    pub mutable: bool,
}

impl GlobalType {
    pub(crate) fn read(r: &mut Reader) -> Result<Self, Error> {
        let ty = ValType::read(r)?;
        let at = r.offset();
        let mutable = match r.byte()? {
            0x00 => false,
            0x01 => true,
            b => return Err(r.error(at, Problem::UnknownMutability(b))),
        };
        Ok(GlobalType { ty, mutable })
    }
}

/// The type of a `block`, `loop` or `if`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlockType {
    /// No parameters, no results (`0x40`).
    Empty,
    /// No parameters, one result.
    Value(ValType),
    /// Parameters and results as a type of the type section states them.
    Type(TypeIdx),
}

impl BlockType {
    pub(crate) fn read(r: &mut Reader) -> Result<Self, Error> {
        let at = r.offset();
        let b = r.peek()?;
        if b == 0x40 {
            r.byte()?;
            return Ok(BlockType::Empty);
        }
        if let Some(t) = ValType::from_byte(b) {
            r.byte()?;
            return Ok(BlockType::Value(t));
        }
        // Otherwise a type index as a non-negative s33: every one-byte
        // negative s33 is either `0x40`, a value type, or not read here.
        let x = r.s33()?;
        u32::try_from(x).map(|x| BlockType::Type(TypeIdx(x))).map_err(|_| r.error(at, Problem::UnknownBlockType(b)))
    }
}
