// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Types and indices. Each index space has its own type, so a function index
//! cannot be handed where a global index belongs.
//!
//! Every byte that begins a type is stated once here: the abstract heap types
//! in one table, and what the first byte of a reference or value type says in
//! `RefLead` and `ValLead`, which reading a type and asking whether a byte
//! begins one both go through, so the two cannot disagree.

use std::fmt;
use std::ops::Range;

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
    /// An index into the type index space: every subtype of every recursion
    /// group of the type section, in order.
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
    /// An index into the tag index space (imports first).
    TagIdx,
    /// An index into a function's locals: its parameters first, then the
    /// locals its body declares.
    LocalIdx,
    /// A branch target, counted outwards from the innermost enclosing block.
    LabelIdx,
    /// An index into the element segments.
    ElemIdx,
    /// An index into the data segments.
    DataIdx,
    /// A field of a structure type, counted from 0.
    FieldIdx,
}

/// The one table of abstract heap types: the byte, the variant, the text
/// format's name, and its abbreviation of the nullable reference. Everything
/// about them is generated from it; a byte listed twice is an unreachable
/// pattern, which the build refuses.
macro_rules! abstract_heap_types {
    ($( $byte:literal => $v:ident = $name:literal, $abbreviation:literal; )*) => {
        /// An abstract heap type: the one-byte heap types of the binary format.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum AbsHeapType {
            $( $v, )*
        }

        impl AbsHeapType {
            /// Every abstract heap type, in the table's order.
            pub const ALL: &[AbsHeapType] = &[$( AbsHeapType::$v, )*];

            /// The byte that encodes it, alone or after `0x63`/`0x64`.
            pub fn byte(self) -> u8 {
                match self {
                    $( AbsHeapType::$v => $byte, )*
                }
            }

            // Denied here, not left to `-D warnings`: a byte listed twice is
            // an unreachable arm of this function's one match, and only this
            // denial makes that a build error in every build.
            #[deny(unreachable_patterns)]
            pub(crate) fn from_byte(b: u8) -> Option<Self> {
                match b {
                    $( $byte => Some(AbsHeapType::$v), )*
                    _ => None,
                }
            }

            /// The text format's name (`func`, `any`, `noexn`).
            pub fn name(self) -> &'static str {
                match self {
                    $( AbsHeapType::$v => $name, )*
                }
            }

            /// The text format's abbreviation of the nullable reference to it
            /// (`funcref`, `nullexnref`).
            pub fn abbreviation(self) -> &'static str {
                match self {
                    $( AbsHeapType::$v => $abbreviation, )*
                }
            }
        }
    };
}

abstract_heap_types! {
    0x70 => Func = "func", "funcref";
    0x73 => NoFunc = "nofunc", "nullfuncref";
    0x6f => Extern = "extern", "externref";
    0x72 => NoExtern = "noextern", "nullexternref";
    0x6e => Any = "any", "anyref";
    0x6d => Eq = "eq", "eqref";
    0x6c => I31 = "i31", "i31ref";
    0x6b => Struct = "struct", "structref";
    0x6a => Array = "array", "arrayref";
    0x71 => None = "none", "nullref";
    0x69 => Exn = "exn", "exnref";
    0x74 => NoExn = "noexn", "nullexnref";
}

/// What a reference points to: an abstract heap type, or a type of the type
/// index space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HeapType {
    Abstract(AbsHeapType),
    Concrete(TypeIdx),
}

impl HeapType {
    /// An abstract heap type's byte, or a type index as a non-negative s33.
    /// Every other negative s33 (`0x40`, `0x65` shared, `0x68` a continuation,
    /// ...) is a heap type not read here, named by its first byte.
    pub(crate) fn read(r: &mut Reader) -> Result<Self, Error> {
        let at = r.offset();
        let b = r.peek()?;
        if let Some(h) = AbsHeapType::from_byte(b) {
            r.byte()?;
            return Ok(HeapType::Abstract(h));
        }
        let x = r.s33()?;
        u32::try_from(x).map(|x| HeapType::Concrete(TypeIdx(x))).map_err(|_| r.error(at, Problem::UnknownHeapType(b)))
    }
}

impl fmt::Display for HeapType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeapType::Abstract(h) => f.write_str(h.name()),
            HeapType::Concrete(x) => write!(f, "{x}"),
        }
    }
}

/// What the first byte of a reference type says it is.
#[derive(Clone, Copy)]
enum RefLead {
    /// `0x63`: `(ref null ht)`, a heap type follows.
    Nullable,
    /// `0x64`: `(ref ht)`, a heap type follows.
    NonNull,
    /// An abstract heap type's byte alone: the nullable reference to it.
    Abbreviated(AbsHeapType),
}

impl RefLead {
    fn of(b: u8) -> Option<Self> {
        match b {
            0x63 => Some(RefLead::Nullable),
            0x64 => Some(RefLead::NonNull),
            _ => AbsHeapType::from_byte(b).map(RefLead::Abbreviated),
        }
    }
}

/// A reference type: whether it admits null, and the heap type it points to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RefType {
    pub nullable: bool,
    pub heap: HeapType,
}

impl RefType {
    /// `funcref`, the nullable reference to any function.
    pub const FUNCREF: RefType = RefType { nullable: true, heap: HeapType::Abstract(AbsHeapType::Func) };
    /// `externref`, the nullable reference to anything the host holds.
    pub const EXTERNREF: RefType = RefType { nullable: true, heap: HeapType::Abstract(AbsHeapType::Extern) };

    pub(crate) fn read(r: &mut Reader) -> Result<Self, Error> {
        let at = r.offset();
        let b = r.byte()?;
        match RefLead::of(b) {
            Some(RefLead::Nullable) => Ok(RefType { nullable: true, heap: HeapType::read(r)? }),
            Some(RefLead::NonNull) => Ok(RefType { nullable: false, heap: HeapType::read(r)? }),
            Some(RefLead::Abbreviated(h)) => Ok(RefType { nullable: true, heap: HeapType::Abstract(h) }),
            None => Err(r.error(at, Problem::UnknownRefType(b))),
        }
    }
}

/// As `wasm-tools print` writes it: the abbreviation for a nullable reference
/// to an abstract heap type, `(ref null 3)`, `(ref func)` or `(ref 3)`
/// otherwise.
impl fmt::Display for RefType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.nullable, self.heap) {
            (true, HeapType::Abstract(h)) => f.write_str(h.abbreviation()),
            (true, HeapType::Concrete(x)) => write!(f, "(ref null {x})"),
            (false, heap) => write!(f, "(ref {heap})"),
        }
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

/// What the first byte of a value type says it is.
#[derive(Clone, Copy)]
enum ValLead {
    /// A number or vector type: the byte is the whole type.
    Num(ValType),
    /// A reference type, of one byte or more.
    Ref,
}

impl ValLead {
    fn of(b: u8) -> Option<Self> {
        Some(match b {
            0x7f => ValLead::Num(ValType::I32),
            0x7e => ValLead::Num(ValType::I64),
            0x7d => ValLead::Num(ValType::F32),
            0x7c => ValLead::Num(ValType::F64),
            0x7b => ValLead::Num(ValType::V128),
            _ => {
                RefLead::of(b)?;
                ValLead::Ref
            }
        })
    }
}

impl ValType {
    /// Whether `b` is the first byte of a value type.
    pub(crate) fn starts_with(b: u8) -> bool {
        ValLead::of(b).is_some()
    }

    pub(crate) fn read(r: &mut Reader) -> Result<Self, Error> {
        let at = r.offset();
        let b = r.peek()?;
        match ValLead::of(b) {
            Some(ValLead::Num(t)) => {
                r.byte()?;
                Ok(t)
            }
            Some(ValLead::Ref) => RefType::read(r).map(ValType::Ref),
            None => Err(r.error(at, Problem::UnknownValueType(b))),
        }
    }

    /// `vec(valtype)`: every entry is at least one byte, so the count is
    /// bounded by the bytes before anything is pushed.
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

/// `mut`, of a global or a field: `0x00` constant, `0x01` variable.
fn mutability(r: &mut Reader) -> Result<bool, Error> {
    let at = r.offset();
    match r.byte()? {
        0x00 => Ok(false),
        0x01 => Ok(true),
        b => Err(r.error(at, Problem::UnknownMutability(b))),
    }
}

/// What a field of a structure or an array holds: a value type, or one of the
/// two packed integer types, which exist only as fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StorageType {
    Val(ValType),
    I8,
    I16,
}

impl StorageType {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let packed = match r.peek()? {
            0x78 => StorageType::I8,
            0x77 => StorageType::I16,
            _ => return ValType::read(r).map(StorageType::Val),
        };
        r.byte()?;
        Ok(packed)
    }
}

impl fmt::Display for StorageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageType::Val(t) => t.fmt(f),
            StorageType::I8 => f.write_str("i8"),
            StorageType::I16 => f.write_str("i16"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FieldType {
    pub storage: StorageType,
    pub mutable: bool,
}

impl FieldType {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let storage = StorageType::read(r)?;
        Ok(FieldType { storage, mutable: mutability(r)? })
    }
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.mutable { write!(f, "(mut {})", self.storage) } else { self.storage.fmt(f) }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StructType {
    pub fields: Vec<FieldType>,
}

impl fmt::Display for StructType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(struct")?;
        for field in &self.fields {
            write!(f, " (field {field})")?;
        }
        f.write_str(")")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ArrayType {
    pub field: FieldType,
}

impl fmt::Display for ArrayType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(array {})", self.field)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FuncType {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
}

/// `(func (param i32 i64) (result i32))`: each group omitted when empty.
impl fmt::Display for FuncType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(func")?;
        for (word, types) in [("param", &self.params), ("result", &self.results)] {
            if !types.is_empty() {
                write!(f, " ({word}")?;
                for t in types {
                    write!(f, " {t}")?;
                }
                f.write_str(")")?;
            }
        }
        f.write_str(")")
    }
}

/// A function, structure or array type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CompositeType {
    Func(FuncType),
    Struct(StructType),
    Array(ArrayType),
}

impl CompositeType {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let at = r.offset();
        match r.byte()? {
            0x5e => Ok(CompositeType::Array(ArrayType { field: FieldType::read(r)? })),
            0x5f => {
                // A field is a storage type and a mutability: two bytes at least.
                let n = r.count(2)?;
                let mut fields = Vec::new();
                for _ in 0..n {
                    fields.push(FieldType::read(r)?);
                }
                Ok(CompositeType::Struct(StructType { fields }))
            }
            0x60 => {
                let params = ValType::read_vec(r)?;
                let results = ValType::read_vec(r)?;
                Ok(CompositeType::Func(FuncType { params, results }))
            }
            // A recursion group's byte inside a group lands here too: groups
            // do not nest.
            form => Err(r.error(at, Problem::UnknownTypeForm(form))),
        }
    }
}

impl fmt::Display for CompositeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompositeType::Func(t) => t.fmt(f),
            CompositeType::Struct(t) => t.fmt(f),
            CompositeType::Array(t) => t.fmt(f),
        }
    }
}

/// An entry of the type index space: a composite type, whether further
/// subtypes may declare it as their supertype (not final), and the supertypes
/// it declares.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SubType {
    pub is_final: bool,
    pub supertypes: Vec<TypeIdx>,
    pub composite: CompositeType,
}

impl SubType {
    /// `0x50 vec(typeidx) comptype` (not final), `0x4f vec(typeidx) comptype`
    /// (final), or a bare `comptype` (final, no supertypes).
    pub(crate) fn read(r: &mut Reader) -> Result<Self, Error> {
        let is_final = match r.peek()? {
            0x50 => false,
            0x4f => true,
            _ => return Ok(SubType { is_final: true, supertypes: Vec::new(), composite: CompositeType::read(r)? }),
        };
        r.byte()?;
        let n = r.count(1)?;
        let mut supertypes = Vec::new();
        for _ in 0..n {
            supertypes.push(TypeIdx::read(r)?);
        }
        Ok(SubType { is_final, supertypes, composite: CompositeType::read(r)? })
    }
}

/// As `wasm-tools print` writes it: the composite type alone when final with
/// no supertypes, otherwise `(sub final 0 (struct))`, `(sub (func))`.
impl fmt::Display for SubType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_final && self.supertypes.is_empty() {
            return self.composite.fmt(f);
        }
        f.write_str("(sub")?;
        if self.is_final {
            f.write_str(" final")?;
        }
        for s in &self.supertypes {
            write!(f, " {s}")?;
        }
        write!(f, " {})", self.composite)
    }
}

/// A recursion group, an entry of the type section, in the two shapes the
/// format gives it: a bare subtype, which is a group of exactly one type the
/// file did not write as a group, or an explicit `rec` (0x4E), which holds
/// zero or more. A bare group of any other size, or a bare group that says it
/// was explicit, cannot be stated.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RecGroup {
    /// A bare subtype: the group of this one type.
    Single(TypeIdx),
    /// An explicit `rec`, defining these type indices (empty for `(rec)`).
    Rec(Range<u32>),
}

/// The head of a recursion group, before its subtypes are read.
pub(crate) enum RecHead {
    /// One bare subtype follows.
    Single,
    /// `0x4e`, then this many subtypes.
    Rec(u32),
}

impl RecGroup {
    /// The type indices the group defines.
    pub fn types(&self) -> Range<u32> {
        match self {
            // A group the reader made has an index below 2^32 - 1 (a subtype
            // takes two bytes of a section of at most 2^32 - 1), so its end
            // fits. Only a group built by hand at index 2^32 - 1 has an end a
            // `u32` cannot hold; that stops here rather than wrapping to an
            // empty range.
            RecGroup::Single(t) => t.0..t.0.checked_add(1).expect("a bare group at type index 2^32 - 1 ends past u32"),
            RecGroup::Rec(types) => types.clone(),
        }
    }

    /// Whether the file wrote the group as an explicit `rec`.
    pub fn is_explicit(&self) -> bool {
        matches!(self, RecGroup::Rec(_))
    }

    /// The head of a recursion group: `0x4e` then a count of subtypes, each
    /// at least two bytes (`0x5f 0x00` is complete); anything else is one
    /// bare subtype, whose first byte is left to be read.
    pub(crate) fn read_head(r: &mut Reader) -> Result<RecHead, Error> {
        if r.peek()? == 0x4e {
            r.byte()?;
            Ok(RecHead::Rec(r.count(2)?))
        } else {
            Ok(RecHead::Single)
        }
    }
}

/// The width of the addresses of a memory or a table: 32 bits, or 64 with
/// memory64 and table64.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressType {
    I32,
    I64,
}

/// The size bounds of a table or a memory, in elements or pages, as the file
/// states them.
///
/// The bounds are `u64` LEB128 for either address type: the specification's
/// current binary format reads them so, and wasm-tools and wabt both accept a
/// 32-bit memory whose bound is padded past five bytes (measured 2026-10-19;
/// WebAssembly 2.0 read them as `u32` and called that malformed). Whether a
/// bound fits its address type is validation, not checked here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limits {
    pub address: AddressType,
    pub min: u64,
    pub max: Option<u64>,
}

/// The bits of a limits' flags byte: a maximum follows, the memory is shared
/// (threads), the addresses are 64-bit. No other bit is read: bit 3 is a
/// custom page size, which is not.
const LIMITS_MAX: u8 = 0x01;
const LIMITS_SHARED: u8 = 0x02;
const LIMITS_64: u8 = 0x04;
/// A table's flags: shared is not read for a table (shared-everything
/// threads).
const TABLE_LIMITS: u8 = LIMITS_MAX | LIMITS_64;
const MEMORY_LIMITS: u8 = LIMITS_MAX | LIMITS_SHARED | LIMITS_64;

impl Limits {
    /// Limits whose flags may set only the bits in `allowed`, and the flags,
    /// for the caller that allowed more than the bounds use.
    fn read(r: &mut Reader, allowed: u8) -> Result<(Self, u8), Error> {
        let at = r.offset();
        let flags = r.byte()?;
        if flags & !allowed != 0 {
            return Err(r.error(at, Problem::UnknownLimitsFlags(flags)));
        }
        let address = if flags & LIMITS_64 != 0 { AddressType::I64 } else { AddressType::I32 };
        let min = r.u64()?;
        let max = if flags & LIMITS_MAX != 0 { Some(r.u64()?) } else { None };
        Ok((Limits { address, min, max }, flags))
    }
}

/// A memory's type. A shared memory with no maximum is well formed and
/// invalid; validation is not done here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemoryType {
    pub limits: Limits,
    pub shared: bool,
}

impl MemoryType {
    pub(crate) fn read(r: &mut Reader) -> Result<Self, Error> {
        let (limits, flags) = Limits::read(r, MEMORY_LIMITS)?;
        Ok(MemoryType { limits, shared: flags & LIMITS_SHARED != 0 })
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
        let (limits, _) = Limits::read(r, TABLE_LIMITS)?;
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
        Ok(GlobalType { ty, mutable: mutability(r)? })
    }
}

/// A tag's type, as an import and the tag section both state it (`0x00
/// typeidx`): the attribute, of which `0x00`, an exception, is the only one,
/// then the function type of its payload.
pub(crate) fn read_tag_type(r: &mut Reader) -> Result<TypeIdx, Error> {
    let at = r.offset();
    match r.byte()? {
        0x00 => TypeIdx::read(r),
        b => Err(r.error(at, Problem::UnknownTagAttribute(b))),
    }
}

/// The type of a `block`, `loop`, `if`, `try` or `try_table`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlockType {
    /// No parameters, no results (`0x40`).
    Empty,
    /// No parameters, one result.
    Value(ValType),
    /// Parameters and results as a type of the type index space states them.
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
        if ValType::starts_with(b) {
            return ValType::read(r).map(BlockType::Value);
        }
        // Otherwise a type index as a non-negative s33: every one-byte
        // negative s33 is either `0x40`, the first byte of a value type, or
        // not read here.
        let x = r.s33()?;
        u32::try_from(x).map(|x| BlockType::Type(TypeIdx(x))).map_err(|_| r.error(at, Problem::UnknownBlockType(b)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The predicate and the reader go through one classification; this
    /// checks the claim over every byte, so a second path cannot grow back
    /// unnoticed. Each byte is followed by `0x70`, so a `0x63`/`0x64` has its
    /// heap type.
    #[test]
    fn starts_with_says_exactly_which_bytes_read_as_a_value_type() {
        let mut starting = 0;
        for b in 0..=255u8 {
            let bytes = [b, 0x70];
            let reads = ValType::read(&mut Reader::new(&bytes)).is_ok();
            assert_eq!(ValType::starts_with(b), reads, "byte {b:#04x}");
            starting += usize::from(reads);
        }
        // Five number and vector types, `0x63`, `0x64`, twelve abstract heap types.
        assert_eq!(starting, 5 + 2 + 12);
    }

    #[test]
    fn the_abstract_heap_type_table_is_one_to_one() {
        assert_eq!(AbsHeapType::ALL.len(), 12);
        for &h in AbsHeapType::ALL {
            assert_eq!(AbsHeapType::from_byte(h.byte()), Some(h));
            assert_eq!(RefType { nullable: true, heap: HeapType::Abstract(h) }.to_string(), h.abbreviation());
            assert_eq!(RefType { nullable: false, heap: HeapType::Abstract(h) }.to_string(), format!("(ref {})", h.name()));
        }
        let distinct = |f: fn(AbsHeapType) -> String| {
            AbsHeapType::ALL.iter().map(|h| f(*h)).collect::<std::collections::BTreeSet<_>>().len()
        };
        assert_eq!(distinct(|h| h.name().to_string()), 12);
        assert_eq!(distinct(|h| h.abbreviation().to_string()), 12);
        let mapped = (0..=255u8).filter(|b| AbsHeapType::from_byte(*b).is_some()).count();
        assert_eq!(mapped, 12);
    }

    #[test]
    fn heap_types_past_the_set_read_here_are_named_by_their_first_byte() {
        let read = |b: &[u8]| HeapType::read(&mut Reader::new(b));
        assert_eq!(read(&[0x05]).unwrap(), HeapType::Concrete(TypeIdx(5)));
        assert_eq!(read(&[0x85, 0x80, 0x80, 0x80, 0x00]).unwrap(), HeapType::Concrete(TypeIdx(5)));
        assert_eq!(read(&[0xff, 0xff, 0xff, 0xff, 0x0f]).unwrap(), HeapType::Concrete(TypeIdx(u32::MAX)));
        for b in [0x40, 0x65, 0x68, 0x7f] {
            match read(&[b]) {
                Err(Error::Unreadable { offset: 0, problem: Problem::UnknownHeapType(got) }) => assert_eq!(got, b),
                other => panic!("{b:#04x}: {other:?}"),
            }
        }
    }

    #[test]
    fn types_are_written_as_wasm_tools_prints_them() {
        let concrete = |nullable, x| RefType { nullable, heap: HeapType::Concrete(TypeIdx(x)) };
        assert_eq!(concrete(true, 3).to_string(), "(ref null 3)");
        assert_eq!(concrete(false, 3).to_string(), "(ref 3)");
        assert_eq!(RefType::FUNCREF.to_string(), "funcref");
        let f = FuncType { params: vec![ValType::I32, ValType::Ref(concrete(true, 1))], results: vec![ValType::Ref(concrete(false, 2))] };
        assert_eq!(f.to_string(), "(func (param i32 (ref null 1)) (result (ref 2)))");
        assert_eq!(FuncType { params: vec![], results: vec![] }.to_string(), "(func)");
        let field = |storage, mutable| FieldType { storage, mutable };
        let s = StructType { fields: vec![field(StorageType::Val(ValType::I32), false), field(StorageType::I8, true)] };
        assert_eq!(s.to_string(), "(struct (field i32) (field (mut i8)))");
        assert_eq!(ArrayType { field: field(StorageType::I16, true) }.to_string(), "(array (mut i16))");
        let sub = |is_final, supertypes: Vec<u32>, composite| SubType {
            is_final,
            supertypes: supertypes.into_iter().map(TypeIdx).collect(),
            composite,
        };
        let empty = || CompositeType::Struct(StructType { fields: vec![] });
        assert_eq!(sub(true, vec![], empty()).to_string(), "(struct)");
        assert_eq!(sub(false, vec![], empty()).to_string(), "(sub (struct))");
        let one = CompositeType::Struct(StructType { fields: vec![field(StorageType::Val(ValType::I32), false)] });
        assert_eq!(sub(true, vec![0], one).to_string(), "(sub final 0 (struct (field i32)))");
        let func = CompositeType::Func(FuncType { params: vec![], results: vec![] });
        assert_eq!(sub(false, vec![0, 1], func).to_string(), "(sub 0 1 (func))");
    }
}
