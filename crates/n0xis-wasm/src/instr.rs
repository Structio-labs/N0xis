// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Every instruction of the core instruction set of WebAssembly 3.0: the
//! one-byte opcodes (with tail calls, typed function references and
//! exception handling), the `0xFB` space (garbage-collected types), the
//! `0xFC` space (saturating truncation, bulk memory, table instructions) and
//! the `0xFD` space (128-bit SIMD and relaxed SIMD); and beside 3.0 the `0xFE`
//! space of threads (atomic memory instructions) and the legacy exception
//! handling instructions (`try`, `catch`, `catch_all`, `delegate`, `rethrow`)
//! that LLVM still emits. A memory argument carries the memory index of
//! multiple memories and the 64-bit offset of memory64.
//!
//! One table at the bottom of this file states each opcode once: its prefix
//! and code, the variant, the immediate it carries and its text name. The
//! enum, the decoder, the names, the rendering and [`OPCODES`] are all
//! generated from it, so they cannot disagree with one another.
//!
//! ## The text rendering
//!
//! [`Instr`]'s `Display` is the text format's instruction syntax, in one
//! canonical spelling chosen so that it can be compared line for line and
//! assembled back:
//!
//! - integers in decimal, `i32.const` and `i64.const` signed;
//! - floats as exact hexadecimal (`0x1.8p+0`, `-0x0p+0`), never rounded, and
//!   `inf`, `-inf`, `nan:0x…` with the payload, so every bit pattern survives;
//! - a memory argument always as `offset=O align=A` (`A` in bytes), preceded by
//!   the memory index when it is not 0;
//! - memory indices of `memory.size`, `memory.grow`, `memory.fill`,
//!   `memory.copy` and `memory.init` only when not 0, as WebAssembly 2.0 text
//!   (which has no memory index) writes them;
//! - table indices always (`call_indirect 0 (type 2)`, `table.get 0`);
//! - block types as `(result t)` or `(type N)`, typed `select` as
//!   `(result t …)`;
//! - reference types as [`RefType`] writes them (`funcref`, `(ref null 3)`,
//!   `(ref any)`); `ref.null` with its heap type, an abstract name or a type
//!   index (`ref.null func`, `ref.null 3`); `ref.test` and `ref.cast` with the
//!   full reference type; `br_on_cast` and `br_on_cast_fail` with the label,
//!   then the source and target types;
//! - `try_table` with its block type, then each clause (`(catch T L)`,
//!   `(catch_ref T L)`, `(catch_all L)`, `(catch_all_ref L)`);
//! - `return_call_indirect` like `call_indirect`;
//! - `atomic.fence` with no immediate: its reserved byte is checked, not
//!   printed; atomic memory arguments are memory arguments, `offset=O align=A`
//!   always;
//! - field, type, tag, data and element indices in decimal, in the text
//!   format's order, which is the binary order except that `call_indirect`,
//!   `return_call_indirect`, `memory.init` and `table.init` put the table or
//!   memory first (the binary format states the type or the segment first);
//! - `v128.const` as `i32x4` with four `0x%08x` words, and `i8x16.shuffle`
//!   with its sixteen lane indices in decimal.
//!
//! No label or symbolic name is ever printed: indices only.

use std::fmt;

use crate::error::{Error, Problem};
use crate::reader::Reader;
use crate::types::{
    BlockType, DataIdx, ElemIdx, FieldIdx, FuncIdx, GlobalIdx, HeapType, LabelIdx, LocalIdx, MemIdx, RefType, TableIdx,
    TagIdx, TypeIdx, ValType,
};

/// An instruction and where it is: the offset of its first byte in the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Located {
    pub offset: usize,
    pub instr: Instr,
}

/// Which opcode an instruction is, as the binary format numbers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Opcode {
    /// `None` for a one-byte opcode, or one of the four prefixes `0xFB`,
    /// `0xFC`, `0xFD`, `0xFE` of the prefixed spaces, whose code follows the
    /// prefix as a u32 LEB128.
    pub prefix: Option<u8>,
    pub code: u32,
    /// The text format's name. A few opcodes share one: `select` (0x1B) and
    /// `select` with types (0x1C); `ref.test` and `ref.cast` to a non-null
    /// and to a nullable type (`0xFB` 20 and 21, 22 and 23).
    pub name: &'static str,
}

/// `br_table`: the branch targets by index, and the default.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BrTargets {
    pub targets: Vec<LabelIdx>,
    pub default: LabelIdx,
}

/// `call_indirect` and `return_call_indirect`: the expected type, and the
/// table the callee is taken from, in binary order; the text format writes
/// the table first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IndirectCall {
    pub ty: TypeIdx,
    pub table: TableIdx,
}

/// The types a typed `select` states.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SelectTypes(pub Vec<ValType>);

/// A memory argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemArg {
    /// The alignment hint as the binary format writes it: a power of two.
    pub align_log2: u32,
    pub offset: u64,
    pub memory: MemIdx,
}

/// The bits of an `f32`, kept as bits so a NaN's payload is never lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ieee32(pub u32);

/// The bits of an `f64`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ieee64(pub u64);

/// A `v128.const` operand, in memory order (byte 0 is lane 0 of `i8x16`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct V128Bytes(pub [u8; 16]);

/// `i8x16.shuffle`'s sixteen lane indices into the two operands (0..32).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShuffleLanes(pub [u8; 16]);

/// A lane index of `extract_lane` and `replace_lane`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LaneIdx(pub u8);

/// The memory argument and lane of `v128.load*_lane` and `v128.store*_lane`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemArgLane {
    pub memarg: MemArg,
    pub lane: LaneIdx,
}

/// `memory.init`: the data segment, then the memory, in binary order; the
/// text format writes the memory first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DataToMemory {
    pub data: DataIdx,
    pub memory: MemIdx,
}

/// `memory.copy`: destination, then source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemoryPair {
    pub dst: MemIdx,
    pub src: MemIdx,
}

/// `table.init`: the element segment, then the table, in binary order; the
/// text format writes the table first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ElemToTable {
    pub elem: ElemIdx,
    pub table: TableIdx,
}

/// `table.copy`: destination, then source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TablePair {
    pub dst: TableIdx,
    pub src: TableIdx,
}

/// `struct.get`, `struct.set` and the like: the structure type, then the field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FieldRef {
    pub ty: TypeIdx,
    pub field: FieldIdx,
}

/// `array.new_fixed`: the array type, then how many operands it takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FixedArray {
    pub ty: TypeIdx,
    pub len: u32,
}

/// `array.new_data` and `array.init_data`: the array type, then the data
/// segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ArrayData {
    pub ty: TypeIdx,
    pub data: DataIdx,
}

/// `array.new_elem` and `array.init_elem`: the array type, then the element
/// segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ArrayElem {
    pub ty: TypeIdx,
    pub elem: ElemIdx,
}

/// `array.copy`: the destination array type, then the source's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ArrayPair {
    pub dst: TypeIdx,
    pub src: TypeIdx,
}

/// The target of `ref.test` and `ref.cast` (`0xFB` 20, 22): a non-null
/// reference to this heap type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NonNull(pub HeapType);

impl NonNull {
    pub fn ref_type(&self) -> RefType {
        RefType { nullable: false, heap: self.0 }
    }
}

/// The target of `ref.test` and `ref.cast` that admit null (`0xFB` 21, 23): a
/// nullable reference to this heap type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nullable(pub HeapType);

impl Nullable {
    pub fn ref_type(&self) -> RefType {
        RefType { nullable: true, heap: self.0 }
    }
}

/// `br_on_cast` and `br_on_cast_fail`: the label, the type of the operand and
/// the type cast to. The binary format states the two heap types and, in a
/// flags byte before the label, whether each is nullable (bit 0 the source,
/// bit 1 the target).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CastBranch {
    pub label: LabelIdx,
    pub from: RefType,
    pub to: RefType,
}

/// A clause of `try_table`: which exceptions it catches and where it branches.
/// The `_ref` forms also hand the branch the caught exception as an `exnref`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Catch {
    Catch { tag: TagIdx, label: LabelIdx },
    CatchRef { tag: TagIdx, label: LabelIdx },
    CatchAll { label: LabelIdx },
    CatchAllRef { label: LabelIdx },
}

/// `try_table`: its block type, then its catch clauses in order.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TryTable {
    pub ty: BlockType,
    pub catches: Vec<Catch>,
}

/// The reserved byte after `atomic.fence`, which must be 0. It carries
/// nothing, so all that is kept is that it was checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FenceZero;

/// How one kind of immediate is read and written.
trait Immediate: Sized {
    fn read(r: &mut Reader) -> Result<Self, Error>;
    /// The immediate's text, with its leading space; nothing when the
    /// canonical form omits it.
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

macro_rules! plain_index_immediate {
    ($($t:ty),*) => {$(
        impl Immediate for $t {
            fn read(r: &mut Reader) -> Result<Self, Error> {
                <$t>::read(r)
            }
            fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, " {self}")
            }
        }
    )*};
}

plain_index_immediate!(TypeIdx, FuncIdx, LocalIdx, GlobalIdx, TagIdx, LabelIdx, TableIdx, DataIdx, ElemIdx);

impl Immediate for MemIdx {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        MemIdx::read(r)
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 != 0 { write!(f, " {self}") } else { Ok(()) }
    }
}

impl Immediate for BlockType {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        BlockType::read(r)
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockType::Empty => Ok(()),
            BlockType::Value(t) => write!(f, " (result {t})"),
            BlockType::Type(x) => write!(f, " (type {x})"),
        }
    }
}

impl Immediate for BrTargets {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let n = r.count(1)?;
        let mut targets = Vec::new();
        for _ in 0..n {
            targets.push(LabelIdx::read(r)?);
        }
        Ok(BrTargets { targets, default: LabelIdx::read(r)? })
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for l in &self.targets {
            write!(f, " {l}")?;
        }
        write!(f, " {}", self.default)
    }
}

impl Immediate for IndirectCall {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let ty = TypeIdx::read(r)?;
        Ok(IndirectCall { ty, table: TableIdx::read(r)? })
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " {} (type {})", self.table, self.ty)
    }
}

impl Immediate for SelectTypes {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        Ok(SelectTypes(ValType::read_vec(r)?))
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(" (result")?;
        for t in &self.0 {
            write!(f, " {t}")?;
        }
        f.write_str(")")
    }
}

impl Immediate for MemArg {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let at = r.offset();
        let flags = r.u32()?;
        // Below 64: the alignment. 64..128: the alignment plus 64, and a
        // memory index follows (multiple memories). Anything else is not a
        // memory argument.
        let (align_log2, memory) = match flags {
            0..64 => (flags, MemIdx(0)),
            64..128 => (flags - 64, MemIdx::read(r)?),
            _ => return Err(r.error(at, Problem::MemArgFlags(flags))),
        };
        Ok(MemArg { align_log2, offset: r.u64()?, memory })
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.memory.0 != 0 {
            write!(f, " {}", self.memory)?;
        }
        write!(f, " offset={} align={}", self.offset, 1u64 << self.align_log2)
    }
}

impl Immediate for i32 {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        r.s32()
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " {self}")
    }
}

impl Immediate for i64 {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        r.s64()
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " {self}")
    }
}

/// An IEEE 754 binary float as exact hexadecimal text.
fn hex_float(f: &mut fmt::Formatter<'_>, bits: u64, mantissa_bits: u32, exponent_bits: u32) -> fmt::Result {
    let mantissa_mask = (1u64 << mantissa_bits) - 1;
    let exponent_max = (1u64 << exponent_bits) - 1;
    let bias = (1i64 << (exponent_bits - 1)) - 1;
    let negative = (bits >> (mantissa_bits + exponent_bits)) & 1 == 1;
    let exponent = (bits >> mantissa_bits) & exponent_max;
    let mantissa = bits & mantissa_mask;
    if negative {
        f.write_str("-")?;
    }
    if exponent == exponent_max {
        return if mantissa == 0 { f.write_str("inf") } else { write!(f, "nan:{mantissa:#x}") };
    }
    if exponent == 0 && mantissa == 0 {
        return f.write_str("0x0p+0");
    }
    let (fraction, power) = if exponent == 0 {
        // Subnormal: shift the leading one up to the implicit bit and drop it.
        let lead = 63 - mantissa.leading_zeros();
        let shift = mantissa_bits - lead;
        ((mantissa << shift) & mantissa_mask, 1 - bias - i64::from(shift))
    } else {
        (mantissa, exponent as i64 - bias)
    };
    // Pad the fraction to whole hex digits, then drop trailing zero digits.
    let pad = (4 - mantissa_bits % 4) % 4;
    let digits = (mantissa_bits + pad) as usize / 4;
    let text = format!("{:0digits$x}", fraction << pad);
    let text = text.trim_end_matches('0');
    if text.is_empty() { write!(f, "0x1p{power:+}") } else { write!(f, "0x1.{text}p{power:+}") }
}

impl Immediate for Ieee32 {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        Ok(Ieee32(u32::from_le_bytes(r.array()?)))
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(" ")?;
        hex_float(f, u64::from(self.0), 23, 8)
    }
}

impl Immediate for Ieee64 {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        Ok(Ieee64(u64::from_le_bytes(r.array()?)))
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(" ")?;
        hex_float(f, self.0, 52, 11)
    }
}

impl Immediate for V128Bytes {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        Ok(V128Bytes(r.array()?))
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(" i32x4")?;
        for word in self.0.as_chunks::<4>().0 {
            write!(f, " {:#010x}", u32::from_le_bytes(*word))?;
        }
        Ok(())
    }
}

impl Immediate for ShuffleLanes {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        Ok(ShuffleLanes(r.array()?))
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for lane in self.0 {
            write!(f, " {lane}")?;
        }
        Ok(())
    }
}

impl Immediate for LaneIdx {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        Ok(LaneIdx(r.byte()?))
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " {}", self.0)
    }
}

impl Immediate for MemArgLane {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let memarg = MemArg::read(r)?;
        Ok(MemArgLane { memarg, lane: LaneIdx::read(r)? })
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.memarg.write(f)?;
        self.lane.write(f)
    }
}

/// `ref.null`'s immediate: `func`, `none`, `3`.
impl Immediate for HeapType {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        HeapType::read(r)
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " {self}")
    }
}

impl Immediate for NonNull {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        Ok(NonNull(HeapType::read(r)?))
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " {}", self.ref_type())
    }
}

impl Immediate for Nullable {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        Ok(Nullable(HeapType::read(r)?))
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " {}", self.ref_type())
    }
}

/// The two nullability bits of `br_on_cast`'s flags; no other bit is defined.
const CAST_FROM_NULLABLE: u8 = 0x01;
const CAST_TO_NULLABLE: u8 = 0x02;

impl Immediate for CastBranch {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let at = r.offset();
        let flags = r.byte()?;
        if flags & !(CAST_FROM_NULLABLE | CAST_TO_NULLABLE) != 0 {
            return Err(r.error(at, Problem::CastFlags(flags)));
        }
        let label = LabelIdx::read(r)?;
        let from = RefType { nullable: flags & CAST_FROM_NULLABLE != 0, heap: HeapType::read(r)? };
        let to = RefType { nullable: flags & CAST_TO_NULLABLE != 0, heap: HeapType::read(r)? };
        Ok(CastBranch { label, from, to })
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " {} {} {}", self.label, self.from, self.to)
    }
}

impl Immediate for FieldRef {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let ty = TypeIdx::read(r)?;
        Ok(FieldRef { ty, field: FieldIdx::read(r)? })
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " {} {}", self.ty, self.field)
    }
}

impl Immediate for FixedArray {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let ty = TypeIdx::read(r)?;
        Ok(FixedArray { ty, len: r.u32()? })
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " {} {}", self.ty, self.len)
    }
}

impl Immediate for ArrayData {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let ty = TypeIdx::read(r)?;
        Ok(ArrayData { ty, data: DataIdx::read(r)? })
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " {} {}", self.ty, self.data)
    }
}

impl Immediate for ArrayElem {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let ty = TypeIdx::read(r)?;
        Ok(ArrayElem { ty, elem: ElemIdx::read(r)? })
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " {} {}", self.ty, self.elem)
    }
}

impl Immediate for ArrayPair {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let dst = TypeIdx::read(r)?;
        Ok(ArrayPair { dst, src: TypeIdx::read(r)? })
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " {} {}", self.dst, self.src)
    }
}

impl Immediate for TryTable {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let ty = BlockType::read(r)?;
        // A clause is a kind byte and at least one index: two bytes.
        let n = r.count(2)?;
        let mut catches = Vec::new();
        for _ in 0..n {
            let at = r.offset();
            catches.push(match r.byte()? {
                0x00 => {
                    let tag = TagIdx::read(r)?;
                    Catch::Catch { tag, label: LabelIdx::read(r)? }
                }
                0x01 => {
                    let tag = TagIdx::read(r)?;
                    Catch::CatchRef { tag, label: LabelIdx::read(r)? }
                }
                0x02 => Catch::CatchAll { label: LabelIdx::read(r)? },
                0x03 => Catch::CatchAllRef { label: LabelIdx::read(r)? },
                b => return Err(r.error(at, Problem::UnknownCatchKind(b))),
            });
        }
        Ok(TryTable { ty, catches })
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.ty.write(f)?;
        for c in &self.catches {
            match c {
                Catch::Catch { tag, label } => write!(f, " (catch {tag} {label})")?,
                Catch::CatchRef { tag, label } => write!(f, " (catch_ref {tag} {label})")?,
                Catch::CatchAll { label } => write!(f, " (catch_all {label})")?,
                Catch::CatchAllRef { label } => write!(f, " (catch_all_ref {label})")?,
            }
        }
        Ok(())
    }
}

impl Immediate for FenceZero {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let at = r.offset();
        match r.byte()? {
            0 => Ok(FenceZero),
            b => Err(r.error(at, Problem::ReservedByte(b))),
        }
    }
    fn write(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

impl Immediate for DataToMemory {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let data = DataIdx::read(r)?;
        Ok(DataToMemory { data, memory: MemIdx::read(r)? })
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.memory.write(f)?;
        write!(f, " {}", self.data)
    }
}

impl Immediate for MemoryPair {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let dst = MemIdx::read(r)?;
        Ok(MemoryPair { dst, src: MemIdx::read(r)? })
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.dst.0 != 0 || self.src.0 != 0 { write!(f, " {} {}", self.dst, self.src) } else { Ok(()) }
    }
}

impl Immediate for ElemToTable {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let elem = ElemIdx::read(r)?;
        Ok(ElemToTable { elem, table: TableIdx::read(r)? })
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " {} {}", self.table, self.elem)
    }
}

impl Immediate for TablePair {
    fn read(r: &mut Reader) -> Result<Self, Error> {
        let dst = TableIdx::read(r)?;
        Ok(TablePair { dst, src: TableIdx::read(r)? })
    }
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " {} {}", self.dst, self.src)
    }
}

/// Binds a payload in a pattern generated from the table; the type is there
/// only to make the repetition match the optional immediate.
macro_rules! bind {
    ($t:ty, $name:ident) => {
        $name
    };
}

macro_rules! instructions {
    (
        plain { $( $pc:literal => $pv:ident $( ( $pt:ty ) )? = $pn:literal ; )* }
        fb { $( $bc:literal => $bv:ident $( ( $bt:ty ) )? = $bname:literal ; )* }
        fc { $( $fc:literal => $fv:ident $( ( $ft:ty ) )? = $fname:literal ; )* }
        fd { $( $dc:literal => $dv:ident $( ( $dt:ty ) )? = $dname:literal ; )* }
        fe { $( $ec:literal => $ev:ident $( ( $et:ty ) )? = $ename:literal ; )* }
    ) => {
        /// One instruction with its immediates, as the binary format encodes them.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum Instr {
            $( $pv $( ($pt) )?, )*
            $( $bv $( ($bt) )?, )*
            $( $fv $( ($ft) )?, )*
            $( $dv $( ($dt) )?, )*
            $( $ev $( ($et) )?, )*
        }

        /// Every opcode this crate decodes, in table order.
        pub const OPCODES: &[Opcode] = &[
            $( Opcode { prefix: None, code: $pc, name: $pn }, )*
            $( Opcode { prefix: Some(0xfb), code: $bc, name: $bname }, )*
            $( Opcode { prefix: Some(0xfc), code: $fc, name: $fname }, )*
            $( Opcode { prefix: Some(0xfd), code: $dc, name: $dname }, )*
            $( Opcode { prefix: Some(0xfe), code: $ec, name: $ename }, )*
        ];

        impl Instr {
            /// The text format's name of the instruction.
            pub fn name(&self) -> &'static str {
                match self {
                    $( Instr::$pv { .. } => $pn, )*
                    $( Instr::$bv { .. } => $bname, )*
                    $( Instr::$fv { .. } => $fname, )*
                    $( Instr::$dv { .. } => $dname, )*
                    $( Instr::$ev { .. } => $ename, )*
                }
            }

            pub fn opcode(&self) -> Opcode {
                match self {
                    $( Instr::$pv { .. } => Opcode { prefix: None, code: $pc, name: $pn }, )*
                    $( Instr::$bv { .. } => Opcode { prefix: Some(0xfb), code: $bc, name: $bname }, )*
                    $( Instr::$fv { .. } => Opcode { prefix: Some(0xfc), code: $fc, name: $fname }, )*
                    $( Instr::$dv { .. } => Opcode { prefix: Some(0xfd), code: $dc, name: $dname }, )*
                    $( Instr::$ev { .. } => Opcode { prefix: Some(0xfe), code: $ec, name: $ename }, )*
                }
            }

            fn write_immediates(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $( Instr::$pv $( (bind!($pt, imm)) )? => { $( Immediate::write(bind!($pt, imm), f)?; )? Ok(()) } )*
                    $( Instr::$bv $( (bind!($bt, imm)) )? => { $( Immediate::write(bind!($bt, imm), f)?; )? Ok(()) } )*
                    $( Instr::$fv $( (bind!($ft, imm)) )? => { $( Immediate::write(bind!($ft, imm), f)?; )? Ok(()) } )*
                    $( Instr::$dv $( (bind!($dt, imm)) )? => { $( Immediate::write(bind!($dt, imm), f)?; )? Ok(()) } )*
                    $( Instr::$ev $( (bind!($et, imm)) )? => { $( Immediate::write(bind!($et, imm), f)?; )? Ok(()) } )*
                }
            }
        }

        fn decode_plain(code: u8, r: &mut Reader) -> Result<Option<Instr>, Error> {
            Ok(Some(match code {
                $( $pc => Instr::$pv $( ( <$pt as Immediate>::read(r)? ) )?, )*
                _ => return Ok(None),
            }))
        }

        fn decode_fb(code: u32, r: &mut Reader) -> Result<Option<Instr>, Error> {
            Ok(Some(match code {
                $( $bc => Instr::$bv $( ( <$bt as Immediate>::read(r)? ) )?, )*
                _ => return Ok(None),
            }))
        }

        fn decode_fe(code: u32, r: &mut Reader) -> Result<Option<Instr>, Error> {
            Ok(Some(match code {
                $( $ec => Instr::$ev $( ( <$et as Immediate>::read(r)? ) )?, )*
                _ => return Ok(None),
            }))
        }

        fn decode_fc(code: u32, r: &mut Reader) -> Result<Option<Instr>, Error> {
            Ok(Some(match code {
                $( $fc => Instr::$fv $( ( <$ft as Immediate>::read(r)? ) )?, )*
                _ => return Ok(None),
            }))
        }

        fn decode_fd(code: u32, r: &mut Reader) -> Result<Option<Instr>, Error> {
            Ok(Some(match code {
                $( $dc => Instr::$dv $( ( <$dt as Immediate>::read(r)? ) )?, )*
                _ => return Ok(None),
            }))
        }
    };
}

impl Instr {
    /// The data segment the instruction names, if it names one: the
    /// instructions the data count rule is about (a data index anywhere in
    /// code needs a data count section).
    pub fn data_index(&self) -> Option<DataIdx> {
        match self {
            Instr::MemoryInit(DataToMemory { data, .. }) | Instr::DataDrop(data) => Some(*data),
            Instr::ArrayNewData(ArrayData { data, .. }) | Instr::ArrayInitData(ArrayData { data, .. }) => Some(*data),
            _ => None,
        }
    }
}

impl fmt::Display for Instr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())?;
        self.write_immediates(f)
    }
}

/// One instruction at the reader's position.
pub(crate) fn decode(r: &mut Reader) -> Result<Instr, Error> {
    let at = r.offset();
    let first = r.byte()?;
    let (prefix, code, decoded) = match first {
        0xfb..=0xfe => {
            let code = r.u32()?;
            let decoded = match first {
                0xfb => decode_fb(code, r)?,
                0xfc => decode_fc(code, r)?,
                0xfd => decode_fd(code, r)?,
                _ => decode_fe(code, r)?,
            };
            (Some(first), code, decoded)
        }
        _ => (None, u32::from(first), decode_plain(first, r)?),
    };
    decoded.ok_or_else(|| r.error(at, Problem::UnknownOpcode { prefix, code }))
}

instructions! {
    plain {
        0x00 => Unreachable = "unreachable";
        0x01 => Nop = "nop";
        0x02 => Block(BlockType) = "block";
        0x03 => Loop(BlockType) = "loop";
        0x04 => If(BlockType) = "if";
        0x05 => Else = "else";
        0x06 => Try(BlockType) = "try";
        0x07 => Catch(TagIdx) = "catch";
        0x08 => Throw(TagIdx) = "throw";
        0x09 => Rethrow(LabelIdx) = "rethrow";
        0x0a => ThrowRef = "throw_ref";
        0x0b => End = "end";
        0x0c => Br(LabelIdx) = "br";
        0x0d => BrIf(LabelIdx) = "br_if";
        0x0e => BrTable(BrTargets) = "br_table";
        0x0f => Return = "return";
        0x10 => Call(FuncIdx) = "call";
        0x11 => CallIndirect(IndirectCall) = "call_indirect";
        0x12 => ReturnCall(FuncIdx) = "return_call";
        0x13 => ReturnCallIndirect(IndirectCall) = "return_call_indirect";
        0x14 => CallRef(TypeIdx) = "call_ref";
        0x15 => ReturnCallRef(TypeIdx) = "return_call_ref";
        0x18 => Delegate(LabelIdx) = "delegate";
        0x19 => CatchAll = "catch_all";
        0x1a => Drop = "drop";
        0x1b => Select = "select";
        0x1c => SelectTyped(SelectTypes) = "select";
        0x1f => TryTable(TryTable) = "try_table";
        0x20 => LocalGet(LocalIdx) = "local.get";
        0x21 => LocalSet(LocalIdx) = "local.set";
        0x22 => LocalTee(LocalIdx) = "local.tee";
        0x23 => GlobalGet(GlobalIdx) = "global.get";
        0x24 => GlobalSet(GlobalIdx) = "global.set";
        0x25 => TableGet(TableIdx) = "table.get";
        0x26 => TableSet(TableIdx) = "table.set";
        0x28 => I32Load(MemArg) = "i32.load";
        0x29 => I64Load(MemArg) = "i64.load";
        0x2a => F32Load(MemArg) = "f32.load";
        0x2b => F64Load(MemArg) = "f64.load";
        0x2c => I32Load8S(MemArg) = "i32.load8_s";
        0x2d => I32Load8U(MemArg) = "i32.load8_u";
        0x2e => I32Load16S(MemArg) = "i32.load16_s";
        0x2f => I32Load16U(MemArg) = "i32.load16_u";
        0x30 => I64Load8S(MemArg) = "i64.load8_s";
        0x31 => I64Load8U(MemArg) = "i64.load8_u";
        0x32 => I64Load16S(MemArg) = "i64.load16_s";
        0x33 => I64Load16U(MemArg) = "i64.load16_u";
        0x34 => I64Load32S(MemArg) = "i64.load32_s";
        0x35 => I64Load32U(MemArg) = "i64.load32_u";
        0x36 => I32Store(MemArg) = "i32.store";
        0x37 => I64Store(MemArg) = "i64.store";
        0x38 => F32Store(MemArg) = "f32.store";
        0x39 => F64Store(MemArg) = "f64.store";
        0x3a => I32Store8(MemArg) = "i32.store8";
        0x3b => I32Store16(MemArg) = "i32.store16";
        0x3c => I64Store8(MemArg) = "i64.store8";
        0x3d => I64Store16(MemArg) = "i64.store16";
        0x3e => I64Store32(MemArg) = "i64.store32";
        0x3f => MemorySize(MemIdx) = "memory.size";
        0x40 => MemoryGrow(MemIdx) = "memory.grow";
        0x41 => I32Const(i32) = "i32.const";
        0x42 => I64Const(i64) = "i64.const";
        0x43 => F32Const(Ieee32) = "f32.const";
        0x44 => F64Const(Ieee64) = "f64.const";
        0x45 => I32Eqz = "i32.eqz";
        0x46 => I32Eq = "i32.eq";
        0x47 => I32Ne = "i32.ne";
        0x48 => I32LtS = "i32.lt_s";
        0x49 => I32LtU = "i32.lt_u";
        0x4a => I32GtS = "i32.gt_s";
        0x4b => I32GtU = "i32.gt_u";
        0x4c => I32LeS = "i32.le_s";
        0x4d => I32LeU = "i32.le_u";
        0x4e => I32GeS = "i32.ge_s";
        0x4f => I32GeU = "i32.ge_u";
        0x50 => I64Eqz = "i64.eqz";
        0x51 => I64Eq = "i64.eq";
        0x52 => I64Ne = "i64.ne";
        0x53 => I64LtS = "i64.lt_s";
        0x54 => I64LtU = "i64.lt_u";
        0x55 => I64GtS = "i64.gt_s";
        0x56 => I64GtU = "i64.gt_u";
        0x57 => I64LeS = "i64.le_s";
        0x58 => I64LeU = "i64.le_u";
        0x59 => I64GeS = "i64.ge_s";
        0x5a => I64GeU = "i64.ge_u";
        0x5b => F32Eq = "f32.eq";
        0x5c => F32Ne = "f32.ne";
        0x5d => F32Lt = "f32.lt";
        0x5e => F32Gt = "f32.gt";
        0x5f => F32Le = "f32.le";
        0x60 => F32Ge = "f32.ge";
        0x61 => F64Eq = "f64.eq";
        0x62 => F64Ne = "f64.ne";
        0x63 => F64Lt = "f64.lt";
        0x64 => F64Gt = "f64.gt";
        0x65 => F64Le = "f64.le";
        0x66 => F64Ge = "f64.ge";
        0x67 => I32Clz = "i32.clz";
        0x68 => I32Ctz = "i32.ctz";
        0x69 => I32Popcnt = "i32.popcnt";
        0x6a => I32Add = "i32.add";
        0x6b => I32Sub = "i32.sub";
        0x6c => I32Mul = "i32.mul";
        0x6d => I32DivS = "i32.div_s";
        0x6e => I32DivU = "i32.div_u";
        0x6f => I32RemS = "i32.rem_s";
        0x70 => I32RemU = "i32.rem_u";
        0x71 => I32And = "i32.and";
        0x72 => I32Or = "i32.or";
        0x73 => I32Xor = "i32.xor";
        0x74 => I32Shl = "i32.shl";
        0x75 => I32ShrS = "i32.shr_s";
        0x76 => I32ShrU = "i32.shr_u";
        0x77 => I32Rotl = "i32.rotl";
        0x78 => I32Rotr = "i32.rotr";
        0x79 => I64Clz = "i64.clz";
        0x7a => I64Ctz = "i64.ctz";
        0x7b => I64Popcnt = "i64.popcnt";
        0x7c => I64Add = "i64.add";
        0x7d => I64Sub = "i64.sub";
        0x7e => I64Mul = "i64.mul";
        0x7f => I64DivS = "i64.div_s";
        0x80 => I64DivU = "i64.div_u";
        0x81 => I64RemS = "i64.rem_s";
        0x82 => I64RemU = "i64.rem_u";
        0x83 => I64And = "i64.and";
        0x84 => I64Or = "i64.or";
        0x85 => I64Xor = "i64.xor";
        0x86 => I64Shl = "i64.shl";
        0x87 => I64ShrS = "i64.shr_s";
        0x88 => I64ShrU = "i64.shr_u";
        0x89 => I64Rotl = "i64.rotl";
        0x8a => I64Rotr = "i64.rotr";
        0x8b => F32Abs = "f32.abs";
        0x8c => F32Neg = "f32.neg";
        0x8d => F32Ceil = "f32.ceil";
        0x8e => F32Floor = "f32.floor";
        0x8f => F32Trunc = "f32.trunc";
        0x90 => F32Nearest = "f32.nearest";
        0x91 => F32Sqrt = "f32.sqrt";
        0x92 => F32Add = "f32.add";
        0x93 => F32Sub = "f32.sub";
        0x94 => F32Mul = "f32.mul";
        0x95 => F32Div = "f32.div";
        0x96 => F32Min = "f32.min";
        0x97 => F32Max = "f32.max";
        0x98 => F32Copysign = "f32.copysign";
        0x99 => F64Abs = "f64.abs";
        0x9a => F64Neg = "f64.neg";
        0x9b => F64Ceil = "f64.ceil";
        0x9c => F64Floor = "f64.floor";
        0x9d => F64Trunc = "f64.trunc";
        0x9e => F64Nearest = "f64.nearest";
        0x9f => F64Sqrt = "f64.sqrt";
        0xa0 => F64Add = "f64.add";
        0xa1 => F64Sub = "f64.sub";
        0xa2 => F64Mul = "f64.mul";
        0xa3 => F64Div = "f64.div";
        0xa4 => F64Min = "f64.min";
        0xa5 => F64Max = "f64.max";
        0xa6 => F64Copysign = "f64.copysign";
        0xa7 => I32WrapI64 = "i32.wrap_i64";
        0xa8 => I32TruncF32S = "i32.trunc_f32_s";
        0xa9 => I32TruncF32U = "i32.trunc_f32_u";
        0xaa => I32TruncF64S = "i32.trunc_f64_s";
        0xab => I32TruncF64U = "i32.trunc_f64_u";
        0xac => I64ExtendI32S = "i64.extend_i32_s";
        0xad => I64ExtendI32U = "i64.extend_i32_u";
        0xae => I64TruncF32S = "i64.trunc_f32_s";
        0xaf => I64TruncF32U = "i64.trunc_f32_u";
        0xb0 => I64TruncF64S = "i64.trunc_f64_s";
        0xb1 => I64TruncF64U = "i64.trunc_f64_u";
        0xb2 => F32ConvertI32S = "f32.convert_i32_s";
        0xb3 => F32ConvertI32U = "f32.convert_i32_u";
        0xb4 => F32ConvertI64S = "f32.convert_i64_s";
        0xb5 => F32ConvertI64U = "f32.convert_i64_u";
        0xb6 => F32DemoteF64 = "f32.demote_f64";
        0xb7 => F64ConvertI32S = "f64.convert_i32_s";
        0xb8 => F64ConvertI32U = "f64.convert_i32_u";
        0xb9 => F64ConvertI64S = "f64.convert_i64_s";
        0xba => F64ConvertI64U = "f64.convert_i64_u";
        0xbb => F64PromoteF32 = "f64.promote_f32";
        0xbc => I32ReinterpretF32 = "i32.reinterpret_f32";
        0xbd => I64ReinterpretF64 = "i64.reinterpret_f64";
        0xbe => F32ReinterpretI32 = "f32.reinterpret_i32";
        0xbf => F64ReinterpretI64 = "f64.reinterpret_i64";
        0xc0 => I32Extend8S = "i32.extend8_s";
        0xc1 => I32Extend16S = "i32.extend16_s";
        0xc2 => I64Extend8S = "i64.extend8_s";
        0xc3 => I64Extend16S = "i64.extend16_s";
        0xc4 => I64Extend32S = "i64.extend32_s";
        0xd0 => RefNull(HeapType) = "ref.null";
        0xd1 => RefIsNull = "ref.is_null";
        0xd2 => RefFunc(FuncIdx) = "ref.func";
        0xd3 => RefEq = "ref.eq";
        0xd4 => RefAsNonNull = "ref.as_non_null";
        0xd5 => BrOnNull(LabelIdx) = "br_on_null";
        0xd6 => BrOnNonNull(LabelIdx) = "br_on_non_null";
    }
    fb {
        0 => StructNew(TypeIdx) = "struct.new";
        1 => StructNewDefault(TypeIdx) = "struct.new_default";
        2 => StructGet(FieldRef) = "struct.get";
        3 => StructGetS(FieldRef) = "struct.get_s";
        4 => StructGetU(FieldRef) = "struct.get_u";
        5 => StructSet(FieldRef) = "struct.set";
        6 => ArrayNew(TypeIdx) = "array.new";
        7 => ArrayNewDefault(TypeIdx) = "array.new_default";
        8 => ArrayNewFixed(FixedArray) = "array.new_fixed";
        9 => ArrayNewData(ArrayData) = "array.new_data";
        10 => ArrayNewElem(ArrayElem) = "array.new_elem";
        11 => ArrayGet(TypeIdx) = "array.get";
        12 => ArrayGetS(TypeIdx) = "array.get_s";
        13 => ArrayGetU(TypeIdx) = "array.get_u";
        14 => ArraySet(TypeIdx) = "array.set";
        15 => ArrayLen = "array.len";
        16 => ArrayFill(TypeIdx) = "array.fill";
        17 => ArrayCopy(ArrayPair) = "array.copy";
        18 => ArrayInitData(ArrayData) = "array.init_data";
        19 => ArrayInitElem(ArrayElem) = "array.init_elem";
        20 => RefTest(NonNull) = "ref.test";
        21 => RefTestNull(Nullable) = "ref.test";
        22 => RefCast(NonNull) = "ref.cast";
        23 => RefCastNull(Nullable) = "ref.cast";
        24 => BrOnCast(CastBranch) = "br_on_cast";
        25 => BrOnCastFail(CastBranch) = "br_on_cast_fail";
        26 => AnyConvertExtern = "any.convert_extern";
        27 => ExternConvertAny = "extern.convert_any";
        28 => RefI31 = "ref.i31";
        29 => I31GetS = "i31.get_s";
        30 => I31GetU = "i31.get_u";
    }
    fc {
        0x00 => I32TruncSatF32S = "i32.trunc_sat_f32_s";
        0x01 => I32TruncSatF32U = "i32.trunc_sat_f32_u";
        0x02 => I32TruncSatF64S = "i32.trunc_sat_f64_s";
        0x03 => I32TruncSatF64U = "i32.trunc_sat_f64_u";
        0x04 => I64TruncSatF32S = "i64.trunc_sat_f32_s";
        0x05 => I64TruncSatF32U = "i64.trunc_sat_f32_u";
        0x06 => I64TruncSatF64S = "i64.trunc_sat_f64_s";
        0x07 => I64TruncSatF64U = "i64.trunc_sat_f64_u";
        0x08 => MemoryInit(DataToMemory) = "memory.init";
        0x09 => DataDrop(DataIdx) = "data.drop";
        0x0a => MemoryCopy(MemoryPair) = "memory.copy";
        0x0b => MemoryFill(MemIdx) = "memory.fill";
        0x0c => TableInit(ElemToTable) = "table.init";
        0x0d => ElemDrop(ElemIdx) = "elem.drop";
        0x0e => TableCopy(TablePair) = "table.copy";
        0x0f => TableGrow(TableIdx) = "table.grow";
        0x10 => TableSize(TableIdx) = "table.size";
        0x11 => TableFill(TableIdx) = "table.fill";
    }
    fd {
        0x00 => V128Load(MemArg) = "v128.load";
        0x01 => V128Load8x8S(MemArg) = "v128.load8x8_s";
        0x02 => V128Load8x8U(MemArg) = "v128.load8x8_u";
        0x03 => V128Load16x4S(MemArg) = "v128.load16x4_s";
        0x04 => V128Load16x4U(MemArg) = "v128.load16x4_u";
        0x05 => V128Load32x2S(MemArg) = "v128.load32x2_s";
        0x06 => V128Load32x2U(MemArg) = "v128.load32x2_u";
        0x07 => V128Load8Splat(MemArg) = "v128.load8_splat";
        0x08 => V128Load16Splat(MemArg) = "v128.load16_splat";
        0x09 => V128Load32Splat(MemArg) = "v128.load32_splat";
        0x0a => V128Load64Splat(MemArg) = "v128.load64_splat";
        0x0b => V128Store(MemArg) = "v128.store";
        0x0c => V128Const(V128Bytes) = "v128.const";
        0x0d => I8x16Shuffle(ShuffleLanes) = "i8x16.shuffle";
        0x0e => I8x16Swizzle = "i8x16.swizzle";
        0x0f => I8x16Splat = "i8x16.splat";
        0x10 => I16x8Splat = "i16x8.splat";
        0x11 => I32x4Splat = "i32x4.splat";
        0x12 => I64x2Splat = "i64x2.splat";
        0x13 => F32x4Splat = "f32x4.splat";
        0x14 => F64x2Splat = "f64x2.splat";
        0x15 => I8x16ExtractLaneS(LaneIdx) = "i8x16.extract_lane_s";
        0x16 => I8x16ExtractLaneU(LaneIdx) = "i8x16.extract_lane_u";
        0x17 => I8x16ReplaceLane(LaneIdx) = "i8x16.replace_lane";
        0x18 => I16x8ExtractLaneS(LaneIdx) = "i16x8.extract_lane_s";
        0x19 => I16x8ExtractLaneU(LaneIdx) = "i16x8.extract_lane_u";
        0x1a => I16x8ReplaceLane(LaneIdx) = "i16x8.replace_lane";
        0x1b => I32x4ExtractLane(LaneIdx) = "i32x4.extract_lane";
        0x1c => I32x4ReplaceLane(LaneIdx) = "i32x4.replace_lane";
        0x1d => I64x2ExtractLane(LaneIdx) = "i64x2.extract_lane";
        0x1e => I64x2ReplaceLane(LaneIdx) = "i64x2.replace_lane";
        0x1f => F32x4ExtractLane(LaneIdx) = "f32x4.extract_lane";
        0x20 => F32x4ReplaceLane(LaneIdx) = "f32x4.replace_lane";
        0x21 => F64x2ExtractLane(LaneIdx) = "f64x2.extract_lane";
        0x22 => F64x2ReplaceLane(LaneIdx) = "f64x2.replace_lane";
        0x23 => I8x16Eq = "i8x16.eq";
        0x24 => I8x16Ne = "i8x16.ne";
        0x25 => I8x16LtS = "i8x16.lt_s";
        0x26 => I8x16LtU = "i8x16.lt_u";
        0x27 => I8x16GtS = "i8x16.gt_s";
        0x28 => I8x16GtU = "i8x16.gt_u";
        0x29 => I8x16LeS = "i8x16.le_s";
        0x2a => I8x16LeU = "i8x16.le_u";
        0x2b => I8x16GeS = "i8x16.ge_s";
        0x2c => I8x16GeU = "i8x16.ge_u";
        0x2d => I16x8Eq = "i16x8.eq";
        0x2e => I16x8Ne = "i16x8.ne";
        0x2f => I16x8LtS = "i16x8.lt_s";
        0x30 => I16x8LtU = "i16x8.lt_u";
        0x31 => I16x8GtS = "i16x8.gt_s";
        0x32 => I16x8GtU = "i16x8.gt_u";
        0x33 => I16x8LeS = "i16x8.le_s";
        0x34 => I16x8LeU = "i16x8.le_u";
        0x35 => I16x8GeS = "i16x8.ge_s";
        0x36 => I16x8GeU = "i16x8.ge_u";
        0x37 => I32x4Eq = "i32x4.eq";
        0x38 => I32x4Ne = "i32x4.ne";
        0x39 => I32x4LtS = "i32x4.lt_s";
        0x3a => I32x4LtU = "i32x4.lt_u";
        0x3b => I32x4GtS = "i32x4.gt_s";
        0x3c => I32x4GtU = "i32x4.gt_u";
        0x3d => I32x4LeS = "i32x4.le_s";
        0x3e => I32x4LeU = "i32x4.le_u";
        0x3f => I32x4GeS = "i32x4.ge_s";
        0x40 => I32x4GeU = "i32x4.ge_u";
        0x41 => F32x4Eq = "f32x4.eq";
        0x42 => F32x4Ne = "f32x4.ne";
        0x43 => F32x4Lt = "f32x4.lt";
        0x44 => F32x4Gt = "f32x4.gt";
        0x45 => F32x4Le = "f32x4.le";
        0x46 => F32x4Ge = "f32x4.ge";
        0x47 => F64x2Eq = "f64x2.eq";
        0x48 => F64x2Ne = "f64x2.ne";
        0x49 => F64x2Lt = "f64x2.lt";
        0x4a => F64x2Gt = "f64x2.gt";
        0x4b => F64x2Le = "f64x2.le";
        0x4c => F64x2Ge = "f64x2.ge";
        0x4d => V128Not = "v128.not";
        0x4e => V128And = "v128.and";
        0x4f => V128Andnot = "v128.andnot";
        0x50 => V128Or = "v128.or";
        0x51 => V128Xor = "v128.xor";
        0x52 => V128Bitselect = "v128.bitselect";
        0x53 => V128AnyTrue = "v128.any_true";
        0x54 => V128Load8Lane(MemArgLane) = "v128.load8_lane";
        0x55 => V128Load16Lane(MemArgLane) = "v128.load16_lane";
        0x56 => V128Load32Lane(MemArgLane) = "v128.load32_lane";
        0x57 => V128Load64Lane(MemArgLane) = "v128.load64_lane";
        0x58 => V128Store8Lane(MemArgLane) = "v128.store8_lane";
        0x59 => V128Store16Lane(MemArgLane) = "v128.store16_lane";
        0x5a => V128Store32Lane(MemArgLane) = "v128.store32_lane";
        0x5b => V128Store64Lane(MemArgLane) = "v128.store64_lane";
        0x5c => V128Load32Zero(MemArg) = "v128.load32_zero";
        0x5d => V128Load64Zero(MemArg) = "v128.load64_zero";
        0x5e => F32x4DemoteF64x2Zero = "f32x4.demote_f64x2_zero";
        0x5f => F64x2PromoteLowF32x4 = "f64x2.promote_low_f32x4";
        0x60 => I8x16Abs = "i8x16.abs";
        0x61 => I8x16Neg = "i8x16.neg";
        0x62 => I8x16Popcnt = "i8x16.popcnt";
        0x63 => I8x16AllTrue = "i8x16.all_true";
        0x64 => I8x16Bitmask = "i8x16.bitmask";
        0x65 => I8x16NarrowI16x8S = "i8x16.narrow_i16x8_s";
        0x66 => I8x16NarrowI16x8U = "i8x16.narrow_i16x8_u";
        0x67 => F32x4Ceil = "f32x4.ceil";
        0x68 => F32x4Floor = "f32x4.floor";
        0x69 => F32x4Trunc = "f32x4.trunc";
        0x6a => F32x4Nearest = "f32x4.nearest";
        0x6b => I8x16Shl = "i8x16.shl";
        0x6c => I8x16ShrS = "i8x16.shr_s";
        0x6d => I8x16ShrU = "i8x16.shr_u";
        0x6e => I8x16Add = "i8x16.add";
        0x6f => I8x16AddSatS = "i8x16.add_sat_s";
        0x70 => I8x16AddSatU = "i8x16.add_sat_u";
        0x71 => I8x16Sub = "i8x16.sub";
        0x72 => I8x16SubSatS = "i8x16.sub_sat_s";
        0x73 => I8x16SubSatU = "i8x16.sub_sat_u";
        0x74 => F64x2Ceil = "f64x2.ceil";
        0x75 => F64x2Floor = "f64x2.floor";
        0x76 => I8x16MinS = "i8x16.min_s";
        0x77 => I8x16MinU = "i8x16.min_u";
        0x78 => I8x16MaxS = "i8x16.max_s";
        0x79 => I8x16MaxU = "i8x16.max_u";
        0x7a => F64x2Trunc = "f64x2.trunc";
        0x7b => I8x16AvgrU = "i8x16.avgr_u";
        0x7c => I16x8ExtaddPairwiseI8x16S = "i16x8.extadd_pairwise_i8x16_s";
        0x7d => I16x8ExtaddPairwiseI8x16U = "i16x8.extadd_pairwise_i8x16_u";
        0x7e => I32x4ExtaddPairwiseI16x8S = "i32x4.extadd_pairwise_i16x8_s";
        0x7f => I32x4ExtaddPairwiseI16x8U = "i32x4.extadd_pairwise_i16x8_u";
        0x80 => I16x8Abs = "i16x8.abs";
        0x81 => I16x8Neg = "i16x8.neg";
        0x82 => I16x8Q15mulrSatS = "i16x8.q15mulr_sat_s";
        0x83 => I16x8AllTrue = "i16x8.all_true";
        0x84 => I16x8Bitmask = "i16x8.bitmask";
        0x85 => I16x8NarrowI32x4S = "i16x8.narrow_i32x4_s";
        0x86 => I16x8NarrowI32x4U = "i16x8.narrow_i32x4_u";
        0x87 => I16x8ExtendLowI8x16S = "i16x8.extend_low_i8x16_s";
        0x88 => I16x8ExtendHighI8x16S = "i16x8.extend_high_i8x16_s";
        0x89 => I16x8ExtendLowI8x16U = "i16x8.extend_low_i8x16_u";
        0x8a => I16x8ExtendHighI8x16U = "i16x8.extend_high_i8x16_u";
        0x8b => I16x8Shl = "i16x8.shl";
        0x8c => I16x8ShrS = "i16x8.shr_s";
        0x8d => I16x8ShrU = "i16x8.shr_u";
        0x8e => I16x8Add = "i16x8.add";
        0x8f => I16x8AddSatS = "i16x8.add_sat_s";
        0x90 => I16x8AddSatU = "i16x8.add_sat_u";
        0x91 => I16x8Sub = "i16x8.sub";
        0x92 => I16x8SubSatS = "i16x8.sub_sat_s";
        0x93 => I16x8SubSatU = "i16x8.sub_sat_u";
        0x94 => F64x2Nearest = "f64x2.nearest";
        0x95 => I16x8Mul = "i16x8.mul";
        0x96 => I16x8MinS = "i16x8.min_s";
        0x97 => I16x8MinU = "i16x8.min_u";
        0x98 => I16x8MaxS = "i16x8.max_s";
        0x99 => I16x8MaxU = "i16x8.max_u";
        0x9b => I16x8AvgrU = "i16x8.avgr_u";
        0x9c => I16x8ExtmulLowI8x16S = "i16x8.extmul_low_i8x16_s";
        0x9d => I16x8ExtmulHighI8x16S = "i16x8.extmul_high_i8x16_s";
        0x9e => I16x8ExtmulLowI8x16U = "i16x8.extmul_low_i8x16_u";
        0x9f => I16x8ExtmulHighI8x16U = "i16x8.extmul_high_i8x16_u";
        0xa0 => I32x4Abs = "i32x4.abs";
        0xa1 => I32x4Neg = "i32x4.neg";
        0xa3 => I32x4AllTrue = "i32x4.all_true";
        0xa4 => I32x4Bitmask = "i32x4.bitmask";
        0xa7 => I32x4ExtendLowI16x8S = "i32x4.extend_low_i16x8_s";
        0xa8 => I32x4ExtendHighI16x8S = "i32x4.extend_high_i16x8_s";
        0xa9 => I32x4ExtendLowI16x8U = "i32x4.extend_low_i16x8_u";
        0xaa => I32x4ExtendHighI16x8U = "i32x4.extend_high_i16x8_u";
        0xab => I32x4Shl = "i32x4.shl";
        0xac => I32x4ShrS = "i32x4.shr_s";
        0xad => I32x4ShrU = "i32x4.shr_u";
        0xae => I32x4Add = "i32x4.add";
        0xb1 => I32x4Sub = "i32x4.sub";
        0xb5 => I32x4Mul = "i32x4.mul";
        0xb6 => I32x4MinS = "i32x4.min_s";
        0xb7 => I32x4MinU = "i32x4.min_u";
        0xb8 => I32x4MaxS = "i32x4.max_s";
        0xb9 => I32x4MaxU = "i32x4.max_u";
        0xba => I32x4DotI16x8S = "i32x4.dot_i16x8_s";
        0xbc => I32x4ExtmulLowI16x8S = "i32x4.extmul_low_i16x8_s";
        0xbd => I32x4ExtmulHighI16x8S = "i32x4.extmul_high_i16x8_s";
        0xbe => I32x4ExtmulLowI16x8U = "i32x4.extmul_low_i16x8_u";
        0xbf => I32x4ExtmulHighI16x8U = "i32x4.extmul_high_i16x8_u";
        0xc0 => I64x2Abs = "i64x2.abs";
        0xc1 => I64x2Neg = "i64x2.neg";
        0xc3 => I64x2AllTrue = "i64x2.all_true";
        0xc4 => I64x2Bitmask = "i64x2.bitmask";
        0xc7 => I64x2ExtendLowI32x4S = "i64x2.extend_low_i32x4_s";
        0xc8 => I64x2ExtendHighI32x4S = "i64x2.extend_high_i32x4_s";
        0xc9 => I64x2ExtendLowI32x4U = "i64x2.extend_low_i32x4_u";
        0xca => I64x2ExtendHighI32x4U = "i64x2.extend_high_i32x4_u";
        0xcb => I64x2Shl = "i64x2.shl";
        0xcc => I64x2ShrS = "i64x2.shr_s";
        0xcd => I64x2ShrU = "i64x2.shr_u";
        0xce => I64x2Add = "i64x2.add";
        0xd1 => I64x2Sub = "i64x2.sub";
        0xd5 => I64x2Mul = "i64x2.mul";
        0xd6 => I64x2Eq = "i64x2.eq";
        0xd7 => I64x2Ne = "i64x2.ne";
        0xd8 => I64x2LtS = "i64x2.lt_s";
        0xd9 => I64x2GtS = "i64x2.gt_s";
        0xda => I64x2LeS = "i64x2.le_s";
        0xdb => I64x2GeS = "i64x2.ge_s";
        0xdc => I64x2ExtmulLowI32x4S = "i64x2.extmul_low_i32x4_s";
        0xdd => I64x2ExtmulHighI32x4S = "i64x2.extmul_high_i32x4_s";
        0xde => I64x2ExtmulLowI32x4U = "i64x2.extmul_low_i32x4_u";
        0xdf => I64x2ExtmulHighI32x4U = "i64x2.extmul_high_i32x4_u";
        0xe0 => F32x4Abs = "f32x4.abs";
        0xe1 => F32x4Neg = "f32x4.neg";
        0xe3 => F32x4Sqrt = "f32x4.sqrt";
        0xe4 => F32x4Add = "f32x4.add";
        0xe5 => F32x4Sub = "f32x4.sub";
        0xe6 => F32x4Mul = "f32x4.mul";
        0xe7 => F32x4Div = "f32x4.div";
        0xe8 => F32x4Min = "f32x4.min";
        0xe9 => F32x4Max = "f32x4.max";
        0xea => F32x4Pmin = "f32x4.pmin";
        0xeb => F32x4Pmax = "f32x4.pmax";
        0xec => F64x2Abs = "f64x2.abs";
        0xed => F64x2Neg = "f64x2.neg";
        0xef => F64x2Sqrt = "f64x2.sqrt";
        0xf0 => F64x2Add = "f64x2.add";
        0xf1 => F64x2Sub = "f64x2.sub";
        0xf2 => F64x2Mul = "f64x2.mul";
        0xf3 => F64x2Div = "f64x2.div";
        0xf4 => F64x2Min = "f64x2.min";
        0xf5 => F64x2Max = "f64x2.max";
        0xf6 => F64x2Pmin = "f64x2.pmin";
        0xf7 => F64x2Pmax = "f64x2.pmax";
        0xf8 => I32x4TruncSatF32x4S = "i32x4.trunc_sat_f32x4_s";
        0xf9 => I32x4TruncSatF32x4U = "i32x4.trunc_sat_f32x4_u";
        0xfa => F32x4ConvertI32x4S = "f32x4.convert_i32x4_s";
        0xfb => F32x4ConvertI32x4U = "f32x4.convert_i32x4_u";
        0xfc => I32x4TruncSatF64x2SZero = "i32x4.trunc_sat_f64x2_s_zero";
        0xfd => I32x4TruncSatF64x2UZero = "i32x4.trunc_sat_f64x2_u_zero";
        0xfe => F64x2ConvertLowI32x4S = "f64x2.convert_low_i32x4_s";
        0xff => F64x2ConvertLowI32x4U = "f64x2.convert_low_i32x4_u";
        0x100 => I8x16RelaxedSwizzle = "i8x16.relaxed_swizzle";
        0x101 => I32x4RelaxedTruncF32x4S = "i32x4.relaxed_trunc_f32x4_s";
        0x102 => I32x4RelaxedTruncF32x4U = "i32x4.relaxed_trunc_f32x4_u";
        0x103 => I32x4RelaxedTruncF64x2SZero = "i32x4.relaxed_trunc_f64x2_s_zero";
        0x104 => I32x4RelaxedTruncF64x2UZero = "i32x4.relaxed_trunc_f64x2_u_zero";
        0x105 => F32x4RelaxedMadd = "f32x4.relaxed_madd";
        0x106 => F32x4RelaxedNmadd = "f32x4.relaxed_nmadd";
        0x107 => F64x2RelaxedMadd = "f64x2.relaxed_madd";
        0x108 => F64x2RelaxedNmadd = "f64x2.relaxed_nmadd";
        0x109 => I8x16RelaxedLaneselect = "i8x16.relaxed_laneselect";
        0x10a => I16x8RelaxedLaneselect = "i16x8.relaxed_laneselect";
        0x10b => I32x4RelaxedLaneselect = "i32x4.relaxed_laneselect";
        0x10c => I64x2RelaxedLaneselect = "i64x2.relaxed_laneselect";
        0x10d => F32x4RelaxedMin = "f32x4.relaxed_min";
        0x10e => F32x4RelaxedMax = "f32x4.relaxed_max";
        0x10f => F64x2RelaxedMin = "f64x2.relaxed_min";
        0x110 => F64x2RelaxedMax = "f64x2.relaxed_max";
        0x111 => I16x8RelaxedQ15mulrS = "i16x8.relaxed_q15mulr_s";
        0x112 => I16x8RelaxedDotI8x16I7x16S = "i16x8.relaxed_dot_i8x16_i7x16_s";
        0x113 => I32x4RelaxedDotI8x16I7x16AddS = "i32x4.relaxed_dot_i8x16_i7x16_add_s";
    }
    fe {
        0x00 => MemoryAtomicNotify(MemArg) = "memory.atomic.notify";
        0x01 => MemoryAtomicWait32(MemArg) = "memory.atomic.wait32";
        0x02 => MemoryAtomicWait64(MemArg) = "memory.atomic.wait64";
        0x03 => AtomicFence(FenceZero) = "atomic.fence";
        0x10 => I32AtomicLoad(MemArg) = "i32.atomic.load";
        0x11 => I64AtomicLoad(MemArg) = "i64.atomic.load";
        0x12 => I32AtomicLoad8U(MemArg) = "i32.atomic.load8_u";
        0x13 => I32AtomicLoad16U(MemArg) = "i32.atomic.load16_u";
        0x14 => I64AtomicLoad8U(MemArg) = "i64.atomic.load8_u";
        0x15 => I64AtomicLoad16U(MemArg) = "i64.atomic.load16_u";
        0x16 => I64AtomicLoad32U(MemArg) = "i64.atomic.load32_u";
        0x17 => I32AtomicStore(MemArg) = "i32.atomic.store";
        0x18 => I64AtomicStore(MemArg) = "i64.atomic.store";
        0x19 => I32AtomicStore8(MemArg) = "i32.atomic.store8";
        0x1a => I32AtomicStore16(MemArg) = "i32.atomic.store16";
        0x1b => I64AtomicStore8(MemArg) = "i64.atomic.store8";
        0x1c => I64AtomicStore16(MemArg) = "i64.atomic.store16";
        0x1d => I64AtomicStore32(MemArg) = "i64.atomic.store32";
        0x1e => I32AtomicRmwAdd(MemArg) = "i32.atomic.rmw.add";
        0x1f => I64AtomicRmwAdd(MemArg) = "i64.atomic.rmw.add";
        0x20 => I32AtomicRmw8AddU(MemArg) = "i32.atomic.rmw8.add_u";
        0x21 => I32AtomicRmw16AddU(MemArg) = "i32.atomic.rmw16.add_u";
        0x22 => I64AtomicRmw8AddU(MemArg) = "i64.atomic.rmw8.add_u";
        0x23 => I64AtomicRmw16AddU(MemArg) = "i64.atomic.rmw16.add_u";
        0x24 => I64AtomicRmw32AddU(MemArg) = "i64.atomic.rmw32.add_u";
        0x25 => I32AtomicRmwSub(MemArg) = "i32.atomic.rmw.sub";
        0x26 => I64AtomicRmwSub(MemArg) = "i64.atomic.rmw.sub";
        0x27 => I32AtomicRmw8SubU(MemArg) = "i32.atomic.rmw8.sub_u";
        0x28 => I32AtomicRmw16SubU(MemArg) = "i32.atomic.rmw16.sub_u";
        0x29 => I64AtomicRmw8SubU(MemArg) = "i64.atomic.rmw8.sub_u";
        0x2a => I64AtomicRmw16SubU(MemArg) = "i64.atomic.rmw16.sub_u";
        0x2b => I64AtomicRmw32SubU(MemArg) = "i64.atomic.rmw32.sub_u";
        0x2c => I32AtomicRmwAnd(MemArg) = "i32.atomic.rmw.and";
        0x2d => I64AtomicRmwAnd(MemArg) = "i64.atomic.rmw.and";
        0x2e => I32AtomicRmw8AndU(MemArg) = "i32.atomic.rmw8.and_u";
        0x2f => I32AtomicRmw16AndU(MemArg) = "i32.atomic.rmw16.and_u";
        0x30 => I64AtomicRmw8AndU(MemArg) = "i64.atomic.rmw8.and_u";
        0x31 => I64AtomicRmw16AndU(MemArg) = "i64.atomic.rmw16.and_u";
        0x32 => I64AtomicRmw32AndU(MemArg) = "i64.atomic.rmw32.and_u";
        0x33 => I32AtomicRmwOr(MemArg) = "i32.atomic.rmw.or";
        0x34 => I64AtomicRmwOr(MemArg) = "i64.atomic.rmw.or";
        0x35 => I32AtomicRmw8OrU(MemArg) = "i32.atomic.rmw8.or_u";
        0x36 => I32AtomicRmw16OrU(MemArg) = "i32.atomic.rmw16.or_u";
        0x37 => I64AtomicRmw8OrU(MemArg) = "i64.atomic.rmw8.or_u";
        0x38 => I64AtomicRmw16OrU(MemArg) = "i64.atomic.rmw16.or_u";
        0x39 => I64AtomicRmw32OrU(MemArg) = "i64.atomic.rmw32.or_u";
        0x3a => I32AtomicRmwXor(MemArg) = "i32.atomic.rmw.xor";
        0x3b => I64AtomicRmwXor(MemArg) = "i64.atomic.rmw.xor";
        0x3c => I32AtomicRmw8XorU(MemArg) = "i32.atomic.rmw8.xor_u";
        0x3d => I32AtomicRmw16XorU(MemArg) = "i32.atomic.rmw16.xor_u";
        0x3e => I64AtomicRmw8XorU(MemArg) = "i64.atomic.rmw8.xor_u";
        0x3f => I64AtomicRmw16XorU(MemArg) = "i64.atomic.rmw16.xor_u";
        0x40 => I64AtomicRmw32XorU(MemArg) = "i64.atomic.rmw32.xor_u";
        0x41 => I32AtomicRmwXchg(MemArg) = "i32.atomic.rmw.xchg";
        0x42 => I64AtomicRmwXchg(MemArg) = "i64.atomic.rmw.xchg";
        0x43 => I32AtomicRmw8XchgU(MemArg) = "i32.atomic.rmw8.xchg_u";
        0x44 => I32AtomicRmw16XchgU(MemArg) = "i32.atomic.rmw16.xchg_u";
        0x45 => I64AtomicRmw8XchgU(MemArg) = "i64.atomic.rmw8.xchg_u";
        0x46 => I64AtomicRmw16XchgU(MemArg) = "i64.atomic.rmw16.xchg_u";
        0x47 => I64AtomicRmw32XchgU(MemArg) = "i64.atomic.rmw32.xchg_u";
        0x48 => I32AtomicRmwCmpxchg(MemArg) = "i32.atomic.rmw.cmpxchg";
        0x49 => I64AtomicRmwCmpxchg(MemArg) = "i64.atomic.rmw.cmpxchg";
        0x4a => I32AtomicRmw8CmpxchgU(MemArg) = "i32.atomic.rmw8.cmpxchg_u";
        0x4b => I32AtomicRmw16CmpxchgU(MemArg) = "i32.atomic.rmw16.cmpxchg_u";
        0x4c => I64AtomicRmw8CmpxchgU(MemArg) = "i64.atomic.rmw8.cmpxchg_u";
        0x4d => I64AtomicRmw16CmpxchgU(MemArg) = "i64.atomic.rmw16.cmpxchg_u";
        0x4e => I64AtomicRmw32CmpxchgU(MemArg) = "i64.atomic.rmw32.cmpxchg_u";
    }
}
