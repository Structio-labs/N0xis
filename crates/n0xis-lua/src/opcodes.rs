//! The LuaJIT 2.0 opcode table — a plain data transcription of the `BCDEF`
//! macro list in LuaJIT's `lj_bc.h` (a format specification, not executable
//! logic copied from it): 92 opcodes, each with how its `A`/`B`/`C-or-D`
//! fields should be interpreted. `n0xis-lua` decodes purely from this table —
//! it never guesses an operand's meaning for an opcode it doesn't recognize
//! (sound-over-complete: an out-of-range byte decodes to `Op::Unknown`, never
//! a fabricated mnemonic).

/// How one operand field should be rendered/resolved. Mirrors `BCMode` in
/// `lj_bc.h`; `None` marks "this opcode doesn't use a B field" (i.e. it's
/// AD-format, and the fourth table column is the D-mode instead of C-mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    None,
    /// A destination register.
    Dst,
    /// A register that's the start of a range (base for calls/returns/etc).
    Base,
    /// A live variable-slot register (a plain operand register read).
    Var,
    /// Like `Base`, for ops that don't need a following register read.
    RBase,
    /// An upvalue index.
    Uv,
    /// An unsigned literal.
    Lit,
    /// A signed literal (bias-encoded).
    Lits,
    /// A primitive type tag (nil/false/true).
    Pri,
    /// Index into the numeric constant pool (`knum`), forward-indexed.
    Num,
    /// Index into the GC constant pool (`kgc`), *backward*-indexed (LuaJIT
    /// stores `kgc` growing down from the same boundary `knum` grows up
    /// from — resolving this is `kgc[sizekgc - 1 - operand]`).
    Str,
    /// Same backward-indexed `kgc` pool, but the referenced constant is a
    /// template table rather than a string.
    Tab,
    /// Same backward-indexed `kgc` pool, referencing a nested prototype.
    Func,
    /// A signed jump offset (bias `0x8000`), relative to the instruction
    /// *after* this one.
    Jump,
    /// Same backward-indexed `kgc` pool, referencing an FFI cdata constant.
    Cdata,
}

/// One opcode's full definition.
#[derive(Debug, Clone, Copy)]
pub struct OpDef {
    pub name: &'static str,
    pub a: Mode,
    /// `Mode::None` here means this is an AD-format instruction (single wide
    /// D field, described by `d`); otherwise this is the B field of an
    /// ABC-format instruction.
    pub b: Mode,
    /// The C field (ABC format) or the D field (AD format, when `b ==
    /// Mode::None`) — whichever applies, per LuaJIT's own `bcmode_hasd`.
    pub d: Mode,
}

macro_rules! op {
    ($name:ident, $a:ident, $b:ident, $d:ident) => {
        OpDef { name: stringify!($name), a: Mode::$a, b: Mode::$b, d: Mode::$d }
    };
}

/// `BCDEF` from `lj_bc.h`, in exact declaration order — that order **is**
/// the opcode numbering (`BC_ISLT = 0`, `BC_ISGE = 1`, … `BC_FUNCCW = 91`).
pub const OPCODES: &[OpDef] = &[
    op!(ISLT, Var, None, Var),
    op!(ISGE, Var, None, Var),
    op!(ISLE, Var, None, Var),
    op!(ISGT, Var, None, Var),
    op!(ISEQV, Var, None, Var),
    op!(ISNEV, Var, None, Var),
    op!(ISEQS, Var, None, Str),
    op!(ISNES, Var, None, Str),
    op!(ISEQN, Var, None, Num),
    op!(ISNEN, Var, None, Num),
    op!(ISEQP, Var, None, Pri),
    op!(ISNEP, Var, None, Pri),
    op!(ISTC, Dst, None, Var),
    op!(ISFC, Dst, None, Var),
    op!(IST, None, None, Var),
    op!(ISF, None, None, Var),
    op!(MOV, Dst, None, Var),
    op!(NOT, Dst, None, Var),
    op!(UNM, Dst, None, Var),
    op!(LEN, Dst, None, Var),
    op!(ADDVN, Dst, Var, Num),
    op!(SUBVN, Dst, Var, Num),
    op!(MULVN, Dst, Var, Num),
    op!(DIVVN, Dst, Var, Num),
    op!(MODVN, Dst, Var, Num),
    op!(ADDNV, Dst, Var, Num),
    op!(SUBNV, Dst, Var, Num),
    op!(MULNV, Dst, Var, Num),
    op!(DIVNV, Dst, Var, Num),
    op!(MODNV, Dst, Var, Num),
    op!(ADDVV, Dst, Var, Var),
    op!(SUBVV, Dst, Var, Var),
    op!(MULVV, Dst, Var, Var),
    op!(DIVVV, Dst, Var, Var),
    op!(MODVV, Dst, Var, Var),
    op!(POW, Dst, Var, Var),
    op!(CAT, Dst, RBase, RBase),
    op!(KSTR, Dst, None, Str),
    op!(KCDATA, Dst, None, Cdata),
    op!(KSHORT, Dst, None, Lits),
    op!(KNUM, Dst, None, Num),
    op!(KPRI, Dst, None, Pri),
    op!(KNIL, Base, None, Base),
    op!(UGET, Dst, None, Uv),
    op!(USETV, Uv, None, Var),
    op!(USETS, Uv, None, Str),
    op!(USETN, Uv, None, Num),
    op!(USETP, Uv, None, Pri),
    op!(UCLO, RBase, None, Jump),
    op!(FNEW, Dst, None, Func),
    op!(TNEW, Dst, None, Lit),
    op!(TDUP, Dst, None, Tab),
    op!(GGET, Dst, None, Str),
    op!(GSET, Var, None, Str),
    op!(TGETV, Dst, Var, Var),
    op!(TGETS, Dst, Var, Str),
    op!(TGETB, Dst, Var, Lit),
    op!(TSETV, Var, Var, Var),
    op!(TSETS, Var, Var, Str),
    op!(TSETB, Var, Var, Lit),
    op!(TSETM, Base, None, Num),
    op!(CALLM, Base, Lit, Lit),
    op!(CALL, Base, Lit, Lit),
    op!(CALLMT, Base, None, Lit),
    op!(CALLT, Base, None, Lit),
    op!(ITERC, Base, Lit, Lit),
    op!(ITERN, Base, Lit, Lit),
    op!(VARG, Base, Lit, Lit),
    op!(ISNEXT, Base, None, Jump),
    op!(RETM, Base, None, Lit),
    op!(RET, RBase, None, Lit),
    op!(RET0, RBase, None, Lit),
    op!(RET1, RBase, None, Lit),
    op!(FORI, Base, None, Jump),
    op!(JFORI, Base, None, Jump),
    op!(FORL, Base, None, Jump),
    op!(IFORL, Base, None, Jump),
    op!(JFORL, Base, None, Lit),
    op!(ITERL, Base, None, Jump),
    op!(IITERL, Base, None, Jump),
    op!(JITERL, Base, None, Lit),
    op!(LOOP, RBase, None, Jump),
    op!(ILOOP, RBase, None, Jump),
    op!(JLOOP, RBase, None, Lit),
    op!(JMP, RBase, None, Jump),
    op!(FUNCF, RBase, None, None),
    op!(IFUNCF, RBase, None, None),
    op!(JFUNCF, RBase, None, Lit),
    op!(FUNCV, RBase, None, None),
    op!(IFUNCV, RBase, None, None),
    op!(JFUNCV, RBase, None, Lit),
    op!(FUNCC, RBase, None, None),
    op!(FUNCCW, RBase, None, None),
];

pub const BC_FUNCF: u8 = 85;
pub const BC_FUNCV: u8 = 88;

/// Look up an opcode's definition. `None` for anything `>= OPCODES.len()` —
/// an out-of-range byte is reported as unknown, never misread as some other
/// opcode.
pub fn opdef(op: u8) -> Option<&'static OpDef> {
    OPCODES.get(op as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_exactly_93_opcodes_matching_bc_max() {
        assert_eq!(OPCODES.len(), 93);
    }

    #[test]
    fn funcf_and_funcv_indices_match_their_constants() {
        assert_eq!(OPCODES[BC_FUNCF as usize].name, "FUNCF");
        assert_eq!(OPCODES[BC_FUNCV as usize].name, "FUNCV");
    }

    #[test]
    fn opcode_zero_is_islt() {
        assert_eq!(OPCODES[0].name, "ISLT");
    }

    #[test]
    fn out_of_range_opcode_is_none() {
        assert!(opdef(255).is_none());
    }
}
