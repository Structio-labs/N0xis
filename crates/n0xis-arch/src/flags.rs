// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Condition-code reconstruction — the half of [`Arch::branch_condition`] that
//! is **not** ISA knowledge.
//!
//! [`branch_condition`] turns a precise [`MicroExpr::Compare`] (the value the
//! flags carry) plus the name of a condition into an exact boolean. Nothing in
//! it decodes an instruction: it reads the [`CmpKind`] the lift recorded and
//! applies the rules that follow from it — a subtraction's flags answer the
//! whole ordering family, a logical op's clear the carry and overflow and
//! therefore answer the sign/zero family, a stored arithmetic result answers
//! only the two that are functions of the result alone.
//!
//! It lived in `x64_lift.rs` until AArch64 needed the same reconstruction. The
//! *vocabulary* stayed x86's — the conditions are named `"je"`, `"jb"`, `"jl"`
//! and so on — because that is the spelling this code was written and measured
//! against, and renaming it would have been a second copy of the table wearing
//! neutral clothes. An architecture whose condition codes are spelled
//! differently maps them onto these names at its own seam; see
//! `Arm64::branch_condition`, where that mapping is also what absorbs the
//! opposite polarity of the two architectures' carry flags.

use crate::microir::{BinOp, Bits, CallTarget, CmpKind, MicroExpr};

/// The width a value carries, where the expression states one.
///
/// A bitwise operation over two values of one width has that width — `edi &
/// esi` is a 32-bit value whether or not anything casts it — and a constant
/// operand does not narrow it. `None` means nothing here states a width, and
/// then the value is whatever the register is.
fn value_width(e: &MicroExpr) -> Option<Bits> {
    match e {
        MicroExpr::Cast { bits, .. } | MicroExpr::Load { bits, .. } if *bits < 64 => Some(*bits),
        MicroExpr::Binary(BinOp::And | BinOp::Or | BinOp::Xor, l, r) => {
            match (value_width(l), value_width(r)) {
                (Some(a), Some(b)) if a == b => Some(a),
                (Some(a), None) if matches!(r.as_ref(), MicroExpr::Const { .. }) => Some(a),
                (None, Some(b)) if matches!(l.as_ref(), MicroExpr::Const { .. }) => Some(b),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Re-read a narrow operand as **signed**.
///
/// `cmp eax, ebx` records both operands as the low 32 bits, zero-extended —
/// which is exactly what the bits *are*. Whether those bits mean a negative
/// number is the branch's question, not the compare's: `jb` and `jl` read the
/// same flags and give opposite answers on `0xffffffff`. So the predicate
/// applies its own interpretation, at the width the operand already carries.
///
/// Measured against the CPU: without this, every signed condition on a 32-bit
/// value whose sign bit is set answered the unsigned question instead.
pub(crate) fn signed_view(e: MicroExpr) -> MicroExpr {
    match e {
        MicroExpr::Cast { signed: false, bits, expr } if bits < 64 => {
            MicroExpr::Cast { signed: true, bits, expr }
        }
        // A narrow operand read straight out of memory — `cmpl $0x0,-0x4(%rbp)`,
        // which is what an unoptimized build compares. Same bytes, same address,
        // read signed. Found only after the corpus was built at four
        // optimization levels: at `-O2` the compare is register-to-register and
        // this path never runs.
        MicroExpr::Load { addr, bits, signed: false } if bits < 64 => {
            MicroExpr::Load { addr, bits, signed: true }
        }
        // A **computed** narrow value. `test edi, esi` records the flags as
        // `edi & esi`, whose sign is bit 31 — but the expression's root is the
        // `and`, not a cast, so the two arms above never saw it and the whole
        // 64-bit value read as positive. clang compiles `if (x < 0)` after a
        // 32-bit `and` exactly that way (`test edi, esi; … cmovns`), where gcc
        // uses `and %esi,%edi; js` and takes the first arm. Four optimization
        // levels of one compiler never showed it; a second compiler did, on the
        // first run.
        other => match value_width(&other) {
            Some(bits) => MicroExpr::Cast { signed: true, bits, expr: Box::new(other) },
            None => other,
        },
    }
}

fn difference_at_width(lhs: MicroExpr, rhs: MicroExpr) -> MicroExpr {
    let bits = value_width(&lhs).or_else(|| value_width(&rhs));
    let difference = MicroExpr::binary(BinOp::Sub, signed_view(lhs), signed_view(rhs));
    match bits {
        Some(bits) => MicroExpr::Cast { signed: true, bits, expr: Box::new(difference) },
        None => difference,
    }
}

/// The exact branch condition for a `jcc` whose flags came from a **logical**
/// operation (`test`/`and`/`or`/`xor`), where the value the flags reflect is
/// `val`. A logical op clears **OF and CF to 0**, so every condition collapses
/// to a sign/zero test on `val` and reconstructs soundly (unlike an arithmetic
/// result, whose signed/carry conditions need the real OF/CF):
///   - signed: `jl`→`val<0`, `jle`→`val<=0`, `jg`→`val>0`, `jge`→`val>=0`;
///   - unsigned (CF=0): `ja`→`val!=0`, `jbe`→`val==0`, `jae`→always, `jb`→never.
fn logical_flag_cond(mnemonic: &str, val: MicroExpr) -> MicroExpr {
    let zero = MicroExpr::constant(0, 64);
    let cmp = |op| MicroExpr::binary(op, val.clone(), zero.clone());
    let scmp = |op| MicroExpr::binary(op, signed_view(val.clone()), zero.clone());
    match mnemonic {
        "je" | "jz" => cmp(BinOp::Eq),
        "jne" | "jnz" => cmp(BinOp::Ne),
        "js" => scmp(BinOp::Slt),
        "jns" => scmp(BinOp::Sge),
        "jl" | "jnge" => scmp(BinOp::Slt),
        "jle" | "jng" => scmp(BinOp::Sle),
        "jg" | "jnle" => scmp(BinOp::Sgt),
        "jge" | "jnl" => scmp(BinOp::Sge),
        "ja" | "jnbe" => cmp(BinOp::Ne),
        "jbe" | "jna" => cmp(BinOp::Eq),
        // CF is provably 0 after a logical op: `jae`/`jnb` always taken, `jb`/
        // `jnae` never. Sound constants (compiler artifacts / provable bounds).
        "jae" | "jnb" | "jnc" => MicroExpr::constant(1, 8),
        "jb" | "jnae" | "jc" => MicroExpr::constant(0, 8),
        _ => MicroExpr::Unknown(format!("cond({mnemonic})")),
    }
}

/// The condition a `jcc` tests after a **floating-point** compare.
///
/// `ucomisd a, b` writes ZF, PF and CF, and leaves SF and OF at zero:
///
/// | outcome        | ZF | PF | CF |
/// |----------------|----|----|----|
/// | unordered (NaN)| 1  | 1  | 1  |
/// | a > b          | 0  | 0  | 0  |
/// | a < b          | 0  | 0  | 1  |
/// | a = b          | 1  | 0  | 0  |
///
/// So the same `jcc` means something different here than after an integer
/// `cmp`: `jb` reads CF, and CF is set both by *less than* and by *unordered*,
/// which is why a NaN takes the "less" branch of `if (x < y)` compiled the
/// obvious way. Naming these predicates after the relation they actually test —
/// LLVM's `fcmp` vocabulary, `o` for ordered and `u` for "or unordered" — keeps
/// that distinction in the IR instead of losing it to a `<`.
///
/// The IR has no float type (`__addsd(x, y)` is how the arithmetic reads), so
/// the result is an intrinsic too, and the suffix carries the width the compare
/// instruction itself named. `None` for a `jcc` this cannot state exactly — a
/// missing condition, never a wrong one.
fn float_branch_condition(cmp: &str, jcc: &str, args: &[MicroExpr]) -> Option<MicroExpr> {
    // `__ucomisd` / `__vcomiss` — the last letter is the operand width.
    let width = match cmp.chars().next_back()? {
        'd' => "sd",
        's' => "ss",
        _ => return None,
    };
    let pred = match jcc {
        "ja" => "ogt",
        "jae" => "oge",
        // CF is set by *less* **and** by unordered.
        "jb" => "ult",
        "jbe" => "ule",
        // ZF is set by *equal* **and** by unordered.
        "je" => "ueq",
        // …so its negation is "ordered and not equal".
        "jne" => "one",
        "jp" => "uno",
        "jnp" => "ord",
        // SF and OF are zero after a float compare, so `js`/`jg`/`jl`/… are
        // either constant or an alias of the above. Compilers do not emit them
        // here, and guessing which alias was meant is exactly the kind of
        // plausible answer this refuses to produce.
        _ => return None,
    };
    Some(MicroExpr::intrinsic(format!("__fcmp_{pred}_{width}"), args.to_vec()))
}

/// The floating-point compares, whose flags [`float_branch_condition`] reads.
/// `comis*` and `ucomis*` differ only in whether a signalling NaN raises an
/// exception; the flags they write are identical.
fn is_float_compare(name: &str) -> bool {
    matches!(
        name,
        "__ucomisd"
            | "__ucomiss"
            | "__comisd"
            | "__comiss"
            | "__vucomisd"
            | "__vucomiss"
            | "__vcomisd"
            | "__vcomiss"
    )
}

/// The flags of an operation the lift cannot state as a comparison: `add`, whose
/// carry is not a comparison of its operands, `inc` and `dec` on memory, which leave
/// the carry alone, and `bt`, whose only product is the carry. They travel as an
/// intrinsic over the operands the operation read, as a float compare's do, and are
/// never printed: [`branch_condition`] turns them into what a branch tests.
pub(crate) const ADD_FLAGS: &str = "__flags_add";
pub(crate) const INC_FLAGS: &str = "__flags_inc";
pub(crate) const DEC_FLAGS: &str = "__flags_dec";
pub(crate) const BT_FLAGS: &str = "__flags_bt";

/// What flags left as a stored result say once the operation is known: `add` keeps
/// its result as a [`CmpKind::Result`] flags value, which alone answers the zero and
/// sign conditions, and its operands are in the result's definition. `result` is
/// what the flags name, and `def_of` reads definitions. An operand that reads memory
/// is left out, since printing it at the branch would read it again, past whatever
/// wrote it since. `None` where the definition is not the plain sum.
pub(crate) fn flags_of_add(flags_value: &MicroExpr, def_of: &dyn Fn(&str) -> Option<MicroExpr>) -> Option<MicroExpr> {
    let MicroExpr::Compare { kind: CmpKind::Result, lhs, .. } = flags_value else { return None };
    let name = match lhs.as_ref() {
        MicroExpr::Var(name) => name,
        MicroExpr::Cast { expr, .. } => match expr.as_ref() {
            MicroExpr::Var(name) => name,
            _ => return None,
        },
        _ => return None,
    };
    let def = def_of(name)?;
    let (a, b) = sum_operands(&def)?;
    let clean = |e: &MicroExpr| !matches!(e, MicroExpr::Load { .. } | MicroExpr::Call { .. });
    (clean(a) && clean(b)).then(|| MicroExpr::intrinsic(ADD_FLAGS, vec![a.clone(), b.clone(), lhs.as_ref().clone()]))
}

/// The operands of a sum as a write leaves it: under the cast a 32-bit write has, or
/// in the low part of the register a narrower one keeps the rest of.
fn sum_operands(e: &MicroExpr) -> Option<(&MicroExpr, &MicroExpr)> {
    match e {
        MicroExpr::Binary(BinOp::Add, a, b) => Some((a, b)),
        MicroExpr::Cast { expr, .. } => sum_operands(expr),
        MicroExpr::Binary(BinOp::Or, _, low) => sum_operands(low),
        _ => None,
    }
}

/// `a @ b` at the width of its operands. Below 64 bits the cast is what makes it wrap
/// there, which every flag of it depends on.
fn at_operand_width(op: BinOp, a: &MicroExpr, b: &MicroExpr) -> MicroExpr {
    let value = MicroExpr::binary(op, a.clone(), b.clone());
    match value_width(a).or_else(|| value_width(b)) {
        Some(bits) => MicroExpr::Cast { signed: false, bits, expr: Box::new(value) },
        None => value,
    }
}

/// OF after `a + b` or `a - b`, as "the sign bit of this is set": an addition
/// overflows when both operands differ in sign from the result, a subtraction when
/// `a` differs from `b` and from the result.
fn overflow_sign(op: BinOp, a: &MicroExpr, b: &MicroExpr, r: &MicroExpr) -> MicroExpr {
    let xor = |x: &MicroExpr, y: &MicroExpr| MicroExpr::binary(BinOp::Xor, x.clone(), y.clone());
    let (first, second) = match op {
        BinOp::Sub => (xor(a, b), xor(a, r)),
        _ => (xor(a, r), xor(b, r)),
    };
    let both = MicroExpr::binary(BinOp::And, first, second);
    match value_width(a).or_else(|| value_width(b)) {
        Some(bits) => MicroExpr::Cast { signed: true, bits, expr: Box::new(both) },
        None => both,
    }
}

/// The conditions a sum's flags answer. `carry` is what CF says, where it says
/// anything: `inc` leaves it as it was, and then only the conditions that do not read
/// it have an answer.
fn sum_condition(jcc: &str, a: &MicroExpr, b: &MicroExpr, result: Option<&MicroExpr>, has_carry: bool) -> Option<MicroExpr> {
    let r = result.cloned().unwrap_or_else(|| at_operand_width(BinOp::Add, a, b));
    let zero = || MicroExpr::constant(0, 64);
    let is_zero = |op| MicroExpr::binary(op, r.clone(), zero());
    let carry = |op| MicroExpr::binary(op, r.clone(), a.clone());
    let overflowed = |op| MicroExpr::binary(op, overflow_sign(BinOp::Add, a, b, &r), zero());
    let negative = || MicroExpr::binary(BinOp::Slt, signed_view(r.clone()), zero());
    let below_zero = |op| MicroExpr::binary(op, negative(), overflowed(BinOp::Slt));
    Some(match jcc {
        "je" | "jz" => is_zero(BinOp::Eq),
        "jne" | "jnz" => is_zero(BinOp::Ne),
        "js" => MicroExpr::binary(BinOp::Slt, signed_view(r.clone()), zero()),
        "jns" => MicroExpr::binary(BinOp::Sge, signed_view(r.clone()), zero()),
        "jo" => overflowed(BinOp::Slt),
        "jno" => overflowed(BinOp::Sge),
        // Signed order is the sign of the exact sum: the result's, flipped by overflow.
        "jl" | "jnge" => below_zero(BinOp::Ne),
        "jge" | "jnl" => below_zero(BinOp::Eq),
        "jle" | "jng" => MicroExpr::binary(BinOp::Or, is_zero(BinOp::Eq), below_zero(BinOp::Ne)),
        "jg" | "jnle" => MicroExpr::binary(BinOp::And, is_zero(BinOp::Ne), below_zero(BinOp::Eq)),
        // A sum wrapped exactly when it came out below what was added to.
        "jb" | "jc" | "jnae" if has_carry => carry(BinOp::Ult),
        "jae" | "jnc" | "jnb" if has_carry => carry(BinOp::Uge),
        "ja" | "jnbe" if has_carry => MicroExpr::binary(BinOp::And, carry(BinOp::Uge), is_zero(BinOp::Ne)),
        "jbe" | "jna" if has_carry => MicroExpr::binary(BinOp::Or, carry(BinOp::Ult), is_zero(BinOp::Eq)),
        _ => return None,
    })
}

/// `bt x, n` puts bit `n` of `x` in CF and says nothing else a compiler reads.
fn bit_test_condition(jcc: &str, x: &MicroExpr, n: &MicroExpr) -> Option<MicroExpr> {
    let bit = MicroExpr::binary(BinOp::And, MicroExpr::binary(BinOp::Shr, x.clone(), n.clone()), MicroExpr::constant(1, 8));
    match jcc {
        "jb" | "jc" | "jnae" => Some(MicroExpr::binary(BinOp::Ne, bit, MicroExpr::constant(0, 64))),
        "jae" | "jnc" | "jnb" => Some(MicroExpr::binary(BinOp::Eq, bit, MicroExpr::constant(0, 64))),
        _ => None,
    }
}

/// A condition of the flags in [`ADD_FLAGS`] and its kin, or `None` if `name` is not
/// one of them; `Some(None)` if the flags do not answer this condition.
fn arithmetic_condition(name: &str, jcc: &str, args: &[MicroExpr]) -> Option<Option<MicroExpr>> {
    let one = || MicroExpr::constant(1, 64);
    Some(match (name, args) {
        (ADD_FLAGS, [a, b]) => sum_condition(jcc, a, b, None, true),
        (ADD_FLAGS, [a, b, r]) => sum_condition(jcc, a, b, Some(r), true),
        (INC_FLAGS, [a]) => sum_condition(jcc, a, &one(), None, false),
        // `dec` is `cmp a, 1` in every flag but the carry, which it leaves.
        (DEC_FLAGS, [a]) => match jcc {
            "ja" | "jae" | "jb" | "jbe" | "jc" | "jnc" | "jnb" | "jnae" | "jna" | "jnbe" => None,
            _ => Some(branch_condition(jcc, &MicroExpr::compare(CmpKind::Cmp, a.clone(), one()))),
        },
        (BT_FLAGS, [x, n]) => bit_test_condition(jcc, x, n),
        _ => return None,
    })
}

/// The condition-code table: which combination of the flags each condition
/// tests, given the precise `Compare` that defined them. Only sound when the
/// dataflow value reaching the branch *is* a `Compare` (see the module docs on
/// [`MicroExpr::OpaqueFlags`]); anything else renders a placeholder rather than
/// a guess.
///
/// `mnemonic` is a condition in the x86 `jcc` spelling — see the module docs
/// for why that vocabulary, and not a neutral invented one, is the interface.
pub(crate) fn branch_condition(mnemonic: &str, flags_value: &MicroExpr) -> MicroExpr {
    if let MicroExpr::Call { target: CallTarget::Intrinsic(name), args } = flags_value {
        if is_float_compare(name) {
            return float_branch_condition(name, mnemonic, args)
                .unwrap_or_else(|| MicroExpr::Unknown(format!("cond({mnemonic}) after {name}")));
        }
        if let Some(answer) = arithmetic_condition(name, mnemonic, args) {
            return answer.unwrap_or_else(|| MicroExpr::Unknown(format!("cond({mnemonic})")));
        }
    }
    let MicroExpr::Compare { kind, lhs, rhs } = flags_value else {
        return MicroExpr::Unknown(format!("cond({mnemonic})"));
    };
    let (lhs, rhs) = (lhs.as_ref().clone(), rhs.as_ref().clone());

    if *kind == CmpKind::Result {
        // Flags from a stored result (`dec ecx`, `sub rax,rbx`, `and edx,edx`):
        // `lhs` is the result, `rhs` is the constant 0. Only the zero flag is a
        // sound function of the result alone, so recover just the equality
        // branches; the sign/magnitude conditions need carry/overflow the
        // result doesn't carry and stay opaque (a missing condition, never a
        // wrong one).
        return match mnemonic {
            "je" => MicroExpr::binary(BinOp::Eq, lhs, rhs),
            "jne" => MicroExpr::binary(BinOp::Ne, lhs, rhs),
            // SF is literally the sign bit of the stored result — a pure function
            // of it, independent of the overflow the magnitude branches need — so
            // `js`/`jns` reconstruct even after arithmetic (`rhs` is the `0`).
            "js" => MicroExpr::binary(BinOp::Slt, signed_view(lhs), rhs),
            "jns" => MicroExpr::binary(BinOp::Sge, signed_view(lhs), rhs),
            _ => MicroExpr::Unknown(format!("cond({mnemonic}) after result")),
        };
    }

    if *kind == CmpKind::LogicalResult {
        // Flags from a logical op that kept its result (`and edx,edx`): OF=CF=0,
        // so the whole family reconstructs from the result's sign/zero-ness.
        return logical_flag_cond(mnemonic, lhs);
    }

    if *kind == CmpKind::Test {
        // `test a,b` sets flags from `a & b` (a *logical* op, so OF and CF are
        // cleared to 0) without storing it; `a,a` is the common "is a zero /
        // negative / <=0" idiom. Because OF=CF=0, every signed *and* unsigned
        // condition is a pure function of the tested value's sign and zero-ness
        // — so the whole `jcc` family reconstructs soundly, not just `je`/`jne`.
        let val = if lhs == rhs { lhs } else { MicroExpr::binary(BinOp::And, lhs, rhs) };
        return logical_flag_cond(mnemonic, val);
    }

    match mnemonic {
        "je" => MicroExpr::binary(BinOp::Eq, lhs, rhs),
        "jne" => MicroExpr::binary(BinOp::Ne, lhs, rhs),
        "ja" => MicroExpr::binary(BinOp::Ugt, lhs, rhs),
        "jae" => MicroExpr::binary(BinOp::Uge, lhs, rhs),
        "jb" => MicroExpr::binary(BinOp::Ult, lhs, rhs),
        "jbe" => MicroExpr::binary(BinOp::Ule, lhs, rhs),
        "jg" => MicroExpr::binary(BinOp::Sgt, signed_view(lhs), signed_view(rhs)),
        "jge" => MicroExpr::binary(BinOp::Sge, signed_view(lhs), signed_view(rhs)),
        "jl" => MicroExpr::binary(BinOp::Slt, signed_view(lhs), signed_view(rhs)),
        "jle" => MicroExpr::binary(BinOp::Sle, signed_view(lhs), signed_view(rhs)),
        "jo" | "jno" => {
            let r = at_operand_width(BinOp::Sub, &lhs, &rhs);
            let op = if mnemonic == "jo" { BinOp::Slt } else { BinOp::Sge };
            MicroExpr::binary(op, overflow_sign(BinOp::Sub, &lhs, &rhs, &r), MicroExpr::constant(0, 64))
        }
        // SF is the sign of the difference at the width compared, and wraps there:
        // sign-extended first, a 32-bit `cmp` that overflows read as its true sign.
        "js" => MicroExpr::binary(BinOp::Slt, difference_at_width(lhs, rhs), MicroExpr::constant(0, 64)),
        "jns" => MicroExpr::binary(BinOp::Sge, difference_at_width(lhs, rhs), MicroExpr::constant(0, 64)),
        _ => MicroExpr::Unknown(format!("cond({mnemonic})")),
    }
}
