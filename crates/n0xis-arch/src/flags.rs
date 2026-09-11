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

/// The condition-code table: which combination of the flags each condition
/// tests, given the precise `Compare` that defined them. Only sound when the
/// dataflow value reaching the branch *is* a `Compare` (see the module docs on
/// [`MicroExpr::OpaqueFlags`]); anything else renders a placeholder rather than
/// a guess.
///
/// `mnemonic` is a condition in the x86 `jcc` spelling — see the module docs
/// for why that vocabulary, and not a neutral invented one, is the interface.
pub(crate) fn branch_condition(mnemonic: &str, flags_value: &MicroExpr) -> MicroExpr {
    if let MicroExpr::Call { target: CallTarget::Intrinsic(name), args } = flags_value
        && is_float_compare(name)
    {
        return float_branch_condition(name, mnemonic, args)
            .unwrap_or_else(|| MicroExpr::Unknown(format!("cond({mnemonic}) after {name}")));
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
        "js" => MicroExpr::binary(
            BinOp::Slt,
            MicroExpr::binary(BinOp::Sub, signed_view(lhs), signed_view(rhs)),
            MicroExpr::constant(0, 64),
        ),
        "jns" => MicroExpr::binary(
            BinOp::Sge,
            MicroExpr::binary(BinOp::Sub, signed_view(lhs), signed_view(rhs)),
            MicroExpr::constant(0, 64),
        ),
        _ => MicroExpr::Unknown(format!("cond({mnemonic})")),
    }
}
