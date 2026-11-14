// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Division by a constant, from the multiply and shift a compiler puts in its
//! place: `x / 10` compiles to `(x * 0xcccccccd) >> 35`, and the text said the
//! second.
//!
//! The shape alone proves nothing: a multiply by a constant and a shift is also
//! fixed-point arithmetic, a hash, a scale. A rewrite is made only where the
//! **error bound** holds for every value the operand can hold, so that the two
//! expressions agree on all of them, not on the ones a test tried. With
//! `m * d = 2^n + e`, `0 <= e < m`, and `x` below `2^w`:
//!
//! - unsigned, `floor(x * m / 2^n) == floor(x / d)` when `e * (2^w - 1) < 2^n`:
//!   for `x = q*d + r` the error term `x * e / 2^n` stays below 1, so it cannot
//!   carry `r / d` past the next integer;
//! - signed, `floor(x * m / 2^n) + (x < 0) == x / d` (C's, toward zero) for `x`
//!   in `[-2^(w-1), 2^(w-1))` when `e > 0` and `e * 2^(w-1) <= 2^n`: a negative
//!   `x` then lands strictly inside `(q - 1, q]` below its quotient, never on it,
//!   and the `+ 1` brings it to the quotient; a non-negative one as above.
//!
//! The compilers choose `m` to meet exactly these bounds, so what they emit
//! passes; anything that does not pass stays the multiply and shift it is, which
//! is correct and longer. The forms below are the ones gcc and clang emit at
//! `-O2` for 32- and 64-bit operands on a 64-bit target; a divisor needing a
//! multiplier past the word (gcc's add-back form, `x / 7` unsigned) is not
//! among them and is left alone.

use std::collections::HashMap;

use n0xis_arch::{BinOp, Bits, CallTarget, MicroExpr, MicroStmt};

use crate::ssa::SsaBlock;

/// The divisor `d` the multiply by `m` and shift by `n` divide by, for every
/// operand of `xbits` bits, or `None` where the bound does not hold. See the
/// module's comment for the two bounds.
pub(crate) fn divisor(m: u128, n: u32, xbits: u32, signed: bool) -> Option<u128> {
    if n > 126 || m < 2 || xbits == 0 || xbits > 64 {
        return None;
    }
    let p = 1u128 << n;
    let d = p.div_ceil(m);
    if d < 2 {
        return None;
    }
    let e = m.checked_mul(d)? - p;
    let holds = if signed {
        e > 0 && e.checked_mul(1u128 << (xbits - 1)).is_some_and(|b| b <= p)
    } else {
        e.checked_mul((1u128 << xbits) - 1).is_some_and(|b| b < p)
    };
    holds.then_some(d)
}

/// What a variable holds, where that is a value of the registers it reads and
/// nothing else: an SSA name is defined once, so its definition can be read where
/// it is used. A load or a call is not such a value, and is not looked through.
pub(crate) fn pure_defs(blocks: &[SsaBlock]) -> HashMap<String, MicroExpr> {
    let mut defs = HashMap::new();
    for b in blocks {
        for s in &b.stmts {
            if let MicroStmt::Assign { dst, value } = &s.stmt
                && is_pure(value)
            {
                defs.insert(dst.clone(), value.clone());
            }
        }
    }
    defs
}

fn is_pure(e: &MicroExpr) -> bool {
    match e {
        MicroExpr::Const { .. } | MicroExpr::Var(_) => true,
        MicroExpr::Unary(_, v) | MicroExpr::Cast { expr: v, .. } => is_pure(v),
        MicroExpr::Binary(_, l, r) => is_pure(l) && is_pure(r),
        MicroExpr::Call { target: CallTarget::Intrinsic(name), args } if name == "__mulh" || name == "__umulh" => {
            args.iter().all(is_pure)
        }
        _ => false,
    }
}

fn resolve<'a>(e: &'a MicroExpr, defs: &'a HashMap<String, MicroExpr>) -> &'a MicroExpr {
    match e {
        MicroExpr::Var(v) => defs.get(v).unwrap_or(e),
        _ => e,
    }
}

fn constant(e: &MicroExpr) -> Option<u128> {
    match e {
        MicroExpr::Const { value, .. } if *value >= 0 => Some(*value as u128),
        _ => None,
    }
}

/// How many bits an operand can hold, read from the zero extension that made it.
fn unsigned_bits(e: &MicroExpr) -> Option<Bits> {
    match e {
        MicroExpr::Cast { signed: false, bits, expr } => Some(unsigned_bits(expr).map_or(*bits, |b| b.min(*bits))),
        MicroExpr::Load { signed: false, bits, .. } => Some(*bits),
        _ => None,
    }
}

/// `x` and `m` of `x * m`, either order, the constant positive.
fn times_constant<'a>(l: &'a MicroExpr, r: &'a MicroExpr) -> Option<(&'a MicroExpr, u128)> {
    match (constant(l), constant(r)) {
        (Some(m), None) => Some((r, m)),
        (None, Some(m)) => Some((l, m)),
        _ => None,
    }
}

/// A product's floor at a shift: the operand, the multiplier, the total shift and
/// the operand's bits. `Sar(x * m, n)` with `x` sign-extended from `w` bits, or
/// `Sar(__mulh(x, m), s)` at 64 bits (`n = 64 + s`), or the high half unshifted.
struct Floor<'a> {
    x: &'a MicroExpr,
    m: u128,
    n: u32,
    w: Bits,
    /// The product or high half itself: its sign is `x`'s, so a sign taken from
    /// it is `x`'s too.
    product: &'a MicroExpr,
}

///
/// `cut`: only the low 32 bits of the floor are read, and there a logical shift by
/// no more than 32 is the same as the arithmetic one (gcc's `x / 3` takes it so).
fn signed_floor<'a>(e: &'a MicroExpr, defs: &'a HashMap<String, MicroExpr>, cut: bool) -> Option<Floor<'a>> {
    let (inner, s) = match e {
        MicroExpr::Binary(BinOp::Sar, t, k) => (t.as_ref(), u32::try_from(constant(k)?).ok()?),
        MicroExpr::Binary(BinOp::Shr, t, k) if cut && constant(k).is_some_and(|k| k <= 32) => (t.as_ref(), u32::try_from(constant(k)?).ok()?),
        other => (other, 0),
    };
    match resolve(inner, defs) {
        // A 64-bit product of a sign-extended narrower operand: exact while it
        // cannot overflow, `|x| * m < 2^63`.
        MicroExpr::Binary(BinOp::Mul, l, r) if s > 0 && s < 64 => {
            let (x, m) = times_constant(l, r)?;
            let MicroExpr::Cast { signed: true, bits: w, .. } = x else { return None };
            (*w <= 32 && m.checked_shl(*w - 1).is_some_and(|b| b < 1 << 63)).then_some(Floor { x, m, n: s, w: *w, product: inner })
        }
        MicroExpr::Call { target: CallTarget::Intrinsic(name), args } if name == "__mulh" && s < 64 => {
            let [a, b, width] = args.as_slice() else { return None };
            if constant(width)? != 64 {
                return None;
            }
            let (x, m) = times_constant(a, b)?;
            let w = match x {
                MicroExpr::Cast { signed: true, bits, .. } => *bits,
                _ => 64,
            };
            (m < 1 << 63).then_some(Floor { x, m, n: 64 + s, w, product: inner })
        }
        _ => None,
    }
}

/// `e` with each cast that only narrows a value already cut at least as far
/// dropped: `(int32_t)(uint32_t)rdi` is `(int32_t)rdi`. The lift writes one
/// operand each way (`movslq %edi` and `sar $31,%edi` read the same `edi`).
fn canonical(e: &MicroExpr) -> MicroExpr {
    match e {
        MicroExpr::Cast { signed, bits, expr } => match expr.as_ref() {
            MicroExpr::Cast { bits: inner, expr: under, .. } if inner >= bits => {
                canonical(&MicroExpr::Cast { signed: *signed, bits: *bits, expr: under.clone() })
            }
            _ => MicroExpr::Cast { signed: *signed, bits: *bits, expr: Box::new(canonical(expr)) },
        },
        other => other.clone(),
    }
}

/// Is `e` `x`'s sign as `0` or `-1` (`Sar(x, k)`, every bit of it the sign bit)?
fn sign_mask(e: &MicroExpr, x: &MicroExpr, w: Bits) -> bool {
    let MicroExpr::Binary(BinOp::Sar, v, k) = e else { return false };
    canonical(v) == canonical(x) && constant(k).is_some_and(|k| k >= u128::from(w - 1) && k < 64)
}

/// Is `e` `x`'s sign as `0` or `1` (`Shr` of the product, or of `x` at 64 bits, by 63)?
fn sign_bit(e: &MicroExpr, f: &Floor, defs: &HashMap<String, MicroExpr>) -> bool {
    let MicroExpr::Binary(BinOp::Shr, v, k) = e else { return false };
    constant(k) == Some(63) && (resolve(v, defs) == resolve(f.product, defs) || (f.w == 64 && v.as_ref() == f.x))
}

/// `e` under any number of cuts to its low 32 bits, and whether there was one.
fn without_cast32(e: &MicroExpr) -> (bool, &MicroExpr) {
    match e {
        MicroExpr::Cast { signed: false, bits: 32, expr } => (true, without_cast32(expr).1),
        other => (false, other),
    }
}

fn divide(op: BinOp, x: &MicroExpr, d: u128) -> MicroExpr {
    MicroExpr::binary(op, canonical(x), MicroExpr::constant(d as i128, 64))
}

/// `e` as a division, where it is one for every operand. `defs` is [`pure_defs`]
/// of the function `e` is in. Only on a 64-bit word: the forms are read as the IR
/// computes them there.
pub(crate) fn as_division(e: &MicroExpr, defs: &HashMap<String, MicroExpr>) -> Option<MicroExpr> {
    match e {
        // Unsigned: `(x * m) >> n` with `x` zero-extended from `w` bits and the
        // product inside the word, or `__umulh(x, m) >> s`.
        MicroExpr::Binary(BinOp::Shr, t, k) => {
            let s = u32::try_from(constant(k)?).ok()?;
            match resolve(t, defs) {
                MicroExpr::Binary(BinOp::Mul, l, r) if s < 64 => {
                    let (x, m) = times_constant(l, r)?;
                    let w = unsigned_bits(x)?;
                    let fits = m.checked_mul((1u128 << w) - 1).is_some_and(|p| p < 1 << 64);
                    (w < 64 && fits).then_some(())?;
                    Some(divide(BinOp::UDiv, x, divisor(m, s, w, false)?))
                }
                MicroExpr::Call { target: CallTarget::Intrinsic(name), args } if name == "__umulh" && s < 64 => {
                    let [a, b, width] = args.as_slice() else { return None };
                    if constant(width)? != 64 {
                        return None;
                    }
                    let (x, m) = times_constant(a, b)?;
                    let w = unsigned_bits(x).map_or(64, |w| w.min(64));
                    Some(divide(BinOp::UDiv, x, divisor(m, 64 + s, w, false)?))
                }
                _ => None,
            }
        }
        // Signed, gcc: `floor - sign` with the sign as `0`/`-1`, both sides at 64
        // bits or both cut to 32. Either way the difference is the quotient at 64
        // bits: cut, a negative floor is `2^32 + q` and its sign `2^32 - 1`.
        MicroExpr::Binary(BinOp::Sub, a, b) => {
            let ((ca, a), (cb, b)) = (without_cast32(a), without_cast32(b));
            let f = signed_floor(a, defs, ca)?;
            (ca == cb && (!ca || f.w <= 32) && sign_mask(b, f.x, f.w)).then_some(())?;
            Some(divide(BinOp::SDiv, f.x, divisor(f.m, f.n, f.w, true)?))
        }
        // Signed, clang: `floor + sign` with the sign as `0`/`1`, at 64 bits.
        MicroExpr::Binary(BinOp::Add, a, b) => {
            let (f, sign) = signed_floor(a, defs, false).map(|f| (f, b)).or_else(|| signed_floor(b, defs, false).map(|f| (f, a)))?;
            sign_bit(sign, &f, defs).then_some(())?;
            Some(divide(BinOp::SDiv, f.x, divisor(f.m, f.n, f.w, true)?))
        }
        // The same cut to 32 bits on each side and after: only the low half is the
        // quotient's, so it is replaced with the cut around it.
        MicroExpr::Cast { signed: false, bits: 32, expr } => {
            let MicroExpr::Binary(BinOp::Add, a, b) = expr.as_ref() else { return None };
            let ((true, a), (true, b)) = (without_cast32(a), without_cast32(b)) else { return None };
            let (f, sign) = signed_floor(a, defs, true).map(|f| (f, b)).or_else(|| signed_floor(b, defs, true).map(|f| (f, a)))?;
            (f.w <= 32 && sign_bit(sign, &f, defs)).then_some(())?;
            Some(MicroExpr::Cast { signed: false, bits: 32, expr: Box::new(divide(BinOp::SDiv, f.x, divisor(f.m, f.n, f.w, true)?)) })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CfgInput, CfgPass, Ctx, DecompInput, DecompPass, DecompStyle, OptimizePass, Pass, SsaPass};
    use n0xis_arch::X64;
    use n0xis_contracts::Va;
    use n0xis_sources::Snapshot;

    // gcc -O2 and clang -O2, x86-64, from `x / 10` and friends (`unsigned`,
    // `int`, `unsigned long`, `long`), the bytes of the whole function.
    const GCC_U32_10: &[u8] = &[0x89, 0xf8, 0xba, 0xcd, 0xcc, 0xcc, 0xcc, 0x48, 0x0f, 0xaf, 0xc2, 0x48, 0xc1, 0xe8, 0x23, 0xc3];
    const GCC_I32_10: &[u8] = &[0x48, 0x63, 0xc7, 0xc1, 0xff, 0x1f, 0x48, 0x69, 0xc0, 0x67, 0x66, 0x66, 0x66, 0x48, 0xc1, 0xf8, 0x22, 0x29, 0xf8, 0xc3];
    const GCC_U64_10: &[u8] = &[
        0x48, 0xb8, 0xcd, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x48, 0xf7, 0xe7, 0x48, 0x89, 0xd0, 0x48, 0xc1, 0xe8, 0x03, 0xc3,
    ];
    const GCC_I64_10: &[u8] = &[
        0x48, 0xb8, 0x67, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x48, 0xf7, 0xef, 0x48, 0xc1, 0xff, 0x3f, 0x48, 0xc1, 0xfa, 0x02,
        0x48, 0x89, 0xd0, 0x48, 0x29, 0xf8, 0xc3,
    ];
    const CLANG_I32_10: &[u8] = &[
        0x48, 0x63, 0xc7, 0x48, 0x69, 0xc0, 0x67, 0x66, 0x66, 0x66, 0x48, 0x89, 0xc1, 0x48, 0xc1, 0xe9, 0x3f, 0x48, 0xc1, 0xf8, 0x22,
        0x01, 0xc8, 0xc3,
    ];
    const CLANG_I64_10: &[u8] = &[
        0x48, 0x89, 0xf8, 0x48, 0xb9, 0x67, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x48, 0xf7, 0xe9, 0x48, 0x89, 0xd0, 0x48, 0xc1,
        0xe8, 0x3f, 0x48, 0xc1, 0xfa, 0x02, 0x48, 0x01, 0xd0, 0xc3,
    ];
    /// `int x / 3`: the floor taken with a logical shift by 32, the same low half.
    const GCC_I32_3: &[u8] = &[0x48, 0x63, 0xc7, 0xc1, 0xff, 0x1f, 0x48, 0x69, 0xc0, 0x56, 0x55, 0x55, 0x55, 0x48, 0xc1, 0xe8, 0x20, 0x29, 0xf8, 0xc3];
    /// `unsigned x / 7`: the multiplier needs 33 bits, and gcc adds back. Not a form read here.
    const GCC_U32_7: &[u8] =
        &[0x89, 0xf8, 0x48, 0x69, 0xc0, 0x25, 0x49, 0x92, 0x24, 0x48, 0xc1, 0xe8, 0x20, 0x29, 0xc7, 0xd1, 0xef, 0x01, 0xf8, 0xc1, 0xe8, 0x02, 0xc3];

    fn on_bytes<T>(code: &[u8], f: impl FnOnce(&Ctx, crate::CfgArtifact) -> T) -> T {
        let snap = Snapshot::builder().region(Va(0x1000), code.to_vec()).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), code.len())).unwrap();
        f(&ctx, cfg)
    }

    fn text(code: &[u8]) -> String {
        on_bytes(code, |ctx, cfg| {
            let input = DecompInput {
                cfg,
                style: DecompStyle::Ssa,
                explain: false,
                strip_block_labels: true,
                var_names: Default::default(),
                var_types: Default::default(),
                struct_defs: Default::default(),
            };
            DecompPass.run(ctx, input).unwrap().pseudo.join("\n")
        })
    }

    /// The optimized IR, which the emulator runs.
    fn optimized(code: &[u8]) -> Vec<crate::ssa::SsaBlock> {
        on_bytes(code, |ctx, cfg| OptimizePass.run(ctx, SsaPass.run(ctx, cfg).unwrap()).unwrap().blocks)
    }

    /// The function's answer for `x` in `rdi`.
    fn run(blocks: &[crate::ssa::SsaBlock], x: u64) -> u64 {
        crate::Emulator::new(blocks, None).set_var("rdi.0", x).run().unwrap().ret.unwrap()
    }

    /// Operands at the edges of each range and between, for the 32- and 64-bit forms.
    fn operands() -> Vec<u64> {
        let mut xs = vec![0, 1, 9, 10, 11, 99, 100, 0x7fff_ffff, 0x8000_0000, 0xffff_fff6, 0xffff_ffff, 1 << 32, u64::MAX, u64::MAX - 9];
        xs.extend([i64::MIN as u64, i64::MAX as u64, (i64::MIN + 9) as u64, -1i64 as u64, -9i64 as u64, -10i64 as u64, -11i64 as u64]);
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..2000 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            xs.push(s);
            xs.push(s & 0xffff_ffff);
        }
        xs
    }

    /// A function's bytes, the division its text should say, and C's own answer.
    type Case = (&'static [u8], &'static str, fn(u64) -> u64);

    #[test]
    fn a_multiply_and_shift_that_divides_for_every_operand_is_a_division() {
        let cases: [Case; 7] = [
            (GCC_U32_10, "((uint32_t)rdi.0 / 0xa)", |x| u64::from(x as u32 / 10)),
            (GCC_I32_10, "((int32_t)rdi.0 / 0xa)", |x| (x as i32 / 10) as u64),
            (GCC_U64_10, "((uint64_t)rdi.0 / 0xa)", |x| x / 10),
            (GCC_I64_10, "((int64_t)rdi.0 / 0xa)", |x| (x as i64 / 10) as u64),
            (CLANG_I32_10, "((int32_t)rdi.0 / 0xa)", |x| (x as i32 / 10) as u64),
            (CLANG_I64_10, "((int64_t)rdi.0 / 0xa)", |x| (x as i64 / 10) as u64),
            (GCC_I32_3, "((int32_t)rdi.0 / 0x3)", |x| (x as i32 / 3) as u64),
        ];
        for (code, said, source) in cases {
            let text = text(code);
            assert!(text.contains(said), "{said}: {text}");
            // What the source computes, the function computes as the text says it:
            // for a 32-bit answer its low half, which is all a caller reads.
            let low = said.contains("32_t");
            let blocks = optimized(code);
            for x in operands() {
                let (got, want) = (run(&blocks, x), source(x));
                let (got, want) = if low { (got as u32 as u64, want as u32 as u64) } else { (got, want) };
                assert_eq!(got, want, "{said} at x={x:#x}");
            }
        }
    }

    /// Cut to 32 bits, a logical shift of the product is its floor only while
    /// the shift leaves no zero inside the low half: by 32 (gcc's `x / 3`), not by
    /// 34, where a negative product gets two zero bits for its two sign bits.
    #[test]
    fn a_logical_floor_is_read_only_where_the_low_half_is_the_same() {
        let cut = |e: MicroExpr| MicroExpr::Cast { signed: false, bits: 32, expr: Box::new(e) };
        let x = MicroExpr::Cast { signed: true, bits: 32, expr: Box::new(MicroExpr::var("rdi.0")) };
        let form = |m: i128, n: i128| {
            let floor = MicroExpr::binary(BinOp::Shr, MicroExpr::binary(BinOp::Mul, x.clone(), MicroExpr::constant(m, 64)), MicroExpr::constant(n, 64));
            let sign = MicroExpr::binary(BinOp::Sar, x.clone(), MicroExpr::constant(31, 64));
            MicroExpr::binary(BinOp::Sub, cut(floor), cut(sign))
        };
        let defs = HashMap::new();
        assert!(as_division(&form(0x5555_5556, 32), &defs).is_some());
        assert_eq!(as_division(&form(0x6666_6667, 34), &defs), None);
        // And the emulator says why: at -1 the logical floor's low half is 0x3fffffff,
        // and the answer 0x40000000 where `-1 / 10` is 0.
        let emulate = |e: MicroExpr| {
            let blocks = vec![crate::ssa::SsaBlock {
                id: 0,
                start: Va(0x1000),
                end: Va(0x1001),
                terminator: "ret".to_string(),
                successors: Vec::new(),
                phis: Vec::new(),
                stmts: vec![crate::ssa::SsaStmt { va: Va(0x1000), stmt: MicroStmt::Return(Some(e)) }],
                condition: None,
            }];
            crate::Emulator::new(&blocks, None).set_var("rdi.0", u64::MAX).run().unwrap().ret.unwrap() as u32
        };
        assert_eq!(emulate(form(0x6666_6667, 34)), 0x4000_0000);
        assert_eq!(emulate(form(0x5555_5556, 32)), 0);
    }

    #[test]
    fn a_multiply_and_shift_that_does_not_divide_stays_as_it_is() {
        // The unsigned `/ 10` with the multiplier one off: the bound fails, and
        // for `x = 0xfffffffa` the bytes give 0x19999999, not 0x19999998.
        let mut near = GCC_U32_10.to_vec();
        near[3] = 0xce;
        let text_near = text(&near);
        assert!(!text_near.contains(" / "), "{text_near}");
        assert!(text_near.contains("0xccccccce"), "{text_near}");
        let add_back = text(GCC_U32_7);
        assert!(!add_back.contains(" / "), "{add_back}");
    }

    /// The bound against every operand, at a width small enough to try them all.
    #[test]
    fn the_bound_is_exactly_what_every_operand_agrees_with() {
        for signed in [false, true] {
            let w = 12u32;
            let mut accepted = 0;
            for d in 2u128..300 {
                for n in w..w + 14 {
                    let m = (1u128 << n).div_ceil(d);
                    for m in [m, m + 1] {
                        let Some(got) = divisor(m, n, w, signed) else { continue };
                        accepted += 1;
                        let xs: Box<dyn Iterator<Item = i128>> =
                            if signed { Box::new(-(1i128 << (w - 1))..(1i128 << (w - 1))) } else { Box::new(0..(1i128 << w)) };
                        for x in xs {
                            let floor = (x * m as i128).div_euclid(1i128 << n);
                            let by_multiply = if signed { floor + i128::from(x < 0) } else { floor };
                            assert_eq!(by_multiply, x / got as i128, "x={x} m={m:#x} n={n} d={got} signed={signed}");
                        }
                    }
                }
            }
            assert!(accepted > 500, "the bound accepts what compilers emit: {accepted}");
        }
    }

    /// What the compilers emit for `/ 10`, `/ 3` and `/ 1000` passes; a multiplier
    /// one off, or an operand wider than the bound was proved for, does not.
    #[test]
    fn a_compilers_multiplier_passes_and_a_near_one_does_not() {
        assert_eq!(divisor(0xcccc_cccd, 35, 32, false), Some(10));
        assert_eq!(divisor(0x6666_6667, 34, 32, true), Some(10));
        assert_eq!(divisor(0x5555_5556, 32, 32, true), Some(3));
        assert_eq!(divisor(0xcccc_cccc_cccc_cccd, 67, 64, false), Some(10));
        assert_eq!(divisor(0x6666_6666_6666_6667, 66, 64, true), Some(10));
        assert_eq!(divisor(0x1062_4dd3, 38, 32, false), Some(1000));
        // `* 0xcccccccd >> 35` is `/ 10` for 32-bit operands, and not for 64-bit ones.
        assert_eq!(divisor(0xcccc_cccd, 35, 64, false), None);
        assert_eq!(divisor(0xcccc_ccce, 35, 32, false), None);
        assert_eq!(divisor(0x6666_6666, 34, 32, true), None);
    }
}
