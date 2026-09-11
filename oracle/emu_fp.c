// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The emulator corpus, part three: floating point.
//
// The census of a shipped library puts this second only to memory: about 90 of
// 400 functions stop on a vector or floating-point construct. Nothing had ever
// checked that layer — not wrongly, but not at all. The lift turns every FP
// instruction into a named intrinsic (`__addsd(x, y)`), which is honest and
// says nothing about whether the intrinsic means what the instruction means.
//
// Every function here takes and returns **bit patterns**, so the driver stays
// an integer-in/integer-out program and the calling convention under test is
// the integer one. That is deliberate: it isolates the arithmetic from the
// argument passing, and it makes the inputs adversarial for free — the driver's
// value list, read as doubles, is NaNs, negative zero, the smallest denormal,
// and a couple of ordinary numbers. Those are exactly the values a naive model
// gets wrong.
//
// Two families:
//   * `emu_fp_*`   — the raw bit pattern as a double. NaN, -0.0, denormals.
//   * `emu_fpn_*`  — the same bits forced into a normal exponent, so ordinary
//                    arithmetic is exercised too and a result that is NaN
//                    either way cannot hide a defect.

#include <stdint.h>
#include <string.h>

#define EXPORT __attribute__((visibility("default")))

// The bit-pattern converters are plumbing, not subject matter. At `-O0` gcc
// emits them as real calls and this corpus stops being leaf-only, which would
// mix "does the emulator follow a call" (already measured elsewhere) into
// "does it know what `addsd` does". Forced inline, they stay plumbing.
#define HELPER static inline __attribute__((always_inline))

HELPER double as_double(uint64_t b) {
    double d;
    memcpy(&d, &b, sizeof d);
    return d;
}

HELPER uint64_t as_bits(double d) {
    uint64_t b;
    memcpy(&b, &d, sizeof b);
    return b;
}

HELPER float as_float(uint64_t b) {
    float f;
    uint32_t w = (uint32_t)b;
    memcpy(&f, &w, sizeof f);
    return f;
}

HELPER uint64_t float_bits(float f) {
    uint32_t w;
    memcpy(&w, &f, sizeof w);
    return w;
}

// Sign and mantissa kept, exponent forced to 0x3fe — a normal number in
// [0.5, 1). Deterministic, and it never produces a NaN or a denormal, so the
// `emu_fpn_*` family measures ordinary arithmetic rather than special cases.
HELPER double normalish(uint64_t b) {
    return as_double((b & 0x800fffffffffffffull) | 0x3fe0000000000000ull);
}

// --- arithmetic, on the raw pattern -----------------------------------------

EXPORT uint64_t emu_fp_add(uint64_t a, uint64_t b) { return as_bits(as_double(a) + as_double(b)); }
EXPORT uint64_t emu_fp_sub(uint64_t a, uint64_t b) { return as_bits(as_double(a) - as_double(b)); }
EXPORT uint64_t emu_fp_mul(uint64_t a, uint64_t b) { return as_bits(as_double(a) * as_double(b)); }
EXPORT uint64_t emu_fp_div(uint64_t a, uint64_t b) { return as_bits(as_double(a) / as_double(b)); }

// --- arithmetic, on values that are certainly normal -------------------------

EXPORT uint64_t emu_fpn_add(uint64_t a, uint64_t b) {
    return as_bits(normalish(a) + normalish(b));
}
EXPORT uint64_t emu_fpn_mul(uint64_t a, uint64_t b) {
    return as_bits(normalish(a) * normalish(b));
}
EXPORT uint64_t emu_fpn_div(uint64_t a, uint64_t b) {
    return as_bits(normalish(a) / normalish(b));
}
// Three operations chained, so an error in one shows up scaled rather than
// cancelled.
EXPORT uint64_t emu_fpn_chain(uint64_t a, uint64_t b, uint64_t c) {
    double x = normalish(a), y = normalish(b), z = normalish(c);
    return as_bits((x + y) * z - x / (y + 2.0));
}

// --- single precision --------------------------------------------------------

EXPORT uint64_t emu_fp_addf(uint64_t a, uint64_t b) {
    return float_bits(as_float(a) + as_float(b));
}
EXPORT uint64_t emu_fp_mulf(uint64_t a, uint64_t b) {
    return float_bits(as_float(a) * as_float(b));
}

// --- the operations whose NaN and zero rules are the whole point -------------
//
// `minsd`/`maxsd` are not `fmin`/`fmax`: if either operand is NaN the result is
// the *second* source, and `min(+0.0, -0.0)` is also the second source. A model
// that reaches for a language-level minimum gets both wrong, and only on the
// inputs nobody tries by hand.

EXPORT uint64_t emu_fp_min(uint64_t a, uint64_t b) {
    double x = as_double(a), y = as_double(b);
    return as_bits(x < y ? x : y);
}
EXPORT uint64_t emu_fp_max(uint64_t a, uint64_t b) {
    double x = as_double(a), y = as_double(b);
    return as_bits(x > y ? x : y);
}
// `__builtin_sqrt` becomes a *call* to libm at `-O0`, and this corpus is
// leaf-only. The instruction is what is under test, so ask for it by name.
HELPER double sqrt_insn(double x) {
    double r;
    __asm__("sqrtsd %1, %0" : "=x"(r) : "x"(x));
    return r;
}

EXPORT uint64_t emu_fp_sqrt(uint64_t a) {
    return as_bits(sqrt_insn(normalish(a)));
}
EXPORT uint64_t emu_fp_neg(uint64_t a) { return as_bits(-as_double(a)); }
EXPORT uint64_t emu_fp_abs(uint64_t a) { return as_bits(__builtin_fabs(as_double(a))); }

// --- conversions -------------------------------------------------------------
//
// The signed/unsigned trap again, in a new place: `cvtsi2sd` reads its integer
// source as **signed**. A lift that widens a 32-bit source with a zero-extend
// turns -1 into 4294967295, and the answer is off by 2^32 rather than wrong in
// a way anyone notices.

EXPORT uint64_t emu_fp_i32_to_d(uint64_t a) { return as_bits((double)(int32_t)a); }
EXPORT uint64_t emu_fp_i64_to_d(uint64_t a) { return as_bits((double)(int64_t)a); }
EXPORT uint64_t emu_fp_u32_to_d(uint64_t a) { return as_bits((double)(uint32_t)a); }
EXPORT uint64_t emu_fp_d_to_i32(uint64_t a) { return (uint64_t)(uint32_t)(int32_t)normalish(a) ; }
EXPORT uint64_t emu_fp_d_to_i64(uint64_t a) {
    return (uint64_t)(int64_t)(normalish(a) * 1024.0);
}
EXPORT uint64_t emu_fp_d_to_f(uint64_t a) { return float_bits((float)normalish(a)); }
EXPORT uint64_t emu_fp_f_to_d(uint64_t a) { return as_bits((double)as_float(a)); }

// --- comparison and branching ------------------------------------------------
//
// `ucomisd` sets ZF, PF and CF, and a compiler reads them with `ja`, `jae`,
// `jb`, `jbe`, `je`, `jne`, `jp`. Unordered — either operand NaN — sets all
// three, so `jb` after a float compare means "less than **or unordered**",
// which is not what `jb` means after an integer `cmp`. Every branch below
// exists to pin one of those readings down, and the NaNs in the driver's value
// list are what make them differ.

EXPORT uint64_t emu_fp_cmp_gt(uint64_t a, uint64_t b) {
    return as_double(a) > as_double(b) ? 11 : 13;
}
EXPORT uint64_t emu_fp_cmp_ge(uint64_t a, uint64_t b) {
    return as_double(a) >= as_double(b) ? 17 : 19;
}
EXPORT uint64_t emu_fp_cmp_lt(uint64_t a, uint64_t b) {
    return as_double(a) < as_double(b) ? 23 : 29;
}
EXPORT uint64_t emu_fp_cmp_le(uint64_t a, uint64_t b) {
    return as_double(a) <= as_double(b) ? 31 : 37;
}
EXPORT uint64_t emu_fp_cmp_eq(uint64_t a, uint64_t b) {
    return as_double(a) == as_double(b) ? 41 : 43;
}
EXPORT uint64_t emu_fp_cmp_ne(uint64_t a, uint64_t b) {
    return as_double(a) != as_double(b) ? 47 : 53;
}
// The one that is only reachable with NaN: `x != x`.
EXPORT uint64_t emu_fp_is_nan(uint64_t a) {
    double x = as_double(a);
    return x != x ? 59 : 61;
}
// Float, not double — the same predicates through `ucomiss`.
EXPORT uint64_t emu_fp_cmpf_lt(uint64_t a, uint64_t b) {
    return as_float(a) < as_float(b) ? 67 : 71;
}
// A branch whose two sides both do arithmetic, so a wrong branch is a wrong
// number and not just a wrong constant.
EXPORT uint64_t emu_fpn_select(uint64_t a, uint64_t b) {
    double x = normalish(a), y = normalish(b);
    return as_bits(x < y ? x * 2.0 : y * 3.0);
}
// A loop with a floating-point accumulator and a floating-point exit test.
EXPORT uint64_t emu_fpn_loop(uint64_t a) {
    double s = 0.0;
    double x = normalish(a) + 0.5;
    for (int i = 0; i < 8; i++) s = s * x + 1.0;
    return as_bits(s);
}
