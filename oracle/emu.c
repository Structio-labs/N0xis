// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The emulator corpus — leaf functions whose answer the CPU itself gives.
//
// Every other oracle here states its truth in `expect.json`, written by hand
// from the C. This shape cannot: the truth of `emu_mix(a,b,c,d)` is a number
// per input, and there are too many to write down. So the oracle is the
// *processor*: `emu_run.c` dlopens this library and calls the same exported
// function at the same address with the same arguments the emulator is given.
// Rung 1 — the answer exists before the question is asked, and no tool
// produced it.
//
// Every function here is a **leaf** (no calls) and touches only its arguments
// and its own stack. That is not a limitation of the corpus but of the first
// emulator: a call needs a callee, and a callee needs either a stub or real
// execution. Non-leaf shapes belong in a later file, not a later argument.

#include <stdint.h>

#define EXPORT __attribute__((visibility("default")))

// --- width: the whole point of the first three -------------------------------

// 32-bit arithmetic that overflows 32 bits. On x86-64 the result is truncated
// to 32 bits and zero-extended to 64. A lifter that widens `eax` to `rax` and
// drops the width computes a different number here — and only here, which is
// why the inputs must be large.
EXPORT uint64_t emu_add32(uint64_t a, uint64_t b) {
    uint32_t x = (uint32_t)a;
    uint32_t y = (uint32_t)b;
    return (uint64_t)(uint32_t)(x + y);
}

// The same in 64 bits, as the control: if this one agrees and `emu_add32`
// does not, the difference is the width and nothing else.
EXPORT uint64_t emu_add64(uint64_t a, uint64_t b) {
    return a + b;
}

// A 32-bit write must clear the upper half of the destination register.
EXPORT uint64_t emu_trunc32(uint64_t a) {
    uint32_t x = (uint32_t)a;
    return (uint64_t)x;
}

// 16- and 8-bit writes do NOT clear the upper bits — the opposite rule, in the
// same instruction family. A lifter that models one and not the other is wrong
// exactly once.
EXPORT uint64_t emu_byte_merge(uint64_t a, uint64_t b) {
    uint64_t r = a;
    *((uint8_t *)&r) = (uint8_t)b;
    return r;
}

EXPORT uint64_t emu_word_merge(uint64_t a, uint64_t b) {
    uint64_t r = a;
    *((uint16_t *)&r) = (uint16_t)b;
    return r;
}

// --- sign ---------------------------------------------------------------------

EXPORT uint64_t emu_sext32(uint64_t a) {
    return (uint64_t)(int64_t)(int32_t)a;
}

EXPORT uint64_t emu_sext8(uint64_t a) {
    return (uint64_t)(int64_t)(int8_t)a;
}

EXPORT uint64_t emu_sar(uint64_t a, uint64_t b) {
    return (uint64_t)(((int64_t)a) >> (b & 63));
}

EXPORT uint64_t emu_shr(uint64_t a, uint64_t b) {
    return a >> (b & 63);
}

EXPORT uint64_t emu_shl(uint64_t a, uint64_t b) {
    return a << (b & 63);
}

// --- branches: every condition code is a separate way to be wrong ------------

EXPORT uint64_t emu_max_signed(uint64_t a, uint64_t b) {
    return ((int64_t)a > (int64_t)b) ? a : b;
}

EXPORT uint64_t emu_max_unsigned(uint64_t a, uint64_t b) {
    return (a > b) ? a : b;
}

// Signed vs unsigned on the same bits: with a = -1 and b = 1 these two return
// opposite answers, so a decoder that maps `jg` to `ja` is caught by value.
EXPORT uint64_t emu_cmp_signed(uint64_t a, uint64_t b) {
    if ((int64_t)a < (int64_t)b) return 111;
    if ((int64_t)a == (int64_t)b) return 222;
    return 333;
}

EXPORT uint64_t emu_cmp_unsigned(uint64_t a, uint64_t b) {
    if (a < b) return 111;
    if (a == b) return 222;
    return 333;
}

// A compare against zero after an arithmetic op — the `CmpKind::Result` path,
// where only the zero flag is soundly recoverable.
EXPORT uint64_t emu_dec_to_zero(uint64_t a) {
    uint64_t n = a & 0xff;
    uint64_t steps = 0;
    while (n--) steps += 3;
    return steps;
}

// --- loops and memory ---------------------------------------------------------

EXPORT uint64_t emu_sum_to(uint64_t n) {
    uint64_t s = 0;
    for (uint64_t i = 0; i < (n & 0xffff); i++) s += i;
    return s;
}

// A stack array — forces real Store/Load traffic through the frame.
EXPORT uint64_t emu_stack_array(uint64_t a, uint64_t b) {
    uint64_t buf[8];
    for (int i = 0; i < 8; i++) buf[i] = a + (uint64_t)i * b;
    uint64_t s = 0;
    for (int i = 0; i < 8; i++) s ^= buf[i] * (uint64_t)(i + 1);
    return s;
}

// Narrow stack slots: an 8-bit store followed by a 32-bit load reads the
// neighbours, so the emulator's memory must be byte-addressed, not slot-keyed.
EXPORT uint64_t emu_narrow_slots(uint64_t a) {
    // No `= {0}`: clang at `-O0` lowers an array initializer to a **call** to
    // `memset`, and this file is leaf-only by construction. The loop below
    // writes all eight bytes before anything reads them, so the initializer was
    // only ever decoration.
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(a >> (i * 8));
    uint32_t lo, hi;
    __builtin_memcpy(&lo, b, 4);
    __builtin_memcpy(&hi, b + 4, 4);
    return (uint64_t)lo * 3u + (uint64_t)hi;
}

// --- mixed arithmetic ---------------------------------------------------------

EXPORT uint64_t emu_mul(uint64_t a, uint64_t b) {
    return a * b;
}

EXPORT uint64_t emu_udiv(uint64_t a, uint64_t b) {
    uint64_t d = (b & 0xffff) | 1;
    return a / d;
}

EXPORT uint64_t emu_umod(uint64_t a, uint64_t b) {
    uint64_t d = (b & 0xffff) | 1;
    return a % d;
}

EXPORT uint64_t emu_sdiv(uint64_t a, uint64_t b) {
    int64_t d = (int64_t)((b & 0xffff) | 1);
    return (uint64_t)((int64_t)a / d);
}

EXPORT uint64_t emu_bitops(uint64_t a, uint64_t b) {
    return ((a & b) ^ (a | b)) + (~a & 0xffff);
}

EXPORT uint64_t emu_mix(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    uint64_t r = a ^ (b << 13);
    r += c * 0x9e3779b97f4a7c15ull;
    r ^= r >> 29;
    r += d;
    r ^= r << 17;
    return r;
}

// A select that a compiler usually emits as `cmov` — no branch at all.
EXPORT uint64_t emu_select(uint64_t a, uint64_t b, uint64_t c) {
    return (a & 1) ? b : c;
}

// --- signed conditions on a narrow value -------------------------------------
//
// The trap these exist for: a 32-bit value that is *negative as an int32* sits
// in a 64-bit register whose full value is positive (0x00000000ffffffff). Every
// signed condition splits on that, and a flags model that records the compare
// at the wrong width answers the opposite question. Only a value like that
// tells the two apart, which is why the input list carries one.

EXPORT uint64_t emu_signed32_branch(uint64_t a) {
    int32_t x = (int32_t)a;
    if (x <= 0) return 7;
    return 9;
}

EXPORT uint64_t emu_and32_branch(uint64_t a, uint64_t b) {
    int32_t x = (int32_t)a & (int32_t)b;
    if (x < 0) return 11;
    if (x == 0) return 13;
    return 17;
}

EXPORT uint64_t emu_sub32_branch(uint64_t a, uint64_t b) {
    int32_t x = (int32_t)a - (int32_t)b;
    if (x > 0) return 19;
    if (x >= 0) return 23;
    return 29;
}

// The unsigned family on the same narrow width — `jb`/`ja` read the carry, and
// a model that reconstructs them from a 64-bit container gets both wrong.
EXPORT uint64_t emu_unsigned32_branch(uint64_t a, uint64_t b) {
    uint32_t x = (uint32_t)a;
    uint32_t y = (uint32_t)b;
    if (x < y) return 31;
    if (x == y) return 37;
    return 41;
}

// A loop whose counter is a 32-bit signed value.
EXPORT uint64_t emu_loop32_signed(uint64_t n) {
    int32_t k = (int32_t)n & 0x3f;
    uint64_t s = 0;
    for (int32_t i = k; i > 0; i--) s += (uint64_t)(uint32_t)i * 7u;
    return s;
}
