// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The corpus for **32-bit** code, where the word is 32 bits and every trap the
// 64-bit corpus exists for comes back one size down.
//
// Everything measured before this was 64-bit. That is not a small omission:
// `reg_read`/`reg_write` decided whether to state an operand's width by asking
// whether it filled its *container*, which is the same question as "is it 64
// bits wide" in 64-bit mode and a different one in 32-bit mode — there `eax`
// **is** the container. So `add eax, ebx` lifted to `rax = rax + rbx`, with no
// width anywhere in it, and a sum that overflows 32 bits stayed 33 bits wide
// forever. Every signed predicate on a 32-bit value answered the unsigned
// question, which is the defect class that cost 52 wrong answers on x86-64.
//
// `uint32_t` in and out, so the i386 convention is four 4-byte stack slots and
// a result in `eax` — no register pairs, nothing but the width under test.
// Leaf functions only, as in `emu.c`.

#include <stdint.h>

#define EXPORT __attribute__((visibility("default")))

// --- the width itself --------------------------------------------------------

EXPORT uint32_t emu32_add(uint32_t a, uint32_t b) { return a + b; }
EXPORT uint32_t emu32_sub(uint32_t a, uint32_t b) { return a - b; }
EXPORT uint32_t emu32_mul(uint32_t a, uint32_t b) { return a * b; }

// Three operations chained, so a lost truncation compounds instead of
// cancelling.
EXPORT uint32_t emu32_chain(uint32_t a, uint32_t b, uint32_t c) {
    return (a + b) * c - (a ^ b);
}

// --- the signed/unsigned split, at 32 bits -----------------------------------
//
// `0xffffffff` is -1 signed and 4 294 967 295 unsigned, and `jl` and `jb` read
// the same flags. In 64-bit mode the operand arrives as an explicit 32-bit cast
// and the predicate re-reads it signed; in 32-bit mode there was no cast to
// re-read, so the whole 64-bit container was compared and it is never negative.

EXPORT uint32_t emu32_signed_branch(uint32_t a, uint32_t b) {
    if ((int32_t)a < (int32_t)b) return 11;
    if ((int32_t)a == (int32_t)b) return 13;
    return 17;
}

EXPORT uint32_t emu32_unsigned_branch(uint32_t a, uint32_t b) {
    if (a < b) return 19;
    if (a == b) return 23;
    return 29;
}

EXPORT uint32_t emu32_and_branch(uint32_t a, uint32_t b) {
    int32_t x = (int32_t)a & (int32_t)b;
    if (x < 0) return 31;
    if (x == 0) return 37;
    return 41;
}

EXPORT uint32_t emu32_sub_branch(uint32_t a, uint32_t b) {
    int32_t x = (int32_t)a - (int32_t)b;
    if (x > 0) return 43;
    if (x >= 0) return 47;
    return 53;
}

// --- narrow writes keep the upper bits, and a 32-bit container has some ------

EXPORT uint32_t emu32_byte_merge(uint32_t a, uint32_t b) {
    uint32_t r = a;
    *((uint8_t *)&r) = (uint8_t)b;
    return r;
}

EXPORT uint32_t emu32_word_merge(uint32_t a, uint32_t b) {
    uint32_t r = a;
    *((uint16_t *)&r) = (uint16_t)b;
    return r;
}

// The second byte of the word — `ah` on i386, which a 32-bit compiler reaches
// for far more often than a 64-bit one.
EXPORT uint32_t emu32_second_byte(uint32_t a) {
    return (a >> 8) & 0xffu;
}

// --- shifts, whose count the machine masks to 31 -----------------------------

EXPORT uint32_t emu32_shl(uint32_t a, uint32_t n) { return a << (n & 31u); }
EXPORT uint32_t emu32_shr(uint32_t a, uint32_t n) { return a >> (n & 31u); }
EXPORT uint32_t emu32_sar(uint32_t a, uint32_t n) {
    return (uint32_t)((int32_t)a >> (int32_t)(n & 31u));
}
EXPORT uint32_t emu32_rol(uint32_t a, uint32_t n) {
    uint32_t k = n & 31u;
    return k == 0 ? a : (a << k) | (a >> (32u - k));
}

// --- division: the one place a 32-bit operation reads a 64-bit dividend ------

EXPORT uint32_t emu32_udiv(uint32_t a, uint32_t b) { return b == 0 ? 0 : a / b; }
EXPORT uint32_t emu32_umod(uint32_t a, uint32_t b) { return b == 0 ? 0 : a % b; }
EXPORT uint32_t emu32_sdiv(uint32_t a, uint32_t b) {
    int32_t x = (int32_t)a, y = (int32_t)b;
    if (y == 0 || (x == INT32_MIN && y == -1)) return 0;
    return (uint32_t)(x / y);
}

// --- a loop whose counter is a 32-bit signed value ---------------------------

EXPORT uint32_t emu32_loop(uint32_t n) {
    int32_t k = (int32_t)(n & 0x3f);
    uint32_t s = 0;
    for (int32_t i = k; i > 0; i--) s += (uint32_t)i * 7u;
    return s;
}

// --- the carry, at 32 bits ---------------------------------------------------

EXPORT uint32_t emu32_carry(uint32_t a, uint32_t b) {
    uint32_t s = a + b;
    return s + (uint32_t)(s < a);
}

EXPORT uint32_t emu32_select(uint32_t a, uint32_t b, uint32_t c) {
    return (a & 1u) ? b : c;
}
