// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The corpus for **packed** SIMD — the largest single block the census names.
//
// The scalar floating-point layer is measured (`emu_fp.c`); this is the other
// half, where one instruction operates on four lanes at once and taking the low
// one is not a smaller answer but a wrong one. Until the emulator's word grew
// to 128 bits none of it could even be represented.
//
// `uint64_t` in and out, as everywhere in this corpus, so the driver is
// unchanged. Each function builds its vectors from the arguments, does packed
// work, and folds both halves back into one integer — so a defect in the upper
// lane is as visible as one in the lower, which is the whole point.

#include <emmintrin.h>
#include <stdint.h>
#include <string.h>

#define EXPORT __attribute__((visibility("default")))
#define HELPER static inline __attribute__((always_inline))

HELPER __m128i make(uint64_t a, uint64_t b) {
    return _mm_set_epi64x((long long)b, (long long)a);
}

// Both halves, mixed so neither can be dropped without changing the answer.
HELPER uint64_t fold(__m128i v) {
    uint64_t lo = (uint64_t)_mm_cvtsi128_si64(v);
    uint64_t hi = (uint64_t)_mm_cvtsi128_si64(_mm_srli_si128(v, 8));
    return lo * 31u + hi;
}

HELPER uint64_t foldd(__m128d v) {
    return fold(_mm_castpd_si128(v));
}

// --- packed integer arithmetic ----------------------------------------------

EXPORT uint64_t emu_simd_add32(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return fold(_mm_add_epi32(make(a, b), make(c, d)));
}
EXPORT uint64_t emu_simd_sub32(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return fold(_mm_sub_epi32(make(a, b), make(c, d)));
}
EXPORT uint64_t emu_simd_add16(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return fold(_mm_add_epi16(make(a, b), make(c, d)));
}
EXPORT uint64_t emu_simd_add8(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return fold(_mm_add_epi8(make(a, b), make(c, d)));
}
EXPORT uint64_t emu_simd_add64(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return fold(_mm_add_epi64(make(a, b), make(c, d)));
}

// --- the lane compare, which the census ranks first --------------------------
//
// `pcmpeqd` writes all-ones or all-zeros **per lane**. A model that answers a
// single boolean for the whole register is not an approximation of that; it is
// a different value in every bit.

EXPORT uint64_t emu_simd_cmpeq32(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return fold(_mm_cmpeq_epi32(make(a, b), make(c, d)));
}
EXPORT uint64_t emu_simd_cmpeq8(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return fold(_mm_cmpeq_epi8(make(a, b), make(c, d)));
}
EXPORT uint64_t emu_simd_cmpgt32(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return fold(_mm_cmpgt_epi32(make(a, b), make(c, d)));
}

// The mask reduction every `memchr`/`strlen` is built out of.
EXPORT uint64_t emu_simd_movemask(uint64_t a, uint64_t b) {
    return (uint64_t)(unsigned)_mm_movemask_epi8(make(a, b));
}

// --- lane movement -----------------------------------------------------------

EXPORT uint64_t emu_simd_unpack_lo(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return fold(_mm_unpacklo_epi32(make(a, b), make(c, d)));
}
EXPORT uint64_t emu_simd_unpack_hi(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return fold(_mm_unpackhi_epi32(make(a, b), make(c, d)));
}
EXPORT uint64_t emu_simd_shuffle(uint64_t a, uint64_t b) {
    return fold(_mm_shuffle_epi32(make(a, b), 0x1b));
}
EXPORT uint64_t emu_simd_shift_bytes(uint64_t a, uint64_t b) {
    return fold(_mm_slli_si128(make(a, b), 3)) ^ fold(_mm_srli_si128(make(a, b), 5));
}

// --- packed bit shifts, whose count is a whole vector -------------------------

EXPORT uint64_t emu_simd_shift32(uint64_t a, uint64_t b) {
    __m128i v = make(a, b);
    return fold(_mm_slli_epi32(v, 5)) ^ fold(_mm_srli_epi32(v, 7)) ^ fold(_mm_srai_epi32(v, 3));
}

// --- packed bitwise, which the lift models as exact bit operations ------------

EXPORT uint64_t emu_simd_bitwise(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    __m128i x = make(a, b), y = make(c, d);
    return fold(_mm_and_si128(x, y)) ^ fold(_mm_or_si128(x, y)) ^ fold(_mm_xor_si128(x, y))
           ^ fold(_mm_andnot_si128(x, y));
}

// --- packed floating point ----------------------------------------------------

EXPORT uint64_t emu_simd_addpd(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return foldd(_mm_add_pd(_mm_castsi128_pd(make(a, b)), _mm_castsi128_pd(make(c, d))));
}
EXPORT uint64_t emu_simd_mulpd(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return foldd(_mm_mul_pd(_mm_castsi128_pd(make(a, b)), _mm_castsi128_pd(make(c, d))));
}
EXPORT uint64_t emu_simd_addps(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    __m128 x = _mm_castsi128_ps(make(a, b));
    __m128 y = _mm_castsi128_ps(make(c, d));
    return fold(_mm_castps_si128(_mm_add_ps(x, y)));
}
EXPORT uint64_t emu_simd_cmppd(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    __m128d x = _mm_castsi128_pd(make(a, b));
    __m128d y = _mm_castsi128_pd(make(c, d));
    return foldd(_mm_cmplt_pd(x, y)) ^ foldd(_mm_cmpeq_pd(x, y));
}

// --- a 128-bit value that only moves ------------------------------------------
//
// No lane arithmetic at all: load, move, store. This is the class the census
// counted 37 of, and it needs a wide *value* and nothing else.

EXPORT uint64_t emu_simd_move(uint64_t a, uint64_t b) {
    __m128i v = make(a, b);
    __m128i buf[2];
    _mm_storeu_si128(&buf[0], v);
    _mm_storeu_si128(&buf[1], _mm_loadu_si128(&buf[0]));
    return fold(_mm_loadu_si128(&buf[1]));
}
