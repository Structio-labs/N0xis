// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Integer multiply and divide in every width x86 has: what a compiler makes of
// a byte, a halfword, a word and a doubleword product, a 128-bit high half, and
// the four divisions. `decomp-behaviour/behave.py --only muldiv` compiles this at
// gcc and clang -O1 and -O2, asks the engine for each body, and runs body and
// source on the same inputs. Every divisor is made non-zero, and a signed one
// positive, in the source itself, so no input can fault the source: a body
// that faulted where the source did not would be a body that differs.
//
// Every parameter and result is a whole register (`W`, `S`) and narrowed inside:
// the harness passes any 64 bits, and clang reads a narrow parameter as already
// extended by its caller, so a narrow one would make the source disagree with itself.
#include <stdint.h>

#define E __attribute__((visibility("default"), noinline))
typedef uint64_t W;
typedef int64_t S;

E W md_mul_u8(W a_, W b_) { uint8_t a = (uint8_t)a_; uint8_t b = (uint8_t)b_; return (uint16_t)((uint16_t)a * b); }
E S md_mul_s8(S a_, S b_) { int8_t a = (int8_t)a_; int8_t b = (int8_t)b_; return (int16_t)((int16_t)a * b); }
E W md_mul_u8_low(W a_, W b_) { uint8_t a = (uint8_t)a_; uint8_t b = (uint8_t)b_; return (uint8_t)((uint8_t)(a * b)); }
E S md_mul_s16(S a_, S b_) { int16_t a = (int16_t)a_; int16_t b = (int16_t)b_; return (int16_t)((int16_t)(a * b)); }
E S md_mul_s16_wide(S a_, S b_) { int16_t a = (int16_t)a_; int16_t b = (int16_t)b_; return (int32_t)((int32_t)a * b); }
E W md_mul_u32(W a_, W b_) { uint32_t a = (uint32_t)a_; uint32_t b = (uint32_t)b_; return (uint32_t)(a * b); }
E W md_mul_u32_wide(W a_, W b_) { uint32_t a = (uint32_t)a_; uint32_t b = (uint32_t)b_; return (uint64_t)((uint64_t)a * b); }
E W md_mul_u64(W a_, W b_) { uint64_t a = (uint64_t)a_; uint64_t b = (uint64_t)b_; return (uint64_t)(a * b); }
E S md_mul_s64(S a_, S b_) { int64_t a = (int64_t)a_; int64_t b = (int64_t)b_; return (int64_t)((int64_t)((uint64_t)a * (uint64_t)b)); }
E W md_mul_u64_imm(W a_) { uint64_t a = (uint64_t)a_; return (uint64_t)(a * 0x1234567u); }
E W md_mulhi_u64(W a_, W b_) { uint64_t a = (uint64_t)a_; uint64_t b = (uint64_t)b_; return (uint64_t)((uint64_t)(((unsigned __int128)a * b) >> 64)); }
E S md_mulhi_s64(S a_, S b_) { int64_t a = (int64_t)a_; int64_t b = (int64_t)b_; return (int64_t)((int64_t)(((__int128)a * b) >> 64)); }
E W md_mulhi_u64_sum(W a, W b) {
    unsigned __int128 p = (unsigned __int128)a * b;
    return (uint64_t)p + (uint64_t)(p >> 64);
}

E W md_div_u8(W a_, W b_) { uint8_t a = (uint8_t)a_; uint8_t b = (uint8_t)b_; return (uint8_t)(a / (uint8_t)(b | 1)); }
E W md_rem_u8(W a_, W b_) { uint8_t a = (uint8_t)a_; uint8_t b = (uint8_t)b_; return (uint8_t)(a % (uint8_t)(b | 1)); }
E S md_div_s16(S a_, S b_) { int16_t a = (int16_t)a_; int16_t b = (int16_t)b_; return (int16_t)((int16_t)(a / (int16_t)((b & 0x7fff) | 1))); }
E S md_rem_s16(S a_, S b_) { int16_t a = (int16_t)a_; int16_t b = (int16_t)b_; return (int16_t)((int16_t)(a % (int16_t)((b & 0x7fff) | 1))); }
E W md_div_u16(W a_, W b_) { uint16_t a = (uint16_t)a_; uint16_t b = (uint16_t)b_; return (uint16_t)(a / (uint16_t)(b | 1)); }
E W md_div_u32(W a_, W b_) { uint32_t a = (uint32_t)a_; uint32_t b = (uint32_t)b_; return (uint32_t)(a / (b | 1)); }
E S md_rem_s32(S a_, S b_) { int32_t a = (int32_t)a_; int32_t b = (int32_t)b_; return (int32_t)(a % ((b & 0x7fffffff) | 1)); }
E W md_div_u64(W a_, W b_) { uint64_t a = (uint64_t)a_; uint64_t b = (uint64_t)b_; return (uint64_t)(a / (b | 1)); }
E W md_rem_u64(W a_, W b_) { uint64_t a = (uint64_t)a_; uint64_t b = (uint64_t)b_; return (uint64_t)(a % (b | 1)); }
E S md_div_s64(S a_, S b_) { int64_t a = (int64_t)a_; int64_t b = (int64_t)b_; return (int64_t)(a / ((b & INT64_MAX) | 1)); }
E S md_rem_s64(S a_, S b_) { int64_t a = (int64_t)a_; int64_t b = (int64_t)b_; return (int64_t)(a % ((b & INT64_MAX) | 1)); }
E W md_divmod_u64(W a, W b) {
    uint64_t d = b | 1;
    return a / d * 3 + a % d;
}
