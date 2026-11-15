/* Each function is named by how it comes to its result and by the type it returns:
 * `<how>_<type>`, with `i8 u8 i16 u16 i32 u64` the type. The type is the truth the test
 * holds the printed return width against; nothing here is read back from the tool.
 *
 *   d_  loads it
 *   c_  computes it
 *   f_  returns a call's result, with a store on either side so the call is a call
 *   t_  returns a call's result by a jump to the callee
 *   p_  one path computes it, the other passes a callee's on
 *
 * A compiler is free to write more of the register than the type has: `int8_t` loaded
 * with `movzbl (%rdi),%eax` defines 32 bits, and the bytes do not say 8. The test says
 * which functions those are from the disassembly. */
#include <stdint.h>
#define NI __attribute__((noinline))

volatile uint64_t sink;

NI int8_t   d_i8 (const int8_t *p, long i)   { return p[i]; }
NI uint8_t  d_u8 (const uint8_t *p, long i)  { return p[i]; }
NI int16_t  d_i16(const int16_t *p, long i)  { return p[i]; }
NI uint16_t d_u16(const uint16_t *p, long i) { return p[i]; }
NI int32_t  d_i32(const int32_t *p, long i)  { return p[i]; }
NI uint64_t d_u64(const uint64_t *p, long i) { return p[i]; }

NI int8_t   c_i8 (int8_t a, int8_t b)     { return (int8_t)(a * b + 3); }
NI uint8_t  c_u8 (long a, long b)         { return a < b; }
NI int16_t  c_i16(int16_t a, int16_t b)   { return (int16_t)(a * b + 3); }
NI uint16_t c_u16(uint16_t a, uint16_t b) { return (uint16_t)(a * b + 3); }
NI int32_t  c_i32(int32_t a, int32_t b)   { return a * b + 3; }
NI uint64_t c_u64(uint64_t a, uint64_t b) { return a * b + 3; }

NI int8_t   f_i8 (const int8_t *p, long i)   { sink = i; int8_t r = d_i8(p, i);    sink = i + 1; return r; }
NI uint8_t  f_u8 (const uint8_t *p, long i)  { sink = i; uint8_t r = d_u8(p, i);   sink = i + 1; return r; }
NI int16_t  f_i16(const int16_t *p, long i)  { sink = i; int16_t r = d_i16(p, i);  sink = i + 1; return r; }
NI uint16_t f_u16(const uint16_t *p, long i) { sink = i; uint16_t r = d_u16(p, i); sink = i + 1; return r; }
NI int32_t  f_i32(const int32_t *p, long i)  { sink = i; int32_t r = d_i32(p, i);  sink = i + 1; return r; }
NI uint64_t f_u64(const uint64_t *p, long i) { sink = i; uint64_t r = d_u64(p, i); sink = i + 1; return r; }

NI int8_t   t_i8 (const int8_t *p, long i)   { return d_i8(p, i + 1); }
NI uint16_t t_u16(const uint16_t *p, long i) { return d_u16(p, i + 1); }
NI uint64_t t_u64(const uint64_t *p, long i) { return d_u64(p, i + 1); }

NI uint8_t  p_u8 (long a, long b, const uint8_t *p)  { if (a > 7) return a < b; return d_u8(p, a); }
NI int8_t   p_i8 (long a, long b, const int8_t *p)   { if (a > 7) return a == b; return d_i8(p, a); }
NI uint16_t p_u16(long a, const uint16_t *p)         { if (a > 7) return 0x1234; return d_u16(p, a); }
NI int32_t  p_i32(long a, long b, const int32_t *p)  { if (a > 7) return a < b; return d_i32(p, a); }
NI uint64_t p_u64(long a, long b, const uint64_t *p) { if (a > 7) return a < b; return d_u64(p, a); }
