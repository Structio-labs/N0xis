// Held-out behaviour corpus: small ordinary C written for this measurement (2026-11-06), before any body of it was read.
// The table at the bottom of behave.py gives each function's argument kinds and return width.
#include <stddef.h>
#include <stdint.h>
#define E __attribute__((visibility("default")))

E size_t h_strlen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }
E const char *h_strchr(const char *s, int c) { for (; *s; s++) if (*s == (char)c) return s; return (char)c ? 0 : s; }
E int h_strcmp(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return (unsigned char)*a - (unsigned char)*b; }
E int h_memcmp(const void *a, const void *b, size_t n) { const unsigned char *x = a, *y = b; for (size_t i = 0; i < n; i++) if (x[i] != y[i]) return x[i] < y[i] ? -1 : 1; return 0; }
E void h_memrev(unsigned char *p, size_t n) { for (size_t i = 0, j = n; i + 1 < j; i++) { j--; unsigned char t = p[i]; p[i] = p[j]; p[j] = t; } }
E uint32_t h_crc32(const unsigned char *p, size_t n) { uint32_t c = ~0u; while (n--) { c ^= *p++; for (int k = 0; k < 8; k++) c = c & 1 ? (c >> 1) ^ 0xedb88320u : c >> 1; } return ~c; }
E uint32_t h_fnv1a(const char *s) { uint32_t h = 2166136261u; while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; } return h; }
E int h_popcount(uint64_t x) { int n = 0; while (x) { x &= x - 1; n++; } return n; }
E uint64_t h_gcd(uint64_t a, uint64_t b) { while (b) { uint64_t t = a % b; a = b; b = t; } return a; }
E uint32_t h_isqrt(uint32_t x) { uint32_t r = 0, b = 1u << 30; while (b > x) b >>= 2; while (b) { if (x >= r + b) { x -= r + b; r = (r >> 1) + b; } else r >>= 1; b >>= 2; } return r; }
E int h_clamp(int x, int lo, int hi) { return x < lo ? lo : x > hi ? hi : x; }
E long h_bsearch(const int32_t *a, long n, int32_t key) { long lo = 0, hi = n - 1; while (lo <= hi) { long m = lo + (hi - lo) / 2; if (a[m] == key) return m; if (a[m] < key) lo = m + 1; else hi = m - 1; } return -1; }
E void h_isort(int16_t *a, size_t n) { for (size_t i = 1; i < n; i++) { int16_t v = a[i]; size_t j = i; while (j > 0 && a[j - 1] > v) { a[j] = a[j - 1]; j--; } a[j] = v; } }
E uint32_t h_bitrev(uint32_t x) { uint32_t r = 0; for (int i = 0; i < 32; i++) { r = (r << 1) | (x & 1); x >>= 1; } return r; }
E long h_atol(const char *s) { long v = 0; int neg = 0; while (*s == ' ') s++; if (*s == '-') { neg = 1; s++; } while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0'); return neg ? -v : v; }
E int h_hexval(int c) { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return -1; }
E int h_utf8len(unsigned char c) { if (c < 0x80) return 1; if ((c & 0xe0) == 0xc0) return 2; if ((c & 0xf0) == 0xe0) return 3; if ((c & 0xf8) == 0xf0) return 4; return 0; }
E int64_t h_sum32(const int32_t *a, size_t n) { int64_t s = 0; for (size_t i = 0; i < n; i++) s += a[i]; return s; }
E int32_t h_max32(const int32_t *a, size_t n) { int32_t m = INT32_MIN; for (size_t i = 0; i < n; i++) if (a[i] > m) m = a[i]; return m; }
struct pt { int32_t x; int16_t y; uint8_t tag; uint64_t w; };
E int64_t h_struct(const struct pt *p) { return (int64_t)p->x + p->y * 3 + (p->tag ? (int64_t)p->w : -1); }
E void h_struct_set(struct pt *p, int v) { p->x = v; p->y = (int16_t)(v >> 8); p->tag = (uint8_t)v | 1; p->w = (uint64_t)v << 33; }
E int h_day(int m) { switch (m) { case 2: return 28; case 4: case 6: case 9: case 11: return 30; case 1: case 3: case 5: case 7: case 8: case 10: case 12: return 31; default: return -1; } }
E int h_fall(int k, int v) { switch (k & 7) { case 0: v += 1; case 1: v *= 3; case 2: v ^= 5; break; case 3: v -= 9; break; case 5: v <<= 2; default: v = ~v; } return v; }
E int64_t h_trace(const int32_t *m, int n) { int64_t t = 0; for (int i = 0; i < n; i++) for (int j = 0; j < n; j++) if (i == j) t += m[i * n + j]; return t; }
E int h_div10(int x) { return x / 10; }
E int h_mod7(int x) { return x % 7; }
E uint32_t h_udiv1000(uint32_t x) { return x / 1000u; }
E uint32_t h_rotl(uint32_t x, int n) { n &= 31; return (x << n) | (x >> ((32 - n) & 31)); }
E int h_cmp3(int64_t a, int64_t b) { return (a > b) - (a < b); }
E int h_abs(int x) { return x < 0 ? -x : x; }
E int32_t h_satadd(int32_t a, int32_t b) { int64_t s = (int64_t)a + b; return s > INT32_MAX ? INT32_MAX : s < INT32_MIN ? INT32_MIN : (int32_t)s; }
E uint8_t h_toupper(uint8_t c) { return c >= 'a' && c <= 'z' ? c - 32 : c; }
E int h_ispow2(uint64_t x) { return x && !(x & (x - 1)); }
E uint64_t h_bswap(uint64_t x) { uint64_t r = 0; for (int i = 0; i < 8; i++) { r = (r << 8) | (x & 0xff); x >>= 8; } return r; }
E int h_count_eq(const unsigned char *p, size_t n, unsigned char c) { int k = 0; for (size_t i = 0; i < n; i++) k += p[i] == c; return k; }
E void h_fill16(uint16_t *p, size_t n, uint16_t v) { for (size_t i = 0; i < n; i++) p[i] = v + (uint16_t)i; }
E uint64_t h_collatz(uint64_t n) { uint64_t s = 0; n = (n & 0xffff) | 1; while (n != 1 && s < 500) { n = n & 1 ? 3 * n + 1 : n / 2; s++; } return s; }
static __attribute__((noinline)) int h_helper(int a, int b, int c) { return a * b + c; }
E int h_call3(int a, int b) { return h_helper(a, b, 7) + h_helper(b, a, 11); }
E int h_call_loop(int n) { int s = 0; for (int i = 0; i < (n & 15); i++) s = h_helper(s, 3, i); return s; }
static const uint8_t h_tab[8] = {3, 1, 4, 1, 5, 9, 2, 6};
E int h_table(unsigned i) { return h_tab[i & 7]; }
E const char *h_name(int k) { return k == 0 ? "zero" : k == 1 ? "one" : "many"; }
