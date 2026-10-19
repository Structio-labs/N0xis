// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// A C program whose shapes are known before the module is read: arithmetic,
// loops, a pointer to a struct, a switch dense enough for a branch table, calls
// through function pointers, globals, 64-bit integers and doubles, and a load
// and a store of every width the instruction set has. `build.sh` compiles it at
// -O0 and -O2 for wasm32.

typedef signed char i8;
typedef unsigned char u8;
typedef short i16;
typedef unsigned short u16;
typedef int i32;
typedef unsigned int u32;
typedef long long i64;
typedef unsigned long long u64;

// Supplied by the host: an import of the module.
__attribute__((import_module("host"), import_name("report"))) void host_report(i32 code, i64 value);
__attribute__((import_module("host"), import_name("scale"))) double host_scale(double x);

struct record {
    i8 tag;
    u8 flags;
    i16 delta;
    u16 port;
    i32 count;
    i64 total;
    float ratio;
    double weight;
    struct record *next;
};

i32 counter = 7;
i64 big_total = 0x123456789abcdefLL;
double accumulated = 1.5;
struct record pool[4];

i32 add(i32 a, i32 b) { return a + b; }
i32 subtract(i32 a, i32 b) { return a - b; }
i32 multiply(i32 a, i32 b) { return a * b; }

typedef i32 (*binary_op)(i32, i32);
binary_op operations[3] = { add, subtract, multiply };

i32 apply(u32 which, i32 a, i32 b) {
    return operations[which % 3](a, b);
}

// Arithmetic of every integer kind, signed and unsigned.
i32 mix32(i32 a, i32 b, u32 c, u32 d) {
    i32 r = (a * b) ^ (a >> 3) ^ (i32)(c >> (d & 7));
    r += (i32)(c / (d | 1)) + a % (b | 1) + (i32)(c % (d | 1));
    r -= a / (b | 1);
    return r | (a & ~b);
}

i64 mix64(i64 a, i64 b, u64 c) {
    i64 r = a * b + (a >> 7) - (i64)(c >> 9);
    r ^= (i64)(c / ((u64)b | 1)) + a / (b | 1) + a % (b | 1);
    return r + (i64)(c % 1000);
}

double mixf(double x, float y, i64 n, u32 m) {
    double r = x * (double)y + (double)n / 3.0 - (double)m;
    float s = (float)r * y - (float)n;
    return r + (double)s + (double)(i64)x + (double)(u32)y;
}

// A loop over an array and one over a linked list.
i64 sum(const i32 *values, i32 n) {
    i64 total = 0;
    for (i32 i = 0; i < n; i++) {
        total += values[i];
    }
    return total;
}

i32 chain_length(const struct record *r) {
    i32 n = 0;
    while (r) {
        n++;
        r = r->next;
    }
    return n;
}

// Every field of the record read at its own width, and every width written.
i64 read_all(const struct record *r) {
    i64 t = r->tag;
    t += r->flags;
    t += r->delta;
    t += r->port;
    t += r->count;
    t += r->total;
    t += (i64)r->ratio;
    t += (i64)r->weight;
    return t;
}

i64 widen_signed8(const i8 *p) { return *p; }
i64 widen_unsigned8(const u8 *p) { return *p; }
i64 widen_signed16(const i16 *p) { return *p; }
i64 widen_unsigned16(const u16 *p) { return *p; }
i64 widen_signed32(const i32 *p) { return *p; }
i64 widen_unsigned32(const u32 *p) { return *p; }

void write_all(struct record *r, i64 v, double w) {
    r->tag = (i8)v;
    r->flags = (u8)(v >> 8);
    r->delta = (i16)v;
    r->port = (u16)(v >> 16);
    r->count = (i32)v;
    r->total = v;
    r->ratio = (float)w;
    r->weight = w;
}

i32 narrow_reads(const i8 *a, const u8 *b, const i16 *c, const u16 *d) { return *a + *b + *c + *d; }

void narrow_writes(i8 *p, i16 *q, i32 v) {
    *p = (i8)v;
    *q = (i16)v;
}

void narrow8(i8 *p, i64 v) { *p = (i8)v; }
void narrow16(i16 *p, i64 v) { *p = (i16)v; }
void narrow32(i32 *p, i64 v) { *p = (i32)v; }

// Dense cases with side effects of their own, so the compiler keeps a branch
// table rather than a lookup table.
i32 dispatch(i32 op, i32 a, i32 b) {
    switch (op) {
    case 0:
        counter += a;
        return counter;
    case 1:
        host_report(1, a);
        return a - b;
    case 2:
        return apply((u32)a, b, op);
    case 3:
        big_total += b;
        return (i32)big_total;
    case 4:
        accumulated = host_scale(accumulated);
        return (i32)accumulated;
    case 5:
        pool[a & 3].count = b;
        return b;
    case 6:
        return chain_length(&pool[b & 3]);
    default:
        return -1;
    }
}
