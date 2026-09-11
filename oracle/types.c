/* Copyright (c) 2026 Tymofii Kosovskyi
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 *
 * Shape: recovered **struct layout**, against DWARF.
 *
 * Type recovery beyond the signature — the struct fields a function touches,
 * the offsets it dereferences — had no external source at all. It is also the
 * part a reader trusts most: `w->field_0x18` reads like a fact about the
 * program, and an offset the pass invented reads exactly the same way.
 *
 * DWARF settles it and costs nothing: `gcc -g` states every member's offset,
 * from the compiler that laid the struct out. The check is one-directional on
 * purpose — **every offset the tool recovers must be a real member** — because
 * the reverse ("every member must be recovered") is not a property of the
 * binary. An optimizer can fold, hoist or drop a field access entirely, so a
 * field that never appears is the compiler's doing, not a miss.
 *
 * The layouts below are chosen to be hostile to a pass that guesses: a `double`
 * next to a pointer, two 4-byte fields sharing an 8-byte slot (24 and 28), a
 * 1-byte field followed by explicit padding, two floats at 16 and 20, and a
 * nested struct pointer so a dereference chains through two objects.
 */
#include <stdint.h>

struct A {
    uint64_t a0;
    double a8;
    void *a16;
    uint32_t a24; /* 24 and 28 share one 8-byte slot: a pass that assumes */
    uint32_t a28; /* pointer-sized fields invents 0x20 and misses these   */
    uint64_t a32;
};

struct B {
    uint8_t b0;
    uint8_t pad[7]; /* explicit padding, so 8 is a real member and 1..7 are not */
    uint64_t b8;
    float b16;
    float b20;
    void *b24;
};

struct C {
    void *vt; /* vtable-shaped first slot */
    struct A *inner;
    uint64_t c16;
};

uint64_t f1(struct A *p) { return p->a0 ^ p->a32; }
uint64_t f2(struct A *p) { return p->a24 + p->a28; }
double f3(struct A *p) { return p->a8; }
void *f4(struct A *p) { return p->a16; }
uint64_t f5(struct B *p) { return p->b0 + p->b8; }
float f6(struct B *p) { return p->b16 * p->b20; }
void *f7(struct B *p) { return p->b24; }
uint64_t f8(struct C *p) { return p->c16 ^ p->inner->a0; }
uint64_t f9(struct C *p) { return (uint64_t)(uintptr_t)p->vt ^ p->inner->a32; }
uint64_t f10(struct A *p) { return p->a0 + (uint64_t)(uintptr_t)p->a16 ? p->a32 : p->a24; }
