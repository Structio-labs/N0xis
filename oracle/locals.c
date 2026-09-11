// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The locals corpus — stack objects whose address the compiler writes down.
//
// A recovered local's *name* (`local_48`) is a displacement from whichever
// frame register the expression happened to use, and comparing that number to
// a disassembler's displacement is how the last attempt at this check went
// wrong: the two count from different places and agreed 781 times out of 782
// by coincidence. An **address** has no such ambiguity.
//
// So this file is compiled with `-g`, and DWARF states each variable's location
// as `DW_OP_fbreg <n>` against `DW_OP_call_frame_cfa`. The CFA is pinned by the
// ABI — on System V x86-64 it is the value `rsp` had at the call site, which is
// entry `rsp` plus the 8 bytes the `call` pushed. That makes every declared
// local a concrete address, and the emulator reports the concrete addresses the
// recovered program actually touches. Same units, no conversion, no coincidence.
//
// Every local here is `volatile` and written unconditionally on every path, so
// "DWARF declares it" and "the run must touch it" are the same statement. A
// local the compiler could keep in a register would prove nothing.

#include <stdint.h>

#define EXPORT __attribute__((visibility("default")))

EXPORT uint64_t loc_three_scalars(uint64_t a, uint64_t b) {
    volatile uint64_t x = a + 1;
    volatile uint64_t y = b + 2;
    volatile uint64_t z = a ^ b;
    return x + y + z;
}

// Mixed widths: an 8-, 16-, 32- and 64-bit slot in one frame. The compiler packs
// them, so a lift that rounds every slot to 8 bytes lands on the wrong address.
EXPORT uint64_t loc_mixed_widths(uint64_t a, uint64_t b) {
    volatile uint8_t p = (uint8_t)a;
    volatile uint16_t q = (uint16_t)b;
    volatile uint32_t r = (uint32_t)(a ^ b);
    volatile uint64_t s = a + b;
    return (uint64_t)p + q + r + s;
}

// An array, written from its first byte to its last.
EXPORT uint64_t loc_array(uint64_t a, uint64_t b) {
    volatile uint64_t buf[6];
    for (int i = 0; i < 6; i++) buf[i] = a + (uint64_t)i * b;
    uint64_t s = 0;
    for (int i = 0; i < 6; i++) s += buf[i];
    return s;
}

// A struct — one DWARF object covering several slots.
struct loc_pair {
    uint64_t lo;
    uint64_t hi;
};

EXPORT uint64_t loc_struct(uint64_t a, uint64_t b) {
    volatile struct loc_pair p;
    p.lo = a;
    p.hi = b;
    return p.lo * 3 + p.hi;
}

// Two frames' worth of locals in one function, so the frame is deep enough that
// an off-by-one-slot error cannot land inside the right object by luck.
EXPORT uint64_t loc_deep(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    volatile uint64_t v0 = a;
    volatile uint64_t v1 = b;
    volatile uint64_t v2 = c;
    volatile uint64_t v3 = d;
    volatile uint64_t v4 = a ^ b;
    volatile uint64_t v5 = b ^ c;
    volatile uint64_t v6 = c ^ d;
    volatile uint64_t v7 = d ^ a;
    return v0 + v1 * 2 + v2 * 3 + v3 * 5 + v4 * 7 + v5 * 11 + v6 * 13 + v7 * 17;
}
