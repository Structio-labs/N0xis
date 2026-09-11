// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The corpus for **computed control flow** — the layer with no outside source
// at all until now.
//
// A jump table resolved wrongly is the worst kind of wrong answer a decompiler
// can produce: not a number that is off, but *control flow that never
// happened*, and every fact derived downstream inherits it. The census of a
// real library shows 19 of 400 functions stopping at an `ijmp`, and nothing
// anywhere had ever checked that the cases n0xis recovers are the cases the
// machine takes.
//
// Each function returns a distinct constant per case, so a wrong edge is a
// wrong number and the processor settles it. Leaf functions, as everywhere in
// this corpus.

#include <stdint.h>

#define EXPORT __attribute__((visibility("default")))

// Dense and contiguous — the shape that becomes a jump table.
EXPORT uint64_t emu_switch_dense(uint64_t a) {
    switch ((int)(a & 0xf)) {
        case 0: return 11;
        case 1: return 13;
        case 2: return 17;
        case 3: return 19;
        case 4: return 23;
        case 5: return 29;
        case 6: return 31;
        case 7: return 37;
        case 8: return 41;
        case 9: return 43;
        case 10: return 47;
        case 11: return 53;
        case 12: return 59;
        case 13: return 61;
        case 14: return 67;
        default: return 71;
    }
}

// Sparse — a compiler usually turns this into a comparison chain or a
// bit-test, which is a different recovery problem with the same answer.
EXPORT uint64_t emu_switch_sparse(uint64_t a) {
    switch ((int)(a & 0xff)) {
        case 3: return 73;
        case 17: return 79;
        case 64: return 83;
        case 129: return 89;
        case 200: return 97;
        default: return 101;
    }
}

// Dense with a hole, so the table has a repeated default entry.
EXPORT uint64_t emu_switch_holes(uint64_t a) {
    switch ((int)(a & 0x1f)) {
        case 0:
        case 4:
        case 8: return 103;
        case 1: return 107;
        case 9: return 109;
        case 16: return 113;
        default: return 127;
    }
}

// A switch whose cases fall through into one another.
EXPORT uint64_t emu_switch_fallthrough(uint64_t a) {
    uint64_t s = 0;
    switch ((int)(a & 7)) {
        case 0: s += 1; /* fall through */
        case 1: s += 2; /* fall through */
        case 2: s += 4; /* fall through */
        case 3: s += 8; break;
        case 4: s += 16; break;
        default: s += 32; break;
    }
    return s * 3 + 1;
}

// A switch inside a loop: the same dispatch reached with a different value each
// time round, so one wrong edge shows up as drift rather than a single wrong
// answer.
EXPORT uint64_t emu_switch_in_loop(uint64_t a) {
    uint64_t s = 0;
    for (int i = 0; i < 12; i++) {
        switch ((int)((a + (uint64_t)i) & 7)) {
            case 0: s += 2; break;
            case 1: s += 3; break;
            case 2: s += 5; break;
            case 3: s += 7; break;
            case 4: s += 11; break;
            case 5: s += 13; break;
            case 6: s += 17; break;
            default: s += 19; break;
        }
    }
    return s;
}

// Two dispatches in one function, so a resolver that reads past the end of the
// first table finds the second one's entries — which are code addresses too,
// and so pass every check a bounds-free probe makes.
EXPORT uint64_t emu_switch_two_tables(uint64_t a, uint64_t b) {
    uint64_t x, y;
    switch ((int)(a & 7)) {
        case 0: x = 1; break;
        case 1: x = 2; break;
        case 2: x = 4; break;
        case 3: x = 8; break;
        case 4: x = 16; break;
        case 5: x = 32; break;
        case 6: x = 64; break;
        default: x = 128; break;
    }
    switch ((int)(b & 7)) {
        case 0: y = 3; break;
        case 1: y = 9; break;
        case 2: y = 27; break;
        case 3: y = 81; break;
        case 4: y = 243; break;
        case 5: y = 729; break;
        case 6: y = 2187; break;
        default: y = 6561; break;
    }
    return x * 10000 + y;
}
