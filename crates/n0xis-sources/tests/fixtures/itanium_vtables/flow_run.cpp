// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The processor's answer to "which f does each call in `flow.cpp` run?".
// `processor_run.sh` builds it from the same source as the fixture, runs it
// and writes the output into `processor_run.txt`.
//
// Each line prints f + 1: D::f gives 43 and B::f gives 7. g on a D runs D::f,
// so a resolution of g's call to B::f, which the vtable stored on g's other
// branch once gave, is wrong; rebuilt runs D::f or B::f by its argument, so no
// one method is its call's.

#include "flow.cpp"

extern "C" int printf(const char *, ...);

// Seen by the compiler as touching the object, as `opaque` is in the fixture.
void opaque(void *p) { asm volatile("" : : "r"(p) : "memory"); }

int main() {
    D d;
    alignas(D) unsigned char m1[sizeof(D)], m2[sizeof(D)], m3[sizeof(D)];
    printf("g(&d, 0): %d\n", g(&d, 0));
    printf("built: %d\n", built(m1));
    printf("rebuilt(m, 0): %d; rebuilt(m, 1): %d\n", rebuilt(m2, 0), rebuilt(m3, 1));
    printf("D::f + 1: 43; B::f + 1: 7\n");
    return 0;
}
