// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The processor's answer to "which method does the dispatch in Base::h call?",
// for an object whose dynamic type is a subclass of the type `this` is
// declared as. Built from the same `vtables.cpp` as the fixtures and run here;
// `processor_run.sh` builds it, runs it and writes `processor_run.txt`.
//
// Base::h is `return g() * 3;` with g virtual. On a Derived, g is Derived::g
// (w + 4), so with w = 10 the processor prints 42. Had the call been Base::g
// (v + 2), as devirtualization once resolved it through `this`'s declared
// type, it would print 6.

#include "vtables.cpp"

extern "C" int printf(const char *, ...);

void opaque(void *) {}

int main() {
    Derived d;
    d.v = 0;
    d.w = 10;
    printf("Base::h on a Derived: %d\n", d.h());
    printf("if the call were Base::g: %d; Derived::g: %d\n", (d.v + 2) * 3, (d.w + 4) * 3);
    return 0;
}
