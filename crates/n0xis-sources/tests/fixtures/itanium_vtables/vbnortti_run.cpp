// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The processor's answer to "where in its `_ZTV` does the vptr of each object
// of `vbnortti.cpp` point?", built from the same source with `-fno-rtti` and
// run by `processor_run.sh`, which records the output in `processor_run.txt`.
// Each line is the byte offset of a live object's vptr from its class's `_ZTV`
// symbol. "Symbol + two pointers" would be 8 on i686 and 16 on x86-64.

#include "vbnortti.cpp"

extern "C" int printf(const char *, ...);
// The tables, by their mangled names; -fno-rtti leaves no type_info to name.
extern "C" char _ZTV2HM[], _ZTV2HL[], _ZTV1Q[];

// Seen by the compiler as touching the object, as `opaque` is in the fixture.
void opaque(void *p) { asm volatile("" : : "r"(p) : "memory"); }

static long vptr_offset(const void *obj, const char *table) { return *(const char *const *)obj - table; }

int main() {
    alignas(HL) unsigned char m[sizeof(HL)];
    printf("build_hm: %d, build_hl: %d, build_q: %d\n", build_hm(m), build_hl(m), build_q(m));
    HM hm;
    HL hl;
    Q q;
    printf("vptr HM %ld\n", vptr_offset(&hm, _ZTV2HM));
    printf("vptr HL %ld\n", vptr_offset(&hl, _ZTV2HL));
    printf("vptr Q %ld\n", vptr_offset(&q, _ZTV1Q));
    return 0;
}
