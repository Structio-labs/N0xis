// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Classes with virtual bases and **no key function**, built by `build.sh` with
// clang -O2 as `vbi-<target>.so` and `vbi-<target>`. clang emits their vtables
// where they are used and no VTT (`_ZTT`) for any of them, so a VTT does not
// show that they have virtual bases; their tables do.
//
// What the source says, and what the tests take from it:
//   M : virtual A, virtual B -- two virtual bases with data: M's table begins
//                               with two virtual-base offsets, neither zero
//   N : virtual P            -- P has no data, so it is N's primary base and
//                               shares N's vptr: its virtual-base offset is 0,
//                               and so are the vcall offsets after it
//   Plain, Tail              -- no virtual base
// A, B and P are never built on their own, so they have a type_info and no
// vtable. Each build_* builds one object in place, hands it to a function
// defined nowhere (so the compiler must read the vptr again), and calls its
// method through the table: M's f3, N's fn, Plain's g, Tail's t.

inline void *operator new(__SIZE_TYPE__, void *at) noexcept { return at; }
void opaque(void *);

struct A {
    int a;
    virtual int fa() const { return a + 1; }
};
struct B {
    int b;
    virtual int fb() const { return b + 2; }
};
struct M : virtual A, virtual B {
    int m;
    __attribute__((noinline)) M() : m(3) {}
    virtual int f1() const { return m + 31; }
    virtual int f2() const { return m + 32; }
    virtual int f3() const { return m + 33; }
};
struct P {
    virtual int fp() const { return 1; }
};
struct N : virtual P {
    __attribute__((noinline)) N() {}
    int fp() const override { return 2; }
    virtual int fn() const { return 3; }
};
struct Plain {
    int x;
    __attribute__((noinline)) Plain() : x(5) {}
    virtual int f() const { return x; }
    virtual int g() const { return x + 1; }
};
// After Plain in the image, so Plain's table has a next one to end it.
struct Tail {
    __attribute__((noinline)) Tail() {}
    virtual int t() const { return 9; }
};
int build_m(void *mem) { M *p = new (mem) M; opaque(p); return p->f3() + 1; }
int build_n(void *mem) { N *p = new (mem) N; opaque(p); return p->fn() + 1; }
int build_plain(void *mem) { Plain *p = new (mem) Plain; opaque(p); return p->g() + 1; }
int build_tail(void *mem) { Tail *p = new (mem) Tail; opaque(p); return p->t(); }
