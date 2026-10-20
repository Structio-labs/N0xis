// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Where a construction gives an object its class, built by `build.sh` as
// `vf-x86_64-linux-gnu`. A construction (a vtable stored into the object, here
// by placement new) is the object's dynamic type only at the points it
// dominates, and only where no other construction of the object can reach.
//
// What the source says:
//   B, D : B           -- two polymorphic classes; slot 0 is f
//   g(mem, rebuild)    -- builds a B in mem only when rebuild is set, and
//                         otherwise calls f on the object it was handed: on a
//                         D that is D::f (processor_run.txt: g(&d, 0) is 43)
//   built(mem)         -- builds a D and calls f on it: D::f
//   rebuilt(mem, again)-- builds a D, and a B over it when again is set, then
//                         calls f: D::f or B::f, by the argument
//   Last               -- a class whose vtable follows D's, so D's table has an
//                         end a slot read is bounded by

inline void *operator new(__SIZE_TYPE__, void *at) noexcept { return at; }

// Defined nowhere here: the compiler cannot see what it does to the object, so
// it has to read the vtable pointer again after the call.
void opaque(void *);

struct B {
    virtual int f() const;
};
struct D : B {
    int f() const override;
};
int B::f() const { return 6; }
int D::f() const { return 42; }

__attribute__((noinline)) int g(void *mem, int rebuild) {
    B *p = static_cast<B *>(mem);
    if (rebuild) {
        new (mem) B;
        return 0;
    }
    return p->f() + 1;
}

__attribute__((noinline)) int built(void *mem) {
    B *p = new (mem) D;
    opaque(p);
    return p->f() + 1;
}

__attribute__((noinline)) int rebuilt(void *mem, int again) {
    B *p = new (mem) D;
    opaque(p);
    // A call on each path, so the two constructions stay two stores rather
    // than one store of a selected vtable.
    if (again) {
        new (mem) B;
        opaque(p);
    }
    return p->f() + 1;
}

struct Last {
    virtual int z() const;
};
int Last::z() const { return 0; }
