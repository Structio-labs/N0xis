// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Classes whose virtual base is **indirect** and shares their vptr, built by
// `build.sh` with clang -O1 as the shared objects `vy-<target>.so`. clang
// emits no VTT for them, their `type_info` pointers are symbolic relocations
// that read zero, and a class's own `type_info` names only its non-virtual
// base, so nothing but the relocations says where their vptr is.
//
// What the source says, and what the tests take from it:
//   Mid : virtual P   -- P has no data, so it is Mid's primary base and shares
//                        Mid's vptr; P's method gives the tables vcall offsets
//   Leaf : Mid        -- an indirect virtual base, laid out the same way: its
//                        table begins with zero offsets
//   Mid2 : virtual E  -- E is empty and has no method, so the table has one
//                        offset, zero, and no vcall offset
//   Leaf2 : Mid2      -- the same, indirect: `_ZTV` + two pointers is the
//                        relocation that names its own `_ZTI`
//   Plain             -- no virtual base: the control
// Each build_* builds one object in place, hands it to a function defined
// nowhere, and calls its method through the table.

inline void *operator new(__SIZE_TYPE__, void *at) noexcept { return at; }
void opaque(void *);

struct P {
    virtual int fp() const { return 1; }
};
struct Mid : virtual P {
    int fp() const override { return 2; }
    virtual int m() const { return 3; }
};
struct Leaf : Mid {
    int m() const override { return 4; }
};
struct E {};
struct Mid2 : virtual E {
    virtual int m2() const { return 5; }
};
struct Leaf2 : Mid2 {
    int m2() const override { return 6; }
};
struct Plain {
    virtual int g() const { return 7; }
};
int build_leaf(void *mem) { Leaf *p = new (mem) Leaf; opaque(p); return p->m(); }
int build_leaf2(void *mem) { Leaf2 *p = new (mem) Leaf2; opaque(p); return p->m2(); }
int build_plain(void *mem) { Plain *p = new (mem) Plain; opaque(p); return p->g(); }
