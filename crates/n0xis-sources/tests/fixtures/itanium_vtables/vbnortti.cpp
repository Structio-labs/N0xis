// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Classes with a virtual base, compiled **without RTTI** (`-fno-rtti`), built
// by `build.sh` with clang -O2 as `vn-<target>` and `vn-<target>.so`. With no
// RTTI there is no `type_info` to say anything, and clang emits no VTT, so
// nothing but the relocations says that `_ZTV` + two pointers is not where
// the first method is.
//
// What the source says, and what the tests take from it:
//   P            -- no virtual base; its key function `p` is defined here,
//                   so its table is emitted here
//   HM : virtual P -- P has no data, so it is HM's primary base and shares
//                   HM's vptr: its virtual-base offset is 0, and so are the
//                   vcall offsets before it. HM's table begins with five zero
//                   words before its first method on either width.
//   HL : HM      -- an indirect virtual base, laid out the same way
//   Q            -- no virtual base: the control
// HM, HL and Q have no key function, so each table is emitted where a
// build_* builds one object in place, hands it to a function defined nowhere
// (so the compiler must read the vptr again), and calls its method.
// `vbnortti_run.cpp` prints where each object's vptr points in its `_ZTV`.

inline void *operator new(__SIZE_TYPE__, void *at) noexcept { return at; }
void opaque(void *);

struct P {
    virtual int p() const;
    virtual ~P();
};
int P::p() const { return 1; }
P::~P() {}
struct HM : virtual P {
    int p() const override { return 11; }
};
struct HL : HM {
    int p() const override { return 12; }
};
// After the others in the image, so the last table has a next one to end it.
struct Q {
    virtual int q() const { return 5; }
};
int build_hm(void *mem) { HM *p = new (mem) HM; opaque(p); return p->p() + 100; }
int build_hl(void *mem) { HL *p = new (mem) HL; opaque(p); return p->p() + 100; }
int build_q(void *mem) { Q *p = new (mem) Q; opaque(p); return p->q() + 100; }
