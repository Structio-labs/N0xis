// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Classes with virtual bases, whose vtables do not start where a class
// without one's do. Built by `build.sh` as `vb-<target>.so`.
//
// What the source says, and what the tests take from it:
//   VBase                 -- no virtual base, so no VTT
//   Mid : virtual VBase   -- a virtual base: a VTT (_ZTT3Mid)
//   Leaf : Mid            -- an indirect virtual base: a VTT (_ZTT4Leaf)
// A vtable of a class with virtual bases begins with its virtual-base
// offsets, then offset_to_top and the type_info pointer, so its first method
// is more than two pointers past the _ZTV symbol.

struct VBase {
    int x;
    virtual int a() const;
};
int VBase::a() const { return x; }

struct Mid : virtual VBase {
    int y;
    int a() const override;
    virtual int m() const;
};
int Mid::a() const { return y; }
int Mid::m() const { return y + 1; }

struct Leaf : Mid {
    int z;
    int m() const override;
};
int Leaf::m() const { return z; }
