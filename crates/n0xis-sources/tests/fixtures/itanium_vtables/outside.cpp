// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// A subclass whose first method is outside `.text`, built by `build.sh` as
// `vo-x86_64-linux-gnu`. `Sub::f` is in a section of its own (`hot_code`,
// executable), so the word where Sub's first method is holds an address
// outside `.text` and inside the code. The scan once took only `.text` for
// code and did not list Sub; it lists it now, and with Sub's base read, Base
// is known to be derived from: `Base::h` calls `g` through `this`, which on a
// Sub runs `Sub::g` (built with a `main` and run on this machine's processor:
// `Base::h` on a Sub printed 123, which is `Sub::g`'s 41 * 3; `Base::g` would
// give 6). `notcode.cpp` is the same classes with `Sub::f` outside the code.
//
// What the source says:
//   Base, Sub : Base, Last  -- three polymorphic classes, no virtual base
//   Sub's slot 0 is Sub::f, in hot_code; Base's slot 1 is g.

struct Base {
    int v;
    virtual int f() const;
    virtual int g() const;
    int h() const;
};
int Base::f() const { return v + 1; }
int Base::g() const { return v + 2; }
__attribute__((noinline)) int Base::h() const { return g() * 3; }

struct Sub : Base {
    int f() const override;
    int g() const override;
};
__attribute__((section("hot_code"))) int Sub::f() const { return 40; }
int Sub::g() const { return 41; }

struct Last {
    virtual int z() const;
};
int Last::z() const { return 0; }
