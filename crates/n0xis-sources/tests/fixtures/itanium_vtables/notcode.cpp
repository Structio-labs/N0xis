// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// A subclass whose first method is outside every executable section, built by
// `build.sh` as `vd-x86_64-linux-gnu`. `Sub::f` is written out in assembly in
// a writable section that is not executable (`"aw"`, no `x`): a compiler puts
// a function only where it marks the section executable, so this is the one
// way to have a vtable slot hold an address that is no code. Sub is not
// listed, and it must still be counted: Sub derives from Base, and `Base::h`
// calls `g` through `this`, which on a Sub runs `Sub::g` (as in `outside.cpp`,
// whose `Sub::f` is in an executable section of its own).
//
// What the source says:
//   Base, Sub : Base, Last  -- three polymorphic classes, no virtual base
//   Sub's slot 0 is Sub::f, in .data.not_code; Base's slot 1 is g.

struct Base {
    int v;
    virtual int f() const;
    virtual int g() const;
    int h() const;
};
int Base::f() const { return v + 1; }
int Base::g() const { return v + 2; }
__attribute__((noinline)) int Base::h() const { return g() * 3; }

// `g` is declared first so that it is Sub's key function: the one this file
// defines in C++, which is what makes the compiler emit Sub's vtable here.
// The slots keep Base's order, f then g.
struct Sub : Base {
    int g() const override;
    int f() const override;
};
int Sub::g() const { return 41; }
asm(".section .data.not_code,\"aw\",@progbits\n"
    ".globl _ZNK3Sub1fEv\n"
    "_ZNK3Sub1fEv:\n"
    "    movl $40, %eax\n"
    "    retq\n"
    ".previous\n");

struct Last {
    virtual int z() const;
};
int Last::z() const { return 0; }
