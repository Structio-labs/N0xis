// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// C++ classes whose vtables are known before any tool is asked: single and
// multiple inheritance, a pure virtual method, and two virtual calls. Built for
// four targets as a shared object and as an executable by `build.sh`.
//
// What the source says, and what the tests take from it:
//   Base, Derived, Shape, Square, Left, Right, Both  -- seven polymorphic classes
//   Derived : Base, Square : Shape, Both : Left, Right
//   Base's slot 1 is Base::g, called through `this` in Base::h and through a
//   freshly built object in fresh().

inline void *operator new(__SIZE_TYPE__, void *at) noexcept { return at; }

// Defined nowhere: the compiler cannot see what it does to the object, so it
// has to read the vtable pointer again after the call.
void opaque(void *);

struct Base {
    int v;
    virtual int f() const;
    virtual int g() const;
    int h() const;
};
int Base::f() const { return v + 1; }
int Base::g() const { return v + 2; }
// A virtual call through `this`, slot 1 of Base's table. `const`, because on
// an ELF only a cv-qualified mangled name proves the first argument is `this`.
__attribute__((noinline)) int Base::h() const { return g() * 3; }

// A virtual call on an object whose vtable this function stored itself.
int fresh(void *mem) {
    Base *b = new (mem) Base;
    opaque(b);
    return b->g() + 1;
}

struct Derived : Base {
    int w;
    int g() const override;
    virtual int k() const;
};
int Derived::g() const { return w + 4; }
int Derived::k() const { return w + 5; }

struct Shape {
    virtual int area() const = 0;
    virtual int sides() const;
};
int Shape::sides() const { return 0; }

struct Square : Shape {
    int s;
    int area() const override;
    int sides() const override;
};
int Square::area() const { return s * s; }
int Square::sides() const { return 4; }

struct Left {
    virtual int l();
};
int Left::l() { return 6; }

struct Right {
    virtual int r();
};
int Right::r() { return 7; }

struct Both : Left, Right {
    int l() override;
    int r() override;
};
int Both::l() { return 8; }
int Both::r() { return 9; }
