// Classes whose hierarchies and slots are written here, for a scan of a stripped image.
// Built by crates/n0xis-cli/tests/rtti_of_a_stripped_image.rs.
#include <stdio.h>

struct Base {
    virtual ~Base();
    virtual int f();
    int field_b = 1;
};
Base::~Base() {}
int Base::f() { return field_b; }

struct Derived : Base {
    ~Derived() override;
    int f() override;
    virtual int g();
    int field_d = 2;
};
Derived::~Derived() {}
int Derived::f() { return field_d; }
int Derived::g() { return field_d + field_b; }

struct Left {
    virtual int l();
    int field_l = 3;
};
int Left::l() { return field_l; }
struct Right {
    virtual int r();
    int field_r = 4;
};
int Right::r() { return field_r; }
// Two bases, so a second table: `offset_to_top` is not zero there, and it is not this
// class's vptr.
struct Both : Left, Right {
    int l() override;
    int r() override;
};
int Both::l() { return field_l + 1; }
int Both::r() { return field_r + 1; }

struct Abstract {
    virtual int pure() = 0;
    virtual ~Abstract();
};
Abstract::~Abstract() {}
struct Concrete : Abstract {
    int pure() override;
};
int Concrete::pure() { return 7; }

namespace deep {
template <class T>
struct Box : Base {
    T value{};
    int f() override { return static_cast<int>(value); }
};
template struct Box<int>;
}  // namespace deep

// gcc writes a type name with no external linkage with a leading `*`.
namespace {
struct Hidden : Base {
    int f() override { return 9; }
};
}  // namespace

// A virtual base: the vptr is not two words into the object, and a class that derives
// from this one has a table for it during construction, with `VMid`'s type_info in it.
struct VBase {
    virtual int v();
};
int VBase::v() { return 11; }
struct VMid : virtual VBase {
    int v() override;
    virtual int m();
};
int VMid::v() { return 12; }
int VMid::m() { return 13; }
struct VLeaf : VMid {
    int m() override;
};
int VLeaf::m() { return 14; }

// A class with a type_info and no table: thrown, and not polymorphic.
struct Thrown {
    int code;
};

__attribute__((noinline)) int use(Base* b, Left* l, Right* r, Abstract* a, VBase* v) {
    return b->f() + l->l() + r->r() + a->pure() + v->v() + dynamic_cast<Derived*>(b)->g();
}

int main(int argc, char** argv) {
    // What the compiler laid out, said by the program itself. Each of these classes has
    // a vptr, so `offsetof` is only conditionally supported: both compilers support it.
    if (argc == 2 && argv[1][0] == 'o') {
        printf("Base %zu\n", __builtin_offsetof(Base, field_b));
        printf("Derived %zu\n", __builtin_offsetof(Derived, field_b));
        printf("Derived %zu\n", __builtin_offsetof(Derived, field_d));
        printf("Left %zu\n", __builtin_offsetof(Left, field_l));
        printf("Right %zu\n", __builtin_offsetof(Right, field_r));
        printf("Both %zu\n", __builtin_offsetof(Both, field_l));
        printf("Both %zu\n", __builtin_offsetof(Both, field_r));
        return 0;
    }
    Derived d;
    Both both;
    Concrete c;
    VLeaf leaf;
    deep::Box<int> box;
    Hidden hidden;
    int n = use(argc & 1 ? static_cast<Base*>(&d) : argc & 2 ? static_cast<Base*>(&box) : &hidden, &both, &both, &c, &leaf);
    try {
        if (n == 12345) throw Thrown{n};
    } catch (const Thrown& t) {
        return t.code;
    }
    return n;
}
