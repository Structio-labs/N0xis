// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The corpus for one question: **does this function receive a `this`
// pointer, and of which class?**
//
// That question is the seed of whole-program type propagation. Measured on a
// shipped library, 474 of 528 typed arguments were refused as not portable —
// correctly, because a name like `struct_rdi_0 *` recovered inside one function
// means nothing in any other. A `this` pointer is the opposite: it is a
// *program-wide* identity, and every one recovered is a seed that can travel.
//
// The trap is that the Itanium ABI mangles a **static member function** exactly
// like an instance method — `_ZN6Widget6staticEi` and `_ZN6Widget8instanceEi`
// have the same shape — and a static member has no `this`. A rule written from
// the name alone would put a `Widget *` in the first argument of a function
// whose first argument is an `int`, and would then propagate that confidently
// through the call graph. So every shape below exists to be got right or got
// wrong on purpose:
//
//   * instance methods, const and non-const, with and without a vtable;
//   * a static member function, which must **not** be claimed;
//   * constructors and a destructor, where the ABI settles it;
//   * an operator, a template instantiation, a nested class;
//   * a free function inside a namespace, whose mangled name looks like a
//     method of a class called `Ui` and is not one.
//
// The truth is not in this comment: it is in the DWARF the compiler writes.
// `DW_AT_object_pointer` on a `DW_TAG_subprogram` is the compiler saying, of
// the function it just emitted, which formal parameter is `this` — an answer
// that exists before the question is asked.

#define EXPORT __attribute__((visibility("default")))

// A class with no virtual functions: nothing in the image names it except the
// mangled symbols of its own methods.
class Plain {
  public:
    Plain(int seed) : a(seed), b(seed * 2) {}
    ~Plain() { a = 0; }
    int scale(int k) { return a * k + b; }
    int peek() const { return a + b; }
    // The trap. Same mangled shape as `scale`, no `this`.
    static int combine(int x, int y) { return x * 3 + y; }
    Plain &operator+=(int k) {
        a += k;
        return *this;
    }

  private:
    int a;
    int b;
};

// A class with a vtable, so RTTI names it in the image.
class Virt {
  public:
    Virt(int seed) : v(seed) {}
    virtual ~Virt() {}
    virtual int compute(int k) { return v * k; }
    int plain_method(int k) { return v + k; }
    static int no_this(int k) { return k - 1; }

  protected:
    int v;
};

class Derived : public Virt {
  public:
    Derived(int seed) : Virt(seed), extra(seed + 1) {}
    int compute(int k) override { return extra * k + v; }

  private:
    int extra;
};

// A nested class — the qualified name has two `::` and only the last is the
// class.
class Outer {
  public:
    class Inner {
      public:
        Inner(int q) : q(q) {}
        int twice() const { return q * 2; }
        static int thrice(int q) { return q * 3; }

      private:
        int q;
    };
};

// A template, instantiated twice: two distinct classes with one source.
template <typename T> class Box {
  public:
    Box(T v) : v(v) {}
    T get() const { return v; }
    T bump(T k) { return v + k; }
    static T zero() { return T(); }

  private:
    T v;
};

// A namespace, not a class. Its mangled name has exactly the shape of a
// method's, and there is no `this` anywhere in it.
namespace Ui {
int helper(int x) { return x + 7; }
int other(int x, int y) { return x * y; }
} // namespace Ui

template class Box<int>;
template class Box<long>;

// Keep every symbol above alive and exported through one entry point, so
// nothing is discarded and the classes are really constructed.
EXPORT long cxx_this_entry(int seed) {
    Plain p(seed);
    Virt v(seed);
    Derived d(seed);
    Outer::Inner in(seed);
    Box<int> bi(seed);
    Box<long> bl(seed);
    Virt *poly = &d;
    p += seed;
    long total = 0;
    total += p.scale(3) + p.peek() + Plain::combine(seed, 2);
    total += poly->compute(4) + v.plain_method(5) + Virt::no_this(6);
    total += in.twice() + Outer::Inner::thrice(seed);
    total += bi.get() + bi.bump(2) + Box<int>::zero();
    total += bl.get() + bl.bump(2) + Box<long>::zero();
    total += Ui::helper(seed) + Ui::other(seed, 3);
    return total;
}
