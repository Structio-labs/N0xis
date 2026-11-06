// Answers of `xref to` that are only in data: nothing calls these directly.
//
// Built by crates/n0xis-cli/tests/xref_finds_what_data_holds.rs. Which method sits
// in which slot of which vtable is written there, from this file; where each is
// comes from `nm`, and what writes it from `readelf -r`.
struct Shape {
    virtual ~Shape() {}
    virtual int area() const = 0;
    virtual int sides() const { return 0; }
};
struct Square : Shape {
    int s;
    explicit Square(int x) : s(x) {}
    int area() const override { return s * s; }
    int sides() const override { return 4; }
};
struct Circle : Shape {
    int r;
    explicit Circle(int x) : r(x) {}
    int area() const override { return 3 * r * r; }
};

extern "C" {
// An indirect handler in a constant pointer table, and one a variable starts with.
__attribute__((noinline)) int handler_add(int x) { return x + 11; }
__attribute__((noinline)) int handler_mul(int x) { return x * 13; }
__attribute__((noinline)) int handler_neg(int x) { return -x + 17; }
__attribute__((noinline)) int handler_hook(int x) { return x ^ 19; }
// Nothing holds this one and nothing calls it: a zero to keep.
__attribute__((noinline, used)) int handler_unused(int x) { return x - 23; }

// Declared `extern` so that the name is in the image under both compilers: a
// `const` object is otherwise internal in C++, and clang mangles such a name.
extern int (*const handlers[3])(int);
int (*const handlers[3])(int) = {handler_add, handler_mul, handler_neg};
int (*hook)(int) = handler_hook;

// A number in data, of a size an address of this image could be: it must never
// read as a pointer on an image that may load anywhere.
volatile unsigned long long not_a_pointer[4] = {1, 2, 3, 4};
}

#if defined(__ELF__)
// Tables of offsets from their own start, as a compiler's relative lookup table:
// no word equals an address and no relocation names one. Two side by side, whose
// second is relative to itself and not to the first, and one of a single entry
// followed by a word that lands nowhere, which is not called a table.
// Hidden, since a shared object cannot state an offset to a symbol a program may replace.
extern "C" {
__attribute__((noinline, used, visibility("hidden"))) int rel_a(int x) { return x + 31; }
__attribute__((noinline, used, visibility("hidden"))) int rel_b(int x) { return x + 37; }
__attribute__((noinline, used, visibility("hidden"))) int rel_c(int x) { return x + 41; }
__attribute__((noinline, used, visibility("hidden"))) int rel_d(int x) { return x + 43; }
__attribute__((noinline, used, visibility("hidden"))) int rel_e(int x) { return x + 47; }
extern const int rel_first[], rel_second[], rel_single[];
}
__asm__(".section .rodata\n"
        ".p2align 2\n"
        ".globl rel_first\nrel_first:\n .long rel_a - rel_first\n .long rel_b - rel_first\n"
        ".globl rel_second\nrel_second:\n .long rel_c - rel_second\n .long rel_d - rel_second\n .long 0x7ffffff0\n"
        ".globl rel_single\nrel_single:\n .long rel_e - rel_single\n .long 0x7ffffff0\n"
        ".text\n");
typedef int (*op)(int);
__attribute__((noinline)) int through_offsets(const int* table, int i, int x) {
    return reinterpret_cast<op>(reinterpret_cast<__INTPTR_TYPE__>(table) + table[i])(x);
}
// Each base taken by an instruction, which is what makes it a base.
__attribute__((noinline)) int use_offsets(int i, int x) {
    return through_offsets(rel_first, i & 1, x) + through_offsets(rel_second, i & 1, x) + through_offsets(rel_single, 0, x);
}
#else
__attribute__((noinline)) int use_offsets(int, int x) { return x; }
#endif

__attribute__((noinline)) int dispatch(int which, int x) {
    return handlers[which % 3](x) + hook(x);
}

__attribute__((noinline)) int make_and_ask(int k) {
    Shape* s = k & 1 ? static_cast<Shape*>(new Square(k)) : new Circle(k);
    int n = s->area() + s->sides();
    delete s;
    return n;
}

int main(int argc, char**) {
    return dispatch(argc, argc) + make_and_ask(argc) + static_cast<int>(not_a_pointer[0]) + use_offsets(argc, argc);
}
