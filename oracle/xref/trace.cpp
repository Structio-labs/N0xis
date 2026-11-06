// A walk of calls with what it cannot follow, written down.
// Built by crates/n0xis-cli/tests/function_trace_says_what_it_left.rs.
#include <stdio.h>

struct Worker {
    virtual ~Worker() {}
    virtual int first(int) const;
    virtual int second(int) const;  // Slot 3: `call [rax+0x18]`.
};
__attribute__((noinline)) int Worker::first(int x) const { return x + 1; }
__attribute__((noinline)) int Worker::second(int x) const { return x + 2; }

extern "C" {
__attribute__((noinline)) int leaf(int x) { return x * 3; }
__attribute__((noinline)) int middle(int x) { return leaf(x) + 5; }

// A call through a slot that names an import: known, and not this image's.
__attribute__((noinline)) int logs(int x) {
    puts("logged");
    return x + 1;
}

// One virtual call and one through a value it is handed, both unknown; one direct,
// which leads to `leaf` one level further.
__attribute__((noinline)) int root(const Worker* w, int (*f)(int), int x) {
    int a = w->second(x);
    int b = f(a);
    return middle(b) + a;
}
}

static int twice(int x) { return x * 2; }

int main(int argc, char**) {
    Worker w;
    return root(&w, twice, argc) + logs(argc);
}
