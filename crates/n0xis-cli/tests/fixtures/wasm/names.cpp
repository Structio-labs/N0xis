// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Function names that are not identifiers, as a C++ producer writes them into
// a module's `name` section (already demangled, by wasm-ld), and a call to an
// imported function. Built by build.sh with clang++ --target=wasm32 -O1
// -fno-inline; what each function is called is known before asking: the
// signatures below.

extern "C" void host_log(int value);

struct Vec {
    int *d;
    int n;
    void push(int x);
    int sum() const;
};

void Vec::push(int x) { d[n++] = x; }

int Vec::sum() const {
    int s = 0;
    for (int i = 0; i < n; i++) s += d[i];
    return s;
}

namespace ns {
template <class T> T twice(T v) { return v + v; }
}

extern "C" __attribute__((visibility("default"))) int entry(int a) {
    static int buf[8];
    Vec v{buf, 0};
    v.push(a);
    v.push(ns::twice(a));
    host_log(a);
    return v.sum() + (int)ns::twice<long long>(a);
}
