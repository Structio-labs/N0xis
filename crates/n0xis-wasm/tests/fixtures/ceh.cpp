// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// C++ exceptions, as `clang++ -fwasm-exceptions` compiles them for wasm32
// without a standard library: `try` with `catch (...)`, a destructor that runs
// while an exception unwinds through its frame, a `try` nested in a handler, a
// rethrow, and a throw of the C++ tag through `__builtin_wasm_throw(0, p)`.
// What the runtime would supply (`__cxa_begin_catch`, `__cxa_end_catch`,
// `__cxa_rethrow` and the C++ tag itself) is left undefined and becomes an
// import of the module, as are the two host functions declared here; so does
// `std::terminate`, which the compiled handlers call, imported as
// `env._ZSt9terminatev`. No personality routine is imported. `build.sh`
// compiles it at -O2 twice: with the legacy exception instructions (LLVM's
// default; wasm-objdump -d counts 15 `try`, 4 `catch`, 11 `catch_all`,
// 5 `rethrow` and 1 `throw`, and no `delegate`) and with the `exnref` ones
// (`try_table`, `throw_ref`, `throw`).
//
// Every function with C linkage this file defines is defined on a line of the
// form
//     extern "C" <type> <name>(<parameters>) {
// (the return type is int or void), so a test finds them all by scanning for
// that shape; the body follows on the lines after it. The one other function
// defined here, the destructor of `Guard`, is inlined into its caller at -O2
// and is not a function of the modules.

extern "C" void may_throw(int code);
extern "C" int report(int value);

struct Guard {
    int value;
    ~Guard() { report(value); }
};

extern "C" int guarded(int x) {
    try {
        may_throw(x);
    } catch (...) {
        return report(-1);
    }
    return report(x);
}

extern "C" int with_cleanup(int x) {
    Guard g{x};
    may_throw(x);
    return x + 1;
}

extern "C" int nested(int x) {
    try {
        may_throw(x);
    } catch (...) {
        try {
            may_throw(x + 1);
        } catch (...) {
            return report(2);
        }
        return report(1);
    }
    return 0;
}

extern "C" int rethrows(int x) {
    try {
        may_throw(x);
    } catch (...) {
        report(3);
        throw;
    }
    return x;
}

extern "C" void raise(void *payload) {
    __builtin_wasm_throw(0, payload);
}
