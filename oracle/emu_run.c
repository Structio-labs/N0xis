// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The rung-1 oracle for the emulator: run the real function on the real CPU.
//
// Prints one JSON line per (function, input vector):
//   {"fn":"emu_add32","args":[...],"ret":...}
// The emulator is handed exactly these arguments and must produce exactly
// this `ret`. Nothing here reads anything n0xis produced.

// One driver, two platforms. The value walk, the argument printing and the
// constant below are the facts this program owns, and a second copy of them for
// Windows would be a second set of facts — which is how every drift in this
// project started. Only the three lines that open a library differ.
#ifdef _WIN32
#include <windows.h>
#define DL_OPEN(p) ((void *)LoadLibraryA(p))
#define DL_SYM(h, n) ((void *)GetProcAddress((HMODULE)(h), (n)))
#define DL_ERR() "LoadLibrary/GetProcAddress failed"
#else
#include <dlfcn.h>
#define DL_OPEN(p) dlopen((p), RTLD_NOW)
#define DL_SYM(h, n) dlsym((h), (n))
#define DL_ERR() dlerror()
#endif

#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// On i386 the corpus under test is `emu32.c`, whose functions are `uint32_t`
// in and out — four 4-byte stack slots and a result in `eax`, with no register
// pair anywhere. The value walk, the printing and the constant below are
// unchanged; only the width of a call is.
#if defined(__i386__)
typedef uint32_t emu_word;
#define EMU_FMT PRIu32
#else
typedef uint64_t emu_word;
#define EMU_FMT PRIu64
#endif

typedef emu_word (*fn4)(emu_word, emu_word, emu_word, emu_word);

// A callee that lives in *this* executable, not in the library under test.
// `oracle/emu_calls.c` calls it through the PLT, so the library's own bytes
// never contain its body — which is exactly the case an emulator has to answer
// with a stated stub value instead of execution. The value is defined once,
// here, and printed below, so the test never carries a second copy of it.
#define EMU_EXT_CONST 0x00c0ffee0badf00dull

uint64_t emu_ext_const(void) {
    return EMU_EXT_CONST;
}

// Deterministic and adversarial on purpose: values whose upper 32 bits are set
// (so a dropped width shows), values that straddle the signed/unsigned split,
// small values, and zero.
static const uint64_t VALUES[] = {
    0x0000000000000000ull,
    0x0000000000000001ull,
    0x000000000000002aull,
    0x00000000ffffffffull,
    0x0000000100000000ull,
    0xdeadbeefcafe1234ull,
    0xffffffffffffffffull,
    0x8000000000000000ull,
    0x7fffffffffffffffull,
    0x0123456789abcdefull,
};
#define NVALUES (sizeof(VALUES) / sizeof(VALUES[0]))

// A fixed, non-random walk over the value list, so the same inputs are used on
// every run and by the emulator. Four arguments per case.
static void args_for(unsigned case_index, uint64_t out[4]) {
    for (int i = 0; i < 4; i++) {
        out[i] = VALUES[(case_index * (unsigned)(i + 1) + (unsigned)i * 3u) % NVALUES];
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: emu_run <library.so> <cases> <fn>...\n");
        return 2;
    }
    void *h = DL_OPEN(argv[1]);
    if (!h) {
        fprintf(stderr, "open: %s\n", DL_ERR());
        return 2;
    }
    unsigned cases = (unsigned)strtoul(argv[2], NULL, 10);
    printf("{\"extern\":\"emu_ext_const\",\"value\":%" PRIu64 "}\n",
           (uint64_t)EMU_EXT_CONST);
    for (int a = 3; a < argc; a++) {
        fn4 f = (fn4)DL_SYM(h, argv[a]);
        if (!f) {
            fprintf(stderr, "symbol %s: %s\n", argv[a], DL_ERR());
            return 2;
        }
        for (unsigned c = 0; c < cases; c++) {
            uint64_t v64[4];
            args_for(c, v64);
            emu_word v[4] = {(emu_word)v64[0], (emu_word)v64[1], (emu_word)v64[2],
                             (emu_word)v64[3]};
            emu_word r = f(v[0], v[1], v[2], v[3]);
            printf("{\"fn\":\"%s\",\"args\":[%" EMU_FMT ",%" EMU_FMT ",%" EMU_FMT ",%" EMU_FMT
                   "],\"ret\":%" EMU_FMT "}\n",
                   argv[a], v[0], v[1], v[2], v[3], r);
        }
    }
    return 0;
}
