// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The emulator corpus, part two: functions that **call** other functions.
//
// `emu.c` is leaves only, and said so: "a call needs a callee, and a callee
// needs either a stub or real execution. Non-leaf shapes belong in a later
// file, not a later argument." This is that file.
//
// Every shape here exists because the emulator has to decide something it did
// not have to decide for a leaf:
//
//   * who the callee is (a direct branch, a PLT stub, a pointer in a register),
//   * what the callee's registers hold on entry (the caller's, not zero),
//   * where its frame goes (below the caller's, once the return address is on
//     the stack — an argument passed on the stack is only found if that is
//     right),
//   * what the caller may still assume afterwards (callee-saved survives,
//     caller-saved does not),
//   * and when to stop (recursion).
//
// The oracle is unchanged: `emu_run.c` calls the real function on the real
// processor with the same arguments, and the numbers must match.

#include <stdint.h>

#define EXPORT __attribute__((visibility("default")))

// The helpers are `noinline` on purpose. Without it `-O2` inlines every one of
// them and the corpus quietly becomes leaves again — a file that tests calls,
// passing because it stopped containing any. They are also all named `emu_h_*`
// so "which symbols are this corpus's own code" is a prefix, not a list of
// exceptions the harness has to keep in step.
#define HELPER static __attribute__((noinline))

// A callee the emulator must find by a direct branch: `static` means no PLT,
// no symbol interposition, just a `call rel32` inside the same section.
HELPER uint32_t emu_h_add3(uint32_t a, uint32_t b, uint32_t c) {
    return a + b + c;
}

EXPORT uint64_t emu_call_direct(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return (uint64_t)emu_h_add3((uint32_t)a, (uint32_t)b, (uint32_t)c) + (uint64_t)(uint32_t)d;
}

// Three frames deep. Each level narrows differently, so a frame that lands in
// the wrong place corrupts a specific level rather than everything at once.
HELPER uint32_t emu_h_lvl1(uint32_t x) {
    return x * 3u + 1u;
}
HELPER uint32_t emu_h_lvl2(uint32_t x) {
    return emu_h_lvl1(x ^ 0x5a5a5a5au) + 2u;
}
HELPER uint32_t emu_h_lvl3(uint32_t x) {
    return emu_h_lvl2(x + 7u) * 5u;
}

EXPORT uint64_t emu_call_chain(uint64_t a) {
    return (uint64_t)emu_h_lvl3((uint32_t)a);
}

// An **exported** callee, called from inside the same shared object. This does
// not become a direct branch to the body: a shared object calls its own
// exported functions through the PLT so `LD_PRELOAD` can interpose, and the
// address in the `call` is a stub. Whoever emulates it has to resolve the stub
// to the local definition the `JUMP_SLOT` relocation names, or the call lands
// on six bytes of jump table.
EXPORT uint64_t emu_call_exported_target(uint64_t a) {
    return (uint64_t)(uint32_t)((uint32_t)a * 11u + 13u);
}

EXPORT uint64_t emu_call_through_plt(uint64_t a) {
    return emu_call_exported_target(a) + 1;
}

// Eight arguments: six go in registers, the last two on the stack. They are
// only read back correctly if the callee's frame sits below the return address
// the `call` pushed — an off-by-eight here reads the return address as an
// argument, and the answer is enormous rather than subtly wrong.
HELPER uint32_t emu_h_eight(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f,
                      uint32_t g, uint32_t h) {
    return a + b * 2u + c * 3u + d * 4u + e * 5u + f * 6u + g * 7u + h * 8u;
}

EXPORT uint64_t emu_call_stack_args(uint64_t a, uint64_t b) {
    uint32_t x = (uint32_t)a;
    uint32_t y = (uint32_t)b;
    return (uint64_t)emu_h_eight(x, y, x ^ y, x + y, x - y, x | y, x & y, ~x);
}

// The caller holds a value across the call. The compiler will keep it in a
// callee-saved register, and the callee will `push`/`pop` that same register:
// the value survives only if the emulator lets the callee read the caller's
// register file and does not let the callee's writes leak back.
HELPER uint32_t emu_h_clobberer(uint32_t x) {
    uint32_t t = x;
    for (unsigned i = 0; i < 4; i++) t = t * 31u + i;
    return t;
}

EXPORT uint64_t emu_call_preserves(uint64_t a, uint64_t b) {
    uint32_t keep = (uint32_t)a ^ 0x1234u;
    uint32_t got = emu_h_clobberer((uint32_t)b);
    return (uint64_t)(keep + got) | ((uint64_t)keep << 32);
}

// Recursion: the same body, a new frame each time, and a bound on the depth.
// Masked so the depth is small and fixed by the input, not by luck.
HELPER uint64_t emu_h_fact(uint32_t n) {
    if (n < 2) return 1;
    return (uint64_t)n * emu_h_fact(n - 1);
}

EXPORT uint64_t emu_call_recursive(uint64_t a) {
    return emu_h_fact((uint32_t)a & 7u);
}

// A call in a loop, so the same callee runs against a different register file
// each time round and a leaked frame shows up as drift rather than one wrong
// number.
EXPORT uint64_t emu_call_in_loop(uint64_t a) {
    uint32_t s = 0;
    for (uint32_t i = 0; i < ((uint32_t)a & 7u) + 1u; i++) s += emu_h_add3(s, i, (uint32_t)a);
    return (uint64_t)s;
}

// An **indirect** call. `volatile` stops the compiler folding the pointer back
// into a direct branch, so the callee address only exists at run time — the
// emulator has to evaluate the target expression rather than read it off the
// instruction.
EXPORT uint64_t emu_call_by_pointer(uint64_t a, uint64_t b, uint64_t c) {
    uint32_t (*volatile f)(uint32_t, uint32_t, uint32_t) = emu_h_add3;
    return (uint64_t)f((uint32_t)a, (uint32_t)b, (uint32_t)c);
}

// A callee **outside the image**: defined by the driver executable, reached
// through the PLT, and unreachable to anything reading only this library. This
// is the case a stub exists for — and the stub's value is a claim the emulator
// is handed, not one it invents. `emu_run.c` owns both the definition and the
// number, and prints the number, so the claim has exactly one source.
extern uint64_t emu_ext_const(void);

EXPORT uint64_t emu_call_import(uint64_t a) {
    return emu_ext_const() ^ a;
}
