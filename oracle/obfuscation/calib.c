/* Copyright (c) 2026 Tymofii Kosovskyi
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 *
 * The small program the obfuscation instrument calibrates on: a handful of
 * functions with early returns and an unconditional tail jump (so a
 * junk-after-transfer transformation has somewhere to plant), a string the
 * program prints about itself (so `strings` has a known answer), and a
 * deterministic result printed to stdout (so "the transformed program still
 * runs and prints the same thing" is a byte comparison). No libc call that
 * varies by run; the output is a pure function of the code.
 */
#include <stdio.h>

__attribute__((noinline)) int add_two(int a, int b) { return a + b; }

__attribute__((noinline)) int classify(int x) {
    if (x < 0) return -1;      /* early return: a `ret` mid-function */
    if (x == 0) return 0;      /* another */
    return 1;
}

__attribute__((noinline)) long sum_to(long n) {
    long s = 0;
    for (long i = 0; i < n; i++) s += i;
    return s;                  /* the loop's back-edge is an unconditional jmp */
}

__attribute__((noinline)) const char *pick(int x) {
    if (x > 0) return "CALIB_POSITIVE";
    return "CALIB_NONPOSITIVE";
}

int main(void) {
    int a = add_two(20, 22);
    int c = classify(a) + classify(-5) + classify(0);
    long s = sum_to(a);
    const char *p = pick(c);
    printf("CALIB_RESULT a=%d c=%d s=%ld p=%s\n", a, c, s, p);
    return 0;
}
