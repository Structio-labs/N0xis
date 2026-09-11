/* Copyright (c) 2026 Tymofii Kosovskyi
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 *
 * Shape: PE, x86-64, Microsoft x64 (Win64).
 *
 * Every name states its own truth: `win64_<ret>_<args>`, where the letters are
 * v=void i=int l=long long f=float d=double p=pointer. `win64_d_id` returns a
 * double and takes an int then a double. A failure is then readable without
 * opening expect.json — which is the point of naming them this way.
 *
 * Win64 shares one **positional** slot between its two argument register
 * files: `f(int, double)` passes in `rcx` and `xmm1`, and `xmm0` stays unused.
 * Counting the files independently — the System V rule — miscounts every mixed
 * signature, so `win64_d_id` and `win64_d_di` are the pair that pins it down.
 */
#include <stdint.h>

void      win64_v_v(void)                          { }
int       win64_i_i2(int a, int b)                 { return a * b; }
double    win64_d_d1(double a)                     { return a * 2.0; }
double    win64_d_d3(double a, double b, double c) { return a + b * c; }
float     win64_f_f2(float a, float b)             { return a - b; }
double    win64_d_id(int n, double x)              { return n * x; }
double    win64_d_di(double x, int n)              { return x / (n | 1); }
char     *win64_p_p1(char *s)                      { return s + 1; }
int64_t   win64_l_l1(int64_t v)                    { return v << 3; }
void      win64_v_pi(int *p, int v)                { *p = v; }
