/* Copyright (c) 2026 Tymofii Kosovskyi
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 *
 * Shape: ELF, x86-64, System V.
 *
 * Every name states its own truth: `sysv_<ret>_<args>`, where the letters are
 * v=void i=int l=long long f=float d=double p=pointer. `sysv_d_id` returns a
 * double and takes an int then a double. A failure is then readable without
 * opening expect.json — which is the point of naming them this way.
 *
 * System V consumes its two argument register files with **independent**
 * counters: `f(int, double)` passes in `rdi` and `xmm0`. That is the half of
 * the ABI the tool did not model, and `sysv_d_id` is the case that proved it.
 */
#include <stdint.h>

void      sysv_v_v(void)                        { }
int       sysv_i_i2(int a, int b)               { return a * b; }
double    sysv_d_d1(double a)                   { return a * 2.0; }
double    sysv_d_d3(double a, double b, double c) { return a + b * c; }
float     sysv_f_f2(float a, float b)           { return a - b; }
double    sysv_d_id(int n, double x)            { return n * x; }
double    sysv_d_di(double x, int n)            { return x / (n | 1); }
char     *sysv_p_p1(char *s)                    { return s + 1; }
int64_t   sysv_l_l1(int64_t v)                  { return v << 3; }
void      sysv_v_pi(int *p, int v)              { *p = v; }
