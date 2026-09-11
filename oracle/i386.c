/* Copyright (c) 2026 Tymofii Kosovskyi
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 *
 * Shape: PE32, i386, `cdecl` and `stdcall`.
 *
 * The naming adds the convention, because on i386 it decides what can be known
 * at all: `i386_<conv>_<ret>_<args>`.
 *
 * **`stdcall` states its arity on the way out** — `ret imm16` pops the argument
 * bytes, so the count is a fact in the bytes.
 *
 * **`cdecl` states nothing.** The caller cleans up, there is no argument
 * register to scan, and the honest answer is that the arity is unknown — which
 * in C is `f()`, not `f(void)`. The tool printed the second: seven of the ten
 * functions in an earlier version of this file were told they take nothing
 * while taking one to three arguments. The evidence is still in the bytes (the
 * incoming stack slots the body reads) and reading it is recorded as open.
 *
 * i386 also returns floating-point values on the **x87 stack**, which the lift
 * does not model at all — `i386_cdecl_d_d1` is the case that keeps that gap
 * visible instead of letting it read as `void`.
 */
#include <stdint.h>

__attribute__((cdecl))   void    i386_cdecl_v_v(void)                    { }
__attribute__((cdecl))   int     i386_cdecl_i_i1(int a)                  { return a + 1; }
__attribute__((cdecl))   int     i386_cdecl_i_i3(int a, int b, int c)    { return a + b * c; }
__attribute__((cdecl))   void    i386_cdecl_v_pi(int *p, int v)          { *p = v; }
__attribute__((cdecl))   double  i386_cdecl_d_d1(double x)               { return x * 2.0; }
__attribute__((cdecl))   float   i386_cdecl_f_f2(float a, float b)       { return a + b; }
__attribute__((cdecl))   int64_t i386_cdecl_l_l1(int64_t v)              { return v << 3; }
__attribute__((cdecl))   char   *i386_cdecl_p_p1(char *s)                { return s + 1; }
__attribute__((stdcall)) int     i386_stdcall_i_i2(int a, int b)         { return a - b; }
__attribute__((stdcall)) void    i386_stdcall_v_p1(int *p)               { *p = 0; }
