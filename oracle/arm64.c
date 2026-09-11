/* Copyright (c) 2026 Tymofii Kosovskyi
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 *
 * Shape: AArch64 — the **decoder's** corpus, not the signature corpus.
 *
 * ARM64 had one verification: three hand-written encodings in
 * `n0xis-core/tests/arm64_exit.rs`. That proves the ISA seam holds; it says
 * nothing about whether the decoder reads real compiler output correctly, and
 * the project's own notes said so — "implemented and self-tested", never
 * "working".
 *
 * These functions exist to make a compiler emit *families*, not arithmetic:
 * floating-point and SIMD, integer division, both conversion directions,
 * a counted loop, a switch (so a jump table and a compare-and-branch), bit
 * manipulation intrinsics, byte and halfword loads/stores, a conditional
 * select, an atomic read-modify-write, and a call between two of them.
 *
 * Build with `-O2` on purpose: `-O0` emits a narrow, stack-shuffling subset
 * and would leave the interesting encodings unexercised.
 *
 * Checked by `crates/n0xis-cli/tests/decoder_agrees_with_objdump.rs` against
 * `llvm-objdump --triple=aarch64`. AArch64 is fixed-width, so boundaries prove
 * nothing here — the comparison is on **mnemonics**, and the alias pairs the
 * architecture itself defines (`mov`/`orr`, `cmp`/`subs`, `b.hs`/`b.cs`) are
 * listed in the test rather than papered over.
 */
typedef unsigned long u64; typedef long i64; typedef unsigned u32; typedef int i32;
typedef unsigned char u8; typedef unsigned short u16;
double  f_d1(double a){return a*2.0;}
double  f_d3(double a,double b,double c){return a+b*c;}
float   f_f2(float a,float b){return a-b;}
double  f_sqrt(double a){return __builtin_sqrt(a);}
i64     f_i2(i64 a,i64 b){return a*b+(a>>3);}
u64     f_div(u64 a,u64 b){return a/b;}
double  f_cvt(i64 n){return (double)n;}
i64     f_cvt2(double x){return (i64)x;}
void    f_v0(void){}
u64     f_loop(u64*p,u32 n){u64 s=0;for(u32 i=0;i<n;i++)s+=p[i]^(s<<1);return s;}
i32     f_sw(i32 x){switch(x){case 1:return 10;case 2:return 20;case 3:return 30;case 7:return 70;default:return -1;}}
u64     f_bits(u64 v){return (v<<7)|(v>>57)|__builtin_popcountll(v);}
u32     f_clz(u64 v){return __builtin_clzll(v)+__builtin_ctzll(v);}
void    f_memzero(u8*p,u32 n){for(u32 i=0;i<n;i++)p[i]=0;}
u16     f_ldst(u16*p,u16 v){u16 o=p[3];p[5]=v;return o;}
i64     f_sel(i64 a,i64 b){return a>b?a:b;}
u64     f_atomic(u64*p){return __atomic_fetch_add(p,1,__ATOMIC_SEQ_CST);}
double  f_arr(double*p,u32 n){double s=0;for(u32 i=0;i<n;i++)s+=p[i]*p[i];return s;}
u64     f_call(u64 x){return f_bits(x)+f_div(x,7);}
