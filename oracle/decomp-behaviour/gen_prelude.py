#!/usr/bin/env python3
"""Writes prelude.h: one fixed file every body compiles against: the types and the operators the engine prints, with their meaning."""
import sys
L = []
A = L.append
A('''#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <emmintrin.h>
typedef unsigned __int128 bh_u128;
typedef __int128 bh_i128;
#define __m128 bh_u128
typedef uint64_t (*bh_fn)();
#ifndef BH_STAR
#define BH_STAR uint64_t
#endif
#ifndef BH_UNDEF
#define BH_UNDEF 0
#endif
typedef BH_STAR bh_star_t;
extern uint64_t G_BASE, G_RDI, G_RSI, G_RDX, G_RCX, G_R8, G_R9;
extern uint8_t bh_fs[4096];
extern void __stack_chk_fail();
static inline double bh_b2d(uint64_t b){double d;memcpy(&d,&b,8);return d;}
static inline uint64_t bh_d2b(double d){uint64_t b;memcpy(&b,&d,8);return b;}
static inline float bh_b2f(uint32_t b){float d;memcpy(&d,&b,4);return d;}
static inline uint32_t bh_f2b(float d){uint32_t b;memcpy(&b,&d,4);return b;}
''')
A('''
/* The n0xis dialect: floating and vector values are register bit patterns; the operator names are the instruction's. */
#define R128 bh_u128
static inline R128 bh_lo(R128 a,uint64_t lo){return (a>>64<<64)|lo;}
#define SD2(n,e) static inline R128 n(R128 a,R128 b){double x=bh_b2d((uint64_t)a),y=bh_b2d((uint64_t)b);(void)x;(void)y;return bh_lo(a,bh_d2b(e));}
#define SS2(n,e) static inline R128 n(R128 a,R128 b){float x=bh_b2f((uint32_t)a),y=bh_b2f((uint32_t)b);(void)x;(void)y;return (a>>32<<32)|bh_f2b(e);}
SD2(__addsd,x+y) SD2(__subsd,x-y) SD2(__mulsd,x*y) SD2(__divsd,x/y) SD2(__minsd,x<y?x:y) SD2(__maxsd,x>y?x:y)
SS2(__addss,x+y) SS2(__subss,x-y) SS2(__mulss,x*y) SS2(__divss,x/y)
static inline R128 __sqrtsd(R128 a){return bh_lo(a,bh_d2b(sqrt(bh_b2d((uint64_t)a))));}
static inline R128 __cvtsi2sd_(int64_t x){return bh_d2b((double)x);}
#define __cvtsi2sd(x) __cvtsi2sd_((int64_t)(x))
static inline int64_t __cvttsd2si(R128 a){return _mm_cvttsd_si64(_mm_castsi128_pd(_mm_set_epi64x(0,(int64_t)(uint64_t)a)));}
static inline uint32_t __cvttsd2si32(R128 a){return (uint32_t)_mm_cvttsd_si32(_mm_castsi128_pd(_mm_set_epi64x(0,(int64_t)(uint64_t)a)));}
static inline R128 __cvtsd2ss(R128 a){return bh_f2b((float)bh_b2d((uint64_t)a));}
static inline R128 __cvtss2sd(R128 a){return bh_d2b((double)bh_b2f((uint32_t)a));}
#define FC(n,e) static inline int n##_sd(R128 a,R128 b){double x=bh_b2d((uint64_t)a),y=bh_b2d((uint64_t)b);return e;} static inline int n##_ss(R128 a,R128 b){float x=bh_b2f((uint32_t)a),y=bh_b2f((uint32_t)b);return e;}
FC(__fcmp_ule,!(x>y)) FC(__fcmp_ult,!(x>=y)) FC(__fcmp_uno,x!=x||y!=y) FC(__fcmp_ord,x==x&&y==y) FC(__fcmp_oeq,x==y) FC(__fcmp_une,!(x==y)) FC(__fcmp_olt,x<y) FC(__fcmp_ole,x<=y) FC(__fcmp_ogt,x>y) FC(__fcmp_oge,x>=y) FC(__fcmp_ueq,!(x<y||x>y))
#define __seg_fs(o) ((uint64_t)bh_fs+(uint64_t)(o))
static inline uint64_t __max(int64_t a,int64_t b){return a>b?a:b;} static inline uint64_t __min(int64_t a,int64_t b){return a<b?a:b;}
static inline uint64_t __umax(uint64_t a,uint64_t b){return a>b?a:b;} static inline uint64_t __umin(uint64_t a,uint64_t b){return a<b?a:b;}
static inline uint64_t __cqo(int64_t x){return x<0?~0ull:0;}
static inline uint64_t __umulh(uint64_t a,uint64_t b,int w){return w>=64?(uint64_t)(((bh_u128)a*b)>>64):(uint64_t)((((uint64_t)(uint32_t)a)*(uint32_t)b)>>32);}
static inline uint64_t __mulh(uint64_t a,uint64_t b,int w){return w>=64?(uint64_t)(((bh_i128)(int64_t)a*(int64_t)b)>>64):(uint64_t)(uint32_t)((((int64_t)(int32_t)a)*(int32_t)b)>>32);}
static inline uint64_t __cdq(uint64_t x){return (uint32_t)((int32_t)x>>31);}
#define BH_DIVIDEND(w,hi,lo) ((w)==32?(bh_u128)(((uint64_t)(uint32_t)(hi)<<32)|(uint32_t)(lo)):(((bh_u128)(hi)<<64)|(lo)))
#define BH_SDIVIDEND(w,hi,lo) ((w)==32?(bh_i128)(int64_t)(((uint64_t)(uint32_t)(hi)<<32)|(uint32_t)(lo)):(bh_i128)(((bh_u128)(hi)<<64)|(lo)))
#define BH_DIVISOR(w,d) ((w)==32?(bh_u128)(uint32_t)(d):(bh_u128)(uint64_t)(d))
#define BH_SDIVISOR(w,d) ((w)==32?(bh_i128)(int32_t)(d):(bh_i128)(int64_t)(d))
static inline uint64_t __udiv(uint64_t hi,uint64_t lo,uint64_t d,int w){return (uint64_t)(BH_DIVIDEND(w,hi,lo)/BH_DIVISOR(w,d));}
static inline uint64_t __urem(uint64_t hi,uint64_t lo,uint64_t d,int w){return (uint64_t)(BH_DIVIDEND(w,hi,lo)%BH_DIVISOR(w,d));}
static inline uint64_t __idiv(uint64_t hi,uint64_t lo,uint64_t d,int w){return (uint64_t)(BH_SDIVIDEND(w,hi,lo)/BH_SDIVISOR(w,d));}
static inline uint64_t __irem(uint64_t hi,uint64_t lo,uint64_t d,int w){return (uint64_t)(BH_SDIVIDEND(w,hi,lo)%BH_SDIVISOR(w,d));}
// The operand's C type is its width, since the lift reads a narrow register through a cast. `bsr` leaves its destination on zero; 0 here.
static inline uint64_t bh_rot(uint64_t x,unsigned n,unsigned w,int left){uint64_t m=w==64?~0ull:(1ull<<w)-1;x&=m;n&=(w>32?63:31);n%=w;if(!n)return x;return ((left?(x<<n)|(x>>(w-n)):(x>>n)|(x<<(w-n))))&m;}
#define __rol(x,n) bh_rot((uint64_t)(x),(unsigned)(n),8*sizeof(x),1)
#define __ror(x,n) bh_rot((uint64_t)(x),(unsigned)(n),8*sizeof(x),0)
#define __bswap(x) (sizeof(x)==4?(uint64_t)__builtin_bswap32((uint32_t)(x)):sizeof(x)==2?(uint64_t)__builtin_bswap16((uint16_t)(x)):(uint64_t)__builtin_bswap64((uint64_t)(x)))
static inline uint64_t bh_bsr(uint64_t x){return x?63-__builtin_clzll(x):0;}
static inline uint64_t bh_bsf(uint64_t x){return x?__builtin_ctzll(x):0;}
#define BH_MASKED(x) (sizeof(x)==8?(uint64_t)(x):(uint64_t)(x)&((1ull<<(8*sizeof(x)))-1))
#define __bsr(x) bh_bsr(BH_MASKED(x))
#define __bsf(x) bh_bsf(BH_MASKED(x))
#define __tzcnt(x) (BH_MASKED(x)?(uint64_t)__builtin_ctzll(BH_MASKED(x)):(uint64_t)(8*sizeof(x)))
#define __lzcnt(x) (BH_MASKED(x)?(uint64_t)(__builtin_clzll(BH_MASKED(x))-(64-8*sizeof(x))):(uint64_t)(8*sizeof(x)))
#define __popcnt(x) ((uint64_t)__builtin_popcountll(BH_MASKED(x)))
static inline __m128i bh_x(R128 a){__m128i r;memcpy(&r,&a,16);return r;}
static inline R128 bh_r(__m128i a){R128 r;memcpy(&r,&a,16);return r;}
static inline __m128d bh_xd(R128 a){__m128d r;memcpy(&r,&a,16);return r;}
static inline R128 bh_rd(__m128d a){R128 r;memcpy(&r,&a,16);return r;}
#define V2(n,e) static inline R128 n(R128 a,R128 b){return bh_r(e(bh_x(a),bh_x(b)));}
V2(__paddb,_mm_add_epi8) V2(__paddw,_mm_add_epi16) V2(__paddd,_mm_add_epi32) V2(__paddq,_mm_add_epi64) V2(__psubb,_mm_sub_epi8) V2(__psubw,_mm_sub_epi16) V2(__psubd,_mm_sub_epi32) V2(__psubq,_mm_sub_epi64)
V2(__pcmpeqb,_mm_cmpeq_epi8) V2(__pcmpeqw,_mm_cmpeq_epi16) V2(__pcmpeqd,_mm_cmpeq_epi32) V2(__pcmpgtb,_mm_cmpgt_epi8) V2(__pcmpgtw,_mm_cmpgt_epi16) V2(__pcmpgtd,_mm_cmpgt_epi32)
V2(__punpcklbw,_mm_unpacklo_epi8) V2(__punpcklwd,_mm_unpacklo_epi16) V2(__punpckldq,_mm_unpacklo_epi32) V2(__punpcklqdq,_mm_unpacklo_epi64) V2(__punpckhbw,_mm_unpackhi_epi8) V2(__punpckhwd,_mm_unpackhi_epi16) V2(__punpckhdq,_mm_unpackhi_epi32) V2(__punpckhqdq,_mm_unpackhi_epi64)
V2(__pand,_mm_and_si128) V2(__por,_mm_or_si128) V2(__pxor,_mm_xor_si128) V2(__pandn,_mm_andnot_si128)
static inline uint64_t __pmovmskb(R128 a){return (uint32_t)_mm_movemask_epi8(bh_x(a));}
#define VS(n,e) static inline R128 n(R128 a,int c){__m128i x=bh_x(a);__m128i co=_mm_cvtsi32_si128(c);return bh_r(e(x,co));}
VS(__pslld,_mm_sll_epi32) VS(__psrld,_mm_srl_epi32) VS(__psrad,_mm_sra_epi32) VS(__psllq,_mm_sll_epi64) VS(__psrlq,_mm_srl_epi64) VS(__psllw,_mm_sll_epi16) VS(__psrlw,_mm_srl_epi16)
static inline R128 __psrldq(R128 a,int c){return c>15?0:a>>(8*c);} static inline R128 __pslldq(R128 a,int c){return c>15?0:a<<(8*c);}
static inline R128 __pshufd(R128 d,R128 a,int imm){uint32_t s[4],o[4];memcpy(s,&a,16);for(int i=0;i<4;i++)o[i]=s[(imm>>(2*i))&3];R128 r;memcpy(&r,o,16);return r;}
#define PD2(n,op) static inline R128 n(R128 a,R128 b){double x[2],y[2];memcpy(x,&a,16);memcpy(y,&b,16);x[0]=x[0] op y[0];x[1]=x[1] op y[1];R128 r;memcpy(&r,x,16);return r;}
#define PS2(n,op) static inline R128 n(R128 a,R128 b){float x[4],y[4];memcpy(x,&a,16);memcpy(y,&b,16);for(int i=0;i<4;i++)x[i]=x[i] op y[i];R128 r;memcpy(&r,x,16);return r;}
PD2(__addpd,+) PD2(__subpd,-) PD2(__mulpd,*) PD2(__divpd,/) PS2(__addps,+) PS2(__subps,-) PS2(__mulps,*) PS2(__divps,/)
#define PDM(n,e) static inline R128 n(R128 a,R128 b){double x[2],y[2];memcpy(x,&a,16);memcpy(y,&b,16);uint64_t o[2];for(int i=0;i<2;i++){double p=x[i],q=y[i];o[i]=(e)?~0ull:0;}R128 r;memcpy(&r,o,16);return r;}
PDM(__fcmpmask_olt_pd,p<q) PDM(__fcmpmask_oeq_pd,p==q) PDM(__fcmpmask_ole_pd,p<=q) PDM(__fcmpmask_une_pd,!(p==q))
''')
open(sys.argv[1], "w").write("\n".join(l for l in L if l) + "\n")
