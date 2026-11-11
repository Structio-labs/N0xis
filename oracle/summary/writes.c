/* `function summary`'s `writes_memory`: do this function's own instructions store
   outside its own stack frame? The answer is in each name, from this source, and the
   same at -O0 and -O2: W_ = yes, F_ = no. What a callee writes does not count.
   Read by crates/n0xis-cli/tests/writes_memory_is_outside_the_frame.rs. */
#include <stdint.h>
#include <immintrin.h>
#define NI __attribute__((noinline, noipa))
int g;
int *gp;
volatile int sink;
NI int  ext(int a) { return a * 7 + 1; }
NI double ext_d(double a) { return a * 0.5; }
NI void W_param(int *p, int v) { *p = v; }                 /* through a parameter */
NI void W_global(int v) { g = v; }                          /* to a global */
NI void W_loaded(int v) { *gp = v; }                        /* through an address loaded from memory */
NI void W_loaded2(int **pp, int v) { **pp = v; }            /* the same, two loads */
NI void W_inc(int *p) { (*p)++; }                           /* read-modify-write */
NI void W_setcc(char *p, int a) { *p = a > 3; }
NI int  W_xchg(int *p) { return __sync_lock_test_and_set(p, 1); }
NI int  W_cas(int *p) { return __sync_val_compare_and_swap(p, 0, 1); }
NI void W_sse(__m128i *p) { _mm_storeu_si128(p, _mm_setzero_si128()); }
NI void W_rep(char *p, long n) { __asm__ volatile("rep stosb" ::"D"(p), "c"(n), "a"(0) : "memory"); }
NI void W_bts(unsigned long *p) { 
#ifdef __x86_64__
    __asm__ volatile("lock btsq $3,%0" : "+m"(*p));
#else
    __asm__ volatile("lock btsl $3,%0" : "+m"(*p));
#endif
 }
NI void W_index(int *p, long i, int v) { p[i] = v; }       /* parameter plus an index */
NI int  F_pure(int a, int b) { return a * 3 + b; }
NI int  F_read(const int *p) { return *p; }
NI int  F_local(int a) { volatile int x = a; return x + 1; }   /* a local, -O0 and -O2 */
NI int  F_spill(int a) { int r = ext(a); return r + a; }       /* callee-saved across a call */
NI double F_spill_d(double a) { double r = ext_d(a); return r * a; } /* a vector spill */
NI int  F_frame_ptr(int a, int i) {                           /* a pointer from the frame, passed nowhere */
    int buf[4] = {0, 0, 0, 0};
    int *q = &buf[1];
    *(volatile int *)q = a;
    return buf[1] + i;
}
NI int  F_calls_writer(int *p) { W_param(p, 5); return 1; }  /* the callee writes, not this */
NI void F_tail(int *p) { W_inc(p); }                         /* a tail call to a writer */
int main(int c, char **v) { (void)v; return c; }
void *keep[] = {(void *)W_param, (void *)W_global, (void *)W_loaded, (void *)W_loaded2, (void *)W_inc, (void *)W_setcc,
                (void *)W_xchg, (void *)W_cas, (void *)W_sse, (void *)W_rep, (void *)W_bts, (void *)W_index, (void *)F_pure,
                (void *)F_read, (void *)F_local, (void *)F_spill, (void *)F_spill_d, (void *)F_frame_ptr,
                (void *)F_calls_writer, (void *)F_tail};
