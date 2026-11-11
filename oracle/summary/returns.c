/* `function summary`'s `returns`: each RET_ hands control back to its caller, each
   NR_ never does. Written from this source, not from any tool's output.
   Read by crates/n0xis-cli/tests/returns_is_what_the_source_says.rs. */
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#define NI __attribute__((noinline))
NI int RET_computed(int i){ static void*t[]={&&a,&&b,&&c}; goto *t[i&1]; a: return 11; b: return 22; c: return 33; }
NI int RET_switch(int k){ switch(k){case 0:return 5;case 1:return 7;case 2:return 9;case 3:return 3;case 4:return 8;case 5:return 13;case 6:return 42;default:return 0;} }
NI int RET_via_ptr(int (*f)(int),int x){ return f(x); }          /* tail jmp through a register */
jmp_buf jb;
NI void RET_longjmp_thrower(int x){ if(x>1000) longjmp(jb,1); }
NI int RET_after_exit_maybe(int x){ if(x==7777) exit(9); return x; }
NI int RET_loop_breaks(int n){ for(;;){ n--; if(n<0) return n; } }
NI int RET_recur(int n){ return n<=0 ? 0 : RET_recur(n-1)+1; }
NI __attribute__((noreturn)) void NR_exit(int c){ fprintf(stderr,"bye\n"); exit(c); }
NI __attribute__((noreturn)) void NR_abort(void){ abort(); }
NI __attribute__((noreturn)) void NR_wrapper(int c){ NR_exit(c+1); }
NI __attribute__((noreturn)) void NR_spin(volatile int*p){ for(;;) (*p)++; }
NI __attribute__((noreturn)) void NR_mutual2(int n);
NI __attribute__((noreturn)) void NR_mutual1(int n){ if(n&1) exit(1); NR_mutual2(n); }
NI __attribute__((noreturn)) void NR_mutual2(int n){ if(n&2) abort(); NR_mutual1(n+1); }
int main(int argc, char **argv) {
    volatile int v = 0;
    (void)argv;
    if (argc == 99) NR_exit(1);
    if (argc == 98) NR_abort();
    if (argc == 97) NR_wrapper(1);
    if (argc == 96) NR_spin(&v);
    if (argc == 95) NR_mutual1(1);
    if (argc == 94) RET_longjmp_thrower(argc);
    return RET_computed(argc) + RET_switch(argc) + RET_via_ptr(RET_recur, argc) + RET_after_exit_maybe(argc) + RET_loop_breaks(argc);
}
