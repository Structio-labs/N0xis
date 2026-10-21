/* A shared object that needs two libraries in a stated order (libm, then
   libc), imports from each by a versioned name, and calls one of its own
   exported functions through its PLT, which is a jump slot bound to a
   definition of its own and so not an import. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

double n0x_cos(double x) { return cos(x); }
int n0x_puts(const char *s) { return puts(s); }
void *n0x_alloc(size_t n) { return malloc(n); }
int n0x_self(int x) { return x + 1; }
int n0x_calls_self(int x) { return n0x_self(x) * 2; }
