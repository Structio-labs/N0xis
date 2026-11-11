/* An i386 executable that calls its imports through PLT stubs: a fixed one
   jumps through an absolute slot (`jmp *slot`), a position-independent one
   through `ebx` (`jmp *disp(%ebx)`, ebx holding the address DT_PLTGOT states).
   It needs libm, then libc, and imports from each. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    (void)argv;
    void *p = malloc((size_t)argc);
    puts("n0x");
    if (argc > 9) exit(3);
    free(p);
    return (int)cos((double)argc);
}
