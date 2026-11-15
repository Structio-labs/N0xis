// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// A threaded interpreter: `goto *` lands on labels of its own function, and
// built with -fcf-protection each landing carries `endbr64`, as an entry does.
// Discovery on the stripped build must list no label as a function; the truth
// is `nm -S` of the build with its symbols
// (crates/n0xis-cli/tests/a_computed_goto_label_is_no_function.rs).
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) long run(const unsigned char *code, long acc)
{
    static void *const ops[] = { &&op_add, &&op_sub, &&op_mul, &&op_xor, &&op_shl, &&op_end };
#define NEXT goto *ops[*code++]
    NEXT;
op_add: acc += code[0] + 3; code++; NEXT;
op_sub: acc -= code[0] * 5; code++; NEXT;
op_mul: acc *= code[0] | 1; code++; NEXT;
op_xor: acc ^= (long)code[0] << 7; code++; NEXT;
op_shl: acc <<= code[0] & 7; code++; NEXT;
op_end: return acc;
}

__attribute__((noinline)) long other(long x) { return x * 7 + 1; }

int main(int argc, char **argv)
{
    unsigned char prog[] = { 0, 9, 1, 2, 2, 3, 3, 4, 4, 1, 5 };
    prog[1] = (unsigned char)argc;
    printf("%ld %ld\n", run(prog, argc > 1 ? atol(argv[1]) : 1), other(argc));
    return 0;
}
