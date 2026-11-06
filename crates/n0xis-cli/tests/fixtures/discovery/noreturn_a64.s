# What follows a call, AArch64 (`calls_that_do_not_return.rs`; rebuilt by
# `plant.sh`). No FDE and no symbol size: every end here is the graph's.
        .text
        .p2align 4
        .type   calls_them_all, %function
calls_them_all:
        bl      before_a_trap
        bl      before_filler
        bl      statement_nops
        bl      last_listed
        ret
        .p2align 4
        .type   helper, %function
helper:
        mov     w0, #0
        ret
        .p2align 4
# The compiler's trap: part of the function.
        .type   before_a_trap, %function
before_a_trap:
        bl      helper
        brk     #1
        .p2align 4
# Filler up to an aligned address nothing jumps to, three `nop`s.
        .type   before_filler, %function
before_filler:
        bl      helper
        nop
        nop
        nop
# False: gcc `-O0` writes `nop` as a statement, twice here.
        .type   statement_nops, %function
statement_nops:
        mov     w1, #0
        bl      helper
        nop
        nop
        ldp     x29, x30, [sp], #16
        ret
        .p2align 4
        .type   last_listed, %function
last_listed:
        ret
