# Calls that do not return, x86-64 (`calls_that_do_not_return.rs`; rebuilt by
# `plant.sh`). No FDE and no symbol size anywhere: every end here is the
# graph's. `helper` returns; what follows each call of it is what is planted.
        .text
        .p2align 4
# Direct calls of everything below: discovery lists a call's target, and nothing
# else here declares a function.
        .type   calls_them_all, @function
calls_them_all:
        call    filler_with_the_function_going_on
        call    before_a_trap_and_a_landing_pad
        call    three_statement_nops
        call    before_a_hand_written_alignment
        call    panics_mid_function
        call    calls_std_that_returns
        call    named_through_relro
        call    nameless_through_relro
        call    through_a_variable
        call    through_an_unknown_slot
        call    wraps_through_a_slot
        call    before_a_trap
        call    before_trapping_filler
        call    before_filler
        call    before_a_loop
        call    jumped_past
        call    statement_nops
        call    past_a_breakpoint
        call    last_listed
        ret
        .p2align 4, 0xcc
        .type   helper, @function
helper:
        xor     %eax, %eax
        ret
        .p2align 4, 0xcc

# --- A call through a slot ---------------------------------------------------
# `.data.rel.ro` is under PT_GNU_RELRO, so a relative relocation is the word's
# value for the life of the process.
        .type   named_through_relro, @function
named_through_relro:
        call    *.Lslot_named(%rip)
        ret
        .p2align 4, 0xcc
# No symbol: a stripped image's callee. Its call is in `calls_them_all` too.
.Lnameless:
        mov     $1, %eax
        ret
        .p2align 4, 0xcc
        .type   nameless_through_relro, @function
nameless_through_relro:
        call    *.Lslot_nameless(%rip)
        ret
        .p2align 4, 0xcc
# The word holds an initial value, in `.data`: a variable the program may store
# another function in. Unknown at run time, so no callee.
        .type   through_a_variable, @function
through_a_variable:
        call    *.Lslot_variable(%rip)
        ret
        .p2align 4, 0xcc
# Nothing relocates the word: it is zero until something fills it.
        .type   through_an_unknown_slot, @function
through_an_unknown_slot:
        call    *.Lslot_unknown(%rip)
        ret
        .p2align 4, 0xcc
# Loops for ever, so the fixpoint proves it. Nothing names it noreturn.
.Lspins:
        jmp     .Lspins
        .p2align 4, 0xcc
# A call through a slot to the above is all it does; code follows the call, so
# only the fixpoint seeing through the slot can say it never returns.
        .type   wraps_through_a_slot, @function
wraps_through_a_slot:
        call    *.Lslot_spins(%rip)
        mov     $2, %eax
        ret
        .p2align 4, 0xcc

# --- The panic family, by name -----------------------------------------------
# Plain code follows each call, as it does after a panic in the middle of a
# function. Mangled by rustc's legacy scheme.
        .type   _ZN4core9panicking5panic17h0123456789abcdefE, @function
_ZN4core9panicking5panic17h0123456789abcdefE:
        ud2
        .p2align 4, 0xcc
        .type   _ZN3std9panicking11panic_count17is_zero_slow_path17h0123456789abcdefE, @function
_ZN3std9panicking11panic_count17is_zero_slow_path17h0123456789abcdefE:
        ret
        .p2align 4, 0xcc
        .type   panics_mid_function, @function
panics_mid_function:
        call    *.Lslot_panic(%rip)
        mov     $5, %eax
        ret
        .p2align 4, 0xcc
        .type   calls_std_that_returns, @function
calls_std_that_returns:
        call    *.Lslot_std(%rip)
        mov     $6, %eax
        ret
        .p2align 4, 0xcc

# --- What follows a call -----------------------------------------------------
# The compiler's trap: part of the function.
        .type   before_a_trap, @function
before_a_trap:
        call    helper
        ud2
        .p2align 4, 0xcc
# False, for the function: a trap ends the block, and what comes next is a
# landing pad only the unwinder reaches, so the function goes on.
        .type   before_a_trap_and_a_landing_pad, @function
before_a_trap_and_a_landing_pad:
        call    helper
        ud2
        mov     %rax, %rbx
        call    helper
        ret
        .p2align 4, 0xcc
# The linker's filler that traps: not part of the function.
        .type   before_trapping_filler, @function
before_trapping_filler:
        call    helper
        .p2align 4, 0xcc
# The assembler's filler that does nothing, one long `nop`, up to an aligned
# address nothing jumps to.
        .type   before_filler, @function
before_filler:
        call    helper
        .p2align 4
# False: the `nop` is run, and the loop is the function going on.
        .type   before_a_loop, @function
before_a_loop:
        call    helper
        .p2align 4
1:      dec     %eax
        jne     1b
        ret
        .p2align 4, 0xcc
# False: something jumps past the call, to where the filler ends.
        .type   jumped_past, @function
jumped_past:
        test    %eax, %eax
        je      1f
        call    helper
        .p2align 4
1:      mov     $3, %eax
        ret
        .p2align 4, 0xcc
# False: gcc `-O0` writes `nop` as a statement, twice here, and the next
# statement happens to land on an aligned address.
        .type   statement_nops, @function
statement_nops:
        nop
        call    helper
        nop
        nop
        leave
        ret
        .p2align 4, 0xcc
# False: more of the same, at gcc `-O0`, in a shape long enough to pass for fill.
        .type   three_statement_nops, @function
three_statement_nops:
        call    helper
        nop
        nop
        nop
        leave
        ret
        .p2align 4, 0xcc
# False: an alignment asked for by hand before a hot loop, and the jump back is
# too far off for the window of the graph to see: here there is none to see.
        .p2align 5, 0xcc
        .type   before_a_hand_written_alignment, @function
before_a_hand_written_alignment:
        call    helper
        .p2align 5
        mov     $7, %eax
        ret
        .p2align 4, 0xcc
# False: a call filler follows, in a function that goes on past it. No branch
# lands where the filler ends, and the branch over the call lands further on, as
# in a case of a jump table or a block aligned before a loop. It returns.
        .p2align 4, 0xcc
        .type   filler_with_the_function_going_on, @function
filler_with_the_function_going_on:
        test    %eax, %eax
        je      2f
        call    helper
        .p2align 4
        mov     $8, %eax
2:      ret
        .p2align 4, 0xcc
# False: a breakpoint a person wrote, and the function goes on past it. The
# next address is not aligned, so this is no filler.
        .type   past_a_breakpoint, @function
past_a_breakpoint:
        call    helper
        int3
        mov     $4, %eax
        ret
        .p2align 4, 0xcc
        .type   last_listed, @function
last_listed:
        ret

        .section .data.rel.ro, "aw"
        .p2align 3
.Lslot_named:
        .quad   helper
.Lslot_nameless:
        .quad   .Lnameless
.Lslot_spins:
        .quad   .Lspins
.Lslot_unknown:
        .quad   0
.Lslot_panic:
        .quad   _ZN4core9panicking5panic17h0123456789abcdefE
.Lslot_std:
        .quad   _ZN3std9panicking11panic_count17is_zero_slow_path17h0123456789abcdefE

        .data
        .p2align 3
.Lslot_variable:
        .quad   helper
