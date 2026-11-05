# Function starts planted where exactly one rule, or none, can find each
# (`discovery_on_planted_images.rs`; rebuilt by `plant.sh`, which records what
# readelf and objdump say the built file holds).
#
#   sym_only     a function only its symbol declares: global, `.size` 6, no
#                FDE, no call to it, no prologue pattern, first in `.text`
#                (nothing ends before it). In `.symtab` and `.dynsym`.
#   zero_size    a global function symbol with no `.size`: no extent, so no
#                declared start; it follows `sym_only`'s declared end.
#   in_data      a function symbol with a size, in `.data`: not code.
#   caller       an FDE of its own; calls `ext` through the PLT (so the linker
#                writes `.plt` and an FDE over it) and calls `big`.
#   big          no symbol size and no FDE, found by the call; 1 700 `add`s
#                and a `ret`, 5 101 bytes: no end in the 4 KiB window the
#                graph of an undeclared start is built in.
        .text
        .globl  sym_only
        .type   sym_only, @function
sym_only:
        mov     $1, %eax
        ret
        .size   sym_only, 6
        .fill   2, 1, 0x90

        .globl  zero_size
        .type   zero_size, @function
zero_size:
        mov     $2, %eax
        ret
        .fill   2, 1, 0x90

        .globl  caller
        .type   caller, @function
caller:
        .cfi_startproc
        sub     $8, %rsp
        .cfi_def_cfa_offset 16
        call    ext@PLT
        call    big
        add     $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
        .size   caller, .-caller
        .fill   2, 1, 0x90

big:
        .rept   1700
        add     $1, %eax
        .endr
        ret

        .data
        .globl  in_data
        .type   in_data, @function
in_data:
        .long   0
        .size   in_data, 4

        .section .note.GNU-stack,"",@progbits
