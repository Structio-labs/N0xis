# One table disagreeing with itself, planted once: `twice` has two FDEs, of
# 16 and 8 bytes, and two symbols, `twice` of 16 bytes and `twice_alias` of
# 12. Three different ends for one start, from two tables each stating two.
        .text
        .p2align 4
        .globl  twice
        .type   twice, @function
        .globl  twice_alias
        .type   twice_alias, @function
twice:
twice_alias:
.Ltwice:
        xor     %eax, %eax
        ret
        .fill   13, 1, 0x90
        .size   twice, 16
        .size   twice_alias, 12

        .section .eh_frame,"a",@progbits
.Lcie:
        .long   .Lcie_end - .Lcie_id
.Lcie_id:
        .long   0
        .byte   1
        .asciz  "zR"
        .uleb128 1
        .sleb128 -8
        .uleb128 16
        .uleb128 1
        .byte   0x1b
        .byte   0x0c, 7, 8
        .byte   0x90, 1
        .p2align 3
.Lcie_end:

        .macro  fde start, len
1:
        .long   3f - 2f
2:
        .long   2b - .Lcie
        .long   \start - .
        .long   \len
        .uleb128 0
        .p2align 3
3:
        .endm

        fde     .Ltwice, 16
        fde     .Ltwice, 8
        .long   0
        .section .note.GNU-stack,"",@progbits
