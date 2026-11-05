# Tables that lie, written by hand (`discovery_on_planted_images.rs`; rebuilt by
# `plant.sh`): a declared source is a claim, what the table says, never the
# truth. What each function really is is the bytes, 16 bytes each at the offsets
# from `.text` below; the unwind table and the symbols state otherwise.
#
# Lying with nothing to contradict them:
#   alone      +0x00 no symbol. Its FDE states +0x04..+0x14: a start inside it,
#              an end inside the next 16 bytes.
#   real_start +0x40 no FDE. The symbol `wrong_start` states +0x44, size 12: a
#              start inside the function, in the middle of its first instruction.
#   wrong_size +0x50 no FDE. Its symbol's true start, with size 32, which
#              swallows `swallowed` at +0x60, which nothing else declares.
# Lying with a second source that says otherwise:
#   witnessed  +0x20 `.size` 16 states the truth. Its FDE states +0x24..+0x34.
#   contested  +0x70 its FDE states the truth, 16 bytes. Its `.size` states 32.
#
# Hand-written `.eh_frame` because a `.cfi_startproc` region states where the
# assembler is, and could not lie.
        .text
.Lalone:
        mov     $1, %eax
        ret
        .fill   10, 1, 0x90
.Lafter_alone:
        mov     $2, %eax
        ret
        .fill   10, 1, 0x90

        .globl  witnessed
        .type   witnessed, @function
witnessed:
.Lwitnessed:
        mov     $3, %eax
        ret
        .fill   10, 1, 0x90
        .size   witnessed, 16
.Lafter_witnessed:
        mov     $4, %eax
        ret
        .fill   10, 1, 0x90

.Lreal_start:
        mov     $5, %eax
        ret
        .fill   10, 1, 0x90
        .globl  wrong_start
        .type   wrong_start, @function
        .set    wrong_start, .Lreal_start + 4
        .size   wrong_start, 12

        .globl  wrong_size
        .type   wrong_size, @function
wrong_size:
        mov     $6, %eax
        ret
        .fill   10, 1, 0x90
.Lswallowed:
        mov     $7, %eax
        ret
        .fill   10, 1, 0x90
        .size   wrong_size, 32

        .globl  contested
        .type   contested, @function
contested:
.Lcontested:
        mov     $8, %eax
        ret
        .fill   10, 1, 0x90
.Lafter_contested:
        mov     $9, %eax
        ret
        .fill   10, 1, 0x90
        .size   contested, 32

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

        fde     .Lalone + 4, 0x10
        fde     .Lwitnessed + 4, 0x10
        fde     .Lcontested, 0x10
        .long   0
        .section .note.GNU-stack,"",@progbits
