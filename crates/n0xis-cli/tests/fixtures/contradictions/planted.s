# Each kind of contradiction `n0x contradictions` reports, planted once.
# The unwind table is written out by hand, so each FDE states exactly the
# range planted here, and two of them can overlap (a `.cfi_startproc` region
# cannot reach into another).
#
#   end      `ends_twice`: `.size` states 8 bytes, its FDE 16.
#   overlap  `outer`'s FDE covers 16 bytes, and `inner` starts 8 bytes in,
#            with an FDE and a size of its own. `outer` states no size.
#   name     one address, `.dynsym` naming it `exported_name` and `.symtab`
#            `symtab_name` (build.sh strips `exported_name` from `.symtab`).
        .text
        .p2align 4
        .globl  ends_twice
        .type   ends_twice, @function
ends_twice:
.Lends_twice:
        xor     %eax, %eax
        ret
        .fill   13, 1, 0x90
        .size   ends_twice, 8

        .globl  outer
        .type   outer, @function
outer:
.Louter:
        xor     %eax, %eax
        .fill   6, 1, 0x90
        .globl  inner
        .type   inner, @function
inner:
.Linner:
        mov     $1, %eax
        ret
        .fill   2, 1, 0x90
        .size   inner, 8

        .globl  exported_name
        .type   exported_name, @function
        .type   symtab_name, @function
exported_name:
.Lexported_name:
symtab_name:
        mov     $2, %eax
        ret
        .fill   10, 1, 0x90
        .size   exported_name, 16
        .size   symtab_name, 16

        .section .eh_frame,"a",@progbits
.Lcie:
        .long   .Lcie_end - .Lcie_id        # length
.Lcie_id:
        .long   0                       # CIE id
        .byte   1                       # version
        .asciz  "zR"                    # augmentation
        .uleb128 1                      # code alignment
        .sleb128 -8                     # data alignment
        .uleb128 16                     # return address register
        .uleb128 1                      # augmentation data length
        .byte   0x1b                    # FDE pointers: pcrel sdata4
        .byte   0x0c, 7, 8              # DW_CFA_def_cfa rsp+8
        .byte   0x90, 1                 # DW_CFA_offset rip, cfa-8
        .p2align 3
.Lcie_end:

        .macro  fde start, len
1:
        .long   3f - 2f                 # length
2:
        .long   2b - .Lcie                # CIE pointer
        .long   \start - .              # pc_begin
        .long   \len                    # pc_range
        .uleb128 0                      # augmentation data length
        .p2align 3
3:
        .endm

        fde     .Lends_twice, 16
        fde     .Louter, 16
        fde     .Linner, 8
        fde     .Lexported_name, 16
        .long   0                       # terminator
        .section .note.GNU-stack,"",@progbits
