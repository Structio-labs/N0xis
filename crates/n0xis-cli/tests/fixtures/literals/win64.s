# The register pairs of x86_64.s under Win64, whose order is rcx, rdx, r8, r9.
    .section .rdata, "dr"
    .byte 0
reg_true_a: .ascii "REG_TRUE"
reg_true_b: .ascii "REG_REST"
    .byte 1, 0
# The immediate is the third argument.
reg_false: .ascii "REG_FALSE_LENGTH"
    .byte 1, 0
# The pair of the other ABI, which on this one is two unrelated registers.
reg_other_abi: .ascii "REG_OTHER_ABI"
    .byte 1, 0

    .text
    .globl _start
_start:
    ret
code_pair_reg_true:
    lea reg_true_a(%rip), %rcx
    mov $8, %edx
    ret
code_false_reg:
    lea reg_false(%rip), %rcx
    mov $4, %r8d
    ret
code_other_abi:
    lea reg_other_abi(%rip), %rdi
    mov $4, %esi
    ret
