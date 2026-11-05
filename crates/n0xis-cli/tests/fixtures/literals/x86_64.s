# Text with known bounds, and every kind of reference to it, for
# `strings_cut_where_a_length_says.rs`. Each run is its own question. A byte 1
# after a run is a run a NUL does not end; the 0 after that only keeps the next
# run apart from it.
#
# What opens the gate, by which of these the image was assembled with:
#   neither symbol: rustc naming itself in `.comment`;
#   PATH_ONLY: a panic location's path in the text, and no `.comment`;
#   NOT_RUST: neither, and every near miss a C program could hold.

.ifndef PATH_ONLY
.ifndef NOT_RUST
    .section .comment
    .asciz "rustc version 1.99.0 (planted)"
.endif
.endif
.ifdef NOT_RUST
    .section .comment
    .asciz "GCC: (GNU) built beside rustc"
.endif

    .section .rodata
.ifdef PATH_ONLY
    .asciz "%s"
.endif
    .byte 0
data_one_a: .ascii "DATA_ONE_A"
data_one_b: .ascii "DATA_ONE_B"
    .byte 1, 0
# A start alone, in a run a NUL ends: the shape of a merged string tail.
data_two_a: .ascii "DATA_TWO_A"
data_two_b: .ascii "DATA_TWO_B"
    .byte 0
# A start alone, in a run no NUL ends.
data_three_a: .ascii "DATA_THREE"
data_three_b: .ascii "DATA_THR_B"
    .byte 1, 0
# A start and an end at one point, in a run a NUL ends.
data_four_a: .ascii "DATA_FOURA"
data_four_b: .ascii "DATA_FOURB"
    .byte 0
code_one_a: .ascii "CODE_ONE_A"
code_one_b: .ascii "CODE_ONE_B"
    .byte 1, 0
code_two_a: .ascii "CODE_TWO_A"
code_two_b: .ascii "CODE_TWO_B"
    .byte 1, 0
both_a: .ascii "BOTH_AAAAA"
both_b: .ascii "BOTH_BBBBB"
both_c: .ascii "BOTH_CCCCC"
both_d: .ascii "BOTH_DDDDD"
    .byte 1, 0
# `lea` into the first argument register, an immediate in the second: the true
# register pair. Every run here is one no NUL ends, where a length alone cuts.
reg_true_a: .ascii "REG_TRUE"
reg_true_b: .ascii "REG_REST"
    .byte 1, 0
# The false one of real code: the immediate is the third argument, and reads as a
# length of the first's text.
reg_false: .ascii "REG_FALSE_LENGTH"
    .byte 1, 0
# The same, with the immediate moved first.
reg_before: .ascii "REG_FALSE_BEFORE"
    .byte 1, 0
# The pair of the other ABI, which on this one is two unrelated registers.
reg_other_abi: .ascii "REG_OTHER_ABI"
    .byte 1, 0
# A `&str` returned: the address in `rax`, the length in `rdx`, at a `ret`...
ret_true_a: .ascii "RET_TRUE"
ret_true_b: .ascii "RET_REST"
    .byte 1, 0
# ...and with no `ret` after them, the same two registers say nothing...
ret_no_ret: .ascii "RET_NOT_AT_A_RET"
    .byte 1, 0
# ...nor another register at a `ret`.
ret_other: .ascii "RET_OTHER_REGISTER"
    .byte 1, 0
# 2n+1, as `eprintln!` states 20 bytes as `mov esi,0x29`. The second is the one to
# end at the run's end; the first's whole immediate ends there too, and half is taken.
odd_double_a: .ascii "ODD_DOUBLED_ONE"
odd_double_b: .ascii "ODD_DOUBLE_SECND"
    .byte 1, 0
# A true odd length: half of it ends nowhere, all of it where a reference starts.
odd_true_a: .ascii "ODD_TRUE_ELEVEN"
odd_true_b: .ascii "ODD_TRUE_B"
    .byte 1, 0
# An odd immediate that ends at no boundary, whole or halved.
odd_nothing: .ascii "ODD_NOTHING_ANYWHERE"
    .byte 1, 0
# An odd length in data is a length: nothing doubles there.
odd_data_a: .ascii "ODD_DATA_A_"
odd_data_b: .ascii "ODD_DATA_B"
    .byte 1, 0
# Doubled, in the slot beside the pointer's.
odd_slot_a: .ascii "ODD_SLOT_A"
odd_slot_b: .ascii "ODD_SLOT_TWO"
    .byte 1, 0
# strncmp(x, "partial_c_string", 3): a length, on a string a NUL ends.
partial: .ascii "partial_c_string"
    .byte 0
# Lengths that run past the run.
false_one: .ascii "false_length_one"
    .byte 0
false_two: .ascii "false_length_two"
    .byte 1, 0
false_three: .ascii "false_length_six"
    .byte 0
.ifdef PATH_ONLY
    .asciz "/rustc/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4/library/core/src/lib.rs"
.endif
.ifdef NOT_RUST
    .asciz "built by rustc 1.99.0"
    .asciz "/usr/lib/rustc/"
    .asciz "/rustc/b940084d7eb6/library/core/src/lib.rs"
.endif

# At an address the words below can state with no relocation.
    .section .fixed, "a"
    .byte 0
number_a: .ascii "NUMBER_AAA"
number_b: .ascii "NUMBER_BBB"
    .byte 1, 0
immed_a: .ascii "IMMED_AAAA"
immed_b: .ascii "IMMED_BBBB"
    .byte 1, 0
imslot_a: .ascii "IMSLOT_AAA"
imslot_b: .ascii "IMSLOT_BBB"
    .byte 1, 0

    .section .data.rel.ro, "aw"
    .balign 8
data_pairs:
pair_data_one: .quad data_one_a, 10
pair_data_two: .quad data_two_b, 10
pair_data_three: .quad data_three_b, 10
pair_data_four_a: .quad data_four_a, 10
pair_data_four_b: .quad data_four_b, 10
pair_both_b:   .quad both_b, 10
pair_both_d:   .quad both_d, 10
pair_partial:  .quad partial, 3
pair_odd_data: .quad odd_data_a, 11
pair_false_one:   .quad false_one, 1000
pair_false_inner: .quad false_one + 6, 11
pair_false_two:   .quad false_two, 17
pair_false_three: .quad false_three + 4, 0
# Into the middle of the printable instructions below: a table of function
# pointers with a small number beside each is any table of them.
pair_blob:     .quad blob + 4, 4
# Two words a loader never touches: in an image that may load anywhere they are
# numbers, in one that runs where it says they are this pair.
pair_number:   .quad 0x900b, 10

    .text
    .globl _start
_start:
    ret
code_pair_one:
    lea code_one_a(%rip), %rdi
    mov $10, %esi
    ret
code_pair_two:
    lea code_two_b(%rip), %rax
    mov %rax, 8(%rsp)
    movq $10, 16(%rsp)
    ret
code_pair_both_c:
    lea both_c(%rip), %rdi
    mov $10, %esi
    ret
code_pair_both_d:
    lea both_d(%rip), %rdi
    mov $10, %esi
    ret
code_pair_partial:
    lea partial(%rip), %rsi
    mov $3, %edx
    ret
code_pair_reg_true:
    lea reg_true_a(%rip), %rdi
    mov $8, %esi
    ret
code_false_reg:
    lea reg_false(%rip), %rdi
    mov $4, %edx
    ret
code_false_reg_before:
    mov $4, %edx
    lea reg_before(%rip), %rdi
    ret
code_other_abi:
    lea reg_other_abi(%rip), %rcx
    mov $4, %edx
    ret
code_pair_ret_true:
    lea ret_true_a(%rip), %rax
    mov $8, %edx
    add $8, %rsp
    ret
code_ret_no_ret:
    lea ret_no_ret(%rip), %rax
    mov $4, %edx
    jmp code_ret_other
code_ret_other:
    lea ret_other(%rip), %rax
    mov $4, %ecx
    ret
code_pair_odd_double_a:
    lea odd_double_a(%rip), %rdi
    mov $31, %esi
    ret
code_pair_odd_double_b:
    lea odd_double_b(%rip), %rdi
    mov $33, %esi
    ret
code_pair_odd_true_a:
    lea odd_true_a(%rip), %rdi
    mov $15, %esi
    ret
code_pair_odd_true_b:
    lea odd_true_b(%rip), %rdi
    mov $10, %esi
    ret
code_odd_nothing:
    lea odd_nothing(%rip), %rdi
    mov $9, %esi
    ret
code_pair_odd_slot_a:
    lea odd_slot_a(%rip), %rax
    mov %rax, 8(%rsp)
    movq $21, 16(%rsp)
    ret
code_pair_odd_slot_b:
    lea odd_slot_b(%rip), %rdi
    mov $25, %esi
    ret
code_false_length:
    lea false_three(%rip), %rdi
    mov $17, %esi
    ret
# Immediates equal to where `.fixed` puts two literals: addresses in an image that
# runs where it says, numbers in one that may load anywhere.
code_immediate:
    mov $0x9021, %edi
    mov $10, %esi
    ret
code_immediate_slot:
    movq $0x9037, 8(%rsp)
    movq $10, 16(%rsp)
    ret
# Each byte a one-byte instruction, and printable.
blob:
    .ascii "PQRSVWXYZ[^_PQRS"
    ret
