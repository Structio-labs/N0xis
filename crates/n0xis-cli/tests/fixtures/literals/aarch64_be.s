# The data pairs of x86_64.s in big-endian words.
    .section .rodata
    .byte 0
data_one_a: .ascii "DATA_ONE_A"
data_one_b: .ascii "DATA_ONE_B"
    .byte 1, 0
data_two_a: .ascii "DATA_TWO_A"
data_two_b: .ascii "DATA_TWO_B"
    .byte 0
partial: .ascii "partial_c_string"
    .byte 0
false_one: .ascii "false_length_one"
    .byte 0

    .section .data.rel.ro, "aw"
    .balign 8
pair_data_one: .xword data_one_a, 10
pair_data_two: .xword data_two_b, 10
pair_partial:  .xword partial, 3
pair_false_one: .xword false_one, 1000

    .text
    .globl _start
_start:
    ret
