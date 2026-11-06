# The gap sweep's jump rules, one frame each, x86-64 (`discovery_on_planted_images.rs`;
# rebuilt by `plant.sh`). A frame is 0x100 bytes of `.text` beginning with a
# function its FDE declares, so what follows it up to the next frame is a gap
# of its own and nothing but the rule under test speaks in it. `.Lend`, the last
# frame, lies past every gap: a jump there leaves whichever gap it is in. The
# addresses below are offsets from `.text`.
        .macro  frame n
        .org    \n * 0x100, 0x90
        .cfi_startproc
        xor     %eax, %eax
        ret
        .cfi_endproc
        .p2align 4, 0x90
        .endm
        # A small function: ret, then filler up to the next 16 bytes.
        .macro  leaf
        mov     $1, %eax
        ret
        .p2align 4, 0x90
        .endm
        # A dispatch through a table of 32-bit offsets, its bound `n`, with the
        # default past the gap so its `ja` says nothing about this gap.
        .macro  dispatch n, table
        cmp     $\n, %edi
        ja      .Lend
        lea     \table(%rip), %rdx
        movslq  (%rdx,%rdi,4), %rax
        add     %rdx, %rax
        jmp     *%rax
        .p2align 4, 0x90
        .endm

        .text
.Ltext:
        frame   0
# Rule A. A jump past the gap's end, direct or conditional, silences nothing.
        frame   1               # starts 0x110 0x120 0x130 0x140
        mov     $1, %eax        # 0x110
        jmp     .Lend
        .p2align 4, 0x90
        leaf                    # 0x120
        test    %edi, %edi      # 0x130
        jne     .Lend
        mov     $1, %eax
        ret
        .p2align 4, 0x90
        leaf                    # 0x140
# What A must not do: a jump inside the gap keeps covering what it jumps over.
        frame   2               # starts 0x210 0x240
        mov     $1, %eax        # 0x210
        jmp     1f
        .p2align 4, 0x90
        leaf                    # 0x220, jumped over
1:      leaf                    # 0x230, the jump's target
        leaf                    # 0x240
# Rule C. After a jump past the gap's end, code that is not aligned goes on.
        frame   3               # starts 0x310 0x330
        mov     $1, %eax        # 0x310
        jmp     .Lend
        mov     $2, %eax        # 0x31a
        mov     $2, %eax
        ret
        .p2align 4, 0x90
        leaf                    # 0x330
# What C must not do: ask alignment anywhere else, after a return and filler
# (0x417) or after a jump backwards (0x437).
        frame   4               # starts 0x410 0x417 0x420 0x430 0x437
        mov     $1, %eax        # 0x410
        ret
        nop
        mov     $1, %eax        # 0x417
        ret
        .p2align 4, 0x90
        leaf                    # 0x420
1:      mov     $1, %eax        # 0x430
        jmp     1b
        mov     $1, %eax        # 0x437
        ret
        .p2align 4, 0x90
# Rule E. A table's cases go on, each after filler where nothing else would
# stop them; 0x540 between them is no case and is a function (the cases are
# exact targets, they cover nothing), and so is 0x570 after the last.
        frame   5               # starts 0x510 0x540 0x570
        dispatch 2, .Ltable5    # 0x510
.Lcase50:
        leaf                    # 0x530
        leaf                    # 0x540
.Lcase51:
        leaf                    # 0x550
.Lcase52:
        leaf                    # 0x560
        leaf                    # 0x570
# E, a case before its dispatch, listed when the walk passed it.
        frame   6               # starts 0x610 0x630 0x660
        leaf                    # 0x610
.Lcase60:
        leaf                    # 0x620
        dispatch 1, .Ltable6    # 0x630
.Lcase61:
        leaf                    # 0x650
        leaf                    # 0x660
# What E must not do: read a table with a case something calls as one function.
# 0x740 is a call target in any case; 0x730 is listed only by the sweep.
        frame   7               # starts 0x710 0x730 0x740 0x750
        dispatch 1, .Ltable7    # 0x710
.Lcase70:
        leaf                    # 0x730
.Lcase71:
        leaf                    # 0x740
        leaf                    # 0x750
# What E must not do: trust a table with no bound; how far it goes is a probe.
        frame   8               # starts 0x810 0x830 0x840 0x850
        lea     .Ltable8(%rip), %rdx
        movslq  (%rdx,%rdi,4), %rax
        add     %rdx, %rax
        jmp     *%rax
        nop
        .p2align 4, 0x90
.Lcase80:
        leaf                    # 0x830
.Lcase81:
        leaf                    # 0x840
        leaf                    # 0x850
# Rule F. A conditional branch back joins what it spans: to the `ret` at 0x915,
# so the starts at 0x920 and 0x930 go and 0x910 stays.
        frame   9               # starts 0x910 0x940
        mov     $1, %eax        # 0x910
1:      ret
        .p2align 4, 0x90
        leaf                    # 0x920
        dec     %edi            # 0x930
        jne     1b
        mov     $1, %eax
        ret
        .p2align 4, 0x90
        leaf                    # 0x940
# F, to a start: that start goes too.
        frame   10              # starts 0xa10 0xa40
        leaf                    # 0xa10
1:      leaf                    # 0xa20
        dec     %edi            # 0xa30
        jne     1b
        ret
        .p2align 4, 0x90
        leaf                    # 0xa40
# What F must not do: take an unconditional jump back, which a tail call is too.
        frame   11              # starts 0xb10 0xb20 0xb30 0xb40
        mov     $1, %eax        # 0xb10
1:      ret
        .p2align 4, 0x90
        leaf                    # 0xb20
        mov     $1, %eax        # 0xb30
        jmp     1b
        .p2align 4, 0x90
        leaf                    # 0xb40
# What F must not do: join across a call target, a function of its own.
        frame   12              # starts 0xc10 0xc20 0xc30 0xc40 0xc50
        leaf                    # 0xc10
.Lcalled12:
        leaf                    # 0xc20
        leaf                    # 0xc30
        dec     %edi            # 0xc40
        jne     .Lcalled12
        mov     $1, %eax
        ret
        .p2align 4, 0x90
        leaf                    # 0xc50
# A branch to itself, conditional and not, spans nothing. The first measurement
# of F panicked on one, on a range that began past its end.
        frame   13              # starts 0xd10 0xd20 0xd30 0xd40
        leaf                    # 0xd10
1:      jne     1b              # 0xd20
        mov     $1, %eax
        ret
        .p2align 4, 0x90
1:      jmp     1b              # 0xd30
        .p2align 4, 0x90
        leaf                    # 0xd40
# Rule H. Code no entry could be: reads a callee-saved register it never wrote
# (0xe20), gives back stack it never took (0xe30, 0xe40, 0xe50). What it must
# not do: refuse a register saved and then set (0xe60), one cleared (0xe70), a
# volatile one (0xe80), or one read only to be changed in place (0xe90).
        frame   14              # starts 0xe10 0xe60 0xe70 0xe80 0xe90
        leaf                    # 0xe10
        mov     %rbx, %rax      # 0xe20
        ret
        .p2align 4, 0x90
        pop     %rbx            # 0xe30
        ret
        .p2align 4, 0x90
        add     $8, %rsp        # 0xe40
        ret
        .p2align 4, 0x90
        leave                   # 0xe50
        ret
        .p2align 4, 0x90
        push    %rbx            # 0xe60
        mov     %rdi, %rbx
        mov     %rbx, %rax
        pop     %rbx
        ret
        .p2align 4, 0x90
        xor     %ebx, %ebx      # 0xe70
        mov     %ebx, %eax
        ret
        .p2align 4, 0x90
        mov     %rdi, %rax      # 0xe80
        ret
        .p2align 4, 0x90
        inc     %ebx            # 0xe90
        mov     %ebx, %eax
        ret
        .p2align 4, 0x90
# Rule I. After a jump through a register nothing explains, what follows at once
# is the same dispatch, through its own direct jumps too (0xf17, 0xf1e). Filler
# ends it: 0xf50 straight after one, as much as 0xf30 after a `ret`.
        frame   15              # starts 0xf10 0xf30 0xf40 0xf50
1:      mov     $1, %eax        # 0xf10
        jmp     *%rax
        mov     $2, %eax        # 0xf17
        jmp     1b
        mov     $3, %eax        # 0xf1e
        ret
        .p2align 4, 0x90
        leaf                    # 0xf30
        mov     $1, %eax        # 0xf40
        jmp     *%rax
        .p2align 4, 0x90
        leaf                    # 0xf50
# What I must not do: go on past a call target (0x1017), after which a jump arms
# the sweep again (0x101e).
        frame   16              # starts 0x1010 0x1017 0x101e 0x1030
1:      mov     $1, %eax        # 0x1010
        jmp     *%rax
.Lcalled16:
        mov     $2, %eax        # 0x1017
        jmp     1b
        mov     $3, %eax        # 0x101e
        ret
        .p2align 4, 0x90
        leaf                    # 0x1030
# What I must not do: read a row of thunks through memory as a dispatch, or a
# jump through the stack (0x1122), after which 0x1126 is a start.
        frame   17              # starts 0x1110 0x1116 0x111c 0x1122 0x1126 0x1130
        jmp     *.Lslot(%rip)   # 0x1110
        jmp     *.Lslot(%rip)   # 0x1116
        jmp     *.Lslot(%rip)   # 0x111c
        jmp     *8(%rsp)        # 0x1122
        mov     $1, %eax        # 0x1126
        ret
        .p2align 4, 0x90
        leaf                    # 0x1130
        .org    0x1200, 0x90
.Lend:
        .cfi_startproc
        call    .Lcase71
        call    .Lcalled12
        call    .Lcalled16
        ret
        .cfi_endproc

        .section .rodata
        .p2align 2
.Ltable5:
        .long   .Lcase50 - .Ltable5, .Lcase51 - .Ltable5, .Lcase52 - .Ltable5
.Ltable6:
        .long   .Lcase60 - .Ltable6, .Lcase61 - .Ltable6
.Ltable7:
        .long   .Lcase70 - .Ltable7, .Lcase71 - .Ltable7
.Ltable8:
        .long   .Lcase80 - .Ltable8, .Lcase81 - .Ltable8
        # Where a probe of the table with no bound stops: no code is this far.
        .long   0x7fffffff, 0x7fffffff
        .data
.Lslot:
        .quad   0

        .section .note.GNU-stack,"",@progbits
