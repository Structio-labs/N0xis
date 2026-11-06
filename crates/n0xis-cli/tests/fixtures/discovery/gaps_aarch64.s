# The gap sweep on an architecture whose `detect_switch` recognizes nothing
# (`discovery_on_planted_images.rs`; rebuilt by `plant.sh`). Frames as in
# `gaps.s`, one per x86-64 rule that does not hold here, each answered as it was
# before those rules existed, and two for the one rule that does: the sweep steps
# by the instruction set's word, so it does not read inside one.
        .macro  frame n
        .org    \n * 0x100, 0
        .cfi_startproc
        mov     w0, #0
        ret
        .cfi_endproc
        .p2align 4
        .endm
        .macro  leaf
        mov     w0, #1
        ret
        .p2align 4
        .endm

        .text
        frame   0
# A jump past the gap's end covers the gap, as it did: no rule A here.
        frame   1  // starts 0x110
        mov     w0, #1  // 0x110
        b       .Lend
        .p2align 4
        leaf  // 0x120
        leaf  // 0x130
# A conditional branch back joins nothing: no rule F.
        frame   2  // starts 0x210 0x220 0x230 0x240
        mov     w0, #1  // 0x210
1:      ret
        .p2align 4
        leaf  // 0x220
        subs    w0, w0, #1  // 0x230
        b.ne    1b
        ret
        .p2align 4
        leaf  // 0x240
# A callee-saved register read at once is no evidence: no rule H.
        frame   3  // starts 0x310 0x320 0x330
        leaf  // 0x310
        mov     x0, x19  // 0x320
        ret
        .p2align 4
        leaf  // 0x330
# What follows an indirect jump arms as it did: no rule I.
        frame   4  // starts 0x410 0x418 0x420 0x430
1:      mov     w0, #1  // 0x410
        br      x0
        mov     w0, #2  // 0x418
        b       1b
        mov     w0, #3  // 0x420
        ret
        .p2align 4
        leaf  // 0x430
# Rule B. Armed, then a zero word, then `movz x0, #0`, whose first two bytes are
# zero too: a byte-wise step left the word at 0x522.
        frame   5  // starts 0x510 0x520 0x530
        mov     w0, #1  // 0x510
        ret
        nop
        .word   0  // 0x51c
        movz    x0, #0  // 0x520
        ret
        .p2align 4
        leaf  // 0x530
# B, a word that does not decode.
        frame   6  // starts 0x610 0x620 0x630
        mov     w0, #1  // 0x610
        ret
        nop
        .word   0xffffffff  // 0x61c
        mov     w0, #2  // 0x620
        ret
        .p2align 4
        leaf  // 0x630
        .org    0x700, 0
.Lend:
        .cfi_startproc
        mov     w0, #9
        ret
        .cfi_endproc

        .section .note.GNU-stack,"",@progbits
