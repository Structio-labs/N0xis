# The rules' edges, x86-64 (`discovery_on_planted_images.rs`; rebuilt by
# `plant.sh`). Offsets from `.text`:
#
#   head    +0x00  first in the section, before the first declared function: the
#                  section's start brackets the gap as a declared end does.
#   second  +0x10  after `head`'s `ret` and filler.
#   f1      +0x20  an FDE.
#   inner   +0x30  nothing declares it. Inside it, `jmp 1f; nop; 1: nop; leave;
#                  ret`: the branch lands in the filler, so `leave` at +0x36 is
#                  the same function going on, as gcc `-O0` writes it.
#   f2      +0x40  an FDE.
#   framed  +0x50  no FDE, no call. `push %rbx`, then `sub $8,%rsp` exactly on
#                  a 16-byte boundary at +0x60: the entry pattern matches
#                  there, and `push` runs on into it, so it is no function.
#   tail    +0x70  a function after `framed`'s `ret` and filler whose first
#                  instruction is the same pattern: an entry.
        .text
.Lhead:
        xor     %eax, %eax
        ret
        .fill   13, 1, 0x90
.Lsecond:
        mov     $1, %eax
        ret
        .fill   10, 1, 0x90
.Lf1:
        .cfi_startproc
        xor     %eax, %eax
        ret
        .cfi_endproc
        .fill   13, 1, 0x90
.Linner:
        xor     %eax, %eax
        jmp     1f
        nop
1:      nop
        .byte   0xc9                    # leave, at +0x36
        ret
        .fill   8, 1, 0x90
.Lf2:
        .cfi_startproc
        xor     %eax, %eax
        ret
        .cfi_endproc
        .fill   13, 1, 0x90
.Lframed:
        xor     %eax, %eax
        .fill   13, 1, 0x90
        push    %rbx
        sub     $8, %rsp
        add     $8, %rsp
        pop     %rbx
        ret
        .fill   6, 1, 0x90
.Ltail:
        sub     $8, %rsp
        add     $8, %rsp
        ret

        .section .note.GNU-stack,"",@progbits
