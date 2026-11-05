# i386 function starts planted between the two shapes discovery misread
# (`discovery_on_planted_images.rs`; rebuilt by `plant.sh`). Each function is
# at the offset from `.text` below, and the bytes between are the padding GNU as
# writes on i386 (the `lea` of a register to itself), spelled out byte by byte
# so the assembler cannot choose another.
#
#   f1     +0x00  an FDE; calls f3 and f4. Ends at +0x0f, then 17 bytes of
#                 `lea` padding: the next function is f2, not the `lea`.
#   f2     +0x20  nothing declares it: found after f1's declared end (and by
#                 the sweep of the gap between f1 and f6).
#   f3     +0x30  reached by f1's call; reads its own address with
#                 `call 1f; 1: pop %ebx`. The `pop` at +0x36 is no function.
#   thunk  +0x40  gcc's form of the same idiom, a real function: called from f4.
#   f4     +0x50  reached by f1's call; ends in a call to f5, which the
#                 linker placed right after it.
#   f5     +0x5a  a real function whose caller's call is to the next
#                 instruction (as a call to a `noreturn` function laid out next
#                 is): it begins with `push`, not `pop`.
#   f6     +0x60  an FDE, so f1..f6 is a gap the sweep walks.
        .text
.Lf1:
        .cfi_startproc
        push    %ebp
        mov     %esp, %ebp
        call    .Lf3
        call    .Lf4
        pop     %ebp
        ret
        .cfi_endproc
        .byte   0x2e, 0x8d, 0xb4, 0x26, 0, 0, 0, 0      # lea %cs:0x0(%esi,%eiz,1),%esi
        .byte   0x8d, 0xb6, 0, 0, 0, 0                  # lea 0x0(%esi),%esi
        .byte   0x8d, 0x76, 0x00                        # lea 0x0(%esi),%esi

.Lf2:
        mov     4(%esp), %eax
        ret
        .byte   0x2e, 0x8d, 0xb4, 0x26, 0, 0, 0, 0      # lea %cs:0x0(%esi,%eiz,1),%esi
        .byte   0x8d, 0x76, 0x00                        # lea 0x0(%esi),%esi

.Lf3:
        push    %ebx
        call    1f
1:      pop     %ebx
        mov     %ebx, %eax
        pop     %ebx
        ret
        .byte   0x8d, 0x74, 0x26, 0x00                  # lea 0x0(%esi,%eiz,1),%esi
        .byte   0x90

.Lthunk:
        mov     (%esp), %ebx
        ret
        .byte   0x8d, 0xb4, 0x26, 0, 0, 0, 0            # lea 0x0(%esi,%eiz,1),%esi
        .byte   0x8d, 0x74, 0x26, 0x00                  # lea 0x0(%esi,%eiz,1),%esi
        .byte   0x90

.Lf4:
        call    .Lthunk
        call    .Lf5
.Lf5:
        push    %ebp
        mov     %esp, %ebp
        pop     %ebp
        ret
        .byte   0x90

.Lf6:
        .cfi_startproc
        xor     %eax, %eax
        ret
        .cfi_endproc

        .section .note.GNU-stack,"",@progbits
