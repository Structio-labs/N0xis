# An AArch64 function built with return-address signing, which nothing but its
# entry pattern can find (`discovery_on_planted_images.rs`; rebuilt by
# `plant.sh`): no symbol, no FDE, no call to it. It begins with `paciasp`, and
# its `stp x29, x30, [sp, #-16]!` is one word later; the function starts at
# the `paciasp`, `.text` + 0.
        .text
        .p2align 4
.Lsigned:
        paciasp
        stp     x29, x30, [sp, #-16]!
        mov     x29, sp
        mov     w0, #7
        ldp     x29, x30, [sp], #16
        autiasp
        ret

# A function that tests before it sets up its frame: the `stp` after the `cbz`
# matches the entry pattern, and the `cbz` runs on into it, so it is no function.
# Its start is `.text` + 0x20, an `stp` after the `nop` that aligns it; the one
# after the `cbz` is `.text` + 0x2c.
        .p2align 4
.Lframed:
        stp     x29, x30, [sp, #-16]!
        ldp     x29, x30, [sp], #16
        cbz     x0, 1f
        stp     x29, x30, [sp, #-16]!
        ldp     x29, x30, [sp], #16
1:      ret

        .section .note.GNU-stack,"",@progbits
