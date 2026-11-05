# Two function symbols with a size on 32-bit ARM (`discovery_on_planted_images.rs`;
# rebuilt by `plant.sh`): `in_arm` in A32 code, `in_thumb` in Thumb code. The
# ARM ELF ABI sets bit 0 of a Thumb function's `st_value`, so `readelf` lists
# `in_thumb` one byte past its first instruction.
        .syntax unified
        .text
        .arm
        .globl  in_arm
        .type   in_arm, %function
in_arm:
        mov     r0, #1
        bx      lr
        .size   in_arm, 8
        .thumb
        .globl  in_thumb
        .thumb_func
        .type   in_thumb, %function
in_thumb:
        movs    r0, #2
        bx      lr
        .size   in_thumb, 4
