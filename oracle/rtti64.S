/* Copyright (c) 2026 Tymofii Kosovskyi
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 *
 * Shape: PE32+ carrying hand-built **64-bit** MSVC RTTI — the other dialect.
 *
 * Written in assembler, not C, for one reason: the 64-bit
 * CompleteObjectLocator stores **image-relative RVAs**, and C has no way to
 * write `&thing - image_base` in a static initializer (the compiler refuses it
 * as non-constant). GNU as for PE has the directive for exactly this — `.rva`.
 *
 * The 64-bit dialect, beside `rtti32.c`'s:
 *   TypeDescriptor { void *vftable; void *spare; char name[]; }   name at +16
 *   CompleteObjectLocator { u32 signature=1; u32 offset; u32 cdOffset;
 *                           rva pTypeDescriptor;   <- RVA, not an absolute VA
 *                           rva pClassDescriptor;
 *                           rva pSelf; }                          24 bytes
 *
 * `pSelf` is what makes the 64-bit form self-validating: the locator points at
 * itself, so a random run of bytes almost never passes. The 32-bit form has no
 * such field, which is why its scan leans on the signature word and the `.?A`
 * name instead.
 */
    .text
    .globl planted_method
planted_method:
    movl $42, %eax
    ret

    .section .rdata,"dr"
    .balign 8
planted_td:
    .quad 0                     /* vftable */
    .quad 0                     /* spare   */
    .asciz ".?AVPlanted64@@"    /* name, at +16 */

    .balign 8
planted_col:
    .long 1                     /* signature: 1 = the 64-bit dialect */
    .long 0                     /* offset    */
    .long 0                     /* cdOffset  */
    .rva planted_td             /* pTypeDescriptor */
    .long 0                     /* pClassDescriptor: none, so no base classes */
    .rva planted_col            /* pSelf — the self-reference */

    /* The COL pointer sits immediately before the vtable, and the vtable's
     * first slot must land in `.text` or the scanner rightly refuses it. */
    .balign 8
    .quad planted_col
    .globl planted_vtable
planted_vtable:
    .quad planted_method
    .quad 0
