// One unwind table, planted so each field a byte-order mistake would change
// has a value only the right order reads (plant.sh assembles it twice: for
// aarch64_be and for aarch64, the little-endian twin).
//
//   plain        an FDE, no LSDA.
//   guarded      an FDE whose CIE carries `zPLR` and whose LSDA is written out
//                by hand below with a `udata4` (0x03) call-site table — so the
//                call sites are fixed-size fields in the image's order, which
//                a compiler's `uleb128` table would not exercise. Two entries:
//                [try_begin, try_end) lands at `catch_here`; [unguarded_begin,
//                unguarded_end) has no landing pad (0) and is no edge.
//   personality  an FDE, no LSDA; the routine `guarded`'s CIE names.
//
// The labels are local symbols, so `readelf -sW` (recorded beside the images)
// lists the addresses the answer must hold.
        .text
        .p2align 4
        .globl  plain
        .type   plain, %function
plain:
        .cfi_startproc
        mov     w0, #1
        ret
        .cfi_endproc
        .size   plain, .-plain

        .p2align 4
        .globl  guarded
        .type   guarded, %function
guarded:
        .cfi_startproc
        .cfi_personality 0x1b, personality
        .cfi_lsda 0x1b, .Llsda
        stp     x29, x30, [sp, #-16]!
        .cfi_def_cfa_offset 16
        .cfi_offset w30, -8
        .cfi_offset w29, -16
try_begin:
        bl      plain
        bl      plain
try_end:
unguarded_begin:
        bl      plain
unguarded_end:
        ldp     x29, x30, [sp], #16
        ret
catch_here:
        mov     w0, #2
        ldp     x29, x30, [sp], #16
        ret
        .cfi_endproc
        .size   guarded, .-guarded

        .p2align 4
        .type   personality, %function
personality:
        .cfi_startproc
        mov     w0, #0
        ret
        .cfi_endproc
        .size   personality, .-personality

        .section .gcc_except_table,"a",%progbits
        .p2align 2
.Llsda:
        .byte   0xff
        .byte   0xff
        .byte   0x03
        .uleb128 .Lcs_end - .Lcs_start
.Lcs_start:
        .long   try_begin - guarded
        .long   try_end - try_begin
        .long   catch_here - guarded
        .uleb128 0
        .long   unguarded_begin - guarded
        .long   unguarded_end - unguarded_begin
        .long   0
        .uleb128 0
.Lcs_end:
