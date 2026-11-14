# Two functions whose jump tables lie back to back in .rodata (tests/whole_program_reads_tables_as_ir_build.rs).
# fa's table has 8 entries and no guard of its index; fb's 4 follow it at once, and only fb's code names them.
# Built: gcc -shared -nostdlib -Wl,--build-id=none -o tables.so tables.s
    .intel_syntax noprefix
    .text
    .globl fa
    .type fa, @function
fa:
    .cfi_startproc
    mov eax, edi
    lea rdx, [rip + .Lta]
    movsxd rax, dword ptr [rdx + rax*4]
    add rax, rdx
    jmp rax
.La0: mov eax, 10
    ret
.La1: mov eax, 11
    ret
.La2: mov eax, 12
    ret
.La3: mov eax, 13
    ret
.La4: mov eax, 14
    ret
.La5: mov eax, 15
    ret
.La6: mov eax, 16
    ret
.La7: mov eax, 17
    ret
    .cfi_endproc
    .size fa, . - fa

    .globl fb
    .type fb, @function
fb:
    .cfi_startproc
    jmp .Lbd
.Lb0: ret
.Lb1: ret
.Lb2: ret
.Lb3: ret
.Lbd:
    cmp edi, 3
    ja .Lb0
    mov eax, edi
    lea rdx, [rip + .Ltb]
    movsxd rax, dword ptr [rdx + rax*4]
    add rax, rdx
    jmp rax
    .cfi_endproc
    .size fb, . - fb

    .section .rodata
    .p2align 2
.Lta:
    .long .La0 - .Lta, .La1 - .Lta, .La2 - .Lta, .La3 - .Lta, .La4 - .Lta, .La5 - .Lta, .La6 - .Lta, .La7 - .Lta
.Ltb:
    .long .Lb0 - .Ltb, .Lb1 - .Ltb, .Lb2 - .Ltb, .Lb3 - .Ltb
    .section .note.GNU-stack, "", @progbits
