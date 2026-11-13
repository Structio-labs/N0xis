# `g`: one function in three unwind entries written out by hand, so that one
# continuation is contiguous with the first entry and the other lies past a
# function of its own, `h`, and chains through the first continuation (a chain
# nested once). `h` is one entry with no chain.
.intel_syntax noprefix
.text
.p2align 4
.globl g
.def g; .scl 2; .type 32; .endef
g:
  push rbx
  sub rsp, 0x20
  mov ebx, ecx
g_part:
  test ebx, ebx
  js g_far
  lea eax, [rbx + 7]
g_back:
  add rsp, 0x20
  pop rbx
  ret
g_part_end:
.p2align 4, 0xcc
.globl h
.def h; .scl 2; .type 32; .endef
h:
  push rbx
  lea eax, [rcx + 3]
  pop rbx
  ret
h_end:
.p2align 4, 0xcc
g_far:
  call h
  mov eax, 0x1234
  jmp g_back
g_far_end:

.section .xdata,"dr"
.p2align 2
g_unwind:
  .byte 0x01, 5, 2, 0          # version 1, no flags; prolog 5 bytes; 2 codes
  .byte 5, 0x32                # at 5: UWOP_ALLOC_SMALL, (3 + 1) * 8 = 0x20
  .byte 1, 0x30                # at 1: UWOP_PUSH_NONVOL rbx
.p2align 2
g_part_unwind:
  .byte 0x21, 0, 0, 0          # version 1, UNW_FLAG_CHAININFO; no codes
  .rva g, g_part, g_unwind     # chained to the first entry
.p2align 2
g_far_unwind:
  .byte 0x21, 0, 0, 0
  .rva g_part, g_part_end, g_part_unwind   # chained to the continuation
.p2align 2
h_unwind:
  .byte 0x01, 1, 1, 0
  .byte 1, 0x30, 0, 0          # at 1: UWOP_PUSH_NONVOL rbx; padded to even

.section .pdata,"dr"
.p2align 2
  .rva g, g_part, g_unwind
  .rva g_part, g_part_end, g_part_unwind
  .rva h, h_end, h_unwind
  .rva g_far, g_far_end, g_far_unwind
