# `f`: one function the assembler splits into three unwind entries with
# `.seh_splitchained`, each continuation chained to the first.
.intel_syntax noprefix
.text
.p2align 4
.globl f
.def f; .scl 2; .type 32; .endef
.seh_proc f
f:
  push rbx
  .seh_pushreg rbx
  .seh_endprologue
  mov eax, ecx
  .seh_splitchained
  push rsi
  .seh_pushreg rsi
  .seh_endprologue
  add eax, 0x11
  .seh_splitchained
  .seh_endprologue
  add eax, 0x22
  pop rsi
  pop rbx
  ret
.seh_endproc
