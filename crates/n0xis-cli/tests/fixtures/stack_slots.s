# Four functions whose stack slots are known before any tool is asked: the
# loads below are the whole of each body, so the slots are exactly these.
# Built with: cc -shared -nostdlib -o stack_slots.so stack_slots.s
# Addresses (nm): both_slots 0x1000, below_only 0x100b, above_only 0x1011,
# other_slot 0x1017.
	.intel_syntax noprefix
	.text

# rsp+8 and rsp-8: under the earlier naming both were `local_8`.
	.globl both_slots
	.type both_slots, @function
both_slots:
	mov rax, QWORD PTR [rsp+8]
	add rax, QWORD PTR [rsp-8]
	ret
	.size both_slots, .-both_slots

# rsp-8 only.
	.globl below_only
	.type below_only, @function
below_only:
	mov rax, QWORD PTR [rsp-8]
	ret
	.size below_only, .-below_only

# rsp+8 only.
	.globl above_only
	.type above_only, @function
above_only:
	mov rax, QWORD PTR [rsp+8]
	ret
	.size above_only, .-above_only

# rsp+16 only: neither slot `local_8` ever named.
	.globl other_slot
	.type other_slot, @function
other_slot:
	mov rax, QWORD PTR [rsp+16]
	ret
	.size other_slot, .-other_slot

	.section .note.GNU-stack,"",@progbits
