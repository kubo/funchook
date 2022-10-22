	.arch armv8-a
	.text
transit:
	// save registers
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	stp x1, x0, [sp, #-16]!
	stp x3, x2, [sp, #-16]!
	stp x5, x4, [sp, #-16]!
	stp x7, x6, [sp, #-16]!
	stp x8, x18, [sp, #-16]!
	stp q1, q0, [sp, #-32]!
	stp q3, q2, [sp, #-32]!
	stp q5, q4, [sp, #-32]!
	stp q7, q6, [sp, #-32]!
	// 1st arg: the start address of transit
	adr x0, transit
	// 2nd arg: stack pointer at the beginning of transit
	sub x1, x29, 16
	// call funchook_hook_caller
	ldr x9, hook_caller_addr
	blr x9
	// restore registers
	ldp q7, q6, [sp], #32
	ldp q5, q4, [sp], #32
	ldp q3, q2, [sp], #32
	ldp q1, q0, [sp], #32
	ldp x8, x18, [sp], #16
	ldp x7, x6, [sp], #16
	ldp x5, x4, [sp], #16
	ldp x3, x2, [sp], #16
	ldp x1, x0, [sp], #16
	ldp x29, x30, [sp], #16
	// jump to hook_func
	ldr x9, hook_func_addr
	br x9

	.balign 8
hook_caller_addr:
	// dummy bytes to be replaced with absolute address of funchook_hook_caller function.
	nop
	nop
hook_func_addr:
	// dummy bytes to be replaced with absolute address of hook function.
	nop
	nop
