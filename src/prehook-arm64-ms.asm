	AREA	|.drectve|, DRECTVE

	EXPORT	|funchook_hook_caller_asm|
	IMPORT	|funchook_hook_caller|

	AREA	|.text$mn|, CODE, ARM64
|funchook_hook_caller_asm| PROC
	// save frame pointer (x29) and link register (x30).
	stp x29, x30, [sp, -0xe0]!
	// set frame pointer
	mov x29, sp
	// save integer or pointer arguments passed in registers.
	stp x0, x1, [sp, 0x10]
	stp x2, x3, [sp, 0x20]
	stp x4, x5, [sp, 0x30]
	stp x6, x7, [sp, 0x40]
	// save indirect return value address and platform register.
	stp x8, x18, [sp, 0x50]
	// save floating-point registers used as arguments.
	stp q0, q1, [sp, 0x60]
	stp q2, q3, [sp, 0x80]
	stp q4, q5, [sp, 0xa0]
	stp q6, q7, [sp, 0xc0]
	// 1st arg: the start address of transit. Note: x10 is set by transit-aarch64.s.
	mov x0, x10
	// 2nd arg: frame pointer
	mov x1, x29
	// call funchook_hook_caller
	bl  funchook_hook_caller
	mov x9, x0
	// restore registers
	ldp x0, x1, [sp, 0x10]
	ldp x2, x3, [sp, 0x20]
	ldp x4, x5, [sp, 0x30]
	ldp x6, x7, [sp, 0x40]
	ldp x8, x18, [sp, 0x50]
	ldp q0, q1, [sp, 0x60]
	ldp q2, q3, [sp, 0x80]
	ldp q4, q5, [sp, 0xa0]
	ldp q6, q7, [sp, 0xc0]
	ldp x29, x30, [sp], 0xe0
	// jump to hook_func
	br x9
	ENDP
	END
