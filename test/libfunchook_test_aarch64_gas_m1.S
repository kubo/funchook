	.arch armv8-a
	.file	"libfunchook_test_aarch64_gas_m1.S"
	.text
	.align	2
	.p2align 3,,7

test_data:
	.8byte 0x1020304050607080, 0x0102030405060708

_call_get_val_in_dll:
	.global	_call_get_val_in_dll
	; .type	call_get_val_in_dll, %function
	stp	x29, x30, [sp, -16]!
	bl	_get_val_in_dll
	ldp	x29, x30, [sp], 16
	ret

_jump_get_val_in_dll:
	.global	_jump_get_val_in_dll
	; .type	jump_get_val_in_dll, %function
	b	_get_val_in_dll

_arm64_test_adr:
	.global	_arm64_test_adr
	; .type	arm64_test_adr, %function
	adr x9, test_data
	ldr x9, [x9]
	add x0, x0, x9
	ret

_arm64_test_beq:
	.global	_arm64_test_beq
	; .type	arm64_test_beq, %function
	adds x0, x0, 1
	beq 1f
	sub x0, x0, 2
1:
	ret

_arm64_test_bne:
	.global	_arm64_test_bne
	; .type	arm64_test_bne, %function
	adds x0, x0, 1
	bne 1f
	sub x0, x0, 2
1:
	ret


_arm64_test_cbnz:
	.global	_arm64_test_cbnz
	; .type	arm64_test_cbnz, %function
	cbnz x0, 1f
	add x0, x0, 2
1:
	sub x0, x0, 1
	ret

_arm64_test_cbz:
	.global	_arm64_test_cbz
	; .type	arm64_test_cbz, %function
	cbz x0, 1f
	add x0, x0, 2
1:
	sub x0, x0, 1
	ret

_arm64_test_ldr_w:
	.global	_arm64_test_ldr_w
	; .type	arm64_test_ldr_w, %function
	ldr w9, test_data
	add x0, x0, x9
	ret

_arm64_test_ldr_x:
	.global	_arm64_test_ldr_x
	; .type	arm64_test_ldr_x, %function
	ldr x9, test_data
	add x0, x0, x9
	ret

_arm64_test_ldr_s:
	.global	_arm64_test_ldr_s
	; .type	arm64_test_ldr_s, %function
	ldr s16, test_data
	mov w9, v16.s[0]
	add x0, x0, x9
	ret

_arm64_test_ldr_d:
	.global	_arm64_test_ldr_d
	; .type	arm64_test_ldr_d, %function
	ldr d16, test_data
	mov x9, v16.d[0]
	add x0, x0, x9
	ret

_arm64_test_ldr_q:
	.global	_arm64_test_ldr_q
	; .type	arm64_test_ldr_q, %function
	ldr q16, test_data
	mov x9, v16.d[0]
	add x0, x0, x9
	mov x9, v16.d[1]
	add x0, x0, x9
	ret

_arm64_test_prfm:
	.global	_arm64_test_prfm
	; .type	arm64_test_prfm, %function
	prfm pldl1keep, test_data
	ldr x9, test_data
	add x0, x0, x9
	ret

_arm64_test_ldrsw:
	.global	_arm64_test_ldrsw
	; .type	arm64_test_ldrsw, %function
	ldrsw x9, 1f
	add x0, x0, x9
	ret

_arm64_test_tbnz:
	.global	_arm64_test_tbnz
	; .type	arm64_test_tbnz, %function
	tbnz x0, 32, 1f
	add x0, x0, 2
1:
	sub x0, x0, 1
	ret

_arm64_test_tbz:
	.global	_arm64_test_tbz
	; .type	arm64_test_tbz, %function
	tbz x0, 32, 1f
	add x0, x0, 2
1:
	sub x0, x0, 1
	ret
