#ifdef __APPLE__
#define call_get_val_in_dll _call_get_val_in_dll
#define get_val_in_dll _get_val_in_dll
#define jump_get_val_in_dll _jump_get_val_in_dll
#define arm64_test_adr _arm64_test_adr
#define arm64_test_beq _arm64_test_beq
#define arm64_test_bne _arm64_test_bne
#define arm64_test_cbnz _arm64_test_cbnz
#define arm64_test_cbz _arm64_test_cbz
#define arm64_test_ldr_w _arm64_test_ldr_w
#define arm64_test_ldr_x _arm64_test_ldr_x
#define arm64_test_ldr_s _arm64_test_ldr_s
#define arm64_test_ldr_d _arm64_test_ldr_d
#define arm64_test_ldr_q _arm64_test_ldr_q
#define arm64_test_prfm _arm64_test_prfm
#define arm64_test_ldrsw _arm64_test_ldrsw
#define arm64_test_tbnz _arm64_test_tbnz
#define arm64_test_tbz _arm64_test_tbz
#define test_data _test_data
#endif
	.arch armv8-a
	.file	"libfunchook_test_aarch64_gas.S"
	.text
	.align	2
	.p2align 3,,7

test_data:
	.8byte 0x1020304050607080, 0x0102030405060708

call_get_val_in_dll:
	.global	call_get_val_in_dll
#ifdef __linux__
	.type	call_get_val_in_dll, %function
#endif
	stp	x29, x30, [sp, -16]!
	bl	get_val_in_dll
	ldp	x29, x30, [sp], 16
	ret

jump_get_val_in_dll:
	.global	jump_get_val_in_dll
#ifdef __linux__
	.type	jump_get_val_in_dll, %function
#endif
	b	get_val_in_dll

arm64_test_adr:
	.global	arm64_test_adr
#ifdef __linux__
	.type	arm64_test_adr, %function
#endif
	adr x9, test_data
	ldr x9, [x9]
	add x0, x0, x9
	ret

arm64_test_beq:
	.global	arm64_test_beq
#ifdef __linux__
	.type	arm64_test_beq, %function
#endif
	adds x0, x0, 1
	beq 1f
	sub x0, x0, 2
1:
	ret

arm64_test_bne:
	.global	arm64_test_bne
#ifdef __linux__
	.type	arm64_test_bne, %function
#endif
	adds x0, x0, 1
	bne 1f
	sub x0, x0, 2
1:
	ret


arm64_test_cbnz:
	.global	arm64_test_cbnz
#ifdef __linux__
	.type	arm64_test_cbnz, %function
#endif
	cbnz x0, 1f
	add x0, x0, 2
1:
	sub x0, x0, 1
	ret

arm64_test_cbz:
	.global	arm64_test_cbz
#ifdef __linux__
	.type	arm64_test_cbz, %function
#endif
	cbz x0, 1f
	add x0, x0, 2
1:
	sub x0, x0, 1
	ret

arm64_test_ldr_w:
	.global	arm64_test_ldr_w
#ifdef __linux__
	.type	arm64_test_ldr_w, %function
#endif
	ldr w9, test_data
	add x0, x0, x9
	ret

arm64_test_ldr_x:
	.global	arm64_test_ldr_x
#ifdef __linux__
	.type	arm64_test_ldr_x, %function
#endif
	ldr x9, test_data
	add x0, x0, x9
	ret

arm64_test_ldr_s:
	.global	arm64_test_ldr_s
#ifdef __linux__
	.type	arm64_test_ldr_s, %function
#endif
	ldr s16, test_data
	mov w9, v16.s[0]
	add x0, x0, x9
	ret

arm64_test_ldr_d:
	.global	arm64_test_ldr_d
#ifdef __linux__
	.type	arm64_test_ldr_d, %function
#endif
	ldr d16, test_data
	mov x9, v16.d[0]
	add x0, x0, x9
	ret

arm64_test_ldr_q:
	.global	arm64_test_ldr_q
#ifdef __linux__
	.type	arm64_test_ldr_q, %function
#endif
	ldr q16, test_data
	mov x9, v16.d[0]
	add x0, x0, x9
	mov x9, v16.d[1]
	add x0, x0, x9
	ret

arm64_test_prfm:
	.global	arm64_test_prfm
#ifdef __linux__
	.type	arm64_test_prfm, %function
#endif
	prfm pldl1keep, test_data
	ldr x9, test_data
	add x0, x0, x9
	ret

arm64_test_ldrsw:
	.global	arm64_test_ldrsw
#ifdef __linux__
	.type	arm64_test_ldrsw, %function
#endif
	ldrsw x9, 1f
	add x0, x0, x9
	ret

arm64_test_tbnz:
	.global	arm64_test_tbnz
#ifdef __linux__
	.type	arm64_test_tbnz, %function
#endif
	tbnz x0, 32, 1f
	add x0, x0, 2
1:
	sub x0, x0, 1
	ret

arm64_test_tbz:
	.global	arm64_test_tbz
#ifdef __linux__
	.type	arm64_test_tbz, %function
#endif
	tbz x0, 32, 1f
	add x0, x0, 2
1:
	sub x0, x0, 1
	ret
