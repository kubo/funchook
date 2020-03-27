	.text
	.syntax unified
	.thumb
	.thumb_func

	.align	2
	.global	jump_get_val_in_dll
	.type	jump_get_val_in_dll, %function
jump_get_val_in_dll:
	b	get_val_in_dll
	.size	jump_get_val_in_dll, .-jump_get_val_in_dll

	.align	2
	.global	call_get_val_in_dll
	.type	call_get_val_in_dll, %function
call_get_val_in_dll:
	push	{r3, lr}
	bl	get_val_in_dll
	pop	{r3, pc}
	nop
	.size	call_get_val_in_dll, .-call_get_val_in_dll

	.align	2
	.global	arm_test_beq_1
	.type	arm_test_beq_1, %function
arm_test_beq_1:
	cmp	r0, #0
	beq	1f
	eors	r0, r0
1:
	nop
	bx	lr
	.size	arm_test_beq_1, .-arm_test_beq_1

	.align	2
	.global	arm_test_beq_2
	.type	arm_test_beq_2, %function
arm_test_beq_2:
	cmp	r0, #0
	beq	1f
	eors	r0, r0
	nop
	nop
	nop
1:
	bx	lr
	.size	arm_test_beq_2, .-arm_test_beq_2
