#ifdef _WIN32
#define get_val _get_val
#define int_val _int_val
#define reset_retval _reset_retval
#define x86_test_jump _x86_test_jump
#define x86_test_error_jump1 _x86_test_error_jump1
#define x86_test_error_jump2 _x86_test_error_jump2
#endif
	.text

	.p2align 4,,15
	.globl	reset_retval
reset_retval:
	xorl	%eax, %eax
	ret

	.p2align 4,,15
	.globl	x86_test_jump
x86_test_jump:
	jmp	get_val

	.p2align 4,,15
	.globl	x86_test_error_jump1
x86_test_error_jump1:
	jmp	label_1 /* jump whose size is not 32-bit */
label_1:
	mov	int_val, %eax
	ret

	.p2align 4,,15
	.globl	x86_test_error_jump2
x86_test_error_jump2:
	xorl	%eax, %eax
label_2:
	nop
	nop
	nop
	nop
	jnz	label_2 /* jump to hot-patched region */
	mov	int_val, %eax
	ret

#ifndef _WIN32
	.p2align 4,,15
	.globl	x86_test_call_get_pc_thunk_ax
x86_test_call_get_pc_thunk_ax:
	call	x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
	movl	int_val@GOT(%eax), %eax
	movl	(%eax), %eax
	ret

	.p2align 4,,15
	.globl	x86_test_call_get_pc_thunk_bx
x86_test_call_get_pc_thunk_bx:
	pushl	%ebx
	call	x86.get_pc_thunk.bx
	addl	$_GLOBAL_OFFSET_TABLE_, %ebx
	movl	int_val@GOT(%ebx), %eax
	movl	(%eax), %eax
	popl	%ebx
	ret

	.p2align 4,,15
	.globl	x86_test_call_get_pc_thunk_cx
x86_test_call_get_pc_thunk_cx:
	call	x86.get_pc_thunk.cx
	addl	$_GLOBAL_OFFSET_TABLE_, %ecx
	movl	int_val@GOT(%ecx), %eax
	movl	(%eax), %eax
	ret

	.p2align 4,,15
	.globl	x86_test_call_get_pc_thunk_dx
x86_test_call_get_pc_thunk_dx:
	call	x86.get_pc_thunk.dx
	addl	$_GLOBAL_OFFSET_TABLE_, %edx
	movl	int_val@GOT(%edx), %eax
	movl	(%eax), %eax
	ret

	.p2align 4,,15
	.globl	x86_test_call_get_pc_thunk_si
x86_test_call_get_pc_thunk_si:
	pushl	%esi
	call	x86.get_pc_thunk.si
	addl	$_GLOBAL_OFFSET_TABLE_, %esi
	movl	int_val@GOT(%esi), %eax
	movl	(%eax), %eax
	popl	%esi
	ret

	.p2align 4,,15
	.globl	x86_test_call_get_pc_thunk_di
x86_test_call_get_pc_thunk_di:
	pushl	%edi
	call	x86.get_pc_thunk.di
	addl	$_GLOBAL_OFFSET_TABLE_, %edi
	movl	int_val@GOT(%edi), %eax
	movl	(%eax), %eax
	popl	%edi
	ret

	.p2align 4,,15
	.globl	x86_test_call_get_pc_thunk_bp
x86_test_call_get_pc_thunk_bp:
	pushl	%ebp
	call	x86.get_pc_thunk.bp
	addl	$_GLOBAL_OFFSET_TABLE_, %ebp
	movl	int_val@GOT(%ebp), %eax
	movl	(%eax), %eax
	popl	%ebp
	ret

	.p2align 4,,15
x86.get_pc_thunk.ax:
	movl (%esp), %eax
	ret

	.p2align 4,,15
x86.get_pc_thunk.bx:
	movl (%esp), %ebx
	ret

	.p2align 4,,15
x86.get_pc_thunk.cx:
	movl (%esp), %ecx
	ret

	.p2align 4,,15
x86.get_pc_thunk.dx:
	movl (%esp), %edx
	ret

	.p2align 4,,15
x86.get_pc_thunk.si:
	movl (%esp), %esi
	ret

	.p2align 4,,15
x86.get_pc_thunk.di:
	movl (%esp), %edi
	ret

	.p2align 4,,15
x86.get_pc_thunk.bp:
	movl (%esp), %ebp
	ret
#endif
