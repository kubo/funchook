// transit code for System V AMD64 ABI
	.text
transit:
	push   %rbp
	mov    %rsp, %rbp
	sub    $0xd0, %rsp
	// save integer or pointer arguments passed in registers.
	mov    %rdi, -0x08(%rbp)
	mov    %rsi, -0x10(%rbp)
	mov    %rdx, -0x18(%rbp)
	mov    %rcx, -0x20(%rbp)
	mov    %r8, -0x28(%rbp)
	mov    %r9, -0x30(%rbp)
	// save number of floating point arguments when the callee is a variadic function.
	mov    %rax, -0x38(%rbp)
	// save static chain pointer just in case even though C/C++ doesn't use it.
	mov    %r10, -0x40(%rbp)
	// save floating-point registers used as arguments.
	movdqa %xmm0, -0x50(%rbp)
	movdqa %xmm1, -0x60(%rbp)
	movdqa %xmm2, -0x70(%rbp)
	movdqa %xmm3, -0x80(%rbp)
	movdqa %xmm4, -0x90(%rbp)
	movdqa %xmm5, -0xa0(%rbp)
	movdqa %xmm6, -0xb0(%rbp)
	movdqa %xmm7, -0xc0(%rbp)
	// 1st arg: the start address of transit
	lea    transit(%rip), %rdi
	// call funchook_hook_caller
	call   *hook_caller_addr(%rip)
	// restore saved registers
	mov    -0x08(%rbp), %rdi
	mov    -0x10(%rbp), %rsi
	mov    -0x18(%rbp), %rdx
	mov    -0x20(%rbp), %rcx
	mov    -0x28(%rbp), %r8
	mov    -0x30(%rbp), %r9
	mov    -0x38(%rbp), %rax
	mov    -0x40(%rbp), %r10
	movdqa -0x50(%rbp), %xmm0
	movdqa -0x60(%rbp), %xmm1
	movdqa -0x70(%rbp), %xmm2
	movdqa -0x80(%rbp), %xmm3
	movdqa -0x90(%rbp), %xmm4
	movdqa -0xa0(%rbp), %xmm5
	movdqa -0xb0(%rbp), %xmm6
	movdqa -0xc0(%rbp), %xmm7
	leave
	// jump to hook_func
	jmp    *hook_func_addr(%rip)

	.balign 8
hook_caller_addr:
	// dummy bytes to be replaced with absolute address of funchook_hook_caller function.
	.byte  0x0f,0x1f,0x40,0x00,0x0f,0x1f,0x40,0x00
hook_func_addr:	
	// dummy bytes to be replaced with absolute address of hook function.
	.byte  0x0f,0x1f,0x40,0x00,0x0f,0x1f,0x40,0x00
