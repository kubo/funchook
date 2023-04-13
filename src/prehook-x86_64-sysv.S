// transit code for System V AMD64 ABI
#if defined __APPLE__
#define funchook_hook_caller_asm _funchook_hook_caller_asm
#define funchook_hook_caller _funchook_hook_caller
#endif // __APPLE__
#if defined __linux__ && defined __PIC__
#define funchook_hook_caller funchook_hook_caller@PLT
#endif // __linux__ && __PIC__
	.text
	.globl	funchook_hook_caller_asm
#if defined __linux__
	.type	funchook_hook_caller_asm, @function
#endif
funchook_hook_caller_asm:
	.cfi_startproc
	.byte 0xf3, 0x0f, 0x1e, 0xfa // same with `endbr64`, which is `nop` on legacy machines
	pushq  %rbp
	.cfi_def_cfa_offset 0x10
	.cfi_offset rbp, -0x10
	movq   %rsp, %rbp
	.cfi_def_cfa_register rbp
	sub    $0xe0, %rsp
	// save integer or pointer arguments passed in registers.
	mov    %rdi, -0x08(%rbp)
	.cfi_offset rdi, -0x18
	mov    %rsi, -0x10(%rbp)
	.cfi_offset rsi, -0x20
	mov    %rdx, -0x18(%rbp)
	.cfi_offset rdx, -0x28
	mov    %rcx, -0x20(%rbp)
	.cfi_offset rcx, -0x30
	mov    %r8, -0x28(%rbp)
	.cfi_offset r8, -0x38
	mov    %r9, -0x30(%rbp)
	.cfi_offset r9, -0x40
	// save number of floating point arguments when the callee is a variadic function.
	mov    %rax, -0x38(%rbp)
	.cfi_offset rax, -0x48
	// save static chain pointer just in case even though C/C++ doesn't use it.
	mov    %r10, -0x40(%rbp)
	.cfi_offset r10, -0x50
	// save floating-point registers used as arguments.
	movdqa %xmm0, -0x50(%rbp)
	.cfi_offset xmm0, -0x60
	movdqa %xmm1, -0x60(%rbp)
	.cfi_offset xmm1, -0x70
	movdqa %xmm2, -0x70(%rbp)
	.cfi_offset xmm2, -0x80
	movdqa %xmm3, -0x80(%rbp)
	.cfi_offset xmm3, -0x90
	movdqa %xmm4, -0x90(%rbp)
	.cfi_offset xmm4, -0xa0
	movdqa %xmm5, -0xa0(%rbp)
	.cfi_offset xmm5, -0xb0
	movdqa %xmm6, -0xb0(%rbp)
	.cfi_offset xmm6, -0xc0
	movdqa %xmm7, -0xc0(%rbp)
	.cfi_offset xmm7, -0xd0
	// zero space for return value
	pxor   %xmm0, %xmm0
	movdqa %xmm0, -0xd0(%rbp)
	movdqa %xmm0, -0xe0(%rbp)
	// 1st arg: the start address of transit. Note: %r11 is set by transit-x86_64.s.
	mov    %r11, %rdi
	// 2nd arg: base pointer
	mov    %rbp, %rsi
	// call funchook_hook_caller
	call   funchook_hook_caller
	mov    %rax, %r11
	cmpb   $0, -0xe0(%rbp)
	jne    .L1
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
	.cfi_remember_state
	.cfi_def_cfa rsp, 8
	// jump to hook_func
	jmp    *%r11
.L1:
	.cfi_restore_state
	mov    -0xd8(%rbp), %rax
	movdqa -0xd0(%rbp), %xmm0
	leave
	.cfi_def_cfa rsp, 8
	retq
	.cfi_endproc
#if !defined __APPLE__
	.size funchook_hook_caller_asm, .-funchook_hook_caller_asm
#endif
