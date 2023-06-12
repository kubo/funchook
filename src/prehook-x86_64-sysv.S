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
	sub    $0xc0, %rsp
	// save integer or pointer arguments passed in registers.
	mov    %rdi, -0xc0(%rbp)
	mov    %rsi, -0xb8(%rbp)
	mov    %rdx, -0xb0(%rbp)
	mov    %rcx, -0xa8(%rbp)
	mov    %r8, -0xa0(%rbp)
	mov    %r9, -0x98(%rbp)
	// save number of floating point arguments when the callee is a variadic function.
	mov    %rax, -0x90(%rbp)
	// save static chain pointer just in case even though C/C++ doesn't use it.
	mov    %r10, -0x88(%rbp)
	// save floating-point registers used as arguments.
	movdqu %xmm0, -0x80(%rbp)
	movdqu %xmm1, -0x70(%rbp)
	movdqu %xmm2, -0x60(%rbp)
	movdqu %xmm3, -0x50(%rbp)
	movdqu %xmm4, -0x40(%rbp)
	movdqu %xmm5, -0x30(%rbp)
	movdqu %xmm6, -0x20(%rbp)
	movdqu %xmm7, -0x10(%rbp)
	// The next instruction isn't necessary usually.
	// It is just in case in order to ensure a 16-byte alignment.
	and    $0xfffffffffffffff0, %rsp
	// 1st arg: the start address of transit. Note: %r11 is set by transit-x86_64.s.
	mov    %r11, %rdi
	// 2nd arg: base pointer
	mov    %rbp, %rsi
	// call funchook_hook_caller
	call   funchook_hook_caller
	mov    %rax, %r11
	// restore saved registers
	mov    -0xc0(%rbp), %rdi
	mov    -0xb8(%rbp), %rsi
	mov    -0xb0(%rbp), %rdx
	mov    -0xa8(%rbp), %rcx
	mov    -0xa0(%rbp), %r8
	mov    -0x98(%rbp), %r9
	mov    -0x90(%rbp), %rax
	mov    -0x88(%rbp), %r10
	movdqu -0x80(%rbp), %xmm0
	movdqu -0x70(%rbp), %xmm1
	movdqu -0x60(%rbp), %xmm2
	movdqu -0x50(%rbp), %xmm3
	movdqu -0x40(%rbp), %xmm4
	movdqu -0x30(%rbp), %xmm5
	movdqu -0x20(%rbp), %xmm6
	movdqu -0x10(%rbp), %xmm7
	leave
	// jump to hook_func
	jmp    *%r11
	.cfi_endproc
#if !defined __APPLE__
	.size funchook_hook_caller_asm, .-funchook_hook_caller_asm
#endif
