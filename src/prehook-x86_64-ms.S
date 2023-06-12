	.text
	.globl	funchook_hook_caller_asm
	.def	funchook_hook_caller_asm;	.scl	2;	.type	32;	.endef

funchook_hook_caller_asm:
	.seh_proc funchook_hook_caller_asm
	push %rbp
	.seh_pushreg %rbp
	mov  %rsp, %rbp
	.seh_setframe rbp, 0
	sub  $0xa0, %rsp
	.seh_stackalloc	0xa0
	.seh_endprologue
	// save integer or pointer arguments passed in registers.
	mov  %rcx, -0x80(%rbp)
	mov  %rdx, -0x78(%rbp)
	mov  %r8, -0x70(%rbp)
	mov  %r9, -0x68(%rbp)
	// save floating-point registers used as arguments.
	movdqu %xmm0, -0x60(%rbp)
	movdqu %xmm1, -0x50(%rbp)
	movdqu %xmm2, -0x40(%rbp)
	movdqu %xmm3, -0x30(%rbp)
	// save floating-point registers used as __vectorcall arguments
	movdqu %xmm4, -0x20(%rbp)
	movdqu %xmm5, -0x10(%rbp)
	// The next instruction isn't necessary usually.
	// It is just in case in order to ensure a 16-byte alignment.
	and    $0xfffffffffffffff0, %rsp
	// 1st arg: the start address of transit. Note: r11 is set by transit-x86_64.s.
	mov  %r11, %rcx
	// 2nd arg: base pointer
	mov  %rbp, %rdx
	// call funchook_hook_caller
	call funchook_hook_caller
	// restore saved registers
	mov  -0x80(%rbp), %rcx
	mov  -0x78(%rbp), %rdx
	mov  -0x70(%rbp), %r8
	mov  -0x68(%rbp), %r9
	movdqu -0x60(%rbp), %xmm0
	movdqu -0x50(%rbp), %xmm1
	movdqu -0x40(%rbp), %xmm2
	movdqu -0x30(%rbp), %xmm3
	movdqu -0x20(%rbp), %xmm4
	movdqu -0x10(%rbp), %xmm5
	leave
	// jump to hook_func
	jmp  *%rax
	.seh_endproc
