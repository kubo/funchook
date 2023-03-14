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
	mov  %rcx, -0x08(%rbp)
	mov  %rdx, -0x10(%rbp)
	mov  %r8, -0x18(%rbp)
	mov  %r9, -0x20(%rbp)
	// save floating-point registers used as arguments.
	movdqa %xmm0, -0x30(%rbp)
	movdqa %xmm1, -0x40(%rbp)
	movdqa %xmm2, -0x50(%rbp)
	movdqa %xmm3, -0x60(%rbp)
	// zero space for return value
	pxor   %xmm0, %xmm0
	movdqa %xmm0, -0x70(%rbp)
	movdqa %xmm0, -0x80(%rbp)
	// 1st arg: the start address of transit. Note: r11 is set by transit-x86_64.s.
	mov  %r11, %rcx
	// 2nd arg: base pointer
	mov  %rbp, %rdx
	// call funchook_hook_caller
	call funchook_hook_caller
	mov  %rax, %r11
	cmpb $0, -0x80(%rbp)
	jne  .L1
	// restore saved registers
	mov  -0x08(%rbp), %rcx
	mov  -0x10(%rbp), %rdx
	mov  -0x18(%rbp), %r8
	mov  -0x20(%rbp), %r9
	movdqa -0x30(%rbp), %xmm0
	movdqa -0x40(%rbp), %xmm1
	movdqa -0x50(%rbp), %xmm2
	movdqa -0x60(%rbp), %xmm3
	leave
	jmp  *%r11
.L1:
	mov    -0x78(%rbp), %rax
	movdqa -0x70(%rbp), %xmm0
	leave
	ret
	.seh_endproc
