#if defined(__MINGW32__)
#define funchook_hook_caller_asm _funchook_hook_caller_asm
#define funchook_hook_caller _funchook_hook_caller
#endif

	.text
	.p2align 4
	.globl funchook_hook_caller_asm
#if defined(__linux__)
	.type funchook_hook_caller_asm, @function
#endif
#if defined(__MINGW32__)
	.def	funchook_hook_caller_asm;	.scl	2;	.type	32
#endif
funchook_hook_caller_asm:
	.cfi_startproc
	// prolog
	.byte 0xf3, 0x0f, 0x1e, 0xfb // same with `endbr32`, which is `nop` on legacy machines
	push %ebp
	.cfi_def_cfa_offset 8
	.cfi_offset ebp, -0x08
	mov  %esp, %ebp
	.cfi_def_cfa_register ebp
	// save %ecx and %edx for fastcall
	push %edx
	.cfi_offset edx, -0x0C
	push %ecx
	.cfi_offset ecx, -0x10
	// The next instruction isn't necessary usually.
	// It is just in case in order to ensure alignment.
	and  $0xfffffff0, %esp
	// align to a 16-byte boundary for linux gcc
	sub  $8, %esp
	// 2nd arg: base pointer
	push %ebp
	// 1st arg: the start address of transit. Note: eax is set by transit-i686.s.
	push %eax
	// call funchook_hook_caller
	call funchook_hook_caller
	// restore ecx, edx
	mov  -0x8(%ebp), %ecx
	mov  -0x4(%ebp), %edx
	// epilog
	leave
	.cfi_def_cfa esp, 4
	// jump to hook_func
	jmp  *%eax
	.cfi_endproc
#if defined(__linux__)
	.size funchook_hook_caller_asm, .-funchook_hook_caller_asm
#endif
#if defined(__MINGW32__)
	.endef
#endif
