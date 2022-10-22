// transit code for x86
	.text
transit:
	// prolog
	push %ebp
	mov  %esp, %ebp
	// save ECX, EDX for fastcall
	push %ecx
	push %edx
	// get the start address of transit to %eax
	call get_eip
	lea  transit - . (%eax),%eax
	// for alignment
	sub  $0x8, %esp
	// 2nd arg: stack pointer at the beginning of transit
	lea 0x4(%ebp), %ecx
	push %ecx
	// 1st arg: the start address of transit
	push %eax
	// call funchook_hook_caller
	lea  hook_caller_addr - transit (%eax),%eax
	call *(%eax)
	pop  %eax
	add  $0xc, %esp
	// restore ECX, EDX
	pop  %edx
	pop  %ecx
	// epilog
	leave
	// jump to hook_func
	lea  hook_func_addr - transit (%eax),%eax
	jmp  *(%eax)

get_eip:
	movl (%esp), %eax
	ret

	.balign 4
hook_caller_addr:
	// dummy bytes to be replaced with absolute address of funchook_hook_caller function.
	.byte  0x0f,0x1f,0x40,0x00
hook_func_addr:
	// dummy bytes to be replaced with absolute address of hook function.
	.byte  0x0f,0x1f,0x40,0x00
