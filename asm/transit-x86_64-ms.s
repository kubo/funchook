// transit code for Microsoft x64 calling convention
	.text
transit:
	// save RCX, RDX, R8, R9 to the shadow space
	mov    %rcx, 0x08(%rsp)
	mov    %rdx, 0x10(%rsp)
	mov    %r8, 0x18(%rsp)
	mov    %r9, 0x20(%rsp)
	sub    $0x68, %rsp
	// save xmm0 - xmm3
	movdqa %xmm0, 0x20(%rsp)
	movdqa %xmm1, 0x30(%rsp)
	movdqa %xmm2, 0x40(%rsp)
	movdqa %xmm3, 0x50(%rsp)
	// 1st arg: the start address of transit
	lea    transit(%rip), %rcx
	// call funchook_hook_caller
	call   *hook_caller_addr(%rip)
	// restore xmm0 - xmm3
	movdqa 0x20(%rsp), %xmm0
	movdqa 0x30(%rsp), %xmm1
	movdqa 0x40(%rsp), %xmm2
	movdqa 0x50(%rsp), %xmm3
	// restore RCX, RDX, R8, R9 from the shadow space
	add    $0x68, %rsp
	mov    0x08(%rsp), %rcx
	mov    0x10(%rsp), %rdx
	mov    0x18(%rsp), %r8
	mov    0x20(%rsp), %r9
	// jump to hook_func
	jmp    *hook_func_addr(%rip)

	.balign 8
hook_caller_addr:
	// dummy bytes to be replaced with absolute address of funchook_hook_caller function.
	.byte  0x0f,0x1f,0x40,0x00,0x0f,0x1f,0x40,0x00
hook_func_addr:	
	// dummy bytes to be replaced with absolute address of hook function.
	.byte  0x0f,0x1f,0x40,0x00,0x0f,0x1f,0x40,0x00
