// transit code for x86
	.text
transit:
	// The address of the `transit` member in `funchook_entry_t` struct
	// is passed to funchook_hook_caller_asm via %eax.
	call get_eip
	lea transit - . (%eax),%eax
	jmp *hook_caller_addr - transit (%eax)
get_eip:
	movl (%esp), %eax
	ret

	.balign 4
hook_caller_addr:
	// dummy bytes to be replaced with absolute address of funchook_hook_caller function.
	.byte  0x0f,0x1f,0x40,0x00
