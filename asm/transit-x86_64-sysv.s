// transit code for System V AMD64 ABI
	.text
transit:
	// %r11 is the address of the `transit` member in `funchook_entry_t` struct.
	lea    transit(%rip), %r11
	jmp   *hook_caller_addr(%rip)
hook_caller_addr:
	// dummy bytes to be replaced with absolute address of funchook_hook_caller function.
	.byte  0x0f,0x1f,0x40,0x00,0x0f,0x1f,0x40,0x00
