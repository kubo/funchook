	.arch armv8-a
	.text
transit:
	// The address of the `transit` member in `funchook_entry_t` struct
	// is passed to funchook_hook_caller_asm via x10
	adr x10, transit
	ldr x9, hook_caller_addr
	br x9

	.balign 8
hook_caller_addr:
	// dummy bytes to be replaced with absolute address of funchook_hook_caller function.
	nop
	nop
