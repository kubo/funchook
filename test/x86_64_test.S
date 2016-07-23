#ifdef __APPLE__
#define reset_retval _reset_retval
#endif
	.text

	.p2align 4,,15
	.globl	reset_retval
reset_retval:
	xorq	%rax, %rax
	ret
