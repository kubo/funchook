
EXTRN	funchook_hook_caller:PROC

_text SEGMENT
funchook_hook_caller_asm PROC FRAME
	push rbp
.pushreg rbp
	mov  rbp, rsp
.setframe rbp, 0
	sub  rsp, 0a0h
.allocstack 0a0h
	;; save integer or pointer arguments passed in registers.
	mov  [rbp - 008h], rcx
.savereg rcx, -008h
	mov  [rbp - 010h], rdx
.savereg rdx, -010h
	mov  [rbp - 018h], r8
.savereg r8, -018h
	mov  [rbp - 020h], r9
.savereg r9, -020h
	;; save floating-point registers used as arguments.
	movdqa [rbp - 030h], xmm0
.savexmm128 xmm0, -030h
	movdqa [rbp - 040h], xmm1
.savexmm128 xmm1, -040h
	movdqa [rbp - 050h], xmm2
.savexmm128 xmm2, -050h
	movdqa [rbp - 060h], xmm3
.savexmm128 xmm3, -060h
.endprolog
	;; zero space for return value
	pxor   xmm0, xmm0
	movdqa [rbp - 070h], xmm0
	movdqa [rbp - 080h], xmm0
	;; 1st arg: the start address of transit. Note: r11 is set by transit-x86_64.s.
	mov  rcx, r11
	;; 2nd arg: base pointer
	mov  rdx, rbp
	;; call funchook_hook_caller
	call funchook_hook_caller
	mov  r11, rax
	cmp  BYTE PTR [rbp - 080h], 0
	jne  L1
	;; restore saved registers
	mov  rcx, [rbp - 008h]
	mov  rdx, [rbp - 010h]
	mov  r8, [rbp - 018h]
	mov  r9, [rbp - 020h]
	movdqa xmm0, [rbp - 030h]
	movdqa xmm1, [rbp - 040h]
	movdqa xmm2, [rbp - 050h]
	movdqa xmm3, [rbp - 060h]
	leave
	jmp  r11
L1:
	mov    rax, [rbp - 078h]
	movdqa xmm0, [rbp - 070h]
	leave
	ret
funchook_hook_caller_asm ENDP
_text ENDS
END
