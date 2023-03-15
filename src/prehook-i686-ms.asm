	.686P
	.XMM
	.model	flat

EXTRN	_funchook_hook_caller:PROC

_TEXT	SEGMENT
_funchook_hook_caller_asm PROC
	push ebp
	mov  ebp, esp
	;; save ECX and EDX for fastcall
	push edx
	push ecx
	;; 2nd arg: base pointer
	push ebp
	;; 1st arg: the start address of transit. Note: eax is set by transit-i686.s.
	push eax
	;; call funchook_hook_caller
	call _funchook_hook_caller
	add  esp, 08h
	;; restore ECX, EDX
	pop  ecx
	pop  edx
	;; epilog
	leave
	;; jump to hook_func
	jmp  eax
_funchook_hook_caller_asm ENDP
_TEXT	ENDS
END
