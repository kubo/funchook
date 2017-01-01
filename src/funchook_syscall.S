/* -*- indent-tabs-mode: nil -*-
 *
 * This file is part of Funchook.
 * https://github.com/kubo/funchook
 *
 * Funchook is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 2 of the License, or (at your
 * option) any later version.
 *
 * As a special exception, the copyright holders of this library give you
 * permission to link this library with independent modules to produce an
 * executable, regardless of the license terms of these independent
 * modules, and to copy and distribute the resulting executable under
 * terms of your choice, provided that you also meet, for each linked
 * independent module, the terms and conditions of the license of that
 * module. An independent module is a module which is not derived from or
 * based on this library. If you modify this library, you may extend this
 * exception to your version of the library, but you are not obliged to
 * do so. If you do not wish to do so, delete this exception statement
 * from your version.
 *
 * Funchook is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Funchook. If not, see <http://www.gnu.org/licenses/>.
 */
#ifdef __APPLE__
#define funchook_os_syscall _funchook_os_syscall
#define funchook_os_errno _funchook_os_errno
#define hidden private_extern
#endif

#ifdef __x86_64__
	.text
	.p2align 4,,15
	.globl	funchook_os_syscall
	.hidden	funchook_os_syscall
funchook_os_syscall:
	movq	%rdi, %rax /* syscall number */
#ifdef __APPLE__
	addq	$0x2000000, %rax
#endif
	movq	%rsi, %rdi   /* 1st argument */
	movq	%rdx, %rsi   /* 2nd argument */
	movq	%rcx, %rdx   /* 3rd argument */
	movq	%r8, %r10    /* 4th argument */
	movq	%r9, %r8     /* 5th argument */
	movq	8(%rsp), %r9 /* 6th argument */
	syscall
#ifdef __APPLE__
	jnc	1f
#else
	cmpq	$-4096, %rax
	jbe	1f
	negl	%eax
#endif
	movq	funchook_os_errno@GOTPCREL(%rip), %rdi
	movl	%eax, (%rdi)
	movq	$-1, %rax
1:
	ret
#endif

#if defined(__i386__) && defined(__linux__)
	.text
	.p2align 4,,15
	.globl	funchook_os_syscall
	.hidden	funchook_os_syscall
funchook_os_syscall:
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	pushl	%ebp
	movl	20(%esp), %eax /* syscall number */
	movl	24(%esp), %ebx /* 1st argument */
	movl	28(%esp), %ecx /* 2nd argument */
	movl	32(%esp), %edx /* 3rd argument */
	movl	36(%esp), %esi /* 4th argument */
	movl	40(%esp), %edi /* 5th argument */
	movl	44(%esp), %ebp /* 6th argument */
	call	*%gs:0x10 	// or int $0x80
	cmpl	$-4096, %eax
	jbe	1f
	call	funchook.get_pc_thunk.cx
	addl	$_GLOBAL_OFFSET_TABLE_, %ecx
	movl	funchook_os_errno@GOT(%ecx), %ecx
	negl	%eax
	movl	%eax, (%ecx)
	movl	$-1, %eax
1:
	popl	%ebp
	popl	%edi
	popl	%esi
	popl	%ebx
	ret

funchook.get_pc_thunk.cx:
	movl	(%esp), %ecx
	ret
#endif

#if defined(__i386__) && defined(__APPLE__)
	.text
	.p2align 4,,15
	.globl	funchook_os_syscall
	.hidden	funchook_os_syscall
funchook_os_syscall:
	popl	%ecx    /* return address */
	popl	%eax    /* syscall number */
	pushl	%ecx
	int	$0x80
	pushl	%ecx
	jc	L_1
	/* success. return %eax */
	ret
	/* failure. set %eax to funchook_os_errno and return -1 */
L_1:
	call	L_2
L_2:
	popl	%ecx    /* get current eip */
	movl	L_funchook_os_errno$non_lazy_ptr-L_2(%ecx), %edx
	movl	%eax, (%edx)
	movl	$-1, %eax
	ret

	.section	__IMPORT,__pointers,non_lazy_symbol_pointers
L_funchook_os_errno$non_lazy_ptr:
	.indirect_symbol	funchook_os_errno
	.long	0
#endif
