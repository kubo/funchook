// -*- c -*-
// Created by asm/template.rb

#if defined(CPU_X86_64) && defined(WIN32)

// Windows x64
#define TRANSIT_CODE_TEMPLATE { \
  /* 0000000000000000 <transit>: */ \
  /*    0: */ 0x48,0x89,0x4c,0x24,0x08,           /* mov    %rcx,0x8(%rsp) */ \
  /*    5: */ 0x48,0x89,0x54,0x24,0x10,           /* mov    %rdx,0x10(%rsp) */ \
  /*    a: */ 0x4c,0x89,0x44,0x24,0x18,           /* mov    %r8,0x18(%rsp) */ \
  /*    f: */ 0x4c,0x89,0x4c,0x24,0x20,           /* mov    %r9,0x20(%rsp) */ \
  /*   14: */ 0x48,0x83,0xec,0x68,                /* sub    $0x68,%rsp */ \
  /*   18: */ 0x66,0x0f,0x7f,0x44,0x24,0x20,      /* movdqa %xmm0,0x20(%rsp) */ \
  /*   1e: */ 0x66,0x0f,0x7f,0x4c,0x24,0x30,      /* movdqa %xmm1,0x30(%rsp) */ \
  /*   24: */ 0x66,0x0f,0x7f,0x54,0x24,0x40,      /* movdqa %xmm2,0x40(%rsp) */ \
  /*   2a: */ 0x66,0x0f,0x7f,0x5c,0x24,0x50,      /* movdqa %xmm3,0x50(%rsp) */ \
  /*   30: */ 0x48,0x8d,0x0d,0xc9,0xff,0xff,0xff, /* lea    -0x37(%rip),%rcx        # 0 <transit> */ \
  /*   37: */ 0xff,0x15,0x3b,0x00,0x00,0x00,      /* callq  *0x3b(%rip)        # 78 <hook_caller_addr> */ \
  /*   3d: */ 0x66,0x0f,0x6f,0x44,0x24,0x20,      /* movdqa 0x20(%rsp),%xmm0 */ \
  /*   43: */ 0x66,0x0f,0x6f,0x4c,0x24,0x30,      /* movdqa 0x30(%rsp),%xmm1 */ \
  /*   49: */ 0x66,0x0f,0x6f,0x54,0x24,0x40,      /* movdqa 0x40(%rsp),%xmm2 */ \
  /*   4f: */ 0x66,0x0f,0x6f,0x5c,0x24,0x50,      /* movdqa 0x50(%rsp),%xmm3 */ \
  /*   55: */ 0x48,0x83,0xc4,0x68,                /* add    $0x68,%rsp */ \
  /*   59: */ 0x48,0x8b,0x4c,0x24,0x08,           /* mov    0x8(%rsp),%rcx */ \
  /*   5e: */ 0x48,0x8b,0x54,0x24,0x10,           /* mov    0x10(%rsp),%rdx */ \
  /*   63: */ 0x4c,0x8b,0x44,0x24,0x18,           /* mov    0x18(%rsp),%r8 */ \
  /*   68: */ 0x4c,0x8b,0x4c,0x24,0x20,           /* mov    0x20(%rsp),%r9 */ \
  /*   6d: */ 0xff,0x25,0x0d,0x00,0x00,0x00,      /* jmpq   *0xd(%rip)        # 80 <hook_func_addr> */ \
  /*   73: */ 0x0f,0x1f,0x44,0x00,0x00,           /* nopl   0x0(%rax,%rax,1) */ \
  /* 0000000000000078 <hook_caller_addr>: */ \
  /*   78: */ 0x0f,0x1f,0x40,0x00,                /* nopl   0x0(%rax) */ \
  /*   7c: */ 0x0f,0x1f,0x40,0x00,                /* nopl   0x0(%rax) */ \
  /* 0000000000000080 <hook_func_addr>: */ \
  /*   80: */ 0x0f,0x1f,0x40,0x00,                /* nopl   0x0(%rax) */ \
  /*   84: */ 0x0f,0x1f,0x40,0x00,                /* nopl   0x0(%rax) */ \
  }
#define TRANSIT_HOOK_CALLER_ADDR 0x78
#define TRANSIT_HOOK_FUNC_ADDR 0x80
#define TRANSIT_CODE_SIZE 0x88

#elif defined(CPU_X86_64)

// Linux x86_64 (System V ABI)
#define TRANSIT_CODE_TEMPLATE { \
  /* 0000000000000000 <transit>: */ \
  /*    0: */ 0x55,                               /* push   %rbp */ \
  /*    1: */ 0x48,0x89,0xe5,                     /* mov    %rsp,%rbp */ \
  /*    4: */ 0x48,0x81,0xec,0xd0,0x00,0x00,0x00, /* sub    $0xd0,%rsp */ \
  /*    b: */ 0x48,0x89,0x7d,0xf8,                /* mov    %rdi,-0x8(%rbp) */ \
  /*    f: */ 0x48,0x89,0x75,0xf0,                /* mov    %rsi,-0x10(%rbp) */ \
  /*   13: */ 0x48,0x89,0x55,0xe8,                /* mov    %rdx,-0x18(%rbp) */ \
  /*   17: */ 0x48,0x89,0x4d,0xe0,                /* mov    %rcx,-0x20(%rbp) */ \
  /*   1b: */ 0x4c,0x89,0x45,0xd8,                /* mov    %r8,-0x28(%rbp) */ \
  /*   1f: */ 0x4c,0x89,0x4d,0xd0,                /* mov    %r9,-0x30(%rbp) */ \
  /*   23: */ 0x48,0x89,0x45,0xc8,                /* mov    %rax,-0x38(%rbp) */ \
  /*   27: */ 0x4c,0x89,0x55,0xc0,                /* mov    %r10,-0x40(%rbp) */ \
  /*   2b: */ 0x66,0x0f,0x7f,0x45,0xb0,           /* movdqa %xmm0,-0x50(%rbp) */ \
  /*   30: */ 0x66,0x0f,0x7f,0x4d,0xa0,           /* movdqa %xmm1,-0x60(%rbp) */ \
  /*   35: */ 0x66,0x0f,0x7f,0x55,0x90,           /* movdqa %xmm2,-0x70(%rbp) */ \
  /*   3a: */ 0x66,0x0f,0x7f,0x5d,0x80,           /* movdqa %xmm3,-0x80(%rbp) */ \
  /*   3f: */ 0x66,0x0f,0x7f,0xa5,0x70,0xff,0xff, /* movdqa %xmm4,-0x90(%rbp) */ \
  /*   46: */ 0xff,                               /*  */ \
  /*   47: */ 0x66,0x0f,0x7f,0xad,0x60,0xff,0xff, /* movdqa %xmm5,-0xa0(%rbp) */ \
  /*   4e: */ 0xff,                               /*  */ \
  /*   4f: */ 0x66,0x0f,0x7f,0xb5,0x50,0xff,0xff, /* movdqa %xmm6,-0xb0(%rbp) */ \
  /*   56: */ 0xff,                               /*  */ \
  /*   57: */ 0x66,0x0f,0x7f,0xbd,0x40,0xff,0xff, /* movdqa %xmm7,-0xc0(%rbp) */ \
  /*   5e: */ 0xff,                               /*  */ \
  /*   5f: */ 0x48,0x8d,0x3d,0x9a,0xff,0xff,0xff, /* lea    -0x66(%rip),%rdi        # 0 <transit> */ \
  /*   66: */ 0xff,0x15,0x5c,0x00,0x00,0x00,      /* callq  *0x5c(%rip)        # c8 <hook_caller_addr> */ \
  /*   6c: */ 0x48,0x8b,0x7d,0xf8,                /* mov    -0x8(%rbp),%rdi */ \
  /*   70: */ 0x48,0x8b,0x75,0xf0,                /* mov    -0x10(%rbp),%rsi */ \
  /*   74: */ 0x48,0x8b,0x55,0xe8,                /* mov    -0x18(%rbp),%rdx */ \
  /*   78: */ 0x48,0x8b,0x4d,0xe0,                /* mov    -0x20(%rbp),%rcx */ \
  /*   7c: */ 0x4c,0x8b,0x45,0xd8,                /* mov    -0x28(%rbp),%r8 */ \
  /*   80: */ 0x4c,0x8b,0x4d,0xd0,                /* mov    -0x30(%rbp),%r9 */ \
  /*   84: */ 0x48,0x8b,0x45,0xc8,                /* mov    -0x38(%rbp),%rax */ \
  /*   88: */ 0x4c,0x8b,0x55,0xc0,                /* mov    -0x40(%rbp),%r10 */ \
  /*   8c: */ 0x66,0x0f,0x6f,0x45,0xb0,           /* movdqa -0x50(%rbp),%xmm0 */ \
  /*   91: */ 0x66,0x0f,0x6f,0x4d,0xa0,           /* movdqa -0x60(%rbp),%xmm1 */ \
  /*   96: */ 0x66,0x0f,0x6f,0x55,0x90,           /* movdqa -0x70(%rbp),%xmm2 */ \
  /*   9b: */ 0x66,0x0f,0x6f,0x5d,0x80,           /* movdqa -0x80(%rbp),%xmm3 */ \
  /*   a0: */ 0x66,0x0f,0x6f,0xa5,0x70,0xff,0xff, /* movdqa -0x90(%rbp),%xmm4 */ \
  /*   a7: */ 0xff,                               /*  */ \
  /*   a8: */ 0x66,0x0f,0x6f,0xad,0x60,0xff,0xff, /* movdqa -0xa0(%rbp),%xmm5 */ \
  /*   af: */ 0xff,                               /*  */ \
  /*   b0: */ 0x66,0x0f,0x6f,0xb5,0x50,0xff,0xff, /* movdqa -0xb0(%rbp),%xmm6 */ \
  /*   b7: */ 0xff,                               /*  */ \
  /*   b8: */ 0x66,0x0f,0x6f,0xbd,0x40,0xff,0xff, /* movdqa -0xc0(%rbp),%xmm7 */ \
  /*   bf: */ 0xff,                               /*  */ \
  /*   c0: */ 0xc9,                               /* leaveq  */ \
  /*   c1: */ 0xff,0x25,0x09,0x00,0x00,0x00,      /* jmpq   *0x9(%rip)        # d0 <hook_func_addr> */ \
  /*   c7: */ 0x90,                               /* nop */ \
  /* 00000000000000c8 <hook_caller_addr>: */ \
  /*   c8: */ 0x0f,0x1f,0x40,0x00,                /* nopl   0x0(%rax) */ \
  /*   cc: */ 0x0f,0x1f,0x40,0x00,                /* nopl   0x0(%rax) */ \
  /* 00000000000000d0 <hook_func_addr>: */ \
  /*   d0: */ 0x0f,0x1f,0x40,0x00,                /* nopl   0x0(%rax) */ \
  /*   d4: */ 0x0f,0x1f,0x40,0x00,                /* nopl   0x0(%rax) */ \
  }
#define TRANSIT_HOOK_CALLER_ADDR 0xc8
#define TRANSIT_HOOK_FUNC_ADDR 0xd0
#define TRANSIT_CODE_SIZE 0xd8

#elif defined(CPU_X86)

// Windows 32-bit and Linux i686
#define TRANSIT_CODE_TEMPLATE { \
  /* 00000000 <transit>: */ \
  /*    0: */ 0x55,                               /* push   %ebp */ \
  /*    1: */ 0x89,0xe5,                          /* mov    %esp,%ebp */ \
  /*    3: */ 0x51,                               /* push   %ecx */ \
  /*    4: */ 0x52,                               /* push   %edx */ \
  /*    5: */ 0xe8,0x1e,0x00,0x00,0x00,           /* call   28 <get_eip> */ \
  /*    a: */ 0x8d,0x40,0xf6,                     /* lea    -0xa(%eax),%eax */ \
  /*    d: */ 0x83,0xec,0x0c,                     /* sub    $0xc,%esp */ \
  /*   10: */ 0x50,                               /* push   %eax */ \
  /*   11: */ 0x8d,0x80,0x2c,0x00,0x00,0x00,      /* lea    0x2c(%eax),%eax */ \
  /*   17: */ 0xff,0x10,                          /* call   *(%eax) */ \
  /*   19: */ 0x58,                               /* pop    %eax */ \
  /*   1a: */ 0x83,0xc4,0x0c,                     /* add    $0xc,%esp */ \
  /*   1d: */ 0x5a,                               /* pop    %edx */ \
  /*   1e: */ 0x59,                               /* pop    %ecx */ \
  /*   1f: */ 0xc9,                               /* leave   */ \
  /*   20: */ 0x8d,0x80,0x30,0x00,0x00,0x00,      /* lea    0x30(%eax),%eax */ \
  /*   26: */ 0xff,0x20,                          /* jmp    *(%eax) */ \
  /* 00000028 <get_eip>: */ \
  /*   28: */ 0x8b,0x04,0x24,                     /* mov    (%esp),%eax */ \
  /*   2b: */ 0xc3,                               /* ret     */ \
  /* 0000002c <hook_caller_addr>: */ \
  /*   2c: */ 0x0f,0x1f,0x40,0x00,                /* nopl   0x0(%eax) */ \
  /* 00000030 <hook_func_addr>: */ \
  /*   30: */ 0x0f,0x1f,0x40,0x00,                /* nopl   0x0(%eax) */ \
  }
#define TRANSIT_HOOK_CALLER_ADDR 0x2c
#define TRANSIT_HOOK_FUNC_ADDR 0x30
#define TRANSIT_CODE_SIZE 0x34

#elif defined(CPU_ARM64)

// ARM64
#define TRANSIT_CODE_TEMPLATE { \
  /* 0000000000000000 <transit>: */ \
  /*    0: */ 0xa9bf7bfd,                         /* stp x29, x30, [sp, #-16]! */ \
  /*    4: */ 0x910003fd,                         /* mov x29, sp */ \
  /*    8: */ 0xa9bf03e1,                         /* stp x1, x0, [sp, #-16]! */ \
  /*    c: */ 0xa9bf0be3,                         /* stp x3, x2, [sp, #-16]! */ \
  /*   10: */ 0xa9bf13e5,                         /* stp x5, x4, [sp, #-16]! */ \
  /*   14: */ 0xa9bf1be7,                         /* stp x7, x6, [sp, #-16]! */ \
  /*   18: */ 0xa9bf4be8,                         /* stp x8, x18, [sp, #-16]! */ \
  /*   1c: */ 0xadbf03e1,                         /* stp q1, q0, [sp, #-32]! */ \
  /*   20: */ 0xadbf0be3,                         /* stp q3, q2, [sp, #-32]! */ \
  /*   24: */ 0xadbf13e5,                         /* stp q5, q4, [sp, #-32]! */ \
  /*   28: */ 0xadbf1be7,                         /* stp q7, q6, [sp, #-32]! */ \
  /*   2c: */ 0x10fffea0,                         /* adr x0, 0 <transit> */ \
  /*   30: */ 0x580001c9,                         /* ldr x9, 68 <hook_caller_addr> */ \
  /*   34: */ 0xd63f0120,                         /* blr x9 */ \
  /*   38: */ 0xacc11be7,                         /* ldp q7, q6, [sp], #32 */ \
  /*   3c: */ 0xacc113e5,                         /* ldp q5, q4, [sp], #32 */ \
  /*   40: */ 0xacc10be3,                         /* ldp q3, q2, [sp], #32 */ \
  /*   44: */ 0xacc103e1,                         /* ldp q1, q0, [sp], #32 */ \
  /*   48: */ 0xa8c14be8,                         /* ldp x8, x18, [sp], #16 */ \
  /*   4c: */ 0xa8c11be7,                         /* ldp x7, x6, [sp], #16 */ \
  /*   50: */ 0xa8c113e5,                         /* ldp x5, x4, [sp], #16 */ \
  /*   54: */ 0xa8c10be3,                         /* ldp x3, x2, [sp], #16 */ \
  /*   58: */ 0xa8c103e1,                         /* ldp x1, x0, [sp], #16 */ \
  /*   5c: */ 0xa8c17bfd,                         /* ldp x29, x30, [sp], #16 */ \
  /*   60: */ 0x58000089,                         /* ldr x9, 70 <hook_func_addr> */ \
  /*   64: */ 0xd61f0120,                         /* br x9 */ \
  /* 0000000000000068 <hook_caller_addr>: */ \
  /*   68: */ 0xd503201f,                         /* nop */ \
  /*   6c: */ 0xd503201f,                         /* nop */ \
  /* 0000000000000070 <hook_func_addr>: */ \
  /*   70: */ 0xd503201f,                         /* nop */ \
  /*   74: */ 0xd503201f,                         /* nop */ \
  }
#define TRANSIT_HOOK_CALLER_ADDR 0x1a
#define TRANSIT_HOOK_FUNC_ADDR 0x1c
#define TRANSIT_CODE_SIZE 0x1e

#endif
