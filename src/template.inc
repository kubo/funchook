// -*- c -*-
// Created by asm/template.rb

#if defined(CPU_X86_64)

// x86_64
#define TRANSIT_CODE_TEMPLATE { \
  /* 0000000000000000 <transit>: */ \
  /*    0: */ 0x4c,0x8d,0x1d,0xf9,0xff,0xff,0xff, /* lea    -0x7(%rip),%r11        # 0 <transit> */ \
  /*    7: */ 0xff,0x25,0x00,0x00,0x00,0x00,      /* jmp    *0x0(%rip)        # d <hook_caller_addr> */ \
  /* 000000000000000d <hook_caller_addr>: */ \
  /*    d: */ 0x0f,0x1f,0x40,0x00,                /* nopl   0x0(%rax) */ \
  /*   11: */ 0x0f,0x1f,0x40,0x00,                /* nopl   0x0(%rax) */ \
  }
#define TRANSIT_HOOK_CALLER_ADDR 0xd
#define TRANSIT_CODE_SIZE 0x15

#elif defined(CPU_X86)

// Windows 32-bit and Linux i686
#define TRANSIT_CODE_TEMPLATE { \
  /* 00000000 <transit>: */ \
  /*    0: */ 0xe8,0x09,0x00,0x00,0x00,           /* call   e <get_eip> */ \
  /*    5: */ 0x8d,0x40,0xfb,                     /* lea    -0x5(%eax),%eax */ \
  /*    8: */ 0xff,0xa0,0x14,0x00,0x00,0x00,      /* jmp    *0x14(%eax) */ \
  /* 0000000e <get_eip>: */ \
  /*    e: */ 0x8b,0x04,0x24,                     /* mov    (%esp),%eax */ \
  /*   11: */ 0xc3,                               /* ret     */ \
  /*   12: */ 0x66,0x90,                          /* xchg   %ax,%ax */ \
  /* 00000014 <hook_caller_addr>: */ \
  /*   14: */ 0x0f,0x1f,0x40,0x00,                /* nopl   0x0(%eax) */ \
  }
#define TRANSIT_HOOK_CALLER_ADDR 0x14
#define TRANSIT_CODE_SIZE 0x18

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
  /*   30: */ 0xd10043a1,                         /* sub x1, x29, #0x10 */ \
  /*   34: */ 0x580001e9,                         /* ldr x9, 70 <hook_caller_addr> */ \
  /*   38: */ 0xd63f0120,                         /* blr x9 */ \
  /*   3c: */ 0xacc11be7,                         /* ldp q7, q6, [sp], #32 */ \
  /*   40: */ 0xacc113e5,                         /* ldp q5, q4, [sp], #32 */ \
  /*   44: */ 0xacc10be3,                         /* ldp q3, q2, [sp], #32 */ \
  /*   48: */ 0xacc103e1,                         /* ldp q1, q0, [sp], #32 */ \
  /*   4c: */ 0xa8c14be8,                         /* ldp x8, x18, [sp], #16 */ \
  /*   50: */ 0xa8c11be7,                         /* ldp x7, x6, [sp], #16 */ \
  /*   54: */ 0xa8c113e5,                         /* ldp x5, x4, [sp], #16 */ \
  /*   58: */ 0xa8c10be3,                         /* ldp x3, x2, [sp], #16 */ \
  /*   5c: */ 0xa8c103e1,                         /* ldp x1, x0, [sp], #16 */ \
  /*   60: */ 0xa8c17bfd,                         /* ldp x29, x30, [sp], #16 */ \
  /*   64: */ 0x580000a9,                         /* ldr x9, 78 <hook_func_addr> */ \
  /*   68: */ 0xd61f0120,                         /* br x9 */ \
  /*   6c: */ 0xd503201f,                         /* nop */ \
  /* 0000000000000070 <hook_caller_addr>: */ \
  /*   70: */ 0xd503201f,                         /* nop */ \
  /*   74: */ 0xd503201f,                         /* nop */ \
  /* 0000000000000078 <hook_func_addr>: */ \
  /*   78: */ 0xd503201f,                         /* nop */ \
  /*   7c: */ 0xd503201f,                         /* nop */ \
  }
#define TRANSIT_HOOK_CALLER_ADDR 0x1c
#define TRANSIT_HOOK_FUNC_ADDR 0x1e
#define TRANSIT_CODE_SIZE 0x20

#endif
