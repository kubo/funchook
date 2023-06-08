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
  /*    0: */ 0x1000000a,                         /* adr x10, 0 <transit> */ \
  /*    4: */ 0x58000069,                         /* ldr x9, 10 <hook_caller_addr> */ \
  /*    8: */ 0xd61f0120,                         /* br x9 */ \
  /*    c: */ 0xd503201f,                         /* nop */ \
  /* 0000000000000010 <hook_caller_addr>: */ \
  /*   10: */ 0xd503201f,                         /* nop */ \
  /*   14: */ 0xd503201f,                         /* nop */ \
  }
#define TRANSIT_HOOK_CALLER_ADDR 0x4
#define TRANSIT_CODE_SIZE 0x6

#endif
