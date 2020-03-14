#ifndef FUNCHOOK_X86_H
#define FUNCHOOK_X86_H 1

#define MAX_INSN_LEN 16
#define MAX_INSN_CHECK_SIZE 256

#define JUMP32_SIZE 5
#ifdef CPU_X86_64
#define JUMP64_SIZE 14
#endif

#define TRAMPOLINE_SIZE (JUMP32_SIZE + (MAX_INSN_LEN - 1) + JUMP32_SIZE)

typedef struct funchook_entry {
    void *target_func;
    void *hook_func;
    uint8_t trampoline[TRAMPOLINE_SIZE];
    uint8_t old_code[JUMP32_SIZE];
    uint8_t new_code[JUMP32_SIZE];
#ifdef CPU_X86_64
    uint8_t transit[JUMP64_SIZE];
#endif
} funchook_entry_t;

typedef struct {
    const uint8_t *dst_addr;
    intptr_t src_addr_offset;
    intptr_t pos_offset;
} ip_displacement_entry_t;

typedef struct {
    ip_displacement_entry_t disp[2];
} ip_displacement_t;

#endif
