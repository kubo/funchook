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
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "funchook_internal.h"
#include "disasm.h"

// imm26 at bit 25~0
#define IMM26_MASK 0x03FFFFFF
#define IMM26_OFFSET(ins) ((int64_t)(int32_t)((ins) << 6) >> 4)

// imm19 at bit 23~5
#define IMM19_MASK 0x00FFFFE0
#define IMM19_OFFSET(ins) (((int64_t)(int32_t)((ins) << 8) >> 11) & ~0x3l)
#define IMM19_RESET(ins) ((ins) & ~IMM19_MASK)
#define TO_IMM19(imm19) ((imm19) << 5)

// immhi at bit 23-5 and immlo at bit 30~29, used by ADR and ADRP
#define IMM_ADR_OFFSET(ins) (IMM19_OFFSET(ins) | ((ins) >> 29) & 0x3)

// imm14 at bit 18~5
#define IMM14_MASK 0x0007FFE0
#define IMM14_OFFSET(ins) (((int64_t)(int32_t)((ins) << 13) >> 16) & ~0x3l)
#define IMM14_RESET(ins) ((ins) & ~IMM14_MASK)
#define TO_IMM14(imm14) ((imm14) << 5)

// Rd and Rt at bit 4~0
#define RD_MASK 0x0000001F
#define RD_REGNO(ins) ((ins) & RD_MASK)
#define RT_REGNO(ins) ((ins) & RD_MASK)

// Rn at bit 9~5
#define RN_MASK 0x000003E0
#define RN_REGNO(ins) (((ins) & RN_MASK) >> 5)
#define TO_RN(regno) ((regno) << 5)

#define RESET_AT(ins, pos) ((ins) & ~(1u << (pos)))
#define INVERT_AT(ins, pos) (((ins) & (1u << (pos))) ^ (1u << (pos)))

typedef struct {
    funchook_t *funchook;
    ip_displacement_t *rip_disp;
    const insn_t *src;
    const insn_t *dst_base;
    insn_t *dst;
} make_trampoline_context_t;

static int to_regno(funchook_t *funchook, uint32_t avail_regs, uint32_t *regno)
{
    if (avail_regs & FUNCHOOK_ARM64_REG_X9) {
        *regno = 9;
    } else if (avail_regs & FUNCHOOK_ARM64_REG_X10) {
        *regno = 10;
    } else if (avail_regs & FUNCHOOK_ARM64_REG_X11) {
        *regno = 11;
    } else if (avail_regs & FUNCHOOK_ARM64_REG_X12) {
        *regno = 12;
    } else if (avail_regs & FUNCHOOK_ARM64_REG_X13) {
        *regno = 13;
    } else if (avail_regs & FUNCHOOK_ARM64_REG_X14) {
        *regno = 14;
    } else if (avail_regs & FUNCHOOK_ARM64_REG_X15) {
        *regno = 15;
    } else {
        funchook_set_error_message(funchook, "All caller-saved registers are used.");
        return FUNCHOOK_ERROR_NO_AVAILABLE_REGISTERS;
    }
    return 0;
}

static int funchook_write_jump32(funchook_t *funchook, const uint32_t *src, const uint32_t *dst, uint32_t *out)
{
    intptr_t imm = ROUND_DOWN((size_t)dst, PAGE_SIZE) - ROUND_DOWN((size_t)src, PAGE_SIZE);
    size_t immlo = (imm >> 12) & 0x03;
    size_t immhi = (imm >> 14) & 0x7FFFFul;

    /* adrp x9, dst */
    out[0] = 0x90000009 | (immlo << 29) | (immhi << 5);
    /* br x9 */
    out[1] = 0xd61f0120;
    funchook_log(funchook, "  Write jump32 0x"ADDR_FMT" -> 0x"ADDR_FMT"\n",
                 (size_t)src, (size_t)dst);
    return 0;
}

static int funchook_write_jump64(funchook_t *funchook, uint32_t *src, const uint32_t *dst, uint32_t avail_regs)
{
    uint32_t regno;
    int rv = to_regno(funchook, avail_regs, &regno);
    if (rv != 0) {
        return rv;
    }
    /* ldr x9, +8 */
    src[0] = 0x58000040 | regno;
    /* br x9 */
    src[1] = 0xd61f0120 | TO_RN(regno);
    /* addr */
    *(const uint32_t**)(src + 2) = dst;
    funchook_log(funchook, "  Write jump64 0x"ADDR_FMT" -> 0x"ADDR_FMT"\n",
                 (size_t)src, (size_t)dst);
    return 0;
}

static size_t target_addr(size_t addr, uint32_t ins, uint8_t insn_id)
{
    switch (insn_id) {
    case FUNCHOOK_ARM64_INSN_ADR:
        return addr + IMM_ADR_OFFSET(ins);
    case FUNCHOOK_ARM64_INSN_ADRP:
        return ROUND_DOWN(addr, PAGE_SIZE) + (IMM_ADR_OFFSET(ins) << 12);
    case FUNCHOOK_ARM64_INSN_B:
    case FUNCHOOK_ARM64_INSN_BL:
        return addr + IMM26_OFFSET(ins);
    case FUNCHOOK_ARM64_INSN_LDR:
    case FUNCHOOK_ARM64_INSN_LDRSW:
    case FUNCHOOK_ARM64_INSN_PRFM:
        if (ins & 0x20000000) {
            return 0;
        }
        /* FALLTHROUGH */
    case FUNCHOOK_ARM64_INSN_B_cond:
    case FUNCHOOK_ARM64_INSN_CBNZ:
    case FUNCHOOK_ARM64_INSN_CBZ:
        return addr + IMM19_OFFSET(ins);
    case FUNCHOOK_ARM64_INSN_TBNZ:
    case FUNCHOOK_ARM64_INSN_TBZ:
        return addr + IMM14_OFFSET(ins);
    }
    return 0;
}

int funchook_make_trampoline(funchook_t *funchook, ip_displacement_t *disp, const insn_t *func, insn_t *trampoline, size_t *trampoline_size)
{
    make_trampoline_context_t ctx;
    funchook_disasm_t disasm;
    int rv;
    unsigned int i;
    const funchook_insn_t *insn;
    uint32_t avail_regs = FUNCHOOK_ARM64_CORRUPTIBLE_REGS;
    size_t *literal_pool = (size_t*)(trampoline + LITERAL_POOL_OFFSET);

#define LDR_ADDR(regno, addr) do { \
    int imm19__ = ((size_t)literal_pool - (size_t)ctx.dst) >> 2; \
    *(literal_pool++) = (addr); \
    *(ctx.dst++) = 0x58000000 | TO_IMM19(imm19__) | (regno); \
} while (0)
#define BR_BY_REG(regno) do { \
    *(ctx.dst++) = 0xD61F0000 | TO_RN(regno); \
} while (0)

    memset(disp, 0, sizeof(*disp));
    memset(trampoline, 0, TRAMPOLINE_BYTE_SIZE);
    *trampoline_size = 0;
    ctx.funchook = funchook;
    ctx.src = func;
    ctx.dst_base = ctx.dst = trampoline;

    rv = funchook_disasm_init(&disasm, funchook, func, MAX_INSN_CHECK_SIZE, (size_t)func);
    if (rv != 0) {
        return rv;
    }

    funchook_log(funchook, "  Original Instructions:\n");
    while ((rv = funchook_disasm_next(&disasm, &insn)) == 0) {
        funchook_insn_info_t info = funchook_disasm_arm64_insn_info(&disasm, insn);
        uint32_t ins = *ctx.src;
        size_t addr;
        uint32_t regno;

        funchook_disasm_log_instruction(&disasm, insn);
        avail_regs &= ~info.regs;
        switch (info.insn_id) {
        default:
            *(ctx.dst++) = ins;
            break;
        case FUNCHOOK_ARM64_INSN_ADR:
            addr = (size_t)ctx.src + IMM_ADR_OFFSET(ins);
            // ldr xd, <label containing addr>
            LDR_ADDR(RD_REGNO(ins), addr);
            break;
        case FUNCHOOK_ARM64_INSN_ADRP:
            addr = ROUND_DOWN((size_t)ctx.src, PAGE_SIZE) + (IMM_ADR_OFFSET(ins) << 12);
            // ldr xd, <label containing addr>
            LDR_ADDR(RD_REGNO(ins), addr);
            break;
        case FUNCHOOK_ARM64_INSN_B_cond:
            addr = (size_t)ctx.src + IMM19_OFFSET(ins);
            rv = to_regno(funchook, avail_regs, &regno);
            if (rv != 0) {
                goto cleanup;
            }
            if ((ins & 0x0F) != 0x0E) {
                // invert condition and skip two instructions
                *(ctx.dst++) = IMM19_RESET(RESET_AT(ins, 0)) | TO_IMM19(3) | INVERT_AT(ins, 0);
            }
            // ldr xt, <label containing addr>
            LDR_ADDR(regno, addr);
            // br xn
            BR_BY_REG(regno);
            break;
        case FUNCHOOK_ARM64_INSN_B:
        case FUNCHOOK_ARM64_INSN_BL:
            addr = (size_t)ctx.src + IMM26_OFFSET(ins);
            rv = to_regno(funchook, avail_regs, &regno);
            if (rv != 0) {
                goto cleanup;
            }
            // ldr xt, <label containing addr>
            LDR_ADDR(regno, addr);
            // br xn or blr xn
            *(ctx.dst++) = 0xD61F0000 | (ins & 0x80000000) >> 10 | TO_RN(regno);
            break;
        case FUNCHOOK_ARM64_INSN_CBNZ:
        case FUNCHOOK_ARM64_INSN_CBZ:
            addr = (size_t)ctx.src + IMM19_OFFSET(ins);
            rv = to_regno(funchook, avail_regs, &regno);
            if (rv != 0) {
                goto cleanup;
            }
            // invert condition and skip two instructions
            *(ctx.dst++) = IMM19_RESET(RESET_AT(ins, 24)) | INVERT_AT(ins, 24) | TO_IMM19(3);
            // ldr xd, <label containing addr>
            LDR_ADDR(regno, addr);
            // br xd
            BR_BY_REG(regno);
            break;
        case FUNCHOOK_ARM64_INSN_LDR:
        case FUNCHOOK_ARM64_INSN_LDRSW:
        case FUNCHOOK_ARM64_INSN_PRFM:
            if (ins & 0x20000000) {
                *(ctx.dst++) = ins;
            } else {
                addr = (size_t)ctx.src + IMM19_OFFSET(ins);
                rv = to_regno(funchook, avail_regs, &regno);
                if (rv != 0) {
                    goto cleanup;
                }
                // ldr xn, <label containing addr>
                LDR_ADDR(regno, addr);
                switch (ins >> 24) {
                case 0x18: // 0001 1000 : LDR <Wt>, <label>
                    // ldr wt, xn
                    *(ctx.dst++) = 0xB9400000 | TO_RN(regno) | RT_REGNO(ins);
                    break;
                case 0x58: // 0101 1000 : LDR <Xt>, <label>
                    // ldr xt, xn
                    *(ctx.dst++) = 0xF9400000 | TO_RN(regno) | RT_REGNO(ins);
                    break;
                case 0x98: // 1001 1000 : LDRSW <Xt>, <label>
                    // ldrsw xt, xn
                    *(ctx.dst++) = 0xB9800000 | TO_RN(regno) | RT_REGNO(ins);
                    break;
                case 0x1C: // 0001 1100 : LDR <St>, <label> (32-bit variant)
                    // ldr st, xn
                    *(ctx.dst++) = 0xBD400000 | TO_RN(regno) | RT_REGNO(ins);
                    break;
                case 0x5C: // 0101 1100 : LDR <Dt>, <label> (64-bit variant)
                    // ldr dt, xn
                    *(ctx.dst++) = 0xFD400000 | TO_RN(regno) | RT_REGNO(ins);
                    break;
                case 0x9C: // 1001 1100 : LDR <Qt>, <label> (128-bit variant)
                    // ldr qt, xn
                    *(ctx.dst++) = 0x3DC00000 | TO_RN(regno) | RT_REGNO(ins);
                    break;
                case 0xD8: // 1101 1000 : PRFM <prfop>, <label>
                    // prfm(immediate) <prfop>, [xn]
                    *(ctx.dst++) = 0xF9800000 | TO_RN(regno) | RT_REGNO(ins);
                    break;
                default:
                    funchook_set_error_message(funchook, "Unknonw instruction: 0x%08x", ins);
                    rv = FUNCHOOK_ERROR_INTERNAL_ERROR;
                    goto cleanup;
                }
            }
            break;
        case FUNCHOOK_ARM64_INSN_TBNZ:
        case FUNCHOOK_ARM64_INSN_TBZ:
            addr = (size_t)ctx.src + IMM14_OFFSET(ins);
            rv = to_regno(funchook, avail_regs, &regno);
            if (rv != 0) {
                goto cleanup;
            }
            // invert condition and skip two instructions
            *(ctx.dst++) = IMM14_RESET(RESET_AT(ins, 24)) | INVERT_AT(ins, 24) | TO_IMM14(3);
            // ldr xd, <label containing addr>
            LDR_ADDR(regno, addr);
            // br xd
            BR_BY_REG(regno);
            break;
        }
        ctx.src++;
        if (ctx.src - func >= JUMP32_SIZE) {
            rv = to_regno(funchook, avail_regs, &regno);
            if (rv != 0) {
                goto cleanup;
            }
            // ldr xn, #
            LDR_ADDR(regno, (size_t)ctx.src);
            // br xn
            BR_BY_REG(regno);

            *trampoline_size = ctx.dst - ctx.dst_base;
            while ((rv = funchook_disasm_next(&disasm, &insn)) == 0) {
                funchook_insn_info_t info = funchook_disasm_arm64_insn_info(&disasm, insn);
                funchook_disasm_log_instruction(&disasm, insn);
                const insn_t *target = (const insn_t *)target_addr((size_t)ctx.src, *ctx.src, info.insn_id);
                if (func < target && target < func + JUMP32_SIZE) {
                    /* jump to the hot-patched region. */
                    funchook_set_error_message(funchook, "instruction jumping back to the hot-patched region was found");
                    rv = FUNCHOOK_ERROR_FOUND_BACK_JUMP;
                    goto cleanup;
                }
            }
            break;
        }
    }
    if (rv != FUNCHOOK_ERROR_END_OF_INSTRUCTION) {
        goto cleanup;
    }
    rv = 0;
    if (ctx.src - func < JUMP32_SIZE) {
        funchook_set_error_message(funchook, "Too short instructions");
        rv = FUNCHOOK_ERROR_TOO_SHORT_INSTRUCTIONS;
        goto cleanup;
    }
cleanup:
    funchook_disasm_cleanup(&disasm);
    return rv;
}

int funchook_fix_code(funchook_t *funchook, funchook_entry_t *entry, const ip_displacement_t *disp, const void *func, const void *hook_func)
{
    /* func -> transit */
    funchook_write_jump32(funchook, func, entry->transit, entry->new_code);
    /* transit -> hook_func */
    funchook_write_jump64(funchook, entry->transit, hook_func, FUNCHOOK_ARM64_REG_X9);
    return 0;
}
