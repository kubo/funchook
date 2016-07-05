/* -*- indent-tabs-mode: nil -*-
 *
 * This file is part of Duckhook.
 * https://github.com/kubo/duckhook
 *
 * Duckhook is free software: you can redistribute it and/or modify it
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
 * Duckhook is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Duckhook. If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <distorm.h>
#include <mnemonics.h>
#ifdef WIN32
#include <windows.h>
#endif
#include "duckhook_internal.h"

#if 0
#define PRINT_INSTRUCTION
#endif

#ifdef PRINT_INSTRUCTION
static void print_instruction(const _CodeInfo *ci, const _DInst *di);
#endif

int duckhook_write_jump32(const uint8_t *src, const uint8_t *dst, uint8_t *out)
{
    out[0] = 0xe9;
    *(int*)(out + 1) = (int)(dst - (src + 5));
    return 0;
}

#ifdef CPU_X86_64

int duckhook_write_jump64(uint8_t *src, const uint8_t *dst)
{
    src[0] = 0xFF;
    src[1] = 0x25;
    src[2] = 0x00;
    src[3] = 0x00;
    src[4] = 0x00;
    src[5] = 0x00;
    *(const uint8_t**)(src + 6) = dst;
    return 0;
}

static int within_32bit_relative(const uint8_t *src, const uint8_t *dst)
{
    int64_t diff = (int64_t)(dst - src);
    return (INT32_MIN <= diff && diff <= INT32_MAX);
}

int duckhook_jump32_avail(const uint8_t *src, const uint8_t *dst)
{
    return within_32bit_relative(src + 5, dst);
}

#endif

int duckhook_make_trampoline(const uint8_t *func, uint8_t *trampoline)
{
    uint8_t work[MAX_INSN_LEN];
    _DInst dis[MAX_INSN_LEN];
    unsigned int di_cnt = 0;
    _CodeInfo ci;
    _DecodeResult decres;
    int offset = 0;
    int i;

    memcpy(work, func, MAX_INSN_LEN);

    ci.codeOffset = (_OffsetType)(size_t)func;
    ci.code = work;
    ci.codeLen = MAX_INSN_LEN;
#ifdef CPU_X86_64
    ci.dt = Decode64Bits;
#else
    ci.dt = Decode32Bits;
#endif
    ci.features = DF_NONE;
    decres = distorm_decompose64(&ci, dis, MAX_INSN_LEN, &di_cnt);
    if (decres != DECRES_SUCCESS) {
        return -1;
    }
    for (i = 0; i < di_cnt; i++) {
        const _DInst *di = &dis[i];
        int j;
        int opsiz = 0;
        int disp_offset = -1;
        int imm_offset = -1;
#ifdef PRINT_INSTRUCTION
        print_instruction(&ci, di);
#endif

#if defined(__linux) && defined(__i386)
        if (*(work + offset) == 0xe8) {
            uint8_t *target = (uint8_t *)(size_t)INSTRUCTION_GET_TARGET(di);
            if (memcmp(target, "\x8b\x1c\x24\xc3", 4) == 0) {
                /* special case to handle "call __i686.get_pc_thunk.bx"
                 * If the target instructions are "movl (%esp), %ebx; ret",
                 * use "movl di->addr + 5, %ebx" instead.
                 */
                *(work + offset) = 0xbb;
                *(uint32_t*)(work + offset + 1) = (uint32_t)(di->addr + 5);
                goto before_copy_code;
            }
            if (memcmp(target, "\x8b\x0c\x24\xc3", 4) == 0) {
                /* special case to handle "call __i686.get_pc_thunk.cx"
                 * If the target instructions are "movl (%esp), %ecx; ret",
                 * use "movl di->addr + 5, %ecx" instead.
                 */
                *(work + offset) = 0xb9;
                *(uint32_t*)(work + offset + 1) = (uint32_t)(di->addr + 5);
                goto before_copy_code;
            }
        }
#endif

        for (j = 0; j < OPERANDS_NO && di->ops[j].type != O_NONE; j++) {
            const _Operand *op = &di->ops[j];
            switch (op->type) {
            case O_IMM:
                opsiz += op->size / 8;
                break;
            case O_PC:
                if (op->size != 32) {
                    return -1;
                }
                imm_offset = opsiz;
                opsiz += op->size / 8;
                break;
            case O_SMEM:
                if (di->dispSize != 0 && op->index == R_RIP) {
                    if (di->dispSize != 32) {
                        return -1;
                    }
                    disp_offset = opsiz;
                }
                opsiz += di->dispSize / 8;
                break;
            case O_MEM:
            case O_DISP:
                opsiz += di->dispSize / 8;
                break;
            }
        }
        if (disp_offset != -1) {
            int32_t *pos = (int32_t*)(work + offset + di->size - opsiz + disp_offset);
#ifdef CPU_X86_64
            size_t addr = (size_t)INSTRUCTION_GET_RIP_TARGET(di);
            if (!within_32bit_relative(trampoline + offset + di->size, (uint8_t*)addr)) {
                /* out of 32-bit relative addressing.
                 * reach here if code_mem_get() returns incorrect address.
                 */
                return -1;
            }
#endif
            if (*pos != (uint32_t)di->disp) {
                /* sanity check.
                 * reach here if opsiz and/or disp_offset are incorrectly
                 * estimated.
                 */
                return -1;
            }
            *pos += func - trampoline; /* fix RIP-relative offset */
        }
        if (imm_offset != -1) {
            uint32_t *pos = (uint32_t*)(work + offset + di->size - opsiz + imm_offset);
#ifdef CPU_X86_64
            size_t addr = (size_t)INSTRUCTION_GET_TARGET(di);
            if (!within_32bit_relative(trampoline + offset + di->size, (uint8_t*)addr)) {
                /* out of 32-bit relative addressing.
                 * reach here if get_buffer() returns incorrect address.
                 */
                return -1;
            }
#endif
            if (*pos != (uint32_t)di->imm.addr) {
                /* sanity check.
                 * reach here if opsiz and/or imm_offset are incorrectly
                 * estimated.
                 */
                return -1;
            }
            *pos += func - trampoline; /* fix RIP-relative offset */
        }
#if defined(__linux) && defined(__i386)
before_copy_code:
#endif
        memcpy(trampoline + offset, work + offset, di->size);
        offset += di->size;
        if (offset >= JUMP32_SIZE) {
            duckhook_write_jump32(trampoline + offset, func + offset, trampoline + offset);
            return 0;
        }
    }
    return -1;
}

#ifdef PRINT_INSTRUCTION
static void print_instruction(const _CodeInfo *ci, const _DInst *di)
{
    _DecodedInst dec;
    int i;

    distorm_format64(ci, di, &dec);
    printf("%0*lx (%02d) %-24s %s%s%s\r\n", ci->dt == Decode64Bits ? 16 : 8, (size_t)dec.offset, dec.size, (char*)dec.instructionHex.p, (char*)dec.mnemonic.p, dec.operands.length != 0 ? " " : "", (char*)dec.operands.p);
    if (di->disp != 0) {
        printf("  disp: 0x%llx, dispSize: %d\n", (unsigned long long)di->disp, di->dispSize);
    }
    for (i = 0; i < OPERANDS_NO; i++) {
        const _Operand *op = &di->ops[i];
        const char *op_type = NULL;
        switch (op->type) {
        case O_REG:
            printf("  [%d] type: REG, index: %d(%s), size: %d\n", i, op->index, GET_REGISTER_NAME(op->index), op->size);
            break;
        case O_IMM:
            op_type = "IMM";
            break;
        case O_IMM1:
            op_type = "IMM1";
            break;
        case O_IMM2:
            op_type = "IMM2";
            break;
        case O_DISP:
            op_type = "DISP";
            break;
        case O_SMEM:
            printf("  [%d] type: SMEM, index: %d(%s), size: %d\n", i, op->index, GET_REGISTER_NAME(op->index), op->size);
            break;
        case O_MEM:
            printf("  [%d] type: MEM, index: %d(%s), size: %d\n", i, op->index, GET_REGISTER_NAME(op->index), op->size);
            break;
        case O_PC:
            op_type = "PC";
            break;
        case O_PTR:
            op_type = "PTR";
            break;
        case O_NONE:
            break;
        default:
            op_type = "???";
            break;
        }
        if (op_type != NULL) {
            printf("  [%d] type: %s, index: %d, size: %d\n", i, op_type, op->index, op->size);
        }
    }
}
#endif
