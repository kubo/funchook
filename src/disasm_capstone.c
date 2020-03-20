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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "funchook_internal.h"
#include "disasm.h"

#ifdef CPU_ARM64
#define CS_ARCH CS_ARCH_ARM64
#define CS_MODE CS_MODE_LITTLE_ENDIAN
#endif

#ifdef CPU_X86_64
#define CS_ARCH CS_ARCH_X86
#define CS_MODE CS_MODE_64
#endif

#ifdef CPU_X86
#define CS_ARCH CS_ARCH_X86
#define CS_MODE CS_MODE_32
#endif

#define LOG_DETAIL 0

#define HEX(x) ((x) < 10 ? (x) + '0' : (x) - 10 + 'A')

int funchook_disasm_init(funchook_disasm_t *disasm, funchook_t *funchook, const insn_t *code, size_t code_size, size_t address)
{
    cs_err err;

    disasm->funchook = funchook;
    disasm->index = 0;
    if ((err = cs_open(CS_ARCH, CS_MODE, &disasm->handle)) != 0) {
        funchook_set_error_message(funchook, "cs_open error: %s", cs_strerror(err));
        return FUNCHOOK_ERROR_INTERNAL_ERROR;
    }
    if ((err = cs_option(disasm->handle, CS_OPT_DETAIL, CS_OPT_ON)) != 0) {
        funchook_set_error_message(funchook, "cs_option error: %s", cs_strerror(err));
        cs_close(&disasm->handle);
        return FUNCHOOK_ERROR_INTERNAL_ERROR;
    }
    if ((disasm->count = cs_disasm(disasm->handle, (const uint8_t*)code, code_size * sizeof(insn_t), address, 0, &disasm->insns)) == 0) {
        err = cs_errno(disasm->handle);
        funchook_set_error_message(funchook, "disassemble error: %s", cs_strerror(err));
        cs_close(&disasm->handle);
        return FUNCHOOK_ERROR_DISASSEMBLY;
    }
    return 0;
}

void funchook_disasm_cleanup(funchook_disasm_t *disasm)
{
    if (disasm->count != 0) {
        cs_free(disasm->insns, disasm->count);
    }
    cs_close(&disasm->handle);
}

int funchook_disasm_next(funchook_disasm_t *disasm, const funchook_insn_t **next_insn)
{
    if (disasm->index < disasm->count) {
        *next_insn = &disasm->insns[disasm->index++];
        return 0;
    } else {
        return FUNCHOOK_ERROR_END_OF_INSTRUCTION;
    }
}

#if LOG_DETAIL
static const char *reg_name(csh handle, unsigned int reg_id)
{
    const char *name = cs_reg_name(handle, reg_id);
    return name ? name : "?";
}

static const char *group_name(csh handle, unsigned int grp_id)
{
    const char *name = cs_group_name(handle, grp_id);
    return name ? name : "?";
}
#endif

void funchook_disasm_log_instruction(funchook_disasm_t *disasm, const funchook_insn_t *insn)
{
    funchook_t *funchook = disasm->funchook;
    char hex[sizeof(insn->bytes) * 3];
    uint16_t i;

    for (i = 0; i < insn->size; i++) {
        hex[i * 3 + 0] = HEX(insn->bytes[i] >> 4);
        hex[i * 3 + 1] = HEX(insn->bytes[i] & 0x0F);
        hex[i * 3 + 2] = ' ';
    }
    hex[insn->size * 3 - 1] = '\0';
    funchook_log(funchook, "    "ADDR_FMT" (%02d) %-24s %s%s%s\n",
                 (size_t)insn->address, insn->size, hex,
                 insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str);
#if LOG_DETAIL
    cs_detail *detail = insn->detail;
    if (detail == NULL) {
        return;
    }
    if (detail->regs_read_count > 0) {
        funchook_log(funchook, "        regs_read:");
        for (i = 0; i < insn->detail->regs_read_count; i++) {
            funchook_log(funchook, " %s", reg_name(handle, insn->detail->regs_read[i]));
        }
        funchook_log(funchook, "\n");
    }
    if (detail->regs_write_count > 0) {
        funchook_log(funchook, "        regs_write:");
        for (i = 0; i < insn->detail->regs_write_count; i++) {
            funchook_log(funchook, " %s", reg_name(handle, insn->detail->regs_write[i]));
        }
        funchook_log(funchook, "\n");
    }
    if (detail->groups_count > 0) {
        funchook_log(funchook, "        groups:");
        for (i = 0; i < insn->detail->groups_count; i++) {
            funchook_log(funchook, " %s", group_name(handle, insn->detail->groups[i]));
        }
        funchook_log(funchook, "\n");
    }
#if defined(CPU_X86_64) || defined(CPU_X86)
    csh handle = disasm->handle;
    cs_x86 *x86 = &detail->x86;
    if (x86->encoding.modrm_offset != 0) {
        funchook_log(funchook, "        encoding.modrm_offset: %u\n", x86->encoding.modrm_offset);
    }
    if (x86->encoding.disp_offset != 0) {
        funchook_log(funchook, "        encoding.disp_offset: %u, size: %u\n", x86->encoding.disp_offset, x86->encoding.disp_size);
    }
    if (x86->encoding.imm_offset != 0) {
        funchook_log(funchook, "        encoding.imm_offset: %u, size: %u\n", x86->encoding.imm_offset, x86->encoding.imm_size);
    }
    if (x86->encoding.disp_offset != 0) {
        int64_t i64;
        const char *sign;

        if (x86->disp >= 0) {
            i64 = x86->disp;
            sign = "";
        } else {
            i64 = -x86->disp;
            sign = "-";
        }
        funchook_log(funchook, "        disp: %s0x%"PRIx64"\n", sign, i64);
    }
    if (x86->sib_index != X86_REG_INVALID) {
        funchook_log(funchook, "        sib_index: %s, sib_scale: %u\n",
                     reg_name(handle, x86->sib_index), x86->sib_scale);
    }
    if (x86->sib_base != X86_REG_INVALID) {
        funchook_log(funchook, "        sib_base: %s\n",
                     reg_name(handle, x86->sib_base));
    }
    if (x86->op_count > 0) {
        for (i = 0; i < x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            int64_t i64;
            const char *sign;
            switch (op->type) {
            case X86_OP_INVALID:
                funchook_log(funchook, "        operands[%u]: INVALID\n", i);
                break;
            case X86_OP_REG:
                funchook_log(funchook, "        operands[%u]: REG %s (size:%u)\n", i, reg_name(handle, op->reg), op->size);
                break;
            case X86_OP_IMM:
                if (op->imm >= 0) {
                    i64 = op->imm;
                    sign = "";
                } else {
                    i64 = -op->imm;
                    sign = "-";
                }
                funchook_log(funchook, "        operands[%u]: IMM %s0x%"PRIx64"\n", i, sign, i64);
                break;
            case X86_OP_MEM:
                if (op->mem.disp >= 0) {
                    i64 = op->mem.disp;
                    sign = "";
                } else {
                    i64 = -op->mem.disp;
                    sign = "-";
                }
                funchook_log(funchook, "        operands[%u]: MEM seg:%s, base:%s, index:%s, scale:%u, disp:%s0x%"PRIx64"\n",
                             i, reg_name(handle, op->mem.segment),
                             reg_name(handle, op->mem.base), reg_name(handle, op->mem.index), op->mem.scale, sign, i64);
                break;
            }
        }
    }
#endif /* defined(CPU_X86_64) || defined(CPU_X86) */
#endif /* LOG_DETAIL */
}

#if defined(CPU_ARM64)
// Check only registers in FUNCHOOK_ARM64_CORRUPTIBLE_REGS
static uint32_t cs2funchook_reg(uint16_t reg)
{
    switch (reg) {
    case ARM64_REG_W9:
    case ARM64_REG_X9:
        return FUNCHOOK_ARM64_REG_X9;
    case ARM64_REG_W10:
    case ARM64_REG_X10:
        return FUNCHOOK_ARM64_REG_X10;
    case ARM64_REG_W11:
    case ARM64_REG_X11:
        return FUNCHOOK_ARM64_REG_X11;
    case ARM64_REG_W12:
    case ARM64_REG_X12:
        return FUNCHOOK_ARM64_REG_X12;
    case ARM64_REG_W13:
    case ARM64_REG_X13:
        return FUNCHOOK_ARM64_REG_X13;
    case ARM64_REG_W14:
    case ARM64_REG_X14:
        return FUNCHOOK_ARM64_REG_X14;
    case ARM64_REG_W15:
    case ARM64_REG_X15:
        return FUNCHOOK_ARM64_REG_X15;
    default:
        return 0;
    }
}

funchook_insn_info_t funchook_disasm_arm64_insn_info(funchook_disasm_t *disasm, const funchook_insn_t *insn)
{
    const cs_detail *detail = insn->detail;
    funchook_insn_info_t info = {0,};
    cs_regs rregs, wregs;
    uint8_t rregs_cnt, wregs_cnt, i;

    switch (insn->id) {
    case ARM64_INS_ADR:
        info.insn_id = FUNCHOOK_ARM64_INSN_ADR;
        break;
    case ARM64_INS_ADRP:
        info.insn_id = FUNCHOOK_ARM64_INSN_ADRP;
        break;
    case ARM64_INS_B:
        if (detail->arm64.cc == ARM64_CC_INVALID) {
            info.insn_id = FUNCHOOK_ARM64_INSN_B;
        } else {
            info.insn_id = FUNCHOOK_ARM64_INSN_B_cond;
        }
        break;
    case ARM64_INS_BL:
        info.insn_id = FUNCHOOK_ARM64_INSN_BL;
        break;
    case ARM64_INS_CBNZ:
        info.insn_id = FUNCHOOK_ARM64_INSN_CBNZ;
        break;
    case ARM64_INS_CBZ:
        info.insn_id = FUNCHOOK_ARM64_INSN_CBZ;
        break;
    case ARM64_INS_LDR:
        info.insn_id = FUNCHOOK_ARM64_INSN_LDR;
        break;
    case ARM64_INS_LDRSW:
        info.insn_id = FUNCHOOK_ARM64_INSN_LDRSW;
        break;
    case ARM64_INS_PRFM:
        info.insn_id = FUNCHOOK_ARM64_INSN_PRFM;
        break;
    case ARM64_INS_TBNZ:
        info.insn_id = FUNCHOOK_ARM64_INSN_TBNZ;
        break;
    case ARM64_INS_TBZ:
        info.insn_id = FUNCHOOK_ARM64_INSN_TBZ;
        break;
    }

    if (!cs_regs_access(disasm->handle, insn, rregs, &rregs_cnt, wregs, &wregs_cnt)) {
        for (i = 0; i < rregs_cnt; i++) {
            info.regs |= cs2funchook_reg(rregs[i]);
        }
        for (i = 0; i < wregs_cnt; i++) {
            info.regs |= cs2funchook_reg(wregs[i]);
        }
    }
    return info;
}
#endif /* defined(CPU_ARM64) */

#if defined(CPU_X86) || defined(CPU_X86_64)
void funchook_disasm_x86_rip_relative(funchook_disasm_t *disasm, const funchook_insn_t *insn, rip_relative_t *rel_disp, rip_relative_t *rel_imm)
{
    int i;
    cs_x86 *x86 = &insn->detail->x86;

    memset(rel_disp, 0, sizeof(rip_relative_t));
    memset(rel_imm, 0, sizeof(rip_relative_t));

    if (x86->encoding.imm_offset != 0) {
        for (i = 0; i < insn->detail->groups_count; i++) {
            if (insn->detail->groups[i] == X86_GRP_BRANCH_RELATIVE) {
                intptr_t imm = 0;
                if (x86->encoding.imm_size == 4) {
                    imm = *(int32_t*)(insn->bytes + x86->encoding.imm_offset);
                } else if (x86->encoding.imm_size == 1) {
                    imm = *(int8_t*)(insn->bytes + x86->encoding.imm_offset);
                } else {
                    // TODO:
                }
                // Fix IP-relative jump or call:
                rel_imm->addr = (uint8_t*)(size_t)(insn->address + insn->size + imm);
                rel_imm->raddr = imm;
                rel_imm->size = x86->encoding.imm_size * 8;
                rel_imm->offset = x86->encoding.imm_offset;
                break;
            }
        }
    }
    if (x86->encoding.disp_offset != 0) {
        for (i = 0; i < x86->op_count; i++) {
            const cs_x86_op *op = &x86->operands[i];
            if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP) {
                // Fix IP-relative addressing such as:
                //    mov eax, dword ptr [rip + 0x236eda]
                //    jmp qword ptr [rip + 0x239468]
                //    call qword ptr [rip + 0x239446]
                //    cmp dword ptr [rip + 0x2d2709], 0
                rel_disp->addr = (uint8_t*)(size_t)(insn->address + insn->size + x86->disp);
                rel_disp->raddr = (intptr_t)x86->disp;
                rel_disp->size = x86->encoding.disp_size * 8;
                rel_disp->offset = x86->encoding.disp_offset;
            }
        }
    }
}
#endif /* defined(CPU_X86) || defined(CPU_X86_64) */
