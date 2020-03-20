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
#include <inttypes.h>
#include <string.h>
#include "funchook_internal.h"
#include "disasm.h"

#ifdef CPU_X86_64
#define MACHINE_MODE ZYDIS_MACHINE_MODE_LONG_64
#define ADDRESS_WIDTH ZYDIS_ADDRESS_WIDTH_64
#else
#define MACHINE_MODE ZYDIS_MACHINE_MODE_LONG_COMPAT_32
#define ADDRESS_WIDTH ZYDIS_ADDRESS_WIDTH_32
#endif

#define HEX(x) ((x) < 10 ? (x) + '0' : (x) - 10 + 'A')

int funchook_disasm_init(funchook_disasm_t *disasm, funchook_t *funchook, const uint8_t *code, size_t code_size, size_t address)
{
    if (ZydisGetVersion() != ZYDIS_VERSION) {
        funchook_set_error_message(funchook,
                                   "Invalid zydis version: expecte 0x%"PRIx64" but 0x%"PRIx64, ZYDIS_VERSION, ZydisGetVersion());
        return FUNCHOOK_ERROR_INTERNAL_ERROR;
    }

    disasm->funchook = funchook;
    ZydisDecoderInit(&disasm->decoder, MACHINE_MODE, ADDRESS_WIDTH);
    ZydisFormatterInit(&disasm->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    disasm->insn.next_address = address;
    disasm->code = code;
    disasm->code_end = code + code_size;
    return 0;
}

void funchook_disasm_cleanup(funchook_disasm_t *disasm)
{
    /* no need to free resources */
}

int funchook_disasm_next(funchook_disasm_t *disasm, const funchook_insn_t **next_insn)
{
    size_t code_size = disasm->code_end - disasm->code;
    ZyanStatus status = ZydisDecoderDecodeBuffer(&disasm->decoder, disasm->code, code_size, &disasm->insn.insn);

    if (ZYAN_SUCCESS(status)) {
        disasm->insn.next_address += disasm->insn.insn.length;
        disasm->code += disasm->insn.insn.length;
        *next_insn = &disasm->insn;
        return 0;
    }
#if 0
    if (status != ZYDIS_STATUS_NO_MORE_DATA && status != ZYDIS_STATUS_INVALID_MAP) {
        funchook_set_error_message(disasm->funchook, "Disassemble Error: 0x%08x", status);
        return FUNCHOOK_ERROR_DISASSEMBLY;
    }
#endif
    return FUNCHOOK_ERROR_END_OF_INSTRUCTION;
}

void funchook_disasm_log_instruction(funchook_disasm_t *disasm, const funchook_insn_t *insn)
{
    funchook_t *funchook = disasm->funchook;
    char buffer[256];
    size_t size = insn->insn.length;
    size_t addr = insn->next_address - size;
    const uint8_t *code = disasm->code - size;
    char hex[24 * 3];
    size_t i;

    ZydisFormatterFormatInstruction(&disasm->formatter, &insn->insn, buffer, sizeof(buffer), addr);

    for (i = 0; i < size; i++) {
        hex[i * 3 + 0] = HEX(code[i] >> 4);
        hex[i * 3 + 1] = HEX(code[i] & 0x0F);
        hex[i * 3 + 2] = ' ';
    }
    hex[size * 3 - 1] = '\0';

    funchook_log(funchook, "    "ADDR_FMT" (%02d) %-24s %s\n",
                 (size_t)addr, insn->insn.length, hex, buffer);
}

void funchook_disasm_x86_rip_relative(funchook_disasm_t *disasm, const funchook_insn_t *insn, rip_relative_t *rel_disp, rip_relative_t *rel_imm)
{
    memset(rel_disp, 0, sizeof(rip_relative_t));
    memset(rel_imm, 0, sizeof(rip_relative_t));

    if (insn->insn.raw.imm[0].offset != 0) {
        if (insn->insn.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE) {
            // Fix IP-relative jump or call
            rel_imm->addr = (uint8_t*)(size_t)(insn->next_address + insn->insn.raw.imm[0].value.s);
            rel_imm->raddr = (intptr_t)insn->insn.raw.imm[0].value.s;
            rel_imm->size = insn->insn.raw.imm[0].size;
            rel_imm->offset = insn->insn.raw.imm[0].offset;
        }
    }
    if (insn->insn.raw.disp.offset != 0) {
        int i;
        for (i = 0; i < insn->insn.operand_count; i++) {
            const ZydisDecodedOperand *op = &insn->insn.operands[i];
            if (op->mem.disp.has_displacement && op->mem.base == ZYDIS_REGISTER_RIP) {
                // Fix IP-relative addressing such as:
                //    mov eax, dword ptr [rip + 0x236eda]
                //    jmp qword ptr [rip + 0x239468]
                //    call qword ptr [rip + 0x239446]
                //    cmp dword ptr [rip + 0x2d2709], 0
                rel_disp->addr = (uint8_t*)(size_t)(insn->next_address + insn->insn.raw.disp.value);
                rel_disp->raddr = (intptr_t)insn->insn.raw.disp.value;
                rel_disp->size = insn->insn.raw.disp.size;
                rel_disp->offset = insn->insn.raw.disp.offset;
                break;
            }
        }
    }
}
