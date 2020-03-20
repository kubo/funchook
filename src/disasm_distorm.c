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

int funchook_disasm_init(funchook_disasm_t *disasm, funchook_t *funchook, const uint8_t *code, size_t code_size, size_t address)
{
    _DecodeResult decres;

    disasm->funchook = funchook;
    disasm->ci.codeOffset = address;
    disasm->ci.code = code;
    disasm->ci.codeLen = (int)code_size;
#ifdef CPU_X86_64
    disasm->ci.dt = Decode64Bits;
#else
    disasm->ci.dt = Decode32Bits;
#endif
    disasm->ci.features = DF_STOP_ON_RET;
    disasm->idx = 0;
    decres = distorm_decompose64(&disasm->ci, disasm->dis, MAX_INSN_CHECK_SIZE, &disasm->cnt);
    if (decres != DECRES_SUCCESS) {
        funchook_set_error_message(funchook, "Disassemble Error: %d", decres);
        return FUNCHOOK_ERROR_DISASSEMBLY;
    }
    return 0;
}

void funchook_disasm_cleanup(funchook_disasm_t *disasm)
{
    /* no need to free resources */
}

int funchook_disasm_next(funchook_disasm_t *disasm, const funchook_insn_t **next_insn)
{
    if (disasm->idx < disasm->cnt) {
        *next_insn = &disasm->dis[disasm->idx++];
        return 0;
    } else {
        return FUNCHOOK_ERROR_END_OF_INSTRUCTION;
    }
}

void funchook_disasm_log_instruction(funchook_disasm_t *disasm, const funchook_insn_t *insn)
{
    _DecodedInst dec;
    distorm_format64(&disasm->ci, insn, &dec);
    funchook_log(disasm->funchook, "    "ADDR_FMT" (%02d) %-24s %s%s%s\n",
                 (size_t)dec.offset, dec.size, (char*)dec.instructionHex.p,
                 (char*)dec.mnemonic.p, dec.operands.length != 0 ? " " : "", (char*)dec.operands.p);
}

void funchook_disasm_x86_rip_relative(funchook_disasm_t *disasm, const funchook_insn_t *insn, rip_relative_t *rel_disp, rip_relative_t *rel_imm)
{
    int opsiz = 0;
    int disp_offset = 0;
    int imm_offset = 0;
    int i;

    memset(rel_disp, 0, sizeof(rip_relative_t));
    memset(rel_imm, 0, sizeof(rip_relative_t));

    /*
     * Estimate total operand size and RIP-relative address offsets.
     */
    for (i = 0; i < OPERANDS_NO && insn->ops[i].type != O_NONE; i++) {
        const _Operand *op = &insn->ops[i];
        switch (op->type) {
        case O_IMM:
            opsiz += op->size / 8;
            break;
        case O_PC:
            rel_imm->addr = (uint8_t*)(size_t)(insn->addr + insn->size + insn->imm.addr);
            rel_imm->raddr = (intptr_t)insn->imm.addr;
            rel_imm->size = op->size;
            imm_offset = opsiz;
            opsiz += op->size / 8;
            break;
        case O_SMEM:
            if (insn->dispSize != 0 && op->index == R_RIP) {
                rel_disp->addr = (uint8_t*)(size_t)(insn->addr + insn->size + insn->disp);
                rel_disp->raddr = (intptr_t)insn->disp;
                rel_disp->size = insn->dispSize;
                disp_offset = opsiz;
            }
            opsiz += insn->dispSize / 8;
            break;
        case O_MEM:
        case O_DISP:
            opsiz += insn->dispSize / 8;
            break;
        }
    }
    switch (insn->opcode) {
    /* CMPSD */
    case I_CMPEQSD:
    case I_CMPLTSD:
    case I_CMPLESD:
    case I_CMPUNORDSD:
    case I_CMPNEQSD:
    case I_CMPNLTSD:
    case I_CMPNLESD:
    case I_CMPORDSD:
    case I_VCMPEQSD:
    case I_VCMPLTSD:
    case I_VCMPLESD:
    case I_VCMPUNORDSD:
    case I_VCMPNEQSD:
    case I_VCMPNLTSD:
    case I_VCMPNLESD:
    case I_VCMPORDSD:
    case I_VCMPEQ_UQSD:
    case I_VCMPNGESD:
    case I_VCMPNGTSD:
    case I_VCMPFALSESD:
    case I_VCMPNEQ_OQSD:
    case I_VCMPGESD:
    case I_VCMPGTSD:
    case I_VCMPTRUESD:
    case I_VCMPEQ_OSSD:
    case I_VCMPLT_OQSD:
    case I_VCMPLE_OQSD:
    case I_VCMPUNORD_SSD:
    case I_VCMPNEQ_USSD:
    case I_VCMPNLT_UQSD:
    case I_VCMPNLE_UQSD:
    case I_VCMPORD_SSD:
    case I_VCMPEQ_USSD:
    case I_VCMPNGE_UQSD:
    case I_VCMPNGT_UQSD:
    case I_VCMPFALSE_OSSD:
    case I_VCMPNEQ_OSSD:
    case I_VCMPGE_OQSD:
    case I_VCMPGT_OQSD:
    /* CMPSS */
    case I_CMPEQSS:
    case I_CMPLTSS:
    case I_CMPLESS:
    case I_CMPUNORDSS:
    case I_CMPNEQSS:
    case I_CMPNLTSS:
    case I_CMPNLESS:
    case I_CMPORDSS:
    case I_VCMPEQSS:
    case I_VCMPLTSS:
    case I_VCMPLESS:
    case I_VCMPUNORDSS:
    case I_VCMPNEQSS:
    case I_VCMPNLTSS:
    case I_VCMPNLESS:
    case I_VCMPORDSS:
    case I_VCMPEQ_UQSS:
    case I_VCMPNGESS:
    case I_VCMPNGTSS:
    case I_VCMPFALSESS:
    case I_VCMPNEQ_OQSS:
    case I_VCMPGESS:
    case I_VCMPGTSS:
    case I_VCMPTRUESS:
    case I_VCMPEQ_OSSS:
    case I_VCMPLT_OQSS:
    case I_VCMPLE_OQSS:
    case I_VCMPUNORD_SSS:
    case I_VCMPNEQ_USSS:
    case I_VCMPNLT_UQSS:
    case I_VCMPNLE_UQSS:
    case I_VCMPORD_SSS:
    case I_VCMPEQ_USSS:
    case I_VCMPNGE_UQSS:
    case I_VCMPNGT_UQSS:
    case I_VCMPFALSE_OSSS:
    case I_VCMPNEQ_OSSS:
    case I_VCMPGE_OQSS:
    case I_VCMPGT_OQSS:
    /* CMPPD */
    case I_CMPEQPD:
    case I_CMPLTPD:
    case I_CMPLEPD:
    case I_CMPUNORDPD:
    case I_CMPNEQPD:
    case I_CMPNLTPD:
    case I_CMPNLEPD:
    case I_CMPORDPD:
    case I_VCMPEQPD:
    case I_VCMPLTPD:
    case I_VCMPLEPD:
    case I_VCMPUNORDPD:
    case I_VCMPNEQPD:
    case I_VCMPNLTPD:
    case I_VCMPNLEPD:
    case I_VCMPORDPD:
    case I_VCMPEQ_UQPD:
    case I_VCMPNGEPD:
    case I_VCMPNGTPD:
    case I_VCMPFALSEPD:
    case I_VCMPNEQ_OQPD:
    case I_VCMPGEPD:
    case I_VCMPGTPD:
    case I_VCMPTRUEPD:
    case I_VCMPEQ_OSPD:
    case I_VCMPLT_OQPD:
    case I_VCMPLE_OQPD:
    case I_VCMPUNORD_SPD:
    case I_VCMPNEQ_USPD:
    case I_VCMPNLT_UQPD:
    case I_VCMPNLE_UQPD:
    case I_VCMPORD_SPD:
    case I_VCMPEQ_USPD:
    case I_VCMPNGE_UQPD:
    case I_VCMPNGT_UQPD:
    case I_VCMPFALSE_OSPD:
    case I_VCMPNEQ_OSPD:
    case I_VCMPGE_OQPD:
    case I_VCMPGT_OQPD:
    case I_VCMPTRUE_USPD:
    /* CMPPS */
    case I_CMPEQPS:
    case I_CMPLTPS:
    case I_CMPLEPS:
    case I_CMPUNORDPS:
    case I_CMPNEQPS:
    case I_CMPNLTPS:
    case I_CMPNLEPS:
    case I_CMPORDPS:
    case I_VCMPEQPS:
    case I_VCMPLTPS:
    case I_VCMPLEPS:
    case I_VCMPUNORDPS:
    case I_VCMPNEQPS:
    case I_VCMPNLTPS:
    case I_VCMPNLEPS:
    case I_VCMPORDPS:
    case I_VCMPEQ_UQPS:
    case I_VCMPNGEPS:
    case I_VCMPNGTPS:
    case I_VCMPFALSEPS:
    case I_VCMPNEQ_OQPS:
    case I_VCMPGEPS:
    case I_VCMPGTPS:
    case I_VCMPTRUEPS:
    case I_VCMPEQ_OSPS:
    case I_VCMPLT_OQPS:
    case I_VCMPLE_OQPS:
    case I_VCMPUNORD_SPS:
    case I_VCMPNEQ_USPS:
    case I_VCMPNLT_UQPS:
    case I_VCMPNLE_UQPS:
    case I_VCMPORD_SPS:
    case I_VCMPEQ_USPS:
    case I_VCMPNGE_UQPS:
    case I_VCMPNGT_UQPS:
    case I_VCMPFALSE_OSPS:
    case I_VCMPNEQ_OSPS:
    case I_VCMPGE_OQPS:
    case I_VCMPGT_OQPS:
    case I_VCMPTRUE_USPS:
    /* ohters */
    case I_PI2FD:
    case I_PI2FW:
    case I_PF2IW:
    case I_PF2ID:
    case I_PSWAPD:
    case I_VPBLENDVB:
    case I_PFNACC:
        opsiz++;
    }

    if (rel_disp->size > 0) {
        rel_disp->offset = insn->size - opsiz + disp_offset;
        funchook_log(disasm->funchook, "      ip-relative %08x, absolute address= "ADDR_FMT", offset=%d, size=%d\n",
                     (uint32_t)rel_disp->raddr, (size_t)rel_disp->addr, rel_disp->offset, rel_disp->size);
    }
    if (rel_imm->size > 0) {
        rel_imm->offset = insn->size - opsiz + imm_offset;
        funchook_log(disasm->funchook, "      ip-relative %08x, absolute address= "ADDR_FMT", offset=%d, size=%d\n",
                     (uint32_t)rel_imm->raddr, (size_t)rel_imm->addr, rel_imm->offset, rel_imm->size);
    }
}
