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
#include <string.h>
#include "funchook_internal.h"
#include "disasm.h"

#define ALIGN ROUND_DOWN

#define REG_IP 12
#define REG_PC 15
#define INVERT_COND(cond)  (cond ^ 1u)

typedef struct {
    funchook_t *funchook;
    const uint16_t *src_base;
    const uint16_t *src;
    const uint16_t *dst_base;
    uint16_t *dst;
    uint32_t *literal_pool;
    funchook_insn_info_t info;
    size_t insn_size;
} make_trampoline_t;

// ldr reg, =addr
static void ldr_reg_addr(make_trampoline_t *mt, uint8_t reg, size_t addr);

static int fix_instrunction_in_trampoline(make_trampoline_t *mt);

int funchook_make_trampoline(funchook_t *funchook, ip_displacement_t *disp, const insn_t *func, insn_t *trampoline, size_t *trampoline_size)
{
    funchook_disasm_t disasm;
    const funchook_insn_t *insn;
    make_trampoline_t mt;
    int i;
    int rv;

    switch ((size_t)func % 4) {
    case 0:
        funchook_set_error_message(funchook, "ARM A32 instructions are not supported.");
        return FUNCHOOK_ERROR_DISASSEMBLY;
    case 1:
        // OK
        break;
    case 2:
    case 3:
        funchook_set_error_message(funchook, "Invalid alignment of the target function. addr=%p", func);
        return FUNCHOOK_ERROR_DISASSEMBLY;
    }
    func = (const uint16_t*)ALIGN((size_t)func, 4);

    mt.funchook = funchook;
    mt.src_base = func;
    mt.src = func;
    mt.dst_base = trampoline;
    mt.dst = trampoline;
    mt.literal_pool = (uint32_t*)(trampoline + LITERAL_POOL_OFFSET);

    memset(disp, 0, sizeof(*disp));
    memset(trampoline, 0, TRAMPOLINE_BYTE_SIZE);
    for (i = 0; i < LITERAL_POOL_OFFSET; i++) {
        trampoline[i] = 0xbf00; // nop
    }
    *trampoline_size = 0;

    rv = funchook_disasm_init(&disasm, funchook, func, MAX_INSN_CHECK_SIZE, (size_t)func);
    if (rv != 0) {
        return rv;
    }

    funchook_log(funchook, "  Original Instructions:\n");
    while ((rv = funchook_disasm_next(&disasm, &insn)) == 0) {
        mt.info = funchook_disasm_arm_insn_info(&disasm, insn);
        mt.insn_size = funchook_insn_size(insn);

        funchook_disasm_log_instruction(&disasm, insn);
        rv = fix_instrunction_in_trampoline(&mt);
        if (rv != 0) {
            goto cleanup;
        }
        mt.src += mt.insn_size;
        if (mt.src - func >= JUMP32_SIZE) {
            // ldr.w    pc, =addr
            ldr_reg_addr(&mt, REG_PC, (size_t)mt.src + 1);
            *trampoline_size = mt.dst - mt.dst_base;
            while ((rv = funchook_disasm_next(&disasm, &insn)) == 0) {
                funchook_disasm_log_instruction(&disasm, insn);
            }
            break;
        }
    }
    if (rv != FUNCHOOK_ERROR_END_OF_INSTRUCTION) {
        goto cleanup;
    }
    rv = 0;
cleanup:
    funchook_disasm_cleanup(&disasm);
    return rv;
}

int funchook_fix_code(funchook_t *funchook, funchook_entry_t *entry, const ip_displacement_t *disp, const void *func, const void *hook_func)
{
    // ldr.w    pc, [pc]
    entry->new_code[0] = 0xf8df;
    entry->new_code[1] = 0xf000;
    *(size_t*)(entry->new_code + 2) = (size_t)hook_func;
    return 0;
}

static void ldr_reg_addr(make_trampoline_t *mt, uint8_t reg, size_t addr)
{
    int imm12 = (size_t)mt->literal_pool - ALIGN((size_t)mt->dst + 4, 4);
    *(mt->literal_pool++) = (addr);
    // ldr.w ip, [pc, #imm12]
    *(mt->dst++) = 0xf8df;
    *(mt->dst++) = (reg << 12) | imm12;
}

static int fix_instrunction_in_trampoline(make_trampoline_t *mt)
{
    uint16_t ins = mt->src[0];
    uint32_t ins2 = mt->insn_size == 2 ? mt->src[1] : 0;
    uint32_t offset;
#undef PC
#define PC ((size_t)mt->src + 4)
#define BITS(n, pos, nbits) (((n) >> pos) & ((1u << nbits) - 1))
#define SIGN_EXTEND32(n, nbits) (((int32_t)((n) << (32 - (nbits)))) >> (32 - (nbits)))

    switch (mt->info.insn_id) {
    case FUNCHOOK_ARM_INSN_OTHER:
        break;
    case FUNCHOOK_ARM_INSN_B:
        offset = (uint16_t*)mt->info.addr - mt->src_base;
        if (offset != 0 && offset < JUMP32_SIZE) {
            funchook_set_error_message(mt->funchook, "instruction jumping back to the hot-patched region was found: 0x%x + %u", (uint32_t)mt->src_base, offset * 2);
            return FUNCHOOK_ERROR_FOUND_BACK_JUMP;
        }
        // b label          ; F5.1.18 B
        if (mt->info.cond < FUNCHOOK_ARM_COND_AL) {
            // b<cond> label          ; F5.1.18 B : T4
            *(mt->dst++) = 0xD002 | INVERT_COND(mt->info.cond) << 8;
        }
        // ldr ip, =addr
        ldr_reg_addr(mt, REG_IP, mt->info.addr | 1u);
        // bx ip            ; F5.1.27 BX : T1
        *(mt->dst++) = 0x4760;
        return 0;
    }

    // add Rdn, pc      ; F5.1.5 ADD, ADDS (register) : T2
    if ((ins & 0xFF78) == 0x4478) {
        uint8_t Rdn = (BITS(ins, 7, 1) << 3) | BITS(ins, 0, 3);
        if (Rdn != 12) {
            // ldr ip, =addr
            ldr_reg_addr(mt, REG_IP, PC);
            // add Rdn, ip
            *(mt->dst++) = (ins & 0xFFE7);
        } else {
            uint32_t addr = PC;
            int pos = 31;

            while (pos >= 8) {
                if (1u << pos & addr) {
                    // See "Modified immediate constants in T32 instructions"
                    uint32_t i_imm3_a = 0x8 + (31 - pos);
                    uint32_t bcdefgh = (addr >> (pos - 7)) & 0x7F;
                    uint32_t i = BITS(i_imm3_a, 4, 1);
                    uint32_t imm3 = BITS(i_imm3_a, 1, 3);
                    uint32_t a = BITS(i_imm3_a, 0, 1);
                    // add Rdn, #const  ; F5.1.4 ADD, ADDS (immediate) : T3
                    *(mt->dst++) = 0xF100 | (i << 10) | Rdn;
                    *(mt->dst++) = (imm3 << 12) | (Rdn << 8) | (a << 7) | bcdefgh;
                    pos -= 8;
                } else {
                    pos--;
                }
            }
            addr &= (1u << pos) - 1;
            if (addr != 0) {
                // add Rdn, #const  ; F5.1.4 ADD, ADDS (immediate) : T3
                *(mt->dst++) = 0xF100 | Rdn;
                *(mt->dst++) = (Rdn << 8) | addr;
            }
        }
        return 0;
    }

    // blx label        ; F5.1.25 BL, BLX (immediate) : T2
    if ((ins & 0xF800) == 0xF000 && ((ins2 & 0xD000) == 0xC000)) {
        uint32_t s = BITS(ins, 10, 1);
        uint32_t imm10h = BITS(ins, 0, 10);
        uint32_t j1 = BITS(ins2, 13, 1);
        uint32_t j2 = BITS(ins2, 11, 1);
        uint32_t imm10l = BITS(ins2, 1, 10);
        uint32_t i1 = !(j1 ^ s);
        uint32_t i2 = !(j2 ^ s);
        int32_t imm32 = SIGN_EXTEND32((s << 24) | (i1 << 23) | (i2 << 22) | (imm10h << 12) | (imm10l << 2), 25);
        uint32_t addr = ALIGN(PC, 4) + imm32;

        // ldr ip, =addr
        ldr_reg_addr(mt, REG_IP, addr);
        // blx ip           ; F5.1.26 BLX (register) : T1
        *(mt->dst++) = 0x47E0;
        return 0;
    }

    // ldr Rt, label    ; F5.1.73 LDR (literal) : T1
    if ((ins & 0xF800) == 0x4800) {
        uint8_t Rt = BITS(ins, 8, 3);
        uint32_t imm8 = BITS(ins, 0, 8);
        uint32_t addr = ALIGN(PC, 4) + (imm8 << 2);

        // ldr.w ip, =addr
        ldr_reg_addr(mt, REG_IP, addr);
        // ldr.w Rt, [ip]   ; F5.1.72 LDR (immediate) : T3
        *(mt->dst++) = 0xf8dc;
        *(mt->dst++) = Rt << 12;
        return 0;
    }

    // ldr Rt, label    ; F5.1.73 LDR (literal) : T2
    if ((ins & 0xFF7F) == 0xF85F) {
        uint32_t u = BITS(ins, 7, 1);
        uint8_t Rt = BITS(ins2, 12, 4);
        uint32_t imm12 = BITS(ins2, 0, 12);
        uint32_t base = ALIGN(PC, 4);
        uint32_t addr = u ? (base + imm12) : (base - imm12);

        // ldr.w ip, =addr
        ldr_reg_addr(mt, REG_IP, addr);
        // ldr.w Rt, [ip]   ; F5.1.72 LDR (immediate) : T3
        *(mt->dst++) = 0xf8dc;
        *(mt->dst++) = Rt << 12;
        return 0;
    }

    memcpy(mt->dst, mt->src, mt->insn_size * 2);
    mt->dst += mt->insn_size;
    return 0;
}
