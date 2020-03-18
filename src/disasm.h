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
#ifndef DISASM_H
#define DISASM_H 1

#ifdef DISASM_DISTORM
#include <distorm.h>
#include <mnemonics.h>

typedef struct funchook_disasm {
    funchook_t *funchook;
    _CodeInfo ci;
    unsigned int idx;
    unsigned int cnt;
    _DInst dis[MAX_INSN_CHECK_SIZE];
} funchook_disasm_t;
typedef _DInst funchook_insn_t;

#define funchook_insn_size(insn) ((insn)->size)
#define funchook_insn_address(insn) ((size_t)(insn)->addr)
#define funchook_insn_branch_address(insn) ((size_t)INSTRUCTION_GET_TARGET(insn))

#endif

#ifdef DISASM_CAPSTONE
#include <capstone/capstone.h>

typedef struct funchook_disasm {
    funchook_t *funchook;
    csh handle;
    cs_insn *insns;
    size_t index;
    size_t count;
} funchook_disasm_t;

typedef cs_insn funchook_insn_t;

#define funchook_insn_size(insn) ((insn)->size / sizeof(insn_t))
#define funchook_insn_address(insn) ((size_t)(insn)->address)
#define funchook_insn_branch_address(insn) ((size_t)(insn)->detail->x86.operands[0].imm)
#endif

#ifdef DISASM_ZYDIS
#include <Zydis/Zydis.h>

typedef struct {
    ZydisDecodedInstruction insn;
    size_t next_address;
} funchook_insn_t;

typedef struct funchook_disasm {
    funchook_t *funchook;
    ZydisDecoder decoder;
    ZydisFormatter formatter;
    funchook_insn_t insn;
    const uint8_t *code;
    const uint8_t *code_end;
} funchook_disasm_t;

#define funchook_insn_size(insn) ((insn)->insn.length)
#define funchook_insn_address(insn) ((insn)->next_address - (insn)->insn.length)
#define funchook_insn_branch_address(insn) ((insn)->next_address + (intptr_t)(insn)->insn.raw.imm[0].value.s)

#endif

#define FUNCHOOK_ERROR_END_OF_INSTRUCTION -2

int funchook_disasm_init(funchook_disasm_t *disasm, funchook_t *funchook, const insn_t *code, size_t code_size, size_t address);
void funchook_disasm_cleanup(funchook_disasm_t *disasm);
int funchook_disasm_next(funchook_disasm_t *disasm, const funchook_insn_t **next_insn);
void funchook_disasm_log_instruction(funchook_disasm_t *disasm, const funchook_insn_t *insn);

#if defined(CPU_ARM64)
funchook_insn_info_t funchook_disasm_arm64_insn_info(funchook_disasm_t *disasm, const funchook_insn_t *insn);
#endif

#if defined(CPU_X86) || defined(CPU_X86_64)
/* RIP-relative address information */
typedef struct {
    insn_t *addr; /* absolute address */
    intptr_t raddr; /* relative address */
    int offset;
    int size;
} rip_relative_t;

void funchook_disasm_x86_rip_relative(funchook_disasm_t *disasm, const funchook_insn_t *insn, rip_relative_t *rel_disp, rip_relative_t *rel_imm);
#endif

#endif
