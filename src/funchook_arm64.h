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
#ifndef FUNCHOOK_ARM64_H
#define FUNCHOOK_ARM64_H 1

#define FUNCHOOK_ARM64_REG_X9 (1u<<9)
#define FUNCHOOK_ARM64_REG_X10 (1u<<10)
#define FUNCHOOK_ARM64_REG_X11 (1u<<11)
#define FUNCHOOK_ARM64_REG_X12 (1u<<12)
#define FUNCHOOK_ARM64_REG_X13 (1u<<13)
#define FUNCHOOK_ARM64_REG_X14 (1u<<14)
#define FUNCHOOK_ARM64_REG_X15 (1u<<15)
#define FUNCHOOK_ARM64_CORRUPTIBLE_REGS (FUNCHOOK_ARM64_REG_X9 \
  | FUNCHOOK_ARM64_REG_X10 | FUNCHOOK_ARM64_REG_X11 \
  | FUNCHOOK_ARM64_REG_X12 | FUNCHOOK_ARM64_REG_X13 \
  | FUNCHOOK_ARM64_REG_X14 | FUNCHOOK_ARM64_REG_X15)

typedef enum {
    FUNCHOOK_ARM64_INSN_OTHER = 0,
    FUNCHOOK_ARM64_INSN_ADR,
    FUNCHOOK_ARM64_INSN_ADRP,
    FUNCHOOK_ARM64_INSN_B,
    FUNCHOOK_ARM64_INSN_BL,
    FUNCHOOK_ARM64_INSN_B_cond,
    FUNCHOOK_ARM64_INSN_CBNZ,
    FUNCHOOK_ARM64_INSN_CBZ,
    FUNCHOOK_ARM64_INSN_LDR,
    FUNCHOOK_ARM64_INSN_LDRSW,
    FUNCHOOK_ARM64_INSN_PRFM,
    FUNCHOOK_ARM64_INSN_TBNZ,
    FUNCHOOK_ARM64_INSN_TBZ,
} funchook_arm64_insn_id_t;

#define MAX_INSN_CHECK_SIZE 64
#define JUMP32_SIZE 2
#define JUMP64_SIZE 4
#define LITERAL_POOL_OFFSET (3 * JUMP32_SIZE + 2)
#define LITERAL_POOL_NUM (JUMP32_SIZE + 1)
#define TRAMPOLINE_SIZE (LITERAL_POOL_OFFSET + 2 * LITERAL_POOL_NUM)

#define FUNCHOOK_ENTRY_AT_PAGE_BOUNDARY 1

typedef uint32_t insn_t;

typedef struct funchook_entry {
    uint32_t transit[JUMP64_SIZE];
    void *target_func;
    void *hook_func;
    uint32_t trampoline[TRAMPOLINE_SIZE];
    uint32_t old_code[JUMP32_SIZE];
    uint32_t new_code[JUMP32_SIZE];
} funchook_entry_t;

typedef struct {
    int dummy;
} ip_displacement_t;

typedef struct {
    funchook_arm64_insn_id_t insn_id;
    uint32_t regs;
} funchook_insn_info_t;

#endif
