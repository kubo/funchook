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
#ifndef FUNCHOOK_ARM_H
#define FUNCHOOK_ARM_H 1

typedef enum {
    FUNCHOOK_ARM_INSN_OTHER = 0,
    FUNCHOOK_ARM_INSN_B,
} funchook_arm_insn_id_t;

typedef enum {
    FUNCHOOK_ARM_COND_EQ = 0x00, // Z == 1
    FUNCHOOK_ARM_COND_NE = 0x01, // Z == 0
    FUNCHOOK_ARM_COND_CS = 0x02, // C == 1
    FUNCHOOK_ARM_COND_CC = 0x03, // C == 0
    FUNCHOOK_ARM_COND_MI = 0x04, // N == 1
    FUNCHOOK_ARM_COND_PL = 0x05, // N == 0
    FUNCHOOK_ARM_COND_VS = 0x06, // V == 1
    FUNCHOOK_ARM_COND_VC = 0x07, // V == 0
    FUNCHOOK_ARM_COND_HI = 0x08, // C == 1 and Z == 0
    FUNCHOOK_ARM_COND_LS = 0x09, // C == 0 or Z == 1
    FUNCHOOK_ARM_COND_GE = 0x0A, // N == V
    FUNCHOOK_ARM_COND_LT = 0x0B, // N != V
    FUNCHOOK_ARM_COND_GT = 0x0C, // Z == 0 and N == V
    FUNCHOOK_ARM_COND_LE = 0x0D, // Z == 1 or N != V
    FUNCHOOK_ARM_COND_AL = 0x0E, // Any
    FUNCHOOK_ARM_COND_INVALID
} funchook_arm_cond_t;

#define MAX_INSN_CHECK_SIZE 64
#define JUMP32_SIZE 4
#define LITERAL_POOL_OFFSET (8 * JUMP32_SIZE + 2)
#define LITERAL_POOL_NUM (JUMP32_SIZE + 1)
#define TRAMPOLINE_SIZE (LITERAL_POOL_OFFSET + 2 * LITERAL_POOL_NUM)

typedef uint16_t insn_t;

typedef struct funchook_entry {
    void *target_func;
    void *hook_func;
    uint16_t trampoline[TRAMPOLINE_SIZE];
    uint16_t old_code[JUMP32_SIZE];
    uint16_t new_code[JUMP32_SIZE];
} funchook_entry_t;

typedef struct {
    int dummy;
} ip_displacement_t;

typedef struct {
    funchook_arm_insn_id_t insn_id;
    funchook_arm_cond_t cond;
    uint32_t addr;
} funchook_insn_info_t;

#endif
