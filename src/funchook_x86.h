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
#ifndef FUNCHOOK_X86_H
#define FUNCHOOK_X86_H 1

#define MAX_INSN_LEN 16
#define MAX_INSN_CHECK_SIZE 256

#define JUMP32_SIZE 5
#ifdef CPU_X86_64
#define JUMP64_SIZE 14
#endif

#define TRAMPOLINE_SIZE (JUMP32_SIZE + (MAX_INSN_LEN - 1) + JUMP32_SIZE)

typedef uint8_t insn_t;

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
    const insn_t *dst_addr;
    intptr_t src_addr_offset;
    intptr_t pos_offset;
} ip_displacement_entry_t;

typedef struct {
    ip_displacement_entry_t disp[2];
} ip_displacement_t;

#endif
