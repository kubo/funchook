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
#ifndef DUCKHOOK_INTERNAL_H
#define DUCKHOOK_INTERNAL_H 1
#include "duckhook.h"

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifdef WIN32
#ifdef _WIN64
#define SIZE_T_FMT "I64"
#define SIZE_T_WIDTH "16"
#else
#define SIZE_T_FMT ""
#define SIZE_T_WIDTH "8"
#endif /* _WIN64 */
#else /* WIN32 */
#if defined(__LP64__) || defined(_LP64)
#define SIZE_T_FMT "l"
#define SIZE_T_WIDTH "16"
#else
#ifdef __APPLE__
#define SIZE_T_FMT "z"
#else
#define SIZE_T_FMT ""
#endif
#define SIZE_T_WIDTH "8"
#endif /* defined(__LP64__) || defined(_LP64) */
#endif /* WIN32 */

#ifndef __GNUC__
#define __attribute__(arg)
#endif

#define ROUND_DOWN(num, unit) ((num) & ~((unit) - 1))
#define ROUND_UP(num, unit) (((num) + (unit) - 1) & ~((unit) - 1))

#if defined _M_AMD64 || defined __x86_64__
#define CPU_X86_64
#endif

#define MAX_INSN_LEN 16
#define MAX_INSN_CHECK_SIZE 256

#define JUMP32_SIZE 5
#ifdef CPU_X86_64
#define JUMP64_SIZE 14
#endif

#define TRAMPOLINE_SIZE (JUMP32_SIZE + (MAX_INSN_LEN - 1) + JUMP32_SIZE)

typedef struct {
    void *addr;
    size_t size;
#ifdef WIN32
    DWORD protect;
#endif
} mem_state_t;

typedef struct {
    const uint8_t *dst_addr;
    char src_addr_offset;
    char pos_offset;
} rip_displacement_t;

typedef struct duckhook_page duckhook_page_t;

/* Functions in duckhook.c */
extern char *duckhook_debug_file;
#ifdef CPU_X86_64
int duckhook_page_avail(duckhook_t *duckhook, duckhook_page_t *page, int idx, uint8_t *addr, rip_displacement_t *disp);
#else
#define duckhook_page_avail(duckhook, page, idx, addr, disp) (1)
#endif
void duckhook_log(duckhook_t *duckhook, const char *fmt, ...) __attribute__((__format__ (__printf__, 2, 3)));
void duckhook_set_error_message(duckhook_t *duckhook, const char *fmt, ...) __attribute__((__format__ (__printf__, 2, 3)));

/* Functions in duckhook_linux.c & duckhook_windows.c */

size_t duckhook_page_size(duckhook_t *duckhook);
int duckhook_page_alloc(duckhook_t *duckhook, duckhook_page_t **page_out, uint8_t *func, rip_displacement_t *disp);
int duckhook_page_free(duckhook_t *duckhook, duckhook_page_t *page);
int duckhook_page_protect(duckhook_t *duckhook, duckhook_page_t *page);
int duckhook_page_unprotect(duckhook_t *duckhook, duckhook_page_t *page);

int duckhook_unprotect_begin(duckhook_t *duckhook, mem_state_t *mstate, void *addr, size_t len);
int duckhook_unprotect_end(duckhook_t *duckhook, const mem_state_t *mstate);

void *duckhook_resolve_func(duckhook_t *duckhook, void *func);
char *duckhook_strerror(int errnum, char *buf, size_t buflen);

/* Functions in duckhook_x86.c */

int duckhook_write_jump32(duckhook_t *duckhook, const uint8_t *src, const uint8_t *dst, uint8_t *out);
#ifdef CPU_X86_64
int duckhook_write_jump64(duckhook_t *duckhook, uint8_t *src, const uint8_t *dst);
int duckhook_within_32bit_relative(const uint8_t *src, const uint8_t *dst);
int duckhook_jump32_avail(const uint8_t *src, const uint8_t *dst);
#endif

int duckhook_make_trampoline(duckhook_t *duckhook, rip_displacement_t *disp, const uint8_t *func, uint8_t *trampoline);
void duckhook_log_trampoline(duckhook_t *duckhook, const uint8_t *trampoline);

#endif
