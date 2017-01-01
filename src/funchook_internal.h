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
#ifndef FUNCHOOK_INTERNAL_H
#define FUNCHOOK_INTERNAL_H 1
#include "funchook.h"
#include "os_func.h"

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

/* This must be same with sysconf(_SC_PAGE_SIZE) on Unix
 * or the dwPageSize member of the SYSTEM_INFO structure on Windows.
 */
#undef PAGE_SIZE
#define PAGE_SIZE 0x1000 /* 4k */

/* This must be same with the dwAllocationGranularity
 * member of the SYSTEM_INFO structure on Windows.
 */
#define ALLOCATION_UNIT 0x10000 /* 64k */

typedef struct {
    void *addr;
    size_t size;
#ifdef WIN32
    DWORD protect;
#endif
} mem_state_t;

typedef struct {
    const uint8_t *dst_addr;
    intptr_t src_addr_offset;
    intptr_t pos_offset;
} rip_displacement_t;

typedef struct funchook_page funchook_page_t;

/* Functions in funchook.c */
extern const size_t funchook_size;
extern char funchook_debug_file[];
#ifdef CPU_X86_64
int funchook_page_avail(funchook_t *funchook, funchook_page_t *page, int idx, uint8_t *addr, rip_displacement_t *disp);
#else
#define funchook_page_avail(funchook, page, idx, addr, disp) (1)
#endif
void funchook_log(funchook_t *funchook, const char *fmt, ...) __attribute__((__format__ (__printf__, 2, 3)));
void funchook_set_error_message(funchook_t *funchook, const char *fmt, ...) __attribute__((__format__ (__printf__, 2, 3)));

/* Functions in funchook_linux.c & funchook_windows.c */
extern const size_t page_size;
extern const size_t allocation_unit; /* windows only */

funchook_t *funchook_alloc(void);
int funchook_free(funchook_t *funchook);

int funchook_page_alloc(funchook_t *funchook, funchook_page_t **page_out, uint8_t *func, rip_displacement_t *disp);
int funchook_page_free(funchook_t *funchook, funchook_page_t *page);
int funchook_page_protect(funchook_t *funchook, funchook_page_t *page);
int funchook_page_unprotect(funchook_t *funchook, funchook_page_t *page);

int funchook_unprotect_begin(funchook_t *funchook, mem_state_t *mstate, void *addr, size_t len);
int funchook_unprotect_end(funchook_t *funchook, const mem_state_t *mstate);

void *funchook_resolve_func(funchook_t *funchook, void *func);
const char *funchook_strerror(int errnum, char *buf, size_t buflen);

/* Functions in funchook_x86.c */

int funchook_write_jump32(funchook_t *funchook, const uint8_t *src, const uint8_t *dst, uint8_t *out);
#ifdef CPU_X86_64
int funchook_write_jump64(funchook_t *funchook, uint8_t *src, const uint8_t *dst);
int funchook_within_32bit_relative(const uint8_t *src, const uint8_t *dst);
int funchook_jump32_avail(const uint8_t *src, const uint8_t *dst);
#endif

int funchook_make_trampoline(funchook_t *funchook, rip_displacement_t *disp, const uint8_t *func, uint8_t *trampoline);
void funchook_log_trampoline(funchook_t *funchook, const uint8_t *trampoline);

#endif
