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
#ifdef WIN32
#include <windows.h>
#endif

#if defined(_MSC_VER) && _MSC_VER < 1700
#ifdef _WIN64
#define PRIxPTR "I64"
#else
#define PRIxPTR ""
#endif
#else
#include <inttypes.h>
#endif

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef __GNUC__
#define __attribute__(arg)
#endif

#define ROUND_DOWN(num, unit) ((num) & ~((unit) - 1))
#define ROUND_UP(num, unit) (((num) + (unit) - 1) & ~((unit) - 1))

#if SIZEOF_VOID_P == 8
#define ADDR_FMT "%016" PRIxPTR
#else
#define ADDR_FMT "%08" PRIxPTR
#endif

#if defined __aarch64__
#define CPU_ARM64
#define CPU_64BIT
#endif

#if defined _M_AMD64 || defined __x86_64__
#define CPU_X86_64
#define CPU_64BIT
#endif

#if defined _M_IX86 || defined __i686__ || defined __i386__
#define CPU_X86
#endif

#if defined(CPU_ARM64)
#include "funchook_arm64.h"
#endif
#if defined(CPU_X86) || defined(CPU_X86_64)
#include "funchook_x86.h"
#endif

#define JUMP32_BYTE_SIZE (JUMP32_SIZE * sizeof(insn_t))
#define TRAMPOLINE_BYTE_SIZE (TRAMPOLINE_SIZE * sizeof(insn_t))

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

typedef struct funchook_page {
#ifdef FUNCHOOK_ENTRY_AT_PAGE_BOUNDARY
    funchook_entry_t entries[1]; /* This contains at most one. */
#endif
    struct funchook_page *next;
    uint16_t used;
#ifndef FUNCHOOK_ENTRY_AT_PAGE_BOUNDARY
    funchook_entry_t entries[1]; /* This contains zero or more. */
#endif
} funchook_page_t;

/* Functions in funchook.c */
extern const size_t funchook_size;
extern char funchook_debug_file[];
void funchook_log(funchook_t *funchook, const char *fmt, ...) __attribute__((__format__ (__printf__, 2, 3)));
void funchook_set_error_message(funchook_t *funchook, const char *fmt, ...) __attribute__((__format__ (__printf__, 2, 3)));

/* Functions in funchook_linux.c & funchook_windows.c */
extern const size_t page_size;
extern const size_t allocation_unit; /* windows only */

funchook_t *funchook_alloc(void);
int funchook_free(funchook_t *funchook);

int funchook_page_alloc(funchook_t *funchook, funchook_page_t **page_out, uint8_t *func, ip_displacement_t *disp);
int funchook_page_free(funchook_t *funchook, funchook_page_t *page);
int funchook_page_protect(funchook_t *funchook, funchook_page_t *page);
int funchook_page_unprotect(funchook_t *funchook, funchook_page_t *page);

int funchook_unprotect_begin(funchook_t *funchook, mem_state_t *mstate, void *addr, size_t len);
int funchook_unprotect_end(funchook_t *funchook, const mem_state_t *mstate);

void *funchook_resolve_func(funchook_t *funchook, void *func);

/* Functions in funchook_{CPU_NAME}.c */
int funchook_make_trampoline(funchook_t *funchook, ip_displacement_t *disp, const insn_t *func, insn_t *trampoline, size_t *trampoline_size);
int funchook_fix_code(funchook_t *funchook, funchook_entry_t *entry, const ip_displacement_t *disp, const void *func, const void *hook_func);
#ifdef CPU_X86_64
int funchook_page_avail(funchook_t *funchook, funchook_page_t *page, int idx, uint8_t *addr, ip_displacement_t *disp);
#else
#define funchook_page_avail(funchook, page, idx, addr, disp) (1)
#endif

#endif
