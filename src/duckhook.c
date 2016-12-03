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
#include "config.h"
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#ifdef WIN32
#include <windows.h>
#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif
#endif
#include "duckhook.h"
#include "duckhook_io.h"
#include "duckhook_internal.h"

#define DUCKHOOK_MAX_ERROR_MESSAGE_LEN 200

typedef struct duckhook_entry {
    void *target_func;
    void *hook_func;
    uint8_t trampoline[TRAMPOLINE_SIZE];
    uint8_t old_code[JUMP32_SIZE];
    uint8_t new_code[JUMP32_SIZE];
#ifdef CPU_X86_64
    uint8_t transit[JUMP64_SIZE];
#endif
} duckhook_entry_t;

struct duckhook_page {
    struct duckhook_page *next;
    uint16_t used;
    duckhook_entry_t entries[1];
};

struct duckhook {
    int installed;
    duckhook_page_t *page_list;
    char error_message[DUCKHOOK_MAX_ERROR_MESSAGE_LEN];
    duckhook_io_t io;
};

char duckhook_debug_file[PATH_MAX];

const size_t duckhook_size = sizeof(duckhook_t);

static size_t num_entries_in_page;

static void duckhook_logv(duckhook_t *duckhook, int set_error, const char *fmt, va_list ap);
static void duckhook_log_end(duckhook_t *duckhook, const char *fmt, ...);
static duckhook_t *duckhook_create_internal(void);
static int duckhook_prepare_internal(duckhook_t *duckhook, void **target_func, void *hook_func);
static int duckhook_install_internal(duckhook_t *duckhook, int flags);
static int duckhook_uninstall_internal(duckhook_t *duckhook, int flags);
static int duckhook_destroy_internal(duckhook_t *duckhook);
static int get_page(duckhook_t *duckhook, duckhook_page_t **page_out, uint8_t *addr, rip_displacement_t *disp);

#ifdef CPU_X86_64

int duckhook_page_avail(duckhook_t *duckhook, duckhook_page_t *page, int idx, uint8_t *addr, rip_displacement_t *disp)
{
    duckhook_entry_t *entry = &page->entries[idx];
    const uint8_t *src;
    const uint8_t *dst;

    if (!duckhook_jump32_avail(addr, entry->trampoline)) {
        duckhook_log(duckhook, "  could not jump function %p to trampoline %p\n", addr, entry->trampoline);
        return 0;
    }
    src = entry->trampoline + disp[0].src_addr_offset;
    dst = disp[0].dst_addr;
    if (!duckhook_within_32bit_relative(src, dst)) {
        duckhook_log(duckhook, "  could not jump trampoline %p to function %p\n",
                     src, dst);
        return 0;
    }
    src = entry->trampoline + disp[1].src_addr_offset;
    dst = disp[1].dst_addr;
    if (dst != 0 && !duckhook_within_32bit_relative(src, dst)) {
        duckhook_log(duckhook, "  could not make 32-bit relative address from %p to %p\n",
                     src, dst);
        return 0;
    }
    return 1;
}

#endif

duckhook_t *duckhook_create(void)
{
    duckhook_t *duckhook = NULL;

    duckhook_log(duckhook, "Enter duckhook_create()\n");
    duckhook = duckhook_create_internal();
    duckhook_log_end(duckhook, "Leave duckhook_create() => %p\n", duckhook);
    return duckhook;
}

int duckhook_prepare(duckhook_t *duckhook, void **target_func, void *hook_func)
{
    int rv;
    void *orig_func;

    duckhook_log(duckhook, "Enter duckhook_prepare(%p, %p, %p)\n", duckhook, target_func, hook_func);
    orig_func = *target_func;
    rv = duckhook_prepare_internal(duckhook, target_func, hook_func);
    duckhook_log_end(duckhook, "Leave duckhook_prepare(..., [%p->%p],...) => %d\n", orig_func, *target_func, rv);
    return rv;
}

int duckhook_install(duckhook_t *duckhook, int flags)
{
    int rv;

    duckhook_log(duckhook, "Enter duckhook_install(%p, 0x%x)\n", duckhook, flags);
    rv = duckhook_install_internal(duckhook, flags);
    duckhook_log_end(duckhook, "Leave duckhook_install() => %d\n", rv);
    return rv;
}

int duckhook_uninstall(duckhook_t *duckhook, int flags)
{
    int rv;

    duckhook_log(duckhook, "Enter duckhook_uninstall(%p, 0x%x)\n", duckhook, flags);
    rv = duckhook_uninstall_internal(duckhook, flags);
    duckhook_log_end(NULL, "Leave duckhook_uninstall() => %d\n", rv);
    return rv;
}

int duckhook_destroy(duckhook_t *duckhook)
{
    int rv;

    duckhook_log(duckhook, "Enter duckhook_destroy(%p)\n", duckhook);
    rv = duckhook_destroy_internal(duckhook);
    duckhook_log_end(rv == 0 ? NULL : duckhook, "Leave duckhook_destroy() => %d\n", rv);
    return rv;
}

int duckhook_set_debug_file(const char *name)
{
    if (name != NULL) {
        strlcpy(duckhook_debug_file, name, sizeof(duckhook_debug_file));
    } else {
        duckhook_debug_file[0] = '\0';
    }
    return 0;
}

void duckhook_log(duckhook_t *duckhook, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    duckhook_logv(duckhook, 0, fmt, ap);
    va_end(ap);
}

void duckhook_set_error_message(duckhook_t *duckhook, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    duckhook_vsnprintf(duckhook->error_message, DUCKHOOK_MAX_ERROR_MESSAGE_LEN, fmt, ap);
    va_end(ap);
    va_start(ap, fmt);
    duckhook_logv(duckhook, 1, fmt, ap);
    va_end(ap);
}

static void duckhook_logv(duckhook_t *duckhook, int set_error, const char *fmt, va_list ap)
{
    duckhook_io_t iobuf;
    duckhook_io_t *io = &iobuf;

    if (*duckhook_debug_file == '\0') {
        return;
    }
    if (duckhook == NULL) {
        duckhook_io_open(&iobuf, duckhook_debug_file, DUCKHOOK_IO_APPEND);
    } else if (duckhook->io.file == INVALID_FILE_HANDLE) {
        duckhook_io_open(&duckhook->io, duckhook_debug_file, DUCKHOOK_IO_APPEND);
        io = &duckhook->io;
    } else {
        io = &duckhook->io;
    }
    if (io->file == INVALID_FILE_HANDLE) {
        return;
    }
    if (set_error) {
        duckhook_io_puts("  ", io);
    }
    duckhook_io_vprintf(io, fmt, ap);
    if (set_error) {
        duckhook_io_putc('\n', io);
    }
    if (duckhook == NULL) {
        duckhook_io_close(io);
    } else {
        duckhook_io_flush(io);
    }
}

static void duckhook_log_end(duckhook_t *duckhook, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    duckhook_logv(duckhook, 0, fmt, ap);
    va_end(ap);
    if (duckhook != NULL && duckhook->io.file != INVALID_FILE_HANDLE) {
        duckhook_io_close(&duckhook->io);
    }
}

static duckhook_t *duckhook_create_internal(void)
{
    duckhook_t *duckhook = duckhook_alloc();
    if (duckhook == NULL) {
        return NULL;
    }
    duckhook->io.file = INVALID_FILE_HANDLE;
    if (num_entries_in_page == 0) {
        num_entries_in_page = (page_size - offsetof(duckhook_page_t, entries)) / sizeof(duckhook_entry_t);
        duckhook_log(duckhook,
#ifdef WIN32
                     "  allocation_unit=%"SIZE_T_FMT"u\n"
#endif
                     "  page_size=%"SIZE_T_FMT"u\n"
                     "  num_entries_in_page=%"SIZE_T_FMT"u\n",
#ifdef WIN32
                     allocation_unit,
#endif
                     page_size, num_entries_in_page);
    }
    return duckhook;
}

static int duckhook_prepare_internal(duckhook_t *duckhook, void **target_func, void *hook_func)
{
    void *func = *target_func;
    uint8_t trampoline[TRAMPOLINE_SIZE];
    rip_displacement_t disp[2] = {{0,},{0,}};
    duckhook_page_t *page = NULL;
    duckhook_entry_t *entry;
    uint8_t *src_addr;
    int rv;

    if (duckhook->installed) {
        duckhook_set_error_message(duckhook, "Could not modify already-installed duckhook handle.");
        return DUCKHOOK_ERROR_ALREADY_INSTALLED;
    }
    func = duckhook_resolve_func(duckhook, func);
    rv = duckhook_make_trampoline(duckhook, disp, func, trampoline);
    if (rv != 0) {
        duckhook_log(duckhook, "  failed to make trampoline\n");
        return rv;
    }
    rv = get_page(duckhook, &page, func, disp);
    if (rv != 0) {
        duckhook_log(duckhook, "  failed to get page\n");
        return rv;
    }
    entry = &page->entries[page->used];
    /* fill members */
    entry->target_func = func;
    entry->hook_func = hook_func;
    memcpy(entry->trampoline, trampoline, TRAMPOLINE_SIZE);
    memcpy(entry->old_code, func, JUMP32_SIZE);
#ifdef CPU_X86_64
    if (duckhook_jump32_avail(func, hook_func)) {
        duckhook_write_jump32(duckhook, func, hook_func, entry->new_code);
        entry->transit[0] = 0;
    } else {
        duckhook_write_jump32(duckhook, func, entry->transit, entry->new_code);
        duckhook_write_jump64(duckhook, entry->transit, hook_func);
    }
#else
    duckhook_write_jump32(duckhook, func, hook_func, entry->new_code);
#endif
    /* fix rip-relative offsets */
    src_addr = entry->trampoline + disp[0].src_addr_offset;
    *(uint32_t*)(entry->trampoline + disp[0].pos_offset) = (uint32_t)(disp[0].dst_addr - src_addr);
    if (disp[1].dst_addr != 0) {
        src_addr = entry->trampoline + disp[1].src_addr_offset;
        *(uint32_t*)(entry->trampoline + disp[1].pos_offset) = (uint32_t)(disp[1].dst_addr - src_addr);
    }
    duckhook_log_trampoline(duckhook, entry->trampoline);

    page->used++;
    *target_func = (void*)entry->trampoline;
    return 0;
}

static int duckhook_install_internal(duckhook_t *duckhook, int flags)
{
    duckhook_page_t *page;

    if (duckhook->installed) {
        return DUCKHOOK_ERROR_ALREADY_INSTALLED;
    }

    for (page = duckhook->page_list; page != NULL; page = page->next) {
        int rv = duckhook_page_protect(duckhook, page);
        int i;

        if (rv != 0) {
            return rv;
        }

        for (i = 0; i < page->used; i++) {
            duckhook_entry_t *entry = &page->entries[i];
            mem_state_t mstate;
            int rv = duckhook_unprotect_begin(duckhook, &mstate, entry->target_func, JUMP32_SIZE);

            if (rv != 0) {
                return rv;
            }
            memcpy(entry->target_func, entry->new_code, JUMP32_SIZE);
            rv = duckhook_unprotect_end(duckhook, &mstate);
            if (rv != 0) {
                return rv;
            }
        }
    }
    duckhook->installed = 1;
    return 0;
}

static int duckhook_uninstall_internal(duckhook_t *duckhook, int flags)
{
    duckhook_page_t *page;

    if (!duckhook->installed) {
        return DUCKHOOK_ERROR_NOT_INSTALLED;
    }

    for (page = duckhook->page_list; page != NULL; page = page->next) {
        int i;

        for (i = 0; i < page->used; i++) {
            duckhook_entry_t *entry = &page->entries[i];
            mem_state_t mstate;
            int rv = duckhook_unprotect_begin(duckhook, &mstate, entry->target_func, JUMP32_SIZE);

            if (rv != 0) {
                return rv;
            }
            memcpy(entry->target_func, entry->old_code, JUMP32_SIZE);
            rv = duckhook_unprotect_end(duckhook, &mstate);
            if (rv != 0) {
                return rv;
            }
        }
        duckhook_page_unprotect(duckhook, page);
    }
    duckhook->installed = 0;
    return 0;
}

static int duckhook_destroy_internal(duckhook_t *duckhook)
{
    duckhook_page_t *page, *page_next;

    if (duckhook == NULL) {
       return -1;
    }
    if (duckhook->installed) {
        return DUCKHOOK_ERROR_ALREADY_INSTALLED;
    }
    for (page = duckhook->page_list; page != NULL; page = page_next) {
        page_next = page->next;
        duckhook_page_free(duckhook, page);
    }
    duckhook_io_close(&duckhook->io);
    duckhook_free(duckhook);
    return 0;
}

static int get_page(duckhook_t *duckhook, duckhook_page_t **page_out, uint8_t *addr, rip_displacement_t *disp)
{
    duckhook_page_t *page;
    int rv;

    for (page = duckhook->page_list; page != NULL; page = page->next) {
        if (page->used < num_entries_in_page && duckhook_page_avail(duckhook, page, page->used, addr, disp)) {
            /* Reuse allocated page. */
            *page_out = page;
            return 0;
        }
    }
    rv = duckhook_page_alloc(duckhook, &page, addr, disp);
    if (rv != 0) {
        return rv;
    }
    page->used = 0;
    page->next = duckhook->page_list;
    duckhook->page_list = page;
    *page_out = page;
    return 0;
}
