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
#ifdef WIN32
#include <windows.h>
#endif
#include "duckhook.h"
#include "duckhook_internal.h"

typedef struct duckhook_entry {
    void *func;
    void *new_func;
    uint8_t trampoline[TRAMPOLINE_SIZE];
    uint8_t old_code[JUMP32_SIZE];
    uint8_t new_code[JUMP32_SIZE];
#ifdef CPU_X86_64
    uint8_t transit[JUMP64_SIZE];
#endif
} duckhook_entry_t;

typedef struct duckhook_buffer {
    struct duckhook_buffer *next;
    uint16_t used;
    duckhook_entry_t entries[1];
} duckhook_buffer_t;

struct duckhook {
    int installed;
    duckhook_buffer_t *buffer;
};

static size_t mem_size;
static size_t num_entries;
static char *debug_file;

static duckhook_t *duckhook_create_internal(void);
static void *duckhook_prepare_internal(duckhook_t *duckhook, void *func, void *new_func);
static int duckhook_install_internal(duckhook_t *duckhook, int flags);
static int duckhook_uninstall_internal(duckhook_t *duckhook, int flags);
static int duckhook_destroy_internal(duckhook_t *duckhook);
static duckhook_buffer_t *get_buffer(duckhook_t *duckhook, uint8_t *addr, rip_displacement_t *disp);

#ifdef CPU_X86_64

static int buffer_avail(duckhook_buffer_t *buf, uint8_t *addr, rip_displacement_t *disp)
{
    duckhook_entry_t *entry = &buf->entries[buf->used];
    const uint8_t *src;
    const uint8_t *dst;

    if (!duckhook_jump32_avail(addr, entry->trampoline)) {
        duckhook_log("  could not jump function %p to trampoline %p\n", addr, entry->trampoline);
        return 0;
    }
    src = entry->trampoline + disp[0].src_addr_offset;
    dst = disp[0].dst_addr;
    if (!duckhook_within_32bit_relative(src, dst)) {
        duckhook_log("  could not jump trampoline %p to function %p\n",
                     src, dst);
        return 0;
    }
    src = entry->trampoline + disp[1].src_addr_offset;
    dst = disp[1].dst_addr;
    if (dst != 0 && !duckhook_within_32bit_relative(src, dst)) {
        duckhook_log("  could not relative address from %p to %p\n",
                     src, dst);
        return 0;
    }
    return 1;
}

#else

#define buffer_avail(buffer, addr, disp) (1)

#endif

duckhook_t *duckhook_create(void)
{
    duckhook_t *duckhook;

    duckhook_log("Enter duckhook_create()\n");
    duckhook = duckhook_create_internal();
    duckhook_log("Leave duckhook_create() => %p\n", duckhook);
    return duckhook;
}

void *duckhook_prepare(duckhook_t *duckhook, void *func, void *new_func)
{
    void *rv;

    duckhook_log("Enter duckhook_prepare(%p, %p, %p)\n", duckhook, func, new_func);
    rv = duckhook_prepare_internal(duckhook, func, new_func);
    duckhook_log("Leave duckhook_prepare() => %p\n", rv);
    return rv;
}

int duckhook_install(duckhook_t *duckhook, int flags)
{
    int rv;

    duckhook_log("Enter duckhook_install(%p, 0x%x)\n", duckhook, flags);
    rv = duckhook_install_internal(duckhook, flags);
    duckhook_log("Leave duckhook_install() => %d\n", rv);
    return rv;
}

int duckhook_uninstall(duckhook_t *duckhook, int flags)
{
    int rv;

    duckhook_log("Enter duckhook_uninstall(%p, 0x%x)\n", duckhook, flags);
    rv = duckhook_uninstall_internal(duckhook, flags);
    duckhook_log("Leave duckhook_uninstall() => %d\n", rv);
    return rv;
}

int duckhook_destroy(duckhook_t *duckhook)
{
    int rv;

    duckhook_log("Enter duckhook_destroy(%p)\n", duckhook);
    rv = duckhook_destroy_internal(duckhook);
    duckhook_log("Leave duckhook_destroy() => %d\n", rv);
    return rv;
}

int duckhook_set_debug_file(const char *name)
{
    if (debug_file != NULL) {
        free(debug_file);
        debug_file = NULL;
    }
    if (name != NULL) {
        debug_file = strdup(name);
        if (debug_file == NULL) {
            return -1;
        }
    }
    return 0;
}

void duckhook_log(const char *fmt, ...)
{
    if (debug_file != NULL) {
        FILE *fp = fopen(debug_file, "a");

        if (fp != NULL) {
            va_list ap;

            va_start(ap, fmt);
            vfprintf(fp, fmt, ap);
            va_end(ap);
            fclose(fp);
        }
    }
}

static duckhook_t *duckhook_create_internal(void)
{
    if (mem_size == 0) {
        mem_size = duckhook_mem_size();
        num_entries = (mem_size - offsetof(duckhook_buffer_t, entries)) / sizeof(duckhook_entry_t);
        duckhook_log("  num_entries_in_page=%"SIZE_T_FMT"u\n", num_entries);
    }
    return calloc(1, sizeof(duckhook_t));
}

static void *duckhook_prepare_internal(duckhook_t *duckhook, void *func, void *new_func)
{
    uint8_t trampoline[TRAMPOLINE_SIZE] = {0,};
    rip_displacement_t disp[2];
    duckhook_buffer_t *buf;
    duckhook_entry_t *entry;
    uint8_t *src_addr;

    if (duckhook->installed) {
        duckhook_log("  already installed\n");
        return NULL;
    }
    if (duckhook_make_trampoline(disp, func, trampoline) != 0) {
        duckhook_log("  failed to make trampoline\n");
        return NULL;
    }
    buf = get_buffer(duckhook, func, disp);
    if (buf == NULL) {
        duckhook_log("  failed to get buffer\n");
        return NULL;
    }
    entry = &buf->entries[buf->used];
    /* fill members */
    entry->func = duckhook_resolve_func(func);
    entry->new_func = new_func;
    memcpy(entry->trampoline, trampoline, TRAMPOLINE_SIZE);
    memcpy(entry->old_code, func, JUMP32_SIZE);
#ifdef CPU_X86_64
    if (duckhook_jump32_avail(func, new_func)) {
        duckhook_write_jump32(func, new_func, entry->new_code);
    } else {
        duckhook_write_jump32(func, entry->transit, entry->new_code);
        duckhook_write_jump64(entry->transit, new_func);
    }
#else
    duckhook_write_jump32(func, new_func, entry->new_code);
#endif
    /* fix rip-relative offsets */
    src_addr = entry->trampoline + disp[0].src_addr_offset;
    *(uint32_t*)(entry->trampoline + disp[0].pos_offset) = (disp[0].dst_addr - src_addr);
    if (disp[1].dst_addr != 0) {
        src_addr = entry->trampoline + disp[1].src_addr_offset;
        *(uint32_t*)(entry->trampoline + disp[1].pos_offset) = (disp[1].dst_addr - src_addr);
    }

    buf->used++;
    return (void*)entry->trampoline;
}

static int duckhook_install_internal(duckhook_t *duckhook, int flags)
{
    duckhook_buffer_t *buf;

    if (duckhook->installed) {
        return -1;
    }

    for (buf = duckhook->buffer; buf != NULL; buf = buf->next) {
        int i;

        duckhook_mem_protect(buf);

        for (i = 0; i < buf->used; i++) {
            duckhook_entry_t *entry = &buf->entries[i];
            mem_state_t mstate;

            if (duckhook_unprotect_begin(&mstate, entry->func, JUMP32_SIZE) != 0) {
                return -1;
            }
            memcpy(entry->func, entry->new_code, JUMP32_SIZE);
            duckhook_unprotect_end(&mstate);
        }
    }
    duckhook->installed = 1;
    return 0;
}

static int duckhook_uninstall_internal(duckhook_t *duckhook, int flags)
{
    duckhook_buffer_t *buf;

    if (!duckhook->installed) {
        return -1;
    }

    for (buf = duckhook->buffer; buf != NULL; buf = buf->next) {
        int i;

        for (i = 0; i < buf->used; i++) {
            duckhook_entry_t *entry = &buf->entries[i];
            mem_state_t mstate;

            if (duckhook_unprotect_begin(&mstate, entry->func, JUMP32_SIZE) != 0) {
                return -1;
            }
            memcpy(entry->func, entry->old_code, JUMP32_SIZE);
            duckhook_unprotect_end(&mstate);
        }
        duckhook_mem_unprotect(buf);
    }
    duckhook->installed = 0;
    return 0;
}

static int duckhook_destroy_internal(duckhook_t *duckhook)
{
    duckhook_buffer_t *buf, *buf_next;

    if (duckhook == NULL) {
       return -1;
    }
    if (duckhook->installed) {
        return -1;
    }
    for (buf = duckhook->buffer; buf != NULL; buf = buf_next) {
        buf_next = buf->next;
        duckhook_mem_free(buf);
    }
    free(duckhook);
    return 0;
}

static duckhook_buffer_t *get_buffer(duckhook_t *duckhook, uint8_t *addr, rip_displacement_t *disp)
{
    duckhook_buffer_t *buf;

    for (buf = duckhook->buffer; buf != NULL; buf = buf->next) {
        if (buf->used < num_entries && buffer_avail(buf, addr, disp)) {
            return buf;
        }
    }
    buf = (duckhook_buffer_t *)duckhook_mem_alloc(addr);
    if (buf == (void*)-1) {
        return NULL;
    }
    buf->used = 0;
    if (!buffer_avail(buf, addr, disp)) {
        return NULL;
    }
    buf->next = duckhook->buffer;
    duckhook->buffer = buf;
    return buf;
}
