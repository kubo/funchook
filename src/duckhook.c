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
#include <stdio.h>
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

static duckhook_buffer_t *get_buffer(duckhook_t *duckhook, uint8_t *addr);

#ifdef CPU_X86_64

static int buffer_avail(duckhook_buffer_t *buffer, uint8_t *mod_start, uint8_t *mod_end)
{
    return duckhook_jump32_avail(mod_end, (uint8_t*)buffer) &&
        duckhook_jump32_avail(mod_start, (uint8_t*)buffer + mem_size);
}

#else

#define buffer_avail(buffer, mod_start, mod_end) (1)

#endif

duckhook_t *duckhook_create(void)
{
    if (mem_size == 0) {
        mem_size = duckhook_mem_size();
        num_entries = (mem_size - offsetof(duckhook_buffer_t, entries)) / mem_size;
    }
    return calloc(1, sizeof(duckhook_t));
}

void *duckhook_prepare(duckhook_t *duckhook, void *func, void *new_func)
{
    duckhook_buffer_t *buf;
    duckhook_entry_t *entry;

    if (duckhook->installed) {
        return NULL;
    }

    buf = get_buffer(duckhook, (uint8_t*)func);
    if (buf == NULL) {
        return NULL;
    }
    entry = &buf->entries[buf->used];
    entry->func = duckhook_resolve_func(func);
    entry->new_func = new_func;

    if (duckhook_make_trampoline(func, entry->trampoline) != 0) {
        return NULL;
    }
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
    buf->used++;
    return (void*)entry->trampoline;
}

int duckhook_install(duckhook_t *duckhook, int flags)
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

int duckhook_uninstall(duckhook_t *duckhook, int flags)
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

int duckhook_destroy(duckhook_t *duckhook)
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

static duckhook_buffer_t *get_buffer(duckhook_t *duckhook, uint8_t *addr)
{
    duckhook_buffer_t *buf;
#ifdef CPU_X86_64
    uint8_t *mod_start, *mod_end;
    if (duckhook_get_module_region(addr, &mod_start, &mod_end) != 0) {
        return NULL;
    }
#else
    addr = NULL; /* no need to check the address. */
#endif

    for (buf = duckhook->buffer; buf != NULL; buf = buf->next) {
        if (buf->used < num_entries && buffer_avail(buf, mod_start, mod_end)) {
            return buf;
        }
    }
    buf = (duckhook_buffer_t *)duckhook_mem_alloc(addr);
    if (buf == (void*)-1) {
        return NULL;
    }
    if (!buffer_avail(buf, mod_start, mod_end)) {
        return NULL;
    }
    buf->next = duckhook->buffer;
    buf->used = 0;
    duckhook->buffer = buf;
    return buf;
}
