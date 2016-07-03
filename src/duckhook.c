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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifdef WIN32
#include <windows.h>
#endif
#include "duckhook.h"
#include "duckhook_internal.h"

struct duckhook_memo {
    void *func;
    void *new_func;
    code_mem_t *code_mem;
    uchar orig_code[JUMP32_SIZE];
};

static code_mem_buffer_t *code_mem_buffer_head;

static int copy_code(void *dest, void *src, size_t n);
static code_mem_buffer_t *code_mem_buffer_alloc(uchar *hint);
static int code_mem_buffer_free(code_mem_buffer_t *mb);
static code_mem_t *code_mem_get(uchar *addr);
static void code_mem_free(code_mem_t *code_mem);

#ifdef CPU_X86_64

static int code_mem_buffer_avail(uchar *mod_start, uchar *mod_end, code_mem_buffer_t *mb)
{
    return duckhook_jump32_avail(mod_end, (uchar*)mb) &&
        duckhook_jump32_avail(mod_start, (uchar*)mb + allocation_unit);
}

#else

#define code_mem_buffer_avail(mod_start, mod_end, mb) (1)

#endif

void *duckhook_install(void *func, void *new_func, duckhook_memo_t **memo_out)
{
    duckhook_memo_t *memo;
    mem_state_t mstate;

    memo = calloc(1, sizeof(duckhook_memo_t));
    if (memo == NULL) {
        return NULL;
    }
    func = duckhook_resolve_func(func);
    memo->func = func;
    memo->new_func = new_func;
    memo->code_mem = code_mem_get(func);
    if (memo->code_mem == NULL) {
        free(memo);
        return NULL;
    }
    memcpy(memo->orig_code, func, JUMP32_SIZE);

    duckhook_unprotect_begin(&mstate, memo->code_mem, sizeof(code_mem_t));
    if (duckhook_make_trampoline(func, memo->code_mem->trampoline) != 0) {
        duckhook_unprotect_end(&mstate);
        return NULL;
    }
#ifdef CPU_X86_64
    if (duckhook_jump32_avail(func, new_func)) {
        memset(memo->code_mem->transit, 0, sizeof(memo->code_mem->transit));
        duckhook_write_jump32(func, new_func, 1);
    } else {
        if (!duckhook_jump32_avail(func, memo->code_mem->transit)) {
            duckhook_unprotect_end(&mstate);
            free(memo);
            return NULL;
        }
        duckhook_write_jump64(memo->code_mem->transit, new_func, 0);
        duckhook_write_jump32(func, memo->code_mem->transit, 1);
    }
#else
    duckhook_write_jump32(func, new_func, 1);
#endif
    memo->code_mem->used = 1;
    duckhook_unprotect_end(&mstate);
    if (memo_out != NULL) {
        *memo_out = memo;
    }
    return (void*)memo->code_mem->trampoline;
}

void duckhook_uninstall(duckhook_memo_t *memo)
{
    copy_code(memo->func, memo->orig_code, JUMP32_SIZE);
    code_mem_free(memo->code_mem);
    free(memo);
}

static int copy_code(void *dest, void *src, size_t n)
{
    mem_state_t mstate;

    if (duckhook_unprotect_begin(&mstate, dest, n) != 0) {
        return -1;
    }
    memcpy(dest, src, n);
    duckhook_unprotect_end(&mstate);
    return 0;
}

static code_mem_buffer_t *code_mem_buffer_alloc(uchar *hint)
{
    code_mem_buffer_t *mb;
    mem_state_t mstate;

#ifdef CPU_X86_64
    mb = duckhook_mem_alloc(hint);
#else
    mb = duckhook_mem_alloc(NULL);
#endif
    if (mb == (void*)-1) {
        return NULL;
    }

    if (duckhook_unprotect_begin(&mstate, mb, sizeof(*mb)) != 0) {
        duckhook_mem_free(mb);
        return NULL;
    }
    mb->next = code_mem_buffer_head;
    mb->prev = &code_mem_buffer_head;
    duckhook_unprotect_end(&mstate);

    if (mb->next != NULL) {
        if (duckhook_unprotect_begin(&mstate, mb->next, sizeof(*mb)) != 0) {
            duckhook_mem_free(mb);
            return NULL;
        }
        mb->next->prev = &mb;
        duckhook_unprotect_end(&mstate);
    }
    code_mem_buffer_head = mb;
    return mb;
}

static int code_mem_buffer_free(code_mem_buffer_t *mb)
{
    mem_state_t mstate = {0,};

    if (mb->prev != &code_mem_buffer_head) {
        if (duckhook_unprotect_begin(&mstate, mb->prev, sizeof(*mb)) != 0) {
            return -1;
        }
        *mb->prev = mb->next;
        duckhook_unprotect_end(&mstate);
    } else {
        code_mem_buffer_head = mb->next;
    }
    if (mb->next != NULL) {
        if (duckhook_unprotect_begin(&mstate, mb->next, sizeof(*mb)) != 0) {
            return -1;
        }
        mb->next->prev = mb->prev;
        duckhook_unprotect_end(&mstate);
    }
    return duckhook_mem_free(mb);
}

static code_mem_t *code_mem_get(uchar *addr)
{
    code_mem_buffer_t *mb;
#ifdef CPU_X86_64
    uchar *mod_start, *mod_end;
    if (duckhook_get_module_region(addr, &mod_start, &mod_end) != 0) {
        return NULL;
    }
#endif

    for (mb = code_mem_buffer_head; mb != NULL; mb = mb->next) {
        int i;
        if (!code_mem_buffer_avail(mod_start, mod_end, mb)) {
            /* too far */
          continue;
        }
        for (i = 0; i < code_mem_count_in_buffer; i++) {
            code_mem_t *code_mem = &mb->code_mem[i];
            if (!code_mem->used) {
                return code_mem;
            }
        }
    }
    mb = code_mem_buffer_alloc(addr);
    if (mb == NULL) {
        return NULL;
    }
    if (!code_mem_buffer_avail(mod_start, mod_end, mb)) {
        code_mem_buffer_free(mb);
        return NULL;
    }
    return &mb->code_mem[0];
}

static void code_mem_free(code_mem_t *code_mem)
{
    code_mem_buffer_t *mb;

    for (mb = code_mem_buffer_head; mb != NULL; mb = mb->next) {
        size_t idx = code_mem - mb->code_mem;
        if (idx < code_mem_count_in_buffer) {
            mem_state_t mstate;

            if (code_mem != mb->code_mem + idx) {
                /* invalid situation */
                return;
            }
            if (duckhook_unprotect_begin(&mstate, mb, sizeof(code_mem_buffer_t) + sizeof(code_mem_t) * idx) != 0) {
                return;
            }
            code_mem->used = 0;
            duckhook_unprotect_end(&mstate);
            for (idx = 0; idx < code_mem_count_in_buffer; idx++) {
                if (mb->code_mem[idx].used) {
	            /* find an unused entry. */
                    return;
                }
            }
            /* all entries are unused. */
            code_mem_buffer_free(mb);
            return;
        }
    }
}
