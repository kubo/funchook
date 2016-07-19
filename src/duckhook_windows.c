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
#define PSAPI_VERSION 1
#include <stdint.h>
#include <windows.h>
#include <psapi.h>
#include "duckhook_internal.h"

typedef struct page_info {
    struct page_info *next;
    struct page_info *prev;
    int num_used;
    char used[1];
} page_list_t;

static size_t allocation_unit; /* 64K */
static size_t page_size; /* 4K */
static size_t max_num_pages; /* 15 */
static page_list_t page_list = {
    &page_list,
    &page_list,
};

size_t duckhook_mem_size()
{
    SYSTEM_INFO si;

    GetSystemInfo(&si);
    page_size = si.dwPageSize;
    allocation_unit = si.dwAllocationGranularity;
    max_num_pages = allocation_unit / page_size - 1;
    return page_size;
}

/* Reserve 64K bytes (allocation_unit) and use the first
 * 4K bytes (1 page) as the control page.
 */
static page_list_t *alloc_page_info(void *hint)
{
    void *addr;
    page_list_t *pl;
#ifdef CPU_X86_64
    void *old_hint = hint;
    while (1) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(hint, &mbi, sizeof(mbi)) == 0) {
            duckhook_log("  Virtual Query %p failed\n", hint);
            return NULL;
        }
        duckhook_log("  process map: %016I64x-%016I64x %s\n",
                     (size_t)mbi.BaseAddress, (size_t)mbi.BaseAddress + mbi.RegionSize,
                     (mbi.State == MEM_FREE) ? "free" : "used");
        if (mbi.State == MEM_FREE) {
            size_t addr = ROUND_UP((size_t)mbi.BaseAddress, allocation_unit);
            int diff = addr - (size_t)mbi.BaseAddress;
            if (diff >= 0) {
                if (mbi.RegionSize - diff >= allocation_unit) {
                    hint = (void*)addr;
                    duckhook_log("  change hint address from %p to %p\n",
                                 old_hint, hint);
                    break;
                }
            }
        }
        hint = (void*)((size_t)mbi.BaseAddress + mbi.RegionSize);
    }
#else
    hint = NULL;
#endif
    pl = VirtualAlloc(hint, allocation_unit, MEM_RESERVE, PAGE_NOACCESS);
    duckhook_log("  reserve memory %p (hint=%p, size=%"SIZE_T_FMT"u)\n", pl, hint, allocation_unit);
    if (pl == NULL) {
        return NULL;
    }
    addr = VirtualAlloc(pl, page_size, MEM_COMMIT, PAGE_READWRITE);
    duckhook_log("  commit memory %p for read-write (hint=%p, size=%"SIZE_T_FMT"u)\n", addr, pl, page_size);
    if (addr == NULL) {
        VirtualFree(pl, 0, MEM_RELEASE);
        return NULL;
    }
    pl->next = page_list.next;
    pl->prev = &page_list;
    page_list.next->prev = pl;
    page_list.next = pl;
    return pl;
}

/*
 * Get one page from page_list, commit it and return it.
 */
void *duckhook_mem_alloc(void *hint)
{
    page_list_t *pl;
    int i;

    for (pl = page_list.next; pl != &page_list; pl = pl->next) {
#ifdef CPU_X86_64
        int64_t diff = (int64_t)pl - (int64_t)hint;
        if (diff > INT_MIN / 2 || INT_MAX / 2 < diff) {
            /* too far */
            continue;
        }
#endif
        if (pl->num_used < max_num_pages) {
            /* use a page in this page_list */
            break;
        }
    }
    if (pl == &page_list) {
        /* no page_list is available. */
        pl = alloc_page_info(hint);
        if (pl == NULL) {
            return (void*)-1;
        }
    }
    for (i = 0; i < max_num_pages; i++) {
        if (!pl->used[i]) {
            void *mem = (void*)((size_t)pl + (i + 1) * page_size);
            void *addr = VirtualAlloc(mem, page_size, MEM_COMMIT, PAGE_READWRITE);
            pl->used[i] = 1;
            pl->num_used++;
            duckhook_log("  %scommit page %p (base=%p(used=%d), idx=%d, size=%"SIZE_T_FMT"u)\n",
                         (mem == addr) ? "" : "failed to ",
                         mem, pl, pl->num_used, i, page_size);
            return addr;
        }
    }
    return (void *)-1;
}

/*
 * Back to one page to page_list.
 */
int duckhook_mem_free(void *mem)
{
    page_list_t *pl = (page_list_t *)((size_t)mem & ~(allocation_unit - 1));
    size_t idx = ((size_t)mem - (size_t)pl) / page_size - 1;
    BOOL ok;

    ok = VirtualFree(mem, page_size, MEM_DECOMMIT);
    duckhook_log("  %sdecommit page %p (base=%p(used=%d), idx=%"SIZE_T_FMT"u, size=%"SIZE_T_FMT"u)\n",
                 ok ? "" : "failed to ",
                 mem, pl, pl->num_used, idx, page_size);
    if (!ok) {
        return -1;
    }
    pl->num_used--;
    pl->used[idx] = 0;
    if (pl->num_used != 0) {
        return 0;
    }
    /* all pages are decommitted. delete this page_list */
    pl->next->prev = pl->prev;
    pl->prev->next = pl->next;
    ok = VirtualFree(pl, 0, MEM_RELEASE);
    duckhook_log("  %srelease memory %p (size=%"SIZE_T_FMT"u)\n",
                 ok ? "" : "failed to ",
                 pl, allocation_unit);
    return ok ? 0 : -1;
}

int duckhook_mem_protect(void *addr)
{
    BOOL ok = VirtualProtect(addr, page_size, PAGE_EXECUTE_READ, NULL);
    duckhook_log("  %sprotect page %p (size=%"SIZE_T_FMT"u, prot=read,exec)\n",
                 ok ? "" : "failed to ",
                 addr, page_size);
    return ok ? 0 : -1;
}

int duckhook_mem_unprotect(void *addr)
{
    BOOL ok = VirtualProtect(addr, page_size, PAGE_READWRITE, NULL);
    duckhook_log("  %sunprotect page %p (size=%"SIZE_T_FMT"u, prot=read,write)\n",
                 ok ? "" : "failed to ",
                 addr, page_size);
    return ok ? 0 : -1;
}

int duckhook_unprotect_begin(mem_state_t *mstate, void *start, size_t len)
{
    size_t saddr = ROUND_DOWN((size_t)start, page_size);
    BOOL ok;

    mstate->addr = (void*)saddr;
    mstate->size = len + (size_t)start - saddr;
    mstate->size = ROUND_UP(mstate->size, page_size);
    ok = VirtualProtect(mstate->addr, mstate->size, PAGE_EXECUTE_READWRITE, &mstate->protect);
    duckhook_log("  %sunprotect memory %p (size=%"SIZE_T_FMT"u) <- %p (size=%"SIZE_T_FMT"u)\n",
                 ok ? "" : "failed to ",
                 mstate->addr, mstate->size, start, len);
    return ok ? 0 : -1;
}

int duckhook_unprotect_end(const mem_state_t *mstate)
{
    BOOL ok = VirtualProtect(mstate->addr, mstate->size, mstate->protect, NULL);
    duckhook_log("  %sprotect memory %p (size=%"SIZE_T_FMT"u)\n",
                 ok ? "" : "failed to ",
                 mstate->addr, mstate->size);
    return ok ? 0 : -1;
}

void *duckhook_resolve_func(void *func)
{
    if (duckhook_debug_file != NULL) {
        char path[PATH_MAX];
        DWORD len = GetMappedFileNameA(GetCurrentProcess(), func, path, sizeof(path));
        if (len > 0) {
            duckhook_log("  func %p is in %.*s\n", func, (int)len, path);
        }
    }
    return func;
}
