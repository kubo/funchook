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
#define PSAPI_VERSION 1
#include <stdint.h>
#include <windows.h>
#include <psapi.h>
#include "funchook_internal.h"

typedef struct page_info {
    struct page_info *next;
    struct page_info *prev;
    int num_used;
    char used[1];
} page_list_t;

const size_t page_size = PAGE_SIZE; /* 4K */
const size_t allocation_unit = ALLOCATION_UNIT; /* 64K */

static size_t max_num_pages = ALLOCATION_UNIT / PAGE_SIZE - 1; /* 15 */
static page_list_t page_list = {
    &page_list,
    &page_list,
};

static const char *to_errmsg(DWORD err, char *buf, size_t bufsiz)
{
    size_t len = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                NULL, err, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                                buf, (DWORD)bufsiz, NULL);
    if (len == 0) {
        return "Unknown Error";
    }
    if (len >= bufsiz) {
        len = bufsiz - 1;
    }
    while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n')) {
        len--;
    }
    buf[len] = '\0';
    return buf;
}

funchook_t *funchook_alloc(void)
{
    size_t size = ROUND_UP(funchook_size, page_size);
    return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
}

int funchook_free(funchook_t *funchook)
{
    VirtualFree(funchook, 0, MEM_RELEASE);
    return 0;
}

/* Reserve 64K bytes (allocation_unit) and use the first
 * 4K bytes (1 page) as the control page.
 */
static int alloc_page_info(funchook_t *funchook, page_list_t **pl_out, void *hint)
{
    void *addr;
    page_list_t *pl;
#ifdef CPU_X86_64
    void *old_hint = hint;
    while (1) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(hint, &mbi, sizeof(mbi)) == 0) {
            DWORD err = GetLastError();
            char errbuf[128];

            funchook_set_error_message(funchook, "Failed to execute VirtualQuery (addr=%p, error=%lu(%s))",
                                       hint,
                                       err, to_errmsg(err, errbuf, sizeof(errbuf)));
            return FUNCHOOK_ERROR_MEMORY_FUNCTION;
        }
        funchook_log(funchook, "  process map: %016I64x-%016I64x %s\n",
                     (size_t)mbi.BaseAddress, (size_t)mbi.BaseAddress + mbi.RegionSize,
                     (mbi.State == MEM_FREE) ? "free" : "used");
        if (mbi.State == MEM_FREE) {
            size_t addr = ROUND_UP((size_t)mbi.BaseAddress, allocation_unit);
            intptr_t diff = addr - (size_t)mbi.BaseAddress;
            if (diff >= 0) {
                if (mbi.RegionSize - diff >= allocation_unit) {
                    hint = (void*)addr;
                    funchook_log(funchook, "  change hint address from %p to %p\n",
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
    if (pl == NULL) {
        DWORD err = GetLastError();
        char errbuf[128];

        funchook_set_error_message(funchook, "Failed to reserve memory %p (hint=%p, size=%"PRIuPTR", errro=%lu(%s))",
                                   pl, hint, allocation_unit,
                                   err, to_errmsg(err, errbuf, sizeof(errbuf)));
        return FUNCHOOK_ERROR_MEMORY_ALLOCATION;
    }
    funchook_log(funchook, "  reserve memory %p (hint=%p, size=%"PRIuPTR")\n", pl, hint, allocation_unit);
    addr = VirtualAlloc(pl, page_size, MEM_COMMIT, PAGE_READWRITE);
    if (addr == NULL) {
        DWORD err = GetLastError();
        char errbuf[128];

        funchook_set_error_message(funchook, "Failed to commit memory %p for read-write (hint=%p, size=%"PRIuPTR", error=%lu(%s))",
                                   addr, pl, page_size,
                                   err, to_errmsg(err, errbuf, sizeof(errbuf)));
        VirtualFree(pl, 0, MEM_RELEASE);
        return FUNCHOOK_ERROR_MEMORY_FUNCTION;
    }
    funchook_log(funchook, "  commit memory %p for read-write (hint=%p, size=%"PRIuPTR")\n", addr, pl, page_size);
    pl->next = page_list.next;
    pl->prev = &page_list;
    page_list.next->prev = pl;
    page_list.next = pl;
    *pl_out = pl;
    return 0;
}

/*
 * Get one page from page_list, commit it and return it.
 */
int funchook_page_alloc(funchook_t *funchook, funchook_page_t **page_out, uint8_t *func, ip_displacement_t *disp)
{
    page_list_t *pl;
    funchook_page_t *page = NULL;
    size_t i;

    for (pl = page_list.next; pl != &page_list; pl = pl->next) {
        for (i = 0; i < max_num_pages; i++) {
            if (!pl->used[i]) {
                funchook_page_t *p = (funchook_page_t *)((size_t)pl + (i + 1) * page_size);
                if (funchook_page_avail(funchook, p, 0, func, disp)) {
                    page = p;
                    goto exit_loop;
                }
            }
        }
    }
exit_loop:
    if (page == NULL) {
        /* no page_list is available. */
        int rv = alloc_page_info(funchook, &pl, func);
        if (rv != 0) {
            return rv;
        }
        i = 0;
        page = (funchook_page_t *)((size_t)pl + page_size);
    }
    if (VirtualAlloc(page, page_size, MEM_COMMIT, PAGE_READWRITE) == NULL) {
        DWORD err = GetLastError();
        char errbuf[128];

        funchook_set_error_message(funchook, "Failed to commit page %p (base=%p(used=%d), idx=%"PRIuPTR", size=%"PRIuPTR", error=%lu(%s))",
                                   page, pl, pl->num_used, i, page_size,
                                   err, to_errmsg(err, errbuf, sizeof(errbuf)));
        return FUNCHOOK_ERROR_MEMORY_FUNCTION;
    }
    pl->used[i] = 1;
    pl->num_used++;
    funchook_log(funchook, "  commit page %p (base=%p(used=%d), idx=%"PRIuPTR", size=%"PRIuPTR")\n",
                 page, pl, pl->num_used, i, page_size);
    *page_out = page;
    return 0;
}

/*
 * Back to one page to page_list.
 */
int funchook_page_free(funchook_t *funchook, funchook_page_t *page)
{
    page_list_t *pl = (page_list_t *)((size_t)page & ~(allocation_unit - 1));
    size_t idx = ((size_t)page - (size_t)pl) / page_size - 1;
    BOOL ok;

    ok = VirtualFree(page, page_size, MEM_DECOMMIT);
    if (!ok) {
        DWORD err = GetLastError();
        char errbuf[128];

        funchook_set_error_message(funchook, "Failed to decommit page %p (base=%p(used=%d), idx=%"PRIuPTR", size=%"PRIuPTR", error=%lu(%s))",
                                   page, pl, pl->num_used, idx, page_size,
                                   err, to_errmsg(err, errbuf, sizeof(errbuf)));
        return FUNCHOOK_ERROR_MEMORY_FUNCTION;
    }
    funchook_log(funchook, "  decommit page %p (base=%p(used=%d), idx=%"PRIuPTR", size=%"PRIuPTR")\n",
                 page, pl, pl->num_used, idx, page_size);
    pl->num_used--;
    pl->used[idx] = 0;
    if (pl->num_used != 0) {
        return 0;
    }
    /* all pages in this allocation unit are decommitted. delete this page_list */
    pl->next->prev = pl->prev;
    pl->prev->next = pl->next;
    ok = VirtualFree(pl, 0, MEM_RELEASE);
    if (!ok) {
        DWORD err = GetLastError();
        char errbuf[128];

        funchook_set_error_message(funchook, "Failed to release memory %p (size=%"PRIuPTR", error=%lu(%s))",
                                   pl, allocation_unit,
                                   err, to_errmsg(err, errbuf, sizeof(errbuf)));
        return FUNCHOOK_ERROR_MEMORY_FUNCTION;
    }
    funchook_log(funchook, "  release memory %p (size=%"PRIuPTR")\n",
                 pl, allocation_unit);
    return 0;
}

int funchook_page_protect(funchook_t *funchook, funchook_page_t *page)
{
    char errbuf[128];
    DWORD oldprot;
    BOOL ok = VirtualProtect(page, page_size, PAGE_EXECUTE_READ, &oldprot);

    if (ok) {
        funchook_log(funchook, "  protect page %p (size=%"PRIuPTR", prot=read,exec)\n",
                     page, page_size);
        return 0;
    }
    funchook_set_error_message(funchook, "Failed to protect page %p (size=%"PRIuPTR", prot=read,exec, error=%lu(%s))",
                               page, page_size,
                               GetLastError(), to_errmsg(GetLastError(), errbuf, sizeof(errbuf)));
    return FUNCHOOK_ERROR_MEMORY_FUNCTION;
}

int funchook_page_unprotect(funchook_t *funchook, funchook_page_t *page)
{
    char errbuf[128];
    DWORD oldprot;
    BOOL ok = VirtualProtect(page, page_size, PAGE_READWRITE, &oldprot);

    if (ok) {
        funchook_log(funchook, "  unprotect page %p (size=%"PRIuPTR", prot=read,write)\n",
                     page, page_size);
        return 0;
    }
    funchook_set_error_message(funchook, "Failed to unprotect page %p (size=%"PRIuPTR", prot=read,write, error=%lu(%s))",
                               page, page_size,
                               GetLastError(), to_errmsg(GetLastError(), errbuf, sizeof(errbuf)));
    return FUNCHOOK_ERROR_MEMORY_FUNCTION;
}

int funchook_unprotect_begin(funchook_t *funchook, mem_state_t *mstate, void *start, size_t len)
{
    char errbuf[128];
    size_t saddr = ROUND_DOWN((size_t)start, page_size);
    BOOL ok;

    mstate->addr = (void*)saddr;
    mstate->size = len + (size_t)start - saddr;
    mstate->size = ROUND_UP(mstate->size, page_size);
    ok = VirtualProtect(mstate->addr, mstate->size, PAGE_EXECUTE_READWRITE, &mstate->protect);
    if (ok) {
        funchook_log(funchook, "  unprotect memory %p (size=%"PRIuPTR") <- %p (size=%"PRIuPTR")\n",
                     mstate->addr, mstate->size, start, len);
        return 0;
    }
    funchook_set_error_message(funchook, "Failed to unprotect memory %p (size=%"PRIuPTR") <- %p (size=%"PRIuPTR", error=%lu(%s))",
                               mstate->addr, mstate->size, start, len,
                               GetLastError(), to_errmsg(GetLastError(), errbuf, sizeof(errbuf)));
    return FUNCHOOK_ERROR_MEMORY_FUNCTION;
}

int funchook_unprotect_end(funchook_t *funchook, const mem_state_t *mstate)
{
    char errbuf[128];
    DWORD oldprot;
    BOOL ok = VirtualProtect(mstate->addr, mstate->size, mstate->protect, &oldprot);

    if (ok) {
        funchook_log(funchook, "  protect memory %p (size=%"PRIuPTR")\n",
                     mstate->addr, mstate->size);
        return 0;
    }
    funchook_set_error_message(funchook, "Failed to protect memory %p (size=%"PRIuPTR", error=%lu(%s))",
                               mstate->addr, mstate->size,
                               GetLastError(), to_errmsg(GetLastError(), errbuf, sizeof(errbuf)));
    return FUNCHOOK_ERROR_MEMORY_FUNCTION;
}

static IMAGE_IMPORT_DESCRIPTOR *get_image_import_descriptor(HMODULE hMod, DWORD *cnt)
{
    IMAGE_DOS_HEADER *doshdr;
    IMAGE_NT_HEADERS *nthdr;
    IMAGE_DATA_DIRECTORY *dir;

    if (memcmp(hMod, "MZ", 2) != 0) {
        return NULL;
    }
    doshdr = (IMAGE_DOS_HEADER*)hMod;
    nthdr = (PIMAGE_NT_HEADERS)((size_t)hMod + doshdr->e_lfanew);
    dir = &nthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir->VirtualAddress == 0) {
        return NULL;
    }
    *cnt = dir->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    return (IMAGE_IMPORT_DESCRIPTOR*)((size_t)hMod + dir->VirtualAddress);
}

void *funchook_resolve_func(funchook_t *funchook, void *func)
{
    char path[MAX_PATH];
    HMODULE hMod;
    BOOL ok;
    IMAGE_IMPORT_DESCRIPTOR *desc_head, *desc;
    uint8_t *fn = (uint8_t*)func;
    size_t pos = 0;
    DWORD cnt;

    if (*funchook_debug_file != '\0') {
        DWORD len = GetMappedFileNameA(GetCurrentProcess(), func, path, sizeof(path));
        if (len > 0) {
            funchook_log(funchook, "  func %p is in %.*s\n", func, (int)len, path);
        }
    }
    if (fn[0] == 0xe9) {
        fn = (fn + 5) + *(int*)(fn + 1);
        funchook_log(funchook, "  relative jump to %p\n", fn);
    }
    if (fn[0] == 0xff && fn[1] == 0x25) {
#ifdef CPU_X86_64
        pos = (size_t)(fn + 6) + *(int*)(fn + 2);
#else
        pos = *(size_t*)(fn + 2);
#endif
        funchook_log(funchook, "  indirect jump to addresss at %p\n", (void*)pos);
    }
    if (pos == 0) {
        return func;
    }
    ok = GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, func, &hMod);
    if (!ok) {
        return func;
    }

    desc_head = get_image_import_descriptor(hMod, &cnt);
    if (desc_head == NULL) {
        return func;
    }

    for (desc = desc_head; desc->Name != 0; desc++) {
        IMAGE_THUNK_DATA *addr_thunk = (IMAGE_THUNK_DATA*)((char*)hMod + desc->FirstThunk);

        while (addr_thunk->u1.Function != 0) {
            if (pos == (size_t)&addr_thunk->u1.Function) {
                func = (void*)addr_thunk->u1.Function;
                if (*funchook_debug_file != '\0') {
                    DWORD len = GetMappedFileNameA(GetCurrentProcess(), func, path, sizeof(path));
                    if (len > 0) {
                        funchook_log(funchook, "  -> func %p in %.*s\n", func, (int)len, path);
                    } else {
                        funchook_log(funchook, "  -> func %p\n", func);
                    }
                }
                return func;
            }
            addr_thunk++;
        }
    }
    return func;
}
