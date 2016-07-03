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
#include <stddef.h>
#include <windows.h>
#include "duckhook_internal.h"

size_t allocation_unit;
size_t code_mem_count_in_buffer;

static size_t page_size;

void *duckhook_mem_alloc(void *hint)
{
    void *mem;

    if (allocation_unit == 0) {
        SYSTEM_INFO si;

        GetSystemInfo(&si);
        page_size = si.dwPageSize;
        allocation_unit = si.dwAllocationGranularity;
        code_mem_count_in_buffer = (allocation_unit - offsetof(code_mem_buffer_t, code_mem)) / sizeof(code_mem_t);
    }
    mem = VirtualAlloc(hint, allocation_unit, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (mem == NULL) {
        return (void *)-1;
    }
    return mem;
}

int duckhook_mem_free(void *mem)
{
    return VirtualFree(mem, 0, MEM_RELEASE) ? 0 : -1;
}

int duckhook_unprotect_begin(mem_state_t *mstate, void *start, size_t len)
{
    size_t saddr = ROUND_DOWN((size_t)start, page_size);

    len += (size_t)start - saddr;
    len = ROUND_UP(len, page_size);
    mstate->addr = (void*)saddr;
    mstate->size = len;
    return VirtualProtect(mstate->addr, mstate->size, PAGE_READWRITE, &mstate->protect) ? 0 : -1;
}

int duckhook_unprotect_end(const mem_state_t *mstate)
{
    return VirtualProtect(mstate->addr, mstate->size, mstate->protect, NULL) ? 0 : -1;
}

void *duckhook_resolve_func(void *func)
{
    return func;
}

int duckhook_get_module_region(const uchar *addr, uchar **start, uchar **end)
{
    MEMORY_BASIC_INFORMATION mbi;
    IMAGE_DOS_HEADER *dhdr;
    IMAGE_NT_HEADERS *nthdr;

    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) {
        return -1;
    }
    dhdr = (IMAGE_DOS_HEADER *)mbi.AllocationBase;
    if (dhdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return -1;
    }
    nthdr = (IMAGE_NT_HEADERS *)((size_t)mbi.AllocationBase + dhdr->e_lfanew);
    if (nthdr->Signature != IMAGE_NT_SIGNATURE) {
        return -1;
    }
    *start = (uchar*)mbi.AllocationBase;
    *end = *start + nthdr->OptionalHeader.SizeOfImage;
    return 0;
}
