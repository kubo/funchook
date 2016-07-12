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
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include "duckhook_internal.h"

static size_t page_size;

size_t duckhook_mem_size()
{
    page_size = sysconf(_SC_PAGE_SIZE);;
    return page_size;
}

void *duckhook_mem_alloc(void *hint)
{
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    if ((size_t)hint < INT_MAX) {
        flags |= MAP_32BIT;
    }
    return mmap(hint, page_size, PROT_READ | PROT_WRITE, flags, -1, 0);
}

int duckhook_mem_free(void *mem)
{
    return munmap(mem, page_size);
}

int duckhook_mem_protect(void *addr)
{
    return mprotect(addr, page_size, PROT_READ | PROT_EXEC);
}
int duckhook_mem_unprotect(void *addr)
{
    return mprotect(addr, page_size, PROT_READ | PROT_WRITE);
}

int duckhook_unprotect_begin(mem_state_t *mstate, void *start, size_t len)
{
    static int prot_rw = 0;
    size_t saddr = ROUND_DOWN((size_t)start, page_size);
    int rv;

    len += (size_t)start - saddr;
    len = ROUND_UP(len, page_size);
    mstate->addr = (void*)saddr;
    mstate->size = len;
    if (prot_rw) {
        return mprotect(mstate->addr, mstate->size, PROT_READ | PROT_WRITE);
    }
    rv = mprotect(mstate->addr, mstate->size, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (rv == -1 && errno == EACCES) {
        prot_rw = 1;
        rv = mprotect(mstate->addr, mstate->size, PROT_READ | PROT_WRITE);
    }
    return rv;
}

int duckhook_unprotect_end(const mem_state_t *mstate)
{
    return mprotect(mstate->addr, mstate->size, PROT_READ | PROT_EXEC);
}

void *duckhook_resolve_func(void *func)
{
    Dl_info dli;
    const ElfW(Ehdr) *ehdr;
    struct link_map *lmap;
    const ElfW(Dyn) *dyn;
    const ElfW(Sym) *symtab = NULL;
    const ElfW(Sym) *symtab_end = NULL;
    const char *strtab = NULL;
    size_t strtab_size = 0;
    int i;

    if (dladdr(func, &dli) == 0) {
        return NULL;
    }
    ehdr = (ElfW(Ehdr) *)dli.dli_fbase;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        return NULL;
    }
    switch (ehdr->e_type) {
    case ET_EXEC:
        lmap = _r_debug.r_map;
        break;
    case ET_DYN:
        for (lmap = _r_debug.r_map; lmap != NULL; lmap = lmap->l_next) {
            if ((void*)lmap->l_addr == dli.dli_fbase) {
                break;
            }
        }
        if (lmap == NULL) {
            return NULL;
        }
        break;
    default:
        return NULL;
    }
    dyn = lmap->l_ld;

    for (i = 0; dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
        case DT_SYMTAB:
            symtab = (const ElfW(Sym) *)dyn[i].d_un.d_ptr;
            break;
        case DT_STRTAB:
            strtab = (const char *)dyn[i].d_un.d_ptr;
            break;
        case DT_STRSZ:
            strtab_size = dyn[i].d_un.d_val;
            break;
        }
    }
    symtab_end = (const ElfW(Sym) *)strtab;
    while (symtab < symtab_end) {
        if (symtab->st_name >= strtab_size) {
            break;
        }
        if (ELF64_ST_TYPE(symtab->st_info) == STT_FUNC &&
            symtab->st_size == 0 && (void*)symtab->st_value == func) {
            void *fn = dlsym(RTLD_DEFAULT, strtab + symtab->st_name);
            if (fn == func) {
                fn = dlsym(RTLD_NEXT, strtab + symtab->st_name);
            }
            if (fn != NULL) {
                func = fn;
            }
            break;
        }
        symtab++;
    }
    return func;
}

int duckhook_get_module_region(const uint8_t *addr, uint8_t **start, uint8_t **end)
{
    Dl_info dli;
    ElfW(Ehdr) *ehdr;
    ElfW(Phdr) *phdr;
    uint8_t *base = NULL;
    int i;

    *start = (uint8_t*)-1;
    *end = 0;

    if (dladdr(addr, &dli) == 0) {
        return -1;
    }
    ehdr = (ElfW(Ehdr) *)dli.dli_fbase;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        return -1;
    }
    if (ehdr->e_type == ET_DYN) {
        base = (uint8_t*)dli.dli_fbase;
    }
    phdr = (ElfW(Phdr) *)((size_t)dli.dli_fbase + ehdr->e_phoff);

    for (i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
	    *start = MIN(*start, base + phdr[i].p_vaddr);
	    *end = MAX(*end, base + phdr[i].p_vaddr + phdr[i].p_memsz);
	}
    }
    return 0;
}
