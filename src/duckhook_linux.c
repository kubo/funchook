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
    page_size = sysconf(_SC_PAGE_SIZE);
    duckhook_log("  page_size=%"SIZE_T_FMT"u\n", page_size);
    return page_size;
}

void *duckhook_mem_alloc(void *hint)
{
    void *addr;
#ifdef CPU_X86_64
    FILE *fp = fopen("/proc/self/maps", "r");
    char buf[PATH_MAX];
    size_t prev_end = 0;
    void *old_hint = hint;

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        size_t start, end;
        duckhook_log("  process maps: %s", buf);
        if (sscanf(buf, "%"SIZE_T_FMT"x-%"SIZE_T_FMT"x", &start, &end) == 2) {
            if (prev_end == 0) {
                if (end >= (size_t)hint) {
                    prev_end = end;
                }
            } else {
                if (start - prev_end >= 3 * page_size) {
                    hint = (void*)(prev_end + page_size);
                    duckhook_log("  change hint address from %p to %p\n",
                                 old_hint, hint);
                    break;
                }
                prev_end = end;
            }
        }
    }
    fclose(fp);
#else
    hint = NULL;
#endif
    addr = mmap(hint, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    duckhook_log("  allocate memory %p (hint=%p, size=%"SIZE_T_FMT"u)\n", addr, hint, page_size);
    return addr;
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
#ifdef __GLIBC__
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
        duckhook_log("  func %p is not in a module. Use it anyway.\n", func);
        return func;
    }
    duckhook_log("  func %p(%s+0x%"SIZE_T_FMT"x) in module %s(base %p)\n",
                 func,
                 dli.dli_sname ? dli.dli_sname : dli.dli_fname,
                 dli.dli_sname ? ((size_t)func - (size_t)dli.dli_saddr) :
                 ((size_t)func - (size_t)dli.dli_fbase),
                 dli.dli_fname, dli.dli_fbase);
    ehdr = (ElfW(Ehdr) *)dli.dli_fbase;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        duckhook_log("  not a valid ELF module %s.\n", dli.dli_fname);
        return func;
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
            duckhook_log("  could not find link_map\n");
            return func;
        }
        break;
    default:
        duckhook_log("  ELF type is neither ET_EXEC nor ET_DYN.\n");
        return func;
    }
    duckhook_log("  link_map=%p\n", lmap);
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
                duckhook_log("  change func address from %p to %p\n",
                             func, fn);
                func = fn;
            }
            break;
        }
        symtab++;
    }
#endif
    return func;
}
