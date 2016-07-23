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
#ifdef __linux
#include <elf.h>
#include <link.h>
#endif
#ifdef __APPLE__
#include <mach/mach.h>
#endif
#include "duckhook_internal.h"

static size_t page_size;

size_t duckhook_mem_size(duckhook_t *duckhook)
{
    page_size = sysconf(_SC_PAGE_SIZE);
    duckhook_log(duckhook, "  page_size=%"SIZE_T_FMT"u\n", page_size);
    return page_size;
}

void *duckhook_mem_alloc(duckhook_t *duckhook, void *hint)
{
    void *addr;
#ifdef CPU_X86_64
#if defined(__linux)
    FILE *fp = fopen("/proc/self/maps", "r");
    char buf[PATH_MAX];
    size_t prev_end = 0;
    void *old_hint = hint;

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        size_t start, end;
        if (sscanf(buf, "%"SIZE_T_FMT"x-%"SIZE_T_FMT"x", &start, &end) == 2) {
            if (prev_end == 0) {
                if (end >= (size_t)hint) {
                    prev_end = end;
                }
            } else {
                if (start - prev_end >= page_size) {
                    hint = (void*)(prev_end);
                    duckhook_log(duckhook, "  -- change hint address from %p to %p\n",
                                 old_hint, hint);
                } else {
                    prev_end = end;
                }
            }
        }
        duckhook_log(duckhook, "  process map: %s", buf);
        if (hint != old_hint) {
            break;
        }
    }
    fclose(fp);
#elif defined(__APPLE__)
    mach_port_t task = mach_task_self();
    vm_size_t size;
    vm_address_t start = (vm_address_t)hint;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object = 0;
    size_t prev_end = ((size_t)-1) - page_size;
    void *old_hint = hint;

    while (vm_region_64(task, &start, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_count, &object) == KERN_SUCCESS) {
        size_t end = start + size;
        if (prev_end + page_size <= start) {
            hint = (void*)(prev_end);
            duckhook_log(duckhook, "  -- change hint address from %p to %p\n",
                         old_hint, hint);
        }
        duckhook_log(duckhook, "  process map: %0"SIZE_T_WIDTH SIZE_T_FMT"x-%0"SIZE_T_WIDTH SIZE_T_FMT"x\n",
                     start, end);
        if (hint != old_hint) {
            break;
        }
        start = prev_end = end;
    }
#else
#error unsupported OS
#endif
#else
    hint = NULL;
#endif
    addr = mmap(hint, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    duckhook_log(duckhook, "  allocate page %p (hint=%p, size=%"SIZE_T_FMT"u)\n", addr, hint, page_size);
    return addr;
}

int duckhook_mem_free(duckhook_t *duckhook, void *mem)
{
    int rv = munmap(mem, page_size);
    duckhook_log(duckhook, "  %sdeallocate page %p (size=%"SIZE_T_FMT"u)\n",
                 (rv == 0) ? "" : "failed to ",
                 mem,  page_size);
    return rv;
}

int duckhook_mem_protect(duckhook_t *duckhook, void *addr)
{
    int rv = mprotect(addr, page_size, PROT_READ | PROT_EXEC);
    duckhook_log(duckhook, "  %sprotect page %p (size=%"SIZE_T_FMT"u)\n",
                 (rv == 0) ? "" : "failed to ",
                 addr, page_size);
    return rv;
}
int duckhook_mem_unprotect(duckhook_t *duckhook, void *addr)
{
    int rv = mprotect(addr, page_size, PROT_READ | PROT_WRITE);
    duckhook_log(duckhook, "  %sunprotect page %p (size=%"SIZE_T_FMT"u)\n",
                 (rv == 0) ? "" : "failed to ",
                 addr, page_size);
    return rv;
}

int duckhook_unprotect_begin(duckhook_t *duckhook, mem_state_t *mstate, void *start, size_t len)
{
    static int prot_rw = 0;
    size_t saddr = ROUND_DOWN((size_t)start, page_size);
    int rv;

    mstate->addr = (void*)saddr;
    mstate->size = len + (size_t)start - saddr;
    mstate->size = ROUND_UP(mstate->size, page_size);
    if (prot_rw) {
        rv = mprotect(mstate->addr, mstate->size, PROT_READ | PROT_WRITE);
        duckhook_log(duckhook, "  %sunprotect memory %p (size=%"SIZE_T_FMT"u, prot=read,write) <- %p (size=%"SIZE_T_FMT"u)\n",
                     (rv == 0) ? "" : "failed to ",
                     mstate->addr, mstate->size, start, len);
        return rv;
    }
    rv = mprotect(mstate->addr, mstate->size, PROT_READ | PROT_WRITE | PROT_EXEC);
    duckhook_log(duckhook, "  %sunprotect memory %p (size=%"SIZE_T_FMT"u, prot=read,write,exec) <- %p (size=%"SIZE_T_FMT"u)\n",
                 (rv == 0) ? "" : "failed to ",
                 mstate->addr, mstate->size, start, len);
    if (rv == -1 && errno == EACCES) {
        prot_rw = 1;
        rv = mprotect(mstate->addr, mstate->size, PROT_READ | PROT_WRITE);
        duckhook_log(duckhook, "  %sunprotect memory %p (size=%"SIZE_T_FMT"u, prot=read,write)\n",
                     (rv == 0) ? "" : "failed to ",
                     mstate->addr, mstate->size);
    }
    return rv;
}

int duckhook_unprotect_end(duckhook_t *duckhook, const mem_state_t *mstate)
{
    int rv = mprotect(mstate->addr, mstate->size, PROT_READ | PROT_EXEC);
    duckhook_log(duckhook, "  %sprotect memory %p (size=%"SIZE_T_FMT"u, prot=read,exec)\n",
                 (rv == 0) ? "" : "failed to ",
                 mstate->addr, mstate->size);
    return rv;
}

void *duckhook_resolve_func(duckhook_t *duckhook, void *func)
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
        duckhook_log(duckhook, "  func %p is not in a module. Use it anyway.\n", func);
        return func;
    }
    duckhook_log(duckhook, "  func %p(%s+0x%"SIZE_T_FMT"x) in module %s(base %p)\n",
                 func,
                 dli.dli_sname ? dli.dli_sname : dli.dli_fname,
                 dli.dli_sname ? ((size_t)func - (size_t)dli.dli_saddr) :
                 ((size_t)func - (size_t)dli.dli_fbase),
                 dli.dli_fname, dli.dli_fbase);
    ehdr = (ElfW(Ehdr) *)dli.dli_fbase;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        duckhook_log(duckhook, "  not a valid ELF module %s.\n", dli.dli_fname);
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
            duckhook_log(duckhook, "  could not find link_map\n");
            return func;
        }
        break;
    default:
        duckhook_log(duckhook, "  ELF type is neither ET_EXEC nor ET_DYN.\n");
        return func;
    }
    duckhook_log(duckhook, "  link_map=%p\n", lmap);
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
                duckhook_log(duckhook, "  change func address from %p to %p\n",
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
