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

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

static size_t page_size;

size_t duckhook_page_size(duckhook_t *duckhook)
{
    page_size = sysconf(_SC_PAGE_SIZE);
    duckhook_log(duckhook, "  page_size=%"SIZE_T_FMT"u\n", page_size);
    return page_size;
}

#ifdef CPU_X86_64

static int get_free_address(duckhook_t *duckhook, void *func_addr, void **addr_out)
{
#if defined(__linux)
    FILE *fp = fopen("/proc/self/maps", "r");
    char buf[PATH_MAX];
    size_t prev_end = 0;

    if (fp == NULL) {
        duckhook_set_error_message(duckhook, "Failed to open /proc/self/maps (%s)",
                                   duckhook_strerror(errno, buf, sizeof(buf)));
        return DUCKHOOK_ERROR_INTERNAL_ERROR;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        size_t start, end;
        if (sscanf(buf, "%"SIZE_T_FMT"x-%"SIZE_T_FMT"x", &start, &end) == 2) {
            if (prev_end == 0) {
                if (end >= (size_t)func_addr) {
                    prev_end = end;
                }
            } else {
                if (start - prev_end >= page_size) {
                    *addr_out = (void*)(prev_end);
                    duckhook_log(duckhook, "  -- Use address %p for function %p\n",
                                 *addr_out, func_addr);
                    duckhook_log(duckhook, "  process map: %s", buf);
                    fclose(fp);
                    return 0;
                } else {
                    prev_end = end;
                }
            }
        }
        duckhook_log(duckhook, "  process map: %s", buf);
    }
    fclose(fp);
    duckhook_set_error_message(duckhook, "Could not find a free region after %p",
                               func_addr);
    return DUCKHOOK_ERROR_MEMORY_ALLOCATION;
#elif defined(__APPLE__)
    mach_port_t task = mach_task_self();
    vm_size_t size;
    vm_address_t start = (vm_address_t)func_addr;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object = 0;
    size_t prev_end = ((size_t)-1) - page_size;

    while (vm_region_64(task, &start, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_count, &object) == KERN_SUCCESS) {
        size_t end = start + size;
        if (prev_end + page_size <= start) {
            *addr_out = (void*)(prev_end);
            duckhook_log(duckhook, "  -- Use address %p for function %p\n",
                         *addr_out, func_addr);
            duckhook_log(duckhook, "  process map: %0"SIZE_T_WIDTH SIZE_T_FMT"x-%0"SIZE_T_WIDTH SIZE_T_FMT"x\n",
                         start, end);
            return 0;
        }
        duckhook_log(duckhook, "  process map: %0"SIZE_T_WIDTH SIZE_T_FMT"x-%0"SIZE_T_WIDTH SIZE_T_FMT"x\n",
                     start, end);
        start = prev_end = end;
    }
    duckhook_set_error_message(duckhook, "Could not find a free region after %p",
                               func_addr);
    return DUCKHOOK_ERROR_MEMORY_ALLOCATION;
#else
#error unsupported OS
#endif
}

#endif /* CPU_X86_64 */

int duckhook_page_alloc(duckhook_t *duckhook, duckhook_page_t **page_out, uint8_t *func, rip_displacement_t *disp)
{
#ifdef CPU_X86_64
    int loop_cnt;

    for (loop_cnt = 0; loop_cnt < 3; loop_cnt++) {
        void *target;
        int rv = get_free_address(duckhook, func, &target);

        if (rv != 0) {
            return rv;
        }
        *page_out = mmap(target, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (*page_out == target) {
            duckhook_log(duckhook, "  allocate page %p (size=%"SIZE_T_FMT"u)\n", *page_out, page_size);
            return 0;
        }
        if (*page_out == MAP_FAILED) {
            char errbuf[64];

            duckhook_set_error_message(duckhook, "mmap failed(addr=%p): %s", target,
                                       duckhook_strerror(errno, errbuf, sizeof(errbuf)));
            return DUCKHOOK_ERROR_MEMORY_ALLOCATION;
        }
        duckhook_log(duckhook, "  allocate page %p (hint=%p, size=%"SIZE_T_FMT"u)\n", *page_out, target, page_size);
        /* other thread might allocate memory at the target address. */
        munmap(*page_out, page_size);
    }
    duckhook_set_error_message(duckhook, "Failed to allocate memory in unused regions");
    return DUCKHOOK_ERROR_MEMORY_ALLOCATION;
#else
    *page_out = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (*page_out == MAP_FAILED) {
        char errbuf[64];

        duckhook_set_error_message(duckhook, "mmap failed: %s", duckhook_strerror(errno, errbuf, sizeof(errbuf)));
        return DUCKHOOK_ERROR_MEMORY_ALLOCATION;
    }
    duckhook_log(duckhook, "  allocate page %p (size=%"SIZE_T_FMT"u)\n", *page_out, page_size);
    return 0;
#endif
}

int duckhook_page_free(duckhook_t *duckhook, duckhook_page_t *page)
{
    int rv = munmap(page, page_size);
    duckhook_log(duckhook, "  %sdeallocate page %p (size=%"SIZE_T_FMT"u)\n",
                 (rv == 0) ? "" : "failed to ",
                 page,  page_size);
    return rv;
}

int duckhook_page_protect(duckhook_t *duckhook, duckhook_page_t *page)
{
    int rv = mprotect(page, page_size, PROT_READ | PROT_EXEC);
    duckhook_log(duckhook, "  %sprotect page %p (size=%"SIZE_T_FMT"u)\n",
                 (rv == 0) ? "" : "failed to ",
                 page, page_size);
    return rv;
}
int duckhook_page_unprotect(duckhook_t *duckhook, duckhook_page_t *page)
{
    int rv = mprotect(page, page_size, PROT_READ | PROT_WRITE);
    duckhook_log(duckhook, "  %sunprotect page %p (size=%"SIZE_T_FMT"u)\n",
                 (rv == 0) ? "" : "failed to ",
                 page, page_size);
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

char *duckhook_strerror(int errnum, char *buf, size_t buflen)
{
#if (!defined(__linux)) || (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && ! _GNU_SOURCE
    /* XSI-compliant strerror_r */
    if (strerror_r(errnum, buf, buflen) != 0) {
        snprintf(buf, buflen, "Unknown error %d", errnum);
    }
    return buf;
#else
    /* GNU-specific strerror_r */
    return strerror_r(errnum, buf, buflen);
#endif
}
