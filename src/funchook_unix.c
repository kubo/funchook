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
#include <stdlib.h>
#include <mach/mach.h>
#endif
#include "funchook_internal.h"

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

const size_t page_size = PAGE_SIZE;

const char *funchook_strerror(int errnum, char *buf, size_t buflen)
{
#ifdef GNU_SPECIFIC_STRERROR_R
    /* GNU-specific version */
    return strerror_r(errnum, buf, buflen);
#else
    /* XSI-compliant version */
    if (strerror_r(errnum, buf, buflen) != 0) {
        snprintf(buf, buflen, "errno %d", errnum);
    }
    return buf;
#endif
}

funchook_t *funchook_alloc(void)
{
    size_t size = ROUND_UP(funchook_size, page_size);
    void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == (void*)-1) {
        return NULL;
    }
    return (funchook_t*)mem;
}

int funchook_free(funchook_t *funchook)
{
    size_t size = ROUND_UP(funchook_size, page_size);
    munmap(funchook, size);
    return 0;
}

#if defined(CPU_64BIT)

typedef struct memory_map memory_map_t;
static int memory_map_open(funchook_t *funchook, memory_map_t *mmap);
static int memory_map_next(memory_map_t *mmap, size_t *start, size_t *end);
static void memory_map_close(memory_map_t *mmap);

#if defined(__linux)
static char scan_address(const char **str, size_t *addr_p)
{
    size_t addr = 0;
    const char *s = *str;

    while (1) {
        char c = *(s++);

        if ('0' <= c && c <= '9') {
            addr = (addr * 16) + (c - '0');
        } else if ('a' <= c && c <= 'f') {
            addr = (addr * 16) + (c - 'a' + 10);
        } else {
            *str = s;
            *addr_p = addr;
            return c;
        }
    }
}

struct memory_map {
    FILE *fp;
};

static int memory_map_open(funchook_t *funchook, memory_map_t *mm)
{
    char buf[64];
    mm->fp = fopen("/proc/self/maps", "r");
    if (mm->fp == NULL) {
        funchook_set_error_message(funchook, "Failed to open /proc/self/maps (%s)",
                                   funchook_strerror(errno, buf, sizeof(buf)));
        return FUNCHOOK_ERROR_INTERNAL_ERROR;
    }
    return 0;
}

static int memory_map_next(memory_map_t *mm, size_t *start, size_t *end)
{
    char buf[PATH_MAX];
    const char *str = buf;

    if (fgets(buf, sizeof(buf), mm->fp) == NULL) {
        return -1;
    }
    if (scan_address(&str, start) != '-') {
        return -1;
    }
    if (scan_address(&str, end) != ' ') {
        return -1;
    }
    return 0;
}

static void memory_map_close(memory_map_t *mm)
{
    fclose(mm->fp);
}

#elif defined(__APPLE__)

struct memory_map {
    mach_port_t task;
    vm_address_t addr;
};

static int memory_map_open(funchook_t *funchook, memory_map_t *mm)
{
    mm->task = mach_task_self();
    mm->addr = 0;
    return 0;
}

static int memory_map_next(memory_map_t *mm, size_t *start, size_t *end)
{
    vm_size_t size;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object = 0;

    if (vm_region_64(mm->task, &mm->addr, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_count, &object) != KERN_SUCCESS) {
        return -1;
    }
    *start = mm->addr;
    *end = mm->addr + size;
    mm->addr += size;
    return 0;
}

static void memory_map_close(memory_map_t *mm)
{
    return;
}

#else
#error unsupported OS
#endif

static int get_free_address(funchook_t *funchook, void *func_addr, void *addrs[2])
{
    memory_map_t mm;
    size_t prev_end = 0;
    size_t start, end;
    int rv;

    if ((rv = memory_map_open(funchook, &mm)) != 0) {
        return rv;
    }
    addrs[0] = addrs[1] = NULL;

    while (memory_map_next(&mm, &start, &end) == 0) {
        funchook_log(funchook, "  process map: "ADDR_FMT"-"ADDR_FMT", prev_end=%"PRIxPTR",addr={%"PRIxPTR",%"PRIxPTR"},psz=%"PRIxPTR"\n",
                     start, end, prev_end, (size_t)addrs[0], (size_t)addrs[1], page_size);
        if (prev_end + page_size <= start) {
            if (start < (size_t)func_addr) {
                size_t addr = start - page_size;
                if ((size_t)func_addr - addr < INT32_MAX) {
                    /* unused memory region before func_addr. */
                    addrs[0] = (void*)addr;
                }
            }
            if ((size_t)func_addr < prev_end) {
                if (prev_end - (size_t)func_addr < INT32_MAX) {
                    /* unused memory region after func_addr. */
                    addrs[1] = (void*)prev_end;
                }
                funchook_log(funchook, "  -- Use address %p or %p for function %p\n",
                             addrs[0], addrs[1], func_addr);
                memory_map_close(&mm);
                return 0;
            }
        }
        prev_end = end;
    }
    if ((size_t)func_addr < prev_end) {
        if (prev_end - (size_t)func_addr < INT32_MAX) {
            /* unused memory region after func_addr. */
            addrs[1] = (void*)prev_end;
        }
        funchook_log(funchook, "  -- Use address %p or %p for function %p\n",
                     addrs[0], addrs[1], func_addr);
        memory_map_close(&mm);
        return 0;
    }
    memory_map_close(&mm);
    funchook_set_error_message(funchook, "Could not find a free region near %p",
                               func_addr);
    return FUNCHOOK_ERROR_MEMORY_ALLOCATION;
}

#endif /* defined(CPU_64BIT) */

int funchook_page_alloc(funchook_t *funchook, funchook_page_t **page_out, uint8_t *func, ip_displacement_t *disp)
{
#if defined(CPU_64BIT)
    int loop_cnt;

    /* Loop three times just to avoid rare cases such as
     * unused memory region is used between 'get_free_address()'
     * and 'mmap()'.
     */
    for (loop_cnt = 0; loop_cnt < 3; loop_cnt++) {
        void *addrs[2];
        int rv = get_free_address(funchook, func, addrs);
        int i;

        if (rv != 0) {
            return rv;
        }
        for (i = 1; i >= 0; i--) {
            /* Try to use addr[1] (unused memory region after `func`)
             * and then addr[0] (before `func`)
             */
            if (addrs[i] == NULL) {
                continue;
            }
            *page_out = mmap(addrs[i], page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (*page_out == addrs[i]) {
                funchook_log(funchook, "  allocate page %p (size=%"PRIuPTR")\n", *page_out, page_size);
                return 0;
            }
            if (*page_out == MAP_FAILED) {
                char errbuf[128];

                funchook_set_error_message(funchook, "mmap failed(addr=%p): %s", addrs[i],
                                           funchook_strerror(errno, errbuf, sizeof(errbuf)));
                return FUNCHOOK_ERROR_MEMORY_ALLOCATION;
            }
            funchook_log(funchook, "  try to allocate %p but %p (size=%"PRIuPTR")\n", addrs[i], *page_out, page_size);
            munmap(*page_out, page_size);
        }
    }
    funchook_set_error_message(funchook, "Failed to allocate memory in unused regions");
    return FUNCHOOK_ERROR_MEMORY_ALLOCATION;
#else
    char errbuf[128];

    *page_out = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (*page_out != MAP_FAILED) {
        funchook_log(funchook, "  allocate page %p (size=%"PRIuPTR")\n", *page_out, page_size);
        return 0;
    }
    funchook_set_error_message(funchook, "mmap failed: %s", funchook_strerror(errno, errbuf, sizeof(errbuf)));
    return FUNCHOOK_ERROR_MEMORY_ALLOCATION;
#endif
}

int funchook_page_free(funchook_t *funchook, funchook_page_t *page)
{
    char errbuf[128];
    int rv = munmap(page, page_size);

    if (rv == 0) {
        funchook_log(funchook, " deallocate page %p (size=%"PRIuPTR")\n",
                     page, page_size);
        return 0;
    }
    funchook_set_error_message(funchook, "Failed to deallocate page %p (size=%"PRIuPTR", error=%s)",
                               page, page_size,
                               funchook_strerror(errno, errbuf, sizeof(errbuf)));
    return FUNCHOOK_ERROR_MEMORY_FUNCTION;
}

int funchook_page_protect(funchook_t *funchook, funchook_page_t *page)
{
    char errbuf[128];
    int rv = mprotect(page, page_size, PROT_READ | PROT_EXEC);

    if (rv == 0) {
        funchook_log(funchook, "  protect page %p (size=%"PRIuPTR")\n",
                     page, page_size);
        return 0;
    }
    funchook_set_error_message(funchook, "Failed to protect page %p (size=%"PRIuPTR", error=%s)",
                               page, page_size,
                               funchook_strerror(errno, errbuf, sizeof(errbuf)));
    return FUNCHOOK_ERROR_MEMORY_FUNCTION;
}

int funchook_page_unprotect(funchook_t *funchook, funchook_page_t *page)
{
    char errbuf[128];
    int rv = mprotect(page, page_size, PROT_READ | PROT_WRITE);

    if (rv == 0) {
        funchook_log(funchook, "  unprotect page %p (size=%"PRIuPTR")\n",
                     page, page_size);
        return 0;
    }
    funchook_set_error_message(funchook, "Failed to unprotect page %p (size=%"PRIuPTR", error=%s)",
                               page, page_size,
                               funchook_strerror(errno, errbuf, sizeof(errbuf)));
    return FUNCHOOK_ERROR_MEMORY_FUNCTION;
}

int funchook_unprotect_begin(funchook_t *funchook, mem_state_t *mstate, void *start, size_t len)
{
    static int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    char errbuf[128];
    size_t saddr = ROUND_DOWN((size_t)start, page_size);
    int rv;

    mstate->addr = (void*)saddr;
    mstate->size = len + (size_t)start - saddr;
    mstate->size = ROUND_UP(mstate->size, page_size);
    rv = mprotect(mstate->addr, mstate->size, prot);
    if (rv == 0) {
        funchook_log(funchook, "  unprotect memory %p (size=%"PRIuPTR", prot=read,write%s) <- %p (size=%"PRIuPTR")\n",
                     mstate->addr, mstate->size, (prot & PROT_EXEC) ? ",exec" : "", start, len);
        return 0;
    }
    if (rv == -1 && errno == EACCES && (prot & PROT_EXEC)) {
        rv = mprotect(mstate->addr, mstate->size, PROT_READ | PROT_WRITE);
        if (rv == 0) {
            prot = PROT_READ | PROT_WRITE;
            funchook_log(funchook, "  unprotect memory %p (size=%"PRIuPTR", prot=read,write) <- %p (size=%"PRIuPTR")\n",
                         mstate->addr, mstate->size, start, len);
            return 0;
        }
    }
    funchook_set_error_message(funchook, "Failed to unprotect memory %p (size=%"PRIuPTR", prot=read,write%s) <- %p (size=%"PRIuPTR", error=%s)",
                               mstate->addr, mstate->size, (prot & PROT_EXEC) ? ",exec" : "", start, len,
                               funchook_strerror(errno, errbuf, sizeof(errbuf)));
    return FUNCHOOK_ERROR_MEMORY_FUNCTION;
}

int funchook_unprotect_end(funchook_t *funchook, const mem_state_t *mstate)
{
    char errbuf[128];
    int rv = mprotect(mstate->addr, mstate->size, PROT_READ | PROT_EXEC);

    if (rv == 0) {
        funchook_log(funchook, "  protect memory %p (size=%"PRIuPTR", prot=read,exec)\n",
                     mstate->addr, mstate->size);
        return 0;
    }
    funchook_set_error_message(funchook, "Failed to protect memory %p (size=%"PRIuPTR", prot=read,exec, error=%s)",
                               mstate->addr, mstate->size,
                               funchook_strerror(errno, errbuf, sizeof(errbuf)));
    return FUNCHOOK_ERROR_MEMORY_FUNCTION;
}

void *funchook_resolve_func(funchook_t *funchook, void *func)
{
#ifdef __GLIBC__
    struct link_map *lmap, *lm;
    const ElfW(Ehdr) *ehdr;
    const ElfW(Dyn) *dyn;
    const ElfW(Sym) *symtab = NULL;
    const ElfW(Sym) *symtab_end = NULL;
    const char *strtab = NULL;
    size_t strtab_size = 0;
    int i;

    lmap = NULL;
    for (lm = _r_debug.r_map; lm != NULL; lm = lm->l_next) {
        if ((void*)lm->l_addr <= func) {
            if (lmap == NULL) {
                lmap = lm;
            } else if (lmap->l_addr > lm->l_addr) {
                lmap = lm;
            }
        }
    }
    if (lmap == NULL) {
        return func;
    }
    if (lmap->l_addr != 0) {
        ehdr = (ElfW(Ehdr) *)lmap->l_addr;
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
            funchook_log(funchook, "  not a valid ELF module %s.\n", lmap->l_name);
            return func;
        }
        if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
          funchook_log(funchook, "  ELF type is neither ET_EXEC nor ET_DYN.\n");
          return func;
        }
    }
    funchook_log(funchook, "  link_map addr=%p, name=%s\n", (void*)lmap->l_addr, lmap->l_name);
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
                funchook_log(funchook, "  change %s address from %p to %p\n",
                             strtab + symtab->st_name, func, fn);
                func = fn;
            }
            break;
        }
        symtab++;
    }
#endif
    return func;
}
