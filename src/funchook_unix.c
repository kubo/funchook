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
#include <mach/mach.h>
#endif
#include "funchook_io.h"
#include "funchook_internal.h"

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

const size_t page_size = PAGE_SIZE;

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

#ifdef CPU_X86_64

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
#endif

static int get_free_address(funchook_t *funchook, void *func_addr, void **addr_out)
{
#if defined(__linux)
    funchook_io_t io;
    char buf[PATH_MAX];
    size_t prev_end = 0;

    if (funchook_io_open(&io, "/proc/self/maps", FUNCHOOK_IO_READ) != 0) {
        funchook_set_error_message(funchook, "Failed to open /proc/self/maps (%s)",
                                   funchook_strerror(errno, buf, sizeof(buf)));
        return FUNCHOOK_ERROR_INTERNAL_ERROR;
    }

    while (funchook_io_gets(buf, sizeof(buf), &io) != NULL) {
        const char *str = buf;
        size_t start, end;

        if (scan_address(&str, &start) == '-' && scan_address(&str, &end) == ' ') {
            /* same with sscanf(buf, "%lx-%lx ", &start, &end) == 2 */
            if (prev_end == 0) {
                if (end >= (size_t)func_addr) {
                    prev_end = end;
                }
            } else {
                if (start - prev_end >= page_size) {
                    *addr_out = (void*)(prev_end);
                    funchook_log(funchook, "  -- Use address %p for function %p\n",
                                 *addr_out, func_addr);
                    funchook_log(funchook, "  process map: %s", buf);
                    funchook_io_close(&io);
                    return 0;
                } else {
                    prev_end = end;
                }
            }
        }
        funchook_log(funchook, "  process map: %s", buf);
    }
    funchook_io_close(&io);
    funchook_set_error_message(funchook, "Could not find a free region after %p",
                               func_addr);
    return FUNCHOOK_ERROR_MEMORY_ALLOCATION;
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
            funchook_log(funchook, "  -- Use address %p for function %p\n",
                         *addr_out, func_addr);
            funchook_log(funchook, "  process map: %0"SIZE_T_WIDTH SIZE_T_FMT"x-%0"SIZE_T_WIDTH SIZE_T_FMT"x\n",
                         start, end);
            return 0;
        }
        funchook_log(funchook, "  process map: %0"SIZE_T_WIDTH SIZE_T_FMT"x-%0"SIZE_T_WIDTH SIZE_T_FMT"x\n",
                     start, end);
        start = prev_end = end;
    }
    funchook_set_error_message(funchook, "Could not find a free region after %p",
                               func_addr);
    return FUNCHOOK_ERROR_MEMORY_ALLOCATION;
#else
#error unsupported OS
#endif
}

#endif /* CPU_X86_64 */

int funchook_page_alloc(funchook_t *funchook, funchook_page_t **page_out, uint8_t *func, rip_displacement_t *disp)
{
#ifdef CPU_X86_64
    int loop_cnt;

    for (loop_cnt = 0; loop_cnt < 3; loop_cnt++) {
        void *target;
        int rv = get_free_address(funchook, func, &target);

        if (rv != 0) {
            return rv;
        }
        *page_out = mmap(target, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (*page_out == target) {
            funchook_log(funchook, "  allocate page %p (size=%"SIZE_T_FMT"u)\n", *page_out, page_size);
            return 0;
        }
        if (*page_out == MAP_FAILED) {
            char errbuf[128];

            funchook_set_error_message(funchook, "mmap failed(addr=%p): %s", target,
                                       funchook_strerror(errno, errbuf, sizeof(errbuf)));
            return FUNCHOOK_ERROR_MEMORY_ALLOCATION;
        }
        funchook_log(funchook, "  allocate page %p (hint=%p, size=%"SIZE_T_FMT"u)\n", *page_out, target, page_size);
        /* other thread might allocate memory at the target address. */
        munmap(*page_out, page_size);
    }
    funchook_set_error_message(funchook, "Failed to allocate memory in unused regions");
    return FUNCHOOK_ERROR_MEMORY_ALLOCATION;
#else
    char errbuf[128];

    *page_out = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (*page_out != MAP_FAILED) {
        funchook_log(funchook, "  allocate page %p (size=%"SIZE_T_FMT"u)\n", *page_out, page_size);
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
        funchook_log(funchook, " deallocate page %p (size=%"SIZE_T_FMT"u)\n",
                     page, page_size);
        return 0;
    }
    funchook_set_error_message(funchook, "Failed to deallocate page %p (size=%"SIZE_T_FMT"u, error=%s)",
                               page, page_size,
                               funchook_strerror(errno, errbuf, sizeof(errbuf)));
    return FUNCHOOK_ERROR_MEMORY_FUNCTION;
}

int funchook_page_protect(funchook_t *funchook, funchook_page_t *page)
{
    char errbuf[128];
    int rv = mprotect(page, page_size, PROT_READ | PROT_EXEC);

    if (rv == 0) {
        funchook_log(funchook, "  protect page %p (size=%"SIZE_T_FMT"u)\n",
                     page, page_size);
        return 0;
    }
    funchook_set_error_message(funchook, "Failed to protect page %p (size=%"SIZE_T_FMT"u, error=%s)",
                               page, page_size,
                               funchook_strerror(errno, errbuf, sizeof(errbuf)));
    return FUNCHOOK_ERROR_MEMORY_FUNCTION;
}

int funchook_page_unprotect(funchook_t *funchook, funchook_page_t *page)
{
    char errbuf[128];
    int rv = mprotect(page, page_size, PROT_READ | PROT_WRITE);

    if (rv == 0) {
        funchook_log(funchook, "  unprotect page %p (size=%"SIZE_T_FMT"u)\n",
                     page, page_size);
        return 0;
    }
    funchook_set_error_message(funchook, "Failed to unprotect page %p (size=%"SIZE_T_FMT"u, error=%s)",
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
        funchook_log(funchook, "  unprotect memory %p (size=%"SIZE_T_FMT"u, prot=read,write%s) <- %p (size=%"SIZE_T_FMT"u)\n",
                     mstate->addr, mstate->size, (prot & PROT_EXEC) ? ",exec" : "", start, len);
        return 0;
    }
    if (rv == -1 && errno == EACCES && (prot & PROT_EXEC)) {
        rv = mprotect(mstate->addr, mstate->size, PROT_READ | PROT_WRITE);
        if (rv == 0) {
            prot = PROT_READ | PROT_WRITE;
            funchook_log(funchook, "  unprotect memory %p (size=%"SIZE_T_FMT"u, prot=read,write) <- %p (size=%"SIZE_T_FMT"u)\n",
                         mstate->addr, mstate->size, start, len);
            return 0;
        }
    }
    funchook_set_error_message(funchook, "Failed to unprotect memory %p (size=%"SIZE_T_FMT"u, prot=read,write%s) <- %p (size=%"SIZE_T_FMT"u, error=%s)",
                               mstate->addr, mstate->size, (prot & PROT_EXEC) ? ",exec" : "", start, len,
                               funchook_strerror(errno, errbuf, sizeof(errbuf)));
    return FUNCHOOK_ERROR_MEMORY_FUNCTION;
}

int funchook_unprotect_end(funchook_t *funchook, const mem_state_t *mstate)
{
    char errbuf[128];
    int rv = mprotect(mstate->addr, mstate->size, PROT_READ | PROT_EXEC);

    if (rv == 0) {
        funchook_log(funchook, "  protect memory %p (size=%"SIZE_T_FMT"u, prot=read,exec)\n",
                     mstate->addr, mstate->size);
        return 0;
    }
    funchook_set_error_message(funchook, "Failed to protect memory %p (size=%"SIZE_T_FMT"u, prot=read,exec, error=%s)",
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

const char *funchook_strerror(int errnum, char *buf, size_t buflen)
{
#ifdef __linux
    if (0 <= errnum && errnum < _sys_nerr) {
        return _sys_errlist[errnum];
    }
#else
    if (0 <= errnum && errnum < sys_nerr) {
        return sys_errlist[errnum];
    }
#endif
    funchook_snprintf(buf, buflen, "Unknown error (%d)", errnum);
    return buf;
}
