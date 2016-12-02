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
#if defined __linux
#define _GNU_SOURCE
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>

#if defined __linux || defined(__APPLE__)
#include <sys/syscall.h>
/* Dont' include unistd.h on macOS.
 * macOS defines syscall as int syscall(int, ...).
 * But it truncates syscall(SYS_mmap, ...)'s return value to 32 bits.
 */
long syscall(long, ...);
#endif

#include "os_func.h"

/* same with memcmp in libc not to use the function in libc */
#ifndef _MSC_VER
#undef memcmp
int memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *c1 = (unsigned char *)s1;
    const unsigned char *c2 = (unsigned char *)s2;
    while (n--) {
        if (*c1 != *c2) {
            return *c1 > *c2 ? 1 : -1;
        }
        c1++; c2++;
    }
    return 0;
}
#endif

/* same with memcmp in libc not to use the function in libc */
#ifndef _MSC_VER
#undef memcpy
void *memcpy(void *dest, const void *src, size_t n)
{
    char *d = (char*)dest;
    const char *s = (const char *)src;
    while (n--) {
        *(d++) = *(s++);
    }
    return dest;
}
#endif

#if defined(__linux) || defined(__APPLE__)
void *duckhook_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
#if defined(__linux) && defined(__i386)
    if (offset & 4095) {
        errno = EINVAL;
        return (void*)-1;
    }
    return (void*)syscall(SYS_mmap2, addr, length, prot, flags, fd, (long)(offset >> 12));
#else
    return (void*)syscall(SYS_mmap, addr, length, prot, flags, fd, offset);
#endif
}

int duckhook_munmap(void *addr, size_t length)
{
    return (int)syscall(SYS_munmap, addr, length);
}

int duckhook_mprotect(void *addr, size_t len, int prot)
{
    return (int)syscall(SYS_mprotect, addr, len, prot);
}
#endif
