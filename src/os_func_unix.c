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
#if defined __linux
#define _GNU_SOURCE
#endif
#include <sys/types.h>
#include <sys/syscall.h>
#include <errno.h>
#include "os_func.h"

int funchook_os_errno;

/* Dont' include unistd.h on macOS.
 * macOS defines syscall as int syscall(int, ...).
 * But it truncates syscall(SYS_mmap, ...)'s return value to 32 bits.
 */
long syscall(long, ...);

int funchook_os_open(const char *pathname, int flags, ...)
{
    mode_t mode;
    va_list ap;

    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, long);
    va_end(ap);
    return (int)syscall(SYS_open, pathname, flags, mode);
}

int funchook_os_close(int fd)
{
    return (int)syscall(SYS_close, fd);
}

ssize_t funchook_os_read(int fd, void *buf, size_t count)
{
    return (ssize_t)syscall(SYS_read, fd, buf, count);
}

ssize_t funchook_os_write(int fd, const void *buf, size_t count)
{
    return (ssize_t)syscall(SYS_write, fd, buf, count);
}

void *funchook_os_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
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

int funchook_os_munmap(void *addr, size_t length)
{
    return (int)syscall(SYS_munmap, addr, length);
}

int funchook_os_mprotect(void *addr, size_t len, int prot)
{
    return (int)syscall(SYS_mprotect, addr, len, prot);
}
