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

#ifdef WIN32
#include <windows.h>
#endif

#if defined __linux || defined(__APPLE__)
#include <fcntl.h>
#include <sys/syscall.h>
/* Dont' include unistd.h on macOS.
 * macOS defines syscall as int syscall(int, ...).
 * But it truncates syscall(SYS_mmap, ...)'s return value to 32 bits.
 */
long syscall(long, ...);
#endif

#include "os_func.h"
#include "printf_base.h"

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

char *duckhook_strlcpy(char *dest, const char *src, size_t n)
{
    if (n != 0) {
        char *d = dest;
        while (--n > 0 && *src) {
            *(d++) = *(src++);
        }
        *d = '\0';
    }
    return dest;
}

int duckhook_snprintf(char *str, size_t size, const char *format, ...)
{
    va_list ap;
    int rv;

    va_start(ap, format);
    rv = duckhook_vsnprintf(str, size, format, ap);
    va_end(ap);
    return rv;
}

typedef struct {
    char *str;
    char *end;
} snprintf_arg_t;

static int snprintf_putc(char c, void *handle)
{
    snprintf_arg_t *arg = (snprintf_arg_t *)handle;
    if (arg->str < arg->end) {
        *(arg->str++) = c;
    }
    return 0;
}

int duckhook_vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    snprintf_arg_t arg;
    int rv;

    arg.str = str;
    arg.end = str + size - 1;
    rv = printf_base(snprintf_putc, &arg, format, ap);
    if (size > 0) {
        *arg.str = '\0';
    }
    return rv;
}

int duckhook_io_open(duckhook_io_t *io, const char *path, int mode)
{
#ifdef WIN32
    DWORD access_mode = GENERIC_READ;
    DWORD creation_disp = 0;
    if (mode == DUCKHOOK_IO_WRITE) {
        access_mode = GENERIC_WRITE;
        creation_disp = CREATE_ALWAYS;
        io->append = 0;
    } else if (mode == DUCKHOOK_IO_APPEND) {
        access_mode = GENERIC_WRITE;
        creation_disp = OPEN_ALWAYS;
        io->append = 1;
    }
    io->file = CreateFileA(path, access_mode, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, creation_disp, FILE_ATTRIBUTE_NORMAL, NULL);
#else
    int flags = O_RDONLY;
    if (mode == DUCKHOOK_IO_WRITE) {
        flags = O_WRONLY | O_CREAT | O_TRUNC;
    } else if (mode == DUCKHOOK_IO_APPEND) {
        flags = O_WRONLY | O_CREAT | O_APPEND;
    }
    io->file = syscall(SYS_open, path, flags, 0666);
#endif
    io->ptr = io->end = io->buf;
    return io->file != INVALID_FILE_HANDLE ? 0 : -1;
}

int duckhook_io_close(duckhook_io_t *io)
{
    if (io->file != INVALID_FILE_HANDLE) {
#ifdef WIN32
        CloseHandle(io->file);
#else
        syscall(SYS_close, io->file);
#endif
        io->file = INVALID_FILE_HANDLE;
    }
    return 0;
}

char *duckhook_io_gets(char *s, int size, duckhook_io_t *io)
{
    char *p = s;
    char *e = s + size - 1;
    while (p < e) {
        if (io->ptr == io->end) {
#ifdef WIN32
            DWORD len;
            if (!ReadFile(io->file, io->buf, sizeof(io->buf), &len, NULL)) {
                len = 0;
            }
#else
            int len = syscall(SYS_read, io->file, io->buf, sizeof(io->buf));
#endif
            if (len <= 0) {
                if (p != s) {
                    break;
                }
                return NULL;
            }
            io->ptr = io->buf;
            io->end = io->buf + len;
        }
        if ((*(p++) = *(io->ptr++)) == '\n') {
           break;
        }
    }
    *p = '\0';
    return s;
}

#define IO_PUTC(c, io) do { \
    if (io->ptr == io->buf + sizeof(io->buf)) { \
        if (duckhook_io_flush(io) != 0) { \
            return -1; \
        } \
    } \
    *(io->ptr++) = (c); \
} while (0)

int duckhook_io_putc(char c, duckhook_io_t *io)
{
#ifdef WIN32
    if (c == '\n') {
        IO_PUTC('\r', io);
    }
#endif
    IO_PUTC(c, io);
    return (unsigned char)c;
}

int duckhook_io_puts(const char *s, duckhook_io_t *io)
{
    while (*s) {
#ifdef WIN32
        if (*s == '\n') {
            IO_PUTC('\r', io);
        }
#endif
        IO_PUTC(*(s++), io);
    }
    return 0;
}

int duckhook_io_vprintf(duckhook_io_t *io, const char *format, va_list ap)
{
    return printf_base((pfb_putc_t)duckhook_io_putc, io, format, ap);
}

int duckhook_io_flush(duckhook_io_t *io)
{
    if (io->ptr != io->buf) {
#ifdef WIN32
        DWORD len = (DWORD)(io->ptr - io->buf);
        DWORD wlen;
        if (io->append) {
            LARGE_INTEGER ll;
            ll.QuadPart = 0;
            if (!SetFilePointerEx(io->file, ll, NULL, FILE_END)) {
                return -1;
            }
        }
        if (!WriteFile(io->file, io->buf, len, &wlen, NULL) || wlen != len) {
            return -1;
        }
#else
        size_t len = io->ptr - io->buf;
        if (syscall(SYS_write, io->file, io->buf, len) != len) {
            return -1;
        }
#endif
        io->ptr = io->buf;
    }
    return 0;
}
