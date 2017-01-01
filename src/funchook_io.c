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
#include <string.h>
#include <errno.h>

#ifdef WIN32
#include <windows.h>
#else
#include <fcntl.h>
#endif

#include "funchook_io.h"
#include "printf_base.h"
#include "os_func.h"

int funchook_io_open(funchook_io_t *io, const char *path, int mode)
{
#ifdef WIN32
    DWORD access_mode = GENERIC_READ;
    DWORD creation_disp = 0;
    if (mode == FUNCHOOK_IO_WRITE) {
        access_mode = GENERIC_WRITE;
        creation_disp = CREATE_ALWAYS;
        io->append = 0;
    } else if (mode == FUNCHOOK_IO_APPEND) {
        access_mode = GENERIC_WRITE;
        creation_disp = OPEN_ALWAYS;
        io->append = 1;
    }
    io->file = CreateFileA(path, access_mode, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, creation_disp, FILE_ATTRIBUTE_NORMAL, NULL);
#else
    int flags = O_RDONLY;
    if (mode == FUNCHOOK_IO_WRITE) {
        flags = O_WRONLY | O_CREAT | O_TRUNC;
    } else if (mode == FUNCHOOK_IO_APPEND) {
        flags = O_WRONLY | O_CREAT | O_APPEND;
    }
    io->file = open(path, flags, 0666);
#endif
    io->ptr = io->end = io->buf;
    return io->file != INVALID_FILE_HANDLE ? 0 : -1;
}

int funchook_io_close(funchook_io_t *io)
{
    if (io->file != INVALID_FILE_HANDLE) {
#ifdef WIN32
        CloseHandle(io->file);
#else
        close(io->file);
#endif
        io->file = INVALID_FILE_HANDLE;
    }
    return 0;
}

char *funchook_io_gets(char *s, int size, funchook_io_t *io)
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
            int len = read(io->file, io->buf, sizeof(io->buf));
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
        if (funchook_io_flush(io) != 0) { \
            return -1; \
        } \
    } \
    *(io->ptr++) = (c); \
} while (0)

int funchook_io_putc(char c, funchook_io_t *io)
{
#ifdef WIN32
    if (c == '\n') {
        IO_PUTC('\r', io);
    }
#endif
    IO_PUTC(c, io);
    return (unsigned char)c;
}

int funchook_io_puts(const char *s, funchook_io_t *io)
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

int funchook_io_vprintf(funchook_io_t *io, const char *format, va_list ap)
{
    return printf_base((pfb_putc_t)funchook_io_putc, io, format, ap);
}

int funchook_io_flush(funchook_io_t *io)
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
        if (write(io->file, io->buf, len) != len) {
            return -1;
        }
#endif
        io->ptr = io->buf;
    }
    return 0;
}
