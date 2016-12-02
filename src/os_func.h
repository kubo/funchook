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
#ifndef OS_FUNC_H
#define OS_FUNC_H 1
#include <stdarg.h>

#if defined(__linux) || defined(__APPLE__)
#define mmap duckhook_mmap
#define munmap duckhook_munmap
#define mprotect duckhook_mprotect

void *duckhook_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int duckhook_munmap(void *addr, size_t length);
int duckhook_mprotect(void *addr, size_t len, int prot);
#endif

#define strlcpy duckhook_strlcpy
#define snprintf duckhook_snprintf
#define vsnprintf duckhook_vsnprintf

char *duckhook_strlcpy(char *dest, const char *src, size_t n);
int duckhook_snprintf(char *str, size_t size, const char *format, ...);
int duckhook_vsnprintf(char *str, size_t size, const char *format, va_list ap);

typedef struct {
#ifdef WIN32
#define INVALID_FILE_HANDLE INVALID_HANDLE_VALUE
    void *file;
    int append;
#else
#define INVALID_FILE_HANDLE -1
    int file;
#endif
    char *ptr;
    char *end;
    char buf[128];
} duckhook_io_t;

#define DUCKHOOK_IO_READ    0
#define DUCKHOOK_IO_WRITE   1
#define DUCKHOOK_IO_APPEND  2
int duckhook_io_open(duckhook_io_t *io, const char *path, int mode);
int duckhook_io_close(duckhook_io_t *io);
char *duckhook_io_gets(char *s, int size, duckhook_io_t *io);
int duckhook_io_putc(char c, duckhook_io_t *io);
int duckhook_io_puts(const char *s, duckhook_io_t *io);
int duckhook_io_vprintf(duckhook_io_t *io, const char *format, va_list ap);
int duckhook_io_flush(duckhook_io_t *io);

#endif /* OS_FUNC_H */
