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
#ifndef FUNCHOOK_IO_H
#define FUNCHOOK_IO_H 1
#include <stdarg.h>

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
} funchook_io_t;

#define FUNCHOOK_IO_READ    0
#define FUNCHOOK_IO_WRITE   1
#define FUNCHOOK_IO_APPEND  2

/*
 * stdio-like functions
 */
int funchook_io_open(funchook_io_t *io, const char *path, int mode);
int funchook_io_close(funchook_io_t *io);
char *funchook_io_gets(char *s, int size, funchook_io_t *io);
int funchook_io_putc(char c, funchook_io_t *io);
int funchook_io_puts(const char *s, funchook_io_t *io);
int funchook_io_vprintf(funchook_io_t *io, const char *format, va_list ap);
int funchook_io_flush(funchook_io_t *io);

#endif /* FUNCHOOK_IO_H */
