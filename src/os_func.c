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
#include <sys/types.h>
#include "printf_base.h"
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

char *funchook_strlcpy(char *dest, const char *src, size_t n)
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

int funchook_snprintf(char *str, size_t size, const char *format, ...)
{
    va_list ap;
    int rv;

    va_start(ap, format);
    rv = funchook_vsnprintf(str, size, format, ap);
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

int funchook_vsnprintf(char *str, size_t size, const char *format, va_list ap)
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
