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
#ifndef OS_FUNC_H
#define OS_FUNC_H 1
#include <stdarg.h>

/* os_func.c */
char *funchook_strlcpy(char *dest, const char *src, size_t n);
int funchook_snprintf(char *str, size_t size, const char *format, ...);
int funchook_vsnprintf(char *str, size_t size, const char *format, va_list ap);

#undef strlcpy
#define strlcpy funchook_strlcpy
#undef snprintf
#define snprintf funchook_snprintf
#undef vsnprintf
#define vsnprintf funchook_vsnprintf

#ifdef WIN32
/* os_func_windows.c */
/* no function for now */
#else
#include <sys/types.h>
/* os_func_unix.c */
extern int funchook_os_errno;
long funchook_os_syscall(long, ...);
int funchook_os_open(const char *pathname, int flags, ...);
int funchook_os_close(int fd);
ssize_t funchook_os_read(int fd, void *buf, size_t count);
ssize_t funchook_os_write(int fd, const void *buf, size_t count);
void *funchook_os_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int funchook_os_munmap(void *addr, size_t length);
int funchook_os_mprotect(void *addr, size_t len, int prot);

#undef errno
#define errno funchook_os_errno
#define syscall funchook_os_syscall
#define open funchook_os_open
#define close funchook_os_close
#define read funchook_os_read
#define write funchook_os_write
#define mmap funchook_os_mmap
#define munmap funchook_os_munmap
#define mprotect funchook_os_mprotect
#endif

#endif /* OS_FUNC_H */
