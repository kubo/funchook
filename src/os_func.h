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

/* os_func.c */
char *duckhook_strlcpy(char *dest, const char *src, size_t n);
int duckhook_snprintf(char *str, size_t size, const char *format, ...);
int duckhook_vsnprintf(char *str, size_t size, const char *format, va_list ap);

#undef strlcpy
#define strlcpy duckhook_strlcpy
#undef snprintf
#define snprintf duckhook_snprintf
#undef vsnprintf
#define vsnprintf duckhook_vsnprintf

#ifdef WIN32
/* os_func_windows.c */
/* no function for now */
#else
/* os_func_unix.c */
extern int duckhook_os_errno;
long duckhook_os_syscall(long, ...);
int duckhook_os_open(const char *pathname, int flags, ...);
int duckhook_os_close(int fd);
ssize_t duckhook_os_read(int fd, void *buf, size_t count);
ssize_t duckhook_os_write(int fd, const void *buf, size_t count);
void *duckhook_os_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int duckhook_os_munmap(void *addr, size_t length);
int duckhook_os_mprotect(void *addr, size_t len, int prot);

#undef errno
#define errno duckhook_os_errno
#define syscall duckhook_os_syscall
#define open duckhook_os_open
#define close duckhook_os_close
#define read duckhook_os_read
#define write duckhook_os_write
#define mmap duckhook_os_mmap
#define munmap duckhook_os_munmap
#define mprotect duckhook_os_mprotect
#endif

#endif /* OS_FUNC_H */
