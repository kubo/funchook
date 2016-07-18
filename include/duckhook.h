/*
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
#ifndef DUCKHOOK_H
#define DUCKHOOK_H 1

/*
 * Only functions with DUCKHOOK_EXPORT are visible from outside of duckhook.dll
 * or libduckhook.so. Others are invisible.
 */
#ifdef WIN32
#ifdef BUILD_DUCKHOOK_DLL
#define DUCKHOOK_EXPORT __declspec(dllexport)
#else /* BUILD_DUCKHOOK_DLL */
#define DUCKHOOK_EXPORT __declspec(dllimport)
#endif /* BUILD_DUCKHOOK_DLL */
#elif defined(__GNUC__)
#define DUCKHOOK_EXPORT __attribute__((visibility("default")))
#else
#define DUCKHOOK_EXPORT
#endif /* WIN32 */

typedef struct duckhook duckhook_t;

/**
 * Create a duckhook handle
 *
 * @return allocated duckhook handle.
 */
DUCKHOOK_EXPORT duckhook_t *duckhook_create(void);

/**
 * Prepare hooking
 *
 * @param duckhook     a duckhook handle created by duckhook_create()
 * @param target_func  function pointer to be intercepted
 * @param hook_func    function pointer which is called istead of target_func
 * @return             trampoline function which is used in hook_func to call the original target_func
 */
DUCKHOOK_EXPORT void *duckhook_prepare(duckhook_t *duckhook, void *target_func, void *hook_func);

/**
 * Install hooks prepared by duckhook_prepare().
 *
 * @param duckhook     a duckhook handle created by duckhook_create()
 * @param flags        reserved. Set zero.
 * @return             0 on success, -1 on error
 */
DUCKHOOK_EXPORT int duckhook_install(duckhook_t *duckhook, int flags);

/**
 * Uninstall hooks installed by duckhook_install().
 *
 * @param duckhook     a duckhook handle created by duckhook_create()
 * @param flags        reserved. Set zero.
 * @return             0 on success, -1 on error
 */
DUCKHOOK_EXPORT int duckhook_uninstall(duckhook_t *duckhook, int flags);

/**
 * Destroy a duckhook handle
 *
 * @param duckhook     a duckhook handle created by duckhook_create()
 * @return             0 on success, -1 on error
 */
DUCKHOOK_EXPORT int duckhook_destroy(duckhook_t *duckhook);

DUCKHOOK_EXPORT int duckhook_set_debug_file(const char *name);

#endif
