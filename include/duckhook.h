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

#ifdef WIN32
#ifdef BUILD_DUCKHOOK_DLL
#define DUCKHOOK_DLLEXPORT __declspec(dllexport)
#else /* BUILD_DUCKHOOK_DLL */
#define DUCKHOOK_DLLEXPORT __declspec(dllimport)
#endif /* BUILD_DUCKHOOK_DLL */
#else /* WIN32 */
#define DUCKHOOK_DLLEXPORT
#endif /* WIN32 */

typedef struct duckhook_memo duckhook_memo_t;

DUCKHOOK_DLLEXPORT void *duckhook_install(void *target_func, void *hook_func, duckhook_memo_t **memo);

DUCKHOOK_DLLEXPORT void duckhook_uninstall(duckhook_memo_t *memo);

#endif
