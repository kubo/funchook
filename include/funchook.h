/*
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
#ifndef FUNCHOOK_H
#define FUNCHOOK_H 1

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Only functions with FUNCHOOK_EXPORT are visible from outside of funchook.dll
 * or libfunchook.so. Others are invisible.
 */
#ifdef FUNCHOOK_EXPORTS
#if defined(_WIN32)
#define FUNCHOOK_EXPORT __declspec(dllexport)
#elif defined(__GNUC__)
#define FUNCHOOK_EXPORT __attribute__((visibility("default")))
#endif
#endif /* FUNCHOOK_EXPORTS */
#ifndef FUNCHOOK_EXPORT
#define FUNCHOOK_EXPORT
#endif

typedef struct funchook funchook_t;

#define FUNCHOOK_ERROR_INTERNAL_ERROR         -1
#define FUNCHOOK_ERROR_SUCCESS                 0
#define FUNCHOOK_ERROR_OUT_OF_MEMORY           1
#define FUNCHOOK_ERROR_ALREADY_INSTALLED       2
#define FUNCHOOK_ERROR_DISASSEMBLY             3
#define FUNCHOOK_ERROR_IP_RELATIVE_OFFSET      4
#define FUNCHOOK_ERROR_CANNOT_FIX_IP_RELATIVE  5
#define FUNCHOOK_ERROR_FOUND_BACK_JUMP         6
#define FUNCHOOK_ERROR_TOO_SHORT_INSTRUCTIONS  7
#define FUNCHOOK_ERROR_MEMORY_ALLOCATION       8 /* memory allocation error */
#define FUNCHOOK_ERROR_MEMORY_FUNCTION         9 /* other memory function errors */
#define FUNCHOOK_ERROR_NOT_INSTALLED          10
#define FUNCHOOK_ERROR_NO_AVAILABLE_REGISTERS 11
#define FUNCHOOK_ERROR_NO_SPACE_NEAR_TARGET_ADDR 12

#define FUNCHOOK_FLAG_THISCALL     (1u << 0)
#define FUNCHOOK_FLAG_FASTCALL     (1u << 1)

typedef struct funchook_arg_handle funchook_arg_handle_t;

typedef struct funchook_info {
    void *original_target_func;
    void *target_func;
    void *trampoline_func;
    void *hook_func;
    void *user_data;
    funchook_arg_handle_t *arg_handle;
} funchook_info_t;

typedef void (*funchook_hook_t)(funchook_info_t *fi);

typedef struct {
    void *hook_func;
    funchook_hook_t prehook;
    void *user_data;
    unsigned int flags;
} funchook_params_t;

/**
 * Create a funchook handle
 *
 * @return allocated funchook handle. NULL when out-of-memory.
 */
FUNCHOOK_EXPORT funchook_t *funchook_create(void);

/**
 * Prepare hooking
 *
 * @param funchook     a funchook handle created by funchook_create()
 * @param target_func  function pointer to be intercepted. The pointer to trampoline function is set on success.
 * @param hook_func    function pointer which is called istead of target_func
 * @return             error code. one of FUNCHOOK_ERROR_*.
 */
FUNCHOOK_EXPORT int funchook_prepare(funchook_t *funchook, void **target_func, void *hook_func);

FUNCHOOK_EXPORT int funchook_prepare_with_params(funchook_t *funchook,
    void **target_func, const funchook_params_t *params);

/**
 * Install hooks prepared by funchook_prepare().
 *
 * @param funchook     a funchook handle created by funchook_create()
 * @param flags        reserved. Set zero.
 * @return             error code. one of FUNCHOOK_ERROR_*.
 */
FUNCHOOK_EXPORT int funchook_install(funchook_t *funchook, int flags);

/**
 * Uninstall hooks installed by funchook_install().
 *
 * @param funchook     a funchook handle created by funchook_create()
 * @param flags        reserved. Set zero.
 * @return             error code. one of FUNCHOOK_ERROR_*.
 */
FUNCHOOK_EXPORT int funchook_uninstall(funchook_t *funchook, int flags);

/**
 * Destroy a funchook handle
 *
 * @param funchook     a funchook handle created by funchook_create()
 * @return             error code. one of FUNCHOOK_ERROR_*.
 */
FUNCHOOK_EXPORT int funchook_destroy(funchook_t *funchook);

/**
 * Get error message
 *
 * @param funchook     a funchook handle created by funchook_create()
 * @return             pointer to buffer containing error message
 */
FUNCHOOK_EXPORT const char *funchook_error_message(const funchook_t *funchook);

/**
 * Set log file name to debug funchook itself.
 *
 * @param name         log file name
 * @return             error code. one of FUNCHOOK_ERROR_*.
 */
FUNCHOOK_EXPORT int funchook_set_debug_file(const char *name);

/* This function is under developemnt. It will be used by C++ template functions later. */
FUNCHOOK_EXPORT void *funchook_arg_get_int_reg_addr(const funchook_arg_handle_t *arg_handle, int pos);

/* This function is under developemnt. It will be used by C++ template functions later. */
FUNCHOOK_EXPORT void *funchook_arg_get_flt_reg_addr(const funchook_arg_handle_t *arg_handle, int pos);

/* This function is under developemnt. It will be used by C++ template functions later. */
FUNCHOOK_EXPORT void *funchook_arg_get_stack_addr(const funchook_arg_handle_t *arg_handle, int pos);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
