#include <stdio.h>
#include <string.h>
#include <funchook.h>
#include "test.h"
#ifdef WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

extern int dllfunc_1(int a, int b);
extern int dllfunc_2(int a, int b);

static int (*dllfunc_1_func)(int a, int b);
static int (*dllfunc_2_func)(int a, int b);

static int dllfunc_1_hook_is_called = 0;
static int dllfunc_1_hook(int a, int b)
{
    dllfunc_1_hook_is_called = 1;
    return dllfunc_1_func(a, b);
}

funchook_info_t saved_func_info;

static void prehook(funchook_info_t *info)
{
    saved_func_info = *info;
}

void test_prehook(void)
{
    funchook_t *funchook;
    int rv;
    void *dllfunc_1_user_data = (void*)0xdeadbeef;
    void *dllfunc_2_user_data = (void*)0xcafebabe;
#ifdef WIN32
    HANDLE hMod = GetModuleHandleA("funchook_test_dll.dll");
    if (hMod == NULL) {
        hMod = GetModuleHandleA("libfunchook_test.so");
    }
    void *dllfunc_1_addr = GetProcAddress(hMod, "dllfunc_1");
    void *dllfunc_2_addr = GetProcAddress(hMod, "dllfunc_2");
#else
    void *dlhandle = dlopen("libfunchook_test.so", RTLD_LAZY);
    void *dllfunc_1_addr = dlsym(dlhandle, "dllfunc_1");
    void *dllfunc_2_addr = dlsym(dlhandle, "dllfunc_2");
    dlclose(dlhandle);
#endif

    printf("[%d] test_prehook\n", ++test_cnt);

    funchook = funchook_create();
    funchook_set_debug_file("debug.log");

    dllfunc_1_func = dllfunc_1;
    const funchook_params_t params1 = {
        .hook_func = dllfunc_1_hook,
        .prehook = prehook,
        .user_data = dllfunc_1_user_data,
    };
    rv = funchook_prepare_with_params(funchook, (void**)&dllfunc_1_func, &params1);
    if (rv != 0) {
        printf("ERROR: failed to prepare hook dllfunc_1 with prehook. (%s)\n", funchook_error_message(funchook));
        error_cnt++;
        return;
    }

    dllfunc_2_func = dllfunc_2;
    const funchook_params_t params2 = {
        .prehook = prehook,
        .user_data = dllfunc_2_user_data,
    };
    rv = funchook_prepare_with_params(funchook, (void**)&dllfunc_2_func, &params2);
    if (rv != 0) {
        printf("ERROR: failed to prepare hook dllfunc_2 with prehook. (%s)\n", funchook_error_message(funchook));
        error_cnt++;
        return;
    }

    rv = funchook_install(funchook, 0);
    if (rv != 0) {
        printf("ERROR: failed to install hooks. (%s)\n", funchook_error_message(funchook));
        error_cnt++;
        return;
    }

    memset(&saved_func_info, 0, sizeof(saved_func_info));
    dllfunc_1_hook_is_called = 0;
    rv = dllfunc_1(2, 3);
    if (rv != 2 * 3 + 1) {
        printf("ERROR: dllfunc_1 returns %d\n", rv);
        error_cnt++;
        return;
    }
    if (dllfunc_1_hook_is_called == 0) {
      printf("ERROR: dllfunc_1_hook isn't called.\n");
      error_cnt++;
      return;
    }
    if (saved_func_info.original_target_func != dllfunc_1 ||
        saved_func_info.target_func != dllfunc_1_addr ||
        saved_func_info.trampoline_func != dllfunc_1_func ||
        saved_func_info.hook_func != dllfunc_1_hook ||
        saved_func_info.user_data != dllfunc_1_user_data) {
        printf("ERROR: unexpected dllfunc_1's saved func_info.\n"
               "   expected {%p, %p, %p, %p, %p}\n"
               "        but {%p, %p, %p, %p, %p}\n",
               dllfunc_1, dllfunc_1_addr, dllfunc_1_func, dllfunc_1_hook, dllfunc_1_user_data,
               saved_func_info.original_target_func,
               saved_func_info.target_func,
               saved_func_info.trampoline_func,
               saved_func_info.hook_func,
               saved_func_info.user_data);
          error_cnt++;
        return;
    }

    memset(&saved_func_info, 0, sizeof(saved_func_info));
    rv = dllfunc_2(3, 4);
    if (rv != 3 * 4 + 2) {
        printf("ERROR: dllfunc_2 returns %d\n", rv);
        error_cnt++;
        return;
    }
    if (saved_func_info.original_target_func != dllfunc_2 ||
        saved_func_info.target_func != dllfunc_2_addr ||
        saved_func_info.trampoline_func != dllfunc_2_func ||
        saved_func_info.hook_func != NULL ||
        saved_func_info.user_data != dllfunc_2_user_data) {
        printf("ERROR: unexpected dllfunc_2's saved func_info.\n"
               "   expected {%p, %p, %p, %p, %p}\n"
               "        but {%p, %p, %p, %p, %p}\n",
               dllfunc_2, dllfunc_2_addr, dllfunc_2_func, NULL, dllfunc_2_user_data,
               saved_func_info.original_target_func,
               saved_func_info.target_func,
               saved_func_info.trampoline_func,
               saved_func_info.hook_func,
               saved_func_info.user_data);
        error_cnt++;
        return;
    }

    funchook_uninstall(funchook, 0);
    funchook_destroy(funchook);
}
