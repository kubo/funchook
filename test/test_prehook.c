#include <stdio.h>
#include <string.h>
#include <funchook.h>
#include "test.h"
#include "unit_test.h"
#include "libfunchook_test.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

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

static void test_dllfunc(void)
{
    funchook_t *funchook;
    void *dllfunc_1_user_data = (void*)(size_t)0xdeadbeef;
    void *dllfunc_2_user_data = (void*)(size_t)0xcafebabe;
#ifdef _WIN32
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

    TEST_NAME2("test_prehook", "func_info");

    funchook = funchook_create();

    dllfunc_1_func = dllfunc_1;
    const funchook_params_t params1 = {
        .hook_func = dllfunc_1_hook,
        .prehook = prehook,
        .user_data = dllfunc_1_user_data,
    };
    ASSERT_FUNCHOOK_OK(funchook_prepare_with_params(funchook, (void**)&dllfunc_1_func, &params1),
                       funchook, "failed to prepare hook dllfunc_1 with prehook.");

    dllfunc_2_func = dllfunc_2;
    const funchook_params_t params2 = {
        .prehook = prehook,
        .user_data = dllfunc_2_user_data,
    };
    ASSERT_FUNCHOOK_OK(funchook_prepare_with_params(funchook, (void**)&dllfunc_2_func, &params2),
                       funchook, "failed to prepare hook dllfunc_2 with prehook.");

    ASSERT_FUNCHOOK_OK(funchook_install(funchook, 0),
                       funchook, "failed to install hooks.");

    memset(&saved_func_info, 0, sizeof(saved_func_info));
    dllfunc_1_hook_is_called = 0;
    ASSERT_EQUAL_INT(2 * 3 + 1, dllfunc_1(2, 3), funchook, "dllfunc_1");
    ASSERT_TRUE(dllfunc_1_hook_is_called, funchook, "dllfunc_1_hook isn't called.");
    ASSERT_TRUE(saved_func_info.original_target_func == dllfunc_1 &&
                saved_func_info.target_func == dllfunc_1_addr &&
                saved_func_info.trampoline_func == dllfunc_1_func &&
                saved_func_info.hook_func == dllfunc_1_hook &&
                saved_func_info.user_data == dllfunc_1_user_data,
                funchook,
                "unexpected dllfunc_1's saved func_info.\n"
                "   expected {%p, %p, %p, %p, %p}\n"
                "        but {%p, %p, %p, %p, %p}",
                dllfunc_1, dllfunc_1_addr, dllfunc_1_func, dllfunc_1_hook, dllfunc_1_user_data,
                saved_func_info.original_target_func,
                saved_func_info.target_func,
                saved_func_info.trampoline_func,
                saved_func_info.hook_func,
                saved_func_info.user_data);

    memset(&saved_func_info, 0, sizeof(saved_func_info));
    ASSERT_EQUAL_INT(3 * 4 + 2, dllfunc_2(3, 4), funchook, "dllfunc_2");
    ASSERT_TRUE(saved_func_info.original_target_func == dllfunc_2 &&
                saved_func_info.target_func == dllfunc_2_addr &&
                saved_func_info.trampoline_func == dllfunc_2_func &&
                saved_func_info.hook_func == NULL &&
                saved_func_info.user_data == dllfunc_2_user_data,
                funchook,
                "unexpected dllfunc_2's saved func_info.\n"
                "   expected {%p, %p, %p, %p, %p}\n"
                "        but {%p, %p, %p, %p, %p}\n",
                dllfunc_2, dllfunc_2_addr, dllfunc_2_func, NULL, dllfunc_2_user_data,
                saved_func_info.original_target_func,
                saved_func_info.target_func,
                saved_func_info.trampoline_func,
                saved_func_info.hook_func,
                saved_func_info.user_data);

    funchook_uninstall(funchook, 0);
    funchook_destroy(funchook);
}

static long (*long_args_func)(long arg1, long arg2, long arg3, long arg4, long arg5, long arg6, long arg7, long arg8, long arg9, long arg10);
long long_args_in_prehook[10];
static void long_args_prehook(funchook_info_t *info)
{
    for (int i = 0; i < 10; i++) {
#if defined __x86_64__ || defined _M_AMD64 || defined __aarch64__ || defined _M_ARM64
#if defined __aarch64__ || defined _M_ARM64
        static const int max_int_reg = 8;
#elif defined _WIN32
        static const int max_int_reg = 4;
#else
        static const int max_int_reg = 6;
#endif
        if (i < max_int_reg) {
            long_args_in_prehook[i] = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, i);
        } else {
            long_args_in_prehook[i] = *(long*)funchook_arg_get_stack_addr(info->arg_handle, i - max_int_reg);
        }
#endif

#if defined __i686__ || defined _M_IX86
        long_args_in_prehook[i] = *(long*)funchook_arg_get_stack_addr(info->arg_handle, i);
#endif
    }
}

static void test_long_args(void)
{
    funchook_t *funchook;

    TEST_NAME2("test_prehook", "long_args");

    funchook = funchook_create();

    long_args_func = long_args;
    const funchook_params_t long_args_params = {
        .prehook = long_args_prehook,
    };
    ASSERT_FUNCHOOK_OK(funchook_prepare_with_params(funchook, (void**)&long_args_func, &long_args_params),
                       funchook, "failed to prepare hook long_args with prehook.");
    ASSERT_FUNCHOOK_OK(funchook_install(funchook, 0),
                       funchook, "failed to install hooks.");

    long retval = long_args(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
    ASSERT_EQUAL_LONG(1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10, retval, funchook, "return value of long_args");
    for (int i = 0; i < 10; i++) {
        ASSERT_TRUE(long_args_in_prehook[i] == i + 1 && long_args_in_target[i] == i + 1,
                    funchook,
                    "unexpected arguments in long_args\n"
                    "          expected [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, ]\n"
                    "   args in prehook [%lu, %lu, %lu, %lu, %lu, %lu, %lu, %lu, %lu, %lu, ]\n"
                    "    args in target [%lu, %lu, %lu, %lu, %lu, %lu, %lu, %lu, %lu, %lu, ]",
                    long_args_in_prehook[0], long_args_in_prehook[1], long_args_in_prehook[2], long_args_in_prehook[3], long_args_in_prehook[4], 
                    long_args_in_prehook[5], long_args_in_prehook[6], long_args_in_prehook[7], long_args_in_prehook[8], long_args_in_prehook[9], 
                    long_args_in_target[0], long_args_in_target[1], long_args_in_target[2], long_args_in_target[3], long_args_in_target[4], 
                    long_args_in_target[5], long_args_in_target[6], long_args_in_target[7], long_args_in_target[8], long_args_in_target[9]);
    }

    funchook_uninstall(funchook, 0);
    funchook_destroy(funchook);
}

static double (*double_args_func)(double arg1, double arg2, double arg3, double arg4, double arg5, double arg6, double arg7, double arg8, double arg9, double arg10);
double double_args_in_prehook[10];
static void double_args_prehook(funchook_info_t *info)
{
    for (int i = 0; i < 10; i++) {
#if defined __x86_64__ || defined _M_AMD64 || defined __aarch64__ || defined _M_ARM64
#if defined __aarch64__ || defined _M_ARM64
        static const int max_flt_reg = 8;
#elif defined _WIN32
        static const int max_flt_reg = 4;
#else
        static const int max_flt_reg = 8;
#endif
        if (i < max_flt_reg) {
            double_args_in_prehook[i] = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, i);
        } else {
            double_args_in_prehook[i] = *(double*)funchook_arg_get_stack_addr(info->arg_handle, i - max_flt_reg);
        }
#endif

#if defined __i686__ || defined _M_IX86
        double_args_in_prehook[i] = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 2 * i);
#endif
    }
}

static void test_double_args(void)
{
    funchook_t *funchook;

    TEST_NAME2("test_prehook", "double_args");

    funchook = funchook_create();

    double_args_func = double_args;
    const funchook_params_t double_args_params = {
        .prehook = double_args_prehook,
    };
    ASSERT_FUNCHOOK_OK(funchook_prepare_with_params(funchook, (void**)&double_args_func, &double_args_params),
                       funchook, "failed to prepare hook double_args with prehook.");
    ASSERT_FUNCHOOK_OK(funchook_install(funchook, 0),
                       funchook, "failed to install hooks.");

    double retval = double_args(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
    ASSERT_EQUAL_DOUBLE(1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10, retval, funchook, "return value of double_args");
    for (int i = 0; i < 10; i++) {
        ASSERT_TRUE(double_args_in_prehook[i] == i + 1 && double_args_in_target[i] == i + 1,
                    funchook,
                    "unexpected arguments in double_args\n"
                    "          expected [%f, %f, %f, %f, %f, %f, %f, %f, %f, %f, ]\n"
                    "   args in prehook [%f, %f, %f, %f, %f, %f, %f, %f, %f, %f, ]\n"
                    "    args in target [%f, %f, %f, %f, %f, %f, %f, %f, %f, %f, ]",
                    1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0,
                    double_args_in_prehook[0], double_args_in_prehook[1], double_args_in_prehook[2],
                    double_args_in_prehook[3], double_args_in_prehook[4], double_args_in_prehook[5],
                    double_args_in_prehook[6], double_args_in_prehook[7], double_args_in_prehook[8],
                    double_args_in_prehook[9],
                    double_args_in_target[0], double_args_in_target[1], double_args_in_target[2],
                    double_args_in_target[3], double_args_in_target[4], double_args_in_target[5],
                    double_args_in_target[6], double_args_in_target[7], double_args_in_target[8],
                    double_args_in_target[9]);
    }

    funchook_uninstall(funchook, 0);
    funchook_destroy(funchook);
}

static mixed_args_t (*mixed_args_func)(
    uint8_t u8_1, double dbl1_1, uint16_t u16_1, float flt1_1, uint32_t u32_1, double dbl2_1,
    long lng_1, float flt2_1, uint64_t u64_1, double dbl3_1, uintptr_t uptr_1, float flt3_1,
    uint8_t u8_2, double dbl1_2, uint16_t u16_2, float flt1_2, uint32_t u32_2, double dbl2_2,
    long lng_2, float flt2_2, uint64_t u64_2, double dbl3_2, uintptr_t uptr_2, float flt3_2);
mixed_args_t mixed_args_in_prehook[2];
static DECL_DUMP_BUF(mixed_args_in_prehook);
static DECL_DUMP_BUF(mixed_args_in_target);

static void mixed_args_prehook(funchook_info_t *info)
{
    memset(mixed_args_in_prehook, PADDING_BYTE, sizeof(mixed_args_in_prehook));
#if defined __x86_64__ && !defined _WIN32
    mixed_args_in_prehook[0].u8 = *(uint8_t*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    mixed_args_in_prehook[0].u16 = *(uint16_t*)funchook_arg_get_int_reg_addr(info->arg_handle, 2);
    mixed_args_in_prehook[0].u32 = *(uint32_t*)funchook_arg_get_int_reg_addr(info->arg_handle, 3);
    mixed_args_in_prehook[0].lng = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 4);
    mixed_args_in_prehook[0].u64 = *(uint64_t*)funchook_arg_get_int_reg_addr(info->arg_handle, 5);

    mixed_args_in_prehook[0].dbl1 = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 0);
    mixed_args_in_prehook[0].flt1 = *(float*)funchook_arg_get_flt_reg_addr(info->arg_handle, 1);
    mixed_args_in_prehook[0].dbl2 = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 2);
    mixed_args_in_prehook[0].flt2 = *(float*)funchook_arg_get_flt_reg_addr(info->arg_handle, 3);
    mixed_args_in_prehook[0].dbl3 = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 4);
    mixed_args_in_prehook[0].flt3 = *(float*)funchook_arg_get_flt_reg_addr(info->arg_handle, 5);
    mixed_args_in_prehook[1].dbl1 = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 6);
    mixed_args_in_prehook[1].flt1 = *(float*)funchook_arg_get_flt_reg_addr(info->arg_handle, 7);

    mixed_args_in_prehook[0].uptr = *(uintptr_t*)funchook_arg_get_stack_addr(info->arg_handle, 0);
    mixed_args_in_prehook[1].u8 = *(uint8_t*)funchook_arg_get_stack_addr(info->arg_handle, 1);
    mixed_args_in_prehook[1].u16 = *(uint16_t*)funchook_arg_get_stack_addr(info->arg_handle, 2);
    mixed_args_in_prehook[1].u32 = *(uint32_t*)funchook_arg_get_stack_addr(info->arg_handle, 3);
    mixed_args_in_prehook[1].dbl2 = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 4);
    mixed_args_in_prehook[1].lng = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 5);
    mixed_args_in_prehook[1].flt2 = *(float*)funchook_arg_get_stack_addr(info->arg_handle, 6);
    mixed_args_in_prehook[1].u64 = *(uint64_t*)funchook_arg_get_stack_addr(info->arg_handle, 7);
    mixed_args_in_prehook[1].dbl3 = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 8);
    mixed_args_in_prehook[1].uptr = *(uintptr_t*)funchook_arg_get_stack_addr(info->arg_handle, 9);
    mixed_args_in_prehook[1].flt3 = *(float*)funchook_arg_get_stack_addr(info->arg_handle, 10);
#endif

#if (defined __x86_64__ || defined _M_AMD64) && defined _WIN32
    mixed_args_in_prehook[0].u8 = *(uint8_t*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    mixed_args_in_prehook[0].dbl1 = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 2);
    mixed_args_in_prehook[0].u16 = *(uint16_t*)funchook_arg_get_int_reg_addr(info->arg_handle, 3);

    mixed_args_in_prehook[0].flt1 = *(float*)funchook_arg_get_stack_addr(info->arg_handle, 0);
    mixed_args_in_prehook[0].u32 = *(uint32_t*)funchook_arg_get_stack_addr(info->arg_handle, 1);
    mixed_args_in_prehook[0].dbl2 = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 2);
    mixed_args_in_prehook[0].lng = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 3);
    mixed_args_in_prehook[0].flt2 = *(float*)funchook_arg_get_stack_addr(info->arg_handle, 4);
    mixed_args_in_prehook[0].u64 = *(uint64_t*)funchook_arg_get_stack_addr(info->arg_handle, 5);
    mixed_args_in_prehook[0].dbl3 = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 6);
    mixed_args_in_prehook[0].uptr = *(uintptr_t*)funchook_arg_get_stack_addr(info->arg_handle, 7);
    mixed_args_in_prehook[0].flt3 = *(float*)funchook_arg_get_stack_addr(info->arg_handle, 8);
    mixed_args_in_prehook[1].u8 = *(uint8_t*)funchook_arg_get_stack_addr(info->arg_handle, 9);
    mixed_args_in_prehook[1].dbl1 = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 10);
    mixed_args_in_prehook[1].u16 = *(uint16_t*)funchook_arg_get_stack_addr(info->arg_handle, 11);
    mixed_args_in_prehook[1].flt1 = *(float*)funchook_arg_get_stack_addr(info->arg_handle, 12);
    mixed_args_in_prehook[1].u32 = *(uint32_t*)funchook_arg_get_stack_addr(info->arg_handle, 13);
    mixed_args_in_prehook[1].dbl2 = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 14);
    mixed_args_in_prehook[1].lng = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 15);
    mixed_args_in_prehook[1].flt2 = *(float*)funchook_arg_get_stack_addr(info->arg_handle, 16);
    mixed_args_in_prehook[1].u64 = *(uint64_t*)funchook_arg_get_stack_addr(info->arg_handle, 17);
    mixed_args_in_prehook[1].dbl3 = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 18);
    mixed_args_in_prehook[1].uptr = *(uintptr_t*)funchook_arg_get_stack_addr(info->arg_handle, 19);
    mixed_args_in_prehook[1].flt3 = *(float*)funchook_arg_get_stack_addr(info->arg_handle, 20);
#endif

#if defined __i686__ || defined _M_IX86
    mixed_args_in_prehook[0].u8 = *(uint8_t*)funchook_arg_get_stack_addr(info->arg_handle, 1);
    mixed_args_in_prehook[0].dbl1 = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 2);
    mixed_args_in_prehook[0].u16 = *(uint16_t*)funchook_arg_get_stack_addr(info->arg_handle, 4);
    mixed_args_in_prehook[0].flt1 = *(float*)funchook_arg_get_stack_addr(info->arg_handle, 5);
    mixed_args_in_prehook[0].u32 = *(uint32_t*)funchook_arg_get_stack_addr(info->arg_handle, 6);
    mixed_args_in_prehook[0].dbl2 = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 7);
    mixed_args_in_prehook[0].lng = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 9);
    mixed_args_in_prehook[0].flt2 = *(float*)funchook_arg_get_stack_addr(info->arg_handle, 10);
    mixed_args_in_prehook[0].u64 = *(uint64_t*)funchook_arg_get_stack_addr(info->arg_handle, 11);
    mixed_args_in_prehook[0].dbl3 = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 13);
    mixed_args_in_prehook[0].uptr = *(uintptr_t*)funchook_arg_get_stack_addr(info->arg_handle, 15);
    mixed_args_in_prehook[0].flt3 = *(float*)funchook_arg_get_stack_addr(info->arg_handle, 16);
    mixed_args_in_prehook[1].u8 = *(uint8_t*)funchook_arg_get_stack_addr(info->arg_handle, 17);
    mixed_args_in_prehook[1].dbl1 = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 18);
    mixed_args_in_prehook[1].u16 = *(uint16_t*)funchook_arg_get_stack_addr(info->arg_handle, 20);
    mixed_args_in_prehook[1].flt1 = *(float*)funchook_arg_get_stack_addr(info->arg_handle, 21);
    mixed_args_in_prehook[1].u32 = *(uint32_t*)funchook_arg_get_stack_addr(info->arg_handle, 22);
    mixed_args_in_prehook[1].dbl2 = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 23);
    mixed_args_in_prehook[1].lng = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 25);
    mixed_args_in_prehook[1].flt2 = *(float*)funchook_arg_get_stack_addr(info->arg_handle, 26);
    mixed_args_in_prehook[1].u64 = *(uint64_t*)funchook_arg_get_stack_addr(info->arg_handle, 27);
    mixed_args_in_prehook[1].dbl3 = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 29);
    mixed_args_in_prehook[1].uptr = *(uintptr_t*)funchook_arg_get_stack_addr(info->arg_handle, 31);
    mixed_args_in_prehook[1].flt3 = *(float*)funchook_arg_get_stack_addr(info->arg_handle, 32);
#endif

#if defined __aarch64__ || defined _M_ARM64
    mixed_args_in_prehook[0].u8 = *(uint8_t*)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    mixed_args_in_prehook[0].u16 = *(uint16_t*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    mixed_args_in_prehook[0].u32 = *(uint32_t*)funchook_arg_get_int_reg_addr(info->arg_handle, 2);
    mixed_args_in_prehook[0].lng = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 3);
    mixed_args_in_prehook[0].u64 = *(uint64_t*)funchook_arg_get_int_reg_addr(info->arg_handle, 4);
    mixed_args_in_prehook[0].uptr = *(uintptr_t*)funchook_arg_get_int_reg_addr(info->arg_handle, 5);
    mixed_args_in_prehook[1].u8 = *(uint8_t*)funchook_arg_get_int_reg_addr(info->arg_handle, 6);
    mixed_args_in_prehook[1].u16 = *(uint16_t*)funchook_arg_get_int_reg_addr(info->arg_handle, 7);

    mixed_args_in_prehook[0].dbl1 = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 0);
    mixed_args_in_prehook[0].flt1 = *(float*)funchook_arg_get_flt_reg_addr(info->arg_handle, 1);
    mixed_args_in_prehook[0].dbl2 = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 2);
    mixed_args_in_prehook[0].flt2 = *(float*)funchook_arg_get_flt_reg_addr(info->arg_handle, 3);
    mixed_args_in_prehook[0].dbl3 = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 4);
    mixed_args_in_prehook[0].flt3 = *(float*)funchook_arg_get_flt_reg_addr(info->arg_handle, 5);
    mixed_args_in_prehook[1].dbl1 = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 6);
    mixed_args_in_prehook[1].flt1 = *(float*)funchook_arg_get_flt_reg_addr(info->arg_handle, 7);

    mixed_args_in_prehook[1].u32 = *(uint32_t*)funchook_arg_get_stack_addr(info->arg_handle, 0);
    mixed_args_in_prehook[1].dbl2 = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 1);
    mixed_args_in_prehook[1].lng = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 2);
    mixed_args_in_prehook[1].flt2 = *(float*)funchook_arg_get_stack_addr(info->arg_handle, 3);
    mixed_args_in_prehook[1].u64 = *(uint64_t*)funchook_arg_get_stack_addr(info->arg_handle, 4);
    mixed_args_in_prehook[1].dbl3 = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 5);
    mixed_args_in_prehook[1].uptr = *(uintptr_t*)funchook_arg_get_stack_addr(info->arg_handle, 6);
    mixed_args_in_prehook[1].flt3 = *(float*)funchook_arg_get_stack_addr(info->arg_handle, 7);
#endif
}

static void test_mixed_args(void)
{
    funchook_t *funchook;

    TEST_NAME2("test_prehook", "mixed_args");

    funchook = funchook_create();

    mixed_args_func = mixed_args;
    const funchook_params_t mixed_args_params = {
        .prehook = mixed_args_prehook,
    };
    ASSERT_FUNCHOOK_OK(funchook_prepare_with_params(funchook, (void**)&mixed_args_func, &mixed_args_params),
                       funchook, "failed to prepare hook mixed_args with prehook.");
    ASSERT_FUNCHOOK_OK(funchook_install(funchook, 0),
                       funchook, "failed to install hooks.");

    mixed_args_t expected_args[2];
    DECL_DUMP_BUF(expected_args);
    memset(expected_args, PADDING_BYTE, sizeof(expected_args));
    expected_args[0].u8 = 1;
    expected_args[0].dbl1 = 2.0;
    expected_args[0].u16 = 3;
    expected_args[0].flt1 = 4.0f;
    expected_args[0].u32 = 5;
    expected_args[0].dbl2 = 6.0;
    expected_args[0].lng = 7;
    expected_args[0].flt2 = 8.0f;
    expected_args[0].u64 = 9;
    expected_args[0].dbl3 = 10.0;
    expected_args[0].uptr = 11;
    expected_args[0].flt3 = 12.0f;
    expected_args[1].u8 = 13;
    expected_args[1].dbl1 = 14.0;
    expected_args[1].u16 = 15;
    expected_args[1].flt1 = 16.0f;
    expected_args[1].u32 = 17;
    expected_args[1].dbl2 = 18.0;
    expected_args[1].lng = 19;
    expected_args[1].flt2 = 20.0f;
    expected_args[1].u64 = 21;
    expected_args[1].dbl3 = 22.0;
    expected_args[1].uptr = 23;
    expected_args[1].flt3 = 24.0f;

    mixed_args_t expected_retval;
    DECL_DUMP_BUF(expected_retval);
    memset(&expected_retval, PADDING_BYTE, sizeof(expected_retval));
    expected_retval.u8 = 1 + 13;
    expected_retval.dbl1 = 2.0 + 14.0;
    expected_retval.u16 = 3 + 15;
    expected_retval.flt1 = 4.0f + 16.0f;
    expected_retval.u32 = 5 + 17;
    expected_retval.dbl2 = 6.0 + 18.0;
    expected_retval.lng = 7 + 19;
    expected_retval.flt2 = 8.0f + 20.0f;
    expected_retval.u64 = 9 + 21;
    expected_retval.dbl3 = 10.0 + 22.0;
    expected_retval.uptr = 11 + 23;
    expected_retval.flt3 = 12.0f + 24.0f;

    mixed_args_t retval = mixed_args(1, 2.0, 3, 4.0f, 5, 6.0,
                                     7, 8.0f, 9, 10.0, 11, 12.0f,
                                     13, 14.0, 15, 16.0f, 17, 18.0,
                                     19, 20.0f, 21, 22.0, 23, 24.0f);
    DECL_DUMP_BUF(retval);
    ASSERT_TRUE(memcmp(&expected_retval, &retval, sizeof(expected_retval)) == 0,
                funchook,
                "unexpected retrun value of mixed_args\n"
                "   expected [%s]\n"
                "     actual [%s]",
                DUMP_TO_BUF(expected_retval),
                DUMP_TO_BUF(retval));
    ASSERT_TRUE(memcmp(&expected_args, mixed_args_in_prehook, sizeof(expected_args)) == 0 &&
                memcmp(&expected_args, mixed_args_in_target, sizeof(expected_args)) == 0,
                funchook,
                "unexpected arguments in mixed_args\n"
                "          expected [%s]\n"
                "   args in prehook [%s]\n"
                "    args in target [%s]",
                DUMP_TO_BUF(expected_args),
                DUMP_TO_BUF(mixed_args_in_prehook),
                DUMP_TO_BUF(mixed_args_in_target));

    funchook_uninstall(funchook, 0);
    funchook_destroy(funchook);
}

fastcall_args_t fastcall_args_in_prehook;
DECL_DUMP_BUF(fastcall_args_in_prehook);
DECL_DUMP_BUF(fastcall_args_in_target);
fastcall_args_t fastcall_args_in_prehook2;
DECL_DUMP_BUF(fastcall_args_in_prehook2);
DECL_DUMP_BUF(fastcall_args_in_target2);
fastcall_args_t fastcall_args_in_prehook3;
DECL_DUMP_BUF(fastcall_args_in_prehook3);
DECL_DUMP_BUF(fastcall_args_in_target3);

static void fastcall_llld_prehook(funchook_info_t *info)
{
    memset(&fastcall_args_in_prehook, PADDING_BYTE, sizeof(fastcall_args_in_prehook));
#if (defined __x86_64__ && !defined _WIN32) || defined __aarch64__ || defined _M_ARM64
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 2);
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 0);
#endif

#if (defined __x86_64__ || defined _M_AMD64) && defined _WIN32
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 2);
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 3);
#endif

#if defined __i686__ || defined _M_IX86
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 1);
#endif
}
static void fastcall_lldl_prehook(funchook_info_t *info)
{
    memset(&fastcall_args_in_prehook, PADDING_BYTE, sizeof(fastcall_args_in_prehook));
#if (defined __x86_64__ && !defined _WIN32) || defined __aarch64__ || defined _M_ARM64
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 2);
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 0);
#endif

#if (defined __x86_64__ || defined _M_AMD64) && defined _WIN32
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 2);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 3);
#endif

#if defined __i686__ || defined _M_IX86
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 2);
#endif
}
static void fastcall_ldll_prehook(funchook_info_t *info)
{
    memset(&fastcall_args_in_prehook, PADDING_BYTE, sizeof(fastcall_args_in_prehook));
#if (defined __x86_64__ && !defined _WIN32) || defined __aarch64__ || defined _M_ARM64
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 2);
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 0);
#endif

#if (defined __x86_64__ || defined _M_AMD64) && defined _WIN32
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 2);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 3);
#endif

#if defined __i686__ || defined _M_IX86
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 2);
#endif
}
static void fastcall_dlll_prehook(funchook_info_t *info)
{
    memset(&fastcall_args_in_prehook, PADDING_BYTE, sizeof(fastcall_args_in_prehook));
#if (defined __x86_64__ && !defined _WIN32) || defined __aarch64__ || defined _M_ARM64
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 2);
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 0);
#endif

#if (defined __x86_64__ || defined _M_AMD64) && defined _WIN32
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 2);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 3);
#endif

#if defined __i686__ || defined _M_IX86
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 2);
#endif
}
static void fastcall_pass_struct_prehook(funchook_info_t *info)
{
    memset(&fastcall_args_in_prehook, PADDING_BYTE, sizeof(fastcall_args_in_prehook));
    memset(&fastcall_args_in_prehook2, PADDING_BYTE, sizeof(fastcall_args_in_prehook));
    memset(&fastcall_args_in_prehook3, PADDING_BYTE, sizeof(fastcall_args_in_prehook));
#if defined(__x86_64__) && !defined(_WIN32)
    fastcall_args_in_prehook = *(fastcall_args_t*)funchook_arg_get_stack_addr(info->arg_handle, 0);
    fastcall_args_in_prehook2 = *(fastcall_args_t*)funchook_arg_get_stack_addr(info->arg_handle, 4);
    fastcall_args_in_prehook3 = *(fastcall_args_t*)funchook_arg_get_stack_addr(info->arg_handle, 8);
#endif

#if (defined __x86_64__ || defined _M_AMD64) && defined _WIN32
    fastcall_args_in_prehook = **(fastcall_args_t**)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    fastcall_args_in_prehook2 = **(fastcall_args_t**)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook3 = **(fastcall_args_t**)funchook_arg_get_int_reg_addr(info->arg_handle, 2);
#endif

#if defined __i686__ || defined _M_IX86
    fastcall_args_in_prehook = *(fastcall_args_t*)funchook_arg_get_stack_addr(info->arg_handle, 0);
    fastcall_args_in_prehook2 = *(fastcall_args_t*)funchook_arg_get_stack_addr(info->arg_handle, sizeof(fastcall_args_t) / 4);
    fastcall_args_in_prehook3 = *(fastcall_args_t*)funchook_arg_get_stack_addr(info->arg_handle, (sizeof(fastcall_args_t) / 4) * 2);
#endif

#if defined __aarch64__ || defined _M_ARM64
    fastcall_args_in_prehook = **(fastcall_args_t**)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    fastcall_args_in_prehook2 = **(fastcall_args_t**)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook3 = **(fastcall_args_t**)funchook_arg_get_int_reg_addr(info->arg_handle, 2);
#endif
}
static void fastcall_ret_struct_prehook(funchook_info_t *info)
{
    memset(&fastcall_args_in_prehook, PADDING_BYTE, sizeof(fastcall_args_in_prehook));
#if defined(__x86_64__) && !defined(_WIN32)
    // System V AMD64 ABI (Linux x86_64 and macOS x86_64)
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 2);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 3);
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 0);
#endif

#if (defined __x86_64__ || defined _M_AMD64) && defined _WIN32
    // Microsoft x64 calling convention (Windows x64)
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 2);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 3);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 0);
#endif

#if defined __i686__
    // Linux i686 and Windows 32-bit (GCC)
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 2);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 3);
#endif

#if defined _M_IX86 && defined _MSC_VER
    // Windows 32-bit (Visual C++)
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_stack_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 3);
#endif

#if defined __aarch64__ || defined _M_ARM64
    fastcall_args_in_prehook.l1 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    fastcall_args_in_prehook.l2 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    fastcall_args_in_prehook.l3 = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 2);
    fastcall_args_in_prehook.d = *(double*)funchook_arg_get_flt_reg_addr(info->arg_handle, 0);
#endif
}

static void test_fastcall_args(void)
{
    funchook_t *funchook;
    void *target_func;

    TEST_NAME2("test_prehook", "fastcall_args");

    funchook = funchook_create();

    target_func = (void*)fastcall_llld;
    const funchook_params_t fastcall_llld_params = {
        .prehook = fastcall_llld_prehook,
    };
    ASSERT_FUNCHOOK_OK(funchook_prepare_with_params(funchook, &target_func, &fastcall_llld_params),
                       funchook, "failed to prepare hook fastcall_llld with prehook.");

    target_func = (void*)fastcall_lldl;
    const funchook_params_t fastcall_lldl_params = {
        .prehook = fastcall_lldl_prehook,
    };
    ASSERT_FUNCHOOK_OK(funchook_prepare_with_params(funchook, &target_func, &fastcall_lldl_params),
                       funchook, "failed to prepare hook fastcall_lldl with prehook.");

    target_func = (void*)fastcall_ldll;
    const funchook_params_t fastcall_ldll_params = {
        .prehook = fastcall_ldll_prehook,
    };
    ASSERT_FUNCHOOK_OK(funchook_prepare_with_params(funchook, &target_func, &fastcall_ldll_params),
                       funchook, "failed to prepare hook fastcall_ldll with prehook.");

    target_func = (void*)fastcall_dlll;
    const funchook_params_t fastcall_dlll_params = {
        .prehook = fastcall_dlll_prehook,
    };
    ASSERT_FUNCHOOK_OK(funchook_prepare_with_params(funchook, &target_func, &fastcall_dlll_params),
                       funchook, "failed to prepare hook fastcall_dlll with prehook.");

    target_func = (void*)fastcall_pass_struct;
    const funchook_params_t fastcall_pass_struct_params = {
        .prehook = fastcall_pass_struct_prehook,
    };
    ASSERT_FUNCHOOK_OK(funchook_prepare_with_params(funchook, &target_func, &fastcall_pass_struct_params),
                       funchook, "failed to prepare hook fastcall_pass_struct with prehook.");

    target_func = (void*)fastcall_ret_struct;
    const funchook_params_t fastcall_ret_struct_params = {
        .prehook = fastcall_ret_struct_prehook,
    };
    ASSERT_FUNCHOOK_OK(funchook_prepare_with_params(funchook, &target_func, &fastcall_ret_struct_params),
                       funchook, "failed to prepare hook fastcall_ret_struct with prehook.");
    ASSERT_FUNCHOOK_OK(funchook_install(funchook, 0),
                       funchook, "failed to install hooks.");

    fastcall_args_t fastcall_args_expected;
    DECL_DUMP_BUF(fastcall_args_expected);
    fastcall_args_t fastcall_args_expected2;
    DECL_DUMP_BUF(fastcall_args_expected2);
    fastcall_args_t fastcall_args_expected3;
    DECL_DUMP_BUF(fastcall_args_expected3);
    double retval;

    memset(&fastcall_args_in_target, 0, sizeof(fastcall_args_t));
    memset(&fastcall_args_expected, PADDING_BYTE, sizeof(fastcall_args_t));
    fastcall_args_expected.l1 = 1;
    fastcall_args_expected.l2 = 2;
    fastcall_args_expected.l3 = 3;
    fastcall_args_expected.d = 4.0;
    retval = fastcall_llld(1, 2, 3, 4.0);
    ASSERT_EQUAL_LONG(1 + 2 + 3 + 4, retval, funchook, "return value of fastcall_llld");
    ASSERT_TRUE(memcmp(&fastcall_args_expected, &fastcall_args_in_target, sizeof(fastcall_args_t)) == 0 &&
                memcmp(&fastcall_args_expected, &fastcall_args_in_prehook, sizeof(fastcall_args_t)) == 0,
                funchook,
                "unexpected arguments in fastcall_llld\n"
                "          expected [%s]\n"
                "   args in prehook [%s]\n"
                "    args in target [%s]",
                DUMP_TO_BUF(fastcall_args_expected),
                DUMP_TO_BUF(fastcall_args_in_prehook),
                DUMP_TO_BUF(fastcall_args_in_target));

    memset(&fastcall_args_in_target, 0, sizeof(fastcall_args_t));
    memset(&fastcall_args_expected, PADDING_BYTE, sizeof(fastcall_args_t));
    fastcall_args_expected.l1 = 1;
    fastcall_args_expected.l2 = 2;
    fastcall_args_expected.d = 3.0;
    fastcall_args_expected.l3 = 4;
    retval = fastcall_lldl(1, 2, 3, 4.0);
    ASSERT_EQUAL_LONG(1 + 2 + 3 + 4, retval, funchook, "return value of fastcall_lldl");
    ASSERT_TRUE(memcmp(&fastcall_args_expected, &fastcall_args_in_target, sizeof(fastcall_args_t)) == 0 &&
                memcmp(&fastcall_args_expected, &fastcall_args_in_prehook, sizeof(fastcall_args_t)) == 0,
                funchook,
                "unexpected arguments in fastcall_lldl\n"
                "          expected [%s]\n"
                "   args in prehook [%s]\n"
                "    args in target [%s]",
                DUMP_TO_BUF(fastcall_args_expected),
                DUMP_TO_BUF(fastcall_args_in_prehook),
                DUMP_TO_BUF(fastcall_args_in_target));

    memset(&fastcall_args_in_target, 0, sizeof(fastcall_args_t));
    memset(&fastcall_args_expected, PADDING_BYTE, sizeof(fastcall_args_t));
    fastcall_args_expected.l1 = 1;
    fastcall_args_expected.d = 2.0;
    fastcall_args_expected.l2 = 3;
    fastcall_args_expected.l3 = 4;
    retval = fastcall_ldll(1, 2.0, 3, 4);
    ASSERT_EQUAL_LONG(1 + 2 + 3 + 4, retval, funchook, "return value of fastcall_ldll");
    ASSERT_TRUE(memcmp(&fastcall_args_expected, &fastcall_args_in_target, sizeof(fastcall_args_t)) == 0 &&
                memcmp(&fastcall_args_expected, &fastcall_args_in_prehook, sizeof(fastcall_args_t)) == 0,
                funchook,
                "unexpected arguments in fastcall_ldll\n"
                "          expected [%s]\n"
                "   args in prehook [%s]\n"
                "    args in target [%s]",
                DUMP_TO_BUF(fastcall_args_expected),
                DUMP_TO_BUF(fastcall_args_in_prehook),
                DUMP_TO_BUF(fastcall_args_in_target));

    memset(&fastcall_args_in_target, 0, sizeof(fastcall_args_t));
    memset(&fastcall_args_expected, PADDING_BYTE, sizeof(fastcall_args_t));
    fastcall_args_expected.d = 1.0;
    fastcall_args_expected.l1 = 2;
    fastcall_args_expected.l2 = 3;
    fastcall_args_expected.l3 = 4;
    retval = fastcall_dlll(1.0, 2, 3, 4);
    ASSERT_EQUAL_LONG(1 + 2 + 3 + 4, retval, funchook, "return value of fastcall_dlll");
    ASSERT_TRUE(memcmp(&fastcall_args_expected, &fastcall_args_in_target, sizeof(fastcall_args_t)) == 0 &&
                memcmp(&fastcall_args_expected, &fastcall_args_in_prehook, sizeof(fastcall_args_t)) == 0,
                funchook,
                "unexpected arguments in fastcall_dlll\n"
                "          expected [%s]\n"
                "   args in prehook [%s]\n"
                "    args in target [%s]",
                DUMP_TO_BUF(fastcall_args_expected),
                DUMP_TO_BUF(fastcall_args_in_prehook),
                DUMP_TO_BUF(fastcall_args_in_target));

    memset(&fastcall_args_in_target, 0, sizeof(fastcall_args_t));
    memset(&fastcall_args_in_target2, 0, sizeof(fastcall_args_t));
    memset(&fastcall_args_in_target3, 0, sizeof(fastcall_args_t));
    memset(&fastcall_args_expected, PADDING_BYTE, sizeof(fastcall_args_t));
    memset(&fastcall_args_expected2, PADDING_BYTE, sizeof(fastcall_args_t));
    memset(&fastcall_args_expected3, PADDING_BYTE, sizeof(fastcall_args_t));
    fastcall_args_expected.l1 = 1;
    fastcall_args_expected.l2 = 2;
    fastcall_args_expected.l3 = 3;
    fastcall_args_expected.d = 4.0;
    fastcall_args_expected2.l1 = 5;
    fastcall_args_expected2.l2 = 6;
    fastcall_args_expected2.l3 = 7;
    fastcall_args_expected2.d = 8.0;
    fastcall_args_expected3.l1 = 9;
    fastcall_args_expected3.l2 = 10;
    fastcall_args_expected3.l3 = 11;
    fastcall_args_expected3.d = 12.0;
    retval = fastcall_pass_struct(fastcall_args_expected, fastcall_args_expected2, fastcall_args_expected3);
    ASSERT_EQUAL_LONG(1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10 + 11 + 12, retval, funchook, "return value of fastcall_llld");
    ASSERT_TRUE(memcmp(&fastcall_args_expected, &fastcall_args_in_target, sizeof(fastcall_args_t)) == 0 &&
                memcmp(&fastcall_args_expected, &fastcall_args_in_prehook, sizeof(fastcall_args_t)) == 0 &&
                memcmp(&fastcall_args_expected2, &fastcall_args_in_target2, sizeof(fastcall_args_t)) == 0 &&
                memcmp(&fastcall_args_expected2, &fastcall_args_in_prehook2, sizeof(fastcall_args_t)) == 0 &&
                memcmp(&fastcall_args_expected3, &fastcall_args_in_target3, sizeof(fastcall_args_t)) == 0 &&
                memcmp(&fastcall_args_expected3, &fastcall_args_in_prehook3, sizeof(fastcall_args_t)) == 0,
                funchook,
                "unexpected arguments in fastcall_pass_struct\n"
                "   arg1   expected [%s]\n"
                "   arg1 in prehook [%s]\n"
                "   arg1  in target [%s]\n"
                "   arg2   expected [%s]\n"
                "   arg2 in prehook [%s]\n"
                "   arg2  in target [%s]\n"
                "   arg3   expected [%s]\n"
                "   arg3 in prehook [%s]\n"
                "   arg3  in target [%s]",
                DUMP_TO_BUF(fastcall_args_expected),
                DUMP_TO_BUF(fastcall_args_in_prehook),
                DUMP_TO_BUF(fastcall_args_in_target),
                DUMP_TO_BUF(fastcall_args_expected2),
                DUMP_TO_BUF(fastcall_args_in_prehook2),
                DUMP_TO_BUF(fastcall_args_in_target2),
                DUMP_TO_BUF(fastcall_args_expected3),
                DUMP_TO_BUF(fastcall_args_in_prehook3),
                DUMP_TO_BUF(fastcall_args_in_target3));

    memset(&fastcall_args_in_target, 0, sizeof(fastcall_args_t));
    memset(&fastcall_args_expected, PADDING_BYTE, sizeof(fastcall_args_t));
    fastcall_args_expected.l1 = 1;
    fastcall_args_expected.d = 2.0;
    fastcall_args_expected.l2 = 3;
    fastcall_args_expected.l3 = 4;
    fastcall_args_t ret_struct = fastcall_ret_struct(1, 2.0, 3, 4);
    DECL_DUMP_BUF(ret_struct);
    ASSERT_TRUE(memcmp(&fastcall_args_expected, &fastcall_args_in_target, sizeof(fastcall_args_t)) == 0 &&
                memcmp(&fastcall_args_expected, &fastcall_args_in_prehook, sizeof(fastcall_args_t)) == 0 &&
                memcmp(&fastcall_args_expected, &ret_struct, sizeof(fastcall_args_t)) == 0,
                funchook,
                "unexpected arguments in fastcall_ret_struct\n"
                "          expected [%s]\n"
                "   args in prehook [%s]\n"
                "    args in target [%s]\n"
                "      return value [%s]",
                DUMP_TO_BUF(fastcall_args_expected),
                DUMP_TO_BUF(fastcall_args_in_prehook),
                DUMP_TO_BUF(fastcall_args_in_target),
                DUMP_TO_BUF(ret_struct));

    funchook_uninstall(funchook, 0);
    funchook_destroy(funchook);
}

void test_prehook(void)
{
    funchook_set_debug_file("debug.log");
    test_dllfunc();
    test_long_args();
    test_double_args();
    test_mixed_args();
    test_fastcall_args();
}
