#include <stdio.h>
#include <funchook.h>
extern "C" {
#include "test.h"
}
#include "libfunchook_test.h"

thiscall_args_t thiscall_args;

void thiscall_prehook(funchook_info_t *info)
{
    funchook_get_arg(info->arg_handle, 1, &thiscall_args.this_);
    funchook_get_arg(info->arg_handle, 2, &thiscall_args.a);
    funchook_get_arg(info->arg_handle, 3, &thiscall_args.b);
}

static void test_thiscall(void)
{
    funchook_t *funchook;
    int rv;
    long (TestCpp::*target_func)(long, long) = &TestCpp::call;

    printf("[%d] test_cpp: thiscall\n", ++test_cnt);

    funchook = funchook_create();

    funchook_params_t params = {0};
    params.prehook = thiscall_prehook;
    params.flags = FUNCHOOK_FLAG_THISCALL;
    params.arg_types = "lpll";
    rv = funchook_prepare_with_params(funchook, (void**)&target_func, &params);
    if (rv != 0) {
        printf("ERROR: failed to prepare hook TestCpp::call with prehook. (%s)\n", funchook_error_message(funchook));
        error_cnt++;
        return;
    }

    rv = funchook_install(funchook, 0);
    if (rv != 0) {
        printf("ERROR: failed to install hooks. (%s)\n", funchook_error_message(funchook));
        error_cnt++;
        funchook_destroy(funchook);
        return;
    }

    TestCpp tc;
    tc.call(1, 2);
    if (thiscall_args.this_ != &tc || thiscall_args.a != 1 || thiscall_args.b != 2) {
        printf("ERROR: unexpected arguments in TestCpp::call\n"
               "   expected [%p, 0x%lx, 0x%lx]\n"
               "        but [%p, 0x%lx, 0x%lx]\n",
               &tc, 1l, 2l, thiscall_args.this_, thiscall_args.a, thiscall_args.b);
        error_cnt++;
    }

    funchook_uninstall(funchook, 0);
    funchook_destroy(funchook);
}

void test_cpp(void)
{
    test_thiscall();
}
