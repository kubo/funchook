#include <stdio.h>
#include <exception>
#include <funchook.h>
extern "C" {
#include "test.h"
}
#include "libfunchook_test.h"

thiscall_args_t thiscall_args;

void thiscall_prehook(funchook_info_t *info)
{
#if defined __i686__ && !defined(_WIN32)
    // All arguments including `this` are passed using stack.
    thiscall_args.this_ = *(void**)funchook_arg_get_stack_addr(info->arg_handle, 0);
    thiscall_args.a = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 1);
    thiscall_args.b = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 2);
#elif (defined __i686__ && defined(_WIN32)) || defined _M_IX86
    // `this` is passed by the ecx register. Others arguments are passed using stack.
    thiscall_args.this_ = *(void**)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    thiscall_args.a = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 0);
    thiscall_args.b = *(long*)funchook_arg_get_stack_addr(info->arg_handle, 1);
#else
    // All arguments including `this` are passed using registers.
    thiscall_args.this_ = *(void**)funchook_arg_get_int_reg_addr(info->arg_handle, 0);
    thiscall_args.a = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 1);
    thiscall_args.b = *(long*)funchook_arg_get_int_reg_addr(info->arg_handle, 2);
#endif
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

namespace {
struct my_exception : public std::exception {};
}

void thiscall_exception_in_prehook(funchook_info_t *info)
{
    throw my_exception();
}

static void test_exception_in_prehook(void)
{
    funchook_t *funchook;
    int rv;
    long (TestCpp::*target_func)(long, long) = &TestCpp::call;

    printf("[%d] test_cpp: exception in prehook\n", ++test_cnt);

    funchook = funchook_create();

    funchook_params_t params = {0};
    params.prehook = thiscall_exception_in_prehook;
    params.flags = FUNCHOOK_FLAG_THISCALL;
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
    bool caught_exception = false;
    try {
        tc.call(1, 2);
    } catch (my_exception&) {
        caught_exception = true;
    }
    if (!caught_exception) {
        printf("ERROR: no exceptions occur\n");
        error_cnt++;
    }

    funchook_uninstall(funchook, 0);
    funchook_destroy(funchook);
}

void test_cpp(void)
{
    test_thiscall();
    test_exception_in_prehook();
}
