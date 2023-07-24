#include <stdio.h>
#include <exception>
#include <funchook.h>
extern "C" {
#include "test.h"
#include "unit_test.h"
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
    long (TestCpp::*target_func)(long, long) = &TestCpp::call;

    TEST_NAME2("test_cpp", "thiscall");

    funchook = funchook_create();

    funchook_params_t params = {NULL, NULL, NULL, 0};
    params.prehook = thiscall_prehook;
    ASSERT_FUNCHOOK_OK(funchook_prepare_with_params(funchook, (void**)&target_func, &params),
                       funchook, "failed to prepare hook TestCpp::call with prehook.");
    ASSERT_FUNCHOOK_OK(funchook_install(funchook, 0),
                       funchook, "failed to install hooks.");

    TestCpp tc;
    tc.call(1, 2);
    ASSERT_TRUE(thiscall_args.this_ == &tc && thiscall_args.a == 1 && thiscall_args.b == 2,
                funchook,
                "unexpected arguments in TestCpp::call\n"
                "   expected [%p, 0x%lx, 0x%lx]\n"
                "        but [%p, 0x%lx, 0x%lx]\n",
                &tc, 1l, 2l, thiscall_args.this_, thiscall_args.a, thiscall_args.b);

    funchook_uninstall(funchook, 0);
    funchook_destroy(funchook);
}

namespace {
struct my_exception : public std::exception {};
}

void thiscall_exception_in_prehook(funchook_info_t *info UNUSED_PARAM)
{
    throw my_exception();
}

static void test_exception_in_prehook(void)
{
    funchook_t *funchook;
    long (TestCpp::*target_func)(long, long) = &TestCpp::call;

    TEST_NAME2("test_cpp", "exception in prehook");

    funchook = funchook_create();

    funchook_params_t params = {NULL, NULL, NULL, 0};
    params.prehook = thiscall_exception_in_prehook;
    ASSERT_FUNCHOOK_OK(funchook_prepare_with_params(funchook, (void**)&target_func, &params),
                       funchook, "failed to prepare hook TestCpp::call with prehook.");
    ASSERT_FUNCHOOK_OK(funchook_install(funchook, 0),
                       funchook, "failed to install hooks.");

    TestCpp tc;
    bool caught_exception = false;
    try {
        tc.call(1, 2);
    } catch (my_exception&) {
        caught_exception = true;
    }
    ASSERT_TRUE(caught_exception, funchook, "no exceptions occur");

    funchook_uninstall(funchook, 0);
    funchook_destroy(funchook);
}

void test_cpp(void)
{
    test_thiscall();
    test_exception_in_prehook();
}
