/* -*- indent-tabs-mode: nil -*-
 */
#include <stdio.h>
#include <duckhook.h>

#ifdef WIN32
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

typedef int (*int_func_t)(void);

extern int reset_retval(void);
DLLEXPORT int get_val_in_exe(void);
extern int get_val_in_dll(void);
extern int get_val_in_exe_from_dll(void);
extern int get_val_in_dll_from_dll(void);
extern int x86_test_jump(void);
extern int x86_test_call_get_pc_thunk_ax(void);
extern int x86_test_call_get_pc_thunk_bx(void);
extern int x86_test_call_get_pc_thunk_cx(void);
extern int x86_test_call_get_pc_thunk_dx(void);
extern int x86_test_call_get_pc_thunk_si(void);
extern int x86_test_call_get_pc_thunk_di(void);
extern int x86_test_call_get_pc_thunk_bp(void);
extern int x86_test_call_and_pop_eax(void);
extern int x86_test_call_and_pop_ebx(void);
extern int x86_test_call_and_pop_ecx(void);
extern int x86_test_call_and_pop_edx(void);
extern int x86_test_call_and_pop_esi(void);
extern int x86_test_call_and_pop_edi(void);
extern int x86_test_call_and_pop_ebp(void);
extern int x86_test_error_jump1(void);
extern int x86_test_error_jump2(void);

#if defined(WIN32) || defined(__APPLE__)
extern void set_int_val(int val);
#else
#define set_int_val(val) do {} while(0)
#endif

#ifdef _MSC_VER
int reset_retval()
{
    return 0;
}
#endif

#if defined(WIN32)
__declspec(dllexport) int int_val = 0xbaceba11;
#else
int int_val = 0xbaceba11;
#endif


static int test_cnt;
static int error_cnt;
static int hook_is_called;
static int_func_t orig_func;

int get_val_in_exe(void)
{
    return int_val;
}

static int hook_func(void)
{
    hook_is_called = 1;
    return orig_func();
}

#define TEST_DUCKHOOK_INT(func) test_duckhook_int(func, #func, NULL, NULL)
#define TEST_DUCKHOOK_INT2(func, func2) test_duckhook_int(func, #func, func2, #func2)

void test_duckhook_int(int_func_t func, const char *func_str, int_func_t func2, const char *func2_str)
{
    duckhook_t *duckhook = duckhook_create();
    int result;
    int expected;
    int rv;

    test_cnt++;
    if (func2 == NULL) {
        printf("[%d] test_duckhook_int: %s\n", test_cnt, func_str);
    } else {
        printf("[%d] test_duckhook_int: %s and %s\n", test_cnt, func_str, func2_str);
    }

    expected = ++int_val;
    set_int_val(int_val);
    reset_retval();
    result = func();
    if (expected != result) {
        printf("ERROR: %s should return %d but %d before hooking.\n", func_str, expected, result);
        error_cnt++;
        return;
    }
    if (func2 != NULL) {
        reset_retval();
        result = func2();
        if (expected != result) {
            printf("ERROR: %s should return %d but %d before hooking.\n", func2_str, expected, result);
            error_cnt++;
            return;
        }
    }
    orig_func = func;
    rv = duckhook_prepare(duckhook, (void**)&orig_func, hook_func);
    if (rv != 0) {
        printf("ERROR: failed to hook %s.\n", func_str);
        error_cnt++;
        return;
    }
    duckhook_install(duckhook, 0);

    hook_is_called = 0;
    expected = ++int_val;
    set_int_val(int_val);
    reset_retval();
    result = func();
    if (hook_is_called == 0) {
        printf("ERROR: hook_func is not called by %s.\n", func_str);
        error_cnt++;
        return;
    }
    if (expected != result) {
        printf("ERROR: %s should return %d but %d after hooking.\n", func_str, expected, result);
        error_cnt++;
        return;
    }
    if (func2 != NULL) {
        hook_is_called = 0;
        reset_retval();
        result = func2();
        if (hook_is_called == 0) {
            printf("ERROR: hook_func is not called by %s.\n", func2_str);
            error_cnt++;
            return;
        }
        if (expected != result) {
            printf("ERROR: %s should return %d but %d after hooking.\n", func2_str, expected, result);
            error_cnt++;
            return;
        }
    }

    duckhook_uninstall(duckhook, 0);

    expected = ++int_val;
    set_int_val(int_val);
    reset_retval();
    result = func();
    if (expected != result) {
        printf("ERROR: %s should return %d but %d after hook is removed.\n", func_str, expected, result);
        error_cnt++;
        return;
    }
    if (func2 != NULL) {
        reset_retval();
        result = func2();
        if (expected != result) {
            printf("ERROR: %s should return %d but %d after hook is removed.\n", func2_str, expected, result);
            error_cnt++;
            return;
        }
    }

    duckhook_destroy(duckhook);
}

#define TEST_DUCKHOOK_EXPECT_ERROR(func, errcode) test_duckhook_expect_error(func, errcode, #func, __LINE__)
void test_duckhook_expect_error(int_func_t func, int errcode, const char *func_str, int line)
{
    duckhook_t *duckhook = duckhook_create();
    int rv;

    test_cnt++;
    printf("[%d] test_duckhook_expect_error: %s\n", test_cnt, func_str);

    orig_func = func;
    rv = duckhook_prepare(duckhook, (void**)&orig_func, hook_func);
    if (rv != errcode) {
        printf("ERROR at line %d: hooking must fail with %d but %d.\n", line, errcode, rv);
        error_cnt++;
    }
    duckhook_destroy(duckhook);
}

int main()
{
    duckhook_set_debug_file("debug.log");

    TEST_DUCKHOOK_INT2(get_val_in_exe, get_val_in_exe_from_dll);
    TEST_DUCKHOOK_INT2(get_val_in_dll, get_val_in_dll_from_dll);

#ifndef _MSC_VER
#if defined __i386 || defined  _M_I386
    TEST_DUCKHOOK_INT(x86_test_jump);
    TEST_DUCKHOOK_EXPECT_ERROR(x86_test_error_jump1, DUCKHOOK_ERROR_CANNOT_FIX_IP_RELATIVE);
    TEST_DUCKHOOK_EXPECT_ERROR(x86_test_error_jump2, DUCKHOOK_ERROR_FOUND_BACK_JUMP);

#ifndef WIN32
    TEST_DUCKHOOK_INT(x86_test_call_get_pc_thunk_ax);
    TEST_DUCKHOOK_INT(x86_test_call_get_pc_thunk_bx);
    TEST_DUCKHOOK_INT(x86_test_call_get_pc_thunk_cx);
    TEST_DUCKHOOK_INT(x86_test_call_get_pc_thunk_dx);
    TEST_DUCKHOOK_INT(x86_test_call_get_pc_thunk_si);
    TEST_DUCKHOOK_INT(x86_test_call_get_pc_thunk_di);
    TEST_DUCKHOOK_INT(x86_test_call_get_pc_thunk_bp);
    TEST_DUCKHOOK_INT(x86_test_call_and_pop_eax);
    TEST_DUCKHOOK_INT(x86_test_call_and_pop_ebx);
    TEST_DUCKHOOK_INT(x86_test_call_and_pop_ecx);
    TEST_DUCKHOOK_INT(x86_test_call_and_pop_edx);
    TEST_DUCKHOOK_INT(x86_test_call_and_pop_esi);
    TEST_DUCKHOOK_INT(x86_test_call_and_pop_edi);
    TEST_DUCKHOOK_INT(x86_test_call_and_pop_ebp);
#endif
#endif

#endif

    if (error_cnt == 0) {
        printf("all %d tests are passed.\n", test_cnt);
        return 0;
    } else {
        printf("%d of %d tests are failed.\n", error_cnt, test_cnt);
        return 1;
    }
}
