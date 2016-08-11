/* -*- indent-tabs-mode: nil -*-
 */
#include <stdio.h>
#include <duckhook.h>

typedef int (*int_func_t)(void);

extern void reset_retval(void);
extern int get_val_in_shared_library(void);
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

#if defined(WIN32)
__declspec(dllexport) int int_val = 0xbaceba11;
#else
int int_val = 0xbaceba11;
#endif


static int test_cnt;
static int error_cnt;
static int hook_is_called;
static int_func_t orig_func;

int get_val()
{
    return int_val;
}

static int hook_func(void)
{
    hook_is_called = 1;
    return orig_func();
}

#define TEST_DUCKHOOK_INT(func) test_duckhook_int(func, #func,  __LINE__)

void test_duckhook_int(int_func_t func, const char *func_str, int line)
{
    duckhook_t *duckhook = duckhook_create();
    int result;
    int expected;
    int rv;

    test_cnt++;
    printf("[%d] test_duckhook_int: %s\n", test_cnt, func_str);

    expected = ++int_val;
    set_int_val(int_val);
    reset_retval();
    result = func();
    if (result != int_val) {
        printf("ERROR at line %d: expected %d but %d before hooking.\n", line, expected, result);
	error_cnt++;
	return;
    }
    orig_func = func;
    rv = duckhook_prepare(duckhook, (void**)&orig_func, hook_func);
    if (rv != 0) {
        printf("ERROR at line %d: failed to hook %s.\n", line, func_str);
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
        printf("ERROR at line %d: hook_func is not called.\n", line);
	error_cnt++;
	return;
    }
    if (expected != result) {
        printf("ERROR at line %d: expected %d but %d after hooking.\n", line, expected, result);
	error_cnt++;
	return;
    }

    duckhook_uninstall(duckhook, 0);

    expected = ++int_val;
    set_int_val(int_val);
    reset_retval();
    result = func();
    if (expected != result) {
        printf("ERROR at line %d: expected %d but %d after hook is removed.\n", line, expected, result);
	error_cnt++;
	return;
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

    TEST_DUCKHOOK_INT(get_val);
    TEST_DUCKHOOK_INT(get_val_in_shared_library);

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

    if (error_cnt == 0) {
        printf("all %d tests are passed.\n", test_cnt);
        return 0;
    } else {
        printf("%d of %d tests are failed.\n", error_cnt, test_cnt);
        return 1;
    }
}
