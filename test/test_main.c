/* -*- indent-tabs-mode: nil -*-
 */
#ifdef WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef WIN32
#include <io.h>
#define mode_t int
#define ssize_t int
#define open _open
#define read _read
#define close _close
#else
#include <unistd.h>
#endif
#include <funchook.h>

#ifdef WIN32
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

#ifdef __GNUC__
#define NOINLINE __attribute__((noinline))
#endif
#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
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

#define TEST_FUNCHOOK_INT(func) test_funchook_int(func, #func, NULL, NULL)
#define TEST_FUNCHOOK_INT2(func, func2) test_funchook_int(func, #func, func2, #func2)

void test_funchook_int(volatile int_func_t func, const char *func_str, volatile int_func_t func2, const char *func2_str)
{
    funchook_t *funchook = funchook_create();
    int result;
    int expected;
    int rv;

    test_cnt++;
    if (func2 == NULL) {
        printf("[%d] test_funchook_int: %s\n", test_cnt, func_str);
    } else {
        printf("[%d] test_funchook_int: %s and %s\n", test_cnt, func_str, func2_str);
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
    rv = funchook_prepare(funchook, (void**)&orig_func, hook_func);
    if (rv != 0) {
        printf("ERROR: failed to hook %s.\n", func_str);
        error_cnt++;
        return;
    }
    funchook_install(funchook, 0);

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

    funchook_uninstall(funchook, 0);

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

    funchook_destroy(funchook);
}

#define TEST_FUNCHOOK_EXPECT_ERROR(func, errcode) test_funchook_expect_error(func, errcode, #func, __LINE__)
void test_funchook_expect_error(int_func_t func, int errcode, const char *func_str, int line)
{
    funchook_t *funchook = funchook_create();
    int rv;

    test_cnt++;
    printf("[%d] test_funchook_expect_error: %s\n", test_cnt, func_str);

    orig_func = func;
    rv = funchook_prepare(funchook, (void**)&orig_func, hook_func);
    if (rv != errcode) {
        printf("ERROR at line %d: hooking must fail with %d but %d.\n", line, errcode, rv);
        error_cnt++;
    }
    funchook_destroy(funchook);
}

static int (*open_func)(const char *pathname, int flags, mode_t mode);
static FILE *(*fopen_func)(const char *pathname, const char *mode);

static int open_hook(const char *pathname, int flags, mode_t mode)
{
    if (strcmp(pathname, "test-1.txt") == 0) {
        pathname = "test-2.txt";
    }
    return open_func(pathname, flags, mode);
}

static FILE *fopen_hook(const char *pathname, const char *mode)
{
    if (strcmp(pathname, "test-1.txt") == 0) {
        pathname = "test-2.txt";
    }
    return fopen_func(pathname, mode);
}

static void read_content_by_open(const char *filename, char *buf, size_t bufsiz)
{
    int fd = open(filename, O_RDONLY);
    ssize_t size = read(fd, buf, bufsiz);

    if (size >= 0) {
        buf[size] = '\0';
    } else {
        strcpy(buf, "read error");
    }
    close(fd);
}

static void read_content_by_fopen(const char *filename, char *buf, size_t bufsiz)
{
    FILE *fp = fopen(filename, "r");
    if (fp != NULL) {
        if (fgets(buf, bufsiz, fp) == NULL) {
            strcpy(buf, "read error");
        }
        fclose(fp);
    } else {
        strcpy(buf, "open error");
    }
}

static void check_content(const char *filename, const char *expect, int line)
{
    char buf[512];

    read_content_by_open(filename, buf, sizeof(buf));
    if (strcmp(buf, expect) != 0) {
        printf("ERROR at line %d: '%s' != '%s' (open)\n", line, buf, expect);
        error_cnt++;
    }
    read_content_by_fopen(filename, buf, sizeof(buf));
    if (strcmp(buf, expect) != 0) {
        printf("ERROR at line %d: '%s' != '%s' (fopen)\n", line, buf, expect);
        error_cnt++;
    }
}

static void test_hook_open_and_fopen(void)
{
    FILE *fp;
    funchook_t *funchook;

#ifdef WIN64
    if (getenv("WINELOADERNOEXEC") != NULL) {
        /* The test doesn't work on Wine. */
        return;
    }
#endif

    test_cnt++;
    printf("[%d] test_hook_open_and_fopen\n", test_cnt);

    /* prepare file contents */
    fp = fopen("test-1.txt", "w");
    fputs("This is test-1.txt.", fp);
    fclose(fp);
    fp = fopen("test-2.txt", "w");
    fputs("This is test-2.txt.", fp);
    fclose(fp);

    /* prepare to hook `open' and `fopen` */
    funchook = funchook_create();
    open_func = (int (*)(const char*, int, mode_t))open;
    funchook_prepare(funchook, (void**)&open_func, open_hook);
    fopen_func = fopen;
    funchook_prepare(funchook, (void**)&fopen_func, fopen_hook);

    /* The contents of test-1.txt should be "This is test-1.txt". */
    check_content("test-1.txt", "This is test-1.txt.", __LINE__);

    /* hook `open' and `fopen` */
    funchook_install(funchook, 0);
    /* Try to open test-1.txt but open test-2.txt. */
    check_content("test-1.txt", "This is test-2.txt.", __LINE__);

    /* restore hooks.  */
    funchook_uninstall(funchook, 0);
    /* Open test-1.txt. */
    check_content("test-1.txt", "This is test-1.txt.", __LINE__);

    funchook_destroy(funchook);
}

#define S(suffix) \
    extern int dllfunc_##suffix(int, int); \
    static int (*dllfunc_##suffix##_func)(int, int); \
    static int dllfunc_##suffix##_hook(int a, int b) { \
        return dllfunc_##suffix##_func(a, b) * 2; \
    } \
    NOINLINE int exefunc_##suffix(int a, int b) { return a * b + suffix; } \
    static int (*exefunc_##suffix##_func)(int, int); \
    static int exefunc_##suffix##_hook(int a, int b) { \
        return exefunc_##suffix##_func(a, b) * 2; \
    }
#include "suffix.list"
#undef S

static NOINLINE int call_dll_and_exe_funcs(int installed)
{
    int rv;
    int mul = installed ? 2 : 1;
    const char *is_str = installed ? "isn't" : "is";
#define S(suffix) \
    rv = dllfunc_##suffix(2, 3); \
    if (rv != (2 * 3 + suffix) * mul) { \
        printf("ERROR: dllfunc_%s %s hooked. (rv=%d)\n", #suffix, is_str, rv); \
        error_cnt++; \
        return -1; \
    } \
    rv = exefunc_##suffix(2, 3); \
    if (rv != (2 * 3 + suffix) * mul) { \
        printf("ERROR: exefunc_%s %s hooked. (rv=%d)\n", #suffix, is_str, rv); \
        error_cnt++; \
        return -1; \
    }
#include "suffix.list"
#undef S
    return 0;
}

static void test_hook_many_funcs(void)
{
    funchook_t *funchook;
    test_cnt++;
    printf("[%d] test_hook_many_funcs\n", test_cnt);
    funchook = funchook_create();
#define S(suffix) \
    dllfunc_##suffix##_func = dllfunc_##suffix; \
    funchook_prepare(funchook, (void**)&dllfunc_##suffix##_func, dllfunc_##suffix##_hook); \
    exefunc_##suffix##_func = exefunc_##suffix; \
    funchook_prepare(funchook, (void**)&exefunc_##suffix##_func, exefunc_##suffix##_hook); \
    putchar('.'); fflush(stdout);
#include "suffix.list"
#undef S
    putchar('\n');

    funchook_install(funchook, 0);
    if (call_dll_and_exe_funcs(1) != 0) {
        return;
    }

    funchook_uninstall(funchook, 0);
    if (call_dll_and_exe_funcs(0) != 0) {
        return;
    }

    funchook_destroy(funchook);
}

int main()
{
    funchook_set_debug_file("debug.log");

    TEST_FUNCHOOK_INT2(get_val_in_exe, get_val_in_exe_from_dll);
    TEST_FUNCHOOK_INT2(get_val_in_dll, get_val_in_dll_from_dll);

#ifndef _MSC_VER
#if defined __i386 || defined  _M_I386
    TEST_FUNCHOOK_INT(x86_test_jump);
    TEST_FUNCHOOK_EXPECT_ERROR(x86_test_error_jump1, FUNCHOOK_ERROR_CANNOT_FIX_IP_RELATIVE);
    TEST_FUNCHOOK_EXPECT_ERROR(x86_test_error_jump2, FUNCHOOK_ERROR_FOUND_BACK_JUMP);

#ifndef WIN32
    TEST_FUNCHOOK_INT(x86_test_call_get_pc_thunk_ax);
    TEST_FUNCHOOK_INT(x86_test_call_get_pc_thunk_bx);
    TEST_FUNCHOOK_INT(x86_test_call_get_pc_thunk_cx);
    TEST_FUNCHOOK_INT(x86_test_call_get_pc_thunk_dx);
    TEST_FUNCHOOK_INT(x86_test_call_get_pc_thunk_si);
    TEST_FUNCHOOK_INT(x86_test_call_get_pc_thunk_di);
    TEST_FUNCHOOK_INT(x86_test_call_get_pc_thunk_bp);
    TEST_FUNCHOOK_INT(x86_test_call_and_pop_eax);
    TEST_FUNCHOOK_INT(x86_test_call_and_pop_ebx);
    TEST_FUNCHOOK_INT(x86_test_call_and_pop_ecx);
    TEST_FUNCHOOK_INT(x86_test_call_and_pop_edx);
    TEST_FUNCHOOK_INT(x86_test_call_and_pop_esi);
    TEST_FUNCHOOK_INT(x86_test_call_and_pop_edi);
    TEST_FUNCHOOK_INT(x86_test_call_and_pop_ebp);
#endif
#endif

#endif

    test_hook_open_and_fopen();
    test_hook_many_funcs();

    if (error_cnt == 0) {
        printf("all %d tests are passed.\n", test_cnt);
        return 0;
    } else {
        printf("%d of %d tests are failed.\n", error_cnt, test_cnt);
        return 1;
    }
}
