#ifndef LIBFUNCHOOK_TEST_H
#define LIBFUNCHOOK_TEST_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#ifdef FUNCHOOK_TEST_EXPORTS
#define TEST_DLL_EXPORT __declspec(dllexport)
#else
#define TEST_DLL_EXPORT __declspec(dllimport)
#endif
#else
#define TEST_DLL_EXPORT
#endif

#ifndef FASTCALL
#if defined _MSC_VER
#define FASTCALL __fastcall
#elif defined __GNUC__ && (defined __i686__ || defined __i386__)
#define FASTCALL __attribute__((fastcall))
#else
#define FASTCALL
#endif
#endif

#define PADDING_BYTE '\xec'

typedef struct {
    uint8_t u8;
    double dbl1;
    uint16_t u16;
    float flt1;
    uint32_t u32;
    double dbl2;
    long lng;
    float flt2;
    uint64_t u64;
    double dbl3;
    uintptr_t uptr;
    float flt3;
} mixed_args_t;

typedef struct {
    long l1;
    long l2;
    long l3;
    double d;
} fastcall_args_t;

extern TEST_DLL_EXPORT void set_val_in_dll(int val);
extern TEST_DLL_EXPORT int get_val_in_dll(void);
extern TEST_DLL_EXPORT long long_args_in_target[10];
extern TEST_DLL_EXPORT long long_args(long arg1, long arg2, long arg3, long arg4, long arg5, long arg6, long arg7, long arg8, long arg9, long arg10);
extern TEST_DLL_EXPORT double double_args_in_target[10];
extern TEST_DLL_EXPORT double double_args(double arg1, double arg2, double arg3, double arg4, double arg5, double arg6, double arg7, double arg8, double arg9, double arg10);
extern TEST_DLL_EXPORT mixed_args_t mixed_args_in_target[2];
extern TEST_DLL_EXPORT mixed_args_t mixed_args(
    uint8_t u8_1, double dbl1_1, uint16_t u16_1, float flt1_1, uint32_t u32_1, double dbl2_1,
    long lng_1, float flt2_1, uint64_t u64_1, double dbl3_1, uintptr_t uptr_1, float flt3_1,
    uint8_t u8_2, double dbl1_2, uint16_t u16_2, float flt1_2, uint32_t u32_2, double dbl2_2,
    long lng_2, float flt2_2, uint64_t u64_2, double dbl3_2, uintptr_t uptr_2, float flt3_2);

extern TEST_DLL_EXPORT fastcall_args_t fastcall_args_in_target;
extern TEST_DLL_EXPORT fastcall_args_t fastcall_args_in_target2;
extern TEST_DLL_EXPORT fastcall_args_t fastcall_args_in_target3;
extern TEST_DLL_EXPORT double FASTCALL fastcall_llld(long l1, long l2, long l3, double d);
extern TEST_DLL_EXPORT double FASTCALL fastcall_lldl(long l1, long l2, double d, long l3);
extern TEST_DLL_EXPORT double FASTCALL fastcall_ldll(long l1, double d, long l2, long l3);
extern TEST_DLL_EXPORT double FASTCALL fastcall_dlll(double d, long l1, long l2, long l3);
extern TEST_DLL_EXPORT double FASTCALL fastcall_pass_struct(fastcall_args_t a1, fastcall_args_t a2, fastcall_args_t a3);
extern TEST_DLL_EXPORT fastcall_args_t FASTCALL fastcall_ret_struct(long l1, double d, long l2, long l3);

#undef S
#define S(suffix) TEST_DLL_EXPORT int dllfunc_##suffix(int a, int b);
#include "suffix.list"
#undef S

#ifdef __cplusplus
}

typedef struct {
    void *this_;
    long a;
    long b;
} thiscall_args_t;

class TEST_DLL_EXPORT TestCpp {
public:
  TestCpp();
  long call(long a, long b);

private:
  long m_;
};

#endif

#endif
