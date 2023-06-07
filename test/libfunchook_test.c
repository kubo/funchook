#include <string.h>
#include "libfunchook_test.h"

static int val_in_dll;

void set_val_in_dll(int val)
{
    val_in_dll = val;
}

int get_val_in_dll()
{
    return val_in_dll;
}

long long_args_in_target[10];

long long_args(long arg1, long arg2, long arg3, long arg4, long arg5, long arg6, long arg7, long arg8, long arg9, long arg10)
{
    long_args_in_target[0] = arg1;
    long_args_in_target[1] = arg2;
    long_args_in_target[2] = arg3;
    long_args_in_target[3] = arg4;
    long_args_in_target[4] = arg5;
    long_args_in_target[5] = arg6;
    long_args_in_target[6] = arg7;
    long_args_in_target[7] = arg8;
    long_args_in_target[8] = arg9;
    long_args_in_target[9] = arg10;
    return arg1 + arg2 + arg3 + arg4 + arg5 + arg6 + arg7 + arg8 + arg9 + arg10;
}

double double_args_in_target[10];

double double_args(double arg1, double arg2, double arg3, double arg4, double arg5, double arg6, double arg7, double arg8, double arg9, double arg10)
{
    double_args_in_target[0] = arg1;
    double_args_in_target[1] = arg2;
    double_args_in_target[2] = arg3;
    double_args_in_target[3] = arg4;
    double_args_in_target[4] = arg5;
    double_args_in_target[5] = arg6;
    double_args_in_target[6] = arg7;
    double_args_in_target[7] = arg8;
    double_args_in_target[8] = arg9;
    double_args_in_target[9] = arg10;
    return arg1 + arg2 + arg3 + arg4 + arg5 + arg6 + arg7 + arg8 + arg9 + arg10;
}

mixed_args_t mixed_args_in_target[2];

mixed_args_t mixed_args(
    uint8_t u8_1, double dbl1_1, uint16_t u16_1, float flt1_1, uint32_t u32_1, double dbl2_1,
    long lng_1, float flt2_1, uint64_t u64_1, double dbl3_1, uintptr_t uptr_1, float flt3_1,
    uint8_t u8_2, double dbl1_2, uint16_t u16_2, float flt1_2, uint32_t u32_2, double dbl2_2,
    long lng_2, float flt2_2, uint64_t u64_2, double dbl3_2, uintptr_t uptr_2, float flt3_2)
{
    mixed_args_t retval = {0,};
    memset(mixed_args_in_target, PADDING_BYTE, sizeof(mixed_args_in_target));
    memset(&retval, PADDING_BYTE, sizeof(retval));
    mixed_args_in_target[0].u8 = u8_1;
    mixed_args_in_target[0].dbl1 = dbl1_1;
    mixed_args_in_target[0].u16 = u16_1;
    mixed_args_in_target[0].flt1 = flt1_1;
    mixed_args_in_target[0].u32 = u32_1;
    mixed_args_in_target[0].dbl2 = dbl2_1;
    mixed_args_in_target[0].lng = lng_1;
    mixed_args_in_target[0].flt2 = flt2_1;
    mixed_args_in_target[0].u64 = u64_1;
    mixed_args_in_target[0].dbl3 = dbl3_1;
    mixed_args_in_target[0].uptr = uptr_1;
    mixed_args_in_target[0].flt3 = flt3_1;
    mixed_args_in_target[1].u8 = u8_2;
    mixed_args_in_target[1].dbl1 = dbl1_2;
    mixed_args_in_target[1].u16 = u16_2;
    mixed_args_in_target[1].flt1 = flt1_2;
    mixed_args_in_target[1].u32 = u32_2;
    mixed_args_in_target[1].dbl2 = dbl2_2;
    mixed_args_in_target[1].lng = lng_2;
    mixed_args_in_target[1].flt2 = flt2_2;
    mixed_args_in_target[1].u64 = u64_2;
    mixed_args_in_target[1].dbl3 = dbl3_2;
    mixed_args_in_target[1].uptr = uptr_2;
    mixed_args_in_target[1].flt3 = flt3_2;
    retval.u8 = u8_1 + u8_2;
    retval.dbl1 = dbl1_1 + dbl1_2;
    retval.u16 = u16_1 + u16_2;
    retval.flt1 = flt1_1 + flt1_2;
    retval.u32 = u32_1 + u32_2;
    retval.dbl2 = dbl2_1 + dbl2_2;
    retval.lng = lng_1 + lng_2;
    retval.flt2 = flt2_1 + flt2_2;
    retval.u64 = u64_1 + u64_2;
    retval.dbl3 = dbl3_1 + dbl3_2;
    retval.uptr = uptr_1 + uptr_2;
    retval.flt3 = flt3_1 + flt3_2;
    return retval;
}

fastcall_args_t fastcall_args_in_target;
fastcall_args_t fastcall_args_in_target2;
fastcall_args_t fastcall_args_in_target3;

double FASTCALL fastcall_llld(long l1, long l2, long l3, double d)
{
    memset(&fastcall_args_in_target, PADDING_BYTE, sizeof(fastcall_args_t));
    fastcall_args_in_target.l1 = l1;
    fastcall_args_in_target.l2 = l2;
    fastcall_args_in_target.l3 = l3;
    fastcall_args_in_target.d = d;
    return (double)l1 + (double)l2 + (double)l3 + d;
}

double FASTCALL fastcall_lldl(long l1, long l2, double d, long l3)
{
    memset(&fastcall_args_in_target, PADDING_BYTE, sizeof(fastcall_args_t));
    fastcall_args_in_target.l1 = l1;
    fastcall_args_in_target.l2 = l2;
    fastcall_args_in_target.l3 = l3;
    fastcall_args_in_target.d = d;
    return (double)l1 + (double)l2 + (double)l3 + d;
}

double FASTCALL fastcall_ldll(long l1, double d, long l2, long l3)
{
    memset(&fastcall_args_in_target, PADDING_BYTE, sizeof(fastcall_args_t));
    fastcall_args_in_target.l1 = l1;
    fastcall_args_in_target.l2 = l2;
    fastcall_args_in_target.l3 = l3;
    fastcall_args_in_target.d = d;
    return (double)l1 + (double)l2 + (double)l3 + d;
}

double FASTCALL fastcall_dlll(double d, long l1, long l2, long l3)
{
    memset(&fastcall_args_in_target, PADDING_BYTE, sizeof(fastcall_args_t));
    fastcall_args_in_target.l1 = l1;
    fastcall_args_in_target.l2 = l2;
    fastcall_args_in_target.l3 = l3;
    fastcall_args_in_target.d = d;
    return (double)l1 + (double)l2 + (double)l3 + d;
}

double FASTCALL fastcall_pass_struct(fastcall_args_t a1, fastcall_args_t a2, fastcall_args_t a3)
{
    memset(&fastcall_args_in_target, PADDING_BYTE, sizeof(fastcall_args_t));
    memset(&fastcall_args_in_target2, PADDING_BYTE, sizeof(fastcall_args_t));
    memset(&fastcall_args_in_target3, PADDING_BYTE, sizeof(fastcall_args_t));
    fastcall_args_in_target.l1 = a1.l1;
    fastcall_args_in_target.l2 = a1.l2;
    fastcall_args_in_target.l3 = a1.l3;
    fastcall_args_in_target.d = a1.d;
    fastcall_args_in_target2.l1 = a2.l1;
    fastcall_args_in_target2.l2 = a2.l2;
    fastcall_args_in_target2.l3 = a2.l3;
    fastcall_args_in_target2.d = a2.d;
    fastcall_args_in_target3.l1 = a3.l1;
    fastcall_args_in_target3.l2 = a3.l2;
    fastcall_args_in_target3.l3 = a3.l3;
    fastcall_args_in_target3.d = a3.d;
    return (double)a1.l1 + (double)a1.l2 + (double)a1.l3 + a1.d
      + (double)a2.l1 + (double)a2.l2 + (double)a2.l3 + a2.d
      + (double)a3.l1 + (double)a3.l2 + (double)a3.l3 + a3.d;
}

fastcall_args_t FASTCALL fastcall_ret_struct(long l1, double d, long l2, long l3)
{
    fastcall_args_t retval;
    memset(&retval, PADDING_BYTE, sizeof(fastcall_args_t));
    retval.l1 = l1;
    retval.l2 = l2;
    retval.l3 = l3;
    retval.d = d;
    memset(&fastcall_args_in_target, PADDING_BYTE, sizeof(fastcall_args_t));
    fastcall_args_in_target.l1 = l1;
    fastcall_args_in_target.l2 = l2;
    fastcall_args_in_target.l3 = l3;
    fastcall_args_in_target.d = d;
    return retval;
}

#undef S
#define S(suffix) int dllfunc_##suffix(int a, int b) { return a * b + suffix; }
#include "suffix.list"
#undef S
