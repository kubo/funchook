#ifdef WIN32
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

#if defined(WIN32) || defined(__APPLE__)
static int int_val;

DLLEXPORT void set_int_val(int val)
{
    int_val = val;
}
#else
extern int int_val;
#endif

DLLEXPORT int get_val_in_dll()
{
    return int_val;
}

#define S(suffix) DLLEXPORT int dllfunc_##suffix(int a, int b) { return a * b + suffix; }
#include "suffix.list"
#undef S
