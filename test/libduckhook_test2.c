#ifdef WIN32
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

extern int get_val_in_exe(void);
extern int get_val_in_dll(void);

DLLEXPORT int get_val_in_exe_from_dll()
{
    return get_val_in_exe();
}

DLLEXPORT int get_val_in_dll_from_dll()
{
    return get_val_in_dll();
}
