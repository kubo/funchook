#ifdef WIN32
static int int_val;
void set_int_val(int val)
{
    int_val = val;
}
#else
extern int int_val;
#endif

int get_val_in_shared_library()
{
    return int_val;
}
