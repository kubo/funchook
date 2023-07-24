#include "unit_test.h"
#include <stdio.h>

static int test_cnt;
int error_cnt;

void unit_test_begin(void)
{
    test_cnt = 0;
    error_cnt = 0;
    funchook_set_debug_file("debug.log");
}

int unit_test_end(void)
{
    if (error_cnt == 0) {
        printf("all %d tests are passed.\nOK\n", test_cnt);
        return 0;
    } else {
        printf("%d of %d tests are failed.\nERROR\n", error_cnt, test_cnt);
        return 1;
    }
}

void unit_test_name(const char *name1, const char *name2)
{
    if (name2) {
        printf("[%d] %s: %s\n", ++test_cnt, name1, name2);
    } else {
        printf("[%d] %s\n", ++test_cnt, name1);
    }
}

char *dump_to_buf(void *addr, size_t size, char *buf, size_t bufsize)
{
    char *p = buf;
    char *end = p + bufsize - 1;
    size_t i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 4 == 0) {
            if (p < end) {
                *(p++) = ' ';
                *p = '\0';
            }
        }
        if (p + 1 < end) {
            sprintf(p, "%02x", ((unsigned char*)addr)[i]);
            p += 2;
        }
    }
    return buf;
}
