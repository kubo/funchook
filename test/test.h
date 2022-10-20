#ifndef TEST_H
#define TEST_H

#ifdef __GNUC__
#define NOINLINE __attribute__((noinline))
#endif
#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#endif

extern int test_cnt;
extern int error_cnt;

void test_prehook(void);

#endif
