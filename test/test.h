#ifndef TEST_H
#define TEST_H

#ifdef __GNUC__
#define NOINLINE __attribute__((noinline))
#endif
#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#endif

#if defined(_WIN32)
#define DLLIMPORT __declspec(dllimport)
#else
#define DLLIMPORT
#endif

extern int test_cnt;
extern int error_cnt;

void test_prehook(void);
void test_cpp(void);

#endif
