#ifndef TEST_H
#define TEST_H

#ifdef __GNUC__
#define NOINLINE __attribute__((noinline))
#define UNUSED_PARAM __attribute__((unused))
#endif
#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#endif

#ifndef UNUSED_PARAM
#define UNUSED_PARAM
#endif

#if defined(_WIN32)
#define DLLIMPORT __declspec(dllimport)
#else
#define DLLIMPORT
#endif

void test_prehook(void);
void test_cpp(void);

#endif
