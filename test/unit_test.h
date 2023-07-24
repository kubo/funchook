#ifndef UNIT_TEST_H
#define UNIT_TEST_H

#include <funchook.h>
#include <stddef.h>

extern int error_cnt;

void unit_test_begin(void);
int unit_test_end(void);
void unit_test_name(const char *name1, const char *name2);

#define TEST_BEGIN() unit_test_begin()
#define TEST_END() unit_test_end()
#define TEST_NAME1(name1) unit_test_name(name1, NULL)
#define TEST_NAME2(name1, name2) unit_test_name(name1, name2)

#define ASSERT_EQUAL_WITH_TYPE(type, fmt, expected, actual, funchook, ...) do { \
    type expected_ = (expected); \
    type actual_ = (actual); \
    if (expected_ != actual_) { \
        printf("ERROR: "); \
        printf(__VA_ARGS__); \
        printf(" (expected " fmt " but " fmt ")\n", expected_, actual_); \
        error_cnt++; \
        if (funchook) { \
            funchook_uninstall(funchook, 0); \
            funchook_destroy(funchook); \
        } \
        return; \
    } \
} while(0)

#define ASSERT_EQUAL_INT(expected, actual, funchook, ...) ASSERT_EQUAL_WITH_TYPE(int, "%d", expected, actual, funchook, __VA_ARGS__)
#define ASSERT_EQUAL_LONG(expected, actual, funchook, ...) ASSERT_EQUAL_WITH_TYPE(long, "%ld", expected, actual, funchook, __VA_ARGS__)
#define ASSERT_EQUAL_UINT64(expected, actual, funchook, ...) ASSERT_EQUAL_WITH_TYPE(uint64_t, "0x%"PRIx64, expected, actual, funchook, __VA_ARGS__)
#define ASSERT_EQUAL_DOUBLE(expected, actual, funchook, ...) ASSERT_EQUAL_WITH_TYPE(double, "%f", expected, actual, funchook, __VA_ARGS__)

#define ASSERT_TRUE(cond, funchook, ...) do { \
    if (!(cond)) { \
        printf("ERROR: "); \
        printf(__VA_ARGS__); \
        printf("\n"); \
        error_cnt++; \
        if (funchook) { \
            funchook_uninstall(funchook, 0); \
            funchook_destroy(funchook); \
        } \
        return; \
    } \
} while(0)

#define ASSERT_FALSE(cond, funchook, ...) do { \
    if (cond) { \
        printf("ERROR: "); \
        printf(__VA_ARGS__); \
        printf("\n"); \
        error_cnt++; \
        if (funchook) { \
            funchook_uninstall(funchook, 0); \
            funchook_destroy(funchook); \
        } \
        return; \
    } \
} while(0)

#define ASSERT_FUNCHOOK_OK(result, funchook, ...) do { \
    int rv_ = (result); \
    if (rv_ != 0 ) { \
        printf("ERROR: "); \
        printf(__VA_ARGS__); \
        printf(" (%s)\n", funchook_error_message(funchook)); \
        error_cnt++; \
        funchook_uninstall(funchook, 0); \
        funchook_destroy(funchook); \
        return; \
    } \
} while(0)

#define DUMP_BYTE_BUFSIZ(size) ( 2 * (size) + (size) / 4 + 1)
#define DECL_DUMP_BUF(name) char name##__buf__[DUMP_BYTE_BUFSIZ(sizeof(name))]
char *dump_to_buf(void *addr, size_t size, char *buf, size_t bufsize);
#define DUMP_TO_BUF(name) dump_to_buf(&name, sizeof(name), name##__buf__, sizeof(name##__buf__))

#endif
