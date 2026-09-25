/*
 * test.h - a minimal self-contained test framework.
 *
 * A test is a `void f(void)` function registered with RUN_TEST. CHECK and
 * CHECK_EQ record a failure (with file and line) and let the test continue,
 * so one run reports every broken expectation, not just the first.
 */
#ifndef PCAPSTAT_TEST_H
#define PCAPSTAT_TEST_H

#include <stdio.h>

void test_fail(const char *file, int line, const char *expr);
void test_fail_eq(const char *file, int line, const char *a, const char *b,
                  unsigned long long va, unsigned long long vb);
void test_check_passed(void);
void test_run(const char *name, void (*fn)(void));

/* Directory for temporary files, from the command line. */
extern const char *test_tmpdir;

#define CHECK(cond)                                         \
    do {                                                    \
        if (cond)                                           \
            test_check_passed();                            \
        else                                                \
            test_fail(__FILE__, __LINE__, #cond);           \
    } while (0)

/* Compare two integer values (any integer or enum type). */
#define CHECK_EQ(a, b)                                                  \
    do {                                                                \
        unsigned long long check_va_ = (unsigned long long)(a);         \
        unsigned long long check_vb_ = (unsigned long long)(b);         \
        if (check_va_ == check_vb_)                                     \
            test_check_passed();                                        \
        else                                                            \
            test_fail_eq(__FILE__, __LINE__, #a, #b, check_va_, check_vb_); \
    } while (0)

#define RUN_TEST(fn) test_run(#fn, fn)

/* Each test file exposes one function that runs its tests. */
void run_pcap_tests(void);
void run_decode_tests(void);
void run_flow_tests(void);
void run_report_tests(void);

#endif /* PCAPSTAT_TEST_H */
