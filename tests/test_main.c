/*
 * test_main.c - test runner.
 *
 *   run_tests [TMPDIR]    TMPDIR (default ".") holds temporary pcap files.
 */
#include <stdio.h>

#include "test.h"

const char *test_tmpdir = ".";

static int tests_run, tests_failed, checks_run, current_failed;

void test_check_passed(void)
{
    checks_run++;
}

void test_fail(const char *file, int line, const char *expr)
{
    checks_run++;
    current_failed = 1;
    fprintf(stderr, "    %s:%d: CHECK(%s) failed\n", file, line, expr);
}

void test_fail_eq(const char *file, int line, const char *a, const char *b,
                  unsigned long long va, unsigned long long vb)
{
    checks_run++;
    current_failed = 1;
    fprintf(stderr, "    %s:%d: CHECK_EQ(%s, %s) failed: %llu != %llu\n",
            file, line, a, b, va, vb);
}

void test_run(const char *name, void (*fn)(void))
{
    current_failed = 0;
    fn();
    tests_run++;
    if (current_failed) {
        tests_failed++;
        printf("FAIL  %s\n", name);
    } else {
        printf("ok    %s\n", name);
    }
}

int main(int argc, char **argv)
{
    if (argc > 1)
        test_tmpdir = argv[1];

    run_pcap_tests();
    run_decode_tests();
    run_flow_tests();
    run_report_tests();
    run_gtpu_tests();

    printf("\n%d tests, %d checks, %d failed\n", tests_run, checks_run,
           tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
