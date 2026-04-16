/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Test Suite - Minimal Test Harness
 *
 * Self-contained test runner with no external dependencies.
 * Provides ASSERT macros, colored output, and failure tracking.
 */
#ifndef TACHYON_TEST_H
#define TACHYON_TEST_H

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <string>

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;
static const char *g_current_test = nullptr;

#define TEST(name)                                                                                 \
    static void test_##name();                                                                     \
    static void run_##name() {                                                                     \
        g_current_test = #name;                                                                    \
        g_tests_run++;                                                                             \
        test_##name();                                                                             \
    }                                                                                              \
    static void test_##name()

#define RUN_TEST(name)                                                                             \
    do {                                                                                           \
        int _before = g_tests_failed;                                                              \
        run_##name();                                                                              \
        if (g_tests_failed == _before) {                                                           \
            g_tests_passed++;                                                                      \
            printf("  \033[32mPASS\033[0m  %s\n", #name);                                          \
        }                                                                                          \
    } while (0)

#define ASSERT_TRUE(expr)                                                                          \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            printf("  \033[31mFAIL\033[0m  %s:%d: "                                                \
                   "ASSERT_TRUE(%s) in %s\n",                                                      \
                   __FILE__, __LINE__, #expr, g_current_test);                                     \
            g_tests_failed++;                                                                      \
            return;                                                                                \
        }                                                                                          \
    } while (0)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))

#define ASSERT_EQ(a, b)                                                                            \
    do {                                                                                           \
        auto _a = (long long)(a);                                                                  \
        auto _b = (long long)(b);                                                                  \
        if (_a != _b) {                                                                            \
            printf("  \033[31mFAIL\033[0m  %s:%d: "                                                \
                   "ASSERT_EQ(%s, %s) => %lld != %lld "                                            \
                   "in %s\n",                                                                      \
                   __FILE__, __LINE__, #a, #b, _a, _b, g_current_test);                            \
            g_tests_failed++;                                                                      \
            return;                                                                                \
        }                                                                                          \
    } while (0)

#define ASSERT_MEM_EQ(a, b, len)                                                                   \
    do {                                                                                           \
        if (memcmp((a), (b), (len)) != 0) {                                                        \
            printf("  \033[31mFAIL\033[0m  %s:%d: "                                                \
                   "ASSERT_MEM_EQ(%s, %s, %d) in %s\n",                                            \
                   __FILE__, __LINE__, #a, #b, (int)(len), g_current_test);                        \
            g_tests_failed++;                                                                      \
            return;                                                                                \
        }                                                                                          \
    } while (0)

static int test_summary() {
    printf("\n  ─────────────────────────────────\n");
    printf("  Total: %d  Passed: \033[32m%d\033[0m  Failed: ", g_tests_run, g_tests_passed);
    if (g_tests_failed > 0)
        printf("\033[31m%d\033[0m\n", g_tests_failed);
    else
        printf("0\n");
    printf("  ─────────────────────────────────\n\n");
    return g_tests_failed > 0 ? 1 : 0;
}

#endif /* TACHYON_TEST_H */
