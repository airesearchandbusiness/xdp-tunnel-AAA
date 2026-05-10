/* SPDX-License-Identifier: MIT */
/*
 * Microbenchmark: structured log throughput (text vs JSON, level-filtered).
 *
 * Compile: cmake -B build -S tests -DBUILD_BENCHMARKS=ON
 * Run:     ./bench_log
 */
#include <benchmark/benchmark.h>
#include "log.h"

#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

namespace {

/* Redirect stderr to /dev/null so the IO is uniform across runs. */
struct StderrSink {
    int saved_fd = -1;
    StderrSink() {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull < 0)
            return;
        saved_fd = dup(STDERR_FILENO);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
    }
    ~StderrSink() {
        if (saved_fd >= 0) {
            dup2(saved_fd, STDERR_FILENO);
            close(saved_fd);
        }
    }
};

} /* namespace */

static void BM_LogTextSimple(benchmark::State &state) {
    StderrSink sink;
    tachyon::log::init(
        {.json = false, .use_syslog = false, .min_level = tachyon::log::Level::INFO});
    for (auto _ : state)
        LOG_INFO("hello world from benchmark iteration %d", 42);
}
BENCHMARK(BM_LogTextSimple);

static void BM_LogJsonSimple(benchmark::State &state) {
    StderrSink sink;
    tachyon::log::init({.json = true, .use_syslog = false, .min_level = tachyon::log::Level::INFO});
    for (auto _ : state)
        LOG_INFO("hello world from benchmark iteration %d", 42);
}
BENCHMARK(BM_LogJsonSimple);

static void BM_LogJsonWithContext(benchmark::State &state) {
    StderrSink sink;
    tachyon::log::init({.json = true, .use_syslog = false, .min_level = tachyon::log::Level::INFO});
    tachyon::log::set_context("session_id", "42");
    tachyon::log::set_context("peer_ip", "10.0.0.1");
    for (auto _ : state)
        LOG_INFO("event with context %d", 42);
    tachyon::log::clear_context();
}
BENCHMARK(BM_LogJsonWithContext);

static void BM_LogFiltered(benchmark::State &state) {
    /* Min level WARN, emitting INFO → fast-path no-op. */
    tachyon::log::init(
        {.json = false, .use_syslog = false, .min_level = tachyon::log::Level::WARN});
    for (auto _ : state)
        LOG_INFO("filtered out, should be near-zero cost");
}
BENCHMARK(BM_LogFiltered);

BENCHMARK_MAIN();
