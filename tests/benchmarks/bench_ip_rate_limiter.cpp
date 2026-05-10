/* SPDX-License-Identifier: MIT */
/*
 * Microbenchmark: IP rate limiter check() throughput across cardinalities.
 *
 * Compile: cmake -B build -S tests -DBUILD_BENCHMARKS=ON
 * Run:     ./bench_ip_rate_limiter
 */
#include <benchmark/benchmark.h>
#include "ip_rate_limiter.h"

#include <cstdint>
#include <random>

using tachyon::rl::IpRateLimiter;

static void BM_IpRateLimiterCheckHotIp(benchmark::State &state) {
    IpRateLimiter rl(4096);
    uint32_t ip = 0x0a000001; /* 10.0.0.1 */
    uint64_t now = 1000;
    for (auto _ : state)
        benchmark::DoNotOptimize(rl.check(ip, now));
}
BENCHMARK(BM_IpRateLimiterCheckHotIp);

static void BM_IpRateLimiterCheckRandomIp(benchmark::State &state) {
    const size_t N = state.range(0);
    IpRateLimiter rl(static_cast<uint32_t>(N) * 2);
    std::mt19937 rng(42);
    std::vector<uint32_t> ips;
    ips.reserve(N);
    for (size_t i = 0; i < N; ++i)
        ips.push_back(rng());
    /* Pre-populate so we measure steady-state lookup cost. */
    uint64_t now = 1000;
    for (auto ip : ips)
        rl.check(ip, now);

    size_t i = 0;
    for (auto _ : state) {
        benchmark::DoNotOptimize(rl.check(ips[i], now));
        i = (i + 1) % N;
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_IpRateLimiterCheckRandomIp)->Arg(64)->Arg(512)->Arg(4096)->Arg(10000);

static void BM_IpRateLimiterRecordFailure(benchmark::State &state) {
    IpRateLimiter rl(4096);
    uint32_t ip = 0x0a000002;
    uint64_t now = 2000;
    for (auto _ : state) {
        rl.record_failure(ip, now);
    }
}
BENCHMARK(BM_IpRateLimiterRecordFailure);

BENCHMARK_MAIN();
