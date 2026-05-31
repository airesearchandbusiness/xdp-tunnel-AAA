/* SPDX-License-Identifier: MIT */
/*
 * Microbenchmark: circuit breaker state-machine overhead.
 *
 * Compile: cmake -B build -S tests -DBUILD_BENCHMARKS=ON
 * Run:     ./bench_circuit_breaker
 */
#include <benchmark/benchmark.h>
#include "circuit_breaker.h"

using tachyon::CircuitBreaker;

static void BM_CircuitBreakerAllowClosed(benchmark::State &state) {
    CircuitBreaker cb;
    uint64_t now = 1000;
    for (auto _ : state)
        benchmark::DoNotOptimize(cb.allow_request(now));
}
BENCHMARK(BM_CircuitBreakerAllowClosed);

static void BM_CircuitBreakerAllowOpen(benchmark::State &state) {
    CircuitBreaker cb(/*threshold=*/1);
    cb.record_failure(1000); /* trips to OPEN */
    uint64_t now = 1001;     /* still in cooldown */
    for (auto _ : state)
        benchmark::DoNotOptimize(cb.allow_request(now));
}
BENCHMARK(BM_CircuitBreakerAllowOpen);

static void BM_CircuitBreakerRecordFailure(benchmark::State &state) {
    CircuitBreaker cb;
    uint64_t now = 1000;
    for (auto _ : state) {
        cb.record_failure(now);
        cb.reset();
    }
}
BENCHMARK(BM_CircuitBreakerRecordFailure);

static void BM_CircuitBreakerNextRetry(benchmark::State &state) {
    CircuitBreaker cb;
    cb.record_failure(1000);
    cb.record_failure(1001);
    cb.record_failure(1002);
    uint64_t now = 1003;
    for (auto _ : state)
        benchmark::DoNotOptimize(cb.next_retry_sec(now));
}
BENCHMARK(BM_CircuitBreakerNextRetry);

BENCHMARK_MAIN();
