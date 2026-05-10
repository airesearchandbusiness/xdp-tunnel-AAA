/* SPDX-License-Identifier: MIT */
#include <benchmark/benchmark.h>
#include <cstring>
#include "tachyon.h"
#include "ratchet.h"

static void BM_RatchetInit(benchmark::State &state) {
    tachyon::ratchet::SendState rs{};
    uint8_t key[32];
    memset(key, 0xAB, 32);
    for (auto _ : state) {
        tachyon::ratchet::ratchet_init(rs, key);
        benchmark::DoNotOptimize(rs);
    }
}
BENCHMARK(BM_RatchetInit);

static void BM_RatchetNext(benchmark::State &state) {
    tachyon::ratchet::SendState rs{};
    uint8_t key[32], out[32];
    memset(key, 0xAB, 32);
    tachyon::ratchet::ratchet_init(rs, key);
    for (auto _ : state) {
        tachyon::ratchet::ratchet_next(rs, out);
        benchmark::DoNotOptimize(out);
    }
}
BENCHMARK(BM_RatchetNext);
