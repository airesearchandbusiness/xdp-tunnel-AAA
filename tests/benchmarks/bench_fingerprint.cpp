/* SPDX-License-Identifier: MIT */
#include <benchmark/benchmark.h>
#include <cstring>
#include "tachyon.h"
#include "fingerprint.h"

static void BM_PortHopCurrent(benchmark::State &state) {
    uint8_t psk[32];
    memset(psk, 0xCD, 32);
    uint64_t ts = 1700000000ULL;
    for (auto _ : state) {
        auto port = tachyon::fp::port_hop_current(psk, 60, ts++);
        benchmark::DoNotOptimize(port);
    }
}
BENCHMARK(BM_PortHopCurrent);
