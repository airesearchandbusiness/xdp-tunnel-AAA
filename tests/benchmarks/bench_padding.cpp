/* SPDX-License-Identifier: MIT */
#include <benchmark/benchmark.h>
#include "tachyon.h"
#include "padding.h"

static void BM_PadmeRound(benchmark::State &state) {
    uint32_t sz = static_cast<uint32_t>(state.range(0));
    for (auto _ : state) {
        auto r = tachyon::padding::padme_round(sz);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_PadmeRound)->Arg(64)->Arg(128)->Arg(256)->Arg(512)->Arg(1024)->Arg(1400);

static void BM_ShaperPollCover(benchmark::State &state) {
    tachyon::padding::ShaperState shaper;
    uint32_t hz = static_cast<uint32_t>(state.range(0));
    tachyon::padding::shaper_init(shaper, hz);
    uint64_t now_ns = 1'000'000'000ULL;
    for (auto _ : state) {
        now_ns += 20'000'000ULL;
        auto r = tachyon::padding::shaper_poll_cover(shaper, now_ns, 64, 1400);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_ShaperPollCover)->Arg(0)->Arg(5)->Arg(50);

static void BM_ShaperOnRealFrame(benchmark::State &state) {
    tachyon::padding::ShaperState shaper;
    tachyon::padding::shaper_init(shaper, 10);
    uint64_t now_ns = 1'000'000'000ULL;
    for (auto _ : state) {
        now_ns += 1'000'000ULL;
        tachyon::padding::shaper_on_real_frame(shaper, now_ns);
    }
}
BENCHMARK(BM_ShaperOnRealFrame);
