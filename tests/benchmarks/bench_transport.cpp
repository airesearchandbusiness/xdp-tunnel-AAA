/* SPDX-License-Identifier: MIT */
/* Tachyon Transport Benchmarks */
#include <benchmark/benchmark.h>
#include <cstring>
#include <vector>
#include "tachyon.h"
#include "transport.h"

class TransportBench : public benchmark::Fixture {
  public:
    void SetUp(benchmark::State &) override { init_crypto_globals(); }
    void TearDown(benchmark::State &) override { free_crypto_globals(); }
};

static void BM_Wrap(benchmark::State &state, int tid) {
    using namespace tachyon::transport;
    auto id = static_cast<TransportId>(tid);
    if (!transport_get(id)) {
        state.SkipWithMessage("transport unavailable");
        return;
    }
    size_t sz = static_cast<size_t>(state.range(0));
    std::vector<uint8_t> in(sz, 0xAB), out(4096);
    FrameContext ctx{};
    ctx.seq = 0;
    ctx.sni = "example.com";
    ctx.conn_id_len = 8;
    RAND_bytes(ctx.conn_id, 8);
    for (auto _ : state) {
        auto r = transport_wrap(id, in.data(), sz, out.data(), out.size(), &ctx);
        benchmark::DoNotOptimize(r.ok);
    }
    state.SetBytesProcessed(state.iterations() * sz);
}

static void BM_Unwrap(benchmark::State &state, int tid) {
    using namespace tachyon::transport;
    auto id = static_cast<TransportId>(tid);
    if (!transport_get(id)) {
        state.SkipWithMessage("transport unavailable");
        return;
    }
    size_t sz = static_cast<size_t>(state.range(0));
    std::vector<uint8_t> in(sz, 0xAB), wrapped(4096), out(4096);
    FrameContext ctx{};
    ctx.seq = 0;
    ctx.sni = "example.com";
    ctx.conn_id_len = 8;
    auto wr = transport_wrap(id, in.data(), sz, wrapped.data(), wrapped.size(), &ctx);
    if (!wr.ok) {
        state.SkipWithMessage("wrap failed");
        return;
    }
    for (auto _ : state) {
        auto r = transport_unwrap(id, wrapped.data(), wr.bytes, out.data(), out.size());
        benchmark::DoNotOptimize(r.ok);
    }
    state.SetBytesProcessed(state.iterations() * sz);
}

#define REGISTER_TRANSPORT_BENCH(Name, Tid)                                                        \
    BENCHMARK_CAPTURE(BM_Wrap, Name##_wrap, Tid)->Arg(64)->Arg(512)->Arg(1400);                    \
    BENCHMARK_CAPTURE(BM_Unwrap, Name##_unwrap, Tid)->Arg(64)->Arg(512)->Arg(1400);

REGISTER_TRANSPORT_BENCH(QUIC, 1)
REGISTER_TRANSPORT_BENCH(HTTP2, 2)
REGISTER_TRANSPORT_BENCH(DoH, 3)
REGISTER_TRANSPORT_BENCH(STUN, 4)
