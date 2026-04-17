/* SPDX-License-Identifier: MIT */
#include "metrics.h"

namespace tachyon::metrics {

static Counters g_counters;

Counters &global() { return g_counters; }

void reset() {
    auto &c = g_counters;
    c.hs_initiated.store(0, std::memory_order_relaxed);
    c.hs_completed.store(0, std::memory_order_relaxed);
    c.hs_failed.store(0, std::memory_order_relaxed);
    c.hs_rekeys.store(0, std::memory_order_relaxed);
    c.tx_packets.store(0, std::memory_order_relaxed);
    c.tx_bytes.store(0, std::memory_order_relaxed);
    c.rx_packets.store(0, std::memory_order_relaxed);
    c.rx_bytes.store(0, std::memory_order_relaxed);
    c.replay_accepted.store(0, std::memory_order_relaxed);
    c.replay_dropped.store(0, std::memory_order_relaxed);
    c.replay_stale.store(0, std::memory_order_relaxed);
    c.cover_frames_sent.store(0, std::memory_order_relaxed);
    c.padme_bytes_overhead.store(0, std::memory_order_relaxed);
    c.transport_wrap_ok.store(0, std::memory_order_relaxed);
    c.transport_wrap_fail.store(0, std::memory_order_relaxed);
    c.transport_unwrap_ok.store(0, std::memory_order_relaxed);
    c.transport_unwrap_fail.store(0, std::memory_order_relaxed);
    c.rl_tx_drops.store(0, std::memory_order_relaxed);
    c.rl_rx_drops.store(0, std::memory_order_relaxed);
}

Snapshot snapshot() {
    auto &c = g_counters;
    return {
        c.hs_initiated.load(std::memory_order_relaxed),
        c.hs_completed.load(std::memory_order_relaxed),
        c.hs_failed.load(std::memory_order_relaxed),
        c.hs_rekeys.load(std::memory_order_relaxed),
        c.tx_packets.load(std::memory_order_relaxed),
        c.tx_bytes.load(std::memory_order_relaxed),
        c.rx_packets.load(std::memory_order_relaxed),
        c.rx_bytes.load(std::memory_order_relaxed),
        c.replay_accepted.load(std::memory_order_relaxed),
        c.replay_dropped.load(std::memory_order_relaxed),
        c.replay_stale.load(std::memory_order_relaxed),
        c.cover_frames_sent.load(std::memory_order_relaxed),
        c.padme_bytes_overhead.load(std::memory_order_relaxed),
        c.transport_wrap_ok.load(std::memory_order_relaxed),
        c.transport_wrap_fail.load(std::memory_order_relaxed),
        c.transport_unwrap_ok.load(std::memory_order_relaxed),
        c.transport_unwrap_fail.load(std::memory_order_relaxed),
        c.rl_tx_drops.load(std::memory_order_relaxed),
        c.rl_rx_drops.load(std::memory_order_relaxed),
    };
}

} /* namespace tachyon::metrics */
