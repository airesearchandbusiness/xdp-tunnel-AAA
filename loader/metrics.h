/* SPDX-License-Identifier: MIT */
/*
 * Thread-safe metrics collector for the control plane.
 *
 * Provides lock-free atomic counters for every observable event across
 * all modules: handshakes, packets, bytes, replays, cover frames, rekeys,
 * and per-transport-engine breakdowns. Designed for:
 *
 *   - `tachyon show` CLI (human-readable snapshot)
 *   - Prometheus / StatsD export (future extension)
 *   - Canary health checks (total_rx > 0 within DPD window)
 *
 * All counters are monotonically increasing uint64_t, reset only on
 * explicit `metrics_reset()` (or process restart). Reads are relaxed-
 * order — they may lag writes by a handful of nanoseconds, which is fine
 * for display / alerting.
 */
#ifndef TACHYON_METRICS_H
#define TACHYON_METRICS_H

#include <atomic>
#include <cstdint>

namespace tachyon::metrics {

struct Counters {
    /* Handshake */
    std::atomic<uint64_t> hs_initiated{0};
    std::atomic<uint64_t> hs_completed{0};
    std::atomic<uint64_t> hs_failed{0};
    std::atomic<uint64_t> hs_rekeys{0};

    /* Data plane (control-plane perspective) */
    std::atomic<uint64_t> tx_packets{0};
    std::atomic<uint64_t> tx_bytes{0};
    std::atomic<uint64_t> rx_packets{0};
    std::atomic<uint64_t> rx_bytes{0};

    /* Replay */
    std::atomic<uint64_t> replay_accepted{0};
    std::atomic<uint64_t> replay_dropped{0};
    std::atomic<uint64_t> replay_stale{0};

    /* Padding / cover traffic */
    std::atomic<uint64_t> cover_frames_sent{0};
    std::atomic<uint64_t> padme_bytes_overhead{0};

    /* Transport */
    std::atomic<uint64_t> transport_wrap_ok{0};
    std::atomic<uint64_t> transport_wrap_fail{0};
    std::atomic<uint64_t> transport_unwrap_ok{0};
    std::atomic<uint64_t> transport_unwrap_fail{0};

    /* Rate limiter */
    std::atomic<uint64_t> rl_tx_drops{0};
    std::atomic<uint64_t> rl_rx_drops{0};
};

/* Singleton accessor. Survives for the process lifetime. */
Counters &global();

/* Zero every counter. Useful for test isolation and `tachyon reset-stats`. */
void reset();

/* Snapshot: copy all counters to a plain (non-atomic) struct for safe
 * serialisation without holding any lock. */
struct Snapshot {
    uint64_t hs_initiated, hs_completed, hs_failed, hs_rekeys;
    uint64_t tx_packets, tx_bytes, rx_packets, rx_bytes;
    uint64_t replay_accepted, replay_dropped, replay_stale;
    uint64_t cover_frames_sent, padme_bytes_overhead;
    uint64_t transport_wrap_ok, transport_wrap_fail;
    uint64_t transport_unwrap_ok, transport_unwrap_fail;
    uint64_t rl_tx_drops, rl_rx_drops;
};
Snapshot snapshot();

} /* namespace tachyon::metrics */

#endif /* TACHYON_METRICS_H */
