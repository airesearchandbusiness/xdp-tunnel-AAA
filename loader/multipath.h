/* SPDX-License-Identifier: MIT */
/*
 * Tachyon - Multi-Path Transport Manager
 *
 * Tracks multiple physical network paths and elects the best one based on
 * a composite score derived from RTT EWMA, packet loss rate, and jitter.
 *
 * Design:
 *   - Caller adds paths (each a bound UDP fd) via add_path()
 *   - Probe RTT samples are fed via on_probe_ack() / on_probe_timeout()
 *   - reelect() re-scores all paths and promotes the best one to primary
 *   - best_fd() returns the current primary socket fd
 *
 * Scoring (lower = better):
 *   score = RTT_ewma × (1 + loss_ppm/1e6) × (1 + jitter/RTT_ewma)
 *
 * EWMA coefficients follow RFC 6298 §2:
 *   α = 1/8 for RTT,  β = 1/4 for mean deviation (jitter)
 *   γ = 1/16 for loss rate
 *
 * Thread-safety: not thread-safe; serialize all calls from the CP main loop.
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include <ctime>
#include <string>
#include <vector>
#include <limits>

namespace tachyon::multipath {

/* ══════════════════════════════════════════════════════════════════════════
 * Per-Path Quality Metrics
 * ══════════════════════════════════════════════════════════════════════════ */

struct PathMetrics {
    int      sock_fd     = -1;    /* UDP socket descriptor                    */
    bool     active      = false; /* Path currently considered reachable       */
    bool     primary     = false; /* Currently elected primary path            */

    /* RTT state (RFC 6298) — all times in microseconds */
    uint64_t rtt_ewma_us  = 0;                                   /* Smoothed RTT          */
    uint64_t rtt_min_us   = std::numeric_limits<uint64_t>::max(); /* Minimum RTT (RTTProp) */
    uint64_t jitter_us    = 0;                                   /* Mean deviation        */

    /* Loss tracking */
    uint32_t loss_ppm       = 0; /* Loss rate (parts-per-million)             */
    uint32_t probes_sent    = 0; /* Lifetime probe count                      */
    uint32_t probes_acked   = 0; /* Lifetime ack count                        */
    uint32_t consecutive_lost = 0; /* Consecutive probes without ack          */

    /* Activity timestamps (monotonic µs) */
    uint64_t last_tx_us   = 0;
    uint64_t last_rx_us   = 0;

    /* Identification */
    std::string local_ip;
    uint16_t    local_port = 0;
};

/* ══════════════════════════════════════════════════════════════════════════
 * Tuning Constants
 * ══════════════════════════════════════════════════════════════════════════ */

static constexpr double   kRttAlpha          = 0.125;  /* 1/8  — RFC 6298 SRTT alpha       */
static constexpr double   kRttBeta           = 0.25;   /* 1/4  — RFC 6298 RTTVAR beta      */
static constexpr double   kLossAlpha         = 0.0625; /* 1/16 — loss EWMA                 */
static constexpr uint32_t kDeadProbeThresh   = 5;      /* Consecutive losses → mark dead   */
static constexpr uint64_t kDefaultBaseRtt    = 50000;  /* 50 ms fallback when no samples   */

/* ══════════════════════════════════════════════════════════════════════════
 * PathManager
 * ══════════════════════════════════════════════════════════════════════════ */

class PathManager {
public:
    PathManager() = default;
    ~PathManager();

    /* Non-copyable: owns socket fds */
    PathManager(const PathManager &) = delete;
    PathManager &operator=(const PathManager &) = delete;

    /* Add a path with an already-bound UDP socket fd.
     * The PathManager takes ownership — it will close(fd) on removal/destroy.
     * Returns the path index (stable for the lifetime of the path). */
    size_t add_path(int sock_fd, const std::string &local_ip, uint16_t local_port);

    /* Deactivate and close a path by index. */
    void remove_path(size_t idx);

    /* Update RTT after receiving a probe acknowledgment.
     * rtt_us: measured one-way trip × 2 (or full RTT if echo-based). */
    void on_probe_ack(size_t path_idx, uint64_t rtt_us);

    /* Record a probe timeout for a path. Increments consecutive_lost;
     * if threshold exceeded the path is marked inactive and reelection occurs. */
    void on_probe_timeout(size_t path_idx);

    /* Record a successful data packet received on path_idx (resets loss streak). */
    void on_data_rx(size_t path_idx, uint64_t now_us);

    /* Re-score all paths and elect the best active one as primary.
     * Should be called every probe interval (~5 s) or on path state change. */
    void reelect();

    /* Scalar composite score for a path (lower is better).
     * Returns UINT64_MAX for inactive / socketless paths. */
    static uint64_t score(const PathMetrics &m);

    /* Socket fd of the currently elected primary path (-1 if no active paths). */
    int best_fd()  const;
    int best_idx() const { return best_idx_; }

    /* Introspection */
    const std::vector<PathMetrics> &paths() const { return paths_; }
    size_t path_count()  const { return paths_.size(); }
    size_t active_count() const;

private:
    std::vector<PathMetrics> paths_;
    int best_idx_ = -1;

    static uint64_t mono_us();
};

} /* namespace tachyon::multipath */
