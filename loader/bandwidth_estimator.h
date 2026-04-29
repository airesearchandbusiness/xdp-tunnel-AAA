/* SPDX-License-Identifier: MIT */
/*
 * Tachyon - BBR-Inspired Bandwidth & RTT Estimator (header-only)
 *
 * Tracks two key path properties (following BBR v1 / RFC 9002):
 *
 *   BtlBw   — Bottleneck Bandwidth: windowed maximum delivery rate.
 *             Updated every time an ACK reports a byte delivery batch.
 *             Represents the achievable throughput of the path.
 *
 *   RTTProp — Propagation RTT: windowed minimum round-trip time.
 *             Represents the baseline latency with no queuing delay.
 *
 * From these two values the estimator derives:
 *   pacing_rate    = BtlBw × pacing_gain     (target send rate)
 *   inflight_cap   = BtlBw × RTTProp × cwnd_gain  (in-flight budget)
 *
 * Additionally tracks smoothed RTT (SRTT) and mean deviation (RTTVAR)
 * per RFC 6298 §2 for retransmission timeout calculations.
 *
 * WindowedMaxFilter — Kathleen Nichols minmax algorithm adapted for
 * a 3-sample circular buffer. Evicts samples older than window_ns.
 *
 * Thread-safety: not thread-safe; single-session use only.
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include <limits>
#include <array>
#include <algorithm>

namespace tachyon {

/* ══════════════════════════════════════════════════════════════════════════
 * Windowed Max Filter (Kathleen Nichols minmax, 3-sample)
 *
 * Tracks the maximum value seen within a sliding time window.
 * Uses a monotonically decreasing deque of 3 entries so that the global
 * max is always available in O(1) from the front.
 * ══════════════════════════════════════════════════════════════════════════ */

template <typename T>
class WindowedMaxFilter {
public:
    struct Sample {
        T        val = {};
        uint64_t t   = 0;
    };

    /* Record a new sample at time `now_ns`, evicting any older than `window_ns`. */
    void update(T val, uint64_t now_ns, uint64_t window_ns) {
        /* Drop the oldest sample if it has fallen out of the window */
        if (size_ > 0 && now_ns - buf_[0].t > window_ns) {
            buf_[0] = buf_[1];
            buf_[1] = buf_[2];
            if (size_ > 1) --size_;
            if (size_ > 1) --size_; /* at most remove one "oldest" per update */
        }

        /* Maintain non-increasing order (discard dominated older samples) */
        while (size_ > 0 && buf_[size_ - 1].val <= val)
            --size_;

        if (size_ < 3)
            buf_[size_++] = {val, now_ns};
    }

    /* Best (maximum) value in the current window, or T{} if empty. */
    T best() const {
        if (size_ == 0)
            return T{};
        T result = buf_[0].val;
        for (size_t i = 1; i < size_; ++i)
            result = std::max(result, buf_[i].val);
        return result;
    }

    bool empty() const { return size_ == 0; }
    void reset() { size_ = 0; }

private:
    std::array<Sample, 3> buf_{};
    size_t size_ = 0;
};

/* ══════════════════════════════════════════════════════════════════════════
 * BandwidthEstimator
 * ══════════════════════════════════════════════════════════════════════════ */

class BandwidthEstimator {
public:
    /* Pacing and congestion-window gains (BBR default probe_bw phase) */
    static constexpr double   kPacingGain  = 1.25;
    static constexpr double   kCwndGain    = 2.0;

    /* Sliding windows for BtlBw and RTTProp estimation */
    static constexpr uint64_t kBwWindowNs  = 10'000'000'000ULL; /* 10 s */
    static constexpr uint64_t kRttWindowNs = 10'000'000'000ULL; /* 10 s */

    /* ── Feedback entry points ─────────────────────────────────────────── */

    /* Call when an ACK reports a delivery batch.
     *
     *   delivered_bytes : bytes confirmed delivered in this ACK window
     *   interval_ns     : elapsed time over which those bytes were delivered
     *   rtt_ns          : round-trip time measured for this ACK
     *   now_ns          : monotonic timestamp of this event (CLOCK_MONOTONIC)
     */
    void on_ack(uint64_t delivered_bytes, uint64_t interval_ns,
                uint64_t rtt_ns, uint64_t now_ns) {
        if (interval_ns == 0)
            return;

        /* Delivery rate sample in bits-per-second */
        const double rate_bps =
            static_cast<double>(delivered_bytes) * 8.0e9 /
            static_cast<double>(interval_ns);

        bw_filter_.update(static_cast<uint64_t>(rate_bps), now_ns, kBwWindowNs);
        btl_bw_bps_ = bw_filter_.best();

        /* RTTProp: minimum RTT, refreshed once per window */
        if (rtt_ns < rtt_prop_ns_ ||
            (rtt_prop_stamp_ > 0 && now_ns - rtt_prop_stamp_ > kRttWindowNs)) {
            rtt_prop_ns_    = rtt_ns;
            rtt_prop_stamp_ = now_ns;
        }

        /* SRTT / RTTVAR per RFC 6298 §2.3 */
        if (srtt_ns_ == 0) {
            srtt_ns_   = rtt_ns;
            rttvar_ns_ = rtt_ns / 2;
        } else {
            const uint64_t dev = (rtt_ns > srtt_ns_)
                                 ? (rtt_ns - srtt_ns_)
                                 : (srtt_ns_ - rtt_ns);
            rttvar_ns_ = (3 * rttvar_ns_ + dev) / 4;   /* β = 1/4 */
            srtt_ns_   = (7 * srtt_ns_ + rtt_ns)  / 8; /* α = 1/8 */
        }

        total_delivered_ += delivered_bytes;
    }

    /* Call on packet loss detection. */
    void on_loss(uint64_t lost_bytes) {
        total_lost_ += lost_bytes;
    }

    /* ── Derived metrics ───────────────────────────────────────────────── */

    /* Estimated bottleneck bandwidth (bits/second). 0 if no samples yet. */
    uint64_t bandwidth_bps() const { return btl_bw_bps_; }

    /* Minimum observed RTT in nanoseconds (propagation delay floor). */
    uint64_t rtt_prop_ns() const { return rtt_prop_ns_; }

    /* Smoothed RTT (RFC 6298 SRTT), nanoseconds. */
    uint64_t srtt_ns() const { return srtt_ns_; }

    /* RTT variance (RFC 6298 RTTVAR), nanoseconds. */
    uint64_t rttvar_ns() const { return rttvar_ns_; }

    /* Retransmission timeout: max(SRTT + 4·RTTVAR, 1s) in nanoseconds. */
    uint64_t rto_ns() const {
        if (srtt_ns_ == 0)
            return 1'000'000'000ULL; /* 1 s initial RTO */
        const uint64_t rto = srtt_ns_ + 4 * rttvar_ns_;
        return (rto > 1'000'000'000ULL) ? rto : 1'000'000'000ULL;
    }

    /* Recommended send pacing rate in bps (BtlBw × pacing_gain). */
    uint64_t pacing_rate_bps() const {
        return static_cast<uint64_t>(
            static_cast<double>(btl_bw_bps_) * kPacingGain);
    }

    /* Recommended in-flight cap in bytes: BtlBw_bps × RTTProp_s × cwnd_gain. */
    uint64_t inflight_cap_bytes() const {
        if (btl_bw_bps_ == 0 || rtt_prop_ns_ == std::numeric_limits<uint64_t>::max())
            return 0;
        const double bw_Bps = static_cast<double>(btl_bw_bps_) / 8.0;
        const double rtt_s  = static_cast<double>(rtt_prop_ns_) / 1e9;
        return static_cast<uint64_t>(bw_Bps * rtt_s * kCwndGain);
    }

    /* Packet loss ratio in [0.0, 1.0]. */
    double loss_ratio() const {
        const uint64_t total = total_delivered_ + total_lost_;
        if (total == 0)
            return 0.0;
        return static_cast<double>(total_lost_) / static_cast<double>(total);
    }

    /* True when loss ratio exceeds threshold_pct percent (default 0.5%). */
    bool is_congested(double threshold_pct = 0.5) const {
        return loss_ratio() * 100.0 > threshold_pct;
    }

    /* ── State management ──────────────────────────────────────────────── */

    /* Reset all state (e.g., after a rekey / path change). */
    void reset() {
        bw_filter_.reset();
        btl_bw_bps_      = 0;
        rtt_prop_ns_     = std::numeric_limits<uint64_t>::max();
        rtt_prop_stamp_  = 0;
        srtt_ns_         = 0;
        rttvar_ns_       = 0;
        total_delivered_ = 0;
        total_lost_      = 0;
    }

    bool has_samples() const { return !bw_filter_.empty(); }

private:
    WindowedMaxFilter<uint64_t> bw_filter_;

    uint64_t btl_bw_bps_     = 0;
    uint64_t rtt_prop_ns_    = std::numeric_limits<uint64_t>::max();
    uint64_t rtt_prop_stamp_ = 0;
    uint64_t srtt_ns_        = 0;
    uint64_t rttvar_ns_      = 0;
    uint64_t total_delivered_ = 0;
    uint64_t total_lost_      = 0;
};

} /* namespace tachyon */
