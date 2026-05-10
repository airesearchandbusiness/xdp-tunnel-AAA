/* SPDX-License-Identifier: MIT */
#pragma once
#include "bandwidth_estimator.h"
#include "metrics.h"

#include <cstdint>

namespace tachyon {

struct TunnelStats {
    uint64_t tx_bytes = 0;
    uint64_t rx_bytes = 0;
    uint64_t cover_frames = 0;
    uint64_t replay_drops = 0;
    double loss_ratio = 0.0;

    static TunnelStats from_metrics() {
        auto s = metrics::snapshot();
        TunnelStats ts;
        ts.tx_bytes = s.tx_bytes;
        ts.rx_bytes = s.rx_bytes;
        ts.cover_frames = s.cover_frames_sent;
        ts.replay_drops = s.replay_dropped;
        return ts;
    }
};

class AdaptiveObfsController {
  public:
    explicit AdaptiveObfsController(uint8_t initial_flags) : flags_(initial_flags) {}

    uint8_t update(const TunnelStats &stats) {
        if (stats.replay_drops > last_replay_drops_ + 100)
            flags_ |= 0x01;
        last_replay_drops_ = stats.replay_drops;
        return flags_;
    }

    uint8_t flags() const { return flags_; }

  private:
    uint8_t flags_;
    uint64_t last_replay_drops_ = 0;
};

class SmartObfsController {
  public:
    SmartObfsController(uint8_t initial_flags, uint32_t initial_cover_hz)
        : obfs_(initial_flags), base_cover_hz_(initial_cover_hz),
          active_cover_hz_(initial_cover_hz) {}

    void on_ack(uint64_t delivered_bytes, uint64_t interval_ns, uint64_t rtt_ns, uint64_t now_ns) {
        bw_.on_ack(delivered_bytes, interval_ns, rtt_ns, now_ns);
    }
    void on_loss(uint64_t lost_bytes) { bw_.on_loss(lost_bytes); }

    uint8_t update(const TunnelStats &stats) {
        uint8_t flags = obfs_.update(stats);
        if (bw_.is_congested()) {
            active_cover_hz_ = base_cover_hz_ / 4;
        } else if (bw_.has_samples() && bw_.loss_ratio() < 0.001) {
            active_cover_hz_ = base_cover_hz_;
        }
        return flags;
    }

    uint32_t active_cover_hz() const { return active_cover_hz_; }
    uint64_t bandwidth_bps() const { return bw_.bandwidth_bps(); }

  private:
    AdaptiveObfsController obfs_;
    BandwidthEstimator bw_;
    uint32_t base_cover_hz_;
    uint32_t active_cover_hz_;
};

} /* namespace tachyon */
