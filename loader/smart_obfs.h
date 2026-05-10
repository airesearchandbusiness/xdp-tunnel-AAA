/* SPDX-License-Identifier: MIT */
#pragma once
#include "tachyon.h"
#include "bandwidth_estimator.h"

namespace tachyon {

class SmartObfsController {
public:
    SmartObfsController(uint8_t initial_flags, uint32_t initial_cover_hz)
        : obfs_(initial_flags), base_cover_hz_(initial_cover_hz),
          active_cover_hz_(initial_cover_hz) {}

    void on_ack(uint64_t delivered_bytes, uint64_t interval_ns,
                uint64_t rtt_ns, uint64_t now_ns) {
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
