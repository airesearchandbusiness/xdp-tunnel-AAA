/* SPDX-License-Identifier: MIT */
#include <gtest/gtest.h>
#include "smart_obfs.h"

using namespace tachyon;

TEST(TunnelStatsTest, DefaultValuesAreZero) {
    TunnelStats ts;
    EXPECT_EQ(ts.tx_bytes, 0u);
    EXPECT_EQ(ts.rx_bytes, 0u);
    EXPECT_EQ(ts.cover_frames, 0u);
    EXPECT_EQ(ts.replay_drops, 0u);
    EXPECT_DOUBLE_EQ(ts.loss_ratio, 0.0);
}

TEST(TunnelStatsTest, FromMetricsSnapshot) {
    metrics::reset();
    metrics::global().tx_bytes.store(1000);
    metrics::global().rx_bytes.store(2000);
    metrics::global().cover_frames_sent.store(5);
    metrics::global().replay_dropped.store(3);
    auto ts = TunnelStats::from_metrics();
    EXPECT_EQ(ts.tx_bytes, 1000u);
    EXPECT_EQ(ts.rx_bytes, 2000u);
    EXPECT_EQ(ts.cover_frames, 5u);
    EXPECT_EQ(ts.replay_drops, 3u);
    metrics::reset();
}

TEST(AdaptiveObfsTest, InitialFlags) {
    AdaptiveObfsController ctrl(0x07);
    EXPECT_EQ(ctrl.flags(), 0x07);
}

TEST(AdaptiveObfsTest, EscalatesOnReplaySpike) {
    AdaptiveObfsController ctrl(0x00);
    TunnelStats ts;
    ts.replay_drops = 200;
    uint8_t flags = ctrl.update(ts);
    EXPECT_NE(flags & 0x01, 0);
}

TEST(SmartObfsTest, ConstructAndQuery) {
    SmartObfsController sc(0x07, 50);
    EXPECT_EQ(sc.active_cover_hz(), 50u);
    EXPECT_EQ(sc.bandwidth_bps(), 0u);
}

TEST(SmartObfsTest, CongestionReducesCoverRate) {
    SmartObfsController sc(0x07, 100);
    for (int i = 0; i < 20; ++i)
        sc.on_loss(1000);
    sc.on_ack(100, 1'000'000'000ULL, 50'000'000ULL, 1'000'000'000ULL);
    TunnelStats ts;
    sc.update(ts);
    EXPECT_LT(sc.active_cover_hz(), 100u);
}

TEST(SmartObfsTest, RecoveryRestoresCoverRate) {
    SmartObfsController sc(0x07, 100);
    sc.on_ack(10000, 1'000'000'000ULL, 10'000'000ULL, 1'000'000'000ULL);
    TunnelStats ts;
    sc.update(ts);
    EXPECT_EQ(sc.active_cover_hz(), 100u);
}

TEST(SmartObfsTest, BandwidthReporting) {
    SmartObfsController sc(0x07, 50);
    sc.on_ack(125000, 1'000'000'000ULL, 20'000'000ULL, 1'000'000'000ULL);
    EXPECT_GT(sc.bandwidth_bps(), 0u);
}
