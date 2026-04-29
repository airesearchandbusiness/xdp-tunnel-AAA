/* SPDX-License-Identifier: MIT */
#include <gtest/gtest.h>
#include "metrics.h"

using namespace tachyon::metrics;

class MetricsTest : public ::testing::Test {
  protected:
    void SetUp() override { reset(); }
};

TEST_F(MetricsTest, InitialCountersAreZero) {
    const auto s = snapshot();
    EXPECT_EQ(s.hs_initiated, 0u);
    EXPECT_EQ(s.tx_packets, 0u);
    EXPECT_EQ(s.replay_dropped, 0u);
    EXPECT_EQ(s.rl_tx_drops, 0u);
}

TEST_F(MetricsTest, IncrementAndSnapshot) {
    auto &c = global();
    c.hs_initiated.fetch_add(1, std::memory_order_relaxed);
    c.hs_initiated.fetch_add(1, std::memory_order_relaxed);
    c.tx_packets.fetch_add(100, std::memory_order_relaxed);
    c.tx_bytes.fetch_add(150000, std::memory_order_relaxed);

    const auto s = snapshot();
    EXPECT_EQ(s.hs_initiated, 2u);
    EXPECT_EQ(s.tx_packets, 100u);
    EXPECT_EQ(s.tx_bytes, 150000u);
}

TEST_F(MetricsTest, ResetClearsAll) {
    auto &c = global();
    c.hs_completed.fetch_add(5, std::memory_order_relaxed);
    c.replay_dropped.fetch_add(3, std::memory_order_relaxed);
    reset();
    const auto s = snapshot();
    EXPECT_EQ(s.hs_completed, 0u);
    EXPECT_EQ(s.replay_dropped, 0u);
}

TEST_F(MetricsTest, AllFieldsExercised) {
    auto &c = global();
    c.hs_failed.fetch_add(1);
    c.hs_rekeys.fetch_add(1);
    c.rx_packets.fetch_add(1);
    c.rx_bytes.fetch_add(1);
    c.replay_accepted.fetch_add(1);
    c.replay_stale.fetch_add(1);
    c.cover_frames_sent.fetch_add(1);
    c.padme_bytes_overhead.fetch_add(1);
    c.transport_wrap_ok.fetch_add(1);
    c.transport_wrap_fail.fetch_add(1);
    c.transport_unwrap_ok.fetch_add(1);
    c.transport_unwrap_fail.fetch_add(1);
    c.rl_rx_drops.fetch_add(1);

    const auto s = snapshot();
    EXPECT_EQ(s.hs_failed, 1u);
    EXPECT_EQ(s.hs_rekeys, 1u);
    EXPECT_EQ(s.rx_packets, 1u);
    EXPECT_EQ(s.replay_stale, 1u);
    EXPECT_EQ(s.cover_frames_sent, 1u);
    EXPECT_EQ(s.transport_wrap_ok, 1u);
    EXPECT_EQ(s.transport_unwrap_fail, 1u);
    EXPECT_EQ(s.rl_rx_drops, 1u);
}
