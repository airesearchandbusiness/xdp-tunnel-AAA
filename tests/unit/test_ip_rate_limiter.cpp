/* SPDX-License-Identifier: MIT */
#include "ip_rate_limiter.h"

#include <gtest/gtest.h>

using tachyon::rl::IpRateLimiter;
using Verdict = IpRateLimiter::Verdict;

class IpRateLimiterTest : public ::testing::Test {
  protected:
    // Small thresholds for easier testing.
    // fail_threshold=3, block_threshold=10, window=60s
    IpRateLimiter limiter{4096, 3, 10, 60};
    static constexpr uint32_t kIP1 = 0x0A000001; // 10.0.0.1
    static constexpr uint32_t kIP2 = 0x0A000002; // 10.0.0.2
};

// Test 1: Fresh IP returns ALLOW
TEST_F(IpRateLimiterTest, FreshIpReturnsAllow) {
    EXPECT_EQ(limiter.check(kIP1, 100), Verdict::ALLOW);
    EXPECT_EQ(limiter.size(), 0u);
}

// Test 2: Under-threshold failures return ALLOW
TEST_F(IpRateLimiterTest, UnderThresholdFailuresReturnAllow) {
    limiter.record_failure(kIP1, 100);
    limiter.record_failure(kIP1, 101);
    // 2 failures, threshold is 3 -- should still ALLOW
    EXPECT_EQ(limiter.check(kIP1, 102), Verdict::ALLOW);
}

// Test 3: At-threshold triggers BACKOFF
TEST_F(IpRateLimiterTest, AtThresholdTriggersBackoff) {
    limiter.record_failure(kIP1, 100);
    limiter.record_failure(kIP1, 101);
    limiter.record_failure(kIP1, 102);
    // 3 failures == fail_threshold, backoff_until = 102 + 2^(3-3)*2 = 102 + 2 = 104
    EXPECT_EQ(limiter.check(kIP1, 103), Verdict::BACKOFF);
}

// Test 4: BACKOFF expires and returns ALLOW
TEST_F(IpRateLimiterTest, BackoffExpiresReturnsAllow) {
    limiter.record_failure(kIP1, 100);
    limiter.record_failure(kIP1, 101);
    limiter.record_failure(kIP1, 102);
    // backoff_until = 104 (base=2, exponent=0 -> 2s backoff from t=102)
    EXPECT_EQ(limiter.check(kIP1, 103), Verdict::BACKOFF);
    // At t=104, backoff has expired (now >= backoff_until)
    EXPECT_EQ(limiter.check(kIP1, 104), Verdict::ALLOW);
}

// Test 5: Above block_threshold returns BLOCK
TEST_F(IpRateLimiterTest, AboveBlockThresholdReturnsBlock) {
    for (uint32_t i = 0; i < 10; ++i)
        limiter.record_failure(kIP1, 100 + i);
    // 10 failures == block_threshold
    EXPECT_EQ(limiter.check(kIP1, 110), Verdict::BLOCK);
}

// Test 6: BLOCK within window, ALLOW after window expires
TEST_F(IpRateLimiterTest, BlockExpiresAfterWindow) {
    for (uint32_t i = 0; i < 10; ++i)
        limiter.record_failure(kIP1, 100 + i);
    EXPECT_EQ(limiter.check(kIP1, 150), Verdict::BLOCK);
    // After window (60s from first_failure_ts=100 -> 161)
    EXPECT_EQ(limiter.check(kIP1, 161), Verdict::ALLOW);
    // Entry should be cleaned up
    EXPECT_EQ(limiter.size(), 0u);
}

// Test 7: record_success clears entry
TEST_F(IpRateLimiterTest, RecordSuccessClearsEntry) {
    limiter.record_failure(kIP1, 100);
    limiter.record_failure(kIP1, 101);
    limiter.record_failure(kIP1, 102);
    EXPECT_EQ(limiter.check(kIP1, 103), Verdict::BACKOFF);
    EXPECT_EQ(limiter.size(), 1u);

    limiter.record_success(kIP1);
    EXPECT_EQ(limiter.size(), 0u);
    EXPECT_EQ(limiter.check(kIP1, 103), Verdict::ALLOW);
}

// Test 8: LRU eviction at max_entries
TEST_F(IpRateLimiterTest, LruEvictionAtMaxEntries) {
    IpRateLimiter small_limiter{4, 3, 10, 60};

    // Fill with 4 IPs
    for (uint32_t i = 1; i <= 4; ++i)
        small_limiter.record_failure(i, 100);
    EXPECT_EQ(small_limiter.size(), 4u);

    // Adding a 5th should evict the oldest (IP=1, which was the first inserted
    // and thus at the back of the LRU list)
    small_limiter.record_failure(5, 101);
    EXPECT_EQ(small_limiter.size(), 4u);

    // The evicted IP should have no entry
    EXPECT_EQ(small_limiter.check(1, 101), Verdict::ALLOW);
}

// Test 9: Exponential backoff grows with repeated failures
TEST_F(IpRateLimiterTest, ExponentialBackoffGrows) {
    // 3 failures: backoff = 2 * 2^0 = 2s
    limiter.record_failure(kIP1, 100);
    limiter.record_failure(kIP1, 100);
    limiter.record_failure(kIP1, 100);
    EXPECT_EQ(limiter.check(kIP1, 101), Verdict::BACKOFF);
    EXPECT_EQ(limiter.check(kIP1, 102), Verdict::ALLOW);

    // 4th failure: backoff = 2 * 2^1 = 4s from t=103
    limiter.record_failure(kIP1, 103);
    EXPECT_EQ(limiter.check(kIP1, 106), Verdict::BACKOFF);
    EXPECT_EQ(limiter.check(kIP1, 107), Verdict::ALLOW);
}

// Test 10: Multiple IPs are independent
TEST_F(IpRateLimiterTest, MultipleIpsAreIndependent) {
    limiter.record_failure(kIP1, 100);
    limiter.record_failure(kIP1, 101);
    limiter.record_failure(kIP1, 102);

    // IP1 is in BACKOFF, IP2 should be fresh
    EXPECT_EQ(limiter.check(kIP1, 103), Verdict::BACKOFF);
    EXPECT_EQ(limiter.check(kIP2, 103), Verdict::ALLOW);
}
