/* SPDX-License-Identifier: MIT */
#include <gtest/gtest.h>
#include "rate_limiter.h"

using namespace tachyon::rl;

TEST(RateLimiter, UnlimitedAlwaysAllows) {
    TokenBucket b;
    bucket_init(b, 0, 0, 0); /* rate 0 → unlimited */
    EXPECT_TRUE(bucket_allow(b, 1'000'000, 0));
    EXPECT_TRUE(bucket_allow(b, 1'000'000, 0));
    EXPECT_EQ(bucket_tokens(b, 0), UINT64_MAX);
}

TEST(RateLimiter, InitialBurstFull) {
    TokenBucket b;
    bucket_init(b, 1000, 5000, 0);
    EXPECT_EQ(bucket_tokens(b, 0), 5000u);
}

TEST(RateLimiter, ConsumeReducesTokens) {
    TokenBucket b;
    bucket_init(b, 1000, 1000, 0);
    EXPECT_TRUE(bucket_allow(b, 400, 0));
    EXPECT_EQ(bucket_tokens(b, 0), 600u);
}

TEST(RateLimiter, DeniesWhenDepleted) {
    TokenBucket b;
    bucket_init(b, 100, 100, 0);
    EXPECT_TRUE(bucket_allow(b, 100, 0));
    EXPECT_FALSE(bucket_allow(b, 1, 0)); /* depleted */
}

TEST(RateLimiter, RefillsOverTime) {
    TokenBucket b;
    bucket_init(b, 1000, 1000, 0);
    EXPECT_TRUE(bucket_allow(b, 1000, 0)); /* drain */
    EXPECT_FALSE(bucket_allow(b, 1, 0));
    /* Advance 500ms → refill 500 tokens */
    EXPECT_TRUE(bucket_allow(b, 500, 500'000'000ULL));
    /* But not 501 total more */
    EXPECT_FALSE(bucket_allow(b, 1, 500'000'000ULL));
}

TEST(RateLimiter, RefillCapsAtBurst) {
    TokenBucket b;
    bucket_init(b, 1000, 500, 0);
    EXPECT_TRUE(bucket_allow(b, 500, 0)); /* drain */
    /* Advance 10 seconds → would add 10000 but burst caps at 500 */
    EXPECT_EQ(bucket_tokens(b, 10'000'000'000ULL), 500u);
}

TEST(RateLimiter, SetRateLive) {
    TokenBucket b;
    bucket_init(b, 1000, 1000, 0);
    EXPECT_TRUE(bucket_allow(b, 800, 0));
    /* Reconfigure to higher rate, keeping remaining tokens */
    bucket_set_rate(b, 2000, 2000, 0);
    EXPECT_EQ(bucket_tokens(b, 0), 200u);
    /* After 1s at new rate → 200 + 2000 = 2000 (capped at burst) */
    EXPECT_EQ(bucket_tokens(b, 1'000'000'000ULL), 2000u);
}

TEST(RateLimiter, ResetFillsBurst) {
    TokenBucket b;
    bucket_init(b, 1000, 1000, 0);
    EXPECT_TRUE(bucket_allow(b, 1000, 0));
    bucket_reset(b, 0);
    EXPECT_EQ(bucket_tokens(b, 0), 1000u);
}

TEST(RateLimiter, DefaultBurstEqualsRate) {
    TokenBucket b;
    bucket_init(b, 5000, 0, 0); /* burst=0 defaults to rate */
    EXPECT_EQ(b.burst, 5000u);
}

TEST(RateLimiter, LargeElapsedNoOverflow) {
    /* 100 Gbps for 100 seconds should not overflow uint64 */
    TokenBucket b;
    const uint64_t rate = 12'500'000'000ULL; /* 100 Gbps in bytes */
    bucket_init(b, rate, rate, 0);
    EXPECT_TRUE(bucket_allow(b, rate, 0)); /* drain */
    EXPECT_TRUE(bucket_allow(b, rate, 1'000'000'000ULL)); /* 1s refill */
}
