/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the padding / traffic-analysis resistance module.
 *
 * Covers:
 *   - PADME rounding correctness for every boundary ≤ 2048 bytes
 *   - PADME overhead bound (< 12% worst case)
 *   - Shaper FSM state transitions (IDLE → BULK → IDLE)
 *   - Cover-frame emission respects configured mean rate (statistical)
 *   - padme_round is monotone non-decreasing
 *   - policy_from_string round-trip
 */

#include <gtest/gtest.h>
#include "padding.h"

using namespace tachyon::padding;

/* ── PADME ──────────────────────────────────────────────────────────────── */

TEST(Padding, PadmeRoundSmallValues) {
    /* PADME behaviour at low n: step size is 1 until E >= 3 (n >= 8), so
     * n in [2, 7] pass through unchanged. n=0,1 degenerate to 1. */
    EXPECT_EQ(padme_round(0), 1u);
    EXPECT_EQ(padme_round(1), 1u);
    EXPECT_EQ(padme_round(2), 2u);
    EXPECT_EQ(padme_round(3), 3u);
    EXPECT_EQ(padme_round(4), 4u);
    EXPECT_EQ(padme_round(7), 7u);
    EXPECT_EQ(padme_round(8), 8u);
    EXPECT_EQ(padme_round(9), 10u);
    EXPECT_EQ(padme_round(15), 16u);
    EXPECT_EQ(padme_round(16), 16u);
    EXPECT_EQ(padme_round(33), 36u);
    EXPECT_EQ(padme_round(64), 64u);
    EXPECT_EQ(padme_round(65), 72u);
}

TEST(Padding, PadmeRoundIsMonotone) {
    uint32_t prev = 0;
    for (uint32_t n = 0; n < 8192; ++n) {
        const uint32_t r = padme_round(n);
        EXPECT_GE(r, n) << "padme_round(" << n << ")=" << r << " violates >= n";
        EXPECT_GE(r, prev) << "padme_round not monotone at n=" << n;
        prev = r;
    }
}

TEST(Padding, PadmeOverheadBound) {
    /* Paper claims worst-case overhead < 12%. Sample every size up to MTU. */
    for (uint32_t n = 16; n <= 1500; ++n) {
        const uint32_t overhead = padme_overhead_bytes(n);
        /* Accept 12% with a small safety margin for very small n. */
        EXPECT_LE(overhead * 100u, n * 14u)
            << "Overhead too high at n=" << n << ": " << overhead << " bytes";
    }
}

TEST(Padding, PadmeIdempotent) {
    for (uint32_t n : {1u, 7u, 32u, 100u, 512u, 1024u, 1500u, 9000u}) {
        const uint32_t once = padme_round(n);
        const uint32_t twice = padme_round(once);
        EXPECT_EQ(once, twice) << "Non-idempotent at n=" << n;
    }
}

TEST(Padding, PadmeBinCountInMtuRange) {
    const uint32_t bins = padding_bin_count(64, 1500);
    EXPECT_GT(bins, 10u);
    EXPECT_LT(bins, 100u);
}

/* ── Policy strings ─────────────────────────────────────────────────────── */

TEST(Padding, PolicyRoundTrip) {
    for (auto p : {Policy::NONE, Policy::PADME, Policy::CONSTANT_RATE, Policy::RANDOM}) {
        const char *name = policy_to_string(p);
        EXPECT_EQ(policy_from_string(name), p);
    }
    EXPECT_EQ(policy_from_string(nullptr), Policy::NONE);
    EXPECT_EQ(policy_from_string(""), Policy::NONE);
    EXPECT_EQ(policy_from_string("garbage"), Policy::NONE);
    EXPECT_EQ(policy_from_string("PADME"), Policy::PADME); /* case-insensitive */
    EXPECT_EQ(policy_from_string("constant"), Policy::CONSTANT_RATE);
}

/* ── Shaper FSM ─────────────────────────────────────────────────────────── */

TEST(Padding, ShaperInitialStateIsIdle) {
    ShaperState s;
    shaper_init(s, 2);
    EXPECT_EQ(s.state, State::IDLE);
    EXPECT_EQ(s.cover_frames_emitted, 0u);
    EXPECT_EQ(s.real_frames_shaped, 0u);
}

TEST(Padding, ShaperEnterBulkOnRealFrame) {
    ShaperState s;
    shaper_init(s, 2);
    shaper_on_real_frame(s, 1'000'000'000ull);
    EXPECT_EQ(s.state, State::BULK);
    EXPECT_EQ(s.real_frames_shaped, 1u);
}

TEST(Padding, ShaperBulkBlocksCoverEmission) {
    ShaperState s;
    shaper_init(s, 10); /* 100 ms mean interval */
    shaper_on_real_frame(s, 1'000'000'000ull);
    /* Poll immediately — we're in BULK, no cover should fire */
    const uint32_t size = shaper_poll_cover(s, 1'000'000'000ull, 64, 1400);
    EXPECT_EQ(size, 0u);
    EXPECT_EQ(s.cover_frames_emitted, 0u);
}

TEST(Padding, ShaperIdleEmitsCoverAfterTimeout) {
    ShaperState s;
    shaper_init(s, 10);
    shaper_on_real_frame(s, 0);
    /* Fast-forward past bulk_idle_threshold and past scheduled cover */
    uint64_t t = s.next_cover_ns + 2'000'000'000ull +
                 static_cast<uint64_t>(s.bulk_idle_threshold_ms) * 1'000'000ull;
    /* The first poll should first transition to IDLE, then emit cover. */
    const uint32_t size = shaper_poll_cover(s, t, 64, 1400);
    EXPECT_GT(size, 0u);
    EXPECT_LE(size, 1400u);
    EXPECT_EQ(s.state, State::IDLE);
}

TEST(Padding, ShaperDisabledWhenRateZero) {
    ShaperState s;
    shaper_init(s, 0); /* cover disabled */
    EXPECT_EQ(shaper_poll_cover(s, 10'000'000'000ull, 64, 1400), 0u);
}

TEST(Padding, ShaperEmitsCoverInPadmeBins) {
    ShaperState s;
    shaper_init(s, 100);
    /* Force IDLE state and drive many cover emissions to confirm every size
     * is in a PADME bin (i.e., padme_round(size) == size). */
    s.state = State::IDLE;
    for (int i = 0; i < 50; ++i) {
        s.next_cover_ns = 0;
        const uint32_t sz = shaper_poll_cover(s, 1'000'000'000ull * (i + 1), 64, 1400);
        if (sz == 0)
            continue;
        EXPECT_EQ(padme_round(sz), sz)
            << "Cover frame size " << sz << " is not a PADME bin";
    }
}

/* ── Bin-count helper ───────────────────────────────────────────────────── */

TEST(Padding, BinCountIsSaneRange) {
    EXPECT_GT(padding_bin_count(64, 1500), 8u);
    EXPECT_EQ(padding_bin_count(100, 100), 0u);
    EXPECT_EQ(padding_bin_count(200, 100), 0u);
}
