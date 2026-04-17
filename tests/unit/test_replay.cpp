/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for loader/replay — userspace sliding-window replay detector.
 *
 * Coverage:
 *   - First-seen sequence is ACCEPTED
 *   - Duplicate sequences are REPLAY
 *   - Sequences older than width are STALE
 *   - Sequences within the window in arbitrary order are all ACCEPTED
 *   - Window advances correctly on new highest
 *   - reset() clears all state
 *   - peek() is pure — does not mutate
 *   - Stats counters increment as expected
 */

#include <gtest/gtest.h>
#include "replay.h"

using namespace tachyon::replay;

TEST(Replay, FirstSeqAccepted) {
    Window w(256);
    EXPECT_EQ(w.check_and_commit(1), Result::ACCEPTED);
    EXPECT_EQ(w.highest(), 1u);
    EXPECT_EQ(w.accepted(), 1u);
}

TEST(Replay, DuplicateIsReplay) {
    Window w(256);
    ASSERT_EQ(w.check_and_commit(42), Result::ACCEPTED);
    EXPECT_EQ(w.check_and_commit(42), Result::REPLAY);
    EXPECT_EQ(w.replays(), 1u);
}

TEST(Replay, InOrderBurstAllAccepted) {
    Window w(256);
    for (uint64_t i = 1; i <= 100; ++i)
        EXPECT_EQ(w.check_and_commit(i), Result::ACCEPTED) << "seq=" << i;
    EXPECT_EQ(w.highest(), 100u);
    EXPECT_EQ(w.accepted(), 100u);
}

TEST(Replay, ReorderedWithinWindowAccepted) {
    Window w(256);
    /* Advance to highest=200 first, then arrival order: 150, 100, 199. */
    ASSERT_EQ(w.check_and_commit(200), Result::ACCEPTED);
    EXPECT_EQ(w.check_and_commit(150), Result::ACCEPTED);
    EXPECT_EQ(w.check_and_commit(100), Result::ACCEPTED);
    EXPECT_EQ(w.check_and_commit(199), Result::ACCEPTED);
    /* Duplicate of a reordered arrival: */
    EXPECT_EQ(w.check_and_commit(150), Result::REPLAY);
}

TEST(Replay, StaleBelowWindow) {
    Window w(64);
    ASSERT_EQ(w.check_and_commit(1000), Result::ACCEPTED);
    /* Anything ≤ 1000 - 64 = 936 is stale */
    EXPECT_EQ(w.check_and_commit(100), Result::STALE);
    EXPECT_EQ(w.check_and_commit(936), Result::STALE);
    EXPECT_EQ(w.check_and_commit(937), Result::ACCEPTED);
    EXPECT_EQ(w.stale(), 2u);
}

TEST(Replay, WindowShiftClearsStaleBits) {
    /* With width=64, hitting seq 1 then 1000 should lose the memory of 1.
     * A second commit of 1 therefore returns STALE, not REPLAY. */
    Window w(64);
    ASSERT_EQ(w.check_and_commit(1), Result::ACCEPTED);
    ASSERT_EQ(w.check_and_commit(1000), Result::ACCEPTED);
    EXPECT_EQ(w.check_and_commit(1), Result::STALE);
}

TEST(Replay, BigJumpClearsEntireWindow) {
    Window w(128);
    ASSERT_EQ(w.check_and_commit(1), Result::ACCEPTED);
    ASSERT_EQ(w.check_and_commit(2), Result::ACCEPTED);
    ASSERT_EQ(w.check_and_commit(3), Result::ACCEPTED);
    /* Jump past the whole window; 1,2,3 should be forgotten */
    ASSERT_EQ(w.check_and_commit(1'000'000), Result::ACCEPTED);
    EXPECT_EQ(w.check_and_commit(1), Result::STALE);
    EXPECT_EQ(w.check_and_commit(2), Result::STALE);
}

TEST(Replay, PeekDoesNotMutate) {
    Window w(256);
    ASSERT_EQ(w.check_and_commit(50), Result::ACCEPTED);
    EXPECT_EQ(w.peek(50), Result::REPLAY);
    EXPECT_EQ(w.peek(99), Result::ACCEPTED);
    /* After peek, a commit for 99 still works */
    EXPECT_EQ(w.check_and_commit(99), Result::ACCEPTED);
    EXPECT_EQ(w.check_and_commit(99), Result::REPLAY);
}

TEST(Replay, ResetClearsState) {
    Window w(128);
    ASSERT_EQ(w.check_and_commit(100), Result::ACCEPTED);
    w.reset();
    EXPECT_EQ(w.highest(), 0u);
    EXPECT_EQ(w.check_and_commit(100), Result::ACCEPTED);
}

TEST(Replay, WidthClampedAndAligned) {
    /* Non-multiple-of-64 widths clamp down; out-of-range clamps in. */
    Window a(63);     /* rounds to 64 */
    Window b(100);    /* rounds to 64 */
    Window c(200'000); /* clamps to 65536 */
    EXPECT_EQ(a.width(), 64u);
    EXPECT_EQ(b.width(), 64u);
    EXPECT_EQ(c.width(), 65536u);
}

TEST(Replay, StatsCountersAccumulate) {
    Window w(128);
    ASSERT_EQ(w.check_and_commit(10), Result::ACCEPTED);
    ASSERT_EQ(w.check_and_commit(20), Result::ACCEPTED);
    ASSERT_EQ(w.check_and_commit(10), Result::REPLAY);
    ASSERT_EQ(w.check_and_commit(20), Result::REPLAY);
    EXPECT_EQ(w.accepted(), 2u);
    EXPECT_EQ(w.replays(),  2u);
    EXPECT_EQ(w.stale(),    0u);
}
