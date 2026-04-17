/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for loader/transcript — incremental SHA-384 transcript.
 *
 * Coverage:
 *   - Empty transcript (label only) is deterministic
 *   - Absorbing different bytes yields different digests
 *   - Absorb framing prevents "ab"+"c" == "a"+"bc" collision
 *   - snapshot() doesn't consume; finalize() does
 *   - clone() produces an independent state
 *   - Different labels yield different base digests
 *   - Move semantics preserve state
 */

#include <gtest/gtest.h>
#include "transcript.h"

#include <cstring>

using namespace tachyon::transcript;

namespace {
bool digests_equal(const uint8_t a[DIGEST_LEN], const uint8_t b[DIGEST_LEN]) {
    return std::memcmp(a, b, DIGEST_LEN) == 0;
}
} /* namespace */

TEST(Transcript, LabelOnlyIsDeterministic) {
    uint8_t d1[DIGEST_LEN], d2[DIGEST_LEN];
    {
        Transcript t("tch5-test");
        ASSERT_TRUE(t.valid());
        ASSERT_TRUE(t.finalize(d1));
    }
    {
        Transcript t("tch5-test");
        ASSERT_TRUE(t.finalize(d2));
    }
    EXPECT_TRUE(digests_equal(d1, d2));
}

TEST(Transcript, DifferentLabelsDiffer) {
    uint8_t d1[DIGEST_LEN], d2[DIGEST_LEN];
    Transcript a("alpha");
    Transcript b("beta");
    ASSERT_TRUE(a.finalize(d1));
    ASSERT_TRUE(b.finalize(d2));
    EXPECT_FALSE(digests_equal(d1, d2));
}

TEST(Transcript, FramingPreventsCollision) {
    /* Without length framing, ("ab","c") and ("a","bc") would hash the
     * same payload. With framing they must differ. */
    uint8_t d1[DIGEST_LEN], d2[DIGEST_LEN];
    Transcript a("L");
    ASSERT_TRUE(a.absorb("ab", 2));
    ASSERT_TRUE(a.absorb("c", 1));
    ASSERT_TRUE(a.finalize(d1));

    Transcript b("L");
    ASSERT_TRUE(b.absorb("a", 1));
    ASSERT_TRUE(b.absorb("bc", 2));
    ASSERT_TRUE(b.finalize(d2));
    EXPECT_FALSE(digests_equal(d1, d2));
}

TEST(Transcript, SnapshotDoesNotConsume) {
    Transcript t("label");
    ASSERT_TRUE(t.absorb("hello", 5));
    uint8_t snap1[DIGEST_LEN], snap2[DIGEST_LEN];
    ASSERT_TRUE(t.snapshot(snap1));
    ASSERT_TRUE(t.snapshot(snap2));
    EXPECT_TRUE(digests_equal(snap1, snap2));
    /* Can continue absorbing after snapshot */
    ASSERT_TRUE(t.absorb("world", 5));
    uint8_t snap3[DIGEST_LEN];
    ASSERT_TRUE(t.snapshot(snap3));
    EXPECT_FALSE(digests_equal(snap1, snap3));
}

TEST(Transcript, FinalizeInvalidatesContext) {
    Transcript t("label");
    uint8_t d[DIGEST_LEN];
    ASSERT_TRUE(t.finalize(d));
    EXPECT_FALSE(t.valid());
    EXPECT_FALSE(t.absorb("x", 1));
    EXPECT_FALSE(t.finalize(d));
}

TEST(Transcript, CloneIsIndependent) {
    Transcript t("label");
    ASSERT_TRUE(t.absorb("shared", 6));
    Transcript branch = t.clone();
    ASSERT_TRUE(branch.valid());

    /* Diverge: each absorbs different data */
    ASSERT_TRUE(t.absorb("A", 1));
    ASSERT_TRUE(branch.absorb("B", 1));
    uint8_t dt[DIGEST_LEN], db[DIGEST_LEN];
    ASSERT_TRUE(t.finalize(dt));
    ASSERT_TRUE(branch.finalize(db));
    EXPECT_FALSE(digests_equal(dt, db));
}

TEST(Transcript, EmptyAbsorbStillCounts) {
    /* absorb("", 0) writes the 4-byte zero length prefix only, which is
     * still a distinguishing input. */
    uint8_t d0[DIGEST_LEN], d1[DIGEST_LEN];
    Transcript a("L");
    ASSERT_TRUE(a.finalize(d0));
    Transcript b("L");
    ASSERT_TRUE(b.absorb(nullptr, 0));
    ASSERT_TRUE(b.finalize(d1));
    EXPECT_FALSE(digests_equal(d0, d1));
}

TEST(Transcript, MovePreservesState) {
    Transcript t("label");
    ASSERT_TRUE(t.absorb("payload", 7));
    uint8_t d_before[DIGEST_LEN], d_after[DIGEST_LEN];
    ASSERT_TRUE(t.snapshot(d_before));
    Transcript moved(std::move(t));
    EXPECT_FALSE(t.valid());
    ASSERT_TRUE(moved.snapshot(d_after));
    EXPECT_TRUE(digests_equal(d_before, d_after));
}
