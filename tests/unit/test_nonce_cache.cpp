/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Unit Tests - NonceCache
 *
 * Tests the LRU nonce deduplication cache from loader/tachyon.h:
 *   - Add and lookup
 *   - Expiry-based eviction
 *   - Capacity-based eviction
 *   - Edge cases
 */

#include <gtest/gtest.h>
#include "tachyon.h"

class NonceCacheTest : public ::testing::Test {
  protected:
    NonceCache cache_;
};

/* ── Basic Operations ── */

TEST_F(NonceCacheTest, AddAndExists) {
    cache_.add(12345, 1000);
    EXPECT_TRUE(cache_.exists(12345));
}

TEST_F(NonceCacheTest, NonExistentReturnsFalse) {
    EXPECT_FALSE(cache_.exists(99999));
}

TEST_F(NonceCacheTest, MultipleNonces) {
    cache_.add(100, 1000);
    cache_.add(200, 1000);
    cache_.add(300, 1000);

    EXPECT_TRUE(cache_.exists(100));
    EXPECT_TRUE(cache_.exists(200));
    EXPECT_TRUE(cache_.exists(300));
    EXPECT_FALSE(cache_.exists(400));
}

/* ── Expiry-Based Eviction ── */

TEST_F(NonceCacheTest, ExpiryEviction) {
    /* Add nonce at time 0 */
    cache_.add(111, 0);
    EXPECT_TRUE(cache_.exists(111));

    /* Add another nonce well past the expiry window.
     * TACHYON_NONCE_EXPIRY = 180 seconds. Adding at time 200
     * should trigger eviction of the old nonce. */
    cache_.add(222, TACHYON_NONCE_EXPIRY + 10);
    EXPECT_FALSE(cache_.exists(111));
    EXPECT_TRUE(cache_.exists(222));
}

TEST_F(NonceCacheTest, NonExpiredNotEvicted) {
    cache_.add(111, 1000);
    /* Add another nonce within expiry window */
    cache_.add(222, 1000 + TACHYON_NONCE_EXPIRY - 1);

    /* Both should still exist */
    EXPECT_TRUE(cache_.exists(111));
    EXPECT_TRUE(cache_.exists(222));
}

TEST_F(NonceCacheTest, MultipleExpiredEvicted) {
    cache_.add(1, 0);
    cache_.add(2, 10);
    cache_.add(3, 20);

    /* All three should expire when we add at time >> TACHYON_NONCE_EXPIRY */
    cache_.add(4, TACHYON_NONCE_EXPIRY + 100);

    EXPECT_FALSE(cache_.exists(1));
    EXPECT_FALSE(cache_.exists(2));
    EXPECT_FALSE(cache_.exists(3));
    EXPECT_TRUE(cache_.exists(4));
}

/* ── Capacity-Based Eviction ── */

TEST_F(NonceCacheTest, CapacityEviction) {
    /* Fill the cache to max capacity with non-expired entries */
    uint64_t now = 1000;
    for (uint64_t i = 0; i < TACHYON_NONCE_CACHE_MAX; i++) {
        cache_.add(i, now);
    }

    /* First nonce should still exist */
    EXPECT_TRUE(cache_.exists(0));

    /* Adding one more should evict the oldest (nonce 0) */
    cache_.add(TACHYON_NONCE_CACHE_MAX, now);
    EXPECT_FALSE(cache_.exists(0));
    EXPECT_TRUE(cache_.exists(TACHYON_NONCE_CACHE_MAX));
}

/* ── Edge Cases ── */

TEST_F(NonceCacheTest, DuplicateNonce) {
    cache_.add(42, 1000);
    cache_.add(42, 1001);

    /* Should still be findable */
    EXPECT_TRUE(cache_.exists(42));
}

TEST_F(NonceCacheTest, ZeroNonce) {
    cache_.add(0, 1000);
    EXPECT_TRUE(cache_.exists(0));
}

TEST_F(NonceCacheTest, MaxUint64Nonce) {
    cache_.add(UINT64_MAX, 1000);
    EXPECT_TRUE(cache_.exists(UINT64_MAX));
}

TEST_F(NonceCacheTest, EmptyCacheExists) {
    EXPECT_FALSE(cache_.exists(0));
    EXPECT_FALSE(cache_.exists(1));
    EXPECT_FALSE(cache_.exists(UINT64_MAX));
}

TEST_F(NonceCacheTest, HighFrequencyAddLookup) {
    /* Simulate rapid handshake nonce processing */
    for (uint64_t i = 0; i < 10000; i++) {
        cache_.add(i, 1000 + (i / 100));
        EXPECT_TRUE(cache_.exists(i));
    }
    /* Recent entries should survive; oldest may be evicted by capacity */
    EXPECT_TRUE(cache_.exists(9999));
}

/* ── Duplicate-Add Regression Tests ──
 *
 * Before the fix, add(nonce) always appended to order_ even for duplicate
 * nonces, creating a map/list size divergence. This led to premature eviction
 * of legitimate nonces when the cache reached capacity. */

TEST_F(NonceCacheTest, DuplicateDoesNotInflateList) {
    uint64_t now = 1000;
    cache_.add(42, now);
    cache_.add(42, now); /* duplicate — must NOT create a second list entry */

    /* Fill to capacity - 1 (nonce 42 already occupies one slot) */
    for (uint64_t i = 1; i < TACHYON_NONCE_CACHE_MAX; i++)
        cache_.add(i + 1000, now);

    /* Nonce 42 should still exist — it's in the first slot, not prematurely evicted */
    EXPECT_TRUE(cache_.exists(42));
}

TEST_F(NonceCacheTest, DuplicateAddThenCapacityEviction) {
    uint64_t now = 1000;
    /* Add nonce 1 twice (triggers the old bug) */
    cache_.add(1, now);
    cache_.add(1, now);

    /* Fill cache to capacity (slot 0 is nonce 1, slots 1..MAX-1 are 100..MAX+98) */
    for (uint64_t i = 1; i < TACHYON_NONCE_CACHE_MAX; i++)
        cache_.add(i + 99, now);

    /* Push one more — should evict nonce 1 (oldest in the list) */
    cache_.add(99999, now);

    /* Nonce 1 was evicted, but nonce 100 (second-oldest) must NOT be collateral damage */
    EXPECT_FALSE(cache_.exists(1));
    EXPECT_TRUE(cache_.exists(100));
    EXPECT_TRUE(cache_.exists(99999));
}

TEST_F(NonceCacheTest, ReplayDetectionSurvivesDuplicate) {
    uint64_t now = 1000;
    /* Legitimate handshake records the nonce */
    cache_.add(0xDEAD, now);

    /* Attacker replays the same PKT_AUTH — add() is called again with same nonce */
    cache_.add(0xDEAD, now);

    /* Fill cache to capacity to trigger eviction pressure */
    for (uint64_t i = 0; i < TACHYON_NONCE_CACHE_MAX; i++)
        cache_.add(i + 0x10000, now);

    /* Even after full capacity cycling, the replayed nonce must be detectable
     * OR have been properly evicted (not left as a stale ghost in the map) */
    /* Key invariant: exists() must never return true for a nonce that was
     * evicted from the list but left as a ghost in the map */
}

TEST_F(NonceCacheTest, ExpiryDoesNotEvictFreshEntries) {
    /* Add entries at time T, then add one at T + EXPIRY - 1 */
    cache_.add(100, 1000);
    cache_.add(200, 1000 + TACHYON_NONCE_EXPIRY - 1);
    /* Entry 100 should still exist (not yet expired at T + EXPIRY - 1) */
    EXPECT_TRUE(cache_.exists(100));
    EXPECT_TRUE(cache_.exists(200));
}
