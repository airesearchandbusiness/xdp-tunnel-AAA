/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for loader/ratchet — forward-secure key ratchet.
 *
 * Coverage:
 *   - Init with the same root twice produces the same first key
 *     (so two endpoints from the same root agree)
 *   - Successive calls produce distinct keys and nonce prefixes
 *   - Counter increments per call
 *   - wipe() scrubs the chain
 *   - ratchet_derive_at is pure and deterministic for a given counter
 *   - Derived secrets have cross-counter independence
 */

#include <gtest/gtest.h>
#include "ratchet.h"

#include <cstring>
#include <set>
#include <string>

using namespace tachyon::ratchet;

namespace {
uint8_t test_root[ROOT_KEY_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};
} /* namespace */

TEST(Ratchet, InitIsDeterministic) {
    SendState a, b;
    ratchet_init(a, test_root);
    ratchet_init(b, test_root);

    uint8_t ka[MSG_KEY_LEN], kb[MSG_KEY_LEN];
    uint8_t na[NONCE_PREFIX_LEN], nb[NONCE_PREFIX_LEN];
    uint64_t ca, cb;
    ASSERT_TRUE(ratchet_next(a, ka, na, &ca));
    ASSERT_TRUE(ratchet_next(b, kb, nb, &cb));
    EXPECT_EQ(std::memcmp(ka, kb, MSG_KEY_LEN), 0);
    EXPECT_EQ(std::memcmp(na, nb, NONCE_PREFIX_LEN), 0);
    EXPECT_EQ(ca, 0u);
    EXPECT_EQ(cb, 0u);
}

TEST(Ratchet, SuccessiveCallsProduceDistinctKeys) {
    SendState s;
    ratchet_init(s, test_root);
    std::set<std::string> seen;
    for (int i = 0; i < 64; ++i) {
        uint8_t k[MSG_KEY_LEN], n[NONCE_PREFIX_LEN];
        uint64_t c;
        ASSERT_TRUE(ratchet_next(s, k, n, &c));
        EXPECT_EQ(c, static_cast<uint64_t>(i));
        seen.insert(std::string(reinterpret_cast<const char *>(k), MSG_KEY_LEN));
    }
    EXPECT_EQ(seen.size(), 64u) << "Ratchet produced duplicate message keys";
}

TEST(Ratchet, CounterIncrements) {
    SendState s;
    ratchet_init(s, test_root);
    uint8_t k[MSG_KEY_LEN], n[NONCE_PREFIX_LEN];
    uint64_t c = 999;
    ASSERT_TRUE(ratchet_next(s, k, n, &c));
    EXPECT_EQ(c, 0u);
    EXPECT_EQ(s.counter, 1u);
    ASSERT_TRUE(ratchet_next(s, k, n, &c));
    EXPECT_EQ(c, 1u);
    EXPECT_EQ(s.counter, 2u);
}

TEST(Ratchet, WipeClearsChain) {
    SendState s;
    ratchet_init(s, test_root);
    uint8_t k[MSG_KEY_LEN], n[NONCE_PREFIX_LEN];
    uint64_t c;
    ASSERT_TRUE(ratchet_next(s, k, n, &c));
    ratchet_wipe(s);
    for (size_t i = 0; i < ROOT_KEY_LEN; ++i)
        EXPECT_EQ(s.chain_key[i], 0u);
    EXPECT_EQ(s.counter, 0u);
}

TEST(Ratchet, DeriveAtIsPureAndDeterministic) {
    uint8_t k1[MSG_KEY_LEN], n1[NONCE_PREFIX_LEN];
    uint8_t k2[MSG_KEY_LEN], n2[NONCE_PREFIX_LEN];
    ASSERT_TRUE(ratchet_derive_at(test_root, 42, k1, n1));
    ASSERT_TRUE(ratchet_derive_at(test_root, 42, k2, n2));
    EXPECT_EQ(std::memcmp(k1, k2, MSG_KEY_LEN), 0);
    EXPECT_EQ(std::memcmp(n1, n2, NONCE_PREFIX_LEN), 0);
}

TEST(Ratchet, DeriveAtCrossCounterIndependence) {
    std::set<std::string> keys;
    for (uint64_t i = 0; i < 128; ++i) {
        uint8_t k[MSG_KEY_LEN], n[NONCE_PREFIX_LEN];
        ASSERT_TRUE(ratchet_derive_at(test_root, i, k, n));
        keys.insert(std::string(reinterpret_cast<const char *>(k), MSG_KEY_LEN));
    }
    EXPECT_EQ(keys.size(), 128u);
}

TEST(Ratchet, DeriveAtDiffersFromRatchetNext) {
    /* The two schemes MUST NOT collide — different labels guarantee this. */
    SendState s;
    ratchet_init(s, test_root);
    uint8_t k_next[MSG_KEY_LEN], n_next[NONCE_PREFIX_LEN];
    uint64_t c;
    ASSERT_TRUE(ratchet_next(s, k_next, n_next, &c));

    uint8_t k_at[MSG_KEY_LEN], n_at[NONCE_PREFIX_LEN];
    ASSERT_TRUE(ratchet_derive_at(test_root, 0, k_at, n_at));

    EXPECT_NE(std::memcmp(k_next, k_at, MSG_KEY_LEN), 0);
}

TEST(Ratchet, NonceAndKeySplitCleanly) {
    /* Nonce prefix and key must come from different 32-byte spans — i.e.
     * they should not memcmp-equal each other. Sanity-check that
     * HKDF-Expand(44) split by the ratchet is non-degenerate. */
    uint8_t k[MSG_KEY_LEN], n[NONCE_PREFIX_LEN];
    ASSERT_TRUE(ratchet_derive_at(test_root, 7, k, n));
    EXPECT_NE(std::memcmp(k, n, NONCE_PREFIX_LEN), 0);
}
