/* SPDX-License-Identifier: MIT */
#include <gtest/gtest.h>
#include <cstring>

#include "tachyon.h"

TEST(X448Test, KeygenSucceeds) {
    uint8_t priv[56], pub[56];
    EXPECT_TRUE(generate_x448_keypair(priv, pub));
}

TEST(X448Test, ECDHRoundTrip) {
    uint8_t priv_a[56], pub_a[56], priv_b[56], pub_b[56];
    ASSERT_TRUE(generate_x448_keypair(priv_a, pub_a));
    ASSERT_TRUE(generate_x448_keypair(priv_b, pub_b));
    uint8_t ss_a[56], ss_b[56];
    ASSERT_TRUE(do_x448_ecdh(priv_a, pub_b, ss_a));
    ASSERT_TRUE(do_x448_ecdh(priv_b, pub_a, ss_b));
    EXPECT_EQ(memcmp(ss_a, ss_b, 56), 0);
}

TEST(X448Test, SharedSecretNonZero) {
    uint8_t priv[56], pub[56], ss[56];
    ASSERT_TRUE(generate_x448_keypair(priv, pub));
    ASSERT_TRUE(do_x448_ecdh(priv, pub, ss));
    uint8_t zero[56] = {0};
    EXPECT_NE(memcmp(ss, zero, 56), 0);
}

TEST(X448Test, KeyLenConstant) {
    EXPECT_EQ(TACHYON_X448_KEY_LEN, 56u);
}

TEST(X448Test, ConfigDefaultIsX25519) {
    TunnelConfig cfg;
    EXPECT_EQ(cfg.kex_type, TACHYON_KEX_X25519);
}
