/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for loader/hybrid_kex — X25519 ‖ ML-KEM-768 hybrid KEM.
 *
 * Every substantive test is skipped when no PQC backend is linked, so CI
 * on Ubuntu 24.04 (OpenSSL 3.0, no liboqs) stays green. The size-constant
 * tests always run because they check compile-time values.
 *
 * Coverage (when backend available):
 *   - keygen → encapsulate → decapsulate round trip yields matching
 *     48-byte shared secrets
 *   - Different context binds to different secrets
 *   - Tampering the X25519 ephemeral half changes the secret
 *   - Tampering the ML-KEM ciphertext half changes the secret
 *     (FIPS 203 §6.3 implicit rejection semantics)
 *   - Two encapsulations to the same pk produce different ciphertexts
 *     (ephemeral randomness)
 *
 * Always-on:
 *   - Struct size constants match the spec (32+1184, 32+2400, 32+1088, 48)
 *   - hybrid_available() returns the same bool as pqc_available()
 */

#include <gtest/gtest.h>
#include "hybrid_kex.h"
#include "pqc.h"

#include <cstring>

using namespace tachyon::hkex;

#define SKIP_IF_UNAVAILABLE()                              \
    do {                                                   \
        if (!hybrid_available())                           \
            GTEST_SKIP() << "Hybrid KEX unavailable: "     \
                         << tachyon::pqc::pqc_backend();   \
    } while (0)

TEST(HybridKex, SizeConstantsMatchSpec) {
    EXPECT_EQ(X25519_PK_LEN, 32u);
    EXPECT_EQ(X25519_SK_LEN, 32u);
    EXPECT_EQ(HYBRID_PK_LEN, 32u + 1184u);
    EXPECT_EQ(HYBRID_SK_LEN, 32u + 2400u);
    EXPECT_EQ(HYBRID_CT_LEN, 32u + 1088u);
    EXPECT_EQ(HYBRID_SS_LEN, 48u);
}

TEST(HybridKex, AvailabilityMatchesPqc) {
    EXPECT_EQ(hybrid_available(), tachyon::pqc::pqc_available());
}

TEST(HybridKex, RoundTrip) {
    SKIP_IF_UNAVAILABLE();
    uint8_t pk[HYBRID_PK_LEN], sk[HYBRID_SK_LEN];
    uint8_t ct[HYBRID_CT_LEN];
    uint8_t ss_send[HYBRID_SS_LEN], ss_recv[HYBRID_SS_LEN];

    ASSERT_TRUE(hybrid_keygen(pk, sk));
    const uint8_t ctx[] = "tch5-handshake-transcript";
    ASSERT_TRUE(hybrid_encapsulate(pk, ctx, sizeof(ctx), ct, ss_send));
    ASSERT_TRUE(hybrid_decapsulate(sk, ct, ctx, sizeof(ctx), ss_recv));
    EXPECT_EQ(std::memcmp(ss_send, ss_recv, HYBRID_SS_LEN), 0);
}

TEST(HybridKex, DifferentContextsDiverge) {
    SKIP_IF_UNAVAILABLE();
    uint8_t pk[HYBRID_PK_LEN], sk[HYBRID_SK_LEN];
    uint8_t ct[HYBRID_CT_LEN];
    uint8_t ss1[HYBRID_SS_LEN], ss2[HYBRID_SS_LEN];

    ASSERT_TRUE(hybrid_keygen(pk, sk));
    ASSERT_TRUE(hybrid_encapsulate(pk, reinterpret_cast<const uint8_t *>("ctxA"), 4, ct, ss1));
    /* Decaps with the WRONG context — must yield a different secret,
     * because the combiner bakes context into the HKDF salt. */
    ASSERT_TRUE(hybrid_decapsulate(sk, ct, reinterpret_cast<const uint8_t *>("ctxB"), 4, ss2));
    EXPECT_NE(std::memcmp(ss1, ss2, HYBRID_SS_LEN), 0);
}

TEST(HybridKex, EphemeralRandomnessProducesDifferentCiphertexts) {
    SKIP_IF_UNAVAILABLE();
    uint8_t pk[HYBRID_PK_LEN], sk[HYBRID_SK_LEN];
    uint8_t ct1[HYBRID_CT_LEN], ct2[HYBRID_CT_LEN];
    uint8_t ss1[HYBRID_SS_LEN], ss2[HYBRID_SS_LEN];

    ASSERT_TRUE(hybrid_keygen(pk, sk));
    ASSERT_TRUE(hybrid_encapsulate(pk, nullptr, 0, ct1, ss1));
    ASSERT_TRUE(hybrid_encapsulate(pk, nullptr, 0, ct2, ss2));
    EXPECT_NE(std::memcmp(ct1, ct2, HYBRID_CT_LEN), 0)
        << "Two encapsulations produced identical ciphertext — ephemeral keys collide!";
    EXPECT_NE(std::memcmp(ss1, ss2, HYBRID_SS_LEN), 0);
}

TEST(HybridKex, TamperingX25519HalfChangesSecret) {
    SKIP_IF_UNAVAILABLE();
    uint8_t pk[HYBRID_PK_LEN], sk[HYBRID_SK_LEN];
    uint8_t ct[HYBRID_CT_LEN];
    uint8_t ss_send[HYBRID_SS_LEN], ss_recv[HYBRID_SS_LEN];

    ASSERT_TRUE(hybrid_keygen(pk, sk));
    ASSERT_TRUE(hybrid_encapsulate(pk, nullptr, 0, ct, ss_send));
    /* Flip a byte in the ephemeral X25519 half (bytes 0..31). */
    ct[5] ^= 0x01;
    ASSERT_TRUE(hybrid_decapsulate(sk, ct, nullptr, 0, ss_recv));
    EXPECT_NE(std::memcmp(ss_send, ss_recv, HYBRID_SS_LEN), 0);
}

TEST(HybridKex, TamperingMlkemHalfChangesSecret) {
    SKIP_IF_UNAVAILABLE();
    uint8_t pk[HYBRID_PK_LEN], sk[HYBRID_SK_LEN];
    uint8_t ct[HYBRID_CT_LEN];
    uint8_t ss_send[HYBRID_SS_LEN], ss_recv[HYBRID_SS_LEN];

    ASSERT_TRUE(hybrid_keygen(pk, sk));
    ASSERT_TRUE(hybrid_encapsulate(pk, nullptr, 0, ct, ss_send));
    /* Flip a byte deep in the ML-KEM ciphertext (bytes 32..1119). */
    ct[500] ^= 0x01;
    ASSERT_TRUE(hybrid_decapsulate(sk, ct, nullptr, 0, ss_recv));
    EXPECT_NE(std::memcmp(ss_send, ss_recv, HYBRID_SS_LEN), 0);
}

TEST(HybridKex, FailsClosedWhenUnavailable) {
    /* When no backend is linked, every call must fail rather than silently
     * degrade to a weaker primitive. */
    if (hybrid_available())
        GTEST_SKIP() << "Backend present — this test is for stub builds";
    uint8_t pk[HYBRID_PK_LEN] = {}, sk[HYBRID_SK_LEN] = {}, ct[HYBRID_CT_LEN] = {},
            ss[HYBRID_SS_LEN] = {};
    EXPECT_FALSE(hybrid_keygen(pk, sk));
    EXPECT_FALSE(hybrid_encapsulate(pk, nullptr, 0, ct, ss));
    EXPECT_FALSE(hybrid_decapsulate(sk, ct, nullptr, 0, ss));
}
