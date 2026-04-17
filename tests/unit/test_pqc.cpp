/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the post-quantum (ML-KEM-768) wrapper.
 *
 * The PQC backend may be unavailable at build time (neither OpenSSL 3.5 nor
 * liboqs linked in); in that case every substantive test is SKIPped with a
 * clear message so CI still goes green.
 *
 * Coverage when backend is present:
 *   - keygen → encaps → decaps round trip yields matching shared secrets
 *   - encaps against a different peer gives different ciphertexts
 *   - tampered ciphertext yields a different (but "successful") secret
 *     per FIPS 203 §6.3 implicit-rejection semantics
 *   - hybrid_combine mixes two IKMs deterministically
 *
 * Always-present:
 *   - pqc_available / pqc_backend strings are non-null
 *   - hkdf_sha384_extract produces 48 bytes of output
 */

#include <gtest/gtest.h>
#include "pqc.h"

#include <cstring>

using namespace tachyon::pqc;

#define SKIP_IF_UNAVAILABLE()                                      \
    do {                                                           \
        if (!pqc_available())                                      \
            GTEST_SKIP() << "PQC backend unavailable: "            \
                         << pqc_backend();                         \
    } while (0)

TEST(Pqc, BackendStringNonNull) {
    ASSERT_NE(pqc_backend(), nullptr);
    EXPECT_GT(strlen(pqc_backend()), 0u);
}

TEST(Pqc, HkdfSha384ExtractAlwaysWorks) {
    const uint8_t ikm[] = {1, 2, 3, 4};
    uint8_t out[48] = {0};
    EXPECT_TRUE(hkdf_sha384_extract(nullptr, 0, ikm, sizeof(ikm), out));
    /* Output must not be all-zero (extremely unlikely) */
    uint8_t zero[48] = {0};
    EXPECT_NE(memcmp(out, zero, 48), 0);
}

TEST(Pqc, HkdfSha384ExtractDeterministic) {
    const uint8_t ikm[] = "deadbeef";
    const uint8_t salt[] = "salt";
    uint8_t a[48] = {0}, b[48] = {0};
    ASSERT_TRUE(hkdf_sha384_extract(salt, sizeof(salt), ikm, sizeof(ikm), a));
    ASSERT_TRUE(hkdf_sha384_extract(salt, sizeof(salt), ikm, sizeof(ikm), b));
    EXPECT_EQ(memcmp(a, b, 48), 0);
}

TEST(Pqc, HkdfSha384DifferentSaltYieldsDifferentPrk) {
    const uint8_t ikm[] = "deadbeef";
    const uint8_t salt1[] = "s1";
    const uint8_t salt2[] = "s2";
    uint8_t a[48] = {0}, b[48] = {0};
    ASSERT_TRUE(hkdf_sha384_extract(salt1, sizeof(salt1), ikm, sizeof(ikm), a));
    ASSERT_TRUE(hkdf_sha384_extract(salt2, sizeof(salt2), ikm, sizeof(ikm), b));
    EXPECT_NE(memcmp(a, b, 48), 0);
}

TEST(Pqc, HybridCombineDifferentContextsProduceDifferentPrks) {
    const uint8_t c[] = "classical32classical32classical2";
    const uint8_t q[] = "pq32pq32pq32pq32pq32pq32pq32pq32";
    uint8_t a[48] = {0}, b[48] = {0};
    ASSERT_TRUE(hybrid_combine(c, sizeof(c), q, sizeof(q), "ctxA", a));
    ASSERT_TRUE(hybrid_combine(c, sizeof(c), q, sizeof(q), "ctxB", b));
    EXPECT_NE(memcmp(a, b, 48), 0);
}

/* ── ML-KEM-768 round-trip ──────────────────────────────────────────────── */

TEST(Pqc, Mlkem768KeygenEncapsDecapsRoundTrip) {
    SKIP_IF_UNAVAILABLE();

    uint8_t pk[MLKEM768_PUBLIC_KEY_LEN];
    uint8_t sk[MLKEM768_SECRET_KEY_LEN];
    uint8_t ct[MLKEM768_CIPHERTEXT_LEN];
    uint8_t ss_enc[MLKEM768_SHARED_SECRET];
    uint8_t ss_dec[MLKEM768_SHARED_SECRET];

    ASSERT_TRUE(mlkem768_keygen(pk, sk));
    ASSERT_TRUE(mlkem768_encapsulate(pk, ct, ss_enc));
    ASSERT_TRUE(mlkem768_decapsulate(sk, ct, ss_dec));

    EXPECT_EQ(memcmp(ss_enc, ss_dec, MLKEM768_SHARED_SECRET), 0);
}

TEST(Pqc, Mlkem768IndependentKeysProduceDifferentSecrets) {
    SKIP_IF_UNAVAILABLE();

    uint8_t pk1[MLKEM768_PUBLIC_KEY_LEN], sk1[MLKEM768_SECRET_KEY_LEN];
    uint8_t pk2[MLKEM768_PUBLIC_KEY_LEN], sk2[MLKEM768_SECRET_KEY_LEN];
    ASSERT_TRUE(mlkem768_keygen(pk1, sk1));
    ASSERT_TRUE(mlkem768_keygen(pk2, sk2));
    /* Different public keys with overwhelming probability */
    EXPECT_NE(memcmp(pk1, pk2, MLKEM768_PUBLIC_KEY_LEN), 0);

    uint8_t ct1[MLKEM768_CIPHERTEXT_LEN], ss1[MLKEM768_SHARED_SECRET];
    uint8_t ct2[MLKEM768_CIPHERTEXT_LEN], ss2[MLKEM768_SHARED_SECRET];
    ASSERT_TRUE(mlkem768_encapsulate(pk1, ct1, ss1));
    ASSERT_TRUE(mlkem768_encapsulate(pk2, ct2, ss2));
    EXPECT_NE(memcmp(ct1, ct2, MLKEM768_CIPHERTEXT_LEN), 0);
    EXPECT_NE(memcmp(ss1, ss2, MLKEM768_SHARED_SECRET), 0);
}

TEST(Pqc, Mlkem768TamperedCiphertextFailsGracefully) {
    SKIP_IF_UNAVAILABLE();

    uint8_t pk[MLKEM768_PUBLIC_KEY_LEN];
    uint8_t sk[MLKEM768_SECRET_KEY_LEN];
    uint8_t ct[MLKEM768_CIPHERTEXT_LEN];
    uint8_t ss_enc[MLKEM768_SHARED_SECRET];
    uint8_t ss_dec[MLKEM768_SHARED_SECRET];

    ASSERT_TRUE(mlkem768_keygen(pk, sk));
    ASSERT_TRUE(mlkem768_encapsulate(pk, ct, ss_enc));

    /* Flip a byte in the ciphertext */
    ct[0] ^= 0x01;
    /* Implicit rejection: decaps "succeeds" but secret differs */
    ASSERT_TRUE(mlkem768_decapsulate(sk, ct, ss_dec));
    EXPECT_NE(memcmp(ss_enc, ss_dec, MLKEM768_SHARED_SECRET), 0);
}

TEST(Pqc, ConstantsMatchFipsSpec) {
    /* FIPS 203 ML-KEM-768 fixed sizes */
    EXPECT_EQ(MLKEM768_PUBLIC_KEY_LEN, 1184u);
    EXPECT_EQ(MLKEM768_SECRET_KEY_LEN, 2400u);
    EXPECT_EQ(MLKEM768_CIPHERTEXT_LEN, 1088u);
    EXPECT_EQ(MLKEM768_SHARED_SECRET, 32u);
}
