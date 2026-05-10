/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Unit Tests — Advanced Protocol Suite (CipherSuite registry,
 * PQ KEM constants, extended wire-format).
 *
 * This file historically held a broader suite that included
 * AdaptiveObfsController, PortRotationInterval and AutoConfig tests.
 * Those features were removed during the v5 / Phase 23 refactor; the
 * surviving symbols are exercised here. Hardware-detection coverage
 * lives in test_autoconf.cpp; the cross-language wire-format coverage
 * lives in test_wire_v5.cpp; this file focuses on the cipher-suite
 * abstraction and the userspace_key_init mirror.
 */

#include <gtest/gtest.h>
#include <cstring>

#include "cipher_suite.h"
#include "pq_kem.h"
#include "tachyon.h"

/* ══════════════════════════════════════════════════════════════════════════
 * CipherSuite Registry Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(CipherSuiteTest, RegistryReturnsChaCha20) {
    const CipherSuite *cs = get_cipher_suite(TACHYON_CIPHER_CHACHA20);
    ASSERT_NE(cs, nullptr);
    EXPECT_EQ(cs->type_id, TACHYON_CIPHER_CHACHA20);
    EXPECT_STREQ(cs->name, "ChaCha20-Poly1305");
    EXPECT_EQ(cs->key_len, 32u);
    EXPECT_EQ(cs->tag_len, 16u);
    EXPECT_EQ(cs->nonce_len, 12u);
}

TEST(CipherSuiteTest, RegistryReturnsAES128GCM) {
    const CipherSuite *cs = get_cipher_suite(TACHYON_CIPHER_AES128GCM);
    ASSERT_NE(cs, nullptr);
    EXPECT_EQ(cs->type_id, TACHYON_CIPHER_AES128GCM);
    EXPECT_STREQ(cs->name, "AES-128-GCM");
    EXPECT_EQ(cs->key_len, 16u);
    EXPECT_EQ(cs->tag_len, 16u);
}

TEST(CipherSuiteTest, RegistryReturnsAES256GCM) {
    const CipherSuite *cs = get_cipher_suite(TACHYON_CIPHER_AES256GCM);
    ASSERT_NE(cs, nullptr);
    EXPECT_EQ(cs->type_id, TACHYON_CIPHER_AES256GCM);
    EXPECT_STREQ(cs->name, "AES-256-GCM");
    EXPECT_EQ(cs->key_len, 32u);
    EXPECT_EQ(cs->tag_len, 16u);
}

TEST(CipherSuiteTest, RegistryReturnsNullForUnknown) {
    EXPECT_EQ(get_cipher_suite(99), nullptr);
    EXPECT_EQ(get_cipher_suite(255), nullptr);
    EXPECT_EQ(get_cipher_suite(TACHYON_CIPHER_MAX + 1), nullptr);
}

TEST(CipherSuiteTest, SelectBestSuiteWithAESNI) {
    const CipherSuite *cs = select_best_suite(true);
    ASSERT_NE(cs, nullptr);
    EXPECT_EQ(cs->type_id, TACHYON_CIPHER_AES256GCM);
}

TEST(CipherSuiteTest, SelectBestSuiteWithoutAESNI) {
    const CipherSuite *cs = select_best_suite(false);
    ASSERT_NE(cs, nullptr);
    EXPECT_EQ(cs->type_id, TACHYON_CIPHER_CHACHA20);
}

TEST(CipherSuiteTest, AllSuitesHaveNonNullFunctions) {
    for (uint8_t id = 0; id <= TACHYON_CIPHER_MAX; id++) {
        const CipherSuite *cs = get_cipher_suite(id);
        ASSERT_NE(cs, nullptr) << "Suite " << static_cast<int>(id) << " missing";
        EXPECT_NE(cs->encrypt, nullptr);
        EXPECT_NE(cs->decrypt, nullptr);
        EXPECT_NE(cs->name, nullptr);
        EXPECT_GT(cs->key_len, 0u);
        EXPECT_EQ(cs->tag_len, 16u); /* All AEAD suites use 16-byte tags */
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 * CipherSuite Round-Trip Encryption Tests
 * ══════════════════════════════════════════════════════════════════════════ */

static void test_suite_roundtrip(uint8_t cipher_id) {
    const CipherSuite *cs = get_cipher_suite(cipher_id);
    ASSERT_NE(cs, nullptr);

    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    uint8_t aad[] = "test-aad";
    const char *plaintext = "hello tachyon";
    size_t pt_len = strlen(plaintext);

    /* Unique key per suite to avoid false positives */
    memset(key, static_cast<int>(cipher_id + 1), cs->key_len);
    memset(nonce, 0xAB, sizeof(nonce));

    uint8_t ct[64] = {};
    uint8_t tag[16] = {};
    ASSERT_TRUE(cs->encrypt(key, nonce, sizeof(nonce), aad, sizeof(aad) - 1,
                            reinterpret_cast<const uint8_t *>(plaintext), pt_len, ct, tag));

    uint8_t pt[64] = {};
    ASSERT_TRUE(cs->decrypt(key, nonce, sizeof(nonce), aad, sizeof(aad) - 1, ct, pt_len, tag, pt));

    EXPECT_EQ(memcmp(pt, plaintext, pt_len), 0);
}

TEST(CipherSuiteTest, ChaCha20RoundTrip) {
    test_suite_roundtrip(TACHYON_CIPHER_CHACHA20);
}

TEST(CipherSuiteTest, AES128GCMRoundTrip) {
    test_suite_roundtrip(TACHYON_CIPHER_AES128GCM);
}

TEST(CipherSuiteTest, AES256GCMRoundTrip) {
    test_suite_roundtrip(TACHYON_CIPHER_AES256GCM);
}

TEST(CipherSuiteTest, TamperedTagFails) {
    const CipherSuite *cs = get_cipher_suite(TACHYON_CIPHER_CHACHA20);
    ASSERT_NE(cs, nullptr);

    uint8_t key[32] = {1};
    uint8_t nonce[12] = {2};
    const char *pt = "tamper-test";
    size_t pt_len = strlen(pt);

    uint8_t ct[64] = {};
    uint8_t tag[16] = {};
    ASSERT_TRUE(cs->encrypt(key, nonce, sizeof(nonce), nullptr, 0,
                            reinterpret_cast<const uint8_t *>(pt), pt_len, ct, tag));

    tag[0] ^= 0xFF; /* Corrupt tag */
    uint8_t out[64] = {};
    EXPECT_FALSE(cs->decrypt(key, nonce, sizeof(nonce), nullptr, 0, ct, pt_len, tag, out));
}

/* ══════════════════════════════════════════════════════════════════════════
 * PQ KEM Constants & Stub Tests
 *
 * Note: tachyon_core is built with TACHYON_PQC_OQS / TACHYON_PQC_OPENSSL
 * (not TACHYON_PQ), so pq_kem.h always selects the stub branch in tests.
 * The "real" KEM exercise lives in test_pqc.cpp behind that backend.
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(PqKemTest, ConstantSizes) {
    EXPECT_EQ(TACHYON_PQ_SS_LEN, 32);
    EXPECT_EQ(TACHYON_PQ_PK_LEN, 1184);
    EXPECT_EQ(TACHYON_PQ_SK_LEN, 2400);
    EXPECT_EQ(TACHYON_PQ_CT_LEN, 1088);
}

TEST(PqKemTest, FlagBitDoesNotConflictWithCpFlagMask) {
    /* TACHYON_FLAG_PQ = 0x02 must not collide with the CP-type bits
     * (TACHYON_CP_FLAG_MASK = 0xF0). */
    EXPECT_EQ(TACHYON_FLAG_PQ & TACHYON_CP_FLAG_MASK, 0u);
}

TEST(PqKemTest, KdfLabelsAreDistinct) {
    EXPECT_NE(std::string(TACHYON_KDF_PQ_HYBRID), std::string(TACHYON_KDF_SESSION_MASTER));
    EXPECT_NE(std::string(TACHYON_KDF_PQ_HYBRID), std::string(TACHYON_KDF_EARLY_SECRET));
    EXPECT_NE(std::string(TACHYON_KDF_PQ_HYBRID), std::string(TACHYON_KDF_CP_AEAD));
}

#ifndef TACHYON_PQ
TEST(PqKemTest, StubsReturnFalseWhenBackendDisabled) {
    PqKemState state;
    EXPECT_FALSE(pq_kem_keygen(state));
    EXPECT_TRUE(state.pk.empty());
    EXPECT_TRUE(state.sk.empty());

    std::vector<uint8_t> ct;
    uint8_t ss[32] = {};
    EXPECT_FALSE(pq_kem_encap(nullptr, ct, ss));
    EXPECT_FALSE(pq_kem_decap(state, nullptr, ss));
    EXPECT_FALSE(pq_combine_secrets(nullptr, nullptr, nullptr));
}
#endif

/* ══════════════════════════════════════════════════════════════════════════
 * Wire Format — extended tachyon_key_init (cipher_type field)
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(WireFormatExtendedTest, KeyInitHasCipherTypeAndIsSeventyTwoBytes) {
    /* Layout: 4 (session_id) + 32 (tx_key) + 32 (rx_key) + 1 (cipher_type)
     *       + 3 (_reserved) = 72 */
    EXPECT_EQ(sizeof(struct tachyon_key_init), 72u);
}

TEST(WireFormatExtendedTest, KeyInitCipherTypeFieldRoundTrips) {
    struct tachyon_key_init ki {};
    ki.cipher_type = TACHYON_CIPHER_AES256GCM;
    EXPECT_EQ(ki.cipher_type, TACHYON_CIPHER_AES256GCM);
}

TEST(WireFormatExtendedTest, UserspaceMirrorMatchesKernelKeyInit) {
    /* userspace_key_init must remain bit-compatible with the kernel struct
     * for BPF map updates; sizeof equality is the cheapest invariant. */
    EXPECT_EQ(sizeof(userspace_key_init), sizeof(struct tachyon_key_init));
}

TEST(WireFormatExtendedTest, CipherIdsMatchExpectedNumericValues) {
    EXPECT_EQ(TACHYON_CIPHER_CHACHA20, 0);
    EXPECT_EQ(TACHYON_CIPHER_AES128GCM, 1);
    EXPECT_EQ(TACHYON_CIPHER_AES256GCM, 2);
    EXPECT_EQ(TACHYON_CIPHER_MAX, 2);
}
