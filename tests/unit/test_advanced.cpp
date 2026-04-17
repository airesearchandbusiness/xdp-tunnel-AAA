/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Unit Tests - Phase 22: Advanced Protocol Suite
 *
 * Tests:
 *   - CipherSuite registry (get_cipher_suite, select_best_suite)
 *   - AES-GCM encrypt/decrypt round-trip via CipherSuite abstraction
 *   - AutoConf hardware detection (cpu_has_aesni, iface_mtu)
 *   - AutoDetectedConfig from probe_hardware()
 *   - Config parsing: CipherType, PortRotationInterval, AutoConfig
 *   - AdaptiveObfsController congestion response
 *   - PQ KEM size constants
 *   - tachyon_key_init size (extended with cipher_type)
 */

#include <gtest/gtest.h>
#include <cstring>
#include <string>

#include "tachyon.h"
#include "cipher_suite.h"
#include "autoconf.h"
#include "pq_kem.h"

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
        ASSERT_NE(cs, nullptr) << "Suite " << (int)id << " missing";
        EXPECT_NE(cs->encrypt, nullptr);
        EXPECT_NE(cs->decrypt, nullptr);
        EXPECT_NE(cs->name, nullptr);
        EXPECT_GT(cs->key_len, 0u);
        EXPECT_EQ(cs->tag_len, 16u);  /* All AEAD suites use 16-byte tags */
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
    memset(key, (int)(cipher_id + 1), cs->key_len);
    memset(nonce, 0xAB, 12);

    uint8_t ct[64] = {};
    uint8_t tag[16] = {};
    ASSERT_TRUE(cs->encrypt(key, nonce, 12,
                             aad, sizeof(aad) - 1,
                             reinterpret_cast<const uint8_t *>(plaintext), pt_len,
                             ct, tag));

    uint8_t pt[64] = {};
    ASSERT_TRUE(cs->decrypt(key, nonce, 12,
                             aad, sizeof(aad) - 1,
                             ct, pt_len, tag, pt));

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
    ASSERT_TRUE(cs->encrypt(key, nonce, 12, nullptr, 0,
                             reinterpret_cast<const uint8_t *>(pt), pt_len,
                             ct, tag));

    tag[0] ^= 0xFF; /* Corrupt tag */
    uint8_t out[64] = {};
    EXPECT_FALSE(cs->decrypt(key, nonce, 12, nullptr, 0, ct, pt_len, tag, out));
}

/* ══════════════════════════════════════════════════════════════════════════
 * AutoConf Hardware Detection Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(AutoConfTest, AESNIDetectionReturnsBool) {
    /* Just verify it doesn't crash and returns a valid bool */
    bool result = cpu_has_aesni();
    EXPECT_TRUE(result == true || result == false);
}

TEST(AutoConfTest, CipherTypeFromHardware) {
    bool has_aes = cpu_has_aesni();
    const CipherSuite *best = select_best_suite(has_aes);
    ASSERT_NE(best, nullptr);
    if (has_aes) {
        EXPECT_EQ(best->type_id, TACHYON_CIPHER_AES256GCM);
    } else {
        EXPECT_EQ(best->type_id, TACHYON_CIPHER_CHACHA20);
    }
}

TEST(AutoConfTest, IfaceMtuEmptyNameReturns1500) {
    uint16_t mtu = iface_mtu("");
    EXPECT_EQ(mtu, 1500u);
}

TEST(AutoConfTest, IfaceMtuInvalidNameReturns1500) {
    uint16_t mtu = iface_mtu("nonexistent_iface_xyz");
    EXPECT_EQ(mtu, 1500u);
}

TEST(AutoConfTest, ProbeHardwareReturnsValidCipher) {
    AutoDetectedConfig cfg = probe_hardware("");
    EXPECT_LE(cfg.cipher_type, TACHYON_CIPHER_MAX);
    EXPECT_GE(cfg.interface_mtu, 576u);
    EXPECT_LE(cfg.interface_mtu, 9000u);
}

TEST(AutoConfTest, ProbeHardwareCipherMatchesAESNI) {
    AutoDetectedConfig cfg = probe_hardware("");
    if (cfg.has_aesni) {
        EXPECT_EQ(cfg.cipher_type, TACHYON_CIPHER_AES256GCM);
    } else {
        EXPECT_EQ(cfg.cipher_type, TACHYON_CIPHER_CHACHA20);
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 * Config Parsing Tests — CipherType, PortRotationInterval, AutoConfig
 * ══════════════════════════════════════════════════════════════════════════ */

/* Helpers */
static TunnelConfig parse_from_string(const std::string &content) {
    /* Write to a temp file and parse */
    char tmpname[] = "/tmp/tachyon_test_XXXXXX.conf";
    int fd = mkstemps(tmpname, 5);
    if (fd < 0)
        return TunnelConfig{};
    write(fd, content.c_str(), content.size());
    close(fd);
    TunnelConfig cfg = parse_config(tmpname);
    unlink(tmpname);
    return cfg;
}

static const std::string kBaseConf = R"(
[Interface]
PrivateKey = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
PeerPublicKey = 2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40
ListenPort = 443
VirtualIP = 10.8.0.1/24
LocalPhysicalIP = 192.168.1.10
PhysicalInterface = eth0

[Peer]
EndpointIP = 192.168.1.20
EndpointMAC = aa:bb:cc:dd:ee:ff
InnerIP = 10.8.0.2
)";

TEST(ConfigAdvancedTest, DefaultCipherIsChaCha20) {
    TunnelConfig cfg = parse_from_string(kBaseConf);
    EXPECT_EQ(cfg.cipher_type, TACHYON_CIPHER_CHACHA20);
}

TEST(ConfigAdvancedTest, CipherTypeChaCha20ByName) {
    TunnelConfig cfg = parse_from_string(kBaseConf + "CipherType = chacha20\n");
    EXPECT_EQ(cfg.cipher_type, TACHYON_CIPHER_CHACHA20);
}

TEST(ConfigAdvancedTest, CipherTypeAES128ByName) {
    TunnelConfig cfg = parse_from_string(kBaseConf + "CipherType = aes128gcm\n");
    EXPECT_EQ(cfg.cipher_type, TACHYON_CIPHER_AES128GCM);
}

TEST(ConfigAdvancedTest, CipherTypeAES256ByName) {
    TunnelConfig cfg = parse_from_string(kBaseConf + "CipherType = aes256gcm\n");
    EXPECT_EQ(cfg.cipher_type, TACHYON_CIPHER_AES256GCM);
}

TEST(ConfigAdvancedTest, CipherTypeByNumeric0) {
    TunnelConfig cfg = parse_from_string(kBaseConf + "CipherType = 0\n");
    EXPECT_EQ(cfg.cipher_type, TACHYON_CIPHER_CHACHA20);
}

TEST(ConfigAdvancedTest, CipherTypeByNumeric2) {
    TunnelConfig cfg = parse_from_string(kBaseConf + "CipherType = 2\n");
    EXPECT_EQ(cfg.cipher_type, TACHYON_CIPHER_AES256GCM);
}

TEST(ConfigAdvancedTest, PortRotationDefaultDisabled) {
    TunnelConfig cfg = parse_from_string(kBaseConf);
    EXPECT_EQ(cfg.port_rotation_interval, 0u);
}

TEST(ConfigAdvancedTest, PortRotationIntervalParsed) {
    TunnelConfig cfg = parse_from_string(kBaseConf + "PortRotationInterval = 60\n");
    EXPECT_EQ(cfg.port_rotation_interval, 60u);
}

TEST(ConfigAdvancedTest, PortRotationIntervalZeroDisabled) {
    TunnelConfig cfg = parse_from_string(kBaseConf + "PortRotationInterval = 0\n");
    EXPECT_EQ(cfg.port_rotation_interval, 0u);
}

TEST(ConfigAdvancedTest, AutoConfigDefaultFalse) {
    TunnelConfig cfg = parse_from_string(kBaseConf);
    EXPECT_FALSE(cfg.auto_config);
}

TEST(ConfigAdvancedTest, AutoConfigTrueParsed) {
    TunnelConfig cfg = parse_from_string(kBaseConf + "AutoConfig = true\n");
    EXPECT_TRUE(cfg.auto_config);
}

TEST(ConfigAdvancedTest, AutoConfigSetsValidCipherType) {
    /* When AutoConfig=true and no CipherType is set, cipher_type is auto-selected */
    TunnelConfig cfg = parse_from_string(kBaseConf + "AutoConfig = true\n");
    EXPECT_TRUE(cfg.auto_config);
    EXPECT_LE(cfg.cipher_type, TACHYON_CIPHER_MAX);
}

TEST(ConfigAdvancedTest, ExplicitCipherTakesPrecedenceOverAutoConfig) {
    /* CipherType=chacha20 + AutoConfig=true should keep chacha20 */
    std::string conf = kBaseConf + "CipherType = chacha20\nAutoConfig = true\n";
    TunnelConfig cfg = parse_from_string(conf);
    EXPECT_EQ(cfg.cipher_type, TACHYON_CIPHER_CHACHA20);
}

/* ══════════════════════════════════════════════════════════════════════════
 * AdaptiveObfsController Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(AdaptiveObfsTest, NoCongestionNoChange) {
    AdaptiveObfsController ctrl(TACHYON_OBFS_ALL);
    TunnelStats stats{0, 0};
    uint8_t flags = ctrl.update(stats);
    EXPECT_EQ(flags, TACHYON_OBFS_ALL);
}

TEST(AdaptiveObfsTest, CongestionReducesPadding) {
    AdaptiveObfsController ctrl(TACHYON_OBFS_ALL);
    TunnelStats stats{50, 50}; /* 100 drops — clearly congested */
    uint8_t flags = ctrl.update(stats);
    /* CONST_PAD and DECOY should be cleared */
    EXPECT_EQ(flags & TACHYON_OBFS_CONST_PAD, 0);
    EXPECT_EQ(flags & TACHYON_OBFS_DECOY, 0);
    /* Other flags should remain */
    EXPECT_NE(flags & TACHYON_OBFS_TTL_JITTER, 0);
}

TEST(AdaptiveObfsTest, ClearRestoresFullFlags) {
    AdaptiveObfsController ctrl(TACHYON_OBFS_ALL);

    /* First trigger congestion */
    TunnelStats congested{50, 50};
    ctrl.update(congested);

    /* Then clear (delta = 0, same total) */
    TunnelStats clear{50, 50}; /* same total → delta = 0 */
    uint8_t flags = ctrl.update(clear);
    EXPECT_EQ(flags, TACHYON_OBFS_ALL);
}

TEST(AdaptiveObfsTest, SmallDropsDoNotTriggerCongestion) {
    AdaptiveObfsController ctrl(TACHYON_OBFS_ALL);
    TunnelStats stats{5, 3}; /* 8 total drops — below threshold of 10 */
    uint8_t flags = ctrl.update(stats);
    EXPECT_EQ(flags, TACHYON_OBFS_ALL);
}

TEST(AdaptiveObfsTest, ExactlyThresholdTriggersCongestion) {
    AdaptiveObfsController ctrl(TACHYON_OBFS_ALL);
    TunnelStats stats{6, 5}; /* 11 total drops — above threshold */
    uint8_t flags = ctrl.update(stats);
    EXPECT_EQ(flags & TACHYON_OBFS_CONST_PAD, 0);
}

TEST(AdaptiveObfsTest, BaseAndActiveFlagsAccess) {
    AdaptiveObfsController ctrl(TACHYON_OBFS_ALL);
    EXPECT_EQ(ctrl.base_flags(), TACHYON_OBFS_ALL);
    EXPECT_EQ(ctrl.active_flags(), TACHYON_OBFS_ALL);
}

TEST(AdaptiveObfsTest, DisabledFlagsUnchangedUnderCongestion) {
    /* If base has CONST_PAD already disabled, congestion changes nothing extra */
    uint8_t base = TACHYON_OBFS_ALL & ~TACHYON_OBFS_CONST_PAD;
    AdaptiveObfsController ctrl(base);
    TunnelStats stats{100, 0};
    uint8_t flags = ctrl.update(stats);
    EXPECT_EQ(flags & TACHYON_OBFS_CONST_PAD, 0);
    EXPECT_EQ(flags & TACHYON_OBFS_DECOY, 0);
    EXPECT_NE(flags & TACHYON_OBFS_TTL_JITTER, 0);
}

/* ══════════════════════════════════════════════════════════════════════════
 * PQ KEM Constants & Stub Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(PqKemTest, ConstantSizes) {
    EXPECT_EQ(TACHYON_PQ_SS_LEN,  32);
    EXPECT_EQ(TACHYON_PQ_PK_LEN,  1184);
    EXPECT_EQ(TACHYON_PQ_SK_LEN,  2400);
    EXPECT_EQ(TACHYON_PQ_CT_LEN,  1088);
}

TEST(PqKemTest, FlagBitDoesNotConflictWithExistingFlags) {
    /* TACHYON_FLAG_PQ = 0x02 must not conflict with PKT type flags 0xC0 prefix */
    EXPECT_EQ(TACHYON_FLAG_PQ & TACHYON_CP_FLAG_MASK, 0u);
}

TEST(PqKemTest, KDFLabelDistinct) {
    EXPECT_NE(std::string(TACHYON_KDF_PQ_HYBRID), std::string(TACHYON_KDF_SESSION_MASTER));
    EXPECT_NE(std::string(TACHYON_KDF_PQ_HYBRID), std::string(TACHYON_KDF_EARLY_SECRET));
    EXPECT_NE(std::string(TACHYON_KDF_PQ_HYBRID), std::string(TACHYON_KDF_CP_AEAD));
}

#ifndef TACHYON_PQ
TEST(PqKemTest, StubsReturnFalseWithoutLiboqs) {
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
 * Wire Format Size Checks (tachyon_key_init extended)
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(WireFormatTest, KeyInitExtendedSize) {
    /* Extended with cipher_type + 3 reserved = 4 + 32 + 32 + 1 + 3 = 72 */
    EXPECT_EQ(sizeof(struct tachyon_key_init), 72u);
}

TEST(WireFormatTest, KeyInitCipherTypeField) {
    struct tachyon_key_init ki{};
    ki.cipher_type = TACHYON_CIPHER_AES256GCM;
    EXPECT_EQ(ki.cipher_type, TACHYON_CIPHER_AES256GCM);
}

TEST(WireFormatTest, UserspaceMirrorMatchesKernelKeyInit) {
    EXPECT_EQ(sizeof(userspace_key_init), sizeof(struct tachyon_key_init));
}

TEST(WireFormatTest, CipherConstantsInRange) {
    EXPECT_EQ(TACHYON_CIPHER_CHACHA20, 0);
    EXPECT_EQ(TACHYON_CIPHER_AES128GCM, 1);
    EXPECT_EQ(TACHYON_CIPHER_AES256GCM, 2);
    EXPECT_EQ(TACHYON_CIPHER_MAX, 2);
}
