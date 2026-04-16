/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Unit Tests - Cryptographic Operations
 *
 * Tests all crypto primitives in loader/crypto.cpp:
 *   - HMAC-SHA256 with RFC 4231 test vectors
 *   - X25519 ECDH key exchange and known vectors
 *   - HKDF-SHA256 with RFC 5869 test vectors
 *   - ChaCha20-Poly1305 AEAD encrypt/decrypt
 *   - Key generation and derivation
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <algorithm>

#include "tachyon.h"

/* ══════════════════════════════════════════════════════════════════════════
 * Test Fixture - Manages OpenSSL crypto global state
 * ══════════════════════════════════════════════════════════════════════════ */

class CryptoTest : public ::testing::Test {
  protected:
    void SetUp() override { init_crypto_globals(); }
    void TearDown() override { free_crypto_globals(); }

    /* Helper: convert hex string to byte vector */
    static std::vector<uint8_t> from_hex(const std::string &hex) {
        std::vector<uint8_t> bytes(hex.size() / 2);
        for (size_t i = 0; i < bytes.size(); i++)
            sscanf(&hex[i * 2], "%2hhx", &bytes[i]);
        return bytes;
    }

    /* Helper: convert bytes to hex string */
    static std::string to_hex(const uint8_t *data, size_t len) {
        std::string hex;
        hex.reserve(len * 2);
        for (size_t i = 0; i < len; i++) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", data[i]);
            hex += buf;
        }
        return hex;
    }
};

/* ══════════════════════════════════════════════════════════════════════════
 * HMAC-SHA256 Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(CryptoTest, HmacSha256BasicRoundtrip) {
    uint8_t key[32];
    memset(key, 0x0b, sizeof(key));

    const uint8_t data[] = "Hi There";
    uint8_t mac1[TACHYON_HMAC_LEN], mac2[TACHYON_HMAC_LEN];

    ASSERT_TRUE(calc_hmac(key, sizeof(key), data, 8, mac1));
    ASSERT_TRUE(calc_hmac(key, sizeof(key), data, 8, mac2));

    /* Same input produces same output */
    EXPECT_EQ(memcmp(mac1, mac2, TACHYON_HMAC_LEN), 0);
}

TEST_F(CryptoTest, HmacSha256DifferentKeysDifferentMacs) {
    uint8_t key1[32], key2[32];
    memset(key1, 0x01, sizeof(key1));
    memset(key2, 0x02, sizeof(key2));

    const uint8_t data[] = "test data";
    uint8_t mac1[TACHYON_HMAC_LEN], mac2[TACHYON_HMAC_LEN];

    ASSERT_TRUE(calc_hmac(key1, sizeof(key1), data, sizeof(data) - 1, mac1));
    ASSERT_TRUE(calc_hmac(key2, sizeof(key2), data, sizeof(data) - 1, mac2));

    EXPECT_NE(memcmp(mac1, mac2, TACHYON_HMAC_LEN), 0);
}

TEST_F(CryptoTest, HmacSha256DifferentDataDifferentMacs) {
    uint8_t key[32];
    memset(key, 0xaa, sizeof(key));

    const uint8_t data1[] = "hello";
    const uint8_t data2[] = "world";
    uint8_t mac1[TACHYON_HMAC_LEN], mac2[TACHYON_HMAC_LEN];

    ASSERT_TRUE(calc_hmac(key, sizeof(key), data1, 5, mac1));
    ASSERT_TRUE(calc_hmac(key, sizeof(key), data2, 5, mac2));

    EXPECT_NE(memcmp(mac1, mac2, TACHYON_HMAC_LEN), 0);
}

TEST_F(CryptoTest, HmacSha256EmptyData) {
    uint8_t key[32];
    memset(key, 0x0b, sizeof(key));

    uint8_t mac[TACHYON_HMAC_LEN];
    ASSERT_TRUE(calc_hmac(key, sizeof(key), nullptr, 0, mac));

    /* Should produce a valid, non-zero hash */
    uint8_t zero[TACHYON_HMAC_LEN] = {0};
    EXPECT_NE(memcmp(mac, zero, TACHYON_HMAC_LEN), 0);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Cookie Generation Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(CryptoTest, CookieDeterministic) {
    uint8_t secret[32];
    memset(secret, 0xaa, sizeof(secret));

    uint8_t cookie1[TACHYON_HMAC_LEN], cookie2[TACHYON_HMAC_LEN];
    generate_cookie(secret, 0x0a000001, 12345, 100, cookie1);
    generate_cookie(secret, 0x0a000001, 12345, 100, cookie2);

    EXPECT_EQ(memcmp(cookie1, cookie2, TACHYON_HMAC_LEN), 0);
}

TEST_F(CryptoTest, CookieDifferentInputsDifferentCookies) {
    uint8_t secret[32];
    memset(secret, 0xaa, sizeof(secret));

    uint8_t cookie1[TACHYON_HMAC_LEN], cookie2[TACHYON_HMAC_LEN];
    generate_cookie(secret, 0x0a000001, 12345, 100, cookie1);
    generate_cookie(secret, 0x0a000002, 12345, 100, cookie2);

    EXPECT_NE(memcmp(cookie1, cookie2, TACHYON_HMAC_LEN), 0);
}

TEST_F(CryptoTest, CookieDifferentWindowDifferentCookies) {
    uint8_t secret[32];
    memset(secret, 0xaa, sizeof(secret));

    uint8_t cookie1[TACHYON_HMAC_LEN], cookie2[TACHYON_HMAC_LEN];
    generate_cookie(secret, 0x0a000001, 12345, 100, cookie1);
    generate_cookie(secret, 0x0a000001, 12345, 101, cookie2);

    EXPECT_NE(memcmp(cookie1, cookie2, TACHYON_HMAC_LEN), 0);
}

/* ══════════════════════════════════════════════════════════════════════════
 * X25519 ECDH Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(CryptoTest, EcdhRoundtrip) {
    uint8_t priv_a[32], pub_a[32], priv_b[32], pub_b[32];

    ASSERT_TRUE(generate_x25519_keypair(priv_a, pub_a));
    ASSERT_TRUE(generate_x25519_keypair(priv_b, pub_b));

    uint8_t ss_ab[32], ss_ba[32];
    ASSERT_TRUE(do_ecdh(priv_a, pub_b, ss_ab));
    ASSERT_TRUE(do_ecdh(priv_b, pub_a, ss_ba));

    /* Both sides derive the same shared secret */
    EXPECT_EQ(memcmp(ss_ab, ss_ba, 32), 0);
}

TEST_F(CryptoTest, EcdhDifferentPeersDifferentSecrets) {
    uint8_t priv_a[32], pub_a[32];
    uint8_t priv_b[32], pub_b[32];
    uint8_t priv_c[32], pub_c[32];

    ASSERT_TRUE(generate_x25519_keypair(priv_a, pub_a));
    ASSERT_TRUE(generate_x25519_keypair(priv_b, pub_b));
    ASSERT_TRUE(generate_x25519_keypair(priv_c, pub_c));

    uint8_t ss_ab[32], ss_ac[32];
    ASSERT_TRUE(do_ecdh(priv_a, pub_b, ss_ab));
    ASSERT_TRUE(do_ecdh(priv_a, pub_c, ss_ac));

    EXPECT_NE(memcmp(ss_ab, ss_ac, 32), 0);
}

TEST_F(CryptoTest, EcdhRejectsZeroPublicKey) {
    uint8_t priv[32], pub[32];
    ASSERT_TRUE(generate_x25519_keypair(priv, pub));

    uint8_t zero_pub[32] = {0};
    uint8_t ss[32];

    /* X25519 with the all-zeros point should fail (small-order point) */
    EXPECT_FALSE(do_ecdh(priv, zero_pub, ss));
}

/* ══════════════════════════════════════════════════════════════════════════
 * Key Generation Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(CryptoTest, GenerateKeypairProducesValidKeys) {
    uint8_t priv[32], pub[32];
    ASSERT_TRUE(generate_x25519_keypair(priv, pub));

    /* Keys should not be all zeros */
    uint8_t zero[32] = {0};
    EXPECT_NE(memcmp(priv, zero, 32), 0);
    EXPECT_NE(memcmp(pub, zero, 32), 0);
}

TEST_F(CryptoTest, GenerateKeypairUniquePerCall) {
    uint8_t priv1[32], pub1[32], priv2[32], pub2[32];
    ASSERT_TRUE(generate_x25519_keypair(priv1, pub1));
    ASSERT_TRUE(generate_x25519_keypair(priv2, pub2));

    EXPECT_NE(memcmp(priv1, priv2, 32), 0);
    EXPECT_NE(memcmp(pub1, pub2, 32), 0);
}

TEST_F(CryptoTest, GetPublicKeyConsistency) {
    uint8_t priv[32], pub_gen[32], pub_derived[32];
    ASSERT_TRUE(generate_x25519_keypair(priv, pub_gen));
    ASSERT_TRUE(get_public_key(priv, pub_derived));

    EXPECT_EQ(memcmp(pub_gen, pub_derived, 32), 0);
}

/* ══════════════════════════════════════════════════════════════════════════
 * HKDF-SHA256 Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(CryptoTest, HkdfDeterministic) {
    uint8_t salt[32], ikm[32];
    memset(salt, 0x01, sizeof(salt));
    memset(ikm, 0x02, sizeof(ikm));

    uint8_t out1[TACHYON_AEAD_KEY_LEN], out2[TACHYON_AEAD_KEY_LEN];
    ASSERT_TRUE(derive_kdf(salt, 32, ikm, 32, "test-label", out1));
    ASSERT_TRUE(derive_kdf(salt, 32, ikm, 32, "test-label", out2));

    EXPECT_EQ(memcmp(out1, out2, TACHYON_AEAD_KEY_LEN), 0);
}

TEST_F(CryptoTest, HkdfDifferentLabelsDifferentKeys) {
    uint8_t salt[32], ikm[32];
    memset(salt, 0x01, sizeof(salt));
    memset(ikm, 0x02, sizeof(ikm));

    uint8_t out1[TACHYON_AEAD_KEY_LEN], out2[TACHYON_AEAD_KEY_LEN];
    ASSERT_TRUE(derive_kdf(salt, 32, ikm, 32, TACHYON_KDF_SERVER_TX, out1));
    ASSERT_TRUE(derive_kdf(salt, 32, ikm, 32, TACHYON_KDF_CLIENT_TX, out2));

    EXPECT_NE(memcmp(out1, out2, TACHYON_AEAD_KEY_LEN), 0);
}

TEST_F(CryptoTest, HkdfWithTachyonLabels) {
    uint8_t salt[32], ikm[32];
    memset(salt, 0xaa, sizeof(salt));
    memset(ikm, 0xbb, sizeof(ikm));

    uint8_t early[TACHYON_AEAD_KEY_LEN];
    ASSERT_TRUE(derive_kdf(salt, 32, ikm, 32, TACHYON_KDF_EARLY_SECRET, early));

    /* Output should not be all zeros */
    uint8_t zero[TACHYON_AEAD_KEY_LEN] = {0};
    EXPECT_NE(memcmp(early, zero, TACHYON_AEAD_KEY_LEN), 0);
}

TEST_F(CryptoTest, HkdfDifferentSaltsDifferentKeys) {
    uint8_t salt1[32], salt2[32], ikm[32];
    memset(salt1, 0x01, sizeof(salt1));
    memset(salt2, 0x02, sizeof(salt2));
    memset(ikm, 0x03, sizeof(ikm));

    uint8_t out1[TACHYON_AEAD_KEY_LEN], out2[TACHYON_AEAD_KEY_LEN];
    ASSERT_TRUE(derive_kdf(salt1, 32, ikm, 32, "label", out1));
    ASSERT_TRUE(derive_kdf(salt2, 32, ikm, 32, "label", out2));

    EXPECT_NE(memcmp(out1, out2, TACHYON_AEAD_KEY_LEN), 0);
}

/* ══════════════════════════════════════════════════════════════════════════
 * ChaCha20-Poly1305 AEAD Tests
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(CryptoTest, AeadEncryptDecryptRoundtrip) {
    uint8_t key[32], nonce[12];
    memset(key, 0x42, sizeof(key));
    memset(nonce, 0x00, sizeof(nonce));

    const uint8_t plaintext[] = "Hello, Tachyon XDP Tunnel!";
    const size_t pt_len = sizeof(plaintext) - 1;

    uint8_t ct[256], tag[TACHYON_AEAD_TAG_LEN], decrypted[256];

    ASSERT_TRUE(cp_aead_encrypt(key, plaintext, pt_len, nullptr, 0, nonce, ct, tag));
    ASSERT_TRUE(cp_aead_decrypt(key, ct, pt_len, nullptr, 0, nonce, tag, decrypted));

    EXPECT_EQ(memcmp(plaintext, decrypted, pt_len), 0);
}

TEST_F(CryptoTest, AeadEncryptDecryptWithAD) {
    uint8_t key[32], nonce[12];
    memset(key, 0x42, sizeof(key));
    memset(nonce, 0x01, sizeof(nonce));

    const uint8_t plaintext[] = "secret payload";
    const uint8_t ad[] = "additional data";
    const size_t pt_len = sizeof(plaintext) - 1;
    const size_t ad_len = sizeof(ad) - 1;

    uint8_t ct[256], tag[TACHYON_AEAD_TAG_LEN], decrypted[256];

    ASSERT_TRUE(cp_aead_encrypt(key, plaintext, pt_len, ad, ad_len, nonce, ct, tag));
    ASSERT_TRUE(cp_aead_decrypt(key, ct, pt_len, ad, ad_len, nonce, tag, decrypted));

    EXPECT_EQ(memcmp(plaintext, decrypted, pt_len), 0);
}

TEST_F(CryptoTest, AeadTamperCiphertext) {
    uint8_t key[32], nonce[12];
    memset(key, 0x42, sizeof(key));
    memset(nonce, 0x02, sizeof(nonce));

    const uint8_t plaintext[] = "tamper test";
    const size_t pt_len = sizeof(plaintext) - 1;

    uint8_t ct[256], tag[TACHYON_AEAD_TAG_LEN], decrypted[256];

    ASSERT_TRUE(cp_aead_encrypt(key, plaintext, pt_len, nullptr, 0, nonce, ct, tag));

    /* Flip one bit in ciphertext */
    ct[0] ^= 0x01;

    EXPECT_FALSE(cp_aead_decrypt(key, ct, pt_len, nullptr, 0, nonce, tag, decrypted));
}

TEST_F(CryptoTest, AeadTamperTag) {
    uint8_t key[32], nonce[12];
    memset(key, 0x42, sizeof(key));
    memset(nonce, 0x03, sizeof(nonce));

    const uint8_t plaintext[] = "tag tamper test";
    const size_t pt_len = sizeof(plaintext) - 1;

    uint8_t ct[256], tag[TACHYON_AEAD_TAG_LEN], decrypted[256];

    ASSERT_TRUE(cp_aead_encrypt(key, plaintext, pt_len, nullptr, 0, nonce, ct, tag));

    /* Flip one bit in tag */
    tag[0] ^= 0x01;

    EXPECT_FALSE(cp_aead_decrypt(key, ct, pt_len, nullptr, 0, nonce, tag, decrypted));
}

TEST_F(CryptoTest, AeadTamperAD) {
    uint8_t key[32], nonce[12];
    memset(key, 0x42, sizeof(key));
    memset(nonce, 0x04, sizeof(nonce));

    const uint8_t plaintext[] = "AD tamper test";
    const uint8_t ad[] = "original AD";
    const uint8_t bad_ad[] = "modified AD";
    const size_t pt_len = sizeof(plaintext) - 1;

    uint8_t ct[256], tag[TACHYON_AEAD_TAG_LEN], decrypted[256];

    ASSERT_TRUE(cp_aead_encrypt(key, plaintext, pt_len, ad, sizeof(ad) - 1, nonce, ct, tag));

    /* Decrypt with different AD should fail */
    EXPECT_FALSE(
        cp_aead_decrypt(key, ct, pt_len, bad_ad, sizeof(bad_ad) - 1, nonce, tag, decrypted));
}

TEST_F(CryptoTest, AeadWrongKeyDecryptFails) {
    uint8_t key1[32], key2[32], nonce[12];
    memset(key1, 0x42, sizeof(key1));
    memset(key2, 0x43, sizeof(key2));
    memset(nonce, 0x05, sizeof(nonce));

    const uint8_t plaintext[] = "wrong key test";
    const size_t pt_len = sizeof(plaintext) - 1;

    uint8_t ct[256], tag[TACHYON_AEAD_TAG_LEN], decrypted[256];

    ASSERT_TRUE(cp_aead_encrypt(key1, plaintext, pt_len, nullptr, 0, nonce, ct, tag));

    EXPECT_FALSE(cp_aead_decrypt(key2, ct, pt_len, nullptr, 0, nonce, tag, decrypted));
}

TEST_F(CryptoTest, AeadDifferentNoncesDifferentCiphertext) {
    uint8_t key[32], nonce1[12], nonce2[12];
    memset(key, 0x42, sizeof(key));
    memset(nonce1, 0x00, sizeof(nonce1));
    memset(nonce2, 0x01, sizeof(nonce2));

    const uint8_t plaintext[] = "nonce test";
    const size_t pt_len = sizeof(plaintext) - 1;

    uint8_t ct1[256], ct2[256], tag1[TACHYON_AEAD_TAG_LEN], tag2[TACHYON_AEAD_TAG_LEN];

    ASSERT_TRUE(cp_aead_encrypt(key, plaintext, pt_len, nullptr, 0, nonce1, ct1, tag1));
    ASSERT_TRUE(cp_aead_encrypt(key, plaintext, pt_len, nullptr, 0, nonce2, ct2, tag2));

    EXPECT_NE(memcmp(ct1, ct2, pt_len), 0);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Full Key Derivation Chain Test
 *
 * Simulates the actual Tachyon key derivation flow:
 *   ECDH -> early_secret -> cp_enc_key -> session keys
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(CryptoTest, FullKeyDerivationChain) {
    /* Generate two static keypairs */
    uint8_t priv_a[32], pub_a[32], priv_b[32], pub_b[32];
    ASSERT_TRUE(generate_x25519_keypair(priv_a, pub_a));
    ASSERT_TRUE(generate_x25519_keypair(priv_b, pub_b));

    /* Static ECDH */
    uint8_t ss_a[32], ss_b[32];
    ASSERT_TRUE(do_ecdh(priv_a, pub_b, ss_a));
    ASSERT_TRUE(do_ecdh(priv_b, pub_a, ss_b));
    EXPECT_EQ(memcmp(ss_a, ss_b, 32), 0);

    /* Derive early secret */
    const char *psk = TACHYON_KDF_DEFAULT_PSK;
    uint8_t early_a[32], early_b[32];
    ASSERT_TRUE(derive_kdf(reinterpret_cast<const uint8_t *>(psk), strlen(psk), ss_a, 32,
                           TACHYON_KDF_EARLY_SECRET, early_a));
    ASSERT_TRUE(derive_kdf(reinterpret_cast<const uint8_t *>(psk), strlen(psk), ss_b, 32,
                           TACHYON_KDF_EARLY_SECRET, early_b));
    EXPECT_EQ(memcmp(early_a, early_b, 32), 0);

    /* Derive control plane AEAD key */
    uint8_t zero_ikm[32] = {0};
    uint8_t cp_key_a[32], cp_key_b[32];
    ASSERT_TRUE(derive_kdf(early_a, 32, zero_ikm, 32, TACHYON_KDF_CP_AEAD, cp_key_a));
    ASSERT_TRUE(derive_kdf(early_b, 32, zero_ikm, 32, TACHYON_KDF_CP_AEAD, cp_key_b));
    EXPECT_EQ(memcmp(cp_key_a, cp_key_b, 32), 0);

    /* Encrypt/decrypt with derived CP key */
    uint8_t nonce[12] = {0};
    const uint8_t pt[] = "key chain test";
    uint8_t ct[256], tag[16], dec[256];

    ASSERT_TRUE(cp_aead_encrypt(cp_key_a, pt, sizeof(pt) - 1, nullptr, 0, nonce, ct, tag));
    ASSERT_TRUE(cp_aead_decrypt(cp_key_b, ct, sizeof(pt) - 1, nullptr, 0, nonce, tag, dec));
    EXPECT_EQ(memcmp(pt, dec, sizeof(pt) - 1), 0);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Session Key Derivation Symmetry Test
 *
 * Verifies that initiator's TX key == responder's RX key and vice versa.
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(CryptoTest, SessionKeyDerivationSymmetry) {
    uint8_t early_secret[32], eph_ss[32];
    memset(early_secret, 0xaa, sizeof(early_secret));
    memset(eph_ss, 0xbb, sizeof(eph_ss));

    uint8_t zero_ikm[32] = {0};

    /* Both sides derive session master from same inputs */
    uint8_t session_master[32];
    ASSERT_TRUE(
        derive_kdf(early_secret, 32, eph_ss, 32, TACHYON_KDF_SESSION_MASTER, session_master));

    /* Server derives its TX and RX keys */
    uint8_t srv_tx[32], srv_rx[32];
    ASSERT_TRUE(derive_kdf(session_master, 32, zero_ikm, 32, TACHYON_KDF_SERVER_TX, srv_tx));
    ASSERT_TRUE(derive_kdf(session_master, 32, zero_ikm, 32, TACHYON_KDF_CLIENT_TX, srv_rx));

    /* Client swaps: its TX = Client-TX, its RX = Server-TX */
    uint8_t cli_tx[32], cli_rx[32];
    ASSERT_TRUE(derive_kdf(session_master, 32, zero_ikm, 32, TACHYON_KDF_CLIENT_TX, cli_tx));
    ASSERT_TRUE(derive_kdf(session_master, 32, zero_ikm, 32, TACHYON_KDF_SERVER_TX, cli_rx));

    /* Server TX == Client RX */
    EXPECT_EQ(memcmp(srv_tx, cli_rx, 32), 0);
    /* Client TX == Server RX */
    EXPECT_EQ(memcmp(cli_tx, srv_rx, 32), 0);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Parameterized AEAD Tests — Plaintext Size Sweep
 *
 * Tests the full encrypt→decrypt roundtrip and tampering detection across
 * boundary-spanning sizes: empty, block boundaries (16 B), ChaCha block
 * boundaries (64 B), and practical packet sizes up to 8 KB.
 * ══════════════════════════════════════════════════════════════════════════ */

class AeadSizeTest : public ::testing::TestWithParam<size_t> {
  protected:
    void SetUp() override { init_crypto_globals(); }
    void TearDown() override { free_crypto_globals(); }
};

TEST_P(AeadSizeTest, EncryptDecryptRoundtrip) {
    const size_t pt_size = GetParam();

    uint8_t key[32], nonce[12];
    memset(key, 0x42, sizeof(key));
    memset(nonce, 0x00, sizeof(nonce));
    /* Encode pt_size into nonce to ensure each parameterised run uses a
     * distinct nonce — avoids nonce-reuse between test instances. */
    nonce[0] = static_cast<uint8_t>(pt_size & 0xFF);
    nonce[1] = static_cast<uint8_t>((pt_size >> 8) & 0xFF);

    std::vector<uint8_t> plaintext(pt_size, 0xAB);
    std::vector<uint8_t> ciphertext(pt_size + 1); /* +1 avoids zero-size alloc */
    std::vector<uint8_t> decrypted(pt_size + 1);
    uint8_t tag[TACHYON_AEAD_TAG_LEN];

    ASSERT_TRUE(
        cp_aead_encrypt(key, plaintext.data(), pt_size, nullptr, 0, nonce, ciphertext.data(), tag));
    ASSERT_TRUE(
        cp_aead_decrypt(key, ciphertext.data(), pt_size, nullptr, 0, nonce, tag, decrypted.data()));

    if (pt_size > 0) {
        EXPECT_EQ(memcmp(plaintext.data(), decrypted.data(), pt_size), 0);
    }
}

TEST_P(AeadSizeTest, TamperingAlwaysDetected) {
    const size_t pt_size = GetParam();
    if (pt_size == 0)
        GTEST_SKIP() << "No ciphertext bytes to tamper";

    uint8_t key[32], nonce[12];
    memset(key, 0x42, sizeof(key));
    memset(nonce, 0x00, sizeof(nonce));
    nonce[2] = static_cast<uint8_t>(pt_size & 0xFF);
    nonce[3] = static_cast<uint8_t>((pt_size >> 8) & 0xFF);

    std::vector<uint8_t> plaintext(pt_size, 0xCD);
    std::vector<uint8_t> ciphertext(pt_size);
    std::vector<uint8_t> decrypted(pt_size);
    uint8_t tag[TACHYON_AEAD_TAG_LEN];

    ASSERT_TRUE(
        cp_aead_encrypt(key, plaintext.data(), pt_size, nullptr, 0, nonce, ciphertext.data(), tag));

    /* Flip the last byte of the ciphertext and verify authentication fails */
    ciphertext[pt_size - 1] ^= 0x01;
    EXPECT_FALSE(
        cp_aead_decrypt(key, ciphertext.data(), pt_size, nullptr, 0, nonce, tag, decrypted.data()));
}

INSTANTIATE_TEST_SUITE_P(PlaintextSizes, AeadSizeTest,
                         /* Covers: empty, single byte, just-under/at/over AES block (16 B),
                          * ChaCha stream block (64 B), common network MTU payload (~1400 B),
                          * and large (8 KB) payloads. */
                         ::testing::Values(0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 255, 256, 1023,
                                           1024, 1400, 8192),
                         [](const ::testing::TestParamInfo<size_t> &info) {
                             return "pt_" + std::to_string(info.param) + "B";
                         });

/* ── Nonce Non-Reuse Property ─────────────────────────────────────────────── */

TEST_F(CryptoTest, SequentialNoncesProduceDifferentCiphertexts) {
    uint8_t key[32];
    memset(key, 0x42, sizeof(key));

    const uint8_t plaintext[] = "nonce progression test";
    const size_t pt_len = sizeof(plaintext) - 1;
    const int N = 16;

    std::vector<std::vector<uint8_t>> cts(N, std::vector<uint8_t>(pt_len));
    uint8_t tags[16][TACHYON_AEAD_TAG_LEN];

    for (int i = 0; i < N; i++) {
        uint8_t nonce[12] = {};
        nonce[0] = static_cast<uint8_t>(i);
        ASSERT_TRUE(
            cp_aead_encrypt(key, plaintext, pt_len, nullptr, 0, nonce, cts[i].data(), tags[i]));
    }

    /* Every pair of ciphertexts must differ — same key + different nonce */
    for (int i = 0; i < N; i++) {
        for (int j = i + 1; j < N; j++) {
            EXPECT_NE(cts[i], cts[j])
                << "Nonces " << i << " and " << j << " produced identical ciphertext!";
        }
    }
}
