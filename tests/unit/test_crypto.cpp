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

/* RFC 7748 Section 6.1 - X25519 Known-Answer Test
 *
 *   Alice private : 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
 *   Alice public  : 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
 *   Bob   private : 5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
 *   Bob   public  : de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
 *   Shared secret : 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
 */
TEST_F(CryptoTest, X25519_RFC7748_Section6_1) {
    auto alice_priv = from_hex("77076d0a7318a57d3c16c17251b26645"
                               "df4c2f87ebc0992ab177fba51db92c2a");
    auto alice_pub_expected = from_hex("8520f0098930a754748b7ddcb43ef75a"
                                       "0dbf3a0d26381af4eba4a98eaa9b4e6a");
    auto bob_priv = from_hex("5dab087e624a8a4b79e17f8b83800ee6"
                             "6f3bb1292618b6fd1c2f8b27ff88e0eb");
    auto bob_pub_expected = from_hex("de9edb7d7b7dc1b4d35b61c2ece43537"
                                     "3f8343c85b78674dadfc7e146f882b4f");
    auto shared_expected = from_hex("4a5d9d5ba4ce2de1728e3bf480350f25"
                                    "e07e21c947d19e3376f09b3c1e161742");

    /* Public-key derivation must match the RFC */
    uint8_t alice_pub[32], bob_pub[32];
    ASSERT_TRUE(get_public_key(alice_priv.data(), alice_pub));
    ASSERT_TRUE(get_public_key(bob_priv.data(), bob_pub));

    EXPECT_EQ(to_hex(alice_pub, 32), to_hex(alice_pub_expected.data(), 32))
        << "Alice public key does not match RFC 7748 Section 6.1";
    EXPECT_EQ(to_hex(bob_pub, 32), to_hex(bob_pub_expected.data(), 32))
        << "Bob public key does not match RFC 7748 Section 6.1";

    /* ECDH in both directions yields the RFC shared secret */
    uint8_t ss_ab[32], ss_ba[32];
    ASSERT_TRUE(do_ecdh(alice_priv.data(), bob_pub, ss_ab));
    ASSERT_TRUE(do_ecdh(bob_priv.data(), alice_pub, ss_ba));

    EXPECT_EQ(to_hex(ss_ab, 32), to_hex(shared_expected.data(), 32))
        << "Alice->Bob shared secret does not match RFC 7748 Section 6.1";
    EXPECT_EQ(to_hex(ss_ba, 32), to_hex(shared_expected.data(), 32))
        << "Bob->Alice shared secret does not match RFC 7748 Section 6.1";
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

/* RFC 5869 Appendix A.1 - HKDF-SHA256 Extract-and-Expand Known-Answer Test
 *
 *   IKM  : 0b × 22
 *   salt : 000102030405060708090a0b0c  (13 bytes)
 *   info : f0f1f2f3f4f5f6f7f8f9         (10 bytes, null-free so safe as C string)
 *   L=42 OKM: 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
 *
 * Since HKDF-Expand produces a continuous keystream, requesting only L=32
 * yields the first 32 bytes of the above OKM, which is what derive_kdf() returns.
 */
TEST_F(CryptoTest, Hkdf_RFC5869_Appendix_A_1) {
    uint8_t ikm[22];
    memset(ikm, 0x0b, sizeof(ikm));
    auto salt = from_hex("000102030405060708090a0b0c");
    const char *info = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9";

    auto expected_first32 =
        from_hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf");

    uint8_t out[TACHYON_AEAD_KEY_LEN];
    ASSERT_TRUE(derive_kdf(salt.data(), salt.size(), ikm, sizeof(ikm), info, out));

    EXPECT_EQ(to_hex(out, TACHYON_AEAD_KEY_LEN),
              to_hex(expected_first32.data(), expected_first32.size()))
        << "HKDF-SHA256 first 32 bytes do not match RFC 5869 Appendix A.1";
}

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

/* RFC 8439 Section 2.8.2 - ChaCha20-Poly1305 AEAD Known-Answer Test
 *
 *   Key        : 808182...9e9f                              (32 bytes)
 *   Nonce (IV) : 070000004041424344454647                   (12 bytes)
 *   AAD        : 50515253c0c1c2c3c4c5c6c7                   (12 bytes)
 *   Plaintext  : "Ladies and Gentlemen of the class of '99: ..." (114 bytes)
 *   Ciphertext : d31a8d34...6116
 *   Tag (Poly1305): 1ae10b594f09e26a7e902ecbd0600691
 */
TEST_F(CryptoTest, AeadRFC8439_Section2_8_2) {
    auto key = from_hex("808182838485868788898a8b8c8d8e8f"
                        "909192939495969798999a9b9c9d9e9f");
    auto nonce = from_hex("070000004041424344454647");
    auto aad = from_hex("50515253c0c1c2c3c4c5c6c7");

    const char *pt_str = "Ladies and Gentlemen of the class of '99: "
                         "If I could offer you only one tip for the future, "
                         "sunscreen would be it.";
    const size_t pt_len = strlen(pt_str);
    ASSERT_EQ(pt_len, 114u);

    auto expected_ct = from_hex("d31a8d34648e60db7b86afbc53ef7ec2"
                                "a4aded51296e08fea9e2b5a736ee62d6"
                                "3dbea45e8ca9671282fafb69da92728b"
                                "1a71de0a9e060b2905d6a5b67ecd3b36"
                                "92ddbd7f2d778b8c9803aee328091b58"
                                "fab324e4fad675945585808b4831d7bc"
                                "3ff4def08e4b7a9de576d26586cec64b"
                                "6116");
    auto expected_tag = from_hex("1ae10b594f09e26a7e902ecbd0600691");

    std::vector<uint8_t> ct(pt_len);
    uint8_t tag[TACHYON_AEAD_TAG_LEN];

    ASSERT_TRUE(cp_aead_encrypt(key.data(), reinterpret_cast<const uint8_t *>(pt_str), pt_len,
                                aad.data(), aad.size(), nonce.data(), ct.data(), tag));

    EXPECT_EQ(to_hex(ct.data(), ct.size()), to_hex(expected_ct.data(), expected_ct.size()))
        << "Ciphertext does not match RFC 8439 Section 2.8.2";
    EXPECT_EQ(to_hex(tag, TACHYON_AEAD_TAG_LEN), to_hex(expected_tag.data(), expected_tag.size()))
        << "Tag does not match RFC 8439 Section 2.8.2";

    /* Decrypt roundtrip recovers the plaintext */
    std::vector<uint8_t> decrypted(pt_len);
    ASSERT_TRUE(cp_aead_decrypt(key.data(), ct.data(), pt_len, aad.data(), aad.size(), nonce.data(),
                                tag, decrypted.data()));
    EXPECT_EQ(memcmp(decrypted.data(), pt_str, pt_len), 0);
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

/* ══════════════════════════════════════════════════════════════════════════
 * RFC 4231 HMAC-SHA256 Known-Answer Tests
 *
 * Test vectors from IETF RFC 4231 §4 (Test Cases for HMAC-SHA-256).
 * These verify that our HMAC implementation is correct against the standard,
 * not merely internally consistent.
 * ══════════════════════════════════════════════════════════════════════════ */

/* RFC 4231 Test Case 1
 * Key  : 20 × 0x0b
 * Data : "Hi There"
 * HMAC : b0344c61d8db38535ca8afceaf0bf12b 881dc200c9833da726e9376c2e32cff7 */
TEST_F(CryptoTest, HmacSha256_RFC4231_TC1) {
    uint8_t key[20];
    memset(key, 0x0b, sizeof(key));

    const char *data = "Hi There";
    uint8_t mac[TACHYON_HMAC_LEN];
    ASSERT_TRUE(calc_hmac(key, sizeof(key), reinterpret_cast<const uint8_t *>(data), 8, mac));

    const auto expected = from_hex("b0344c61d8db38535ca8afceaf0bf12b"
                                   "881dc200c9833da726e9376c2e32cff7");
    EXPECT_EQ(to_hex(mac, TACHYON_HMAC_LEN), to_hex(expected.data(), expected.size()))
        << "HMAC-SHA256 result does not match RFC 4231 TC1";
}

/* RFC 4231 Test Case 2
 * Key  : "Jefe" (4 bytes)
 * Data : "what do ya want for nothing?"
 * HMAC : 5bdcc146bf60754e6a042426089575c7 5a003f089d2739839dec58b964ec3843
 * (verified against OpenSSL 3.x CLI: echo -n '...' | openssl dgst -sha256 -hmac 'Jefe') */
TEST_F(CryptoTest, HmacSha256_RFC4231_TC2) {
    const char *key = "Jefe";
    const char *data = "what do ya want for nothing?";
    uint8_t mac[TACHYON_HMAC_LEN];
    ASSERT_TRUE(calc_hmac(reinterpret_cast<const uint8_t *>(key), 4,
                          reinterpret_cast<const uint8_t *>(data), 28, mac));

    const auto expected = from_hex("5bdcc146bf60754e6a042426089575c7"
                                   "5a003f089d2739839dec58b964ec3843");
    EXPECT_EQ(to_hex(mac, TACHYON_HMAC_LEN), to_hex(expected.data(), expected.size()))
        << "HMAC-SHA256 result does not match RFC 4231 TC2";
}

/* RFC 4231 Test Case 3
 * Key  : 20 × 0xaa
 * Data : 50 × 0xdd
 * HMAC : 773ea91e36800e46854db8ebd09181a7 2959098b3ef8c122d9635514ced565fe */
TEST_F(CryptoTest, HmacSha256_RFC4231_TC3) {
    uint8_t key[20];
    memset(key, 0xaa, sizeof(key));

    uint8_t data[50];
    memset(data, 0xdd, sizeof(data));

    uint8_t mac[TACHYON_HMAC_LEN];
    ASSERT_TRUE(calc_hmac(key, sizeof(key), data, sizeof(data), mac));

    const auto expected = from_hex("773ea91e36800e46854db8ebd09181a7"
                                   "2959098b3ef8c122d9635514ced565fe");
    EXPECT_EQ(to_hex(mac, TACHYON_HMAC_LEN), to_hex(expected.data(), expected.size()))
        << "HMAC-SHA256 result does not match RFC 4231 TC3";
}

/* ══════════════════════════════════════════════════════════════════════════
 * Runtime Wire-Format Layout Verification
 *
 * Belt-and-suspenders complement to the compile-time static_assert checks
 * in common.h.  Catches size mismatches that slip through on compilers
 * that differ in their struct padding behaviour.
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(WireFormatTest, GhostHeaderSizeAndOffsets) {
    EXPECT_EQ(sizeof(struct tachyon_ghost_hdr), 20u);
    EXPECT_EQ(offsetof(struct tachyon_ghost_hdr, session_id), 4u);
    EXPECT_EQ(offsetof(struct tachyon_ghost_hdr, seq), 8u);
    EXPECT_EQ(offsetof(struct tachyon_ghost_hdr, nonce_salt), 16u);
}

TEST(WireFormatTest, ControlPlaneMessageSizes) {
    EXPECT_EQ(sizeof(struct tachyon_msg_init), 20u);
    EXPECT_EQ(sizeof(struct tachyon_msg_cookie), 48u);
    EXPECT_EQ(sizeof(struct tachyon_msg_auth), 100u);
    EXPECT_EQ(sizeof(struct tachyon_msg_finish), 64u);
    EXPECT_EQ(sizeof(struct tachyon_msg_keepalive), 48u);
}

TEST(WireFormatTest, MapValueSizes) {
    EXPECT_EQ(sizeof(struct tachyon_key_init), 68u);
    EXPECT_EQ(sizeof(struct tachyon_stats), 112u);
    EXPECT_EQ(sizeof(struct tachyon_event), 24u);
    EXPECT_EQ(sizeof(struct tachyon_config), 4u);
    EXPECT_EQ(sizeof(struct tachyon_lpm_key_v4), 8u);
    EXPECT_EQ(sizeof(struct tachyon_rate_cfg), 32u);
}

TEST(WireFormatTest, UserspaceStructsMatchBpfMapTypes) {
    EXPECT_EQ(sizeof(MsgInit), sizeof(struct tachyon_msg_init));
    EXPECT_EQ(sizeof(MsgCookie), sizeof(struct tachyon_msg_cookie));
    EXPECT_EQ(sizeof(MsgAuth), sizeof(struct tachyon_msg_auth));
    EXPECT_EQ(sizeof(MsgFinish), sizeof(struct tachyon_msg_finish));
    EXPECT_EQ(sizeof(MsgKeepalive), sizeof(struct tachyon_msg_keepalive));
    EXPECT_EQ(sizeof(userspace_config), sizeof(struct tachyon_config));
    EXPECT_EQ(sizeof(userspace_key_init), sizeof(struct tachyon_key_init));
    EXPECT_EQ(sizeof(userspace_stats), sizeof(struct tachyon_stats));
}

/* ══════════════════════════════════════════════════════════════════════════
 * Forward Secrecy Key Ratchet Tests
 *
 * Verify that the key ratchet derivation produces unique, irreversible
 * key chains — each ratchet step produces a completely different key,
 * and knowing key[N] does not reveal key[N-1].
 * ══════════════════════════════════════════════════════════════════════════ */

TEST_F(CryptoTest, KeyRatchetProducesUniqueKeys) {
    uint8_t chain[32], key[32];
    memset(chain, 0xaa, 32);
    memset(key, 0xbb, 32);

    uint8_t keys[4][32];
    for (int i = 0; i < 4; i++) {
        uint8_t new_key[32];
        ASSERT_TRUE(derive_kdf(chain, 32, key, 32, TACHYON_KDF_KEY_RATCHET, new_key));
        memcpy(keys[i], new_key, 32);

        /* Advance chain */
        uint8_t new_chain[32];
        ASSERT_TRUE(derive_kdf(chain, 32, new_key, 32, TACHYON_KDF_DECOY_SEED, new_chain));
        memcpy(chain, new_chain, 32);
        memcpy(key, new_key, 32);
    }

    /* Each ratchet step must produce a distinct key */
    for (int i = 0; i < 4; i++) {
        for (int j = i + 1; j < 4; j++) {
            EXPECT_NE(memcmp(keys[i], keys[j], 32), 0)
                << "Ratchet keys " << i << " and " << j << " collide";
        }
    }
}

TEST_F(CryptoTest, KeyRatchetIsDeterministic) {
    uint8_t chain[32], key[32];
    memset(chain, 0xcc, 32);
    memset(key, 0xdd, 32);

    uint8_t result1[32], result2[32];
    ASSERT_TRUE(derive_kdf(chain, 32, key, 32, TACHYON_KDF_KEY_RATCHET, result1));

    /* Same inputs must produce same output */
    ASSERT_TRUE(derive_kdf(chain, 32, key, 32, TACHYON_KDF_KEY_RATCHET, result2));
    EXPECT_EQ(memcmp(result1, result2, 32), 0);
}
