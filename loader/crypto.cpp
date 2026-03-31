/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Control Plane - Cryptographic Operations
 *
 * All crypto primitives used by the control plane: HMAC-SHA256, X25519 ECDH,
 * HKDF-SHA256 (Extract+Expand), ChaCha20-Poly1305 AEAD, and key generation.
 *
 * Security properties:
 *   - Every OpenSSL allocation is NULL-checked
 *   - ECDH detects zero shared secrets (small-order point attack)
 *   - HKDF uses proper Extract-and-Expand per RFC 5869
 *   - AEAD encrypt/decrypt propagate errors to caller
 */

#include "tachyon.h"

/* ══════════════════════════════════════════════════════════════════════════
 * Global Crypto State
 * ══════════════════════════════════════════════════════════════════════════ */

volatile sig_atomic_t g_exiting = 0;
EVP_MAC *g_mac = nullptr;
EVP_KDF *g_kdf = nullptr;

void init_crypto_globals()
{
    g_mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    g_kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!g_mac || !g_kdf) {
        LOG_ERR("Failed to fetch OpenSSL crypto engines (HMAC/HKDF)");
        exit(1);
    }
}

void free_crypto_globals()
{
    if (g_mac) { EVP_MAC_free(g_mac); g_mac = nullptr; }
    if (g_kdf) { EVP_KDF_free(g_kdf); g_kdf = nullptr; }
}

/* ══════════════════════════════════════════════════════════════════════════
 * HMAC-SHA256
 * ══════════════════════════════════════════════════════════════════════════ */

bool calc_hmac(const uint8_t *key, size_t key_len,
               const uint8_t *data, size_t data_len,
               uint8_t *out_mac)
{
    EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(g_mac);
    if (!mctx) {
        LOG_ERR("EVP_MAC_CTX_new failed");
        return false;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                         const_cast<char *>("SHA256"), 0),
        OSSL_PARAM_END
    };

    bool ok = true;
    if (EVP_MAC_init(mctx, key, key_len, params) <= 0 ||
        EVP_MAC_update(mctx, data, data_len) <= 0) {
        LOG_ERR("HMAC init/update failed");
        ok = false;
    } else {
        size_t out_len = 0;
        if (EVP_MAC_final(mctx, out_mac, &out_len, TACHYON_HMAC_LEN) <= 0) {
            LOG_ERR("HMAC final failed");
            ok = false;
        }
    }

    EVP_MAC_CTX_free(mctx);
    return ok;
}

void generate_cookie(const uint8_t *secret, uint32_t client_ip,
                     uint64_t nonce, uint64_t window,
                     uint8_t *out_cookie)
{
    uint8_t buf[20];
    memcpy(buf, &client_ip, 4);
    memcpy(buf + 4, &nonce, 8);
    memcpy(buf + 12, &window, 8);
    calc_hmac(secret, TACHYON_HMAC_LEN, buf, sizeof(buf), out_cookie);
}

/* ══════════════════════════════════════════════════════════════════════════
 * X25519 ECDH
 * ══════════════════════════════════════════════════════════════════════════ */

bool do_ecdh(const uint8_t *my_priv, const uint8_t *peer_pub,
             uint8_t *out_shared_secret)
{
    bool result = false;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519,
                                                   nullptr, my_priv, 32);
    if (!pkey) {
        LOG_ERR("ECDH: failed to create private key");
        return false;
    }

    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,
                                                   nullptr, peer_pub, 32);
    if (!peer) {
        LOG_ERR("ECDH: failed to create peer public key");
        EVP_PKEY_free(pkey);
        return false;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        LOG_ERR("ECDH: failed to create context");
        goto cleanup_keys;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer) <= 0) {
        LOG_ERR("ECDH: derive init/set_peer failed");
        goto cleanup_ctx;
    }

    {
        size_t slen = TACHYON_X25519_KEY_LEN;
        if (EVP_PKEY_derive(ctx, out_shared_secret, &slen) <= 0 ||
            slen != TACHYON_X25519_KEY_LEN) {
            LOG_ERR("ECDH: derive failed");
            goto cleanup_ctx;
        }
    }

    /* Reject zero shared secret (small-order point attack) */
    {
        uint8_t zero[TACHYON_X25519_KEY_LEN] = {0};
        if (CRYPTO_memcmp(out_shared_secret, zero, TACHYON_X25519_KEY_LEN) == 0) {
            LOG_ERR("ECDH: zero shared secret detected (possible attack)");
            OPENSSL_cleanse(out_shared_secret, TACHYON_X25519_KEY_LEN);
            goto cleanup_ctx;
        }
    }

    result = true;

cleanup_ctx:
    EVP_PKEY_CTX_free(ctx);
cleanup_keys:
    EVP_PKEY_free(peer);
    EVP_PKEY_free(pkey);
    return result;
}

/* ══════════════════════════════════════════════════════════════════════════
 * HKDF-SHA256 (Extract and Expand per RFC 5869)
 * ══════════════════════════════════════════════════════════════════════════ */

bool derive_kdf(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const char *info, uint8_t *out_key)
{
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(g_kdf);
    if (!kctx) {
        LOG_ERR("KDF: context allocation failed");
        return false;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest",
                                         const_cast<char *>("SHA256"), 0),
        OSSL_PARAM_construct_int("mode", const_cast<int *>(&(const int &)(int){EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND})),
        OSSL_PARAM_construct_octet_string("salt",
                                          const_cast<uint8_t *>(salt), salt_len),
        OSSL_PARAM_construct_octet_string("key",
                                          const_cast<uint8_t *>(ikm), ikm_len),
        OSSL_PARAM_construct_octet_string("info",
                                          const_cast<char *>(info), strlen(info)),
        OSSL_PARAM_END
    };

    int ret = EVP_KDF_derive(kctx, out_key, TACHYON_AEAD_KEY_LEN, params);
    EVP_KDF_CTX_free(kctx);

    if (ret <= 0) {
        LOG_ERR("KDF: derivation failed for label '%s'", info);
        return false;
    }
    return true;
}

/* ══════════════════════════════════════════════════════════════════════════
 * ChaCha20-Poly1305 AEAD (Control Plane Encryption)
 * ══════════════════════════════════════════════════════════════════════════ */

bool cp_aead_encrypt(const uint8_t *key, const uint8_t *pt, size_t pt_len,
                     const uint8_t *ad, size_t ad_len,
                     const uint8_t *nonce,
                     uint8_t *ct, uint8_t *tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG_ERR("AEAD encrypt: context allocation failed");
        return false;
    }

    int len;
    bool ok = false;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(),
                           nullptr, key, nonce) <= 0)
        goto out;

    if (ad && ad_len > 0) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, ad, ad_len) <= 0)
            goto out;
    }

    if (EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len) <= 0)
        goto out;

    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) <= 0)
        goto out;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                            TACHYON_AEAD_TAG_LEN, tag) <= 0)
        goto out;

    ok = true;

out:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok)
        LOG_ERR("AEAD encrypt failed");
    return ok;
}

bool cp_aead_decrypt(const uint8_t *key, const uint8_t *ct, size_t ct_len,
                     const uint8_t *ad, size_t ad_len,
                     const uint8_t *nonce, const uint8_t *tag,
                     uint8_t *pt)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG_ERR("AEAD decrypt: context allocation failed");
        return false;
    }

    int len;
    bool ok = false;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(),
                           nullptr, key, nonce) <= 0)
        goto out;

    if (ad && ad_len > 0) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, ad, ad_len) <= 0)
            goto out;
    }

    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) <= 0)
        goto out;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                            TACHYON_AEAD_TAG_LEN,
                            const_cast<uint8_t *>(tag)) <= 0)
        goto out;

    ok = (EVP_DecryptFinal_ex(ctx, pt + len, &len) > 0);

out:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* ══════════════════════════════════════════════════════════════════════════
 * X25519 Key Generation
 * ══════════════════════════════════════════════════════════════════════════ */

bool generate_x25519_keypair(uint8_t *priv_out, uint8_t *pub_out)
{
    EVP_PKEY *pk = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
    if (!pk) {
        LOG_ERR("X25519 keygen failed");
        return false;
    }

    size_t len = TACHYON_X25519_KEY_LEN;
    bool ok = (EVP_PKEY_get_raw_private_key(pk, priv_out, &len) > 0);
    if (ok) {
        len = TACHYON_X25519_KEY_LEN;
        ok = (EVP_PKEY_get_raw_public_key(pk, pub_out, &len) > 0);
    }

    EVP_PKEY_free(pk);
    if (!ok)
        LOG_ERR("X25519 key extraction failed");
    return ok;
}

bool get_public_key(const uint8_t *priv, uint8_t *pub_out)
{
    EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519,
                                                 nullptr, priv, 32);
    if (!pk) {
        LOG_ERR("Failed to load private key");
        return false;
    }

    size_t len = TACHYON_X25519_KEY_LEN;
    bool ok = (EVP_PKEY_get_raw_public_key(pk, pub_out, &len) > 0);
    EVP_PKEY_free(pk);
    return ok;
}
