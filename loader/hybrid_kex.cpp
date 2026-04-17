/* SPDX-License-Identifier: MIT */
#include "hybrid_kex.h"

#include <cerrno>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace tachyon::hkex {

using namespace tachyon::pqc;

/* ── X25519 helpers ────────────────────────────────────────────────────────
 *
 * Wraps EVP_PKEY_X25519 so the rest of the file can think of X25519 as
 * "make keypair → do DH → 32-byte shared secret" without manual EVP
 * bookkeeping leaking into every call site. The raw key APIs land in
 * OpenSSL 1.1.1, so these paths work on every supported distro.
 */

static bool x25519_keygen(uint8_t pk[X25519_PK_LEN], uint8_t sk[X25519_SK_LEN]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx)
        return false;

    EVP_PKEY *key = nullptr;
    bool ok = EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &key) == 1;
    EVP_PKEY_CTX_free(ctx);
    if (!ok) {
        EVP_PKEY_free(key);
        return false;
    }

    size_t pk_len = X25519_PK_LEN, sk_len = X25519_SK_LEN;
    ok = EVP_PKEY_get_raw_public_key(key, pk, &pk_len) == 1 &&
         EVP_PKEY_get_raw_private_key(key, sk, &sk_len) == 1 &&
         pk_len == X25519_PK_LEN && sk_len == X25519_SK_LEN;
    EVP_PKEY_free(key);
    return ok;
}

static bool x25519_derive(const uint8_t sk[X25519_SK_LEN],
                          const uint8_t peer_pk[X25519_PK_LEN],
                          uint8_t ss[X25519_SS_LEN]) {
    EVP_PKEY *my = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, sk, X25519_SK_LEN);
    EVP_PKEY *peer =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pk, X25519_PK_LEN);
    if (!my || !peer) {
        EVP_PKEY_free(my);
        EVP_PKEY_free(peer);
        return false;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my, nullptr);
    size_t len = X25519_SS_LEN;
    bool ok = ctx && EVP_PKEY_derive_init(ctx) == 1 &&
              EVP_PKEY_derive_set_peer(ctx, peer) == 1 && EVP_PKEY_derive(ctx, ss, &len) == 1 &&
              len == X25519_SS_LEN;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(my);
    EVP_PKEY_free(peer);
    return ok;
}

/* ── Combiner ─────────────────────────────────────────────────────────────
 *
 * HKDF-Extract-SHA384 over the concatenation ss_classical || ss_pq with a
 * caller-supplied salt.  The salt MUST include a handshake transcript
 * binding or at minimum an application label, otherwise combiner outputs
 * across deployments can collide.  The pqc::hkdf_sha384_extract helper
 * already encapsulates the OpenSSL EVP_KDF dance.
 */
static bool combine(const uint8_t ss_x25519[X25519_SS_LEN],
                    const uint8_t ss_mlkem[MLKEM768_SHARED_SECRET],
                    const uint8_t *salt, size_t salt_len, uint8_t out[HYBRID_SS_LEN]) {
    uint8_t ikm[X25519_SS_LEN + MLKEM768_SHARED_SECRET];
    std::memcpy(ikm, ss_x25519, X25519_SS_LEN);
    std::memcpy(ikm + X25519_SS_LEN, ss_mlkem, MLKEM768_SHARED_SECRET);
    const bool ok = hkdf_sha384_extract(salt, salt_len, ikm, sizeof(ikm), out);
    /* ikm holds both raw KEM secrets — scrub before returning. */
    OPENSSL_cleanse(ikm, sizeof(ikm));
    return ok;
}

/* ── Public API ───────────────────────────────────────────────────────── */

bool hybrid_available() { return pqc_available(); }

bool hybrid_keygen(uint8_t pk[HYBRID_PK_LEN], uint8_t sk[HYBRID_SK_LEN]) {
    if (!pqc_available()) {
        errno = ENOTSUP;
        return false;
    }
    uint8_t x_pk[X25519_PK_LEN], x_sk[X25519_SK_LEN];
    if (!x25519_keygen(x_pk, x_sk))
        return false;

    uint8_t m_pk[MLKEM768_PUBLIC_KEY_LEN], m_sk[MLKEM768_SECRET_KEY_LEN];
    if (!mlkem768_keygen(m_pk, m_sk)) {
        OPENSSL_cleanse(x_sk, sizeof(x_sk));
        return false;
    }

    std::memcpy(pk, x_pk, X25519_PK_LEN);
    std::memcpy(pk + X25519_PK_LEN, m_pk, MLKEM768_PUBLIC_KEY_LEN);
    std::memcpy(sk, x_sk, X25519_SK_LEN);
    std::memcpy(sk + X25519_SK_LEN, m_sk, MLKEM768_SECRET_KEY_LEN);

    /* The assembled sk buffer now owns the secrets; wipe our locals. */
    OPENSSL_cleanse(x_sk, sizeof(x_sk));
    OPENSSL_cleanse(m_sk, sizeof(m_sk));
    return true;
}

bool hybrid_encapsulate(const uint8_t peer_pk[HYBRID_PK_LEN], const uint8_t *context,
                        size_t context_len, uint8_t ct[HYBRID_CT_LEN],
                        uint8_t ss[HYBRID_SS_LEN]) {
    if (!pqc_available()) {
        errno = ENOTSUP;
        return false;
    }

    /* Draw an ephemeral X25519 keypair; the public half ships in ct[0..32]. */
    uint8_t e_pk[X25519_PK_LEN], e_sk[X25519_SK_LEN];
    if (!x25519_keygen(e_pk, e_sk))
        return false;

    uint8_t ss_x[X25519_SS_LEN];
    const bool dh_ok = x25519_derive(e_sk, peer_pk, ss_x);
    OPENSSL_cleanse(e_sk, sizeof(e_sk));
    if (!dh_ok)
        return false;

    uint8_t mct[MLKEM768_CIPHERTEXT_LEN], ss_m[MLKEM768_SHARED_SECRET];
    if (!mlkem768_encapsulate(peer_pk + X25519_PK_LEN, mct, ss_m)) {
        OPENSSL_cleanse(ss_x, sizeof(ss_x));
        return false;
    }

    const bool combine_ok = combine(ss_x, ss_m, context, context_len, ss);
    OPENSSL_cleanse(ss_x, sizeof(ss_x));
    OPENSSL_cleanse(ss_m, sizeof(ss_m));
    if (!combine_ok)
        return false;

    std::memcpy(ct, e_pk, X25519_PK_LEN);
    std::memcpy(ct + X25519_PK_LEN, mct, MLKEM768_CIPHERTEXT_LEN);
    return true;
}

bool hybrid_decapsulate(const uint8_t sk[HYBRID_SK_LEN], const uint8_t ct[HYBRID_CT_LEN],
                        const uint8_t *context, size_t context_len,
                        uint8_t ss[HYBRID_SS_LEN]) {
    if (!pqc_available()) {
        errno = ENOTSUP;
        return false;
    }

    uint8_t ss_x[X25519_SS_LEN];
    if (!x25519_derive(sk, ct, ss_x)) /* local x25519_sk × peer_ephemeral_pk */
        return false;

    uint8_t ss_m[MLKEM768_SHARED_SECRET];
    /* ML-KEM decaps always "succeeds" — on tampered ct it returns a
     * pseudorandom secret per FIPS 203 §6.3 implicit rejection. Treat
     * false here as a true implementation failure, not a protocol one. */
    if (!mlkem768_decapsulate(sk + X25519_SK_LEN, ct + X25519_PK_LEN, ss_m)) {
        OPENSSL_cleanse(ss_x, sizeof(ss_x));
        return false;
    }

    const bool ok = combine(ss_x, ss_m, context, context_len, ss);
    OPENSSL_cleanse(ss_x, sizeof(ss_x));
    OPENSSL_cleanse(ss_m, sizeof(ss_m));
    return ok;
}

} /* namespace tachyon::hkex */
