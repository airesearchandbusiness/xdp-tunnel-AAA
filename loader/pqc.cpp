/* SPDX-License-Identifier: MIT */
#include "pqc.h"

#include <cstring>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#if defined(TACHYON_PQC_OPENSSL) && OPENSSL_VERSION_NUMBER < 0x30500000L
#error "TACHYON_PQC_OPENSSL requires OpenSSL 3.5+ (ML-KEM native support)"
#endif

#ifdef TACHYON_PQC_OQS
#include <oqs/oqs.h>
#endif

namespace tachyon::pqc {

/* ── Backend selection ──────────────────────────────────────────────────── */

bool pqc_available() {
#if defined(TACHYON_PQC_OPENSSL) || defined(TACHYON_PQC_OQS)
    return true;
#else
    return false;
#endif
}

const char *pqc_backend() {
#if defined(TACHYON_PQC_OPENSSL)
    return "openssl-3.5+";
#elif defined(TACHYON_PQC_OQS)
    return "liboqs";
#else
    return "unavailable";
#endif
}

/* ── Key generation ─────────────────────────────────────────────────────── */

#if defined(TACHYON_PQC_OPENSSL)

static const char *ml_kem_name() { return "ML-KEM-768"; }

bool mlkem768_keygen(uint8_t *pk_out, uint8_t *sk_out) {
    bool ok = false;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, ml_kem_name(), nullptr);
    EVP_PKEY *pkey = nullptr;
    if (!ctx)
        goto out;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto out;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        goto out;

    {
        size_t pk_len = MLKEM768_PUBLIC_KEY_LEN;
        if (EVP_PKEY_get_raw_public_key(pkey, pk_out, &pk_len) <= 0 ||
            pk_len != MLKEM768_PUBLIC_KEY_LEN)
            goto out;
    }
    {
        size_t sk_len = MLKEM768_SECRET_KEY_LEN;
        if (EVP_PKEY_get_raw_private_key(pkey, sk_out, &sk_len) <= 0 ||
            sk_len != MLKEM768_SECRET_KEY_LEN)
            goto out;
    }
    ok = true;

out:
    if (pkey)
        EVP_PKEY_free(pkey);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (!ok) {
        OPENSSL_cleanse(pk_out, MLKEM768_PUBLIC_KEY_LEN);
        OPENSSL_cleanse(sk_out, MLKEM768_SECRET_KEY_LEN);
    }
    return ok;
}

bool mlkem768_encapsulate(const uint8_t *peer_pk, uint8_t *ct_out, uint8_t *ss_out) {
    bool ok = false;
    EVP_PKEY *pkey =
        EVP_PKEY_new_raw_public_key_ex(nullptr, ml_kem_name(), nullptr, peer_pk,
                                       MLKEM768_PUBLIC_KEY_LEN);
    EVP_PKEY_CTX *ctx = nullptr;
    if (!pkey)
        goto out;

    ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx || EVP_PKEY_encapsulate_init(ctx, nullptr) <= 0)
        goto out;

    {
        size_t ct_len = MLKEM768_CIPHERTEXT_LEN;
        size_t ss_len = MLKEM768_SHARED_SECRET;
        if (EVP_PKEY_encapsulate(ctx, ct_out, &ct_len, ss_out, &ss_len) <= 0 ||
            ct_len != MLKEM768_CIPHERTEXT_LEN || ss_len != MLKEM768_SHARED_SECRET)
            goto out;
    }
    ok = true;

out:
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (!ok) {
        OPENSSL_cleanse(ct_out, MLKEM768_CIPHERTEXT_LEN);
        OPENSSL_cleanse(ss_out, MLKEM768_SHARED_SECRET);
    }
    return ok;
}

bool mlkem768_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss_out) {
    bool ok = false;
    EVP_PKEY *pkey =
        EVP_PKEY_new_raw_private_key_ex(nullptr, ml_kem_name(), nullptr, sk,
                                        MLKEM768_SECRET_KEY_LEN);
    EVP_PKEY_CTX *ctx = nullptr;
    if (!pkey)
        goto out;

    ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx || EVP_PKEY_decapsulate_init(ctx, nullptr) <= 0)
        goto out;

    {
        size_t ss_len = MLKEM768_SHARED_SECRET;
        if (EVP_PKEY_decapsulate(ctx, ss_out, &ss_len, ct, MLKEM768_CIPHERTEXT_LEN) <= 0 ||
            ss_len != MLKEM768_SHARED_SECRET)
            goto out;
    }
    ok = true;

out:
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (!ok)
        OPENSSL_cleanse(ss_out, MLKEM768_SHARED_SECRET);
    return ok;
}

#elif defined(TACHYON_PQC_OQS)

bool mlkem768_keygen(uint8_t *pk_out, uint8_t *sk_out) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem)
        return false;
    bool ok = (OQS_KEM_keypair(kem, pk_out, sk_out) == OQS_SUCCESS);
    OQS_KEM_free(kem);
    if (!ok) {
        OPENSSL_cleanse(pk_out, MLKEM768_PUBLIC_KEY_LEN);
        OPENSSL_cleanse(sk_out, MLKEM768_SECRET_KEY_LEN);
    }
    return ok;
}

bool mlkem768_encapsulate(const uint8_t *peer_pk, uint8_t *ct_out, uint8_t *ss_out) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem)
        return false;
    bool ok = (OQS_KEM_encaps(kem, ct_out, ss_out, peer_pk) == OQS_SUCCESS);
    OQS_KEM_free(kem);
    if (!ok) {
        OPENSSL_cleanse(ct_out, MLKEM768_CIPHERTEXT_LEN);
        OPENSSL_cleanse(ss_out, MLKEM768_SHARED_SECRET);
    }
    return ok;
}

bool mlkem768_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss_out) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem)
        return false;
    bool ok = (OQS_KEM_decaps(kem, ss_out, ct, sk) == OQS_SUCCESS);
    OQS_KEM_free(kem);
    if (!ok)
        OPENSSL_cleanse(ss_out, MLKEM768_SHARED_SECRET);
    return ok;
}

#else /* No backend */

bool mlkem768_keygen(uint8_t *pk_out, uint8_t *sk_out) {
    memset(pk_out, 0, MLKEM768_PUBLIC_KEY_LEN);
    memset(sk_out, 0, MLKEM768_SECRET_KEY_LEN);
    return false;
}
bool mlkem768_encapsulate(const uint8_t *, uint8_t *ct_out, uint8_t *ss_out) {
    memset(ct_out, 0, MLKEM768_CIPHERTEXT_LEN);
    memset(ss_out, 0, MLKEM768_SHARED_SECRET);
    return false;
}
bool mlkem768_decapsulate(const uint8_t *, const uint8_t *, uint8_t *ss_out) {
    memset(ss_out, 0, MLKEM768_SHARED_SECRET);
    return false;
}

#endif

/* ── HKDF-SHA384 ────────────────────────────────────────────────────────── */

bool hkdf_sha384_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                         size_t ikm_len, uint8_t out[48]) {
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf)
        return false;
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx)
        return false;

    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
    const uint8_t empty_salt[1] = {0};
    const uint8_t *s = (salt && salt_len) ? salt : empty_salt;
    size_t sl = (salt && salt_len) ? salt_len : 0;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", const_cast<char *>("SHA384"), 0),
        OSSL_PARAM_construct_int("mode", &mode),
        OSSL_PARAM_construct_octet_string("salt", const_cast<uint8_t *>(s), sl),
        OSSL_PARAM_construct_octet_string("key", const_cast<uint8_t *>(ikm), ikm_len),
        OSSL_PARAM_END};

    const int rc = EVP_KDF_derive(kctx, out, 48, params);
    EVP_KDF_CTX_free(kctx);
    return rc > 0;
}

bool hybrid_combine(const uint8_t *ss_classical, size_t ss_classical_len,
                    const uint8_t *ss_pq, size_t ss_pq_len, const char *context,
                    uint8_t out[48]) {
    /* Concatenate IKM = classical || pq so a break of either primitive alone
     * cannot reveal the combined secret (per hybrid-KEX best practice). */
    uint8_t ikm[256];
    if (ss_classical_len + ss_pq_len > sizeof(ikm))
        return false;
    size_t pos = 0;
    if (ss_classical && ss_classical_len) {
        memcpy(ikm + pos, ss_classical, ss_classical_len);
        pos += ss_classical_len;
    }
    if (ss_pq && ss_pq_len) {
        memcpy(ikm + pos, ss_pq, ss_pq_len);
        pos += ss_pq_len;
    }

    const uint8_t *salt = context ? reinterpret_cast<const uint8_t *>(context) : nullptr;
    const size_t salt_len = context ? strlen(context) : 0;
    const bool ok = hkdf_sha384_extract(salt, salt_len, ikm, pos, out);
    OPENSSL_cleanse(ikm, sizeof(ikm));
    return ok;
}

} /* namespace tachyon::pqc */
