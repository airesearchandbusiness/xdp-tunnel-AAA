/* SPDX-License-Identifier: MIT */
#include "ratchet.h"

#include <cstring>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>

#include "secmem.h"

namespace tachyon::ratchet {

namespace {

/*
 * HKDF-Expand-SHA256 over a single info label. Kept local to this TU
 * because pqc.cpp exposes SHA384; the ratchet uses SHA256 so that each
 * chain step costs ~half the CPU of the handshake combiner.
 */
bool hkdf_sha256_expand(const uint8_t prk[32], const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len) {
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf)
        return false;
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx)
        return false;

    int mode = EVP_PKEY_HKDEF_MODE_EXPAND_ONLY;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char *>("SHA2-256"), 0),
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t *>(prk), 32),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<uint8_t *>(info),
                                          info_len),
        OSSL_PARAM_construct_end(),
    };
    const bool ok = EVP_KDF_derive(ctx, out, out_len, params) == 1;
    EVP_KDF_CTX_free(ctx);
    return ok;
}

constexpr const char *LABEL_CHAIN_INIT = "tch5-ratchet-chain";
constexpr const char *LABEL_CHAIN_NEXT = "tch5-ratchet-next";
constexpr const char *LABEL_MSG_KEY    = "tch5-ratchet-msg";

/* Build the info string "label" || counter_be8 for msg-key derivation. */
void write_counter_be(uint8_t out[8], uint64_t c) {
    for (int i = 7; i >= 0; --i) {
        out[i] = static_cast<uint8_t>(c & 0xFF);
        c >>= 8;
    }
}

} /* namespace */

void ratchet_init(SendState &s, const uint8_t root[ROOT_KEY_LEN]) {
    ratchet_wipe(s);
    /* Derive the initial chain key from the root using a fixed domain tag.
     * This keeps the root usable for other purposes (e.g., a parallel
     * send/recv pair) without collision. */
    hkdf_sha256_expand(root, reinterpret_cast<const uint8_t *>(LABEL_CHAIN_INIT),
                       std::strlen(LABEL_CHAIN_INIT), s.chain_key, ROOT_KEY_LEN);
    s.counter = 0;
}

void ratchet_wipe(SendState &s) {
    secmem::secure_zero(s.chain_key, sizeof(s.chain_key));
    s.counter = 0;
}

bool ratchet_next(SendState &s, uint8_t out_key[MSG_KEY_LEN],
                  uint8_t out_nonce[NONCE_PREFIX_LEN], uint64_t *out_counter) {
    if (s.counter == UINT64_MAX)
        return false; /* overflow — caller must rekey */

    uint8_t info[32];
    const size_t label_len = std::strlen(LABEL_MSG_KEY);
    std::memcpy(info, LABEL_MSG_KEY, label_len);
    write_counter_be(info + label_len, s.counter);

    uint8_t derived[DERIVED_LEN];
    if (!hkdf_sha256_expand(s.chain_key, info, label_len + 8, derived, DERIVED_LEN))
        return false;

    std::memcpy(out_key, derived, MSG_KEY_LEN);
    std::memcpy(out_nonce, derived + MSG_KEY_LEN, NONCE_PREFIX_LEN);
    if (out_counter)
        *out_counter = s.counter;
    secmem::secure_zero(derived, sizeof(derived));

    /* Advance the chain: chain_key' = HKDF(chain_key, "next"). We derive
     * into a temporary so a crypto failure cannot desync the counter. */
    uint8_t next_chain[ROOT_KEY_LEN];
    const bool adv_ok = hkdf_sha256_expand(s.chain_key,
                                           reinterpret_cast<const uint8_t *>(LABEL_CHAIN_NEXT),
                                           std::strlen(LABEL_CHAIN_NEXT), next_chain,
                                           ROOT_KEY_LEN);
    if (!adv_ok) {
        secmem::secure_zero(next_chain, sizeof(next_chain));
        secmem::secure_zero(out_key, MSG_KEY_LEN);
        secmem::secure_zero(out_nonce, NONCE_PREFIX_LEN);
        return false;
    }
    secmem::secure_zero(s.chain_key, sizeof(s.chain_key));
    std::memcpy(s.chain_key, next_chain, ROOT_KEY_LEN);
    secmem::secure_zero(next_chain, sizeof(next_chain));
    ++s.counter;
    return true;
}

bool ratchet_derive_at(const uint8_t root[ROOT_KEY_LEN], uint64_t counter,
                       uint8_t out_key[MSG_KEY_LEN], uint8_t out_nonce[NONCE_PREFIX_LEN]) {
    /* Pure function. Mix counter and a unique sub-label into info so that
     * ratchet_derive_at(root, i) ≠ ratchet_next output at step i (those
     * two schemes serve different purposes and must not collide). */
    static constexpr const char *LABEL_AT = "tch5-ratchet-at";
    uint8_t info[32];
    const size_t label_len = std::strlen(LABEL_AT);
    std::memcpy(info, LABEL_AT, label_len);
    write_counter_be(info + label_len, counter);

    uint8_t derived[DERIVED_LEN];
    const bool ok = hkdf_sha256_expand(root, info, label_len + 8, derived, DERIVED_LEN);
    if (ok) {
        std::memcpy(out_key, derived, MSG_KEY_LEN);
        std::memcpy(out_nonce, derived + MSG_KEY_LEN, NONCE_PREFIX_LEN);
    }
    secmem::secure_zero(derived, sizeof(derived));
    return ok;
}

} /* namespace tachyon::ratchet */
