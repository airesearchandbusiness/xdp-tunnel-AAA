/* SPDX-License-Identifier: MIT */
/*
 * Tachyon - Modular Cipher Suite Abstraction
 *
 * Provides a registry of AEAD cipher suites so the handshake state
 * machine can select algorithms without hard-coded function calls.
 * All implementations delegate to existing OpenSSL EVP paths.
 *
 * Usage:
 *   const CipherSuite *cs = get_cipher_suite(TACHYON_CIPHER_AES256GCM);
 *   cs->encrypt(key, nonce, ...);
 *
 *   const CipherSuite *best = select_best_suite(cpu_has_aesni());
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include "../src/common.h"

/* ══════════════════════════════════════════════════════════════════════════
 * CipherSuite Interface
 * ══════════════════════════════════════════════════════════════════════════ */

struct CipherSuite {
    uint8_t     type_id;   /* TACHYON_CIPHER_* constant              */
    const char *name;      /* Human-readable identifier              */
    size_t      key_len;   /* Key size in bytes                      */
    size_t      tag_len;   /* Authentication tag size in bytes       */
    size_t      nonce_len; /* Nonce (IV) size in bytes               */

    /* Encrypt plaintext pt[pt_len] into ct[], append tag[] (tag_len bytes).
     * Returns true on success. ct must have room for pt_len bytes. */
    bool (*encrypt)(const uint8_t *key,
                    const uint8_t *nonce, size_t nonce_len,
                    const uint8_t *aad,   size_t aad_len,
                    const uint8_t *pt,    size_t pt_len,
                    uint8_t *ct, uint8_t *tag);

    /* Decrypt ct[ct_len] using tag[] into pt[].
     * Returns true on success (tag verified). */
    bool (*decrypt)(const uint8_t *key,
                    const uint8_t *nonce, size_t nonce_len,
                    const uint8_t *aad,   size_t aad_len,
                    const uint8_t *ct,    size_t ct_len,
                    const uint8_t *tag,
                    uint8_t *pt);
};

/* ══════════════════════════════════════════════════════════════════════════
 * Registry API
 * ══════════════════════════════════════════════════════════════════════════ */

/* Look up a cipher suite by type_id. Returns nullptr for unknown IDs. */
const CipherSuite *get_cipher_suite(uint8_t type_id);

/* Select the best available suite for the local hardware.
 * If has_aesni is true, prefers AES-256-GCM for throughput.
 * Otherwise falls back to ChaCha20-Poly1305 (constant-time, no AES-NI needed). */
const CipherSuite *select_best_suite(bool has_aesni);
