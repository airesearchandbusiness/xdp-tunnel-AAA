/* SPDX-License-Identifier: MIT */
/*
 * Tachyon - Post-Quantum Hybrid KEM (X25519 + ML-KEM-768)
 *
 * This file provides a feature-gated post-quantum hybrid key encapsulation
 * mechanism. When enabled (cmake -DTACHYON_PQ=ON with liboqs installed),
 * the handshake augments X25519 ECDH with ML-KEM-768 (Kyber768) to provide
 * "harvest now, decrypt later" resistance against quantum adversaries.
 *
 * Security model (hybrid KEM):
 *   shared_secret = HKDF-SHA256(
 *       IKM  = X25519_ss || Kyber768_ss,
 *       info = "Tachyon-PQ-Hybrid",
 *   )
 *
 * Combining both shared secrets means security holds as long as EITHER
 * X25519 OR ML-KEM-768 is unbroken — a classical attacker gains nothing
 * from the PQ component; a quantum attacker is stopped by the PQ component.
 *
 * When TACHYON_PQ is not defined (default), this header provides stub types
 * and functions that compile to no-ops, leaving zero overhead on the binary.
 *
 * Build:
 *   cmake -B build -S tests -DTACHYON_PQ=ON          (requires liboqs >= 0.10)
 *   cmake -B build -S tests                           (classic X25519 only)
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

/* ══════════════════════════════════════════════════════════════════════════
 * Protocol Constants (defined regardless of TACHYON_PQ)
 * ══════════════════════════════════════════════════════════════════════════ */

/* KDF label for the hybrid IKM combination */
#define TACHYON_KDF_PQ_HYBRID "Tachyon-PQ-Hybrid"

/* Flag bit in MsgInit.flags / MsgAuth.flags signalling PQ KEM in use */
#define TACHYON_FLAG_PQ 0x02

/* ML-KEM-768 wire sizes (per NIST FIPS 203) */
#define TACHYON_PQ_PK_LEN  1184  /* ML-KEM-768 public key bytes   */
#define TACHYON_PQ_SK_LEN  2400  /* ML-KEM-768 secret key bytes   */
#define TACHYON_PQ_CT_LEN  1088  /* ML-KEM-768 ciphertext bytes   */
#define TACHYON_PQ_SS_LEN    32  /* ML-KEM-768 shared secret bytes */

#ifdef TACHYON_PQ
/* ══════════════════════════════════════════════════════════════════════════
 * Live Implementation (requires liboqs)
 * ══════════════════════════════════════════════════════════════════════════ */

#include <oqs/oqs.h>

struct PqKemState {
    std::vector<uint8_t> pk;  /* ML-KEM-768 public key  (TACHYON_PQ_PK_LEN bytes) */
    std::vector<uint8_t> sk;  /* ML-KEM-768 secret key  (TACHYON_PQ_SK_LEN bytes) */
};

/* Generate an ML-KEM-768 keypair. Returns false on failure. */
inline bool pq_kem_keygen(PqKemState &state) {
    state.pk.resize(OQS_KEM_ml_kem_768_length_public_key);
    state.sk.resize(OQS_KEM_ml_kem_768_length_secret_key);
    OQS_STATUS st = OQS_KEM_ml_kem_768_keypair(state.pk.data(), state.sk.data());
    if (st != OQS_SUCCESS) {
        state.pk.clear();
        state.sk.clear();
        return false;
    }
    return true;
}

/* Encapsulate to peer_pk. Writes ciphertext to ct, shared secret to ss[32].
 * ct must be at least TACHYON_PQ_CT_LEN bytes. */
inline bool pq_kem_encap(const uint8_t *peer_pk, std::vector<uint8_t> &ct,
                          uint8_t ss[TACHYON_PQ_SS_LEN]) {
    ct.resize(OQS_KEM_ml_kem_768_length_ciphertext);
    OQS_STATUS st = OQS_KEM_ml_kem_768_encaps(ct.data(), ss, peer_pk);
    if (st != OQS_SUCCESS) {
        ct.clear();
        return false;
    }
    return true;
}

/* Decapsulate ct using secret key in state. Writes shared secret to ss[32]. */
inline bool pq_kem_decap(const PqKemState &state, const uint8_t *ct,
                          uint8_t ss[TACHYON_PQ_SS_LEN]) {
    if (state.sk.empty())
        return false;
    OQS_STATUS st = OQS_KEM_ml_kem_768_decaps(ss, ct, state.sk.data());
    return st == OQS_SUCCESS;
}

/* Combine X25519 and ML-KEM shared secrets via HKDF-SHA256.
 * x25519_ss: 32 bytes (X25519 shared secret)
 * kyber_ss:  32 bytes (ML-KEM-768 shared secret)
 * out:       32 bytes (combined session key material) */
inline bool pq_combine_secrets(const uint8_t *x25519_ss, const uint8_t *kyber_ss,
                                uint8_t *out) {
    /* Concatenate both shared secrets as IKM */
    uint8_t ikm[64];
    memcpy(ikm,      x25519_ss, 32);
    memcpy(ikm + 32, kyber_ss,  32);

    /* Use a fixed all-zero salt (HKDF spec allows this) */
    static const uint8_t zero_salt[32] = {0};

    /* HKDF-Extract: PRK = HMAC-SHA256(salt, IKM) */
    /* HKDF-Expand:  out = HKDF-Expand(PRK, info, 32) */
    /* Delegated to derive_kdf() from crypto.cpp */
    extern bool derive_kdf(const uint8_t *, size_t, const uint8_t *, size_t,
                            const char *, uint8_t *);
    return derive_kdf(zero_salt, 32, ikm, 64, TACHYON_KDF_PQ_HYBRID, out);
}

#else /* !TACHYON_PQ */
/* ══════════════════════════════════════════════════════════════════════════
 * Stub Definitions (no liboqs — PQ support disabled at compile time)
 * ══════════════════════════════════════════════════════════════════════════ */

struct PqKemState {
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
};

inline bool pq_kem_keygen(PqKemState &) { return false; }
inline bool pq_kem_encap(const uint8_t *, std::vector<uint8_t> &, uint8_t *) { return false; }
inline bool pq_kem_decap(const PqKemState &, const uint8_t *, uint8_t *) { return false; }
inline bool pq_combine_secrets(const uint8_t *, const uint8_t *, uint8_t *) { return false; }

#endif /* TACHYON_PQ */

/* ══════════════════════════════════════════════════════════════════════════
 * Compile-Time Size Checks (always compiled regardless of TACHYON_PQ)
 * ══════════════════════════════════════════════════════════════════════════ */

static_assert(TACHYON_PQ_SS_LEN == 32, "ML-KEM-768 shared secret must be 32 bytes");
static_assert(TACHYON_PQ_PK_LEN == 1184, "ML-KEM-768 public key must be 1184 bytes");
static_assert(TACHYON_PQ_CT_LEN == 1088, "ML-KEM-768 ciphertext must be 1088 bytes");
