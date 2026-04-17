/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Control Plane - Post-Quantum Key Encapsulation
 *
 * Thin wrapper around ML-KEM-768 (NIST FIPS 203 / CRYSTALS-Kyber) with three
 * backends selected at compile time:
 *
 *   1. OpenSSL >= 3.5 native EVP_KEM            (-DTACHYON_PQC_OPENSSL)
 *   2. liboqs >= 0.10                           (-DTACHYON_PQC_OQS)
 *   3. Unavailable — function stubs that return false
 *
 * The build system picks a backend via pkg-config; the detection contract is
 * captured in the static helper `pqc_available()` which is the ONLY runtime
 * gate callers should check.
 *
 * Handshake-integration model:
 *
 *   ss_classical = X25519(client_sk, server_pk)        // 32 bytes
 *   ss_pq        = ML_KEM_768.Decap(client_sk, ct)     // 32 bytes
 *   combined     = HKDF-Extract("tch-pq v5", ss_classical || ss_pq)
 *
 * Only the *combined* secret is ever used as IKM; either component alone must
 * not leak session keys. Because X25519 stays in the mix, a catastrophic
 * break of ML-KEM falls back to classical DH security (and vice versa).
 *
 * Key/ciphertext sizes are those of FIPS 203 parameter set ML-KEM-768.
 */
#ifndef TACHYON_PQC_H
#define TACHYON_PQC_H

#include <cstdint>
#include <cstddef>

namespace tachyon::pqc {

/* FIPS 203 parameter set 3 (ML-KEM-768) — classical ~192-bit / PQ ~cat 3 */
constexpr size_t MLKEM768_PUBLIC_KEY_LEN  = 1184;
constexpr size_t MLKEM768_SECRET_KEY_LEN  = 2400;
constexpr size_t MLKEM768_CIPHERTEXT_LEN  = 1088;
constexpr size_t MLKEM768_SHARED_SECRET   = 32;

/*
 * pqc_available - Returns true when a real PQC backend is linked in and
 * usable. When false, every other function in this namespace returns false
 * unconditionally and tests should skip PQC-dependent assertions.
 */
bool pqc_available();

/*
 * Human-readable backend identifier, e.g. "openssl-3.5", "liboqs-0.10.1",
 * or "unavailable". Never nullptr.
 */
const char *pqc_backend();

/*
 * mlkem768_keygen - Generate a fresh keypair. Both pointers MUST reference
 * buffers of MLKEM768_PUBLIC_KEY_LEN and MLKEM768_SECRET_KEY_LEN bytes
 * respectively. Returns true on success, false if the backend is unavailable
 * or the RNG failed.
 *
 * On failure, buffers are zeroed to preserve "all or nothing" semantics.
 */
bool mlkem768_keygen(uint8_t *pk_out, uint8_t *sk_out);

/*
 * mlkem768_encapsulate - Given a peer public key, produce (ciphertext,
 * shared_secret). Caller buffers must be MLKEM768_CIPHERTEXT_LEN and
 * MLKEM768_SHARED_SECRET bytes.
 */
bool mlkem768_encapsulate(const uint8_t *peer_pk, uint8_t *ct_out, uint8_t *ss_out);

/*
 * mlkem768_decapsulate - Recover the shared secret from a ciphertext using
 * the local secret key. Implementations are constant-time on malformed
 * ciphertext per FIPS 203 §6.3 ("implicit rejection").
 */
bool mlkem768_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss_out);

/*
 * hkdf_sha384_extract - Convenience HKDF-Extract with SHA-384 used to mix
 * X25519 and ML-KEM shared secrets into a single 48-byte pseudo-random key.
 *
 *   out = HKDF-Extract-SHA384(salt, ikm)
 *
 * Returns true on success. Safe to call regardless of pqc_available().
 */
bool hkdf_sha384_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                         size_t ikm_len, uint8_t out[48]);

/*
 * hybrid_combine - Concatenate classical || pq secrets and derive a 48-byte
 * combined PRK via HKDF-SHA384. `context` is an optional domain-separation
 * string (may be nullptr). Output is suitable as input_keying_material for a
 * subsequent HKDF-Expand that produces tunnel session keys.
 */
bool hybrid_combine(const uint8_t *ss_classical, size_t ss_classical_len,
                    const uint8_t *ss_pq, size_t ss_pq_len, const char *context,
                    uint8_t out[48]);

} /* namespace tachyon::pqc */

#endif /* TACHYON_PQC_H */
