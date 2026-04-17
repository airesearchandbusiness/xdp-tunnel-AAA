/* SPDX-License-Identifier: MIT */
/*
 * Hybrid post-quantum / classical key exchange.
 *
 * This is the production-grade wrapper that network.cpp will call for the
 * Tachyon v5 handshake. It composes X25519 (RFC 7748) with ML-KEM-768
 * (FIPS 203) into a single primitive whose shared secret stays secure as
 * long as *either* underlying KEM is unbroken.
 *
 * Combiner: HKDF-SHA384-Extract(salt=context, ikm = ss_x25519 || ss_mlkem).
 *           Output is 48 bytes — drop-in for an HKDF-SHA384 PRK.
 *
 * The combiner follows the hybrid-KEM construction analysed in
 * Bindel–Brendel–Fischlin–Goncalves–Stebila 2019 ("Hybrid key encapsulation
 * mechanisms and authenticated key exchange"): splitting the KEM shared
 * secrets into the HKDF IKM and using an application-specific salt as
 * context yields an IND-CCA hybrid whose security reduces to the stronger
 * of its components.
 *
 * When no ML-KEM backend is linked (see pqc.cpp), every function returns
 * false and sets errno=ENOTSUP so callers can cleanly fall back to pure
 * X25519 — there is no silent degradation.
 *
 * Thread-safety: every function is pure — no shared state. Safe to invoke
 * from any thread.
 */
#ifndef TACHYON_HYBRID_KEX_H
#define TACHYON_HYBRID_KEX_H

#include <cstddef>
#include <cstdint>

#include "pqc.h"

namespace tachyon::hkex {

constexpr size_t X25519_PK_LEN   = 32;
constexpr size_t X25519_SK_LEN   = 32;
constexpr size_t X25519_SS_LEN   = 32;

constexpr size_t HYBRID_PK_LEN   = X25519_PK_LEN + tachyon::pqc::MLKEM768_PUBLIC_KEY_LEN;  /* 1216 */
constexpr size_t HYBRID_SK_LEN   = X25519_SK_LEN + tachyon::pqc::MLKEM768_SECRET_KEY_LEN;  /* 2432 */
constexpr size_t HYBRID_CT_LEN   = X25519_PK_LEN + tachyon::pqc::MLKEM768_CIPHERTEXT_LEN;  /* 1120 */
constexpr size_t HYBRID_SS_LEN   = 48;  /* HKDF-SHA384 PRK width */

/*
 * Long-term key generation.
 *
 * Layout:
 *   pk = x25519_pk(32) || mlkem_pk(1184)
 *   sk = x25519_sk(32) || mlkem_sk(2400)
 *
 * Both halves are generated with independent CSPRNG draws. Returns false on
 * any backend failure; on false, the caller must treat the buffers as
 * uninitialised — we do *not* partially-fill.
 */
bool hybrid_keygen(uint8_t pk[HYBRID_PK_LEN], uint8_t sk[HYBRID_SK_LEN]);

/*
 * Encapsulate to a peer's hybrid public key.
 *
 * Draws an ephemeral X25519 keypair, performs X25519 against the peer's
 * static X25519 public key, and ML-KEM encapsulates to the peer's ML-KEM
 * public key. The ciphertext layout mirrors the public-key layout:
 *   ct = ephemeral_x25519_pk(32) || mlkem_ct(1088)
 *
 * `context` is mixed into the HKDF salt, binding the shared secret to the
 * application / handshake transcript. Pass the transcript hash here.
 */
bool hybrid_encapsulate(const uint8_t peer_pk[HYBRID_PK_LEN],
                        const uint8_t *context, size_t context_len,
                        uint8_t ct[HYBRID_CT_LEN],
                        uint8_t ss[HYBRID_SS_LEN]);

/*
 * Decapsulate with the local hybrid secret key.
 *
 * Recovers both halves of the shared secret and combines them with the
 * same context. Returns true on success; returns true with a pseudorandom
 * ss on invalid ML-KEM ciphertext (FIPS 203 §6.3 implicit rejection) —
 * match this against the sender's expected value to detect tampering.
 */
bool hybrid_decapsulate(const uint8_t sk[HYBRID_SK_LEN],
                        const uint8_t ct[HYBRID_CT_LEN],
                        const uint8_t *context, size_t context_len,
                        uint8_t ss[HYBRID_SS_LEN]);

/*
 * Query whether the hybrid path is usable on this build. Equivalent to
 * tachyon::pqc::pqc_available() — provided so callers don't need to reach
 * across modules.
 */
bool hybrid_available();

} /* namespace tachyon::hkex */

#endif /* TACHYON_HYBRID_KEX_H */
