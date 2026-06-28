/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Post-Quantum Hybrid Authenticated Key Exchange (PQ-AKE)
 *
 * A socket-agnostic, message-oriented 1.5-RTT mutually-authenticated handshake
 * that upgrades the tunnel's key agreement to be quantum-resistant. It composes
 * only primitives that already ship and are unit-tested elsewhere — there is no
 * novel cryptography here:
 *
 *   - Confidentiality (forward-secret, post-quantum): an *ephemeral* hybrid KEM
 *     (X25519 + ML-KEM-768, tachyon::hkex) keys the session. Because the KEM is
 *     ephemeral and discarded after the handshake, a future quantum adversary
 *     who recorded the traffic cannot recover the session key (defeats the
 *     "harvest now, decrypt later" threat).
 *   - Authentication: a static-static X25519 ECDH between the two peers'
 *     long-term keys (the Noise-IK / WireGuard known-peer model — each side is
 *     configured with the other's static public key). Only the two genuine
 *     peers can compute it, so a valid key-confirmation proves identity.
 *   - Binding: every message is folded into a running SHA-256 transcript that
 *     is used both as the KEM context and as the AEAD associated data, so any
 *     tampering or downgrade attempt breaks key confirmation.
 *
 * Message flow (initiator I, responder R):
 *   1. I -> R   INIT     : nonce_i || epk_i            (ephemeral hybrid pubkey)
 *   2. R -> I   RESPONSE : nonce_r || ct_e || tag_R    (KEM ciphertext + R's auth)
 *   3. I -> R   CONFIRM  : tag_I                       (I's auth)
 * After CONFIRM both sides hold identical per-direction session keys.
 *
 * This type is deliberately transport-free: it consumes and produces byte
 * buffers, so it is driven identically by the control-plane socket loop and by
 * the in-process two-peer test. All secret material is zeroized on destruction.
 */
#ifndef TACHYON_PQ_HANDSHAKE_H
#define TACHYON_PQ_HANDSHAKE_H

#include "hybrid_kex.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace tachyon::pqhs {

/* ── Sizes ──────────────────────────────────────────────────────────────── */
constexpr size_t KEY_LEN = 32;   /* session / chaining keys                  */
constexpr size_t NONCE_LEN = 16; /* per-message random nonce                 */
constexpr size_t TAG_LEN = 16;   /* AEAD authentication tag                  */
constexpr size_t STATIC_KEY_LEN = 32;
constexpr size_t EPK_LEN = tachyon::hkex::HYBRID_PK_LEN; /* 1216             */
constexpr size_t CT_LEN = tachyon::hkex::HYBRID_CT_LEN;  /* 1120             */

/* Wire message sizes (2-byte header = version || type). */
constexpr size_t HDR_LEN = 2;
constexpr size_t MSG_INIT_LEN = HDR_LEN + NONCE_LEN + EPK_LEN;              /* 1234 */
constexpr size_t MSG_RESPONSE_LEN = HDR_LEN + NONCE_LEN + CT_LEN + TAG_LEN; /* 1154 */
constexpr size_t MSG_CONFIRM_LEN = HDR_LEN + TAG_LEN;                       /* 18   */

/* Result of feeding a message to the state machine. */
enum class Result {
    OK,           /* message accepted; output (if any) produced              */
    BAD_MESSAGE,  /* malformed/short/wrong type or version                   */
    AUTH_FAIL,    /* key confirmation did not verify (impersonation/tamper)  */
    CRYPTO_ERROR, /* a primitive failed (RNG, KEM, KDF) — fail closed        */
    STATE_ERROR,  /* called out of order                                     */
};

/* Long-term identity: this peer's X25519 static key pair and the *known*
 * static public key of the peer it is talking to (configured out of band). */
struct StaticIdentity {
    uint8_t priv[STATIC_KEY_LEN];
    uint8_t my_pub[STATIC_KEY_LEN];
    uint8_t peer_pub[STATIC_KEY_LEN];
};

/* Shared transcript / key-schedule state. Not for direct use — see the
 * Initiator / Responder drivers below. */
class HandshakeBase {
  public:
    bool complete() const { return complete_; }

    /* After completion, export the two directional 32-byte session keys.
     * tx = this peer's send key, rx = this peer's receive key. The peers'
     * keys mirror: initiator.tx == responder.rx and vice versa. Returns false
     * if the handshake is not complete. */
    bool export_keys(uint8_t tx[KEY_LEN], uint8_t rx[KEY_LEN]) const;

  protected:
    explicit HandshakeBase(const StaticIdentity &id);
    ~HandshakeBase();
    HandshakeBase(const HandshakeBase &) = delete;
    HandshakeBase &operator=(const HandshakeBase &) = delete;

    /* Mix `data` into the running transcript hash (th_ = SHA256(th_ || data)). */
    void mix_transcript(const uint8_t *data, size_t len);
    /* Derive master + directional + confirmation keys from (ss_e || ss_ss) and
     * the current transcript. Populates k_i2r_, k_r2i_, k_conf_. */
    bool derive_keys(const uint8_t *ss_e, size_t ss_e_len, const uint8_t *ss_ss);
    /* Produce / verify a key-confirmation tag for direction byte `dir`. */
    bool make_confirm(uint8_t dir, uint8_t tag[TAG_LEN]) const;
    bool check_confirm(uint8_t dir, const uint8_t tag[TAG_LEN]) const;

    StaticIdentity id_;
    uint8_t th_[KEY_LEN];     /* running transcript hash                       */
    uint8_t k_i2r_[KEY_LEN];  /* initiator -> responder session key            */
    uint8_t k_r2i_[KEY_LEN];  /* responder -> initiator session key            */
    uint8_t k_conf_[KEY_LEN]; /* key-confirmation key                          */
    bool complete_ = false;
    bool keys_ready_ = false;
    bool is_initiator_ = false;
};

/* Initiator driver: create_init() then process_response(). */
class Initiator : public HandshakeBase {
  public:
    explicit Initiator(const StaticIdentity &id);
    ~Initiator();

    /* Step 1: build the INIT message. */
    bool create_init(std::vector<uint8_t> &out);

    /* Step 2: consume the RESPONSE, authenticate the responder, and emit the
     * CONFIRM message. On Result::OK the handshake is complete(). */
    Result process_response(const uint8_t *msg, size_t len, std::vector<uint8_t> &confirm_out);

  private:
    uint8_t eph_pub_[EPK_LEN];
    uint8_t eph_sec_[tachyon::hkex::HYBRID_SK_LEN];
    bool init_sent_ = false;
};

/* Responder driver: process_init() then process_confirm(). */
class Responder : public HandshakeBase {
  public:
    explicit Responder(const StaticIdentity &id);
    ~Responder();

    /* Step 1: consume the INIT, key the session, and emit the RESPONSE. */
    Result process_init(const uint8_t *msg, size_t len, std::vector<uint8_t> &response_out);

    /* Step 2: consume the CONFIRM and authenticate the initiator. On
     * Result::OK the handshake is complete(). */
    Result process_confirm(const uint8_t *msg, size_t len);

  private:
    bool init_seen_ = false;
};

} /* namespace tachyon::pqhs */

#endif /* TACHYON_PQ_HANDSHAKE_H */
