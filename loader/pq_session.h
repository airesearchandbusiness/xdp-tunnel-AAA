/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Post-Quantum Session Establishment (pqc_mode = hybrid)
 *
 * This is the transport-binding layer that turns the pure, socket-free
 * tachyon::pqhs handshake into something the control-plane UDP loop (and the
 * two-peer integration test) can drive directly. It adds exactly the three
 * concerns the bare AKE deliberately leaves out:
 *
 *   1. Wire framing — each pqhs message is carried inside a small packed header
 *      (type byte in the 0xC0 control range + session id) so the existing XDP
 *      RX path forwards it to userspace and the loop can demultiplex it.
 *   2. Anti-DoS — the responder reuses the classical stateless cookie round
 *      (INIT -> COOKIE) and validates the returned cookie *before* spending a
 *      KEM decapsulation, so a spoofed-source flood cannot make it do
 *      asymmetric work. This mirrors the classical AUTH gate exactly.
 *   3. Pre-shared-key binding — the configured PSK is folded into the final
 *      per-direction session keys, so hybrid mode keeps the same extra
 *      symmetric authentication factor the classical path has. The fold uses
 *      direction-stable labels, so both peers still agree.
 *
 * Everything cryptographic lives in tachyon::pqhs and tachyon::hkex; this layer
 * only marshals bytes and folds in the PSK. Like pqhs it is transport-free —
 * it consumes and produces buffers — so the unit test exercises the full
 * exchange both in-process and over a real loopback UDP socketpair.
 *
 * Roles:
 *   Client   = handshake initiator (sends PQ_INIT, finishes on PQ_RESPONSE).
 *   Server   = handshake responder (cookie-gated; replies PQ_RESPONSE, finishes
 *              on PQ_CONFIRM).
 *
 * All secret material (PSK, derived keys) is zeroized on destruction.
 */
#ifndef TACHYON_PQ_SESSION_H
#define TACHYON_PQ_SESSION_H

#include "pq_handshake.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace tachyon::pqsession {

/* Cookie length mirrors the classical handshake (TACHYON_HMAC_LEN). Defined
 * locally so this header does not have to pull in the BPF umbrella header. */
constexpr size_t COOKIE_LEN = 32;
constexpr size_t HMAC_SECRET_LEN = 32;
constexpr size_t SESSION_KEY_LEN = 32;

/* Wire type bytes (mirror TACHYON_PKT_PQ_* in src/common.h; a static_assert in
 * pq_session.cpp keeps them in lock-step). Exposed so callers and tests can
 * name them without including the BPF umbrella header. */
constexpr uint8_t PKT_PQ_INIT = 0xC7;
constexpr uint8_t PKT_PQ_RESPONSE = 0xC8;
constexpr uint8_t PKT_PQ_CONFIRM = 0xC9;

/* Wire packet sizes: a small framing header followed by the raw pqhs message.
 *   PQ_INIT    : hdr(8) || client_nonce(8) || cookie(32) || pqhs INIT      */
constexpr size_t PQ_HDR_LEN = 8; /* flags||pad3||session_id */
constexpr size_t PQ_INIT_LEN = PQ_HDR_LEN + 8 + COOKIE_LEN + tachyon::pqhs::MSG_INIT_LEN;
constexpr size_t PQ_RESPONSE_LEN = PQ_HDR_LEN + tachyon::pqhs::MSG_RESPONSE_LEN;
constexpr size_t PQ_CONFIRM_LEN = PQ_HDR_LEN + tachyon::pqhs::MSG_CONFIRM_LEN;

/* Outcome of feeding a packet to a Client/Server. */
enum class Step {
    OK,           /* processed; reply_out may carry a packet to send back        */
    COMPLETE,     /* handshake done; export_keys() is ready (reply may be set)    */
    IGNORE,       /* not for us (wrong session/role/version) — drop silently      */
    BAD_MESSAGE,  /* malformed / wrong length / wrong type                        */
    DOS_REJECT,   /* responder: cookie did not validate — caller should penalize  */
    AUTH_FAIL,    /* key confirmation failed — impersonation or tampering         */
    CRYPTO_ERROR, /* a primitive failed — fail closed                             */
    STATE_ERROR,  /* called out of order                                          */
};

/* Whether this build can actually run a hybrid handshake (needs an ML-KEM
 * backend). When false, callers must keep using the classical path. */
bool available();

/* ── Client (initiator) ─────────────────────────────────────────────────── */
class Client {
  public:
    /* `psk`/`psk_len` may be empty; a fixed default label is substituted so the
     * derivation is uniform (mirrors the classical safe_psk handling). */
    Client(const tachyon::pqhs::StaticIdentity &id, uint32_t session_id, const uint8_t *psk,
           size_t psk_len);
    ~Client();
    Client(const Client &) = delete;
    Client &operator=(const Client &) = delete;

    /* Build the PQ_INIT packet once the COOKIE has been received. `cookie` is
     * the 32-byte value from the MsgCookie; `client_nonce` echoes the nonce the
     * cookie was minted for, so the responder can revalidate it. */
    bool make_init(const uint8_t *cookie, uint64_t client_nonce,
                   std::vector<uint8_t> &out); /* cookie is COOKIE_LEN bytes */

    /* Feed a received PQ_RESPONSE. On Step::COMPLETE the PQ_CONFIRM to send is
     * written to reply_out and export_keys() becomes valid. */
    Step on_response(const uint8_t *pkt, size_t len, std::vector<uint8_t> &reply_out);

    bool complete() const { return complete_; }

    /* Final, PSK-folded per-direction keys, ready for inject_keys_to_kernel.
     * tx = this peer's send key (initiator -> responder). */
    bool export_keys(uint8_t *tx, uint8_t *rx) const; /* each SESSION_KEY_LEN bytes */

  private:
    tachyon::pqhs::Initiator hs_;
    uint32_t session_id_;
    std::vector<uint8_t> psk_;
    bool init_made_ = false;
    bool complete_ = false;
};

/* ── Server (responder) ─────────────────────────────────────────────────── */
class Server {
  public:
    Server(const tachyon::pqhs::StaticIdentity &id, uint32_t session_id, const uint8_t *psk,
           size_t psk_len);
    ~Server();
    Server(const Server &) = delete;
    Server &operator=(const Server &) = delete;

    /* Feed a received PQ_INIT. The cookie carried in the packet is validated
     * against `cookie_secret` for `src_ip_net` across the current and previous
     * one-minute windows (`window`, `window-1`) *before* any KEM work, exactly
     * like the classical AUTH gate. On Step::OK the PQ_RESPONSE is written to
     * response_out. */
    Step on_init(const uint8_t *pkt, size_t len, const uint8_t *cookie_secret, uint32_t src_ip_net,
                 uint64_t window, std::vector<uint8_t> &response_out);

    /* Feed a received PQ_CONFIRM. On Step::COMPLETE export_keys() is valid. */
    Step on_confirm(const uint8_t *pkt, size_t len);

    bool complete() const { return complete_; }

    /* tx = this peer's send key (responder -> initiator). */
    bool export_keys(uint8_t *tx, uint8_t *rx) const; /* each SESSION_KEY_LEN bytes */

  private:
    tachyon::pqhs::Responder hs_;
    uint32_t session_id_;
    std::vector<uint8_t> psk_;
    bool init_seen_ = false;
    bool complete_ = false;
};

} /* namespace tachyon::pqsession */

#endif /* TACHYON_PQ_SESSION_H */
