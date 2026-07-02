/* SPDX-License-Identifier: MIT */
#include "pq_session.h"

#include "tachyon.h" /* derive_kdf, generate_cookie, packet flags, PSK label */

#include <arpa/inet.h> /* htonl / ntohl */
#include <cstring>
#include <openssl/crypto.h>

namespace tachyon::pqsession {

/* Keep the BPF-free header constants locked to the canonical packet flags. */
static_assert(PKT_PQ_INIT == TACHYON_PKT_PQ_INIT, "PQ_INIT wire type drift");
static_assert(PKT_PQ_RESPONSE == TACHYON_PKT_PQ_RESPONSE, "PQ_RESPONSE wire type drift");
static_assert(PKT_PQ_CONFIRM == TACHYON_PKT_PQ_CONFIRM, "PQ_CONFIRM wire type drift");
static_assert(PKT_CLASSICAL_AUTH == TACHYON_PKT_AUTH, "AUTH wire type drift");
static_assert(PKT_CLASSICAL_FINISH == TACHYON_PKT_FINISH, "FINISH wire type drift");

bool handshake_flag_allowed(uint8_t flag, bool hybrid_mode) {
    const bool is_pq = (flag == PKT_PQ_INIT || flag == PKT_PQ_RESPONSE || flag == PKT_PQ_CONFIRM);
    const bool is_classical_kex = (flag == PKT_CLASSICAL_AUTH || flag == PKT_CLASSICAL_FINISH);
    if (hybrid_mode)
        return !is_classical_kex; /* hybrid must not run the classical exchange */
    return !is_pq;                /* classical must not run the PQ exchange      */
}

namespace {

namespace pqhs = tachyon::pqhs;

/* Direction-stable KDF labels for the PSK fold. The label tracks the physical
 * direction of the key (initiator->responder vs responder->initiator), not the
 * local role, so both peers fold the same PSK into the same wire key and still
 * agree. */
constexpr char kLabelI2R[] = "Tachyon-PQ-Session-I2R";
constexpr char kLabelR2I[] = "Tachyon-PQ-Session-R2I";

void put_header(uint8_t *p, uint8_t flag, uint32_t session_id) {
    p[0] = flag;
    p[1] = p[2] = p[3] = 0;
    uint32_t be = htonl(session_id);
    std::memcpy(p + 4, &be, 4);
}

/* True iff the packet is well-formed for `flag` and carries our session id. A
 * packet at least `want_len` bytes is accepted; the fixed-size message lives in
 * the prefix and any trailing bytes are PaDMe padding added by send_framed
 * (the classical handlers are length-tolerant the same way). Sets
 * `mismatch_session` so the caller can distinguish "not for us" (drop) from
 * "malformed" (penalize). */
bool header_ok(const uint8_t *pkt, size_t len, size_t want_len, uint8_t flag, uint32_t session_id,
               bool &mismatch_session) {
    mismatch_session = false;
    if (pkt == nullptr || len < want_len)
        return false;
    if (pkt[0] != flag)
        return false;
    uint32_t be;
    std::memcpy(&be, pkt + 4, 4);
    if (ntohl(be) != session_id) {
        mismatch_session = true;
        return false;
    }
    return true;
}

Step map_result(pqhs::Result r) {
    switch (r) {
    case pqhs::Result::OK:
        return Step::OK;
    case pqhs::Result::BAD_MESSAGE:
        return Step::BAD_MESSAGE;
    case pqhs::Result::AUTH_FAIL:
        return Step::AUTH_FAIL;
    case pqhs::Result::CRYPTO_ERROR:
        return Step::CRYPTO_ERROR;
    case pqhs::Result::STATE_ERROR:
        return Step::STATE_ERROR;
    }
    return Step::CRYPTO_ERROR;
}

/* out = HKDF(salt = psk, ikm = pq_key, info = label). Binding the PSK as the
 * salt keeps hybrid mode's pre-shared-key authentication factor. */
bool fold_psk(const std::vector<uint8_t> &psk, const uint8_t *pq_key, const char *label,
              uint8_t *out) {
    /* pq_key and out are each SESSION_KEY_LEN bytes. */
    return derive_kdf(psk.data(), psk.size(), pq_key, SESSION_KEY_LEN, label, out);
}

std::vector<uint8_t> make_psk(const uint8_t *psk, size_t psk_len) {
    /* Mirror the classical safe_psk: an empty PSK falls back to a fixed label so
     * the derivation is always well-defined. */
    if (psk == nullptr || psk_len == 0) {
        const char *d = TACHYON_KDF_DEFAULT_PSK;
        return std::vector<uint8_t>(d, d + std::strlen(d));
    }
    return std::vector<uint8_t>(psk, psk + psk_len);
}

} // namespace

bool available() {
    return tachyon::hkex::hybrid_available();
}

/* ── Client (initiator) ─────────────────────────────────────────────────── */

Client::Client(const pqhs::StaticIdentity &id, uint32_t session_id, const uint8_t *psk,
               size_t psk_len)
    : hs_(id), session_id_(session_id), psk_(make_psk(psk, psk_len)) {}

Client::~Client() {
    if (!psk_.empty())
        OPENSSL_cleanse(psk_.data(), psk_.size());
}

bool Client::make_init(const uint8_t *cookie, uint64_t client_nonce, std::vector<uint8_t> &out) {
    if (init_made_)
        return false;
    std::vector<uint8_t> body;
    if (!hs_.create_init(body) || body.size() != pqhs::MSG_INIT_LEN)
        return false;

    out.resize(PQ_INIT_LEN);
    put_header(out.data(), TACHYON_PKT_PQ_INIT, session_id_);
    std::memcpy(out.data() + PQ_HDR_LEN, &client_nonce, 8);
    std::memcpy(out.data() + PQ_HDR_LEN + 8, cookie, COOKIE_LEN);
    std::memcpy(out.data() + PQ_HDR_LEN + 8 + COOKIE_LEN, body.data(), pqhs::MSG_INIT_LEN);
    init_made_ = true;
    return true;
}

Step Client::on_response(const uint8_t *pkt, size_t len, std::vector<uint8_t> &reply_out) {
    if (!init_made_ || complete_)
        return Step::STATE_ERROR;
    bool wrong_session = false;
    if (!header_ok(pkt, len, PQ_RESPONSE_LEN, TACHYON_PKT_PQ_RESPONSE, session_id_, wrong_session))
        return wrong_session ? Step::IGNORE : Step::BAD_MESSAGE;

    std::vector<uint8_t> confirm_body;
    pqhs::Result r = hs_.process_response(pkt + PQ_HDR_LEN, pqhs::MSG_RESPONSE_LEN, confirm_body);
    if (r != pqhs::Result::OK)
        return map_result(r);
    if (confirm_body.size() != pqhs::MSG_CONFIRM_LEN)
        return Step::CRYPTO_ERROR;

    reply_out.resize(PQ_CONFIRM_LEN);
    put_header(reply_out.data(), TACHYON_PKT_PQ_CONFIRM, session_id_);
    std::memcpy(reply_out.data() + PQ_HDR_LEN, confirm_body.data(), pqhs::MSG_CONFIRM_LEN);
    complete_ = true;
    return Step::COMPLETE;
}

bool Client::export_keys(uint8_t *tx, uint8_t *rx) const {
    if (!complete_)
        return false;
    uint8_t pq_tx[SESSION_KEY_LEN], pq_rx[SESSION_KEY_LEN];
    if (!hs_.export_keys(pq_tx, pq_rx))
        return false;
    /* Initiator: tx is I->R, rx is R->I. */
    bool ok = fold_psk(psk_, pq_tx, kLabelI2R, tx) && fold_psk(psk_, pq_rx, kLabelR2I, rx);
    OPENSSL_cleanse(pq_tx, SESSION_KEY_LEN);
    OPENSSL_cleanse(pq_rx, SESSION_KEY_LEN);
    return ok;
}

/* ── Server (responder) ─────────────────────────────────────────────────── */

Server::Server(const pqhs::StaticIdentity &id, uint32_t session_id, const uint8_t *psk,
               size_t psk_len)
    : hs_(id), session_id_(session_id), psk_(make_psk(psk, psk_len)) {}

Server::~Server() {
    if (!psk_.empty())
        OPENSSL_cleanse(psk_.data(), psk_.size());
}

Step Server::on_init(const uint8_t *pkt, size_t len, const uint8_t *cookie_secret,
                     uint32_t src_ip_net, uint64_t window, std::vector<uint8_t> &response_out) {
    if (init_seen_ || complete_)
        return Step::STATE_ERROR;
    bool wrong_session = false;
    if (!header_ok(pkt, len, PQ_INIT_LEN, TACHYON_PKT_PQ_INIT, session_id_, wrong_session))
        return wrong_session ? Step::IGNORE : Step::BAD_MESSAGE;

    uint64_t client_nonce;
    std::memcpy(&client_nonce, pkt + PQ_HDR_LEN, 8);
    const uint8_t *cookie = pkt + PQ_HDR_LEN + 8;

    /* Anti-DoS: validate the stateless cookie across the current and previous
     * window BEFORE any KEM decapsulation — identical to the classical AUTH
     * gate. Constant-time compare; either window may match. */
    uint8_t c1[COOKIE_LEN], c2[COOKIE_LEN];
    if (!generate_cookie(cookie_secret, src_ip_net, client_nonce, window, c1) ||
        !generate_cookie(cookie_secret, src_ip_net, client_nonce, window - 1, c2))
        return Step::CRYPTO_ERROR;
    if (CRYPTO_memcmp(c1, cookie, COOKIE_LEN) != 0 && CRYPTO_memcmp(c2, cookie, COOKIE_LEN) != 0)
        return Step::DOS_REJECT;

    const uint8_t *body = pkt + PQ_HDR_LEN + 8 + COOKIE_LEN;
    std::vector<uint8_t> resp_body;
    pqhs::Result r = hs_.process_init(body, pqhs::MSG_INIT_LEN, resp_body);
    if (r != pqhs::Result::OK)
        return map_result(r);
    if (resp_body.size() != pqhs::MSG_RESPONSE_LEN)
        return Step::CRYPTO_ERROR;

    response_out.resize(PQ_RESPONSE_LEN);
    put_header(response_out.data(), TACHYON_PKT_PQ_RESPONSE, session_id_);
    std::memcpy(response_out.data() + PQ_HDR_LEN, resp_body.data(), pqhs::MSG_RESPONSE_LEN);
    init_seen_ = true;
    return Step::OK;
}

Step Server::on_confirm(const uint8_t *pkt, size_t len) {
    if (!init_seen_ || complete_)
        return Step::STATE_ERROR;
    bool wrong_session = false;
    if (!header_ok(pkt, len, PQ_CONFIRM_LEN, TACHYON_PKT_PQ_CONFIRM, session_id_, wrong_session))
        return wrong_session ? Step::IGNORE : Step::BAD_MESSAGE;

    pqhs::Result r = hs_.process_confirm(pkt + PQ_HDR_LEN, pqhs::MSG_CONFIRM_LEN);
    if (r != pqhs::Result::OK)
        return map_result(r);
    complete_ = true;
    return Step::COMPLETE;
}

bool Server::export_keys(uint8_t *tx, uint8_t *rx) const {
    if (!complete_)
        return false;
    uint8_t pq_tx[SESSION_KEY_LEN], pq_rx[SESSION_KEY_LEN];
    if (!hs_.export_keys(pq_tx, pq_rx))
        return false;
    /* Responder: tx is R->I, rx is I->R. */
    bool ok = fold_psk(psk_, pq_tx, kLabelR2I, tx) && fold_psk(psk_, pq_rx, kLabelI2R, rx);
    OPENSSL_cleanse(pq_tx, SESSION_KEY_LEN);
    OPENSSL_cleanse(pq_rx, SESSION_KEY_LEN);
    return ok;
}

} /* namespace tachyon::pqsession */
