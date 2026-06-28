/* SPDX-License-Identifier: MIT */
#include "pq_handshake.h"

#include "tachyon.h" /* do_ecdh, derive_kdf, cp_aead_encrypt/decrypt */

#include <cstring>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

namespace tachyon::pqhs {

namespace {

constexpr uint8_t kVersion = 1;
constexpr uint8_t kTypeInit = 1;
constexpr uint8_t kTypeResponse = 2;
constexpr uint8_t kTypeConfirm = 3;

/* Direction bytes for the two key-confirmation tags. They double as the AEAD
 * nonce discriminator so the responder's and initiator's confirmations never
 * share a (key, nonce) pair under the single confirmation key. */
constexpr uint8_t kDirResponder = 2;
constexpr uint8_t kDirInitiator = 3;

constexpr char kProtocolLabel[] = "Tachyon-PQ-AKE-v1";

/* SHA-256 of up to two concatenated chunks via the modern EVP interface. */
bool sha256(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len, uint8_t out[KEY_LEN]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return false;
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
              (a == nullptr || EVP_DigestUpdate(ctx, a, a_len) == 1) &&
              (b == nullptr || EVP_DigestUpdate(ctx, b, b_len) == 1) &&
              EVP_DigestFinal_ex(ctx, out, nullptr) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

} // namespace

/* ── HandshakeBase ──────────────────────────────────────────────────────── */

HandshakeBase::HandshakeBase(const StaticIdentity &id) {
    std::memcpy(&id_, &id, sizeof(id_));
    /* Seed the transcript with the protocol label so cross-protocol messages
     * can never collide. */
    sha256(reinterpret_cast<const uint8_t *>(kProtocolLabel), sizeof(kProtocolLabel) - 1, nullptr,
           0, th_);
    std::memset(k_i2r_, 0, KEY_LEN);
    std::memset(k_r2i_, 0, KEY_LEN);
    std::memset(k_conf_, 0, KEY_LEN);
}

HandshakeBase::~HandshakeBase() {
    OPENSSL_cleanse(&id_, sizeof(id_));
    OPENSSL_cleanse(k_i2r_, KEY_LEN);
    OPENSSL_cleanse(k_r2i_, KEY_LEN);
    OPENSSL_cleanse(k_conf_, KEY_LEN);
    OPENSSL_cleanse(th_, KEY_LEN);
}

void HandshakeBase::mix_transcript(const uint8_t *data, size_t len) {
    /* th_ <- SHA256(th_ || data). EVP consumes th_ into the context before the
     * final write, so reusing th_ as the output is safe. */
    sha256(th_, KEY_LEN, data, len, th_);
}

bool HandshakeBase::derive_keys(const uint8_t *ss_e, size_t ss_e_len, const uint8_t *ss_ss) {
    /* ikm = ss_e (ephemeral hybrid KEM) || ss_ss (static-static auth DH). */
    uint8_t ikm[tachyon::hkex::HYBRID_SS_LEN + STATIC_KEY_LEN];
    if (ss_e_len > tachyon::hkex::HYBRID_SS_LEN)
        return false;
    std::memcpy(ikm, ss_e, ss_e_len);
    std::memcpy(ikm + ss_e_len, ss_ss, STATIC_KEY_LEN);
    const size_t ikm_len = ss_e_len + STATIC_KEY_LEN;

    uint8_t master[KEY_LEN];
    bool ok = derive_kdf(th_, KEY_LEN, ikm, ikm_len, "Tachyon-PQ-Master", master);
    OPENSSL_cleanse(ikm, sizeof(ikm));
    if (!ok)
        return false;

    const uint8_t zero[KEY_LEN] = {0};
    ok = derive_kdf(master, KEY_LEN, zero, KEY_LEN, "Tachyon-PQ-I2R", k_i2r_) &&
         derive_kdf(master, KEY_LEN, zero, KEY_LEN, "Tachyon-PQ-R2I", k_r2i_) &&
         derive_kdf(master, KEY_LEN, zero, KEY_LEN, "Tachyon-PQ-Confirm", k_conf_);
    OPENSSL_cleanse(master, KEY_LEN);
    if (!ok)
        return false;
    keys_ready_ = true;
    return true;
}

bool HandshakeBase::make_confirm(uint8_t dir, uint8_t tag[TAG_LEN]) const {
    if (!keys_ready_)
        return false;
    uint8_t nonce[TACHYON_AEAD_IV_LEN] = {0};
    nonce[0] = dir;
    uint8_t dummy = 0;
    /* Empty-plaintext AEAD: the tag authenticates the transcript (AD) under the
     * confirmation key, proving the sender derived the same key schedule. */
    return cp_aead_encrypt(k_conf_, &dummy, 0, th_, KEY_LEN, nonce, &dummy, tag);
}

bool HandshakeBase::check_confirm(uint8_t dir, const uint8_t tag[TAG_LEN]) const {
    if (!keys_ready_)
        return false;
    uint8_t nonce[TACHYON_AEAD_IV_LEN] = {0};
    nonce[0] = dir;
    uint8_t dummy = 0;
    return cp_aead_decrypt(k_conf_, &dummy, 0, th_, KEY_LEN, nonce, tag, &dummy);
}

bool HandshakeBase::export_keys(uint8_t tx[KEY_LEN], uint8_t rx[KEY_LEN]) const {
    if (!complete_ || !keys_ready_)
        return false;
    if (is_initiator_) {
        std::memcpy(tx, k_i2r_, KEY_LEN);
        std::memcpy(rx, k_r2i_, KEY_LEN);
    } else {
        std::memcpy(tx, k_r2i_, KEY_LEN);
        std::memcpy(rx, k_i2r_, KEY_LEN);
    }
    return true;
}

/* ── Initiator ──────────────────────────────────────────────────────────── */

Initiator::Initiator(const StaticIdentity &id) : HandshakeBase(id) {
    is_initiator_ = true;
    std::memset(eph_pub_, 0, sizeof(eph_pub_));
    std::memset(eph_sec_, 0, sizeof(eph_sec_));
}

Initiator::~Initiator() {
    OPENSSL_cleanse(eph_sec_, sizeof(eph_sec_));
}

bool Initiator::create_init(std::vector<uint8_t> &out) {
    if (init_sent_)
        return false;
    if (!tachyon::hkex::hybrid_keygen(eph_pub_, eph_sec_))
        return false;

    out.resize(MSG_INIT_LEN);
    out[0] = kVersion;
    out[1] = kTypeInit;
    if (RAND_bytes(out.data() + HDR_LEN, NONCE_LEN) != 1)
        return false;
    std::memcpy(out.data() + HDR_LEN + NONCE_LEN, eph_pub_, EPK_LEN);

    /* Bind the whole INIT message into the transcript (-> th1). */
    mix_transcript(out.data(), MSG_INIT_LEN);
    init_sent_ = true;
    return true;
}

Result Initiator::process_response(const uint8_t *msg, size_t len,
                                   std::vector<uint8_t> &confirm_out) {
    if (!init_sent_ || complete_)
        return Result::STATE_ERROR;
    if (msg == nullptr || len != MSG_RESPONSE_LEN)
        return Result::BAD_MESSAGE;
    if (msg[0] != kVersion || msg[1] != kTypeResponse)
        return Result::BAD_MESSAGE;

    const uint8_t *ct = msg + HDR_LEN + NONCE_LEN;
    const uint8_t *tag_r = msg + HDR_LEN + NONCE_LEN + CT_LEN;

    /* Recover the ephemeral hybrid secret. The KEM context is th1 (transcript
     * after INIT) — exactly what the responder used to encapsulate. */
    uint8_t ss_e[tachyon::hkex::HYBRID_SS_LEN];
    if (!tachyon::hkex::hybrid_decapsulate(eph_sec_, ct, th_, KEY_LEN, ss_e)) {
        OPENSSL_cleanse(ss_e, sizeof(ss_e));
        return Result::CRYPTO_ERROR;
    }
    OPENSSL_cleanse(eph_sec_, sizeof(eph_sec_)); /* forward secrecy */

    /* Static-static authentication DH. */
    uint8_t ss_ss[STATIC_KEY_LEN];
    if (!do_ecdh(id_.priv, id_.peer_pub, ss_ss)) {
        OPENSSL_cleanse(ss_e, sizeof(ss_e));
        OPENSSL_cleanse(ss_ss, sizeof(ss_ss));
        return Result::CRYPTO_ERROR;
    }

    /* Fold the RESPONSE (minus its tag) into the transcript (-> th2). */
    mix_transcript(msg, HDR_LEN + NONCE_LEN + CT_LEN);

    bool ok = derive_keys(ss_e, sizeof(ss_e), ss_ss);
    OPENSSL_cleanse(ss_e, sizeof(ss_e));
    OPENSSL_cleanse(ss_ss, sizeof(ss_ss));
    if (!ok)
        return Result::CRYPTO_ERROR;

    /* Authenticate the responder. */
    if (!check_confirm(kDirResponder, tag_r))
        return Result::AUTH_FAIL;

    /* Emit our own confirmation (authenticates us to the responder). */
    confirm_out.resize(MSG_CONFIRM_LEN);
    confirm_out[0] = kVersion;
    confirm_out[1] = kTypeConfirm;
    if (!make_confirm(kDirInitiator, confirm_out.data() + HDR_LEN))
        return Result::CRYPTO_ERROR;

    complete_ = true;
    return Result::OK;
}

/* ── Responder ──────────────────────────────────────────────────────────── */

Responder::Responder(const StaticIdentity &id) : HandshakeBase(id) {
    is_initiator_ = false;
}

Responder::~Responder() = default;

Result Responder::process_init(const uint8_t *msg, size_t len, std::vector<uint8_t> &response_out) {
    if (init_seen_)
        return Result::STATE_ERROR;
    if (msg == nullptr || len != MSG_INIT_LEN)
        return Result::BAD_MESSAGE;
    if (msg[0] != kVersion || msg[1] != kTypeInit)
        return Result::BAD_MESSAGE;

    const uint8_t *epk = msg + HDR_LEN + NONCE_LEN;

    /* Bind the INIT into the transcript (-> th1), then encapsulate to the
     * initiator's ephemeral hybrid key with th1 as the KEM context. */
    mix_transcript(msg, MSG_INIT_LEN);

    response_out.resize(MSG_RESPONSE_LEN);
    response_out[0] = kVersion;
    response_out[1] = kTypeResponse;
    if (RAND_bytes(response_out.data() + HDR_LEN, NONCE_LEN) != 1)
        return Result::CRYPTO_ERROR;

    uint8_t ss_e[tachyon::hkex::HYBRID_SS_LEN];
    uint8_t *ct_out = response_out.data() + HDR_LEN + NONCE_LEN;
    if (!tachyon::hkex::hybrid_encapsulate(epk, th_, KEY_LEN, ct_out, ss_e)) {
        OPENSSL_cleanse(ss_e, sizeof(ss_e));
        return Result::CRYPTO_ERROR;
    }

    uint8_t ss_ss[STATIC_KEY_LEN];
    if (!do_ecdh(id_.priv, id_.peer_pub, ss_ss)) {
        OPENSSL_cleanse(ss_e, sizeof(ss_e));
        OPENSSL_cleanse(ss_ss, sizeof(ss_ss));
        return Result::CRYPTO_ERROR;
    }

    /* Fold the RESPONSE body (minus the tag) into the transcript (-> th2). */
    mix_transcript(response_out.data(), HDR_LEN + NONCE_LEN + CT_LEN);

    bool ok = derive_keys(ss_e, sizeof(ss_e), ss_ss);
    OPENSSL_cleanse(ss_e, sizeof(ss_e));
    OPENSSL_cleanse(ss_ss, sizeof(ss_ss));
    if (!ok)
        return Result::CRYPTO_ERROR;

    /* Append our key-confirmation tag. */
    if (!make_confirm(kDirResponder, response_out.data() + HDR_LEN + NONCE_LEN + CT_LEN))
        return Result::CRYPTO_ERROR;

    init_seen_ = true;
    return Result::OK;
}

Result Responder::process_confirm(const uint8_t *msg, size_t len) {
    if (!init_seen_ || complete_)
        return Result::STATE_ERROR;
    if (msg == nullptr || len != MSG_CONFIRM_LEN)
        return Result::BAD_MESSAGE;
    if (msg[0] != kVersion || msg[1] != kTypeConfirm)
        return Result::BAD_MESSAGE;

    if (!check_confirm(kDirInitiator, msg + HDR_LEN))
        return Result::AUTH_FAIL;

    complete_ = true;
    return Result::OK;
}

} /* namespace tachyon::pqhs */
