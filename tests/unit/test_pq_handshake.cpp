/* SPDX-License-Identifier: MIT */
/*
 * Two-peer integration tests for the post-quantum hybrid AKE. Both roles run
 * in-process and exchange messages as byte buffers, so the full handshake —
 * key agreement, mutual authentication, and tamper/impersonation rejection —
 * is exercised without sockets or the kernel datapath.
 */
#include <gtest/gtest.h>

#include "pq_handshake.h"

#include <cstring>
#include <vector>

/* From crypto.cpp; forward-declared to keep this TU free of the loader's
 * BPF-pulling umbrella header. */
bool generate_x25519_keypair(uint8_t *priv_out, uint8_t *pub_out);
void init_crypto_globals();

/* HKDF/AEAD in crypto.cpp need the fetched OpenSSL primitives; initialise them
 * once for the whole suite (mirrors CryptoTest::SetUp). */
class PqCryptoEnvironment : public ::testing::Environment {
  public:
    void SetUp() override { init_crypto_globals(); }
};
const ::testing::Environment *const kPqEnv =
    ::testing::AddGlobalTestEnvironment(new PqCryptoEnvironment);

namespace pqhs = tachyon::pqhs;

/* The full handshake needs a working ML-KEM backend; skip cleanly on builds
 * compiled with the stub KEM (no OpenSSL>=3.5 / liboqs). Parsing- and
 * state-machine-only tests run regardless. */
#define REQUIRE_PQ_BACKEND()                                                                       \
    do {                                                                                           \
        if (!tachyon::hkex::hybrid_available())                                                    \
            GTEST_SKIP() << "no post-quantum KEM backend in this build";                           \
    } while (0)

namespace {

struct Peer {
    uint8_t priv[32];
    uint8_t pub[32];
};

Peer make_peer() {
    Peer p{};
    EXPECT_TRUE(generate_x25519_keypair(p.priv, p.pub));
    return p;
}

pqhs::StaticIdentity id_of(const Peer &me, const Peer &other) {
    pqhs::StaticIdentity id{};
    std::memcpy(id.priv, me.priv, 32);
    std::memcpy(id.my_pub, me.pub, 32);
    std::memcpy(id.peer_pub, other.pub, 32);
    return id;
}

/* Drive a complete handshake. Returns true on mutual completion; on success the
 * four session keys are written out for inspection. */
bool run_handshake(const pqhs::StaticIdentity &init_id, const pqhs::StaticIdentity &resp_id,
                   uint8_t i_tx[32], uint8_t i_rx[32], uint8_t r_tx[32], uint8_t r_rx[32]) {
    pqhs::Initiator initr(init_id);
    pqhs::Responder respr(resp_id);

    std::vector<uint8_t> m1, m2, m3;
    if (!initr.create_init(m1))
        return false;
    if (respr.process_init(m1.data(), m1.size(), m2) != pqhs::Result::OK)
        return false;
    if (initr.process_response(m2.data(), m2.size(), m3) != pqhs::Result::OK)
        return false;
    if (respr.process_confirm(m3.data(), m3.size()) != pqhs::Result::OK)
        return false;
    if (!initr.complete() || !respr.complete())
        return false;
    return initr.export_keys(i_tx, i_rx) && respr.export_keys(r_tx, r_rx);
}

} // namespace

TEST(PqHandshake, MessageSizesAreFixed) {
    EXPECT_EQ(pqhs::MSG_INIT_LEN, pqhs::HDR_LEN + pqhs::NONCE_LEN + pqhs::EPK_LEN);
    EXPECT_EQ(pqhs::MSG_RESPONSE_LEN,
              pqhs::HDR_LEN + pqhs::NONCE_LEN + pqhs::CT_LEN + pqhs::TAG_LEN);
    EXPECT_EQ(pqhs::MSG_CONFIRM_LEN, pqhs::HDR_LEN + pqhs::TAG_LEN);
}

TEST(PqHandshake, FullHandshakeAgreesOnKeys) {
    REQUIRE_PQ_BACKEND();
    Peer i = make_peer(), r = make_peer();
    uint8_t i_tx[32], i_rx[32], r_tx[32], r_rx[32];
    ASSERT_TRUE(run_handshake(id_of(i, r), id_of(r, i), i_tx, i_rx, r_tx, r_rx));

    /* Per-direction agreement: initiator's send key == responder's receive key. */
    EXPECT_EQ(std::memcmp(i_tx, r_rx, 32), 0);
    EXPECT_EQ(std::memcmp(i_rx, r_tx, 32), 0);
    /* The two directions must use distinct keys. */
    EXPECT_NE(std::memcmp(i_tx, i_rx, 32), 0);
}

TEST(PqHandshake, EachHandshakeDerivesFreshKeys) {
    REQUIRE_PQ_BACKEND();
    Peer i = make_peer(), r = make_peer();
    uint8_t a_tx[32], a_rx[32], b_tx[32], b_rx[32];
    ASSERT_TRUE(run_handshake(id_of(i, r), id_of(r, i), a_tx, a_rx, b_tx, b_rx));

    uint8_t c_tx[32], c_rx[32], d_tx[32], d_rx[32];
    ASSERT_TRUE(run_handshake(id_of(i, r), id_of(r, i), c_tx, c_rx, d_tx, d_rx));

    /* Same static identities, but fresh ephemerals -> different session keys
     * (forward secrecy). */
    EXPECT_NE(std::memcmp(a_tx, c_tx, 32), 0);
}

TEST(PqHandshake, TamperedResponseFailsAuthentication) {
    REQUIRE_PQ_BACKEND();
    Peer i = make_peer(), r = make_peer();
    pqhs::Initiator initr(id_of(i, r));
    pqhs::Responder respr(id_of(r, i));

    std::vector<uint8_t> m1, m2, m3;
    ASSERT_TRUE(initr.create_init(m1));
    ASSERT_EQ(respr.process_init(m1.data(), m1.size(), m2), pqhs::Result::OK);

    /* Flip a byte inside the KEM ciphertext. */
    m2[pqhs::HDR_LEN + pqhs::NONCE_LEN + 5] ^= 0x40;

    pqhs::Result res = initr.process_response(m2.data(), m2.size(), m3);
    EXPECT_TRUE(res == pqhs::Result::AUTH_FAIL || res == pqhs::Result::CRYPTO_ERROR);
    EXPECT_FALSE(initr.complete());
}

TEST(PqHandshake, TamperedConfirmFailsAuthentication) {
    REQUIRE_PQ_BACKEND();
    Peer i = make_peer(), r = make_peer();
    pqhs::Initiator initr(id_of(i, r));
    pqhs::Responder respr(id_of(r, i));

    std::vector<uint8_t> m1, m2, m3;
    ASSERT_TRUE(initr.create_init(m1));
    ASSERT_EQ(respr.process_init(m1.data(), m1.size(), m2), pqhs::Result::OK);
    ASSERT_EQ(initr.process_response(m2.data(), m2.size(), m3), pqhs::Result::OK);

    m3[pqhs::HDR_LEN + 2] ^= 0x01; /* corrupt the initiator's confirmation tag */
    EXPECT_EQ(respr.process_confirm(m3.data(), m3.size()), pqhs::Result::AUTH_FAIL);
    EXPECT_FALSE(respr.complete());
}

TEST(PqHandshake, ImpersonatedPeerFailsAuthentication) {
    REQUIRE_PQ_BACKEND();
    Peer i = make_peer(), r = make_peer(), attacker = make_peer();

    /* The responder believes it is talking to `attacker`, not the real
     * initiator `i`. Its static-static DH therefore differs, so the derived
     * confirmation key differs and the initiator must reject the response. */
    pqhs::Initiator initr(id_of(i, r));
    pqhs::Responder respr(id_of(r, attacker));

    std::vector<uint8_t> m1, m2, m3;
    ASSERT_TRUE(initr.create_init(m1));
    ASSERT_EQ(respr.process_init(m1.data(), m1.size(), m2), pqhs::Result::OK);
    EXPECT_EQ(initr.process_response(m2.data(), m2.size(), m3), pqhs::Result::AUTH_FAIL);
    EXPECT_FALSE(initr.complete());
}

TEST(PqHandshake, MalformedMessagesAreRejected) {
    Peer i = make_peer(), r = make_peer();
    pqhs::Responder respr(id_of(r, i));

    std::vector<uint8_t> out;
    /* Wrong length. */
    std::vector<uint8_t> short_msg(10, 0);
    EXPECT_EQ(respr.process_init(short_msg.data(), short_msg.size(), out),
              pqhs::Result::BAD_MESSAGE);

    /* Right length, wrong version. */
    std::vector<uint8_t> bad_ver(pqhs::MSG_INIT_LEN, 0);
    bad_ver[0] = 0xFF;
    bad_ver[1] = 1;
    EXPECT_EQ(respr.process_init(bad_ver.data(), bad_ver.size(), out), pqhs::Result::BAD_MESSAGE);

    /* Right length and version, wrong type. */
    std::vector<uint8_t> bad_type(pqhs::MSG_INIT_LEN, 0);
    bad_type[0] = 1;
    bad_type[1] = 0x09;
    EXPECT_EQ(respr.process_init(bad_type.data(), bad_type.size(), out), pqhs::Result::BAD_MESSAGE);
}

TEST(PqHandshake, OutOfOrderCallsRejected) {
    Peer i = make_peer(), r = make_peer();
    pqhs::Initiator initr(id_of(i, r));

    /* process_response before create_init. */
    std::vector<uint8_t> dummy(pqhs::MSG_RESPONSE_LEN, 0), out;
    EXPECT_EQ(initr.process_response(dummy.data(), dummy.size(), out), pqhs::Result::STATE_ERROR);

    /* export_keys before completion. */
    uint8_t tx[32], rx[32];
    EXPECT_FALSE(initr.export_keys(tx, rx));
}
